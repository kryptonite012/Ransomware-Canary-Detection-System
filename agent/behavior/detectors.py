"""Behavioral detection: correlates filesystem events over time.

Each detector emits a :class:`BehaviorSignal` when a threshold is crossed.
Signals are deliberately coarse ("rapid mass modification", "mass deletion")
and carry evidence (counts, example paths, directories, processes) so that the
risk engine and the dashboard can explain *why* a score rose.

A sliding time window (deque of timestamped records) backs the rate-based
detectors; an adaptive per-endpoint baseline flags activity that is abnormal
*for this machine* even when it is below the static thresholds.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from agent.core.events import CHANGE_TYPES, EventType, FileEvent
from agent.entropy.filetypes import category_for

# Extensions ransomware commonly appends; used only as a weak corroborating hint.
SUSPICIOUS_EXTENSIONS = frozenset({
    ".encrypted", ".enc", ".locked", ".crypt", ".crypted", ".cry", ".cerber", ".locky", ".zepto",
    ".odin", ".thor", ".aesir", ".zzz", ".micro", ".ecc", ".ezz", ".exx", ".ccc", ".vvv", ".abc",
    ".xyz", ".ttt", ".crypto", ".coded", ".wncry", ".wcry", ".wannacry", ".ransom", ".pays", ".id",
    ".kkk", ".fun", ".gww", ".btc", ".kraken", ".darkness", ".nochance", ".oshit", ".r5a", ".conficker",
})

RANSOM_NOTE_HINTS = (
    "readme", "decrypt", "how_to", "howto", "recover", "restore", "unlock", "ransom", "your_files",
    "help_decrypt", "_open_", "important",
)
RANSOM_NOTE_EXTS = (".txt", ".html", ".hta", ".htm")


@dataclass(slots=True)
class BehaviorSignal:
    signal_type: str
    description: str
    severity_hint: str  # low | medium | high
    count: int = 0
    evidence: dict[str, Any] = field(default_factory=dict)
    sample_paths: list[str] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)
    pids: list[int] = field(default_factory=list)


class _SlidingWindow:
    """Timestamped records kept within ``window`` seconds."""

    def __init__(self, window: float):
        self.window = window
        self.records: deque[tuple[float, Any]] = deque()

    def add(self, item: Any, now: float) -> None:
        self.records.append((now, item))
        self._trim(now)

    def _trim(self, now: float) -> None:
        cutoff = now - self.window
        while self.records and self.records[0][0] < cutoff:
            self.records.popleft()

    def items(self, now: float) -> list[Any]:
        self._trim(now)
        return [item for _, item in self.records]

    def __len__(self) -> int:
        return len(self.records)


class AdaptiveBaseline:
    """Welford mean/variance of change-events per fixed bucket."""

    def __init__(self, bucket_seconds: float, learning_buckets: int, sigma: float, min_events: int):
        self.bucket_seconds = bucket_seconds
        self.learning_buckets = learning_buckets
        self.sigma = sigma
        self.min_events = min_events
        self._bucket_start = 0.0
        self._bucket_count = 0
        self.n = 0
        self.mean = 0.0
        self._m2 = 0.0

    def observe(self, now: float) -> tuple[bool, float, float]:
        """Record one change event; returns (is_anomaly, current_bucket, threshold)."""
        if self._bucket_start == 0.0:
            self._bucket_start = now
        anomaly = False
        threshold = float("inf")
        if now - self._bucket_start >= self.bucket_seconds:
            count = self._bucket_count
            if self.n >= self.learning_buckets and self.n >= 3:
                std = (self._m2 / self.n) ** 0.5
                threshold = self.mean + self.sigma * std
                if count > threshold and count >= self.min_events:
                    anomaly = True
            self.n += 1
            delta = count - self.mean
            self.mean += delta / self.n
            self._m2 += delta * (count - self.mean)
            self._bucket_start = now
            self._bucket_count = 0
        self._bucket_count += 1
        return anomaly, self._bucket_count, threshold

    @property
    def ready(self) -> bool:
        return self.n >= self.learning_buckets

    def snapshot(self) -> dict:
        std = (self._m2 / self.n) ** 0.5 if self.n else 0.0
        return {"buckets": self.n, "mean": round(self.mean, 2), "std": round(std, 2),
                "ready": self.ready}


class BehaviorEngine:
    def __init__(self, settings):
        self.s = settings
        w = settings.window_seconds
        self.mods = _SlidingWindow(w)
        self.deletes = _SlidingWindow(w)
        self.renames = _SlidingWindow(w)
        self.ext_changes = _SlidingWindow(w)
        self.replacements = _SlidingWindow(w)
        self.notes = _SlidingWindow(max(w, 60))
        self._rewrite_counts: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=20))
        self.baseline = AdaptiveBaseline(settings.baseline_bucket_seconds, settings.baseline_learning_buckets,
                                         settings.baseline_sigma, settings.baseline_min_events)
        self._last_emit: dict[str, float] = {}
        self.signals_emitted = 0

    def observe(self, ev: FileEvent, now: float | None = None) -> list[BehaviorSignal]:
        if ev.is_directory or ev.event_type not in CHANGE_TYPES:
            return []
        now = time.monotonic() if now is None else now
        path = ev.path
        directory = os.path.dirname(path)
        signals: list[BehaviorSignal] = []

        anomaly, _, threshold = self.baseline.observe(now)

        if ev.event_type in (EventType.MODIFIED, EventType.CREATED):
            self.mods.add((path, directory, ev.pid), now)
            self._track_rewrite(path, now)
        elif ev.event_type is EventType.DELETED:
            self.deletes.add((path, directory, ev.pid), now)
        elif ev.event_type is EventType.MOVED:
            self.renames.add((ev.src_path, ev.dest_path, ev.pid), now)
            self.mods.add((path, directory, ev.pid), now)
            self._check_extension_change(ev, now)
            self._check_replacement(ev, now)

        self._maybe_ransom_note(path, now)

        signals.extend(self._evaluate(now))
        if anomaly:
            signals.append(self._maybe(BehaviorSignal(
                "baseline_deviation",
                f"file-change rate exceeds this endpoint's learned baseline (>{threshold:.0f}/bucket)",
                "medium", count=self.baseline._bucket_count,
                evidence=self.baseline.snapshot())))
        emitted = [s for s in signals if s is not None]
        self.signals_emitted += len(emitted)
        return emitted

    def _track_rewrite(self, path: str, now: float) -> None:
        dq = self._rewrite_counts[path]
        dq.append(now)
        cutoff = now - self.s.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _check_extension_change(self, ev: FileEvent, now: float) -> None:
        src_ext = os.path.splitext(ev.src_path)[1].lower()
        dst_ext = os.path.splitext(ev.dest_path or "")[1].lower()
        if src_ext != dst_ext and dst_ext:
            suspicious = dst_ext in SUSPICIOUS_EXTENSIONS
            self.ext_changes.add((ev.src_path, ev.dest_path, dst_ext, suspicious, ev.pid), now)

    def _check_replacement(self, ev: FileEvent, now: float) -> None:
        # A rename where the source keeps a "real" document extension but the
        # destination differs is a classic encrypt-then-replace pattern.
        src_cat = category_for(ev.src_path)
        if not src_cat.expected_high_entropy and src_cat.name not in ("unknown", "executable"):
            dst_ext = os.path.splitext(ev.dest_path or "")[1].lower()
            src_ext = os.path.splitext(ev.src_path)[1].lower()
            if dst_ext != src_ext:
                self.replacements.add((ev.src_path, ev.dest_path, ev.pid), now)

    def _maybe_ransom_note(self, path: str, now: float) -> None:
        name = os.path.basename(path).lower()
        ext = os.path.splitext(name)[1]
        if ext in RANSOM_NOTE_EXTS and any(h in name for h in RANSOM_NOTE_HINTS):
            self.notes.add(path, now)

    def _evaluate(self, now: float) -> list[BehaviorSignal | None]:
        s = self.s
        out: list[BehaviorSignal | None] = []

        mods = self.mods.items(now)
        if len(mods) >= s.mass_modification_threshold:
            dirs = {d for _, d, _ in mods}
            pids = {p for _, _, p in mods if p}
            out.append(self._maybe(BehaviorSignal(
                "rapid_mass_modification",
                f"{len(mods)} files modified within {s.window_seconds:.0f}s across {len(dirs)} director(ies)",
                "high", count=len(mods),
                evidence={"window_seconds": s.window_seconds, "directories": len(dirs)},
                sample_paths=[p for p, _, _ in mods[:10]], directories=sorted(dirs)[:10],
                pids=sorted(pids)[:10])))
            if len(dirs) >= s.directory_spread_threshold:
                out.append(self._maybe(BehaviorSignal(
                    "directory_spread",
                    f"mass modification spans {len(dirs)} directories (lateral spread)",
                    "medium", count=len(dirs), directories=sorted(dirs)[:15])))

        dels = self.deletes.items(now)
        if len(dels) >= s.mass_deletion_threshold:
            out.append(self._maybe(BehaviorSignal(
                "mass_deletion",
                f"{len(dels)} files deleted within {s.window_seconds:.0f}s",
                "high", count=len(dels), sample_paths=[p for p, _, _ in dels[:10]],
                directories=sorted({d for _, d, _ in dels})[:10])))

        ext = self.ext_changes.items(now)
        if len(ext) >= s.extension_change_threshold:
            susp = [e for e in ext if e[3]]
            uniq_ext = {e[2] for e in ext}
            out.append(self._maybe(BehaviorSignal(
                "suspicious_extension_change",
                f"{len(ext)} files changed extension ({len(uniq_ext)} distinct new extension(s))"
                + (f", {len(susp)} known ransomware extension(s)" if susp else ""),
                "high" if susp else "medium", count=len(ext),
                evidence={"new_extensions": sorted(uniq_ext)[:10], "known_ransomware": len(susp)},
                sample_paths=[e[1] for e in ext[:10]])))

        repl = self.replacements.items(now)
        if len(repl) >= s.replacement_threshold:
            out.append(self._maybe(BehaviorSignal(
                "file_replacement",
                f"{len(repl)} document files replaced with a different extension",
                "medium", count=len(repl), sample_paths=[r[1] for r in repl[:10]])))

        rewritten = [p for p, dq in self._rewrite_counts.items() if len(dq) >= s.rewrite_count_per_file]
        if len(rewritten) >= s.rewrite_files_threshold:
            out.append(self._maybe(BehaviorSignal(
                "repeated_rewrites",
                f"{len(rewritten)} files rewritten >= {s.rewrite_count_per_file} times rapidly",
                "low", count=len(rewritten), sample_paths=rewritten[:10])))

        notes = self.notes.items(now)
        if len(notes) >= s.ransom_note_threshold:
            out.append(self._maybe(BehaviorSignal(
                "ransom_note",
                f"{len(notes)} probable ransom-note file(s) created",
                "high", count=len(notes), sample_paths=notes[:10],
                directories=sorted({os.path.dirname(p) for p in notes})[:10])))
        return out

    def _maybe(self, signal: BehaviorSignal) -> BehaviorSignal | None:
        """Apply per-type cooldown so one burst does not emit the same signal repeatedly."""
        now = time.monotonic()
        last = self._last_emit.get(signal.signal_type, 0.0)
        if now - last < self.s.signal_cooldown_seconds:
            return None
        self._last_emit[signal.signal_type] = now
        return signal

    def prune(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        for w in (self.mods, self.deletes, self.renames, self.ext_changes, self.replacements, self.notes):
            w._trim(now)
        cutoff = now - self.s.window_seconds
        for path in list(self._rewrite_counts):
            dq = self._rewrite_counts[path]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del self._rewrite_counts[path]

    def stats(self, now: float | None = None) -> dict:
        now = time.monotonic() if now is None else now
        return {
            "window_modifications": len(self.mods.items(now)),
            "window_deletions": len(self.deletes.items(now)),
            "window_renames": len(self.renames.items(now)),
            "signals_emitted": self.signals_emitted,
            "baseline": self.baseline.snapshot(),
        }
