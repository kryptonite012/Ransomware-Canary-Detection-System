"""Shannon entropy analysis with file-type awareness.

Why entropy is not enough on its own
------------------------------------
Encrypted data has ~8 bits/byte of entropy, but so does a ZIP, a JPEG or an
MP4.  A naive "entropy > 7.5 ⇒ ransomware" rule fires constantly on a normal
machine.  SENTINEL reduces false positives by combining three signals:

* **Category baseline** - a ``.zip`` is *expected* to be high entropy, so high
  entropy there is unremarkable; high entropy in a ``.txt`` or ``.csv`` is not.
* **Delta from history** - a file that *was* structured (low/medium entropy)
  and suddenly becomes near-random is the classic encryption signature.
* **Magic / structure check** - encryption destroys the header.  A ``.docx``
  that no longer starts with ``PK`` or a ``.pdf`` without ``%PDF`` is suspect
  regardless of the exact entropy value.

Chunked analysis catches partial-file / intermittent encryption where only the
first N bytes of each file are encrypted.
"""
from __future__ import annotations

import logging
import math
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

import numpy as np

from agent.entropy.filetypes import FileCategory, category_for, check_magic, looks_like_text

log = logging.getLogger("sentinel.entropy")

_LOG2 = math.log(2)


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string in bits/byte (0..8)."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    total = counts.sum()
    probs = counts[counts > 0] / total
    return float(-np.sum(probs * (np.log(probs) / _LOG2)))


@dataclass(slots=True)
class EntropyResult:
    path: str
    entropy: float
    max_chunk_entropy: float
    category: str
    magic_ok: bool | None
    size: int
    previous_entropy: float | None = None
    delta: float | None = None
    suspicious: bool = False
    reason: str | None = None

    def to_history_row(self) -> dict:
        return {
            "file_path": self.path[:2048],
            "file_category": self.category,
            "previous_entropy": self.previous_entropy,
            "current_entropy": round(self.entropy, 4),
            "entropy_delta": round(self.delta, 4) if self.delta is not None else None,
            "max_chunk_entropy": round(self.max_chunk_entropy, 4),
            "magic_ok": self.magic_ok,
            "suspicious": self.suspicious,
            "reason": self.reason,
        }


class _Cache:
    """LRU cache of (mtime, size) -> entropy, so unchanged files are not re-read."""

    def __init__(self, maxsize: int):
        self.maxsize = maxsize
        self._d: OrderedDict[str, tuple[float, int, float, bool | None]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, path: str, mtime: float, size: int) -> tuple[float, bool | None] | None:
        with self._lock:
            entry = self._d.get(path)
            if entry and entry[0] == mtime and entry[1] == size:
                self._d.move_to_end(path)
                return entry[2], entry[3]
            return None

    def put(self, path: str, mtime: float, size: int, entropy: float, magic_ok: bool | None) -> None:
        with self._lock:
            self._d[path] = (mtime, size, entropy, magic_ok)
            self._d.move_to_end(path)
            while len(self._d) > self.maxsize:
                self._d.popitem(last=False)

    def previous(self, path: str) -> float | None:
        with self._lock:
            entry = self._d.get(path)
            return entry[2] if entry else None

    def seed(self, path: str, entropy: float | None, magic_ok: bool | None = None) -> None:
        if entropy is None:
            return
        with self._lock:
            if path not in self._d:
                self._d[path] = (-1.0, -1, entropy, magic_ok)

    def __len__(self) -> int:
        return len(self._d)


class EntropyAnalyzer:
    def __init__(self, settings):
        self.s = settings
        self.cache = _Cache(settings.cache_size)
        self.analyses = 0
        self.cache_hits = 0
        self.errors = 0

    def seed_baseline(self, path: str, entropy: float | None, magic_ok: bool | None = None) -> None:
        self.cache.seed(path, entropy, magic_ok)

    def _read_header(self, path: str) -> bytes:
        try:
            with open(path, "rb") as fh:
                return fh.read(64)
        except OSError:
            return b""

    def analyze(self, path: str, known_prev: float | None = None) -> EntropyResult | None:
        s = self.s
        try:
            st = os.stat(path)
        except OSError:
            return None
        size = st.st_size
        if size < s.min_file_size:
            return None
        category = category_for(path)

        cached = self.cache.get(path, st.st_mtime, size)
        if cached is not None:
            self.cache_hits += 1
            return None  # unchanged since last analysis

        prev = known_prev if known_prev is not None else self.cache.previous(path)
        try:
            entropy, max_chunk, header = self._compute(path, size)
        except OSError:
            self.errors += 1
            return None
        self.analyses += 1
        magic_ok = check_magic(path, header)

        result = EntropyResult(
            path=path, entropy=entropy, max_chunk_entropy=max_chunk, category=category.name,
            magic_ok=magic_ok, size=size, previous_entropy=prev,
            delta=(entropy - prev) if prev is not None else None,
        )
        self._classify(result, category, header)
        self.cache.put(path, st.st_mtime, size, entropy, magic_ok)
        return result

    def _compute(self, path: str, size: int) -> tuple[float, float, bytes]:
        s = self.s
        with open(path, "rb") as fh:
            header = fh.read(64)
            fh.seek(0)
            if size <= s.full_read_max_bytes:
                data = fh.read()
                overall = shannon_entropy(data)
                max_chunk = overall
                if size > s.chunk_size:
                    max_chunk = max(
                        shannon_entropy(data[i: i + s.chunk_size])
                        for i in range(0, len(data), s.chunk_size)
                    )
                return overall, max_chunk, header
            # Large file: sample evenly spaced chunks.
            positions = np.linspace(0, size - s.chunk_size, s.sample_chunks, dtype=np.int64)
            chunks: list[float] = []
            combined = bytearray()
            for pos in positions:
                fh.seek(int(pos))
                chunk = fh.read(s.chunk_size)
                if chunk:
                    chunks.append(shannon_entropy(chunk))
                    if len(combined) < s.chunk_size * 2:
                        combined.extend(chunk[: s.chunk_size])
            overall = shannon_entropy(bytes(combined)) if combined else (chunks[0] if chunks else 0.0)
            return overall, (max(chunks) if chunks else overall), header

    def _classify(self, r: EntropyResult, category: FileCategory, header: bytes) -> None:
        s = self.s
        reasons: list[str] = []
        # 1. Structure destroyed: strongest single-file signal.
        if r.magic_ok is False:
            reasons.append(f"{r.category} file no longer matches its expected header")

        high = r.max_chunk_entropy >= s.high_entropy_threshold
        if category.text_like:
            text_now = looks_like_text(header)
            if r.entropy >= s.text_high_entropy_threshold and not text_now:
                reasons.append(
                    f"{r.category} file is no longer textual (entropy {r.entropy:.2f})"
                )
        elif high and not category.expected_high_entropy:
            reasons.append(
                f"high entropy {r.max_chunk_entropy:.2f} in {r.category} file (not normally compressed)"
            )

        # 2. Sudden transformation: was structured, now near-random.
        if r.delta is not None and r.delta >= s.min_entropy_delta and r.max_chunk_entropy >= s.high_entropy_threshold:
            if r.previous_entropy is not None and r.previous_entropy < s.high_entropy_threshold:
                reasons.append(
                    f"entropy rose {r.delta:.2f} (from {r.previous_entropy:.2f} to {r.entropy:.2f})"
                )

        if reasons:
            # For expected-high-entropy types (zip/jpeg/...), only a destroyed
            # header or a genuine transformation counts; steady-state high
            # entropy is normal and must not alert.
            if category.expected_high_entropy and r.magic_ok is not False and (
                r.delta is None or r.previous_entropy is None or r.previous_entropy >= s.high_entropy_threshold
            ):
                return
            r.suspicious = True
            r.reason = "; ".join(reasons)

    def stats(self) -> dict:
        return {
            "analyses": self.analyses,
            "cache_hits": self.cache_hits,
            "cache_size": len(self.cache),
            "errors": self.errors,
        }


class RateLimiter:
    """Simple token-bucket rate limiter for entropy analysis."""

    def __init__(self, rate_per_second: int):
        self.rate = max(1, rate_per_second)
        self.capacity = self.rate
        self.tokens = float(self.rate)
        self.updated = time.monotonic()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
            self.updated = now
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False
