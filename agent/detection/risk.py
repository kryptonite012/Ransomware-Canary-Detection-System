"""Risk scoring engine.

Independent detection signals (canary triggers, entropy spikes, behavioural
bursts, suspicious processes, integrity findings) are fused into a single
0-100 ransomware risk score.

Design requirements from the specification:

* **No double counting** - the same logical signal arriving repeatedly must not
  inflate the score without bound.  Each active signal contributes its base
  weight once; repeats add a small, capped increment.
* **Correlation confidence** - several *different* signal types being active at
  once is far more indicative than any one alone, so a correlation bonus is
  added when >= 2 distinct types are live.
* **Decay** - signals expire after a TTL so the score falls back to normal once
  activity stops (ransomware that is contained should not leave the endpoint
  pinned at "critical" forever).
* **Explainability** - every score carries the list of contributing signals and
  how many points each added.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from agent.core.config import RiskSettings, risk_level_for


@dataclass
class _ActiveSignal:
    signal_type: str
    base_weight: int
    first_seen: float
    last_seen: float
    count: int
    description: str
    severity_hint: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def contribution(self, settings: RiskSettings) -> float:
        extra = min(
            self.base_weight * settings.repeat_max_ratio,
            self.base_weight * settings.repeat_increment_ratio * (self.count - 1),
        )
        return float(self.base_weight) + extra


@dataclass
class RiskUpdate:
    score: float
    level: str
    changed_level: bool
    previous_level: str
    contributions: list[dict[str, Any]]
    correlation_bonus: float
    triggering_signal: str
    new_signal: bool


class RiskEngine:
    def __init__(self, settings: RiskSettings):
        self.s = settings
        self._signals: dict[str, _ActiveSignal] = {}
        self._lock = threading.Lock()
        self._score = 0.0
        self._level = "normal"
        self.peak_score = 0.0
        self.peak_level = "normal"

    def update_settings(self, settings: RiskSettings) -> None:
        with self._lock:
            self.s = settings

    def add_signal(self, signal_type: str, description: str, severity_hint: str = "medium",
                   evidence: dict[str, Any] | None = None, now: float | None = None) -> RiskUpdate:
        now = time.monotonic() if now is None else now
        weight = self.s.weights.get(signal_type, 10)
        with self._lock:
            self._expire(now)
            existing = self._signals.get(signal_type)
            if existing is None:
                self._signals[signal_type] = _ActiveSignal(
                    signal_type, weight, now, now, 1, description, severity_hint, evidence or {})
                new_signal = True
            else:
                existing.last_seen = now
                existing.count += 1
                existing.description = description
                existing.base_weight = weight
                if evidence:
                    existing.evidence = evidence
                new_signal = False
            return self._recompute(signal_type, new_signal, now)

    def _expire(self, now: float) -> None:
        ttl = self.s.signal_ttl_seconds
        for key in [k for k, v in self._signals.items() if now - v.last_seen > ttl]:
            del self._signals[key]

    def _recompute(self, triggering: str, new_signal: bool, now: float) -> RiskUpdate:
        contributions: list[dict[str, Any]] = []
        total = 0.0
        for sig in sorted(self._signals.values(), key=lambda s: s.base_weight, reverse=True):
            pts = sig.contribution(self.s)
            total += pts
            contributions.append({
                "signal_type": sig.signal_type, "points": round(pts, 1), "base_weight": sig.base_weight,
                "count": sig.count, "description": sig.description, "severity_hint": sig.severity_hint,
                "age_seconds": round(now - sig.first_seen, 1), "evidence": sig.evidence,
            })
        distinct = len(self._signals)
        bonus = 0.0
        for n, b in sorted(self.s.correlation_bonus.items()):
            if distinct >= int(n):
                bonus = float(b)
        total += bonus
        score = max(0.0, min(100.0, total))
        prev_level = self._level
        level = risk_level_for(score, self.s.level_thresholds)
        self._score, self._level = score, level
        if score > self.peak_score:
            self.peak_score, self.peak_level = score, level
        return RiskUpdate(
            score=round(score, 1), level=level, changed_level=level != prev_level, previous_level=prev_level,
            contributions=contributions, correlation_bonus=bonus, triggering_signal=triggering,
            new_signal=new_signal)

    def decay(self, now: float | None = None) -> RiskUpdate | None:
        now = time.monotonic() if now is None else now
        with self._lock:
            before = len(self._signals)
            self._expire(now)
            if len(self._signals) == before and self._signals:
                return None
            return self._recompute("decay", False, now)

    def snapshot(self, now: float | None = None) -> dict[str, Any]:
        now = time.monotonic() if now is None else now
        with self._lock:
            self._expire(now)
            update = self._recompute("snapshot", False, now)
            return {
                "score": update.score,
                "level": update.level,
                "peak_score": round(self.peak_score, 1),
                "peak_level": self.peak_level,
                "active_signals": update.contributions,
                "correlation_bonus": update.correlation_bonus,
                "distinct_signals": len(self._signals),
            }

    def reset(self) -> None:
        with self._lock:
            self._signals.clear()
            self._score = 0.0
            self._level = "normal"

    @property
    def score(self) -> float:
        return self._score

    @property
    def level(self) -> str:
        return self._level
