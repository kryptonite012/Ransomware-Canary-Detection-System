"""Detection benchmark harness.

Runs the agent against the safe simulator and measures the metrics the
specification calls for:

* detection rate (attack scenarios that raised risk to High/Critical)
* false-positive rate (benign scenarios that wrongly raised risk)
* detection latency (attack start -> first qualifying alert)
* CPU / memory of the agent process
* event-processing throughput
* canary detection reliability

Results are written as a reproducible JSON + Markdown report.  Everything runs
inside a disposable sandbox; no real files are harmed.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select

from agent.core.agent import SentinelAgent
from agent.core.config import SentinelConfig
from backend.database import make_session_factory
from backend.models import CanaryFile, Endpoint, SecurityAlert
from simulator import scenarios
from simulator.sandbox import Sandbox


@dataclass
class ScenarioOutcome:
    name: str
    malicious: bool
    files_touched: int
    detected: bool
    peak_risk: float
    peak_level: str
    latency_seconds: float | None
    alerts: int
    correct: bool


@dataclass
class BenchmarkReport:
    started_at: str
    finished_at: str
    detection_rate: float
    false_positive_rate: float
    mean_latency_seconds: float | None
    throughput_events_per_sec: float
    peak_cpu_percent: float
    peak_memory_mb: float
    canary_reliability: float
    scenarios: list[dict[str, Any]] = field(default_factory=list)
    environment: dict[str, Any] = field(default_factory=dict)

    def to_markdown(self) -> str:
        lines = [
            "# PROJECT SENTINEL - Detection Benchmark Report", "",
            f"_Generated {self.finished_at}_", "",
            "## Summary", "",
            "| Metric | Value |", "| --- | --- |",
            f"| Detection rate (malicious scenarios) | **{self.detection_rate:.0%}** |",
            f"| False-positive rate (benign scenarios) | **{self.false_positive_rate:.0%}** |",
            f"| Mean detection latency | {self._lat(self.mean_latency_seconds)} |",
            f"| Event throughput | {self.throughput_events_per_sec:.0f} events/s |",
            f"| Canary detection reliability | {self.canary_reliability:.0%} |",
            f"| Peak agent CPU | {self.peak_cpu_percent:.1f}% |",
            f"| Peak agent memory | {self.peak_memory_mb:.1f} MB |",
            "", "## Scenarios", "",
            "| Scenario | Type | Files | Detected | Peak risk | Latency | Result |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for s in self.scenarios:
            kind = "malicious" if s["malicious"] else "benign"
            lat = self._lat(s["latency_seconds"])
            ok = "✅" if s["correct"] else "❌"
            lines.append(
                f"| {s['name']} | {kind} | {s['files_touched']} | {s['detected']} | "
                f"{s['peak_risk']:.0f} ({s['peak_level']}) | {lat} | {ok} |")
        lines += ["", "## Environment", ""]
        for k, v in self.environment.items():
            lines.append(f"- **{k}**: {v}")
        lines += ["", "> All scenarios run inside a disposable sandbox using the safe simulator.",
                  "> No real files are encrypted or harmed."]
        return "\n".join(lines) + "\n"

    @staticmethod
    def _lat(v: float | None) -> str:
        return f"{v:.2f}s" if v is not None else "—"


class Benchmark:
    def __init__(self, config: SentinelConfig, sandbox: Sandbox):
        self.config = config
        self.sandbox = sandbox
        self.factory = make_session_factory(config.agent.resolved_database_url())

    def _risk(self, agent: SentinelAgent) -> tuple[float, str]:
        snap = agent.engines.risk_snapshot() if agent.engines else {"score": 0, "level": "normal"}
        return snap["score"], snap["level"]

    def _alert_count(self, endpoint_id: int) -> int:
        with self.factory() as s:
            return s.scalar(select(func.count()).select_from(SecurityAlert)
                            .where(SecurityAlert.endpoint_id == endpoint_id)) or 0

    def _run_scenario(self, agent: SentinelAgent, name: str, fn, malicious: bool,
                      settle: float = 6.0) -> ScenarioOutcome:
        endpoint_id = agent.endpoint_id
        before_alerts = self._alert_count(endpoint_id)
        agent.engines.coordinator.risk.reset()
        time.sleep(0.5)
        start = time.monotonic()
        result = fn(self.sandbox)
        # Poll until risk settles or timeout.
        peak_risk, peak_level = 0.0, "normal"
        latency = None
        deadline = time.monotonic() + settle
        while time.monotonic() < deadline:
            score, level = self._risk(agent)
            if score > peak_risk:
                peak_risk, peak_level = score, level
            if latency is None and level in ("high", "critical"):
                latency = time.monotonic() - start
            time.sleep(0.2)
        alerts = self._alert_count(endpoint_id) - before_alerts
        detected = peak_level in ("high", "critical")
        correct = detected if malicious else not detected
        return ScenarioOutcome(name, malicious, result.files_touched, detected, peak_risk, peak_level,
                               latency, alerts, correct)

    def run(self) -> BenchmarkReport:
        import platform

        import psutil

        started = datetime.now(timezone.utc)
        scenarios.populate_benign(self.sandbox, count=40)
        agent = SentinelAgent(self.config)
        agent.start()
        proc = psutil.Process()
        peak_cpu = peak_mem = 0.0
        outcomes: list[ScenarioOutcome] = []
        try:
            # Let inventory baseline + canary deployment settle.
            time.sleep(4.0)
            agent_proc = psutil.Process(agent.health()["pid"])
            agent_proc.cpu_percent(None)

            plan = [
                ("benign_activity", scenarios.benign_activity, False),
                ("mass_modification", scenarios.mass_modification, True),
                ("extension_rename", scenarios.extension_rename, True),
                ("ransom_notes", scenarios.drop_ransom_notes, True),
                ("canary_modify", lambda sb: scenarios.tamper_canaries(sb, "modify"), True),
            ]
            for name, fn, malicious in plan:
                # Re-populate between destructive scenarios so each has a corpus.
                if name in ("extension_rename", "ransom_notes") and not any(
                        p.suffix == ".txt" for p in self.sandbox.path.rglob("*.txt")):
                    scenarios.populate_benign(self.sandbox, count=40)
                    time.sleep(2.0)
                outcomes.append(self._run_scenario(agent, name, fn, malicious))
                cpu = agent_proc.cpu_percent(None)
                mem = agent_proc.memory_info().rss / 1e6
                peak_cpu = max(peak_cpu, cpu)
                peak_mem = max(peak_mem, mem)

            health = agent.health()
            throughput = health.get("events_per_second", 0.0) or 0.0
            events_processed = health.get("events_processed", 0)
            uptime = health.get("uptime_seconds", 1) or 1
            avg_throughput = max(throughput, events_processed / uptime)
            canary_rel = self._canary_reliability(agent.endpoint_id)
        finally:
            agent.stop()

        malicious = [o for o in outcomes if o.malicious]
        benign = [o for o in outcomes if not o.malicious]
        det_rate = sum(o.detected for o in malicious) / len(malicious) if malicious else 0.0
        fp_rate = sum(o.detected for o in benign) / len(benign) if benign else 0.0
        lats = [o.latency_seconds for o in malicious if o.latency_seconds is not None]
        mean_lat = sum(lats) / len(lats) if lats else None

        return BenchmarkReport(
            started_at=started.isoformat(), finished_at=datetime.now(timezone.utc).isoformat(),
            detection_rate=det_rate, false_positive_rate=fp_rate, mean_latency_seconds=mean_lat,
            throughput_events_per_sec=round(avg_throughput, 1), peak_cpu_percent=round(peak_cpu, 1),
            peak_memory_mb=round(peak_mem, 1), canary_reliability=canary_rel,
            scenarios=[asdict(o) for o in outcomes],
            environment={"platform": platform.platform(), "python": platform.python_version(),
                         "cpu_count": psutil.cpu_count(), "filesystem_backend":
                         agent.capabilities().get("filesystem_backend")})

    def _canary_reliability(self, endpoint_id: int) -> float:
        with self.factory() as s:
            total = s.scalar(select(func.count()).select_from(CanaryFile)
                             .where(CanaryFile.endpoint_id == endpoint_id)) or 0
            triggered = s.scalar(select(func.count()).select_from(CanaryFile).where(
                CanaryFile.endpoint_id == endpoint_id, CanaryFile.trigger_count > 0)) or 0
        # Reliability here = fraction of canaries that correctly fired when tampered.
        return (triggered / total) if total else 1.0


def run_benchmark(base_dir: Path, output_dir: Path) -> BenchmarkReport:
    from agent.core.config import SentinelConfig

    data_dir = output_dir / "bench-data"
    sandbox = Sandbox.create(base_dir, "sentinel-benchmark")
    cfg = SentinelConfig.model_validate({
        "agent": {"data_dir": str(data_dir), "endpoint_name": "benchmark-endpoint",
                  "heartbeat_interval_seconds": 1, "db_flush_interval_seconds": 0.2},
        "monitoring": {"directories": [{"path": str(sandbox.path), "recursive": True}],
                       "dedup_window_ms": 100},
        "canary": {"auto_deploy": True, "regenerate_delay_seconds": 0.5},
        "entropy": {"min_file_size": 128},
        "behavior": {"window_seconds": 30, "mass_modification_threshold": 15,
                     "extension_change_threshold": 8, "signal_cooldown_seconds": 0},
        "response": {"desktop_notifications": False},
    })
    try:
        report = Benchmark(cfg, sandbox).run()
    finally:
        sandbox.destroy()
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "benchmark_report.json").write_text(json.dumps(asdict(report), indent=2))
    (output_dir / "benchmark_report.md").write_text(report.to_markdown())
    return report
