from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.core.config import SentinelConfig  # noqa: E402
from agent.core.signing import generate_keypair  # noqa: E402


def wait_for(predicate, timeout: float = 10.0, interval: float = 0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(interval)
    return predicate()


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    return d


@pytest.fixture
def watched_dir(tmp_path: Path) -> Path:
    d = tmp_path / "watched"
    d.mkdir()
    return d


@pytest.fixture
def keypair(data_dir: Path) -> tuple[Path, Path]:
    priv = data_dir / "secrets" / "control_plane_ed25519.key"
    pub = data_dir / "secrets" / "control_plane_ed25519.pub"
    generate_keypair(priv, pub)
    return priv, pub


def make_config(data_dir: Path, watched: list[Path] | None = None, **overrides) -> SentinelConfig:
    raw = {
        "agent": {
            "data_dir": str(data_dir),
            "endpoint_name": f"test-{os.getpid()}-{time.monotonic_ns()}",
            "heartbeat_interval_seconds": 1,
            "command_poll_interval_seconds": 0.5,
            "config_poll_interval_seconds": 1,
            "db_flush_interval_seconds": 0.2,
            "queue_size": 10000,
        },
        "monitoring": {
            "directories": [{"path": str(p), "recursive": True} for p in (watched or [])],
            "dedup_window_ms": 200,
        },
    }
    for section, values in overrides.items():
        raw.setdefault(section, {}).update(values)
    return SentinelConfig.model_validate(raw)


@pytest.fixture
def config_factory(data_dir):
    def factory(watched=None, **overrides):
        return make_config(data_dir, watched, **overrides)
    return factory
