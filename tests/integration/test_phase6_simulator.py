"""Phase 6: simulator safety + benchmark produces real metrics."""
from __future__ import annotations

import pytest

from simulator import scenarios
from simulator.sandbox import Sandbox, SandboxError

pytestmark = pytest.mark.integration


def test_sandbox_refuses_unmarked_directory(tmp_path):
    (tmp_path / "realdata").mkdir()
    with pytest.raises(SandboxError):
        Sandbox.attach(tmp_path / "realdata")


def test_sandbox_refuses_protected_locations(tmp_path, monkeypatch):
    with pytest.raises(SandboxError):
        Sandbox.create(tmp_path, name="..")  # escapes via resolve -> different dir
    import pathlib
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: tmp_path))
    # creating the home directory itself as a sandbox base child is fine, but the
    # home dir itself is forbidden:
    sb = Sandbox(tmp_path)
    with pytest.raises(SandboxError):
        sb._assert_owned()


def test_scenarios_stay_inside_sandbox(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("precious")
    sb = Sandbox.create(tmp_path / "sbx")
    scenarios.populate_benign(sb, count=10)
    scenarios.mass_modification(sb)
    scenarios.extension_rename(sb)
    scenarios.encrypt_and_replace(sb)
    # The file outside the sandbox is untouched.
    assert outside.read_text() == "precious"
    # Everything the simulator created is under the sandbox.
    for p in sb.path.rglob("*"):
        assert sb.path in p.resolve().parents or p.resolve() == sb.path


def test_benchmark_detects_attacks_and_not_benign(tmp_path):
    from simulator.benchmark import run_benchmark
    report = run_benchmark(tmp_path, tmp_path / "results")
    # Malicious scenarios should be detected; benign should not trip.
    assert report.detection_rate >= 0.75, f"detection too low: {report.detection_rate}"
    assert report.false_positive_rate <= 0.0 + 1e-9, f"false positives: {report.false_positive_rate}"
    assert (tmp_path / "results" / "benchmark_report.md").exists()
    assert (tmp_path / "results" / "benchmark_report.json").exists()
    # canary reliability should be high (tampered canaries fired)
    assert report.canary_reliability >= 0.5
