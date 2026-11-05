import os

import pytest
from pydantic import ValidationError

from agent.core.config import SentinelConfig, risk_level_for
from agent.core.signing import (
    HmacSigner, Signer, Verifier, command_payload, directory_payload, generate_keypair, policy_payload,
)
from agent.filesystem.exclusions import ExclusionRules, SelfWriteGuard, is_within


def test_exclusion_patterns_and_directories(tmp_path):
    rules = ExclusionRules(["*.tmp", "~$*", "*/node_modules/*"], [str(tmp_path / "data")])
    assert rules.is_excluded(str(tmp_path / "a.tmp"))
    assert rules.is_excluded(str(tmp_path / "~$report.docx"))
    assert rules.is_excluded(str(tmp_path / "proj" / "node_modules" / "x.js"))
    assert rules.is_excluded(str(tmp_path / "data" / "sentinel.db"))
    assert rules.is_excluded(str(tmp_path / "data"))
    assert not rules.is_excluded(str(tmp_path / "datafile.txt"))  # prefix but not a child
    assert not rules.is_excluded(str(tmp_path / "report.docx"))


def test_self_write_guard_expires():
    g = SelfWriteGuard(ttl_seconds=0.05)
    g.register("/x/y")
    assert g.is_self_write("/x/y")
    import time
    time.sleep(0.08)
    assert not g.is_self_write("/x/y")


def test_is_within(tmp_path):
    assert is_within(str(tmp_path / "a" / "b"), str(tmp_path))
    assert not is_within(str(tmp_path) + "-other", str(tmp_path))


def test_config_defaults_and_validation():
    cfg = SentinelConfig()
    assert cfg.risk.weights["canary_modified"] == 50
    assert len(cfg.canary.names) == 5
    with pytest.raises(ValidationError):
        SentinelConfig.model_validate({"risk": {"level_thresholds": {"low": 50, "elevated": 40, "high": 60,
                                                                     "critical": 80}}})
    with pytest.raises(ValidationError):
        SentinelConfig.model_validate({"canary": {"names": ["../escape.txt"]}})
    with pytest.raises(ValidationError):
        SentinelConfig.model_validate({"agent": {"unknown_key": 1}})


def test_policy_override_merges_and_rejects_bootstrap_sections():
    cfg = SentinelConfig()
    new = cfg.with_policy({"entropy": {"high_entropy_threshold": 7.5}})
    assert new.entropy.high_entropy_threshold == 7.5
    assert new.entropy.min_file_size == cfg.entropy.min_file_size
    with pytest.raises(ValueError):
        cfg.with_policy({"agent": {"database_url": "sqlite:///evil.db"}})


def test_risk_levels():
    t = {"low": 20, "elevated": 40, "high": 60, "critical": 80}
    assert risk_level_for(0, t) == "normal"
    assert risk_level_for(19.9, t) == "normal"
    assert risk_level_for(20, t) == "low"
    assert risk_level_for(59, t) == "elevated"
    assert risk_level_for(60, t) == "high"
    assert risk_level_for(100, t) == "critical"


def test_ed25519_sign_verify_and_tamper(tmp_path):
    priv, pub = tmp_path / "k.key", tmp_path / "k.pub"
    generate_keypair(priv, pub)
    assert oct(os.stat(priv).st_mode & 0o777) == "0o600"
    signer, verifier = Signer.from_file(priv), Verifier.from_file(pub)
    payload = directory_payload(1, "/home/u/Documents", True, True)
    sig = signer.sign(payload)
    assert verifier.verify(payload, sig)
    tampered = directory_payload(1, "/", True, True)
    assert not verifier.verify(tampered, sig)
    assert not verifier.verify(payload, None)
    assert not verifier.verify(payload, "not-base64!!")
    cmd = command_payload(5, 1, "ping", {})
    assert verifier.verify(cmd, signer.sign(cmd))
    pol = policy_payload(3, {"entropy": {}})
    assert verifier.verify(pol, signer.sign(pol))
    with pytest.raises(FileExistsError):
        generate_keypair(priv, pub)


def test_hmac_signer():
    h = HmacSigner(b"k" * 32)
    sig = h.sign({"a": 1})
    assert h.verify({"a": 1}, sig)
    assert not h.verify({"a": 2}, sig)
    with pytest.raises(ValueError):
        HmacSigner(b"short")
