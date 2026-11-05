from agent.behavior.detectors import BehaviorEngine, AdaptiveBaseline
from agent.core.config import BehaviorSettings, RiskSettings
from agent.core.events import EventType, FileEvent
from agent.detection.risk import RiskEngine


def _bev(**kw):
    base = dict(window_seconds=10, mass_modification_threshold=10, mass_deletion_threshold=5,
                extension_change_threshold=3, directory_spread_threshold=3, replacement_threshold=3,
                signal_cooldown_seconds=0)
    base.update(kw)
    return BehaviorEngine(BehaviorSettings(**base))


def test_rapid_mass_modification():
    be = _bev()
    sigs = []
    for i in range(12):
        sigs += be.observe(FileEvent(EventType.MODIFIED, f"/docs/f{i}.doc"), now=100 + i * 0.1)
    types = {s.signal_type for s in sigs}
    assert "rapid_mass_modification" in types
    mm = next(s for s in sigs if s.signal_type == "rapid_mass_modification")
    assert mm.count >= 10 and mm.sample_paths


def test_directory_spread():
    be = _bev(mass_modification_threshold=6, directory_spread_threshold=3)
    sigs = []
    for i in range(8):
        sigs += be.observe(FileEvent(EventType.MODIFIED, f"/d{i % 4}/f{i}.doc"), now=100 + i * 0.1)
    assert any(s.signal_type == "directory_spread" for s in sigs)


def test_mass_deletion():
    be = _bev()
    sigs = []
    for i in range(6):
        sigs += be.observe(FileEvent(EventType.DELETED, f"/docs/f{i}.doc"), now=50 + i * 0.1)
    assert any(s.signal_type == "mass_deletion" for s in sigs)


def test_suspicious_extension_change():
    be = _bev()
    sigs = []
    for i in range(4):
        sigs += be.observe(FileEvent(EventType.MOVED, f"/d/f{i}.docx", dest_path=f"/d/f{i}.docx.locked"),
                           now=10 + i * 0.1)
    s = next(s for s in sigs if s.signal_type == "suspicious_extension_change")
    assert s.severity_hint == "high"  # .locked is a known ransomware extension
    assert s.evidence["known_ransomware"] >= 3


def test_ransom_note_detection():
    be = _bev(ransom_note_threshold=2, signal_cooldown_seconds=0)
    sigs = be.observe(FileEvent(EventType.CREATED, "/docs/README_DECRYPT.txt"), now=1)
    sigs += be.observe(FileEvent(EventType.CREATED, "/pics/HOW_TO_RECOVER.html"), now=2)
    assert any(s.signal_type == "ransom_note" for s in sigs)


def test_cooldown_prevents_duplicate_signals():
    be = _bev(signal_cooldown_seconds=60)
    first = []
    for i in range(12):
        first += be.observe(FileEvent(EventType.MODIFIED, f"/d/f{i}.doc"), now=1 + i * 0.01)
    second = []
    for i in range(12, 24):
        second += be.observe(FileEvent(EventType.MODIFIED, f"/d/f{i}.doc"), now=2 + i * 0.01)
    assert sum(s.signal_type == "rapid_mass_modification" for s in first) == 1
    assert sum(s.signal_type == "rapid_mass_modification" for s in second) == 0


def test_adaptive_baseline_learns_then_flags():
    b = AdaptiveBaseline(bucket_seconds=1.0, learning_buckets=5, sigma=3, min_events=5)
    t = 0.0
    # Drive 8 quiet buckets of ~2 events each (a bucket closes on the first
    # event after its interval elapses).
    for _ in range(8):
        b.observe(t)       # opens/accounts current bucket
        b.observe(t + 0.2)
        t += 1.01          # next observe will close this bucket
    assert b.ready
    # Now a sudden burst within a single bucket must be flagged as anomalous.
    anomaly_seen = False
    start = t
    for i in range(60):
        a, _, _ = b.observe(start + i * 0.001)
        anomaly_seen = anomaly_seen or a
    # close the busy bucket
    a, _, _ = b.observe(start + 2.0)
    assert anomaly_seen or a


def test_risk_no_double_counting_and_decay():
    r = RiskEngine(RiskSettings(signal_ttl_seconds=100))
    u1 = r.add_signal("entropy_spike", "x", now=0)
    assert u1.score == 15 and u1.new_signal
    u2 = r.add_signal("entropy_spike", "x", now=1)  # repeat: small capped increment
    assert u2.score > 15 and u2.score < 25 and not u2.new_signal
    # add a different signal -> correlation bonus kicks in at 2 distinct
    u3 = r.add_signal("rapid_mass_modification", "y", now=2)
    assert u3.correlation_bonus == 10
    assert u3.level in ("elevated", "high")
    # after TTL everything decays back to normal
    dec = r.decay(now=200)
    assert dec is not None and dec.score == 0 and dec.level == "normal"


def test_risk_canary_is_high_severity():
    r = RiskEngine(RiskSettings())
    u = r.add_signal("canary_modified", "canary touched", now=0)
    assert u.score == 50 and u.level == "elevated"
    u2 = r.add_signal("entropy_spike", "entropy", now=1)
    assert u2.level in ("high", "critical")


def test_risk_clamped_to_100():
    r = RiskEngine(RiskSettings())
    for st in ("canary_modified", "canary_deleted", "entropy_spike", "rapid_mass_modification",
               "mass_deletion", "suspicious_process", "ransom_note"):
        u = r.add_signal(st, st, now=0)
    assert u.score == 100 and u.level == "critical"


def test_risk_explainable_snapshot():
    r = RiskEngine(RiskSettings())
    r.add_signal("entropy_spike", "spike in notes.txt", evidence={"path": "/x"}, now=0)
    snap = r.snapshot(now=1)
    assert snap["active_signals"][0]["signal_type"] == "entropy_spike"
    assert snap["active_signals"][0]["evidence"]["path"] == "/x"
