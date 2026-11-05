from agent.core.events import EventType, FileEvent
from agent.core.queue import BoundedEventQueue, Deduplicator


def test_deduplicator_suppresses_within_window():
    d = Deduplicator(window_seconds=0.5)
    key = ("modified", "/a", None)
    assert d.is_duplicate(key, now=100.0) is False
    assert d.is_duplicate(key, now=100.2) is True
    assert d.is_duplicate(key, now=100.6) is False  # window elapsed
    assert d.suppressed == 1


def test_deduplicator_distinguishes_keys():
    d = Deduplicator(window_seconds=1)
    assert not d.is_duplicate(("modified", "/a", None), now=1)
    assert not d.is_duplicate(("modified", "/b", None), now=1)
    assert not d.is_duplicate(("deleted", "/a", None), now=1)


def test_deduplicator_disabled():
    d = Deduplicator(window_seconds=0)
    assert not d.is_duplicate(("x",), now=1)
    assert not d.is_duplicate(("x",), now=1)


def test_deduplicator_bounded_memory():
    d = Deduplicator(window_seconds=100, max_keys=100)
    for i in range(1000):
        d.is_duplicate(("modified", f"/f{i}", None), now=1)
    assert len(d._seen) <= 101


def test_queue_coalesces_repeated_events():
    q = BoundedEventQueue(maxsize=100, dedup_window_seconds=1)
    for _ in range(10):
        q.put(FileEvent(EventType.MODIFIED, "/tmp/x"))
    assert q.qsize() == 1
    assert q.stats()["deduplicated"] == 9


def test_queue_backpressure_drops_without_blocking():
    q = BoundedEventQueue(maxsize=1000, dedup_window_seconds=0)
    for i in range(1500):
        q.put(FileEvent(EventType.CREATED, f"/tmp/{i}"))
    assert q.qsize() == 1000
    assert q.dropped == 500
    assert q.under_pressure


def test_get_batch():
    q = BoundedEventQueue(maxsize=1000, dedup_window_seconds=0)
    for i in range(30):
        q.put(FileEvent(EventType.CREATED, f"/tmp/{i}"))
    batch = q.get_batch(25, timeout=0.1)
    assert len(batch) == 25
    assert len(q.get_batch(25, timeout=0.1)) == 5
    assert q.get_batch(25, timeout=0.05) == []
