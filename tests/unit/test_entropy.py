import os
import secrets

import pytest

from agent.core.config import EntropySettings
from agent.entropy.analyzer import EntropyAnalyzer, RateLimiter, shannon_entropy
from agent.entropy.filetypes import category_for, check_magic, looks_like_text


def test_shannon_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) == 0.0
    assert shannon_entropy(bytes(range(256)) * 10) == pytest.approx(8.0, abs=1e-6)
    assert 0 < shannon_entropy(b"hello world the quick brown fox") < 5.5
    assert shannon_entropy(secrets.token_bytes(65536)) > 7.9


def test_filetype_category_and_magic():
    assert category_for("a.zip").expected_high_entropy
    assert not category_for("a.txt").expected_high_entropy
    assert category_for("a.txt").text_like
    assert check_magic("a.pdf", b"%PDF-1.7 rest") is True
    assert check_magic("a.pdf", b"ENCRYPTED!!!") is False
    assert check_magic("a.unknownext", b"xxxx") is None
    assert check_magic("a.docx", b"PK\x03\x04rest") is True


def test_looks_like_text():
    assert looks_like_text(b"plain ascii text\nwith newlines\t")
    assert not looks_like_text(secrets.token_bytes(64))
    assert looks_like_text("café résumé".encode("utf-8"))


def _settings(**kw):
    return EntropySettings(**kw)


def test_detects_text_file_encrypted(tmp_path):
    a = EntropyAnalyzer(_settings())
    f = tmp_path / "notes.txt"
    f.write_text("meeting notes " * 500)
    r1 = a.analyze(str(f))
    assert r1 is not None and not r1.suspicious
    # unchanged file -> cache hit, no re-analysis
    assert a.analyze(str(f)) is None
    f.write_bytes(secrets.token_bytes(20000))
    os.utime(str(f), (f.stat().st_atime, f.stat().st_mtime + 10))
    r2 = a.analyze(str(f))
    assert r2 is not None and r2.suspicious
    assert r2.delta and r2.delta > 1.0


def test_high_entropy_zip_not_flagged(tmp_path):
    a = EntropyAnalyzer(_settings())
    f = tmp_path / "archive.zip"
    f.write_bytes(b"PK\x03\x04" + secrets.token_bytes(40000))
    r = a.analyze(str(f))
    assert r is not None and not r.suspicious  # expected-high-entropy + valid header


def test_magic_mismatch_flags_even_when_entropy_plausible(tmp_path):
    a = EntropyAnalyzer(_settings())
    f = tmp_path / "report.pdf"
    f.write_bytes(secrets.token_bytes(30000))  # no %PDF header
    r = a.analyze(str(f))
    assert r is not None and r.suspicious
    assert r.magic_ok is False
    assert "header" in r.reason


def test_small_file_skipped(tmp_path):
    a = EntropyAnalyzer(_settings(min_file_size=1024))
    f = tmp_path / "x.txt"
    f.write_bytes(b"tiny")
    assert a.analyze(str(f)) is None


def test_seed_baseline_enables_delta_after_restart(tmp_path):
    a = EntropyAnalyzer(_settings())
    f = tmp_path / "data.csv"
    f.write_bytes(secrets.token_bytes(20000))
    a.seed_baseline(str(f), 2.0)
    r = a.analyze(str(f))
    assert r is not None and r.previous_entropy == 2.0 and r.suspicious


def test_large_file_chunked(tmp_path):
    a = EntropyAnalyzer(_settings(full_read_max_bytes=4096, chunk_size=1024, sample_chunks=4))
    f = tmp_path / "big.bin"
    f.write_bytes(b"A" * 5000 + secrets.token_bytes(5000))
    r = a.analyze(str(f))
    assert r is not None and r.max_chunk_entropy > r.entropy - 2  # captured a high-entropy region


def test_rate_limiter():
    rl = RateLimiter(5)
    allowed = sum(rl.allow() for _ in range(20))
    assert allowed == 5
