"""Safe ransomware-behaviour simulations.

Every scenario runs strictly inside a :class:`Sandbox`.  They reproduce the
*observable behaviour* of ransomware (rapid modification, extension changes,
high-entropy rewrites, canary tampering, mass deletion) without executing any
real malware and without ever touching data outside the sandbox.

These scenarios are what the test suite and benchmark harness use to measure
detection rate, false-positive rate and latency.
"""
from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

from simulator.sandbox import Sandbox

SUSPICIOUS_EXT = ".locked"


@dataclass
class ScenarioResult:
    name: str
    files_touched: int
    duration_seconds: float
    details: dict = field(default_factory=dict)


def _write(path: Path, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)


def populate_benign(sb: Sandbox, count: int = 40, subdirs: int = 3) -> int:
    """Create realistic, low-entropy documents to serve as the victim corpus."""
    created = 0
    for i in range(subdirs):
        d = sb.resolve_inside(f"dept_{i}")
        d.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        d = sb.resolve_inside(f"dept_{i % subdirs}")
        p = d / f"document_{i:03d}.txt"
        _write(p, (f"Quarterly report section {i}\n"
                   "This is ordinary business text with low entropy.\n" * 40).encode())
        created += 1
    # A couple of naturally high-entropy files (zip/jpg) to probe false positives.
    _write(sb.resolve_inside("archive.zip"), b"PK\x03\x04" + secrets.token_bytes(20000))
    _write(sb.resolve_inside("photo.jpg"), b"\xff\xd8\xff\xe0" + secrets.token_bytes(20000))
    return created + 2


def benign_activity(sb: Sandbox, edits: int = 15) -> ScenarioResult:
    """Ordinary user edits - must NOT raise risk (false-positive probe)."""
    start = time.time()
    n = 0
    for i in range(edits):
        p = sb.resolve_inside(f"dept_{i % 3}", f"document_{i:03d}.txt")
        if p.exists():
            with open(p, "a") as fh:
                fh.write(f"\nAppended note {i} during normal work.\n")
            n += 1
        time.sleep(0.05)
    return ScenarioResult("benign_activity", n, time.time() - start)


def mass_modification(sb: Sandbox, delay: float = 0.0) -> ScenarioResult:
    """Overwrite every document with high-entropy data (simulated encryption)."""
    start = time.time()
    n = 0
    for root, _dirs, files in os.walk(sb.path):
        for name in files:
            if name.endswith(".txt"):
                _write(Path(root) / name, secrets.token_bytes(4096))
                n += 1
                if delay:
                    time.sleep(delay)
    return ScenarioResult("mass_modification", n, time.time() - start)


def extension_rename(sb: Sandbox) -> ScenarioResult:
    """Rename documents to a ransomware-style extension."""
    start = time.time()
    n = 0
    for root, _dirs, files in os.walk(sb.path):
        for name in files:
            if name.endswith(".txt"):
                src = Path(root) / name
                src.rename(src.with_suffix(src.suffix + SUSPICIOUS_EXT))
                n += 1
    return ScenarioResult("extension_rename", n, time.time() - start)


def encrypt_and_replace(sb: Sandbox) -> ScenarioResult:
    """Classic pattern: write an encrypted copy, then delete the original."""
    start = time.time()
    n = 0
    for root, _dirs, files in os.walk(sb.path):
        for name in list(files):
            if name.endswith(".txt"):
                src = Path(root) / name
                enc = src.with_suffix(".txt.enc")
                _write(enc, secrets.token_bytes(4096))
                src.unlink()
                n += 1
    return ScenarioResult("encrypt_and_replace", n, time.time() - start)


def mass_deletion(sb: Sandbox) -> ScenarioResult:
    start = time.time()
    n = 0
    for root, _dirs, files in os.walk(sb.path):
        for name in list(files):
            if name.endswith((".txt", ".enc", SUSPICIOUS_EXT)):
                (Path(root) / name).unlink()
                n += 1
    return ScenarioResult("mass_deletion", n, time.time() - start)


def drop_ransom_notes(sb: Sandbox, count: int = 3) -> ScenarioResult:
    start = time.time()
    for i in range(count):
        p = sb.resolve_inside(f"dept_{i % 3}", "README_DECRYPT_YOUR_FILES.txt")
        _write(p, b"Your files have been encrypted (SIMULATION). This is a decoy ransom note.\n")
    return ScenarioResult("ransom_notes", count, time.time() - start)


def tamper_canaries(sb: Sandbox, interaction: str = "modify") -> ScenarioResult:
    """Interact with any canary files the agent deployed into the sandbox."""
    start = time.time()
    n = 0
    for root, _dirs, files in os.walk(sb.path):
        for name in files:
            if "Canary" in name:
                p = Path(root) / name
                if interaction == "delete":
                    p.unlink()
                elif interaction == "rename":
                    p.rename(p.with_suffix(p.suffix + SUSPICIOUS_EXT))
                else:
                    _write(p, secrets.token_bytes(2048))
                n += 1
    return ScenarioResult(f"canary_{interaction}", n, time.time() - start)


SCENARIOS = {
    "benign": benign_activity,
    "mass_modification": mass_modification,
    "extension_rename": extension_rename,
    "encrypt_and_replace": encrypt_and_replace,
    "mass_deletion": mass_deletion,
    "ransom_notes": drop_ransom_notes,
    "canary_modify": lambda sb: tamper_canaries(sb, "modify"),
    "canary_delete": lambda sb: tamper_canaries(sb, "delete"),
}
