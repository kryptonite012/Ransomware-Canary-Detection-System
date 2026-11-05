"""Disposable sandbox management for the ransomware simulator.

Hard safety rules (enforced, not advisory):

* The simulator only ever operates inside a directory that contains a
  ``.sentinel-sandbox`` marker file that *it* created.  It refuses to touch any
  directory lacking that marker, so it can never be pointed at real user data.
* The sandbox path must be inside the configured base and must not be a system
  directory, the user's home, or a monitored production path.
* No file outside the sandbox is ever read, written, renamed or deleted.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

MARKER = ".sentinel-sandbox"
_FORBIDDEN_ROOTS = ["/", "/home", "/root", "/etc", "/var", "/usr", "/bin", "/boot", "/lib",
                    "/opt", "/sys", "/proc", "/dev", str(Path.home())]


class SandboxError(RuntimeError):
    pass


def _is_forbidden(path: Path) -> bool:
    resolved = path.resolve()
    for forbidden in _FORBIDDEN_ROOTS:
        if str(resolved) == str(Path(forbidden).resolve()):
            return True
    return False


class Sandbox:
    def __init__(self, path: Path):
        self.path = Path(path).resolve()

    @classmethod
    def create(cls, base: Path, name: str = "sentinel-sim") -> "Sandbox":
        base = Path(base).resolve()
        if not name or "/" in name or "\\" in name or name in (".", "..") or "\x00" in name:
            raise SandboxError(f"invalid sandbox name: {name!r}")
        path = (base / name).resolve()
        if path != base / name:  # normalization changed the path -> escape attempt
            raise SandboxError(f"sandbox name escapes base: {name!r}")
        if base not in path.parents:
            raise SandboxError(f"sandbox path must be inside the base directory: {path}")
        if _is_forbidden(path) or _is_forbidden(base):
            raise SandboxError(f"refusing to create a sandbox at a protected location: {path}")
        path.mkdir(parents=True, exist_ok=True)
        marker = path / MARKER
        marker.write_text("This directory is a disposable PROJECT SENTINEL simulation sandbox.\n"
                          "It is safe to delete. The simulator only operates inside marked sandboxes.\n")
        return cls(path)

    @classmethod
    def attach(cls, path: Path) -> "Sandbox":
        sb = cls(path)
        sb._assert_owned()
        return sb

    def _assert_owned(self) -> None:
        if _is_forbidden(self.path):
            raise SandboxError(f"{self.path} is a protected location")
        if not self.path.is_dir():
            raise SandboxError(f"{self.path} is not a directory")
        if not (self.path / MARKER).is_file():
            raise SandboxError(
                f"{self.path} is not a SENTINEL sandbox (missing {MARKER} marker); refusing to operate")

    def resolve_inside(self, *parts: str) -> Path:
        """Return a path inside the sandbox, guaranteeing it cannot escape."""
        target = (self.path.joinpath(*parts)).resolve()
        if target != self.path and self.path not in target.parents:
            raise SandboxError(f"path escapes sandbox: {target}")
        return target

    def destroy(self) -> None:
        self._assert_owned()
        shutil.rmtree(self.path, ignore_errors=True)
