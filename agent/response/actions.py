"""Executors for response actions.

Every executor is designed around the specification's hard safety rules:

* Never terminate arbitrary system processes - a configurable allow-list of
  critical OS process names can never be suspended or killed.
* Prefer reversible actions.  Process **suspension** (SIGSTOP / Windows suspend)
  and directory **write-protection** are reversible and record rollback data;
  termination is offered but is a separate, explicitly-approved action.
* Never delete or encrypt user data.  There is no executor that destroys user
  files.
* Network isolation defaults to **dry-run**: it records what it *would* do
  rather than actually cutting the network, unless explicitly enabled.

Executors return ``ActionResult(ok, detail, rollback)``.  ``rollback`` is stored
on the :class:`ResponseAction` row so the action can be undone.
"""
from __future__ import annotations

import logging
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from typing import Any

import psutil

log = logging.getLogger("sentinel.actions")


@dataclass
class ActionResult:
    ok: bool
    detail: str
    rollback: dict[str, Any] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)


class ActionExecutor:
    def __init__(self, config, self_writes=None):
        self.config = config
        self.self_writes = self_writes
        self.protected_names = {n.lower() for n in config.response.protected_process_names}

    # ------------------------------------------------------------------ processes
    def _guard_process(self, pid: int) -> psutil.Process:
        if pid in (0, os.getpid(), os.getppid()):
            raise PermissionError("refusing to act on the agent's own process")
        proc = psutil.Process(pid)  # raises NoSuchProcess if gone
        name = (proc.name() or "").lower()
        if name in self.protected_names:
            raise PermissionError(f"process {name!r} is on the protected list and will not be touched")
        if pid == 1:
            raise PermissionError("refusing to act on PID 1")
        return proc

    def suspend_process(self, pid: int, **_: Any) -> ActionResult:
        proc = self._guard_process(pid)
        info = {"pid": pid, "name": proc.name(), "exe": _safe(proc.exe)}
        proc.suspend()
        log.warning("suspended process %s (pid %d)", info["name"], pid)
        return ActionResult(True, f"suspended {info['name']} (pid {pid})",
                            rollback={"action": "resume_process", "pid": pid}, data=info)

    def resume_process(self, pid: int, **_: Any) -> ActionResult:
        proc = psutil.Process(pid)
        proc.resume()
        return ActionResult(True, f"resumed pid {pid}", data={"pid": pid})

    def terminate_process(self, pid: int, force: bool = False, **_: Any) -> ActionResult:
        proc = self._guard_process(pid)
        name = proc.name()
        # Preserve identity before termination (irreversible) for the audit trail.
        info = {"pid": pid, "name": name, "exe": _safe(proc.exe), "cmdline": _safe(proc.cmdline)}
        if force:
            proc.kill()
        else:
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except psutil.TimeoutExpired:
            pass
        log.warning("terminated process %s (pid %d, force=%s)", name, pid, force)
        return ActionResult(True, f"terminated {name} (pid {pid})", data=info)

    # ------------------------------------------------------------------ directories
    def protect_directory(self, path: str, **_: Any) -> ActionResult:
        """Make a directory tree read-only (remove write bits), reversibly."""
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            return ActionResult(False, f"{path} is not a directory")
        if os.name == "nt":
            return self._protect_directory_windows(path)
        original: dict[str, int] = {}
        count = 0
        for root, dirs, files in os.walk(path):
            for name in files + dirs:
                fp = os.path.join(root, name)
                try:
                    mode = os.stat(fp).st_mode
                    original[fp] = stat.S_IMODE(mode)
                    os.chmod(fp, stat.S_IMODE(mode) & ~0o222)  # clear write bits
                    count += 1
                except OSError:
                    continue
        try:
            dmode = os.stat(path).st_mode
            original[path] = stat.S_IMODE(dmode)
            os.chmod(path, stat.S_IMODE(dmode) & ~0o222)
        except OSError:
            pass
        log.warning("write-protected %d entries under %s", count, path)
        return ActionResult(True, f"write-protected {count} entries under {path}",
                            rollback={"action": "unprotect_directory", "modes": original},
                            data={"path": path, "entries": count})

    def _protect_directory_windows(self, path: str) -> ActionResult:
        # Use attrib +R recursively; rollback via attrib -R.
        try:
            subprocess.run(["attrib", "+R", os.path.join(path, "*"), "/S", "/D"], check=False,
                           capture_output=True)
        except OSError as exc:
            return ActionResult(False, f"attrib failed: {exc}")
        return ActionResult(True, f"set read-only attribute under {path}",
                            rollback={"action": "unprotect_directory_windows", "path": path},
                            data={"path": path})

    def unprotect_directory(self, modes: dict[str, int], **_: Any) -> ActionResult:
        restored = 0
        for fp, mode in modes.items():
            try:
                os.chmod(fp, mode)
                restored += 1
            except OSError:
                continue
        return ActionResult(True, f"restored permissions on {restored} entries")

    def unprotect_directory_windows(self, path: str, **_: Any) -> ActionResult:
        subprocess.run(["attrib", "-R", os.path.join(path, "*"), "/S", "/D"], check=False,
                       capture_output=True)
        return ActionResult(True, f"cleared read-only attribute under {path}")

    # ------------------------------------------------------------------ network
    def isolate_network(self, **_: Any) -> ActionResult:
        iso = self.config.response.network_isolation
        intent = {"allow_hosts": iso.allow_hosts, "allow_ports": iso.allow_ports}
        if not iso.enabled or iso.dry_run:
            log.warning("network isolation requested (DRY RUN): %s", intent)
            return ActionResult(True, "network isolation simulated (dry run); no rules applied",
                                data={"dry_run": True, **intent})
        # Real isolation is intentionally conservative and platform specific; it
        # is only attempted when explicitly enabled and not in dry-run.
        return ActionResult(False, "live network isolation is not enabled on this platform build",
                            data={"dry_run": False, **intent})

    def dispatch(self, action_type: str, target: dict[str, Any]) -> ActionResult:
        handler = {
            "suspend_process": self.suspend_process,
            "resume_process": self.resume_process,
            "terminate_process": self.terminate_process,
            "protect_directory": self.protect_directory,
            "unprotect_directory": self.unprotect_directory,
            "unprotect_directory_windows": self.unprotect_directory_windows,
            "isolate_network": self.isolate_network,
            "notify": lambda **_: ActionResult(True, "notification dispatched"),
        }.get(action_type)
        if handler is None:
            return ActionResult(False, f"unknown action type {action_type}")
        try:
            return handler(**(target or {}))
        except psutil.NoSuchProcess:
            return ActionResult(False, "target process no longer exists")
        except (psutil.AccessDenied, PermissionError) as exc:
            return ActionResult(False, f"not permitted: {exc}")
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("action %s failed", action_type)
            return ActionResult(False, f"error: {exc}")


def _safe(fn) -> str | None:
    try:
        v = fn()
        return " ".join(v) if isinstance(v, list) else v
    except Exception:
        return None
