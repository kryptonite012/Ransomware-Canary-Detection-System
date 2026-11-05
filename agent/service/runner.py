"""Foreground service runner with signal handling and systemd integration."""
from __future__ import annotations

import logging
import os
import signal
import socket
import threading

from agent.core.agent import SentinelAgent
from agent.core.config import SentinelConfig

log = logging.getLogger("sentinel.service")


def sd_notify(message: str) -> bool:
    """Minimal sd_notify(3) implementation (no external dependency)."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr or os.name == "nt":
        return False
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(addr)
            sock.sendall(message.encode())
        return True
    except OSError:
        return False


def _watchdog_interval() -> float | None:
    usec = os.environ.get("WATCHDOG_USEC")
    if not usec:
        return None
    try:
        return int(usec) / 1_000_000 / 2
    except ValueError:
        return None


def run_service(config: SentinelConfig) -> int:
    agent = SentinelAgent(config)

    def _handle(signum, _frame):
        log.info("received signal %s; shutting down", signum)
        agent.request_stop()

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, lambda *_: threading.Thread(target=agent.reload_policy, daemon=True).start())

    agent.start()
    sd_notify("READY=1\nSTATUS=monitoring")
    interval = _watchdog_interval()
    try:
        while not agent.stopping:
            if interval:
                # Only pet the systemd watchdog while the pipeline is healthy.
                if agent.monitor.alive:
                    sd_notify("WATCHDOG=1")
                agent._stop.wait(interval)
            else:
                agent._stop.wait(1.0)
    finally:
        sd_notify("STOPPING=1")
        agent.stop()
    return 0
