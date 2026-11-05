"""Best-effort desktop notifications (cross-platform, no hard dependencies)."""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys

log = logging.getLogger("sentinel.notify")


def send_desktop_notification(title: str, message: str, urgency: str = "critical") -> bool:
    """Show a desktop notification if the platform supports it; never raises."""
    try:
        if sys.platform.startswith("linux"):
            return _linux(title, message, urgency)
        if sys.platform == "darwin":
            return _macos(title, message)
        if os.name == "nt":
            return _windows(title, message)
    except Exception:
        log.debug("desktop notification failed", exc_info=True)
    return False


def _linux(title: str, message: str, urgency: str) -> bool:
    exe = shutil.which("notify-send")
    if not exe:
        return False
    subprocess.run([exe, "-u", "critical" if urgency == "critical" else "normal",
                    "-a", "PROJECT SENTINEL", title, message], check=False, capture_output=True, timeout=5)
    return True


def _macos(title: str, message: str) -> bool:
    exe = shutil.which("osascript")
    if not exe:
        return False
    safe = message.replace('"', "'")[:400]
    subprocess.run([exe, "-e", f'display notification "{safe}" with title "PROJECT SENTINEL: {title}"'],
                   check=False, capture_output=True, timeout=5)
    return True


def _windows(title: str, message: str) -> bool:
    # Use PowerShell toast via BurntToast if present, else a balloon fallback.
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        return False
    safe_t = title.replace("'", "`'")[:100]
    safe_m = message.replace("'", "`'")[:400]
    script = (
        "[reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null;"
        "$n = New-Object System.Windows.Forms.NotifyIcon;"
        "$n.Icon = [System.Drawing.SystemIcons]::Warning; $n.Visible = $true;"
        f"$n.ShowBalloonTip(8000, 'SENTINEL: {safe_t}', '{safe_m}', 'Warning');"
    )
    subprocess.run([ps, "-NoProfile", "-Command", script], check=False, capture_output=True, timeout=8)
    return True
