"""Windows Service wrapper for the SENTINEL agent.

Requires pywin32 (installed only on Windows). Install/manage with::

    python -m agent.service.windows_service install
    python -m agent.service.windows_service start
    python -m agent.service.windows_service stop
    python -m agent.service.windows_service remove

The service reads SENTINEL_CONFIG (set it as a machine environment variable, or
edit DEFAULT_CONFIG below) and runs the same SentinelAgent used on Linux.
"""
from __future__ import annotations

import os
import sys

DEFAULT_CONFIG = os.environ.get("SENTINEL_CONFIG", r"C:\ProgramData\Sentinel\sentinel.yaml")

try:
    import servicemanager  # type: ignore
    import win32event  # type: ignore
    import win32service  # type: ignore
    import win32serviceutil  # type: ignore
    _HAVE_PYWIN32 = True
except ImportError:  # pragma: no cover - only meaningful on Windows
    _HAVE_PYWIN32 = False


if _HAVE_PYWIN32:
    class SentinelService(win32serviceutil.ServiceFramework):
        _svc_name_ = "SentinelAgent"
        _svc_display_name_ = "PROJECT SENTINEL Ransomware Detection Agent"
        _svc_description_ = ("Continuously monitors file-system activity, deploys canary files and "
                             "detects ransomware behaviour.")

        def __init__(self, args):
            super().__init__(args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._agent = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self._agent is not None:
                self._agent.request_stop()
            win32event.SetEvent(self._stop_event)

        def SvcDoRun(self):
            from agent.core.agent import SentinelAgent
            from agent.core.config import load_config
            from agent.core.logging_setup import configure_logging

            config = load_config(DEFAULT_CONFIG)
            configure_logging(config.agent.log_level, config.agent.log_file)
            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                                  servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""))
            self._agent = SentinelAgent(config)
            self._agent.start()
            try:
                win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)
            finally:
                self._agent.stop()


def main() -> int:
    if not _HAVE_PYWIN32:
        print("pywin32 is required for the Windows service (pip install pywin32)", file=sys.stderr)
        return 1
    win32serviceutil.HandleCommandLine(SentinelService)
    return 0


if __name__ == "__main__":
    sys.exit(main())
