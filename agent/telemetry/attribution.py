"""Process attribution capabilities (detailed implementation added with telemetry)."""
from __future__ import annotations

import sys


def attribution_capabilities() -> dict:
    return {"process_attribution": [], "platform_family": sys.platform}
