"""Blocking local dashboard command."""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

from sastsimi.dashboard.server import serve_dashboard


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def run(data_dir: Path, host: str, port: int) -> None:
    if not _loopback(host):
        raise ValueError("DASHBOARD_LOOPBACK_ONLY")
    if not 1 <= port <= 65535:
        raise ValueError("DASHBOARD_PORT_INVALID")
    sys.stdout.write(f"대시보드: http://{host}:{port}\n종료: Ctrl+C\n")
    try:
        serve_dashboard(data_dir, host, port)
    except KeyboardInterrupt:
        return


__all__ = ["run"]
