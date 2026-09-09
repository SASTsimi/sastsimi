"""Read-only command implementations; no external processes or state writes."""

import platform
import struct
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class HostInfo:
    system: str
    release: str
    version: str
    machine: str
    python: tuple[int, int, int]
    implementation: str
    bits: int


def inspect_host() -> HostInfo:
    system = platform.system()
    release, version = platform.release(), ""
    if system == "Linux":
        try:
            distribution = platform.freedesktop_os_release()
        except OSError:
            distribution = {}
        release = distribution.get("ID", "")
        version = distribution.get("VERSION_ID", "")
    elif system == "Windows":
        release = platform.win32_ver()[0]
    return HostInfo(
        system,
        release,
        version,
        platform.machine(),
        sys.version_info[:3],
        platform.python_implementation(),
        struct.calcsize("P") * 8,
    )


def doctor() -> bool:
    host = inspect_host()
    supported_os = (
        host.system == "Windows" and host.release in {"11", "2022Server"}
    ) or (
        host.system == "Linux" and host.release == "ubuntu" and host.version == "24.04"
    )
    return (
        supported_os
        and host.machine.lower() in {"amd64", "x86_64"}
        and host.python[:2] == (3, 12)
        and host.implementation == "CPython"
        and host.bits == 64
    )
