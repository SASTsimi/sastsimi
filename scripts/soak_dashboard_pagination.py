"""Long-running, read-only HTTP soak for the isolated dashboard DEMO server."""

from __future__ import annotations

import argparse
import ctypes
import json
import time
import urllib.request
from ctypes import wintypes
from dataclasses import asdict, dataclass
from urllib.parse import quote


@dataclass
class Report:
    duration_seconds: float = 0
    requests: int = 0
    errors: int = 0
    maximum_items: int = 0
    server_working_set_start: int | None = None
    server_working_set_end: int | None = None
    server_working_set_maximum: int | None = None
    last_error: str | None = None


def _working_set(pid: int | None) -> int | None:
    if pid is None:
        return None

    class Counters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    handle = kernel32.OpenProcess(0x1000 | 0x0010, False, pid)
    if not handle:
        return None
    try:
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return None
        return int(counters.WorkingSetSize)
    finally:
        kernel32.CloseHandle(handle)


def _get(url: str) -> dict[str, object] | list[object]:
    with urllib.request.urlopen(url, timeout=10) as response:
        decoded = json.load(response)
    if isinstance(decoded, dict):
        return dict(decoded)
    if isinstance(decoded, list):
        return list(decoded)
    raise AssertionError("JSON response is neither an object nor an array")


def _items(payload: object, label: str) -> list[object]:
    if not isinstance(payload, dict):
        raise AssertionError(f"{label} response is not an object")
    items = payload.get("items")
    if not isinstance(items, list):
        raise AssertionError(f"{label} response has no item list")
    return items


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--analysis-id", required=True)
    parser.add_argument("--duration", type=int, default=1800)
    parser.add_argument("--server-pid", type=int)
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    analysis = quote(args.analysis_id, safe="")
    report = Report()
    report.server_working_set_start = _working_set(args.server_pid)
    report.server_working_set_maximum = report.server_working_set_start
    tabs = ("findings", "coverage", "artifacts", "llm", "outputs")
    started = time.monotonic()
    iteration = 0
    while time.monotonic() - started < args.duration:
        try:
            tab = tabs[iteration % len(tabs)]
            page_number = iteration % 3 + 1
            page = _get(
                f"{base}/api/analyses/{analysis}/tabs/{tab}"
                f"?page={page_number}&page_size=10"
            )
            if not isinstance(page, dict):
                raise AssertionError("list response is not an object")
            items = page.get("items")
            if not isinstance(items, list) or len(items) > 10:
                raise AssertionError("list response exceeded 10 items")
            report.maximum_items = max(report.maximum_items, len(items))
            report.requests += 1

            logs = _get(f"{base}/api/analyses/{analysis}/logs?limit=10")
            if not isinstance(logs, dict):
                raise AssertionError("latest log response is not an object")
            if len(_items(logs, "latest log")) > 10:
                raise AssertionError("latest log response exceeded 10 items")
            report.requests += 1
            cursor = logs.get("next_cursor")
            if cursor and iteration % 5 == 0:
                older = _get(
                    f"{base}/api/analyses/{analysis}/logs"
                    f"?before={quote(str(cursor), safe='')}&limit=10"
                )
                if len(_items(older, "older log")) > 10:
                    raise AssertionError("older log response exceeded 10 items")
                report.requests += 1

            if iteration % 10 == 0:
                search = _get(
                    f"{base}/api/analyses/{analysis}/tabs/artifacts"
                    "?page=1&page_size=10&query=DEMO"
                )
                if len(_items(search, "search")) > 10:
                    raise AssertionError("search response exceeded 10 items")
                _get(f"{base}/api/analyses/{analysis}/llm/simple-1")
                report.requests += 2

            current = _working_set(args.server_pid)
            if current is not None:
                previous = report.server_working_set_maximum or 0
                report.server_working_set_maximum = max(previous, current)
        except Exception as error:  # soak must record and continue
            report.errors += 1
            report.last_error = f"{type(error).__name__}: {error}"
        iteration += 1
        elapsed = int(time.monotonic() - started)
        if elapsed and elapsed % 60 < 2:
            print(
                json.dumps(
                    {
                        "elapsed": elapsed,
                        "requests": report.requests,
                        "errors": report.errors,
                        "working_set": _working_set(args.server_pid),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
        time.sleep(2)
    report.duration_seconds = round(time.monotonic() - started, 3)
    report.server_working_set_end = _working_set(args.server_pid)
    print(json.dumps(asdict(report), sort_keys=True), flush=True)
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
