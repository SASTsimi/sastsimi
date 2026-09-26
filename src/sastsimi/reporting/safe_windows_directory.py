"""Shared guarded directory handles for report and attachment publication."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

from sastsimi.ports.report_export import ReportUnavailable

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _directory_identity(info: os.stat_result) -> tuple[int, int, int]:
    if not stat.S_ISDIR(info.st_mode):
        raise ReportUnavailable("UNSAFE_REPORT_PATH")
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def _capture_directory_identity(path: Path) -> tuple[int, int, int] | None:
    try:
        return _directory_identity(os.stat(path, follow_symlinks=False))
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ReportUnavailable("UNSAFE_REPORT_PATH") from error


class _WindowsFunction(Protocol):
    argtypes: list[object]
    restype: object

    def __call__(self, *args: object) -> int | None: ...


class _Kernel32(Protocol):
    CreateFileW: _WindowsFunction
    CloseHandle: _WindowsFunction


def _platform_attribute(owner: object, name: str) -> object:
    return getattr(owner, name)


@contextmanager
def _locked_windows_directory(
    path: Path,
    *,
    expected_identity: tuple[int, int, int] | None = None,
    allow_write_sharing: bool = False,
) -> Iterator[None]:
    import ctypes
    import msvcrt

    try:
        path.mkdir(exist_ok=True)
    except OSError as error:
        raise ReportUnavailable("UNSAFE_REPORT_PATH") from error
    load_library = cast(Callable[..., object], _platform_attribute(ctypes, "WinDLL"))
    kernel32 = cast(_Kernel32, load_library("kernel32", use_last_error=True))
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    generic_read = 0x80000000
    share_read = 0x00000001
    share_mode = share_read | (0x00000002 if allow_write_sharing else 0)
    open_existing = 3
    file_flag_backup_semantics = 0x02000000
    file_flag_open_reparse_point = 0x00200000
    handle = create_file(
        str(path),
        generic_read,
        share_mode,
        None,
        open_existing,
        file_flag_backup_semantics | file_flag_open_reparse_point,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle is None or handle == invalid_handle:
        get_last_error = cast(
            Callable[[], int], _platform_attribute(ctypes, "get_last_error")
        )
        raise ReportUnavailable("UNSAFE_REPORT_PATH") from OSError(
            get_last_error(), "REPORT_DIRECTORY_OPEN_FAILED", str(path)
        )
    descriptor: int | None = None
    try:
        open_osfhandle = cast(
            Callable[[int, int], int],
            _platform_attribute(msvcrt, "open_osfhandle"),
        )
        descriptor = open_osfhandle(handle, os.O_RDONLY)
        information = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(information.st_mode)
            or int(getattr(information, "st_file_attributes", 0))
            & _FILE_ATTRIBUTE_REPARSE_POINT
            or int(getattr(information, "st_reparse_tag", 0)) != 0
            or (
                expected_identity is not None
                and _directory_identity(information) != expected_identity
            )
        ):
            raise ReportUnavailable("UNSAFE_REPORT_PATH")
        yield
    finally:
        if descriptor is None:
            close_handle(handle)
        else:
            os.close(descriptor)


@contextmanager
def _guarded_windows_replace_directory(path: Path) -> Iterator[None]:
    """Keep the directory non-empty while replacement needs write sharing."""

    guard_path = path / f".report-export-{uuid4().hex}.guard"
    guard = None
    with _locked_windows_directory(path):
        try:
            guard = guard_path.open("xb")
        except OSError as error:
            raise ReportUnavailable("UNSAFE_REPORT_PATH") from error
    try:
        with _locked_windows_directory(path, allow_write_sharing=True):
            yield
    finally:
        if guard is not None:
            guard.close()
        try:
            guard_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ReportUnavailable("UNSAFE_REPORT_PATH") from error
