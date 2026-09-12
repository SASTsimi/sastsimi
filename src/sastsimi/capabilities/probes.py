"""Bounded, shell-free probes that emit only sanitized observations."""

from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast
from urllib.request import Request, urlopen

from sastsimi.ports.dto import MonotonicActionDeadline, ProcessSpec
from sastsimi.sandbox.controller import verify_outer_boundary_controls
from sastsimi.static_analysis.process_windows import WindowsProcessBackend
from sastsimi.static_analysis.repository_loader import (
    canonicalize_repository_source,
    validate_clone_destination,
)

_OUTPUT_LIMIT = 64 * 1024
_WINDOWS_REPARSE_POINT = 0x400
_MINIMAL_ENV_KEYS = frozenset(
    {
        "SYSTEMROOT",
        "WINDIR",
        "TMP",
        "TEMP",
        "LANG",
        "LC_ALL",
    }
)


@dataclass(frozen=True)
class CommandObservation:
    succeeded: bool
    safe_stdout: str | None


class CommandProbeRunner(Protocol):
    def run(
        self,
        executable: Path,
        arguments: tuple[str, ...],
        *,
        timeout_ms: int,
        environment_overrides: Mapping[str, str] | None = None,
    ) -> CommandObservation: ...


class OpenAIProbeTransport(Protocol):
    def probe(self, *, model: str, secret: str) -> bool: ...


class SubprocessCommandProbeRunner:
    """Run one exact executable with bounded stdout and discarded stderr."""

    def run(
        self,
        executable: Path,
        arguments: tuple[str, ...],
        *,
        timeout_ms: int,
        environment_overrides: Mapping[str, str] | None = None,
    ) -> CommandObservation:
        safe_environment = {
            key: value for key, value in os.environ.items() if key in _MINIMAL_ENV_KEYS
        }
        safe_environment.update(
            {
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        if environment_overrides not in (None, {}, {"DOCKER_BUILDKIT": "0"}):
            raise ValueError("PROBE_ENVIRONMENT_OVERRIDE_DENIED")
        if environment_overrides:
            safe_environment.update(environment_overrides)
        if os.name == "nt":
            return self._run_windows(
                executable, arguments, timeout_ms, safe_environment
            )

        output = bytearray()
        overflow = threading.Event()
        process = subprocess.Popen(
            (str(executable), *arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            cwd=str(executable.parent),
            env=safe_environment,
            start_new_session=True,
        )

        def read_stdout() -> None:
            assert process.stdout is not None
            while chunk := process.stdout.read(1024):
                remaining = _OUTPUT_LIMIT + 1 - len(output)
                output.extend(chunk[:remaining])
                if len(output) > _OUTPUT_LIMIT:
                    overflow.set()
                    self._terminate_tree(process)
                    return

        reader = threading.Thread(target=read_stdout, daemon=True)
        reader.start()
        reader.join(timeout_ms / 1000)
        if reader.is_alive() or overflow.is_set():
            self._terminate_tree(process)
            reader.join(1)
            process.wait(timeout=1)
            return CommandObservation(False, None)
        try:
            return_code = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self._terminate_tree(process)
            process.wait(timeout=1)
            return CommandObservation(False, None)
        if return_code != 0:
            return CommandObservation(False, None)
        return self._decode(output)

    @staticmethod
    def _decode(output: bytes | bytearray) -> CommandObservation:
        try:
            text = bytes(output).decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError:
            return CommandObservation(False, None)
        if not text or any(
            ord(character) < 32 and character not in "\r\n\t" for character in text
        ):
            return CommandObservation(False, None)
        return CommandObservation(True, " ".join(text.split())[:_OUTPUT_LIMIT])

    def _run_windows(
        self,
        executable: Path,
        arguments: tuple[str, ...],
        timeout_ms: int,
        safe_environment: dict[str, str],
    ) -> CommandObservation:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            return CommandObservation(False, None)

        stdout = _BoundedProbeOutput()
        stderr = _DiscardProbeOutput()
        started_ns = time.monotonic_ns()
        spec = ProcessSpec(
            invocation_id="capability-probe-command",
            command_kind="CAPABILITY_PROBE",
            attempt_id="capability-probe-attempt",
            argv=(str(executable), *arguments),
            cwd=executable.parent,
            env=tuple(sorted(safe_environment.items())),
            attempt_output_dir=executable.parent,
            stdout_limit_bytes=_OUTPUT_LIMIT,
            stderr_limit_bytes=1,
            attempt_output_limit_bytes=_OUTPUT_LIMIT,
            deadline=MonotonicActionDeadline(
                action_id="capability-probe-action",
                started_ns=started_ns,
                expires_ns=started_ns + timeout_ms * 1_000_000,
            ),
        )

        async def execute() -> CommandObservation:
            outcome = await WindowsProcessBackend().run(
                spec,
                timeout_ms,
                stdout,
                stderr,
                asyncio.Event(),
            )
            if (
                outcome.return_code != 0
                or outcome.timed_out
                or outcome.cancelled
                or stdout.overflow
            ):
                return CommandObservation(False, None)
            return self._decode(stdout.data)

        try:
            return asyncio.run(execute())
        except (OSError, RuntimeError, TimeoutError):
            return CommandObservation(False, None)

    @staticmethod
    def _terminate_tree(process: subprocess.Popen[bytes]) -> None:
        try:
            # start_new_session=True makes the original pid the process-group id.
            # The group remains addressable after its leader exits.
            kill_group = cast(Callable[[int, int], None], os.__dict__["killpg"])
            kill_signal = cast(int, signal.__dict__["SIGKILL"])
            kill_group(process.pid, kill_signal)
            return
        except (OSError, ProcessLookupError):
            pass
        try:
            process.kill()
        except OSError:
            pass


class _BoundedProbeOutput:
    def __init__(self) -> None:
        self.data = bytearray()
        self.overflow = False

    def write(self, data: bytes) -> None:
        remaining = _OUTPUT_LIMIT - len(self.data)
        if len(data) > remaining:
            self.overflow = True
        if remaining > 0:
            self.data.extend(data[:remaining])


class _DiscardProbeOutput:
    def write(self, data: bytes) -> None:
        del data


class OpenAIResponsesProbe:
    """Probe API-key authentication and strict structured output over HTTPS."""

    endpoint = "https://api.openai.com/v1/responses"

    def probe(self, *, model: str, secret: str) -> bool:
        payload = json.dumps(
            {
                "model": model,
                "input": "Return JSON with ok=true.",
                "store": False,
                "max_output_tokens": 32,
                "text": {
                    "format": {
                        "type": "json_schema",
                        "name": "sastsimi_capability_probe",
                        "strict": True,
                        "schema": {
                            "type": "object",
                            "properties": {"ok": {"type": "boolean"}},
                            "required": ["ok"],
                            "additionalProperties": False,
                        },
                    }
                },
            },
            separators=(",", ":"),
        ).encode()
        request = Request(
            self.endpoint,
            data=payload,
            method="POST",
            headers={
                "Authorization": "Bearer " + secret,
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=15) as response:  # noqa: S310 - fixed HTTPS
                if response.status != 200:
                    return False
                body = response.read(64 * 1024 + 1)
        except Exception:
            return False
        if len(body) > 64 * 1024:
            return False
        try:
            value = json.loads(body)
            texts = [
                item["text"]
                for output in value.get("output", [])
                for item in output.get("content", [])
                if item.get("type") == "output_text"
            ]
            return any(json.loads(text) == {"ok": True} for text in texts)
        except (KeyError, TypeError, ValueError):
            return False


class ProductionExecutableRegistry:
    """Closed allowlist of external tools plus the exact in-process interpreter."""

    def __init__(
        self,
        entries: dict[str, Path],
        *,
        forbidden_roots: tuple[Path, ...],
        in_process_keys: frozenset[str] = frozenset(),
    ) -> None:
        self._forbidden_roots = tuple(
            root.resolve(strict=False) for root in forbidden_roots
        )
        self._in_process_keys = in_process_keys
        if not in_process_keys <= set(entries):
            raise ValueError("CAPABILITY_IN_PROCESS_KEY_UNKNOWN")
        self._entries = {
            key: self._validate(path, in_process=key in in_process_keys)
            for key, path in entries.items()
            if path is not None
        }

    def resolve(self, key: str) -> Path | None:
        path = self._entries.get(key)
        return (
            self._validate(path, in_process=key in self._in_process_keys)
            if path is not None
            else None
        )

    def _validate(self, path: Path, *, in_process: bool) -> Path:
        try:
            if not path.is_absolute():
                raise ValueError
            current = path
            while True:
                metadata = current.lstat()
                if current.is_symlink() or (
                    getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
                ):
                    raise ValueError
                if current.parent == current:
                    break
                current = current.parent
            resolved = path.resolve(strict=True)
            if not resolved.is_file():
                raise ValueError
            if in_process:
                if resolved != Path(sys.executable).resolve(strict=True):
                    raise ValueError
            else:
                for root in self._forbidden_roots:
                    try:
                        resolved.relative_to(root)
                    except ValueError:
                        continue
                    raise ValueError
                if not _trusted_executable_acl(resolved):
                    raise ValueError
            return resolved
        except (OSError, ValueError) as error:
            raise ValueError("CAPABILITY_EXECUTABLE_PATH_DENIED") from error


def _trusted_executable_acl(path: Path) -> bool:
    """Require a path that the effective account cannot replace or modify."""

    if os.name == "nt":
        return not _windows_path_is_mutable(path)
    current = path
    while True:
        metadata = current.lstat()
        if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return False
        if current.parent == current:
            return True
        current = current.parent


def _windows_path_is_mutable(path: Path) -> bool:
    """Use the effective Windows token to test file and parent write rights."""

    import ctypes
    from ctypes import wintypes

    windll = ctypes.__dict__.get("windll")
    if windll is None:
        raise OSError("WINDOWS_NATIVE_API_UNAVAILABLE")
    create_file = windll.kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    close_handle = windll.kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    invalid = ctypes.c_void_p(-1).value
    share_all = 0x00000001 | 0x00000002 | 0x00000004
    open_existing = 3
    backup_semantics = 0x02000000

    def can_open(candidate: Path, access: int, *, directory: bool) -> bool:
        handle = create_file(
            str(candidate),
            access,
            share_all,
            None,
            open_existing,
            backup_semantics if directory else 0,
            None,
        )
        if handle == invalid:
            return False
        close_handle(handle)
        return True

    file_rights = (0x40000000, 0x00010000, 0x00040000, 0x00080000)
    if any(can_open(path, access, directory=False) for access in file_rights):
        return True
    directory_rights = (
        0x00000002,
        0x00000040,
        0x00010000,
        0x00040000,
        0x00080000,
    )
    current = path.parent
    while True:
        if any(
            can_open(current, access, directory=True) for access in directory_rights
        ):
            return True
        if current.parent == current:
            return False
        current = current.parent


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def python_ast_observation(executable: Path) -> tuple[str, str] | None:
    try:
        executable = executable.resolve(strict=True)
        if executable != Path(sys.executable).resolve(strict=True):
            return None
        before = sha256_file(executable)
        tree = ast.parse("def checked(value: int) -> int:\n    return value + 1\n")
        digest = sha256_file(executable)
    except (OSError, SyntaxError):
        return None
    if not isinstance(tree, ast.Module) or not tree.body or before != digest:
        return None
    version = ".".join(str(part) for part in sys.version_info[:3])
    return version, digest


def safe_repository_loader_control(scratch_root: Path) -> bool:
    scratch_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch_root) as temporary:
        root = Path(temporary) / "storage"
        child = root / "workspace"
        outside = Path(temporary) / "outside"
        root.mkdir()
        child.mkdir()
        outside.mkdir()
        if validate_clone_destination(child, root) != child.resolve(strict=True):
            return False
        try:
            validate_clone_destination(outside, root)
        except ValueError:
            pass
        else:
            return False
        for unsafe_source in (
            "file:///outside/repository",
            "https://user:password@example.invalid/repository",
        ):
            try:
                canonicalize_repository_source(unsafe_source)
            except ValueError:
                continue
            return False
        return True
    return False


__all__ = [
    "CommandObservation",
    "CommandProbeRunner",
    "OpenAIProbeTransport",
    "OpenAIResponsesProbe",
    "ProductionExecutableRegistry",
    "SubprocessCommandProbeRunner",
    "python_ast_observation",
    "safe_repository_loader_control",
    "sha256_file",
    "verify_outer_boundary_controls",
]
