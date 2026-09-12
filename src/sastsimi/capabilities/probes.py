"""Bounded, shell-free probes that emit only sanitized observations."""

from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
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
        "USERPROFILE",
        "HOME",
        "TMP",
        "TEMP",
        "LANG",
        "LC_ALL",
        "DOCKER_CONFIG",
    }
)


@dataclass(frozen=True)
class CommandObservation:
    succeeded: bool
    safe_stdout: str | None


class CommandProbeRunner(Protocol):
    def run(
        self, executable: Path, arguments: tuple[str, ...], *, timeout_ms: int
    ) -> CommandObservation: ...


class OpenAIProbeTransport(Protocol):
    def probe(self, *, model: str, secret: str) -> bool: ...


class SubprocessCommandProbeRunner:
    """Run one exact executable with bounded stdout and discarded stderr."""

    def run(
        self, executable: Path, arguments: tuple[str, ...], *, timeout_ms: int
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
        if process.poll() is not None:
            return
        try:
            kill_group = cast(
                Callable[[int, int], None],
                os.killpg,  # type: ignore[attr-defined]
            )
            kill_signal = cast(
                int,
                signal.SIGKILL,  # type: ignore[attr-defined]
            )
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


def locate_executable(name: str) -> Path | None:
    found = shutil.which(name)
    return Path(found).resolve(strict=True) if found is not None else None


class ProductionExecutableRegistry:
    """Closed allowlist of absolute executables outside mutable task roots."""

    def __init__(
        self, entries: dict[str, Path], *, forbidden_roots: tuple[Path, ...]
    ) -> None:
        self._forbidden_roots = tuple(
            root.resolve(strict=False) for root in forbidden_roots
        )
        self._entries = {
            key: self._validate(path)
            for key, path in entries.items()
            if path is not None
        }

    @classmethod
    def discover(
        cls,
        *,
        names: tuple[str, ...],
        forbidden_roots: tuple[Path, ...],
    ) -> ProductionExecutableRegistry:
        entries: dict[str, Path] = {"python": Path(sys.executable)}
        for name in names:
            found = shutil.which(name)
            if found is not None:
                entries[name] = Path(found)
        return cls(entries, forbidden_roots=forbidden_roots)

    def resolve(self, key: str) -> Path | None:
        path = self._entries.get(key)
        return self._validate(path) if path is not None else None

    def _validate(self, path: Path) -> Path:
        try:
            if not path.is_absolute():
                raise ValueError
            current = path
            while True:
                stat = current.lstat()
                if current.is_symlink() or (
                    getattr(stat, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
                ):
                    raise ValueError
                if current.parent == current:
                    break
                current = current.parent
            resolved = path.resolve(strict=True)
            if not resolved.is_file():
                raise ValueError
            for root in self._forbidden_roots:
                try:
                    resolved.relative_to(root)
                except ValueError:
                    continue
                raise ValueError
            return resolved
        except (OSError, ValueError) as error:
            raise ValueError("CAPABILITY_EXECUTABLE_PATH_DENIED") from error


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
    "locate_executable",
    "python_ast_observation",
    "safe_repository_loader_control",
    "sha256_file",
    "verify_outer_boundary_controls",
]
