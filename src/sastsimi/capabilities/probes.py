"""Bounded, shell-free probes that emit only sanitized observations."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.request import Request, urlopen

from sastsimi.sandbox.controller import verify_outer_boundary_controls
from sastsimi.static_analysis.repository_loader import (
    canonicalize_repository_source,
    validate_clone_destination,
)

_OUTPUT_LIMIT = 4096


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
        output = bytearray()
        overflow = threading.Event()
        process = subprocess.Popen(
            (str(executable), *arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
        )

        def read_stdout() -> None:
            assert process.stdout is not None
            while chunk := process.stdout.read(1024):
                remaining = _OUTPUT_LIMIT + 1 - len(output)
                output.extend(chunk[:remaining])
                if len(output) > _OUTPUT_LIMIT:
                    overflow.set()
                    process.kill()
                    return

        reader = threading.Thread(target=read_stdout, daemon=True)
        reader.start()
        reader.join(timeout_ms / 1000)
        if reader.is_alive() or overflow.is_set():
            process.kill()
            reader.join(1)
            process.wait(timeout=1)
            return CommandObservation(False, None)
        try:
            return_code = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
            return CommandObservation(False, None)
        if return_code != 0:
            return CommandObservation(False, None)
        try:
            text = bytes(output).decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError:
            return CommandObservation(False, None)
        if not text or any(
            ord(character) < 32 and character not in "\r\n\t" for character in text
        ):
            return CommandObservation(False, None)
        return CommandObservation(True, " ".join(text.split())[:256])


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def python_ast_observation() -> tuple[str, str] | None:
    try:
        executable = Path(sys.executable).resolve(strict=True)
        tree = ast.parse("def checked(value: int) -> int:\n    return value + 1\n")
        digest = sha256_file(executable)
    except (OSError, SyntaxError):
        return None
    if not isinstance(tree, ast.Module) or not tree.body:
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
    "SubprocessCommandProbeRunner",
    "locate_executable",
    "python_ast_observation",
    "safe_repository_loader_control",
    "sha256_file",
    "verify_outer_boundary_controls",
]
