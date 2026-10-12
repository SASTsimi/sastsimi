"""Narrow recovery evidence for generated SQLite file-path assumptions."""

from __future__ import annotations

import pytest

from sastsimi.simple_runtime import recovery

_STDERR = (
    b"RuntimeError: storage_path_unverified\n"
    b"Traceback (function names only): <module> -> main -> "
    b"configure_sqlite_storage\n"
)
_CANDIDATE = b"""
import ast
import sqlite3
from pathlib import Path

def configure_sqlite_storage():
    for source in Path('/workspace').rglob('*.py'):
        ast.parse(source.read_text())
    file_names = list(Path('/workspace').rglob('*.db'))
    if len(file_names) != 1:
        raise RuntimeError('storage_path_unverified')
    original_connect = sqlite3.connect

def main():
    configure_sqlite_storage()

main()
"""
_IN_MEMORY_SOURCE = b"""
import sqlite3

def make_server():
    return sqlite3.connect(':memory:', isolation_level=None)
"""
_SHELL_CANDIDATE = b"#!/bin/sh\nset -u\npython3 - <<'PY'\n" + _CANDIDATE + b"PY\n"


@pytest.mark.parametrize(
    "candidate", [_CANDIDATE, _SHELL_CANDIDATE, _SHELL_CANDIDATE.rstrip(b"\n")]
)
def test_verified_in_memory_source_and_file_only_poc_get_fixed_repair_guidance(
    candidate: bytes,
) -> None:
    assert recovery.sqlite_in_memory_storage_failure(
        _STDERR, b"", candidate, _IN_MEMORY_SOURCE
    )

    decision = recovery.sqlite_in_memory_storage_recovery_decision()
    assert decision.category is recovery.RecoveryCategory.GENERATED_INPUT
    assert decision.action is recovery.RecoveryAction.REGENERATE_INPUT
    assert decision.environment_patch == ""
    assert "in-memory" in decision.guidance
    assert "file" in decision.guidance
    assert "no file" in decision.guidance
    assert "target" in decision.guidance
    assert "counterevidence" in decision.guidance
    assert "/workspace" not in decision.guidance


@pytest.mark.parametrize(
    "source",
    [
        b"import sqlite3\ndef open_db():\n return sqlite3.connect('app.sqlite3')\n",
        (
            b"import sqlite3\ndef open_db(path):\n"
            b" sqlite3.connect(':memory:')\n return sqlite3.connect(path)\n"
        ),
        b"import sqlite3\ndef open_db(path):\n return sqlite3.connect(path)\n",
        b"import sqlite3\nassert True\n",
        b"def open_db():\n return sqlite3.connect(':memory:')\n",
    ],
)
def test_file_backed_mixed_dynamic_or_unproven_source_cannot_replay(
    source: bytes,
) -> None:
    assert not recovery.sqlite_in_memory_storage_failure(
        _STDERR, b"", _CANDIDATE, source
    )


@pytest.mark.parametrize(
    ("stderr", "stdout", "candidate"),
    [
        (_STDERR + b"another error\n", b"", _CANDIDATE),
        (_STDERR.replace(b"storage_path_unverified", b"other"), b"", _CANDIDATE),
        (_STDERR, b"target was reached\n", _CANDIDATE),
        (_STDERR, b"", b"def configure_sqlite_storage():\n pass\n"),
        (
            _STDERR,
            b"",
            _CANDIDATE.replace(
                b"raise RuntimeError('storage_path_unverified')",
                b"raise RuntimeError('different_error')",
            ),
        ),
    ],
)
def test_mixed_output_or_unrelated_generated_error_cannot_replay(
    stderr: bytes, stdout: bytes, candidate: bytes
) -> None:
    assert not recovery.sqlite_in_memory_storage_failure(
        stderr, stdout, candidate, _IN_MEMORY_SOURCE
    )


def test_explicit_source_paths_keep_multiple_files_for_pinned_proof() -> None:
    candidate = _SHELL_CANDIDATE.replace(
        b"def main():\n",
        b"def main():\n"
        b"    route_source = root / 'app' / 'route.py'\n"
        b"    server_source = root / 'app' / 'server.py'\n",
    ).replace(
        b"from pathlib import Path\n",
        b"from pathlib import Path\nroot = Path('/workspace')\n",
    )
    assert recovery.sqlite_in_memory_target_paths(candidate) == (
        "app/route.py",
        "app/server.py",
    )
