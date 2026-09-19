from __future__ import annotations

import ast
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_DOCKERFILE = _ROOT / "docker" / "codeql" / "Dockerfile"
_ENTRYPOINT = _ROOT / "docker" / "codeql" / "sastsimi-codeql"
_BUILDER = _ROOT / "tools" / "build_codeql_image.py"


def test_dockerfile_is_offline_pinned_and_installs_only_verified_local_inputs() -> None:
    dockerfile = _DOCKERFILE.read_text(encoding="utf-8")

    assert dockerfile.startswith(
        "FROM debian:bookworm-slim@sha256:"
        "f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b "
        "AS bundle-verifier\n"
    )
    assert 'LABEL org.opencontainers.image.version="2.27.0"' in dockerfile
    assert (
        'LABEL io.sastsimi.codeql.bundle.sha256="'
        '8e870433e5c80d0e916c3c1aa9005fc88aab990bcdcc649fade9dfc4d7e94305"'
        in dockerfile
    )
    assert 'LABEL io.sastsimi.codeql.bundle.size="686083106"' in dockerfile
    assert (
        dockerfile.count(
            "f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b"
        )
        == 2
    )
    assert "COPY --chown=0:0 codeql-bundle-linux64.tar.gz /tmp/" in dockerfile
    assert "sha256sum --check --strict" in dockerfile
    assert (
        "8e870433e5c80d0e916c3c1aa9005fc88aab990bcdcc649fade9dfc4d7e94305" in dockerfile
    )
    assert "ADD --chown=0:0 codeql-bundle-linux64.tar.gz /opt/" in dockerfile
    assert (
        "COPY --chmod=0555 sastsimi-codeql /usr/local/bin/sastsimi-codeql" in dockerfile
    )
    assert "USER 65532:65532" in dockerfile
    assert 'ENTRYPOINT ["/usr/local/bin/sastsimi-codeql"]' in dockerfile
    assert "CMD" not in dockerfile
    for forbidden in (
        "apt-get",
        "apt ",
        "curl",
        "wget",
        "git clone",
        "http://",
        "https://",
    ):
        assert forbidden not in dockerfile


def test_builder_verifies_fixed_bundle_before_networkless_shell_free_build() -> None:
    source = _BUILDER.read_text(encoding="utf-8")
    tree = ast.parse(source)

    assert 'BUNDLE_NAME = "codeql-bundle-linux64.tar.gz"' in source
    assert "BUNDLE_SIZE = 686_083_106" in source
    expected_digest = (
        'BUNDLE_SHA256 = "'
        '8e870433e5c80d0e916c3c1aa9005fc88aab990bcdcc649fade9dfc4d7e94305"'
    )
    assert expected_digest in source
    assert all(
        value in source for value in ('"build"', '"--pull=false"', '"--network=none"')
    )
    assert "stdout=subprocess.DEVNULL" in source
    assert "stderr=subprocess.DEVNULL" in source
    assert "BUNDLE_HASH_MISMATCH" in source
    assert "BUNDLE_SIZE_MISMATCH" in source

    run_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "run"
    ]
    assert run_calls
    for call in run_calls:
        shell = next(
            (keyword.value for keyword in call.keywords if keyword.arg == "shell"), None
        )
        assert isinstance(shell, ast.Constant) and shell.value is False


def test_entrypoint_has_two_exact_modes_and_no_dynamic_command_execution() -> None:
    entrypoint = _ENTRYPOINT.read_text(encoding="utf-8")

    assert entrypoint.startswith("#!/bin/sh\nset -eu\n")
    assert 'case "$1" in' in entrypoint
    assert "analyze)" in entrypoint
    assert "probe)" in entrypoint
    assert "UNKNOWN_MODE" in entrypoint
    assert "eval" not in entrypoint
    assert 'analyze "$@"' in entrypoint
    assert 'probe "$@"' in entrypoint
    for forbidden in ("curl", "wget", "apt-get", "apk ", "dnf ", "git clone"):
        assert forbidden not in entrypoint

    assert "cp -R /input/database/. /work/database/codeql-db/" in entrypoint
    assert "/opt/codeql/codeql database analyze" in entrypoint
    assert "/work/database/codeql-db" in entrypoint
    assert "/input/query-pack" in entrypoint
    assert "--format=sarifv2.1.0" in entrypoint
    assert "--output=/work/output/result.sarif" in entrypoint
    assert "--threads=1" in entrypoint
    assert "--ram=1024" in entrypoint
    assert "1>&2" in entrypoint
    assert "cat /work/output/result.sarif" in entrypoint


def test_probe_is_version_pinned_non_sparse_and_emits_one_bounded_json_line() -> None:
    entrypoint = _ENTRYPOINT.read_text(encoding="utf-8")

    assert 'EXPECTED_CODEQL_VERSION="2.27.0"' in entrypoint
    assert "/opt/codeql/codeql version --format=terse" in entrypoint
    assert entrypoint.count('case "$1" in') >= 2
    assert 'case "$2" in' in entrypoint
    assert "dd if=/dev/zero" in entrypoint
    assert "conv=fsync" in entrypoint
    assert "truncate" not in entrypoint
    assert 'denial_code="ENOSPC"' in entrypoint
    assert 'denial_code="EDQUOT"' in entrypoint
    assert "PROBE_DENIAL_NOT_OBSERVED" in entrypoint
    assert entrypoint.count("printf '{") == 1
    assert '"schema_version":1' in entrypoint
    assert '"codeql_version":"%s"' in entrypoint
    assert '"database":{' in entrypoint
    assert '"output":{' in entrypoint


def _shell() -> str | None:
    discovered = shutil.which("sh")
    if discovered:
        return discovered
    git_shell = Path(r"C:\Program Files\Git\bin\sh.exe")
    return str(git_shell) if git_shell.is_file() else None


def test_entrypoint_has_valid_posix_shell_syntax() -> None:
    shell = _shell()
    if shell is None:
        pytest.skip("POSIX shell parser is not installed")

    result = subprocess.run(
        (shell, "-n", str(_ENTRYPOINT)),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        shell=False,
        check=False,
        timeout=10,
    )

    if b"couldn't create signal pipe" in result.stderr:
        pytest.skip("installed shell cannot run inside the Windows sandbox")

    assert result.returncode == 0, result.stderr.decode(errors="replace")
