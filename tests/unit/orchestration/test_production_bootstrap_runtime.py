from __future__ import annotations

import hashlib
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest

from sastsimi.composition.production_bootstrap_runtime import (
    ProductionDynamicRuntimeFactory,
    ProductionStaticRuntimeFactory,
    _guarded_read,
)
from sastsimi.composition.production_composition import (
    ProductionCapabilityUnavailable,
    ProductionInstallationContext,
)
from sastsimi.composition.production_default_assembler import (
    _require_static_runtime_ports,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.ports.dto import ProcessReceipt
from tests.integration.static_quota_support import TestQuota


def test_static_runtime_supplies_configured_codeql_quota_to_default_assembler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quota = TestQuota(tmp_path / "quota", monkeypatch)
    context = cast(Any, SimpleNamespace(data_dir=tmp_path))
    ports = ProductionStaticRuntimeFactory(
        output_quota=quota,
        codeql_database_limit_bytes=131072,
    )(context)
    _require_static_runtime_ports(
        ports, cast(Any, SimpleNamespace(enabled_tools=("CODEQL",)))
    )
    assert ports.output_quota is quota
    assert ports.codeql_database_limit_bytes == 131072


def test_default_static_runtime_keeps_unconfigured_codeql_blocked(
    tmp_path: Path,
) -> None:
    ports = ProductionStaticRuntimeFactory()(
        cast(Any, SimpleNamespace(data_dir=tmp_path))
    )
    with pytest.raises(ValueError, match="PRODUCTION_CODEQL_HARD_QUOTA_REQUIRED"):
        _require_static_runtime_ports(
            ports, cast(Any, SimpleNamespace(enabled_tools=("CODEQL",)))
        )


def _write_process_receipt(
    data_dir: Path,
    *,
    action_id: str = "action-1",
    attempt_id: str = "attempt-1",
) -> tuple[object, Path]:
    attempt = data_dir / "static-execution" / "ast" / "bound-attempt"
    attempt.mkdir(parents=True)
    marker = {
        "schema_version": 1,
        "tool": "AST",
        "workspace_id": "workspace-1",
        "commit_id": "a" * 40,
        "action_id": action_id,
        "attempt_id": attempt_id,
    }
    (attempt / "sastsimi-attempt.json").write_bytes(canonical_bytes(marker))
    stdout = b'{"symbols": []}'
    stderr = b""
    (attempt / "stdout.bin").write_bytes(stdout)
    (attempt / "stderr.bin").write_bytes(stderr)
    receipt = ProcessReceipt(
        action_id=action_id,
        invocation_id="invocation-1",
        command_kind="python-ast",
        attempt_id=attempt_id,
        command_fingerprint="1" * 64,
        outcome="SUCCEEDED",
        return_code=0,
        stdout_name="stdout.bin",
        stdout_size=len(stdout),
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_name="stderr.bin",
        stderr_size=0,
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        elapsed_ms=3,
    )
    (attempt / "invocation.receipt.json").write_bytes(canonical_bytes(asdict(receipt)))
    return receipt, attempt


def _ports(data_dir: Path) -> object:
    context = cast(
        ProductionInstallationContext,
        cast(Any, SimpleNamespace(data_dir=data_dir)),
    )
    return ProductionStaticRuntimeFactory()(context)


def test_static_runtime_reads_the_exact_attempt_process_receipt(tmp_path: Path) -> None:
    receipt, _attempt = _write_process_receipt(tmp_path)

    ports = cast(Any, _ports(tmp_path))

    assert ports.process_receipts("action-1", "attempt-1") == (receipt,)


def test_static_runtime_rejects_a_missing_runtime_owned_receipt_root(
    tmp_path: Path,
) -> None:
    ports = cast(Any, _ports(tmp_path))

    with pytest.raises(ValueError, match="STATIC_PROCESS_RECEIPT_ROOT_INVALID"):
        ports.process_receipts("action-1", "attempt-1")


def test_static_runtime_rejects_a_receipt_whose_output_was_changed(
    tmp_path: Path,
) -> None:
    _receipt, attempt = _write_process_receipt(tmp_path)
    (attempt / "stdout.bin").write_bytes(b"tampered")

    ports = cast(Any, _ports(tmp_path))

    with pytest.raises(ValueError, match="STATIC_PROCESS_RECEIPT_INVALID"):
        ports.process_receipts("action-1", "attempt-1")


def test_guarded_receipt_read_allows_access_time_only_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "stdout.bin"
    target.write_bytes(b"trusted output")
    actual = target.lstat()
    first = SimpleNamespace(
        st_dev=actual.st_dev,
        st_ino=actual.st_ino,
        st_mode=actual.st_mode,
        st_size=actual.st_size,
        st_mtime_ns=actual.st_mtime_ns,
        st_nlink=actual.st_nlink,
        st_file_attributes=getattr(actual, "st_file_attributes", 0),
        st_atime_ns=1,
    )
    second = SimpleNamespace(**{**vars(first), "st_atime_ns": 2})
    original = Path.lstat
    observations = iter((first, first, second))

    def changed_atime(path: Path) -> object:
        if path == target:
            return next(observations)
        return original(path)

    monkeypatch.setattr(Path, "lstat", changed_atime)

    assert _guarded_read(target, 1024) == b"trusted output"


def test_dynamic_runtime_defers_docker_resolver_until_dynamic_use() -> None:
    calls: list[object] = []

    def resolver_factory(assembly: object) -> object:
        calls.append(assembly)
        return SimpleNamespace()

    factory = ProductionDynamicRuntimeFactory(
        docker_resolver_factory=cast(Any, resolver_factory)
    )
    captured: dict[str, object] = {}

    def build_dynamic(**kwargs: object) -> object:
        captured.update(kwargs)
        return SimpleNamespace(feature=cast(Any, object()), readiness_checks=())

    assembly = SimpleNamespace(resolved=object(), materialized=object())
    with patch(
        "sastsimi.composition.production_bootstrap_runtime."
        "build_production_dynamic_feature",
        side_effect=build_dynamic,
    ):
        built = factory(
            cast(Any, assembly),
            cast(Any, SimpleNamespace()),
            cast(Any, object()),
        )

    assert calls == []
    assert built.readiness_checks == ()
    with pytest.raises(
        ProductionCapabilityUnavailable,
        match="PRODUCTION_DOCKER_RESOLVER_INVALID",
    ):
        cast(Any, captured["docker_target_resolver"]).resolve_current(
            cast(Any, object())
        )
    assert calls == [assembly]
