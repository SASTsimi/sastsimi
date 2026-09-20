from __future__ import annotations

import hashlib
import json
from pathlib import Path

from sastsimi.composition.production_static_adapters import (
    _persist_container_codeql_receipt,
)
from sastsimi.static_analysis.container_codeql import ContainerCodeQLSpec
from sastsimi.static_analysis.container_codeql_runtime import (
    CodeQLContainerRunResult,
    CodeQLContainerRunStatus,
)


def test_container_codeql_result_is_persisted_as_exact_process_receipt(
    tmp_path: Path,
) -> None:
    docker = tmp_path / "docker"
    docker.write_bytes(b"docker")
    database = tmp_path / "database"
    query_pack = tmp_path / "query-pack"
    workspace = tmp_path / "workspace"
    attempt_root = tmp_path / "attempt"
    for path in (database, query_pack, workspace, attempt_root):
        path.mkdir()
    spec = ContainerCodeQLSpec(
        docker_executable=docker,
        image_digest="sha256:" + "a" * 64,
        database_source=database,
        query_pack_source=query_pack,
        workspace_root=workspace,
        action_id="action-1",
        attempt_id="attempt-1",
        user="1000:1000",
        pids_limit=64,
        memory_limit_bytes=536_870_912,
        cpu_limit_millicores=500,
        database_limit_bytes=268_435_456,
        output_limit_bytes=16_777_216,
    )
    sarif = b'{"version":"2.1.0","runs":[]}'
    result = CodeQLContainerRunResult(
        status=CodeQLContainerRunStatus.SUCCEEDED,
        raw_sarif=sarif,
        reason=None,
        image_digest=spec.image_digest,
        database_digest="sha256:" + "b" * 64,
        tracked_manifest_digest="sha256:" + "c" * 64,
        query_digest="sha256:" + "d" * 64,
    )

    _persist_container_codeql_receipt(attempt_root, spec, result, elapsed_ms=17)

    receipts = list(attempt_root.glob("*.receipt.json"))
    assert len(receipts) == 1
    value = json.loads(receipts[0].read_bytes())
    assert value["action_id"] == "action-1"
    assert value["attempt_id"] == "attempt-1"
    assert value["command_kind"] == "codeql-container-analyze"
    assert value["outcome"] == "SUCCEEDED"
    assert value["return_code"] == 0
    stdout = attempt_root / value["stdout_name"]
    stderr = attempt_root / value["stderr_name"]
    assert stdout.read_bytes() == sarif
    assert stderr.read_bytes() == b""
    assert value["stdout_sha256"] == hashlib.sha256(sarif).hexdigest()

