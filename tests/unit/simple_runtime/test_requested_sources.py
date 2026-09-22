"""The requested paths are model output, so the workspace boundary must hold."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.retrieval import (
    MAX_FILE_BYTES,
    MAX_REQUESTED_FILES,
    MAX_TOTAL_BYTES,
    collect_requested_sources,
)
from sastsimi.simple_runtime.stages import ProConStage


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "backend" / "chainlit").mkdir(parents=True)
    (root / "backend" / "chainlit" / "markdown.py").write_text(
        "def get_markdown_str(root, language):\n    return None\n", encoding="utf-8"
    )
    (tmp_path / "outside.txt").write_text("host secret", encoding="utf-8")
    return root


def _paths(record: dict[str, object]) -> list[str]:
    served = record["served"]
    assert isinstance(served, list)
    return [item["path"] for item in served]


def _refusals(record: dict[str, object]) -> dict[str, str]:
    refused = record["refused"]
    assert isinstance(refused, list)
    return {item["path"]: item["reason"] for item in refused}


def test_a_requested_repository_file_is_served_with_its_text(
    workspace: Path,
) -> None:
    record = collect_requested_sources(
        ["backend/chainlit/markdown.py"], workspace=workspace
    )

    assert _paths(record) == ["backend/chainlit/markdown.py"]
    served = record["served"]
    assert isinstance(served, list)
    assert "get_markdown_str" in served[0]["content"]
    assert served[0]["line_count"] == 3


def test_every_way_out_of_the_workspace_is_refused(workspace: Path) -> None:
    escapes = [
        "../outside.txt",
        "backend/../../outside.txt",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "backend\\..\\..\\outside.txt",
    ]

    record = collect_requested_sources(escapes, workspace=workspace)

    assert _paths(record) == []
    assert set(_refusals(record)) == set(escapes)
    assert set(_refusals(record).values()) == {"PATH_OUTSIDE_REPOSITORY"}


def test_a_symlink_pointing_out_of_the_workspace_is_refused(
    workspace: Path, tmp_path: Path
) -> None:
    link = workspace / "escape.txt"
    try:
        os.symlink(tmp_path / "outside.txt", link)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks unavailable")

    record = collect_requested_sources(["escape.txt"], workspace=workspace)

    assert _paths(record) == []
    assert _refusals(record) == {"escape.txt": "PATH_OUTSIDE_REPOSITORY"}


def test_a_missing_or_non_file_path_is_reported_not_guessed(
    workspace: Path,
) -> None:
    record = collect_requested_sources(
        ["backend/chainlit/nope.py", "backend/chainlit"], workspace=workspace
    )

    assert _paths(record) == []
    assert _refusals(record) == {
        "backend/chainlit/nope.py": "NOT_FOUND",
        "backend/chainlit": "NOT_A_FILE",
    }


def test_the_file_count_is_bounded(workspace: Path) -> None:
    names = []
    for index in range(MAX_REQUESTED_FILES + 3):
        name = f"f{index}.py"
        (workspace / name).write_text("x = 1\n", encoding="utf-8")
        names.append(name)

    record = collect_requested_sources(names, workspace=workspace)

    assert len(_paths(record)) == MAX_REQUESTED_FILES
    assert set(_refusals(record).values()) == {"FILE_BUDGET_EXHAUSTED"}


def test_an_oversized_file_is_refused_rather_than_truncated(
    workspace: Path,
) -> None:
    (workspace / "big.py").write_text("x" * (MAX_FILE_BYTES + 1), encoding="utf-8")

    record = collect_requested_sources(["big.py"], workspace=workspace)

    assert _paths(record) == []
    assert _refusals(record) == {"big.py": "FILE_TOO_LARGE"}


def test_the_batch_stops_at_the_total_budget(workspace: Path) -> None:
    body = "y" * (MAX_FILE_BYTES - 1)
    names = []
    for index in range(MAX_REQUESTED_FILES):
        name = f"b{index}.py"
        (workspace / name).write_text(body, encoding="utf-8")
        names.append(name)

    record = collect_requested_sources(names, workspace=workspace)

    served_bytes = record["served_bytes"]
    assert isinstance(served_bytes, int)
    assert served_bytes <= MAX_TOTAL_BYTES
    assert "TOTAL_BUDGET_EXHAUSTED" in set(_refusals(record).values())


def test_a_binary_file_is_refused(workspace: Path) -> None:
    (workspace / "blob.bin").write_bytes(b"\xff\xfe\x00\x01")

    record = collect_requested_sources(["blob.bin"], workspace=workspace)

    assert _paths(record) == []
    assert _refusals(record) == {"blob.bin": "NOT_UTF8_TEXT"}


def test_a_repeated_or_already_supplied_path_is_read_once(workspace: Path) -> None:
    record = collect_requested_sources(
        ["backend/chainlit/markdown.py", "./backend/chainlit/markdown.py"],
        workspace=workspace,
    )
    assert _paths(record) == ["backend/chainlit/markdown.py"]

    skipped = collect_requested_sources(
        ["backend/chainlit/markdown.py"],
        workspace=workspace,
        already_supplied=["backend/chainlit/markdown.py"],
    )
    assert _paths(skipped) == []
    assert _refusals(skipped) == {}


class _RequestingClient:
    """Both agents name one file each, the way the prompt requires."""

    def __init__(self) -> None:
        self.calls = 0

    async def call(self, **kwargs: object) -> SimpleLLMCallResult:
        self.calls += 1
        wanted = (
            "backend/chainlit/markdown.py" if self.calls == 1 else "../outside.txt"
        )
        return SimpleLLMCallResult(
            value={
                "claims": ["c"],
                "evidence_refs": [],
                "limitations": ["source not read"],
                "requested_paths": [wanted],
            },
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


@pytest.mark.asyncio
async def test_pro_con_hands_the_requested_source_to_the_next_stage(
    tmp_path: Path, workspace: Path
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    stage = ProConStage(
        cast(Any, _RequestingClient()), artifacts, workspace=workspace
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )

    result = await stage(checkpoint, {})

    # Pro, Con, and the sources the two of them asked for.
    assert len(result.output_refs) == 3
    record = json.loads(artifacts.read(result.output_refs[-1]))
    assert record["kind"] == "simple_requested_sources"
    assert [item["path"] for item in record["served"]] == [
        "backend/chainlit/markdown.py"
    ]
    assert record["refused"] == [
        {"path": "../outside.txt", "reason": "PATH_OUTSIDE_REPOSITORY"}
    ]


@pytest.mark.asyncio
async def test_pro_con_without_a_workspace_serves_nothing(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    stage = ProConStage(
        cast(Any, _RequestingClient()),
        SimpleArtifactRepository(tmp_path / "data", identity),
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )

    result = await stage(checkpoint, {})

    assert len(result.output_refs) == 2
