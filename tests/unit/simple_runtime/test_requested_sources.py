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


def test_a_long_file_is_served_whole_rather_than_refused(
    workspace: Path,
) -> None:
    """A file is not less worth reading for being long.

    Measured on open-webui: the one file a path-traversal hypothesis named,
    ``routers/retrieval.py`` at 124 KB, was refused while four files nobody had
    asked about were served in the same batch.
    """

    (workspace / "big.py").write_text("x" * 124_000, encoding="utf-8")

    record = collect_requested_sources(["big.py"], workspace=workspace)

    assert _paths(record) == ["big.py"]
    assert _refusals(record) == {}


def test_the_batch_stops_at_the_total_budget(workspace: Path) -> None:
    body = "y" * 63_999
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
        self.saw_history: list[bool] = []

    async def call(self, **kwargs: object) -> SimpleLLMCallResult:
        # Pro and Con share this client and run at the same time, so what to
        # ask for next is decided from the prompt rather than from a counter.
        self.calls += 1
        prompt = kwargs.get("prompt")
        text = prompt if isinstance(prompt, bytes) else b""
        rounds = text.count(b'"round"')
        self.saw_history.append(b"simple_exploration_history" in text)
        if rounds == 0:
            # One file it may have, one it may not.
            wanted = ["backend/chainlit/markdown.py", "../outside.txt"]
        elif rounds == 1:
            # What the first reading made worth asking for.
            wanted = ["backend/chainlit/config.py"]
        else:
            wanted = []
        return SimpleLLMCallResult(
            value={
                "claims": [f"after {rounds} rounds"],
                "evidence_refs": [],
                "limitations": ["source not read"],
                "requested_paths": wanted,
                "requested_ast_paths": [],
            },
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


def _stage(tmp_path: Path, workspace: Path, client: object) -> tuple[Any, Any, Any]:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    stage = ProConStage(cast(Any, client), artifacts, workspace=workspace)
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )
    return stage, artifacts, checkpoint


@pytest.mark.asyncio
async def test_reading_a_file_lets_the_agent_ask_for_the_next_one(
    tmp_path: Path, workspace: Path
) -> None:
    """One request-and-read is not enough: a guard often lives elsewhere."""

    client = _RequestingClient()
    stage, artifacts, checkpoint = _stage(tmp_path, workspace, client)

    result = await stage(checkpoint, {})

    # Pro and Con only; what each of them read is inside its own artifact.
    assert len(result.output_refs) == 2
    record = json.loads(artifacts.read(result.output_refs[0]))
    rounds = record["exploration"]["rounds"]
    assert [entry["round"] for entry in rounds] == [1, 2]
    assert [item["path"] for item in rounds[0]["sources"]["served"]] == [
        "backend/chainlit/markdown.py"
    ]
    assert rounds[0]["sources"]["refused"] == [
        {"path": "../outside.txt", "reason": "PATH_OUTSIDE_REPOSITORY"}
    ]
    # The second round asked for a file the first round's reading suggested.
    assert rounds[1]["requested_paths"] == ["backend/chainlit/config.py"]


@pytest.mark.asyncio
async def test_what_was_read_is_shown_back_to_the_agent(
    tmp_path: Path, workspace: Path
) -> None:
    client = _RequestingClient()
    stage, _artifacts, checkpoint = _stage(tmp_path, workspace, client)

    await stage(checkpoint, {})

    # Exactly two openings - one per agent - and every other call is shown
    # what that agent had already read.
    assert client.saw_history.count(False) == 2
    assert client.saw_history.count(True) == client.calls - 2


@pytest.mark.asyncio
async def test_an_agent_that_asks_for_nothing_is_called_once(
    tmp_path: Path, workspace: Path
) -> None:
    class _Quiet:
        def __init__(self) -> None:
            self.calls = 0

        async def call(self, **kwargs: object) -> SimpleLLMCallResult:
            self.calls += 1
            return SimpleLLMCallResult(
                value={
                    "claims": ["settled"],
                    "evidence_refs": [],
                    "limitations": [],
                    "requested_paths": [],
                    "requested_ast_paths": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    client = _Quiet()
    stage, _artifacts, checkpoint = _stage(tmp_path, workspace, client)

    await stage(checkpoint, {})

    # Two agents, one call each.
    assert client.calls == 2
