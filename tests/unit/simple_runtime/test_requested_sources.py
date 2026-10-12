from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.retrieval import collect_requested_sources


def _pinned_commit(workspace: Path, files: dict[str, str]) -> str:
    workspace.mkdir()
    subprocess.run(("git", "init", "-q", str(workspace)), check=True)
    for name, content in files.items():
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    subprocess.run(("git", "-C", str(workspace), "add", "."), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "pinned",
        ),
        check=True,
    )
    return subprocess.check_output(
        ("git", "-C", str(workspace), "rev-parse", "HEAD"), text=True
    ).strip()


def test_pinned_source_retries_one_git_timeout_without_using_partial_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[tuple[str, ...]] = []
    object_id = "a" * 40

    def fake_run(
        command: tuple[str, ...], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        commands.append(command)
        assert kwargs["timeout"] == 10
        if "ls-tree" in command:
            if sum("ls-tree" in item for item in commands) == 1:
                raise subprocess.TimeoutExpired(
                    command,
                    10,
                    output=b"100644 blob " + object_id.encode() + b"\twrong.py\0",
                )
            output = b"100644 blob " + object_id.encode() + b"\tapp.py\0"
        elif command[-2:] == ("-s", object_id):
            output = b"6\n"
        elif command[-2:] == ("blob", object_id):
            output = b"safe\n"
        else:
            raise AssertionError(f"unexpected Git command: {command}")
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b"")

    monkeypatch.setattr("sastsimi.simple_runtime.retrieval.subprocess.run", fake_run)

    result = collect_requested_sources(
        ("app.py",),
        workspace=tmp_path,
        tracked=("app.py",),
        pinned_commit="b" * 40,
    )

    assert result["served"] == [{"path": "app.py", "content": "safe\n"}]
    assert result["refused"] == []
    assert sum("ls-tree" in command for command in commands) == 2
    assert len(commands) == 4


def test_pinned_source_stops_after_repeated_git_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = 0

    def fake_run(
        command: tuple[str, ...], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal attempts
        attempts += 1
        raise subprocess.TimeoutExpired(command, 10, output=b"untrusted partial")

    monkeypatch.setattr("sastsimi.simple_runtime.retrieval.subprocess.run", fake_run)

    result = collect_requested_sources(
        ("app.py",),
        workspace=tmp_path,
        tracked=("app.py",),
        pinned_commit="b" * 40,
    )

    assert result["served"] == []
    assert result["refused"] == [
        {"path": "app.py", "reason": "PINNED_SOURCE_UNAVAILABLE"}
    ]
    assert attempts == 2


@pytest.mark.parametrize(
    ("returncode", "output"),
    (
        (1, b""),
        (0, b"100644 blob\tapp.py\0"),
    ),
)
def test_pinned_source_does_not_retry_non_timeout_or_malformed_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    output: bytes,
) -> None:
    attempts = 0

    def fake_run(
        command: tuple[str, ...], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal attempts
        attempts += 1
        return subprocess.CompletedProcess(
            command, returncode, stdout=output, stderr=b""
        )

    monkeypatch.setattr("sastsimi.simple_runtime.retrieval.subprocess.run", fake_run)

    result = collect_requested_sources(
        ("app.py",),
        workspace=tmp_path,
        tracked=("app.py",),
        pinned_commit="b" * 40,
    )

    assert result["served"] == []
    assert result["refused"] == [
        {"path": "app.py", "reason": "PINNED_SOURCE_UNAVAILABLE"}
    ]
    assert attempts == 1


def test_host_paths_and_bad_spans_are_refused(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("first\nsecond\n", encoding="utf-8")
    result = collect_requested_sources(
        (
            "../secret",
            "C:\\Users\\secret",
            "\\\\host\\share",
            "app.py:0-1",
            "app.py:5-6",
        ),
        workspace=tmp_path,
        tracked=("app.py",),
    )

    assert result["served"] == []
    assert len(result["refused"]) == 5


def test_only_tracked_in_root_lines_are_served(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("first\nsecond\n", encoding="utf-8")
    (tmp_path / "local.env").write_text("SECRET=hidden\n", encoding="utf-8")
    result = collect_requested_sources(
        ("app.py:2-2", "local.env"), workspace=tmp_path, tracked=("app.py",)
    )

    assert len(result["served"]) == 1
    assert result["served"][0]["content"] == "2|second"
    assert result["refused"][0]["reason"] == "NOT_TRACKED"


def test_outside_symlink_is_refused(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-source.txt"
    outside.write_text("private", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        return
    result = collect_requested_sources(
        ("link.txt",), workspace=tmp_path, tracked=("link.txt",)
    )
    assert result["served"] == []
    assert result["refused"][0]["reason"] == "PATH_OUTSIDE_REPOSITORY"


def test_tracked_symlink_to_untracked_local_file_is_refused(tmp_path: Path) -> None:
    local = tmp_path / "local.env"
    local.write_text("SECRET=hidden", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(local)
    except OSError:
        return
    result = collect_requested_sources(
        ("link.txt",), workspace=tmp_path, tracked=("link.txt",)
    )
    assert result["served"] == []


def test_symlink_classification_is_enforced_without_windows_privilege(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = tmp_path / "link.txt"
    link.write_text("SECRET=hidden", encoding="utf-8")
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == link or original(path))

    result = collect_requested_sources(
        ("link.txt",), workspace=tmp_path, tracked=("link.txt",)
    )

    assert result["served"] == []


def test_oversized_source_is_refused_before_reading_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "large.py"
    source.write_bytes(b"x" * 1_000)
    original = Path.read_bytes

    def guarded_read(path: Path) -> bytes:
        if path == source:
            raise AssertionError("oversized source content should not be read")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read)

    result = collect_requested_sources(
        ("large.py",),
        workspace=tmp_path,
        tracked=("large.py",),
        max_total_bytes=100,
    )

    assert result["served"] == []
    assert result["refused"] == [
        {"path": "large.py", "reason": "TOTAL_BUDGET_EXHAUSTED"}
    ]


def test_requested_path_count_limit_refuses_extra_files(tmp_path: Path) -> None:
    (tmp_path / "first.py").write_text("first = 1\n", encoding="utf-8")
    (tmp_path / "second.py").write_text("second = 2\n", encoding="utf-8")

    result = collect_requested_sources(
        ("first.py", "second.py"),
        workspace=tmp_path,
        tracked=("first.py", "second.py"),
        max_requests=1,
    )

    assert [item["path"] for item in result["served"]] == ["first.py"]
    assert result["refused"] == [
        {"path": "second.py", "reason": "REQUEST_LIMIT_EXCEEDED"}
    ]


def test_escaped_source_never_truncates_prompt_artifact(tmp_path: Path) -> None:
    (tmp_path / "newlines.py").write_bytes(b"\n" * 128_000)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)

    result = collect_requested_sources(
        ("newlines.py",)
        + tuple(f"missing-{index}-" + "x" * 220 for index in range(31)),
        workspace=tmp_path,
        tracked=("newlines.py",),
        max_total_bytes=128_000,
        max_requests=32,
        max_artifact_bytes=240_000,
    )
    ref = artifacts.put_json(result)
    context = json.loads(artifacts.prompt_context((ref,)))

    assert context["exact_inputs"][0]["data"]["kind"] == "simple_requested_sources"
    assert result["served"] == []
    assert len(result["refused"]) == 32
    assert result["refused"][-1] == {
        "path": "newlines.py",
        "reason": "PROMPT_BUDGET_EXHAUSTED",
    }


def test_large_pinned_python_source_keeps_relation_and_class_as_partial(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "repo"
    models = (
        "class Ticket:\n"
        "    kbitem = models.ForeignKey(\n"
        '        "KBItem", on_delete=models.CASCADE\n'
        "    )\n" + "# unrelated source context\n" * 2500 + "class KBItem:\n"
        "    pass\n"
    )
    commit = _pinned_commit(
        workspace,
        {"urls.py": "# route\n" * 1200, "models.py": models},
    )
    # An uncommitted edit must not leak into the pinned excerpt.
    (workspace / "models.py").write_text("class WrongVersion: pass\n", encoding="utf-8")

    result = collect_requested_sources(
        ("urls.py", "models.py"),
        workspace=workspace,
        tracked=("urls.py", "models.py"),
        pinned_commit=commit,
        max_total_bytes=128_000,
        max_artifact_bytes=16_000,
    )

    models_result = next(
        item for item in result["served"] if item["path"] == "models.py"
    )
    assert models_result["partial"] is True
    assert "kbitem = models.ForeignKey(" in models_result["content"]
    assert '"KBItem"' in models_result["content"]
    assert "class KBItem:" in models_result["content"]
    assert "WrongVersion" not in models_result["content"]
    assert (
        models_result["source_sha256"]
        == hashlib.sha256(models.encode("utf-8")).hexdigest()
    )
    assert models_result["omitted_line_count"] > 0
    assert models_result["included_line_ranges"]
    assert models_result["omitted_line_ranges"]
    assert {item["path"] for item in result["refused"]} == set()


def test_pinned_line_span_charges_only_returned_source_bytes(tmp_path: Path) -> None:
    workspace = tmp_path / "repo"
    source = "# filler\n" * 1500 + "class Needed:\n    pass\n"
    commit = _pinned_commit(workspace, {"large.py": source})

    result = collect_requested_sources(
        ("large.py:1501-1502",),
        workspace=workspace,
        tracked=("large.py",),
        pinned_commit=commit,
        max_total_bytes=100,
    )

    assert result["served"] == [
        {"path": "large.py:1501-1502", "content": "1501|class Needed:\n1502|    pass"}
    ]
    assert result["served_bytes"] == len(result["served"][0]["content"].encode())
    assert result["refused"] == []


def test_line_span_budget_uses_redacted_returned_bytes(tmp_path: Path) -> None:
    (tmp_path / "path.py").write_text(str(tmp_path) + "\n", encoding="utf-8")
    expected = "1|[REDACTED:HOST_ABSOLUTE_PATH]"

    result = collect_requested_sources(
        ("path.py:1-1",),
        workspace=tmp_path,
        tracked=("path.py",),
        max_total_bytes=len(expected.encode()),
    )

    assert result["served"] == [{"path": "path.py:1-1", "content": expected}]
    assert result["served_bytes"] == len(expected.encode())


def test_pinned_python_larger_than_total_budget_is_served_as_partial(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "repo"
    source = (
        "class Ticket:\n"
        '    kbitem = models.ForeignKey("KBItem", on_delete=models.CASCADE)\n'
        + "# source not needed for schema outline\n"
        * 4000
        + "class KBItem:\n"
        "    pass\n"
    )
    assert len(source.encode()) > 128_000
    commit = _pinned_commit(workspace, {"models.py": source})

    result = collect_requested_sources(
        ("models.py",),
        workspace=workspace,
        tracked=("models.py",),
        pinned_commit=commit,
        max_total_bytes=128_000,
        max_artifact_bytes=96_000,
    )

    assert len(result["served"]) == 1
    excerpt = result["served"][0]
    assert excerpt["partial"] is True
    assert "kbitem = models.ForeignKey" in excerpt["content"]
    assert "class KBItem:" in excerpt["content"]
    assert result["served_bytes"] < 16_384
    assert excerpt["omitted_line_count"] > 4000
    assert result["refused"] == []


def test_artifact_budget_projects_large_source_before_refusing_later_files(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "repo"
    urls = "# route to ticket view\n" * 520
    public_views = "# public ticket view\n" * 540
    models = (
        "class Ticket:\n"
        '    kbitem = models.ForeignKey("KBItem", on_delete=models.CASCADE)\n'
        + "# unrelated model details\n" * 3000
        + "class KBItem:\n    pass\n"
    )
    update_ticket = "# ticket update flow\n" * 530
    settings = "# application settings\n" * 510
    files = {
        "helpdesk/urls.py": urls,
        "helpdesk/views/public.py": public_views,
        "helpdesk/models.py": models,
        "helpdesk/update_ticket.py": update_ticket,
        "config/settings.py": settings,
    }
    assert 96_000 < sum(len(value.encode()) for value in files.values()) < 128_000
    commit = _pinned_commit(workspace, files)

    result = collect_requested_sources(
        tuple(files),
        workspace=workspace,
        tracked=tuple(files),
        pinned_commit=commit,
        max_total_bytes=128_000,
        max_artifact_bytes=96_000,
    )

    assert [item["path"] for item in result["served"]] == list(files)
    assert result["refused"] == []
    assert result["served"][2]["partial"] is True
    assert (
        result["served"][2]["source_sha256"]
        == hashlib.sha256(models.encode()).hexdigest()
    )
    for item, source in zip(result["served"], files.values(), strict=True):
        if item["path"] != "helpdesk/models.py":
            assert item["content"] == source
