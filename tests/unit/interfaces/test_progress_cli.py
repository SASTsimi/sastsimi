from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from io import StringIO
from typing import Literal

from sastsimi.interfaces.cli.progress import ProgressRenderer
from sastsimi.progress.models import ProgressSnapshot


@dataclass(frozen=True)
class _Event:
    event_id: str = "event-1"
    status: str = "SUCCEEDED"
    stage: str = "PRO_CON_DONE"
    agent_role: str = "Pro Agent"
    tool_name: str | None = "opengrep"
    summary_ko: str = "근거를 저장했습니다."
    started_at: datetime = datetime(2026, 1, 1, tzinfo=UTC)


def _snapshot(
    percent: int,
    *,
    status: Literal["RUNNING", "BLOCKED", "FAILED", "COMPLETE"] = "RUNNING",
) -> ProgressSnapshot:
    return ProgressSnapshot(
        analysis_id="analysis-1",
        status=status,
        completed_units=percent // 10,
        known_units=10,
        percent=percent,
        current_stage="PRO_CON_DONE",
        current_hypothesis_id="hypothesis-1",
    )


def test_tty_progress_bar_renders_truthful_percent_without_json() -> None:
    stream = StringIO()
    renderer = ProgressRenderer(stream=stream, is_tty=True, width=10)

    renderer.render(_snapshot(40))
    renderer.render(_snapshot(100, status="COMPLETE"))

    output = stream.getvalue()
    assert "[████------]" in output
    assert "40%" in output
    assert "100%" in output
    assert '"percent"' not in output


def test_non_tty_progress_only_emits_stage_transitions() -> None:
    stream = StringIO()
    renderer = ProgressRenderer(stream=stream, is_tty=False)

    renderer.render(_snapshot(10))
    renderer.render(_snapshot(20))
    renderer.render(
        _snapshot(30).model_copy(update={"current_stage": "POC_EXECUTION_DONE"})
    )

    assert stream.getvalue().count("PRO_CON_DONE") == 1
    assert stream.getvalue().count("POC_EXECUTION_DONE") == 1


def test_progress_is_appended_to_analysis_log_without_terminal_coloring(
    tmp_path,
) -> None:
    stream = StringIO()
    renderer = ProgressRenderer(
        stream=stream,
        is_tty=True,
        log_dir=tmp_path,
    )

    renderer.render(_snapshot(40))
    renderer.render(_snapshot(100, status="COMPLETE"))

    log = (tmp_path / "analysis-1.log").read_text(encoding="utf-8")
    assert "status=RUNNING stage=PRO_CON_DONE" in log
    assert "status=COMPLETE stage=PRO_CON_DONE" in log
    assert "hypothesis=hypothesis-1" in log
    assert "\033[" not in log


def test_progress_log_rejects_unsafe_analysis_path(tmp_path) -> None:
    renderer = ProgressRenderer(
        stream=StringIO(),
        is_tty=False,
        log_dir=tmp_path,
    )

    renderer.render(_snapshot(10).model_copy(update={"analysis_id": "../escape"}))

    assert not list(tmp_path.iterdir())


def test_progress_renders_agent_tool_event_once_and_saves_it(tmp_path) -> None:
    stream = StringIO()
    renderer = ProgressRenderer(
        stream=stream,
        is_tty=False,
        log_dir=tmp_path,
        event_reader=lambda _analysis_id: (_Event(),),
    )

    renderer.render(_snapshot(10))
    renderer.render(_snapshot(20))

    assert stream.getvalue().count("Pro Agent · tool=opengrep") == 1
    log = (tmp_path / "analysis-1.log").read_text(encoding="utf-8")
    assert log.count('"event":"event-1"') == 1
    assert '"agent":"Pro Agent","tool":"opengrep"' in log
