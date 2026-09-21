from __future__ import annotations

from io import StringIO
from typing import Literal

from sastsimi.interfaces.cli.progress import ProgressRenderer
from sastsimi.progress.models import ProgressSnapshot


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
