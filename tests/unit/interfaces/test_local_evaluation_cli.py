from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi import bootstrap
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.interfaces.cli import local_evaluation as command
from sastsimi.interfaces.cli.main import main
from sastsimi.interfaces.cli.result import project as project_result
from sastsimi.interfaces.cli.status import project as project_status
from sastsimi.ports.scheduler import AnalysisStatusView, RunOutcome


class _Entrypoint:
    def __init__(self) -> None:
        self.calls: list[command.LocalEvaluationAnalyzeRequest] = []
        self.resume_calls: list[command.LocalEvaluationResumeRequest] = []

    async def __call__(
        self, request: command.LocalEvaluationAnalyzeRequest
    ) -> RunOutcome:
        self.calls.append(request)
        return RunOutcome("analysis-local-1", "TERMINAL", None)

    async def resume(
        self, request: command.LocalEvaluationResumeRequest
    ) -> RunOutcome:
        self.resume_calls.append(request)
        return RunOutcome(request.analysis_id, "BLOCKED", None)

def test_local_evaluation_uses_shipped_composition_when_not_injected(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrypoint = _Entrypoint()
    builds: list[str] = []

    def build() -> _Entrypoint:
        builds.append("built")
        return entrypoint

    monkeypatch.setattr(
        bootstrap,
        "build_local_evaluation_analyze",
        cast(object, build),
        raising=False,
    )

    assert (
        main(
            [
                "--data-dir",
                str(tmp_path / "data"),
                "evaluate",
                "analyze",
                "--repo",
                "https://example.invalid/repository.git",
                "--commit",
                "a" * 40,
                "--profile",
                str(tmp_path / "local-evaluation.toml"),
                "--format",
                "json",
            ]
        )
        == 0
    )

    assert builds == ["built"]
    assert len(entrypoint.calls) == 1
    assert json.loads(capsys.readouterr().out)["data"]["purpose"] == (
        "LOCAL_EVALUATION"
    )


def test_local_evaluation_analyze_is_explicitly_not_production(
    tmp_path: Path,
    capsys: object,
) -> None:
    entrypoint = _Entrypoint()
    profile = tmp_path / "local-evaluation.toml"

    assert (
        main(
            [
                "--data-dir",
                str(tmp_path / "data"),
                "evaluate",
                "analyze",
                "--repo",
                "https://example.invalid/repository.git",
                "--commit",
                "a" * 40,
                "--profile",
                str(profile),
                "--format",
                "json",
            ],
            local_evaluation_analyze=entrypoint,
        )
        == 0
    )

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    output = json.loads(captured.out)
    assert output["command"] == "evaluate analyze"
    assert output["data"] == {
        "analysis_id": "analysis-local-1",
        "status": "TERMINAL",
        "result_record_id": None,
        "purpose": "LOCAL_EVALUATION",
        "production_ready": False,
    }
    assert captured.err == ""
    assert entrypoint.calls == [
        command.LocalEvaluationAnalyzeRequest(
            data_dir=tmp_path / "data",
            repository="https://example.invalid/repository.git",
            commit="a" * 40,
            profile=profile,
        )
    ]


def test_local_evaluation_rejects_non_exact_commit_before_calling_entrypoint(
    capsys: object,
) -> None:
    entrypoint = _Entrypoint()

    assert (
        main(
            [
                "evaluate",
                "analyze",
                "--repo",
                "repository",
                "--commit",
                "main",
                "--profile",
                "local-evaluation.toml",
                "--format",
                "json",
            ],
            local_evaluation_analyze=entrypoint,
        )
        == 2
    )
    assert entrypoint.calls == []
    assert capsys.readouterr().out == ""  # type: ignore[attr-defined]


def test_local_evaluation_resume_is_explicit_and_single_shot(
    tmp_path: Path,
    capsys: object,
) -> None:
    entrypoint = _Entrypoint()
    profile = tmp_path / "local-evaluation.toml"

    assert (
        main(
            [
                "--data-dir",
                str(tmp_path / "data"),
                "evaluate",
                "resume",
                "analysis-local-1",
                "--profile",
                str(profile),
                "--format",
                "json",
            ],
            local_evaluation_analyze=entrypoint,
        )
        == 5
    )

    output = json.loads(capsys.readouterr().err)  # type: ignore[attr-defined]
    assert output["command"] == "evaluate resume"
    assert output["data"]["status"] == "BLOCKED"
    assert output["data"]["resume_mode"] == "FAILED_COHORT_ONLY"
    assert entrypoint.resume_calls == [
        command.LocalEvaluationResumeRequest(
            data_dir=tmp_path / "data",
            analysis_id="analysis-local-1",
            profile=profile,
        )
    ]


def test_local_evaluation_status_and_results_remain_clearly_labelled() -> None:
    status = project_status(
        AnalysisStatusView(
            analysis_id="analysis-local-1",
            run_status="RUNNING",
            work_counts=(),
            cancel_requested=False,
            waiting_for=(),
            result_ref=None,
            purpose="LOCAL_EVALUATION",
        )
    )
    result = project_result(
        AnalysisRunResult.model_construct(
            meta=SimpleNamespace(analysis_id="analysis-local-1"),
            purpose="LOCAL_EVALUATION",
            status="FAILED",
            program_id="program-1",
            workspace_id=None,
            commit_id=None,
            hypothesis_counts={},
            verdict_counts={},
            gate_counts={},
            finding_refs=(),
            report_draft_refs=(),
            elapsed_ms=1,
        ),
        output_format="summary",
    )

    for projection in (status, result):
        assert projection["purpose"] == "LOCAL_EVALUATION"
        assert projection["production_ready"] is False
