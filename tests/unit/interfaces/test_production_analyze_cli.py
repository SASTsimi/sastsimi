from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastsimi import bootstrap
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.interfaces.cli import analyze as analyze_command
from sastsimi.interfaces.cli.main import main
from sastsimi.ports.scheduler import AnalysisStatusView, RunOutcome


class _Entrypoint:
    def __init__(self) -> None:
        self.calls: list[analyze_command.ProductionAnalyzeRequest] = []

    async def __call__(
        self, request: analyze_command.ProductionAnalyzeRequest
    ) -> RunOutcome:
        self.calls.append(request)
        return RunOutcome("analysis-1", "BLOCKED", None)


class _Application:
    def status(self, analysis_id: str) -> AnalysisStatusView:
        return AnalysisStatusView(
            analysis_id=analysis_id,
            run_status="BLOCKED",
            work_counts=(("DYNAMIC_REPRO:BLOCKED", 1),),
            cancel_requested=False,
            waiting_for=("INPUT",),
            result_ref=None,
        )

    def result(self, analysis_id: str) -> AnalysisRunResult:
        raise ValueError(f"not terminal: {analysis_id}")


def test_production_analyze_passes_only_explicit_exact_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    entrypoint = _Entrypoint()
    profile = tmp_path / "production.toml"
    repository = tmp_path / "repository"

    assert (
        main(
            [
                "--data-dir",
                str(tmp_path / "data"),
                "analyze",
                "--repo",
                str(repository),
                "--commit",
                "a" * 40,
                "--profile",
                str(profile),
                "--format",
                "json",
            ],
            production_analyze=entrypoint,
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["data"] == {
        "analysis_id": "analysis-1",
        "status": "BLOCKED",
        "result_record_id": None,
    }
    assert entrypoint.calls == [
        analyze_command.ProductionAnalyzeRequest(
            data_dir=tmp_path / "data",
            repository=str(repository),
            commit="a" * 40,
            profile=profile,
        )
    ]


@pytest.mark.parametrize(
    "arguments",
    [
        ["--repo", "repository", "--profile", "profile.toml"],
        [
            "--repo",
            "repository",
            "--commit",
            "branch-or-short-sha",
            "--profile",
            "profile.toml",
        ],
        [
            "--repo",
            "repository",
            "--commit",
            "A" * 40,
            "--profile",
            "profile.toml",
        ],
    ],
)
def test_production_analyze_rejects_missing_or_non_exact_commit(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    entrypoint = _Entrypoint()

    assert main(["analyze", *arguments], production_analyze=entrypoint) == 2

    assert entrypoint.calls == []
    assert capsys.readouterr().out == ""


def test_production_analyze_builds_the_real_composition_not_fake(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    entrypoint = _Entrypoint()

    def forbidden_fake(_data_dir: Path) -> object:
        raise AssertionError("production must not use the fake pipeline")

    def build_production() -> _Entrypoint:
        return entrypoint

    monkeypatch.setattr(bootstrap, "build_fake_pipeline", forbidden_fake)
    monkeypatch.setattr(bootstrap, "build_production_analyze", build_production)

    assert (
        main(
            [
                "--data-dir",
                str(tmp_path),
                "analyze",
                "--repo",
                "repository",
                "--commit",
                "b" * 64,
                "--profile",
                "profile.toml",
                "--format",
                "json",
            ]
        )
        == 0
    )

    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out)["data"]["analysis_id"] == "analysis-1"
    assert entrypoint.calls[0].repository == "repository"


def test_production_status_is_separate_from_demo_results(
    capsys: pytest.CaptureFixture[str],
) -> None:
    application = _Application()

    assert (
        main(
            ["status", "analysis-1", "--format", "json"],
            production_query=application,
        )
        == 0
    )

    output = json.loads(capsys.readouterr().out)
    assert output["data"]["analysis_id"] == "analysis-1"
    assert output["data"]["status"] == "BLOCKED"
    assert output["data"]["waiting_for"] == ["INPUT"]


def test_production_results_without_available_query_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def unavailable(_data_dir: Path) -> object:
        raise analyze_command.ProductionAnalyzeUnavailable

    monkeypatch.setattr(bootstrap, "build_production_query", unavailable)

    assert main(["results", "analysis-1", "--format", "json"]) == 4

    output = capsys.readouterr()
    assert output.out == ""
    assert "CAPABILITY_UNSUPPORTED" in output.err
