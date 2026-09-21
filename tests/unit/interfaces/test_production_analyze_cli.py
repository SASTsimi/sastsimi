from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from sastsimi import bootstrap
from sastsimi.composition.production_default_assembler import (
    ProductionStaticRuntimePorts,
    _require_static_runtime_ports,
)
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.interfaces.cli import analyze as analyze_command
from sastsimi.interfaces.cli.main import main
from sastsimi.orchestration.production_provisioning import StaticAnalysisProvisioning
from sastsimi.ports.scheduler import (
    AnalysisStatusView,
    RunDisposition,
    RunOutcome,
    WorkFailureView,
)
from sastsimi.ports.static_tool import ProductionStaticOutputQuotaPort


class _Entrypoint:
    def __init__(self, disposition: RunDisposition = "BLOCKED") -> None:
        self.calls: list[analyze_command.ProductionAnalyzeRequest] = []
        self.disposition = disposition

    async def __call__(
        self, request: analyze_command.ProductionAnalyzeRequest
    ) -> RunOutcome:
        self.calls.append(request)
        return RunOutcome("analysis-1", self.disposition, None)


@pytest.mark.parametrize("quota_supplied", [False, True])
def test_required_codeql_readiness_is_exit_four_without_a_verdict(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], quota_supplied: bool
) -> None:
    class RequiredCodeQL:
        async def __call__(
            self, request: analyze_command.ProductionAnalyzeRequest
        ) -> RunOutcome:
            ports = ProductionStaticRuntimePorts(
                process_receipts=lambda _action, _attempt: None,
                cancellation_observation=lambda _request, _profile: None,
                dispatch_state=lambda _attempt: None,
                attempt_dispatch=lambda _attempt: None,
                output_quota=cast(ProductionStaticOutputQuotaPort, object())
                if quota_supplied
                else None,
                codeql_database_limit_bytes=4096 if quota_supplied else None,
            )
            _require_static_runtime_ports(
                ports,
                StaticAnalysisProvisioning.model_construct(
                    enabled_tools=("AST", "CODEQL")
                ),
            )
            raise AssertionError(
                "Unavailable CodeQL must stop before any tool work or result"
            )

    assert (
        main(
            [
                "--data-dir",
                str(tmp_path),
                "analyze",
                "--repo",
                "repository",
                "--commit",
                "a" * 40,
                "--profile",
                "profile.toml",
                "--format",
                "json",
            ],
            production_analyze=RequiredCodeQL(),
        )
        == 4
    )
    output = capsys.readouterr()
    assert output.out == ""
    wire = json.loads(output.err)
    assert wire["command"] == "analyze"
    assert wire["code"] == "CAPABILITY_UNSUPPORTED"
    assert (
        wire["data"]["reason_code"]
        == "PRODUCTION_CODEQL_SAFE_PREREQUISITES_UNAVAILABLE"
    )
    assert set(wire["data"]) == {"message", "reason_code"}


class _Application:
    def status(self, analysis_id: str) -> AnalysisStatusView:
        return AnalysisStatusView(
            analysis_id=analysis_id,
            run_status="BLOCKED",
            work_counts=(("DYNAMIC_REPRO:BLOCKED", 1),),
            cancel_requested=False,
            waiting_for=("INPUT",),
            result_ref=None,
            failures=(
                WorkFailureView(
                    work_id="dynamic-1",
                    work_type="DYNAMIC_REPRO",
                    status="BLOCKED",
                    stop_reason="SANDBOX_CAPABILITY_MISSING",
                    error_ids=(),
                    waiting_for=("INPUT",),
                ),
            ),
        )

    def result(self, analysis_id: str) -> AnalysisRunResult:
        del analysis_id
        raise ValueError("RESULT_NOT_TERMINAL")


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
        == 5
    )

    output = json.loads(capsys.readouterr().err)
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


def test_production_analyze_builds_the_real_composition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    entrypoint = _Entrypoint()

    def build_production() -> _Entrypoint:
        return entrypoint

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
        == 5
    )

    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err)["data"]["analysis_id"] == "analysis-1"
    assert entrypoint.calls[0].repository == "repository"


@pytest.mark.parametrize(
    ("disposition", "expected_exit_code"),
    [
        ("TERMINAL", 0),
        ("BLOCKED", 5),
        ("FAILED", 6),
        ("CANCELLED", 7),
    ],
)
def test_production_analyze_maps_run_disposition_to_process_exit_code(
    disposition: RunDisposition,
    expected_exit_code: int,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    entrypoint = _Entrypoint(disposition)

    assert (
        main(
            [
                "--data-dir",
                str(tmp_path / "data"),
                "analyze",
                "--repo",
                "repository",
                "--commit",
                "d" * 40,
                "--profile",
                "profile.toml",
                "--format",
                "json",
            ],
            production_analyze=entrypoint,
        )
        == expected_exit_code
    )

    captured = capsys.readouterr()
    wire = captured.out if expected_exit_code == 0 else captured.err
    assert json.loads(wire)["data"]["status"] == disposition


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
    assert output["data"]["failures"] == [
        {
            "work_id": "dynamic-1",
            "work_type": "DYNAMIC_REPRO",
            "status": "BLOCKED",
            "stop_reason": "SANDBOX_CAPABILITY_MISSING",
            "error_ids": [],
            "waiting_for": ["INPUT"],
        }
    ]


def test_production_unavailable_prints_only_the_safe_reason_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class _UnavailableEntrypoint:
        async def __call__(
            self, request: analyze_command.ProductionAnalyzeRequest
        ) -> RunOutcome:
            del request
            raise analyze_command.ProductionAnalyzeUnavailable(
                "PRODUCTION_PROVIDER_APPROVAL_INCOMPLETE"
            )

    assert (
        main(
            [
                "--data-dir",
                "data",
                "analyze",
                "--repo",
                "repository",
                "--commit",
                "c" * 40,
                "--profile",
                "profile.toml",
                "--format",
                "json",
            ],
            production_analyze=_UnavailableEntrypoint(),
        )
        == 4
    )
    output = json.loads(capsys.readouterr().err)
    assert output["data"]["reason_code"] == ("PRODUCTION_PROVIDER_APPROVAL_INCOMPLETE")


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


def test_production_results_nonterminal_uses_incomplete_exit_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            ["results", "analysis-1", "--format", "json"],
            production_query=_Application(),
        )
        == 8
    )

    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err)["code"] == "RESULT_INCOMPLETE"


def test_production_results_reference_mismatch_uses_integrity_exit_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class _MismatchedApplication(_Application):
        def result(self, analysis_id: str) -> AnalysisRunResult:
            del analysis_id
            raise ValueError("ANALYSIS_RESULT_EXACT_REF_MISMATCH")

    assert (
        main(
            ["results", "analysis-1", "--format", "json"],
            production_query=_MismatchedApplication(),
        )
        == 9
    )

    output = capsys.readouterr()
    assert output.out == ""
    assert json.loads(output.err)["code"] == "INTEGRITY_ERROR"
