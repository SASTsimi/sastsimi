from __future__ import annotations

import json
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.interfaces.cli import onboarding as onboarding_command
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.interfaces.cli.onboarding import (
    run_init,
    run_prepare,
    run_requirements,
    run_status,
)
from sastsimi.orchestration.production_capabilities import production_profile_hash
from sastsimi.orchestration.production_onboarding import (
    ProductionOnboardingManifest,
)
from sastsimi.prompts.production import REQUIRED_PRODUCTION_PROMPT_ROUTES
from tests.unit.orchestration.test_production_onboarding import (
    _manifest_payload,
    _production_profile,
)


@pytest.fixture
def work_dir() -> Iterator[Path]:
    path = Path.cwd() / f".onboarding-cli-test-{uuid4()}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path)


def test_prepare_imports_exact_safe_evidence_and_status_is_ready(
    work_dir: Path,
) -> None:
    profile = _production_profile()
    manifest = ProductionOnboardingManifest.model_validate_json(
        json.dumps(_manifest_payload(Path.cwd()))
    )
    manifest_path = work_dir / "approval.json"
    manifest_path.write_text(manifest.model_dump_json(), encoding="utf-8")
    evidence_path = work_dir / "observations.json"
    evidence_path.write_bytes(b"safe evidence")

    result = run_prepare(
        work_dir / "data",
        profile=profile,
        manifest_path=manifest_path,
        evidence_paths=(evidence_path,),
        repository_root=Path.cwd(),
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
    )
    status = run_status(
        work_dir / "data",
        profile=profile,
        repository_root=Path.cwd(),
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
    )

    assert result.code == ExitCode.OK
    assert result.data == {
        "profile_hash": production_profile_hash(profile),
        "status": "READY",
    }
    assert status == result


def test_prepare_never_promotes_missing_observation_to_pass(work_dir: Path) -> None:
    profile = _production_profile()
    manifest = ProductionOnboardingManifest.model_validate_json(
        json.dumps(_manifest_payload(Path.cwd()))
    )
    manifest_path = work_dir / "approval.json"
    manifest_path.write_text(manifest.model_dump_json(), encoding="utf-8")

    result = run_prepare(
        work_dir / "data",
        profile=profile,
        manifest_path=manifest_path,
        evidence_paths=(),
        repository_root=Path.cwd(),
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
    )

    assert result.code == ExitCode.CAPABILITY_UNSUPPORTED
    assert result.data["status"] == "BLOCKED"
    assert result.data["reason_code"] == "PRODUCTION_ONBOARDING_EVIDENCE_MISSING"


def test_requirements_lists_exact_pvd_and_prompt_work_without_claiming_ready() -> None:
    result = run_requirements(_production_profile(), repository_root=Path.cwd())

    assert result.code == ExitCode.CAPABILITY_UNSUPPORTED
    assert result.data["status"] == "BLOCKED"
    assert result.data["required_pvd_tests"] == [
        f"PVD-{index:02d}" for index in range(1, 17)
    ]
    routes = result.data["required_routes"]
    assert isinstance(routes, list)
    assert len(routes) == len(REQUIRED_PRODUCTION_PROMPT_ROUTES)
    assert all(item["template_sha256"] for item in routes)


def test_prepare_does_not_publish_a_manifest_until_validation_passes(
    work_dir: Path,
) -> None:
    profile = _production_profile()
    manifest = ProductionOnboardingManifest.model_validate_json(
        json.dumps(_manifest_payload(Path.cwd()))
    )
    manifest_path = work_dir / "approval.json"
    manifest_path.write_text(manifest.model_dump_json(), encoding="utf-8")
    data_dir = work_dir / "data"

    blocked = run_prepare(
        data_dir,
        profile=profile,
        manifest_path=manifest_path,
        evidence_paths=(),
        repository_root=Path.cwd(),
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
    )
    assert blocked.code == ExitCode.CAPABILITY_UNSUPPORTED
    assert not (data_dir / "onboarding" / "profiles").exists()

    evidence_path = work_dir / "observations.json"
    evidence_path.write_bytes(b"safe evidence")
    retried = run_prepare(
        data_dir,
        profile=profile,
        manifest_path=manifest_path,
        evidence_paths=(evidence_path,),
        repository_root=Path.cwd(),
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
    )

    assert retried.code == ExitCode.OK


def test_init_writes_pending_operator_plan_with_real_probe_commands(
    work_dir: Path,
) -> None:
    profile = _production_profile()
    output_dir = work_dir / "operator-plan"

    result = run_init(
        output_dir,
        profile=profile,
        repository_root=Path.cwd(),
    )

    assert result.code == ExitCode.OK
    assert result.data["status"] == "PREPARATION_REQUIRED"
    plan_path = Path(str(result.data["plan_path"]))
    assert plan_path == output_dir / "onboarding-plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan["profile_hash"] == production_profile_hash(profile)
    assert plan["status"] == "PREPARATION_REQUIRED"
    assert {item["kind"] for item in plan["capability_probes"]} == {
        "CODEQL",
        "DOCKER",
        "GIT",
        "OPENAI_API",
        "OPENGREP",
        "PYTHON_AST",
        "PYTHON_RUNTIME",
    }
    openai = next(
        item for item in plan["capability_probes"] if item["kind"] == "OPENAI_API"
    )
    assert openai["argv"][-4:] == [
        "--model",
        "gpt-test",
        "--credential-ref",
        "env:OPENAI_API_KEY",
    ]
    assert all(item["status"] == "NOT_RUN" for item in plan["capability_probes"])
    assert all(item["result"] == "PENDING" for item in plan["pvd_checks"])
    assert all(item["decision"] == "PENDING" for item in plan["route_reviews"])
    assert '"PASS"' not in plan_path.read_text(encoding="utf-8")
    assert not (output_dir / "production-onboarding.json").exists()


def test_init_refuses_to_overwrite_an_existing_operator_plan(work_dir: Path) -> None:
    output_dir = work_dir / "operator-plan"
    output_dir.mkdir()
    plan_path = output_dir / "onboarding-plan.json"
    plan_path.write_text("operator-owned", encoding="utf-8")

    result = run_init(
        output_dir,
        profile=_production_profile(),
        repository_root=Path.cwd(),
    )

    assert result.code == ExitCode.CONFIG_ERROR
    assert result.data == {
        "reason_code": "ONBOARDING_PLAN_ALREADY_EXISTS",
        "status": "BLOCKED",
    }
    assert plan_path.read_text(encoding="utf-8") == "operator-owned"


def test_main_exposes_onboarding_init_without_marking_capabilities_ready(
    work_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile = _production_profile()
    output_dir = work_dir / "operator-plan"
    monkeypatch.setattr(
        "sastsimi.interfaces.cli.main.load_production_profile",
        lambda _path: profile,
    )

    assert main(
        [
            "onboarding",
            "init",
            "--profile",
            "production.toml",
            "--output-dir",
            str(output_dir),
            "--format",
            "json",
        ]
    ) == int(ExitCode.OK)

    output = json.loads(capsys.readouterr().out)
    assert output["command"] == "onboarding init"
    assert output["data"]["status"] == "PREPARATION_REQUIRED"
    assert (output_dir / "onboarding-plan.json").is_file()


def test_main_exposes_explicit_onboarding_status_command(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile = _production_profile()
    calls: list[tuple[Path, ProductionProfile]] = []

    monkeypatch.setattr(
        "sastsimi.interfaces.cli.main.load_production_profile",
        lambda _path: profile,
    )

    def status(
        data_dir: Path,
        *,
        profile: ProductionProfile,
        repository_root: Path,
        clock: object,
    ) -> onboarding_command.OnboardingCommandResult:
        del repository_root, clock
        calls.append((data_dir, profile))
        return onboarding_command.OnboardingCommandResult(
            ExitCode.CAPABILITY_UNSUPPORTED,
            {"status": "BLOCKED", "reason_code": "PROVIDER_TERMS_APPROVAL_STALE"},
        )

    monkeypatch.setattr(onboarding_command, "run_status", status)

    assert main(
        [
            "--data-dir",
            "operator-data",
            "onboarding",
            "status",
            "--profile",
            "production.toml",
            "--format",
            "json",
        ]
    ) == int(ExitCode.CAPABILITY_UNSUPPORTED)
    assert calls and calls[0][1] == profile
    output = json.loads(capsys.readouterr().out)
    assert output["data"]["reason_code"] == "PROVIDER_TERMS_APPROVAL_STALE"
