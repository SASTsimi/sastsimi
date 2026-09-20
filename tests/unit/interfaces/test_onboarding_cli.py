from __future__ import annotations

import json
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.contracts.refs import HostConfigurationRef
from sastsimi.interfaces.cli import onboarding as onboarding_command
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import _approved_probe_resolver, main
from sastsimi.interfaces.cli.onboarding import (
    run_compose,
    run_init,
    run_prepare,
    run_prepare_bundle,
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
    _provisioning_payload,
)
from tests.unit.orchestration.test_production_provisioning import (
    _artifact_templates,
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


def test_main_exposes_onboarding_compose_with_explicit_inputs(
    work_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile = _production_profile()
    calls: list[dict[str, object]] = []

    def resolver(_probe_id: str) -> tuple[str, HostConfigurationRef]:
        raise AssertionError("compose command mock must not resolve probes")

    monkeypatch.setattr(
        "sastsimi.interfaces.cli.main.load_production_profile",
        lambda _path: profile,
    )
    monkeypatch.setattr(
        "sastsimi.interfaces.cli.main._approved_probe_resolver",
        lambda *_args, **_kwargs: resolver,
    )

    def compose(
        data_dir: Path, **values: object
    ) -> onboarding_command.OnboardingCommandResult:
        calls.append({"data_dir": data_dir, **values})
        return onboarding_command.OnboardingCommandResult(
            ExitCode.OK, {"status": "COMPOSED"}
        )

    monkeypatch.setattr(onboarding_command, "run_compose", compose)
    output = work_dir / "bundle"
    assert main(
        [
            "--data-dir",
            str(work_dir / "data"),
            "onboarding",
            "compose",
            "--profile",
            "production.toml",
            "--approval-input",
            "approval.json",
            "--slot-template",
            "slot.json",
            "--evidence",
            "evidence.json",
            "--output-dir",
            str(output),
            "--format",
            "json",
        ]
    ) == int(ExitCode.OK)

    assert calls[0]["approval_input_path"] == Path("approval.json")
    assert calls[0]["slot_template_paths"] == (Path("slot.json"),)
    assert calls[0]["evidence_paths"] == (Path("evidence.json"),)
    assert calls[0]["output_dir"] == output
    assert calls[0]["resolve_probe"] is resolver
    assert json.loads(capsys.readouterr().out)["data"]["status"] == "COMPOSED"


def test_compose_probe_resolver_rejects_a_probe_without_human_approval(
    work_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = SimpleNamespace(
        probe_id="probe-unapproved",
        approved_profile_ref=None,
        approval_target_hash="a" * 64,
    )
    service = SimpleNamespace(list=lambda: (receipt,))
    monkeypatch.setattr(
        "sastsimi.interfaces.cli.main.capability_command.build_service",
        lambda *_args, **_kwargs: service,
    )
    resolver = _approved_probe_resolver(
        work_dir, _production_profile(), docker_host=None
    )

    with pytest.raises(ValueError, match="CAPABILITY_PROBE_NOT_APPROVED"):
        resolver("probe-unapproved")


def test_compose_probe_resolver_uses_read_only_current_approval_lookup(
    work_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw_ref = _provisioning_payload(_production_profile())["capabilities"][0][
        "profile_ref"
    ]
    approved_ref = HostConfigurationRef.model_validate(raw_ref)
    receipt = SimpleNamespace(
        probe_id="probe-approved",
        kind="GIT",
        approved_profile_ref=approved_ref,
        approval_target_hash="a" * 64,
    )
    calls: list[tuple[str, HostConfigurationRef]] = []

    def require_approved_current(
        probe_id: str, expected_ref: HostConfigurationRef
    ) -> HostConfigurationRef:
        calls.append((probe_id, expected_ref))
        return expected_ref

    service = SimpleNamespace(
        list=lambda: (receipt,),
        require_approved_current=require_approved_current,
        approve=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("compose must not approve or re-probe capabilities")
        ),
    )
    monkeypatch.setattr(
        "sastsimi.interfaces.cli.main.capability_command.build_service",
        lambda *_args, **_kwargs: service,
    )

    resolver = _approved_probe_resolver(
        work_dir, _production_profile(), docker_host=None
    )

    assert resolver("probe-approved") == ("GIT", approved_ref)
    assert calls == [("probe-approved", approved_ref)]


def _write_compose_inputs(
    root: Path,
) -> tuple[Path, tuple[Path, ...], tuple[Path, ...], dict[str, HostConfigurationRef]]:
    profile = _production_profile()
    manifest = _manifest_payload(Path.cwd())
    capabilities = _provisioning_payload(profile)["capabilities"]
    assert isinstance(capabilities, list)
    refs = {
        str(item["slot"]): HostConfigurationRef.model_validate(item["profile_ref"])
        for item in capabilities
    }
    approval = {
        "schema_version": 1,
        "created_at": manifest["created_at"],
        "expires_at": manifest["expires_at"],
        "approved_by": manifest["approved_by"],
        "policy_artifact_sha256": manifest["policy_artifact_sha256"],
        "capability_probes": [
            {"slot": slot, "probe_id": f"probe-{slot.lower()}"} for slot in refs
        ],
        "provider_approvals": manifest["provider_approvals"],
        "route_approvals": manifest["route_approvals"],
    }
    approval_path = root / "approval-input.json"
    approval_path.write_text(json.dumps(approval), encoding="utf-8")

    templates, _ = _artifact_templates()
    slot_paths: list[Path] = []
    for slot, data in templates.items():
        payload = json.loads(data)
        payload["profile_hash"] = production_profile_hash(profile)
        payload["host_id"] = profile.host_id
        path = root / f"{slot.lower()}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        slot_paths.append(path)

    evidence_values = {
        b"safe evidence",
        b"storage-enforcement",
        b"python-ast-config",
        b"policy-source",
        b"policy-freshness",
        b"sandbox-policy",
    }
    for data in templates.values():
        payload = json.loads(data)
        for item in payload["record_templates"]:
            evidence_values.add(str(item["template_key"]).encode())
    evidence_paths: list[Path] = []
    for index, value in enumerate(sorted(evidence_values)):
        path = root / f"evidence-{index}.json"
        path.write_bytes(value)
        evidence_paths.append(path)
    return approval_path, tuple(slot_paths), tuple(evidence_paths), refs


def test_compose_builds_atomic_exact_bundle_then_prepare_imports_it(
    work_dir: Path,
) -> None:
    profile = _production_profile()
    approval, slots, evidence, refs = _write_compose_inputs(work_dir)
    output_dir = work_dir / "composed"

    result = run_compose(
        work_dir / "data",
        profile=profile,
        approval_input_path=approval,
        slot_template_paths=slots,
        evidence_paths=evidence,
        output_dir=output_dir,
        repository_root=Path.cwd(),
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
        resolve_probe=lambda probe_id: (
            (
                "PYTHON_AST"
                if probe_id == "probe-ast"
                else "PYTHON_RUNTIME"
                if probe_id == "probe-python_runtime"
                else "GIT"
            ),
            refs[
                probe_id.removeprefix("probe-").upper()
                if probe_id != "probe-python_runtime"
                else "PYTHON_RUNTIME"
            ],
        ),
    )

    assert result.code == ExitCode.OK
    assert result.data["status"] == "COMPOSED"
    assert (output_dir / "production-onboarding.json").is_file()
    assert (output_dir / "production-provisioning.json").is_file()
    assert not list(output_dir.rglob("*.tmp"))
    assert str(work_dir) not in (output_dir / "bundle-index.json").read_text(
        encoding="utf-8"
    )

    prepared = run_prepare_bundle(
        work_dir / "prepared-data",
        profile=profile,
        bundle_dir=output_dir,
        repository_root=Path.cwd(),
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
    )
    assert prepared.code == ExitCode.OK
    assert prepared.data["status"] == "READY"


def test_compose_missing_or_secret_evidence_leaves_no_partial_bundle(
    work_dir: Path,
) -> None:
    profile = _production_profile()
    approval, slots, evidence, refs = _write_compose_inputs(work_dir)
    output_dir = work_dir / "composed"

    missing = run_compose(
        work_dir / "data",
        profile=profile,
        approval_input_path=approval,
        slot_template_paths=slots,
        evidence_paths=evidence[1:],
        output_dir=output_dir,
        repository_root=Path.cwd(),
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
        resolve_probe=lambda probe_id: (
            "PYTHON_AST" if probe_id == "probe-ast" else "GIT",
            refs["AST" if probe_id == "probe-ast" else "GIT_CLONE"],
        ),
    )
    assert missing.code == ExitCode.CAPABILITY_UNSUPPORTED
    assert not output_dir.exists()

    secret_path = work_dir / "secret-evidence.json"
    secret_path.write_text("api_key=sk-not-allowed-here", encoding="utf-8")
    secret = run_compose(
        work_dir / "data",
        profile=profile,
        approval_input_path=approval,
        slot_template_paths=slots,
        evidence_paths=(*evidence, secret_path),
        output_dir=output_dir,
        repository_root=Path.cwd(),
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
        resolve_probe=lambda probe_id: (
            "PYTHON_AST" if probe_id == "probe-ast" else "GIT",
            refs["AST" if probe_id == "probe-ast" else "GIT_CLONE"],
        ),
    )
    assert secret.code == ExitCode.CAPABILITY_UNSUPPORTED
    assert not output_dir.exists()


def test_prepare_bundle_rejects_an_unindexed_extra_file(work_dir: Path) -> None:
    profile = _production_profile()
    approval, slots, evidence, refs = _write_compose_inputs(work_dir)
    output_dir = work_dir / "composed"
    composed = run_compose(
        work_dir / "data",
        profile=profile,
        approval_input_path=approval,
        slot_template_paths=slots,
        evidence_paths=evidence,
        output_dir=output_dir,
        repository_root=Path.cwd(),
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
        resolve_probe=lambda probe_id: (
            (
                "PYTHON_AST"
                if probe_id == "probe-ast"
                else "PYTHON_RUNTIME"
                if probe_id == "probe-python_runtime"
                else "GIT"
            ),
            refs[
                probe_id.removeprefix("probe-").upper()
                if probe_id != "probe-python_runtime"
                else "PYTHON_RUNTIME"
            ],
        ),
    )
    assert composed.code == ExitCode.OK
    (output_dir / "unexpected.txt").write_text(
        "unindexed operator data", encoding="utf-8"
    )

    result = run_prepare_bundle(
        work_dir / "prepared-data",
        profile=profile,
        bundle_dir=output_dir,
        repository_root=Path.cwd(),
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
    )

    assert result.code == ExitCode.CAPABILITY_UNSUPPORTED
    assert result.data["reason_code"] == "PRODUCTION_ONBOARDING_BUNDLE_INVALID"


# mypy: disable-error-code="index"
