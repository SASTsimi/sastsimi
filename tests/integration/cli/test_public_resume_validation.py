"""Restart inspection reads pinned bytes and never activates an execution graph."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sastsimi.composition.production_entrypoint import builtin_resource_root
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.ids import AnalysisId, CommitId, WorkspaceId
from sastsimi.contracts.refs import RunStoredDataRef, reference
from sastsimi.orchestration.analysis_state_factory import AnalysisStateFactory
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.storage.artifact_store import LocalArtifactStore
from sastsimi.storage.budget_registry import BudgetProfileRegistry
from tests.integration.runtime_support import Harness
from tests.unit.orchestration.test_production_onboarding import (
    _manifest_payload,
    _parse,
    _production_profile,
    _provisioning_payload,
)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "corrupt-artifact",
        "changed-profile",
        "expired",
        "budget",
        "stale",
        "unresolved",
        "cancelled",
        "terminal",
        "future",
        "provisioning-mismatch",
        "catalog-missing",
        "catalog-corrupt",
        "binding-missing",
    ],
)
def test_exact_descriptor_survives_fresh_reader_without_current_onboarding(
    tmp_path: Path,
    fault: str | None,
) -> None:
    from sastsimi.orchestration.production_descriptor import (
        load_production_descriptor,
        persist_production_descriptor,
    )

    harness = Harness(tmp_path)
    profile = _production_profile()
    scope = PlannedRunScope(
        AnalysisId("a1"), WorkspaceId("ws1"), CommitId("a" * 40), "repository"
    )
    artifacts = LocalArtifactStore(
        tmp_path / "artifacts", scope.workspace_id, scope.commit_id
    )
    provisioning_payload = _provisioning_payload(profile)
    if fault == "provisioning-mismatch":
        provisioning_payload["profile_hash"] = "b" * 64
    provisioning = canonical_bytes(provisioning_payload)
    provisioning_hash = content_hash(provisioning_payload)
    manifest = _parse(
        _manifest_payload(Path(__file__).resolve().parents[3])
        | {
            "schema_version": 2,
            "provisioning_manifest_sha256": provisioning_hash,
        }
    )
    from sastsimi.orchestration.production_onboarding import (
        ProductionProvisioningManifest,
    )

    templates = ProductionProvisioningManifest.model_validate_json(provisioning)
    template_data = {
        item.content_sha256: f"{item.slot}-data".encode()
        for item in templates.artifacts
    }

    def evidence(digest: str) -> bytes:
        return (
            provisioning
            if digest == provisioning_hash
            else template_data.get(digest, b"safe evidence")
        )

    profile_ref, onboarding_ref = persist_production_descriptor(
        artifacts=artifacts,
        analysis_id=scope.analysis_id,
        profile=profile,
        manifest=manifest,
        evidence=evidence,
    )
    if fault == "changed-profile":
        changed = profile.model_copy(update={"host_id": "changed-host"})
        profile_ref = artifacts.commit_run(
            artifacts.stage_bytes(
                canonical_bytes(changed.model_dump(mode="json")), "application/json"
            ),
            scope.analysis_id,
        )
    from sastsimi.contracts.analysis import AnalysisStartRequest

    request = AnalysisStartRequest.model_validate_json(
        json.dumps(
            {
                "repository_ref": "repository",
                "requested_git_ref": "a" * 40,
                "program_id": profile.program_id,
                "purpose": "PRODUCTION",
            }
        )
    )
    from sastsimi.orchestration.production_operator_profiles import (
        ProductionOperatorProfiles,
        ProductionTrustedEvidence,
    )
    from sastsimi.storage.configuration_registry import ConfigurationRegistry
    from tests.integration.storage.test_production_authority import _bind
    from tests.unit.orchestration.test_production_operator_profiles import _Clock, _Ids

    settings = profile.budget
    if fault == "budget":
        settings = settings.model_copy(update={"max_total_retries": 0})
    profiles = ProductionOperatorProfiles(
        scope=scope,
        program_id=profile.program_id,
        settings=settings,
        clock=_Clock(),
        ids=_Ids(),
    )
    harness.clock.wall_time = datetime(2026, 9, 13, tzinfo=UTC)
    harness.records.evidence = ProductionTrustedEvidence(profiles)
    profiles.publish_code_profiles(ConfigurationRegistry(harness.records, artifacts))
    catalog = profiles.authority_catalog(profile_ref, onboarding_ref)
    catalog_ref = artifacts.commit_run(
        artifacts.stage_bytes(canonical_bytes(catalog), "application/json"),
        scope.analysis_id,
    )
    execution = profiles.execution_profile
    execution_ref = reference(execution)
    assert isinstance(execution_ref, RunStoredDataRef)
    bootstrap = AnalysisStateFactory(
        harness.clock,
        harness.ids,
        scope=scope,
        production_profile_ref=profile_ref,
        production_onboarding_ref=onboarding_ref,
        production_authority_catalog_ref=catalog_ref,
    ).create(request, execution_ref)
    if fault == "catalog-missing":
        from dataclasses import replace

        legacy_input = bootstrap.run_input.model_copy(
            update={"production_authority_catalog_ref": None}
        )
        bootstrap = replace(
            bootstrap, run_input=legacy_input,
            state=bootstrap.state.model_copy(
                update={"analysis_input_ref": reference(legacy_input)}
            ),
        )
    registry = BudgetProfileRegistry(
        harness.records, harness.clock, harness.ids, artifacts=artifacts
    )
    registry.pin_execution(execution, bootstrap.state, bootstrap.run_input)
    fresh = LocalArtifactStore(tmp_path / "artifacts", None, None)
    if fault == "corrupt-artifact":
        artifacts.path_for(profile_ref.content_hash).write_bytes(
            b"corrupt-private-data"
        )
    now = datetime(2026, 11 if fault == "expired" else 9, 14, tzinfo=UTC)
    if fault == "future":
        now = datetime(2026, 9, 12, tzinfo=UTC)
    if fault in {
        "corrupt-artifact",
        "changed-profile",
        "expired",
        "future",
        "provisioning-mismatch",
    }:
        with pytest.raises((ValueError, RuntimeError)):
            load_production_descriptor(
                state=bootstrap.state,
                records=harness.records,
                artifacts=fresh,
                repository_root=builtin_resource_root(),
                now=now,
            )
        return
    descriptor = load_production_descriptor(
        state=bootstrap.state,
        records=harness.records,
        artifacts=fresh,
        repository_root=builtin_resource_root(),
        now=datetime(2026, 9, 14, tzinfo=UTC),
    )
    assert descriptor.scope == scope
    assert descriptor.request == request
    assert descriptor.profile == profile
    assert descriptor.onboarding == manifest
    assert descriptor.run_input == bootstrap.run_input

    # The exact pinned bytes remain authoritative across a new reader instance.
    assert not (tmp_path / "onboarding").exists()
    assert profile_ref.content_hash == content_hash(profile.model_dump(mode="json"))
    assert onboarding_ref.content_hash == content_hash(manifest)
    if fault != "binding-missing":
        _bind(harness, profiles, registry)
    if fault == "catalog-corrupt":
        artifacts.path_for(catalog_ref.content_hash).write_bytes(b"corrupt-catalog")

    # A valid restart descriptor can be inspected, but the public command must
    # still fail closed without changing records or activating execution.
    import subprocess
    import sys

    from sqlalchemy import insert

    from sastsimi.storage import models
    from tests.integration.cli.test_run_control import _attempt, _work
    from tests.integration.storage.test_production_authority import _rows

    blocked = _work("BLOCKED")
    previous = _attempt(blocked, status="FAILED")
    if fault == "stale":
        previous = previous.model_copy(update={"input_hash": "f" * 64})
    with harness.database.write() as connection:
        connection.execute(
            insert(models.work_states).values(
                work_id=str(blocked.work_id),
                analysis_id="a1",
                registration_key="resume-test",
                status="BLOCKED",
                state_version=blocked.state_version,
                payload=canonical_bytes(blocked).decode(),
            )
        )
        connection.execute(
            insert(models.work_attempts).values(
                attempt_id=str(previous.attempt_id),
                work_id=str(blocked.work_id),
                attempt_number=1,
                status="FAILED",
                payload=canonical_bytes(previous).decode(),
            )
        )
        if fault == "unresolved":
            connection.execute(
                insert(models.external_dispatches).values(
                    action_id="uncertain-action",
                    work_id=str(blocked.work_id),
                    attempt_id=str(previous.attempt_id),
                    decision_ref="{}",
                    reservation_ref="{}",
                    prepared_at="2026-09-13T00:00:00Z",
                    dispatched_at="2026-09-13T00:00:00Z",
                )
            )
    if fault == "cancelled":
        from sastsimi.storage.run_control import RunControlStore

        RunControlStore(harness.database, harness.clock).request_cancel(
            "a1", "OPERATOR_REQUEST"
        )
    if fault == "terminal":
        from sqlalchemy import update

        from tests.integration.cli.test_run_control import _run_state

        with harness.database.write() as connection:
            connection.execute(
                update(models.analysis_runs)
                .where(models.analysis_runs.c.analysis_id == "a1")
                .values(payload=canonical_bytes(_run_state("CANCELLED")).decode())
            )

    before = _rows(harness)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from datetime import UTC, datetime\n"
            "from unittest.mock import patch\n"
            "from sastsimi.runtime.system_support import SystemClock\n"
            "from sastsimi.interfaces.cli.main import main\n"
            "from tests.integration.storage.authority_read_guard import "
            "readonly_authority_guard\n"
            "with patch.object(SystemClock, 'now', return_value="
            "datetime(2026, 9, 14, tzinfo=UTC)), readonly_authority_guard():\n"
            "    raise SystemExit(main())\n",
            "--data-dir",
            str(tmp_path),
            "resume",
            "a1",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 4
    assert json.loads(result.stderr)["data"]["reason_code"] == {
        "budget": "PRODUCTION_RESUME_BUDGET_EXHAUSTED",
        "stale": "RESUME_INPUT_CHANGED",
        "unresolved": "PRODUCTION_RESUME_INPUT_INVALID",
        "cancelled": "RUN_NOT_RESUMABLE",
        "terminal": "RUN_NOT_RESUMABLE",
        "catalog-missing": "PRODUCTION_AUTHORITY_CATALOG_REQUIRED",
        "catalog-corrupt": "HASH_MISMATCH",
        "binding-missing": "PRODUCTION_AUTHORITY_BINDING_NOT_PINNED",
    }.get(fault or "", "PRODUCTION_RESUME_DISPATCH_NOT_AVAILABLE")
    assert _rows(harness) == before


@pytest.mark.parametrize("case", ["legacy", "cross-run", "corrupt"])
def test_resume_rejects_unsafe_descriptor_without_dispatch(
    tmp_path: Path,
    case: str,
) -> None:
    from sastsimi.orchestration.production_descriptor import load_production_descriptor

    harness = Harness(tmp_path)
    registry = BudgetProfileRegistry(harness.records, harness.clock, harness.ids)
    harness.pin_execution(registry, harness.execution())
    state = registry.current_state("a1")
    if case == "cross-run":
        state = state.model_copy(
            update={
                "analysis_input_ref": state.analysis_input_ref.model_copy(
                    update={"analysis_id": AnalysisId("a2")}
                )
            }
        )
    if case == "corrupt":
        state = state.model_copy(
            update={
                "analysis_input_ref": state.analysis_input_ref.model_copy(
                    update={"content_hash": "b" * 64}
                )
            }
        )
    artifacts = LocalArtifactStore(tmp_path / "artifacts", None, None)
    with pytest.raises((ValueError, LookupError)):
        load_production_descriptor(
            state=state,
            records=harness.records,
            artifacts=artifacts,
            repository_root=builtin_resource_root(),
            now=datetime(2026, 9, 14, tzinfo=UTC),
        )
