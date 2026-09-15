"""Authority publication is atomic; restarted inspection cannot write or dispatch."""

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select, update

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.analysis import AnalysisRunInput, AnalysisRunState
from sastsimi.contracts.budget import ProfileStatus, Purpose
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import AnalysisId, LogicalRecordId, RecordId
from sastsimi.contracts.records import RunMeta
from sastsimi.contracts.refs import RunStoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.orchestration.analysis_state_factory import AnalysisStateFactory
from sastsimi.orchestration.production_operator_profiles import (
    ProductionOperatorProfiles,
    ProductionTrustedEvidence,
)
from sastsimi.storage import models
from sastsimi.storage.artifact_store import LocalArtifactStore
from sastsimi.storage.budget_registry import BudgetProfileRegistry
from sastsimi.storage.configuration_registry import ConfigurationRegistry
from sastsimi.storage.records import next_meta
from sastsimi.storage.run_states import save_run
from tests.integration.runtime_support import Harness
from tests.unit.orchestration.test_production_operator_profiles import (
    NOW,
    _Clock,
    _Ids,
    _request,
    _scope,
    _settings,
)


def _prepare(
    root: Path, *, bind: bool = True, pin: bool = True
) -> tuple[
    Harness, ProductionOperatorProfiles, LocalArtifactStore, BudgetProfileRegistry
]:
    harness = Harness(root)
    profiles = ProductionOperatorProfiles(
        scope=_scope(),
        program_id="program-one",
        settings=_settings(),
        clock=_Clock(),
        ids=_Ids(),
    )
    harness.records.evidence = ProductionTrustedEvidence(profiles)
    harness.clock.wall_time = NOW
    artifacts = LocalArtifactStore(
        root / "artifacts", _scope().workspace_id, _scope().commit_id
    )
    descriptor_ref = artifacts.commit_run(
        artifacts.stage_bytes(b"{}", "application/json"), _scope().analysis_id
    )
    profiles.publish_code_profiles(ConfigurationRegistry(harness.records, artifacts))
    catalog = profiles.authority_catalog(descriptor_ref, descriptor_ref)
    catalog_ref = artifacts.commit_run(
        artifacts.stage_bytes(canonical_bytes(catalog), "application/json"),
        _scope().analysis_id,
    )
    registry = BudgetProfileRegistry(
        harness.records, harness.clock, harness.ids, artifacts=artifacts
    )
    execution_ref = reference(profiles.execution_profile)
    assert isinstance(execution_ref, RunStoredDataRef)
    bootstrap = AnalysisStateFactory(
        harness.clock,
        harness.ids,
        scope=_scope(),
        production_profile_ref=descriptor_ref,
        production_onboarding_ref=descriptor_ref,
        production_authority_catalog_ref=catalog_ref,
    ).create(_request(), execution_ref)
    if pin:
        registry.pin_execution(
            profiles.execution_profile, bootstrap.state, bootstrap.run_input
        )
        assert registry.current_state("analysis-one").budget_binding_ref is None
    if bind:
        _bind(harness, profiles, registry)
    return harness, profiles, artifacts, registry


def _bind(
    harness: Harness,
    profiles: ProductionOperatorProfiles,
    registry: BudgetProfileRegistry,
) -> None:
    scope = profiles.scope
    state = registry.current_state(str(scope.analysis_id))
    workspace = CodeWorkspace(
        meta=RunMeta(
            record_id=RecordId("workspace-ready"),
            logical_record_id=LogicalRecordId("workspace"),
            record_type="code_workspace",
            schema_version="1.0.0",
            revision_number=1,
            previous_record_id=None,
            created_at=NOW,
            analysis_id=scope.analysis_id,
        ),
        workspace_id=scope.workspace_id,
        analysis_id=scope.analysis_id,
        repository_url=scope.repository_ref,
        commit_id=scope.commit_id,
        status="READY",
    )
    workspace_ref = reference(workspace)
    assert isinstance(workspace_ref, RunStoredDataRef)
    ready = AnalysisRunState.model_validate(
        state.model_dump()
        | {
            "meta": next_meta(state.meta, harness.clock, harness.ids),
            "workspace_ref": workspace_ref,
            "workspace_id": scope.workspace_id,
            "commit_id": scope.commit_id,
        }
    )
    with harness.database.write() as connection:
        harness.records.publish(
            connection, harness.records.stage(connection, workspace)
        )
        save_run(harness.records, connection, ready, state)
    state_ref = reference(ready)
    assert isinstance(state_ref, RunStoredDataRef)
    registry.pin_binding(profiles.binding, workspace_ref, state_ref)


def _rows(harness: Harness) -> tuple[str, ...]:
    with harness.database.engine.connect() as connection:
        return tuple(
            repr(connection.execute(select(table)).all())
            for table in models.metadata.sorted_tables
        )


def test_fresh_process_resolves_all_exact_roles_without_authority_construction(
    tmp_path: Path,
) -> None:
    harness, profiles, _artifacts, _registry = _prepare(tmp_path)
    before = _rows(harness)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from datetime import UTC, datetime\n"
            "from pathlib import Path\n"
            "from tests.integration.storage.authority_read_guard import "
            "readonly_authority_guard\n"
            "from sastsimi.storage.production_authority import "
            "ProductionAuthorityInspector\n"
            "from sastsimi.storage.database import Database\n"
            "from sastsimi.storage.repositories import SQLiteRecordStore\n"
            "from sastsimi.storage.artifact_store import LocalArtifactStore\n"
            "from sastsimi.contracts.canonical_json import canonical_bytes\n"
            "import sys\n"
            "root=Path(sys.argv[1])\n"
            "db=Database(root/'db'/'sastsimi.sqlite3')\n"
            "with readonly_authority_guard():\n"
            "    reader=ProductionAuthorityInspector(SQLiteRecordStore(db), "
            "LocalArtifactStore(root/'artifacts', None, None))\n"
            "    value=reader.inspect('analysis-one', "
            "now=datetime(2026,9,14,tzinfo=UTC))\n"
            "    print(canonical_bytes({role.value:ref "
            "for role,ref in value.role_identity_refs.items()}).decode())\n",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        role.value: profiles.identity_ref(role).model_dump(mode="json")
        for role in RequesterRole
    }
    assert _rows(harness) == before


@pytest.mark.parametrize(
    "fault",
    [
        "missing-record",
        "hash",
        "stale",
        "approval",
        "unbound",
        "state-pointer",
        "execution-pin",
        "binding-pin",
    ],
)
def test_invalid_authority_fails_without_mutation(tmp_path: Path, fault: str) -> None:
    from sastsimi.storage.production_authority import ProductionAuthorityInspector

    harness, profiles, artifacts, registry = _prepare(tmp_path, bind=fault != "unbound")
    if fault == "hash":
        catalog_ref = registry.current_input(
            "analysis-one"
        ).production_authority_catalog_ref
        assert catalog_ref is not None
        artifacts.path_for(catalog_ref.content_hash).write_bytes(b"corrupt")
    elif fault in {"missing-record", "stale"}:
        identity = profiles.identity_ref(RequesterRole.RECOVERY)
        with harness.database.write() as connection:
            if fault == "missing-record":
                connection.execute(
                    models.current_records.delete().where(
                        models.current_records.c.record_id == str(identity.record_id)
                    )
                )
                connection.execute(
                    models.record_revisions.delete().where(
                        models.record_revisions.c.record_id == str(identity.record_id)
                    )
                )
            else:
                connection.execute(
                    update(models.current_records)
                    .where(
                        models.current_records.c.record_id == str(identity.record_id)
                    )
                    .values(record_id=str(reference(profiles.work_profile).record_id))
                )
    elif fault == "state-pointer":
        state = registry.current_state("analysis-one")
        with harness.database.write() as connection:
            connection.execute(
                update(models.current_records)
                .where(
                    models.current_records.c.logical_record_id
                    == str(state.meta.logical_record_id)
                )
                .values(record_id=str(reference(profiles.work_profile).record_id))
            )
    elif fault.endswith("-pin"):
        with harness.database.write() as connection:
            result = connection.execute(
                update(models.budget_profiles)
                .where(
                    models.budget_profiles.c.analysis_id == "analysis-one",
                    models.budget_profiles.c.kind
                    == (
                        "execution_budget_profile"
                        if fault == "execution-pin"
                        else "budget_profile_binding"
                    ),
                )
                .values(ref=canonical_bytes(reference(profiles.work_profile)).decode())
            )
            assert result.rowcount == 1
    before = _rows(harness)
    with pytest.raises(
        (ValueError, LookupError),
        match=(
            "PRODUCTION_AUTHORITY_BINDING_NOT_PINNED" if fault == "unbound" else None
        ),
    ):
        ProductionAuthorityInspector(harness.records, artifacts).inspect(
            "analysis-one",
            now=datetime(2026, 9, 12 if fault == "approval" else 14, tzinfo=UTC),
        )
    assert _rows(harness) == before


def test_competing_publication_cannot_replace_reachable_input(tmp_path: Path) -> None:
    harness, profiles, artifacts, registry = _prepare(tmp_path, bind=False)
    state = registry.current_state("analysis-one")
    run_input = registry.current_input("analysis-one")
    catalog_ref = artifacts.commit_run(
        artifacts.stage_bytes(b"{}", "application/json"), _scope().analysis_id
    )
    replacement = AnalysisRunInput.model_validate(
        run_input.model_dump()
        | {
            "meta": next_meta(run_input.meta, harness.clock, harness.ids),
            "production_authority_catalog_ref": catalog_ref,
        }
    )
    replacement_ref = reference(replacement)
    candidate = state.model_copy(update={"analysis_input_ref": replacement_ref})
    before = _rows(harness)
    with pytest.raises(ValueError):
        registry.pin_execution(profiles.execution_profile, candidate, replacement)
    assert _rows(harness) == before
    assert registry.current_input("analysis-one") == run_input


@pytest.mark.parametrize(
    "fault, reason",
    [
        ("unapproved", "PRODUCTION_AUTHORITY_CONFIGURATION_NOT_APPROVED"),
        ("foreign", "PRODUCTION_AUTHORITY_SCOPE_MISMATCH"),
        ("inactive", "PRODUCTION_AUTHORITY_PROFILE_NOT_ACTIVE"),
        ("purpose", "PRODUCTION_AUTHORITY_PURPOSE_MISMATCH"),
        ("identity", "PRODUCTION_AUTHORITY_IDENTITY_NOT_APPROVED"),
    ],
)
def test_unapproved_common_profile_cannot_publish_initial_authority(
    tmp_path: Path, fault: str, reason: str
) -> None:
    from sqlalchemy import insert

    harness, profiles, artifacts, registry = _prepare(tmp_path, bind=False, pin=False)
    original = (
        profiles.role_profiles[RequesterRole.RECOVERY]
        if fault in {"purpose", "identity"}
        else profiles.verification_profile
    )
    substituted = original.model_copy(
        update={
            "meta": original.meta.model_copy(
                update={
                    "record_id": RecordId("unapproved-profile"),
                    "logical_record_id": LogicalRecordId("unapproved-profile"),
                }
            ),
        }
    )
    if fault == "foreign":
        substituted = substituted.model_copy(
            update={
                "meta": substituted.meta.model_copy(
                    update={"analysis_id": AnalysisId("foreign")}
                )
            }
        )
    elif fault == "inactive":
        substituted = substituted.model_copy(update={"status": ProfileStatus.RETIRED})
    elif fault == "purpose":
        substituted = substituted.model_copy(update={"purpose": Purpose.EVALUATION})
    substituted_ref = reference(substituted)
    with harness.database.write() as connection:
        harness.records.publish(
            connection, harness.records.stage(connection, substituted)
        )
        connection.execute(
            insert(models.current_records).values(
                logical_record_id="unapproved-profile",
                record_id="unapproved-profile",
                state_version=1,
            )
        )
    descriptor_ref = artifacts.commit_run(
        artifacts.stage_bytes(b"{}", "application/json"), _scope().analysis_id
    )
    catalog = profiles.authority_catalog(descriptor_ref, descriptor_ref)
    if fault in {"purpose", "identity"}:
        catalog = catalog.model_copy(
            update={
                "role_identities": (
                    *catalog.role_identities[:-1],
                    catalog.role_identities[-1].model_copy(
                        update={"identity_ref": substituted_ref}
                    ),
                )
            }
        )
    else:
        catalog = catalog.model_copy(
            update={"verification_budget_profile_ref": substituted_ref}
        )
    catalog_ref = artifacts.commit_run(
        artifacts.stage_bytes(canonical_bytes(catalog), "application/json"),
        _scope().analysis_id,
    )
    bootstrap = AnalysisStateFactory(
        harness.clock,
        harness.ids,
        scope=_scope(),
        production_profile_ref=descriptor_ref,
        production_onboarding_ref=descriptor_ref,
        production_authority_catalog_ref=catalog_ref,
    ).create(_request(), catalog.execution_budget_profile_ref)
    before = _rows(harness)
    with pytest.raises(ValueError, match=reason):
        registry.pin_execution(
            profiles.execution_profile, bootstrap.state, bootstrap.run_input
        )
    assert _rows(harness) == before


def test_binding_constituents_cannot_diverge_from_catalog(tmp_path: Path) -> None:
    harness, profiles, _artifacts, registry = _prepare(tmp_path)
    state = registry.current_state("analysis-one")
    profiles.binding = profiles.binding.model_copy(
        update={
            "work_budget_profile_ref": profiles.identity_ref(
                RequesterRole.ORCHESTRATION
            ),
        }
    )
    harness.records.evidence = ProductionTrustedEvidence(profiles)
    before = _rows(harness)
    assert state.workspace_ref is not None
    state_ref = reference(state)
    assert isinstance(state_ref, RunStoredDataRef)
    with pytest.raises(ValueError, match="PRODUCTION_AUTHORITY_BINDING_MISMATCH"):
        registry.pin_binding(profiles.binding, state.workspace_ref, state_ref)
    assert _rows(harness) == before


def test_snapshot_is_immutable_and_exact_republication_is_idempotent(
    tmp_path: Path,
) -> None:
    from sastsimi.storage.production_authority import ProductionAuthorityInspector

    harness, profiles, artifacts, registry = _prepare(tmp_path)
    before = _rows(harness)
    snapshot = ProductionAuthorityInspector(harness.records, artifacts).inspect(
        "analysis-one", now=NOW
    )
    with pytest.raises(TypeError):
        identities = snapshot.role_identity_refs
        identities[RequesterRole.RECOVERY] = None  # type: ignore[index]
    registry.pin_execution(
        profiles.execution_profile,
        registry.current_state("analysis-one"),
        registry.current_input("analysis-one"),
    )
    assert _rows(harness) == before


def test_competing_initializations_publish_only_one_catalog(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    harness, profiles, artifacts, registry = _prepare(tmp_path, bind=False, pin=False)
    candidates = []
    for data in (b"{}", b'{"variant":1}'):
        descriptor_ref = artifacts.commit_run(
            artifacts.stage_bytes(data, "application/json"), profiles.scope.analysis_id
        )
        catalog = profiles.authority_catalog(descriptor_ref, descriptor_ref)
        catalog_ref = artifacts.commit_run(
            artifacts.stage_bytes(canonical_bytes(catalog), "application/json"),
            profiles.scope.analysis_id,
        )
        candidates.append(
            AnalysisStateFactory(
                harness.clock,
                harness.ids,
                scope=profiles.scope,
                production_profile_ref=descriptor_ref,
                production_onboarding_ref=descriptor_ref,
                production_authority_catalog_ref=catalog_ref,
            ).create(_request(), catalog.execution_budget_profile_ref)
        )
    barrier = Barrier(2)

    def publish(index: int) -> bool:
        candidate = candidates[index]
        barrier.wait(timeout=10)
        try:
            registry.pin_execution(
                profiles.execution_profile, candidate.state, candidate.run_input
            )
        except ValueError as error:
            assert str(error) == "BUDGET run state mismatch"
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(publish, (0, 1)))
    assert sorted(results) == [False, True]
    winner = candidates[results.index(True)]
    assert registry.current_input("analysis-one") == winner.run_input
    with harness.database.engine.connect() as connection:
        assert (
            len(
                connection.execute(
                    select(models.records).where(
                        models.records.c.kind == "analysis_run_input"
                    )
                ).all()
            )
            == 1
        )
        assert connection.execute(select(models.work_states)).all() == []
