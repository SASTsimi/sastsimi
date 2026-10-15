"""A reboot can close an undelivered surface call without completing its work."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attempt_owner import AttemptOwner
from sastsimi.simple_runtime.models import CheckpointIdentity, SimpleAnalysisRun
from sastsimi.simple_runtime.run_lease import analysis_run_lease
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _windows_start_identity(started_at: datetime) -> str:
    delta = started_at - datetime(1601, 1, 1, tzinfo=UTC)
    ticks = (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10
    return f"windows:{ticks:016x}"


def _case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    SimpleAnalysisRun,
    str,
    StoredDataRef,
    datetime,
]:
    identity = CheckpointIdentity(
        analysis_id="analysis-reboot-orphan",
        workspace_id="workspace-reboot-orphan",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    placeholder = artifacts.put_json({"kind": "pinned-placeholder"})
    scope = "f" * 64
    plan = {
        "kind": "simple_surface_enrichment_plan_v9",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope_fingerprint": scope,
        "static_bundle_hash": placeholder.content_hash,
        "prior_v8_plan_ref": placeholder.model_dump(mode="json"),
        "targets": [{"surface_id": "surface-1", "path": "app/main.py"}],
        "expected_parts": [
            {
                "surface_id": "surface-1",
                "context_id": "context-1",
                "context_hash": "b" * 64,
                "context_part": {"source_sha256": "c" * 64},
            }
        ],
    }
    plan_ref = artifacts.put_json(plan)
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repo.git",
        provider="codex",
        llm_provider="codex",
        model="test-model",
        model_route_version=1,
        model_routes={"hypothesis_surface": "test-model"},
        candidate_pipeline_version=2,
        candidate_scope_fingerprint=scope,
        static_bundle_ref=placeholder,
        python_scope_certificate_ref=placeholder,
        surface_enrichment_plan_ref=placeholder,
        surface_enrichment_v5_plan_ref=placeholder,
        surface_enrichment_v6_plan_ref=placeholder,
        surface_enrichment_v7_plan_ref=placeholder,
        surface_enrichment_v8_plan_ref=placeholder,
        surface_enrichment_v9_plan_ref=plan_ref,
        surface_enrichment_status="RUNNING",
    )
    store.save_analysis_run(run)
    call_id = "surface-call-before-reboot"
    assert store.begin_codex_call(call_id, identity.analysis_id)
    now = datetime.now(UTC)
    call_started = now - timedelta(minutes=15)
    child_started = now - timedelta(minutes=10)
    boot_at = now - timedelta(minutes=5)
    start_identity = _windows_start_identity(child_started)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_codex_calls SET started_at = ? WHERE call_id = ?",
            (call_started.isoformat(), call_id),
        )
    store.begin_codex_child_spawn(
        call_id=call_id, analysis_id=identity.analysis_id, phase="EXEC"
    )
    store.record_codex_child_spawn(
        call_id=call_id,
        analysis_id=identity.analysis_id,
        phase="EXEC",
        pid=4242,
        start_identity=start_identity,
    )
    attempt_ref = artifacts.put_json(
        {
            "kind": "simple_llm_attempt",
            "provider": "codex-cli",
            "agent": "hypothesis_surface",
            "model": "test-model",
            "status": "SUCCEEDED",
        }
    )
    store.record_llm_attempt(
        attempt_id=call_id,
        analysis_id=identity.analysis_id,
        agent="hypothesis_surface",
        model="test-model",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=1000,
        input_tokens=10,
        output_tokens=5,
        cost_cents=None,
        artifact_ref=attempt_ref,
        owner=AttemptOwner(
            analysis_id=identity.analysis_id,
            stage="HYPOTHESIS_SURFACE",
            surface_id="surface-1",
            context_id="context-1",
            file_path="app/main.py",
        ),
    )
    marker = {
        "kind": "simple_codex_reboot_orphan_confirmation",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "call_id": call_id,
        "call_started_at": call_started.isoformat(),
        "surface_id": "surface-1",
        "context_id": "context-1",
        "file_path": "app/main.py",
        "model": "test-model",
        "surface_plan_hash": plan_ref.content_hash,
        "attempt_ref": attempt_ref.model_dump(mode="json"),
        "verification_method": "windows_reboot",
        "observed_boot_at": boot_at.isoformat(),
        "observed_at": now.isoformat(),
        "observed_children": [
            {"phase": "EXEC", "pid": 4242, "start_identity": start_identity}
        ],
        "former_parent_pid": 4242,
        "observed_matching_process_count": 0,
        "process_tree_stopped": True,
    }
    marker_ref = artifacts.put_json(marker)
    monkeypatch.setattr(
        "sastsimi.providers.codex_subscription.windows_boot_time_utc",
        lambda: boot_at,
    )
    monkeypatch.setattr(
        "sastsimi.providers.codex_subscription.child_identity_matches",
        lambda _pid, _start_identity: None,
    )
    return store, artifacts, run, call_id, marker_ref, boot_at


def test_reboot_orphans_undelivered_surface_call_without_completing_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, run, call_id, marker_ref, boot_at = _case(tmp_path, monkeypatch)
    before = store.usage_summary(run.analysis_id)

    assert store.orphan_codex_rebooted_surface_call(
        run.analysis_id, call_id, marker_ref, artifacts
    )
    assert not store.orphan_codex_rebooted_surface_call(
        run.analysis_id, call_id, marker_ref, artifacts
    )

    assert store.unresolved_codex_call(run.analysis_id) is None
    assert not store.confirmed_codex_call_covering(run.analysis_id, boot_at)
    assert store.list_checkpoints(run.analysis_id) == ()
    assert (
        store.list_surface_exploration_progress(
            artifacts.identity, run.candidate_scope_fingerprint or ""
        )
        == {}
    )
    assert store.usage_summary(run.analysis_id) == before
    with sqlite3.connect(store.database_path) as connection:
        call = connection.execute(
            "SELECT status, confirmation_ref_json FROM simple_codex_calls "
            "WHERE call_id = ?",
            (call_id,),
        ).fetchone()
        attempt = connection.execute(
            "SELECT status FROM simple_llm_attempts WHERE attempt_id = ?", (call_id,)
        ).fetchone()
        orphan_count = connection.execute(
            "SELECT COUNT(*) FROM simple_codex_orphaned_calls WHERE call_id = ?",
            (call_id,),
        ).fetchone()
        child = connection.execute(
            "SELECT status FROM simple_codex_child_spawns WHERE call_id = ?",
            (call_id,),
        ).fetchone()
    assert call == ("SAFE", marker_ref.model_dump_json())
    assert attempt == ("SUCCEEDED",)
    assert orphan_count == (1,)
    assert child == ("EXITED",)
    assert store.begin_codex_call("new-surface-call", run.analysis_id)


@pytest.mark.parametrize(
    "invalid",
    [
        "wrong_call",
        "wrong_start",
        "wrong_model",
        "wrong_owner",
        "wrong_plan",
        "progress_committed",
        "boot_before_child",
        "live_boot_before_child",
        "boot_unknown",
        "child_live",
        "child_identity_unknown",
    ],
)
def test_reboot_orphan_rejects_unbound_or_incomplete_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    store, artifacts, run, call_id, marker_ref, boot_at = _case(tmp_path, monkeypatch)
    marker = json.loads(artifacts.read(marker_ref))
    if invalid == "wrong_call":
        marker["call_id"] = "another-call"
    elif invalid == "wrong_start":
        marker["call_started_at"] = (boot_at - timedelta(hours=1)).isoformat()
    elif invalid == "wrong_model":
        marker["model"] = "another-model"
    elif invalid == "wrong_owner":
        with sqlite3.connect(store.database_path) as connection:
            connection.execute(
                "UPDATE simple_llm_attempt_metadata SET context_id = 'other-context' "
                "WHERE attempt_id = ?",
                (call_id,),
            )
    elif invalid == "wrong_plan":
        plan_ref = run.surface_enrichment_v9_plan_ref
        assert plan_ref is not None
        plan = json.loads(artifacts.read(plan_ref))
        plan["expected_parts"][0]["context_id"] = "other-context"
        changed_ref = artifacts.put_json(plan)
        store.save_analysis_run(
            run.model_copy(update={"surface_enrichment_v9_plan_ref": changed_ref})
        )
        marker["surface_plan_hash"] = changed_ref.content_hash
    elif invalid == "progress_committed":
        with sqlite3.connect(store.database_path) as connection:
            connection.execute(
                "INSERT INTO simple_surface_exploration_progress "
                "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
                "surface_id, context_id, static_bundle_hash, index_hash, "
                "context_hash, source_sha256, status, proposal_version, "
                "result_ref_json, registrations_json) "
                "VALUES (?, ?, ?, ?, 'surface-1', 'context-1', ?, ?, ?, ?, "
                "'NO_HYPOTHESIS', 9, ?, '[]')",
                (
                    run.analysis_id,
                    run.workspace_id,
                    run.commit_id,
                    run.candidate_scope_fingerprint,
                    "d" * 64,
                    "e" * 64,
                    "b" * 64,
                    "c" * 64,
                    marker_ref.model_dump_json(),
                ),
            )
    elif invalid == "boot_before_child":
        marker["observed_boot_at"] = (boot_at - timedelta(minutes=6)).isoformat()
        monkeypatch.setattr(
            "sastsimi.providers.codex_subscription.windows_boot_time_utc",
            lambda: boot_at - timedelta(minutes=6),
        )
    elif invalid == "live_boot_before_child":
        identity = _windows_start_identity(boot_at - timedelta(seconds=30))
        with sqlite3.connect(store.database_path) as connection:
            connection.execute(
                "UPDATE simple_codex_child_spawns SET start_identity = ? "
                "WHERE call_id = ?",
                (identity, call_id),
            )
        marker["observed_children"][0]["start_identity"] = identity
        monkeypatch.setattr(
            "sastsimi.providers.codex_subscription.windows_boot_time_utc",
            lambda: boot_at - timedelta(seconds=45),
        )
    elif invalid == "boot_unknown":
        monkeypatch.setattr(
            "sastsimi.providers.codex_subscription.windows_boot_time_utc",
            lambda: None,
        )
    elif invalid == "child_live":
        monkeypatch.setattr(
            "sastsimi.providers.codex_subscription.child_identity_matches",
            lambda _pid, _start_identity: True,
        )
    elif invalid == "child_identity_unknown":
        with sqlite3.connect(store.database_path) as connection:
            connection.execute(
                "UPDATE simple_codex_child_spawns SET start_identity = ? "
                "WHERE call_id = ?",
                ("windows:unknown-filetime", call_id),
            )
        marker["observed_children"][0]["start_identity"] = "windows:unknown-filetime"
    changed_ref = artifacts.put_json(marker)

    with pytest.raises(ValueError, match="CODEX_ORPHAN_RECOVERY_INVALID"):
        store.orphan_codex_rebooted_surface_call(
            run.analysis_id, call_id, changed_ref, artifacts
        )
    assert store.unresolved_codex_call(run.analysis_id) == call_id


def test_reboot_orphan_rejects_concurrent_analysis_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, run, call_id, marker_ref, _boot_at = _case(tmp_path, monkeypatch)
    with analysis_run_lease(tmp_path, run.analysis_id):
        with pytest.raises(ValueError, match="CODEX_ORPHAN_RECOVERY_ACTIVE_RUN"):
            store.orphan_codex_rebooted_surface_call(
                run.analysis_id, call_id, marker_ref, artifacts
            )
    assert store.unresolved_codex_call(run.analysis_id) == call_id
