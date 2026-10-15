"""A completed Codex surface call cannot silently run again after a crash."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sastsimi.simple_runtime.attempt_owner import AttemptOwner
from sastsimi.simple_runtime.models import SimpleStage
from tests.simple_runtime.test_surface_v9_additive_resume import (
    _case,
    _DeterministicAgent,
)
from tests.unit.simple_runtime.test_codex_orphan_recovery import (
    _windows_start_identity,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("call_safe", [False, True], ids=["in-flight", "safe"])
async def test_v9_missing_progress_blocks_completed_codex_call_before_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, call_safe: bool
) -> None:
    """Removing the saved-attempt preflight would invoke the Agent again."""

    case = _case(tmp_path, monkeypatch)
    app = case["app"]
    store = case["store"]
    run = case["run"]
    identity = case["identity"]
    artifacts = case["artifacts"]
    app._prepare_v9_surface_enrichment(run, identity, artifacts)
    pinned = store.require_analysis_run(identity.analysis_id)
    plan, contexts = app._saved_surface_enrichment_v9(pinned, identity, artifacts)
    assert contexts
    context = contexts[0]
    payload = json.loads(artifacts.read(context.context_ref))
    path = payload["context_part"]["path"]
    call_id = "completed-before-progress"
    assert store.begin_codex_call(call_id, identity.analysis_id)
    attempt_ref = artifacts.put_json(
        {
            "kind": "simple_llm_attempt",
            "provider": "codex-cli",
            "agent": "hypothesis_surface",
            "model": "test-model",
            "status": "SUCCEEDED",
            "raw_output_ref": None,
            "parsed_output_ref": None,
        }
    )
    store.record_llm_attempt(
        attempt_id=call_id,
        analysis_id=identity.analysis_id,
        agent="hypothesis_surface",
        model="test-model",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=10,
        input_tokens=5,
        output_tokens=5,
        cost_cents=None,
        artifact_ref=attempt_ref,
        owner=AttemptOwner(
            analysis_id=identity.analysis_id,
            stage="HYPOTHESIS_SURFACE",
            surface_id=context.surface_id,
            context_id=context.context_id,
            file_path=path,
        ),
    )
    if call_safe:
        store.mark_codex_call_safe(call_id, identity.analysis_id)
    agent = _DeterministicAgent(artifacts)
    monkeypatch.setattr(app, "_candidate_hypotheses", agent)

    result = await app._run_v9_surface_enrichment(
        pinned, identity, case["static"], artifacts, plan, contexts
    )

    assert result.status == "BLOCKED"
    assert result.error_code == "HYPOTHESIS_SURFACE_SAVED_CALL_UNADOPTABLE"
    assert result.current_stage is SimpleStage.HYPOTHESIS_DONE
    assert agent.calls == 0
    assert (
        store.list_surface_exploration_progress(
            identity, pinned.candidate_scope_fingerprint or ""
        )
        == {}
    )
    assert (
        store.require_analysis_run(identity.analysis_id).surface_enrichment_status
        == "BLOCKED"
    )


@pytest.mark.asyncio
async def test_v9_reboot_orphan_allows_one_audited_resume_then_blocks_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reboot proof authorizes one logical retry, never a second replay."""

    case = _case(tmp_path, monkeypatch)
    app = case["app"]
    store = case["store"]
    identity = case["identity"]
    artifacts = case["artifacts"]
    run = case["run"].model_copy(
        update={
            "provider": "codex",
            "llm_provider": "codex",
            "model": "test-model",
            "model_route_version": 1,
            "model_routes": {"hypothesis_surface": "test-model"},
            "candidate_pipeline_version": 2,
            "surface_enrichment_status": "RUNNING",
        }
    )
    store.save_analysis_run(run)
    app._prepare_v9_surface_enrichment(run, identity, artifacts)
    pinned = store.require_analysis_run(identity.analysis_id)
    plan_ref = pinned.surface_enrichment_v9_plan_ref
    assert plan_ref is not None
    plan, contexts = app._saved_surface_enrichment_v9(pinned, identity, artifacts)
    assert contexts
    context = contexts[0]
    payload = json.loads(artifacts.read(context.context_ref))
    path = payload["context_part"]["path"]
    call_id = "orphaned-completed-call"
    assert store.begin_codex_call(call_id, identity.analysis_id)
    now = datetime.now(UTC)
    started = now - timedelta(minutes=15)
    child_started = now - timedelta(minutes=10)
    booted = now - timedelta(minutes=5)
    child_identity = _windows_start_identity(child_started)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_codex_calls SET started_at = ? WHERE call_id = ?",
            (started.isoformat(), call_id),
        )
    store.begin_codex_child_spawn(
        call_id=call_id, analysis_id=identity.analysis_id, phase="EXEC"
    )
    store.record_codex_child_spawn(
        call_id=call_id,
        analysis_id=identity.analysis_id,
        phase="EXEC",
        pid=4242,
        start_identity=child_identity,
    )
    attempt_ref = artifacts.put_json(
        {
            "kind": "simple_llm_attempt",
            "provider": "codex-cli",
            "agent": "hypothesis_surface",
            "model": "test-model",
            "status": "SUCCEEDED",
            "raw_output_ref": None,
            "parsed_output_ref": None,
        }
    )
    owner = AttemptOwner(
        analysis_id=identity.analysis_id,
        stage="HYPOTHESIS_SURFACE",
        surface_id=context.surface_id,
        context_id=context.context_id,
        file_path=path,
    )
    store.record_llm_attempt(
        attempt_id=call_id,
        analysis_id=identity.analysis_id,
        agent="hypothesis_surface",
        model="test-model",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=10,
        input_tokens=5,
        output_tokens=5,
        cost_cents=None,
        artifact_ref=attempt_ref,
        owner=owner,
    )
    marker_ref = artifacts.put_json(
        {
            "kind": "simple_codex_reboot_orphan_confirmation",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "call_id": call_id,
            "call_started_at": started.isoformat(),
            "surface_id": context.surface_id,
            "context_id": context.context_id,
            "file_path": path,
            "model": "test-model",
            "surface_plan_hash": plan_ref.content_hash,
            "attempt_ref": attempt_ref.model_dump(mode="json"),
            "verification_method": "windows_reboot",
            "observed_boot_at": booted.isoformat(),
            "observed_at": now.isoformat(),
            "observed_children": [
                {"phase": "EXEC", "pid": 4242, "start_identity": child_identity}
            ],
            "former_parent_pid": 4242,
            "observed_matching_process_count": 0,
            "process_tree_stopped": True,
        }
    )
    monkeypatch.setattr(
        "sastsimi.providers.codex_subscription.windows_boot_time_utc",
        lambda: booted,
    )
    monkeypatch.setattr(
        "sastsimi.providers.codex_subscription.child_identity_matches",
        lambda _pid, _start_identity: None,
    )
    assert store.orphan_codex_rebooted_surface_call(
        identity.analysis_id, call_id, marker_ref, artifacts
    )
    # A completed call owned by another Agent does not consume this part's
    # one reboot-authorized logical retry.
    unrelated_id = "unrelated-pro-call"
    assert store.begin_codex_call(unrelated_id, identity.analysis_id)
    store.record_llm_attempt(
        attempt_id=unrelated_id,
        analysis_id=identity.analysis_id,
        agent="pro",
        model="test-model",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=10,
        input_tokens=5,
        output_tokens=5,
        cost_cents=None,
        artifact_ref=artifacts.put_json({"kind": "simple_llm_attempt", "agent": "pro"}),
        owner=AttemptOwner(
            analysis_id=identity.analysis_id,
            stage="PRO_CON",
            hypothesis_id="unrelated-hypothesis",
        ),
    )
    store.mark_codex_call_safe(unrelated_id, identity.analysis_id)

    class _CrashAfterRetry:
        calls = 0

        async def propose_surface(self, *args: object) -> object:
            self.calls += 1
            if self.calls == 1:
                retry_id = "one-audited-retry"
                assert store.begin_codex_call(retry_id, identity.analysis_id)
                store.record_llm_attempt(
                    attempt_id=retry_id,
                    analysis_id=identity.analysis_id,
                    agent="hypothesis_surface",
                    model="test-model",
                    attempt_number=1,
                    status="SUCCEEDED",
                    elapsed_ms=10,
                    input_tokens=5,
                    output_tokens=5,
                    cost_cents=None,
                    artifact_ref=attempt_ref,
                    owner=owner,
                )
                store.mark_codex_call_safe(retry_id, identity.analysis_id)
                raise RuntimeError("simulated crash before progress commit")
            return await _DeterministicAgent(artifacts).propose_surface(*args)

    agent = _CrashAfterRetry()
    monkeypatch.setattr(app, "_candidate_hypotheses", agent)
    with pytest.raises(RuntimeError, match="simulated crash"):
        await app._run_v9_surface_enrichment(
            pinned, identity, case["static"], artifacts, plan, contexts
        )
    with sqlite3.connect(store.database_path) as connection:
        retry_of = connection.execute(
            "SELECT retry_of FROM simple_llm_attempt_metadata WHERE attempt_id = ?",
            ("one-audited-retry",),
        ).fetchone()
    assert retry_of == (call_id,)

    second = await app._run_v9_surface_enrichment(
        pinned, identity, case["static"], artifacts, plan, contexts
    )
    assert second.status == "BLOCKED"
    assert second.error_code == "HYPOTHESIS_SURFACE_SAVED_CALL_UNADOPTABLE"
    assert agent.calls == 1
    assert (
        store.list_surface_exploration_progress(
            identity, pinned.candidate_scope_fingerprint or ""
        )
        == {}
    )
