"""LOCAL_EVALUATION policy must never look like official bounty approval."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.composition.local_evaluation_policy import (
    LocalEvaluationPolicyPostWorkspaceSeeder,
    LocalEvaluationPolicySource,
    local_evaluation_policy_boundary_bytes,
)
from sastsimi.contracts.actions import ActionType, RequesterRole
from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.ids import ProgramId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.policy.adapters.official_http import PolicySourceBoundaryError
from sastsimi.ports.dto import OfficialPolicyFetchRequest
from sastsimi.runtime.fake_support import FakeClock


def _record_ref(kind: str, value: str) -> StoredDataRef:
    return StoredDataRef.model_validate(
        dict(
            stored_data_id=value,
            data_kind=kind,
            content_hash="a" * 64,
            workspace_id="workspace-1",
            commit_id="b" * 40,
            record_id=value,
        )
    )


def _request() -> AnalysisStartRequest:
    return AnalysisStartRequest(
        repository_ref="https://example.invalid/repository.git",
        requested_git_ref="b" * 40,
        program_id=ProgramId("local-program"),
        purpose=Purpose.LOCAL_EVALUATION,
    )


def test_boundary_declares_local_only_and_denies_external_disclosure() -> None:
    raw = local_evaluation_policy_boundary_bytes(
        analysis_id="analysis-1",
        program_id=ProgramId("local-program"),
    )

    value = json.loads(raw)

    assert value["purpose"] == "LOCAL_EVALUATION"
    assert value["official_program_policy"] == "NOT_PROVIDED"
    assert value["external_disclosure"] == "DENY"
    assert value["remote_target_testing"] == "DENY"
    assert value["allowed_execution"] == [
        "LOCAL_STATIC_ANALYSIS",
        "LOCAL_ISOLATED_SANDBOX",
    ]
    assert "UNAPPROVED_EGRESS" in value["hard_restrictions"]


def test_source_returns_unverified_boundary_for_exact_run_scope() -> None:
    clock = FakeClock()
    binding_ref = _record_ref("budget_profile_binding", "binding-1")
    boundary_ref = StoredDataRef.model_validate(
        dict(
            stored_data_id="c" * 64,
            data_kind="artifact",
            content_hash="c" * 64,
            workspace_id="workspace-1",
            commit_id="b" * 40,
            record_id=None,
        )
    )
    raw = local_evaluation_policy_boundary_bytes(
        analysis_id="analysis-1",
        program_id=ProgramId("local-program"),
    )
    digest = hashlib.sha256(raw).hexdigest()
    source = LocalEvaluationPolicySource(
        program_id=ProgramId("local-program"),
        source_config_ref=binding_ref,
        boundary_ref=boundary_ref.model_copy(
            update={"stored_data_id": digest, "content_hash": digest}
        ),
        boundary_bytes=raw,
        analysis_id="analysis-1",
        clock=clock,
    )
    action = SimpleNamespace(
        action_type=ActionType.FETCH_POLICY,
        requested_by=RequesterRole.POLICY_COLLECTOR,
        input_refs=(binding_ref,),
    )

    result = asyncio.run(
        source.fetch_official(
            OfficialPolicyFetchRequest(
                action=cast(Any, action),
                program_id=ProgramId("local-program"),
                source_config_ref=binding_ref,
            )
        )
    )

    assert result.content == raw
    assert result.source_check.status == "UNVERIFIED"
    assert result.source_check.evidence_refs == ()
    assert result.source_check.source_ref.content_hash == digest
    assert result.source_check.publisher == "LOCAL_EVALUATION_OPERATOR"


def test_source_rejects_other_program_or_configuration() -> None:
    binding_ref = _record_ref("budget_profile_binding", "binding-1")
    other_ref = _record_ref("budget_profile_binding", "binding-2")
    boundary_ref = StoredDataRef.model_validate(
        dict(
            stored_data_id="c" * 64,
            data_kind="artifact",
            content_hash="c" * 64,
            workspace_id="workspace-1",
            commit_id="b" * 40,
            record_id=None,
        )
    )
    raw = local_evaluation_policy_boundary_bytes(
        analysis_id="analysis-1",
        program_id=ProgramId("local-program"),
    )
    digest = hashlib.sha256(raw).hexdigest()
    source = LocalEvaluationPolicySource(
        program_id=ProgramId("local-program"),
        source_config_ref=binding_ref,
        boundary_ref=boundary_ref.model_copy(
            update={"stored_data_id": digest, "content_hash": digest}
        ),
        boundary_bytes=raw,
        analysis_id="analysis-1",
        clock=FakeClock(),
    )
    action = SimpleNamespace(
        action_type=ActionType.FETCH_POLICY,
        requested_by=RequesterRole.POLICY_COLLECTOR,
        input_refs=(other_ref,),
    )

    with pytest.raises(
        PolicySourceBoundaryError, match="LOCAL_POLICY_FETCH_SCOPE_MISMATCH"
    ):
        asyncio.run(
            source.fetch_official(
                OfficialPolicyFetchRequest(
                    action=cast(Any, action),
                    program_id=ProgramId("other-program"),
                    source_config_ref=other_ref,
                )
            )
        )


class _Runner:
    def __init__(self) -> None:
        self.begin_calls: list[dict[str, object]] = []
        self.enqueue_calls: list[tuple[object, ...]] = []
        self.binding_meta = RecordMeta.model_validate(
            dict(
                schema_version="1.0.0",
                record_id="binding-record",
                logical_record_id="binding-record",
                record_type="budget_profile_binding",
                revision_number=1,
                previous_record_id=None,
                created_at=datetime(2026, 9, 20, tzinfo=UTC),
                analysis_id="analysis-1",
                workspace_id="workspace-1",
                commit_id="b" * 40,
                hypothesis_id=None,
                attempt_id=None,
            )
        )
        records = SimpleNamespace(
            get_exact=lambda _ref: SimpleNamespace(meta=self.binding_meta)
        )
        self.runtime = SimpleNamespace(unit_of_work=SimpleNamespace(records=records))

    def begin_policy(self, *args: object, **kwargs: object) -> object:
        self.begin_calls.append({"args": args, **kwargs})
        return SimpleNamespace(work="pending-policy-work")

    def enqueue_registered(self, *args: object, **kwargs: object) -> object:
        self.enqueue_calls.append((*args, kwargs))
        return "ready-policy-work"


def test_seeder_registers_one_exact_local_policy_work() -> None:
    runner = _Runner()
    identity_ref = _record_ref("agent_identity", "orchestration-identity")
    binding_ref = _record_ref("budget_profile_binding", "binding-1")
    boundary_ref = StoredDataRef.model_validate(
        dict(
            stored_data_id="c" * 64,
            data_kind="artifact",
            content_hash="c" * 64,
            workspace_id="workspace-1",
            commit_id="b" * 40,
            record_id=None,
        )
    )
    seeder = LocalEvaluationPolicyPostWorkspaceSeeder(
        runner=cast(Any, runner),
        orchestration_identity_ref=identity_ref,
        boundary_ref=boundary_ref,
        parser_name="local-evaluation-policy-parser",
        parser_version="1",
    )
    state = SimpleNamespace(
        purpose=Purpose.LOCAL_EVALUATION,
        program_id=ProgramId("local-program"),
        budget_binding_ref=binding_ref,
        workspace_id=binding_ref.workspace_id,
        commit_id=binding_ref.commit_id,
        run_policy_state_ref=None,
        meta=SimpleNamespace(analysis_id=runner.binding_meta.analysis_id),
    )

    ready = seeder.ensure_initial(_request(), cast(Any, state), binding_ref)

    assert len(ready) == 1
    assert cast(Any, ready[0]) == "ready-policy-work"
    assert runner.begin_calls[0]["program_id"] == "local-program"
    assert runner.begin_calls[0]["source_config_ref"] == binding_ref
    assert runner.begin_calls[0]["source_input_refs"] == (boundary_ref,)
    assert runner.begin_calls[0]["parser_name"] == "local-evaluation-policy-parser"
    assert runner.begin_calls[0]["args"][1] == runner.binding_meta
    assert runner.enqueue_calls[0][0] == "pending-policy-work"
    assert runner.enqueue_calls[0][1] == binding_ref


def test_seeder_is_idempotent_and_rejects_non_local_use() -> None:
    runner = _Runner()
    identity_ref = _record_ref("agent_identity", "orchestration-identity")
    binding_ref = _record_ref("budget_profile_binding", "binding-1")
    seeder = LocalEvaluationPolicyPostWorkspaceSeeder(
        runner=cast(Any, runner),
        orchestration_identity_ref=identity_ref,
        boundary_ref=StoredDataRef.model_validate(
            dict(
                stored_data_id="c" * 64,
                data_kind="artifact",
                content_hash="c" * 64,
                workspace_id="workspace-1",
                commit_id="b" * 40,
                record_id=None,
            )
        ),
        parser_name="local-evaluation-policy-parser",
        parser_version="1",
    )
    already_seeded = SimpleNamespace(
        purpose=Purpose.LOCAL_EVALUATION,
        program_id=ProgramId("local-program"),
        budget_binding_ref=binding_ref,
        workspace_id=binding_ref.workspace_id,
        commit_id=binding_ref.commit_id,
        run_policy_state_ref=binding_ref,
        meta=SimpleNamespace(analysis_id="analysis-1"),
    )
    assert (
        seeder.ensure_initial(_request(), cast(Any, already_seeded), binding_ref) == ()
    )
    assert runner.begin_calls == []

    wrong = _request().model_copy(update={"purpose": Purpose.PRODUCTION})
    with pytest.raises(ValueError, match="LOCAL_POLICY_PURPOSE_REQUIRED"):
        seeder.ensure_initial(
            wrong,
            cast(
                Any,
                SimpleNamespace(
                    purpose=Purpose.PRODUCTION,
                    program_id=ProgramId("local-program"),
                    budget_binding_ref=binding_ref,
                    workspace_id=binding_ref.workspace_id,
                    commit_id=binding_ref.commit_id,
                    run_policy_state_ref=None,
                    meta=SimpleNamespace(analysis_id="analysis-1"),
                ),
            ),
            binding_ref,
        )


# mypy: disable-error-code="index"
