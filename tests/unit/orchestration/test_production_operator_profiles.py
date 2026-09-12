from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sastsimi.config.production_profile import ProductionBudgetSettings
from sastsimi.contracts.actions import ActionRequest, ActionType, RequesterRole
from sastsimi.contracts.analysis import AnalysisRunState, AnalysisStartRequest
from sastsimi.contracts.budget import WORK_OPERATIONS, Purpose
from sastsimi.contracts.ids import (
    ActionId,
    AnalysisId,
    AttemptId,
    CommitId,
    LogicalRecordId,
    OpaqueId,
    RecordId,
    WorkId,
    WorkspaceId,
)
from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.work import (
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.orchestration.production_operator_profiles import (
    ProductionOperatorProfiles,
    ProductionTrustedEvidence,
)
from sastsimi.orchestration.run_scope_plan import PlannedRunScope

NOW = datetime(2026, 9, 13, tzinfo=UTC)


class _Clock:
    def now(self) -> datetime:
        return NOW

    def monotonic_ms(self) -> int:
        return 0


class _Ids:
    def __init__(self) -> None:
        self.index = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.index += 1
        return kind(f"operator-{kind.__name__.lower()}-{self.index}")


class _Publisher:
    def __init__(self) -> None:
        self.work = []
        self.verification = []
        self.dynamic = []

    def register_work_budget(self, record: object) -> StoredDataRef:
        self.work.append(record)
        ref = reference(record)
        assert isinstance(ref, StoredDataRef)
        return ref

    def register_verification_budget(self, record: object) -> StoredDataRef:
        self.verification.append(record)
        ref = reference(record)
        assert isinstance(ref, StoredDataRef)
        return ref

    def register_dynamic_lifecycle(self, record: object) -> StoredDataRef:
        self.dynamic.append(record)
        ref = reference(record)
        assert isinstance(ref, StoredDataRef)
        return ref


def _settings() -> ProductionBudgetSettings:
    return ProductionBudgetSettings(
        profile_key="operator-default",
        approval_key="approved-v1",
        approved_by="security-team",
        pricing_revision="pricing-v1",
        currency="USD",
        max_analysis_elapsed_ms=3_600_000,
        max_total_cost_minor_units=100_000,
        max_total_work=1_000,
        max_total_llm_calls=500,
        max_total_retries=100,
        max_parallel_work=8,
        work_timeout_ms=600_000,
        max_attempts_per_work=3,
        max_calls_per_work=10,
        max_items_per_work=1_000,
        max_verification_elapsed_ms=900_000,
        max_work_per_verification=100,
        max_llm_calls_per_verification=50,
        max_retries_per_work=3,
        max_parallel_evidence_calls=2,
        max_dynamic_attempts=3,
    )


def _scope() -> PlannedRunScope:
    return PlannedRunScope(
        analysis_id=AnalysisId("analysis-one"),
        workspace_id=WorkspaceId("workspace-one"),
        commit_id=CommitId("a" * 40),
        repository_ref="https://example.invalid/project.git",
    )


def _request(commit: str = "a" * 40) -> AnalysisStartRequest:
    return AnalysisStartRequest(
        repository_ref="https://example.invalid/project.git",
        requested_git_ref=commit,
        program_id="program-one",
        purpose=Purpose.PRODUCTION,
    )


def _workspace_ready_state(catalog: ProductionOperatorProfiles) -> AnalysisRunState:
    execution_ref = reference(catalog.execution_profile)
    assert isinstance(execution_ref, RunStoredDataRef)
    return AnalysisRunState(
        meta=RunMeta(
            record_id="state-ready",
            logical_record_id="state",
            record_type="analysis_run_state",
            schema_version="1.0.0",
            revision_number=2,
            previous_record_id="state-started",
            created_at=NOW,
            analysis_id=_scope().analysis_id,
        ),
        purpose=Purpose.PRODUCTION,
        eval_config_refs=(),
        analysis_input_ref=RunStoredDataRef(
            stored_data_id="input",
            data_kind="analysis_run_input",
            content_hash="d" * 64,
            analysis_id=_scope().analysis_id,
            record_id="input",
        ),
        program_id="program-one",
        execution_budget_profile_ref=execution_ref,
        budget_binding_ref=None,
        workspace_id=_scope().workspace_id,
        commit_id=_scope().commit_id,
        workspace_ref=RunStoredDataRef(
            stored_data_id="workspace",
            data_kind="code_workspace",
            content_hash="e" * 64,
            analysis_id=_scope().analysis_id,
            record_id="workspace",
        ),
        run_policy_state_ref=None,
        status="RUNNING",
        analysis_result_ref=None,
        started_at=NOW,
        finished_at=None,
        elapsed_ms=0,
    )


def test_builds_and_publishes_exact_operator_owned_budget_and_role_profiles() -> None:
    catalog = ProductionOperatorProfiles(
        scope=_scope(),
        program_id="program-one",
        settings=_settings(),
        clock=_Clock(),
        ids=_Ids(),
    )
    evidence = ProductionTrustedEvidence(catalog)
    publisher = _Publisher()

    catalog.publish_code_profiles(publisher)
    execution = catalog.resolve_active_execution(_request())
    binding = catalog.resolve_active_binding(
        _request(), _workspace_ready_state(catalog)
    )

    assert evidence.approved(execution)
    assert evidence.pricing(execution)
    assert evidence.approved(binding)
    assert evidence.budget_configuration_approved(catalog.work_profile)
    assert len(catalog.work_profile.limits) == len(WORK_OPERATIONS) + 1
    assert len(publisher.work) == len(RequesterRole)
    assert publisher.verification == [catalog.verification_profile]
    assert publisher.dynamic == [catalog.dynamic_profile]
    assert (
        evidence.identity_role(catalog.identity_ref(RequesterRole.HYPOTHESIS))
        == RequesterRole.HYPOTHESIS
    )
    assert (
        evidence.identity_role(catalog.identity_ref(RequesterRole.REPOSITORY_LOADER))
        == RequesterRole.REPOSITORY_LOADER
    )


def test_rejects_wrong_scope_and_never_approves_a_modified_profile() -> None:
    catalog = ProductionOperatorProfiles(
        scope=_scope(),
        program_id="program-one",
        settings=_settings(),
        clock=_Clock(),
        ids=_Ids(),
    )
    evidence = ProductionTrustedEvidence(catalog)

    with pytest.raises(ValueError, match="OPERATOR_PROFILE_SCOPE_MISMATCH"):
        catalog.resolve_active_execution(_request("b" * 40))

    modified = catalog.execution_profile.model_copy(update={"max_total_llm_calls": 501})
    assert not evidence.approved(modified)
    assert not evidence.pricing(modified)


def test_multi_output_approval_is_exact_and_exists_only_inside_its_context() -> None:
    catalog = ProductionOperatorProfiles(
        scope=_scope(),
        program_id="program-one",
        settings=_settings(),
        clock=_Clock(),
        ids=_Ids(),
    )
    evidence = ProductionTrustedEvidence(catalog)
    identity = catalog.identity_ref(RequesterRole.STATIC_ANALYSIS)
    attempt_id = AttemptId("attempt-one")
    transition_ref = StoredDataRef(
        stored_data_id="transition",
        data_kind="state_transition",
        content_hash="f" * 64,
        workspace_id=_scope().workspace_id,
        commit_id=_scope().commit_id,
        record_id="transition",
    )
    work = WorkExecutionState(
        meta=RecordMeta(
            record_id="work-one",
            logical_record_id="work-one",
            record_type="work_execution_state",
            schema_version="1.0.0",
            revision_number=2,
            previous_record_id="work-pending",
            created_at=NOW,
            analysis_id=_scope().analysis_id,
            workspace_id=_scope().workspace_id,
            commit_id=_scope().commit_id,
            hypothesis_id=None,
            attempt_id=None,
        ),
        work_id=WorkId("work-one"),
        parent_work_ref=None,
        work_type=WorkType.STATIC_TOOL,
        subject_type=SubjectType.ANALYSIS,
        subject_id=_scope().analysis_id,
        work_generation=1,
        status=WorkStatus.RUNNING,
        state_version=2,
        last_transition_ref=transition_ref,
        last_transition_commit_ref=None,
        active_attempt_id=attempt_id,
        input_hash="1" * 64,
        dedupe_key="2" * 64,
        trigger_primitive_ref=None,
        input_refs=(),
        output_refs=(),
        gap_ids=(),
        error_ids=(),
        waiting_for=(),
        stop_reason=None,
        started_at=NOW,
        finished_at=None,
        elapsed_ms=0,
    )
    work_ref = reference(work)
    assert isinstance(work_ref, StoredDataRef)
    outputs = (
        StoredDataRef(
            stored_data_id="result-one",
            data_kind="tool_run_result",
            content_hash="b" * 64,
            workspace_id=_scope().workspace_id,
            commit_id=_scope().commit_id,
            record_id="result-one",
        ),
        StoredDataRef(
            stored_data_id="result-two",
            data_kind="rule_execution_record",
            content_hash="c" * 64,
            workspace_id=_scope().workspace_id,
            commit_id=_scope().commit_id,
            record_id="result-two",
        ),
    )
    action = ActionRequest(
        meta=RecordMeta(
            record_id=RecordId("action-record"),
            logical_record_id=LogicalRecordId("action-record"),
            record_type="action_request",
            schema_version="1.0.0",
            revision_number=1,
            previous_record_id=None,
            created_at=NOW,
            analysis_id=_scope().analysis_id,
            workspace_id=_scope().workspace_id,
            commit_id=_scope().commit_id,
            hypothesis_id=None,
            attempt_id=attempt_id,
        ),
        action_id=ActionId("action-one"),
        requested_by=RequesterRole.STATIC_ANALYSIS,
        requester_identity_ref=identity,
        action_type=ActionType.SAVE_RESULT,
        work_ref=work_ref,
        expected_state_version=2,
        expected_verification_generation=None,
        generation_restart_reason=None,
        generation_restart_basis_refs=(),
        input_refs=(),
        dynamic_request_ref=None,
        reproduction_plan_ref=None,
        result_kind="tool_run_result",
        candidate_result_ref=outputs[0],
        llm_call_spec_ref=None,
        tool_name=None,
        file_paths=(),
        provider_profile_ref=None,
        session_mode=None,
        sandbox_profile_ref=None,
        resource_profile_ref=None,
        run_policy_state_ref=None,
        image_digest=None,
        network_targets=(),
        resource_limits=None,
        reason="trusted-runtime",
        requested_at=NOW,
    )

    assert evidence.authorized_outputs(action) is None
    with evidence.output_approval(action, work, outputs):
        assert evidence.authorized_outputs(action) == outputs
        substituted = action.model_copy(update={"reason": "repository-substitution"})
        assert evidence.authorized_outputs(substituted) is None
    assert evidence.authorized_outputs(action) is None
