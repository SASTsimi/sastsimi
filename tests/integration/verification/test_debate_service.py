"""Integration checks for the production Pro/Con debate coordinator."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime
from io import BytesIO
from types import SimpleNamespace
from typing import Any

import pytest

from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    ProfileStatus,
    Purpose,
    VerificationBudgetProfile,
)
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.ids import AttemptId
from sastsimi.contracts.llm import (
    LLMCallSpec,
    LLMInvocationRequest,
    LLMInvocationResult,
    PromptContextBinding,
    PromptPayload,
)
from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import (
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.verification import ProEvidenceResult
from sastsimi.contracts.work import (
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.dto import Record, StagedArtifact
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from sastsimi.verification.debate_service import (
    CurrentEvidenceParallelLimit,
    DebateIncompleteError,
    DebateService,
)

NOW = datetime(2026, 9, 11, tzinfo=UTC)


def _ref(kind: str, name: str, *, record: bool = True) -> StoredDataRef:
    digest = hashlib.sha256(f"{kind}:{name}".encode()).hexdigest()
    return StoredDataRef.model_validate(
        {
            "stored_data_id": name,
            "data_kind": kind,
            "content_hash": digest,
            "workspace_id": "ws1",
            "commit_id": "c1",
            "record_id": f"{name}-record" if record else None,
        }
    )


def _run_ref(kind: str, name: str) -> RunStoredDataRef:
    digest = hashlib.sha256(f"{kind}:{name}".encode()).hexdigest()
    return RunStoredDataRef.model_validate(
        {
            "stored_data_id": name,
            "data_kind": kind,
            "content_hash": digest,
            "record_id": f"{name}-record",
            "analysis_id": "analysis-1",
        }
    )


def _meta(kind: str, name: str, *, attempt: str | None) -> RecordMeta:
    return RecordMeta.model_validate(
        {
            "record_id": f"{name}-record",
            "logical_record_id": f"{name}-logical",
            "record_type": kind,
            "schema_version": "1.0.0",
            "revision_number": 1,
            "previous_record_id": None,
            "created_at": NOW,
            "analysis_id": "analysis-1",
            "workspace_id": "ws1",
            "commit_id": "c1",
            "hypothesis_id": "hypothesis-1",
            "attempt_id": attempt,
        }
    )


def _work(
    role: str,
    public_inputs: tuple[StoredDataRef, ...],
    *,
    parent: WorkExecutionState | None = None,
) -> WorkExecutionState:
    is_parent = role == "VERIFICATION"
    attempt = None if is_parent else f"{role.lower()}-attempt"
    parent_ref = None
    if not is_parent:
        assert parent is not None
        parent_ref = reference(parent)
    return WorkExecutionState.model_validate(
        {
            "meta": _meta("work_execution_state", f"{role.lower()}-work", attempt=None),
            "work_id": f"{role.lower()}-work",
            "parent_work_ref": parent_ref,
            "work_type": WorkType.VERIFICATION
            if is_parent
            else WorkType(f"{role}_EVIDENCE"),
            "subject_type": SubjectType.HYPOTHESIS,
            "subject_id": "hypothesis-1",
            "work_generation": 3,
            "status": WorkStatus.RUNNING,
            "state_version": 2,
            "last_transition_ref": _ref(
                "state_transition", f"{role.lower()}-transition"
            ),
            "last_transition_commit_ref": None,
            "active_attempt_id": "verification-attempt" if is_parent else attempt,
            "input_hash": content_hash(public_inputs),
            "dedupe_key": hashlib.sha256(f"dedupe:{role}".encode()).hexdigest(),
            "trigger_primitive_ref": None,
            "input_refs": public_inputs,
            "output_refs": (),
            "gap_ids": (),
            "error_ids": (),
            "waiting_for": (),
            "stop_reason": None,
            "started_at": NOW,
            "finished_at": None,
            "elapsed_ms": 0,
        }
    )


class MemoryArtifacts:
    def __init__(self) -> None:
        self.data: dict[tuple[str, str], bytes] = {}

    def put(self, payload: object) -> StoredDataRef:
        data = canonical_bytes(payload)
        digest = hashlib.sha256(data).hexdigest()
        ref = StoredDataRef.model_validate(
            {
                "stored_data_id": digest,
                "data_kind": "artifact",
                "content_hash": digest,
                "workspace_id": "ws1",
                "commit_id": "c1",
                "record_id": None,
            }
        )
        self.data[(str(ref.stored_data_id), ref.content_hash)] = data
        return ref

    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact:
        return StagedArtifact(data=data, media_type=media_type)

    def commit(self, staged: StagedArtifact) -> StoredDataRef:
        return self.put(__import__("json").loads(staged.data))

    def open_verified(self, ref: StoredDataRef) -> BytesIO:
        return BytesIO(self.data[(str(ref.stored_data_id), ref.content_hash)])


class MemoryRecords:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], Record] = {}

    @staticmethod
    def _key(ref: RecordRef) -> tuple[str, str]:
        return str(ref.record_id), ref.content_hash

    def publish(self, value: Record) -> StoredDataRef:
        ref = reference(value)
        assert isinstance(ref, StoredDataRef)
        self.values[self._key(ref)] = value
        return ref

    def get_exact(self, ref: RecordRef) -> Record:
        return self.values[self._key(ref)]

    def stage_record(self, record: Record) -> RecordRef:
        return reference(record)


class MetadataFactory:
    def __init__(self) -> None:
        self.sequence = 0

    def __call__(
        self, source: RecordMeta, record_type: str, attempt_id: AttemptId | None
    ) -> RecordMeta:
        self.sequence += 1
        name = f"{record_type}-{self.sequence}"
        return RecordMeta.model_validate(
            source.model_dump()
            | {
                "record_id": f"{name}-record",
                "logical_record_id": f"{name}-logical",
                "record_type": record_type,
                "revision_number": 1,
                "previous_record_id": None,
                "created_at": NOW,
                "attempt_id": attempt_id,
            }
        )


class ClaimIds:
    def __init__(self) -> None:
        self.sequence = 0

    def __call__(self, role: str) -> str:
        self.sequence += 1
        return f"{role.lower()}-claim-{self.sequence}"


class RecordingPublisher:
    def __init__(self, records: MemoryRecords) -> None:
        self.records = records
        self.published: list[Record] = []

    def __call__(
        self,
        work: WorkExecutionState,
        value: Record,
        _invocation: PersistedLLMInvocation,
    ) -> StoredDataRef:
        assert isinstance(value.meta, RecordMeta)
        assert value.meta.attempt_id == work.active_attempt_id
        self.published.append(value)
        return self.records.publish(value)


class ConcurrentLLMCalls:
    def __init__(
        self,
        records: MemoryRecords,
        artifacts: MemoryArtifacts,
        outputs: dict[str, object],
        *,
        fail_roles: frozenset[str] = frozenset(),
    ) -> None:
        self.records = records
        self.artifacts = artifacts
        self.outputs = outputs
        self.fail_roles = fail_roles
        self.active = 0
        self.max_active = 0
        self.calls: list[str] = []

    async def invoke(
        self,
        *,
        work: WorkExecutionState,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
    ) -> PersistedLLMInvocation:
        del reservation_ref
        spec = self.records.get_exact(call_spec_ref)
        assert isinstance(spec, LLMCallSpec)
        self.calls.append(str(spec.agent_role))
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(0)
            if str(spec.agent_role) in self.fail_roles:
                raise RuntimeError("provider failed")
        finally:
            self.active -= 1
        request = LLMInvocationRequest.model_validate(
            spec.model_dump()
            | {
                "meta": _meta(
                    "llm_invocation_request",
                    f"{spec.agent_role.lower()}-request",
                    attempt=str(work.active_attempt_id),
                ),
                "action_decision_ref": decision_ref,
                "call_spec_ref": call_spec_ref,
            }
        )
        output_ref = self.artifacts.put(self.outputs[str(spec.agent_role)])
        result = LLMInvocationResult.model_validate(
            {
                "meta": _meta(
                    "llm_invocation_result",
                    f"{spec.agent_role.lower()}-result",
                    attempt=str(work.active_attempt_id),
                ),
                "llm_call_id": spec.llm_call_id,
                "purpose": spec.purpose,
                "status": "SUCCEEDED",
                "provider": "OPENAI",
                "model": spec.model,
                "actual_session_mode": "NEW",
                "session_ref": f"{spec.agent_role.lower()}-session",
                "response_ref": output_ref,
                "parsed_output_ref": output_ref,
                "usage": None,
                "started_at": NOW,
                "finished_at": NOW,
                "elapsed_ms": 1,
                "safe_error": None,
            }
        )
        return PersistedLLMInvocation(
            request,
            result,
            _ref("llm_invocation_log", f"{spec.agent_role.lower()}-log"),
            "RETURNED",
        )


def _authorized_call(
    records: MemoryRecords,
    role: str,
    child: WorkExecutionState,
    public_inputs: tuple[StoredDataRef, ...],
) -> Any:
    task_kind = {
        "PRO": "COLLECT_SUPPORT",
        "CON": "COLLECT_COUNTEREVIDENCE",
    }[role]
    bindings = tuple(
        PromptContextBinding(
            slot=f"input-{index}",
            data_kind=ref.data_kind,
            source_ref=ref,
            projected_data_ref=_ref(
                "artifact", f"projected-{role}-{index}", record=False
            ),
            field_paths=("meta",),
            trust_class="UNTRUSTED_DATA",
        )
        for index, ref in enumerate(public_inputs)
    )
    payload = PromptPayload.model_validate(
        {
            "meta": _meta(
                "prompt_payload",
                f"{role.lower()}-payload",
                attempt=str(child.active_attempt_id),
            ),
            "registry_entry_ref": _ref(
                "prompt_registry_entry", f"{role.lower()}-entry"
            ),
            "prompt_key": f"{role.lower()}-review-evidence",
            "agent_role": role,
            "task_kind": task_kind,
            "purpose": "PRODUCTION",
            "template_ref": _ref("artifact", f"{role.lower()}-template", record=False),
            "template_version": "1.0.0",
            "context_bindings": bindings,
            "rendered_prompt_ref": _ref(
                "artifact", f"{role.lower()}-rendered", record=False
            ),
            "output_schema_ref": _ref("output_schema_spec", f"{role.lower()}-schema"),
        }
    )
    payload_ref = records.publish(payload)
    spec = LLMCallSpec.model_validate(
        {
            "meta": _meta(
                "llm_call_spec",
                f"{role.lower()}-spec",
                attempt=str(child.active_attempt_id),
            ),
            "llm_call_id": f"{role.lower()}-call",
            "agent_role": role,
            "task_kind": task_kind,
            "purpose": "PRODUCTION",
            "provider_profile_ref": _ref(
                "provider_profile", f"{role.lower()}-provider"
            ),
            "model": "model-test",
            "session_policy": "NEW",
            "parent_session_ref": None,
            "context_refs": public_inputs,
            "prompt_registry_entry_ref": payload.registry_entry_ref,
            "prompt_key": payload.prompt_key,
            "prompt_template_ref": payload.template_ref,
            "prompt_template_version": payload.template_version,
            "prompt_payload_ref": payload_ref,
            "execution_limits_ref": _ref("execution_limits", f"{role.lower()}-limits"),
            "retry_policy_ref": _ref("llm_retry_policy", f"{role.lower()}-retry"),
            "tool_policy_ref": _ref("llm_tool_policy", f"{role.lower()}-tools"),
            "redaction_policy_ref": _ref(
                "prompt_redaction_policy", f"{role.lower()}-redaction"
            ),
            "semantic_validator_ref": _ref(
                "semantic_validator_spec", f"{role.lower()}-validator"
            ),
            "output_schema_ref": payload.output_schema_ref,
            "output_schema": '{"type":"object"}',
            "token_budget": 100,
            "timeout_ms": 1_000,
        }
    )
    return SimpleNamespace(
        work=child,
        decision_ref=_ref("action_decision", f"{role.lower()}-decision"),
        reservation_ref=_ref("budget_reservation", f"{role.lower()}-reservation"),
        call_spec_ref=records.publish(spec),
    )


def _output(role: str, evidence_ref: StoredDataRef) -> dict[str, Any]:
    return {
        "evidence": [
            {
                "statement": f"{role} observed the exact source-to-sink path",
                "evidence_refs": [evidence_ref.model_dump(mode="json")],
                "code_locations": [
                    {
                        "workspace_id": "ws1",
                        "commit_id": "c1",
                        "file_path": "src/app.py",
                        "start_line": 10,
                        "end_line": 11,
                        "start_column": None,
                        "end_column": None,
                    }
                ],
                "limitations": [],
            }
        ],
        "summary": f"{role} completed an independent review",
        "limitations": [],
    }


@pytest.mark.asyncio
async def test_budget_limit_rejects_zero_and_allows_parallel_new_sessions() -> None:
    """Catches a zero-capacity hang, serial bypass, or shared Pro/Con session."""
    public_inputs = tuple(
        sorted(
            (
                _ref("static_fact_bundle", "facts"),
                _ref("playbook_application", "application"),
            ),
            key=canonical_bytes,
        )
    )
    parent = _work("VERIFICATION", public_inputs)
    pro_work = _work("PRO", public_inputs, parent=parent)
    con_work = _work("CON", public_inputs, parent=parent)
    records, artifacts = MemoryRecords(), MemoryArtifacts()
    pro_call = _authorized_call(records, "PRO", pro_work, public_inputs)
    con_call = _authorized_call(records, "CON", con_work, public_inputs)
    calls = ConcurrentLLMCalls(
        records,
        artifacts,
        {
            "PRO": _output("PRO", public_inputs[0]),
            "CON": _output("CON", public_inputs[0]),
        },
    )
    publisher = RecordingPublisher(records)
    blocked_service = DebateService(
        records=records,
        artifacts=artifacts,
        llm_calls=calls,
        metadata_factory=MetadataFactory(),
        claim_id_factory=ClaimIds(),
        publish_result=publisher,
        parallel_limit=lambda _work: 0,
    )
    with pytest.raises(ValueError, match="BUDGET_EXCEEDED"):
        await asyncio.wait_for(
            blocked_service.run(
                verification_work=parent,
                public_input_refs=public_inputs,
                pro_call=pro_call,
                con_call=con_call,
            ),
            timeout=0.05,
        )
    assert calls.calls == []

    service = DebateService(
        records=records,
        artifacts=artifacts,
        llm_calls=calls,
        metadata_factory=MetadataFactory(),
        claim_id_factory=ClaimIds(),
        publish_result=publisher,
        parallel_limit=lambda _work: 2,
    )

    result = await service.run(
        verification_work=parent,
        public_input_refs=public_inputs,
        pro_call=pro_call,
        con_call=con_call,
    )

    assert calls.max_active == 2
    assert set(calls.calls) == {"PRO", "CON"}
    assert result.pro.debate_input_hash == result.con.debate_input_hash
    assert result.pro.meta.attempt_id != result.con.meta.attempt_id
    assert result.pro.llm_call_id != result.con.llm_call_id
    assert result.pro_session_ref != result.con_session_ref
    assert result.pro.evidence[0].claim_id.startswith("pro-claim-")
    assert result.con.evidence[0].claim_id.startswith("con-claim-")
    assert result.pro.evidence[0].source_role == "PRO"
    assert result.con.evidence[0].source_role == "CON"
    assert records.get_exact(result.pro_ref) == result.pro
    assert records.get_exact(result.con_ref) == result.con


@pytest.mark.asyncio
async def test_limit_one_serializes_calls_and_failure_cannot_complete_debate() -> None:
    """Catches bypassing the trusted evidence cap or joining one-sided evidence."""
    public_inputs = tuple(
        sorted(
            (
                _ref("static_fact_bundle", "facts"),
                _ref("playbook_application", "application"),
            ),
            key=canonical_bytes,
        )
    )
    parent = _work("VERIFICATION", public_inputs)
    pro_work = _work("PRO", public_inputs, parent=parent)
    con_work = _work("CON", public_inputs, parent=parent)
    records, artifacts = MemoryRecords(), MemoryArtifacts()
    pro_call = _authorized_call(records, "PRO", pro_work, public_inputs)
    con_call = _authorized_call(records, "CON", con_work, public_inputs)
    calls = ConcurrentLLMCalls(
        records,
        artifacts,
        {
            "PRO": _output("PRO", public_inputs[0]),
            "CON": _output("CON", public_inputs[0]),
        },
        fail_roles=frozenset({"CON"}),
    )
    publisher = RecordingPublisher(records)
    service = DebateService(
        records=records,
        artifacts=artifacts,
        llm_calls=calls,
        metadata_factory=MetadataFactory(),
        claim_id_factory=ClaimIds(),
        publish_result=publisher,
        parallel_limit=lambda _work: 1,
    )

    with pytest.raises(DebateIncompleteError) as captured:
        await service.run(
            verification_work=parent,
            public_input_refs=public_inputs,
            pro_call=pro_call,
            con_call=con_call,
        )

    assert calls.max_active == 1
    assert set(calls.calls) == {"PRO", "CON"}
    assert captured.value.failure_count == 1
    assert captured.value.completed_refs == tuple(
        reference(value) for value in publisher.published
    )
    assert len(publisher.published) == 1
    assert isinstance(publisher.published[0], ProEvidenceResult)


def test_parallel_limit_uses_only_current_exact_active_budget_binding() -> None:
    """Catches caller limits, inactive bindings, or non-exact profile resolution."""
    public_inputs = (_ref("static_fact_bundle", "facts"),)
    parent = _work("VERIFICATION", public_inputs)
    records = MemoryRecords()
    execution_ref = _run_ref("execution_budget_profile", "execution-budget")
    profile = VerificationBudgetProfile.model_validate(
        {
            "meta": _meta(
                "verification_budget_profile", "verification-budget", attempt=None
            ).model_copy(update={"hypothesis_id": None}),
            "profile_key": "verification",
            "max_verification_elapsed_ms": 1_000,
            "max_work_per_verification": 5,
            "max_llm_calls_per_verification": 5,
            "max_retries_per_work": 1,
            "max_parallel_evidence_calls": 1,
            "status": ProfileStatus.ACTIVE,
        }
    )
    profile_ref = records.publish(profile)
    binding = BudgetProfileBinding.model_validate(
        {
            "meta": _meta(
                "budget_profile_binding", "budget-binding", attempt=None
            ).model_copy(update={"hypothesis_id": None}),
            "binding_key": "binding",
            "purpose": Purpose.PRODUCTION,
            "execution_budget_profile_ref": execution_ref,
            "work_budget_profile_ref": _ref("work_budget_profile", "work-budget"),
            "verification_budget_profile_ref": profile_ref,
            "dynamic_lifecycle_profile_ref": _ref(
                "dynamic_reproduction_lifecycle_profile", "dynamic-budget"
            ),
            "approval_ref": execution_ref,
            "approved_by": "R8",
            "approved_at": NOW,
            "status": ProfileStatus.ACTIVE,
        }
    )
    binding_ref = records.publish(binding)
    run = AnalysisRunState.model_validate(
        {
            "meta": RunMeta.model_validate(
                {
                    "record_id": "run-record",
                    "logical_record_id": "run-logical",
                    "record_type": "analysis_run_state",
                    "schema_version": "1.0.0",
                    "revision_number": 1,
                    "previous_record_id": None,
                    "created_at": NOW,
                    "analysis_id": "analysis-1",
                }
            ),
            "purpose": Purpose.PRODUCTION,
            "eval_config_refs": (),
            "analysis_input_ref": _run_ref("analysis_run_input", "run-input"),
            "program_id": "program-1",
            "execution_budget_profile_ref": execution_ref,
            "budget_binding_ref": binding_ref,
            "workspace_id": "ws1",
            "commit_id": "c1",
            "workspace_ref": _run_ref("code_workspace", "workspace"),
            "run_policy_state_ref": None,
            "status": "RUNNING",
            "analysis_result_ref": None,
            "started_at": NOW,
            "finished_at": None,
            "elapsed_ms": 0,
        }
    )
    current = SimpleNamespace(current_state=lambda _analysis_id: run)
    resolver = CurrentEvidenceParallelLimit(records=records, run_states=current)

    assert resolver(parent) == 1

    draft_binding = binding.model_copy(
        update={
            "meta": _meta(
                "budget_profile_binding", "draft-binding", attempt=None
            ).model_copy(update={"hypothesis_id": None}),
            "approval_ref": None,
            "approved_at": None,
            "status": ProfileStatus.DRAFT,
        }
    )
    draft_ref = records.publish(draft_binding)
    current.current_state = lambda _analysis_id: run.model_copy(
        update={"budget_binding_ref": draft_ref}
    )
    with pytest.raises(ValueError, match="EVIDENCE_BUDGET_PROFILE_NOT_CURRENT"):
        resolver(parent)

    current.current_state = lambda _analysis_id: run
    stale_profile = profile.model_copy(
        update={
            "meta": profile.meta.model_copy(
                update={
                    "record_id": "verification-budget-record-v2",
                    "revision_number": 2,
                    "previous_record_id": profile.meta.record_id,
                }
            )
        }
    )
    records.values[records._key(profile_ref)] = stale_profile
    with pytest.raises(ValueError, match="EVIDENCE_BUDGET_PROFILE_NOT_CURRENT"):
        resolver(parent)
