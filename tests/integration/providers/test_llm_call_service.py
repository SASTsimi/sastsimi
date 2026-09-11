import asyncio
import hashlib
import inspect
import io
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, BinaryIO, Literal, cast

import pytest
from pydantic import JsonValue
from sqlalchemy import create_engine

from sastsimi.bootstrap import build_runtime, upgrade_database
from sastsimi.contracts.actions import (
    REQUIRED_CHECKS,
    ActionCheck,
    ActionDecision,
    ActionRequest,
    ActionType,
    CheckResult,
    Decision,
    RequesterRole,
    SessionMode,
    UseStatus,
)
from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import AnalysisId, AttemptId, CommitId, WorkspaceId
from sastsimi.contracts.llm import (
    InvocationStatus,
    LLMCallSpec,
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    OutputSchemaSpec,
    PromptPayload,
    ProviderProfile,
    ProviderValidationEvidence,
    SemanticValidatorSpec,
)
from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import (
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.work import (
    SubjectType,
    TransitionCommit,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.dto import (
    CancellationResult,
    CapabilityProbeResult,
    Record,
    StagedArtifact,
    TransitionCommitRequest,
)
from sastsimi.prompts.validation import validate_output
from sastsimi.providers.base import (
    NormalizedProviderResult,
    ProviderInputMismatchError,
)
from sastsimi.providers.storage_io import (
    StoredInvocationResultBuilder,
    StoredOutputValidator,
    StoredPromptInputResolver,
)
from sastsimi.runtime.action_validator import RuntimeValidator
from sastsimi.runtime.external_call_service import ExternalCallService
from sastsimi.runtime.llm_call_service import (
    ExactAdapterResolver,
    LLMCallService,
    llm_action_input_refs,
)
from sastsimi.storage import models
from sastsimi.storage.action_validator import RuntimeValidator as SQLiteValidator
from sastsimi.storage.fake_action_validator import FakeRecordOutputRuntimeValidator
from sastsimi.storage.llm_session_guard import LLMParentSessionGuard
from sastsimi.storage.repositories import SQLiteRecordStore
from tests.contract.domain.canonical_fixtures import make
from tests.integration.runtime_support import TestIds

NOW = datetime(2026, 9, 11, tzinfo=UTC)
TEMPLATE = b"Return only the approved structured result."
SCHEMA = canonical_bytes({"type": "object"})


def metadata(
    kind: str,
    record_id: str,
    *,
    hypothesis_id: str | None = "h1",
    attempt_id: str | AttemptId | None = "at1",
) -> RecordMeta:
    return RecordMeta.model_validate(
        {
            "record_id": record_id,
            "logical_record_id": record_id,
            "record_type": kind,
            "schema_version": "1.0.0",
            "revision_number": 1,
            "previous_record_id": None,
            "created_at": NOW,
            "analysis_id": "a1",
            "workspace_id": "ws1",
            "commit_id": "c1",
            "hypothesis_id": hypothesis_id,
            "attempt_id": attempt_id,
        }
    )


def run_metadata(kind: str, record_id: str) -> RunMeta:
    return RunMeta.model_validate(
        {
            "record_id": record_id,
            "logical_record_id": record_id,
            "record_type": kind,
            "schema_version": "1.0.0",
            "revision_number": 1,
            "previous_record_id": None,
            "created_at": NOW,
            "analysis_id": "a1",
        }
    )


def run_ref(kind: str, name: str) -> RunStoredDataRef:
    return RunStoredDataRef.model_validate(
        {
            "stored_data_id": name,
            "data_kind": kind,
            "content_hash": hashlib.sha256(f"{kind}:{name}".encode()).hexdigest(),
            "analysis_id": "a1",
            "record_id": f"{name}-record",
        }
    )


def analysis_run_state() -> AnalysisRunState:
    return AnalysisRunState.model_validate(
        {
            "meta": run_metadata("analysis_run_state", "run-state"),
            "purpose": Purpose.EVALUATION,
            "eval_config_refs": (stored_ref("evaluation_config", "eval"),),
            "program_id": "program-1",
            "execution_budget_profile_ref": run_ref(
                "execution_budget_profile", "budget"
            ),
            "budget_binding_ref": None,
            "workspace_id": "ws1",
            "commit_id": "c1",
            "workspace_ref": None,
            "run_policy_state_ref": None,
            "status": "RUNNING",
            "analysis_result_ref": None,
            "started_at": NOW,
            "finished_at": None,
            "elapsed_ms": 0,
        }
    )


class MetadataFactory:
    def __init__(self) -> None:
        self.index = 0

    def __call__(
        self,
        source: RecordMeta,
        record_type: str,
        attempt_id: AttemptId | None,
    ) -> RecordMeta:
        self.index += 1
        return metadata(
            record_type,
            f"{record_type}-{self.index}",
            hypothesis_id=str(source.hypothesis_id)
            if source.hypothesis_id is not None
            else None,
            attempt_id=attempt_id,
        )


def ref_key(ref: RecordRef) -> bytes:
    return canonical_bytes(ref)


class MemoryRecords:
    def __init__(self) -> None:
        self.published: dict[bytes, Record] = {}
        self.staged: dict[bytes, Record] = {}

    def publish(self, record: Record) -> StoredDataRef:
        exact = reference(record)
        assert isinstance(exact, StoredDataRef)
        self.published[ref_key(exact)] = record
        return exact

    def get_exact(self, ref: RecordRef) -> Record:
        try:
            return self.published[ref_key(ref)]
        except KeyError as error:
            raise LookupError("exact record not published") from error

    def stage_record(self, record: Record) -> RecordRef:
        exact = reference(record)
        self.staged[ref_key(exact)] = record
        return exact

    def commit_transition(self, request: TransitionCommitRequest) -> TransitionCommit:
        raise AssertionError("transition commits are not used by these tests")


class MemoryArtifacts:
    def __init__(self) -> None:
        self.data: dict[bytes, bytes] = {}

    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact:
        return StagedArtifact(data=data, media_type=media_type)

    def commit(self, staged: StagedArtifact) -> StoredDataRef:
        digest = hashlib.sha256(staged.data).hexdigest()
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
        self.data[ref_key(ref)] = staged.data
        return ref

    def commit_run(
        self, staged: StagedArtifact, analysis_id: AnalysisId
    ) -> RunStoredDataRef:
        digest = hashlib.sha256(staged.data).hexdigest()
        ref = RunStoredDataRef.model_validate(
            {
                "stored_data_id": digest,
                "data_kind": "artifact",
                "content_hash": digest,
                "analysis_id": analysis_id,
                "record_id": None,
            }
        )
        self.data[ref_key(ref)] = staged.data
        return ref

    def open_verified(self, ref: StoredDataRef | RunStoredDataRef) -> BinaryIO:
        try:
            data = self.data[ref_key(ref)]
        except KeyError as error:
            raise LookupError("exact artifact not found") from error
        if hashlib.sha256(data).hexdigest() != ref.content_hash:
            raise ValueError("HASH_MISMATCH")
        return io.BytesIO(data)


@dataclass
class FixedClock:
    tick: int = 0

    def now(self) -> datetime:
        return NOW

    def monotonic_ms(self) -> int:
        self.tick += 1
        return self.tick


class RecordingAuthorization:
    def __init__(self, records: MemoryRecords, claimed_ref: StoredDataRef) -> None:
        self.records = records
        self.claimed_ref = claimed_ref
        self.dispatched = 0
        self.returned = 0
        self.invocations: list[
            tuple[LLMInvocationRequest, LLMInvocationResult, LLMInvocationLog]
        ] = []

    def claim_external(
        self,
        work_id: str,
        decision_ref: RecordRef,
        reservation_ref: RecordRef | None,
    ) -> RecordRef:
        assert work_id == "work-1"
        assert decision_ref.data_kind == "action_decision"
        assert reservation_ref is not None
        return self.claimed_ref

    def mark_dispatched(
        self,
        decision_ref: RecordRef,
        provider_request_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        self.dispatched += 1

    def mark_returned(self, decision_ref: RecordRef) -> None:
        self.returned += 1

    def record_invocation(
        self,
        request: LLMInvocationRequest,
        result: LLMInvocationResult,
        log: LLMInvocationLog,
    ) -> StoredDataRef:
        assert ref_key(reference(request)) in self.records.staged
        self.records.stage_record(result)
        log_ref = self.records.stage_record(log)
        self.invocations.append((request, result, log))
        assert isinstance(log_ref, StoredDataRef)
        return log_ref

    def authorize(
        self,
        action: ActionRequest,
        work: WorkExecutionState | None = None,
        reservation_ref: RecordRef | None = None,
    ) -> ActionDecision:
        raise AssertionError("the service accepts an already-authorized decision")


class FixedRunStates:
    def __init__(self, state: AnalysisRunState) -> None:
        self.state = state

    def current_state(self, analysis_id: str) -> AnalysisRunState:
        assert analysis_id == str(self.state.meta.analysis_id)
        return self.state


class FixedCurrentSelection:
    def __init__(self, *, current: bool = True) -> None:
        self.current = current
        self.checks = 0

    def require_current(self, request: LLMInvocationRequest) -> None:
        self.checks += 1
        if not self.current:
            raise ValueError("LLM_CONFIGURATION_NOT_CURRENT")


class FixedParentSession:
    def __init__(self, *, compatible: bool = True) -> None:
        self.compatible = compatible
        self.checks = 0

    def require_compatible_parent(
        self, request: LLMInvocationRequest, work: WorkExecutionState
    ) -> None:
        self.checks += 1
        assert request.parent_session_ref is not None
        assert work.active_attempt_id == request.meta.attempt_id
        if not self.compatible:
            raise ValueError("LLM_PARENT_SESSION_NOT_COMPATIBLE")


class FakeAdapter:
    def __init__(
        self,
        records: MemoryRecords,
        result_builder: StoredInvocationResultBuilder,
        output_validator: StoredOutputValidator,
        raw_output: bytes,
        status: InvocationStatus,
        *,
        cancel_requested: bool = False,
        actual_session_mode: Literal["NEW", "RESUMED"] = "NEW",
    ) -> None:
        self.records = records
        self.result_builder = result_builder
        self.output_validator = output_validator
        self.raw_output = raw_output
        self.status = status
        self.cancel_requested = cancel_requested
        self.actual_session_mode = actual_session_mode
        self.calls = 0

    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult:
        assert ref_key(reference(request)) in self.records.staged
        self.calls += 1
        if self.cancel_requested:
            raise asyncio.CancelledError
        validated = None
        parsed_output = None
        response_text = None
        safe_error = None
        session_ref = None
        if self.status == "SUCCEEDED":
            schema: dict[str, JsonValue] = {"type": "object"}
            output_schema = self.records.get_exact(request.output_schema_ref)
            assert isinstance(output_schema, OutputSchemaSpec)
            validated = self.output_validator.validate(
                self.raw_output,
                schema=schema,
                output_schema=output_schema,
                request=request,
            )
            response_text = self.raw_output.decode("utf-8")
            parsed_output = json.loads(response_text)
            session_ref = "session-1"
        else:
            safe_error = f"{self.status}: safe provider failure"
        outcome = NormalizedProviderResult(
            status=self.status,
            provider="OPENAI",
            model=request.model,
            actual_session_mode=self.actual_session_mode,
            session_ref=session_ref,
            response_text=response_text,
            parsed_output=parsed_output,
            validated_output=validated,
            usage=None,
            started_at=NOW,
            finished_at=NOW,
            elapsed_ms=1,
            safe_error=safe_error,
        )
        return self.result_builder.build(request, outcome)

    async def probe(
        self, candidate: ProviderValidationEvidence
    ) -> CapabilityProbeResult:
        raise AssertionError("not used")

    async def cancel(self, invocation_id: str) -> CancellationResult:
        return CancellationResult(False, "not active")


@dataclass
class Fixture:
    records: MemoryRecords
    artifacts: MemoryArtifacts
    work: WorkExecutionState
    run_state: AnalysisRunState
    spec_ref: StoredDataRef
    provider_ref: StoredDataRef
    payload_ref: StoredDataRef
    validator_ref: StoredDataRef
    decision_ref: StoredDataRef
    claimed_ref: StoredDataRef
    reservation_ref: StoredDataRef
    raw_output: bytes
    metadata_factory: MetadataFactory


def artifact_ref(artifacts: MemoryArtifacts, data: bytes) -> StoredDataRef:
    return artifacts.commit(artifacts.stage_bytes(data, "application/json"))


def fixture() -> Fixture:
    records = MemoryRecords()
    artifacts = MemoryArtifacts()
    metadata_factory = MetadataFactory()
    schema_artifact_ref = artifact_ref(artifacts, SCHEMA)
    output_schema = OutputSchemaSpec.model_validate(
        {
            "meta": metadata("output_schema_spec", "schema", attempt_id=None),
            "schema_key": "hypothesis-proposal-v1",
            "schema_artifact_ref": schema_artifact_ref,
            "result_kind": "hypothesis_proposal",
        }
    )
    output_schema_ref = records.publish(output_schema)
    semantic_validator = SemanticValidatorSpec.model_validate(
        {
            "meta": metadata("semantic_validator_spec", "validator", attempt_id=None),
            "validator_key": "hypothesis-proposal-v1",
            "implementation_ref": artifact_ref(artifacts, b"validator-v1"),
            "test_refs": (),
        }
    )
    validator_ref = records.publish(semantic_validator)
    template_ref = artifact_ref(artifacts, TEMPLATE)
    rendered = TEMPLATE + b'\n<UNTRUSTED_DATA>\n{"bindings":[]}\n</UNTRUSTED_DATA>\n'
    rendered_ref = artifact_ref(artifacts, rendered)
    prompt_payload = PromptPayload.model_validate(
        {
            "meta": metadata("prompt_payload", "payload"),
            "registry_entry_ref": stored_ref("prompt_registry_entry", "entry"),
            "prompt_key": "hypothesis-generate",
            "agent_role": "HYPOTHESIS",
            "task_kind": "GENERATE_INITIAL",
            "purpose": "EVALUATION",
            "template_ref": template_ref,
            "template_version": "1.0.0",
            "context_bindings": (),
            "rendered_prompt_ref": rendered_ref,
            "output_schema_ref": output_schema_ref,
        }
    )
    payload_ref = records.publish(prompt_payload)
    profile_data = make("ProviderProfile", "provider_profile")
    profile_data["meta"] = metadata(
        "provider_profile", "profile", hypothesis_id=None, attempt_id=None
    )
    profile_data["model"] = "gpt-test"
    profile_data["validation_evidence_ref"] = stored_ref(
        "provider_validation_evidence", "pvd"
    )
    profile_data["limitations"] = ()
    profile_data["checked_at"] = NOW
    profile_data["evidence_urls"] = ()
    provider = ProviderProfile.model_validate(profile_data)
    provider_ref = records.publish(provider)
    spec = LLMCallSpec.model_validate(
        {
            "meta": metadata("llm_call_spec", "spec"),
            "llm_call_id": "call-1",
            "agent_role": "HYPOTHESIS",
            "task_kind": "GENERATE_INITIAL",
            "purpose": "EVALUATION",
            "provider_profile_ref": provider_ref,
            "model": "gpt-test",
            "session_policy": "NEW",
            "parent_session_ref": None,
            "context_refs": (),
            "prompt_registry_entry_ref": prompt_payload.registry_entry_ref,
            "prompt_key": prompt_payload.prompt_key,
            "prompt_template_ref": template_ref,
            "prompt_template_version": prompt_payload.template_version,
            "prompt_payload_ref": payload_ref,
            "execution_limits_ref": stored_ref("execution_limits", "limits"),
            "retry_policy_ref": stored_ref("llm_retry_policy", "retry"),
            "tool_policy_ref": stored_ref("llm_tool_policy", "tool"),
            "redaction_policy_ref": stored_ref("prompt_redaction_policy", "redaction"),
            "semantic_validator_ref": validator_ref,
            "output_schema_ref": output_schema_ref,
            "output_schema": SCHEMA.decode("utf-8"),
            "token_budget": 100,
            "timeout_ms": 1_000,
        }
    )
    spec_ref = records.publish(spec)
    work = WorkExecutionState.model_validate(
        {
            "meta": metadata("work_execution_state", "work", attempt_id=None),
            "work_id": "work-1",
            "parent_work_ref": None,
            "work_type": WorkType.HYPOTHESIS_PROPOSAL,
            "subject_type": SubjectType.HYPOTHESIS,
            "subject_id": "h1",
            "work_generation": 1,
            "status": WorkStatus.RUNNING,
            "state_version": 2,
            "last_transition_ref": stored_ref("state_transition", "transition"),
            "last_transition_commit_ref": None,
            "active_attempt_id": "at1",
            "input_hash": "a" * 64,
            "dedupe_key": "b" * 64,
            "trigger_primitive_ref": None,
            "input_refs": (),
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
    raw_output_data = {
        "statement": "Untrusted input may reach a SQL execution sink",
        "falsification_questions": [{"question": "Is the value parameterized?"}],
        "validation_checks": [{"instruction": "Trace the source-to-sink path"}],
    }
    raw_output = json.dumps(raw_output_data, indent=2).encode("utf-8")
    work_ref = records.publish(work)
    expected_inputs = llm_action_input_refs(spec_ref, spec, prompt_payload)
    action = ActionRequest.model_validate(
        {
            "meta": metadata("action_request", "action"),
            "action_id": "action-1",
            "requested_by": RequesterRole.HYPOTHESIS,
            "requester_identity_ref": stored_ref("agent_identity", "hypothesis"),
            "action_type": ActionType.CALL_LLM,
            "work_ref": work_ref,
            "expected_state_version": work.state_version,
            "expected_verification_generation": None,
            "generation_restart_reason": None,
            "generation_restart_basis_refs": (),
            "input_refs": expected_inputs,
            "dynamic_request_ref": None,
            "reproduction_plan_ref": None,
            "result_kind": None,
            "candidate_result_ref": None,
            "llm_call_spec_ref": spec_ref,
            "tool_name": None,
            "file_paths": (),
            "provider_profile_ref": provider_ref,
            "session_mode": SessionMode.NEW,
            "sandbox_profile_ref": None,
            "resource_profile_ref": None,
            "run_policy_state_ref": None,
            "image_digest": None,
            "network_targets": (),
            "resource_limits": None,
            "reason": "Run one authorized hypothesis call",
            "requested_at": NOW,
        }
    )
    action_ref = records.publish(action)
    required_checks = tuple(REQUIRED_CHECKS[action.action_type])
    decision = ActionDecision.model_validate(
        {
            "meta": metadata("action_decision", "decision"),
            "decision_id": "decision-1",
            "action_ref": action_ref,
            "decision": Decision.ALLOW,
            "required_checks": required_checks,
            "check_results": tuple(
                ActionCheck(
                    check_type=check,
                    result=CheckResult.PASS,
                    reason_code="APPROVED",
                    safe_message="Approved",
                )
                for check in required_checks
            ),
            "checked_state_version": work.state_version,
            "checked_config_refs": tuple(
                item for item in expected_inputs if item.record_id is not None
            ),
            "valid_until": NOW + timedelta(hours=1),
            "error_ids": (),
            "use_status": UseStatus.UNUSED,
            "used_at": None,
            "expired_at": None,
            "expire_reason": None,
            "outcome_refs": (),
            "decided_at": NOW,
        }
    )
    decision_ref = records.publish(decision)
    claimed_meta = RecordMeta.model_validate(
        metadata("action_decision", "claimed").model_dump()
        | {
            "logical_record_id": decision.meta.logical_record_id,
            "revision_number": 2,
            "previous_record_id": decision.meta.record_id,
        }
    )
    claimed = ActionDecision.model_validate(
        decision.model_dump()
        | {
            "meta": claimed_meta,
            "use_status": UseStatus.USED,
            "used_at": NOW,
        }
    )
    claimed_ref = records.publish(claimed)
    run_state = analysis_run_state()
    return Fixture(
        records=records,
        artifacts=artifacts,
        work=work,
        run_state=run_state,
        spec_ref=spec_ref,
        provider_ref=provider_ref,
        payload_ref=payload_ref,
        validator_ref=validator_ref,
        decision_ref=decision_ref,
        claimed_ref=claimed_ref,
        reservation_ref=stored_ref("budget_reservation", "reservation"),
        raw_output=raw_output,
        metadata_factory=metadata_factory,
    )


def stored_ref(kind: str, name: str) -> StoredDataRef:
    digest = hashlib.sha256(f"{kind}:{name}".encode()).hexdigest()
    return StoredDataRef.model_validate(
        {
            "stored_data_id": name,
            "data_kind": kind,
            "content_hash": digest,
            "workspace_id": "ws1",
            "commit_id": "c1",
            "record_id": f"{name}-record",
        }
    )


def build_service(
    data: Fixture,
    status: InvocationStatus,
    *,
    current_selection: FixedCurrentSelection | None = None,
    parent_sessions: FixedParentSession | None = None,
    cancel: bool = False,
    actual_session_mode: Literal["NEW", "RESUMED"] = "NEW",
) -> tuple[LLMCallService, FakeAdapter, RecordingAuthorization]:
    prompt_resolver = StoredPromptInputResolver(data.records, data.artifacts)
    validators: dict[StoredDataRef, Callable[[object], None]] = {
        data.validator_ref: lambda _record: None
    }
    output_validator = StoredOutputValidator(
        data.records,
        validators,
        validate_output,
    )
    result_builder = StoredInvocationResultBuilder(
        data.records, data.artifacts, data.metadata_factory
    )
    adapter = FakeAdapter(
        data.records,
        result_builder,
        output_validator,
        data.raw_output,
        status,
        cancel_requested=cancel,
        actual_session_mode=actual_session_mode,
    )
    adapters = ExactAdapterResolver({(data.provider_ref, "gpt-test"): adapter})
    authorization = RecordingAuthorization(data.records, data.claimed_ref)
    service = LLMCallService(
        records=data.records,
        artifacts=data.artifacts,
        external=ExternalCallService(authorization),
        validator=RuntimeValidator(authorization),
        adapters=adapters,
        metadata_factory=data.metadata_factory,
        run_states=FixedRunStates(data.run_state),
        current_selection=current_selection or FixedCurrentSelection(),
        parent_sessions=parent_sessions or FixedParentSession(),
        clock=FixedClock(),
    )
    assert prompt_resolver is not None  # exact resolver is tested independently below
    return service, adapter, authorization


def resume_fixture(data: Fixture) -> None:
    spec = data.records.get_exact(data.spec_ref)
    assert isinstance(spec, LLMCallSpec)
    resumed_spec = spec.model_copy(
        update={"session_policy": "RESUME", "parent_session_ref": "session-parent"}
    )
    resumed_spec_ref = data.records.publish(resumed_spec)
    decision = data.records.get_exact(data.decision_ref)
    claimed = data.records.get_exact(data.claimed_ref)
    assert isinstance(decision, ActionDecision)
    assert isinstance(claimed, ActionDecision)
    action = data.records.get_exact(decision.action_ref)
    payload = data.records.get_exact(data.payload_ref)
    assert isinstance(action, ActionRequest)
    assert isinstance(payload, PromptPayload)
    resumed_action = action.model_copy(
        update={
            "llm_call_spec_ref": resumed_spec_ref,
            "provider_profile_ref": resumed_spec.provider_profile_ref,
            "session_mode": "RESUME",
            "input_refs": llm_action_input_refs(
                resumed_spec_ref, resumed_spec, payload
            ),
        }
    )
    resumed_action_ref = data.records.publish(resumed_action)
    resumed_decision = decision.model_copy(update={"action_ref": resumed_action_ref})
    resumed_decision_ref = data.records.publish(resumed_decision)
    resumed_claimed = claimed.model_copy(update={"action_ref": resumed_action_ref})
    resumed_claimed_ref = data.records.publish(resumed_claimed)
    data.spec_ref = resumed_spec_ref
    data.decision_ref = resumed_decision_ref
    data.claimed_ref = resumed_claimed_ref


@pytest.mark.asyncio
async def test_llm_call_stages_exact_request_and_persists_safe_success() -> None:
    """Catches provider I/O before request staging or persisting raw response bytes."""
    data = fixture()
    service, adapter, authorization = build_service(data, "SUCCEEDED")

    outcome = await service.invoke(
        work=data.work,
        decision_ref=data.decision_ref,
        reservation_ref=data.reservation_ref,
        call_spec_ref=data.spec_ref,
    )

    assert adapter.calls == 1
    assert authorization.dispatched == authorization.returned == 1
    assert len(authorization.invocations) == 1
    request, result, log = authorization.invocations[0]
    assert outcome.result == result
    assert outcome.log_ref == reference(log)
    assert request.action_decision_ref == data.claimed_ref
    assert result.status == "SUCCEEDED"
    assert result.parsed_output_ref is not None
    assert ref_key(result.parsed_output_ref) in data.artifacts.data
    assert result.response_ref is not None
    assert result.response_ref == result.parsed_output_ref
    safe_response = data.artifacts.data[ref_key(result.response_ref)]
    assert safe_response == canonical_bytes(json.loads(data.raw_output))
    assert safe_response != data.raw_output


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["AUTH_REQUIRED", "TIMED_OUT", "INVALID_OUTPUT"])
async def test_provider_failure_is_persisted_without_domain_output(
    status: InvocationStatus,
) -> None:
    """Catches provider failures disappearing or becoming vulnerability verdicts."""
    data = fixture()
    service, _adapter, authorization = build_service(data, status)

    outcome = await service.invoke(
        work=data.work,
        decision_ref=data.decision_ref,
        reservation_ref=data.reservation_ref,
        call_spec_ref=data.spec_ref,
    )

    assert outcome.result.status == status
    assert outcome.result.parsed_output_ref is None
    assert outcome.result.response_ref is None
    assert outcome.result.safe_error == f"{status}: safe provider failure"
    assert len(authorization.invocations) == 1
    request, result, log = authorization.invocations[0]
    assert ref_key(reference(request)) in data.records.staged
    assert ref_key(reference(result)) in data.records.staged
    assert ref_key(reference(log)) in data.records.staged
    assert all(
        record.meta.record_type
        in {
            "llm_invocation_request",
            "llm_invocation_result",
            "llm_invocation_log",
        }
        for record in data.records.staged.values()
    )


@pytest.mark.asyncio
async def test_prompt_resolver_rejects_a_same_name_wrong_exact_revision() -> None:
    """Catches replacing a requested PromptPayload with another hash/revision."""
    data = fixture()
    resolver = StoredPromptInputResolver(data.records, data.artifacts)
    spec = data.records.get_exact(data.spec_ref)
    assert isinstance(spec, LLMCallSpec)
    request = LLMInvocationRequest.model_validate(
        spec.model_dump()
        | {
            "meta": metadata("llm_invocation_request", "request"),
            "action_decision_ref": data.claimed_ref,
            "call_spec_ref": data.spec_ref,
            "prompt_payload_ref": data.payload_ref.model_copy(
                update={"content_hash": "f" * 64}
            ),
        }
    )

    with pytest.raises(ProviderInputMismatchError, match="PROVIDER_INPUT_MISMATCH"):
        await resolver.resolve(request)


@pytest.mark.asyncio
async def test_runtime_owned_output_metadata_is_invalid_and_never_staged() -> None:
    """Catches untrusted provider output trying to allocate a domain record."""
    data = fixture()
    output = make("HypothesisProposal", "hypothesis_proposal")
    output["meta"] = metadata(
        "hypothesis_proposal", "old-output", attempt_id="old-attempt"
    ).model_dump(mode="json")
    data.raw_output = canonical_bytes(output)
    service, adapter, authorization = build_service(data, "SUCCEEDED")

    outcome = await service.invoke(
        work=data.work,
        decision_ref=data.decision_ref,
        reservation_ref=data.reservation_ref,
        call_spec_ref=data.spec_ref,
    )

    assert adapter.calls == 1
    assert outcome.result.status == "INVALID_OUTPUT"
    assert outcome.result.parsed_output_ref is None
    assert all(
        record.meta.record_type != "hypothesis_proposal"
        for record in data.records.staged.values()
    )
    assert len(authorization.invocations) == 1


@pytest.mark.asyncio
async def test_evaluation_call_is_rejected_in_a_production_run_before_io() -> None:
    """Catches EVALUATION prompt data being mixed into a PRODUCTION analysis."""
    data = fixture()
    data.run_state = AnalysisRunState.model_validate(
        data.run_state.model_dump()
        | {"purpose": Purpose.PRODUCTION, "eval_config_refs": ()}
    )
    service, adapter, authorization = build_service(data, "SUCCEEDED")

    with pytest.raises(ValueError, match="LLM_PURPOSE_OR_RUN_SCOPE_MISMATCH"):
        await service.invoke(
            work=data.work,
            decision_ref=data.decision_ref,
            reservation_ref=data.reservation_ref,
            call_spec_ref=data.spec_ref,
        )

    assert adapter.calls == 0
    assert authorization.dispatched == authorization.returned == 0


@pytest.mark.asyncio
async def test_stale_prompt_or_provider_selection_blocks_provider_io() -> None:
    """Catches an ACTIVE/current selection changing after action authorization."""
    data = fixture()
    selection = FixedCurrentSelection(current=False)
    service, adapter, authorization = build_service(
        data, "SUCCEEDED", current_selection=selection
    )

    outcome = await service.invoke(
        work=data.work,
        decision_ref=data.decision_ref,
        reservation_ref=data.reservation_ref,
        call_spec_ref=data.spec_ref,
    )

    assert selection.checks == 1
    assert adapter.calls == 0
    assert outcome.result.status == "FAILED"
    assert outcome.result.parsed_output_ref is None
    assert all(
        record.meta.record_type != "hypothesis_proposal"
        for record in data.records.staged.values()
    )
    assert len(authorization.invocations) == 1


@pytest.mark.asyncio
async def test_cancelled_provider_call_is_persisted_without_a_domain_result() -> None:
    """Catches cancellation escaping without a durable safe invocation outcome."""
    data = fixture()
    service, adapter, authorization = build_service(data, "SUCCEEDED", cancel=True)

    outcome = await service.invoke(
        work=data.work,
        decision_ref=data.decision_ref,
        reservation_ref=data.reservation_ref,
        call_spec_ref=data.spec_ref,
    )

    assert adapter.calls == 1
    assert outcome.result.status == "CANCELLED"
    assert outcome.result.parsed_output_ref is None
    assert outcome.result.safe_error == "CANCELLED: provider request was cancelled"
    assert authorization.dispatched == authorization.returned == 1
    assert len(authorization.invocations) == 1


@pytest.mark.asyncio
async def test_new_session_request_rejects_a_resumed_provider_result() -> None:
    """Catches provider session crossover despite an exact NEW request."""
    data = fixture()
    service, adapter, authorization = build_service(
        data, "SUCCEEDED", actual_session_mode="RESUMED"
    )

    outcome = await service.invoke(
        work=data.work,
        decision_ref=data.decision_ref,
        reservation_ref=data.reservation_ref,
        call_spec_ref=data.spec_ref,
    )

    assert adapter.calls == 1
    assert outcome.result.status == "INVALID_OUTPUT"
    assert outcome.result.parsed_output_ref is None
    assert all(
        record.meta.record_type != "hypothesis_proposal"
        for record in data.records.staged.values()
    )
    assert len(authorization.invocations) == 1


@pytest.mark.asyncio
async def test_resume_uses_a_compatible_parent_before_provider_io() -> None:
    data = fixture()
    resume_fixture(data)
    parent_sessions = FixedParentSession()
    service, adapter, _authorization = build_service(
        data,
        "SUCCEEDED",
        parent_sessions=parent_sessions,
        actual_session_mode="RESUMED",
    )

    outcome = await service.invoke(
        work=data.work,
        decision_ref=data.decision_ref,
        reservation_ref=data.reservation_ref,
        call_spec_ref=data.spec_ref,
    )

    assert parent_sessions.checks == 1
    assert adapter.calls == 1
    assert outcome.result.status == "SUCCEEDED"
    assert outcome.result.actual_session_mode == "RESUMED"


@pytest.mark.asyncio
async def test_incompatible_parent_session_is_rejected_before_provider_io() -> None:
    data = fixture()
    resume_fixture(data)
    parent_sessions = FixedParentSession(compatible=False)
    service, adapter, authorization = build_service(
        data,
        "SUCCEEDED",
        parent_sessions=parent_sessions,
        actual_session_mode="RESUMED",
    )

    outcome = await service.invoke(
        work=data.work,
        decision_ref=data.decision_ref,
        reservation_ref=data.reservation_ref,
        call_spec_ref=data.spec_ref,
    )

    assert parent_sessions.checks == 1
    assert adapter.calls == 0
    assert outcome.result.status == "FAILED"
    assert outcome.result.actual_session_mode == "RESUMED"
    assert len(authorization.invocations) == 1


@pytest.mark.asyncio
async def test_record_shaped_provider_output_is_fake_only() -> None:
    data = fixture()
    service, _adapter, authorization = build_service(data, "SUCCEEDED")
    await service.invoke(
        work=data.work,
        decision_ref=data.decision_ref,
        reservation_ref=data.reservation_ref,
        call_spec_ref=data.spec_ref,
    )
    _request, result, _log = authorization.invocations[0]
    record_output_ref = stored_ref("hypothesis_proposal", "provider-output")
    forged = result.model_copy(update={"parsed_output_ref": record_output_ref})
    validator = object.__new__(SQLiteValidator)

    with pytest.raises(ValueError, match="INVOCATION_OUTPUT_MISMATCH"):
        validator._require_provider_output_authority(forged)

    fake_validator = object.__new__(FakeRecordOutputRuntimeValidator)
    fake_validator._require_provider_output_authority(forged)


def _published_session_guard(
    data: Fixture,
    request: LLMInvocationRequest,
    result: LLMInvocationResult,
    log: LLMInvocationLog,
) -> LLMParentSessionGuard:
    engine = create_engine("sqlite://")
    models.metadata.create_all(engine)
    database = cast(Any, SimpleNamespace(engine=engine, recovery_failed=False))
    records = SQLiteRecordStore(database)
    claimed = data.records.get_exact(data.claimed_ref)
    initial = data.records.get_exact(data.decision_ref)
    assert isinstance(claimed, ActionDecision)
    assert isinstance(initial, ActionDecision)
    action = data.records.get_exact(initial.action_ref)
    assert isinstance(action, ActionRequest)
    with engine.begin() as connection:
        for record in (data.work, action, initial, claimed, request, result, log):
            exact = records.stage(connection, record)
            records.publish(connection, exact)
    return LLMParentSessionGuard(records)


@pytest.mark.asyncio
async def test_persisted_successful_session_is_compatible_with_same_work_attempt() -> (
    None
):
    data = fixture()
    service, _adapter, authorization = build_service(data, "SUCCEEDED")
    await service.invoke(
        work=data.work,
        decision_ref=data.decision_ref,
        reservation_ref=data.reservation_ref,
        call_spec_ref=data.spec_ref,
    )
    request, result, log = authorization.invocations[0]
    guard = _published_session_guard(data, request, result, log)
    resumed = request.model_copy(
        update={"session_policy": "RESUME", "parent_session_ref": result.session_ref}
    )

    guard.require_compatible_parent(resumed, data.work)


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", ("cross_work", "cross_attempt", "stale", "failed"))
async def test_parent_session_rejects_incompatible_or_failed_invocation(
    invalid: str,
) -> None:
    data = fixture()
    service, _adapter, authorization = build_service(data, "SUCCEEDED")
    await service.invoke(
        work=data.work,
        decision_ref=data.decision_ref,
        reservation_ref=data.reservation_ref,
        call_spec_ref=data.spec_ref,
    )
    request, result, log = authorization.invocations[0]
    if invalid == "failed":
        safe_error = "FAILED: provider request failed"
        result = result.model_copy(
            update={
                "status": "FAILED",
                "response_ref": None,
                "parsed_output_ref": None,
                "safe_error": safe_error,
            }
        )
        log = log.model_copy(
            update={
                "status": "FAILED",
                "exposed_response_ref": None,
                "parsed_output_ref": None,
                "safe_error": safe_error,
            }
        )
    guard = _published_session_guard(data, request, result, log)
    resumed = request.model_copy(
        update={"session_policy": "RESUME", "parent_session_ref": result.session_ref}
    )
    current_work = data.work
    if invalid == "cross_work":
        current_work = data.work.model_copy(update={"work_id": "other-work"})
    elif invalid == "cross_attempt":
        current_work = data.work.model_copy(
            update={"active_attempt_id": "other-attempt"}
        )
        resumed = resumed.model_copy(
            update={
                "meta": resumed.meta.model_copy(update={"attempt_id": "other-attempt"})
            }
        )
    elif invalid == "stale":
        resumed = resumed.model_copy(
            update={
                "prompt_registry_entry_ref": stored_ref(
                    "prompt_registry_entry", "newer-entry"
                )
            }
        )

    with pytest.raises(ValueError, match="LLM_PARENT_SESSION_NOT_COMPATIBLE"):
        guard.require_compatible_parent(resumed, current_work)


def test_build_runtime_composes_the_llm_call_service(tmp_path: Path) -> None:
    """Catches a tested LLM service never being exposed by the real runtime."""
    upgrade_database(tmp_path)
    runtime = build_runtime(
        tmp_path,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        clock=FixedClock(),
        ids=TestIds(),
    )

    assert isinstance(runtime.llm_calls, LLMCallService)
    authorization = cast(SQLiteValidator, runtime.validator.authorization)
    assert type(authorization) is SQLiteValidator


def test_public_build_runtime_has_no_fake_output_escape() -> None:
    assert (
        "allow_fake_record_llm_output"
        not in inspect.signature(build_runtime).parameters
    )
