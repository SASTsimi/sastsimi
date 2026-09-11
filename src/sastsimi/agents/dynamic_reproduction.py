"""Dynamic Reproduction LLM boundary and trusted stage finalizers.

The Provider only proposes content.  Exact references, record metadata, IDs,
attempt/generation scope, and the eventual dynamic result remain runtime-owned.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal, Protocol, cast

from pydantic import JsonValue, ValidationError

from sastsimi.contracts._domain import SafeDiagnostic, same_scope
from sastsimi.contracts.base import (
    ContractModel,
    NonEmptyStr,
    NonNegativeInt,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import (
    AgentLog,
    DynamicReproductionConclusion,
    DynamicReproductionRequest,
    DynamicReproductionToolRequest,
    EnvironmentRequirement,
    EnvironmentRequirements,
    HypothesisOutcome,
    NeedKind,
    PoCCandidate,
    ReproductionPlan,
    SafeCommandValue,
    SandboxCommandInput,
    SandboxEnvironment,
)
from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation


class DynamicLLMCall(Protocol):
    async def invoke(
        self,
        *,
        work: WorkExecutionState,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
    ) -> PersistedLLMInvocation: ...


@dataclass(frozen=True)
class DynamicAgentInvocation:
    """Already-authorized inputs for one exact T09 call."""

    decision_ref: StoredDataRef
    reservation_ref: RecordRef
    call_spec_ref: StoredDataRef


@dataclass(frozen=True)
class DynamicAgentOutcome[T]:
    invocation: PersistedLLMInvocation
    record: T | None


class _EnvironmentRequirementContent(ContractModel):
    source_need_index: NonNegativeInt | None
    kind: NeedKind
    name: NonEmptyStr
    required: bool
    expected: SafeDiagnostic | None
    alternatives: tuple[SafeDiagnostic, ...]


class _EnvironmentRequirementsContent(ContractModel):
    items: tuple[_EnvironmentRequirementContent, ...]


class _ReproductionPlanContent(ContractModel):
    strategy_summary: NonEmptyStr
    requested_evidence: tuple[NonEmptyStr, ...]


class _PoCCandidateContent(ContractModel):
    content: NonEmptyStr


class _SandboxCommandContent(ContractModel):
    executable: SafeCommandValue
    arguments: tuple[SafeCommandValue, ...]
    working_directory: SafeCommandValue


class _ToolRequestContent(ContractModel):
    action: Literal[
        "RUN_COMMAND", "USE_POC_CANDIDATE", "REQUEST_SANDBOX_RECREATE", "FINISH"
    ]
    command: _SandboxCommandContent | None
    recreate_reason: (
        Literal["STATE_CHANGED", "CONFIG_CHANGED", "STATE_UNCERTAIN"] | None
    )
    rationale: NonEmptyStr


class _ConclusionContent(ContractModel):
    proposed_outcome: HypothesisOutcome
    observation_indexes: tuple[NonNegativeInt, ...]
    hypothesis_evidence_indexes: tuple[NonNegativeInt, ...]
    hypothesis_linkage: NonEmptyStr
    limitations: tuple[NonEmptyStr, ...]


_TASK_DERIVE = "DERIVE_ENVIRONMENT"
_TASK_PLAN = "PLAN_REPRODUCTION"
_TASK_CANDIDATE = "CREATE_POC_CANDIDATE"
_TASK_EXECUTE = "EXECUTE_REPRODUCTION"
_TASK_INTERPRET = "INTERPRET_ATTEMPT"

_RUNTIME_OWNED_KEYS = frozenset(
    {
        "meta",
        "record_id",
        "logical_record_id",
        "record_type",
        "schema_version",
        "revision_number",
        "previous_record_id",
        "created_at",
        "analysis_id",
        "workspace_id",
        "commit_id",
        "hypothesis_id",
        "attempt_id",
        "verification_generation",
        "request_ref",
        "reproduction_plan_ref",
        "environment_requirements_ref",
        "sandbox_profile_ref",
        "environment_recipe_ref",
        "environment_ref",
        "previous_environment_ref",
        "agent_log_ref",
        "agent_conclusion_ref",
        "action_decision_ref",
        "policy_decision_ref",
        "resource_profile_ref",
        "run_policy_state_ref",
        "content_ref",
        "content_digest",
        "llm_call_id",
        "turn_number",
        "poc_candidate_ref",
        "poc_ref",
        "observation_refs",
        "hypothesis_evidence_refs",
        "disproof_evidence_refs",
        "cleanup_ref",
        "failure_category",
        "failure_reason",
        "hypothesis_disproved",
        "cleanup_status",
    }
)


class DynamicReproductionAgent:
    """Convert five content-only LLM outputs into exact R7 domain records."""

    def __init__(
        self,
        *,
        llm_calls: DynamicLLMCall,
        artifacts: ArtifactStore,
        ids: IdGenerator,
        clock: Clock,
    ) -> None:
        self._llm_calls = llm_calls
        self._artifacts = artifacts
        self._ids = ids
        self._clock = clock

    async def derive_environment(
        self,
        *,
        work: WorkExecutionState,
        authorization: DynamicAgentInvocation,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
    ) -> DynamicAgentOutcome[EnvironmentRequirements]:
        self._require_work_request(work, request, request_ref)
        invocation, value = await self._invoke(
            work=work,
            authorization=authorization,
            task_kind=_TASK_DERIVE,
            context_refs=(request_ref,),
        )
        if value is None:
            return DynamicAgentOutcome(invocation, None)
        try:
            content = _EnvironmentRequirementsContent.model_validate_json(
                canonical_bytes(value)
            )
        except ValidationError as error:
            raise ValueError("DYNAMIC_STAGE_OUTPUT_INVALID") from error
        record = self._finalize_requirements(work, request, request_ref, content)
        return DynamicAgentOutcome(invocation, record)

    async def plan_reproduction(
        self,
        *,
        work: WorkExecutionState,
        authorization: DynamicAgentInvocation,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        requirements: EnvironmentRequirements,
        requirements_ref: StoredDataRef,
    ) -> DynamicAgentOutcome[ReproductionPlan]:
        self._require_work_request(work, request, request_ref)
        self._require_dynamic_record(
            work,
            requirements,
            requirements_ref,
            request_ref,
            "environment_requirements",
        )
        invocation, value = await self._invoke(
            work=work,
            authorization=authorization,
            task_kind=_TASK_PLAN,
            context_refs=(request_ref, requirements_ref),
        )
        if value is None:
            return DynamicAgentOutcome(invocation, None)
        try:
            content = _ReproductionPlanContent.model_validate_json(
                canonical_bytes(value)
            )
        except ValidationError as error:
            raise ValueError("DYNAMIC_STAGE_OUTPUT_INVALID") from error
        record = ReproductionPlan(
            meta=self._fresh_meta(work, "reproduction_plan"),
            request_ref=request_ref,
            purpose=request.purpose,
            hypothesis_ref=request.hypothesis_ref,
            environment_requirements_ref=requirements_ref,
            sandbox_profile_ref=request.sandbox_profile_ref,
            reproduction_goal=request.goal,
            strategy_summary=content.strategy_summary,
            requested_evidence=content.requested_evidence,
        )
        return DynamicAgentOutcome(invocation, record)

    async def create_poc_candidate(
        self,
        *,
        work: WorkExecutionState,
        authorization: DynamicAgentInvocation,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        plan: ReproductionPlan,
        plan_ref: StoredDataRef,
        environment: SandboxEnvironment,
        environment_ref: StoredDataRef,
    ) -> DynamicAgentOutcome[PoCCandidate]:
        self._require_work_request(work, request, request_ref)
        self._require_dynamic_record(
            work, plan, plan_ref, request_ref, "reproduction_plan"
        )
        self._require_dynamic_record(
            work, environment, environment_ref, request_ref, "sandbox_environment"
        )
        if (
            environment.reproduction_plan_ref != plan_ref
            or environment.status != "READY"
        ):
            raise ValueError("DYNAMIC_ENVIRONMENT_NOT_READY")
        invocation, value = await self._invoke(
            work=work,
            authorization=authorization,
            task_kind=_TASK_CANDIDATE,
            context_refs=(request_ref, plan_ref, environment_ref),
        )
        if value is None:
            return DynamicAgentOutcome(invocation, None)
        try:
            content = _PoCCandidateContent.model_validate_json(canonical_bytes(value))
        except ValidationError as error:
            raise ValueError("DYNAMIC_STAGE_OUTPUT_INVALID") from error
        content_ref = self._artifacts.commit(
            self._artifacts.stage_bytes(content.content.encode("utf-8"), "text/plain")
        )
        record = PoCCandidate(
            meta=self._fresh_meta(work, "poc_candidate"),
            request_ref=request_ref,
            reproduction_plan_ref=plan_ref,
            content_ref=content_ref,
            content_digest=content_ref.content_hash,
            llm_call_id=invocation.request.llm_call_id,
            created_at=self._clock.now(),
        )
        return DynamicAgentOutcome(invocation, record)

    async def next_tool_request(
        self,
        *,
        work: WorkExecutionState,
        authorization: DynamicAgentInvocation,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        requirements: EnvironmentRequirements,
        requirements_ref: StoredDataRef,
        plan: ReproductionPlan,
        plan_ref: StoredDataRef,
        environment: SandboxEnvironment,
        environment_ref: StoredDataRef,
        candidate: PoCCandidate | None,
        candidate_ref: StoredDataRef | None,
        log: AgentLog,
        log_ref: StoredDataRef,
        prior_tool_refs: tuple[StoredDataRef, ...],
        observation_refs: tuple[StoredDataRef, ...],
        turn_number: int,
    ) -> DynamicAgentOutcome[DynamicReproductionToolRequest]:
        self._require_work_request(work, request, request_ref)
        self._require_dynamic_record(
            work,
            requirements,
            requirements_ref,
            request_ref,
            "environment_requirements",
        )
        self._require_dynamic_record(
            work, plan, plan_ref, request_ref, "reproduction_plan"
        )
        self._require_dynamic_record(
            work, environment, environment_ref, request_ref, "sandbox_environment"
        )
        self._require_dynamic_record(work, log, log_ref, request_ref, "agent_log")
        self._require_optional_candidate(
            work, candidate, candidate_ref, request_ref, plan_ref
        )
        if (
            environment.status != "READY"
            or environment.reproduction_plan_ref != plan_ref
        ):
            raise ValueError("DYNAMIC_ENVIRONMENT_NOT_READY")
        contexts = (
            request_ref,
            requirements_ref,
            plan_ref,
            environment_ref,
            *((candidate_ref,) if candidate_ref is not None else ()),
            log_ref,
            *prior_tool_refs,
            *observation_refs,
        )
        invocation, value = await self._invoke(
            work=work,
            authorization=authorization,
            task_kind=_TASK_EXECUTE,
            context_refs=contexts,
        )
        if value is None:
            return DynamicAgentOutcome(invocation, None)
        try:
            content = _ToolRequestContent.model_validate_json(canonical_bytes(value))
            action = content.action
            if (action == "RUN_COMMAND") != (content.command is not None) or (
                action == "REQUEST_SANDBOX_RECREATE"
            ) != (content.recreate_reason is not None):
                raise ValueError("DYNAMIC_TOOL_ACTION_MISMATCH")
            command = (
                SandboxCommandInput(
                    executable=content.command.executable,
                    arguments=content.command.arguments,
                    working_directory=content.command.working_directory,
                    environment_binding_refs=(),
                    stdin_ref=None,
                    secret_refs=(),
                )
                if content.command is not None
                else None
            )
            record = DynamicReproductionToolRequest.model_validate(
                {
                    "meta": self._fresh_meta(work, "dynamic_reproduction_tool_request"),
                    "request_ref": request_ref,
                    "reproduction_plan_ref": plan_ref,
                    "environment_ref": environment_ref,
                    "turn_number": turn_number,
                    "action": action,
                    "command": command,
                    "poc_candidate_ref": (
                        candidate_ref if action == "USE_POC_CANDIDATE" else None
                    ),
                    "recreate_reason": (
                        content.recreate_reason
                        if action == "REQUEST_SANDBOX_RECREATE"
                        else None
                    ),
                    "rationale": content.rationale,
                    "llm_call_id": invocation.request.llm_call_id,
                }
            )
        except ValidationError as error:
            raise ValueError("DYNAMIC_STAGE_OUTPUT_INVALID") from error
        return DynamicAgentOutcome(invocation, record)

    async def interpret_attempt(
        self,
        *,
        work: WorkExecutionState,
        authorization: DynamicAgentInvocation,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        plan: ReproductionPlan,
        plan_ref: StoredDataRef,
        environment: SandboxEnvironment,
        environment_ref: StoredDataRef,
        candidate: PoCCandidate | None,
        candidate_ref: StoredDataRef | None,
        log: AgentLog,
        log_ref: StoredDataRef,
        observation_refs: tuple[StoredDataRef, ...],
    ) -> DynamicAgentOutcome[DynamicReproductionConclusion]:
        self._require_work_request(work, request, request_ref)
        self._require_dynamic_record(
            work, plan, plan_ref, request_ref, "reproduction_plan"
        )
        self._require_dynamic_record(
            work, environment, environment_ref, request_ref, "sandbox_environment"
        )
        self._require_dynamic_record(work, log, log_ref, request_ref, "agent_log")
        self._require_optional_candidate(
            work, candidate, candidate_ref, request_ref, plan_ref
        )
        contexts = (
            request_ref,
            plan_ref,
            environment_ref,
            *((candidate_ref,) if candidate_ref is not None else ()),
            log_ref,
            *observation_refs,
        )
        invocation, value = await self._invoke(
            work=work,
            authorization=authorization,
            task_kind=_TASK_INTERPRET,
            context_refs=contexts,
        )
        if value is None:
            return DynamicAgentOutcome(invocation, None)
        try:
            content = _ConclusionContent.model_validate_json(canonical_bytes(value))
            selected_observations = _select_refs(
                observation_refs, content.observation_indexes
            )
            evidence = _select_refs(
                observation_refs, content.hypothesis_evidence_indexes
            )
            record = DynamicReproductionConclusion(
                meta=self._fresh_meta(work, "dynamic_reproduction_conclusion"),
                request_ref=request_ref,
                reproduction_plan_ref=plan_ref,
                environment_ref=environment_ref,
                poc_candidate_ref=candidate_ref,
                observation_refs=selected_observations,
                proposed_outcome=content.proposed_outcome,
                hypothesis_evidence_refs=evidence,
                hypothesis_linkage=content.hypothesis_linkage,
                limitations=content.limitations,
                llm_call_id=invocation.request.llm_call_id,
            )
        except (IndexError, ValidationError) as error:
            raise ValueError("DYNAMIC_STAGE_OUTPUT_INVALID") from error
        return DynamicAgentOutcome(invocation, record)

    async def _invoke(
        self,
        *,
        work: WorkExecutionState,
        authorization: DynamicAgentInvocation,
        task_kind: str,
        context_refs: tuple[StoredDataRef, ...],
    ) -> tuple[PersistedLLMInvocation, JsonValue | None]:
        invocation = await self._llm_calls.invoke(
            work=work,
            decision_ref=authorization.decision_ref,
            reservation_ref=authorization.reservation_ref,
            call_spec_ref=authorization.call_spec_ref,
        )
        self._require_invocation(
            invocation,
            work=work,
            authorization=authorization,
            task_kind=task_kind,
            context_refs=context_refs,
        )
        if invocation.result.status != "SUCCEEDED":
            return invocation, None
        output_ref = invocation.result.parsed_output_ref
        if output_ref is None:
            raise ValueError("DYNAMIC_STAGE_OUTPUT_INVALID")
        try:
            with self._artifacts.open_verified(output_ref) as stream:
                raw = stream.read()
            value = json.loads(raw)
            if canonical_bytes(value) != raw or not isinstance(value, dict):
                raise ValueError("DYNAMIC_STAGE_OUTPUT_INVALID")
            _reject_runtime_authority(cast(JsonValue, value))
        except ValueError:
            raise
        except (OSError, TypeError, json.JSONDecodeError) as error:
            raise ValueError("DYNAMIC_STAGE_OUTPUT_INVALID") from error
        return invocation, cast(JsonValue, value)

    @staticmethod
    def _require_invocation(
        invocation: PersistedLLMInvocation,
        *,
        work: WorkExecutionState,
        authorization: DynamicAgentInvocation,
        task_kind: str,
        context_refs: tuple[StoredDataRef, ...],
    ) -> None:
        request, result = invocation.request, invocation.result
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("DYNAMIC_INVOCATION_MISMATCH")
        expected_session_policy = "AUTO" if task_kind == _TASK_EXECUTE else "NEW"
        expected_mode = "RESUMED" if request.parent_session_ref is not None else "NEW"
        scope = (
            "analysis_id",
            "workspace_id",
            "commit_id",
            "hypothesis_id",
            "attempt_id",
        )
        if (
            request.agent_role != "DYNAMIC_REPRODUCTION"
            or request.task_kind != task_kind
            or request.session_policy != expected_session_policy
            or (task_kind != _TASK_EXECUTE and request.parent_session_ref is not None)
            or request.action_decision_ref != authorization.decision_ref
            or request.call_spec_ref != authorization.call_spec_ref
            or request.context_refs != context_refs
            or request.meta.attempt_id != work.active_attempt_id
            or any(
                getattr(request.meta, name) != getattr(work.meta, name)
                for name in (
                    "analysis_id",
                    "workspace_id",
                    "commit_id",
                    "hypothesis_id",
                )
            )
            or result.llm_call_id != request.llm_call_id
            or result.purpose != request.purpose
            or result.model != request.model
            or result.actual_session_mode != expected_mode
            or any(
                getattr(result.meta, name) != getattr(request.meta, name)
                for name in scope
            )
            or invocation.log_ref.data_kind != "llm_invocation_log"
            or invocation.log_ref.workspace_id != work.meta.workspace_id
            or invocation.log_ref.commit_id != work.meta.commit_id
        ):
            raise ValueError("DYNAMIC_INVOCATION_MISMATCH")
        output_ref = result.parsed_output_ref
        if result.status == "SUCCEEDED":
            if (
                output_ref is None
                or result.response_ref != output_ref
                or output_ref.record_id is not None
                or output_ref.data_kind != "artifact"
                or output_ref.workspace_id != work.meta.workspace_id
                or output_ref.commit_id != work.meta.commit_id
            ):
                raise ValueError("DYNAMIC_INVOCATION_MISMATCH")
        elif output_ref is not None or result.response_ref is not None:
            raise ValueError("DYNAMIC_INVOCATION_MISMATCH")

    def _finalize_requirements(
        self,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        content: _EnvironmentRequirementsContent,
    ) -> EnvironmentRequirements:
        needs = request.environment_needs
        used: set[int] = set()
        items: list[EnvironmentRequirement] = []
        extra_sources = tuple(
            dict.fromkeys((*request.code_refs, *request.static_evidence_refs))
        )
        for proposed in content.items:
            index = proposed.source_need_index
            if index is None:
                requirement_id = str(self._ids.new(RecordId))
                source_refs = extra_sources
            else:
                if index >= len(needs) or index in used:
                    raise ValueError("ENVIRONMENT_NEED_COVERAGE")
                need = needs[index]
                if need.kind != proposed.kind or (
                    need.required and not proposed.required
                ):
                    raise ValueError("ENVIRONMENT_NEED_COVERAGE")
                used.add(index)
                requirement_id = need.need_id
                source_refs = need.source_refs
            items.append(
                EnvironmentRequirement(
                    requirement_id=requirement_id,
                    kind=proposed.kind,
                    name=proposed.name,
                    required=proposed.required,
                    expected=proposed.expected,
                    expected_ref=None,
                    alternatives=proposed.alternatives,
                    check_ref=None,
                    secret_ref=None,
                    source_refs=source_refs,
                )
            )
        if used != set(range(len(needs))):
            raise ValueError("ENVIRONMENT_NEED_COVERAGE")
        return EnvironmentRequirements(
            meta=self._fresh_meta(work, "environment_requirements"),
            request_ref=request_ref,
            items=tuple(items),
        )

    @staticmethod
    def _require_work_request(
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
    ) -> None:
        if (
            not isinstance(work.meta, RecordMeta)
            or work.work_type != WorkType.DYNAMIC_REPRO
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
            or reference(request) != request_ref
            or work.input_refs != (request_ref,)
            or request.verification_generation != work.work_generation
            or request.meta.hypothesis_id != work.meta.hypothesis_id
            or request.meta.analysis_id != work.meta.analysis_id
            or request.meta.workspace_id != work.meta.workspace_id
            or request.meta.commit_id != work.meta.commit_id
        ):
            raise ValueError("DYNAMIC_REQUEST_CLOSURE_MISMATCH")

    @staticmethod
    def _require_dynamic_record(
        work: WorkExecutionState,
        record: object,
        record_ref: StoredDataRef,
        request_ref: StoredDataRef,
        kind: str,
    ) -> None:
        meta = getattr(record, "meta", None)
        if (
            not isinstance(work.meta, RecordMeta)
            or not isinstance(meta, RecordMeta)
            or reference(record) != record_ref  # type: ignore[arg-type]
            or record_ref.data_kind != kind
            or getattr(record, "request_ref", None) != request_ref
            or meta.attempt_id != work.active_attempt_id
        ):
            raise ValueError("DYNAMIC_STAGE_CLOSURE_MISMATCH")
        same_scope(work.meta, meta, hypothesis=True, attempt=False)

    @classmethod
    def _require_optional_candidate(
        cls,
        work: WorkExecutionState,
        candidate: PoCCandidate | None,
        candidate_ref: StoredDataRef | None,
        request_ref: StoredDataRef,
        plan_ref: StoredDataRef,
    ) -> None:
        if (candidate is None) != (candidate_ref is None):
            raise ValueError("DYNAMIC_STAGE_CLOSURE_MISMATCH")
        if candidate is not None and candidate_ref is not None:
            cls._require_dynamic_record(
                work, candidate, candidate_ref, request_ref, "poc_candidate"
            )
            if candidate.reproduction_plan_ref != plan_ref:
                raise ValueError("DYNAMIC_STAGE_CLOSURE_MISMATCH")

    def _fresh_meta(self, work: WorkExecutionState, kind: str) -> RecordMeta:
        if not isinstance(work.meta, RecordMeta) or work.active_attempt_id is None:
            raise ValueError("DYNAMIC_WORK_NOT_ACTIVE")
        record_id = self._ids.new(RecordId)
        return RecordMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=kind,
            schema_version=work.meta.schema_version,
            revision_number=1,
            previous_record_id=None,
            created_at=self._clock.now(),
            analysis_id=work.meta.analysis_id,
            workspace_id=work.meta.workspace_id,
            commit_id=work.meta.commit_id,
            hypothesis_id=work.meta.hypothesis_id,
            attempt_id=work.active_attempt_id,
        )


def _reject_runtime_authority(value: JsonValue) -> None:
    if isinstance(value, dict):
        if _RUNTIME_OWNED_KEYS.intersection(value):
            raise ValueError("OUTPUT_RUNTIME_AUTHORITY_DENIED")
        for item in value.values():
            _reject_runtime_authority(item)
    elif isinstance(value, list):
        for item in value:
            _reject_runtime_authority(item)


def _select_refs(
    available: tuple[StoredDataRef, ...], indexes: tuple[int, ...]
) -> tuple[StoredDataRef, ...]:
    if len(indexes) != len(set(indexes)) or any(
        index >= len(available) for index in indexes
    ):
        raise IndexError("DYNAMIC_OBSERVATION_INDEX_INVALID")
    return tuple(available[index] for index in indexes)


__all__ = [
    "DynamicAgentInvocation",
    "DynamicAgentOutcome",
    "DynamicLLMCall",
    "DynamicReproductionAgent",
]
