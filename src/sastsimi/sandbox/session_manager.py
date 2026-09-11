"""Trusted append-only session log and validated-PoC finalization."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, cast

from pydantic import ValidationError

from sastsimi.contracts._domain import DomainRecord, exact, same_scope
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import (
    AgentLog,
    AgentLogEvent,
    CleanupResult,
    DynamicReproductionConclusion,
    DynamicReproductionRequest,
    DynamicReproductionResult,
    DynamicReproductionToolRequest,
    EnvironmentRecipe,
    EnvironmentRequirements,
    PlanIssueItem,
    PoCBundle,
    PoCCandidate,
    ReproductionPlan,
    SandboxCommandRecord,
    SandboxEnvironment,
    SandboxPolicyDecision,
    is_poc_execution_command,
    validate_dynamic_closure,
    validate_log_revision,
)
from sastsimi.contracts.ids import ActionId, LogicalRecordId, RecordId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.storage.records import next_meta

type DynamicStatus = Literal["SUCCEEDED", "PARTIAL", "FAILED", "BLOCKED", "CANCELLED"]
type FailureCategory = Literal[
    "NONE",
    "POLICY_BLOCKED",
    "EXTERNAL_CONFIGURATION",
    "PLAN",
    "ENVIRONMENT_SETUP",
    "DEPENDENCY",
    "AGENT",
    "EXECUTION",
    "OBSERVATION",
    "TIMEOUT",
    "RESOURCE_LIMIT",
    "RETRY_LIMIT",
    "INTERNAL",
]


@dataclass(frozen=True)
class DynamicFinalizationInput:
    request: DynamicReproductionRequest
    plan: ReproductionPlan | None
    policy: SandboxPolicyDecision | None
    recipe: EnvironmentRecipe | None
    environment: SandboxEnvironment | None
    candidate: PoCCandidate | None
    conclusion: DynamicReproductionConclusion | None
    cleanup: CleanupResult | None
    observation_refs: tuple[StoredDataRef, ...]
    status: DynamicStatus
    failure_category: FailureCategory
    failure_reason: str | None
    plan_issues: tuple[PlanIssueItem, ...]
    started_at: datetime
    finished_at: datetime
    requirements: EnvironmentRequirements | None = None
    command_records: tuple[SandboxCommandRecord, ...] = ()
    tool_requests: tuple[DynamicReproductionToolRequest, ...] = ()
    attempt_environments: tuple[SandboxEnvironment, ...] = ()
    attempt_recipes: tuple[EnvironmentRecipe, ...] = ()
    attempt_resource_refs: tuple[StoredDataRef, ...] = ()
    resolved_evidence: Mapping[StoredDataRef, DomainRecord] = field(
        default_factory=dict
    )


@dataclass(frozen=True)
class FinalizedDynamicRecords:
    log: AgentLog
    poc: PoCBundle | None
    result: DynamicReproductionResult


class ReproductionSessionManager:
    """Own log revisions and promote only an executed, supported PoC candidate."""

    def __init__(self, *, clock: Clock, ids: IdGenerator) -> None:
        self._clock = clock
        self._ids = ids
        self._latest_logs: dict[str, AgentLog] = {}
        self._event_bytes: dict[str, tuple[str, bytes]] = {}

    def start(
        self,
        *,
        request_ref: StoredDataRef,
        meta: RecordMeta,
        policy_decision_ref: StoredDataRef | None = None,
    ) -> AgentLog:
        if meta.record_type != AgentLog.KIND or meta.attempt_id is None:
            raise ValueError("SESSION_LOG_METADATA_MISMATCH")
        key = str(meta.logical_record_id)
        if key in self._latest_logs:
            raise ValueError("RECOVERY_FAILED: log already started")
        event = AgentLogEvent(
            event_id=str(self._ids.new(RecordId)),
            sequence=1,
            action_id=self._ids.new(ActionId),
            event_type="SESSION_STARTED",
            actor="REPRODUCTION_SESSION_MANAGER",
            environment_ref=None,
            environment_recipe_ref=None,
            poc_candidate_ref=None,
            tool_request_ref=None,
            command_ref=None,
            command_digest=None,
            redaction_status=None,
            input_refs=(
                (request_ref,)
                if policy_decision_ref is None
                else (request_ref, policy_decision_ref)
            ),
            output_refs=(),
            exit_code=None,
            timed_out=None,
            safe_message="Dynamic reproduction session started",
            occurred_at=self._clock.now(),
        )
        log = AgentLog(meta=meta, request_ref=request_ref, events=(event,))
        self._remember(log)
        return log

    def append(self, *, previous: AgentLog, event: AgentLogEvent) -> AgentLog:
        key = str(previous.meta.logical_record_id)
        latest = self._latest_logs.get(key)
        if latest is None:
            self._remember(previous)
            latest = previous
        if content_hash(previous) != content_hash(latest):
            replay = next(
                (item for item in latest.events if item.event_id == event.event_id),
                None,
            )
            if replay is not None and canonical_bytes(replay) == canonical_bytes(event):
                return latest
            raise ValueError("STALE_RESULT: AgentLog revision is not current")

        existing = next(
            (item for item in latest.events if item.event_id == event.event_id), None
        )
        if existing is not None:
            if canonical_bytes(existing) == canonical_bytes(event):
                return latest
            raise ValueError("RECOVERY_FAILED: changed event replay")
        if event.sequence != len(latest.events) + 1:
            raise ValueError("RECOVERY_FAILED: log sequence is not contiguous")
        if event.occurred_at < latest.events[-1].occurred_at:
            raise ValueError("RECOVERY_FAILED: event time regressed")
        if any(item.event_type == "SESSION_FINISHED" for item in latest.events):
            raise ValueError("RECOVERY_FAILED: session is already finished")
        if event.event_type == "SESSION_STARTED":
            raise ValueError("RECOVERY_FAILED: session already started")
        seen = self._event_bytes.get(event.event_id)
        if seen is not None:
            raise ValueError("RECOVERY_FAILED: event_id was already used")
        try:
            current = AgentLog(
                meta=cast(RecordMeta, next_meta(latest.meta, self._clock, self._ids)),
                request_ref=latest.request_ref,
                events=(*latest.events, event),
            )
            validate_log_revision(latest, current)
        except (ValidationError, ValueError) as error:
            raise ValueError(f"RECOVERY_FAILED: {error}") from error
        self._remember(current)
        return current

    def finalize(
        self, *, data: DynamicFinalizationInput, log: AgentLog, meta: RecordMeta
    ) -> FinalizedDynamicRecords:
        self._require_attempt_scope(data, log, meta)
        candidate = (
            data.candidate if self._candidate_is_current(data, log, meta) else None
        )
        can_promote, execution = self._can_promote(data, log, meta, candidate)

        result_status = data.status
        failure_category = data.failure_category
        failure_reason = data.failure_reason
        conclusion = data.conclusion
        if data.status not in {"SUCCEEDED", "PARTIAL"}:
            conclusion = None
        elif conclusion is not None and conclusion.proposed_outcome == "SUPPORTED":
            if not can_promote:
                result_status = "FAILED"
                failure_category = "EXECUTION"
                failure_reason = "Validated PoC closure is incomplete"
                conclusion = None
        elif (
            conclusion is not None
            and conclusion.proposed_outcome == "DISPROVED"
            and not self._has_observed_disproof(log, conclusion)
        ):
            result_status = "FAILED"
            failure_category = "OBSERVATION"
            failure_reason = "Disproof is not connected to a completed observation"
            conclusion = None
        elif not self._conclusion_is_current(data, meta, candidate):
            result_status = "FAILED"
            failure_category = "AGENT"
            failure_reason = "Dynamic conclusion closure is incomplete"
            conclusion = None

        outcome = (
            conclusion.proposed_outcome
            if conclusion is not None and result_status in {"SUCCEEDED", "PARTIAL"}
            else "INCONCLUSIVE"
        )
        poc = (
            self._make_poc(data, log, meta, cast(AgentLogEvent, execution), candidate)
            if can_promote
            and outcome == "SUPPORTED"
            and candidate is not None
            and conclusion is not None
            else None
        )
        result = self._make_result(
            data=data,
            log=log,
            meta=meta,
            candidate=candidate,
            conclusion=conclusion,
            poc=poc,
            status=result_status,
            failure_category=failure_category,
            failure_reason=failure_reason,
        )
        validate_dynamic_closure(
            result,
            data.request,
            log,
            generation=data.request.verification_generation,
            plan=data.plan,
            recipe=data.recipe,
            environment=data.environment,
            candidate=candidate,
            poc=poc,
            conclusion=conclusion,
            policy=data.policy,
            cleanup=data.cleanup,
            resolved_evidence=data.resolved_evidence,
            command_records=data.command_records,
            tool_requests=data.tool_requests,
            attempt_environments=data.attempt_environments,
            attempt_recipes=data.attempt_recipes,
            requirements=data.requirements,
            attempt_resource_refs=data.attempt_resource_refs,
        )
        return FinalizedDynamicRecords(log=log, poc=poc, result=result)

    def _remember(self, log: AgentLog) -> None:
        key = str(log.meta.logical_record_id)
        self._latest_logs[key] = log
        for event in log.events:
            stored = self._event_bytes.get(event.event_id)
            value = (key, canonical_bytes(event))
            if stored is not None and stored != value:
                raise ValueError("RECOVERY_FAILED: event_id collision")
            self._event_bytes[event.event_id] = value

    @staticmethod
    def _require_attempt_scope(
        data: DynamicFinalizationInput, log: AgentLog, meta: RecordMeta
    ) -> None:
        if meta.hypothesis_id is None or meta.attempt_id is None:
            raise ValueError("DYNAMIC_FINALIZATION_SCOPE_MISMATCH")
        exact(log.request_ref, data.request, meta)
        same_scope(meta, data.request.meta)
        same_scope(meta, log.meta, attempt=True)
        records = (
            data.requirements,
            data.plan,
            data.policy,
            data.recipe,
            data.environment,
            data.cleanup,
            *data.command_records,
            *data.tool_requests,
            *data.attempt_environments,
            *data.attempt_recipes,
        )
        for record in records:
            if record is None:
                continue
            same_scope(meta, record.meta, attempt=True)
            exact(record.request_ref, data.request, meta)

    @staticmethod
    def _candidate_is_current(
        data: DynamicFinalizationInput, log: AgentLog, meta: RecordMeta
    ) -> bool:
        candidate = data.candidate
        if candidate is None or data.plan is None:
            return False
        try:
            same_scope(meta, candidate.meta, attempt=True)
            exact(candidate.request_ref, data.request, meta)
            exact(candidate.reproduction_plan_ref, data.plan, meta)
        except ValueError:
            return False
        candidate_ref = _logged_ref(log, candidate, "poc_candidate_ref", meta)
        if candidate_ref is None:
            return False
        return any(
            event.poc_candidate_ref == candidate_ref
            and (
                (
                    event.event_type == "POC_CANDIDATE_CREATED"
                    and event.actor == "DYNAMIC_REPRODUCTION"
                )
                or (
                    event.event_type == "POC_EXECUTION_STARTED"
                    and event.actor == "TOOL_RUNTIME"
                )
            )
            for event in log.events
        )

    @staticmethod
    def _conclusion_is_current(
        data: DynamicFinalizationInput,
        meta: RecordMeta,
        candidate: PoCCandidate | None,
    ) -> bool:
        conclusion = data.conclusion
        if conclusion is None or data.plan is None or data.environment is None:
            return False
        try:
            same_scope(meta, conclusion.meta, attempt=True)
            exact(conclusion.request_ref, data.request, meta)
            exact(conclusion.reproduction_plan_ref, data.plan, meta)
            exact(conclusion.environment_ref, data.environment, meta)
            if conclusion.poc_candidate_ref is not None:
                if candidate is None:
                    return False
                exact(conclusion.poc_candidate_ref, candidate, meta)
        except ValueError:
            return False
        return (conclusion.poc_candidate_ref is None) == (candidate is None)

    def _can_promote(
        self,
        data: DynamicFinalizationInput,
        log: AgentLog,
        meta: RecordMeta,
        candidate: PoCCandidate | None,
    ) -> tuple[bool, AgentLogEvent | None]:
        if (
            data.status != "SUCCEEDED"
            or data.failure_category != "NONE"
            or data.failure_reason is not None
            or candidate is None
            or data.conclusion is None
            or data.conclusion.proposed_outcome != "SUPPORTED"
            or not self._conclusion_is_current(data, meta, candidate)
            or data.plan is None
            or data.policy is None
            or data.policy.decision != "ALLOW"
            or data.recipe is None
            or data.environment is None
            or data.cleanup is None
            or data.cleanup.status != "SUCCEEDED"
            or any(issue.status == "OPEN" for issue in data.plan_issues)
            or not self._lifecycle_is_complete(log)
        ):
            return False, None
        candidate_ref = _logged_ref(log, candidate, "poc_candidate_ref", meta)
        environment_ref = _logged_ref(log, data.environment, "environment_ref", meta)
        recipe_ref = _logged_ref(log, data.recipe, "environment_recipe_ref", meta)
        if candidate_ref is None or environment_ref is None or recipe_ref is None:
            return False, None
        executions = [
            event
            for event in log.events
            if event.event_type == "POC_EXECUTION_FINISHED"
            and event.actor == "TOOL_RUNTIME"
            and event.poc_candidate_ref == candidate_ref
            and event.environment_ref == environment_ref
            and event.environment_recipe_ref == recipe_ref
            and event.exit_code == 0
            and event.timed_out is False
            and event.output_refs
            and event.input_refs == (candidate.content_ref,)
        ]
        if len(executions) != 1:
            return False, None
        execution = executions[0]
        started = [
            event
            for event in log.events
            if event.event_type == "POC_EXECUTION_STARTED"
            and event.actor == "TOOL_RUNTIME"
            and event.action_id == execution.action_id
            and event.poc_candidate_ref == candidate_ref
            and event.environment_ref == environment_ref
            and event.environment_recipe_ref == recipe_ref
            and event.input_refs == (candidate.content_ref,)
        ]
        commands = [
            event
            for event in log.events
            if event.event_type == "COMMAND_FINISHED"
            and event.actor == "TOOL_RUNTIME"
            and event.action_id == execution.action_id
            and event.poc_candidate_ref == candidate_ref
            and event.environment_ref == environment_ref
            and event.environment_recipe_ref == recipe_ref
            and event.exit_code == 0
            and event.timed_out is False
        ]
        if len(started) != 1 or len(commands) != 1:
            return False, None
        command = commands[0]
        command_records = [
            record
            for record in data.command_records
            if command.command_ref is not None
            and command.command_ref.record_id == record.meta.record_id
            and command.command_ref.content_hash == content_hash(record)
            and record.action_id == execution.action_id
            and record.environment_ref == environment_ref
            and record.environment_recipe_ref == recipe_ref
        ]
        if len(command_records) != 1 or not is_poc_execution_command(
            command_records[0]
        ):
            return False, None
        command_starts = [
            event
            for event in log.events
            if event.event_type == "COMMAND_STARTED"
            and event.actor == "TOOL_RUNTIME"
            and event.action_id == execution.action_id
            and event.command_ref == command.command_ref
            and event.tool_request_ref == command.tool_request_ref
            and event.command_digest == command.command_digest
            and event.redaction_status == command.redaction_status
            and event.poc_candidate_ref == candidate_ref
            and event.environment_ref == environment_ref
            and event.environment_recipe_ref == recipe_ref
        ]
        evidence = set(data.conclusion.hypothesis_evidence_refs)
        poc_provenance = (
            execution.command_ref,
            execution.tool_request_ref,
            execution.command_digest,
            execution.redaction_status,
        )
        command_provenance = (
            command.command_ref,
            command.tool_request_ref,
            command.command_digest,
            command.redaction_status,
        )
        if (
            len(command_starts) != 1
            or poc_provenance != command_provenance
            or not evidence.intersection(execution.output_refs)
        ):
            return False, None
        return True, execution

    @staticmethod
    def _lifecycle_is_complete(log: AgentLog) -> bool:
        for prefix in ("SESSION", "AGENT"):
            starts = [
                event
                for event in log.events
                if event.event_type == f"{prefix}_STARTED"
                and event.actor == "REPRODUCTION_SESSION_MANAGER"
            ]
            finishes = [
                event
                for event in log.events
                if event.event_type == f"{prefix}_FINISHED"
                and event.actor == "REPRODUCTION_SESSION_MANAGER"
            ]
            if (
                len(starts) != 1
                or len(finishes) != 1
                or starts[0].action_id != finishes[0].action_id
                or starts[0].sequence >= finishes[0].sequence
            ):
                return False
        return True

    def _has_observed_disproof(
        self, log: AgentLog, conclusion: DynamicReproductionConclusion
    ) -> bool:
        if not self._lifecycle_is_complete(log):
            return False
        evidence = set(conclusion.hypothesis_evidence_refs)
        return bool(evidence) and any(
            event.event_type == "COMMAND_FINISHED"
            and event.actor == "TOOL_RUNTIME"
            and event.exit_code == 0
            and event.timed_out is False
            and evidence.intersection(event.output_refs)
            for event in log.events
        )

    def _make_poc(
        self,
        data: DynamicFinalizationInput,
        log: AgentLog,
        meta: RecordMeta,
        execution: AgentLogEvent,
        candidate: PoCCandidate,
    ) -> PoCBundle:
        assert data.plan is not None
        assert data.recipe is not None
        assert data.environment is not None
        assert data.conclusion is not None
        candidate_ref = cast(StoredDataRef, execution.poc_candidate_ref)
        environment_ref = cast(StoredDataRef, execution.environment_ref)
        recipe_ref = cast(StoredDataRef, execution.environment_recipe_ref)
        return PoCBundle(
            meta=self._fresh_meta(meta, PoCBundle.KIND),
            request_ref=log.request_ref,
            reproduction_plan_ref=data.conclusion.reproduction_plan_ref,
            environment_recipe_ref=recipe_ref,
            environment_ref=environment_ref,
            agent_log_ref=_stored_ref(log),
            candidate_ref=candidate_ref,
            candidate_digest=candidate.content_digest,
            execution_action_id=execution.action_id,
            evidence_refs=data.conclusion.hypothesis_evidence_refs,
            validated_at=data.finished_at,
        )

    def _make_result(
        self,
        *,
        data: DynamicFinalizationInput,
        log: AgentLog,
        meta: RecordMeta,
        candidate: PoCCandidate | None,
        conclusion: DynamicReproductionConclusion | None,
        poc: PoCBundle | None,
        status: DynamicStatus,
        failure_category: FailureCategory,
        failure_reason: str | None,
    ) -> DynamicReproductionResult:
        outcome = (
            conclusion.proposed_outcome
            if conclusion is not None and status in {"SUCCEEDED", "PARTIAL"}
            else "INCONCLUSIVE"
        )
        evidence = conclusion.hypothesis_evidence_refs if conclusion else ()
        observations = data.observation_refs
        limitations = conclusion.limitations if conclusion else ()
        plan_issues = data.plan_issues
        plan_status: Literal[
            "EXECUTABLE", "EXECUTABLE_WITH_LIMITATIONS", "NEEDS_REVISION"
        ] = (
            "NEEDS_REVISION"
            if any(issue.status == "OPEN" for issue in plan_issues)
            else "EXECUTABLE_WITH_LIMITATIONS"
            if limitations
            else "EXECUTABLE"
        )
        policy_ref = (
            _input_ref(log, data.policy, meta) if data.policy is not None else None
        )
        if data.policy is not None and policy_ref is None:
            raise ValueError("SANDBOX_POLICY_LOG_MISMATCH")
        cleanup_ref = _stored_ref(data.cleanup) if data.cleanup is not None else None
        environment_ref = None
        if data.environment is not None:
            environment_ref = _logged_ref(
                log, data.environment, "environment_ref", meta
            )
            if environment_ref is None:
                raise ValueError("DYNAMIC_ENVIRONMENT_LOG_MISMATCH")
        plan_ref = None
        if conclusion is not None:
            plan_ref = conclusion.reproduction_plan_ref
        elif candidate is not None:
            plan_ref = candidate.reproduction_plan_ref
        elif data.environment is not None:
            plan_ref = data.environment.reproduction_plan_ref
        elif data.plan is not None:
            plan_ref = _stored_ref(data.plan)
        recipe_ref = None
        if data.recipe is not None:
            if data.environment is not None:
                recipe_ref = data.environment.environment_recipe_ref
            else:
                recipe_ref = _logged_ref(
                    log, data.recipe, "environment_recipe_ref", meta
                ) or _stored_ref(data.recipe)
        candidate_ref = None
        if candidate is not None:
            candidate_ref = _logged_ref(log, candidate, "poc_candidate_ref", meta)
            if candidate_ref is None:
                raise ValueError("CANDIDATE_LOG_REQUIRED")
        return DynamicReproductionResult(
            meta=self._fresh_meta(meta, DynamicReproductionResult.KIND),
            action_decision_ref=(
                data.policy.action_decision_ref if data.policy is not None else None
            ),
            request_ref=log.request_ref,
            reproduction_plan_ref=plan_ref,
            purpose=data.request.purpose,
            policy_decision_ref=policy_ref,
            agent_invoked=any(
                event.event_type == "AGENT_STARTED" for event in log.events
            ),
            agent_log_ref=_stored_ref(log),
            agent_conclusion_ref=(
                _stored_ref(conclusion) if conclusion is not None else None
            ),
            environment_recipe_ref=recipe_ref,
            environment_ref=environment_ref,
            poc_candidate_ref=candidate_ref,
            poc_ref=_stored_ref(poc) if poc is not None else None,
            observation_refs=observations,
            status=status,
            failure_category=failure_category,
            failure_reason=failure_reason,
            plan_issues=plan_issues,
            hypothesis_outcome=outcome,
            hypothesis_evidence_refs=evidence,
            hypothesis_disproved=outcome == "DISPROVED",
            disproof_evidence_refs=evidence if outcome == "DISPROVED" else (),
            hypothesis_linkage=(
                conclusion.hypothesis_linkage
                if conclusion is not None
                else failure_reason or "Dynamic reproduction produced no verdict"
            ),
            plan_execution_status=plan_status,
            plan_issue_evidence_refs=tuple(
                reference for issue in plan_issues for reference in issue.related_refs
            ),
            limitations=limitations,
            cleanup_required=environment_ref is not None,
            cleanup_status=data.cleanup.status if data.cleanup else "NOT_REQUIRED",
            cleanup_ref=cleanup_ref,
            started_at=data.started_at,
            finished_at=data.finished_at,
            elapsed_ms=max(
                0, int((data.finished_at - data.started_at).total_seconds() * 1000)
            ),
        )

    def _fresh_meta(self, source: RecordMeta, kind: str) -> RecordMeta:
        record_id = self._ids.new(RecordId)
        return RecordMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=kind,
            schema_version=source.schema_version,
            revision_number=1,
            previous_record_id=None,
            created_at=self._clock.now(),
            analysis_id=source.analysis_id,
            workspace_id=source.workspace_id,
            commit_id=source.commit_id,
            hypothesis_id=source.hypothesis_id,
            attempt_id=source.attempt_id,
        )


def _stored_ref(record: DomainRecord) -> StoredDataRef:
    value = reference(record)
    if not isinstance(value, StoredDataRef):
        raise ValueError("DYNAMIC_RECORD_REFERENCE_REQUIRED")
    return value


def _logged_ref(
    log: AgentLog, target: DomainRecord, field_name: str, consumer: RecordMeta
) -> StoredDataRef | None:
    for event in log.events:
        value = getattr(event, field_name)
        if isinstance(value, StoredDataRef):
            try:
                exact(value, target, consumer)
            except ValueError:
                continue
            return value
    return None


def _input_ref(
    log: AgentLog, target: DomainRecord, consumer: RecordMeta
) -> StoredDataRef | None:
    for event in log.events:
        for value in event.input_refs:
            if not isinstance(value, StoredDataRef):
                continue
            try:
                exact(value, target, consumer)
            except ValueError:
                continue
            return value
    return None


__all__ = [
    "DynamicFinalizationInput",
    "FinalizedDynamicRecords",
    "ReproductionSessionManager",
]
