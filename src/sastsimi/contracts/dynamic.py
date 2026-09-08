"""R6 requests, R7 execution records and PoC provenance (§08.7)."""

from typing import Literal, Self

from pydantic import AwareDatetime, model_validator

from ._domain import DomainRecord, SafeDiagnostic, exact, exact_set, same_scope, unique
from .base import ContractModel, NonEmptyStr, NonNegativeInt, PositiveInt, Sha256
from .canonical_json import content_hash
from .ids import ActionId
from .records import validate_revision
from .refs import StoredDataRef, require_record_ref

type NeedKind = Literal[
    "APP_ROLE",
    "AUTH",
    "DATA",
    "DATABASE",
    "SERVICE",
    "FIXTURE",
    "MOCK",
    "VERSION",
    "HEALTH_CHECK",
]
type DynamicPurpose = Literal["POC_CONFIRMATION", "VERDICT_EVIDENCE"]
type HypothesisOutcome = Literal["SUPPORTED", "DISPROVED", "INCONCLUSIVE"]


class EnvironmentNeed(ContractModel):
    need_id: NonEmptyStr
    kind: NeedKind
    description: NonEmptyStr
    required: bool
    source_refs: tuple[StoredDataRef, ...]


class DynamicReproductionRequest(DomainRecord):
    KIND = "dynamic_reproduction_request"
    HYPOTHESIS = True
    verification_assignment_ref: StoredDataRef
    verification_generation: PositiveInt
    hypothesis_ref: StoredDataRef
    purpose: DynamicPurpose
    initial_verdict: Literal["TRUE", "HOLD"]
    goal: NonEmptyStr
    environment_needs: tuple[EnvironmentNeed, ...]
    sandbox_profile_ref: StoredDataRef
    code_refs: tuple[StoredDataRef, ...]
    static_evidence_refs: tuple[StoredDataRef, ...]
    pro_evidence_ref: StoredDataRef
    con_evidence_ref: StoredDataRef
    created_at: AwareDatetime

    @model_validator(mode="after")
    def purpose_shape(self) -> Self:
        if (self.purpose == "POC_CONFIRMATION") != (self.initial_verdict == "TRUE"):
            raise ValueError("DYNAMIC_PURPOSE_MISMATCH")
        unique(need.need_id for need in self.environment_needs)
        return self


class DynamicRecord(DomainRecord):
    HYPOTHESIS = True
    request_ref: StoredDataRef

    @model_validator(mode="after")
    def exact_request(self) -> Self:
        require_record_ref(self.request_ref, "dynamic_reproduction_request")
        return self


class EnvironmentRequirement(ContractModel):
    requirement_id: NonEmptyStr
    kind: NeedKind
    name: NonEmptyStr
    required: bool
    expected: NonEmptyStr | None
    expected_ref: StoredDataRef | None
    alternatives: tuple[NonEmptyStr, ...]
    check_ref: StoredDataRef | None
    secret_ref: StoredDataRef | None
    source_refs: tuple[StoredDataRef, ...]

    @model_validator(mode="after")
    def secret_handle(self) -> Self:
        if self.secret_ref is not None and self.secret_ref.data_kind != "secret_handle":
            raise ValueError("SECRET_HANDLE_REQUIRED")
        return self


class EnvironmentRequirements(DynamicRecord):
    KIND = "environment_requirements"
    items: tuple[EnvironmentRequirement, ...]

    @model_validator(mode="after")
    def ids(self) -> Self:
        unique(item.requirement_id for item in self.items)
        return self


class ReproductionPlan(DynamicRecord):
    KIND = "reproduction_plan"
    purpose: DynamicPurpose
    hypothesis_ref: StoredDataRef
    environment_requirements_ref: StoredDataRef
    sandbox_profile_ref: StoredDataRef
    reproduction_goal: NonEmptyStr
    strategy_summary: NonEmptyStr
    requested_evidence: tuple[NonEmptyStr, ...]


class SandboxProfile(DomainRecord):
    KIND = "sandbox_profile"
    HYPOTHESIS = False
    ATTEMPT = False
    network_mode: Literal["DEFAULT_DENY"]
    allowed_egress_refs: tuple[StoredDataRef, ...]
    isolation_policy_refs: tuple[StoredDataRef, ...]
    cpu_limit_millicores: PositiveInt
    memory_limit_bytes: PositiveInt
    disk_limit_bytes: PositiveInt
    pid_limit: PositiveInt
    max_requested_execution_ms: PositiveInt
    created_at: AwareDatetime


class EnvironmentRecipe(DynamicRecord):
    KIND = "environment_recipe"
    environment_requirements_ref: StoredDataRef
    recipe_source_ref: StoredDataRef
    source_refs: tuple[StoredDataRef, ...]
    base_image_digest: NonEmptyStr
    built_image_digest: NonEmptyStr
    baseline_recipe_ref: StoredDataRef | None
    build_disposition: Literal["BUILT", "REUSED"]
    created_at: AwareDatetime

    @model_validator(mode="after")
    def baseline(self) -> Self:
        if self.build_disposition == "REUSED" and self.baseline_recipe_ref is None:
            raise ValueError("BASELINE_RECIPE_REQUIRED")
        return self


class EnvironmentCheck(ContractModel):
    requirement_id: NonEmptyStr
    status: Literal["MATCH", "MISMATCH", "NOT_CHECKED", "ERROR"]
    actual: NonEmptyStr | None
    actual_ref: StoredDataRef | None
    difference: NonEmptyStr | None
    evidence_refs: tuple[StoredDataRef, ...]
    check_result_ref: StoredDataRef | None

    @model_validator(mode="after")
    def check_shape(self) -> Self:
        if not self.evidence_refs and self.check_result_ref is None:
            raise ValueError("ENVIRONMENT_CHECK_EVIDENCE_REQUIRED")
        if (
            self.status in {"MATCH", "MISMATCH"}
            and self.actual is None
            and self.actual_ref is None
        ):
            raise ValueError("ENVIRONMENT_ACTUAL_REQUIRED")
        if self.status != "MATCH" and self.difference is None:
            raise ValueError("ENVIRONMENT_DIFFERENCE_REQUIRED")
        return self


class SandboxEnvironment(DynamicRecord):
    KIND = "sandbox_environment"
    reproduction_plan_ref: StoredDataRef
    environment_recipe_ref: StoredDataRef
    requirements_ref: StoredDataRef
    container_instance_id: NonEmptyStr
    container_action: Literal["CREATED", "REUSED"]
    container_reason: Literal[
        "INITIAL_CLEAN",
        "NO_RELEVANT_CHANGE",
        "STATE_CHANGED",
        "CONFIG_CHANGED",
        "STATE_UNCERTAIN",
    ]
    previous_environment_ref: StoredDataRef | None
    status: Literal["READY", "MISMATCH", "ERROR"]
    checks: tuple[EnvironmentCheck, ...]
    limitations: tuple[NonEmptyStr, ...]
    created_at: AwareDatetime

    @model_validator(mode="after")
    def container_shape(self) -> Self:
        unique(check.requirement_id for check in self.checks)
        if (self.container_action == "REUSED") != (
            self.container_reason == "NO_RELEVANT_CHANGE"
        ):
            raise ValueError("CONTAINER_REUSE_MISMATCH")
        if (self.container_reason == "INITIAL_CLEAN") != (
            self.previous_environment_ref is None
        ):
            raise ValueError("CONTAINER_PREDECESSOR_REQUIRED")
        return self


class PlanIssueItem(ContractModel):
    issue_code: Literal[
        "MISSING_INPUT",
        "CONTRADICTORY_REQUIREMENT",
        "UNEXECUTABLE_GOAL",
        "STALE_REFERENCE",
        "OTHER",
    ]
    status: Literal["OPEN", "RESOLVED"]
    message: NonEmptyStr
    related_refs: tuple[StoredDataRef, ...]


class SandboxPolicyDecision(DynamicRecord):
    KIND = "sandbox_policy_decision"
    action_decision_ref: StoredDataRef
    sandbox_profile_ref: StoredDataRef
    resource_profile_ref: StoredDataRef
    run_policy_state_ref: StoredDataRef
    policy_collection_result_ref: StoredDataRef | None
    policy_record_ref: StoredDataRef | None
    execution_scope: Literal["LOCAL_ONLY"]
    observed_policy_status: Literal[
        "PREPARING", "CURRENT", "ABSENT", "BLOCKED", "FAILED", "UNVERIFIED"
    ]
    decision: Literal["ALLOW", "DENY"]
    reason_codes: tuple[NonEmptyStr, ...]
    checked_boundary_refs: tuple[StoredDataRef, ...]
    decided_at: AwareDatetime

    @model_validator(mode="after")
    def policy_shape(self) -> Self:
        if not self.reason_codes:
            raise ValueError("POLICY_REASON_REQUIRED")
        if self.observed_policy_status == "PREPARING" and (
            self.policy_collection_result_ref is not None
            or self.policy_record_ref is not None
        ):
            raise ValueError("POLICY_PROVENANCE_MISMATCH")
        if self.observed_policy_status == "CURRENT" and (
            self.policy_collection_result_ref is None or self.policy_record_ref is None
        ):
            raise ValueError("POLICY_PROVENANCE_MISMATCH")
        if (
            self.observed_policy_status in {"ABSENT", "BLOCKED", "FAILED"}
            and self.policy_record_ref is not None
        ):
            raise ValueError("POLICY_PROVENANCE_MISMATCH")
        return self


class SandboxCommandInput(ContractModel):
    executable: NonEmptyStr
    arguments: tuple[str, ...]
    working_directory: NonEmptyStr
    environment_binding_refs: tuple[StoredDataRef, ...]
    stdin_ref: StoredDataRef | None
    secret_refs: tuple[StoredDataRef, ...]

    @model_validator(mode="after")
    def secret_handles(self) -> Self:
        if any(ref.data_kind != "secret_handle" for ref in self.secret_refs):
            raise ValueError("SECRET_HANDLE_REQUIRED")
        return self


class SandboxCommandRecord(DynamicRecord, SandboxCommandInput):
    KIND = "sandbox_command_record"
    action_id: ActionId
    tool_request_ref: StoredDataRef
    reproduction_plan_ref: StoredDataRef
    environment_recipe_ref: StoredDataRef
    environment_ref: StoredDataRef
    command_digest: Sha256
    redaction_status: Literal["REDACTED", "NOT_REQUIRED"]
    created_at: AwareDatetime

    @model_validator(mode="after")
    def digest(self) -> Self:
        command = {
            name: getattr(self, name) for name in SandboxCommandInput.model_fields
        }
        if self.command_digest != content_hash(command):
            raise ValueError("COMMAND_DIGEST_MISMATCH")
        return self


class CleanupResult(DynamicRecord):
    KIND = "cleanup_result"
    environment_refs: tuple[StoredDataRef, ...]
    resource_refs: tuple[StoredDataRef, ...]
    status: Literal["SUCCEEDED", "FAILED"]
    failure_reason: NonEmptyStr | None
    finished_at: AwareDatetime

    @model_validator(mode="after")
    def failure(self) -> Self:
        if (self.status == "FAILED") != (self.failure_reason is not None):
            raise ValueError("CLEANUP_STATUS_MISMATCH")
        return self


class AgentLogEvent(ContractModel):
    event_id: NonEmptyStr
    sequence: PositiveInt
    action_id: ActionId
    event_type: Literal[
        "SESSION_STARTED",
        "AGENT_STARTED",
        "AGENT_FINISHED",
        "COMMAND_STARTED",
        "COMMAND_FINISHED",
        "POC_CANDIDATE_CREATED",
        "POC_EXECUTION_STARTED",
        "POC_EXECUTION_FINISHED",
        "OBSERVATION_RECORDED",
        "SANDBOX_RECREATE_REQUESTED",
        "SANDBOX_RECREATED",
        "CLEANUP_STARTED",
        "CLEANUP_FINISHED",
        "POLICY_BLOCKED",
        "ERROR",
        "SESSION_FINISHED",
    ]
    actor: Literal[
        "DYNAMIC_REPRODUCTION",
        "REPRODUCTION_SETUP_AUTOMATION",
        "TOOL_RUNTIME",
        "SANDBOX_CONTROLLER",
        "REPRODUCTION_SESSION_MANAGER",
    ]
    environment_ref: StoredDataRef | None
    environment_recipe_ref: StoredDataRef | None
    poc_candidate_ref: StoredDataRef | None
    tool_request_ref: StoredDataRef | None
    command_ref: StoredDataRef | None
    command_digest: Sha256 | None
    redaction_status: Literal["REDACTED", "NOT_REQUIRED"] | None
    input_refs: tuple[StoredDataRef, ...]
    output_refs: tuple[StoredDataRef, ...]
    exit_code: int | None
    safe_message: SafeDiagnostic | None
    occurred_at: AwareDatetime

    @model_validator(mode="after")
    def command_shape(self) -> Self:
        command = self.event_type in {"COMMAND_STARTED", "COMMAND_FINISHED"}
        if any(
            (value is not None) != command
            for value in (
                self.tool_request_ref,
                self.command_ref,
                self.command_digest,
                self.redaction_status,
            )
        ):
            raise ValueError("COMMAND_EVENT_PROVENANCE")
        if command and (
            self.environment_ref is None or self.environment_recipe_ref is None
        ):
            raise ValueError("COMMAND_ENVIRONMENT_REQUIRED")
        return self


class AgentLog(DynamicRecord):
    KIND = "agent_log"
    events: tuple[AgentLogEvent, ...]

    @model_validator(mode="after")
    def event_sequence(self) -> Self:
        unique(event.event_id for event in self.events)
        if [event.sequence for event in self.events] != list(
            range(1, len(self.events) + 1)
        ):
            raise ValueError("LOG_SEQUENCE_MISMATCH")
        pending: dict[tuple[str, ActionId], AgentLogEvent] = {}
        for event in self.events:
            if event.event_type.endswith("_STARTED"):
                key = (event.event_type.removesuffix("_STARTED"), event.action_id)
                if key in pending:
                    raise ValueError("LOG_ACTION_DUPLICATE")
                pending[key] = event
            elif event.event_type.endswith("_FINISHED"):
                key = (event.event_type.removesuffix("_FINISHED"), event.action_id)
                start = pending.pop(key, None)
                if start is None:
                    raise ValueError("LOG_ACTION_START_REQUIRED")
                if event.occurred_at < start.occurred_at:
                    raise ValueError("LOG_TIME_MISMATCH")
                if key[0] in {"COMMAND", "POC_EXECUTION"}:
                    for name in (
                        "command_ref",
                        "tool_request_ref",
                        "command_digest",
                        "environment_ref",
                        "environment_recipe_ref",
                        "poc_candidate_ref",
                    ):
                        if getattr(start, name) != getattr(event, name):
                            raise ValueError("LOG_ACTION_PROVENANCE_MISMATCH")
        return self


class PoCCandidate(DynamicRecord):
    KIND = "poc_candidate"
    reproduction_plan_ref: StoredDataRef
    content_ref: StoredDataRef
    content_digest: Sha256
    llm_call_id: NonEmptyStr
    created_at: AwareDatetime

    @model_validator(mode="after")
    def digest(self) -> Self:
        if self.content_digest != self.content_ref.content_hash:
            raise ValueError("CANDIDATE_DIGEST_MISMATCH")
        return self


class DynamicReproductionConclusion(DynamicRecord):
    KIND = "dynamic_reproduction_conclusion"
    reproduction_plan_ref: StoredDataRef
    environment_ref: StoredDataRef
    poc_candidate_ref: StoredDataRef | None
    observation_refs: tuple[StoredDataRef, ...]
    proposed_outcome: HypothesisOutcome
    hypothesis_evidence_refs: tuple[StoredDataRef, ...]
    hypothesis_linkage: NonEmptyStr
    limitations: tuple[NonEmptyStr, ...]
    llm_call_id: NonEmptyStr


class DynamicReproductionToolRequest(DynamicRecord):
    KIND = "dynamic_reproduction_tool_request"
    reproduction_plan_ref: StoredDataRef
    environment_ref: StoredDataRef
    turn_number: PositiveInt
    action: Literal[
        "RUN_COMMAND", "USE_POC_CANDIDATE", "REQUEST_SANDBOX_RECREATE", "FINISH"
    ]
    command: SandboxCommandInput | None
    poc_candidate_ref: StoredDataRef | None
    recreate_reason: (
        Literal["STATE_CHANGED", "CONFIG_CHANGED", "STATE_UNCERTAIN"] | None
    )
    rationale: NonEmptyStr
    llm_call_id: NonEmptyStr

    @model_validator(mode="after")
    def action_shape(self) -> Self:
        if (
            (self.action == "RUN_COMMAND") != (self.command is not None)
            or (self.action == "USE_POC_CANDIDATE")
            != (self.poc_candidate_ref is not None)
            or (self.action == "REQUEST_SANDBOX_RECREATE")
            != (self.recreate_reason is not None)
        ):
            raise ValueError("DYNAMIC_TOOL_ACTION_MISMATCH")
        return self


class PoCBundle(DynamicRecord):
    KIND = "poc_bundle"
    reproduction_plan_ref: StoredDataRef
    environment_recipe_ref: StoredDataRef
    environment_ref: StoredDataRef
    agent_log_ref: StoredDataRef
    candidate_ref: StoredDataRef
    candidate_digest: Sha256
    execution_action_id: ActionId
    evidence_refs: tuple[StoredDataRef, ...]
    validated_at: AwareDatetime


class DynamicReproductionResult(DynamicRecord):
    KIND = "dynamic_reproduction_result"
    action_decision_ref: StoredDataRef | None
    reproduction_plan_ref: StoredDataRef | None
    purpose: DynamicPurpose
    policy_decision_ref: StoredDataRef | None
    agent_invoked: bool
    agent_log_ref: StoredDataRef
    agent_conclusion_ref: StoredDataRef | None
    environment_recipe_ref: StoredDataRef | None
    environment_ref: StoredDataRef | None
    poc_candidate_ref: StoredDataRef | None
    poc_ref: StoredDataRef | None
    observation_refs: tuple[StoredDataRef, ...]
    status: Literal["SUCCEEDED", "PARTIAL", "FAILED", "BLOCKED", "CANCELLED"]
    failure_category: Literal[
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
    failure_reason: NonEmptyStr | None
    plan_issues: tuple[PlanIssueItem, ...]
    hypothesis_outcome: HypothesisOutcome
    hypothesis_evidence_refs: tuple[StoredDataRef, ...]
    hypothesis_disproved: bool
    disproof_evidence_refs: tuple[StoredDataRef, ...]
    hypothesis_linkage: NonEmptyStr
    plan_execution_status: Literal[
        "EXECUTABLE", "EXECUTABLE_WITH_LIMITATIONS", "NEEDS_REVISION"
    ]
    plan_issue_evidence_refs: tuple[StoredDataRef, ...]
    limitations: tuple[NonEmptyStr, ...]
    cleanup_required: bool
    cleanup_status: Literal["SUCCEEDED", "FAILED", "NOT_REQUIRED"]
    cleanup_ref: StoredDataRef | None
    started_at: AwareDatetime
    finished_at: AwareDatetime
    elapsed_ms: NonNegativeInt

    @model_validator(mode="after")
    def result_shape(self) -> Self:
        successful = self.status in {"SUCCEEDED", "PARTIAL"}
        supported = (
            self.status == "SUCCEEDED" and self.hypothesis_outcome == "SUPPORTED"
        )
        if successful != (self.failure_category == "NONE") or successful != (
            self.failure_reason is None
        ):
            raise ValueError("DYNAMIC_FAILURE_STATUS_MISMATCH")
        if self.status != "SUCCEEDED" and self.hypothesis_outcome != "INCONCLUSIVE":
            raise ValueError("EXECUTION_FAILURE_IS_NOT_VERDICT")
        if supported != (self.poc_ref is not None):
            raise ValueError("VALIDATED_POC_STATUS_MISMATCH")
        if supported and (
            not self.agent_invoked
            or any(
                ref is None
                for ref in (
                    self.reproduction_plan_ref,
                    self.environment_recipe_ref,
                    self.environment_ref,
                    self.poc_candidate_ref,
                )
            )
        ):
            raise ValueError("VALIDATED_POC_PROVENANCE_REQUIRED")
        if self.hypothesis_outcome != "INCONCLUSIVE" and (
            not self.observation_refs or not self.hypothesis_evidence_refs
        ):
            raise ValueError("DYNAMIC_OBSERVATIONS_REQUIRED")
        if (
            self.hypothesis_outcome == "DISPROVED"
        ) != self.hypothesis_disproved or self.hypothesis_disproved != bool(
            self.disproof_evidence_refs
        ):
            raise ValueError("DISPROOF_EVIDENCE_MISMATCH")
        if successful and (not self.agent_invoked or self.agent_conclusion_ref is None):
            raise ValueError("DYNAMIC_CONCLUSION_REQUIRED")
        if self.status == "PARTIAL" and (
            not self.observation_refs or not self.limitations
        ):
            raise ValueError("PARTIAL_EVIDENCE_REQUIRED")
        if not self.agent_invoked and self.agent_conclusion_ref is not None:
            raise ValueError("UNINVOKED_CONCLUSION_FORBIDDEN")
        if self.action_decision_ref is None:
            if (
                self.failure_category != "PLAN"
                or self.agent_invoked
                or any(
                    ref is not None
                    for ref in (
                        self.policy_decision_ref,
                        self.environment_recipe_ref,
                        self.environment_ref,
                        self.poc_candidate_ref,
                        self.poc_ref,
                    )
                )
            ):
                raise ValueError("PRE_BOUNDARY_FAILURE_MISMATCH")
        if (self.agent_invoked or self.failure_category == "POLICY_BLOCKED") and (
            self.action_decision_ref is None or self.policy_decision_ref is None
        ):
            raise ValueError("BOUNDARY_DECISION_REQUIRED")
        if self.cleanup_required != (
            self.cleanup_status != "NOT_REQUIRED"
        ) or self.cleanup_required != (self.cleanup_ref is not None):
            raise ValueError("CLEANUP_STATUS_MISMATCH")
        if self.environment_ref is not None and not self.cleanup_required:
            raise ValueError("CLEANUP_REQUIRED")
        if any(issue.status == "OPEN" for issue in self.plan_issues) and (
            self.hypothesis_outcome != "INCONCLUSIVE"
            or self.status not in {"FAILED", "BLOCKED"}
        ):
            raise ValueError("OPEN_PLAN_ISSUE")
        if self.plan_execution_status == "NEEDS_REVISION" and not self.plan_issues:
            raise ValueError("PLAN_ISSUE_REQUIRED")
        if self.finished_at < self.started_at:
            raise ValueError("INVALID_TIME_RANGE")
        return self


def validate_log_revision(previous: AgentLog, current: AgentLog) -> None:
    validate_revision(previous.meta, current.meta)
    same_scope(previous.meta, current.meta, attempt=True)
    if (
        previous.request_ref != current.request_ref
        or len(current.events) <= len(previous.events)
        or current.events[: len(previous.events)] != previous.events
    ):
        raise ValueError("LOG_APPEND_ONLY")


def validate_poc_candidate(poc: PoCBundle, candidate: PoCCandidate) -> None:
    exact(poc.candidate_ref, candidate, poc.meta)
    same_scope(poc.meta, candidate.meta, attempt=True)
    if poc.candidate_digest != candidate.content_digest:
        raise ValueError("POC_CANDIDATE_DIGEST_MISMATCH")
    if (
        poc.request_ref != candidate.request_ref
        or poc.reproduction_plan_ref != candidate.reproduction_plan_ref
    ):
        raise ValueError("POC_PROVENANCE_MISMATCH")


def validate_environment(
    environment: SandboxEnvironment,
    requirements: EnvironmentRequirements,
    plan: ReproductionPlan,
    recipe: EnvironmentRecipe,
) -> None:
    for ref, target in (
        (environment.requirements_ref, requirements),
        (environment.reproduction_plan_ref, plan),
        (environment.environment_recipe_ref, recipe),
    ):
        exact(ref, target, environment.meta)
        same_scope(environment.meta, target.meta, attempt=True)
        if target.request_ref != environment.request_ref:
            raise ValueError("DYNAMIC_REQUEST_MISMATCH")
    if (
        plan.environment_requirements_ref != environment.requirements_ref
        or recipe.environment_requirements_ref != environment.requirements_ref
    ):
        raise ValueError("ENVIRONMENT_REQUIREMENTS_MISMATCH")
    exact_set(
        (c.requirement_id for c in environment.checks),
        (r.requirement_id for r in requirements.items),
    )
    checks = {check.requirement_id: check for check in environment.checks}
    required = [
        checks[item.requirement_id] for item in requirements.items if item.required
    ]
    expected = (
        "ERROR"
        if any(c.status == "ERROR" for c in required)
        else "MISMATCH"
        if any(c.status != "MATCH" for c in required)
        else "READY"
    )
    if environment.status != expected:
        raise ValueError("ENVIRONMENT_STATUS_MISMATCH")
    for item in requirements.items:
        check = checks[item.requirement_id]
        if (
            item.kind == "VERSION"
            and check.status == "MATCH"
            and check.actual is not None
        ):
            if check.actual not in (item.expected, *item.alternatives):
                raise ValueError("ENVIRONMENT_VERSION_MISMATCH")
            if check.actual != item.expected and not check.difference:
                raise ValueError("ENVIRONMENT_DIFFERENCE_REQUIRED")


def validate_dynamic_closure(
    result: DynamicReproductionResult,
    request: DynamicReproductionRequest,
    log: AgentLog,
    *,
    generation: int,
    plan: ReproductionPlan | None = None,
    recipe: EnvironmentRecipe | None = None,
    environment: SandboxEnvironment | None = None,
    candidate: PoCCandidate | None = None,
    poc: PoCBundle | None = None,
    conclusion: DynamicReproductionConclusion | None = None,
    policy: SandboxPolicyDecision | None = None,
    cleanup: CleanupResult | None = None,
) -> None:
    exact(result.request_ref, request, result.meta)
    same_scope(result.meta, request.meta)  # R6 producer attempt differs from R7.
    if (
        request.verification_generation != generation
        or result.purpose != request.purpose
    ):
        raise ValueError("STALE_RESULT")
    pairs = (
        (result.agent_log_ref, log),
        (result.reproduction_plan_ref, plan),
        (result.environment_recipe_ref, recipe),
        (result.environment_ref, environment),
        (result.poc_candidate_ref, candidate),
        (result.poc_ref, poc),
        (result.agent_conclusion_ref, conclusion),
        (result.policy_decision_ref, policy),
        (result.cleanup_ref, cleanup),
    )
    for ref, target in pairs:
        if (ref is None) != (target is None):
            raise ValueError("DYNAMIC_CLOSURE_MISSING")
        if ref is not None and target is not None:
            exact(ref, target, result.meta)
            same_scope(result.meta, target.meta, attempt=True)
            if target.request_ref != result.request_ref:
                raise ValueError("DYNAMIC_REQUEST_MISMATCH")
    if result.agent_invoked != any(
        event.event_type == "AGENT_STARTED" for event in log.events
    ):
        raise ValueError("AGENT_LOG_INVOCATION_MISMATCH")
    if plan is not None and (
        plan.purpose,
        plan.hypothesis_ref,
        plan.sandbox_profile_ref,
    ) != (request.purpose, request.hypothesis_ref, request.sandbox_profile_ref):
        raise ValueError("DYNAMIC_PLAN_REQUEST_MISMATCH")
    if policy is not None:
        if (result.agent_invoked and policy.decision != "ALLOW") or (
            result.failure_category == "POLICY_BLOCKED" and policy.decision != "DENY"
        ):
            raise ValueError("SANDBOX_POLICY_DECISION_MISMATCH")
        if not any(
            event.event_type in {"SESSION_STARTED", "POLICY_BLOCKED"}
            and result.policy_decision_ref in event.input_refs
            for event in log.events
        ):
            raise ValueError("SANDBOX_POLICY_LOG_MISMATCH")
    if conclusion is not None:
        if (
            result.hypothesis_outcome,
            result.hypothesis_linkage,
            result.limitations,
        ) != (
            conclusion.proposed_outcome,
            conclusion.hypothesis_linkage,
            conclusion.limitations,
        ):
            raise ValueError("DYNAMIC_CONCLUSION_DRIFT")
        exact_set(result.hypothesis_evidence_refs, conclusion.hypothesis_evidence_refs)
        exact_set(result.observation_refs, conclusion.observation_refs)
    if candidate is not None and not any(
        event.poc_candidate_ref == result.poc_candidate_ref
        and event.event_type in {"POC_CANDIDATE_CREATED", "POC_EXECUTION_STARTED"}
        for event in log.events
    ):
        raise ValueError("CANDIDATE_LOG_REQUIRED")
    if poc is not None:
        if candidate is None:
            raise ValueError("POC_CANDIDATE_REQUIRED")
        validate_poc_candidate(poc, candidate)
        for name in (
            "request_ref",
            "reproduction_plan_ref",
            "environment_recipe_ref",
            "environment_ref",
            "agent_log_ref",
        ):
            if getattr(poc, name) != getattr(result, name):
                raise ValueError("POC_PROVENANCE_MISMATCH")
        if (
            poc.candidate_ref != result.poc_candidate_ref
            or poc.candidate_digest != candidate.content_digest
        ):
            raise ValueError("POC_CANDIDATE_MISMATCH")
        executions = [
            event
            for event in log.events
            if event.event_type == "POC_EXECUTION_FINISHED"
            and event.action_id == poc.execution_action_id
            and event.poc_candidate_ref == poc.candidate_ref
            and event.exit_code == 0
        ]
        if len(executions) != 1 or not poc.evidence_refs:
            raise ValueError("POC_EXECUTION_REQUIRED")
    if cleanup is not None and cleanup.status != result.cleanup_status:
        raise ValueError("CLEANUP_STATUS_MISMATCH")
