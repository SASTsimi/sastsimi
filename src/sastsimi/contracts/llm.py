"""Architecture v5 §08 configuration and call provenance; no provider behavior."""

from typing import ClassVar, Literal, Self

from pydantic import AwareDatetime, model_validator

from ._domain import DomainRecord, unique
from .base import ContractModel, NonEmptyStr, NonNegativeInt, PositiveInt
from .evaluation import UsageMeasurement
from .refs import StoredDataRef, require_record_ref
from .static import CodeLocation

type Capability = Literal["SUPPORTED", "UNSUPPORTED", "UNVERIFIED"]
type LLMRole = Literal[
    "HYPOTHESIS",
    "VERIFICATION",
    "PRO",
    "CON",
    "CWE_LABELING",
    "CHAINING",
    "TECHNICAL_GATE",
    "RULE_SCOPE_GATE",
    "REPORTER",
    "POLICY_PARSER",
    "DYNAMIC_REPRODUCTION",
]
type InvocationStatus = Literal[
    "SUCCEEDED",
    "FAILED",
    "INVALID_OUTPUT",
    "TIMED_OUT",
    "RATE_LIMITED",
    "AUTH_REQUIRED",
    "CANCELLED",
]
type Purpose = Literal["EVALUATION", "PRODUCTION"]
type SessionPolicy = Literal["NEW", "RESUME", "AUTO"]
type Provider = Literal["OPENAI", "ANTHROPIC"]
type Product = Literal["OPENAI_API", "CODEX", "ANTHROPIC_API", "CLAUDE_CODE"]
type Transport = Literal[
    "RESPONSES_API",
    "CODEX_CLIENT",
    "MESSAGES_API",
    "CLAUDE_CODE_CLIENT",
]
type Environment = Literal[
    "PERSONAL_LOCAL", "TEAM_LOCAL", "PRIVATE_CI", "SHARED_SERVER"
]
type AuthMode = Literal["API_KEY", "SUBSCRIPTION_LOGIN"]
type TrustClass = Literal["TRUSTED_INSTRUCTION", "UNTRUSTED_DATA"]


class LLMRecord(DomainRecord):
    ATTEMPT: ClassVar[bool | None] = None


class ProviderCapabilities(ContractModel):
    non_interactive: Capability
    structured_output: Capability
    new_session: Capability
    resume_session: Capability
    parallel_calls: Capability
    cancellation: Capability
    timeout_detection: Capability
    auth_expiry_detection: Capability
    rate_limit_detection: Capability
    request_id: Capability
    token_usage: Capability
    session_metadata: Capability
    runtime_tool_loop: Capability


class ProviderValidationTest(ContractModel):
    test_id: Literal[
        "PVD-01",
        "PVD-02",
        "PVD-03",
        "PVD-04",
        "PVD-05",
        "PVD-06",
        "PVD-07",
        "PVD-08",
        "PVD-09",
        "PVD-10",
        "PVD-11",
        "PVD-12",
        "PVD-13",
        "PVD-14",
        "PVD-15",
        "PVD-16",
    ]
    result: Literal["PASS", "FAIL", "NOT_APPLICABLE"]
    evidence_refs: tuple[StoredDataRef, ...]
    safe_summary: NonEmptyStr


class ProviderIdentity(LLMRecord):
    HYPOTHESIS = False
    ATTEMPT = False
    profile_key: NonEmptyStr
    provider: Provider
    product: Product
    transport: Transport
    model: NonEmptyStr
    environment: Environment
    auth_mode: AuthMode
    client_name: NonEmptyStr
    client_version: NonEmptyStr


class ProviderValidationEvidence(ProviderIdentity):
    KIND = "provider_validation_evidence"
    tests: tuple[ProviderValidationTest, ...]
    checked_at: AwareDatetime
    checked_by: NonEmptyStr


class ClientExecutionProfile(LLMRecord):
    KIND = "client_execution_profile"
    HYPOTHESIS = False
    ATTEMPT = False
    execution_key: NonEmptyStr
    working_directory_mode: Literal["ISOLATED_EMPTY"]
    filesystem_mode: Literal["NO_REPOSITORY_ACCESS"]
    tool_mode: Literal["DISABLED"]
    mcp_mode: Literal["DISABLED"]
    hooks_mode: Literal["DISABLED"]
    plugin_mode: Literal["DISABLED"]
    instruction_sources: Literal["EXPLICIT_SASTSIMI_PAYLOAD_ONLY"]
    environment_variable_allowlist: tuple[NonEmptyStr, ...]
    network_policy_ref: StoredDataRef
    provider_fallback: Literal["DISABLED"]
    verification_evidence_ref: StoredDataRef


class ProviderProfile(ProviderIdentity):
    KIND = "provider_profile"
    credential_source: Literal["ENVIRONMENT", "SECRET_STORE", "OFFICIAL_CLIENT_SESSION"]
    capabilities: ProviderCapabilities
    support_status: Literal["SUPPORTED", "EXPERIMENTAL", "REJECTED"]
    validation_evidence_ref: StoredDataRef
    client_execution_profile_ref: StoredDataRef | None
    limitations: tuple[NonEmptyStr, ...]
    checked_at: AwareDatetime
    evidence_urls: tuple[NonEmptyStr, ...]

    @model_validator(mode="after")
    def provider_shape(self) -> Self:
        expected = {
            "OPENAI_API": ("OPENAI", "RESPONSES_API", "API_KEY"),
            "ANTHROPIC_API": ("ANTHROPIC", "MESSAGES_API", "API_KEY"),
            "CODEX": ("OPENAI", "CODEX_CLIENT", "SUBSCRIPTION_LOGIN"),
            "CLAUDE_CODE": ("ANTHROPIC", "CLAUDE_CODE_CLIENT", "SUBSCRIPTION_LOGIN"),
        }[self.product]
        if (self.provider, self.transport, self.auth_mode) != expected:
            raise ValueError("PROVIDER_PROFILE_IDENTITY_MISMATCH")
        subscription = self.auth_mode == "SUBSCRIPTION_LOGIN"
        if subscription != (self.client_execution_profile_ref is not None) or (
            subscription != (self.credential_source == "OFFICIAL_CLIENT_SESSION")
        ):
            raise ValueError("PROVIDER_PROFILE_EXECUTION_MISMATCH")
        try:
            require_record_ref(
                self.validation_evidence_ref, "provider_validation_evidence"
            )
            if self.client_execution_profile_ref is not None:
                require_record_ref(
                    self.client_execution_profile_ref, "client_execution_profile"
                )
        except ValueError as error:
            raise ValueError("PROVIDER_PROFILE_EXACT_EVIDENCE_REQUIRED") from error
        return self


class ExecutionLimits(LLMRecord):
    KIND = "execution_limits"
    limits_key: NonEmptyStr
    token_budget: NonNegativeInt | None
    timeout_ms: PositiveInt
    max_parallel_calls: NonNegativeInt
    max_calls_per_work: NonNegativeInt


class LLMRetryPolicy(LLMRecord):
    KIND = "llm_retry_policy"
    policy_key: NonEmptyStr
    max_schema_repairs: NonNegativeInt
    max_semantic_repairs: NonNegativeInt
    max_retries: NonNegativeInt
    max_failovers: NonNegativeInt
    retryable_statuses: tuple[
        Literal[
            "FAILED",
            "INVALID_OUTPUT",
            "TIMED_OUT",
            "RATE_LIMITED",
            "AUTH_REQUIRED",
        ],
        ...,
    ]
    backoff_policy_ref: StoredDataRef | None


class LLMToolPolicy(LLMRecord):
    KIND = "llm_tool_policy"
    policy_key: NonEmptyStr
    allowed_tools: tuple[NonEmptyStr, ...]
    forbidden_actions: tuple[NonEmptyStr, ...]
    sandbox_only: bool


class PromptRedactionPolicy(LLMRecord):
    KIND = "prompt_redaction_policy"
    policy_key: NonEmptyStr
    remove_categories: tuple[
        Literal[
            "CREDENTIAL",
            "COOKIE",
            "TOKEN",
            "BROWSER_PROFILE",
            "HOST_ABSOLUTE_PATH",
            "HIDDEN_REASONING",
        ],
        ...,
    ]
    fail_closed: Literal[True]


class OutputSchemaSpec(LLMRecord):
    KIND = "output_schema_spec"
    schema_key: NonEmptyStr
    schema_artifact_ref: StoredDataRef
    result_kind: NonEmptyStr


class SemanticValidatorSpec(LLMRecord):
    KIND = "semantic_validator_spec"
    validator_key: NonEmptyStr
    implementation_ref: StoredDataRef
    test_refs: tuple[StoredDataRef, ...]


class PromptInputSlot(ContractModel):
    slot: NonEmptyStr
    data_kind: NonEmptyStr
    field_paths: tuple[NonEmptyStr, ...]
    cardinality: Literal[
        "REQUIRED_ONE", "OPTIONAL_ONE", "REQUIRED_MANY", "OPTIONAL_MANY"
    ]
    trust_class: TrustClass


class PromptRegistryEntry(LLMRecord):
    KIND = "prompt_registry_entry"
    prompt_key: NonEmptyStr
    agent_role: LLMRole
    task_kind: NonEmptyStr
    purpose: Purpose
    template_ref: StoredDataRef
    template_version: NonEmptyStr
    input_slots: tuple[PromptInputSlot, ...]
    forbidden_context_kinds: tuple[NonEmptyStr, ...]
    output_schema_ref: StoredDataRef
    session_policy: SessionPolicy
    provider_profile_refs: tuple[StoredDataRef, ...]
    execution_limits_ref: StoredDataRef
    retry_policy_ref: StoredDataRef
    semantic_validator_ref: StoredDataRef
    tool_policy_ref: StoredDataRef
    redaction_policy_ref: StoredDataRef
    result_kind: NonEmptyStr
    status: Literal["DRAFT", "ACTIVE", "RETIRED"]
    quality_evaluation_ref: StoredDataRef | None
    owner_role: NonEmptyStr
    reviewer_roles: tuple[NonEmptyStr, ...]

    @model_validator(mode="after")
    def registry_shape(self) -> Self:
        unique(slot.slot for slot in self.input_slots)
        unique(self.provider_profile_refs)
        if not self.provider_profile_refs or any(
            slot.data_kind in self.forbidden_context_kinds for slot in self.input_slots
        ):
            raise ValueError("PROMPT_CONTEXT_DENIED")
        if self.purpose == "PRODUCTION" and self.status == "ACTIVE":
            if self.quality_evaluation_ref is None:
                raise ValueError("QUALITY_EVIDENCE_REQUIRED")
            require_record_ref(self.quality_evaluation_ref, "evaluation_recommendation")
        return self


class PromptContextBinding(ContractModel):
    slot: NonEmptyStr
    data_kind: NonEmptyStr
    source_ref: StoredDataRef
    projected_data_ref: StoredDataRef
    field_paths: tuple[NonEmptyStr, ...]
    trust_class: TrustClass


class PromptPayload(LLMRecord):
    KIND = "prompt_payload"
    registry_entry_ref: StoredDataRef
    prompt_key: NonEmptyStr
    agent_role: LLMRole
    task_kind: NonEmptyStr
    purpose: Purpose
    template_ref: StoredDataRef
    template_version: NonEmptyStr
    context_bindings: tuple[PromptContextBinding, ...]
    rendered_prompt_ref: StoredDataRef
    output_schema_ref: StoredDataRef


class LLMCallSpec(LLMRecord):
    KIND = "llm_call_spec"
    llm_call_id: NonEmptyStr
    agent_role: LLMRole
    task_kind: NonEmptyStr
    purpose: Purpose
    provider_profile_ref: StoredDataRef
    model: NonEmptyStr
    session_policy: SessionPolicy
    parent_session_ref: NonEmptyStr | None
    context_refs: tuple[StoredDataRef, ...]
    prompt_registry_entry_ref: StoredDataRef
    prompt_key: NonEmptyStr
    prompt_template_ref: StoredDataRef
    prompt_template_version: NonEmptyStr
    prompt_payload_ref: StoredDataRef
    execution_limits_ref: StoredDataRef
    retry_policy_ref: StoredDataRef
    tool_policy_ref: StoredDataRef
    redaction_policy_ref: StoredDataRef
    semantic_validator_ref: StoredDataRef
    output_schema_ref: StoredDataRef
    output_schema: NonEmptyStr
    token_budget: NonNegativeInt | None
    timeout_ms: PositiveInt

    @model_validator(mode="after")
    def session_shape(self) -> Self:
        if self.agent_role in {"PRO", "CON"} and (
            self.session_policy != "NEW" or self.parent_session_ref is not None
        ):
            raise ValueError("EVIDENCE_NEW_SESSION_REQUIRED")
        if (self.session_policy == "NEW" and self.parent_session_ref is not None) or (
            self.session_policy == "RESUME" and self.parent_session_ref is None
        ):
            raise ValueError("LLM_SESSION_REFERENCE_MISMATCH")
        return self


class LLMInvocationRequest(LLMRecord):
    KIND = "llm_invocation_request"
    llm_call_id: NonEmptyStr
    action_decision_ref: StoredDataRef
    call_spec_ref: StoredDataRef
    agent_role: LLMRole
    task_kind: NonEmptyStr
    purpose: Purpose
    provider_profile_ref: StoredDataRef
    model: NonEmptyStr
    session_policy: SessionPolicy
    parent_session_ref: NonEmptyStr | None
    context_refs: tuple[StoredDataRef, ...]
    prompt_registry_entry_ref: StoredDataRef
    prompt_key: NonEmptyStr
    prompt_template_ref: StoredDataRef
    prompt_template_version: NonEmptyStr
    prompt_payload_ref: StoredDataRef
    execution_limits_ref: StoredDataRef
    retry_policy_ref: StoredDataRef
    tool_policy_ref: StoredDataRef
    redaction_policy_ref: StoredDataRef
    semantic_validator_ref: StoredDataRef
    output_schema_ref: StoredDataRef
    output_schema: NonEmptyStr
    token_budget: NonNegativeInt | None
    timeout_ms: PositiveInt


class LLMInvocationResult(LLMRecord):
    KIND = "llm_invocation_result"
    llm_call_id: NonEmptyStr
    purpose: Purpose
    status: InvocationStatus
    provider: NonEmptyStr
    model: NonEmptyStr
    actual_session_mode: Literal["NEW", "RESUMED"]
    session_ref: NonEmptyStr | None
    response_ref: StoredDataRef | None
    parsed_output_ref: StoredDataRef | None
    usage: UsageMeasurement | None
    started_at: AwareDatetime
    finished_at: AwareDatetime
    elapsed_ms: NonNegativeInt
    safe_error: NonEmptyStr | None

    @model_validator(mode="after")
    def result_shape(self) -> Self:
        if self.finished_at < self.started_at or (
            self.status == "SUCCEEDED"
            and (self.parsed_output_ref is None or self.safe_error is not None)
        ):
            raise ValueError("INVOCATION_RESULT_MISMATCH")
        return self


class LLMInvocationLog(LLMRecord):
    KIND = "llm_invocation_log"
    llm_call_id: NonEmptyStr
    action_decision_ref: StoredDataRef
    call_spec_ref: StoredDataRef
    agent_role: LLMRole
    task_kind: NonEmptyStr
    purpose: Purpose
    provider_profile_ref: StoredDataRef
    provider: NonEmptyStr
    model: NonEmptyStr
    session_policy: SessionPolicy
    session_ref: NonEmptyStr | None
    parent_session_ref: NonEmptyStr | None
    prompt_registry_entry_ref: StoredDataRef
    prompt_key: NonEmptyStr
    prompt_template_ref: StoredDataRef
    prompt_template_version: NonEmptyStr
    prompt_payload_ref: StoredDataRef
    execution_limits_ref: StoredDataRef
    retry_policy_ref: StoredDataRef
    tool_policy_ref: StoredDataRef
    redaction_policy_ref: StoredDataRef
    semantic_validator_ref: StoredDataRef
    output_schema_ref: StoredDataRef
    context_refs: tuple[StoredDataRef, ...]
    retrieved_code_locations: tuple[CodeLocation, ...]
    exposed_request_ref: StoredDataRef
    exposed_response_ref: StoredDataRef | None
    parsed_output_ref: StoredDataRef | None
    tool_calls: tuple[StoredDataRef, ...]
    usage: UsageMeasurement | None
    started_at: AwareDatetime
    finished_at: AwareDatetime
    elapsed_ms: NonNegativeInt
    retry_count: NonNegativeInt
    status: InvocationStatus
    safe_error: NonEmptyStr | None
    validation_errors: tuple[NonEmptyStr, ...]
    repair_attempts: NonNegativeInt
    retry_of_llm_call_id: NonEmptyStr | None
    failover_from_llm_call_id: NonEmptyStr | None
    redaction_result: Literal["APPLIED", "NOT_REQUIRED", "FAILED"]

    @model_validator(mode="after")
    def log_shape(self) -> Self:
        if (
            self.finished_at < self.started_at
            or (
                self.retry_of_llm_call_id is not None
                and self.failover_from_llm_call_id is not None
            )
            or (
                self.status == "SUCCEEDED"
                and (self.parsed_output_ref is None or self.safe_error is not None)
            )
        ):
            raise ValueError("INVOCATION_LOG_MISMATCH")
        return self
