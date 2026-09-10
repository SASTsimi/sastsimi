"""Port-owned transport DTOs, not competing Task 5 domain schemas.

BoundaryRecord carries an exact reference to a later domain record. Adapters
resolve and validate the expected domain kind before I/O; no untyped payload
or provider/runtime implementation is introduced here.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.budget import BudgetLedgerEntry, BudgetReservation
from sastsimi.contracts.dynamic import CleanupResult as CleanupResult
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    DynamicReproductionToolRequest,
    EnvironmentRequirements,
    ReproductionPlan,
    SandboxPolicyDecision,
)
from sastsimi.contracts.dynamic import SandboxCommandRecord as SandboxCommandRecord
from sastsimi.contracts.dynamic import SandboxEnvironment as SandboxEnvironment
from sastsimi.contracts.ids import ProgramId
from sastsimi.contracts.llm import (
    LLMInvocationRequest as LLMInvocationRequest,
)
from sastsimi.contracts.llm import LLMInvocationResult as LLMInvocationResult
from sastsimi.contracts.llm import ProviderProfile as ProviderProfile
from sastsimi.contracts.llm import ProviderValidationEvidence
from sastsimi.contracts.policy import PolicySourceCheck
from sastsimi.contracts.records import RecordMetadata
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
)
from sastsimi.contracts.static import CodeWorkspace, RuleExecutionRecord
from sastsimi.contracts.static import ToolRunResult as ToolRunResult
from sastsimi.contracts.work import (
    StateTransition,
    TransitionCommit,
    WorkAttempt,
    WorkExecutionState,
)


class Record(Protocol):
    @property
    def meta(self) -> RecordMetadata: ...


@dataclass(frozen=True)
class BoundaryRecord:
    ref: RecordRef


@dataclass(frozen=True)
class CancellationResult:
    cancelled: bool
    reason: str | None


class AttemptOutputBudgetPort(Protocol):
    """Attempt-owned aggregate allocation across process invocations/streams."""

    attempt_id: str
    limit_bytes: int

    def grow(self, key: tuple[str, str], desired_bytes: int) -> int: ...

    @property
    def used_bytes(self) -> int: ...


@dataclass(frozen=True)
class StagedArtifact:
    data: bytes
    media_type: str


@dataclass(frozen=True)
class TransitionCommitRequest:
    transition: StateTransition
    commit: TransitionCommit
    records: tuple[Record, ...]


@dataclass(frozen=True)
class WorkContext:
    work: WorkExecutionState
    attempt: WorkAttempt


@dataclass(frozen=True)
class WorkHandlerResult:
    output_refs: tuple[RecordRef, ...]


@dataclass(frozen=True)
class BudgetReservationRequest:
    reservation: BudgetReservation


@dataclass(frozen=True)
class BudgetCommitRequest:
    entry: BudgetLedgerEntry


@dataclass(frozen=True)
class BudgetReleaseRequest:
    reservation: BudgetReservation


@dataclass(frozen=True)
class CapabilityProbeResult:
    """Narrow, non-persisted provider-boundary probe result."""

    evidence: ProviderValidationEvidence


@dataclass(frozen=True)
class CanonicalRepositorySource:
    url: str
    host: str
    repository_path: str


@dataclass(frozen=True)
class MonotonicActionDeadline:
    action_id: str
    started_ns: int
    expires_ns: int

    def remaining_ms(self, now_ns: int) -> int:
        return max(0, (self.expires_ns - now_ns) // 1_000_000)


@dataclass(frozen=True)
class ProcessSpec:
    invocation_id: str
    attempt_id: str
    argv: tuple[str, ...]
    cwd: Path
    env: tuple[tuple[str, str], ...]
    attempt_output_dir: Path
    stdout_limit_bytes: int
    stderr_limit_bytes: int
    attempt_output_limit_bytes: int
    deadline: MonotonicActionDeadline


@dataclass(frozen=True)
class ProcessReceipt:
    invocation_id: str
    attempt_id: str
    command_fingerprint: str
    outcome: Literal["SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED"]
    return_code: int | None
    stdout_name: str
    stdout_size: int
    stdout_sha256: str
    stderr_name: str
    stderr_size: int
    stderr_sha256: str
    elapsed_ms: int


@dataclass(frozen=True)
class StaticActionReceipt:
    action_id: str
    attempt_id: str
    operation_kind: Literal["REPOSITORY_PREPARE", "STATIC_TOOL", "CONTEXT_READ"]
    input_fingerprint: str
    process_receipt_hashes: tuple[str, ...]
    observation_name: str
    observation_size: int
    observation_sha256: str
    elapsed_ms: int
    lease_id: str | None = None


@dataclass(frozen=True)
class ProcessResult:
    outcome: Literal["SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED"]
    return_code: int | None
    stdout: bytes
    stderr_tail: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    elapsed_ms: int
    receipt: ProcessReceipt
    receipt_path: Path


@dataclass(frozen=True)
class StaticCapabilityObservation:
    available: bool
    tool_name: str
    tool_kind: Literal["STRUCTURE", "RULE_BASED"]
    executable_key: str
    observed_executable_sha256: str | None
    observed_version: str | None
    expected_version: str
    reason_code: str | None


@dataclass(frozen=True)
class ToolCapabilityResult:
    ref: StoredDataRef
    available: bool
    tool_name: str
    tool_kind: Literal["STRUCTURE", "RULE_BASED"]
    executable_key: str
    observed_executable_sha256: str | None
    observed_version: str | None
    expected_version: str
    reason_code: str | None


@dataclass(frozen=True)
class CandidateLocation:
    file_path: str
    start_line: int
    start_column: int | None
    end_line: int
    end_column: int | None


@dataclass(frozen=True)
class CandidateSymbol:
    source_key: str
    symbol_kind: str
    native_kind: str | None
    name: str
    location: CandidateLocation


@dataclass(frozen=True)
class CandidateFact:
    source_key: str
    fact_kind: str
    symbol_source_key: str | None
    location: CandidateLocation
    rule_id: str | None


@dataclass(frozen=True)
class CandidateRelation:
    source_key: str
    relation_kind: str
    from_symbol_source_key: str | None
    from_location: CandidateLocation
    to_symbol_source_key: str | None
    to_location: CandidateLocation
    rule_id: str | None


@dataclass(frozen=True)
class CandidateGap:
    stage: str
    code: str
    reason: str
    description: str
    affected_paths: tuple[str, ...]
    affected_languages: tuple[str, ...]
    affected_locations: tuple[CandidateLocation, ...]
    retryable: bool


@dataclass(frozen=True)
class CandidateError:
    stage: str
    code: str
    safe_message: str
    retryable: bool


@dataclass(frozen=True)
class CandidateRule:
    rule_id: str
    selection_status: str
    execution_status: str
    hit_count: int | None
    reason: str | None
    detail: str | None


@dataclass(frozen=True)
class StaticRuleMapping:
    rule_id: str
    result_fact_kind: str
    flow_start_fact_kind: str | None
    requires_code_flow: bool


@dataclass(frozen=True)
class TrackedFile:
    git_path: str
    git_mode: str
    blob_id: str
    size_bytes: int


@dataclass(frozen=True)
class RepositoryPreparation:
    analysis_id: str
    workspace_id: str
    repository_url: str
    requested_ref: str
    status: Literal["READY", "FAILED"]
    resolved_commit_id: str | None
    root: Path | None
    tracked_files: tuple[TrackedFile, ...]
    gaps: tuple[CandidateGap, ...]
    errors: tuple[CandidateError, ...]
    lease_id: str | None = None


@dataclass(frozen=True)
class StaticToolObservation:
    tool_name: str
    tool_version: str
    tool_kind: Literal["STRUCTURE", "RULE_BASED"]
    status: Literal["SUCCEEDED", "PARTIAL", "FAILED", "SKIPPED"]
    raw_output: bytes | None
    raw_media_type: str | None
    analyzed_paths: tuple[str, ...]
    skipped_paths: tuple[str, ...]
    analyzed_languages: tuple[str, ...]
    skipped_languages: tuple[str, ...]
    notes: tuple[str, ...]
    selected_rule_packs: tuple[str, ...]
    rules: tuple[CandidateRule, ...]
    symbols: tuple[CandidateSymbol, ...]
    facts: tuple[CandidateFact, ...]
    relations: tuple[CandidateRelation, ...]
    gaps: tuple[CandidateGap, ...]
    errors: tuple[CandidateError, ...]
    started_monotonic_ms: int
    finished_monotonic_ms: int


@dataclass(frozen=True)
class PublishedStaticToolMaterial:
    result: ToolRunResult
    result_ref: StoredDataRef
    rule_execution: RuleExecutionRecord | None
    rule_execution_ref: StoredDataRef | None
    observation: StaticToolObservation


@dataclass(frozen=True)
class PublishedWorkspaceMaterial:
    workspace: CodeWorkspace
    workspace_ref: RunStoredDataRef
    work: WorkExecutionState
    analysis_state: AnalysisRunState


@dataclass(frozen=True)
class PrebuiltCodeQLDatabase:
    workspace_id: str
    commit_id: str
    language: str
    database_root: Path
    database_digest: str


@dataclass(frozen=True)
class WorkspaceStoragePolicy:
    schema_version: Literal["1.0"]
    max_git_bytes: int
    max_checkout_bytes: int
    max_file_count: int
    min_free_bytes: int


@dataclass(frozen=True)
class WorkspaceStorageLease:
    lease_id: str
    attempt_id: str
    workspace_id: str
    root: Path
    backend_key: str
    policy_ref: RunStoredDataRef
    enforcement_evidence: str


@dataclass(frozen=True)
class WorkspaceStorageUsage:
    git_bytes: int
    checkout_bytes: int
    file_count: int
    free_bytes: int


@dataclass(frozen=True)
class StaticToolRequest:
    action: ActionRequest
    workspace: CodeWorkspace
    tool_profile_ref: StoredDataRef
    analysis_config_ref: StoredDataRef
    rule_catalog_ref: StoredDataRef | None


@dataclass(frozen=True)
class OfficialPolicyFetchRequest:
    action: ActionRequest
    program_id: ProgramId
    source_config_ref: BudgetScopeRef


@dataclass(frozen=True)
class OfficialPolicySource:
    source_check: PolicySourceCheck
    content: bytes


@dataclass(frozen=True)
class SandboxPrepareRequest:
    request: DynamicReproductionRequest
    requirements: EnvironmentRequirements
    plan: ReproductionPlan
    boundary_decision: SandboxPolicyDecision


@dataclass(frozen=True)
class ApprovedSandboxCommand:
    tool_request: DynamicReproductionToolRequest
    boundary_decision: SandboxPolicyDecision


@dataclass(frozen=True)
class SandboxCleanupRequest:
    request: DynamicReproductionRequest
    environments: tuple[SandboxEnvironment, ...]
    resource_refs: tuple[StoredDataRef, ...]
