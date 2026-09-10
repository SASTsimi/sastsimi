"""Port-owned transport DTOs, not competing Task 5 domain schemas.

BoundaryRecord carries an exact reference to a later domain record. Adapters
resolve and validate the expected domain kind before I/O; no untyped payload
or provider/runtime implementation is introduced here.
"""

from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.actions import ActionRequest
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
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef
from sastsimi.contracts.static import CodeWorkspace
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


# Static tool capability probing belongs to the later static adapter implementation.
type ToolCapabilityResult = BoundaryRecord


@dataclass(frozen=True)
class StaticToolRequest:
    action: ActionRequest
    workspace: CodeWorkspace
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
