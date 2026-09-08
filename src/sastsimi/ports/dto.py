"""Port-owned transport DTOs, not competing Task 5 domain schemas.

BoundaryRecord carries an exact reference to a later domain record. Adapters
resolve and validate the expected domain kind before I/O; no untyped payload
or provider/runtime implementation is introduced here.
"""

from dataclasses import dataclass
from typing import Protocol

from sastsimi.contracts.budget import BudgetLedgerEntry, BudgetReservation
from sastsimi.contracts.records import RecordMetadata
from sastsimi.contracts.refs import RecordRef
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


type ProviderProfile = BoundaryRecord
type CapabilityProbeResult = BoundaryRecord
type LLMInvocationRequest = BoundaryRecord
type LLMInvocationResult = BoundaryRecord
type OfficialPolicyFetchRequest = BoundaryRecord
type OfficialPolicySource = BoundaryRecord
type ToolCapabilityResult = BoundaryRecord
type StaticToolRequest = BoundaryRecord
type ToolRunResult = BoundaryRecord
type SandboxPrepareRequest = BoundaryRecord
type SandboxEnvironment = BoundaryRecord
type ApprovedSandboxCommand = BoundaryRecord
type SandboxCommandRecord = BoundaryRecord
type SandboxCleanupRequest = BoundaryRecord
type CleanupResult = BoundaryRecord
