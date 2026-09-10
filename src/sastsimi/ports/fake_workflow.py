"""Narrow callable ports used by the deterministic vertical-slice adapters."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.dynamic import (
    CleanupResult,
    DynamicReproductionRequest,
    DynamicReproductionResult,
    PoCBundle,
    SandboxCommandRecord,
    SandboxEnvironment,
)
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    HypothesisProposal,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.llm import (
    LLMInvocationRequest,
    LLMInvocationResult,
    ProviderValidationEvidence,
)
from sastsimi.contracts.policy import RunPolicyState
from sastsimi.contracts.refs import RecordRef, StoredDataRef
from sastsimi.contracts.static import StaticFactBundle, ToolRunResult
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import (
    ApprovedSandboxCommand,
    CapabilityProbeResult,
    OfficialPolicyFetchRequest,
    OfficialPolicySource,
    SandboxCleanupRequest,
    SandboxPrepareRequest,
    StaticToolRequest,
)

type ProviderInvoker = Callable[
    [LLMInvocationRequest, LLMInvocationResult], Awaitable[LLMInvocationResult]
]
type ProviderProber = Callable[
    [ProviderValidationEvidence], Awaitable[CapabilityProbeResult]
]
type StaticInvoker = Callable[
    [StaticToolRequest, ToolRunResult], Awaitable[ToolRunResult]
]
type SandboxPreparer = Callable[
    [SandboxPrepareRequest, SandboxEnvironment], Awaitable[SandboxEnvironment]
]
type SandboxExecutor = Callable[
    [ApprovedSandboxCommand, SandboxCommandRecord], Awaitable[SandboxCommandRecord]
]
type SandboxCleaner = Callable[
    [SandboxCleanupRequest, CleanupResult], Awaitable[CleanupResult]
]
type PolicyFetcher = Callable[
    [OfficialPolicyFetchRequest, OfficialPolicySource], Awaitable[OfficialPolicySource]
]


class NoMatchBuilder(Protocol):
    def __call__(
        self,
        *,
        meta: dict[str, Any],
        primitive_ref: StoredDataRef | None = None,
        primitive_refs: tuple[StoredDataRef, ...] = (),
    ) -> ChainingResult: ...


class PolicyPreparationPort(Protocol):
    def start(self, scope: StoredDataRef, orchestrator_ref: StoredDataRef) -> Any: ...

    def prepare(
        self,
        scope: StoredDataRef,
        orchestrator_ref: StoredDataRef,
        work: Any | None = None,
    ) -> RunPolicyState: ...


class ChainingOutcomePort(Protocol):
    @property
    def primitive_ref(self) -> StoredDataRef | None: ...

    @property
    def stopped(self) -> bool: ...


class ChainingWorkflowPort(Protocol):
    def run(
        self,
        *,
        verification: VerificationResult,
        scope: StoredDataRef,
        orchestrator_ref: StoredDataRef,
        generation: int,
        verification_ref: StoredDataRef,
        technical_ref: StoredDataRef,
        collection_ref: StoredDataRef,
        review_ref: StoredDataRef,
        label_ref: StoredDataRef,
        observation: StoredDataRef,
        admission_decision: Literal["ALLOW", "DENY"],
        publish_denied_primitive: bool,
        stop_after_chaining: bool,
    ) -> ChainingOutcomePort: ...


@dataclass(frozen=True)
class VerificationExecution:
    """Exact per-hypothesis verification output and its producing context."""

    result: VerificationResult
    work_ref: RecordRef
    hypothesis_ref: StoredDataRef
    process_ref: StoredDataRef
    generation: int


class DynamicReproductionWorkflow(Protocol):
    """Public typed seam owned by the reproduction package."""

    def run(
        self,
        *,
        scope: StoredDataRef,
        owner_ref: StoredDataRef,
        orchestrator_ref: StoredDataRef,
        verification_work: WorkExecutionState,
        assignment_ref: StoredDataRef,
        hypothesis_ref: StoredDataRef,
        evidence_ref: StoredDataRef,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        assessment_ref: StoredDataRef,
        policy_ref: StoredDataRef,
        playbook_ref: StoredDataRef,
        application_ref: StoredDataRef,
    ) -> tuple[DynamicReproductionRequest, DynamicReproductionResult, PoCBundle]: ...


@dataclass(frozen=True)
class InitialVerificationInputs:
    scope: StoredDataRef
    owner_ref: StoredDataRef
    orchestrator_ref: StoredDataRef
    proposal: HypothesisProposal
    hypothesis: VulnerabilityHypothesis
    process: HypothesisProcessState
    bundle: StaticFactBundle
    playbook_ref: StoredDataRef
    policy_ref: StoredDataRef
