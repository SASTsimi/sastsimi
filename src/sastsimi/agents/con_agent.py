"""Trusted finalization for content-only Con Agent output."""

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.verification import ConEvidenceResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.runtime.llm_call_service import (
    InvocationMetadataFactory,
    PersistedLLMInvocation,
)

from .pro import ClaimIdFactory, _EvidenceAgentFinalizer


class ConAgent:
    """Finalize Con output without trusting provider-owned metadata or IDs."""

    def __init__(
        self,
        *,
        artifacts: ArtifactStore,
        metadata_factory: InvocationMetadataFactory,
        claim_id_factory: ClaimIdFactory,
    ) -> None:
        self._finalizer = _EvidenceAgentFinalizer(
            role="CON",
            artifacts=artifacts,
            metadata_factory=metadata_factory,
            claim_id_factory=claim_id_factory,
        )

    def finalize(
        self,
        invocation: PersistedLLMInvocation,
        *,
        parent_work: WorkExecutionState,
        evidence_work: WorkExecutionState,
        debate_input_hash: str,
        allowed_evidence_refs: tuple[StoredDataRef, ...],
    ) -> ConEvidenceResult:
        return ConEvidenceResult.model_validate(
            self._finalizer.content(
                invocation,
                parent_work=parent_work,
                evidence_work=evidence_work,
                debate_input_hash=debate_input_hash,
                allowed_evidence_refs=allowed_evidence_refs,
            )
        )


__all__ = ["ConAgent"]
