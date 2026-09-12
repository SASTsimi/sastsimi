"""Trusted finalization for content-only Pro Agent output."""

from __future__ import annotations

from collections.abc import Callable
from typing import BinaryIO, Literal, Protocol

from pydantic import model_validator

from sastsimi.contracts.base import ContractModel, NonEmptyStr
from sastsimi.contracts.llm import LLMInvocationRequest, LLMInvocationResult
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.static import CodeLocation
from sastsimi.contracts.verification import EvidenceClaim, ProEvidenceResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.llm_invocation import (
    InvocationMetadataFactory,
    PersistedLLMInvocation,
)

type ClaimIdFactory = Callable[[str], str]


class ArtifactReader(Protocol):
    """The evidence finalizer only needs verified reads, not store mutation."""

    def open_verified(self, ref: StoredDataRef) -> BinaryIO: ...


_EVIDENCE_TASK_BY_ROLE = {
    "PRO": "COLLECT_SUPPORT",
    "CON": "COLLECT_COUNTEREVIDENCE",
}


class _EvidenceClaimContent(ContractModel):
    statement: NonEmptyStr
    evidence_refs: tuple[StoredDataRef, ...]
    code_locations: tuple[CodeLocation, ...]
    limitations: tuple[NonEmptyStr, ...]

    @model_validator(mode="after")
    def has_evidence(self) -> _EvidenceClaimContent:
        if not self.evidence_refs:
            raise ValueError("EVIDENCE_REQUIRED")
        return self


class _EvidenceOutputContent(ContractModel):
    evidence: tuple[_EvidenceClaimContent, ...]
    summary: NonEmptyStr
    limitations: tuple[NonEmptyStr, ...]


class _EvidenceAgentFinalizer:
    """Convert untrusted JSON content into one runtime-owned evidence record."""

    def __init__(
        self,
        *,
        role: Literal["PRO", "CON"],
        artifacts: ArtifactReader,
        metadata_factory: InvocationMetadataFactory,
        claim_id_factory: ClaimIdFactory,
    ) -> None:
        self.role = role
        self.artifacts = artifacts
        self.metadata_factory = metadata_factory
        self.claim_id_factory = claim_id_factory

    def content(
        self,
        invocation: PersistedLLMInvocation,
        *,
        parent_work: WorkExecutionState,
        evidence_work: WorkExecutionState,
        debate_input_hash: str,
        allowed_evidence_refs: tuple[StoredDataRef, ...],
    ) -> dict[str, object]:
        if not isinstance(parent_work.meta, RecordMeta) or not isinstance(
            evidence_work.meta, RecordMeta
        ):
            raise ValueError("EVIDENCE_SCOPE_MISMATCH")
        request = LLMInvocationRequest.model_validate_json(
            invocation.request.model_dump_json()
        )
        result = LLMInvocationResult.model_validate_json(
            invocation.result.model_dump_json()
        )
        expected_scope = (
            evidence_work.meta.analysis_id,
            evidence_work.meta.workspace_id,
            evidence_work.meta.commit_id,
            evidence_work.meta.hypothesis_id,
            evidence_work.active_attempt_id,
        )
        request_scope = (
            request.meta.analysis_id,
            request.meta.workspace_id,
            request.meta.commit_id,
            request.meta.hypothesis_id,
            request.meta.attempt_id,
        )
        result_scope = (
            result.meta.analysis_id,
            result.meta.workspace_id,
            result.meta.commit_id,
            result.meta.hypothesis_id,
            result.meta.attempt_id,
        )
        if request_scope != expected_scope or result_scope != expected_scope:
            raise ValueError("EVIDENCE_SCOPE_MISMATCH")
        if (
            request.agent_role != self.role
            or request.task_kind != _EVIDENCE_TASK_BY_ROLE[self.role]
            or request.session_policy != "NEW"
            or request.parent_session_ref is not None
            or result.actual_session_mode != "NEW"
            or not result.session_ref
            or result.llm_call_id != request.llm_call_id
            or result.purpose != request.purpose
        ):
            raise ValueError("EVIDENCE_NEW_SESSION_REQUIRED")
        if result.status != "SUCCEEDED" or result.parsed_output_ref is None:
            raise ValueError("EVIDENCE_PROVIDER_RESULT_UNAVAILABLE")
        output_ref = result.parsed_output_ref
        if (
            result.response_ref != output_ref
            or output_ref.record_id is not None
            or output_ref.data_kind != "artifact"
            or str(output_ref.stored_data_id) != output_ref.content_hash
            or output_ref.workspace_id != evidence_work.meta.workspace_id
            or output_ref.commit_id != evidence_work.meta.commit_id
            or tuple(request.context_refs) != allowed_evidence_refs
        ):
            raise ValueError("EVIDENCE_OUTPUT_ARTIFACT_INVALID")
        try:
            with self.artifacts.open_verified(output_ref) as stream:
                output = _EvidenceOutputContent.model_validate_json(stream.read())
        except ValueError:
            raise
        except Exception as error:
            raise ValueError("EVIDENCE_OUTPUT_ARTIFACT_INVALID") from error
        allowed = set(allowed_evidence_refs)
        if any(
            ref not in allowed
            for claim in output.evidence
            for ref in claim.evidence_refs
        ):
            raise ValueError("CROSS_ROLE_INPUT_DENIED")
        meta = self.metadata_factory(
            evidence_work.meta,
            f"{self.role.lower()}_evidence_result",
            evidence_work.active_attempt_id,
        )
        if (
            meta.analysis_id != evidence_work.meta.analysis_id
            or meta.workspace_id != evidence_work.meta.workspace_id
            or meta.commit_id != evidence_work.meta.commit_id
            or meta.hypothesis_id != evidence_work.meta.hypothesis_id
            or meta.attempt_id != evidence_work.active_attempt_id
        ):
            raise ValueError("EVIDENCE_RUNTIME_METADATA_MISMATCH")
        claims = tuple(
            EvidenceClaim(
                claim_id=self.claim_id_factory(self.role),
                statement=claim.statement,
                source_role=self.role,
                evidence_refs=claim.evidence_refs,
                code_locations=claim.code_locations,
                limitations=claim.limitations,
            )
            for claim in output.evidence
        )
        return {
            "meta": meta,
            "role": self.role,
            "parent_work_id": parent_work.work_id,
            "evidence_work_id": evidence_work.work_id,
            "verification_generation": parent_work.work_generation,
            "llm_call_id": request.llm_call_id,
            "debate_input_hash": debate_input_hash,
            "evidence": claims,
            "summary": output.summary,
            "limitations": output.limitations,
        }


class ProAgent:
    """Finalize Pro output without trusting provider-owned metadata or IDs."""

    def __init__(
        self,
        *,
        artifacts: ArtifactReader,
        metadata_factory: InvocationMetadataFactory,
        claim_id_factory: ClaimIdFactory,
    ) -> None:
        self._finalizer = _EvidenceAgentFinalizer(
            role="PRO",
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
    ) -> ProEvidenceResult:
        return ProEvidenceResult.model_validate(
            self._finalizer.content(
                invocation,
                parent_work=parent_work,
                evidence_work=evidence_work,
                debate_input_hash=debate_input_hash,
                allowed_evidence_refs=allowed_evidence_refs,
            )
        )


__all__ = ["ArtifactReader", "ProAgent"]
