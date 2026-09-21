"""Shared deterministic Verification workflow for initial and REVISE generations."""

from __future__ import annotations

from sastsimi.agents.verification import (
    VerificationAgent,
    VerificationAgentOutcome,
    VerificationCallRefs,
)
from sastsimi.contracts.dynamic import DynamicReproductionRequest
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.verification import (
    VerificationInitialAssessment,
    VerificationResult,
)
from sastsimi.ports.verification_assembly import (
    VerificationGenerationInputs,
)


def select_revise_context(
    hypotheses: tuple[VulnerabilityHypothesis, ...],
    processes: tuple[HypothesisProcessState, ...],
    hypothesis_id: object,
) -> tuple[VulnerabilityHypothesis, HypothesisProcessState]:
    """Resolve one hypothesis's exact current state without shared-host context."""
    matching_hypotheses = tuple(
        item for item in hypotheses if item.meta.hypothesis_id == hypothesis_id
    )
    matching_processes = tuple(
        item for item in processes if item.meta.hypothesis_id == hypothesis_id
    )
    if len(matching_hypotheses) != 1 or len(matching_processes) != 1:
        raise LookupError("EXACT_REVISED_VERIFICATION_CONTEXT_NOT_FOUND")
    return matching_hypotheses[0], matching_processes[0]


class VerificationService:
    """Own context, debate, assessment, optional dynamic and final verdict."""

    def __init__(self, agent: VerificationAgent) -> None:
        self._trusted_agent = agent

    async def assess_initial(
        self,
        *,
        generation: VerificationGenerationInputs,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationInitialAssessment:
        """Finalize one successful T09 assessment artifact using trusted scope."""
        if self._trusted_agent is None:
            raise RuntimeError("TRUSTED_VERIFICATION_AGENT_NOT_CONFIGURED")
        return await self._trusted_agent.assess_initial(
            generation=generation,
            pro_ref=pro_ref,
            con_ref=con_ref,
            call=call,
        )

    async def assess_initial_with_invocation(
        self,
        *,
        generation: VerificationGenerationInputs,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationAgentOutcome[VerificationInitialAssessment]:
        """Expose exact invocation provenance for trusted intermediate publication."""
        if self._trusted_agent is None:
            raise RuntimeError("TRUSTED_VERIFICATION_AGENT_NOT_CONFIGURED")
        return await self._trusted_agent.assess_initial_with_invocation(
            generation=generation,
            pro_ref=pro_ref,
            con_ref=con_ref,
            call=call,
        )

    async def create_dynamic_request_with_invocation(
        self,
        *,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
        verification_assignment_ref: StoredDataRef,
        sandbox_profile_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationAgentOutcome[DynamicReproductionRequest]:
        """Return the exact CREATE_DYNAMIC_REQUEST invocation and trusted request."""
        if self._trusted_agent is None:
            raise RuntimeError("TRUSTED_VERIFICATION_AGENT_NOT_CONFIGURED")
        return await self._trusted_agent.create_dynamic_request_with_invocation(
            generation=generation,
            assessment_ref=assessment_ref,
            verification_assignment_ref=verification_assignment_ref,
            sandbox_profile_ref=sandbox_profile_ref,
            call=call,
        )

    async def finalize_without_dynamic(
        self,
        *,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationResult:
        """Finalize only FALSE/HOLD; T11 owns all final TRUE prerequisites."""
        if self._trusted_agent is None:
            raise RuntimeError("TRUSTED_VERIFICATION_AGENT_NOT_CONFIGURED")
        return await self._trusted_agent.finalize_without_dynamic(
            generation=generation,
            assessment_ref=assessment_ref,
            pro_ref=pro_ref,
            con_ref=con_ref,
            call=call,
        )

    async def finalize_without_dynamic_with_invocation(
        self,
        *,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationAgentOutcome[VerificationResult]:
        """Expose exact invocation provenance for trusted terminal publication."""
        if self._trusted_agent is None:
            raise RuntimeError("TRUSTED_VERIFICATION_AGENT_NOT_CONFIGURED")
        return await self._trusted_agent.finalize_without_dynamic_with_invocation(
            generation=generation,
            assessment_ref=assessment_ref,
            pro_ref=pro_ref,
            con_ref=con_ref,
            call=call,
        )

    async def finalize_with_dynamic(
        self,
        *,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
        dynamic_request_ref: StoredDataRef,
        dynamic_result_ref: StoredDataRef,
        poc_ref: StoredDataRef | None,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationResult:
        """Finalize an exact completed dynamic attempt; never convert R7 failures."""
        if self._trusted_agent is None:
            raise RuntimeError("TRUSTED_VERIFICATION_AGENT_NOT_CONFIGURED")
        return await self._trusted_agent.finalize_with_dynamic(
            generation=generation,
            assessment_ref=assessment_ref,
            dynamic_request_ref=dynamic_request_ref,
            dynamic_result_ref=dynamic_result_ref,
            poc_ref=poc_ref,
            pro_ref=pro_ref,
            con_ref=con_ref,
            call=call,
        )

    async def finalize_with_dynamic_with_invocation(
        self,
        *,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
        dynamic_request_ref: StoredDataRef,
        dynamic_result_ref: StoredDataRef,
        poc_ref: StoredDataRef | None,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationAgentOutcome[VerificationResult]:
        """Return the exact FINAL_VERDICT invocation with the trusted result."""
        if self._trusted_agent is None:
            raise RuntimeError("TRUSTED_VERIFICATION_AGENT_NOT_CONFIGURED")
        return await self._trusted_agent.finalize_with_dynamic_with_invocation(
            generation=generation,
            assessment_ref=assessment_ref,
            dynamic_request_ref=dynamic_request_ref,
            dynamic_result_ref=dynamic_result_ref,
            poc_ref=poc_ref,
            pro_ref=pro_ref,
            con_ref=con_ref,
            call=call,
        )
