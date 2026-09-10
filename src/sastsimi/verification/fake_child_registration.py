"""Trusted registration of material proposals from committed fake source results."""

from sastsimi.contracts.hypothesis import HypothesisProposal
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner


def register_verification_children(
    *,
    runtime: RuntimeServices,
    runner: WorkflowRunner,
    scope: StoredDataRef,
    orchestration_identity: StoredDataRef,
    source: VerificationResult,
) -> tuple[StoredDataRef, ...]:
    """Copy exact nested children through a separate public work/commit boundary."""
    source_ref = reference(source)
    if not isinstance(source_ref, StoredDataRef):
        raise TypeError("VERIFICATION_CHILD_SOURCE_SCOPE_MISMATCH")
    registered: list[StoredDataRef] = []
    for proposal in source.material_child_proposals:
        if not isinstance(proposal, HypothesisProposal):
            raise TypeError("VERIFICATION_CHILD_PROPOSAL_REQUIRED")
        work = runner.start(
            scope,
            source.meta,
            "HYPOTHESIS_PROPOSAL",
            "PROPOSAL",
            str(proposal.proposal_id),
            orchestration_identity,
            inputs=(source_ref,),
            generation=1,
        )
        registered_proposal = HypothesisProposal.model_validate(
            proposal.model_dump()
            | {
                "meta": runner.metadata(
                    work.meta,
                    "hypothesis_proposal",
                    attempt_id=work.active_attempt_id,
                )
                | {"hypothesis_id": None}
            }
        )
        completed = runner.complete(
            work,
            orchestration_identity,
            "ORCHESTRATION",
            (registered_proposal,),
        )
        proposal_ref = completed.output_refs[0]
        if not isinstance(proposal_ref, StoredDataRef):
            raise TypeError("VERIFICATION_CHILD_PROPOSAL_SCOPE_MISMATCH")
        registered.append(proposal_ref)
    return tuple(registered)
