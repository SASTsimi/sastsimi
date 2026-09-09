"""Shared deterministic Pro/Con orchestration for every generation."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import ConEvidenceResult, ProEvidenceResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.orchestration.fake_configuration import register_fake_llm_call
from sastsimi.orchestration.fake_support import FakeEvidence
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .fake_base import ProviderInvoker
from .fake_provider_runtime import invoke_fake_provider, persist_fake_invocation


@dataclass(frozen=True)
class FakeDebateResult:
    pro: ProEvidenceResult
    con: ConEvidenceResult
    pro_ref: StoredDataRef
    con_ref: StoredDataRef


def run_fake_debate(
    *,
    runtime: RuntimeServices,
    runner: WorkflowRunner,
    evidence: FakeEvidence,
    scope: StoredDataRef,
    owner_ref: StoredDataRef,
    orchestrator_ref: StoredDataRef,
    proposal_ref: StoredDataRef,
    verification_work: WorkExecutionState,
    debate_inputs: tuple[StoredDataRef, ...],
    record_meta: Callable[..., RecordMeta],
    artifact: Callable[[str], RecordRef],
    stored_artifact: Callable[[str], StoredDataRef],
    now: Callable[[], datetime],
    build_evidence: Callable[
        [str, WorkExecutionState, WorkExecutionState, tuple[StoredDataRef, ...]],
        ProEvidenceResult | ConEvidenceResult,
    ],
    provider_invoke: ProviderInvoker,
) -> FakeDebateResult:
    """Register both branches first, then invoke each real fake provider path."""
    if (
        not isinstance(verification_work.meta, RecordMeta)
        or verification_work.meta.hypothesis_id is None
    ):
        raise TypeError("FAKE_DEBATE_HYPOTHESIS_SCOPE_REQUIRED")
    children: list[tuple[str, StoredDataRef, WorkExecutionState]] = []
    evidence.identities[owner_ref] = RequesterRole.VERIFICATION
    for role, identity in zip(
        ("PRO", "CON"), (orchestrator_ref, proposal_ref), strict=True
    ):
        child = runner.start(
            scope,
            verification_work.meta,
            f"{role}_EVIDENCE",
            "HYPOTHESIS",
            str(verification_work.meta.hypothesis_id),
            owner_ref,
            role="VERIFICATION",
            inputs=debate_inputs,
            parent=reference(verification_work),
            generation=verification_work.work_generation,
        )
        children.append((role, identity, child))

    results: list[ProEvidenceResult | ConEvidenceResult] = []
    for role, identity, child in children:
        call_ref, provider_ref = register_fake_llm_call(
            runtime,
            evidence,
            record_meta,
            artifact,
            now(),
            runner=runner,
            scope=scope,
            orchestration_identity=identity,
            role=role,
            result_kind=f"{role.lower()}_evidence_result",
            context_refs=debate_inputs,
        )
        selected_role = RequesterRole(role)
        evidence.identities[identity] = selected_role

        def build_output(
            _decision: StoredDataRef,
            selected_role: str = role,
            selected_work: WorkExecutionState = child,
        ) -> ProEvidenceResult | ConEvidenceResult:
            return build_evidence(
                selected_role, selected_work, verification_work, debate_inputs
            )

        result, invocation = invoke_fake_provider(
            runtime=runtime,
            runner=runner,
            work=child,
            scope=scope,
            identity=identity,
            action_role=selected_role,
            action_type="CALL_LLM",
            call_spec_ref=call_ref,
            provider_profile_ref=provider_ref,
            artifact=stored_artifact,
            build_output=build_output,
            provider_invoke=provider_invoke,
        )
        if not isinstance(result, (ProEvidenceResult, ConEvidenceResult)):
            raise TypeError("FAKE_DEBATE_OUTPUT_MISMATCH")
        completed = runner.complete(child, identity, role, (result,))
        output_ref = completed.output_refs[0]
        if not isinstance(output_ref, StoredDataRef):
            raise TypeError("FAKE_DEBATE_OUTPUT_SCOPE_MISMATCH")
        persist_fake_invocation(runtime, invocation, output_ref)
        results.append(result)

    pro, con = results
    if not isinstance(pro, ProEvidenceResult) or not isinstance(con, ConEvidenceResult):
        raise TypeError("FAKE_DEBATE_ROLE_MISMATCH")
    pro_ref, con_ref = reference(pro), reference(con)
    if not isinstance(pro_ref, StoredDataRef) or not isinstance(con_ref, StoredDataRef):
        raise TypeError("FAKE_DEBATE_OUTPUT_SCOPE_MISMATCH")
    return FakeDebateResult(pro, con, pro_ref, con_ref)
