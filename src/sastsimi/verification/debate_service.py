"""Shared deterministic Pro/Con orchestration for every generation."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import ConEvidenceResult, ProEvidenceResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.fake_workflow import ProviderInvoker, ProviderProber
from sastsimi.runtime.fake_llm_configuration import register_fake_llm_call
from sastsimi.runtime.fake_llm_invocation import (
    invoke_fake_provider,
    persist_fake_invocation,
)
from sastsimi.runtime.fake_support import FakeEvidence
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner


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
    verification_work: WorkExecutionState,
    debate_inputs: tuple[StoredDataRef, ...],
    record_meta: Callable[..., RecordMeta],
    artifact: Callable[[str], RecordRef],
    stored_artifact: Callable[[str], StoredDataRef],
    now: Callable[[], datetime],
    provider_invoke: ProviderInvoker,
    provider_probe: ProviderProber,
) -> FakeDebateResult:
    """Register both branches first, then invoke each real fake provider path."""
    if (
        not isinstance(verification_work.meta, RecordMeta)
        or verification_work.meta.hypothesis_id is None
    ):
        raise TypeError("FAKE_DEBATE_HYPOTHESIS_SCOPE_REQUIRED")
    children: list[tuple[str, StoredDataRef, WorkExecutionState]] = []
    for role in ("PRO", "CON"):
        identity = evidence.stored_identity(RequesterRole(role))
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
            provider_probe,
            runner=runner,
            work=child,
            scope=scope,
            orchestration_identity=orchestrator_ref,
            role=role,
            result_kind=f"{role.lower()}_evidence_result",
            context_refs=debate_inputs,
        )
        selected_role = RequesterRole(role)

        def build_output(
            _decision: StoredDataRef,
            selected_role: str = role,
            selected_work: WorkExecutionState = child,
        ) -> ProEvidenceResult | ConEvidenceResult:
            model = ProEvidenceResult if selected_role == "PRO" else ConEvidenceResult
            return model.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=runner.metadata(
                            verification_work.meta,
                            f"{selected_role.lower()}_evidence_result",
                            attempt_id=selected_work.active_attempt_id,
                        ),
                        role=selected_role,
                        parent_work_id=verification_work.work_id,
                        evidence_work_id=selected_work.work_id,
                        verification_generation=verification_work.work_generation,
                        llm_call_id=f"fake-{selected_role.lower()}-call",
                        debate_input_hash=content_hash(debate_inputs),
                        evidence=(),
                        summary=f"{selected_role} reviewed the exact fake path",
                        limitations=(),
                    )
                )
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
        persist_fake_invocation(runtime, invocation)
        completed = runner.complete(child, identity, role, (result,))
        output_ref = completed.output_refs[0]
        if not isinstance(output_ref, StoredDataRef):
            raise TypeError("FAKE_DEBATE_OUTPUT_SCOPE_MISMATCH")
        results.append(result)

    pro, con = results
    if not isinstance(pro, ProEvidenceResult) or not isinstance(con, ConEvidenceResult):
        raise TypeError("FAKE_DEBATE_ROLE_MISMATCH")
    pro_ref, con_ref = reference(pro), reference(con)
    if not isinstance(pro_ref, StoredDataRef) or not isinstance(con_ref, StoredDataRef):
        raise TypeError("FAKE_DEBATE_OUTPUT_SCOPE_MISMATCH")
    return FakeDebateResult(pro, con, pro_ref, con_ref)


class DebateService:
    """Run the same-input Pro/Con fan-out and exact result join."""

    run = staticmethod(run_fake_debate)
