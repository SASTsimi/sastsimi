"""Shared deterministic assembly for initial and revised Verification generations."""

from __future__ import annotations

from typing import Any

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import HypothesisId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.verification import (
    VerificationInitialAssessment,
    VerificationResult,
)
from sastsimi.ports.verification_assembly import VerificationGenerationInputs


def build_initial_assessment(
    *,
    meta: dict[str, Any],
    inputs: VerificationGenerationInputs,
    verdict: str,
    revised: bool,
) -> VerificationInitialAssessment:
    """Build the common pre-dynamic synthesis output for either generation."""
    return VerificationInitialAssessment.model_validate_json(
        canonical_bytes(
            dict(
                meta=meta,
                verification_work_id=inputs.work_id,
                verification_generation=inputs.generation,
                hypothesis_ref=inputs.hypothesis_ref,
                policy_ref=inputs.policy_ref,
                playbook_ref=inputs.playbook_ref,
                playbook_application_ref=inputs.application_ref,
                pro_evidence_ref=inputs.pro_ref,
                con_evidence_ref=inputs.con_ref,
                next_step=(
                    "POC_CONFIRMATION"
                    if verdict == "TRUE"
                    else "FINALIZE_WITHOUT_DYNAMIC"
                ),
                proposed_verdict=verdict,
                rationale=(
                    "The revised generation closed the request"
                    if revised
                    else "The deterministic debate is complete"
                ),
                evidence_refs=(inputs.evidence_ref,),
                unresolved_conditions=("Reachability",) if verdict == "HOLD" else (),
                llm_call_id=("fake-revised-synthesis" if revised else "fake-synthesis"),
            )
        )
    )


def build_verification_result(
    *,
    meta: dict[str, Any],
    inputs: VerificationGenerationInputs,
    verdict: str,
    dynamic_request_ref: StoredDataRef | None,
    dynamic_result_ref: StoredDataRef | None,
    poc_ref: StoredDataRef | None,
    observation_ref: StoredDataRef,
    revised: bool,
    material_child_meta: dict[str, Any] | None = None,
    parent_hypothesis_id: HypothesisId | None = None,
) -> VerificationResult:
    """Assemble the exact shared final shape after provider/dynamic validation."""
    true_result = verdict == "TRUE"
    falsification_outcome = {
        "FALSE": "DISPROVED",
        "HOLD": "INCONCLUSIVE",
        "TRUE": "NOT_DISPROVED",
    }[verdict]
    supporting = (
        (
            dict(
                claim_id="fake-revised-poc" if revised else "fake-executed-poc",
                statement=(
                    "The revised PoC reached the sink"
                    if revised
                    else "The deterministic PoC reached the sink"
                ),
                source_role="VERIFICATION",
                evidence_refs=(observation_ref,),
                code_locations=(inputs.location,),
                limitations=(),
            ),
        )
        if true_result
        else ()
    )
    required = (
        (
            dict(
                draft_id="fake-input",
                entity_refs=(),
                privilege_level=None,
                evidence_refs=(observation_ref,),
                description="Attacker-controlled input",
            ),
        )
        if true_result
        else ()
    )
    provided = (
        (
            dict(
                draft_id="fake-output",
                entity_refs=(),
                privilege_level="application",
                evidence_refs=(observation_ref,),
                description=(
                    "Validated revised sink execution"
                    if revised
                    else "Validated sink execution"
                ),
            ),
        )
        if true_result
        else ()
    )
    children: tuple[dict[str, object], ...] = ()
    if material_child_meta is not None:
        if parent_hypothesis_id is None:
            raise ValueError("MATERIAL_CHILD_PARENT_REQUIRED")
        children = (
            dict(
                meta=material_child_meta,
                proposal_id="fake-material-child",
                proposal_state="HYPOTHESIS_ONLY",
                assertion_mode="NON_FINAL",
                origin="VERIFICATION",
                vulnerability_type_candidates=(),
                target_entities=(),
                target_locations=(inputs.location,),
                suspected_path=(inputs.location,),
                observed_facts=(),
                assumptions=("A separate sink may be reachable",),
                restrictions=(),
                falsification_questions=(
                    dict(
                        question_id="child-reachability",
                        question="Can the separate sink be reached?",
                    ),
                ),
                validation_checks=(
                    dict(
                        validation_id="child-path",
                        instruction="Validate the separate exact path",
                    ),
                ),
                parent_hypothesis_ids=(parent_hypothesis_id,),
                source_primitive_match_id=None,
            ),
        )
    return VerificationResult.model_validate_json(
        canonical_bytes(
            dict(
                meta=meta,
                playbook_ref=inputs.playbook_ref,
                playbook_application_ref=inputs.application_ref,
                verification_mode="ALWAYS_DEBATE",
                debate_triggers=(),
                debate_skip_reason=None,
                debate_input_hash=inputs.debate_input_hash,
                pro_evidence_ref=inputs.pro_ref,
                con_evidence_ref=inputs.con_ref,
                supporting_evidence=supporting,
                counter_evidence=(),
                falsification_results=tuple(
                    dict(
                        question_id=question_id,
                        outcome=falsification_outcome,
                        evidence_refs=(inputs.evidence_ref,),
                        rationale=(
                            "The revised proof is supported"
                            if revised
                            else "The fake evidence determines this outcome"
                        ),
                    )
                    for question_id in inputs.falsification_question_ids
                ),
                validation_results=tuple(
                    dict(
                        validation_id=validation_id,
                        completion="COMPLETE",
                        evidence_refs=(inputs.evidence_ref,),
                        summary=(
                            "The revised exact path was checked"
                            if revised
                            else "The exact fake path was checked"
                        ),
                    )
                    for validation_id in inputs.validation_ids
                ),
                initial_verdict=verdict,
                dynamic_request_ref=dynamic_request_ref,
                dynamic_result_ref=dynamic_result_ref,
                poc_ref=poc_ref,
                verdict=verdict,
                verdict_rationale=(
                    "Deterministic revised fake outcome"
                    if revised
                    else "Deterministic fake outcome"
                ),
                restrictions=(),
                bypass_candidates=(),
                required_primitive_candidates=required,
                provided_primitive_candidates=provided,
                impact_escalation_candidates=(),
                material_child_proposals=children,
                unresolved_conditions=("Reachability",) if verdict == "HOLD" else (),
                metrics=dict(
                    pro_tokens=1,
                    con_tokens=1,
                    synthesis_tokens=1,
                    elapsed_ms=1,
                    verdict_changed_after_debate=False,
                    hold_resolved=False,
                    false_positive_reduction_candidate=verdict == "FALSE",
                    new_bypass_count=0,
                    new_restriction_count=0,
                    new_falsification_count=0,
                ),
                errors=(),
            )
        )
    )


class FakeVerificationAssembly:
    """Concrete domain service shared by initial and REVISE orchestration."""

    build_initial_assessment = staticmethod(build_initial_assessment)
    build_result = staticmethod(build_verification_result)
