"""Typed Verification generation assembly boundary."""

from dataclasses import dataclass
from typing import Any, Protocol

from sastsimi.contracts.ids import HypothesisId, WorkId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.static import CodeLocation
from sastsimi.contracts.verification import (
    VerificationInitialAssessment,
    VerificationResult,
)


@dataclass(frozen=True)
class VerificationGenerationInputs:
    work_id: WorkId
    generation: int
    hypothesis_ref: StoredDataRef
    policy_ref: StoredDataRef
    playbook_ref: StoredDataRef
    application_ref: StoredDataRef
    pro_ref: StoredDataRef
    con_ref: StoredDataRef
    debate_input_hash: str
    evidence_ref: StoredDataRef
    location: CodeLocation
    falsification_question_ids: tuple[str, ...]
    validation_ids: tuple[str, ...]


class VerificationAssemblyPort(Protocol):
    def build_initial_assessment(
        self,
        *,
        meta: dict[str, Any],
        inputs: VerificationGenerationInputs,
        verdict: str,
        revised: bool,
    ) -> VerificationInitialAssessment: ...

    def build_result(
        self,
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
    ) -> VerificationResult: ...
