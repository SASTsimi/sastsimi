from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.observability.agent_activity import AgentActivityEvent


class SimpleStage(StrEnum):
    STATIC_DONE = "STATIC_DONE"
    HYPOTHESIS_DONE = "HYPOTHESIS_DONE"
    PRO_CON_DONE = "PRO_CON_DONE"
    VERIFICATION_INITIAL_DONE = "VERIFICATION_INITIAL_DONE"
    POC_CANDIDATE_DONE = "POC_CANDIDATE_DONE"
    POC_EXECUTION_DONE = "POC_EXECUTION_DONE"
    VERIFICATION_FINAL_DONE = "VERIFICATION_FINAL_DONE"
    CWE_DONE = "CWE_DONE"
    TECH_GATE_DONE = "TECH_GATE_DONE"
    SCOPE_GATE_DONE = "SCOPE_GATE_DONE"
    PRIMITIVE_ADMISSION_DONE = "PRIMITIVE_ADMISSION_DONE"
    CHAINING_DONE = "CHAINING_DONE"
    FINDING_DONE = "FINDING_DONE"
    REPORT_DONE = "REPORT_DONE"


STAGE_ORDER: tuple[SimpleStage, ...] = tuple(SimpleStage)
HYPOTHESIS_STAGES: tuple[SimpleStage, ...] = STAGE_ORDER[2:]
STAGE_VERSION: dict[SimpleStage, str] = {
    stage: (
        "3"
        if stage is SimpleStage.REPORT_DONE
        else "2"
        if stage
        in {
            SimpleStage.VERIFICATION_INITIAL_DONE,
            SimpleStage.POC_EXECUTION_DONE,
        }
        else "1"
    )
    for stage in STAGE_ORDER
}


class StageStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class CheckpointIdentity(ContractModel):
    analysis_id: str
    workspace_id: str
    commit_id: str
    hypothesis_id: str | None


class SimpleAnalysisRun(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    analysis_id: str
    display_analysis_id: str
    workspace_id: str
    commit_id: str
    repository: str
    llm_provider: str | None = None
    on_demand_possible: bool = False
    workspace_path: Path | None = None
    repository_profile_ref: StoredDataRef | None = None
    static_bundle_ref: StoredDataRef | None = None
    security_policy_ref: StoredDataRef | None = None
    hypothesis_ids: tuple[str, ...] = ()
    parent_hypothesis_ids: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    chain_depths: dict[str, int] = Field(default_factory=dict)


def input_reference_hash(refs: tuple[StoredDataRef, ...]) -> str:
    return hashlib.sha256(canonical_bytes(refs)).hexdigest()


class StageCheckpoint(ContractModel):
    identity: CheckpointIdentity
    stage: SimpleStage
    stage_version: str = "1"
    status: StageStatus
    input_refs: tuple[StoredDataRef, ...]
    input_hash: str
    output_refs: tuple[StoredDataRef, ...] = ()
    attempt_id: str | None = None
    attempt_number: int = 0
    recovery_lineage_id: str | None = None
    recovery_origin_stage: SimpleStage | None = None
    recovery_decision_refs: tuple[StoredDataRef, ...] = ()
    error_code: str | None = None
    retryable: bool = False
    recipe_ref: StoredDataRef | None = None
    image_digest: str | None = None
    container_id: str | None = None
    validated_poc_ref: StoredDataRef | None = None
    report_ref: StoredDataRef | None = None
    verdict: Literal["TRUE", "FALSE", "HOLD"] | None = None
    markdown_path: str | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def require_exact_input_hash(self) -> StageCheckpoint:
        if self.input_hash != input_reference_hash(self.input_refs):
            raise ValueError("SIMPLE_RUNTIME_INPUT_HASH_MISMATCH")
        return self


class StageResult(ContractModel):
    output_refs: tuple[StoredDataRef, ...]
    validated_poc_ref: StoredDataRef | None = None
    report_ref: StoredDataRef | None = None
    verdict: Literal["TRUE", "FALSE", "HOLD"] | None = None
    recipe_ref: StoredDataRef | None = None
    image_digest: str | None = None
    container_id: str | None = None
    markdown_path: str | None = None
    activity_events: tuple[AgentActivityEvent, ...] = ()


class StageFailure(ContractModel):
    code: str
    retryable: bool
    safe_message: str
    invalid_field: str | None = None
    evidence_refs: tuple[StoredDataRef, ...] = ()
