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
MAX_RECOVERY_ATTEMPTS = 3
STAGE_VERSION: dict[SimpleStage, str] = {
    stage: (
        "6"
        if stage is SimpleStage.VERIFICATION_INITIAL_DONE
        else "6"
        if stage is SimpleStage.POC_CANDIDATE_DONE
        else "4"
        if stage is SimpleStage.REPORT_DONE
        else "3"
        if stage
        in {SimpleStage.POC_EXECUTION_DONE, SimpleStage.VERIFICATION_FINAL_DONE}
        else "2"
        if stage is SimpleStage.TECH_GATE_DONE
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


class CandidateTerminal(ContractModel):
    """Durable proof that a candidate pipeline finished known downstream work."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["COMPLETE", "PARTIAL"]
    bundle_hash: str
    scope_fingerprint: str
    decision_counts: dict[str, int]
    deep_counts: dict[str, int]
    hypothesis_count: int = Field(ge=0)
    surface_index_hash: str | None = None
    surface_coverage_hash: str | None = None
    surface_counts: dict[str, int] = Field(default_factory=dict)
    producer_finished: bool = False
    chaining_pool_fingerprint: str | None = None
    chaining_batch_count: int | None = Field(default=None, ge=0)
    pending_child_count: int = Field(default=0, ge=0)


class SimpleAnalysisRun(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    analysis_id: str
    display_analysis_id: str
    workspace_id: str
    commit_id: str
    repository: str
    profile_ref: str | None = None
    provider: str | None = None
    model: str | None = None
    started_at: datetime | None = None
    llm_provider: str | None = None
    on_demand_possible: bool = False
    workspace_path: Path | None = None
    repository_profile_ref: StoredDataRef | None = None
    static_bundle_ref: StoredDataRef | None = None
    static_coverage_ref: StoredDataRef | None = None
    static_disposition: Literal["FULL", "PARTIAL"] = "FULL"
    security_policy_ref: StoredDataRef | None = None
    policy_snapshot_ref: StoredDataRef | None = None
    candidate_pipeline_version: int | None = None
    candidate_scope_fingerprint: str | None = None
    candidate_terminal: CandidateTerminal | None = None
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
    gate_revision_count: int = Field(default=0, ge=0)
    recovery_lineage_id: str | None = None
    recovery_origin_stage: SimpleStage | None = None
    recovery_decision_refs: tuple[StoredDataRef, ...] = ()
    poc_stop_decision_ref: StoredDataRef | None = None
    external_prerequisites_ref: StoredDataRef | None = None
    environment_block_ref: StoredDataRef | None = None
    error_code: str | None = None
    retryable: bool = False
    recipe_ref: StoredDataRef | None = None
    image_digest: str | None = None
    container_id: str | None = None
    validated_poc_ref: StoredDataRef | None = None
    report_ref: StoredDataRef | None = None
    bundle_manifest_ref: StoredDataRef | None = None
    bundle_archive_ref: StoredDataRef | None = None
    verdict: Literal["TRUE", "FALSE", "HOLD"] | None = None
    gate_decision: Literal["ACCEPT", "REVISE", "REJECT"] | None = None
    markdown_path: str | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def require_exact_input_hash(self) -> StageCheckpoint:
        if self.input_hash != input_reference_hash(self.input_refs):
            raise ValueError("SIMPLE_RUNTIME_INPUT_HASH_MISMATCH")
        return self


class StageResult(ContractModel):
    output_refs: tuple[StoredDataRef, ...]
    external_prerequisites_ref: StoredDataRef | None = None
    environment_block_ref: StoredDataRef | None = None
    validated_poc_ref: StoredDataRef | None = None
    report_ref: StoredDataRef | None = None
    bundle_manifest_ref: StoredDataRef | None = None
    bundle_archive_ref: StoredDataRef | None = None
    verdict: Literal["TRUE", "FALSE", "HOLD"] | None = None
    gate_decision: Literal["ACCEPT", "REVISE", "REJECT"] | None = None
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


def terminal_initial_outcome(
    checkpoint: StageCheckpoint | None,
) -> Literal["INCONCLUSIVE"] | None:
    """Return an explicit, non-reportable unmet attack prerequisite."""

    if (
        checkpoint is not None
        and checkpoint.stage is SimpleStage.VERIFICATION_INITIAL_DONE
        and checkpoint.status is StageStatus.SUCCEEDED
        and checkpoint.stage_version
        == STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE]
        and checkpoint.verdict == "HOLD"
        and (
            (
                checkpoint.external_prerequisites_ref is not None
                and checkpoint.environment_block_ref is None
                and checkpoint.external_prerequisites_ref in checkpoint.output_refs
            )
            or (
                checkpoint.external_prerequisites_ref is None
                and checkpoint.environment_block_ref is not None
                and checkpoint.environment_block_ref in checkpoint.output_refs
            )
        )
        and checkpoint.recipe_ref is None
        and checkpoint.validated_poc_ref is None
    ):
        return "INCONCLUSIVE"
    return None


def terminal_poc_outcome(
    checkpoint: StageCheckpoint | None,
) -> Literal["INCONCLUSIVE"] | None:
    """Return a completed, non-reportable PoC after exhaustion or verified STOP."""

    if (
        checkpoint is not None
        and checkpoint.stage is SimpleStage.POC_EXECUTION_DONE
        and checkpoint.status is StageStatus.SUCCEEDED
        and checkpoint.stage_version == STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE]
        and checkpoint.verdict == "HOLD"
        and (
            checkpoint.attempt_number >= MAX_RECOVERY_ATTEMPTS
            or checkpoint.poc_stop_decision_ref is not None
        )
        and checkpoint.validated_poc_ref is None
        and len(checkpoint.output_refs) >= 2
    ):
        return "INCONCLUSIVE"
    return None


def terminal_gate_outcome(
    checkpoint: StageCheckpoint | None,
) -> Literal["REJECT", "INCONCLUSIVE"] | None:
    """Return a non-reportable terminal decision, never an execution failure."""

    if (
        checkpoint is None
        or checkpoint.stage is not SimpleStage.TECH_GATE_DONE
        or checkpoint.status is not StageStatus.SUCCEEDED
        or checkpoint.stage_version != STAGE_VERSION[SimpleStage.TECH_GATE_DONE]
    ):
        return None
    if checkpoint.gate_decision == "REJECT":
        return "REJECT"
    if checkpoint.gate_decision == "REVISE" and checkpoint.gate_revision_count >= 2:
        return "INCONCLUSIVE"
    return None
