"""Typed boundary for run-local policy state and run-neutral cache lookup."""

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.ids import LogicalRecordId, ProgramId
from sastsimi.contracts.policy import PolicyCacheRecord, RunPolicyState
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import WorkExecutionState


@dataclass(frozen=True, slots=True)
class PolicyCacheKey:
    program_id: ProgramId
    source_config_hash: str
    parser_name: str
    parser_version: str
    freshness_criterion_hash: str

    @property
    def logical_record_id(self) -> LogicalRecordId:
        return LogicalRecordId(
            content_hash(
                [
                    "policy-cache",
                    self.program_id,
                    self.source_config_hash,
                    self.parser_name,
                    self.parser_version,
                    self.freshness_criterion_hash,
                ]
            )
        )

    @classmethod
    def from_record(cls, record: PolicyCacheRecord) -> "PolicyCacheKey":
        return cls(
            program_id=record.meta.program_id,
            source_config_hash=record.source_config_ref.content_hash,
            parser_name=record.parser_name,
            parser_version=record.parser_version,
            freshness_criterion_hash=record.freshness_criterion_ref.content_hash,
        )


@dataclass(frozen=True, slots=True)
class PolicyPreparation:
    work: WorkExecutionState
    state: RunPolicyState


@runtime_checkable
class PolicyRuntimePort(Protocol):
    def begin(
        self,
        work: WorkExecutionState,
        decision_ref: RecordRef,
        reservation_ref: RecordRef,
        state: RunPolicyState,
    ) -> PolicyPreparation: ...

    def current_state(self, analysis_id: str) -> RunPolicyState | None: ...

    def current_cache(self, key: PolicyCacheKey) -> PolicyCacheRecord | None: ...
