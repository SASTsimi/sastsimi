"""Read-only Context planning inputs and trusted ceiling resolution ports."""

from dataclasses import dataclass
from typing import Literal, Protocol

from sastsimi.contracts.chaining import ChainingResult, Primitive
from sastsimi.contracts.hypothesis import HypothesisProposal
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.static import (
    CodeLocation,
    CodeRelation,
    CodeSymbol,
    ContextRetrievalLimits,
)
from sastsimi.contracts.work import WorkExecutionState

RelationQuery = Literal[
    "CALLERS", "CALLEES", "DATA_FLOW_NEIGHBORS", "AUTH_GUARDS", "ROUTE_BINDINGS"
]


@dataclass(frozen=True)
class ContextRetrievalIntent:
    proposal_ref: StoredDataRef
    bundle_ref: StoredDataRef
    requested_entities: tuple[CodeSymbol, ...]
    requested_locations: tuple[CodeLocation, ...]
    relation_query: tuple[RelationQuery, ...]
    reason: str
    requested_limits: ContextRetrievalLimits


@dataclass(frozen=True)
class ContextCeilingProfile:
    ref: StoredDataRef
    limits: ContextRetrievalLimits


@dataclass(frozen=True)
class ChainingContextRecords:
    proposal_ref: StoredDataRef
    proposal: HypothesisProposal
    chaining_result_ref: StoredDataRef
    chaining_result: ChainingResult
    upstream_ref: StoredDataRef
    upstream: Primitive
    downstream_ref: StoredDataRef
    downstream: Primitive


@dataclass(frozen=True)
class ContextReadPlan:
    intent_hash: str
    workspace_id: str
    commit_id: str
    proposal_ref: StoredDataRef
    bundle_ref: StoredDataRef
    ceiling_profile_ref: StoredDataRef
    requested_limits: ContextRetrievalLimits
    entities: tuple[CodeSymbol, ...]
    locations: tuple[CodeLocation, ...]
    relations: tuple[CodeRelation, ...]
    file_paths: tuple[str, ...]
    lineage_refs: tuple[StoredDataRef, ...]


class ContextLineageReaderPort(Protocol):
    def read_for(
        self, proposal_ref: StoredDataRef, source_primitive_match_id: str
    ) -> ChainingContextRecords: ...


class ContextLimitPolicyPort(Protocol):
    def ceilings_for(self, work: WorkExecutionState) -> ContextCeilingProfile: ...
