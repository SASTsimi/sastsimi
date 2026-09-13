"""SQLite-backed exact Primitive ancestry for production Chaining."""

from __future__ import annotations

from sqlalchemy import select

from sastsimi.contracts.chaining import Primitive
from sastsimi.contracts.hypothesis import HypothesisProposal, VulnerabilityHypothesis
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.chaining import PinnedChainingUniverse

from . import models
from .codec import REF_ADAPTER
from .context_lineage import ContextLineageReader
from .repositories import SQLiteRecordStore


class SQLiteChainingLineage:
    """Reconstruct committed ancestry from exact child-hypothesis provenance."""

    def __init__(self, records: SQLiteRecordStore) -> None:
        self.records = records
        self._context = ContextLineageReader(records)

    def ancestors(
        self,
        *,
        primitive_ref: StoredDataRef,
        universe: PinnedChainingUniverse,
    ) -> tuple[StoredDataRef, ...]:
        allowed = frozenset(universe.considered_primitive_refs)
        if primitive_ref not in allowed:
            raise ValueError("CHAINING_LINEAGE_OUTSIDE_PINNED_UNIVERSE")
        resolved: list[StoredDataRef] = []
        visiting: set[StoredDataRef] = set()

        def visit(current_ref: StoredDataRef) -> None:
            if current_ref in visiting:
                raise ValueError("CHAINING_LINEAGE_CYCLE")
            visiting.add(current_ref)
            primitive = self.records.get_exact(current_ref)
            if (
                not isinstance(primitive, Primitive)
                or reference(primitive) != current_ref
            ):
                raise ValueError("CHAINING_LINEAGE_MISMATCH")
            hypothesis = self._current_hypothesis(primitive)
            proposal = self.records.get_exact(hypothesis.proposal_ref)
            if (
                not isinstance(proposal, HypothesisProposal)
                or reference(proposal) != hypothesis.proposal_ref
                or proposal.origin != hypothesis.origin
            ):
                raise ValueError("CHAINING_LINEAGE_MISMATCH")
            if hypothesis.origin == "CHAINING":
                match_id = hypothesis.source_primitive_match_id
                if match_id is None:
                    raise ValueError("CHAINING_LINEAGE_MISMATCH")
                context = self._context.read_for(hypothesis.proposal_ref, match_id)
                for parent_ref in (context.upstream_ref, context.downstream_ref):
                    if parent_ref not in allowed:
                        raise ValueError("CHAINING_LINEAGE_OUTSIDE_PINNED_UNIVERSE")
                    if parent_ref not in resolved:
                        resolved.append(parent_ref)
                        visit(parent_ref)
            visiting.remove(current_ref)

        visit(primitive_ref)
        return tuple(resolved)

    def _current_hypothesis(self, primitive: Primitive) -> VulnerabilityHypothesis:
        candidates: list[VulnerabilityHypothesis] = []
        with self.records.database.engine.connect() as connection:
            rows = connection.execute(
                select(models.records.c.ref)
                .join(
                    models.current_records,
                    models.current_records.c.record_id == models.records.c.record_id,
                )
                .where(models.records.c.kind == "vulnerability_hypothesis")
            ).scalars()
            for wire in rows:
                ref = REF_ADAPTER.validate_json(wire)
                if not isinstance(ref, StoredDataRef):
                    continue
                record = self.records.resolve(connection, ref)
                if (
                    isinstance(record, VulnerabilityHypothesis)
                    and record.meta.hypothesis_id == primitive.source_hypothesis_id
                    and record.meta.analysis_id == primitive.meta.analysis_id
                    and record.meta.workspace_id == primitive.meta.workspace_id
                    and record.meta.commit_id == primitive.meta.commit_id
                ):
                    candidates.append(record)
        if len(candidates) != 1:
            raise ValueError("CHAINING_LINEAGE_HYPOTHESIS_NOT_CURRENT")
        return candidates[0]


__all__ = ["SQLiteChainingLineage"]
