"""Exact read-only resolution of Chaining provenance used by Context planning."""

from sqlalchemy import Connection, select

from sastsimi.contracts.chaining import ChainingResult, Primitive
from sastsimi.contracts.hypothesis import HypothesisProposal
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import CommitState, TransitionCommit
from sastsimi.ports.context import ChainingContextRecords

from . import models
from .codec import REF_ADAPTER
from .repositories import SQLiteRecordStore


class ContextLineageReader:
    """Resolve one committed match; never create or choose Chaining records."""

    def __init__(self, records: SQLiteRecordStore) -> None:
        self.records = records

    def read_for(
        self, proposal_ref: StoredDataRef, source_primitive_match_id: str
    ) -> ChainingContextRecords:
        with self.records.database.engine.connect() as connection:
            proposal = self.records.resolve(connection, proposal_ref)
            if (
                not isinstance(proposal, HypothesisProposal)
                or reference(proposal) != proposal_ref
                or proposal.origin != "CHAINING"
                or proposal.source_primitive_match_id != source_primitive_match_id
            ):
                raise ValueError("CONTEXT_LINEAGE_MISMATCH")
            candidates: list[tuple[StoredDataRef, ChainingResult]] = []
            rows = connection.execute(
                select(models.records.c.ref).where(
                    models.records.c.kind == "chaining_result"
                )
            ).scalars()
            for wire in rows:
                ref = REF_ADAPTER.validate_json(wire)
                if not isinstance(ref, StoredDataRef):
                    continue
                result = self.records.resolve(connection, ref)
                if not isinstance(result, ChainingResult) or reference(result) != ref:
                    raise ValueError("CONTEXT_LINEAGE_MISMATCH")
                matches = tuple(
                    item
                    for item in result.primitive_match_candidates
                    if item.primitive_match_id == source_primitive_match_id
                )
                proposals = tuple(
                    item
                    for item in result.chained_hypothesis_proposals
                    if reference(item) == proposal_ref
                )
                if matches or proposals:
                    if len(matches) != 1 or proposals != (proposal,):
                        raise ValueError("CONTEXT_LINEAGE_MISMATCH")
                    candidates.append((ref, result))
            if len(candidates) != 1:
                raise ValueError("CONTEXT_LINEAGE_MISMATCH")
            result_ref, result = candidates[0]
            current_id = connection.execute(
                select(models.current_records.c.record_id).where(
                    models.current_records.c.logical_record_id
                    == str(result.meta.logical_record_id)
                )
            ).scalar()
            if current_id != str(result_ref.record_id) or not self._is_committed(
                connection, result_ref
            ):
                raise ValueError("CONTEXT_LINEAGE_NOT_COMMITTED")
            match = next(
                item
                for item in result.primitive_match_candidates
                if item.primitive_match_id == source_primitive_match_id
            )
            upstream = self.records.resolve(connection, match.upstream_result_ref)
            downstream = self.records.resolve(connection, match.downstream_input_ref)
            if (
                not isinstance(upstream, Primitive)
                or not isinstance(downstream, Primitive)
                or reference(upstream) != match.upstream_result_ref
                or reference(downstream) != match.downstream_input_ref
            ):
                raise ValueError("CONTEXT_LINEAGE_MISMATCH")
            return ChainingContextRecords(
                proposal_ref=proposal_ref,
                proposal=proposal,
                chaining_result_ref=result_ref,
                chaining_result=result,
                upstream_ref=match.upstream_result_ref,
                upstream=upstream,
                downstream_ref=match.downstream_input_ref,
                downstream=downstream,
            )

    def _is_committed(self, connection: Connection, ref: StoredDataRef) -> bool:
        rows = connection.execute(select(models.transition_commits.c.payload)).scalars()
        commits = tuple(TransitionCommit.model_validate_json(row) for row in rows)
        return (
            sum(
                commit.state == CommitState.COMMITTED and ref in commit.output_refs
                for commit in commits
            )
            == 1
        )
