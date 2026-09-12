"""Exact committed primitive snapshot validation for chaining results."""

from sqlalchemy import Connection, select

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.chaining import (
    ChainingResult,
    LineageExclusion,
    Primitive,
    PrimitiveIndexState,
    validate_chaining_closure,
)
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.chaining import ChainingLineagePort, PinnedChainingUniverse
from sastsimi.ports.dto import Record

from . import models
from .codec import REF_ADAPTER
from .stage_policy import resolved
from .work_service import WorkService


def _expected_lineage_exclusions(
    result: ChainingResult,
    universe: PinnedChainingUniverse,
    lineage: ChainingLineagePort,
) -> tuple[LineageExclusion, ...]:
    expected: list[LineageExclusion] = []
    used = set(result.input_primitive_refs)
    seen: set[tuple[StoredDataRef, StoredDataRef]] = set()
    for match in result.primitive_match_candidates:
        for matched_ref in (
            match.upstream_result_ref,
            match.downstream_input_ref,
        ):
            ancestors = lineage.ancestors(
                primitive_ref=matched_ref,
                universe=universe,
            )
            if len(set(ancestors)) != len(ancestors) or any(
                ancestor == matched_ref
                or ancestor not in result.considered_primitive_refs
                for ancestor in ancestors
            ):
                raise ValueError("CHAINING_LINEAGE_RESOLUTION_INVALID")
            if any(ancestor in used for ancestor in ancestors):
                raise ValueError("CHAINING_LINEAGE_REUSED_ANCESTOR")
            for ancestor in ancestors:
                pair = (ancestor, matched_ref)
                if pair in seen:
                    continue
                seen.add(pair)
                expected.append(
                    LineageExclusion(
                        excluded_primitive_ref=ancestor,
                        excluded_by_ref=matched_ref,
                        reason_code="ANCESTOR_REUSE",
                    )
                )
    return tuple(expected)


def validate_chaining_output(
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    outputs: tuple[Record, ...],
    lineage: ChainingLineagePort | None = None,
) -> None:
    results = [item for item in outputs if isinstance(item, ChainingResult)]
    if not results:
        return
    if len(results) != 1 or len(outputs) != 1 or work.work_type != "CHAINING":
        raise ValueError("CHAINING_EXACT_OUTPUT_REQUIRED")
    result = results[0]
    if not isinstance(work.meta, RecordMeta):
        raise ValueError("CHAINING_CODE_SCOPE_REQUIRED")
    work_meta = work.meta
    index_refs = tuple(
        ref for ref in work.input_refs if ref.data_kind == "primitive_index_state"
    )
    primitive_input_refs = tuple(
        ref for ref in work.input_refs if ref.data_kind == "primitive"
    )
    if (
        not index_refs
        or any(not isinstance(ref, StoredDataRef) for ref in index_refs)
        or len(index_refs) + len(primitive_input_refs) != len(work.input_refs)
        or {canonical_bytes(ref) for ref in primitive_input_refs}
        != {canonical_bytes(ref) for ref in result.considered_primitive_refs}
    ):
        raise ValueError("CHAINING_INPUT_SNAPSHOT_MISMATCH")
    indexes = tuple(
        resolved(works.records, connection, ref, PrimitiveIndexState)
        for ref in index_refs
    )
    pinned_from_indexes = tuple(
        primitive_ref for index in indexes for primitive_ref in index.primitive_refs
    )
    if {canonical_bytes(ref) for ref in pinned_from_indexes} != {
        canonical_bytes(ref) for ref in result.considered_primitive_refs
    }:
        raise ValueError("CHAINING_CURRENT_INDEX_MISMATCH")
    primitives = tuple(
        resolved(works.records, connection, ref, Primitive)
        for ref in result.considered_primitive_refs
    )
    processes = tuple(
        value
        for wire in connection.execute(
            select(models.records.c.ref)
            .join(
                models.current_records,
                models.current_records.c.record_id == models.records.c.record_id,
            )
            .where(models.records.c.kind == "hypothesis_process_state")
        ).scalars()
        if isinstance(
            value := works.records.resolve(connection, REF_ADAPTER.validate_json(wire)),
            HypothesisProcessState,
        )
        and value.meta.analysis_id == work.meta.analysis_id
        and isinstance(value.meta, RecordMeta)
        and value.meta.workspace_id == work_meta.workspace_id
        and value.meta.commit_id == work_meta.commit_id
    )
    process_by_hypothesis = {
        str(process.meta.hypothesis_id): process
        for process in processes
        if process.meta.hypothesis_id is not None
    }
    index_by_hypothesis = {
        str(index.meta.hypothesis_id): index
        for index in indexes
        if index.meta.hypothesis_id is not None
    }
    for primitive in primitives:
        hypothesis_id = str(primitive.meta.hypothesis_id)
        index = index_by_hypothesis.get(hypothesis_id)
        process = process_by_hypothesis.get(hypothesis_id)
        if index is None or process is None or process.status != "TERMINAL":
            raise ValueError("CHAINING_CURRENT_VERIFICATION_MISMATCH")
        verification = resolved(
            works.records,
            connection,
            primitive.source_verification_ref,
            VerificationResult,
        )
        if not isinstance(verification.meta, RecordMeta) or not isinstance(
            primitive.meta, RecordMeta
        ):
            raise ValueError("CHAINING_CODE_SCOPE_REQUIRED")
        if (
            index.current_verification_ref != primitive.source_verification_ref
            or process.verification_result_ref != primitive.source_verification_ref
            or verification.meta.analysis_id != work.meta.analysis_id
            or verification.meta.workspace_id != work_meta.workspace_id
            or verification.meta.commit_id != work_meta.commit_id
            or primitive.meta.analysis_id != work.meta.analysis_id
            or primitive.meta.workspace_id != work_meta.workspace_id
            or primitive.meta.commit_id != work_meta.commit_id
            or verification.meta.hypothesis_id != primitive.meta.hypothesis_id
            or primitive.workspace_id != work_meta.workspace_id
            or primitive.commit_id != work_meta.commit_id
        ):
            raise ValueError("CHAINING_CURRENT_VERIFICATION_MISMATCH")
    expected_exclusions: tuple[LineageExclusion, ...] = ()
    if result.primitive_match_candidates or result.excluded_lineage_refs:
        if lineage is None or work.trigger_primitive_ref is None:
            raise ValueError("CHAINING_LINEAGE_VALIDATOR_REQUIRED")
        stored_index_refs = tuple(
            ref for ref in index_refs if isinstance(ref, StoredDataRef)
        )
        universe = PinnedChainingUniverse(
            trigger_primitive_ref=work.trigger_primitive_ref,
            index_refs=stored_index_refs,
            considered_primitive_refs=result.considered_primitive_refs,
        )
        expected_exclusions = _expected_lineage_exclusions(
            result,
            universe,
            lineage,
        )
    validate_chaining_closure(
        result,
        primitives,
        result.considered_primitive_refs,
        expected_exclusions,
    )
