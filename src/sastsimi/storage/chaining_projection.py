"""Exact committed primitive snapshot validation for chaining results."""

from sqlalchemy import Connection, select

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.chaining import (
    ChainingResult,
    Primitive,
    PrimitiveIndexState,
    validate_chaining_closure,
)
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import Record

from . import models
from .codec import REF_ADAPTER
from .stage_policy import current as require_current
from .stage_policy import resolved
from .work_service import WorkService


def validate_chaining_output(
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    outputs: tuple[Record, ...],
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
        or len(index_refs) + len(primitive_input_refs) != len(work.input_refs)
        or {canonical_bytes(ref) for ref in primitive_input_refs}
        != {canonical_bytes(ref) for ref in result.considered_primitive_refs}
    ):
        raise ValueError("CHAINING_INPUT_SNAPSHOT_MISMATCH")
    indexes = tuple(
        resolved(works.records, connection, ref, PrimitiveIndexState)
        for ref in index_refs
    )
    for ref in index_refs:
        require_current(works.records, connection, ref)
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
            or work.work_generation != process.verification_generation
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
    validate_chaining_closure(
        result,
        primitives,
        result.considered_primitive_refs,
        result.excluded_lineage_refs,
    )
