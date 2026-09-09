"""Exact committed primitive snapshot validation for chaining results."""

from sqlalchemy import Connection

from sastsimi.contracts.chaining import (
    ChainingResult,
    Primitive,
    validate_chaining_closure,
)
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import Record

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
    primitives = tuple(
        resolved(works.records, connection, ref, Primitive)
        for ref in result.considered_primitive_refs
    )
    validate_chaining_closure(
        result,
        primitives,
        result.considered_primitive_refs,
        result.excluded_lineage_refs,
    )
