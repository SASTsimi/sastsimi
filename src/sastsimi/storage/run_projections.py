"""Derived analysis pointers share the owning terminal journal/CAS transaction."""

from sqlalchemy import Connection

from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.policy import (
    PolicyCacheRecord,
    PolicyCollectionResult,
    ProgramPolicyRecord,
    RunPolicyState,
    validate_run_policy,
)
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import Record

from .codec import reference
from .records import next_meta
from .run_states import get_run, save_run
from .work_service import WorkService


def run_policy_projection(
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    outputs: tuple[Record, ...],
    *,
    publish: bool,
) -> None:
    policies = [item for item in outputs if isinstance(item, RunPolicyState)]
    if not policies:
        return
    if len(policies) != 1 or work.work_type != "POLICY_FETCH":
        raise ValueError("POLICY_STATE_CLOSURE_MISMATCH")
    policy = policies[0]
    state = get_run(connection, str(work.meta.analysis_id))
    if state.status != "RUNNING" or state.run_policy_state_ref is not None:
        raise ValueError("POLICY_ALREADY_FROZEN")
    if policy.program_id != state.program_id or policy.policy_work_ref != reference(
        work
    ):
        raise ValueError("POLICY_STATE_CLOSURE_MISMATCH")
    candidates = {reference(item): item for item in outputs}

    def resolve[T: Record](ref: RecordRef | None, model: type[T]) -> T | None:
        if ref is None:
            return None
        value = candidates.get(ref)
        if value is None:
            value = works.records.resolve(connection, ref)
        if not isinstance(value, model):
            raise ValueError("POLICY_STATE_CLOSURE_MISMATCH")
        return value

    collection = resolve(policy.collection_result_ref, PolicyCollectionResult)
    if collection is not None and collection.meta.attempt_id != work.active_attempt_id:
        raise ValueError("POLICY_STATE_CLOSURE_MISMATCH: current attempt required")
    validate_run_policy(
        policy,
        collection,
        resolve(policy.policy_record_ref, ProgramPolicyRecord),
        started_at=state.started_at,
        cache=resolve(policy.policy_cache_ref, PolicyCacheRecord),
    )
    if publish:
        updated = AnalysisRunState.model_validate(
            state.model_dump()
            | dict(
                meta=next_meta(state.meta, works.clock, works.ids),
                run_policy_state_ref=reference(policy),
            )
        )
        save_run(works.records, connection, updated, state)
