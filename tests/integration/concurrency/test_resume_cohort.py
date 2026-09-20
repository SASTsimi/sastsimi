"""Resume admission fails closed for a whole durable blocked cohort."""

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from threading import Event

import pytest
from sqlalchemy import Connection, insert, select, update

from sastsimi.contracts.ids import WorkId
from sastsimi.contracts.refs import RunStoredDataRef, reference
from sastsimi.contracts.work import WaitingFor, WorkAttempt, WorkExecutionState
from sastsimi.storage import models
from sastsimi.storage.records import next_meta
from sastsimi.storage.run_control import RunControlStore
from sastsimi.storage.run_states import save_run
from sastsimi.storage.work_dispatch import _resume_reason_is_resolvable
from tests.integration.concurrency.test_atomic_dispatch import (
    _block_for_resume,
    _dispatch,
    _ready_work,
    _run_state_ref,
    _start_attempt_rows,
)
from tests.integration.runtime_support import NOW


def test_local_dynamic_provider_input_failure_is_resumable() -> None:
    work = type(
        "BlockedWork",
        (),
        {
            "work_type": "DYNAMIC_REPRO",
            "stop_reason": "WORK_HANDLER_FAILED",
            "waiting_for": ("INPUT",),
        },
    )()

    assert _resume_reason_is_resolvable("LOCAL_EVALUATION", work)


def test_production_dynamic_provider_input_failure_stays_blocked() -> None:
    work = type(
        "BlockedWork",
        (),
        {
            "work_type": "DYNAMIC_REPRO",
            "stop_reason": "WORK_HANDLER_FAILED",
            "waiting_for": ("INPUT",),
        },
    )()

    assert not _resume_reason_is_resolvable("PRODUCTION", work)


@pytest.mark.parametrize(
    "case",
    ["retry", "missing", "ready", "running", "lease", "dispatch", "prepared"],
)
def test_resume_rejects_incomplete_or_nonquiescent_cohort(
    tmp_path: Path, case: str
) -> None:
    harness, runtime, ready = _ready_work(
        tmp_path, parallel=2, count=2, total_retries=1 if case == "retry" else None
    )
    dispatch, first, first_attempt = _block_for_resume(
        harness, runtime, ready[0], "worker-1"
    )
    candidates: tuple[tuple[WorkExecutionState, WorkAttempt], ...] = (
        (first, first_attempt),
    )
    if case not in {"ready", "running"}:
        _, second, second_attempt = _block_for_resume(
            harness, runtime, ready[1], "worker-2"
        )
        if case != "missing":
            candidates += ((second, second_attempt),)
    elif case == "running":
        assert (
            dispatch.try_claim_ready(
                "a1",
                str(ready[1].work_id),
                ready[1].state_version,
                "worker-2",
                NOW + timedelta(seconds=30),
            )
            is not None
        )
    with harness.database.write() as connection:
        if case == "lease":
            connection.execute(
                update(models.work_states)
                .where(models.work_states.c.work_id == str(ready[1].work_id))
                .values(worker_id="stale-worker", lease_expires_at=NOW.isoformat())
            )
        elif case == "dispatch":
            connection.execute(
                insert(models.external_dispatches).values(
                    action_id="unresolved",
                    work_id=str(ready[1].work_id),
                    attempt_id=str(candidates[1][1].attempt_id),
                    decision_ref="{}",
                    reservation_ref="{}",
                    prepared_at=NOW.isoformat(),
                    dispatched_at=NOW.isoformat(),
                )
            )
        elif case == "prepared":
            connection.execute(
                insert(models.transition_commits).values(
                    transition_commit_id="pending",
                    work_id=str(first.work_id),
                    expected_state_version=first.state_version,
                    candidate_binding="pending",
                    state="PREPARED",
                    payload="{}",
                    request="{}",
                )
            )
    before = dispatch.work_for_run("a1")
    budget_before = _start_attempt_rows(harness)
    with pytest.raises(ValueError):
        dispatch.resume_blocked(
            expected_run_state_ref=_run_state_ref(runtime),
            candidates=candidates,
        )
    assert dispatch.work_for_run("a1") == before
    assert _start_attempt_rows(harness) == budget_before


@pytest.mark.parametrize("reason", ["UNKNOWN", "AUTHORITY_DENIED", "RECOVERY_FAILED"])
def test_resume_rejects_unapproved_stop_reason(tmp_path: Path, reason: str) -> None:
    harness, runtime, (ready,) = _ready_work(tmp_path)
    dispatch, blocked, attempt = _block_for_resume(
        harness, runtime, ready, "worker", reason=reason
    )
    with pytest.raises(ValueError, match="RESUME_REASON_NOT_RESOLVABLE"):
        dispatch.resume_blocked(
            expected_run_state_ref=_run_state_ref(runtime),
            candidates=((blocked, attempt),),
        )
    assert runtime.work.get(str(blocked.work_id)) == blocked


@pytest.mark.parametrize("case", ["duplicate", "extra"])
def test_resume_rejects_duplicate_or_extra_member(tmp_path: Path, case: str) -> None:
    harness, runtime, (ready,) = _ready_work(tmp_path)
    dispatch, blocked, attempt = _block_for_resume(harness, runtime, ready, "worker")
    extra = (
        blocked
        if case == "duplicate"
        else blocked.model_copy(update={"work_id": WorkId("extra-work")})
    )
    with pytest.raises(ValueError):
        dispatch.resume_blocked(
            ((blocked, attempt), (extra, attempt)),
            expected_run_state_ref=_run_state_ref(runtime),
        )
    assert runtime.work.get(str(blocked.work_id)) == blocked


def test_resume_replay_creates_no_revision_or_budget_charge(tmp_path: Path) -> None:
    harness, runtime, (ready,) = _ready_work(tmp_path)
    dispatch, blocked, attempt = _block_for_resume(harness, runtime, ready, "worker")
    request = ((blocked, attempt),)
    result = dispatch.resume_blocked(
        expected_run_state_ref=_run_state_ref(runtime),
        candidates=request,
    )
    with harness.database.engine.connect() as connection:
        before = connection.execute(select(models.records.c.record_id)).all()
    assert (
        dispatch.resume_blocked(
            expected_run_state_ref=_run_state_ref(runtime),
            candidates=request,
        )
        == result
    )
    with harness.database.engine.connect() as connection:
        assert connection.execute(select(models.records.c.record_id)).all() == before
    assert _start_attempt_rows(harness) == (1, 1, 0)


def test_resume_replay_rejects_changed_projected_work_version(tmp_path: Path) -> None:
    harness, runtime, (ready,) = _ready_work(tmp_path)
    dispatch, blocked, attempt = _block_for_resume(harness, runtime, ready, "worker")
    expected = _run_state_ref(runtime)
    dispatch.resume_blocked(((blocked, attempt),), expected_run_state_ref=expected)
    with harness.database.write() as connection:
        connection.execute(
            update(models.work_states)
            .where(models.work_states.c.work_id == str(blocked.work_id))
            .values(state_version=blocked.state_version + 2)
        )
    with pytest.raises(ValueError):
        dispatch.resume_blocked(((blocked, attempt),), expected_run_state_ref=expected)


def test_resume_rollback_retains_all_blocked_revisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness, runtime, ready = _ready_work(tmp_path, parallel=2, count=2)
    dispatch, first, first_attempt = _block_for_resume(harness, runtime, ready[0], "w1")
    _, second, second_attempt = _block_for_resume(harness, runtime, ready[1], "w2")
    original = dispatch.works.save

    def fail_second(
        connection: Connection, old: WorkExecutionState, new: WorkExecutionState
    ) -> None:
        if old.work_id == second.work_id:
            raise ValueError("injected failure")
        original(connection, old, new)

    monkeypatch.setattr(dispatch.works, "save", fail_second)
    with pytest.raises(ValueError, match="injected failure"):
        dispatch.resume_blocked(
            expected_run_state_ref=_run_state_ref(runtime),
            candidates=((first, first_attempt), (second, second_attempt)),
        )
    assert runtime.work.get(str(first.work_id)) == first
    assert runtime.work.get(str(second.work_id)) == second
    assert _start_attempt_rows(harness) == (2, 2, 0)


@pytest.mark.parametrize("case", ["run", "attempt", "work", "generation", "waiting"])
def test_resume_requires_current_exact_published_context(
    tmp_path: Path, case: str
) -> None:
    harness, runtime, (ready,) = _ready_work(tmp_path)
    dispatch, blocked, attempt = _block_for_resume(harness, runtime, ready, "worker")
    with harness.database.write() as connection:
        if case == "run":
            state = runtime.budget_registry.current_state("a1")
            connection.execute(
                update(models.current_records)
                .where(
                    models.current_records.c.logical_record_id
                    == str(state.meta.logical_record_id)
                )
                .values(record_id=str(ready.meta.record_id))
            )
        elif case == "attempt":
            attempt = attempt.model_copy(update={"elapsed_ms": 1})
            connection.execute(
                update(models.work_attempts)
                .where(models.work_attempts.c.attempt_id == str(attempt.attempt_id))
                .values(payload=attempt.model_dump_json())
            )
        elif case == "work":
            connection.execute(
                update(models.current_records)
                .where(
                    models.current_records.c.logical_record_id
                    == str(blocked.meta.logical_record_id)
                )
                .values(record_id=str(ready.meta.record_id))
            )
        else:
            changed = blocked.model_copy(
                update={
                    "meta": next_meta(blocked.meta, harness.clock, harness.ids),
                    "state_version": blocked.state_version + 1,
                    **(
                        {"work_generation": 2}
                        if case == "generation"
                        else {"waiting_for": (WaitingFor.BUDGET,)}
                    ),
                }
            )
            changed = WorkExecutionState.model_validate_json(changed.model_dump_json())
            dispatch.works.save(connection, blocked, changed)
            blocked = changed
    with pytest.raises(ValueError):
        dispatch.resume_blocked(
            expected_run_state_ref=_run_state_ref(runtime),
            candidates=((blocked, attempt),),
        )
    assert runtime.work.get(str(blocked.work_id)) == blocked


def test_resume_rejects_changed_run_revision_with_unchanged_work(
    tmp_path: Path,
) -> None:
    harness, runtime, (ready,) = _ready_work(tmp_path)
    dispatch, blocked, attempt = _block_for_resume(harness, runtime, ready, "worker")
    observed = runtime.budget_registry.current_state("a1")
    updated = observed.model_copy(
        update={
            "meta": next_meta(observed.meta, harness.clock, harness.ids),
            "elapsed_ms": 1,
        }
    )
    with harness.database.write() as connection:
        save_run(harness.records, connection, updated, observed)
    observed_ref = reference(observed)
    assert isinstance(observed_ref, RunStoredDataRef)
    with pytest.raises(ValueError):
        dispatch.resume_blocked(
            expected_run_state_ref=observed_ref, candidates=((blocked, attempt),)
        )
    assert runtime.work.get(str(blocked.work_id)) == blocked


def test_resume_rejects_work_outside_current_hypothesis_generation(
    tmp_path: Path,
) -> None:
    from tests.integration.storage.test_hypothesis_projection import prepared_hypothesis

    h, runtime, runner, identity, _, _ = prepared_hypothesis(tmp_path)
    (hypothesis,) = runtime.queries.current_records("a1", "vulnerability_hypothesis")
    (process,) = runtime.queries.current_records("a1", "hypothesis_process_state")
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    assert scope is not None
    work = runner.start(
        scope,
        hypothesis.meta,
        "STATIC_NORMALIZE",
        "HYPOTHESIS",
        str(hypothesis.meta.hypothesis_id),
        identity,
    )
    blocked = runner.block(work, identity, "WAITING_FOR_INPUT")
    assert blocked.work_generation != process.verification_generation
    dispatch = _dispatch(runtime)
    attempt = dispatch.attempts_for_work(str(blocked.work_id))[-1]
    with pytest.raises(ValueError, match="GENERATION"):
        dispatch.resume_blocked(
            ((blocked, attempt),), expected_run_state_ref=_run_state_ref(runtime)
        )
    assert runtime.work.get(str(blocked.work_id)) == blocked


def test_resumed_claim_keeps_prior_attempt_immutable(tmp_path: Path) -> None:
    harness, runtime, (ready,) = _ready_work(tmp_path)
    dispatch, blocked, attempt = _block_for_resume(harness, runtime, ready, "worker")
    (resumed,) = dispatch.resume_blocked(
        expected_run_state_ref=_run_state_ref(runtime),
        candidates=((blocked, attempt),),
    )
    assert _start_attempt_rows(harness) == (1, 1, 0)
    claimed = dispatch.try_claim_ready(
        "a1",
        str(resumed.work_id),
        resumed.state_version,
        "resumed-worker",
        NOW + timedelta(seconds=30),
    )
    assert claimed is not None
    assert claimed.attempt.trigger == "RESUME"
    assert claimed.attempt.attempt_number == 2
    assert harness.records.get_exact(reference(attempt)) == attempt
    assert dispatch.attempts_for_work(str(blocked.work_id)) == (
        attempt,
        claimed.attempt,
    )


@pytest.mark.parametrize("replay", [False, True])
def test_resume_rechecks_durable_budget_pin_even_on_replay(
    tmp_path: Path, replay: bool
) -> None:
    harness, runtime, (ready,) = _ready_work(tmp_path)
    dispatch, blocked, attempt = _block_for_resume(harness, runtime, ready, "worker")
    if replay:
        dispatch.resume_blocked(
            expected_run_state_ref=_run_state_ref(runtime),
            candidates=((blocked, attempt),),
        )
    before = dispatch.work_for_run("a1")
    with harness.database.write() as connection:
        connection.execute(
            update(models.budget_profiles)
            .where(models.budget_profiles.c.analysis_id == "a1")
            .values(ref="{}")
        )
    with pytest.raises(ValueError):
        dispatch.resume_blocked(
            expected_run_state_ref=_run_state_ref(runtime),
            candidates=((blocked, attempt),),
        )
    assert dispatch.work_for_run("a1") == before


def test_cancellation_committed_before_resume_admission_wins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness, runtime, (ready,) = _ready_work(tmp_path)
    dispatch, blocked, attempt = _block_for_resume(harness, runtime, ready, "worker")
    waiting, release = Event(), Event()
    database = dispatch.works.records.database
    original = database.write

    @contextmanager
    def delayed_write() -> Iterator[Connection]:
        waiting.set()
        assert release.wait(5)
        with original() as connection:
            yield connection

    monkeypatch.setattr(database, "write", delayed_write)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            dispatch.resume_blocked,
            ((blocked, attempt),),
            expected_run_state_ref=_run_state_ref(runtime),
        )
        assert waiting.wait(5)
        try:
            RunControlStore(harness.database, harness.clock).request_cancel(
                "a1", "USER_REQUEST"
            )
        finally:
            release.set()
        with pytest.raises(ValueError, match="RUN_CANCELLED"):
            future.result(timeout=5)
    assert runtime.work.get(str(blocked.work_id)) == blocked


# mypy: disable-error-code="arg-type"
