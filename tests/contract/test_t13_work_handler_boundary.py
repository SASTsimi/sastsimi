from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.work import WorkAttempt, WorkExecutionState
from sastsimi.ports.dto import WorkContext
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import wire


def _context(work_type: str) -> WorkContext:
    meta_data = make("WorkExecutionState")["meta"] | {
        "attempt_id": None,
        "hypothesis_id": None,
    }
    meta = wire(RecordMeta, meta_data)
    input_hash = content_hash(())
    work = WorkExecutionState.model_construct(
        meta=meta,
        work_id="work-1",
        work_type=work_type,
        status="RUNNING",
        active_attempt_id="at-running",
        input_refs=(),
        input_hash=input_hash,
    )
    attempt = WorkAttempt.model_construct(
        meta=meta.model_copy(update={"attempt_id": "at-running"}),
        work_id="work-1",
        attempt_id="at-running",
        input_hash=input_hash,
        status="RUNNING",
    )
    return WorkContext(work=work, attempt=attempt)


@pytest.mark.parametrize("work_type", ["CHAINING", "HYPOTHESIS_PROPOSAL"])
def test_handler_boundary_accepts_only_claimed_current_context(work_type: str) -> None:
    from sastsimi.chaining.work_handlers import require_claimed_context

    context = _context(work_type)

    require_claimed_context(context, work_type)
    stale = WorkContext(
        work=context.work,
        attempt=context.attempt.model_copy(update={"input_hash": "f" * 64}),
    )
    with pytest.raises(ValueError, match="WORK_CONTEXT_NOT_CURRENT"):
        require_claimed_context(stale, work_type)


def test_lane_d_has_no_inline_execution_or_concrete_adapter_imports() -> None:
    from sastsimi.chaining import work_handlers
    from sastsimi.runtime import chaining_child_registration, chaining_reconciliation

    modules = (work_handlers, chaining_child_registration, chaining_reconciliation)
    forbidden_calls = (
        ".start(",
        ".activate(",
        ".claim(",
        "AttemptService",
        "WorkflowRunner",
    )
    forbidden_imports = (
        "sastsimi.storage",
        "sastsimi.providers",
        "sastsimi.reporting",
        "sastsimi.verification.fake_child_registration",
    )
    for module in modules:
        source = inspect.getsource(module)
        assert all(value not in source for value in forbidden_calls)
        assert all(value not in source for value in forbidden_imports)

    service_source = Path("src/sastsimi/chaining/service.py").read_text(
        encoding="utf-8"
    )
    assert all(value not in service_source for value in forbidden_imports)
    assert "self._publisher.publish(" in service_source
    assert "reserve_for_result(" not in service_source
    child_source = Path(
        "src/sastsimi/runtime/chaining_child_registration.py"
    ).read_text(encoding="utf-8")
    assert "ReadyWorkPort" in child_source
    assert "from sastsimi.ports.ready_work" not in child_source
