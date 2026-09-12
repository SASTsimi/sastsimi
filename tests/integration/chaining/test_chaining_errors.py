from __future__ import annotations

from types import SimpleNamespace

import pytest

from sastsimi.chaining.service import ChainingWorkflowService
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.chaining import PinnedChainingUniverse
from tests.integration.chaining.test_true_hold_true_true import (
    _Agent,
    _as_ref,
    _Children,
    _context,
    _Ids,
    _Lineage,
    _metadata,
    _Pools,
    _primitive,
    _Publisher,
    _Records,
)


class _FailedAgent:
    async def match(self, **kwargs: object) -> object:
        del kwargs
        return SimpleNamespace(content=None, invocation=SimpleNamespace())


class _FailingPublisher(_Publisher):
    def publish(self, **kwargs: object) -> object:
        self.result = kwargs["result"]
        raise OSError("storage unavailable")


class _BadChildren(_Children):
    def enqueue_ready(self, **kwargs: object) -> object:
        work = super().enqueue_ready(**kwargs)
        return work.model_copy(
            update={"status": "RUNNING", "active_attempt_id": "unexpected"}
        )


def _service(
    agent: object, publisher: object, children: _Children
) -> tuple[ChainingWorkflowService, object]:
    trigger = _primitive("A", inputs=(), result="provided")
    other = _primitive("B", inputs=("provided",), result="next")
    refs = tuple(reference(value) for value in (trigger, other))
    assert all(isinstance(ref, StoredDataRef) for ref in refs)
    context = _context(refs, refs[0])  # type: ignore[arg-type]
    universe = PinnedChainingUniverse(
        trigger_primitive_ref=refs[0],  # type: ignore[arg-type]
        index_refs=(_as_ref("primitive_index_state", "index"),),
        considered_primitive_refs=refs,  # type: ignore[arg-type]
    )
    return (
        ChainingWorkflowService(
            agent=agent,  # type: ignore[arg-type]
            records=_Records((trigger, other)),
            pools=_Pools(reference(context.work), universe),  # type: ignore[arg-type]
            lineage=_Lineage({}),
            publisher=publisher,  # type: ignore[arg-type]
            children=children,
            ids=_Ids(),
            metadata_factory=_metadata,
            requester_identity_ref=_as_ref("requester_identity", "r"),
        ),
        context,
    )


def _call() -> object:
    return SimpleNamespace(
        decision_ref=_as_ref("action_decision", "decision"),
        reservation_ref=_as_ref("budget_reservation", "reservation"),
        call_spec_ref=_as_ref("llm_call_spec", "spec"),
    )


@pytest.mark.asyncio
async def test_provider_failure_is_not_published_as_empty_no_match() -> None:
    publisher, children = _Publisher(), _Children()
    service, context = _service(_FailedAgent(), publisher, children)

    with pytest.raises(ValueError, match="CHAINING_AGENT_FAILED"):
        await service.execute(context=context, call=_call())  # type: ignore[arg-type]

    assert publisher.result is None
    assert children.calls == []


@pytest.mark.asyncio
async def test_storage_failure_never_hands_off_uncommitted_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sastsimi.chaining.service.llm_invocation_save_refs",
        lambda **_: ("llm-proof",),
    )
    publisher, children = _FailingPublisher(), _Children()
    service, context = _service(_Agent(("comparison-1",)), publisher, children)

    with pytest.raises(OSError, match="storage unavailable"):
        await service.execute(context=context, call=_call())  # type: ignore[arg-type]

    assert publisher.result is not None
    assert children.calls == []


@pytest.mark.asyncio
async def test_explicit_no_match_is_published_without_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sastsimi.chaining.service.llm_invocation_save_refs",
        lambda **_: ("llm-proof",),
    )
    publisher, children = _Publisher(), _Children()
    service, context = _service(_Agent(()), publisher, children)

    outcome = await service.execute(
        context=context,  # type: ignore[arg-type]
        call=_call(),  # type: ignore[arg-type]
    )

    assert outcome.result.primitive_match_candidates == ()
    assert len(outcome.result.no_match_reasons) == 1
    assert children.calls == []


@pytest.mark.asyncio
async def test_child_handoff_must_stop_at_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sastsimi.chaining.service.llm_invocation_save_refs",
        lambda **_: ("llm-proof",),
    )
    publisher, children = _Publisher(), _BadChildren()
    service, context = _service(_Agent(("comparison-1",)), publisher, children)

    with pytest.raises(ValueError, match="CHAINING_CHILD_NOT_READY"):
        await service.execute(
            context=context,  # type: ignore[arg-type]
            call=_call(),  # type: ignore[arg-type]
        )

    assert publisher.result is not None
