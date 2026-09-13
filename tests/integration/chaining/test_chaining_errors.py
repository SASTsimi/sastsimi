from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi.chaining.service import (
    ChainingCallRefs,
    ChainingCallResolver,
    ChainingWorkflowService,
)
from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.ids import ProposalId
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.chaining import (
    ChainingAgentInput,
    ChainingAgentOutcome,
    ChainingAgentPort,
    ChainingResultPublisherPort,
    PinnedChainingUniverse,
)
from sastsimi.ports.dto import WorkContext
from sastsimi.ports.record_store import RecordStore
from tests.integration.chaining.test_true_hold_true_true import (
    _LLM_PROOF_REFS,
    _Agent,
    _Artifacts,
    _as_ref,
    _call_resolver,
    _Children,
    _context,
    _Ids,
    _Lineage,
    _metadata_factory,
    _Pools,
    _primitive,
    _Publisher,
    _Records,
)


class _FailedAgent(_Agent):
    def __init__(self) -> None:
        super().__init__(())

    async def match(
        self,
        *,
        context: WorkContext,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
        content: ChainingAgentInput,
    ) -> ChainingAgentOutcome:
        del context, decision_ref, reservation_ref, call_spec_ref, content
        return cast(
            ChainingAgentOutcome,
            SimpleNamespace(content=None, invocation=SimpleNamespace()),
        )


class _FailingPublisher(_Publisher):
    def publish(
        self,
        *,
        context: WorkContext,
        result: ChainingResult,
        action_input_refs: tuple[RecordRef, ...],
    ) -> WorkExecutionState:
        del context, action_input_refs
        self.result = result
        raise OSError("storage unavailable")


class _BadChildren(_Children):
    def enqueue_ready(
        self,
        *,
        source_result_ref: StoredDataRef,
        proposal_id: ProposalId,
        requester_identity_ref: BudgetScopeRef,
    ) -> WorkExecutionState:
        work = super().enqueue_ready(
            source_result_ref=source_result_ref,
            proposal_id=proposal_id,
            requester_identity_ref=requester_identity_ref,
        )
        return work.model_copy(
            update={"status": "RUNNING", "active_attempt_id": "unexpected"}
        )


def _service(
    agent: ChainingAgentPort,
    publisher: ChainingResultPublisherPort,
    children: _Children,
    *,
    omit_source_evidence: bool = False,
) -> tuple[ChainingWorkflowService, WorkContext]:
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
    records = _Records((trigger, other))
    if omit_source_evidence:
        records.values = {
            key: value
            for key, value in records.values.items()
            if key.data_kind != "verification_result"
        }
    return (
        ChainingWorkflowService(
            agent=agent,
            records=cast(RecordStore, records),
            artifacts=cast(ArtifactStore, _Artifacts()),
            pools=_Pools(reference(context.work), universe),  # type: ignore[arg-type]
            lineage=_Lineage({}),
            publisher=publisher,
            children=children,
            ids=_Ids(),
            metadata_factory=_metadata_factory,
            requester_identity_ref=_as_ref("requester_identity", "r"),
        ),
        context,
    )


def _resolver(*, prompt_hash: str) -> ChainingCallResolver:
    def resolve(
        _context: WorkContext,
        _content: ChainingAgentInput,
    ) -> tuple[ChainingCallRefs, str]:
        return (
            cast(
                ChainingCallRefs,
                SimpleNamespace(
                    decision_ref=_as_ref("action_decision", "decision"),
                    reservation_ref=_as_ref("budget_reservation", "reservation"),
                    call_spec_ref=_as_ref("llm_call_spec", "spec"),
                ),
            ),
            prompt_hash,
        )

    return cast(ChainingCallResolver, resolve)


@pytest.mark.asyncio
async def test_provider_failure_is_not_published_as_empty_no_match() -> None:
    publisher, children = _Publisher(), _Children()
    service, context = _service(_FailedAgent(), publisher, children)

    with pytest.raises(ValueError, match="CHAINING_AGENT_FAILED"):
        await service.execute(context=context, resolve_call=_call_resolver)

    assert publisher.result is None
    assert children.calls == []


@pytest.mark.asyncio
async def test_missing_exact_source_evidence_fails_before_agent_call() -> None:
    agent = _Agent(())
    publisher, children = _Publisher(), _Children()
    service, context = _service(
        agent,
        publisher,
        children,
        omit_source_evidence=True,
    )

    with pytest.raises(ValueError, match="CHAINING_EVIDENCE_REFERENCE_INVALID"):
        await service.execute(context=context, resolve_call=_call_resolver)

    assert agent.content is None
    assert publisher.result is None
    assert children.calls == []


@pytest.mark.asyncio
async def test_mismatched_prompt_binding_stops_before_agent_call() -> None:
    agent = _Agent(())
    publisher, children = _Publisher(), _Children()
    service, context = _service(agent, publisher, children)

    with pytest.raises(ValueError, match="CHAINING_PROMPT_CONTENT_MISMATCH"):
        await service.execute(
            context=context,
            resolve_call=_resolver(prompt_hash="f" * 64),
        )

    assert agent.content is None
    assert publisher.result is None
    assert children.calls == []


@pytest.mark.asyncio
async def test_storage_failure_never_hands_off_uncommitted_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sastsimi.chaining.service.llm_invocation_save_refs",
        lambda **_: _LLM_PROOF_REFS,
    )
    publisher, children = _FailingPublisher(), _Children()
    service, context = _service(_Agent(("comparison-1",)), publisher, children)

    with pytest.raises(OSError, match="storage unavailable"):
        await service.execute(context=context, resolve_call=_call_resolver)

    assert publisher.result is not None
    assert children.calls == []


@pytest.mark.asyncio
async def test_explicit_no_match_is_published_without_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sastsimi.chaining.service.llm_invocation_save_refs",
        lambda **_: _LLM_PROOF_REFS,
    )
    publisher, children = _Publisher(), _Children()
    service, context = _service(_Agent(()), publisher, children)

    outcome = await service.execute(
        context=context,
        resolve_call=_call_resolver,
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
        lambda **_: _LLM_PROOF_REFS,
    )
    publisher, children = _Publisher(), _BadChildren()
    service, context = _service(_Agent(("comparison-1",)), publisher, children)

    with pytest.raises(ValueError, match="CHAINING_CHILD_NOT_READY"):
        await service.execute(
            context=context,
            resolve_call=_call_resolver,
        )

    assert publisher.result is not None
