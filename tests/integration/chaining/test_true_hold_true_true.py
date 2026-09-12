from __future__ import annotations

from types import SimpleNamespace

import pytest

from sastsimi.chaining.service import ChainingWorkflowService
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.chaining import Primitive
from sastsimi.contracts.ids import OpaqueId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import WorkAttempt, WorkExecutionState
from sastsimi.ports.chaining import (
    ChainedHypothesisContent,
    ChainingAgentOutput,
    ChainingDecision,
    ChainingPoolHistory,
    PinnedChainingUniverse,
)
from sastsimi.ports.dto import WorkContext
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import location, meta, ref, wire


def _stored(kind: str, name: str) -> dict[str, object]:
    return ref(kind) | {
        "stored_data_id": f"stored-{kind}-{name}",
        "record_id": f"{kind}-{name}",
        "content_hash": content_hash([kind, name]),
    }


def _symbol(name: str) -> dict[str, object]:
    return {
        "symbol_id": f"symbol-{name}",
        "symbol_kind": "CALLABLE",
        "native_kind": "function",
        "name": name,
        "location": location() | {"file_path": f"src/{name}.py"},
    }


def _draft(name: str) -> dict[str, object]:
    return {
        "draft_id": f"draft-{name}",
        "entity_refs": [_symbol(name)],
        "privilege_level": None,
        "evidence_refs": [_stored("code", name) | {"record_id": None}],
        "description": f"capability {name}",
    }


def _primitive(
    name: str,
    *,
    inputs: tuple[str, ...],
    result: str | None,
) -> Primitive:
    evidence = _stored("code", name) | {"record_id": None}
    data = {
        "meta": meta("primitive", hypothesis=f"hyp-{name}")
        | {
            "record_id": f"primitive-{name}",
            "logical_record_id": f"primitive-logical-{name}",
        },
        "primitive_id": f"primitive-{name}",
        "workspace_id": "ws1",
        "commit_id": "c1",
        "inputs": [_draft(value) for value in inputs],
        "result": _draft(result) if result else None,
        "restrictions": [],
        "source_hypothesis_id": f"hyp-{name}",
        "source_verification_ref": _stored("verification_result", name),
        "technical_review_ref": (
            _stored("technical_evidence_review", name) if result else None
        ),
        "admission_decision_ref": (
            _stored("primitive_admission_decision", name) if result else None
        ),
        "evidence_refs": [evidence],
        "description": f"primitive {name}",
    }
    return wire(Primitive, data)


def _context(refs: tuple[StoredDataRef, ...], trigger: StoredDataRef) -> WorkContext:
    inputs = (_as_ref("primitive_index_state", "index"), *refs)
    serialized_inputs = [value.model_dump(mode="json") for value in inputs]
    work_data = make("WorkExecutionState") | {
        "meta": meta("work_execution_state", hypothesis=None, attempt=None),
        "work_id": "chain-work",
        "work_type": "CHAINING",
        "subject_type": "ANALYSIS",
        "subject_id": "a1",
        "status": "RUNNING",
        "state_version": 2,
        "last_transition_ref": _stored("state_transition", "run"),
        "last_transition_commit_ref": None,
        "active_attempt_id": "chain-attempt",
        "input_hash": content_hash(inputs),
        "dedupe_key": content_hash(["chain-work", inputs]),
        "trigger_primitive_ref": trigger.model_dump(mode="json"),
        "input_refs": serialized_inputs,
        "started_at": "2026-09-08T00:00:00Z",
    }
    work = wire(WorkExecutionState, work_data)
    attempt_data = make("WorkAttempt") | {
        "meta": meta("work_attempt", hypothesis=None, attempt="chain-attempt"),
        "work_id": "chain-work",
        "attempt_id": "chain-attempt",
        "input_hash": content_hash(inputs),
    }
    return WorkContext(work, wire(WorkAttempt, attempt_data))


def _as_ref(kind: str, name: str) -> StoredDataRef:
    return StoredDataRef.model_validate(_stored(kind, name))


class _Records:
    def __init__(self, primitives: tuple[Primitive, ...]) -> None:
        self.values = {reference(value): value for value in primitives}

    def get_exact(self, value: object) -> object:
        return self.values[value]


class _Pools:
    def __init__(
        self, work_ref: StoredDataRef, universe: PinnedChainingUniverse
    ) -> None:
        self.current = ChainingPoolHistory(work_ref, universe)
        self.others = {
            primitive_ref: ChainingPoolHistory(
                _as_ref("work_execution_state", str(index)),
                PinnedChainingUniverse(
                    trigger_primitive_ref=primitive_ref,
                    index_refs=universe.index_refs,
                    considered_primitive_refs=(primitive_ref,),
                ),
            )
            for index, primitive_ref in enumerate(
                universe.considered_primitive_refs, start=1
            )
            if primitive_ref != universe.trigger_primitive_ref
        }

    def get_for_trigger(self, trigger_work_ref: StoredDataRef) -> ChainingPoolHistory:
        assert trigger_work_ref == self.current.trigger_work_ref
        return self.current

    def get_for_primitive(
        self, trigger_primitive_ref: StoredDataRef
    ) -> ChainingPoolHistory:
        return self.others[trigger_primitive_ref]


class _Lineage:
    def __init__(self, parents: dict[StoredDataRef, tuple[StoredDataRef, ...]]) -> None:
        self.parents = parents

    def ancestors(
        self, *, primitive_ref: StoredDataRef, universe: object
    ) -> tuple[StoredDataRef, ...]:
        del universe
        return self.parents.get(primitive_ref, ())


class _Ids:
    def __init__(self) -> None:
        self.value = 0

    def new(self, kind: type[OpaqueId]) -> OpaqueId:
        self.value += 1
        return kind(f"generated-{self.value}")


class _Agent:
    def __init__(self, match_comparisons: tuple[str, ...]) -> None:
        self.match_comparisons = match_comparisons

    async def match(self, **kwargs: object) -> object:
        content = kwargs["content"]
        decisions = tuple(
            ChainingDecision(
                comparison_key=item.comparison_key,
                outcome="MATCH"
                if item.comparison_key in self.match_comparisons
                else "NO_MATCH",
                reason_code=(
                    None
                    if item.comparison_key in self.match_comparisons
                    else "ENTITY_UNRELATED"
                ),
                detail="compatible"
                if item.comparison_key in self.match_comparisons
                else "unrelated",
                evidence_keys=(content.evidence[0].evidence_key,),
                child=(
                    ChainedHypothesisContent(
                        statement="Combined path may be exploitable",
                        vulnerability_type_candidates=("CHAIN",),
                        falsification_questions=("Can the path be blocked?",),
                        validation_checks=("Validate the complete path",),
                    )
                    if item.comparison_key in self.match_comparisons
                    else None
                ),
            )
            for item in content.comparisons
        )
        return SimpleNamespace(
            content=ChainingAgentOutput(decisions),
            invocation=SimpleNamespace(),
        )


class _Publisher:
    def __init__(self) -> None:
        self.result = None

    def publish(
        self,
        *,
        context: WorkContext,
        result: object,
        action_input_refs: tuple[object, ...],
    ) -> WorkExecutionState:
        assert action_input_refs == ("llm-proof",)
        self.result = result
        return context.work.model_copy(
            update={
                "status": "SUCCEEDED",
                "active_attempt_id": None,
                "output_refs": (reference(result),),
            }
        )


class _Children:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def enqueue_ready(self, **kwargs: object) -> WorkExecutionState:
        proposal_id = str(kwargs["proposal_id"])
        self.calls.append(proposal_id)
        return WorkExecutionState.model_construct(
            work_id=f"child-{proposal_id}",
            work_type="HYPOTHESIS_PROPOSAL",
            subject_type="PROPOSAL",
            subject_id=proposal_id,
            status="READY",
            active_attempt_id=None,
            output_refs=(),
        )


def _metadata(source: RecordMeta, kind: str, attempt_id: object) -> RecordMeta:
    _metadata.value += 1
    return source.model_copy(
        update={
            "record_id": f"{kind}-{_metadata.value}",
            "logical_record_id": f"{kind}-logical-{_metadata.value}",
            "record_type": kind,
            "attempt_id": attempt_id,
        }
    )


_metadata.value = 0


@pytest.mark.asyncio
@pytest.mark.parametrize("hold_trigger", [False, True])
async def test_true_hold_and_true_true_create_child_only_after_commit(
    monkeypatch: pytest.MonkeyPatch,
    hold_trigger: bool,
) -> None:
    monkeypatch.setattr(
        "sastsimi.chaining.service.llm_invocation_save_refs",
        lambda **_: ("llm-proof",),
    )
    trigger = _primitive(
        "A",
        inputs=("needed",) if hold_trigger else (),
        result=None if hold_trigger else "provided",
    )
    other = _primitive(
        "B",
        inputs=() if hold_trigger else ("needed",),
        result="provided",
    )
    refs = tuple(reference(value) for value in (trigger, other))
    assert all(isinstance(value, StoredDataRef) for value in refs)
    context = _context(refs, refs[0])  # type: ignore[arg-type]
    universe = PinnedChainingUniverse(
        trigger_primitive_ref=refs[0],  # type: ignore[arg-type]
        index_refs=(_as_ref("primitive_index_state", "index"),),
        considered_primitive_refs=refs,  # type: ignore[arg-type]
    )
    publisher, children = _Publisher(), _Children()
    service = ChainingWorkflowService(
        agent=_Agent(("comparison-1",)),
        records=_Records((trigger, other)),
        pools=_Pools(reference(context.work), universe),  # type: ignore[arg-type]
        lineage=_Lineage({}),
        publisher=publisher,
        children=children,
        ids=_Ids(),
        metadata_factory=_metadata,
        requester_identity_ref=_as_ref("requester_identity", "r"),
    )

    outcome = await service.execute(
        context=context,
        call=SimpleNamespace(
            decision_ref=_as_ref("action_decision", "decision"),
            reservation_ref=_as_ref("budget_reservation", "reservation"),
            call_spec_ref=_as_ref("llm_call_spec", "spec"),
        ),
    )

    assert len(outcome.result.primitive_match_candidates) == 1
    assert len(outcome.result.chained_hypothesis_proposals) == 1
    assert publisher.result is outcome.result
    assert children.calls == [
        str(outcome.result.chained_hypothesis_proposals[0].proposal_id)
    ]


@pytest.mark.asyncio
async def test_one_call_keeps_deepest_success_and_ignores_ancestor_decisions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sastsimi.chaining.service.llm_invocation_save_refs",
        lambda **_: ("llm-proof",),
    )
    values = (
        _primitive("A", inputs=(), result="a"),
        _primitive("B", inputs=("a",), result="b"),
        _primitive("BC", inputs=("a",), result="bc"),
        _primitive("BCD", inputs=("a",), result="bcd"),
    )
    refs = tuple(reference(value) for value in values)
    context = _context(refs, refs[0])  # type: ignore[arg-type]
    universe = PinnedChainingUniverse(
        trigger_primitive_ref=refs[0],  # type: ignore[arg-type]
        index_refs=(_as_ref("primitive_index_state", "index"),),
        considered_primitive_refs=refs,  # type: ignore[arg-type]
    )
    publisher, children = _Publisher(), _Children()
    service = ChainingWorkflowService(
        agent=_Agent(("comparison-1", "comparison-2", "comparison-3")),
        records=_Records(values),
        pools=_Pools(reference(context.work), universe),  # type: ignore[arg-type]
        lineage=_Lineage(  # type: ignore[arg-type]
            {refs[2]: (refs[1],), refs[3]: (refs[2], refs[1])}
        ),
        publisher=publisher,
        children=children,
        ids=_Ids(),
        metadata_factory=_metadata,
        requester_identity_ref=_as_ref("requester_identity", "r"),
    )

    outcome = await service.execute(
        context=context,
        call=SimpleNamespace(
            decision_ref=_as_ref("action_decision", "decision"),
            reservation_ref=_as_ref("budget_reservation", "reservation"),
            call_spec_ref=_as_ref("llm_call_spec", "spec"),
        ),
    )

    assert len(outcome.result.primitive_match_candidates) == 1
    assert outcome.result.primitive_match_candidates[0].downstream_input_ref == refs[3]
    assert {
        item.excluded_primitive_ref for item in outcome.result.excluded_lineage_refs
    } == {refs[1], refs[2]}
    assert len(children.calls) == 1
