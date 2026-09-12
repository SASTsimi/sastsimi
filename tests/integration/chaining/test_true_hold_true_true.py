from __future__ import annotations

import hashlib
from io import BytesIO
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.chaining.service import ChainingWorkflowService, chaining_input_hash
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.chaining import Primitive
from sastsimi.contracts.gates import TechnicalEvidenceReview
from sastsimi.contracts.ids import OpaqueId, StoredDataId, WorkspaceId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkAttempt, WorkExecutionState
from sastsimi.ports.artifact_store import ArtifactStore
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


def _draft(
    name: str, evidence_ref: StoredDataRef | None = None
) -> dict[str, object]:
    evidence = (
        evidence_ref.model_dump(mode="json")
        if evidence_ref is not None
        else _stored("code", name) | {"record_id": None}
    )
    return {
        "draft_id": f"draft-{name}",
        "entity_refs": [_symbol(name)],
        "privilege_level": None,
        "evidence_refs": [evidence],
        "description": f"capability {name}",
    }


def _primitive(
    name: str,
    *,
    inputs: tuple[str, ...],
    result: str | None,
) -> Primitive:
    verification = _verification(
        name,
        rationale=f"Verified capability and constraints for primitive {name}",
        final_true=result is not None,
    )
    verification_ref = reference(verification)
    assert isinstance(verification_ref, StoredDataRef)
    technical = _technical(name, verification_ref) if result is not None else None
    technical_ref = reference(technical) if technical is not None else None
    data = {
        "meta": meta("primitive", hypothesis=f"hyp-{name}")
        | {
            "record_id": f"primitive-{name}",
            "logical_record_id": f"primitive-logical-{name}",
        },
        "primitive_id": f"primitive-{name}",
        "workspace_id": "ws1",
        "commit_id": "c1",
        "inputs": [_draft(value, verification_ref) for value in inputs],
        "result": _draft(result, verification_ref) if result else None,
        "restrictions": [],
        "source_hypothesis_id": f"hyp-{name}",
        "source_verification_ref": verification_ref.model_dump(mode="json"),
        "technical_review_ref": (
            technical_ref.model_dump(mode="json") if technical_ref else None
        ),
        "admission_decision_ref": (
            _stored("primitive_admission_decision", name) if result else None
        ),
        "evidence_refs": [verification_ref.model_dump(mode="json")],
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
    def __init__(self, records: tuple[object, ...]) -> None:
        self.values = {reference(value): value for value in records}  # type: ignore[arg-type]
        for value in records:
            if not isinstance(value, Primitive):
                continue
            name = str(value.primitive_id).removeprefix("primitive-")
            verification = _verification(
                name,
                rationale=f"Verified capability and constraints for primitive {name}",
                final_true=value.result is not None,
            )
            verification_ref = reference(verification)
            if verification_ref == value.source_verification_ref:
                self.values.setdefault(verification_ref, verification)
            if value.technical_review_ref is not None:
                technical = _technical(name, value.source_verification_ref)
                technical_ref = reference(technical)
                if technical_ref == value.technical_review_ref:
                    self.values.setdefault(technical_ref, technical)

    def get_exact(self, value: object) -> object:
        return self.values[value]


class _Artifacts:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def add(self, data: bytes) -> StoredDataRef:
        digest = hashlib.sha256(data).hexdigest()
        self.values[digest] = data
        return StoredDataRef(
            stored_data_id=StoredDataId(digest),
            data_kind="artifact",
            content_hash=digest,
            workspace_id="ws1",
            commit_id="c1",
            record_id=None,
        )

    def open_verified(self, ref: StoredDataRef) -> BytesIO:
        data = self.values[ref.content_hash]
        if hashlib.sha256(data).hexdigest() != ref.content_hash:
            raise ValueError("HASH_MISMATCH")
        return BytesIO(data)


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
        self.content = None

    async def match(self, **kwargs: object) -> object:
        content = kwargs["content"]
        self.content = content
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
            input_refs=(kwargs["source_result_ref"],),
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


def _resolve_call(_context: object, content: object) -> object:
    return (
        SimpleNamespace(
            decision_ref=_as_ref("action_decision", "decision"),
            reservation_ref=_as_ref("budget_reservation", "reservation"),
            call_spec_ref=_as_ref("llm_call_spec", "spec"),
        ),
        chaining_input_hash(content),  # type: ignore[arg-type]
    )


def _verification(
    name: str, *, rationale: str, final_true: bool = False
) -> VerificationResult:
    data = make("VerificationResult")
    data["meta"] = meta("verification_result", hypothesis=f"hyp-{name}") | {
        "record_id": f"verification-result-{name}",
        "logical_record_id": f"verification-result-logical-{name}",
    }
    data["verdict_rationale"] = rationale
    data["supporting_evidence"][0]["statement"] = (
        "Request data reaches the privileged operation after an authorization check"
    )
    if final_true:
        data.update(
            initial_verdict="TRUE",
            verdict="TRUE",
            dynamic_request_ref=_stored("dynamic_reproduction_request", name),
            dynamic_result_ref=_stored("dynamic_reproduction_result", name),
            poc_ref=_stored("poc_bundle", name),
            unresolved_conditions=[],
        )
    return wire(VerificationResult, data)


def _technical(
    name: str, verification_ref: StoredDataRef
) -> TechnicalEvidenceReview:
    data = make("TechnicalEvidenceReview")
    data["meta"] = meta("technical_evidence_review", hypothesis=f"hyp-{name}") | {
        "record_id": f"technical-review-{name}",
        "logical_record_id": f"technical-review-logical-{name}",
    }
    data["verification_result_ref"] = verification_ref.model_dump(mode="json")
    data["code_flow_linkage"] = (
        "The source reaches the sink after the permission check in request order"
    )
    data["restriction_assessment"] = "The authenticated-user restriction remains"
    return wire(TechnicalEvidenceReview, data)


def _primitive_with_exact_sources(
    primitive: Primitive,
    *,
    verification: VerificationResult,
    technical: TechnicalEvidenceReview | None,
) -> Primitive:
    verification_ref = reference(verification)
    assert isinstance(verification_ref, StoredDataRef)
    data = primitive.model_dump(mode="json")
    data["source_verification_ref"] = verification_ref.model_dump(mode="json")
    data["technical_review_ref"] = (
        reference(technical).model_dump(mode="json") if technical is not None else None
    )
    data["evidence_refs"] = [verification_ref.model_dump(mode="json")]
    for draft in (*data["inputs"], *((data["result"],) if data["result"] else ())):
        draft["evidence_refs"] = [verification_ref.model_dump(mode="json")]
    return wire(Primitive, data)


def _primitive_with_artifact_evidence(
    primitive: Primitive,
    *,
    verification: VerificationResult,
    artifact_ref: StoredDataRef,
) -> tuple[Primitive, VerificationResult, TechnicalEvidenceReview | None]:
    verification_data: dict[str, Any] = verification.model_dump(mode="json")
    supporting = cast(list[dict[str, Any]], verification_data["supporting_evidence"])
    supporting[0]["evidence_refs"] = [artifact_ref.model_dump(mode="json")]
    verification = wire(VerificationResult, verification_data)
    verification_ref = reference(verification)
    assert isinstance(verification_ref, StoredDataRef)
    name = str(primitive.primitive_id).removeprefix("primitive-")
    technical = (
        _technical(name, verification_ref) if primitive.result is not None else None
    )
    primitive_data: dict[str, Any] = primitive.model_dump(mode="json")
    primitive_data["source_verification_ref"] = verification_ref.model_dump(mode="json")
    primitive_data["technical_review_ref"] = (
        reference(technical).model_dump(mode="json") if technical is not None else None
    )
    primitive_data["evidence_refs"] = [artifact_ref.model_dump(mode="json")]
    drafts = list(cast(list[dict[str, Any]], primitive_data["inputs"]))
    result = primitive_data["result"]
    if isinstance(result, dict):
        drafts.append(result)
    for draft in drafts:
        draft["evidence_refs"] = [artifact_ref.model_dump(mode="json")]
    return wire(Primitive, primitive_data), verification, technical


def _tamper_artifact_evidence_unchecked(
    primitive: Primitive,
    verification: VerificationResult,
    artifact_ref: StoredDataRef,
) -> tuple[Primitive, VerificationResult, TechnicalEvidenceReview]:
    claim = verification.supporting_evidence[0].model_copy(
        update={"evidence_refs": (artifact_ref,)}
    )
    verification = verification.model_copy(update={"supporting_evidence": (claim,)})
    verification_ref = reference(verification)
    assert isinstance(verification_ref, StoredDataRef)
    name = str(primitive.primitive_id).removeprefix("primitive-")
    technical = _technical(name, verification_ref)
    primitive = primitive.model_copy(
        update={
            "source_verification_ref": verification_ref,
            "technical_review_ref": reference(technical),
            "evidence_refs": (artifact_ref,),
            "inputs": tuple(
                draft.model_copy(update={"evidence_refs": (artifact_ref,)})
                for draft in primitive.inputs
            ),
            "result": (
                primitive.result.model_copy(
                    update={"evidence_refs": (artifact_ref,)}
                )
                if primitive.result is not None
                else None
            ),
        }
    )
    return primitive, verification, technical


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
        artifacts=cast(ArtifactStore, _Artifacts()),
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
        resolve_call=_resolve_call,
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
        artifacts=cast(ArtifactStore, _Artifacts()),
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
        resolve_call=_resolve_call,
    )

    assert len(outcome.result.primitive_match_candidates) == 1
    assert outcome.result.primitive_match_candidates[0].downstream_input_ref == refs[3]
    assert {
        item.excluded_primitive_ref for item in outcome.result.excluded_lineage_refs
    } == {refs[1], refs[2]}
    assert len(children.calls) == 1


@pytest.mark.asyncio
async def test_one_directional_pair_preserves_each_matched_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lineage ranks the pair once, while each matched input remains material."""

    monkeypatch.setattr(
        "sastsimi.chaining.service.llm_invocation_save_refs",
        lambda **_: ("llm-proof",),
    )
    trigger = _primitive("A", inputs=(), result="provided")
    other = _primitive(
        "B",
        inputs=("first-required-input", "second-required-input"),
        result="next",
    )
    refs = tuple(reference(value) for value in (trigger, other))
    context = _context(refs, refs[0])  # type: ignore[arg-type]
    universe = PinnedChainingUniverse(
        trigger_primitive_ref=refs[0],  # type: ignore[arg-type]
        index_refs=(_as_ref("primitive_index_state", "index"),),
        considered_primitive_refs=refs,  # type: ignore[arg-type]
    )
    publisher, children = _Publisher(), _Children()
    service = ChainingWorkflowService(
        agent=_Agent(("comparison-1", "comparison-2")),
        records=_Records((trigger, other)),
        artifacts=cast(ArtifactStore, _Artifacts()),
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
        resolve_call=_resolve_call,
    )

    assert {
        item.matched_input_id for item in outcome.result.primitive_match_candidates
    } == {"draft-first-required-input", "draft-second-required-input"}
    assert len(outcome.result.chained_hypothesis_proposals) == 2
    assert len(children.calls) == 2


@pytest.mark.asyncio
async def test_prompt_uses_exact_redacted_semantic_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sastsimi.chaining.service.llm_invocation_save_refs",
        lambda **_: ("llm-proof",),
    )
    trigger_verification = _verification(
        "A",
        rationale="password=hunter2 confirms the upstream capability",
        final_true=True,
    )
    trigger_verification_ref = reference(trigger_verification)
    assert isinstance(trigger_verification_ref, StoredDataRef)
    trigger_technical = _technical("A", trigger_verification_ref)
    trigger = _primitive_with_exact_sources(
        _primitive("A", inputs=(), result="provided"),
        verification=trigger_verification,
        technical=trigger_technical,
    )
    other_verification = _verification(
        "B", rationale="Downstream input is reachable", final_true=True
    )
    other_verification_ref = reference(other_verification)
    assert isinstance(other_verification_ref, StoredDataRef)
    other_technical = _technical("B", other_verification_ref)
    other = _primitive_with_exact_sources(
        _primitive("B", inputs=("provided",), result="next"),
        verification=other_verification,
        technical=other_technical,
    )
    refs = tuple(reference(value) for value in (trigger, other))
    context = _context(refs, refs[0])  # type: ignore[arg-type]
    universe = PinnedChainingUniverse(
        trigger_primitive_ref=refs[0],  # type: ignore[arg-type]
        index_refs=(_as_ref("primitive_index_state", "index"),),
        considered_primitive_refs=refs,  # type: ignore[arg-type]
    )
    agent = _Agent(())
    service = ChainingWorkflowService(
        agent=agent,
        records=_Records(
            (
                trigger,
                other,
                trigger_verification,
                other_verification,
                trigger_technical,
                other_technical,
            )
        ),
        artifacts=cast(ArtifactStore, _Artifacts()),
        pools=_Pools(reference(context.work), universe),  # type: ignore[arg-type]
        lineage=_Lineage({}),
        publisher=_Publisher(),
        children=_Children(),
        ids=_Ids(),
        metadata_factory=_metadata,
        requester_identity_ref=_as_ref("requester_identity", "r"),
    )

    await service.execute(
        context=context,
        resolve_call=_resolve_call,
    )

    assert agent.content is not None
    summaries = "\n".join(item.summary for item in agent.content.evidence)
    assert "source reaches the sink after the permission check" in summaries
    assert "authenticated-user restriction remains" in summaries
    assert "hunter2" not in summaries
    assert "[REDACTED:CREDENTIAL]" in summaries
    assert "stored_data_id" not in summaries
    assert "verification-result-A" not in summaries


@pytest.mark.asyncio
async def test_prompt_projects_verified_artifact_evidence_bounded_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sastsimi.chaining.service.llm_invocation_save_refs",
        lambda **_: ("llm-proof",),
    )
    artifacts = _Artifacts()
    artifact_ref = artifacts.add(
        b"password=hunter2\nallow_admin()\n" + b"x" * 5000 + b"TAIL_SECRET"
    )
    trigger, trigger_verification, trigger_technical = (
        _primitive_with_artifact_evidence(
            _primitive("A", inputs=(), result="provided"),
            verification=_verification(
                "A", rationale="Artifact-backed capability", final_true=True
            ),
            artifact_ref=artifact_ref,
        )
    )
    other_verification = _verification(
        "B", rationale="Downstream input is reachable", final_true=True
    )
    other_verification_ref = reference(other_verification)
    assert isinstance(other_verification_ref, StoredDataRef)
    other_technical = _technical("B", other_verification_ref)
    other = _primitive_with_exact_sources(
        _primitive("B", inputs=("provided",), result="next"),
        verification=other_verification,
        technical=other_technical,
    )
    refs = tuple(reference(value) for value in (trigger, other))
    context = _context(refs, refs[0])  # type: ignore[arg-type]
    universe = PinnedChainingUniverse(
        trigger_primitive_ref=refs[0],  # type: ignore[arg-type]
        index_refs=(_as_ref("primitive_index_state", "index"),),
        considered_primitive_refs=refs,  # type: ignore[arg-type]
    )
    agent = _Agent(())
    service = ChainingWorkflowService(
        agent=agent,
        records=_Records(
            (
                trigger,
                other,
                trigger_verification,
                trigger_technical,
                other_verification,
                other_technical,
            )
        ),
        artifacts=cast(ArtifactStore, artifacts),
        pools=_Pools(reference(context.work), universe),  # type: ignore[arg-type]
        lineage=_Lineage({}),
        publisher=_Publisher(),
        children=_Children(),
        ids=_Ids(),
        metadata_factory=_metadata,
        requester_identity_ref=_as_ref("requester_identity", "r"),
    )

    await service.execute(context=context, resolve_call=_resolve_call)

    assert agent.content is not None
    summaries = "\n".join(item.summary for item in agent.content.evidence)
    assert "allow_admin" in summaries
    assert "hunter2" not in summaries
    assert "TAIL_SECRET" not in summaries
    assert "[REDACTED:CREDENTIAL]" in summaries


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["hash", "scope", "ref"])
async def test_artifact_evidence_tampering_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    monkeypatch.setattr(
        "sastsimi.chaining.service.llm_invocation_save_refs",
        lambda **_: ("llm-proof",),
    )
    artifacts = _Artifacts()
    artifact_ref = artifacts.add(b"allow_admin()")
    trigger, verification, _ = _primitive_with_artifact_evidence(
        _primitive("A", inputs=(), result="provided"),
        verification=_verification(
            "A", rationale="Artifact-backed capability", final_true=True
        ),
        artifact_ref=artifact_ref,
    )
    if tamper == "hash":
        artifact_ref = artifact_ref.model_copy(
            update={
                "stored_data_id": StoredDataId("0" * 64),
                "content_hash": "0" * 64,
            }
        )
    elif tamper == "scope":
        artifact_ref = artifact_ref.model_copy(
            update={"workspace_id": WorkspaceId("foreign")}
        )
    else:
        artifact_ref = artifact_ref.model_copy(
            update={"stored_data_id": StoredDataId("0" * 64)}
        )
    trigger, verification, technical = _tamper_artifact_evidence_unchecked(
        trigger,
        verification,
        artifact_ref,
    )
    other = _primitive("B", inputs=("provided",), result="next")
    refs = tuple(reference(value) for value in (trigger, other))
    context = _context(refs, refs[0])  # type: ignore[arg-type]
    universe = PinnedChainingUniverse(
        trigger_primitive_ref=refs[0],  # type: ignore[arg-type]
        index_refs=(_as_ref("primitive_index_state", "index"),),
        considered_primitive_refs=refs,  # type: ignore[arg-type]
    )
    agent = _Agent(())
    service = ChainingWorkflowService(
        agent=agent,
        records=_Records((trigger, other, verification, technical)),
        artifacts=cast(ArtifactStore, artifacts),
        pools=_Pools(reference(context.work), universe),  # type: ignore[arg-type]
        lineage=_Lineage({}),
        publisher=_Publisher(),
        children=_Children(),
        ids=_Ids(),
        metadata_factory=_metadata,
        requester_identity_ref=_as_ref("requester_identity", "r"),
    )

    with pytest.raises(ValueError, match="CHAINING_EVIDENCE_REFERENCE_INVALID"):
        await service.execute(context=context, resolve_call=_resolve_call)
    assert agent.content is None
