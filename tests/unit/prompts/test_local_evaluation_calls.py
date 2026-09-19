from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, cast

import pytest

from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.llm import PromptInputSlot, PromptRegistryEntry
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import StaticFactBundle
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.authorized_llm_call import AuthorizedLLMCall
from sastsimi.prompts.builder import PromptSource
from sastsimi.prompts.local_calls import (
    ConfiguredLocalEvaluationCallResolver,
    ExactAnalysisLocalEvaluationRouteLookup,
    LocalEvaluationRouteBinding,
)
from sastsimi.prompts.local_evaluation import (
    ApprovedLocalEvaluationRoute,
    LocalEvaluationRoute,
    PreparedLocalEvaluationCall,
)
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import bundle, meta


def _ref(kind: str, value: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(value),
        data_kind=kind,
        content_hash="a" * 64,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        record_id=RecordId(value),
    )


def _entry(provider_ref: StoredDataRef) -> PromptRegistryEntry:
    payload = make("PromptRegistryEntry")
    payload["meta"] = meta("prompt_registry_entry", hypothesis=None, attempt=None)
    return PromptRegistryEntry.model_validate_json(
        json.dumps(
            payload
            | {
                "agent_role": "HYPOTHESIS",
                "task_kind": "GENERATE_INITIAL",
                "purpose": "LOCAL_EVALUATION",
                "prompt_key": "hypothesis.generate.local-v1",
                "input_slots": (
                    PromptInputSlot(
                        slot="facts",
                        data_kind="static_fact_bundle",
                        field_paths=("/entities",),
                        cardinality="REQUIRED_ONE",
                        trust_class="UNTRUSTED_DATA",
                    ),
                ),
                "session_policy": "NEW",
                "quality_evaluation_ref": None,
                "provider_profile_refs": (provider_ref,),
            },
            default=lambda value: value.model_dump(mode="json"),
        )
    )


class _Records:
    def __init__(self, values: dict[StoredDataRef, object]) -> None:
        self.values = values

    def get_exact(self, ref: StoredDataRef) -> Any:
        return self.values[ref]


class _Queries:
    def __init__(self, entry: PromptRegistryEntry) -> None:
        self.entry = entry

    def current_records(self, analysis_id: str, kind: str) -> tuple[object, ...]:
        if analysis_id == "a1" and kind == PromptRegistryEntry.KIND:
            return (self.entry,)
        return ()


@dataclass
class _Configuration:
    prepared: PreparedLocalEvaluationCall
    captured_sources: tuple[object, ...] = ()

    def prepare_call(self, **kwargs: object) -> PreparedLocalEvaluationCall:
        self.captured_sources = cast(tuple[object, ...], kwargs["sources"])
        return self.prepared

    def bind_artifact_source(self, slot: str, ref: StoredDataRef) -> object:
        raise AssertionError((slot, ref))


class _Authorizer:
    def __init__(self, call: AuthorizedLLMCall) -> None:
        self.call = call
        self.prepared: object | None = None

    def authorize(self, **kwargs: object) -> AuthorizedLLMCall:
        self.prepared = kwargs["prepared"]
        return self.call

    def settle(self, call: object, invocation: object) -> None:
        assert call is self.call
        assert invocation is not None


def _work() -> WorkExecutionState:
    payload = make("WorkExecutionState")
    payload["meta"] = meta("work_execution_state", hypothesis="h1", attempt=None)
    return WorkExecutionState.model_validate_json(
        json.dumps(
            payload
            | {
                "work_type": "HYPOTHESIS_PROPOSAL",
                "subject_type": "ANALYSIS",
                "subject_id": "a1",
                "status": "RUNNING",
                "active_attempt_id": "at1",
                "started_at": "2026-09-20T00:00:00Z",
                "dedupe_key": "d" * 64,
                "state_version": 2,
                "last_transition_ref": {
                    "stored_data_id": "transition-s1",
                    "data_kind": "state_transition",
                    "record_id": "transition-r1",
                    "content_hash": "b" * 64,
                    "workspace_id": "ws1",
                    "commit_id": "c1",
                },
            }
        )
    )


def test_exact_lookup_rejects_cross_analysis_route() -> None:
    provider_ref = _ref("provider_profile", "p1")
    entry = _entry(provider_ref)
    entry_ref = cast(StoredDataRef, reference(entry))
    route = LocalEvaluationRoute(
        role="HYPOTHESIS",
        task_kind="GENERATE_INITIAL",
        provider_profile_key="codex-local",
        model="configured-model",
        prompt_key="hypothesis.generate.local-v1",
    )
    approved = ApprovedLocalEvaluationRoute(entry_ref, provider_ref)
    lookup = ExactAnalysisLocalEvaluationRouteLookup(
        records=cast(Any, _Records({entry_ref: entry})),
        queries=cast(Any, _Queries(entry)),
        bindings=(LocalEvaluationRouteBinding("a1", route, approved),),
    )

    with pytest.raises(ValueError, match="LOCAL_EVALUATION_LLM_ROUTE_NOT_CONFIGURED"):
        lookup("different-analysis", "HYPOTHESIS", "GENERATE_INITIAL")


def test_resolver_prepares_exact_sources_and_uses_authority() -> None:
    provider_ref = _ref("provider_profile", "provider-r1")
    entry = _entry(provider_ref)
    entry_ref = cast(StoredDataRef, reference(entry))
    facts = StaticFactBundle.model_validate_json(json.dumps(bundle()))
    facts_ref = cast(StoredDataRef, reference(facts))
    route = LocalEvaluationRoute(
        role="HYPOTHESIS",
        task_kind="GENERATE_INITIAL",
        provider_profile_key="codex-local",
        model="configured-model",
        prompt_key="hypothesis.generate.local-v1",
    )
    approval = ApprovedLocalEvaluationRoute(
        entry_ref, provider_ref
    )
    prepared = PreparedLocalEvaluationCall(
        payload=cast(Any, object()),
        payload_ref=_ref("prompt_payload", "payload-r1"),
        call_spec=cast(
            Any,
            type(
                "Spec",
                (),
                {
                    "agent_role": "HYPOTHESIS",
                    "task_kind": "GENERATE_INITIAL",
                    "purpose": "LOCAL_EVALUATION",
                    "session_policy": "NEW",
                    "parent_session_ref": None,
                    "model": "configured-model",
                    "provider_profile_ref": approval.provider_profile_ref,
                    "context_refs": (facts_ref,),
                },
            )(),
        ),
        call_spec_ref=_ref("llm_call_spec", "spec-r1"),
    )
    work = _work()
    authorized = AuthorizedLLMCall(
        work=work,
        decision_ref=_ref("action_decision", "decision-r1"),
        reservation_ref=_ref("budget_reservation", "reservation-r1"),
        call_spec_ref=prepared.call_spec_ref,
    )
    configuration = _Configuration(prepared)
    authorizer = _Authorizer(authorized)
    resolver = ConfiguredLocalEvaluationCallResolver(
        configuration=cast(Any, configuration),
        records=cast(Any, _Records({entry_ref: entry, facts_ref: facts})),
        route_lookup=lambda *_args: (route, approval, entry),
        authorizer=cast(Any, authorizer),
    )

    assert (
        resolver.resolve(
            work=work,
            role="HYPOTHESIS",
            task_kind="GENERATE_INITIAL",
            source_refs=(facts_ref,),
        )
        == authorized
    )
    assert authorizer.prepared is prepared
    assert len(configuration.captured_sources) == 1
    source = configuration.captured_sources[0]
    assert isinstance(source, PromptSource)
    assert source.source_ref == facts_ref
