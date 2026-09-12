"""Production prompt provisioning uses only exact approved configuration."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.evaluation import EvaluationRecommendation
from sastsimi.contracts.ids import CommitId, OpaqueId, WorkspaceId
from sastsimi.contracts.llm import (
    ExecutionLimits,
    LLMCallSpec,
    LLMRetryPolicy,
    LLMToolPolicy,
    OutputSchemaSpec,
    PromptPayload,
    PromptRedactionPolicy,
    PromptRegistryEntry,
    ProviderProfile,
    SemanticValidatorSpec,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.static import StaticFactBundle
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.prompts.builder import PromptSource
from sastsimi.prompts.production import (
    REQUIRED_PRODUCTION_PROMPT_ROUTES,
    ApprovedProductionRoute,
    ProductionLLMConfigurationService,
    ProductionPromptApproval,
)
from sastsimi.prompts.registry import REQUIRED_TEMPLATE_SECTIONS
from sastsimi.runtime.prompt_registry import PromptRegistry
from sastsimi.storage.artifact_store import LocalArtifactStore
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import bundle, meta


class _Ids:
    def __init__(self) -> None:
        self.value = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.value += 1
        return kind(f"production-{self.value}")


class _Clock:
    def now(self) -> datetime:
        return datetime(2026, 9, 13, tzinfo=UTC)


def _key(ref: RecordRef) -> tuple[str, str]:
    return str(ref.record_id), ref.content_hash


class _Records:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], object] = {}

    def add(self, record: object) -> StoredDataRef:
        exact = reference(record)  # type: ignore[arg-type]
        assert isinstance(exact, StoredDataRef)
        self.values[_key(exact)] = record
        return exact

    def get_exact(self, ref: RecordRef) -> object:
        try:
            return self.values[_key(ref)]
        except KeyError as error:
            raise LookupError("missing record") from error


class _Queries:
    def __init__(self, records: _Records) -> None:
        self.records = records

    def current_records(self, analysis_id: str, kind: str) -> tuple[Any, ...]:
        candidates = tuple(
            value
            for value in self.records.values.values()
            if str(getattr(getattr(value, "meta", None), "analysis_id", ""))
            == analysis_id
            and getattr(getattr(value, "meta", None), "record_type", None) == kind
        )
        latest: dict[str, Any] = {}
        for candidate in candidates:
            logical = str(candidate.meta.logical_record_id)
            if (
                logical not in latest
                or candidate.meta.revision_number > latest[logical].meta.revision_number
            ):
                latest[logical] = candidate
        return tuple(latest.values())

    def published_records(self, analysis_id: str) -> tuple[Any, ...]:
        return tuple(
            value
            for value in self.records.values.values()
            if str(getattr(getattr(value, "meta", None), "analysis_id", ""))
            == analysis_id
        )


class _Configuration:
    def __init__(self, records: _Records) -> None:
        self.records = records

    def register_prompt_entry(self, record: PromptRegistryEntry) -> StoredDataRef:
        return self.records.add(record)

    def register_prompt_payload(self, record: PromptPayload) -> StoredDataRef:
        return self.records.add(record)

    def register_call_spec(self, record: LLMCallSpec) -> StoredDataRef:
        return self.records.add(record)


@dataclass(frozen=True)
class _Route:
    role: str
    task_kind: str
    provider_profile_key: str
    model: str
    prompt_key: str


def _config_record(record_model: type[Any], kind: str, **changes: object) -> Any:
    payload = make(record_model.__name__)
    payload["meta"] = meta(kind, hypothesis=None, attempt=None)
    return record_model.model_validate_json(
        json.dumps(
            payload | changes,
            default=lambda value: value.model_dump(mode="json"),
        )
    )


def _service(
    tmp_path: Path,
) -> tuple[ProductionLLMConfigurationService, _Records, LocalArtifactStore]:
    records = _Records()
    queries = _Queries(records)
    configuration = _Configuration(records)
    artifacts = LocalArtifactStore(
        tmp_path / "artifacts",
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
    )
    prompts = PromptRegistry(configuration, records, queries)  # type: ignore[arg-type]
    return (
        ProductionLLMConfigurationService(
            repository_root=Path.cwd(),
            records=records,  # type: ignore[arg-type]
            queries=queries,
            configuration=configuration,  # type: ignore[arg-type]
            prompt_registry=prompts,
            artifacts=artifacts,
            ids=_Ids(),
            clock=_Clock(),
        ),
        records,
        artifacts,
    )


def _approved_hypothesis_route(
    service: ProductionLLMConfigurationService,
    records: _Records,
    artifacts: LocalArtifactStore,
) -> tuple[_Route, ApprovedProductionRoute]:
    template_path = Path(
        "src/sastsimi/prompts/templates/hypothesis/generate-initial/1.0.0.md"
    )
    template = template_path.read_bytes()
    template_ref = artifacts.commit(artifacts.stage_bytes(template, "text/markdown"))
    schema_ref = artifacts.commit(
        artifacts.stage_bytes(b'{"type":"array"}', "application/schema+json")
    )
    implementation_ref = artifacts.commit(
        artifacts.stage_bytes(b"validator", "text/plain")
    )
    test_ref = artifacts.commit(artifacts.stage_bytes(b"test", "text/plain"))

    provider = _config_record(
        ProviderProfile,
        "provider_profile",
        profile_key="approved-provider",
        model="approved-model",
        validation_evidence_ref={
            "stored_data_id": "provider-validation",
            "data_kind": "provider_validation_evidence",
            "record_id": "provider-validation",
            "content_hash": "a" * 64,
            "workspace_id": "ws1",
            "commit_id": "c1",
        },
    )
    provider_ref = records.add(provider)
    limits = _config_record(ExecutionLimits, "execution_limits", timeout_ms=5_000)
    retry = _config_record(LLMRetryPolicy, "llm_retry_policy")
    tools = _config_record(
        LLMToolPolicy,
        "llm_tool_policy",
        allowed_tools=(),
        forbidden_actions=("provider-tool-use",),
        sandbox_only=True,
    )
    redaction = _config_record(
        PromptRedactionPolicy,
        "prompt_redaction_policy",
        remove_categories=(
            "CREDENTIAL",
            "COOKIE",
            "TOKEN",
            "BROWSER_PROFILE",
            "HOST_ABSOLUTE_PATH",
            "HIDDEN_REASONING",
        ),
        fail_closed=True,
    )
    schema = _config_record(
        OutputSchemaSpec,
        "output_schema_spec",
        schema_artifact_ref=schema_ref,
        result_kind="hypothesis_proposal",
    )
    semantic = _config_record(
        SemanticValidatorSpec,
        "semantic_validator_spec",
        implementation_ref=implementation_ref,
        test_refs=(test_ref,),
    )
    support_refs = tuple(
        records.add(record)
        for record in (limits, retry, tools, redaction, schema, semantic)
    )
    evaluation = _config_record(
        PromptRegistryEntry,
        "prompt_registry_entry",
        prompt_key="hypothesis.generate-initial.evaluation-v1",
        agent_role="HYPOTHESIS",
        task_kind="GENERATE_INITIAL",
        purpose="EVALUATION",
        template_ref=template_ref,
        template_version="1.0.0",
        input_slots=(
            {
                "slot": "facts",
                "data_kind": "static_fact_bundle",
                "field_paths": (
                    "/entities",
                    "/locations",
                    "/tool_runs",
                    "/gaps",
                    "/errors",
                ),
                "cardinality": "REQUIRED_ONE",
                "trust_class": "UNTRUSTED_DATA",
            },
        ),
        forbidden_context_kinds=(
            "credential",
            "provider_profile",
            "llm_invocation_log",
        ),
        output_schema_ref=support_refs[4],
        session_policy="NEW",
        provider_profile_refs=(provider_ref,),
        execution_limits_ref=support_refs[0],
        retry_policy_ref=support_refs[1],
        tool_policy_ref=support_refs[2],
        redaction_policy_ref=support_refs[3],
        semantic_validator_ref=support_refs[5],
        result_kind="hypothesis_proposal",
        status="ACTIVE",
        quality_evaluation_ref=None,
    )
    evaluation_ref = records.add(evaluation)
    recommendation = _config_record(
        EvaluationRecommendation,
        "evaluation_recommendation",
        target_provider_profile_ref=provider_ref,
        target_model=provider.model,
        target_session_policy="NEW",
        target_prompt_registry_entry_ref=evaluation_ref,
        decision="ACCEPT_FOR_PRODUCTION",
    )
    recommendation_ref = records.add(recommendation)
    route = _Route(
        role="HYPOTHESIS",
        task_kind="GENERATE_INITIAL",
        provider_profile_key="approved-provider",
        model="approved-model",
        prompt_key="hypothesis.generate-initial.production-v1",
    )
    activation = service.plan_activation(
        scope=RecordMeta.model_validate_json(
            json.dumps(meta("configuration", hypothesis=None, attempt=None))
        ),
        route=route,  # type: ignore[arg-type]
        approval=ProductionPromptApproval(
            evaluation_prompt_ref=evaluation_ref,
            quality_evaluation_ref=recommendation_ref,
            provider_profile_ref=provider_ref,
        ),
    )
    return route, service.publish_activation(activation)


def test_approved_route_creates_active_entry_and_attempt_call(tmp_path: Path) -> None:
    assert len(REQUIRED_PRODUCTION_PROMPT_ROUTES) == 16
    service, records, artifacts = _service(tmp_path)
    route, approved = _approved_hypothesis_route(service, records, artifacts)
    work_data = make("WorkExecutionState")
    work_data["meta"] = meta("work_execution_state", hypothesis="h1", attempt=None)
    work = WorkExecutionState.model_validate_json(
        json.dumps(
            work_data
            | {
                "work_type": "VERIFICATION",
                "subject_type": "HYPOTHESIS",
                "subject_id": "h1",
                "status": "RUNNING",
                "active_attempt_id": "at1",
                "started_at": "2026-09-13T00:00:00Z",
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
    facts = StaticFactBundle.model_validate_json(json.dumps(bundle()))
    facts_ref = records.add(facts)

    prepared = service.prepare_call(
        route=route,  # type: ignore[arg-type]
        approval=approved,
        work=work,
        sources=(PromptSource("facts", facts_ref, facts),),
    )

    assert prepared.payload.agent_role == "HYPOTHESIS"
    assert prepared.call_spec.model == "approved-model"
    assert prepared.call_spec.context_refs == (facts_ref,)
    assert records.get_exact(prepared.payload_ref) == prepared.payload
    assert records.get_exact(prepared.call_spec_ref) == prepared.call_spec
    assert content_hash(prepared.payload) == prepared.payload_ref.content_hash


def test_every_production_route_has_a_loadable_canonical_template() -> None:
    for route in REQUIRED_PRODUCTION_PROMPT_ROUTES:
        text = route.template_path.read_text(encoding="utf-8")
        assert all(f"# {section}" in text for section in REQUIRED_TEMPLATE_SECTIONS), (
            route.template_path
        )


def test_missing_or_mismatched_approval_fails_closed(tmp_path: Path) -> None:
    service, records, artifacts = _service(tmp_path)
    route, approved = _approved_hypothesis_route(service, records, artifacts)

    with pytest.raises(ValueError, match="PRODUCTION_PROMPT_APPROVAL_REQUIRED"):
        service.resolve_route(
            route=route,  # type: ignore[arg-type]
            approval=approved.model_copy(update={"quality_evaluation_ref": None}),
        )
    with pytest.raises(ValueError, match="PRODUCTION_PROVIDER_ROUTE_MISMATCH"):
        service.resolve_route(
            route=_Route(
                role=route.role,
                task_kind=route.task_kind,
                provider_profile_key="wrong-provider",
                model=route.model,
                prompt_key=route.prompt_key,
            ),  # type: ignore[arg-type]
            approval=approved,
        )
