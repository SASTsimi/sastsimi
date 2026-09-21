"""Production prompt provisioning uses only exact approved configuration."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.evaluation import EvaluationRecommendation
from sastsimi.contracts.ids import (
    CommitId,
    OpaqueId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.llm import (
    ExecutionLimits,
    LLMCallSpec,
    LLMRetryPolicy,
    LLMRole,
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
from sastsimi.ports.authorized_llm_call import AuthorizedLLMCall
from sastsimi.ports.dto import Record
from sastsimi.ports.production_prompt import (
    ApprovedProductionRoute,
    PreparedProductionCall,
    ProductionPromptApproval,
)
from sastsimi.prompts.builder import PromptSource
from sastsimi.prompts.production import (
    REQUIRED_PRODUCTION_PROMPT_ROUTES,
    ProductionLLMConfigurationService,
)
from sastsimi.prompts.production_calls import ConfiguredProductionCallResolver
from sastsimi.prompts.registry import REQUIRED_TEMPLATE_SECTIONS
from sastsimi.runtime.prompt_registry import PromptRegistry
from sastsimi.storage.artifact_store import LocalArtifactStore
from sastsimi.verification.production_llm_work_handlers import (
    ProductionDynamicStageCallResolver,
)
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import bundle, meta
from tests.unit.orchestration.test_production_llm_work_handlers import (
    _dynamic_candidate_fixture,
)


class _Ids:
    def __init__(self) -> None:
        self.value = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.value += 1
        return kind(f"production-{self.value}")


class _Clock:
    def now(self) -> datetime:
        return datetime(2026, 9, 13, tzinfo=UTC)

    def monotonic_ms(self) -> int:
        return 0


def _key(ref: RecordRef) -> tuple[str, str]:
    return str(ref.record_id), ref.content_hash


class _Records:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], Record] = {}

    def add(self, record: Record) -> StoredDataRef:
        exact = reference(record)
        assert isinstance(exact, StoredDataRef)
        self.values[_key(exact)] = record
        return exact

    def get_exact(self, ref: RecordRef) -> Record:
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


class _CapturingAuthorizer:
    def __init__(self) -> None:
        self.prepared: PreparedProductionCall | None = None

    @staticmethod
    def _ref(kind: str) -> StoredDataRef:
        return StoredDataRef(
            stored_data_id=StoredDataId(f"candidate-{kind}"),
            data_kind=kind,
            record_id=RecordId(f"candidate-{kind}"),
            content_hash="b" * 64,
            workspace_id=WorkspaceId("ws1"),
            commit_id=CommitId("c1"),
        )

    def authorize(
        self, *, work: WorkExecutionState, prepared: PreparedProductionCall
    ) -> AuthorizedLLMCall:
        self.prepared = prepared
        return AuthorizedLLMCall(
            work=work,
            decision_ref=self._ref("action_decision"),
            reservation_ref=self._ref("budget_reservation"),
            call_spec_ref=prepared.call_spec_ref,
        )

    def settle(self, call: AuthorizedLLMCall, invocation: object) -> None:
        raise AssertionError((call, invocation))


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


def _approved_route(
    service: ProductionLLMConfigurationService,
    records: _Records,
    artifacts: LocalArtifactStore,
    *,
    template_path: Path,
    template_version: str,
    role: str,
    task_kind: str,
    result_kind: str,
    evaluation_prompt_key: str,
    production_prompt_key: str,
    input_slots: tuple[dict[str, object], ...],
) -> tuple[_Route, ApprovedProductionRoute]:
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
        result_kind=result_kind,
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
        prompt_key=evaluation_prompt_key,
        agent_role=role,
        task_kind=task_kind,
        purpose="EVALUATION",
        template_ref=template_ref,
        template_version=template_version,
        input_slots=input_slots,
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
        result_kind=result_kind,
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
        role=role,
        task_kind=task_kind,
        provider_profile_key="approved-provider",
        model="approved-model",
        prompt_key=production_prompt_key,
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


def _approved_hypothesis_route(
    service: ProductionLLMConfigurationService,
    records: _Records,
    artifacts: LocalArtifactStore,
) -> tuple[_Route, ApprovedProductionRoute]:
    return _approved_route(
        service,
        records,
        artifacts,
        template_path=Path(
            "src/sastsimi/prompts/templates/hypothesis/generate-initial/1.0.2.md"
        ),
        template_version="1.0.2",
        role="HYPOTHESIS",
        task_kind="GENERATE_INITIAL",
        result_kind="hypothesis_proposal",
        evaluation_prompt_key="hypothesis.generate-initial.evaluation-v1",
        production_prompt_key="hypothesis.generate-initial.production-v1",
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
    )


def _candidate_input_slots(
    *,
    fragment_field_paths: tuple[str, ...] = ("/redacted_body",),
    fragment_cardinality: str = "REQUIRED_MANY",
    fragment_trust_class: str = "UNTRUSTED_DATA",
    include_fragment_slot: bool = True,
) -> tuple[dict[str, object], ...]:
    record_slots: tuple[dict[str, object], ...] = (
        {
            "slot": "request",
            "data_kind": "dynamic_reproduction_request",
            "field_paths": ("$",),
            "cardinality": "REQUIRED_ONE",
            "trust_class": "UNTRUSTED_DATA",
        },
        {
            "slot": "plan",
            "data_kind": "reproduction_plan",
            "field_paths": ("$",),
            "cardinality": "REQUIRED_ONE",
            "trust_class": "UNTRUSTED_DATA",
        },
        {
            "slot": "environment",
            "data_kind": "sandbox_environment",
            "field_paths": ("$",),
            "cardinality": "REQUIRED_ONE",
            "trust_class": "UNTRUSTED_DATA",
        },
        {
            "slot": "code_contexts",
            "data_kind": "code_context_response",
            "field_paths": ("$",),
            "cardinality": "REQUIRED_MANY",
            "trust_class": "UNTRUSTED_DATA",
        },
    )
    if not include_fragment_slot:
        return record_slots
    return (
        *record_slots,
        {
            "slot": "code_fragments",
            "data_kind": "artifact",
            "field_paths": fragment_field_paths,
            "cardinality": fragment_cardinality,
            "trust_class": fragment_trust_class,
        },
    )


def _approved_candidate_route(
    service: ProductionLLMConfigurationService,
    records: _Records,
    artifacts: LocalArtifactStore,
    *,
    fragment_field_paths: tuple[str, ...] = ("/redacted_body",),
    fragment_cardinality: str = "REQUIRED_MANY",
    fragment_trust_class: str = "UNTRUSTED_DATA",
    include_fragment_slot: bool = True,
) -> tuple[_Route, ApprovedProductionRoute]:
    return _approved_route(
        service,
        records,
        artifacts,
        template_path=Path(
            "src/sastsimi/prompts/templates/dynamic-reproduction/"
            "create-poc-candidate/1.0.2.md"
        ),
        template_version="1.0.2",
        role="DYNAMIC_REPRODUCTION",
        task_kind="CREATE_POC_CANDIDATE",
        result_kind="poc_candidate",
        evaluation_prompt_key="dynamic.create-poc-candidate.evaluation-v1",
        production_prompt_key="dynamic.create-poc-candidate.production-v1",
        input_slots=_candidate_input_slots(
            fragment_field_paths=fragment_field_paths,
            fragment_cardinality=fragment_cardinality,
            fragment_trust_class=fragment_trust_class,
            include_fragment_slot=include_fragment_slot,
        ),
    )


def test_approved_route_creates_active_entry_and_attempt_call(tmp_path: Path) -> None:
    assert len(REQUIRED_PRODUCTION_PROMPT_ROUTES) == 17
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
    assert prepared.payload.template_version == "1.0.2"
    assert prepared.call_spec.model == "approved-model"
    assert prepared.call_spec.context_refs == (facts_ref,)
    assert records.get_exact(prepared.payload_ref) == prepared.payload
    assert records.get_exact(prepared.call_spec_ref) == prepared.call_spec
    assert content_hash(prepared.payload) == prepared.payload_ref.content_hash
    with artifacts.open_verified(prepared.payload.rendered_prompt_ref) as stream:
        rendered = stream.read()
    assert b"copy complete objects exactly, field-for-field" in rendered
    assert b"Never synthesize a code range" in rendered


def test_every_production_route_has_a_loadable_canonical_template() -> None:
    for route in REQUIRED_PRODUCTION_PROMPT_ROUTES:
        text = route.template_path.read_text(encoding="utf-8")
        assert all(f"# {section}" in text for section in REQUIRED_TEMPLATE_SECTIONS), (
            route.template_path
        )


def test_evidence_templates_require_exact_visible_reference_objects() -> None:
    routes = {
        route.role: route
        for route in REQUIRED_PRODUCTION_PROMPT_ROUTES
        if route.role in {"PRO", "CON"}
    }

    assert set(routes) == {"PRO", "CON"}
    for route in routes.values():
        assert route.template_path.name == "1.0.2.md"
        text = route.template_path.read_text(encoding="utf-8")
        assert "Copy one complete reference object exactly" in text
        assert "Never assemble a reference" in text
        # EvidenceClaim rejects a repeated reference and an error/gap citation,
        # so the template has to say so before the call rather than after it.
        assert "`evidence_refs` must be a set" in text
        assert "cite it at\nmost once per claim" in text
        assert (
            "Never cite an analysis error, a data\ngap, or an initial assessment"
            in text
        )


def test_policy_parser_template_requires_empty_items_when_absent() -> None:
    route = next(
        route
        for route in REQUIRED_PRODUCTION_PROMPT_ROUTES
        if route.role == "POLICY_PARSER"
    )

    assert route.template_path.name == "1.0.1.md"
    text = route.template_path.read_text(encoding="utf-8")
    # The collector rejects an ABSENT_CONFIRMED result that carries any policy
    # item, so the template has to forbid inferring one.
    assert "every policy item" in text
    assert "Never infer an item from the repository" in text
    for field in (
        "in_scope_assets",
        "testing_restrictions",
        "impact_criteria",
        "disclosure_requirements",
    ):
        assert field in text


def test_assess_initial_template_binds_verdict_to_its_only_route() -> None:
    route = next(
        route
        for route in REQUIRED_PRODUCTION_PROMPT_ROUTES
        if route.role == "VERIFICATION" and route.task_kind == "ASSESS_INITIAL"
    )

    assert route.template_path.name == "1.0.1.md"
    text = route.template_path.read_text(encoding="utf-8")
    # VerificationInitialAssessment.assessment_route rejects any other pairing,
    # so the template states the mapping instead of leaving it implied.
    assert "`TRUE` requires `POC_CONFIRMATION`" in text
    assert "`FALSE` requires `FINALIZE_WITHOUT_DYNAMIC`" in text
    assert "`VERDICT_EVIDENCE` never carries `TRUE` or `FALSE`" in text
    assert "is still `HOLD`, not `TRUE`" in text


def test_final_verdict_template_defines_completed_check_semantics() -> None:
    route = next(
        route
        for route in REQUIRED_PRODUCTION_PROMPT_ROUTES
        if route.role == "VERIFICATION" and route.task_kind == "FINAL_VERDICT"
    )

    assert route.template_path.name == "1.0.2.md"
    text = route.template_path.read_text(encoding="utf-8")
    assert "records whether you completed the assessment" in text
    assert "use INCOMPLETE merely because" in text
    # VerificationResult rejects the whole verdict on any of these.
    assert "every validation result is COMPLETE" in text
    assert "if any falsification result is DISPROVED then the" in text
    assert "never TRUE" in text


@pytest.mark.parametrize(
    ("field_paths", "cardinality", "trust_class", "include_slot"),
    (
        (("/redacted_body",), "REQUIRED_MANY", "UNTRUSTED_DATA", False),
        (("/content_hash",), "REQUIRED_MANY", "UNTRUSTED_DATA", True),
        (("/redacted_body",), "REQUIRED_ONE", "UNTRUSTED_DATA", True),
        (("/redacted_body",), "REQUIRED_MANY", "TRUSTED_INSTRUCTION", True),
    ),
)
def test_candidate_activation_requires_exact_redacted_artifact_projection(
    tmp_path: Path,
    field_paths: tuple[str, ...],
    cardinality: str,
    trust_class: str,
    include_slot: bool,
) -> None:
    service, records, artifacts = _service(tmp_path)

    with pytest.raises(ValueError, match="PRODUCTION_PROMPT_ROUTE_MISMATCH"):
        _approved_candidate_route(
            service,
            records,
            artifacts,
            fragment_field_paths=field_paths,
            fragment_cardinality=cardinality,
            fragment_trust_class=trust_class,
            include_fragment_slot=include_slot,
        )


def test_candidate_call_renders_redacted_code_and_persists_every_exact_ref(
    tmp_path: Path,
) -> None:
    service, records, artifacts = _service(tmp_path / "configuration")
    route, approved = _approved_candidate_route(service, records, artifacts)
    (
        context_records,
        context_artifacts,
        work,
        request_ref,
        plan_ref,
        environment_ref,
        response_ref,
        fragment_refs,
    ) = _dynamic_candidate_fixture(tmp_path / "context")
    for record in context_records.values.values():
        records.add(record)
    for fragment_ref in fragment_refs:
        with context_artifacts.open_verified(fragment_ref) as stream:
            fragment = stream.read()
        copied_fragment_ref = artifacts.commit(
            artifacts.stage_bytes(fragment, "text/plain")
        )
    assert copied_fragment_ref == fragment_ref

    authorizer = _CapturingAuthorizer()

    def route_lookup(
        analysis_id: str, role: LLMRole, task_kind: str
    ) -> tuple[_Route, ApprovedProductionRoute]:
        assert (analysis_id, role, task_kind) == (
            "a1",
            "DYNAMIC_REPRODUCTION",
            "CREATE_POC_CANDIDATE",
        )
        return route, approved

    configured = ConfiguredProductionCallResolver(
        configuration=service,
        records=records,  # type: ignore[arg-type]
        route_lookup=route_lookup,  # type: ignore[arg-type]
        authorizer=authorizer,
    )
    resolver = ProductionDynamicStageCallResolver(
        configured,
        max_execute_turns=1,
        records=records,  # type: ignore[arg-type]
        artifacts=artifacts,
    )

    authorization = resolver.resolve(
        work=work,
        task_kind="CREATE_POC_CANDIDATE",
        context_refs=(request_ref, plan_ref, environment_ref),
    )

    expected_refs = (
        request_ref,
        plan_ref,
        environment_ref,
        response_ref,
        *fragment_refs,
    )
    prepared = authorizer.prepared
    assert prepared is not None
    assert prepared.call_spec.context_refs == expected_refs
    assert (
        tuple(binding.source_ref for binding in prepared.payload.context_bindings)
        == expected_refs
    )
    assert records.get_exact(prepared.payload_ref) == prepared.payload
    assert records.get_exact(prepared.call_spec_ref) == prepared.call_spec
    assert authorization.context_refs == expected_refs
    with artifacts.open_verified(prepared.payload.rendered_prompt_ref) as stream:
        rendered = stream.read()
    assert b"print('safe')" in rendered
    assert b"safe-fragment-2" in rendered
    assert b"[REDACTED:TOKEN]" in rendered
    assert b"sk-sensitive-code-token" not in rendered


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
