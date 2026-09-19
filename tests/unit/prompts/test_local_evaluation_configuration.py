"""LOCAL_EVALUATION prompt routes never mint Production authority."""

from __future__ import annotations

import json
import shutil
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from sastsimi.contracts.ids import CommitId, OpaqueId, WorkspaceId
from sastsimi.contracts.llm import (
    ExecutionLimits,
    LLMCallSpec,
    LLMRetryPolicy,
    LLMToolPolicy,
    OutputSchemaSpec,
    PromptInputSlot,
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
from sastsimi.ports.dto import Record
from sastsimi.prompts.builder import PromptSource
from sastsimi.prompts.local_evaluation import (
    LOCAL_EVALUATION_EXECUTE_UNAVAILABLE,
    REQUIRED_LOCAL_EVALUATION_PROMPT_ROUTES,
    LocalEvaluationLLMConfigurationService,
    LocalEvaluationPromptSupport,
    LocalEvaluationRoute,
)
from sastsimi.prompts.registry import REQUIRED_TEMPLATE_SECTIONS
from sastsimi.runtime.prompt_registry import PromptRegistry
from sastsimi.storage.artifact_store import LocalArtifactStore
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import bundle, meta


@pytest.fixture
def work_path() -> Generator[Path, None, None]:
    path = Path.cwd() / f".local-prompt-test-{uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


class _Ids:
    def __init__(self) -> None:
        self.value = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.value += 1
        return kind(f"local-prompt-{self.value}")


class _Clock:
    def now(self) -> datetime:
        return datetime(2026, 9, 20, tzinfo=UTC)

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
            if isinstance(value.meta, RecordMeta)
            and str(value.meta.analysis_id) == analysis_id
            and value.meta.record_type == kind
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


class _Configuration:
    def __init__(self, records: _Records) -> None:
        self.records = records

    def register_prompt_entry(self, record: PromptRegistryEntry) -> StoredDataRef:
        return self.records.add(record)

    def register_prompt_payload(self, record: PromptPayload) -> StoredDataRef:
        return self.records.add(record)

    def register_call_spec(self, record: LLMCallSpec) -> StoredDataRef:
        return self.records.add(record)


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
) -> tuple[
    LocalEvaluationLLMConfigurationService,
    _Records,
    LocalArtifactStore,
]:
    records = _Records()
    queries = _Queries(records)
    configuration = _Configuration(records)
    artifacts = LocalArtifactStore(
        tmp_path / "artifacts",
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
    )
    prompt_registry = PromptRegistry(configuration, records, queries)  # type: ignore[arg-type]
    return (
        LocalEvaluationLLMConfigurationService(
            repository_root=Path.cwd(),
            records=records,  # type: ignore[arg-type]
            configuration=configuration,  # type: ignore[arg-type]
            prompt_registry=prompt_registry,
            artifacts=artifacts,
            ids=_Ids(),
            clock=_Clock(),
        ),
        records,
        artifacts,
    )


def _support(
    records: _Records,
    artifacts: LocalArtifactStore,
    *,
    result_kind: str,
    template_path: Path,
) -> tuple[LocalEvaluationPromptSupport, ProviderProfile]:
    template_ref = artifacts.commit(
        artifacts.stage_bytes(template_path.read_bytes(), "text/markdown")
    )
    schema_artifact_ref = artifacts.commit(
        artifacts.stage_bytes(b'{"type":"array"}', "application/schema+json")
    )
    implementation_ref = artifacts.commit(
        artifacts.stage_bytes(b"validator", "text/plain")
    )
    test_ref = artifacts.commit(artifacts.stage_bytes(b"test", "text/plain"))
    provider = _config_record(
        ProviderProfile,
        "provider_profile",
        profile_key="codex-local",
        provider="OPENAI",
        product="CODEX",
        transport="CODEX_CLIENT",
        model="gpt-5.6-sol",
        environment="PERSONAL_LOCAL",
        auth_mode="SUBSCRIPTION_LOGIN",
        client_name="codex-cli",
        client_version="0.152.1",
        credential_source="OFFICIAL_CLIENT_SESSION",
        validation_evidence_ref={
            "stored_data_id": "provider-validation-stored",
            "data_kind": "provider_validation_evidence",
            "record_id": "provider-validation-record",
            "content_hash": "f" * 64,
            "workspace_id": "ws1",
            "commit_id": "c1",
        },
        client_execution_profile_ref={
            "stored_data_id": "client-execution-profile-stored",
            "data_kind": "client_execution_profile",
            "record_id": "client-execution-profile-record",
            "content_hash": "e" * 64,
            "workspace_id": "ws1",
            "commit_id": "c1",
        },
        capabilities={
            "non_interactive": "SUPPORTED",
            "structured_output": "SUPPORTED",
            "new_session": "SUPPORTED",
            "resume_session": "UNSUPPORTED",
            "parallel_calls": "SUPPORTED",
            "cancellation": "SUPPORTED",
            "timeout_detection": "SUPPORTED",
            "auth_expiry_detection": "SUPPORTED",
            "rate_limit_detection": "SUPPORTED",
            "request_id": "SUPPORTED",
            "token_usage": "SUPPORTED",
            "session_metadata": "SUPPORTED",
            "runtime_tool_loop": "UNSUPPORTED",
        },
        support_status="SUPPORTED",
    )
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
        schema_artifact_ref=schema_artifact_ref,
        result_kind=result_kind,
    )
    semantic = _config_record(
        SemanticValidatorSpec,
        "semantic_validator_spec",
        implementation_ref=implementation_ref,
        test_refs=(test_ref,),
    )
    refs = tuple(
        records.add(record)
        for record in (provider, limits, retry, tools, redaction, schema, semantic)
    )
    return (
        LocalEvaluationPromptSupport(
            template_ref=template_ref,
            provider_profile_ref=refs[0],
            execution_limits_ref=refs[1],
            retry_policy_ref=refs[2],
            tool_policy_ref=refs[3],
            redaction_policy_ref=refs[4],
            output_schema_ref=refs[5],
            semantic_validator_ref=refs[6],
        ),
        provider,
    )


def _scope() -> RecordMeta:
    return RecordMeta.model_validate_json(
        json.dumps(meta("configuration", hypothesis=None, attempt=None))
    )


def _work() -> WorkExecutionState:
    payload = make("WorkExecutionState")
    payload["meta"] = meta("work_execution_state", hypothesis="h1", attempt=None)
    return WorkExecutionState.model_validate_json(
        json.dumps(
            payload
            | {
                "work_type": "VERIFICATION",
                "subject_type": "HYPOTHESIS",
                "subject_id": "h1",
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


def test_local_route_set_uses_all_canonical_agent_templates_except_execute() -> None:
    keys = {
        (route.role, route.task_kind)
        for route in REQUIRED_LOCAL_EVALUATION_PROMPT_ROUTES
    }

    assert len(keys) == 16
    assert ("DYNAMIC_REPRODUCTION", "EXECUTE_REPRODUCTION") not in keys
    assert {route.role for route in REQUIRED_LOCAL_EVALUATION_PROMPT_ROUTES} == {
        "HYPOTHESIS",
        "PRO",
        "CON",
        "VERIFICATION",
        "DYNAMIC_REPRODUCTION",
        "CWE_LABELING",
        "TECHNICAL_GATE",
        "RULE_SCOPE_GATE",
        "REPORTER",
        "POLICY_PARSER",
        "CHAINING",
    }
    for route in REQUIRED_LOCAL_EVALUATION_PROMPT_ROUTES:
        text = route.template_path.read_text(encoding="utf-8")
        assert all(f"# {section}" in text for section in REQUIRED_TEMPLATE_SECTIONS)


def test_local_route_builds_exact_new_session_payload_without_production_authority(
    work_path: Path,
) -> None:
    service, records, artifacts = _service(work_path)
    required = REQUIRED_LOCAL_EVALUATION_PROMPT_ROUTES[0]
    support, provider = _support(
        records,
        artifacts,
        result_kind=required.result_kind,
        template_path=required.template_path,
    )
    route = LocalEvaluationRoute(
        role=required.role,
        task_kind=required.task_kind,
        provider_profile_key=provider.profile_key,
        model=provider.model,
        prompt_key="hypothesis.generate-initial.local-v1",
    )
    approved = service.activate_route(
        scope=_scope(),
        route=route,
        support=support,
        input_slots=(
            PromptInputSlot(
                slot="facts",
                data_kind="static_fact_bundle",
                field_paths=(
                    "/entities",
                    "/locations",
                    "/tool_runs",
                    "/gaps",
                    "/errors",
                ),
                cardinality="REQUIRED_ONE",
                trust_class="UNTRUSTED_DATA",
            ),
        ),
    )
    entry = records.get_exact(approved.active_prompt_ref)
    assert isinstance(entry, PromptRegistryEntry)
    assert entry.purpose == "LOCAL_EVALUATION"
    assert entry.session_policy == "NEW"
    assert entry.quality_evaluation_ref is None
    assert entry.provider_profile_refs == (support.provider_profile_ref,)

    facts = StaticFactBundle.model_validate_json(json.dumps(bundle()))
    facts_ref = records.add(facts)
    prepared = service.prepare_call(
        route=route,
        approved=approved,
        work=_work(),
        sources=(PromptSource("facts", facts_ref, facts),),
    )

    assert prepared.payload.purpose == "LOCAL_EVALUATION"
    assert prepared.call_spec.purpose == "LOCAL_EVALUATION"
    assert prepared.call_spec.provider_profile_ref == support.provider_profile_ref
    assert prepared.call_spec.model == provider.model
    assert prepared.call_spec.session_policy == "NEW"
    assert prepared.call_spec.parent_session_ref is None
    assert not hasattr(approved, "quality_evaluation_ref")
    assert not hasattr(service, "evaluation_recommendation")


def test_execute_reproduction_route_is_explicitly_unavailable(work_path: Path) -> None:
    service, records, artifacts = _service(work_path)
    support, provider = _support(
        records,
        artifacts,
        result_kind="dynamic_reproduction_tool_request",
        template_path=Path(
            "src/sastsimi/prompts/templates/dynamic-reproduction/"
            "execute-reproduction/1.0.1.md"
        ),
    )
    route = LocalEvaluationRoute(
        role="DYNAMIC_REPRODUCTION",
        task_kind="EXECUTE_REPRODUCTION",
        provider_profile_key=provider.profile_key,
        model=provider.model,
        prompt_key="dynamic.execute.local-v1",
    )

    with pytest.raises(ValueError, match=LOCAL_EVALUATION_EXECUTE_UNAVAILABLE):
        service.activate_route(
            scope=_scope(), route=route, support=support, input_slots=()
        )


def test_local_route_rejects_model_or_provider_drift(work_path: Path) -> None:
    service, records, artifacts = _service(work_path)
    required = REQUIRED_LOCAL_EVALUATION_PROMPT_ROUTES[0]
    support, provider = _support(
        records,
        artifacts,
        result_kind=required.result_kind,
        template_path=required.template_path,
    )
    route = LocalEvaluationRoute(
        role=required.role,
        task_kind=required.task_kind,
        provider_profile_key=provider.profile_key,
        model="different-model",
        prompt_key="hypothesis.generate-initial.local-v1",
    )

    with pytest.raises(ValueError, match="LOCAL_EVALUATION_PROVIDER_ROUTE_MISMATCH"):
        service.activate_route(
            scope=_scope(), route=route, support=support, input_slots=()
        )
