"""Real-storage coverage for safe provider output artifacts."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, cast

import pytest
from sqlalchemy import select

from sastsimi.bootstrap import build_runtime, upgrade_database
from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import AttemptId
from sastsimi.contracts.llm import (
    LLMCallSpec,
    LLMInvocationRequest,
    LLMInvocationResult,
    OutputSchemaSpec,
    PromptPayload,
    ProviderValidationEvidence,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.orchestration.fake_setup import FakeSetupDependencies, FakeSetupStages
from sastsimi.ports.dto import (
    CancellationResult,
    CapabilityProbeResult,
    OfficialPolicyFetchRequest,
    OfficialPolicySource,
)
from sastsimi.prompts.validation import validate_output
from sastsimi.providers.base import (
    NormalizedProviderResult,
    ProviderInvalidOutputError,
    StructuredOutputValue,
)
from sastsimi.providers.fake import FakeProviderAdapter
from sastsimi.providers.storage_io import (
    StoredInvocationResultBuilder,
    StoredOutputValidator,
)
from sastsimi.runtime.fake_llm_configuration import register_fake_llm_call
from sastsimi.runtime.fake_support import (
    FakeClock,
    FakeEvidence,
    FakeIds,
    FakeRecordFactory,
)
from sastsimi.runtime.llm_call_service import llm_action_input_refs
from sastsimi.storage import models
from sastsimi.storage.artifact_store import LocalArtifactStore
from sastsimi.storage.database import Database
from sastsimi.storage.repositories import SQLiteRecordStore


class _ValidatedArtifactAdapter:
    """Exercise the production validator/builder while replacing only network I/O."""

    def __init__(
        self,
        *,
        records: SQLiteRecordStore,
        artifacts: LocalArtifactStore,
        output_schema_ref: StoredDataRef,
        semantic_validator_ref: StoredDataRef,
        raw_output: bytes,
        metadata_factory: Any,
        clock: FakeClock,
    ) -> None:
        self._records = records
        self._raw_output = raw_output
        self._clock = clock
        self._output_schema_ref = output_schema_ref
        self._validator = StoredOutputValidator(
            records,
            {semantic_validator_ref: lambda _value: None},
            validate_output,
        )
        self._builder = StoredInvocationResultBuilder(
            records,
            artifacts,
            metadata_factory,
        )

    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult:
        schema = self._records.get_exact(self._output_schema_ref)
        assert isinstance(schema, OutputSchemaSpec)
        started_at = self._clock.now()
        try:
            validated = self._validator.validate(
                self._raw_output,
                schema={},
                output_schema=schema,
                request=request,
            )
        except ProviderInvalidOutputError:
            outcome = NormalizedProviderResult(
                status="INVALID_OUTPUT",
                provider="OPENAI",
                model=request.model,
                actual_session_mode="NEW",
                session_ref=None,
                response_text=None,
                parsed_output=None,
                validated_output=None,
                usage=None,
                started_at=started_at,
                finished_at=self._clock.now(),
                elapsed_ms=0,
                safe_error=(
                    "INVALID_OUTPUT: provider returned invalid structured output"
                ),
            )
        else:
            parsed = cast(StructuredOutputValue, json.loads(self._raw_output))
            outcome = NormalizedProviderResult(
                status="SUCCEEDED",
                provider="OPENAI",
                model=request.model,
                actual_session_mode="NEW",
                session_ref="local-session",
                response_text=self._raw_output.decode("utf-8"),
                parsed_output=parsed,
                validated_output=validated,
                usage=None,
                started_at=started_at,
                finished_at=self._clock.now(),
                elapsed_ms=0,
                safe_error=None,
            )
        return self._builder.build(request, outcome)

    async def probe(
        self, candidate: ProviderValidationEvidence
    ) -> CapabilityProbeResult:
        return CapabilityProbeResult(candidate)

    async def cancel(self, invocation_id: str) -> CancellationResult:
        del invocation_id
        return CancellationResult(False, "No active test invocation")


async def _unused_provider_call(
    request: LLMInvocationRequest, result: LLMInvocationResult
) -> LLMInvocationResult:
    del request
    return result


async def _probe_provider(
    candidate: ProviderValidationEvidence,
) -> CapabilityProbeResult:
    return await FakeProviderAdapter({}).probe(candidate)


async def _unused_policy_fetch(
    request: OfficialPolicyFetchRequest, expected: OfficialPolicySource
) -> OfficialPolicySource:
    del request
    return expected


def _record_kinds(database: Database) -> set[str]:
    with database.engine.connect() as connection:
        return set(connection.execute(select(models.records.c.kind)).scalars())


async def _invoke(
    root: Path, raw_output: bytes
) -> tuple[LLMInvocationResult, StoredDataRef, Database, LocalArtifactStore]:
    clock = FakeClock()
    ids = FakeIds()
    evidence = FakeEvidence()
    records = FakeRecordFactory(clock, ids)
    setup = FakeSetupStages(
        FakeSetupDependencies(
            data_dir=root,
            runtime_builder=build_runtime,
            database_upgrader=upgrade_database,
            provider_invoke=_unused_provider_call,
            provider_probe=_probe_provider,
            policy_fetch=_unused_policy_fetch,
            clock=clock,
            ids=ids,
            evidence=evidence,
            records=records,
        )
    )
    scope, _owner_ref, orchestrator_ref = setup._bootstrap()
    assert setup.runtime is not None and setup.runner is not None
    runtime = setup.runtime
    runner = setup.runner
    work = runner.start(
        scope,
        records.record_meta("hypothesis_stage"),
        "HYPOTHESIS_PROPOSAL",
        "PROPOSAL",
        "sqlite-provider-output",
        orchestrator_ref,
    )
    call_spec_ref, provider_ref = await asyncio.to_thread(
        register_fake_llm_call,
        runtime,
        evidence,
        records.record_meta,
        records.artifact,
        clock.now(),
        _probe_provider,
        runner=runner,
        work=work,
        scope=scope,
        orchestration_identity=orchestrator_ref,
        role="HYPOTHESIS",
        result_kind="hypothesis_proposal",
    )
    spec = runtime.unit_of_work.records.get_exact(call_spec_ref)
    assert isinstance(spec, LLMCallSpec)
    payload = runtime.unit_of_work.records.get_exact(spec.prompt_payload_ref)
    assert isinstance(payload, PromptPayload)

    def invocation_meta(
        source: RecordMeta, record_type: str, attempt_id: AttemptId | None
    ) -> RecordMeta:
        return RecordMeta.model_validate(
            runner.metadata(source, record_type, attempt_id=attempt_id)
        )

    adapter = _ValidatedArtifactAdapter(
        records=cast(SQLiteRecordStore, runtime.unit_of_work.records),
        artifacts=cast(LocalArtifactStore, runtime.unit_of_work.artifacts),
        output_schema_ref=spec.output_schema_ref,
        semantic_validator_ref=spec.semantic_validator_ref,
        raw_output=raw_output,
        metadata_factory=invocation_meta,
        clock=clock,
    )
    resolver = cast(Any, runtime.llm_calls)._adapters
    cast(Any, resolver)._adapters[(provider_ref, spec.model)] = adapter
    identity = evidence.stored_identity(RequesterRole.HYPOTHESIS)
    action = runner.action(
        work,
        identity,
        RequesterRole.HYPOTHESIS.value,
        "CALL_LLM",
        llm_call_spec_ref=call_spec_ref,
        provider_profile_ref=provider_ref,
        session_mode="NEW",
        input_refs=llm_action_input_refs(call_spec_ref, spec, payload),
    )
    reservation = runner.reserve(
        work,
        scope,
        action,
        runner.units(elapsed_ms=1, llm_call_count=1, cost_minor_units=1),
    )
    decision = runner.authorize(work, action, reservation)
    assert isinstance(decision, StoredDataRef)
    reservation_ref = runtime.unit_of_work.records.stage_record(reservation)
    outcome = await runtime.llm_calls.invoke(
        work=work,
        decision_ref=decision,
        reservation_ref=reservation_ref,
        call_spec_ref=call_spec_ref,
    )
    paths = RuntimePaths(root)
    database = Database(paths.database)
    assert isinstance(work.meta, RecordMeta)
    reopened_artifacts = LocalArtifactStore(
        paths.artifacts, work.meta.workspace_id, work.meta.commit_id
    )
    result_ref = reference(outcome.result)
    assert isinstance(result_ref, StoredDataRef)
    return outcome.result, result_ref, database, reopened_artifacts


@pytest.mark.asyncio
async def test_sqlite_invocation_persists_canonical_json_artifact_only(
    tmp_path: Path,
) -> None:
    raw = b'{"statement": "untrusted input reaches a SQL sink"}'

    result, result_ref, database, artifacts = await _invoke(tmp_path, raw)

    assert result.status == "SUCCEEDED"
    assert result.parsed_output_ref is not None
    assert result.response_ref == result.parsed_output_ref
    with artifacts.open_verified(result.parsed_output_ref) as stream:
        assert stream.read() == canonical_bytes(json.loads(raw))
    reopened_records = SQLiteRecordStore(database)
    assert reopened_records.get_exact(result_ref) == result
    assert "hypothesis_proposal" not in _record_kinds(database)


@pytest.mark.asyncio
async def test_sqlite_invalid_runtime_owned_output_has_no_domain_result_or_refs(
    tmp_path: Path,
) -> None:
    raw = canonical_bytes(
        {
            "meta": {"record_id": "provider-owned-record"},
            "proposal_id": "provider-owned-proposal",
            "statement": "must not become a domain record",
        }
    )

    result, result_ref, database, artifacts = await _invoke(tmp_path, raw)

    assert result.status == "INVALID_OUTPUT"
    assert result.response_ref is None
    assert result.parsed_output_ref is None
    reopened_records = SQLiteRecordStore(database)
    assert reopened_records.get_exact(result_ref) == result
    assert not _record_kinds(database).intersection(
        {"hypothesis_proposal", "vulnerability_hypothesis", "verification_result"}
    )

    safe_ref = artifacts.commit(
        artifacts.stage_bytes(b'{"safe":true}', "application/json")
    )
    wrong_workspace = safe_ref.model_copy(update={"workspace_id": "other-workspace"})
    with pytest.raises(ValueError, match="WORKSPACE_MISMATCH"):
        artifacts.open_verified(wrong_workspace)
    wrong_hash = safe_ref.model_copy(update={"content_hash": "f" * 64})
    with pytest.raises(ValueError, match="Artifact reference mismatch"):
        artifacts.open_verified(wrong_hash)
