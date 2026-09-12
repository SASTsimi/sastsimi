"""Run-init policy preparation freezes one exact result independently of static work."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from sastsimi.agents.policy_parser import (
    ParsedPolicyContent,
    PolicyItemContent,
    PolicyParserAgentOutcome,
)
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.policy import (
    PolicyCacheRecord,
    PolicyParserResult,
    PolicySourceCheck,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.work import WorkAttempt
from sastsimi.policy.adapters.official_http import (
    PolicyFetchError,
    PolicySourceBoundaryError,
)
from sastsimi.policy.cache_service import PolicyCacheService
from sastsimi.policy.collector import PolicyCollector
from sastsimi.policy.preparation_service import PolicyPreparationService
from sastsimi.policy.program_catalog import ProgramCatalog, ProgramCatalogEntry
from sastsimi.policy.work_handler import PolicyWorkHandler
from sastsimi.ports.dto import OfficialPolicySource, WorkContext
from sastsimi.ports.policy_runtime import PolicyCacheKey
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.storage import models
from sastsimi.storage.artifact_store import LocalArtifactStore
from sastsimi.storage.policy_runtime import publish_current, validate_cache_head
from tests.integration.storage.test_intermediate_publication import (
    prepared_policy_parser,
)


class _Source:
    def __init__(self, result: OfficialPolicySource | Exception) -> None:
        self.result = result
        self.calls = 0

    async def fetch_official(self, request: Any) -> OfficialPolicySource:
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        assert request.source_config_ref in request.action.input_refs
        return self.result


class _Parser:
    def __init__(
        self,
        *,
        runner: WorkflowRunner,
        invocation_ref: StoredDataRef,
        parsed_ref: StoredDataRef,
        parser_name: str,
        parser_version: str,
    ) -> None:
        self.runner = runner
        self.invocation_ref = invocation_ref
        self.parsed_ref = parsed_ref
        self.parser_name = parser_name
        self.parser_version = parser_version
        self.calls = 0

    async def parse(
        self, *, work: Any, source_ref: StoredDataRef
    ) -> PolicyParserAgentOutcome:
        self.calls += 1
        result = PolicyParserResult.model_validate(
            dict(
                meta=self.runner.metadata(
                    work.meta,
                    "policy_parser_result",
                    attempt_id=work.active_attempt_id,
                ),
                parser_result_id="parser-result",
                parser_name=self.parser_name,
                parser_version=self.parser_version,
                source_ref=source_ref,
                llm_invocation_ref=self.invocation_ref,
                parsed_output_ref=self.parsed_ref,
                status="SUCCEEDED",
                error_ids=(),
                completed_at=self.runner.clock.now(),
            )
        )
        content = ParsedPolicyContent(
            document_status="FOUND",
            policy_version="2026-09",
            in_scope_assets=(
                PolicyItemContent(
                    item_key="asset-main",
                    value="example.test",
                    description="Officially listed asset",
                    conditions=(),
                    source_locator="$.scope.in[0]",
                ),
            ),
            out_of_scope_assets=(),
            accepted_vulnerability_classes=(),
            excluded_vulnerability_classes=(),
            testing_restrictions=(),
            reward_conditions=(),
            impact_criteria=(),
            disclosure_requirements=(),
            missing_information=(),
        )
        return PolicyParserAgentOutcome(result, content, (self.invocation_ref,))


def _artifact(root: Path, work: Any, value: bytes) -> StoredDataRef:
    artifacts = LocalArtifactStore(
        root / "policy-artifacts",
        work.meta.workspace_id,
        work.meta.commit_id,
    )
    return artifacts.commit(artifacts.stage_bytes(value, "application/json"))


def _attempt(h: Any, work: Any) -> WorkAttempt:
    with h.database.engine.connect() as connection:
        payload = connection.execute(
            select(models.work_attempts.c.payload).where(
                models.work_attempts.c.attempt_id == str(work.active_attempt_id)
            )
        ).scalar_one()
    return WorkAttempt.model_validate_json(payload)


def _runner_with_output_approval(h: Any, runtime: Any) -> WorkflowRunner:
    @contextmanager
    def approve(action: Any, _work: Any, refs: tuple[Any, ...]) -> Iterator[None]:
        old = h.evidence.authorized_outputs
        h.evidence.authorized_outputs = lambda request: (
            refs if request.action_id == action.action_id else old(request)
        )
        try:
            yield
        finally:
            h.evidence.authorized_outputs = old

    return WorkflowRunner(runtime, h.clock, h.ids, output_approval=approve)


def _subject(
    tmp_path: Path, source_failure: Exception | None = None
) -> tuple[Any, ...]:
    h, runtime, _, work, *_ = prepared_policy_parser(
        tmp_path,
        parallel=2,
        prepare=True,
    )
    runner = _runner_with_output_approval(h, runtime)
    preparing = runtime.policy.current_state(str(work.meta.analysis_id))
    assert preparing is not None
    collector_identity = preparing.source_config_ref
    parser_identity = work.last_transition_ref
    assert isinstance(parser_identity, StoredDataRef)
    h.evidence.identities[collector_identity] = RequesterRole.POLICY_COLLECTOR
    h.evidence.identities[parser_identity] = RequesterRole.POLICY_PARSER
    parsed_ref = _artifact(tmp_path, work, b'{"parsed":true}')
    source_ref = _artifact(
        tmp_path,
        work,
        b'{"scope":{"in":["example.test"]}}',
    )
    evidence_ref = _artifact(tmp_path, work, b'{"etag":"v1"}')
    source_result: OfficialPolicySource | Exception = (
        source_failure
        if source_failure is not None
        else OfficialPolicySource(
            PolicySourceCheck(
                source_id="official-program-policy",
                source_ref=source_ref,
                source_url="https://policy.example.test/program",
                publisher="Example Security",
                status="VERIFIED",
                evidence_refs=(evidence_ref,),
                checked_at=h.clock.now(),
            ),
            b'{"scope":{"in":["example.test"]}}',
        )
    )
    entry = ProgramCatalogEntry(
        program_id=preparing.program_id,
        program_namespace="example",
        external_program_id="external-program",
        source_config_ref=preparing.source_config_ref,
        source_version="2026-09-12",
        official_endpoint="https://policy.example.test/program",
        publisher="Example Security",
        parser_name=preparing.parser_name,
        parser_version=preparing.parser_version,
        freshness_criterion_ref=parser_identity,
        freshness_ttl_seconds=3600,
        timeout_seconds=2,
        max_response_bytes=1024,
        allowed_content_types=("application/json",),
    )
    source = _Source(source_result)
    parser = _Parser(
        runner=runner,
        invocation_ref=parser_identity,
        parsed_ref=parsed_ref,
        parser_name=preparing.parser_name,
        parser_version=preparing.parser_version,
    )
    cache = PolicyCacheService(runtime=runtime.policy, records=h.records)
    collector = PolicyCollector(
        runner=runner,
        policy_runtime=runtime.policy,
        ids=h.ids,
        clock=h.clock,
    )
    service = PolicyPreparationService(
        runtime=runtime,
        runner=runner,
        catalog=ProgramCatalog((entry,)),
        source=source,
        parser=parser,
        cache=cache,
        collector=collector,
        collector_identity_ref=collector_identity,
        parser_identity_ref=parser_identity,
    )
    return h, runtime, runner, work, entry, source, parser, service


@pytest.mark.asyncio
async def test_found_policy_freezes_while_static_work_remains_independent(
    tmp_path: Path,
) -> None:
    h, runtime, runner, work, _, source, parser, service = _subject(tmp_path)
    scope = runtime.work.registration_scope(str(work.work_id))
    preparing = runtime.policy.current_state(str(work.meta.analysis_id))
    assert preparing is not None
    orchestration = preparing.source_config_ref
    h.evidence.identities[orchestration] = RequesterRole.ORCHESTRATION
    static = runner.enqueue(
        scope,
        work.meta,
        "STATIC_NORMALIZE",
        "ANALYSIS",
        str(work.meta.analysis_id),
        orchestration,
        inputs=(),
    )
    h.evidence.identities[orchestration] = RequesterRole.POLICY_COLLECTOR

    result = await PolicyWorkHandler(service).execute(
        WorkContext(work, _attempt(h, work))
    )

    final = runtime.policy.current_state(str(work.meta.analysis_id))
    assert final is not None
    assert final.status == "CURRENT"
    assert final.policy_record_ref is not None
    assert final.policy_cache_ref is not None
    assert source.calls == 1
    assert parser.calls == 1
    assert runtime.work.get(str(static.work_id)).status == "READY"
    assert result.output_refs == runtime.work.get(str(work.work_id)).output_refs


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected_state"),
    [
        (PolicyFetchError("temporary fetch failure"), "BLOCKED"),
        (PolicySourceBoundaryError("source boundary violation"), "FAILED"),
    ],
)
async def test_expired_cache_failure_is_not_old_success(
    tmp_path: Path,
    failure: Exception,
    expected_state: str,
) -> None:
    h, runtime, _, work, entry, source, parser, service = _subject(
        tmp_path,
        source_failure=failure,
    )
    preparing = runtime.policy.current_state(str(work.meta.analysis_id))
    assert preparing is not None
    key = PolicyCacheKey(
        program_id=entry.program_id,
        source_config_hash=entry.source_config_ref.content_hash,
        parser_name=entry.parser_name,
        parser_version=entry.parser_version,
        freshness_criterion_hash=entry.freshness_criterion_ref.content_hash,
    )
    checked_at = h.clock.now() - timedelta(days=2)
    stale_record_ref = entry.freshness_criterion_ref
    old = PolicyCacheRecord.model_validate(
        dict(
            meta=runtime.policy.cache_metadata(key, schema_version="1.0.0"),
            source_config_ref=entry.source_config_ref,
            parser_name=entry.parser_name,
            parser_version=entry.parser_version,
            collection_status="FOUND",
            collection_result_ref=stale_record_ref,
            parser_result_refs=(stale_record_ref,),
            policy_record_ref=stale_record_ref,
            freshness_criterion_ref=entry.freshness_criterion_ref,
            freshness_checked_at=checked_at,
            freshness_evidence_refs=(entry.freshness_criterion_ref,),
            freshness_valid_until=checked_at + timedelta(hours=1),
            published_at=checked_at,
        )
    )
    with h.database.write() as connection:
        validate_cache_head(connection, old, exact_key=True)
        old_ref = h.records.stage(connection, old)
        h.records.publish(connection, old_ref)
        publish_current(connection, old, None)

    await PolicyWorkHandler(service).execute(WorkContext(work, _attempt(h, work)))

    final = runtime.policy.current_state(str(work.meta.analysis_id))
    assert final is not None
    assert final.status == expected_state
    assert final.policy_cache_ref is None
    assert final.collection_result_ref is not None
    collection = h.records.get_exact(final.collection_result_ref)
    assert collection.status == "COLLECTION_FAILED"
    assert source.calls == 1
    assert parser.calls == 0
    assert runtime.policy.current_cache(key) == old
