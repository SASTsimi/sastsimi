from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from sastsimi.composition.production_composition import (
    ProductionCapabilityUnavailable,
)
from sastsimi.composition.production_policy_builder import (
    build_policy_catalog_entry,
    policy_freshness_evidence_bytes,
    policy_source_evidence_bytes,
)
from sastsimi.config.production_profile import PolicySource
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    LogicalRecordId,
    ProgramId,
    RecordId,
    WorkspaceId,
)
from sastsimi.contracts.policy import (
    OfficialPolicySourceConfig,
    PolicyFreshnessCriterion,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.orchestration.production_provisioning import PolicyCatalogProvisioning
from sastsimi.storage.artifact_store import LocalArtifactStore


def _policy() -> PolicySource:
    return PolicySource(
        program_namespace="hackerone",
        external_program_id="example",
        source_version="2026-09-13",
        official_endpoint="https://example.com/security-policy",
        publisher="example",
        parser_name="policy-v1",
        parser_version="1.0.0",
        freshness_ttl_seconds=3600,
        timeout_seconds=10,
        max_response_bytes=1_000_000,
        allowed_content_types=("text/html",),
    )


def _document(policy: PolicySource) -> tuple[PolicyCatalogProvisioning, bytes, bytes]:
    source = policy_source_evidence_bytes(ProgramId("program-1"), policy)
    freshness = policy_freshness_evidence_bytes(ProgramId("program-1"), policy)
    source_digest = hashlib.sha256(source).hexdigest()
    freshness_digest = hashlib.sha256(freshness).hexdigest()
    source_record = _source_record(policy, source_digest)
    freshness_record = _freshness_record(policy, freshness_digest)
    return (
        PolicyCatalogProvisioning(
            schema_version=1,
            slot="POLICY_CATALOG",
            profile_hash="a" * 64,
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="b" * 40,
            record_refs=(
                cast(StoredDataRef, reference(source_record)),
                cast(StoredDataRef, reference(freshness_record)),
            ),
            evidence_sha256=(source_digest, freshness_digest),
            source_configuration_sha256=source_digest,
            freshness_criterion_sha256=freshness_digest,
            parser_implementation_key="OFFICIAL_HTTP_POLICY_V1",
        ),
        source,
        freshness,
    )


def _meta(kind: str, suffix: str) -> RecordMeta:
    return RecordMeta(
        record_id=RecordId(f"record-{suffix}"),
        logical_record_id=LogicalRecordId(f"logical-{suffix}"),
        record_type=kind,
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=datetime(2026, 9, 13, tzinfo=UTC),
        analysis_id=AnalysisId("analysis-1"),
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("b" * 40),
        hypothesis_id=None,
        attempt_id=None,
    )


def _source_record(policy: PolicySource, digest: str) -> OfficialPolicySourceConfig:
    from sastsimi.contracts.ids import StoredDataId
    from sastsimi.contracts.refs import StoredDataRef

    return OfficialPolicySourceConfig(
        meta=_meta(OfficialPolicySourceConfig.KIND, "source"),
        program_id=ProgramId("program-1"),
        source_artifact_ref=StoredDataRef(
            stored_data_id=StoredDataId(digest),
            data_kind="artifact",
            content_hash=digest,
            workspace_id=WorkspaceId("workspace-1"),
            commit_id=CommitId("b" * 40),
            record_id=None,
        ),
        program_namespace=policy.program_namespace,
        external_program_id=policy.external_program_id,
        source_version=policy.source_version,
        official_endpoint=policy.official_endpoint,
        publisher=policy.publisher,
        parser_name=policy.parser_name,
        parser_version=policy.parser_version,
        timeout_seconds=policy.timeout_seconds,
        max_response_bytes=policy.max_response_bytes,
        allowed_content_types=policy.allowed_content_types,
        allowed_redirect_hosts=policy.allowed_redirect_hosts,
    )


def _freshness_record(policy: PolicySource, digest: str) -> PolicyFreshnessCriterion:
    from sastsimi.contracts.ids import StoredDataId
    from sastsimi.contracts.refs import StoredDataRef

    return PolicyFreshnessCriterion(
        meta=_meta(PolicyFreshnessCriterion.KIND, "freshness"),
        program_id=ProgramId("program-1"),
        criterion_artifact_ref=StoredDataRef(
            stored_data_id=StoredDataId(digest),
            data_kind="artifact",
            content_hash=digest,
            workspace_id=WorkspaceId("workspace-1"),
            commit_id=CommitId("b" * 40),
            record_id=None,
        ),
        source_version=policy.source_version,
        freshness_ttl_seconds=policy.freshness_ttl_seconds,
    )


def test_builds_exact_catalog_entry_from_verified_evidence(tmp_path: Path) -> None:
    policy = _policy()
    document, source, freshness = _document(policy)
    source_record = _source_record(policy, hashlib.sha256(source).hexdigest())
    freshness_record = _freshness_record(policy, hashlib.sha256(freshness).hexdigest())
    artifacts = LocalArtifactStore(
        tmp_path / "artifacts", WorkspaceId("workspace-1"), CommitId("b" * 40)
    )
    for payload in (source, freshness):
        artifacts.commit(artifacts.stage_bytes(payload, "application/json"))

    entry = build_policy_catalog_entry(
        program_id=ProgramId("program-1"),
        analysis_id=AnalysisId("analysis-1"),
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("b" * 40),
        expected=policy,
        document=document,
        source_config=source_record,
        freshness_criterion=freshness_record,
        evidence={
            hashlib.sha256(source).hexdigest(): source,
            hashlib.sha256(freshness).hexdigest(): freshness,
        },
        artifacts=artifacts,
    )

    assert entry.program_id == ProgramId("program-1")
    assert entry.official_endpoint == policy.official_endpoint
    assert entry.source_config_ref == reference(source_record)
    assert entry.freshness_criterion_ref == reference(freshness_record)


def test_rejects_profile_that_does_not_match_approved_policy_evidence(
    tmp_path: Path,
) -> None:
    policy = _policy()
    document, source, freshness = _document(policy)
    source_record = _source_record(policy, hashlib.sha256(source).hexdigest())
    freshness_record = _freshness_record(policy, hashlib.sha256(freshness).hexdigest())
    artifacts = LocalArtifactStore(
        tmp_path / "artifacts", WorkspaceId("workspace-1"), CommitId("b" * 40)
    )
    for payload in (source, freshness):
        artifacts.commit(artifacts.stage_bytes(payload, "application/json"))
    changed = policy.model_copy(
        update={"official_endpoint": "https://example.org/policy"}
    )

    with pytest.raises(ProductionCapabilityUnavailable) as failure:
        build_policy_catalog_entry(
            program_id=ProgramId("program-1"),
            analysis_id=AnalysisId("analysis-1"),
            workspace_id=WorkspaceId("workspace-1"),
            commit_id=CommitId("b" * 40),
            expected=changed,
            document=document,
            source_config=source_record,
            freshness_criterion=freshness_record,
            evidence={
                hashlib.sha256(source).hexdigest(): source,
                hashlib.sha256(freshness).hexdigest(): freshness,
            },
            artifacts=artifacts,
        )

    assert failure.value.reason_code == "PRODUCTION_POLICY_CONFIGURATION_STALE"
