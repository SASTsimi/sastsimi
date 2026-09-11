"""Official policy fetches fail closed before unsafe bytes are persisted."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, ProgramId, WorkspaceId
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef
from sastsimi.policy.adapters.official_http import (
    HttpPolicyResponse,
    OfficialHttpPolicySource,
    PinnedHttpRequest,
    PolicyFetchError,
    PolicySourceBoundaryError,
)
from sastsimi.policy.program_catalog import ProgramCatalog, ProgramCatalogEntry
from sastsimi.ports.dto import OfficialPolicyFetchRequest
from sastsimi.storage.artifact_store import LocalArtifactStore
from tests.integration.runtime_support import TestClock
from tests.unit.contracts.test_core_models import action, meta, ref


@dataclass
class _Transport:
    responses: list[HttpPolicyResponse | Exception]
    calls: list[PinnedHttpRequest]

    async def send(self, request: PinnedHttpRequest) -> HttpPolicyResponse:
        self.calls.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _request(source_config_ref: BudgetScopeRef) -> OfficialPolicyFetchRequest:
    fetch_action = ActionRequest.model_validate_json(
        canonical_bytes(
            action(
                meta=meta(
                    True,
                    record_type="action_request",
                    attempt_id="attempt-1",
                ),
                requested_by="POLICY_COLLECTOR",
                requester_identity_ref=ref("agent_identity", True),
                action_type="FETCH_POLICY",
                work_ref=ref(code=True),
                expected_state_version=2,
                input_refs=[source_config_ref],
                reason="Fetch the catalog-approved official policy",
            )
        )
    )
    return OfficialPolicyFetchRequest(
        action=fetch_action,
        program_id=ProgramId("program"),
        source_config_ref=source_config_ref,
    )


def _subject(
    root: Path,
    *,
    responses: list[HttpPolicyResponse | Exception],
    resolver: Mapping[str, tuple[str, ...]],
    max_bytes: int = 64,
) -> tuple[
    OfficialHttpPolicySource,
    _Transport,
    LocalArtifactStore,
    BudgetScopeRef,
]:
    artifacts = LocalArtifactStore(
        root / "artifacts", WorkspaceId("w1"), CommitId("c1")
    )
    source_config = StoredDataRef.model_validate(
        ref("policy_source_config", True)
    )
    freshness = StoredDataRef.model_validate(
        ref("policy_freshness_criterion", True)
    )
    entry = ProgramCatalogEntry(
        program_id=ProgramId("program"),
        program_namespace="example",
        external_program_id="external-1",
        source_config_ref=source_config,
        source_version="2026-09-12",
        official_endpoint="https://policy.example.test/program",
        publisher="Example Security",
        parser_name="policy-parser",
        parser_version="1.0.0",
        freshness_criterion_ref=freshness,
        freshness_ttl_seconds=3600,
        timeout_seconds=2,
        max_response_bytes=max_bytes,
        allowed_content_types=("application/json",),
        allowed_redirect_hosts=("policy.example.test",),
    )
    transport = _Transport(responses, [])
    subject = OfficialHttpPolicySource(
        catalog=ProgramCatalog((entry,)),
        artifacts=artifacts,
        transport=transport,
        resolver=lambda host: resolver[host],
        clock=TestClock(),
    )
    return subject, transport, artifacts, source_config


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    ["private_dns", "redirect", "oversized", "timeout"],
)
async def test_unsafe_policy_source_is_rejected_before_body_persistence(
    tmp_path: Path, case: str
) -> None:
    """Catches SSRF, redirect escape, or oversized content reaching artifacts."""
    public = {"policy.example.test": ("93.184.216.34",)}
    responses = [
        HttpPolicyResponse(
            status=200,
            headers={"content-type": "application/json"},
            body=b'{"policy":"ok"}',
            peer_ip="93.184.216.34",
        )
    ]
    resolver = public
    max_bytes = 64
    if case == "private_dns":
        resolver = {"policy.example.test": ("127.0.0.1",)}
    elif case == "redirect":
        responses = [
            HttpPolicyResponse(
                status=302,
                headers={"location": "https://127.0.0.1/private"},
                body=b"",
                peer_ip="93.184.216.34",
            )
        ]
    elif case == "oversized":
        max_bytes = 8
    else:
        responses = [TimeoutError()]
    subject, transport, artifacts, source_config = _subject(
        tmp_path,
        responses=responses,
        resolver=resolver,
        max_bytes=max_bytes,
    )
    before = tuple((artifacts.root / "sha256").rglob("*"))

    expected = PolicyFetchError if case == "timeout" else PolicySourceBoundaryError
    with pytest.raises(expected):
        await subject.fetch_official(_request(source_config))

    after = tuple((artifacts.root / "sha256").rglob("*"))
    assert after == before
    if case == "private_dns":
        assert transport.calls == []


@pytest.mark.asyncio
async def test_policy_source_redacts_secret_like_values_before_commit(
    tmp_path: Path,
) -> None:
    """Removing redaction would persist an authorization value in the body."""
    raw = b'{"authorization":"Bearer private-value","scope":"public"}'
    subject, _, artifacts, source_config = _subject(
        tmp_path,
        responses=[
            HttpPolicyResponse(
                status=200,
                headers={
                    "content-type": "application/json",
                    "etag": '"v1"',
                    "last-modified": "Fri, 12 Sep 2026 00:00:00 GMT",
                    "set-cookie": "session=private",
                },
                body=raw,
                peer_ip="93.184.216.34",
            )
        ],
        resolver={"policy.example.test": ("93.184.216.34",)},
    )

    source = await subject.fetch_official(_request(source_config))

    parsed = json.loads(source.content)
    assert parsed == {"authorization": "<redacted>", "scope": "public"}
    assert b"private-value" not in source.content
    assert b"<redacted>" in source.content
    stored = artifacts.open_verified(source.source_check.source_ref).read()
    assert stored == source.content
    provenance = artifacts.open_verified(source.source_check.evidence_refs[0]).read()
    assert b"private" not in provenance
    assert b"set-cookie" not in provenance.lower()


@pytest.mark.asyncio
async def test_unknown_program_is_rejected_before_transport(tmp_path: Path) -> None:
    subject, transport, _, source_config = _subject(
        tmp_path,
        responses=[],
        resolver={"policy.example.test": ("93.184.216.34",)},
    )
    request = _request(source_config)
    wrong = OfficialPolicyFetchRequest(
        action=request.action,
        program_id=ProgramId("unknown-program"),
        source_config_ref=request.source_config_ref,
    )

    with pytest.raises(ValueError, match="POLICY_PROGRAM_UNKNOWN_OR_AMBIGUOUS"):
        await subject.fetch_official(wrong)

    assert transport.calls == []
