"""Truthful production OpenAI Provider Verification Dataset probes."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

import pytest

from sastsimi.config.secrets import SecretReference
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.contracts.llm import ProviderValidationEvidence
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.providers.openai_api import OpenAIResponsesApiAdapter
from sastsimi.providers.openai_pvd import (
    OpenAIPVDCheckObservation,
    OpenAIResponsesPVDProbeRunner,
    PVDTestId,
)
from sastsimi.runtime.system_support import SystemClock
from sastsimi.storage.artifact_store import LocalArtifactStore

_CHECKED_AT = datetime(2026, 9, 13, 3, 0, tzinfo=UTC)
_COMMIT_ID = "b" * 40
_SECRET = "sk-this-must-never-reach-evidence"


class FixedClock:
    def now(self) -> datetime:
        return _CHECKED_AT

    def monotonic_ms(self) -> int:
        return 0


def _artifact_ref(digest: str) -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": digest,
            "data_kind": "artifact",
            "content_hash": digest,
            "workspace_id": "workspace-1",
            "commit_id": _COMMIT_ID,
            "record_id": None,
        }
    )


def _provider_ref() -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": "provider-profile",
            "data_kind": "provider_profile",
            "content_hash": "a" * 64,
            "workspace_id": "workspace-1",
            "commit_id": _COMMIT_ID,
            "record_id": "provider-profile-record",
        }
    )


def _candidate() -> ProviderValidationEvidence:
    recycled_ref = _artifact_ref("d" * 64)
    return ProviderValidationEvidence.model_validate(
        {
            "meta": {
                "record_id": "openai-pvd-evidence",
                "logical_record_id": "openai-pvd-evidence",
                "record_type": "provider_validation_evidence",
                "schema_version": "1.0.0",
                "revision_number": 1,
                "previous_record_id": None,
                "created_at": datetime(2026, 9, 13, 1, 0, tzinfo=UTC),
                "analysis_id": "analysis-1",
                "workspace_id": "workspace-1",
                "commit_id": _COMMIT_ID,
                "hypothesis_id": None,
                "attempt_id": None,
            },
            "profile_key": "openai-primary",
            "provider": "OPENAI",
            "product": "OPENAI_API",
            "transport": "RESPONSES_API",
            "model": "configured-openai-model",
            "environment": "PRIVATE_CI",
            "auth_mode": "API_KEY",
            "client_name": "openai-python",
            "client_version": "2.54.0",
            "tests": tuple(
                {
                    "test_id": f"PVD-{index:02d}",
                    "result": "PASS",
                    "evidence_refs": (recycled_ref,),
                    "safe_summary": "unexecuted caller assertion",
                }
                for index in range(1, 16)
            ),
            "checked_at": datetime(2026, 9, 13, 1, 0, tzinfo=UTC),
            "checked_by": "capability-operator",
        }
    )


def _adapter(runner: OpenAIResponsesPVDProbeRunner) -> OpenAIResponsesApiAdapter:
    return OpenAIResponsesApiAdapter(
        provider_profile_ref=_provider_ref(),
        model="configured-openai-model",
        credential_ref=SecretReference(reference="env:OPENAI_API_KEY"),
        prompt_resolver=cast(Any, object()),
        secret_resolver=cast(Any, object()),
        client_factory=cast(Any, object()),
        session_store=cast(Any, object()),
        output_schema_validator=cast(Any, object()),
        result_builder=cast(Any, object()),
        clock=SystemClock(),
        probe_runner=runner,
    )


@dataclass
class RecordingCheck:
    test_id: PVDTestId
    seen: list[PVDTestId]
    result: Literal["PASS", "FAIL", "NOT_APPLICABLE"] = "PASS"

    async def execute(
        self,
        candidate: ProviderValidationEvidence,
        adapter: OpenAIResponsesApiAdapter,
    ) -> OpenAIPVDCheckObservation:
        self.seen.append(self.test_id)
        assert candidate.model == adapter.model
        return OpenAIPVDCheckObservation(
            test_id=self.test_id,
            result=self.result,
            safe_summary=f"{self.test_id} executed against the configured adapter",
            evidence=canonical_bytes(
                {
                    "adapter_model": adapter.model,
                    "executed": True,
                    "test_id": self.test_id,
                }
            ),
        )


@pytest.mark.asyncio
async def test_probe_executes_all_fifteen_checks_and_replaces_prefilled_evidence(
    tmp_path: Path,
) -> None:
    """Catches recycling caller-authored PASS results without executing PVD."""
    seen: list[PVDTestId] = []
    checks = tuple(
        RecordingCheck(
            cast(PVDTestId, f"PVD-{index:02d}"),
            seen,
            result="NOT_APPLICABLE" if index == 13 else "PASS",
        )
        for index in range(1, 16)
    )
    artifacts = LocalArtifactStore(
        tmp_path / "artifacts", WorkspaceId("workspace-1"), CommitId(_COMMIT_ID)
    )
    runner = OpenAIResponsesPVDProbeRunner(
        checks=checks,
        artifacts=cast(ArtifactStore, artifacts),
        clock=FixedClock(),
        per_check_timeout_ms=100,
    )

    result = await _adapter(runner).probe(_candidate())

    assert sorted(seen) == [f"PVD-{index:02d}" for index in range(1, 16)]
    assert result.evidence.checked_at == _CHECKED_AT
    assert [test.result for test in result.evidence.tests] == [
        *("PASS" for _ in range(12)),
        "NOT_APPLICABLE",
        "PASS",
        "PASS",
    ], result.evidence.tests
    recycled_ref = _artifact_ref("d" * 64)
    assert all(test.evidence_refs != (recycled_ref,) for test in result.evidence.tests)
    assert all(len(test.evidence_refs) == 1 for test in result.evidence.tests)
    for test in result.evidence.tests:
        with artifacts.open_verified(test.evidence_refs[0]) as stream:
            receipt = json.loads(stream.read())
        assert receipt["candidate_identity_sha256"] == hashlib.sha256(
            canonical_bytes(
                {
                    "auth_mode": "API_KEY",
                    "client_name": "openai-python",
                    "client_version": "2.54.0",
                    "environment": "PRIVATE_CI",
                    "model": "configured-openai-model",
                    "product": "OPENAI_API",
                    "profile_key": "openai-primary",
                    "provider": "OPENAI",
                    "transport": "RESPONSES_API",
                }
            )
        ).hexdigest()
        assert receipt["test_id"] == test.test_id
        assert receipt["result"] == test.result
        assert receipt["observation"]["executed"] is True


@dataclass
class RaisingCheck(RecordingCheck):
    async def execute(
        self,
        candidate: ProviderValidationEvidence,
        adapter: OpenAIResponsesApiAdapter,
    ) -> OpenAIPVDCheckObservation:
        self.seen.append(self.test_id)
        raise RuntimeError(_SECRET)


@dataclass
class HangingCheck(RecordingCheck):
    async def execute(
        self,
        candidate: ProviderValidationEvidence,
        adapter: OpenAIResponsesApiAdapter,
    ) -> OpenAIPVDCheckObservation:
        self.seen.append(self.test_id)
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


@dataclass
class LeakingCheck(RecordingCheck):
    async def execute(
        self,
        candidate: ProviderValidationEvidence,
        adapter: OpenAIResponsesApiAdapter,
    ) -> OpenAIPVDCheckObservation:
        self.seen.append(self.test_id)
        return OpenAIPVDCheckObservation(
            test_id=self.test_id,
            result="PASS",
            safe_summary="returned an unsafe observation",
            evidence=canonical_bytes({"message": f"api_key={_SECRET}"}),
        )


@pytest.mark.asyncio
async def test_probe_fails_closed_for_missing_exception_timeout_and_secret(
    tmp_path: Path,
) -> None:
    """Catches incomplete or unsafe checks becoming publishable PASS evidence."""
    seen: list[PVDTestId] = []
    checks: list[RecordingCheck] = []
    for index in range(1, 16):
        test_id = cast(PVDTestId, f"PVD-{index:02d}")
        if index == 2:
            continue
        if index == 7:
            checks.append(HangingCheck(test_id, seen))
        elif index == 8:
            checks.append(RaisingCheck(test_id, seen))
        elif index == 11:
            checks.append(LeakingCheck(test_id, seen))
        else:
            checks.append(RecordingCheck(test_id, seen))
    artifacts = LocalArtifactStore(
        tmp_path / "artifacts", WorkspaceId("workspace-1"), CommitId(_COMMIT_ID)
    )
    runner = OpenAIResponsesPVDProbeRunner(
        checks=tuple(checks),
        artifacts=cast(ArtifactStore, artifacts),
        clock=FixedClock(),
        per_check_timeout_ms=5,
    )

    result = await asyncio.wait_for(_adapter(runner).probe(_candidate()), timeout=0.5)

    by_id = {test.test_id: test for test in result.evidence.tests}
    assert set(by_id) == {f"PVD-{index:02d}" for index in range(1, 16)}
    assert by_id["PVD-02"].result == "FAIL"
    assert by_id["PVD-07"].result == "FAIL"
    assert by_id["PVD-08"].result == "FAIL"
    assert by_id["PVD-11"].result == "FAIL"
    assert all(test.evidence_refs for test in result.evidence.tests)
    serialized = result.evidence.model_dump_json()
    assert _SECRET not in serialized
    for test in result.evidence.tests:
        with artifacts.open_verified(test.evidence_refs[0]) as stream:
            assert _SECRET.encode() not in stream.read()
