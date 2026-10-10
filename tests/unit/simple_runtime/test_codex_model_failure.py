from __future__ import annotations

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.providers.base import CodexProcessRequest, CodexProcessResult
from sastsimi.simple_runtime.models import StageFailure
from sastsimi.simple_runtime.provider import SimpleCodexClient


class _ResultRunner:
    def __init__(self, result: CodexProcessResult) -> None:
        self.result = result

    async def execute(self, _request: CodexProcessRequest) -> CodexProcessResult:
        return self.result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("model_unavailable", "code", "retryable"),
    [(True, "MODEL_UNAVAILABLE", False), (False, "FAILED", True)],
)
async def test_codex_model_failure_becomes_terminal_stage_failure_only_when_explicit(
    model_unavailable: bool,
    code: str,
    retryable: bool,
) -> None:
    client = SimpleCodexClient(
        runner=_ResultRunner(
            CodexProcessResult(
                "FAILED", None, None, model_unavailable=model_unavailable
            )
        ),
        provider_profile_ref=StoredDataRef.model_validate(
            {
                "stored_data_id": "provider-profile",
                "data_kind": "provider_profile",
                "content_hash": "c" * 64,
                "workspace_id": "workspace-1",
                "commit_id": "commit-1",
                "record_id": "provider-profile-record",
            }
        ),
        model="unknown-model",
    )

    result = await client.call(
        prompt=b"safe", output_schema={"type": "object"}, timeout_ms=1000
    )

    assert isinstance(result, StageFailure)
    assert result.code == code
    assert result.retryable is retryable
    assert result.safe_message == (
        "Codex model is unavailable"
        if model_unavailable
        else "Codex call did not succeed: FAILED"
    )
