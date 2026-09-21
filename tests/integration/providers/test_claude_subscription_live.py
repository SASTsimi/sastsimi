"""Explicit opt-in smoke test for a locally authenticated official Claude Code CLI.

This test makes a real subscription call, so it is skipped unless the operator
opts in.  The default suite makes no external call.
"""

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sastsimi.composition.local_claude_binding import build_local_claude_binding
from sastsimi.config.local_evaluation_profile import LocalClaudeSubscriptionSettings
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import AnalysisId, CommitId, OpaqueId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.providers.base import CodexProcessRequest
from sastsimi.providers.claude_subscription import ClaudeCliProcessRunner
from sastsimi.storage.artifact_store import LocalArtifactStore

_LIVE_ENABLED = os.environ.get("SASTSIMI_CLAUDE_LIVE") == "1"
pytestmark = pytest.mark.skipif(
    not _LIVE_ENABLED,
    reason="set SASTSIMI_CLAUDE_LIVE=1 for the credential-safe live probe",
)


class _Ids:
    def __init__(self) -> None:
        self.value = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.value += 1
        return kind(f"claude-live-{kind.__name__.lower()}-{self.value}")


class _Clock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic_ms(self) -> int:
        return 0


@pytest.mark.asyncio
async def test_logged_in_subscription_returns_one_isolated_structured_result(
    tmp_path: Path,
) -> None:
    executable_value = os.environ.get("SASTSIMI_CLAUDE_LIVE_EXECUTABLE")
    config_dir_value = os.environ.get("SASTSIMI_CLAUDE_LIVE_CONFIG_DIR")
    client_version = os.environ.get("SASTSIMI_CLAUDE_LIVE_CLIENT_VERSION")
    model = os.environ.get("SASTSIMI_CLAUDE_LIVE_MODEL")
    assert executable_value and config_dir_value and client_version and model

    executable = Path(executable_value).resolve()
    scope = PlannedRunScope(
        analysis_id=AnalysisId("claude-live-analysis"),
        workspace_id=WorkspaceId("claude-live-workspace"),
        commit_id=CommitId("c" * 40),
        repository_ref="https://example.invalid/live.git",
    )
    records = build_local_claude_binding(
        settings=LocalClaudeSubscriptionSettings(
            provider_profile_key="anthropic.claude-code.subscription.live",
            executable_path=executable,
            executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            claude_config_dir=Path(config_dir_value).resolve(),
            client_version=client_version,
            model=model,
        ),
        scope=scope,
        artifacts=LocalArtifactStore(
            tmp_path / "artifacts",
            workspace_id=scope.workspace_id,
            commit_id=scope.commit_id,
        ),
        ids=_Ids(),
        clock=_Clock(),
    )
    runner = ClaudeCliProcessRunner(binding=records.binding)
    provider_profile_ref = reference(records.provider)
    assert isinstance(provider_profile_ref, StoredDataRef)
    schema = {
        "type": "object",
        "properties": {"status": {"type": "string", "const": "ok"}},
        "required": ["status"],
        "additionalProperties": False,
    }

    result = await runner.execute(
        CodexProcessRequest(
            invocation_id="claude-live-structured-probe",
            provider_profile_ref=provider_profile_ref,
            model=model,
            prompt=b'Return exactly one JSON object whose status field is "ok".',
            output_schema=canonical_bytes(schema),
            timeout_ms=180_000,
        )
    )

    # Reaching SUCCEEDED proves the whole boundary held: the pinned executable,
    # the subscription-only credential check, the reported isolation in the init
    # event, and a structured answer carrying no tool activity.
    assert result.status == "SUCCEEDED"
    assert result.final_message is not None
    assert json.loads(result.final_message) == {"status": "ok"}
    assert result.provider_session_id
