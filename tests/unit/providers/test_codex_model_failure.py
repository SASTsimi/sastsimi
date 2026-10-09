from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.providers.base import CodexProcessRequest
from sastsimi.providers.codex_subscription import CodexCliProcessRunner, _ChildResult


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stdout", "stderr", "expected"),
    [
        (
            b'{"type":"turn.failed","error":{"code":"model_not_found"}}\n',
            b"",
            True,
        ),
        (b"", b"Error: Model 'unknown-model' is not supported.\n", True),
        (b"", b"Error: request failed for another reason\n", False),
        (
            b'{"type":"item.completed","item":{"text":"model_not_found"}}\n',
            b"Error: request failed\n",
            False,
        ),
    ],
)
async def test_codex_exec_failure_flags_only_explicit_unsupported_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
    stderr: bytes,
    expected: bool,
) -> None:
    runner = object.__new__(CodexCliProcessRunner)
    runner.executable = SimpleNamespace(path=tmp_path / "codex")  # type: ignore[assignment]
    runner.binding = SimpleNamespace(  # type: ignore[assignment]
        provider_profile=SimpleNamespace(client_version="1.0")
    )
    monkeypatch.setattr(runner, "verify_binding", lambda _request: None)
    monkeypatch.setattr(runner, "verify_executable", lambda: None)
    monkeypatch.setattr(runner, "child_environment", lambda _source: {})
    monkeypatch.setattr(runner, "execution_argv", lambda *_args: ("codex", "exec"))

    async def run_child(
        _argv: tuple[str, ...], *, phase: str, **_kwargs: object
    ) -> _ChildResult:
        if phase == "VERSION":
            return _ChildResult(0, b"codex-cli 1.0\n", b"")
        if phase == "LOGIN":
            return _ChildResult(0, b"Logged in using ChatGPT\n", b"")
        return _ChildResult(1, stdout, stderr)

    monkeypatch.setattr(runner, "_run_child", run_child)
    request = CodexProcessRequest(
        invocation_id="unsupported-model-test",
        provider_profile_ref=_provider_ref(),
        model="unknown-model",
        prompt=b"safe",
        output_schema=b'{"type":"object"}',
        timeout_ms=1000,
    )

    result = await runner.execute(request)

    assert result.status == "FAILED"
    assert result.model_unavailable is expected
    assert result.final_message is None
    assert result.provider_session_id is None
    if stdout:
        assert stdout.decode("utf-8", errors="replace") not in repr(result)
    if stderr:
        assert stderr.decode("utf-8", errors="replace") not in repr(result)


def _provider_ref() -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": "provider-profile",
            "data_kind": "provider_profile",
            "content_hash": "c" * 64,
            "workspace_id": "workspace-1",
            "commit_id": "commit-1",
            "record_id": "provider-profile-record",
        }
    )
