"""Negative tests for the official Claude Code subscription boundary.

Every assertion here encodes a property that was measured against the pinned
official client ``2.1.197``.  The adapter must keep failing closed when the client
stops reporting the isolation it reported then.
"""

import hashlib
import json
from pathlib import Path

import pytest

from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    ProviderProfile,
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.providers.base import (
    CodexProcessRequest,
    ProviderInputMismatchError,
    ProviderInvalidOutputError,
)
from sastsimi.providers.claude_subscription import (
    ApprovedClaudeExecutable,
    ApprovedClaudeExecutionBinding,
    ClaudeCliProcessRunner,
    ProviderExecutableBindingError,
    _ChildResult,
    _claude_output_schema,
    _is_exact_subscription_login,
    _require_claude_cli_version,
    _validated_event_stream,
)
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import ref

_MODEL = "profile-selected-model"
_CLIENT_VERSION = "2.1.197"
_ALLOWLIST = (
    "CLAUDE_CONFIG_DIR",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
)


def _approved_records() -> tuple[ProviderProfile, ClientExecutionProfile]:
    validation_ref = StoredDataRef.model_validate(ref("provider_validation_evidence"))
    client = ClientExecutionProfile.model_validate_json(
        json.dumps(
            make("ClientExecutionProfile")
            | {
                "environment_variable_allowlist": _ALLOWLIST,
                "verification_evidence_ref": validation_ref.model_dump(mode="json"),
            }
        )
    )
    profile = ProviderProfile.model_validate_json(
        json.dumps(
            make("ProviderProfile")
            | {
                "provider": "ANTHROPIC",
                "product": "CLAUDE_CODE",
                "transport": "CLAUDE_CODE_CLIENT",
                "model": _MODEL,
                "environment": "PERSONAL_LOCAL",
                "auth_mode": "SUBSCRIPTION_LOGIN",
                "credential_source": "OFFICIAL_CLIENT_SESSION",
                "client_name": "claude-code",
                "client_version": _CLIENT_VERSION,
                "support_status": "EXPERIMENTAL",
                "validation_evidence_ref": validation_ref.model_dump(mode="json"),
                "client_execution_profile_ref": reference(client).model_dump(
                    mode="json"
                ),
            }
        )
    )
    return profile, client


def _supported_records() -> tuple[
    ProviderProfile, ClientExecutionProfile, ProviderValidationEvidence
]:
    profile, client = _approved_records()
    evidence = ProviderValidationEvidence.model_validate_json(
        json.dumps(
            make("ProviderValidationEvidence")
            | {
                "meta": profile.meta.model_copy(
                    update={
                        "record_type": "provider_validation_evidence",
                        "record_id": RecordId("supported-claude-validation-r1"),
                        "logical_record_id": LogicalRecordId(
                            "supported-claude-validation-l1"
                        ),
                    }
                ),
                **{
                    field: getattr(profile, field)
                    for field in (
                        "profile_key",
                        "provider",
                        "product",
                        "transport",
                        "model",
                        "environment",
                        "auth_mode",
                        "client_name",
                        "client_version",
                    )
                },
                "tests": tuple(
                    {
                        "test_id": f"PVD-{index:02d}",
                        "result": "PASS",
                        "evidence_refs": (ref("observation", record=False),),
                        "safe_summary": "approved observation",
                    }
                    for index in range(1, 17)
                ),
            },
            default=lambda value: value.model_dump(mode="json"),
        )
    )
    validation_ref = reference(evidence)
    assert isinstance(validation_ref, StoredDataRef)
    client = client.model_copy(update={"verification_evidence_ref": validation_ref})
    profile = profile.model_copy(
        update={
            "support_status": "SUPPORTED",
            "validation_evidence_ref": validation_ref,
            "client_execution_profile_ref": reference(client),
        }
    )
    return profile, client, evidence


def request(
    profile_ref: StoredDataRef | None = None, model: str = _MODEL
) -> CodexProcessRequest:
    profile, _client = _approved_records()
    approved_profile_ref = reference(profile)
    assert isinstance(approved_profile_ref, StoredDataRef)
    return CodexProcessRequest(
        invocation_id="call-1",
        provider_profile_ref=profile_ref or approved_profile_ref,
        model=model,
        prompt=b"SECRET PROMPT SENT ONLY ON STDIN",
        output_schema=b'{"type":"object"}',
        timeout_ms=30_000,
    )


def approved_runner() -> ClaudeCliProcessRunner:
    executable = Path(__file__).resolve()
    profile, client = _approved_records()
    binding = ApprovedClaudeExecutionBinding(
        provider_profile=profile,
        client_execution_profile=client,
        executable=ApprovedClaudeExecutable(
            path=executable,
            sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        ),
        claude_config_dir=executable.parent,
        runtime_environment="PERSONAL_LOCAL",
    )
    return ClaudeCliProcessRunner(binding=binding)


def _option(argv: tuple[str, ...], flag: str) -> str:
    return argv[argv.index(flag) + 1]


def _init_event(**overrides: object) -> dict[str, object]:
    event = {
        "type": "system",
        "subtype": "init",
        "session_id": "session-1",
        "tools": [],
        "mcp_servers": [],
        "plugins": [],
        "slash_commands": [],
        "skills": [],
        "agents": ["claude", "Explore", "general-purpose", "Plan"],
        "model": _MODEL,
        "claude_code_version": _CLIENT_VERSION,
        "permissionMode": "dontAsk",
        "apiKeySource": "none",
    }
    event.update(overrides)
    return event


def _stream(*events: dict[str, object]) -> bytes:
    return b"\n".join(json.dumps(event).encode("utf-8") for event in events)


_TERMINAL_RESULT: dict[str, object] = {
    "type": "result",
    "subtype": "success",
    "session_id": "session-1",
    "is_error": False,
    "api_error_status": None,
    "permission_denials": [],
    "structured_output": {"answer": "4"},
}


def _assistant(content: list[dict[str, object]]) -> dict[str, object]:
    return {
        "type": "assistant",
        "session_id": "session-1",
        "parent_tool_use_id": None,
        "message": {"model": _MODEL, "content": content},
    }


def _stream_with(*injected: dict[str, object]) -> bytes:
    """An otherwise complete, valid stream carrying exactly one injected event.

    Every other event is well-formed, so a rejection can only be attributed to the
    injected one.
    """
    return _stream(_init_event(), *injected, _TERMINAL_RESULT)


def _success_stream(**init_overrides: object) -> bytes:
    return _stream(
        _init_event(**init_overrides),
        {
            "type": "assistant",
            "session_id": "session-1",
            "parent_tool_use_id": None,
            "message": {
                "model": _MODEL,
                "content": [
                    {"type": "tool_use", "name": "StructuredOutput", "input": {}}
                ],
            },
        },
        {
            "type": "user",
            "session_id": "session-1",
            "parent_tool_use_id": None,
            "message": {"content": [{"type": "tool_result"}]},
        },
        {
            "type": "result",
            "subtype": "success",
            "session_id": "session-1",
            "is_error": False,
            "api_error_status": None,
            "permission_denials": [],
            "structured_output": {"answer": "4"},
        },
    )


def _validate(stream: bytes) -> tuple[str, bytes, str]:
    return _validated_event_stream(stream, model=_MODEL, client_version=_CLIENT_VERSION)


def test_command_is_pinned_isolated_and_prompt_is_stdin_only() -> None:
    runner = approved_runner()
    work = (Path.cwd() / "empty-work").resolve()

    argv = runner.execution_argv(request(), work, b'{"type":"object"}')

    assert argv[0] == str(runner.executable.path)
    assert argv[1] == "-p"
    assert "SECRET PROMPT" not in " ".join(argv)
    assert _option(argv, "--model") == _MODEL
    # Every built-in tool is removed; the client then exposes only its own
    # structured-output transport to the model.
    assert _option(argv, "--tools") == ""
    assert _option(argv, "--permission-mode") == "dontAsk"
    assert _option(argv, "--setting-sources") == ""
    assert _option(argv, "--output-format") == "stream-json"
    for flag in (
        "--safe-mode",
        "--strict-mcp-config",
        "--disable-slash-commands",
        "--no-session-persistence",
        "--verbose",
    ):
        assert flag in argv
    # A settings document may define apiKeyHelper, which is both an API credential
    # path and arbitrary command execution inside this boundary.
    for forbidden in (
        "--settings",
        "--mcp-config",
        "--plugin-dir",
        "--plugin-url",
        "--add-dir",
        "--agents",
        "--allowedTools",
        "--append-system-prompt",
        "--dangerously-skip-permissions",
        "--resume",
        "--continue",
        "--fallback-model",
    ):
        assert forbidden not in argv


def test_minimal_environment_drops_ambient_credentials_and_paths() -> None:
    runner = approved_runner()
    source = {
        "SYSTEMROOT": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "COMSPEC": r"C:\Windows\System32\cmd.exe",
        "ANTHROPIC_API_KEY": "must-not-cross",
        "ANTHROPIC_AUTH_TOKEN": "must-not-cross",
        "CLAUDE_CODE_OAUTH_TOKEN": "must-not-cross",
        "ANTHROPIC_BASE_URL": "http://attacker.invalid",
        "AWS_SECRET_ACCESS_KEY": "must-not-cross",
        "PATH": r"C:\attacker-controlled",
        "HOME": r"C:\attacker-controlled",
        "PYTHONPATH": r"C:\attacker-controlled",
    }

    child_environment = runner.child_environment(source)

    assert child_environment["CLAUDE_CONFIG_DIR"] == str(runner.claude_config_dir)
    assert child_environment["SYSTEMROOT"] == r"C:\Windows"
    for leaked in (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "AWS_SECRET_ACCESS_KEY",
        "PATH",
        "HOME",
        "PYTHONPATH",
    ):
        assert leaked not in child_environment


def test_child_environment_disables_fallback_autoupdate_and_managed_settings() -> None:
    child_environment = approved_runner().child_environment({})

    assert child_environment["CLAUDE_CODE_DISABLE_NONSTREAMING_FALLBACK"] == "1"
    assert child_environment["CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK"] == "1"
    assert child_environment["DISABLE_AUTOUPDATER"] == "1"
    assert child_environment["CLAUDE_CODE_DISABLE_BUNDLED_SKILLS"] == "1"
    assert child_environment["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] == "1"
    assert child_environment["CLAUDE_CODE_DISABLE_CLAUDE_MDS"] == "1"
    assert child_environment["CLAUDE_CODE_MANAGED_SETTINGS_PATH"] in {
        "/dev/null",
        "nul",
    }


def test_constructor_rejects_an_unapproved_executable_digest() -> None:
    profile, client = _approved_records()

    with pytest.raises(ProviderExecutableBindingError):
        ClaudeCliProcessRunner(
            binding=ApprovedClaudeExecutionBinding(
                provider_profile=profile,
                client_execution_profile=client,
                executable=ApprovedClaudeExecutable(
                    path=Path(__file__).resolve(),
                    sha256="0" * 64,
                ),
                claude_config_dir=Path(__file__).resolve().parent,
                runtime_environment="PERSONAL_LOCAL",
            )
        )


def test_executable_digest_is_rechecked_immediately_before_use(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "claude"
    executable.write_bytes(b"approved-official-client")
    profile, client = _approved_records()
    runner = ClaudeCliProcessRunner(
        binding=ApprovedClaudeExecutionBinding(
            provider_profile=profile,
            client_execution_profile=client,
            executable=ApprovedClaudeExecutable(
                path=executable.resolve(),
                sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            ),
            claude_config_dir=tmp_path.resolve(),
            runtime_environment="PERSONAL_LOCAL",
        )
    )

    executable.write_bytes(b"replaced-after-approval")

    with pytest.raises(ProviderExecutableBindingError):
        runner.verify_executable()


def test_execution_binding_rejects_a_non_subscription_product() -> None:
    profile, client = _approved_records()
    executable = Path(__file__).resolve()

    with pytest.raises(ValueError, match="CLAUDE_EXECUTION_BINDING_MISMATCH"):
        ApprovedClaudeExecutionBinding(
            provider_profile=profile.model_copy(
                update={
                    "product": "CODEX",
                    "provider": "OPENAI",
                    "transport": "CODEX_CLIENT",
                }
            ),
            client_execution_profile=client,
            executable=ApprovedClaudeExecutable(
                path=executable,
                sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            ),
            claude_config_dir=executable.parent,
            runtime_environment="PERSONAL_LOCAL",
        )


def test_execution_binding_rejects_a_stale_runtime_environment() -> None:
    profile, client = _approved_records()
    executable = Path(__file__).resolve()

    with pytest.raises(ValueError, match="CLAUDE_EXECUTION_BINDING_MISMATCH"):
        ApprovedClaudeExecutionBinding(
            provider_profile=profile,
            client_execution_profile=client,
            executable=ApprovedClaudeExecutable(
                path=executable,
                sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            ),
            claude_config_dir=executable.parent,
            runtime_environment="SHARED_SERVER",
        )


def test_execution_binding_rejects_a_widened_environment_allowlist() -> None:
    profile, client = _approved_records()
    executable = Path(__file__).resolve()
    widened = client.model_copy(
        update={
            "environment_variable_allowlist": (*_ALLOWLIST, "ANTHROPIC_API_KEY"),
        }
    )

    with pytest.raises(ValueError, match="CLAUDE_EXECUTION_BINDING_MISMATCH"):
        ApprovedClaudeExecutionBinding(
            provider_profile=profile,
            client_execution_profile=widened,
            executable=ApprovedClaudeExecutable(
                path=executable,
                sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            ),
            claude_config_dir=executable.parent,
            runtime_environment="PERSONAL_LOCAL",
        )


def test_execution_binding_rejects_a_supported_profile_without_evidence() -> None:
    profile, client, _evidence = _supported_records()
    executable = Path(__file__).resolve()

    with pytest.raises(ValueError, match="CLAUDE_EXECUTION_BINDING_MISMATCH"):
        ApprovedClaudeExecutionBinding(
            provider_profile=profile,
            client_execution_profile=client,
            executable=ApprovedClaudeExecutable(
                path=executable,
                sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            ),
            claude_config_dir=executable.parent,
            runtime_environment="PERSONAL_LOCAL",
        )


def test_supported_binding_requires_and_rechecks_exact_pvd() -> None:
    profile, client, evidence = _supported_records()
    executable = Path(__file__).resolve()
    incomplete = evidence.model_copy(update={"tests": evidence.tests[:5]})

    with pytest.raises(ValueError, match="CLAUDE_EXECUTION_BINDING_MISMATCH"):
        ApprovedClaudeExecutionBinding(
            provider_profile=profile,
            client_execution_profile=client,
            executable=ApprovedClaudeExecutable(
                path=executable,
                sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            ),
            claude_config_dir=executable.parent,
            runtime_environment="PERSONAL_LOCAL",
            provider_validation_evidence=incomplete,
        )


def test_model_cannot_be_reinterpreted_as_a_cli_option() -> None:
    runner = approved_runner()

    for hostile in ("--dangerously-skip-permissions", "-p", "sonnet --add-dir /"):
        with pytest.raises(ProviderInputMismatchError):
            runner.execution_argv(
                request(model=hostile),
                (Path.cwd() / "work").resolve(),
                b'{"type":"object"}',
            )


def test_version_check_requires_the_exact_pinned_client() -> None:
    _require_claude_cli_version(
        _ChildResult(0, b"2.1.197 (Claude Code)\n", b""), "2.1.197"
    )

    for wrong in (
        _ChildResult(0, b"2.1.198 (Claude Code)\n", b""),
        _ChildResult(1, b"2.1.197 (Claude Code)\n", b""),
        _ChildResult(0, b"2.1.197\n", b""),
        _ChildResult(0, b"2.1.197 (Claude Code)\nextra\n", b""),
    ):
        with pytest.raises(ProviderExecutableBindingError):
            _require_claude_cli_version(wrong, "2.1.197")


def test_login_status_accepts_only_an_exact_subscription_login() -> None:
    subscription = {
        "loggedIn": True,
        "authMethod": "claude.ai",
        "apiProvider": "firstParty",
        "subscriptionType": "max",
    }
    assert _is_exact_subscription_login(
        _ChildResult(0, json.dumps(subscription).encode("utf-8"), b"")
    )


def test_login_status_rejects_every_api_credential_path() -> None:
    rejected = (
        {"loggedIn": False, "authMethod": "none", "apiProvider": "firstParty"},
        # An ambient API key must never satisfy a subscription profile.
        {
            "loggedIn": True,
            "authMethod": "api_key",
            "apiProvider": "firstParty",
            "apiKeySource": "ANTHROPIC_API_KEY",
            "subscriptionType": "max",
        },
        # apiKeyHelper is both an API credential path and command execution.
        {
            "loggedIn": True,
            "authMethod": "claude.ai",
            "apiProvider": "firstParty",
            "apiKeySource": "apiKeyHelper",
            "subscriptionType": "max",
        },
        # Each of these isolates one rejected field: nothing else in the payload
        # would independently fail, so the named check is what rejects it.
        {
            "loggedIn": True,
            "authMethod": "oauth_token",
            "apiProvider": "firstParty",
            "subscriptionType": "max",
        },
        {
            "loggedIn": True,
            "authMethod": "api_key",
            "apiProvider": "firstParty",
            "subscriptionType": "max",
        },
        {
            "loggedIn": False,
            "authMethod": "claude.ai",
            "apiProvider": "firstParty",
            "subscriptionType": "max",
        },
        {
            "loggedIn": True,
            "authMethod": "claude.ai",
            "apiProvider": "firstParty",
            "apiKeySource": "none",
            "subscriptionType": "max",
        },
        {
            "loggedIn": True,
            "authMethod": "claude.ai",
            "apiProvider": "firstParty",
            "subscriptionType": "",
        },
        # A third-party provider would move the call off the official service.
        {
            "loggedIn": True,
            "authMethod": "claude.ai",
            "apiProvider": "bedrock",
            "subscriptionType": "max",
        },
        {"loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty"},
    )
    for payload in rejected:
        assert not _is_exact_subscription_login(
            _ChildResult(0, json.dumps(payload).encode("utf-8"), b"")
        )


def test_login_status_rejects_unparsable_or_oversized_output() -> None:
    assert not _is_exact_subscription_login(_ChildResult(0, b"not json", b""))
    assert not _is_exact_subscription_login(_ChildResult(0, b"[]", b""))
    assert not _is_exact_subscription_login(_ChildResult(0, b"", b""))
    # Oversized but otherwise valid and accepted-looking: only the size bound
    # rejects it, so a padded payload can never be parsed into a trusted login.
    padded = json.dumps(
        {
            "loggedIn": True,
            "authMethod": "claude.ai",
            "apiProvider": "firstParty",
            "subscriptionType": "max",
            "padding": "x" * 70_000,
        }
    ).encode("utf-8")
    assert len(padded) > 65_536
    assert not _is_exact_subscription_login(_ChildResult(0, padded, b""))


def test_event_stream_extracts_only_the_official_session_and_answer() -> None:
    status, message, session_id = _validate(_success_stream())

    assert status == "SUCCEEDED"
    assert session_id == "session-1"
    assert json.loads(message) == {"answer": "4"}


def test_init_accepts_only_this_adapter_own_output_transport_as_a_tool() -> None:
    # Passing an output schema registers StructuredOutput as a tool; it is the
    # adapter's own answer channel, so it is the only permitted name.
    for tools in ([], ["StructuredOutput"]):
        assert _validate(_success_stream(tools=tools))[0] == "SUCCEEDED"

    for tools in (
        ["Bash"],
        ["StructuredOutput", "Read"],
        ["mcp__server__tool"],
        # A non-list must be rejected as invalid, never coerced into a set.
        "StructuredOutput",
        None,
        {"StructuredOutput": True},
    ):
        with pytest.raises(ProviderInvalidOutputError):
            _validate(_success_stream(tools=tools))


def test_accepts_the_event_stream_the_official_client_actually_emits() -> None:
    """Regression guard pinned to a real 2.1.197 run.

    The shape below was captured from a live subscription call: the init event
    reports the structured-output tool because a schema was passed, dozens of
    ``thinking_tokens`` progress events precede the answer, and the model emits a
    reasoning block and a text block before the structured tool call.
    """
    observed = _stream(
        _init_event(tools=["StructuredOutput"]),
        {
            "type": "system",
            "subtype": "thinking_tokens",
            "session_id": "session-1",
            "estimated_tokens": 41,
            "estimated_tokens_delta": 6,
        },
        _assistant([{"type": "thinking", "thinking": "reasoning"}]),
        _assistant([{"type": "text", "text": "answering"}]),
        _assistant([{"type": "tool_use", "name": "StructuredOutput", "input": {}}]),
        {
            "type": "user",
            "session_id": "session-1",
            "parent_tool_use_id": None,
            "message": {"content": [{"type": "tool_result"}]},
        },
        {
            "type": "rate_limit_event",
            "session_id": "session-1",
            "rate_limit_info": {"status": "allowed"},
        },
        _TERMINAL_RESULT,
    )

    status, message, session_id = _validate(observed)

    assert status == "SUCCEEDED"
    assert session_id == "session-1"
    assert json.loads(message) == {"answer": "4"}


def test_event_stream_requires_the_reported_isolation() -> None:
    escapes = (
        {"tools": ["Bash"]},
        {"mcp_servers": [{"name": "x", "status": "connected"}]},
        {"plugins": [{"name": "x", "path": "/x"}]},
        {"slash_commands": ["run"]},
        {"skills": ["deep-research"]},
        {"permissionMode": "bypassPermissions"},
        {"agents": ["claude", "Explore", "general-purpose", "Plan", "statusline"]},
        {"memory_paths": {"auto": "/home/user/.claude/memory/"}},
    )
    for override in escapes:
        with pytest.raises(ProviderInvalidOutputError):
            _validate(_success_stream(**override))


def test_event_stream_rejects_every_api_credential_source() -> None:
    for source in ("ANTHROPIC_API_KEY", "apiKeyHelper", "ANTHROPIC_AUTH_TOKEN", None):
        with pytest.raises(ProviderInvalidOutputError):
            _validate(_success_stream(apiKeySource=source))


def test_event_stream_rejects_a_model_or_client_version_reroute() -> None:
    with pytest.raises(ProviderInvalidOutputError):
        _validate(_success_stream(model="claude-opus-4-8"))
    with pytest.raises(ProviderInvalidOutputError):
        _validate(_success_stream(claude_code_version="2.1.198"))


def test_event_stream_rejects_every_forbidden_tool_event() -> None:
    # The control proves the surrounding stream is valid, so each rejection below
    # is attributable to the tool name alone.
    assert (
        _validate(
            _stream_with(_assistant([{"type": "tool_use", "name": "StructuredOutput"}]))
        )[0]
        == "SUCCEEDED"
    )

    for name in ("Bash", "Read", "Write", "Edit", "WebFetch", "Task", "mcp__x__y"):
        with pytest.raises(ProviderInvalidOutputError):
            _validate(_stream_with(_assistant([{"type": "tool_use", "name": name}])))


def _user(content: list[dict[str, object]]) -> dict[str, object]:
    return {
        "type": "user",
        "session_id": "session-1",
        "parent_tool_use_id": None,
        "message": {"content": content},
    }


_REFUSAL = (
    "<tool_use_error>Error: No such tool available: Bash. Bash exists but is "
    "not enabled in this context.</tool_use_error>"
)


def test_a_tool_request_the_client_refused_is_not_an_escape() -> None:
    # Asking for a tool is not using one: this boundary enables no tools, so the
    # client answers the request with an error and the turn continues.  Failing
    # the whole call here would discard an answer that never left the boundary.
    status, message, _session = _validate(
        _stream_with(
            _assistant([{"type": "tool_use", "id": "toolu_1", "name": "Bash"}]),
            _user(
                [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_1",
                        "is_error": True,
                        "content": _REFUSAL,
                    }
                ]
            ),
        )
    )

    assert status == "SUCCEEDED"
    assert json.loads(message) == {"answer": "4"}


def test_a_tool_request_that_was_not_refused_fails_closed() -> None:
    request = _assistant([{"type": "tool_use", "id": "toolu_1", "name": "Bash"}])

    # No reply at all.
    with pytest.raises(ProviderInvalidOutputError):
        _validate(_stream_with(request))

    # A reply that is not the client's refusal - the tool actually ran.
    with pytest.raises(ProviderInvalidOutputError):
        _validate(
            _stream_with(
                request,
                _user(
                    [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_1",
                            "content": "uid=0(root)",
                        }
                    ]
                ),
            )
        )

    # An error reply that is not a refusal: the tool ran and failed.
    with pytest.raises(ProviderInvalidOutputError):
        _validate(
            _stream_with(
                request,
                _user(
                    [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_1",
                            "is_error": True,
                            "content": "command not found",
                        }
                    ]
                ),
            )
        )

    # A refusal recorded against a different request leaves this one unanswered.
    with pytest.raises(ProviderInvalidOutputError):
        _validate(
            _stream_with(
                request,
                _user(
                    [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_other",
                            "is_error": True,
                            "content": _REFUSAL,
                        }
                    ]
                ),
            )
        )


def test_a_tool_request_without_an_identifier_fails_closed() -> None:
    # Without an id the refusal can never be matched, so it is never allowed.
    with pytest.raises(ProviderInvalidOutputError):
        _validate(_stream_with(_assistant([{"type": "tool_use", "name": "Bash"}])))


def test_event_stream_allows_reasoning_blocks_without_storing_them() -> None:
    # The official client emits a reasoning block before the structured answer.
    # It may appear, but only structured_output ever crosses the boundary.
    for block in ({"type": "thinking"}, {"type": "redacted_thinking"}):
        status, message, _session = _validate(_stream_with(_assistant([block])))
        assert status == "SUCCEEDED"
        assert json.loads(message) == {"answer": "4"}


def test_event_stream_rejects_an_unknown_assistant_content_block() -> None:
    for block in (
        {"type": "image"},
        {"type": "server_tool_use"},
        {"type": "mcp_tool_use"},
    ):
        with pytest.raises(ProviderInvalidOutputError):
            _validate(_stream_with(_assistant([block])))


def test_event_stream_rejects_subagent_messages() -> None:
    nested = _assistant([{"type": "text", "text": "x"}])
    nested["parent_tool_use_id"] = "toolu_1"

    with pytest.raises(ProviderInvalidOutputError):
        _validate(_stream_with(nested))


def test_event_stream_rejects_an_assistant_model_reroute() -> None:
    rerouted = _assistant([{"type": "text", "text": "x"}])
    rerouted["message"] = {
        "model": "claude-opus-4-8",
        "content": [{"type": "text", "text": "x"}],
    }

    with pytest.raises(ProviderInvalidOutputError):
        _validate(_stream_with(rerouted))


def test_event_stream_requires_one_session_and_one_terminal_result() -> None:
    with pytest.raises(ProviderInvalidOutputError):
        _validate(_stream(_init_event()))
    with pytest.raises(ProviderInvalidOutputError):
        _validate(b"")
    second_session = _stream(
        _init_event(),
        {
            "type": "user",
            "session_id": "session-2",
            "parent_tool_use_id": None,
            "message": {"content": []},
        },
    )
    with pytest.raises(ProviderInvalidOutputError):
        _validate(second_session)


def test_event_stream_allows_only_informational_system_progress() -> None:
    # The official client emits many thinking_tokens progress events between the
    # init event and the answer.
    progress = {
        "type": "system",
        "subtype": "thinking_tokens",
        "session_id": "session-1",
        "estimated_tokens": 12,
        "estimated_tokens_delta": 3,
    }
    retry = {"type": "system", "subtype": "api_retry", "session_id": "session-1"}
    assert _validate(_stream_with(progress, progress, retry))[0] == "SUCCEEDED"

    for subtype in ("init", "permission_denied", "plugin_install", None):
        with pytest.raises(ProviderInvalidOutputError):
            _validate(
                _stream_with(
                    {
                        "type": "system",
                        "subtype": subtype,
                        "session_id": "session-1",
                    }
                )
            )


def test_event_stream_rejects_an_unknown_or_out_of_order_event() -> None:
    with pytest.raises(ProviderInvalidOutputError):
        _validate(_stream({"type": "stream_event", "session_id": "session-1"}))
    out_of_order = _stream(
        {
            "type": "assistant",
            "session_id": "session-1",
            "parent_tool_use_id": None,
            "message": {"model": _MODEL, "content": []},
        },
        _init_event(),
    )
    with pytest.raises(ProviderInvalidOutputError):
        _validate(out_of_order)


def test_event_stream_rejects_a_truncated_stream() -> None:
    with pytest.raises(ProviderInvalidOutputError):
        _validate(b"x" * 1_048_576)


def test_terminal_failures_collapse_to_safe_statuses_only() -> None:
    def terminal(**fields: object) -> bytes:
        event: dict[str, object] = {
            "type": "result",
            "subtype": "success",
            "session_id": "session-1",
            "permission_denials": [],
        }
        event.update(fields)
        return _stream(_init_event(), event)

    # The client exits 0 on authentication failure, so only the structured status
    # distinguishes these outcomes.
    assert _validate(terminal(is_error=True, api_error_status=401))[0] == (
        "AUTH_REQUIRED"
    )
    assert _validate(terminal(is_error=True, api_error_status=403))[0] == (
        "AUTH_REQUIRED"
    )
    assert _validate(terminal(is_error=True, api_error_status=429))[0] == (
        "RATE_LIMITED"
    )
    assert _validate(terminal(is_error=True, api_error_status=None))[0] == "FAILED"
    assert _validate(terminal(is_error=True, api_error_status=500))[0] == "FAILED"


def test_successful_result_requires_structured_output_and_no_denials() -> None:
    def terminal(**fields: object) -> bytes:
        event: dict[str, object] = {
            "type": "result",
            "subtype": "success",
            "session_id": "session-1",
            "is_error": False,
            "api_error_status": None,
            "permission_denials": [],
            "structured_output": {"answer": "4"},
        }
        event.update(fields)
        return _stream(_init_event(), event)

    with pytest.raises(ProviderInvalidOutputError):
        _validate(terminal(structured_output="not-an-object"))
    with pytest.raises(ProviderInvalidOutputError):
        _validate(terminal(structured_output=None))
    # A denial proves the model reached for something outside the boundary.
    with pytest.raises(ProviderInvalidOutputError):
        _validate(terminal(permission_denials=[{"tool_name": "Bash"}]))


def test_event_stream_rejects_duplicate_json_members() -> None:
    with pytest.raises(ProviderInvalidOutputError):
        _validate(b'{"type":"system","type":"result"}')


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("auth_payload", "expected"),
    [
        ({"loggedIn": False, "authMethod": "none"}, "AUTH_REQUIRED"),
        (
            {
                "loggedIn": True,
                "authMethod": "api_key",
                "apiProvider": "firstParty",
                "apiKeySource": "ANTHROPIC_API_KEY",
                "subscriptionType": "max",
            },
            "AUTH_REQUIRED",
        ),
    ],
)
async def test_an_api_credential_never_reaches_the_model_call(
    monkeypatch: pytest.MonkeyPatch, auth_payload: dict[str, object], expected: str
) -> None:
    runner = approved_runner()
    spawned: list[tuple[str, ...]] = []

    async def fake_child(argv: tuple[str, ...], **_kwargs: object) -> _ChildResult:
        spawned.append(argv)
        if argv[-1] == "--version":
            return _ChildResult(0, f"{_CLIENT_VERSION} (Claude Code)\n".encode(), b"")
        if argv[-1] == "--json":
            return _ChildResult(0, json.dumps(auth_payload).encode("utf-8"), b"")
        raise AssertionError("the model call must not be reached")

    monkeypatch.setattr(runner, "_run_child", fake_child)

    result = await runner.execute(request())

    assert result.status == expected
    assert result.final_message is None
    # Only the version and auth preflight children ran; the prompt never left.
    assert len(spawned) == 2


@pytest.mark.asyncio
async def test_a_child_that_dies_is_failed_not_reported_as_bad_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = approved_runner()
    subscription = json.dumps(
        {
            "loggedIn": True,
            "authMethod": "claude.ai",
            "apiProvider": "firstParty",
            "subscriptionType": "max",
        }
    ).encode("utf-8")

    async def fake_child(argv: tuple[str, ...], **_kwargs: object) -> _ChildResult:
        if argv[-1] == "--version":
            return _ChildResult(0, f"{_CLIENT_VERSION} (Claude Code)\n".encode(), b"")
        if argv[-1] == "--json":
            return _ChildResult(0, subscription, b"")
        return _ChildResult(1, b"", b"crashed before producing any event")

    monkeypatch.setattr(runner, "_run_child", fake_child)

    result = await runner.execute(request())

    # A dead child produced no answer to judge, so this is a failed call rather
    # than an unusable model output.
    assert result.status == "FAILED"


def test_array_schema_gets_only_transport_envelope() -> None:
    scalar = {"type": "object", "properties": {"a": {"type": "string"}}}
    assert _claude_output_schema(scalar) == scalar

    array = {"type": "array", "items": {"type": "string"}}
    assert _claude_output_schema(array) == {
        "type": "object",
        "properties": {"items": {"type": "array", "items": {"type": "string"}}},
        "required": ["items"],
        "additionalProperties": False,
    }


def test_array_schema_hoists_definitions_for_root_references() -> None:
    array = {
        "type": "array",
        "items": {"$ref": "#/$defs/item"},
        "$defs": {"item": {"type": "string"}},
    }

    adapted = _claude_output_schema(array)

    assert adapted["$defs"] == {"item": {"type": "string"}}
    assert "$defs" not in adapted["properties"]["items"]


_RATE_LIMIT_NOTICE: dict[str, object] = {
    "type": "assistant",
    "session_id": "session-1",
    "parent_tool_use_id": None,
    "error": "rate_limit",
    "message": {
        "model": "<synthetic>",
        "content": [
            {
                "type": "text",
                "text": (
                    "API Error: Server is temporarily limiting requests "
                    "(not your usage limit)"
                ),
            }
        ],
    },
}


def test_a_rate_limited_run_is_reported_as_rate_limited_not_failed() -> None:
    """Measured against a real 429: the client builds its own notice message.

    That notice names ``<synthetic>`` instead of the approved model.  Reading it
    as a model reroute threw away the terminal event, so every rate-limited call
    arrived as a bare ``FAILED`` with nothing left to explain it.
    """

    stream = _stream(
        _init_event(),
        {
            "type": "rate_limit_event",
            "session_id": "session-1",
            "rate_limit_info": {"status": "rejected", "isUsingOverage": False},
        },
        _RATE_LIMIT_NOTICE,
        {
            "type": "result",
            "subtype": "success",
            "session_id": "session-1",
            "is_error": True,
            "api_error_status": 429,
            "permission_denials": [],
        },
    )

    status, message, session = _validate(stream)

    assert status == "RATE_LIMITED"
    assert message == b""
    assert session == "session-1"


def test_a_synthetic_notice_carrying_a_tool_request_still_fails_closed() -> None:
    """The notice is accepted only because it carries nothing but its text."""

    notice = json.loads(json.dumps(_RATE_LIMIT_NOTICE))
    notice["message"]["content"] = [
        {"type": "tool_use", "id": "toolu_1", "name": "Bash"}
    ]

    with pytest.raises(ProviderInvalidOutputError):
        _validate(_stream_with(notice))


def test_a_model_reroute_without_an_error_is_still_rejected() -> None:
    """Only a notice the client itself marked as an error may name another model."""

    notice = json.loads(json.dumps(_RATE_LIMIT_NOTICE))
    del notice["error"]

    with pytest.raises(ProviderInvalidOutputError):
        _validate(_stream_with(notice))
