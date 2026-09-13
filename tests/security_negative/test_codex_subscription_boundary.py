import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import JsonValue

import sastsimi.providers.codex_subscription as codex_subscription
from sastsimi.contracts.llm import ClientExecutionProfile, ProviderProfile
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.providers.base import (
    CodexProcessRequest,
    ProviderInputMismatchError,
    ProviderInvalidOutputError,
)
from sastsimi.providers.codex_subscription import (
    ApprovedCodexExecutable,
    ApprovedCodexExecutionBinding,
    CodexCliProcessRunner,
    ProviderExecutableBindingError,
    _ChildResult,
    _classify_child_failure,
    _codex_output_schema,
    _is_exact_chatgpt_login_status,
    _validated_session_id,
)
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import ref


def _approved_records() -> tuple[ProviderProfile, ClientExecutionProfile]:
    validation_ref = StoredDataRef.model_validate(ref("provider_validation_evidence"))
    client = ClientExecutionProfile.model_validate_json(
        json.dumps(
            make("ClientExecutionProfile")
            | {
                "environment_variable_allowlist": (
                    "CODEX_HOME",
                    "SYSTEMROOT",
                    "WINDIR",
                    "COMSPEC",
                    "TEMP",
                    "TMP",
                ),
                "verification_evidence_ref": validation_ref.model_dump(mode="json"),
            }
        )
    )
    profile = ProviderProfile.model_validate_json(
        json.dumps(
            make("ProviderProfile")
            | {
                "product": "CODEX",
                "transport": "CODEX_CLIENT",
                "model": "profile-selected-model",
                "environment": "PERSONAL_LOCAL",
                "auth_mode": "SUBSCRIPTION_LOGIN",
                "credential_source": "OFFICIAL_CLIENT_SESSION",
                "client_name": "codex-cli",
                "client_version": "0.152.1",
                "support_status": "EXPERIMENTAL",
                "validation_evidence_ref": validation_ref.model_dump(mode="json"),
                "client_execution_profile_ref": reference(client).model_dump(
                    mode="json"
                ),
            }
        )
    )
    return profile, client


def request(profile_ref: StoredDataRef | None = None) -> CodexProcessRequest:
    profile, _client = _approved_records()
    approved_profile_ref = reference(profile)
    assert isinstance(approved_profile_ref, StoredDataRef)
    return CodexProcessRequest(
        invocation_id="call-1",
        provider_profile_ref=profile_ref or approved_profile_ref,
        model="profile-selected-model",
        prompt=b"SECRET PROMPT SENT ONLY ON STDIN",
        output_schema=b'{"type":"object"}',
        timeout_ms=30_000,
    )


def approved_runner() -> CodexCliProcessRunner:
    executable = Path(__file__).resolve()
    profile, client = _approved_records()
    binding = ApprovedCodexExecutionBinding(
        provider_profile=profile,
        client_execution_profile=client,
        executable=ApprovedCodexExecutable(
            path=executable,
            sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        ),
        codex_home=executable.parent,
        runtime_environment="PERSONAL_LOCAL",
    )
    return CodexCliProcessRunner(binding=binding)


def test_command_is_pinned_isolated_and_prompt_is_stdin_only() -> None:
    runner = approved_runner()
    work = (Path.cwd() / "empty-work").resolve()
    schema = (Path.cwd() / "control" / "schema.json").resolve()
    output = (Path.cwd() / "control" / "last-message.json").resolve()

    argv = runner.execution_argv(request(), work, schema, output)

    assert argv[0] == str(runner.executable.path)
    assert argv[1] == "exec"
    assert argv[-1] == "-"
    assert "SECRET PROMPT" not in " ".join(argv)
    assert _option(argv, "--model") == "profile-selected-model"
    assert _option(argv, "--sandbox") == "read-only"
    assert _option(argv, "--cd") == str(work)
    assert _option(argv, "--output-schema") == str(schema)
    assert _option(argv, "--output-last-message") == str(output)
    for flag in (
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--skip-git-repo-check",
        "--json",
    ):
        assert flag in argv
    for feature in (
        "apps",
        "browser_use",
        "browser_use_external",
        "browser_use_full_cdp_access",
        "code_mode_host",
        "computer_use",
        "hooks",
        "image_generation",
        "multi_agent",
        "personality",
        "plugins",
        "remote_plugin",
        "shell_tool",
        "skill_mcp_dependency_install",
        "skill_search",
        "unified_exec",
        "view_image",
        "workspace_dependencies",
    ):
        assert _repeated_options(argv, "--disable").count(feature) == 1
    configs = _repeated_options(argv, "--config")
    assert 'forced_login_method="chatgpt"' in configs
    assert 'model_provider="openai"' in configs
    assert 'approval_policy="never"' in configs
    assert 'web_search="disabled"' in configs
    assert "mcp_servers={}" in configs
    assert "hooks={}" in configs
    assert "project_doc_max_bytes=0" in configs


def test_minimal_environment_drops_ambient_credentials_and_paths() -> None:
    runner = approved_runner()
    source = {
        "SYSTEMROOT": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "COMSPEC": r"C:\Windows\System32\cmd.exe",
        "OPENAI_API_KEY": "must-not-cross",
        "CODEX_API_KEY": "must-not-cross",
        "AWS_SECRET_ACCESS_KEY": "must-not-cross",
        "PATH": r"C:\attacker-controlled",
        "PYTHONPATH": r"C:\attacker-controlled",
    }

    child_environment = runner.child_environment(source)

    assert child_environment["CODEX_HOME"] == str(runner.codex_home)
    assert child_environment["SYSTEMROOT"] == r"C:\Windows"
    assert "OPENAI_API_KEY" not in child_environment
    assert "CODEX_API_KEY" not in child_environment
    assert "AWS_SECRET_ACCESS_KEY" not in child_environment
    assert "PATH" not in child_environment
    assert "PYTHONPATH" not in child_environment


def test_constructor_rejects_an_unapproved_executable_digest() -> None:
    approved = approved_runner()
    profile, client = _approved_records()

    with pytest.raises(ProviderExecutableBindingError):
        CodexCliProcessRunner(
            binding=ApprovedCodexExecutionBinding(
                provider_profile=profile,
                client_execution_profile=client,
                executable=ApprovedCodexExecutable(
                    path=approved.executable.path,
                    sha256="0" * 64,
                ),
                codex_home=approved.codex_home,
                runtime_environment="PERSONAL_LOCAL",
            ),
        )


def test_executable_digest_is_rechecked_immediately_before_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = approved_runner()
    monkeypatch.setattr(
        codex_subscription,
        "_sha256_file",
        lambda _path: "0" * 64,
    )

    with pytest.raises(ProviderExecutableBindingError):
        runner.verify_executable()


def test_execution_binding_rejects_a_different_provider_profile() -> None:
    runner = approved_runner()
    approved_profile_ref = reference(runner.binding.provider_profile)
    assert isinstance(approved_profile_ref, StoredDataRef)
    wrong_ref = approved_profile_ref.model_copy(
        update={"record_id": "different-profile-r1"}
    )

    with pytest.raises(ProviderInputMismatchError):
        runner.verify_binding(request(wrong_ref))


def test_execution_binding_rejects_a_stale_runtime_environment() -> None:
    executable = Path(__file__).resolve()
    profile, client = _approved_records()

    with pytest.raises(ValueError, match="CODEX_EXECUTION_BINDING_MISMATCH"):
        ApprovedCodexExecutionBinding(
            provider_profile=profile,
            client_execution_profile=client,
            executable=ApprovedCodexExecutable(
                path=executable,
                sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            ),
            codex_home=executable.parent,
            runtime_environment="PRIVATE_CI",
        )


def test_execution_binding_rejects_different_client_approval_evidence() -> None:
    executable = Path(__file__).resolve()
    profile, client = _approved_records()
    different_evidence = client.verification_evidence_ref.model_copy(
        update={"record_id": "different-validation-r1"}
    )
    stale_client = client.model_copy(
        update={"verification_evidence_ref": different_evidence}
    )
    stale_profile = profile.model_copy(
        update={"client_execution_profile_ref": reference(stale_client)}
    )

    with pytest.raises(ValueError, match="CODEX_EXECUTION_BINDING_MISMATCH"):
        ApprovedCodexExecutionBinding(
            provider_profile=stale_profile,
            client_execution_profile=stale_client,
            executable=ApprovedCodexExecutable(
                path=executable,
                sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            ),
            codex_home=executable.parent,
            runtime_environment="PERSONAL_LOCAL",
        )


def test_execution_binding_rejects_a_supported_codex_profile() -> None:
    executable = Path(__file__).resolve()
    profile, client = _approved_records()

    with pytest.raises(ValueError, match="CODEX_EXECUTION_BINDING_MISMATCH"):
        ApprovedCodexExecutionBinding(
            provider_profile=profile.model_copy(update={"support_status": "SUPPORTED"}),
            client_execution_profile=client,
            executable=ApprovedCodexExecutable(
                path=executable,
                sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            ),
            codex_home=executable.parent,
            runtime_environment="PERSONAL_LOCAL",
        )


def test_execution_binding_rechecks_codex_home_before_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = approved_runner()
    is_dir = Path.is_dir
    monkeypatch.setattr(
        Path,
        "is_dir",
        lambda path: False if path == runner.codex_home else is_dir(path),
    )

    with pytest.raises(ProviderExecutableBindingError):
        runner.verify_binding(request())


@pytest.mark.parametrize(
    "result",
    [
        _ChildResult(0, b"Not logged in using ChatGPT\n", b""),
        _ChildResult(0, b"Logged in using ChatGPT and API key\n", b""),
        _ChildResult(0, b"Logged in using ChatGPT\nextra diagnostic\n", b""),
        _ChildResult(0, b"", b"Logged in using ChatGPT\nextra diagnostic\n"),
    ],
)
def test_login_status_rejects_ambiguous_or_augmented_auth_modes(
    result: _ChildResult,
) -> None:
    assert not _is_exact_chatgpt_login_status(result)


def test_login_status_accepts_only_the_exact_official_chatgpt_status() -> None:
    assert _is_exact_chatgpt_login_status(
        _ChildResult(0, b"Logged in using ChatGPT\n", b"")
    )


@pytest.mark.asyncio
async def test_execute_rejects_a_different_cli_version_before_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = approved_runner()
    calls: list[tuple[str, ...]] = []

    class ExistingDirectory:
        def __enter__(self) -> str:
            return str(Path.cwd())

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(
        "sastsimi.providers.codex_subscription.tempfile.TemporaryDirectory",
        lambda **_kwargs: ExistingDirectory(),
    )
    monkeypatch.setattr(Path, "mkdir", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(Path, "write_bytes", lambda _path, data: len(data))

    async def wrong_version(argv: tuple[str, ...], **_kwargs: object) -> _ChildResult:
        calls.append(argv)
        return _ChildResult(0, b"codex-cli 9.9.9\n", b"")

    monkeypatch.setattr(runner, "_run_child", wrong_version)

    result = await runner.execute(request())

    assert result.status == "FAILED"
    assert calls == [(str(runner.executable.path), "--version")]


def test_model_cannot_be_reinterpreted_as_a_cli_option() -> None:
    runner = approved_runner()
    malicious = replace(request(), model="--dangerously-bypass-approvals-and-sandbox")

    with pytest.raises(ProviderInputMismatchError):
        runner.execution_argv(
            malicious,
            (Path.cwd() / "work").resolve(),
            (Path.cwd() / "schema.json").resolve(),
            (Path.cwd() / "output.json").resolve(),
        )


def test_array_schema_gets_only_transport_envelope() -> None:
    schema: dict[str, JsonValue] = {
        "type": "array",
        "items": {"type": "string"},
    }
    assert _codex_output_schema(schema) == {
        "type": "object",
        "properties": {"items": schema},
        "required": ["items"],
        "additionalProperties": False,
    }


@pytest.mark.parametrize(
    "event_stream",
    [
        b'{"type":"thread.started","thread_id":"one","thread_id":"two"}\n',
        b'{"type":"thread.started","thread_id":"one"}\n',
        b'{"type":"turn.completed"}\n',
        b"not-json\n",
    ],
)
def test_jsonl_requires_one_session_and_a_completed_turn(event_stream: bytes) -> None:
    with pytest.raises(ProviderInvalidOutputError):
        _validated_session_id(event_stream)


def test_jsonl_extracts_only_the_official_session_event() -> None:
    stream = (
        b'{"type":"thread.started","thread_id":"thread-1"}\n'
        b'{"type":"turn.started"}\n'
        b'{"type":"item.completed","item":{"type":"agent_message"}}\n'
        b'{"type":"item.completed","item":{"type":"reasoning"}}\n'
        b'{"type":"turn.completed","usage":{"input_tokens":1}}\n'
    )

    assert _validated_session_id(stream) == "thread-1"


@pytest.mark.parametrize(
    "event",
    [
        b'{"type":"error","message":"provider error"}',
        b'{"type":"turn.failed","error":{"message":"provider error"}}',
        (
            b'{"type":"item.completed","item":{"type":"error",'
            b'"message":"model rerouted: requested-model -> fallback-model"}}'
        ),
    ],
)
def test_jsonl_rejects_errors_and_model_reroutes(event: bytes) -> None:
    stream = (
        b'{"type":"thread.started","thread_id":"thread-1"}\n'
        b'{"type":"turn.started"}\n'
        + event
        + b'\n{"type":"turn.completed","usage":{}}\n'
    )

    with pytest.raises(ProviderInvalidOutputError):
        _validated_session_id(stream)


@pytest.mark.parametrize(
    "item_type",
    [
        "command_execution",
        "file_change",
        "mcp_tool_call",
        "web_search",
        "collab_tool_call",
        "tool_call",
        "todo_list",
    ],
)
def test_jsonl_rejects_every_forbidden_tool_event(item_type: str) -> None:
    stream = (
        b'{"type":"thread.started","thread_id":"thread-1"}\n'
        b'{"type":"turn.started"}\n'
        + ('{"type":"item.completed","item":{"type":"' + item_type + '"}}\n').encode()
        + b'{"type":"turn.completed","usage":{}}\n'
    )

    with pytest.raises(ProviderInvalidOutputError):
        _validated_session_id(stream)


@pytest.mark.parametrize(
    "stream",
    [
        (
            b'{"type":"thread.started","thread_id":"thread-1"}\n'
            b'{"type":"item.completed","item":{"type":"agent_message"}}\n'
            b'{"type":"turn.completed","usage":{}}\n'
        ),
        (
            b'{"type":"turn.started"}\n'
            b'{"type":"thread.started","thread_id":"thread-1"}\n'
            b'{"type":"turn.completed","usage":{}}\n'
        ),
        (
            b'{"type":"thread.started","thread_id":"thread-1"}\n'
            b'{"type":"turn.started"}\n'
            b'{"type":"unknown.event"}\n'
            b'{"type":"turn.completed","usage":{}}\n'
        ),
        (
            b'{"type":"thread.started","thread_id":"thread-1"}\n'
            b'{"type":"turn.started"}\n'
            b'{"type":"turn.completed","usage":{}}\n'
            b'{"type":"item.completed","item":{"type":"agent_message"}}\n'
        ),
    ],
)
def test_jsonl_requires_one_ordered_success_lifecycle(stream: bytes) -> None:
    with pytest.raises(ProviderInvalidOutputError):
        _validated_session_id(stream)


@pytest.mark.parametrize(
    ("diagnostic", "expected"),
    [
        (b"401 not logged in: secret-token", "AUTH_REQUIRED"),
        (b"429 usage limit: secret-token", "RATE_LIMITED"),
        (b"unknown client failure at C:/private/path", "FAILED"),
    ],
)
def test_child_diagnostics_collapse_to_safe_status_only(
    diagnostic: bytes, expected: str
) -> None:
    status = _classify_child_failure(_ChildResult(1, b"", diagnostic))

    assert status == expected
    assert "secret-token" not in status
    assert "private/path" not in status


def _option(argv: tuple[str, ...], name: str) -> str:
    return argv[argv.index(name) + 1]


def _repeated_options(argv: tuple[str, ...], name: str) -> list[str]:
    return [argv[index + 1] for index, value in enumerate(argv) if value == name]
