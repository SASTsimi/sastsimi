import hashlib
from pathlib import Path

import pytest
from pydantic import JsonValue

import sastsimi.providers.codex_subscription as codex_subscription
from sastsimi.providers.base import (
    CodexProcessRequest,
    ProviderInputMismatchError,
    ProviderInvalidOutputError,
)
from sastsimi.providers.codex_subscription import (
    ApprovedCodexExecutable,
    CodexCliProcessRunner,
    ProviderExecutableBindingError,
    _ChildResult,
    _classify_child_failure,
    _codex_output_schema,
    _validated_session_id,
)


def request() -> CodexProcessRequest:
    return CodexProcessRequest(
        invocation_id="call-1",
        model="profile-selected-model",
        prompt=b"SECRET PROMPT SENT ONLY ON STDIN",
        output_schema=b'{"type":"object"}',
        timeout_ms=30_000,
    )


def approved_runner() -> CodexCliProcessRunner:
    executable = Path(__file__).resolve()
    binding = ApprovedCodexExecutable(
        path=executable,
        sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
    )
    return CodexCliProcessRunner(
        executable=binding,
        codex_home=executable.parent,
    )


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

    with pytest.raises(ProviderExecutableBindingError):
        CodexCliProcessRunner(
            executable=ApprovedCodexExecutable(
                path=approved.executable.path,
                sha256="0" * 64,
            ),
            codex_home=approved.codex_home,
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


def test_model_cannot_be_reinterpreted_as_a_cli_option() -> None:
    runner = approved_runner()
    malicious = CodexProcessRequest(
        invocation_id="call-1",
        model="--dangerously-bypass-approvals-and-sandbox",
        prompt=b"prompt",
        output_schema=b'{"type":"object"}',
        timeout_ms=30_000,
    )

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
        b'{"type":"item.completed","item":{"type":"agent_message"}}\n'
        b'{"type":"turn.completed","usage":{"input_tokens":1}}\n'
    )

    assert _validated_session_id(stream) == "thread-1"


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
