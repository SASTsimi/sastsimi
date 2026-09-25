# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastsimi.config.user_config import UserConfigStore
from sastsimi.interfaces.cli.main import main
from sastsimi.setup.service import (
    SetupChoices,
    SetupService,
    SystemToolDiscovery,
    ToolInspection,
)


class _Discovery:
    def __init__(self, missing: frozenset[str] = frozenset()) -> None:
        self._missing = missing

    def inspect(self) -> tuple[ToolInspection, ...]:
        return tuple(
            ToolInspection(
                name=name,
                available=name not in self._missing,
                executable=None if name in self._missing else Path(f"C:/{name}.exe"),
                version=None
                if name in self._missing
                else "2.1.280"
                if name == "claude"
                else "1.0.0",
                executable_sha256=None if name in self._missing else "a" * 64,
            )
            for name in (
                "git",
                "python",
                "opengrep",
                "codeql",
                "docker",
                "codex",
                "cursor_agent",
                "claude",
            )
        )


def _service(tmp_path: Path, *, missing: frozenset[str] = frozenset()):
    return SetupService(
        config_store=UserConfigStore(tmp_path / "config.toml"),
        discovery=_Discovery(missing),
        profile_path=tmp_path / "profile.toml",
        auth_checker=lambda _choices, _tools: True,
    )


def test_setup_cli_writes_ready_secret_free_configuration(
    tmp_path: Path, capsys
) -> None:
    service = _service(tmp_path)

    code = main(
        [
            "setup",
            "--non-interactive",
            "--data-dir",
            str(tmp_path / "data"),
            "--auth",
            "subscription",
            "--provider",
            "codex",
            "--model",
            "configured-model",
            "--profile",
            "full",
            "--docker-network",
            "none",
            "--format",
            "json",
        ],
        setup_service=service,
    )

    assert code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["data"]["status"] == "READY"
    assert output["data"]["missing_tools"] == []
    saved = service.config_store.load()
    assert saved.credential_ref == "OFFICIAL_CLIENT_SESSION"
    assert saved.setup_ready is True
    raw = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert "access_token" not in raw
    assert "refresh_token" not in raw
    assert "sk-" not in raw


def test_setup_cli_selects_claude_without_api_key(tmp_path: Path, capsys) -> None:
    service = _service(tmp_path)
    code = main(
        [
            "setup",
            "--non-interactive",
            "--data-dir",
            str(tmp_path / "data"),
            "--auth",
            "subscription",
            "--provider",
            "claude",
            "--model",
            "operator-selected-model",
            "--profile",
            "lightweight",
            "--format",
            "json",
        ],
        setup_service=service,
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)["data"]["status"] == "READY"
    saved = service.config_store.load()
    assert saved.provider == "claude"
    assert saved.credential_ref == "CLAUDE_CLI_LOGIN"
    from sastsimi.config.user_config import load_simple_execution_profile

    profile = load_simple_execution_profile(service._profile_path)
    assert "claude" in profile.tools


def test_claude_setup_rejects_unverified_cli_version(tmp_path: Path) -> None:
    class OldDiscovery(_Discovery):
        def inspect(self) -> tuple[ToolInspection, ...]:
            return tuple(
                item.model_copy(update={"version": "2.1.250"})
                if item.name == "claude"
                else item
                for item in super().inspect()
            )

    service = SetupService(
        config_store=UserConfigStore(tmp_path / "config.toml"),
        discovery=OldDiscovery(),
        profile_path=tmp_path / "profile.toml",
        auth_checker=lambda _choices, _tools: True,
    )
    result = service.configure(
        SetupChoices(
            data_dir=tmp_path / "data",
            auth_mode="SUBSCRIPTION_LOGIN",
            provider="claude",
            model="operator-model",
            credential_ref="CLAUDE_CLI_LOGIN",
            execution_profile="LIGHTWEIGHT",
            max_cost_minor_units=10_000,
            max_tokens=500_000,
            max_elapsed_seconds=3_600,
            docker_network="NONE",
        )
    )
    assert result.status == "BLOCKED"
    assert any("CLAUDE_CLI_UNSUPPORTED_VERSION" in item for item in result.next_actions)


def test_claude_auth_requires_first_party_subscription_even_on_zero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    from sastsimi.setup.service import _default_auth_checker

    choices = SetupChoices(
        data_dir=Path("C:/data"),
        auth_mode="SUBSCRIPTION_LOGIN",
        provider="claude",
        model="operator-model",
        credential_ref="CLAUDE_CLI_LOGIN",
        execution_profile="LIGHTWEIGHT",
        max_cost_minor_units=10_000,
        max_tokens=500_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
    )
    tool = ToolInspection(
        name="claude",
        available=True,
        executable=Path("C:/claude.exe"),
        version="2.1.280",
        executable_sha256="a" * 64,
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [],
            0,
            stdout='{"loggedIn":false,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"pro"}',
            stderr="",
        ),
    )
    assert _default_auth_checker(choices, {"claude": tool}) is False
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [],
            0,
            stdout='{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"pro"}',
            stderr="",
        ),
    )
    assert _default_auth_checker(choices, {"claude": tool}) is True


def test_claude_factory_routes_only_selected_provider(tmp_path: Path) -> None:
    from sastsimi.composition.simple_runtime_composition import SimpleClientFactory
    from sastsimi.config.user_config import load_simple_execution_profile
    from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
    from sastsimi.simple_runtime.claude_provider import ClaudeProvider
    from sastsimi.simple_runtime.models import CheckpointIdentity

    service = _service(tmp_path)
    configured = service.configure(
        SetupChoices(
            data_dir=tmp_path / "data",
            auth_mode="SUBSCRIPTION_LOGIN",
            provider="claude",
            model="operator-model",
            credential_ref="CLAUDE_CLI_LOGIN",
            execution_profile="LIGHTWEIGHT",
            max_cost_minor_units=10_000,
            max_tokens=500_000,
            max_elapsed_seconds=3_600,
            docker_network="NONE",
        )
    )
    profile = load_simple_execution_profile(configured.profile_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    client = SimpleClientFactory(profile)(
        identity, SimpleArtifactRepository(tmp_path / "data", identity)
    )
    assert isinstance(client, ClaudeProvider)


def test_setup_cli_blocks_full_profile_when_codeql_is_missing(
    tmp_path: Path, capsys
) -> None:
    service = _service(tmp_path, missing=frozenset({"codeql"}))

    code = main(
        [
            "setup",
            "--non-interactive",
            "--data-dir",
            str(tmp_path / "data"),
            "--auth",
            "api-key",
            "--provider",
            "openai",
            "--model",
            "configured-model",
            "--profile",
            "full",
            "--docker-network",
            "none",
            "--format",
            "json",
        ],
        setup_service=service,
    )

    assert code == 4
    output = json.loads(capsys.readouterr().err)
    assert output["data"]["status"] == "BLOCKED"
    assert output["data"]["missing_tools"] == ["codeql"]
    assert service.config_store.load().setup_ready is False


def test_setup_service_accepts_explicit_choices_without_cli(tmp_path: Path) -> None:
    service = _service(tmp_path)
    result = service.configure(
        SetupChoices(
            data_dir=tmp_path / "data",
            auth_mode="API_KEY",
            provider="openai",
            model="configured-model",
            credential_ref="env:OPENAI_API_KEY",
            execution_profile="LIGHTWEIGHT",
            max_cost_minor_units=10_000,
            max_tokens=500_000,
            max_elapsed_seconds=3_600,
            docker_network="NONE",
        )
    )

    assert result.status == "READY"
    assert result.profile_path.is_file()


def test_cursor_setup_keeps_models_and_fallback_without_secret(tmp_path: Path) -> None:
    service = _service(tmp_path)
    result = service.configure(
        SetupChoices(
            data_dir=tmp_path / "data",
            auth_mode="API_KEY",
            provider="cursor",
            model="available-model",
            credential_ref="env:CURSOR_API_KEY",
            execution_profile="LIGHTWEIGHT",
            max_cost_minor_units=10_000,
            max_tokens=500_000,
            max_elapsed_seconds=3_600,
            docker_network="NONE",
            agent_models={"verification_result": "verification-model"},
            llm_timeout_seconds=45,
            llm_max_retries=1,
            llm_max_concurrency=3,
            cursor_allow_on_demand=True,
            fallback_provider="openai",
            fallback_model="fallback-model",
        )
    )
    assert result.status == "READY"
    saved = service.config_store.load()
    assert saved.provider == "cursor"
    assert saved.agent_models == {"verification_result": "verification-model"}
    assert saved.fallback_provider == "openai"
    from sastsimi.config.user_config import load_simple_execution_profile

    profile = load_simple_execution_profile(result.profile_path)
    assert profile.llm_max_concurrency == 3
    assert profile.cursor_allow_on_demand
    assert "test-key" not in result.profile_path.read_text(encoding="utf-8")


def test_cursor_setup_requires_usage_acknowledgement(tmp_path: Path) -> None:
    service = _service(tmp_path)
    result = service.configure(
        SetupChoices(
            data_dir=tmp_path / "data",
            auth_mode="API_KEY",
            provider="cursor",
            model="available-model",
            credential_ref="env:CURSOR_API_KEY",
            execution_profile="LIGHTWEIGHT",
            max_cost_minor_units=10_000,
            max_tokens=500_000,
            max_elapsed_seconds=3_600,
            docker_network="NONE",
        )
    )
    assert result.status == "BLOCKED"
    assert not service.config_store.load().setup_ready


def test_cursor_cli_member_login_is_default_for_cursor_setup(tmp_path: Path) -> None:
    service = _service(tmp_path)
    result = service.configure(
        SetupChoices(
            data_dir=tmp_path / "data",
            auth_mode="SUBSCRIPTION_LOGIN",
            provider="cursor",
            model="auto",
            credential_ref="CURSOR_CLI_LOGIN",
            execution_profile="LIGHTWEIGHT",
            max_cost_minor_units=10_000,
            max_tokens=500_000,
            max_elapsed_seconds=3_600,
            docker_network="NONE",
            cursor_allow_on_demand=True,
        )
    )
    assert result.status == "READY"
    saved = service.config_store.load()
    assert saved.auth_mode == "SUBSCRIPTION_LOGIN"
    assert saved.credential_ref == "CURSOR_CLI_LOGIN"
    assert "cursor_agent" in result.profile_path.read_text(encoding="utf-8")


def test_cursor_factory_rediscovers_cli_after_installer_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sastsimi.composition.simple_runtime_composition import SimpleClientFactory
    from sastsimi.config.user_config import load_simple_execution_profile
    from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
    from sastsimi.simple_runtime.cursor_provider import (
        CursorProvider,
        OfficialCursorCLITransport,
    )
    from sastsimi.simple_runtime.models import CheckpointIdentity

    service = _service(tmp_path)
    configured = service.configure(
        SetupChoices(
            data_dir=tmp_path / "data",
            auth_mode="SUBSCRIPTION_LOGIN",
            provider="cursor",
            model="auto",
            credential_ref="CURSOR_CLI_LOGIN",
            execution_profile="LIGHTWEIGHT",
            max_cost_minor_units=10_000,
            max_tokens=500_000,
            max_elapsed_seconds=3_600,
            docker_network="NONE",
            cursor_allow_on_demand=True,
        )
    )
    native = tmp_path / "current" / "node.exe"
    native.parent.mkdir()
    native.write_bytes(b"native")
    native.with_name("index.js").write_text("", encoding="utf-8")
    monkeypatch.setattr(
        "sastsimi.composition.simple_runtime_composition.SystemToolDiscovery._inspect_cursor_agent",
        lambda: ToolInspection(
            name="cursor_agent",
            available=True,
            executable=native,
            version="current",
            executable_sha256="b" * 64,
        ),
    )
    profile = load_simple_execution_profile(configured.profile_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    client = SimpleClientFactory(profile)(
        identity, SimpleArtifactRepository(tmp_path / "data", identity)
    )
    assert isinstance(client, CursorProvider)
    assert isinstance(client._transport, OfficialCursorCLITransport)
    assert client._transport._executable == str(native)


def test_cursor_models_reports_cli_login_failure(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from sastsimi.simple_runtime.cursor_provider import CursorCLIAuthenticationError

    async def rejected() -> set[str]:
        raise CursorCLIAuthenticationError()

    monkeypatch.setattr(
        "sastsimi.composition.simple_runtime_composition.list_cursor_models",
        rejected,
    )
    assert main(["cursor-models"]) != 0
    assert "CURSOR_AUTH_FAILED" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_cursor_model_listing_uses_optional_key_after_cli_logout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sastsimi.composition import simple_runtime_composition as composition
    from sastsimi.simple_runtime.cursor_provider import CursorCLIAuthenticationError

    class LoggedOutCLI:
        def __init__(self, _executable: str) -> None:
            pass

        async def list_models(self, _key: str) -> set[str]:
            raise CursorCLIAuthenticationError()

    class KeySDK:
        def __init__(self, _workspace: str) -> None:
            pass

        async def list_models(self, key: str) -> set[str]:
            assert key == "test-key"
            return {"sdk-model"}

    monkeypatch.setenv("CURSOR_API_KEY", "test-key")
    monkeypatch.setattr(
        SystemToolDiscovery,
        "_inspect_cursor_agent",
        lambda: ToolInspection(
            name="cursor_agent",
            available=True,
            executable=Path("C:/cursor-agent/node.exe"),
        ),
    )
    monkeypatch.setattr(composition, "OfficialCursorCLITransport", LoggedOutCLI)
    monkeypatch.setattr(composition, "OfficialCursorTransport", KeySDK)
    assert await composition.list_cursor_models() == {"sdk-model"}


def test_cursor_cli_setup_defaults_to_subscription_auth(tmp_path: Path) -> None:
    service = _service(tmp_path)
    code = main(
        [
            "setup",
            "--non-interactive",
            "--provider",
            "cursor",
            "--model",
            "auto",
            "--profile",
            "lightweight",
            "--cursor-allow-on-demand",
            "--data-dir",
            str(tmp_path / "data"),
        ],
        setup_service=service,
    )
    assert code == 0
    saved = service.config_store.load()
    assert saved.auth_mode == "SUBSCRIPTION_LOGIN"
    assert saved.credential_ref == "CURSOR_CLI_LOGIN"
