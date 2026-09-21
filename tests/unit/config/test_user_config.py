from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.config.user_config import (
    SimpleExecutionProfile,
    SimpleToolBinding,
    UserConfig,
    UserConfigStore,
    default_user_config_path,
    load_simple_execution_profile,
)


def test_user_config_round_trip_is_atomic_and_contains_no_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sastsimi.config.user_config as module

    monkeypatch.setattr(module, "user_config_dir", lambda _name: str(tmp_path))
    store = UserConfigStore()
    profile_path = tmp_path / "profile.toml"
    config = UserConfig(
        data_dir=tmp_path / "data",
        profile_path=profile_path,
        auth_mode="API_KEY",
        provider="openai",
        model="configured-model",
        credential_ref="env:OPENAI_API_KEY",
        execution_profile="FULL",
        max_cost_minor_units=10_000,
        max_tokens=500_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
        enabled_tools=("AST", "OPENGREP", "CODEQL", "DOCKER"),
        detected_versions={"git": "2.51.0", "python": "3.12.10"},
        setup_ready=True,
    )

    written = store.save(config)

    assert written == default_user_config_path()
    assert store.load() == config
    assert not tuple(tmp_path.glob("*.tmp"))
    raw = written.read_text(encoding="utf-8")
    assert "OPENAI_API_KEY" in raw
    assert "sk-test-secret" not in raw


def test_user_config_rejects_literal_credentials(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="USER_CONFIG_CREDENTIAL_REF_INVALID"):
        UserConfig(
            data_dir=tmp_path / "data",
            profile_path=tmp_path / "profile.toml",
            auth_mode="API_KEY",
            provider="openai",
            model="configured-model",
            credential_ref="sk-test-secret",
            execution_profile="FULL",
            max_cost_minor_units=10_000,
            max_tokens=500_000,
            max_elapsed_seconds=3_600,
            docker_network="NONE",
            enabled_tools=("AST", "OPENGREP", "CODEQL", "DOCKER"),
            detected_versions={},
            setup_ready=False,
        )


def test_simple_execution_profile_supports_api_and_subscription_without_secret(
    tmp_path: Path,
) -> None:
    api = SimpleExecutionProfile(
        provider_profile_ref="local-openai",
        provider="openai",
        model="configured-model",
        auth_mode="API_KEY",
        credential_ref="env:OPENAI_API_KEY",
        data_dir=tmp_path / "data",
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=10_000,
        max_tokens=500_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
        tools={
            "python": SimpleToolBinding(
                executable_path=tmp_path / "python.exe",
                version="3.12.10",
                executable_sha256="a" * 64,
            )
        },
    )
    subscription = api.model_copy(
        update={
            "provider_profile_ref": "local-codex",
            "provider": "codex",
            "auth_mode": "SUBSCRIPTION_LOGIN",
            "credential_ref": "OFFICIAL_CLIENT_SESSION",
        }
    )

    api_path = tmp_path / "api.toml"
    subscription_path = tmp_path / "subscription.toml"
    api.write(api_path)
    subscription.write(subscription_path)

    assert load_simple_execution_profile(api_path) == api
    assert load_simple_execution_profile(subscription_path) == subscription
    assert "sk-" not in api_path.read_text(encoding="utf-8")


def test_simple_execution_profile_preserves_an_empty_tool_table(
    tmp_path: Path,
) -> None:
    profile = SimpleExecutionProfile(
        provider_profile_ref="local-openai",
        provider="openai",
        model="configured-model",
        auth_mode="API_KEY",
        credential_ref="env:OPENAI_API_KEY",
        data_dir=tmp_path / "data",
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=10_000,
        max_tokens=500_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
        tools={},
    )
    path = tmp_path / "profile.toml"

    profile.write(path)

    assert load_simple_execution_profile(path) == profile


def _profile(tmp_path: Path, **overrides: object) -> SimpleExecutionProfile:
    fields: dict[str, object] = {
        "provider_profile_ref": "local-claude",
        "provider": "claude",
        "model": "claude-sonnet-5",
        "auth_mode": "SUBSCRIPTION_LOGIN",
        "credential_ref": "OFFICIAL_CLIENT_SESSION",
        "data_dir": tmp_path / "data",
        "workspace_root": tmp_path / "workspaces",
        "max_cost_minor_units": 10_000,
        "max_tokens": 500_000,
        "max_elapsed_seconds": 3_600,
        "docker_network": "NONE",
        "tools": {},
    }
    fields.update(overrides)
    return SimpleExecutionProfile(**fields)  # type: ignore[arg-type]


def test_one_configured_model_serves_every_role(tmp_path: Path) -> None:
    profile = _profile(tmp_path)

    assert profile.deep_model is None
    assert profile.model_for(deep=True) == "claude-sonnet-5"
    assert profile.model_for(deep=False) == "claude-sonnet-5"
    assert "deep_model" not in profile.to_toml()


def test_deep_model_reaches_only_the_reasoning_roles(tmp_path: Path) -> None:
    profile = _profile(tmp_path, deep_model="claude-opus-5")

    assert profile.model_for(deep=True) == "claude-opus-5"
    assert profile.model_for(deep=False) == "claude-sonnet-5"
    assert 'deep_model = "claude-opus-5"' in profile.to_toml()


def test_deep_model_rejects_an_unsafe_name(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="SIMPLE_PROFILE_NAME_INVALID"):
        _profile(tmp_path, deep_model="../../etc/passwd")
