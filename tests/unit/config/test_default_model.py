from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.config.default_model import set_default_model
from sastsimi.config.user_config import (
    SimpleExecutionProfile,
    SimpleToolBinding,
    UserConfig,
    UserConfigStore,
    load_simple_execution_profile,
)


@pytest.fixture
def paired(tmp_path: Path) -> tuple[UserConfigStore, UserConfig]:
    store = UserConfigStore(tmp_path / "config.toml")
    config = UserConfig(
        data_dir=tmp_path / "data",
        profile_path=tmp_path / "profile.toml",
        auth_mode="SUBSCRIPTION_LOGIN",
        provider="codex",
        model="old-model",
        credential_ref="OFFICIAL_CLIENT_SESSION",
        execution_profile="FULL",
        max_cost_minor_units=12345,
        max_tokens=123456,
        max_elapsed_seconds=777,
        docker_network="BRIDGE",
        enabled_tools=("AST", "OPENGREP", "CODEQL", "DOCKER"),
        detected_versions={"git": "2.51.0"},
        setup_ready=True,
        agent_models={"verification_result": "existing-override"},
    )
    profile = SimpleExecutionProfile(
        provider_profile_ref="local-codex",
        provider="codex",
        model="old-model",
        auth_mode="SUBSCRIPTION_LOGIN",
        credential_ref="OFFICIAL_CLIENT_SESSION",
        data_dir=config.data_dir,
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=12345,
        max_tokens=123456,
        max_elapsed_seconds=777,
        docker_network="BRIDGE",
        tools={
            "codex": SimpleToolBinding(
                executable_path=tmp_path / "codex.exe",
                version="1.0.0",
                executable_sha256="a" * 64,
            )
        },
        agent_models={"verification_result": "existing-override"},
    )
    store.save(config)
    profile.write(config.profile_path)
    return store, config


def test_default_model_update_preserves_every_other_field(
    paired: tuple[UserConfigStore, UserConfig],
) -> None:
    store, config = paired
    before_config = store.load()
    before_profile = load_simple_execution_profile(config.profile_path)

    set_default_model("gpt-6-sol", store)

    after_config = store.load()
    after_profile = load_simple_execution_profile(config.profile_path)
    assert after_config.model == after_profile.model == "gpt-6-sol"
    assert after_config.model_dump(exclude={"model"}) == before_config.model_dump(
        exclude={"model"}
    )
    assert after_profile.model_dump(exclude={"model"}) == before_profile.model_dump(
        exclude={"model"}
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider", "openai"),
        ("data_dir", Path("C:/different")),
        ("model", "other-model"),
    ],
)
def test_profile_mismatch_does_not_write(
    paired: tuple[UserConfigStore, UserConfig], field: str, value: object
) -> None:
    store, config = paired
    profile = load_simple_execution_profile(config.profile_path)
    profile.model_copy(update={field: value}).write(config.profile_path)
    originals = (store.path.read_bytes(), config.profile_path.read_bytes())

    with pytest.raises(ValueError, match="DEFAULT_MODEL_PROFILE_MISMATCH"):
        set_default_model("gpt-6-sol", store)

    assert (store.path.read_bytes(), config.profile_path.read_bytes()) == originals


def test_invalid_model_does_not_write(
    paired: tuple[UserConfigStore, UserConfig],
) -> None:
    store, config = paired
    originals = (store.path.read_bytes(), config.profile_path.read_bytes())

    with pytest.raises(ValueError):
        set_default_model(" bad\nmodel", store)

    assert (store.path.read_bytes(), config.profile_path.read_bytes()) == originals


def test_second_write_failure_restores_both(
    paired: tuple[UserConfigStore, UserConfig],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, config = paired
    originals = (store.path.read_bytes(), config.profile_path.read_bytes())

    def fail_save(_config: UserConfig) -> Path:
        raise OSError("injected")

    monkeypatch.setattr(store, "save", fail_save)
    with pytest.raises(OSError, match="injected"):
        set_default_model("gpt-6-sol", store)

    assert (store.path.read_bytes(), config.profile_path.read_bytes()) == originals
    assert not list(tmp_path.glob("*.tmp"))
