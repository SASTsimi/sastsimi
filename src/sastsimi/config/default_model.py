"""Controlled update of the two user-local SimpleRuntime model settings."""

from __future__ import annotations

from sastsimi.config.user_config import (
    SimpleExecutionProfile,
    UserConfig,
    UserConfigStore,
    _atomic_write,
    load_simple_execution_profile,
)


def set_default_model(model: str, store: UserConfigStore | None = None) -> None:
    selected = store or UserConfigStore()
    config = selected.load()
    profile = load_simple_execution_profile(config.profile_path)
    if (
        config.provider != "codex"
        or profile.provider != config.provider
        or profile.data_dir != config.data_dir
        or profile.model != config.model
    ):
        raise ValueError("DEFAULT_MODEL_PROFILE_MISMATCH")
    next_config = UserConfig.model_validate({**config.model_dump(), "model": model})
    next_profile = SimpleExecutionProfile.model_validate(
        {**profile.model_dump(), "model": model}
    )
    original_config = selected.path.read_bytes()
    original_profile = config.profile_path.read_bytes()
    try:
        next_profile.write(config.profile_path)
        selected.save(next_config)
    except BaseException:
        _atomic_write(config.profile_path, original_profile.decode("utf-8"))
        _atomic_write(selected.path, original_config.decode("utf-8"))
        raise
