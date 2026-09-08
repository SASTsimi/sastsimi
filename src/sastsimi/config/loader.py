"""Parse every trusted source before applying its precedence."""

import os
import tomllib
from collections.abc import Mapping
from pathlib import Path

from pydantic import ValidationError

from sastsimi.config.models import AppConfig
from sastsimi.config.precedence import ENV_FIELDS, OVERRIDE_FIELDS, merge_sources


class ConfigError(ValueError):
    """Safe error category; never include raw validation inputs or host paths."""


def _validate(source: Mapping[str, object], *, override: bool = False) -> None:
    if override and set(source) - OVERRIDE_FIELDS:
        raise ConfigError("Configuration override is not allowed")
    try:
        AppConfig.model_validate(source)
    except (ValidationError, ValueError, OSError):
        raise ConfigError("Invalid configuration value") from None


def load_config(
    *,
    config_path: Path | None = None,
    environ: Mapping[str, str] | None = None,
    cli: Mapping[str, object] | None = None,
) -> AppConfig:
    file_source: dict[str, object] = {}
    if config_path is not None:
        try:
            with config_path.open("rb") as stream:
                file_source = tomllib.load(stream)
        except (OSError, ValueError):
            raise ConfigError("Unable to read approved configuration") from None
        if "schema_version" not in file_source:
            raise ConfigError("Configuration schema version is required")
    _validate(file_source)
    environment = os.environ if environ is None else environ
    env_source: dict[str, object] = {}
    for name, value in environment.items():
        if name.startswith("SASTSIMI_"):
            if name not in ENV_FIELDS:
                raise ConfigError("Unknown configuration environment variable")
            env_source[ENV_FIELDS[name]] = value
    _validate(env_source, override=True)
    cli_source = {} if cli is None else dict(cli)
    _validate(cli_source, override=True)
    return AppConfig.model_validate(merge_sources(file_source, env_source, cli_source))
