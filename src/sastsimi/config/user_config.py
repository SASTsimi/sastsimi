"""Secret-free defaults for the public SimpleRuntime command surface."""

from __future__ import annotations

import json
import os
import re
import tempfile
import tomllib
from pathlib import Path
from typing import Literal, Self

from platformdirs import user_config_dir
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_ENV_REFERENCE = re.compile(r"^env:[A-Z][A-Z0-9_]{1,127}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TOOL_NAMES = ("AST", "OPENGREP", "CODEQL", "DOCKER")


def default_user_config_path() -> Path:
    return Path(user_config_dir("sastsimi")) / "config.toml"


def _local_path(value: object) -> Path:
    if (
        not isinstance(value, (str, Path))
        or not str(value).strip()
        or "\x00" in str(value)
    ):
        raise ValueError("USER_CONFIG_PATH_INVALID")
    path = Path(value).expanduser().absolute()
    if path.parent == path:
        raise ValueError("USER_CONFIG_PATH_INVALID")
    return path


def _credential_ref(auth_mode: str, value: str) -> str:
    if auth_mode == "API_KEY" and _ENV_REFERENCE.fullmatch(value):
        return value
    if auth_mode == "SUBSCRIPTION_LOGIN" and value == "OFFICIAL_CLIENT_SESSION":
        return value
    raise ValueError("USER_CONFIG_CREDENTIAL_REF_INVALID")


def _quoted(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def _string_array(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(_quoted(value) for value in values) + "]"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


class UserConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    data_dir: Path
    profile_path: Path
    auth_mode: Literal["API_KEY", "SUBSCRIPTION_LOGIN"]
    provider: str
    model: str
    # The model the hypothesis agent uses when the operator wants a stronger
    # one for it than for the rest of the run.  Every proposal the run can ever
    # reach is decided there, so it is the one role worth paying more for.
    # ``None`` keeps every role on ``model``.
    deep_model: str | None = None
    credential_ref: str
    execution_profile: Literal["FULL", "LIGHTWEIGHT"]
    max_cost_minor_units: int = Field(gt=0)
    max_tokens: int = Field(gt=0)
    max_elapsed_seconds: int = Field(gt=0)
    docker_network: Literal["NONE", "BRIDGE"]
    enabled_tools: tuple[Literal["AST", "OPENGREP", "CODEQL", "DOCKER"], ...]
    detected_versions: dict[str, str]
    setup_ready: bool

    @field_validator("data_dir", "profile_path", mode="before")
    @classmethod
    def validate_paths(cls, value: object) -> Path:
        return _local_path(value)

    @field_validator("provider", "model")
    @classmethod
    def safe_names(cls, value: str) -> str:
        if _SAFE_NAME.fullmatch(value) is None:
            raise ValueError("USER_CONFIG_NAME_INVALID")
        return value

    @field_validator("deep_model")
    @classmethod
    def safe_deep_model(cls, value: str | None) -> str | None:
        if value is not None and _SAFE_NAME.fullmatch(value) is None:
            raise ValueError("USER_CONFIG_NAME_INVALID")
        return value

    @field_validator("detected_versions")
    @classmethod
    def safe_versions(cls, values: dict[str, str]) -> dict[str, str]:
        if any(
            _SAFE_NAME.fullmatch(key) is None
            or not value
            or len(value) > 160
            or any(ord(character) < 32 for character in value)
            for key, value in values.items()
        ):
            raise ValueError("USER_CONFIG_TOOL_VERSION_INVALID")
        return dict(sorted(values.items()))

    @model_validator(mode="after")
    def validate_auth_and_tools(self) -> Self:
        _credential_ref(self.auth_mode, self.credential_ref)
        if len(self.enabled_tools) != len(set(self.enabled_tools)):
            raise ValueError("USER_CONFIG_TOOL_DUPLICATE")
        if self.execution_profile == "FULL" and set(self.enabled_tools) != set(
            _TOOL_NAMES
        ):
            raise ValueError("USER_CONFIG_FULL_TOOL_SET_INVALID")
        return self

    def to_toml(self) -> str:
        lines = [
            f"schema_version = {self.schema_version}",
            f"data_dir = {_quoted(self.data_dir.as_posix())}",
            f"profile_path = {_quoted(self.profile_path.as_posix())}",
            f"auth_mode = {_quoted(self.auth_mode)}",
            f"provider = {_quoted(self.provider)}",
            f"model = {_quoted(self.model)}",
            *(
                ()
                if self.deep_model is None
                else (f"deep_model = {_quoted(self.deep_model)}",)
            ),
            f"credential_ref = {_quoted(self.credential_ref)}",
            f"execution_profile = {_quoted(self.execution_profile)}",
            f"max_cost_minor_units = {self.max_cost_minor_units}",
            f"max_tokens = {self.max_tokens}",
            f"max_elapsed_seconds = {self.max_elapsed_seconds}",
            f"docker_network = {_quoted(self.docker_network)}",
            f"enabled_tools = {_string_array(tuple(self.enabled_tools))}",
            f"setup_ready = {str(self.setup_ready).lower()}",
            "",
            "[detected_versions]",
        ]
        lines.extend(
            f"{key} = {_quoted(value)}" for key, value in self.detected_versions.items()
        )
        return "\n".join(lines) + "\n"


class SimpleToolBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    executable_path: Path
    version: str
    executable_sha256: str

    @field_validator("executable_path", mode="before")
    @classmethod
    def validate_path(cls, value: object) -> Path:
        return _local_path(value)

    @field_validator("executable_sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("SIMPLE_PROFILE_TOOL_DIGEST_INVALID")
        return value


class SimpleExecutionProfile(BaseModel):
    """Small host-local profile for the public SimpleRuntime path."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    provider_profile_ref: str
    provider: str
    model: str
    deep_model: str | None = None
    auth_mode: Literal["API_KEY", "SUBSCRIPTION_LOGIN"]
    credential_ref: str
    data_dir: Path
    workspace_root: Path
    max_cost_minor_units: int = Field(gt=0)
    max_tokens: int = Field(gt=0)
    max_elapsed_seconds: int = Field(gt=0)
    docker_network: Literal["NONE", "BRIDGE"]
    # How many hypotheses may be worked on at once.  One keeps the run strictly
    # sequential; each extra one adds a concurrent official-client process and a
    # concurrent reproduction container, so the ceiling is the host's memory.
    max_parallel_hypotheses: int = Field(default=1, ge=1, le=16)
    # Three separate resources sit under that flow, so each has its own ceiling
    # rather than one number chosen for the heaviest of them.  Calls share one
    # subscription; a build was measured at over two gigabytes; a reproduction
    # container costs a few megabytes.
    max_parallel_calls: int = Field(default=1, ge=1, le=16)
    max_parallel_builds: int = Field(default=1, ge=1, le=8)
    max_parallel_containers: int = Field(default=1, ge=1, le=16)
    tools: dict[str, SimpleToolBinding]

    @field_validator("data_dir", "workspace_root", mode="before")
    @classmethod
    def validate_paths(cls, value: object) -> Path:
        return _local_path(value)

    @field_validator("provider_profile_ref", "provider", "model")
    @classmethod
    def safe_names(cls, value: str) -> str:
        if _SAFE_NAME.fullmatch(value) is None:
            raise ValueError("SIMPLE_PROFILE_NAME_INVALID")
        return value

    @field_validator("deep_model")
    @classmethod
    def safe_deep_model(cls, value: str | None) -> str | None:
        if value is not None and _SAFE_NAME.fullmatch(value) is None:
            raise ValueError("SIMPLE_PROFILE_NAME_INVALID")
        return value

    def model_for(self, *, deep: bool) -> str:
        """Return the model one role runs on; ``deep`` roles may differ."""

        return self.deep_model if deep and self.deep_model else self.model

    @model_validator(mode="after")
    def validate_credential(self) -> Self:
        _credential_ref(self.auth_mode, self.credential_ref)
        return self

    def to_toml(self) -> str:
        lines = [
            f"schema_version = {self.schema_version}",
            f"provider_profile_ref = {_quoted(self.provider_profile_ref)}",
            f"provider = {_quoted(self.provider)}",
            f"model = {_quoted(self.model)}",
            *(
                ()
                if self.deep_model is None
                else (f"deep_model = {_quoted(self.deep_model)}",)
            ),
            f"auth_mode = {_quoted(self.auth_mode)}",
            f"credential_ref = {_quoted(self.credential_ref)}",
            f"data_dir = {_quoted(self.data_dir.as_posix())}",
            f"workspace_root = {_quoted(self.workspace_root.as_posix())}",
            f"max_cost_minor_units = {self.max_cost_minor_units}",
            f"max_tokens = {self.max_tokens}",
            f"max_elapsed_seconds = {self.max_elapsed_seconds}",
            f"docker_network = {_quoted(self.docker_network)}",
            f"max_parallel_hypotheses = {self.max_parallel_hypotheses}",
            f"max_parallel_calls = {self.max_parallel_calls}",
            f"max_parallel_builds = {self.max_parallel_builds}",
            f"max_parallel_containers = {self.max_parallel_containers}",
            "",
            "[tools]",
        ]
        for name, binding in sorted(self.tools.items()):
            lines.extend(
                (
                    "",
                    f"[tools.{name}]",
                    f"executable_path = {_quoted(binding.executable_path.as_posix())}",
                    f"version = {_quoted(binding.version)}",
                    f"executable_sha256 = {_quoted(binding.executable_sha256)}",
                )
            )
        return "\n".join(lines) + "\n"

    def write(self, path: Path) -> None:
        _atomic_write(path, self.to_toml())


class UserConfigStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_user_config_path()

    def save(self, config: UserConfig) -> Path:
        _atomic_write(self.path, config.to_toml())
        return self.path

    def load(self) -> UserConfig:
        try:
            with self.path.open("rb") as stream:
                return UserConfig.model_validate(tomllib.load(stream))
        except (OSError, ValueError) as error:
            raise ValueError("USER_CONFIG_INVALID") from error


def load_simple_execution_profile(path: Path) -> SimpleExecutionProfile:
    try:
        with path.open("rb") as stream:
            return SimpleExecutionProfile.model_validate(tomllib.load(stream))
    except (OSError, ValueError) as error:
        raise ValueError("SIMPLE_EXECUTION_PROFILE_INVALID") from error


__all__ = [
    "SimpleExecutionProfile",
    "SimpleToolBinding",
    "UserConfig",
    "UserConfigStore",
    "default_user_config_path",
    "load_simple_execution_profile",
]
