"""Detect local tools and persist a runnable, secret-free profile."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from sastsimi.config.user_config import (
    SimpleExecutionProfile,
    SimpleToolBinding,
    UserConfig,
    UserConfigStore,
)

_TOOL_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("git", ("git", "--version")),
    ("python", (sys.executable, "--version")),
    ("opengrep", ("opengrep", "--version")),
    ("codeql", ("codeql", "version", "--format=terse")),
    ("docker", ("docker", "version", "--format", "{{.Client.Version}}")),
    ("codex", ("codex", "--version")),
    ("cursor_agent", ("agent", "--version")),
    ("claude", ("claude", "--version")),
)


class ToolInspection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    available: bool
    executable: Path | None = None
    version: str | None = None
    executable_sha256: str | None = None


class SetupInspection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tools: tuple[ToolInspection, ...]


class SetupChoices(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data_dir: Path
    auth_mode: Literal["API_KEY", "SUBSCRIPTION_LOGIN"]
    provider: str
    model: str
    credential_ref: str
    execution_profile: Literal["FULL", "LIGHTWEIGHT"]
    max_cost_minor_units: int = Field(gt=0)
    max_tokens: int = Field(gt=0)
    max_elapsed_seconds: int = Field(gt=0)
    docker_network: Literal["NONE", "BRIDGE"]
    agent_models: dict[str, str] = Field(default_factory=dict)
    llm_timeout_seconds: int = Field(default=180, gt=0, le=3600)
    llm_max_retries: int = Field(default=2, ge=0, le=5)
    llm_max_concurrency: int = Field(default=2, gt=0, le=32)
    hypothesis_feed: Literal["current", "facts_survey"] = "current"
    cursor_allow_on_demand: bool = False
    fallback_provider: Literal["none", "openai", "codex"] = "none"
    fallback_model: str | None = None


class SetupResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["READY", "BLOCKED"]
    config_path: Path
    profile_path: Path
    missing_tools: tuple[str, ...]
    next_actions: tuple[str, ...]


class ToolDiscovery(Protocol):
    def inspect(self) -> tuple[ToolInspection, ...]: ...


class SystemToolDiscovery:
    def inspect(self) -> tuple[ToolInspection, ...]:
        return tuple(self._inspect(name, command) for name, command in _TOOL_COMMANDS)

    @staticmethod
    def _inspect(name: str, command: tuple[str, ...]) -> ToolInspection:
        if name == "cursor_agent":
            return SystemToolDiscovery._inspect_cursor_agent()
        executable_names = (
            (command[0], "opengrep_windows_x86.exe")
            if name == "opengrep"
            else (command[0],)
        )
        found = next(
            (
                candidate
                for executable_name in executable_names
                if (candidate := shutil.which(executable_name))
            ),
            None,
        )
        executable = (
            Path(command[0]) if name == "python" else Path(found) if found else None
        )
        if executable is None or not executable.is_file():
            return ToolInspection(name=name, available=False)
        executable = SystemToolDiscovery._native_codex_executable(name, executable)
        if name == "claude":
            native = (
                executable.parent
                / "node_modules"
                / "@anthropic-ai"
                / "claude-code"
                / "bin"
                / "claude.exe"
            )
            if native.is_file():
                executable = native
        try:
            completed = subprocess.run(
                (str(executable), *command[1:]),
                check=False,
                capture_output=True,
                text=True,
                # OpenGrep and CodeQL may need a few seconds for a cold first
                # start even when the executable is healthy.  Setup is a
                # one-time operation, so prefer an accurate capability check
                # over reporting a slow tool as missing.
                timeout=20,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ToolInspection(name=name, available=False)
        output = (completed.stdout or completed.stderr).splitlines()
        version = output[0].strip()[:160] if output else ""
        if name == "codex":
            prefix = "codex-cli "
            if not version.startswith(prefix):
                return ToolInspection(name=name, available=False)
            version = version.removeprefix(prefix)
        if name == "claude":
            suffix = " (Claude Code)"
            if not version.endswith(suffix):
                return ToolInspection(name=name, available=False)
            version = version.removesuffix(suffix)
        if (
            completed.returncode != 0
            or not version
            or any(ord(character) < 32 for character in version)
        ):
            return ToolInspection(name=name, available=False)
        if name == "codeql" and not SystemToolDiscovery._has_codeql_query_pack(
            executable
        ):
            return ToolInspection(name=name, available=False)
        digest = hashlib.sha256()
        try:
            with executable.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            return ToolInspection(name=name, available=False)
        return ToolInspection(
            name=name,
            available=True,
            executable=executable.resolve(),
            version=version,
            executable_sha256=digest.hexdigest(),
        )

    @staticmethod
    def _inspect_cursor_agent() -> ToolInspection:
        launcher = shutil.which("agent") or shutil.which("cursor-agent")
        if launcher is None and os.name == "nt":
            candidate = (
                Path(os.environ.get("LOCALAPPDATA", "")) / "cursor-agent" / "agent.cmd"
            )
            launcher = str(candidate) if candidate.is_file() else None
        if launcher is None:
            return ToolInspection(name="cursor_agent", available=False)
        try:
            completed = subprocess.run(
                (launcher, "--version"),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ToolInspection(name="cursor_agent", available=False)
        version = (
            completed.stdout.strip().splitlines()[0] if completed.stdout.strip() else ""
        )
        if completed.returncode != 0 or not version or len(version) > 160:
            return ToolInspection(name="cursor_agent", available=False)
        versions = Path(launcher).parent / "versions"
        native = versions / version / "node.exe"
        script = native.with_name("index.js")
        if not native.is_file() or not script.is_file():
            return ToolInspection(name="cursor_agent", available=False)
        digest_builder = hashlib.sha256()
        try:
            with native.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest_builder.update(chunk)
        except OSError:
            return ToolInspection(name="cursor_agent", available=False)
        digest = digest_builder.hexdigest()
        return ToolInspection(
            name="cursor_agent",
            available=True,
            executable=native.resolve(),
            version=version,
            executable_sha256=digest,
        )

    @staticmethod
    def _native_codex_executable(name: str, executable: Path) -> Path:
        """Prefer the official native Codex binary over its Node launcher.

        The npm launcher uses ``#!/usr/bin/env node``. Provider children run
        without an ambient PATH so credentials and unapproved executables do
        not leak into the boundary. Official Codex packages also ship the
        native binary; pinning that file keeps the boundary strict and makes
        subscription login portable on Linux/WSL.
        """

        if name != "codex":
            return executable
        try:
            resolved = executable.resolve(strict=True)
        except OSError:
            return executable
        if resolved.name == "codex.js":
            package_root = resolved.parent.parent
        elif resolved.name.lower() in {"codex.cmd", "codex.ps1"}:
            package_root = resolved.parent / "node_modules" / "@openai" / "codex"
        else:
            return executable
        candidates = sorted(
            candidate
            for candidate in package_root.glob(
                "node_modules/@openai/codex-*/vendor/*/bin/codex*"
            )
            if candidate.is_file() and candidate.name in {"codex", "codex.exe"}
        )
        return candidates[0] if len(candidates) == 1 else executable

    @staticmethod
    def _has_codeql_query_pack(executable: Path) -> bool:
        try:
            completed = subprocess.run(
                (str(executable), "resolve", "packs", "--format=json"),
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
                shell=False,
            )
            if completed.returncode != 0:
                return False
            resolved = json.loads(completed.stdout)
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            return False

        def contains_query_pack(value: object) -> bool:
            if isinstance(value, dict):
                if any(
                    isinstance(key, str)
                    and key.startswith("codeql/")
                    and key.endswith("-queries")
                    and isinstance(item, dict)
                    and item.get("kind") == "query"
                    for key, item in value.items()
                ):
                    return True
                return any(contains_query_pack(item) for item in value.values())
            if isinstance(value, list):
                return any(contains_query_pack(item) for item in value)
            return False

        return contains_query_pack(resolved)


AuthChecker = Callable[[SetupChoices, dict[str, ToolInspection]], bool]


def _default_auth_checker(
    choices: SetupChoices, tools: dict[str, ToolInspection]
) -> bool:
    if choices.auth_mode == "API_KEY":
        variable = choices.credential_ref.removeprefix("env:")
        return bool(variable and os.environ.get(variable))
    if choices.provider == "claude":
        claude = tools.get("claude")
        if claude is None or not claude.available or claude.executable is None:
            return False
        try:
            completed = subprocess.run(
                (str(claude.executable), "auth", "status", "--json"),
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
                shell=False,
            )
            if completed.returncode != 0 or len(completed.stdout) > 65_536:
                return False
            payload = json.loads(completed.stdout)
        except (OSError, subprocess.SubprocessError, ValueError):
            return False
        return (
            isinstance(payload, dict)
            and payload.get("loggedIn") is True
            and payload.get("authMethod") == "claude.ai"
            and payload.get("apiProvider") == "firstParty"
            and "apiKeySource" not in payload
            and isinstance(payload.get("subscriptionType"), str)
            and bool(payload["subscriptionType"].strip())
        )
    if choices.provider == "cursor":
        cursor = tools.get("cursor_agent")
        if cursor is None or not cursor.available or cursor.executable is None:
            return False
        try:
            completed = subprocess.run(
                (
                    str(cursor.executable),
                    str(cursor.executable.with_name("index.js")),
                    "status",
                ),
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        status = (completed.stdout + completed.stderr).lower()
        return (
            completed.returncode == 0
            and ("logged in" in status or "authenticated" in status)
            and "not logged in" not in status
            and "not authenticated" not in status
        )
    codex = tools.get("codex")
    if codex is None or not codex.available or codex.executable is None:
        return False
    try:
        completed = subprocess.run(
            (str(codex.executable), "login", "status"),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


class SetupService:
    def __init__(
        self,
        *,
        config_store: UserConfigStore | None = None,
        discovery: ToolDiscovery | None = None,
        profile_path: Path | None = None,
        auth_checker: AuthChecker | None = None,
    ) -> None:
        self.config_store = config_store or UserConfigStore()
        self._discovery = discovery or SystemToolDiscovery()
        self._profile_path = profile_path or self.config_store.path.with_name(
            "profile.toml"
        )
        self._auth_checker = auth_checker or _default_auth_checker

    def inspect(self) -> SetupInspection:
        return SetupInspection(tools=self._discovery.inspect())

    def configure(self, choices: SetupChoices) -> SetupResult:
        if choices.provider == "claude" and not (
            choices.auth_mode == "SUBSCRIPTION_LOGIN"
            and choices.credential_ref == "CLAUDE_CLI_LOGIN"
        ):
            raise ValueError("CLAUDE_SUBSCRIPTION_REQUIRED")
        if choices.provider == "cursor" and not (
            choices.auth_mode == "API_KEY"
            and choices.credential_ref == "env:CURSOR_API_KEY"
            or choices.auth_mode == "SUBSCRIPTION_LOGIN"
            and choices.credential_ref == "CURSOR_CLI_LOGIN"
        ):
            raise ValueError("CURSOR_API_KEY_REQUIRED")
        inspection = self.inspect()
        tools = {item.name: item for item in inspection.tools}
        required = {"git", "python", "opengrep", "docker"}
        if choices.execution_profile == "FULL":
            required.add("codeql")
        if choices.auth_mode == "SUBSCRIPTION_LOGIN" and choices.provider not in {
            "cursor",
            "claude",
        }:
            required.add("codex")
        if choices.provider == "claude":
            required.add("claude")
        if choices.provider == "cursor" and choices.auth_mode == "SUBSCRIPTION_LOGIN":
            required.add("cursor_agent")
        if choices.fallback_provider == "codex":
            required.add("codex")
        missing = tuple(
            sorted(
                name
                for name in required
                if name not in tools or not tools[name].available
            )
        )
        auth_ready = self._auth_checker(choices, tools)
        cursor_usage_acknowledged = (
            choices.provider != "cursor" or choices.cursor_allow_on_demand
        )
        claude_version_ready = (
            choices.provider != "claude"
            or tools.get("claude") is not None
            and tools["claude"].version == "2.1.280"
        )
        ready = (
            not missing
            and auth_ready
            and cursor_usage_acknowledged
            and claude_version_ready
        )
        enabled_tools: tuple[Literal["AST", "OPENGREP", "CODEQL", "DOCKER"], ...] = (
            ("AST", "OPENGREP", "CODEQL", "DOCKER")
            if choices.execution_profile == "FULL"
            else ("AST", "OPENGREP", "DOCKER")
        )
        detected_versions = {
            name: item.version
            for name, item in tools.items()
            if item.available and item.version is not None
        }
        config = UserConfig(
            data_dir=choices.data_dir,
            profile_path=self._profile_path,
            auth_mode=choices.auth_mode,
            provider=choices.provider,
            model=choices.model,
            credential_ref=choices.credential_ref,
            execution_profile=choices.execution_profile,
            max_cost_minor_units=choices.max_cost_minor_units,
            max_tokens=choices.max_tokens,
            max_elapsed_seconds=choices.max_elapsed_seconds,
            docker_network=choices.docker_network,
            enabled_tools=enabled_tools,
            detected_versions=detected_versions,
            setup_ready=ready,
            agent_models=choices.agent_models,
            llm_timeout_seconds=choices.llm_timeout_seconds,
            llm_max_retries=choices.llm_max_retries,
            llm_max_concurrency=choices.llm_max_concurrency,
            hypothesis_feed=choices.hypothesis_feed,
            cursor_allow_on_demand=choices.cursor_allow_on_demand,
            fallback_provider=choices.fallback_provider,
            fallback_model=choices.fallback_model,
        )
        bindings = {
            name: SimpleToolBinding(
                executable_path=item.executable,
                version=item.version,
                executable_sha256=item.executable_sha256,
            )
            for name, item in tools.items()
            if item.available
            and item.executable is not None
            and item.version is not None
            and item.executable_sha256 is not None
            and name in required
        }
        profile = SimpleExecutionProfile(
            provider_profile_ref=f"local-{choices.provider}",
            provider=choices.provider,
            model=choices.model,
            auth_mode=choices.auth_mode,
            credential_ref=choices.credential_ref,
            data_dir=choices.data_dir,
            workspace_root=choices.data_dir / "workspaces",
            max_cost_minor_units=choices.max_cost_minor_units,
            max_tokens=choices.max_tokens,
            max_elapsed_seconds=choices.max_elapsed_seconds,
            docker_network=choices.docker_network,
            tools=bindings,
            agent_models=choices.agent_models,
            llm_timeout_seconds=choices.llm_timeout_seconds,
            llm_max_retries=choices.llm_max_retries,
            llm_max_concurrency=choices.llm_max_concurrency,
            hypothesis_feed=choices.hypothesis_feed,
            cursor_allow_on_demand=choices.cursor_allow_on_demand,
            fallback_provider=choices.fallback_provider,
            fallback_model=choices.fallback_model,
        )
        profile.write(self._profile_path)
        config_path = self.config_store.save(config)
        next_actions = tuple(
            [*(f"Install or configure {name}." for name in missing)]
            + (
                []
                if auth_ready
                else [
                    "CLAUDE_AUTH_REQUIRED: run claude auth login with your own "
                    "claude.ai subscription account."
                    if choices.provider == "claude"
                    else "Complete the selected Provider authentication."
                ]
            )
            + (
                []
                if claude_version_ready
                else [
                    "CLAUDE_CLI_UNSUPPORTED_VERSION: install Claude Code CLI 2.1.280."
                ]
            )
            + (
                []
                if cursor_usage_acknowledged
                else [
                    "Cursor SDK cannot disable on-demand usage per request; "
                    "review Team billing and set --cursor-allow-on-demand."
                ]
            )
        )
        return SetupResult(
            status="READY" if ready else "BLOCKED",
            config_path=config_path,
            profile_path=self._profile_path,
            missing_tools=missing,
            next_actions=next_actions,
        )


__all__ = [
    "SetupChoices",
    "SetupInspection",
    "SetupResult",
    "SetupService",
    "SystemToolDiscovery",
    "ToolInspection",
]
