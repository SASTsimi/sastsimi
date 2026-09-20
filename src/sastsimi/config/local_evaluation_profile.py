"""Secret-free configuration for explicitly non-production local evaluation."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal, Self

from pydantic import ValidationError, field_validator, model_validator

from sastsimi.config.codeql_container import CodeQLContainerRuntimeConfig
from sastsimi.config.production_profile import (
    TimeoutSettings,
    WorkerSettings,
    WorkspaceLimitSettings,
)
from sastsimi.contracts.base import (
    ContractModel,
    NonEmptyStr,
    NonNegativeInt,
    PositiveInt,
    Sha256,
)


class LocalEvaluationProfileError(ValueError):
    """Safe configuration error that never echoes submitted values or paths."""


def _absolute_non_root_path(value: object) -> Path:
    if not isinstance(value, (str, Path)):
        raise ValueError("LOCAL_EVALUATION_PATH_INVALID")
    text = str(value)
    path = Path(value)
    if (
        not text
        or text != text.strip()
        or any(ord(character) < 32 for character in text)
        or ".." in path.parts
        or not path.is_absolute()
        or path.parent == path
    ):
        raise ValueError("LOCAL_EVALUATION_PATH_INVALID")
    return path


class LocalCapabilitySelection(ContractModel):
    """Exact registry keys selected for repository preparation and static facts."""

    git_profile_key: NonEmptyStr
    python_runtime_profile_key: NonEmptyStr
    python_ast_profile_key: NonEmptyStr
    opengrep_profile_key: NonEmptyStr
    codeql_profile_key: NonEmptyStr

    @model_validator(mode="after")
    def unique_profile_keys(self) -> Self:
        keys = (
            self.git_profile_key,
            self.python_runtime_profile_key,
            self.python_ast_profile_key,
            self.opengrep_profile_key,
            self.codeql_profile_key,
        )
        if len(keys) != len(set(keys)):
            raise ValueError("LOCAL_EVALUATION_CAPABILITY_KEY_REUSED")
        return self

    @property
    def static_profile_keys(self) -> tuple[str, str, str]:
        return (
            self.python_ast_profile_key,
            self.opengrep_profile_key,
            self.codeql_profile_key,
        )


class LocalCodexSubscriptionSettings(ContractModel):
    """Hash-pinned official Codex client binding with no credential payload."""

    provider_profile_key: NonEmptyStr
    product: Literal["CODEX"] = "CODEX"
    transport: Literal["CODEX_CLIENT"] = "CODEX_CLIENT"
    auth_mode: Literal["SUBSCRIPTION_LOGIN"] = "SUBSCRIPTION_LOGIN"
    credential_source: Literal["OFFICIAL_CLIENT_SESSION"] = "OFFICIAL_CLIENT_SESSION"
    executable_path: Path
    executable_sha256: Sha256
    codex_home: Path
    client_version: NonEmptyStr
    model: NonEmptyStr

    @field_validator("executable_path", "codex_home", mode="before")
    @classmethod
    def absolute_binding_paths(cls, value: object) -> Path:
        return _absolute_non_root_path(value)

    @model_validator(mode="after")
    def immutable_client_outside_credential_home(self) -> Self:
        executable = self.executable_path.resolve(strict=False)
        home = self.codex_home.resolve(strict=False)
        if executable == home or home in executable.parents:
            raise ValueError("LOCAL_EVALUATION_CODEX_PATHS_OVERLAP")
        return self


class LocalEvaluationBudgetSettings(ContractModel):
    """Runtime limits for local evaluation, without any approval assertion."""

    profile_key: NonEmptyStr
    pricing_revision: NonEmptyStr
    currency: NonEmptyStr
    max_analysis_elapsed_ms: PositiveInt
    max_total_cost_minor_units: PositiveInt
    max_total_work: PositiveInt
    max_total_llm_calls: PositiveInt
    max_total_retries: NonNegativeInt
    max_parallel_work: PositiveInt
    work_timeout_ms: PositiveInt
    max_attempts_per_work: PositiveInt
    max_calls_per_work: PositiveInt
    max_items_per_work: PositiveInt
    max_verification_elapsed_ms: PositiveInt
    max_work_per_verification: PositiveInt
    max_llm_calls_per_verification: PositiveInt
    max_retries_per_work: NonNegativeInt
    max_parallel_evidence_calls: PositiveInt
    max_dynamic_attempts: PositiveInt

    @model_validator(mode="after")
    def limits_fit_parent_profiles(self) -> Self:
        if (
            self.max_parallel_work > self.max_total_work
            or self.max_work_per_verification > self.max_total_work
            or self.max_llm_calls_per_verification > self.max_total_llm_calls
            or self.max_parallel_evidence_calls > self.max_parallel_work
        ):
            raise ValueError("LOCAL_EVALUATION_BUDGET_LIMIT_HIERARCHY_INVALID")
        return self

    @property
    def approval_key(self) -> str:
        """Local declaration identity; it is not a Production approval."""

        return f"local-evaluation:{self.profile_key}"

    @property
    def approved_by(self) -> str:
        """Fixed local operator identity required by the shared budget contract."""

        return "LOCAL_EVALUATION_OPERATOR"


class LocalEvaluationProfile(ContractModel):
    """One explicit local run profile that cannot represent production approval."""

    schema_version: Literal[1]
    purpose: Literal["LOCAL_EVALUATION"] = "LOCAL_EVALUATION"
    production_ready: Literal[False] = False
    program_id: NonEmptyStr
    host_id: NonEmptyStr
    workspace_root: Path
    allow_local_repository: bool = False
    taxonomy_version: NonEmptyStr
    worker: WorkerSettings
    timeouts: TimeoutSettings
    workspace_limits: WorkspaceLimitSettings
    budget: LocalEvaluationBudgetSettings
    codeql_container: CodeQLContainerRuntimeConfig
    capabilities: LocalCapabilitySelection
    codex: LocalCodexSubscriptionSettings

    @field_validator("workspace_root", mode="before")
    @classmethod
    def absolute_workspace_root(cls, value: object) -> Path:
        return _absolute_non_root_path(value)

    @model_validator(mode="after")
    def isolate_code_and_credentials(self) -> Self:
        workspace = self.workspace_root.resolve(strict=False)
        home = self.codex.codex_home.resolve(strict=False)
        executable = self.codex.executable_path.resolve(strict=False)
        if (
            workspace == home
            or workspace in home.parents
            or home in workspace.parents
            or workspace == executable
            or workspace in executable.parents
        ):
            raise ValueError("LOCAL_EVALUATION_CREDENTIAL_PATH_OVERLAP")
        # A claimed Verification work keeps one running slot while it starts
        # the independently tracked Pro and Con children.  Preserve two spare
        # slots even when every foreground worker has claimed a parent, or the
        # configured limits can deadlock before either evidence branch starts.
        if self.budget.max_parallel_work < self.worker.max_workers + 2:
            raise ValueError("LOCAL_EVALUATION_PARALLEL_BUDGET_DEADLOCK")
        return self


def load_local_evaluation_profile(path: Path) -> LocalEvaluationProfile:
    """Load only the selected TOML file; no environment or profile fallback."""

    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
        return LocalEvaluationProfile.model_validate(raw)
    except (OSError, ValueError, ValidationError):
        raise LocalEvaluationProfileError("Invalid local evaluation profile") from None


__all__ = [
    "LocalCapabilitySelection",
    "LocalCodexSubscriptionSettings",
    "LocalEvaluationBudgetSettings",
    "LocalEvaluationProfile",
    "LocalEvaluationProfileError",
    "load_local_evaluation_profile",
]
