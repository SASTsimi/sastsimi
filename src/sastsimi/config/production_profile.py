"""Strict, credential-free production analysis configuration."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Literal, Self
from urllib.parse import parse_qsl, urlsplit

from pydantic import ValidationError, field_validator, model_validator

from sastsimi.config.secrets import SecretReference
from sastsimi.contracts.base import (
    ContractModel,
    NonEmptyStr,
    NonNegativeInt,
    PositiveInt,
)
from sastsimi.contracts.llm import Environment, LLMRole, Product

_SECRET_QUERY_KEYS = frozenset(
    {"api_key", "apikey", "access_token", "token", "secret", "password"}
)


class ProductionProfileError(ValueError):
    """Safe configuration error that never includes submitted values or paths."""


class WorkerSettings(ContractModel):
    max_workers: PositiveInt
    lease_ms: PositiveInt
    heartbeat_ms: PositiveInt
    poll_ms: PositiveInt

    @model_validator(mode="after")
    def heartbeat_precedes_lease(self) -> Self:
        if self.heartbeat_ms >= self.lease_ms:
            raise ValueError("WORKER_HEARTBEAT_MUST_PRECEDE_LEASE")
        return self


class TimeoutSettings(ContractModel):
    workspace_ms: PositiveInt
    static_tool_ms: PositiveInt
    llm_ms: PositiveInt
    sandbox_ms: PositiveInt
    shutdown_ms: PositiveInt


class WorkspaceLimitSettings(ContractModel):
    """Operator-owned bounds for one checked-out repository workspace."""

    max_git_bytes: PositiveInt
    max_checkout_bytes: PositiveInt
    max_file_count: PositiveInt
    min_free_bytes: PositiveInt


class ProductionBudgetSettings(ContractModel):
    """Explicit limits used to create one run's immutable budget profiles."""

    profile_key: NonEmptyStr
    approval_key: NonEmptyStr
    approved_by: NonEmptyStr
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
            raise ValueError("PRODUCTION_BUDGET_LIMIT_HIERARCHY_INVALID")
        return self


class ToolExecutables(ContractModel):
    git: NonEmptyStr
    python: NonEmptyStr
    codeql: NonEmptyStr
    opengrep: NonEmptyStr
    docker: NonEmptyStr

    @field_validator("*")
    @classmethod
    def safe_command_name(cls, value: str) -> str:
        if (
            value != value.strip()
            or value.startswith("-")
            or re.search(r"[\x00\r\n]", value)
        ):
            raise ValueError("TOOL_EXECUTABLE_INVALID")
        return value


class PolicySource(ContractModel):
    program_namespace: NonEmptyStr
    external_program_id: NonEmptyStr
    source_version: NonEmptyStr
    official_endpoint: NonEmptyStr
    publisher: NonEmptyStr
    parser_name: NonEmptyStr
    parser_version: NonEmptyStr
    freshness_ttl_seconds: PositiveInt
    timeout_seconds: PositiveInt
    max_response_bytes: PositiveInt
    allowed_content_types: tuple[NonEmptyStr, ...]
    allowed_redirect_hosts: tuple[NonEmptyStr, ...] = ()

    @field_validator("allowed_content_types", "allowed_redirect_hosts", mode="before")
    @classmethod
    def toml_arrays_to_tuples(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def official_https_source(self) -> Self:
        endpoint = urlsplit(self.official_endpoint)
        hostname = endpoint.hostname.casefold() if endpoint.hostname else None
        if (
            endpoint.scheme != "https"
            or hostname is None
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.port not in {None, 443}
            or endpoint.fragment
            or any(
                name.casefold() in _SECRET_QUERY_KEYS
                for name, _value in parse_qsl(endpoint.query, keep_blank_values=True)
            )
            or not self.allowed_content_types
            or any(
                host != host.strip() or ":" in host or "/" in host
                for host in self.allowed_redirect_hosts
            )
        ):
            raise ValueError("POLICY_SOURCE_INVALID")
        return self


class ProviderConnection(ContractModel):
    provider_profile_key: NonEmptyStr
    product: Product
    environment: Environment
    client_name: NonEmptyStr
    client_version: NonEmptyStr
    credential_ref: SecretReference


class LLMRoute(ContractModel):
    role: LLMRole
    task_kind: NonEmptyStr
    provider_profile_key: NonEmptyStr
    model: NonEmptyStr
    prompt_key: NonEmptyStr


class ProductionProfile(ContractModel):
    """One explicit production profile; no Provider or model fallback is implied."""

    schema_version: Literal[1]
    program_id: NonEmptyStr
    host_id: NonEmptyStr
    workspace_root: Path
    taxonomy_version: NonEmptyStr
    worker: WorkerSettings
    timeouts: TimeoutSettings
    workspace_limits: WorkspaceLimitSettings
    budget: ProductionBudgetSettings
    tools: ToolExecutables
    policy: PolicySource
    providers: tuple[ProviderConnection, ...]
    llm_routes: tuple[LLMRoute, ...]

    @field_validator("providers", "llm_routes", mode="before")
    @classmethod
    def toml_tables_to_tuples(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("workspace_root", mode="before")
    @classmethod
    def absolute_workspace_root(cls, value: object) -> Path:
        if not isinstance(value, (str, Path)):
            raise ValueError("WORKSPACE_ROOT_INVALID")
        path = Path(value)
        if not str(path).strip() or "\x00" in str(path) or not path.is_absolute():
            raise ValueError("WORKSPACE_ROOT_INVALID")
        return path

    @model_validator(mode="after")
    def exact_routes(self) -> Self:
        provider_keys = tuple(item.provider_profile_key for item in self.providers)
        route_keys = tuple((item.role, item.task_kind) for item in self.llm_routes)
        if (
            not provider_keys
            or len(provider_keys) != len(set(provider_keys))
            or not route_keys
            or len(route_keys) != len(set(route_keys))
            or any(
                route.provider_profile_key not in provider_keys
                for route in self.llm_routes
            )
        ):
            raise ValueError("PRODUCTION_LLM_ROUTE_INVALID")
        return self


def load_production_profile(path: Path) -> ProductionProfile:
    """Load one explicitly selected TOML file without environment discovery."""

    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
        return ProductionProfile.model_validate(raw)
    except (OSError, ValueError, ValidationError):
        raise ProductionProfileError("Invalid production profile") from None


__all__ = [
    "LLMRoute",
    "PolicySource",
    "ProductionBudgetSettings",
    "ProductionProfile",
    "ProductionProfileError",
    "ProviderConnection",
    "TimeoutSettings",
    "ToolExecutables",
    "WorkerSettings",
    "WorkspaceLimitSettings",
    "load_production_profile",
]
