"""Public one-time setup command."""

from __future__ import annotations

import os
from argparse import Namespace
from collections.abc import Callable
from pathlib import Path
from typing import Literal, cast

from platformdirs import user_data_dir

from sastsimi.setup.service import SetupChoices, SetupResult, SetupService


def choices_from_args(
    args: Namespace, *, input_fn: Callable[[str], str] = input
) -> SetupChoices:
    non_interactive = bool(args.non_interactive)

    def value(current: str | None, prompt: str, default: str) -> str:
        if current:
            return current
        if non_interactive:
            return default
        entered = input_fn(f"{prompt} [{default}]: ").strip()
        return entered or default

    requested_provider = args.provider or os.environ.get("SASTSIMI_LLM_PROVIDER")
    auth = value(
        args.auth,
        "인증 방식(api-key/subscription)",
        "subscription",
    )
    provider = value(
        requested_provider,
        "Provider",
        "codex" if auth == "subscription" else "openai",
    )
    credential_ref = (
        "CLAUDE_CLI_LOGIN"
        if provider == "claude" and auth == "subscription"
        else "CURSOR_CLI_LOGIN"
        if provider == "cursor" and auth == "subscription"
        else "env:CURSOR_API_KEY"
        if provider == "cursor" and auth == "api-key"
        else "OFFICIAL_CLIENT_SESSION"
        if auth == "subscription"
        else "env:OPENAI_API_KEY"
    )
    raw_agent_models = getattr(args, "agent_model", None) or []
    agent_models: dict[str, str] = {}
    for item in raw_agent_models:
        name, separator, model_name = item.partition("=")
        if not separator or not name or not model_name:
            raise ValueError("AGENT_MODEL_FORMAT_INVALID")
        agent_models[name] = model_name
    model = args.model or (
        os.environ.get("SASTSIMI_CURSOR_MODEL") if provider == "cursor" else None
    )
    if provider in {"cursor", "claude"} and not model and non_interactive:
        raise ValueError(f"{provider.upper()}_MODEL_REQUIRED: use --model")
    execution_profile_value = (args.execution_profile or "full").upper()
    if execution_profile_value not in {"FULL", "LIGHTWEIGHT"}:
        raise ValueError("SETUP_EXECUTION_PROFILE_INVALID")
    execution_profile = cast(Literal["FULL", "LIGHTWEIGHT"], execution_profile_value)
    docker_network_value = (args.docker_network or "none").upper()
    if docker_network_value not in {"NONE", "BRIDGE"}:
        raise ValueError("SETUP_DOCKER_NETWORK_INVALID")
    docker_network = cast(Literal["NONE", "BRIDGE"], docker_network_value)
    return SetupChoices(
        data_dir=Path(args.setup_data_dir or user_data_dir("sastsimi")).absolute(),
        auth_mode="SUBSCRIPTION_LOGIN" if auth == "subscription" else "API_KEY",
        provider=provider,
        model=value(
            model, "모델", "" if provider in {"cursor", "claude"} else "gpt-5.6-sol"
        ),
        credential_ref=credential_ref,
        execution_profile=execution_profile,
        max_cost_minor_units=args.max_cost_minor_units,
        max_tokens=args.max_tokens,
        max_elapsed_seconds=args.max_elapsed_seconds,
        docker_network=docker_network,
        agent_models=agent_models,
        llm_timeout_seconds=getattr(args, "llm_timeout_seconds", 180),
        llm_max_retries=getattr(args, "llm_max_retries", 2),
        llm_max_concurrency=getattr(args, "llm_max_concurrency", 2),
        hypothesis_feed=getattr(args, "hypothesis_feed", "current"),
        max_parallel_hypotheses=getattr(args, "max_parallel_hypotheses", 1),
        max_parallel_builds=getattr(args, "max_parallel_builds", 1),
        max_parallel_containers=getattr(args, "max_parallel_containers", 1),
        cursor_allow_on_demand=bool(getattr(args, "cursor_allow_on_demand", False)),
        fallback_provider=getattr(args, "fallback_provider", "none"),
        fallback_model=getattr(args, "fallback_model", None),
    )


def run(
    service: SetupService,
    args: Namespace,
    *,
    input_fn: Callable[[str], str] = input,
) -> SetupResult:
    return service.configure(choices_from_args(args, input_fn=input_fn))


__all__ = ["choices_from_args", "run"]
