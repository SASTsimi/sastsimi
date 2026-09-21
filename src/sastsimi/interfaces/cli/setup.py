"""Public one-time setup command."""

from __future__ import annotations

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

    auth = value(args.auth, "인증 방식(api-key/subscription)", "subscription")
    provider = value(
        args.provider,
        "Provider",
        "codex" if auth == "subscription" else "openai",
    )
    credential_ref = (
        "OFFICIAL_CLIENT_SESSION" if auth == "subscription" else "env:OPENAI_API_KEY"
    )
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
        model=value(args.model, "모델", "gpt-5.6-sol"),
        credential_ref=credential_ref,
        execution_profile=execution_profile,
        max_cost_minor_units=args.max_cost_minor_units,
        max_tokens=args.max_tokens,
        max_elapsed_seconds=args.max_elapsed_seconds,
        docker_network=docker_network,
    )


def run(
    service: SetupService,
    args: Namespace,
    *,
    input_fn: Callable[[str], str] = input,
) -> SetupResult:
    return service.configure(choices_from_args(args, input_fn=input_fn))


__all__ = ["choices_from_args", "run"]
