"""Bounded, typed recovery decisions for the sequential SimpleRuntime."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Protocol

from pydantic import ValidationError

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .models import StageCheckpoint, StageFailure
from .provider import SimpleLLMClient

MAX_RECOVERY_ATTEMPTS = 3
_MAX_ENVIRONMENT_PATCH_BYTES = 8 * 1024
_RECOVERY_TIMEOUT_MS = 120_000


class RecoveryCategory(StrEnum):
    TRANSIENT_TOOL = "TRANSIENT_TOOL"
    GENERATED_INPUT = "GENERATED_INPUT"
    ENVIRONMENT = "ENVIRONMENT"
    TERMINAL = "TERMINAL"


class RecoveryAction(StrEnum):
    RETRY_STAGE = "RETRY_STAGE"
    REBUILD_ENVIRONMENT = "REBUILD_ENVIRONMENT"
    REGENERATE_INPUT = "REGENERATE_INPUT"
    STOP = "STOP"


class RecoveryDecision(ContractModel):
    category: RecoveryCategory
    action: RecoveryAction
    diagnosis: str
    guidance: str
    environment_patch: str = ""


class RecoveryResolution(ContractModel):
    decision: RecoveryDecision
    decision_ref: StoredDataRef


class RecoveryCoordinator(Protocol):
    async def decide(
        self,
        checkpoint: StageCheckpoint,
        failure: StageFailure,
    ) -> RecoveryResolution: ...


TERMINAL_ERROR_CODES = frozenset(
    {
        "AUTH_REQUIRED",
        "AUTH_INVALID",
        "POLICY_DENIED",
        "CAPABILITY_DENIED",
        "RECOVERY_EXHAUSTED",
        "SIMPLE_RUNTIME_REFERENCE_SCOPE_MISMATCH",
    }
)

ALLOWED_ACTIONS = {
    RecoveryCategory.TRANSIENT_TOOL: frozenset(
        {RecoveryAction.RETRY_STAGE, RecoveryAction.STOP}
    ),
    RecoveryCategory.GENERATED_INPUT: frozenset(
        {RecoveryAction.REGENERATE_INPUT, RecoveryAction.STOP}
    ),
    RecoveryCategory.ENVIRONMENT: frozenset(
        {RecoveryAction.REBUILD_ENVIRONMENT, RecoveryAction.STOP}
    ),
    RecoveryCategory.TERMINAL: frozenset({RecoveryAction.STOP}),
}

_ALLOWED_PACKAGE_COMMAND_PREFIXES = (
    "python -m pip install ",
    "python3 -m pip install ",
    "pip install ",
    "pip3 install ",
    "apt-get update",
    "apt-get install ",
    "apk add ",
    "dnf install ",
    "yum install ",
    "npm ci",
    "npm install ",
    "pnpm install",
    "yarn install",
    "uv sync",
    "poetry install",
    "bundle install",
    "composer install",
    "cargo fetch",
    "go mod download",
)
_FORBIDDEN_PATCH_FRAGMENT = re.compile(
    r"(?i)(?:https?://|[a-z]:[\\/]|\\\\|/var/run/docker\.sock|"
    r"/run/docker\.sock|--mount|\$\(|`|&&|\|\||[;|<>])"
)

_DECISION_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "category": {
            "type": "string",
            "enum": [item.value for item in RecoveryCategory],
        },
        "action": {
            "type": "string",
            "enum": [item.value for item in RecoveryAction],
        },
        "diagnosis": {"type": "string"},
        "guidance": {"type": "string"},
        "environment_patch": {"type": "string"},
    },
    "required": [
        "category",
        "action",
        "diagnosis",
        "guidance",
        "environment_patch",
    ],
}


def validate_environment_patch(patch: str) -> str:
    """Accept only bounded dependency-installer RUN directives."""

    normalized = "\n".join(line.strip() for line in patch.strip().splitlines())
    if not normalized or len(normalized.encode("utf-8")) > _MAX_ENVIRONMENT_PATCH_BYTES:
        raise ValueError("RECOVERY_ENVIRONMENT_PATCH_FORBIDDEN")
    for line in normalized.splitlines():
        if not line.startswith("RUN ") or _FORBIDDEN_PATCH_FRAGMENT.search(line):
            raise ValueError("RECOVERY_ENVIRONMENT_PATCH_FORBIDDEN")
        command = line[4:].strip().lower()
        if not any(
            _allowed_package_command(command, item)
            for item in _ALLOWED_PACKAGE_COMMAND_PREFIXES
        ):
            raise ValueError("RECOVERY_ENVIRONMENT_PATCH_FORBIDDEN")
    return normalized


def _allowed_package_command(command: str, allowed: str) -> bool:
    base = allowed.rstrip()
    if command == base:
        return True
    return command.startswith(allowed if allowed.endswith(" ") else base + " ")


class SimpleRecoveryCoordinator:
    def __init__(
        self,
        *,
        client: SimpleLLMClient,
        artifacts: SimpleArtifactRepository,
    ) -> None:
        self._client = client
        self._artifacts = artifacts

    async def decide(
        self,
        checkpoint: StageCheckpoint,
        failure: StageFailure,
    ) -> RecoveryResolution:
        if checkpoint.identity != self._artifacts.identity:
            raise ValueError("RECOVERY_IDENTITY_SCOPE_MISMATCH")
        if not failure.retryable or failure.code in TERMINAL_ERROR_CODES:
            return self._store(
                checkpoint,
                failure,
                self._stop(
                    "failure is not eligible for automatic recovery",
                    "manual review is required",
                ),
            )

        refs = tuple(dict.fromkeys(checkpoint.input_refs + failure.evidence_refs))
        context = self._artifacts.prompt_context(refs)
        prompt = b"\n".join(
            (
                b"Classify one failed SimpleRuntime stage and choose one "
                b"bounded action.",
                b"Never treat an execution error as a vulnerability FALSE verdict.",
                b"Do not request host changes, source edits, credentials, "
                b"or policy changes.",
                canonical_bytes(
                    {
                        "stage": checkpoint.stage.value,
                        "attempt": checkpoint.attempt_number,
                        "error_code": failure.code,
                        "retryable": failure.retryable,
                        "safe_message": failure.safe_message,
                    }
                ),
                context,
            )
        )
        try:
            response = await self._client.call(
                prompt=prompt,
                output_schema=_DECISION_SCHEMA,
                timeout_ms=_RECOVERY_TIMEOUT_MS,
            )
        except Exception:
            response = StageFailure(
                code="RECOVERY_PROVIDER_FAILED",
                retryable=False,
                safe_message="Recovery provider did not return a decision",
            )
        if isinstance(response, StageFailure):
            decision = self._stop(
                "recovery provider did not return a decision",
                "preserve the failure for manual review",
            )
        else:
            try:
                decision = RecoveryDecision.model_validate_json(
                    canonical_bytes(response.value)
                )
                decision = self._validate_decision(decision)
            except (ValidationError, ValueError):
                decision = self._stop(
                    "recovery output failed policy validation",
                    "preserve the failure for manual review",
                )
        return self._store(checkpoint, failure, decision)

    @staticmethod
    def _validate_decision(decision: RecoveryDecision) -> RecoveryDecision:
        if decision.action not in ALLOWED_ACTIONS[decision.category]:
            raise ValueError("RECOVERY_ACTION_CATEGORY_MISMATCH")
        if decision.action is RecoveryAction.REBUILD_ENVIRONMENT:
            return decision.model_copy(
                update={
                    "environment_patch": validate_environment_patch(
                        decision.environment_patch
                    )
                }
            )
        if decision.environment_patch.strip():
            raise ValueError("RECOVERY_ENVIRONMENT_PATCH_UNEXPECTED")
        return decision

    @staticmethod
    def _stop(diagnosis: str, guidance: str) -> RecoveryDecision:
        return RecoveryDecision(
            category=RecoveryCategory.TERMINAL,
            action=RecoveryAction.STOP,
            diagnosis=diagnosis,
            guidance=guidance,
            environment_patch="",
        )

    def _store(
        self,
        checkpoint: StageCheckpoint,
        failure: StageFailure,
        decision: RecoveryDecision,
    ) -> RecoveryResolution:
        decision_ref = self._artifacts.put_json(
            {
                "kind": "simple_recovery_decision",
                "identity": checkpoint.identity.model_dump(mode="json"),
                "stage": checkpoint.stage.value,
                "attempt": checkpoint.attempt_number,
                "attempt_id": checkpoint.attempt_id,
                "original_error": failure.model_dump(mode="json"),
                "decision": decision.model_dump(mode="json"),
            }
        )
        return RecoveryResolution(decision=decision, decision_ref=decision_ref)


__all__ = [
    "ALLOWED_ACTIONS",
    "MAX_RECOVERY_ATTEMPTS",
    "TERMINAL_ERROR_CODES",
    "RecoveryAction",
    "RecoveryCategory",
    "RecoveryCoordinator",
    "RecoveryDecision",
    "RecoveryResolution",
    "SimpleRecoveryCoordinator",
    "validate_environment_patch",
]
