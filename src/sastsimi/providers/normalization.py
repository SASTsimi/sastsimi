"""Safe provider error normalization; raw exception text never crosses the boundary."""

from dataclasses import dataclass

from sastsimi.contracts.llm import InvocationStatus

from .base import (
    CredentialUnavailableError,
    ProviderInputMismatchError,
    ProviderInvalidOutputError,
)


@dataclass(frozen=True)
class NormalizedFailure:
    status: InvocationStatus
    safe_error: str


_FAILURES: dict[InvocationStatus, str] = {
    "AUTH_REQUIRED": "AUTH_REQUIRED: OpenAI API authentication is required",
    "TIMED_OUT": "TIMED_OUT: OpenAI API request exceeded its deadline",
    "RATE_LIMITED": "RATE_LIMITED: OpenAI API rate limit was reached",
    "INVALID_OUTPUT": ("INVALID_OUTPUT: OpenAI API returned invalid structured output"),
    "CANCELLED": "CANCELLED: OpenAI API request was cancelled",
    "FAILED": "FAILED: OpenAI API request failed",
}

_CODEX_FAILURES: dict[InvocationStatus, str] = {
    "AUTH_REQUIRED": "AUTH_REQUIRED: Codex ChatGPT login is required",
    "TIMED_OUT": "TIMED_OUT: Codex subscription request exceeded its deadline",
    "RATE_LIMITED": "RATE_LIMITED: Codex subscription usage limit was reached",
    "INVALID_OUTPUT": "INVALID_OUTPUT: Codex returned invalid structured output",
    "CANCELLED": "CANCELLED: Codex subscription request was cancelled",
    "FAILED": "FAILED: Codex subscription request failed",
    "SUCCEEDED": "FAILED: Codex subscription result status was inconsistent",
}


def failure(status: InvocationStatus) -> NormalizedFailure:
    return NormalizedFailure(status, _FAILURES[status])


def codex_failure(status: InvocationStatus) -> NormalizedFailure:
    if status == "SUCCEEDED":
        return NormalizedFailure("FAILED", _CODEX_FAILURES[status])
    return NormalizedFailure(status, _CODEX_FAILURES[status])


def normalize_codex_exception(error: BaseException) -> NormalizedFailure:
    """Classify local Codex boundary failures without copying exception text."""
    if isinstance(error, ProviderInvalidOutputError):
        return codex_failure("INVALID_OUTPUT")
    if isinstance(error, ProviderInputMismatchError):
        return NormalizedFailure(
            "FAILED", "FAILED: authorized Codex request inputs did not match"
        )
    if isinstance(error, TimeoutError):
        return codex_failure("TIMED_OUT")
    return codex_failure("FAILED")


def normalize_exception(error: BaseException) -> NormalizedFailure:
    """Classify documented SDK errors without copying their possibly-secret message."""
    name = type(error).__name__
    status_code = getattr(error, "status_code", None)
    if isinstance(error, CredentialUnavailableError) or name == "AuthenticationError":
        return failure("AUTH_REQUIRED")
    if (
        isinstance(error, TimeoutError)
        or name == "APITimeoutError"
        or status_code == 408
    ):
        return failure("TIMED_OUT")
    if name == "RateLimitError" or status_code == 429:
        return failure("RATE_LIMITED")
    if isinstance(error, ProviderInvalidOutputError) or name in {
        "APIResponseValidationError",
        "ValidationError",
    }:
        return failure("INVALID_OUTPUT")
    if isinstance(error, ProviderInputMismatchError):
        return NormalizedFailure(
            "FAILED", "FAILED: authorized OpenAI request inputs did not match"
        )
    return failure("FAILED")


def normalize_response_failure(
    status: str, error_code: str | None
) -> NormalizedFailure:
    """Normalize non-completed Responses API objects without trusting error messages."""
    if status == "cancelled":
        return failure("CANCELLED")
    if error_code == "rate_limit_exceeded":
        return failure("RATE_LIMITED")
    return failure("FAILED")


__all__ = [
    "NormalizedFailure",
    "codex_failure",
    "failure",
    "normalize_codex_exception",
    "normalize_exception",
    "normalize_response_failure",
]
