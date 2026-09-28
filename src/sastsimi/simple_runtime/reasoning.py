"""Fail-closed reasoning-effort selection at provider boundaries."""

from .models import StageFailure

CODEX_EFFORTS = frozenset({"none", "minimal", "low", "medium", "high", "xhigh", "max"})
OPENAI_EFFORTS = frozenset({"none", "minimal", "low", "medium", "high", "xhigh", "max"})
CLAUDE_EFFORTS = frozenset({"low", "medium", "high"})


def validate_reasoning_effort(
    provider: str,
    model: str,
    effort: str | None,
    *,
    supported_levels: frozenset[str] | None,
) -> str | None | StageFailure:
    """Reject unsupported explicit effort; never silently use a different level.

    Model-specific API rejection remains terminal when a provider has no account
    capability catalog. The provider/model names are intentionally not logged here.
    """
    del provider, model
    if effort is None:
        return None
    if supported_levels is None or effort not in supported_levels:
        return StageFailure(
            code="REASONING_EFFORT_UNSUPPORTED",
            retryable=False,
            safe_message=(
                "Selected reasoning effort is unavailable for this provider/model"
            ),
        )
    return effort
