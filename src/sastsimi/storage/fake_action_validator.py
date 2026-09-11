"""Fake vertical-slice storage authority; never compose in production."""

from sastsimi.contracts.llm import LLMInvocationResult

from .action_validator import RuntimeValidator


class FakeRecordOutputRuntimeValidator(RuntimeValidator):
    """Permit the deterministic pre-T10 fake's trusted record-shaped fixture."""

    def _require_provider_output_authority(self, result: LLMInvocationResult) -> None:
        return None


__all__ = ["FakeRecordOutputRuntimeValidator"]
