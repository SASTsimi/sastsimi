"""Select a provider client by Agent role without changing the provider."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from sastsimi.config.model_roles import model_for_agent

from .attempt_owner import AttemptOwner, PromptByteCounts
from .models import StageFailure
from .provider import SimpleLLMCallResult, SimpleLLMClient


class ModelRoutedClient:
    """Lazily cache one fully limited client for each selected model."""

    def __init__(
        self,
        *,
        primary_model: str,
        agent_models: Mapping[str, str],
        client_factory: Callable[[str], SimpleLLMClient],
    ) -> None:
        self._primary_model = primary_model
        self._agent_models = dict(agent_models)
        self._client_factory = client_factory
        self._clients: dict[str, SimpleLLMClient] = {}

    def client_for_agent(self, agent_name: str) -> SimpleLLMClient:
        """Return the exact model-bound client selected for a role."""
        model = model_for_agent(self._primary_model, self._agent_models, agent_name)
        client = self._clients.get(model)
        if client is None:
            client = self._client_factory(model)
            self._clients[model] = client
        return client

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
        owner: AttemptOwner | None = None,
        prompt_bytes: PromptByteCounts | None = None,
        invocation_id: str | None = None,
    ) -> SimpleLLMCallResult | StageFailure:
        return await self.client_for_agent(agent_name).call(
            prompt=prompt,
            output_schema=output_schema,
            timeout_ms=timeout_ms,
            agent_name=agent_name,
            owner=owner,
            prompt_bytes=prompt_bytes,
            invocation_id=invocation_id,
        )


__all__ = ["ModelRoutedClient"]
