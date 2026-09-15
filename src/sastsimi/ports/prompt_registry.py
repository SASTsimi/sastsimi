"""Exact prompt publication and active-entry selection boundary."""

from typing import Protocol

from sastsimi.contracts.llm import LLMRole, PromptRegistryEntry, Purpose
from sastsimi.contracts.refs import StoredDataRef


class PromptRegistryPort(Protocol):
    def publish(self, entry: PromptRegistryEntry) -> StoredDataRef: ...

    def require_active(
        self,
        entry_ref: StoredDataRef,
        *,
        agent_role: LLMRole,
        task_kind: str,
        purpose: Purpose,
    ) -> PromptRegistryEntry: ...
