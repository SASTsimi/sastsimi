"""Injected static-tool execution and committed context retrieval services."""

from typing import Protocol

from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef
from sastsimi.contracts.static import (
    CodeContextResponse,
    CodeWorkspace,
    StaticFactBundle,
)
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.context import ContextRetrievalIntent
from sastsimi.ports.dto import StaticToolRequest


class StaticToolServicePort(Protocol):
    async def run(self, request: StaticToolRequest) -> object: ...

    async def recover(self, request: StaticToolRequest) -> object: ...


class ContextRetrievalServicePort(Protocol):
    async def retrieve(
        self,
        *,
        work: WorkExecutionState,
        intent: ContextRetrievalIntent,
        workspace: CodeWorkspace,
        bundle: StaticFactBundle,
        budget_scope: BudgetScopeRef,
        requester_identity: BudgetScopeRef,
        requester_role: str,
        service_identity: BudgetScopeRef,
        work_timeout_ms: int,
    ) -> tuple[CodeContextResponse, StoredDataRef]: ...
