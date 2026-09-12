"""Trusted session-finalization seam for dynamic reproduction."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol

from sastsimi.contracts.domain import DomainRecord
from sastsimi.contracts.dynamic import (
    AgentLog,
    AgentLogEvent,
    CleanupResult,
    DynamicReproductionConclusion,
    DynamicReproductionRequest,
    DynamicReproductionResult,
    DynamicReproductionToolRequest,
    EnvironmentRecipe,
    EnvironmentRequirements,
    PlanIssueItem,
    PoCBundle,
    PoCCandidate,
    ReproductionPlan,
    SandboxCommandRecord,
    SandboxEnvironment,
    SandboxPolicyDecision,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef

type DynamicStatus = Literal["SUCCEEDED", "PARTIAL", "FAILED", "BLOCKED", "CANCELLED"]
type FailureCategory = Literal[
    "NONE",
    "POLICY_BLOCKED",
    "EXTERNAL_CONFIGURATION",
    "PLAN",
    "ENVIRONMENT_SETUP",
    "DEPENDENCY",
    "AGENT",
    "EXECUTION",
    "OBSERVATION",
    "TIMEOUT",
    "RESOURCE_LIMIT",
    "RETRY_LIMIT",
    "INTERNAL",
]


@dataclass(frozen=True)
class DynamicFinalizationInput:
    request: DynamicReproductionRequest
    plan: ReproductionPlan | None
    policy: SandboxPolicyDecision | None
    recipe: EnvironmentRecipe | None
    environment: SandboxEnvironment | None
    candidate: PoCCandidate | None
    conclusion: DynamicReproductionConclusion | None
    cleanup: CleanupResult | None
    observation_refs: tuple[StoredDataRef, ...]
    status: DynamicStatus
    failure_category: FailureCategory
    failure_reason: str | None
    plan_issues: tuple[PlanIssueItem, ...]
    started_at: datetime
    finished_at: datetime
    requirements: EnvironmentRequirements | None = None
    command_records: tuple[SandboxCommandRecord, ...] = ()
    tool_requests: tuple[DynamicReproductionToolRequest, ...] = ()
    attempt_environments: tuple[SandboxEnvironment, ...] = ()
    attempt_recipes: tuple[EnvironmentRecipe, ...] = ()
    attempt_resource_refs: tuple[StoredDataRef, ...] = ()
    resolved_evidence: Mapping[StoredDataRef, DomainRecord] = field(
        default_factory=dict
    )


@dataclass(frozen=True)
class FinalizedDynamicRecords:
    log: AgentLog
    poc: PoCBundle | None
    result: DynamicReproductionResult


class ReproductionSessionPort(Protocol):
    def start(
        self,
        *,
        request_ref: StoredDataRef,
        meta: RecordMeta,
        policy_decision_ref: StoredDataRef | None = None,
    ) -> AgentLog: ...

    def append(self, *, previous: AgentLog, event: AgentLogEvent) -> AgentLog: ...

    def finalize(
        self, *, data: DynamicFinalizationInput, log: AgentLog, meta: RecordMeta
    ) -> FinalizedDynamicRecords: ...


__all__ = [
    "DynamicFinalizationInput",
    "DynamicStatus",
    "FailureCategory",
    "FinalizedDynamicRecords",
    "ReproductionSessionPort",
]
