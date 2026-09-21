"""Fail-closed policy preparation for explicit LOCAL_EVALUATION runs.

This module never invents an official bug-bounty policy.  It provides one
run-scoped declaration saying that no official program policy was supplied,
permits only local analysis, and denies external disclosure.  The existing
Policy Parser and Policy Collector still create the canonical policy result
chain; because the declaration is deliberately UNVERIFIED, Rule Scope must
remain ``UNCERTAIN + DENY``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast

from sastsimi.agents.policy_parser import PolicyParserAgent
from sastsimi.composition.production_feature_installer import LocalPolicyFeature
from sastsimi.config.local_evaluation_profile import LocalEvaluationProfile
from sastsimi.contracts.actions import ActionType, RequesterRole
from sastsimi.contracts.analysis import AnalysisRunState, AnalysisStartRequest
from sastsimi.contracts.base import ContractModel, NonEmptyStr
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import ProgramId
from sastsimi.contracts.policy import PolicySourceCheck
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.orchestration.run_initialization import PostWorkspaceSeederPort
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.policy.adapters.official_http import (
    OfficialHttpPolicySource,
    PinnedHttpsTransport,
    PolicySourceBoundaryError,
    resolve_public_addresses,
)
from sastsimi.policy.cache_service import PolicyCacheService
from sastsimi.policy.collector import PolicyCollector
from sastsimi.policy.preparation_service import PolicyPreparationService
from sastsimi.policy.program_catalog import ProgramCatalog
from sastsimi.policy.work_handler import PolicyWorkHandler
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import OfficialPolicyFetchRequest, OfficialPolicySource
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.llm_invocation import PersistedLLMInvocation
from sastsimi.ports.policy_catalog import ProgramCatalogEntry
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.verification.production_llm_work_handlers import ProductionCallPort

_PARSER_NAME = "local-evaluation-policy-parser"
_PARSER_VERSION = "1"
_LOCAL_ENDPOINT = "https://local-evaluation.invalid/no-official-program-policy"


class LocalEvaluationPolicyBoundary(ContractModel):
    """Credential-free declaration bound to one exact local analysis."""

    schema_version: Literal[1]
    analysis_id: NonEmptyStr
    program_id: ProgramId
    purpose: Literal["LOCAL_EVALUATION"]
    official_program_policy: Literal["NOT_PROVIDED"]
    external_disclosure: Literal["DENY"]
    remote_target_testing: Literal["DENY"]
    allowed_execution: tuple[
        Literal["LOCAL_STATIC_ANALYSIS", "LOCAL_ISOLATED_SANDBOX"], ...
    ]
    hard_restrictions: tuple[
        Literal[
            "REMOTE_TARGET_INTERACTION",
            "HOST_ACCESS",
            "DOCKER_SOCKET_ACCESS",
            "SECRET_ACCESS",
            "OTHER_WORKSPACE_ACCESS",
            "UNAPPROVED_EGRESS",
        ],
        ...,
    ]
    policy_interpretation: NonEmptyStr


def local_evaluation_policy_boundary_bytes(
    *, analysis_id: str, program_id: ProgramId
) -> bytes:
    """Return the canonical local declaration supplied to the Policy Parser."""

    return canonical_bytes(
        LocalEvaluationPolicyBoundary(
            schema_version=1,
            analysis_id=analysis_id,
            program_id=program_id,
            purpose="LOCAL_EVALUATION",
            official_program_policy="NOT_PROVIDED",
            external_disclosure="DENY",
            remote_target_testing="DENY",
            allowed_execution=(
                "LOCAL_STATIC_ANALYSIS",
                "LOCAL_ISOLATED_SANDBOX",
            ),
            hard_restrictions=(
                "REMOTE_TARGET_INTERACTION",
                "HOST_ACCESS",
                "DOCKER_SOCKET_ACCESS",
                "SECRET_ACCESS",
                "OTHER_WORKSPACE_ACCESS",
                "UNAPPROVED_EGRESS",
            ),
            policy_interpretation=(
                "This is a local execution boundary, not an official bounty "
                "policy or disclosure authorization. Treat official program "
                "policy as unavailable and keep Rule Scope uncertain with "
                "external disclosure denied."
            ),
        )
    )


@dataclass(frozen=True, slots=True)
class LocalEvaluationPolicySource:
    """Serve one immutable local declaration without network access."""

    program_id: ProgramId
    source_config_ref: BudgetScopeRef
    boundary_ref: StoredDataRef
    boundary_bytes: bytes
    analysis_id: str
    clock: Clock

    def __post_init__(self) -> None:
        digest = hashlib.sha256(self.boundary_bytes).hexdigest()
        if (
            not self.analysis_id.strip()
            or not isinstance(self.source_config_ref, StoredDataRef)
            or self.boundary_ref.data_kind != "artifact"
            or self.boundary_ref.record_id is not None
            or self.boundary_ref.content_hash != digest
            or str(self.boundary_ref.stored_data_id) != digest
            or (self.boundary_ref.workspace_id, self.boundary_ref.commit_id)
            != (
                self.source_config_ref.workspace_id,
                self.source_config_ref.commit_id,
            )
        ):
            raise ValueError("LOCAL_POLICY_BOUNDARY_INVALID")
        value = LocalEvaluationPolicyBoundary.model_validate_json(self.boundary_bytes)
        if (
            value.analysis_id != self.analysis_id
            or value.program_id != self.program_id
            or canonical_bytes(value) != self.boundary_bytes
        ):
            raise ValueError("LOCAL_POLICY_BOUNDARY_INVALID")

    async def fetch_official(
        self, request: OfficialPolicyFetchRequest
    ) -> OfficialPolicySource:
        """Return UNVERIFIED evidence so local use can never imply approval."""

        action = request.action
        if (
            request.program_id != self.program_id
            or request.source_config_ref != self.source_config_ref
            or action.action_type != ActionType.FETCH_POLICY
            or action.requested_by != RequesterRole.POLICY_COLLECTOR
            or tuple(action.input_refs) != (self.source_config_ref,)
        ):
            raise PolicySourceBoundaryError("LOCAL_POLICY_FETCH_SCOPE_MISMATCH")
        return OfficialPolicySource(
            source_check=PolicySourceCheck(
                source_id=f"local-policy-boundary-{self.analysis_id}",
                source_ref=self.boundary_ref,
                source_url="local-evaluation://policy/not-provided",
                publisher="LOCAL_EVALUATION_OPERATOR",
                status="UNVERIFIED",
                evidence_refs=(),
                checked_at=self.clock.now(),
            ),
            content=self.boundary_bytes,
        )


@dataclass(frozen=True, slots=True)
class LocalEvaluationPolicyPostWorkspaceSeeder(PostWorkspaceSeederPort):
    """Register one analysis-scoped policy work after the checkout is frozen."""

    runner: WorkflowRunner
    orchestration_identity_ref: BudgetScopeRef
    # None when the run collects an officially published endpoint: the document
    # only exists once the fetch succeeds, so no source artifact can be pinned
    # in advance.
    boundary_ref: StoredDataRef | None
    parser_name: str = _PARSER_NAME
    parser_version: str = _PARSER_VERSION

    def ensure_initial(
        self,
        request: AnalysisStartRequest,
        state: AnalysisRunState,
        binding_ref: StoredDataRef,
    ) -> tuple[WorkExecutionState, ...]:
        if (
            request.purpose != Purpose.LOCAL_EVALUATION
            or state.purpose != Purpose.LOCAL_EVALUATION
            or state.program_id != request.program_id
        ):
            raise ValueError("LOCAL_POLICY_PURPOSE_REQUIRED")
        if state.run_policy_state_ref is not None:
            return ()
        if (
            state.budget_binding_ref != binding_ref
            or state.workspace_id != binding_ref.workspace_id
            or state.commit_id != binding_ref.commit_id
        ):
            raise ValueError("LOCAL_POLICY_RUN_SCOPE_MISMATCH")
        binding = self.runner.runtime.unit_of_work.records.get_exact(binding_ref)
        binding_meta = getattr(binding, "meta", None)
        if (
            not isinstance(binding_meta, RecordMeta)
            or binding_meta.analysis_id != state.meta.analysis_id
            or binding_meta.workspace_id != state.workspace_id
            or binding_meta.commit_id != state.commit_id
        ):
            raise ValueError("LOCAL_POLICY_RUN_SCOPE_MISMATCH")
        prepared = self.runner.begin_policy(
            binding_ref,
            binding_meta,
            self.orchestration_identity_ref,
            program_id=str(request.program_id),
            source_config_ref=binding_ref,
            source_input_refs=(
                () if self.boundary_ref is None else (self.boundary_ref,)
            ),
            parser_name=self.parser_name,
            parser_version=self.parser_version,
        )
        ready = self.runner.enqueue_registered(
            prepared.work,
            binding_ref,
            self.orchestration_identity_ref,
            role="ORCHESTRATION",
        )
        return (ready,)


class _LocalPolicyContext(Protocol):
    request: AnalysisStartRequest
    profile: LocalEvaluationProfile
    scope: PlannedRunScope
    clock: Clock
    ids: IdGenerator
    role_identity_refs: Mapping[RequesterRole, BudgetScopeRef]
    budget_binding_ref: StoredDataRef
    runtime: RuntimeServices
    runner: WorkflowRunner


@dataclass(frozen=True, slots=True)
class _LocalPolicyParserInvocation:
    calls: ProductionCallPort
    context: _LocalPolicyContext

    async def invoke(
        self, *, work: WorkExecutionState, source_ref: StoredDataRef
    ) -> PersistedLLMInvocation:
        call = self.calls.resolve(
            work=work,
            role="POLICY_PARSER",
            task_kind="PARSE_OFFICIAL_POLICY",
            source_refs=(source_ref,),
        )
        invocation = await self.context.runtime.llm_calls.invoke(
            work=work,
            decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
        )
        self.calls.settle(call, invocation)
        return invocation


def build_local_evaluation_policy_feature(
    *,
    context: _LocalPolicyContext,
    calls: ProductionCallPort,
    boundary_ref: StoredDataRef,
    boundary_bytes: bytes,
) -> LocalPolicyFeature:
    """Build local policy preparation without weakening Production policy I/O."""

    if context.request.purpose != Purpose.LOCAL_EVALUATION:
        raise ValueError("LOCAL_POLICY_PURPOSE_REQUIRED")
    raw = local_evaluation_policy_boundary_bytes(
        analysis_id=str(context.scope.analysis_id),
        program_id=context.request.program_id,
    )
    artifacts: ArtifactStore = context.runtime.unit_of_work.artifacts
    if (
        boundary_bytes != raw
        or boundary_ref.data_kind != "artifact"
        or boundary_ref.record_id is not None
        or boundary_ref.workspace_id != context.scope.workspace_id
        or boundary_ref.commit_id != context.scope.commit_id
    ):
        raise ValueError("LOCAL_POLICY_RUN_SCOPE_MISMATCH")
    configured = context.profile.policy
    if configured is None:
        entry = ProgramCatalogEntry(
            program_id=context.request.program_id,
            program_namespace="local-evaluation",
            external_program_id=f"local-{context.scope.analysis_id}",
            source_config_ref=context.budget_binding_ref,
            source_version="local-boundary-v1",
            official_endpoint=_LOCAL_ENDPOINT,
            publisher="LOCAL_EVALUATION_OPERATOR",
            parser_name=_PARSER_NAME,
            parser_version=_PARSER_VERSION,
            freshness_criterion_ref=context.budget_binding_ref,
            freshness_ttl_seconds=1,
            timeout_seconds=1,
            max_response_bytes=max(4096, len(raw)),
            allowed_content_types=("application/json",),
        )
        catalog = ProgramCatalog((entry,))
        source: object = LocalEvaluationPolicySource(
            program_id=context.request.program_id,
            source_config_ref=context.budget_binding_ref,
            boundary_ref=boundary_ref,
            boundary_bytes=raw,
            analysis_id=str(context.scope.analysis_id),
            clock=context.clock,
        )
    else:
        # The operator named an officially published endpoint, so this run
        # collects and parses that exact document instead of the local
        # declaration.  The repository never becomes a policy source.
        entry = ProgramCatalogEntry(
            program_id=context.request.program_id,
            program_namespace=configured.program_namespace,
            external_program_id=configured.external_program_id,
            source_config_ref=context.budget_binding_ref,
            source_version=configured.source_version,
            official_endpoint=configured.official_endpoint,
            publisher=configured.publisher,
            parser_name=_PARSER_NAME,
            parser_version=_PARSER_VERSION,
            freshness_criterion_ref=context.budget_binding_ref,
            freshness_ttl_seconds=configured.freshness_ttl_seconds,
            timeout_seconds=configured.timeout_seconds,
            max_response_bytes=configured.max_response_bytes,
            allowed_content_types=configured.allowed_content_types,
            allowed_redirect_hosts=configured.allowed_redirect_hosts,
        )
        catalog = ProgramCatalog((entry,))
        source = OfficialHttpPolicySource(
            catalog=catalog,
            artifacts=artifacts,
            transport=PinnedHttpsTransport(),
            resolver=resolve_public_addresses,
            clock=context.clock,
        )
    parser = PolicyParserAgent(
        invocations=_LocalPolicyParserInvocation(calls, context),
        artifacts=artifacts,
        ids=context.ids,
        clock=context.clock,
        parser_name=_PARSER_NAME,
        parser_version=_PARSER_VERSION,
    )
    service = PolicyPreparationService(
        runtime=context.runtime,
        runner=context.runner,
        catalog=catalog,
        source=cast(Any, source),
        parser=parser,
        cache=PolicyCacheService(
            runtime=context.runtime.policy,
            records=context.runtime.unit_of_work.records,
        ),
        collector=PolicyCollector(
            runner=context.runner,
            policy_runtime=context.runtime.policy,
            ids=context.ids,
            clock=context.clock,
        ),
        collector_identity_ref=context.role_identity_refs[
            RequesterRole.POLICY_COLLECTOR
        ],
        parser_identity_ref=context.role_identity_refs[RequesterRole.POLICY_PARSER],
    )
    return LocalPolicyFeature(
        handler=PolicyWorkHandler(service),
        seeder=LocalEvaluationPolicyPostWorkspaceSeeder(
            runner=context.runner,
            orchestration_identity_ref=context.role_identity_refs[
                RequesterRole.ORCHESTRATION
            ],
            boundary_ref=None if configured is not None else boundary_ref,
        ),
    )


__all__ = [
    "LocalEvaluationPolicyBoundary",
    "LocalEvaluationPolicyPostWorkspaceSeeder",
    "LocalEvaluationPolicySource",
    "build_local_evaluation_policy_feature",
    "local_evaluation_policy_boundary_bytes",
]
