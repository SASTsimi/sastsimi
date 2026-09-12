from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from inspect import signature
from pathlib import Path

import pytest

from sastsimi.agents.chaining import ChainingAgent
from sastsimi.bootstrap import T13Services, build_runtime, build_t13_services
from sastsimi.chaining.publication import RuntimeChainingResultPublisher
from sastsimi.chaining.service import ChainingCallRefs
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.ids import (
    CommitId,
    OpaqueId,
    ProposalId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.chaining import (
    ChainingAgentInput,
    ChainingProposalRegistration,
    PinnedChainingUniverse,
)
from sastsimi.ports.dto import WorkContext
from sastsimi.reporting.primitive_admission import PrimitiveAdmissionRuntime
from sastsimi.runtime.chaining_reconciliation import ChainingReconciliationService
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.storage.chaining_registration import (
    ChainingCohortStore,
    ChainingCommittedSourceStore,
    ChainingPoolHistoryStore,
)
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import upgrade


class _Clock:
    def now(self) -> datetime:
        return datetime(2026, 9, 12, tzinfo=UTC)

    def monotonic_ms(self) -> int:
        return 0


class _Ids:
    def __init__(self) -> None:
        self.value = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.value += 1
        return kind(f"composition-{kind.__name__.lower()}-{self.value}")


def _ref(kind: str, suffix: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(f"{kind}-{suffix}"),
        data_kind=kind,
        content_hash="a" * 64,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        record_id=RecordId(f"{kind}-{suffix}"),
    )


class _Lineage:
    def ancestors(
        self,
        *,
        primitive_ref: StoredDataRef,
        universe: PinnedChainingUniverse,
    ) -> tuple[StoredDataRef, ...]:
        del primitive_ref, universe
        return ()


class _ChildHandoff:
    def enqueue_ready(
        self,
        *,
        source_result_ref: StoredDataRef,
        proposal_id: ProposalId,
        requester_identity_ref: BudgetScopeRef,
    ) -> WorkExecutionState:
        del source_result_ref, proposal_id, requester_identity_ref
        raise AssertionError("composition must not execute child handoff")


class _ProposalRegistration:
    def register_claimed(
        self,
        *,
        context: WorkContext,
        source_result_ref: StoredDataRef,
        proposal_id: ProposalId,
        requester_identity_ref: BudgetScopeRef,
    ) -> ChainingProposalRegistration:
        del context, source_result_ref, proposal_id, requester_identity_ref
        raise AssertionError("composition must not register a proposal")


def _resolve_call(
    context: WorkContext,
    content: ChainingAgentInput,
) -> tuple[ChainingCallRefs, str]:
    del context, content
    raise AssertionError("composition must not resolve a call")


@dataclass(frozen=True)
class _Composition:
    runtime: object
    runner: WorkflowRunner
    clock: _Clock
    ids: _Ids
    lineage: _Lineage
    children: _ChildHandoff
    proposals: _ProposalRegistration
    scope: StoredDataRef
    identities: dict[RequesterRole, StoredDataRef]


def _composition(tmp_path: Path, *, bind_lineage: bool = True) -> _Composition:
    clock = _Clock()
    ids = _Ids()
    lineage = _Lineage()
    upgrade(Database(tmp_path / "db" / "sastsimi.sqlite3"))
    runtime = build_runtime(
        tmp_path,
        WorkspaceId("ws1"),
        CommitId("c1"),
        clock,
        ids,
        chaining_lineage=lineage if bind_lineage else None,
    )
    identities = {
        role: _ref("agent_identity", role.value.lower())
        for role in (
            RequesterRole.ORCHESTRATION,
            RequesterRole.CHAINING,
            RequesterRole.PRIMITIVE_ADMISSION_RUNTIME,
            RequesterRole.RECOVERY,
        )
    }
    return _Composition(
        runtime=runtime,
        runner=WorkflowRunner(runtime, clock, ids),
        clock=clock,
        ids=ids,
        lineage=lineage,
        children=_ChildHandoff(),
        proposals=_ProposalRegistration(),
        scope=_ref("budget_profile_binding", "analysis"),
        identities=identities,
    )


def _build(composition: _Composition) -> T13Services:
    from typing import cast

    from sastsimi.runtime.services import RuntimeServices

    return build_t13_services(
        runtime=cast(RuntimeServices, composition.runtime),
        runner=composition.runner,
        clock=composition.clock,
        ids=composition.ids,
        budget_scope_ref=composition.scope,
        role_identity_refs=composition.identities,
        chaining_call_resolver=_resolve_call,
        chaining_lineage=composition.lineage,
        child_handoff=composition.children,
        proposal_registration=composition.proposals,
    )


def test_compose_t13_services_wires_exact_trusted_dependencies(tmp_path: Path) -> None:
    composition = _composition(tmp_path)

    services = _build(composition)

    primitive_identity = composition.identities[
        RequesterRole.PRIMITIVE_ADMISSION_RUNTIME
    ]
    chaining_identity = composition.identities[RequesterRole.CHAINING]
    orchestration_identity = composition.identities[RequesterRole.ORCHESTRATION]
    recovery_identity = composition.identities[RequesterRole.RECOVERY]
    assert isinstance(services, T13Services)
    assert isinstance(services.primitive_update.admission, PrimitiveAdmissionRuntime)
    assert services.primitive_update.admission._identity_ref == primitive_identity
    assert isinstance(services.primitive_update.sources, ChainingCommittedSourceStore)
    assert isinstance(services.primitive_update.cohorts, ChainingCohortStore)
    assert services.primitive_update.requester_identity_ref == primitive_identity
    assert services.primitive_update.budget_scope_ref == composition.scope
    assert isinstance(services.chaining.service._agent, ChainingAgent)
    assert isinstance(services.chaining.service._pools, ChainingPoolHistoryStore)
    assert services.chaining.service._lineage is composition.lineage
    assert isinstance(
        services.chaining.service._publisher, RuntimeChainingResultPublisher
    )
    assert services.chaining.service._publisher._identity == chaining_identity
    assert services.chaining.service._children is composition.children
    assert services.chaining.service._identity == chaining_identity
    assert services.chaining.resolve_call is _resolve_call
    assert services.hypothesis_proposal.registration is composition.proposals
    assert services.hypothesis_proposal.requester_identity_ref == orchestration_identity
    assert isinstance(services.reconciliation, ChainingReconciliationService)
    assert services.reconciliation._children is composition.children
    assert services.reconciliation._identity == recovery_identity
    assert {"provider", "model"}.isdisjoint(signature(build_t13_services).parameters)


@pytest.mark.parametrize(
    "missing",
    (
        RequesterRole.ORCHESTRATION,
        RequesterRole.CHAINING,
        RequesterRole.PRIMITIVE_ADMISSION_RUNTIME,
        RequesterRole.RECOVERY,
    ),
)
def test_compose_t13_services_rejects_missing_identity(
    tmp_path: Path,
    missing: RequesterRole,
) -> None:
    composition = _composition(tmp_path)
    composition.identities.pop(missing)

    with pytest.raises(ValueError, match=rf"^{missing.value}_IDENTITY_REQUIRED$"):
        _build(composition)


def test_compose_t13_services_rejects_unvalidated_lineage_seam(
    tmp_path: Path,
) -> None:
    composition = _composition(tmp_path, bind_lineage=False)

    with pytest.raises(ValueError, match="^CHAINING_LINEAGE_RUNTIME_MISMATCH$"):
        _build(composition)
