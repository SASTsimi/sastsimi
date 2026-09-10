"""Context recovery consumes one exact durable receipt without rereading code."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from sqlalchemy import delete, insert

from sastsimi.contracts.actions import ActionDecision, ActionRequest, RequesterRole
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.hypothesis import HypothesisProposal
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import (
    CodeContextRequest,
    CodeContextResponse,
    CodeLocation,
    CodeWorkspace,
    ContextRetrievalLimits,
    StaticFactBundle,
)
from sastsimi.ports.context import ContextRetrievalIntent
from sastsimi.ports.dto import (
    MonotonicActionDeadline,
    ProcessReceipt,
    TrackedFile,
)
from sastsimi.storage import models
from sastsimi.storage.artifact_store import LocalArtifactStore
from sastsimi.storage.recovery_service import RecoveryService as SQLiteRecoveryService
from sastsimi.verification.context_service import ContextRetrievalService
from tests.contract.domain.canonical_fixtures import make
from tests.integration.storage.test_intermediate_publication import (
    prepared_policy_parser,
)


class _CrashAfterReceipt(RuntimeError):
    pass


class _ReceiptLocator:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.read_checks = 0
        self.validations = 0

    def root_for(self, workspace: CodeWorkspace) -> Path:
        del workspace
        return self.root

    async def assert_unchanged(
        self,
        workspace: CodeWorkspace,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_id: str,
    ) -> tuple[ProcessReceipt, ...]:
        del workspace
        self.read_checks += 1
        return tuple(
            self._receipt(deadline.action_id, attempt_id, check_id, command)
            for command in ("head", "worktree", "index", "manifest")
        )

    def validate_integrity_receipts(
        self,
        workspace: CodeWorkspace,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_ids: tuple[str, ...],
        receipts: tuple[ProcessReceipt, ...],
    ) -> None:
        del workspace
        expected = tuple(
            self._receipt(deadline.action_id, attempt_id, check_id, command)
            for check_id in check_ids
            for command in ("head", "worktree", "index", "manifest")
        )
        if receipts != expected:
            raise ValueError("WORKSPACE_PROCESS_RECEIPTS_INVALID")
        self.validations += 1

    @staticmethod
    def _receipt(
        action_id: str, attempt_id: str, check_id: str, command: str
    ) -> ProcessReceipt:
        fingerprint = hashlib.sha256(
            canonical_bytes((action_id, attempt_id, check_id, command))
        ).hexdigest()
        empty = hashlib.sha256(b"").hexdigest()
        return ProcessReceipt(
            action_id=action_id,
            invocation_id=f"{action_id}:workspace-guard:{check_id}:{command}",
            command_kind=f"guard-{command}",
            attempt_id=attempt_id,
            command_fingerprint=fingerprint,
            outcome="SUCCEEDED",
            return_code=0,
            stdout_name=f"{check_id}-{command}.stdout",
            stdout_size=0,
            stdout_sha256=empty,
            stderr_name=f"{check_id}-{command}.stderr",
            stderr_size=0,
            stderr_sha256=empty,
            elapsed_ms=1,
        )


class _TrackedResolver:
    def __init__(self, git_path: str, source: Path) -> None:
        self.git_path = git_path
        self.source = source
        self.calls = 0

    def __call__(self, workspace: CodeWorkspace) -> tuple[TrackedFile, ...]:
        del workspace
        self.calls += 1
        return (
            TrackedFile(
                self.git_path,
                "100644",
                "0" * 40,
                self.source.stat().st_size,
            ),
        )


def _code_record(name: str, meta: RecordMeta) -> HypothesisProposal | StaticFactBundle:
    raw = make(name)
    raw["meta"].update(
        analysis_id=str(meta.analysis_id),
        workspace_id=str(meta.workspace_id),
        commit_id=str(meta.commit_id),
    )
    if name == "HypothesisProposal":
        raw["meta"]["hypothesis_id"] = "h1"
        return HypothesisProposal.model_validate_json(
            canonical_bytes(raw).replace(b'"ws1"', b'"w1"')
        )
    return StaticFactBundle.model_validate_json(
        canonical_bytes(raw).replace(b'"ws1"', b'"w1"')
    )


@pytest.mark.parametrize(
    (
        "crash_stage",
        "tamper_process_receipt",
        "wrong_service_identity",
        "post_receipt_case",
    ),
    (
        ("AUTHORIZED", False, False, "VALID"),
        ("CLAIMED", False, False, "VALID"),
        ("CLAIMED", False, True, "VALID"),
        ("REQUEST_BOUND", False, False, "VALID"),
        ("DISPATCHED", False, False, "VALID"),
        ("RECEIPT_DURABLE", False, False, "VALID"),
        ("RECEIPT_DURABLE", True, False, "VALID"),
        ("RECEIPT_DURABLE", False, True, "VALID"),
        ("RECEIPT_DURABLE", False, False, "WRONG_ISSUED"),
        ("RECEIPT_DURABLE", False, False, "STALE_BUNDLE"),
    ),
)
@pytest.mark.asyncio
async def test_complete_receipt_recovers_once_without_source_reread(
    tmp_path: Path,
    crash_stage: str,
    tamper_process_receipt: bool,
    wrong_service_identity: bool,
    post_receipt_case: str,
) -> None:
    h, runtime, runner, policy_work, parser, _ = prepared_policy_parser(
        tmp_path, context=True
    )
    orchestration = next(
        ref
        for ref, role in h.evidence.identities.items()
        if role == RequesterRole.POLICY_PARSER
    )
    runner.complete(policy_work, orchestration, "POLICY_PARSER", (parser,))
    service_identity = next(
        ref
        for ref, role in h.evidence.identities.items()
        if role == RequesterRole.CONTEXT_RETRIEVAL_SERVICE
    )
    h.evidence.identities[orchestration] = RequesterRole.ORCHESTRATION
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    workspace_ref = runtime.budget_registry.current_state("a1").workspace_ref
    assert scope is not None and workspace_ref is not None
    workspace = h.records.get_exact(workspace_ref)
    assert isinstance(workspace, CodeWorkspace)
    assert workspace.commit_id is not None
    artifacts = runtime.unit_of_work.artifacts
    assert isinstance(artifacts, LocalArtifactStore)
    artifacts.workspace_id = workspace.workspace_id
    artifacts.commit_id = workspace.commit_id
    meta = RecordMeta.model_validate(
        parser.meta.model_dump() | {"hypothesis_id": "h1", "attempt_id": None}
    )
    proposal = _code_record("HypothesisProposal", meta)
    bundle = _code_record("StaticFactBundle", meta)
    assert isinstance(proposal, HypothesisProposal)
    assert isinstance(bundle, StaticFactBundle)
    proposal_ref = StoredDataRef.model_validate(h.publish(proposal))
    bundle_ref = StoredDataRef.model_validate(h.publish(bundle))
    with h.database.write() as connection:
        for record in (proposal, bundle):
            connection.execute(
                insert(models.current_records).values(
                    logical_record_id=str(record.meta.logical_record_id),
                    record_id=str(record.meta.record_id),
                    state_version=1,
                )
            )
    limits = ContextRetrievalLimits(
        max_depth=1,
        max_fragments=2,
        max_bytes=16_384,
        max_requests_per_hypothesis=2,
        timeout_ms=100,
    )
    ceiling_raw = canonical_bytes(
        {
            "kind": "context_ceiling_profile",
            "schema_version": "1.0",
            **limits.model_dump(),
        }
    )
    ceiling_ref = artifacts.commit(
        artifacts.stage_bytes(ceiling_raw, "application/json")
    )
    work = runner.start(
        scope,
        meta,
        "CONTEXT_RETRIEVAL",
        "HYPOTHESIS",
        "h1",
        orchestration,
        inputs=(proposal_ref, bundle_ref, ceiling_ref),
    )
    code_root = tmp_path / "checked-out"
    code_root.mkdir()
    git_path = "app.py"
    source = code_root.joinpath(*git_path.split("/"))
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("def seed():\n    return 1\n", encoding="utf-8")
    locator = _ReceiptLocator(code_root)
    tracked = _TrackedResolver(git_path, source)

    def checkpoint(stage: str) -> None:
        if stage == crash_stage:
            raise _CrashAfterReceipt

    location = CodeLocation(
        workspace_id=workspace.workspace_id,
        commit_id=workspace.commit_id,
        file_path=git_path,
        start_line=1,
        start_column=None,
        end_line=2,
        end_column=None,
    )
    service = ContextRetrievalService(
        runtime=runtime,
        runner=runner,
        workspace_locator=locator,
        tracked_files_for=tracked,
        receipt_root=tmp_path / "receipts",
        monotonic_ns=lambda: 1_000_000,
        checkpoint=checkpoint,
    )
    intent = ContextRetrievalIntent(
        proposal_ref=proposal_ref,
        bundle_ref=bundle_ref,
        requested_entities=(),
        requested_locations=(location,),
        relation_query=(),
        reason="Read exact location",
        requested_limits=limits,
    )
    assert runtime.unit_of_work.records.get_exact(proposal_ref) == proposal
    assert runtime.unit_of_work.records.get_exact(bundle_ref) == bundle
    assert bundle in runtime.queries.current_records("a1", "static_fact_bundle")
    assert proposal in runtime.queries.current_records("a1", "hypothesis_proposal")
    assert runtime.budget_registry.current_state("a1").workspace_ref == reference(
        workspace
    )
    assert proposal.meta.hypothesis_id == work.meta.hypothesis_id
    h.evidence.identities[orchestration] = RequesterRole.PRO
    with pytest.raises(_CrashAfterReceipt):
        await service.retrieve(
            work=work,
            intent=intent,
            workspace=workspace,
            bundle=bundle,
            budget_scope=scope,
            requester_identity=orchestration,
            requester_role="PRO",
            service_identity=service_identity,
            work_timeout_ms=100,
        )
    expected_reads_before_recovery = 2 if crash_stage == "RECEIPT_DURABLE" else 0
    assert locator.read_checks == expected_reads_before_recovery
    assert tracked.calls == (1 if crash_stage == "RECEIPT_DURABLE" else 0)

    records = runtime.queries.published_records("a1")
    action = next(
        item
        for item in records
        if isinstance(item, ActionRequest)
        and item.action_type == "READ_CODE"
        and item.work_ref == reference(work)
    )
    action_ref = reference(action)
    assert isinstance(action_ref, StoredDataRef)
    decisions = sorted(
        (
            item
            for item in records
            if isinstance(item, ActionDecision) and item.action_ref == action_ref
        ),
        key=lambda item: item.meta.revision_number,
    )
    issued_ref = reference(decisions[0])
    assert isinstance(issued_ref, StoredDataRef)
    reservation = next(
        item
        for item in records
        if isinstance(item, BudgetReservation) and item.action_ref == action_ref
    )
    reservation_ref = reference(reservation)
    assert isinstance(reservation_ref, StoredDataRef)
    plan_refs = tuple(ref for ref in action.input_refs if ref not in work.input_refs)
    assert len(plan_refs) == 1
    plan_ref = plan_refs[0]
    assert isinstance(plan_ref, StoredDataRef)

    if crash_stage != "RECEIPT_DURABLE":
        supplied_decision_ref = reference(decisions[-1])
        assert isinstance(supplied_decision_ref, StoredDataRef)
        requests_before = tuple(
            item for item in records if isinstance(item, CodeContextRequest)
        )
        assert len(requests_before) == (
            1 if crash_stage in {"REQUEST_BOUND", "DISPATCHED"} else 0
        )
        service.checkpoint = lambda _stage: None
        if wrong_service_identity:
            with pytest.raises(ValueError, match="CONTEXT_AUTHORITY_MISMATCH"):
                await service.recover_pending(
                    work=work,
                    intent=intent,
                    workspace=workspace,
                    bundle=bundle,
                    action_ref=action_ref,
                    decision_ref=supplied_decision_ref,
                    reservation_ref=reservation_ref,
                    plan_ref=plan_ref,
                    service_identity=orchestration,
                    work_timeout_ms=100,
                )
            assert locator.read_checks == 0 and tracked.calls == 0
            return
        if crash_stage == "DISPATCHED":
            recovery = runtime.recovery.recovery
            assert isinstance(recovery, SQLiteRecoveryService)
            recovery.recovery_identity_ref = scope
            h.evidence.identities[scope] = RequesterRole.RECOVERY
            with pytest.raises(ValueError, match="CONTEXT_RECOVERY_UNCERTAIN"):
                await service.recover_pending(
                    work=work,
                    intent=intent,
                    workspace=workspace,
                    bundle=bundle,
                    action_ref=action_ref,
                    decision_ref=supplied_decision_ref,
                    reservation_ref=reservation_ref,
                    plan_ref=plan_ref,
                    service_identity=service_identity,
                    work_timeout_ms=100,
                )
            blocked = runtime.work.get(str(work.work_id))
            assert blocked.status == "BLOCKED"
            assert blocked.waiting_for == ("INPUT",)
            assert blocked.stop_reason == "RECOVERY_FAILED"
            assert blocked.active_attempt_id is None
            assert blocked.output_refs == ()
            with pytest.raises(ValueError, match="CONTEXT_RECOVERY_INVALID"):
                await service.recover_pending(
                    work=work,
                    intent=intent,
                    workspace=workspace,
                    bundle=bundle,
                    action_ref=action_ref,
                    decision_ref=supplied_decision_ref,
                    reservation_ref=reservation_ref,
                    plan_ref=plan_ref,
                    service_identity=service_identity,
                    work_timeout_ms=100,
                )
            assert locator.read_checks == 0 and tracked.calls == 0
            assert not runtime.queries.current_records("a1", "code_context_response")
            return
        recovered, output_ref = await service.recover_pending(
            work=work,
            intent=intent,
            workspace=workspace,
            bundle=bundle,
            action_ref=action_ref,
            decision_ref=supplied_decision_ref,
            reservation_ref=reservation_ref,
            plan_ref=plan_ref,
            service_identity=service_identity,
            work_timeout_ms=100,
        )
        assert recovered == h.records.get_exact(output_ref)
        assert runtime.work.get(str(work.work_id)).status == "SUCCEEDED"
        current_records = runtime.queries.published_records("a1")
        assert (
            len(
                tuple(
                    item for item in current_records if isinstance(item, ActionRequest)
                )
            )
            == len(tuple(item for item in records if isinstance(item, ActionRequest)))
            + 1
        )
        assert (
            len(
                tuple(
                    item
                    for item in current_records
                    if isinstance(item, ActionRequest)
                    and item.action_type == "READ_CODE"
                    and item.work_ref == reference(work)
                )
            )
            == 1
        )
        assert (
            len(
                {
                    str(item.reservation_id)
                    for item in current_records
                    if isinstance(item, BudgetReservation)
                    and item.action_ref == action_ref
                }
            )
            == 1
        )
        context_requests = tuple(
            item for item in current_records if isinstance(item, CodeContextRequest)
        )
        assert len(context_requests) == 1
        assert locator.read_checks == 2 and tracked.calls == 1
        return

    claimed_ref = reference(decisions[1])
    assert isinstance(claimed_ref, StoredDataRef)
    request_ref = decisions[-1].outcome_refs[0]
    assert isinstance(request_ref, StoredDataRef)

    selected_issued_ref = (
        claimed_ref if post_receipt_case == "WRONG_ISSUED" else issued_ref
    )
    selected_service_identity = (
        orchestration if wrong_service_identity else service_identity
    )
    if post_receipt_case == "STALE_BUNDLE":
        with h.database.write() as connection:
            connection.execute(
                delete(models.current_records).where(
                    models.current_records.c.logical_record_id
                    == str(bundle.meta.logical_record_id)
                )
            )

    def recover() -> tuple[CodeContextResponse, StoredDataRef]:
        return service.recover_after_receipt(
            work=work,
            action_ref=action_ref,
            issued_decision_ref=selected_issued_ref,
            claimed_decision_ref=claimed_ref,
            reservation_ref=reservation_ref,
            request_ref=request_ref,
            plan_ref=plan_ref,
            service_identity=selected_service_identity,
        )

    validations_before_recovery = locator.validations
    if wrong_service_identity:
        with pytest.raises(ValueError, match="CONTEXT_AUTHORITY_MISMATCH"):
            recover()
        assert runtime.work.get(str(work.work_id)).status == "RUNNING"
        assert not runtime.queries.current_records("a1", "code_context_response")
        assert locator.read_checks == 2 and tracked.calls == 1
        assert locator.validations == validations_before_recovery
        return

    if post_receipt_case in {"WRONG_ISSUED", "STALE_BUNDLE"}:
        with pytest.raises(ValueError, match="CONTEXT_RECOVERY_INVALID"):
            recover()
        assert runtime.work.get(str(work.work_id)).status == "RUNNING"
        assert not runtime.queries.current_records("a1", "code_context_response")
        assert locator.read_checks == 2 and tracked.calls == 1
        assert locator.validations == validations_before_recovery
        return

    if tamper_process_receipt:
        process_path = next((tmp_path / "receipts").glob("*.process.json"))
        process_path.write_bytes(b"{}")
        before_validations = locator.validations
        with pytest.raises(ValueError, match="CONTEXT_RECEIPT_INVALID"):
            recover()
        assert runtime.work.get(str(work.work_id)).status == "RUNNING"
        assert not runtime.queries.current_records("a1", "code_context_response")
        assert locator.read_checks == 2 and tracked.calls == 1
        assert locator.validations == before_validations
        return

    recovered, output_ref = recover()
    assert recovered == h.records.get_exact(output_ref)
    assert runtime.work.get(str(work.work_id)).status == "SUCCEEDED"
    assert locator.read_checks == 2 and tracked.calls == 1
    first_validations = locator.validations

    replayed, replay_ref = recover()
    assert (replayed, replay_ref) == (recovered, output_ref)
    assert locator.read_checks == 2 and tracked.calls == 1
    assert locator.validations == first_validations + 1
