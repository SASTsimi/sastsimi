"""Deterministic READ_CODE orchestration through public runtime services."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Protocol

from pydantic import TypeAdapter
from sqlalchemy import select

from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    Decision,
    RequesterRole,
    UseStatus,
    validate_decision_for_action,
    validate_decision_revision,
)
from sastsimi.contracts.budget import (
    BudgetReservation,
    ReservationStatus,
    validate_reservation_revision,
)
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.hypothesis import HypothesisProposal
from sastsimi.contracts.ids import ErrorId, GapId, TransitionCommitId, TransitionId
from sastsimi.contracts.records import RecordMeta, RecordMetadata
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.contracts.static import (
    AnalysisError,
    CodeContextRequest,
    CodeContextResponse,
    CodeLocation,
    CodeWorkspace,
    ContextRetrievalLimits,
    DataGap,
    StaticFactBundle,
)
from sastsimi.contracts.work import (
    StateTransition,
    TransitionCommit,
    WorkExecutionState,
)
from sastsimi.ports.context import (
    ChainingContextRecords,
    ContextCeilingProfile,
    ContextLineageReaderPort,
    ContextReadPlan,
    ContextRetrievalIntent,
)
from sastsimi.ports.dto import (
    MonotonicActionDeadline,
    ProcessReceipt,
    StaticActionReceipt,
    TrackedFile,
    TransitionCommitRequest,
)
from sastsimi.ports.workspace import WorkspaceLocatorPort
from sastsimi.runtime.fake_support import FakeEvidence
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.static_analysis.context_retrieval import (
    ContextReadObservation,
    context_intent_hash,
    decode_context_read_plan,
    encode_context_read_plan,
    plan_context_retrieval,
    read_context_files,
)
from sastsimi.storage import models
from sastsimi.storage.codec import REF_ADAPTER
from sastsimi.storage.context_policy import (
    context_dispatch_state,
    resolve_context_ceiling,
)
from sastsimi.storage.recovery_service import RecoveryService as SQLiteRecoveryService
from sastsimi.storage.repositories import SQLiteRecordStore

_MAX_RECEIPT_BYTES = 64 * 1024
_INTEGRITY_SEQUENCE = (
    "guard-head",
    "guard-worktree",
    "guard-index",
    "guard-manifest",
)


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_nlink,
        getattr(value, "st_file_attributes", 0),
    )


def _guarded_read(path: Path, limit: int) -> bytes:
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or getattr(before, "st_file_attributes", 0) & 0x400
            or before.st_size > limit
        ):
            raise ValueError
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            raise ValueError
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = path.lstat()
        if len(raw) > limit or _file_identity(after) != _file_identity(opened):
            raise ValueError
        return raw
    except (OSError, ValueError) as error:
        raise ValueError("CONTEXT_RECEIPT_INVALID") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class TrackedFilesResolver(Protocol):
    def __call__(self, workspace: CodeWorkspace) -> tuple[TrackedFile, ...]: ...


class ContextRetrievalService:
    """Own the authorized read, durable receipt, accounting and final publication."""

    def __init__(
        self,
        *,
        runtime: RuntimeServices,
        runner: WorkflowRunner,
        workspace_locator: WorkspaceLocatorPort,
        tracked_files_for: TrackedFilesResolver,
        receipt_root: Path,
        lineage_reader: ContextLineageReaderPort | None = None,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        checkpoint: Callable[[str], None] = lambda _stage: None,
    ) -> None:
        self.runtime = runtime
        self.runner = runner
        self.workspace_locator = workspace_locator
        self.tracked_files_for = tracked_files_for
        self.receipt_root = receipt_root
        self.lineage_reader = lineage_reader
        self.monotonic_ns = monotonic_ns
        self.checkpoint = checkpoint

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
    ) -> tuple[CodeContextResponse, StoredDataRef]:
        """Execute one request; never expose a response before COMMITTED."""
        self._require_service_identity(service_identity)
        current = self.runtime.work.get(str(work.work_id))
        if (
            current != work
            or work.active_attempt_id is None
            or not isinstance(work.meta, RecordMeta)
        ):
            raise ValueError("ATTEMPT_NOT_ACTIVE")
        exact_proposal = self.runtime.unit_of_work.records.get_exact(
            intent.proposal_ref
        )
        exact_bundle = self.runtime.unit_of_work.records.get_exact(intent.bundle_ref)
        run_state = self.runtime.budget_registry.current_state(
            str(work.meta.analysis_id)
        )
        current_bundles = self.runtime.queries.current_records(
            str(work.meta.analysis_id), "static_fact_bundle"
        )
        current_proposals = self.runtime.queries.current_records(
            str(work.meta.analysis_id), "hypothesis_proposal"
        )
        if (
            not isinstance(exact_proposal, HypothesisProposal)
            or exact_bundle != bundle
            or reference(bundle) != intent.bundle_ref
            or bundle not in current_bundles
            or exact_proposal not in current_proposals
            or run_state.workspace_ref != reference(workspace)
            or exact_proposal.meta.hypothesis_id != work.meta.hypothesis_id
        ):
            raise ValueError("CONTEXT_INPUT_MISMATCH")
        if (
            work.input_refs.count(intent.proposal_ref) != 1
            or work.input_refs.count(intent.bundle_ref) != 1
        ):
            raise ValueError("CONTEXT_INPUT_MISMATCH")
        ceilings = resolve_context_ceiling(self.runtime.unit_of_work.artifacts, work)
        self._require_request_capacity(
            work, ceilings.limits.max_requests_per_hypothesis
        )
        lineage = self._lineage(intent)
        plan = plan_context_retrieval(
            intent=intent,
            bundle=bundle,
            workspace=workspace,
            work=work,
            ceilings=ceilings,
            work_timeout_ms=work_timeout_ms,
            lineage=lineage,
        )
        plan_raw = encode_context_read_plan(plan)
        if len(plan_raw) > intent.requested_limits.max_bytes:
            raise ValueError("CONTEXT_PLAN_TOO_LARGE")
        plan_ref = self.runtime.unit_of_work.artifacts.commit(
            self.runtime.unit_of_work.artifacts.stage_bytes(
                plan_raw, "application/json"
            )
        )
        if (
            plan_ref.content_hash != hashlib.sha256(plan_raw).hexdigest()
            or str(plan_ref.stored_data_id) != plan_ref.content_hash
            or plan_ref.record_id is not None
        ):
            raise ValueError("CONTEXT_PLAN_CHANGED")
        action = self.runner.action(
            work,
            requester_identity,
            requester_role,
            "READ_CODE",
            input_refs=(*work.input_refs, plan_ref),
            file_paths=plan.file_paths,
            reason=intent.reason,
        )
        reservation = self.runner.reserve(
            work,
            budget_scope,
            action,
            self.runner.units(
                elapsed_ms=intent.requested_limits.timeout_ms,
                cost_minor_units=1,
            ),
        )
        decision_ref = self.runner.authorize(work, action, reservation)
        self.checkpoint("AUTHORIZED")
        used_ref = self.runtime.validator.claim_external(
            str(work.work_id), decision_ref, reference(reservation)
        )
        self.checkpoint("CLAIMED")
        request = self.runtime.context.bind(
            str(work.work_id),
            used_ref,
            requested_entities=plan.entities,
            requested_locations=plan.locations,
            relation_query=intent.relation_query,
            limits=intent.requested_limits,
        )
        self.checkpoint("REQUEST_BOUND")
        action_ref = reference(action)
        reservation_ref = reference(reservation)
        request_ref = reference(request)
        if (
            not isinstance(action_ref, StoredDataRef)
            or not isinstance(reservation_ref, StoredDataRef)
            or not isinstance(decision_ref, StoredDataRef)
            or not isinstance(used_ref, StoredDataRef)
            or not isinstance(request_ref, StoredDataRef)
        ):
            raise ValueError("CONTEXT_SCOPE_MISMATCH")
        return await self._execute_bound(
            work=work,
            intent=intent,
            workspace=workspace,
            bundle=bundle,
            ceilings=ceilings,
            lineage=lineage,
            plan=plan,
            plan_raw=plan_raw,
            plan_ref=plan_ref,
            action=action,
            action_ref=action_ref,
            issued_decision_ref=decision_ref,
            claimed_decision_ref=used_ref,
            reservation=reservation,
            request=request,
            request_ref=request_ref,
            service_identity=service_identity,
        )

    async def _execute_bound(
        self,
        *,
        work: WorkExecutionState,
        intent: ContextRetrievalIntent,
        workspace: CodeWorkspace,
        bundle: StaticFactBundle,
        ceilings: ContextCeilingProfile,
        lineage: ChainingContextRecords | None,
        plan: ContextReadPlan,
        plan_raw: bytes,
        plan_ref: StoredDataRef,
        action: ActionRequest,
        action_ref: StoredDataRef,
        issued_decision_ref: StoredDataRef,
        claimed_decision_ref: StoredDataRef,
        reservation: BudgetReservation,
        request: CodeContextRequest,
        request_ref: StoredDataRef,
        service_identity: BudgetScopeRef,
    ) -> tuple[CodeContextResponse, StoredDataRef]:
        """Execute only an exact claimed and request-bound READ_CODE closure."""
        self._require_unchanged(
            intent, bundle, workspace, work, ceilings, lineage, plan_raw
        )
        self.runtime.validator.mark_dispatched(
            issued_decision_ref, idempotency_key=str(action.action_id)
        )
        self.checkpoint("DISPATCHED")
        started_ns = self.monotonic_ns()
        deadline = MonotonicActionDeadline(
            action_id=str(action.action_id),
            started_ns=started_ns,
            expires_ns=started_ns + intent.requested_limits.timeout_ms * 1_000_000,
        )
        self._require_unchanged(
            intent, bundle, workspace, work, ceilings, lineage, plan_raw
        )
        integrity_receipts = list(
            await self.workspace_locator.assert_unchanged(
                workspace,
                deadline,
                attempt_id=str(work.active_attempt_id),
                check_id="pre-read",
            )
        )
        observation = read_context_files(
            plan=plan,
            workspace_root=self.workspace_locator.root_for(workspace),
            tracked_files=self.tracked_files_for(workspace),
            deadline=deadline,
            monotonic_ns=self.monotonic_ns,
            cancelled=lambda: self.runtime.work.get(str(work.work_id)) != work,
        )
        integrity_receipts.extend(
            await self.workspace_locator.assert_unchanged(
                workspace,
                deadline,
                attempt_id=str(work.active_attempt_id),
                check_id="post-read",
            )
        )
        self.workspace_locator.validate_integrity_receipts(
            workspace,
            deadline,
            attempt_id=str(work.active_attempt_id),
            check_ids=("pre-read", "post-read"),
            receipts=tuple(integrity_receipts),
        )
        elapsed_ms = max(0, (self.monotonic_ns() - started_ns) // 1_000_000)
        fragment_refs = tuple(
            self.runtime.unit_of_work.artifacts.commit(
                self.runtime.unit_of_work.artifacts.stage_bytes(
                    fragment.data, "text/plain; charset=utf-8"
                )
            )
            for fragment in observation.fragments
        )
        gaps, errors = self._diagnostics(work, observation)
        response = CodeContextResponse.model_validate_json(
            canonical_bytes(
                {
                    "meta": self.runner.metadata(
                        work.meta,
                        "code_context_response",
                        attempt_id=work.active_attempt_id,
                    ),
                    "code_request_id": request.code_request_id,
                    "entities": plan.entities,
                    "locations": tuple(item.location for item in observation.fragments),
                    "code_fragment_refs": fragment_refs,
                    "discovered_relations": plan.relations,
                    "gaps": gaps,
                    "errors": errors,
                    "truncated": observation.truncated,
                    "returned_fragment_count": len(fragment_refs),
                    "returned_bytes": observation.returned_bytes,
                    "consumed_token_estimate": None,
                }
            )
        )
        candidate = canonical_bytes(response)
        if len(candidate) > ceilings.limits.max_bytes:
            raise ValueError("CONTEXT_RESPONSE_TOO_LARGE")
        receipt, receipt_raw = self._write_receipt(
            action_id=str(action.action_id),
            action_ref=action_ref,
            work=work,
            attempt_id=str(work.active_attempt_id),
            decision_ref=claimed_decision_ref,
            request_ref=request_ref,
            plan_ref=plan_ref,
            plan=plan,
            response=response,
            candidate=candidate,
            elapsed_ms=elapsed_ms,
            process_receipts=tuple(integrity_receipts),
        )
        recovered, recovered_response, recovered_raw, recovered_process = (
            self._read_receipt(
                action_ref=action_ref,
                work=work,
                attempt_id=str(work.active_attempt_id),
                decision_ref=claimed_decision_ref,
                request_ref=request_ref,
                plan_ref=plan_ref,
                plan=plan,
                max_bytes=ceilings.limits.max_bytes,
            )
        )
        self.workspace_locator.validate_integrity_receipts(
            workspace,
            deadline,
            attempt_id=str(work.active_attempt_id),
            check_ids=("pre-read", "post-read"),
            receipts=recovered_process,
        )
        if (
            recovered != receipt
            or recovered_response != response
            or recovered_raw != receipt_raw
            or recovered_process != tuple(integrity_receipts)
        ):
            raise ValueError("CONTEXT_RECEIPT_INVALID")
        receipt_ref = self.runtime.unit_of_work.artifacts.commit(
            self.runtime.unit_of_work.artifacts.stage_bytes(
                receipt_raw, "application/json"
            )
        )
        if receipt_ref.content_hash != hashlib.sha256(receipt_raw).hexdigest():
            raise ValueError("CONTEXT_RECEIPT_INVALID")
        self.checkpoint("RECEIPT_DURABLE")
        self.runtime.validator.mark_returned(issued_decision_ref)
        self.checkpoint("RETURNED")
        self._account_once(reservation, elapsed_ms)
        self.checkpoint("ACCOUNTED")
        completed = self._complete(
            runtime=self.runtime,
            runner=self.runner,
            work=work,
            service_identity=service_identity,
            response=response,
            read_decision_ref=claimed_decision_ref,
            request_ref=request_ref,
            plan_ref=plan_ref,
            profile_ref=plan.ceiling_profile_ref,
            receipt_ref=receipt_ref,
            fragment_refs=fragment_refs,
        )
        output_ref = completed.output_refs[0]
        if not isinstance(output_ref, StoredDataRef) or output_ref != reference(
            response
        ):
            raise ValueError("CONTEXT_RESPONSE_COMMIT_MISMATCH")
        return response, output_ref

    @staticmethod
    def _complete(
        *,
        runtime: RuntimeServices,
        runner: WorkflowRunner,
        work: WorkExecutionState,
        service_identity: BudgetScopeRef,
        response: CodeContextResponse,
        read_decision_ref: StoredDataRef,
        request_ref: StoredDataRef,
        plan_ref: StoredDataRef,
        profile_ref: StoredDataRef,
        receipt_ref: StoredDataRef,
        fragment_refs: tuple[StoredDataRef, ...],
    ) -> WorkExecutionState:
        """Commit the exact returned/read/receipt closure in one SAVE_RESULT."""
        records = runtime.unit_of_work.records
        read_decision_ref = ContextRetrievalService._current_read_decision_ref(
            runtime, read_decision_ref, request_ref
        )
        response_ref = records.stage_record(response)
        inputs = tuple(
            dict.fromkeys(
                (
                    *work.input_refs,
                    read_decision_ref,
                    request_ref,
                    plan_ref,
                    profile_ref,
                    receipt_ref,
                    *fragment_refs,
                )
            )
        )
        save = runner.action(
            work,
            service_identity,
            "CONTEXT_RETRIEVAL_SERVICE",
            "SAVE_RESULT",
            input_refs=inputs,
            result_kind=response_ref.data_kind,
            candidate_result_ref=response_ref,
            reason="Publish one verified Context response closure",
        )
        decision_ref = runner.authorize(work, save)
        transition = StateTransition.model_validate_json(
            canonical_bytes(
                {
                    "meta": runner.metadata(
                        work.meta,
                        "state_transition",
                        attempt_id=work.active_attempt_id,
                    ),
                    "transition_id": runner.ids.new(TransitionId),
                    "work_id": work.work_id,
                    "action_decision_ref": decision_ref,
                    "from_status": work.status,
                    "to_status": "SUCCEEDED",
                    "expected_state_version": work.state_version,
                    "new_state_version": work.state_version + 1,
                    "attempt_id": work.active_attempt_id,
                    "cause": "COMPLETED",
                    "output_refs": (response_ref,),
                    "gap_ids": tuple(str(item.gap_id) for item in response.gaps),
                    "error_ids": tuple(str(item.error_id) for item in response.errors),
                    "dedupe_key": content_hash(
                        (work.work_id, work.state_version, response_ref)
                    ),
                    "created_at": runner.clock.now(),
                }
            )
        )
        commit = TransitionCommit.model_validate_json(
            canonical_bytes(
                {
                    "meta": runner.metadata(
                        work.meta,
                        "transition_commit",
                        attempt_id=work.active_attempt_id,
                    ),
                    "transition_commit_id": runner.ids.new(TransitionCommitId),
                    "work_id": work.work_id,
                    "transition_ref": records.stage_record(transition),
                    "expected_state_version": work.state_version,
                    "target_state_version": work.state_version + 1,
                    "attempt_id": work.active_attempt_id,
                    "target_status": "SUCCEEDED",
                    "output_refs": (response_ref,),
                    "gap_ids": transition.gap_ids,
                    "error_ids": transition.error_ids,
                    "state": "PREPARED",
                    "prepared_at": runner.clock.now(),
                    "committed_at": None,
                    "abort_reason": None,
                }
            )
        )
        runtime.transitions.commit(
            TransitionCommitRequest(transition, commit, (response,))
        )
        return runtime.work.get(str(work.work_id))

    @staticmethod
    def _current_read_decision_ref(
        runtime: RuntimeServices,
        claimed_ref: StoredDataRef,
        request_ref: StoredDataRef,
    ) -> StoredDataRef:
        claimed = runtime.unit_of_work.records.get_exact(claimed_ref)
        if not isinstance(claimed, ActionDecision):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        matches = tuple(
            item
            for item in runtime.queries.published_records(str(claimed.meta.analysis_id))
            if isinstance(item, ActionDecision)
            and item.decision_id == claimed.decision_id
            and item.action_ref == claimed.action_ref
            and item.decision == "ALLOW"
            and item.use_status == "USED"
            and request_ref in item.outcome_refs
        )
        if len(matches) != 1:
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        current_ref = reference(matches[0])
        if not isinstance(current_ref, StoredDataRef):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        return current_ref

    async def recover_pending(
        self,
        *,
        work: WorkExecutionState,
        intent: ContextRetrievalIntent,
        workspace: CodeWorkspace,
        bundle: StaticFactBundle,
        action_ref: StoredDataRef,
        decision_ref: StoredDataRef,
        reservation_ref: StoredDataRef,
        plan_ref: StoredDataRef,
        service_identity: BudgetScopeRef,
        work_timeout_ms: int,
    ) -> tuple[CodeContextResponse, StoredDataRef]:
        """Resume an exact authorized or claimed READ_CODE before dispatch."""
        self._require_service_identity(service_identity)
        current = self.runtime.work.get(str(work.work_id))
        if (
            current != work
            or work.active_attempt_id is None
            or not isinstance(work.meta, RecordMeta)
        ):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        records = self.runtime.unit_of_work.records
        action = records.get_exact(action_ref)
        supplied_decision = records.get_exact(decision_ref)
        reservation = records.get_exact(reservation_ref)
        if (
            not isinstance(action, ActionRequest)
            or not isinstance(supplied_decision, ActionDecision)
            or not isinstance(reservation, BudgetReservation)
            or not isinstance(action.meta, RecordMeta)
            or action.action_type != "READ_CODE"
            or action.work_ref != reference(work)
            or action.expected_state_version != work.state_version
            or action.meta.attempt_id != work.active_attempt_id
            or action.input_refs != (*work.input_refs, plan_ref)
            or action.reason != intent.reason
            or reservation.status != ReservationStatus.RESERVED
            or reservation.action_ref != action_ref
            or reservation.work_ref != reference(work)
            or supplied_decision.action_ref != action_ref
            or supplied_decision.decision != Decision.ALLOW
        ):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        try:
            initial_dispatch_state = context_dispatch_state(
                records,
                action_id=str(action.action_id),
                work_id=str(work.work_id),
                attempt_id=str(work.active_attempt_id),
            )
        except ValueError:
            initial_dispatch_state = None
        if initial_dispatch_state == "DISPATCHED":
            self._block_uncertain_context(work)
        if initial_dispatch_state == "RETURNED":
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        ceilings = resolve_context_ceiling(self.runtime.unit_of_work.artifacts, work)
        try:
            with self.runtime.unit_of_work.artifacts.open_verified(plan_ref) as stream:
                plan_raw = stream.read(ceilings.limits.max_bytes + 1)
            if len(plan_raw) > ceilings.limits.max_bytes:
                raise ValueError
            plan = decode_context_read_plan(plan_raw)
        except (OSError, ValueError) as error:
            raise ValueError("CONTEXT_RECOVERY_INVALID") from error
        lineage = self._lineage(intent)
        if (
            hashlib.sha256(plan_raw).hexdigest() != plan_ref.content_hash
            or str(plan_ref.stored_data_id) != plan_ref.content_hash
            or plan_ref.record_id is not None
            or action.file_paths != plan.file_paths
            or plan.ceiling_profile_ref != ceilings.ref
        ):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        self._require_recovery_inputs(intent, workspace, bundle, work)
        recomputed = plan_context_retrieval(
            intent=intent,
            bundle=bundle,
            workspace=workspace,
            work=work,
            ceilings=ceilings,
            work_timeout_ms=work_timeout_ms,
            lineage=lineage,
        )
        if encode_context_read_plan(recomputed) != plan_raw:
            raise ValueError("CONTEXT_PLAN_CHANGED")

        decisions = tuple(
            sorted(
                (
                    item
                    for item in self.runtime.queries.published_records(
                        str(work.meta.analysis_id)
                    )
                    if isinstance(item, ActionDecision)
                    and item.decision_id == supplied_decision.decision_id
                    and item.action_ref == action_ref
                ),
                key=lambda item: item.meta.revision_number,
            )
        )
        decision_refs = tuple(reference(item) for item in decisions)
        issued = tuple(
            item for item in decisions if item.use_status == UseStatus.UNUSED
        )
        used = tuple(item for item in decisions if item.use_status == UseStatus.USED)
        if (
            decision_ref not in decision_refs
            or len(issued) != 1
            or issued[0].decision != Decision.ALLOW
            or issued[0].valid_until is None
            or not issued[0].decided_at
            <= self.runner.clock.now()
            <= issued[0].valid_until
            or any(
                item.decision != Decision.ALLOW
                or item.valid_until != issued[0].valid_until
                or item.checked_state_version != work.state_version
                for item in decisions
            )
        ):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        issued_ref = reference(issued[0])
        if not isinstance(issued_ref, StoredDataRef):
            raise ValueError("CONTEXT_RECOVERY_INVALID")

        if not used:
            if decision_ref != issued_ref:
                raise ValueError("CONTEXT_RECOVERY_INVALID")
            self._require_request_capacity(
                work, ceilings.limits.max_requests_per_hypothesis
            )
            claimed_ref = self.runtime.validator.claim_external(
                str(work.work_id), issued_ref, reservation_ref
            )
            if not isinstance(claimed_ref, StoredDataRef):
                raise ValueError("CONTEXT_RECOVERY_INVALID")
        else:
            if len(used) not in {1, 2}:
                raise ValueError("CONTEXT_RECOVERY_INVALID")
            claimed = tuple(item for item in used if not item.outcome_refs)
            completed = tuple(item for item in used if item.outcome_refs)
            if (
                len(claimed) != 1
                or len(completed) > 1
                or any(
                    len(item.outcome_refs) != 1
                    or item.outcome_refs[0].data_kind != "code_context_request"
                    for item in completed
                )
            ):
                raise ValueError("CONTEXT_RECOVERY_INVALID")
            claimed_ref = reference(claimed[0])
            if not isinstance(claimed_ref, StoredDataRef):
                raise ValueError("CONTEXT_RECOVERY_INVALID")

        dispatch_state = context_dispatch_state(
            records,
            action_id=str(action.action_id),
            work_id=str(work.work_id),
            attempt_id=str(work.active_attempt_id),
        )
        if dispatch_state == "DISPATCHED":
            self._block_uncertain_context(work)
        if dispatch_state != "PREPARED":
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        request = self.runtime.context.bind(
            str(work.work_id),
            claimed_ref,
            requested_entities=plan.entities,
            requested_locations=plan.locations,
            relation_query=intent.relation_query,
            limits=intent.requested_limits,
        )
        request_ref = reference(request)
        if not isinstance(request_ref, StoredDataRef):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        self._require_unchanged(
            intent, bundle, workspace, work, ceilings, lineage, plan_raw
        )
        return await self._execute_bound(
            work=work,
            intent=intent,
            workspace=workspace,
            bundle=bundle,
            ceilings=ceilings,
            lineage=lineage,
            plan=plan,
            plan_raw=plan_raw,
            plan_ref=plan_ref,
            action=action,
            action_ref=action_ref,
            issued_decision_ref=issued_ref,
            claimed_decision_ref=claimed_ref,
            reservation=reservation,
            request=request,
            request_ref=request_ref,
            service_identity=service_identity,
        )

    def _require_recovery_inputs(
        self,
        intent: ContextRetrievalIntent,
        workspace: CodeWorkspace,
        bundle: StaticFactBundle,
        work: WorkExecutionState,
    ) -> None:
        """Fail closed unless all caller-supplied inputs are still exact/current."""
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("CONTEXT_INPUT_MISMATCH")
        exact_proposal = self.runtime.unit_of_work.records.get_exact(
            intent.proposal_ref
        )
        exact_bundle = self.runtime.unit_of_work.records.get_exact(intent.bundle_ref)
        run_state = self.runtime.budget_registry.current_state(
            str(work.meta.analysis_id)
        )
        if (
            not isinstance(exact_proposal, HypothesisProposal)
            or exact_bundle != bundle
            or reference(bundle) != intent.bundle_ref
            or bundle
            not in self.runtime.queries.current_records(
                str(work.meta.analysis_id), "static_fact_bundle"
            )
            or exact_proposal
            not in self.runtime.queries.current_records(
                str(work.meta.analysis_id), "hypothesis_proposal"
            )
            or run_state.workspace_ref != reference(workspace)
            or self.runtime.unit_of_work.records.get_exact(run_state.workspace_ref)
            != workspace
            or exact_proposal.meta.hypothesis_id != work.meta.hypothesis_id
            or work.input_refs.count(intent.proposal_ref) != 1
            or work.input_refs.count(intent.bundle_ref) != 1
        ):
            raise ValueError("CONTEXT_INPUT_MISMATCH")

    def _require_service_identity(self, service_identity: BudgetScopeRef) -> None:
        records = self.runtime.unit_of_work.records
        if (
            not isinstance(records, SQLiteRecordStore)
            or records.evidence.identity_role(service_identity)
            != RequesterRole.CONTEXT_RETRIEVAL_SERVICE
        ):
            raise ValueError("CONTEXT_AUTHORITY_MISMATCH")
        records.get_exact(service_identity)

    def _block_uncertain_context(self, work: WorkExecutionState) -> None:
        recovery = self.runtime.recovery.recovery
        if not isinstance(recovery, SQLiteRecoveryService):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        recovery.block_uncertain(work)
        blocked = self.runtime.work.get(str(work.work_id))
        if (
            blocked.status != "BLOCKED"
            or blocked.waiting_for != ("INPUT",)
            or blocked.stop_reason != "RECOVERY_FAILED"
        ):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        raise ValueError("CONTEXT_RECOVERY_UNCERTAIN")

    def _require_receipt_recovery_closure(
        self,
        *,
        work: WorkExecutionState,
        action_ref: StoredDataRef,
        issued_decision_ref: StoredDataRef,
        claimed_decision_ref: StoredDataRef,
        reservation_ref: StoredDataRef,
        request_ref: StoredDataRef,
        plan_ref: StoredDataRef,
        service_identity: BudgetScopeRef,
    ) -> tuple[
        ActionRequest,
        BudgetReservation,
        ContextCeilingProfile,
        ContextReadPlan,
        CodeWorkspace,
    ]:
        """Resolve and revalidate the complete authorized receipt closure."""
        self._require_service_identity(service_identity)
        if work.active_attempt_id is None or not isinstance(work.meta, RecordMeta):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        records = self.runtime.unit_of_work.records
        if not isinstance(records, SQLiteRecordStore):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        work_ref = reference(work)
        action = records.get_exact(action_ref)
        issued = records.get_exact(issued_decision_ref)
        claimed = records.get_exact(claimed_decision_ref)
        reservation = records.get_exact(reservation_ref)
        request = records.get_exact(request_ref)
        if (
            records.get_exact(work_ref) != work
            or not isinstance(action, ActionRequest)
            or not isinstance(action.meta, RecordMeta)
            or not isinstance(issued, ActionDecision)
            or not isinstance(claimed, ActionDecision)
            or not isinstance(reservation, BudgetReservation)
            or not isinstance(request, CodeContextRequest)
            or action.action_type != ActionType.READ_CODE
            or action.work_ref != work_ref
            or action.expected_state_version != work.state_version
            or action.meta.attempt_id != work.active_attempt_id
            or issued.action_ref != action_ref
            or claimed.action_ref != action_ref
            or issued.decision != Decision.ALLOW
            or issued.use_status != UseStatus.UNUSED
            or issued.outcome_refs
            or claimed.decision != Decision.ALLOW
            or claimed.use_status != UseStatus.USED
            or claimed.outcome_refs
            or request.action_decision_ref != claimed_decision_ref
            or request.reason != action.reason
        ):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        try:
            validate_decision_for_action(issued, ActionType.READ_CODE)
            validate_decision_for_action(claimed, ActionType.READ_CODE)
            validate_decision_revision(issued, claimed)
        except ValueError as error:
            raise ValueError("CONTEXT_RECOVERY_INVALID") from error

        with records.database.engine.connect() as connection:
            action_row = (
                connection.execute(
                    select(models.action_requests).where(
                        models.action_requests.c.action_id == str(action.action_id)
                    )
                )
                .mappings()
                .one_or_none()
            )
            current_decision_wire = connection.execute(
                select(models.action_decisions.c.payload).where(
                    models.action_decisions.c.action_id == str(action.action_id)
                )
            ).scalar_one_or_none()
            reservation_row = (
                connection.execute(
                    select(models.budget_reservations).where(
                        models.budget_reservations.c.reservation_id
                        == str(reservation.reservation_id)
                    )
                )
                .mappings()
                .one_or_none()
            )
            dispatch = (
                connection.execute(
                    select(models.external_dispatches).where(
                        models.external_dispatches.c.action_id == str(action.action_id)
                    )
                )
                .mappings()
                .one_or_none()
            )
        try:
            durable_issued_ref = (
                REF_ADAPTER.validate_json(action_row["decision_ref"])
                if action_row is not None
                else None
            )
            durable_action_ref = (
                REF_ADAPTER.validate_json(action_row["request_ref"])
                if action_row is not None
                else None
            )
            current_decision = (
                ActionDecision.model_validate_json(current_decision_wire)
                if current_decision_wire is not None
                else None
            )
            initial_reservation_ref = (
                REF_ADAPTER.validate_json(reservation_row["initial_ref"])
                if reservation_row is not None
                else None
            )
            current_reservation = (
                BudgetReservation.model_validate_json(reservation_row["payload"])
                if reservation_row is not None
                else None
            )
        except ValueError as error:
            raise ValueError("CONTEXT_RECOVERY_INVALID") from error
        if (
            durable_action_ref != action_ref
            or durable_issued_ref != issued_decision_ref
            or not isinstance(current_decision, ActionDecision)
            or initial_reservation_ref != reservation_ref
            or not isinstance(current_reservation, BudgetReservation)
            or dispatch is None
            or dispatch["work_id"] != str(work.work_id)
            or dispatch["attempt_id"] != str(work.active_attempt_id)
            or REF_ADAPTER.validate_json(dispatch["decision_ref"])
            != issued_decision_ref
            or REF_ADAPTER.validate_json(dispatch["reservation_ref"]) != reservation_ref
            or dispatch["dispatched_at"] is None
        ):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        try:
            validate_decision_for_action(current_decision, ActionType.READ_CODE)
            validate_decision_revision(claimed, current_decision)
        except ValueError as error:
            raise ValueError("CONTEXT_RECOVERY_INVALID") from error
        if (
            current_decision.decision != Decision.ALLOW
            or current_decision.use_status != UseStatus.USED
            or current_decision.outcome_refs != (request_ref,)
            or reservation.status != ReservationStatus.RESERVED
            or reservation.action_ref != action_ref
            or reservation.work_ref != work_ref
            or reservation.budget_binding_ref
            != self.runtime.budget_registry.current_state(
                str(work.meta.analysis_id)
            ).budget_binding_ref
            or current_reservation.status
            not in {ReservationStatus.RESERVED, ReservationStatus.COMMITTED}
        ):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        if current_reservation != reservation:
            try:
                validate_reservation_revision(reservation, current_reservation)
            except ValueError as error:
                raise ValueError("CONTEXT_RECOVERY_INVALID") from error
            if current_reservation.status != ReservationStatus.COMMITTED:
                raise ValueError("CONTEXT_RECOVERY_INVALID")

        ceiling = resolve_context_ceiling(self.runtime.unit_of_work.artifacts, work)
        try:
            with self.runtime.unit_of_work.artifacts.open_verified(plan_ref) as stream:
                plan_raw = stream.read(ceiling.limits.max_bytes + 1)
            if len(plan_raw) > ceiling.limits.max_bytes:
                raise ValueError
            plan = decode_context_read_plan(plan_raw)
        except (OSError, ValueError) as error:
            raise ValueError("CONTEXT_RECOVERY_INVALID") from error
        if (
            plan_ref.record_id is not None
            or str(plan_ref.stored_data_id) != plan_ref.content_hash
            or plan_ref.content_hash != hashlib.sha256(plan_raw).hexdigest()
            or plan.ceiling_profile_ref != ceiling.ref
            or action.input_refs != (*work.input_refs, plan_ref)
            or action.file_paths != plan.file_paths
            or request.requested_entities != plan.entities
            or request.requested_locations != plan.locations
            or request.limits != plan.requested_limits
            or request
            not in self.runtime.queries.current_records(
                str(work.meta.analysis_id), "code_context_request"
            )
        ):
            raise ValueError("CONTEXT_RECOVERY_INVALID")

        intent = ContextRetrievalIntent(
            proposal_ref=plan.proposal_ref,
            bundle_ref=plan.bundle_ref,
            requested_entities=request.requested_entities,
            requested_locations=request.requested_locations,
            relation_query=request.relation_query,
            reason=action.reason,
            requested_limits=request.limits,
        )
        run_state = self.runtime.budget_registry.current_state(
            str(work.meta.analysis_id)
        )
        if run_state.workspace_ref is None:
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        workspace = records.get_exact(run_state.workspace_ref)
        bundle = records.get_exact(intent.bundle_ref)
        if not isinstance(workspace, CodeWorkspace) or not isinstance(
            bundle, StaticFactBundle
        ):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        try:
            self._require_recovery_inputs(intent, workspace, bundle, work)
            lineage = self._lineage(intent)
            recomputed = plan_context_retrieval(
                intent=intent,
                bundle=bundle,
                workspace=workspace,
                work=work,
                ceilings=ceiling,
                work_timeout_ms=request.limits.timeout_ms,
                lineage=lineage,
            )
        except ValueError as error:
            raise ValueError("CONTEXT_RECOVERY_INVALID") from error
        if (
            encode_context_read_plan(recomputed) != plan_raw
            or context_intent_hash(intent) != plan.intent_hash
        ):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        return action, reservation, ceiling, plan, workspace

    def recover_after_receipt(
        self,
        *,
        work: WorkExecutionState,
        action_ref: StoredDataRef,
        issued_decision_ref: StoredDataRef,
        claimed_decision_ref: StoredDataRef,
        reservation_ref: StoredDataRef,
        request_ref: StoredDataRef,
        plan_ref: StoredDataRef,
        service_identity: BudgetScopeRef,
    ) -> tuple[CodeContextResponse, StoredDataRef]:
        """Resume a complete receipt without another integrity or source read."""
        (
            action,
            reservation,
            ceiling,
            plan,
            workspace,
        ) = self._require_receipt_recovery_closure(
            work=work,
            action_ref=action_ref,
            issued_decision_ref=issued_decision_ref,
            claimed_decision_ref=claimed_decision_ref,
            reservation_ref=reservation_ref,
            request_ref=request_ref,
            plan_ref=plan_ref,
            service_identity=service_identity,
        )
        receipt, response, receipt_raw, process_receipts = self._read_receipt(
            action_ref=action_ref,
            work=work,
            attempt_id=str(work.active_attempt_id),
            decision_ref=claimed_decision_ref,
            request_ref=request_ref,
            plan_ref=plan_ref,
            plan=plan,
            max_bytes=ceiling.limits.max_bytes,
        )
        recovery_deadline = MonotonicActionDeadline(
            action_id=str(action.action_id), started_ns=0, expires_ns=1
        )
        self.workspace_locator.validate_integrity_receipts(
            workspace,
            recovery_deadline,
            attempt_id=str(work.active_attempt_id),
            check_ids=("pre-read", "post-read"),
            receipts=process_receipts,
        )
        receipt_ref = self.runtime.unit_of_work.artifacts.commit(
            self.runtime.unit_of_work.artifacts.stage_bytes(
                receipt_raw, "application/json"
            )
        )
        current = self.runtime.work.get(str(work.work_id))
        response_ref = reference(response)
        if current.status == "SUCCEEDED":
            if current.output_refs != (response_ref,):
                raise ValueError("CONTEXT_RECOVERY_INVALID")
            if not isinstance(response_ref, StoredDataRef):
                raise ValueError("CONTEXT_RECOVERY_INVALID")
            return response, response_ref
        if current != work:
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        phase = context_dispatch_state(
            self.runtime.unit_of_work.records,
            action_id=str(action.action_id),
            work_id=str(work.work_id),
            attempt_id=str(work.active_attempt_id),
        )
        if phase == "PREPARED":
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        if phase == "DISPATCHED":
            self.runtime.validator.mark_returned(issued_decision_ref)
        self._account_once(reservation, receipt.elapsed_ms)
        completed = self._complete(
            runtime=self.runtime,
            runner=self.runner,
            work=work,
            service_identity=service_identity,
            response=response,
            read_decision_ref=claimed_decision_ref,
            request_ref=request_ref,
            plan_ref=plan_ref,
            profile_ref=ceiling.ref,
            receipt_ref=receipt_ref,
            fragment_refs=response.code_fragment_refs,
        )
        output_ref = completed.output_refs[0]
        if not isinstance(output_ref, StoredDataRef):
            raise ValueError("CONTEXT_RECOVERY_INVALID")
        return response, output_ref

    def _require_request_capacity(self, work: WorkExecutionState, maximum: int) -> None:
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("CONTEXT_SCOPE_MISMATCH")
        requests = tuple(
            item
            for item in self.runtime.queries.published_records(
                str(work.meta.analysis_id)
            )
            if isinstance(item, CodeContextRequest)
            and item.meta.hypothesis_id == work.meta.hypothesis_id
        )
        request_ids = {str(item.code_request_id) for item in requests}
        if len(request_ids) >= maximum:
            raise ValueError("CONTEXT_REQUEST_LIMIT_EXCEEDED")

    def _lineage(self, intent: ContextRetrievalIntent) -> ChainingContextRecords | None:
        records = self.runtime.unit_of_work.records
        proposal = records.get_exact(intent.proposal_ref)
        source_match = getattr(proposal, "source_primitive_match_id", None)
        if source_match is None:
            return None
        if self.lineage_reader is None:
            raise ValueError("CONTEXT_LINEAGE_READER_REQUIRED")
        return self.lineage_reader.read_for(intent.proposal_ref, str(source_match))

    def _require_unchanged(
        self,
        intent: ContextRetrievalIntent,
        bundle: StaticFactBundle,
        workspace: CodeWorkspace,
        work: WorkExecutionState,
        ceilings: ContextCeilingProfile,
        lineage: ChainingContextRecords | None,
        expected: bytes,
    ) -> None:
        current = self.runtime.work.get(str(work.work_id))
        current_ceiling = resolve_context_ceiling(
            self.runtime.unit_of_work.artifacts, current
        )
        if current != work or current_ceiling != ceilings:
            raise ValueError("CONTEXT_PROFILE_CHANGED")
        recomputed = plan_context_retrieval(
            intent=intent,
            bundle=bundle,
            workspace=workspace,
            work=current,
            ceilings=current_ceiling,
            work_timeout_ms=intent.requested_limits.timeout_ms,
            lineage=self._lineage(intent) if lineage is not None else None,
        )
        if encode_context_read_plan(recomputed) != expected:
            raise ValueError("CONTEXT_PLAN_CHANGED")

    def _diagnostics(
        self, work: WorkExecutionState, observation: ContextReadObservation
    ) -> tuple[tuple[DataGap, ...], tuple[AnalysisError, ...]]:
        failed_paths = observation.failed_paths
        replacement_paths = observation.replacement_paths
        truncated = observation.truncated
        now = self.runner.clock.now()
        gaps: list[DataGap] = []
        errors: list[AnalysisError] = []
        if truncated:
            gaps.append(
                DataGap(
                    gap_id=self.runner.ids.new(GapId),
                    stage="CONTEXT",
                    code="CONTEXT_TRUNCATED",
                    reason="TRUNCATED",
                    description="Authorized Context limits stopped the next read.",
                    affected_paths=(),
                    affected_languages=(),
                    affected_locations=(),
                    retryable=False,
                    related_record_ids=(),
                    created_at=now,
                )
            )
        for path in failed_paths:
            error_id = self.runner.ids.new(ErrorId)
            errors.append(
                AnalysisError(
                    error_id=error_id,
                    stage="CONTEXT",
                    code="CONTEXT_READ_FAILED",
                    safe_message="An authorized tracked file could not be read safely.",
                    retryable=False,
                    work_id=work.work_id,
                    attempt_id=work.active_attempt_id,
                    related_record_ids=(),
                    created_at=now,
                )
            )
            gaps.append(
                DataGap(
                    gap_id=self.runner.ids.new(GapId),
                    stage="CONTEXT",
                    code="CONTEXT_READ_FAILED",
                    reason="FAILED",
                    description="A tracked code path failed its safe-read checks.",
                    affected_paths=(path,),
                    affected_languages=(),
                    affected_locations=(),
                    retryable=False,
                    related_record_ids=(str(error_id),),
                    created_at=now,
                )
            )
        for path in replacement_paths:
            gaps.append(
                DataGap(
                    gap_id=self.runner.ids.new(GapId),
                    stage="CONTEXT",
                    code="CONTEXT_UTF8_REPLACED",
                    reason="UNSUPPORTED",
                    description="Invalid UTF-8 bytes were explicitly replaced.",
                    affected_paths=(path,),
                    affected_languages=(),
                    affected_locations=(),
                    retryable=False,
                    related_record_ids=(),
                    created_at=now,
                )
            )
        return tuple(gaps), tuple(errors)

    def _account_once(self, reservation: BudgetReservation, elapsed_ms: int) -> None:
        reservation_ref = reference(reservation)
        entries = tuple(
            item
            for item in self.runtime.queries.published_records(
                str(reservation.meta.analysis_id)
            )
            if getattr(item, "reservation_ref", None) == reservation_ref
        )
        actual = self.runner.units(elapsed_ms=elapsed_ms, cost_minor_units=1)
        if entries:
            if len(entries) != 1 or getattr(entries[0], "actual_units", None) != actual:
                raise ValueError("CONTEXT_ACCOUNTING_MISMATCH")
            return
        self.runner.account(reservation, actual)

    def _write_receipt(
        self,
        *,
        action_id: str,
        action_ref: StoredDataRef,
        work: WorkExecutionState,
        attempt_id: str,
        decision_ref: StoredDataRef,
        request_ref: StoredDataRef,
        plan_ref: StoredDataRef,
        plan: ContextReadPlan,
        response: CodeContextResponse,
        candidate: bytes,
        elapsed_ms: int,
        process_receipts: tuple[ProcessReceipt, ...],
    ) -> tuple[StaticActionReceipt, bytes]:
        self.receipt_root.mkdir(parents=True, exist_ok=True)
        if self.receipt_root.is_symlink():
            raise ValueError("CONTEXT_RECEIPT_INVALID")
        root = self.receipt_root.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("CONTEXT_RECEIPT_INVALID")
        self._validate_process_receipts(action_id, attempt_id, process_receipts)
        prefix = hashlib.sha256(str(action_ref.record_id).encode()).hexdigest()[:24]
        observation_name = prefix + ".context.json"
        self._atomic_write(root / observation_name, candidate)
        process_hashes: list[str] = []
        for process_receipt in process_receipts:
            raw = canonical_bytes(asdict(process_receipt))
            digest = hashlib.sha256(raw).hexdigest()
            self._atomic_write(root / f"{digest}.process.json", raw)
            process_hashes.append(digest)
        fingerprint = self._input_fingerprint(
            action_ref=action_ref,
            work=work,
            attempt_id=attempt_id,
            decision_ref=decision_ref,
            request_ref=request_ref,
            plan_ref=plan_ref,
            plan=plan,
        )
        receipt = StaticActionReceipt(
            action_id=action_id,
            attempt_id=attempt_id,
            operation_kind="CONTEXT_READ",
            input_fingerprint=fingerprint,
            process_receipt_hashes=tuple(process_hashes),
            observation_name=observation_name,
            observation_size=len(candidate),
            observation_sha256=hashlib.sha256(candidate).hexdigest(),
            elapsed_ms=elapsed_ms,
        )
        receipt_raw = canonical_bytes(asdict(receipt))
        self._atomic_write(root / (prefix + ".receipt.json"), receipt_raw)
        if response.returned_fragment_count != len(response.code_fragment_refs):
            raise ValueError("CONTEXT_RECEIPT_INVALID")
        return receipt, receipt_raw

    @staticmethod
    def _input_fingerprint(
        *,
        action_ref: StoredDataRef,
        work: WorkExecutionState,
        attempt_id: str,
        decision_ref: StoredDataRef,
        request_ref: StoredDataRef,
        plan_ref: StoredDataRef,
        plan: ContextReadPlan,
    ) -> str:
        return hashlib.sha256(
            canonical_bytes(
                (
                    "context_read_v1",
                    action_ref,
                    reference(work),
                    attempt_id,
                    decision_ref,
                    request_ref,
                    plan_ref,
                    plan.ceiling_profile_ref,
                    plan.proposal_ref,
                    plan.bundle_ref,
                    plan.lineage_refs,
                    tuple(sorted(plan.file_paths)),
                )
            )
        ).hexdigest()

    def _read_receipt(
        self,
        *,
        action_ref: StoredDataRef,
        work: WorkExecutionState,
        attempt_id: str,
        decision_ref: StoredDataRef,
        request_ref: StoredDataRef,
        plan_ref: StoredDataRef,
        plan: ContextReadPlan,
        max_bytes: int,
    ) -> tuple[
        StaticActionReceipt,
        CodeContextResponse,
        bytes,
        tuple[ProcessReceipt, ...],
    ]:
        try:
            root = self.receipt_root.resolve(strict=True)
            if self.receipt_root.is_symlink() or not root.is_dir():
                raise ValueError
            action = self.runtime.unit_of_work.records.get_exact(action_ref)
            if not isinstance(action, ActionRequest):
                raise ValueError
            prefix = hashlib.sha256(str(action_ref.record_id).encode()).hexdigest()[:24]
            raw = _guarded_read(root / (prefix + ".receipt.json"), _MAX_RECEIPT_BYTES)
            value = json.loads(raw)
            if not isinstance(value, dict) or set(value) != set(
                StaticActionReceipt.__dataclass_fields__
            ):
                raise ValueError
            receipt = TypeAdapter(StaticActionReceipt).validate_python(value)
            expected_fingerprint = self._input_fingerprint(
                action_ref=action_ref,
                work=work,
                attempt_id=attempt_id,
                decision_ref=decision_ref,
                request_ref=request_ref,
                plan_ref=plan_ref,
                plan=plan,
            )
            if (
                canonical_bytes(asdict(receipt)) != raw
                or receipt.action_id != str(action.action_id)
                or receipt.attempt_id != attempt_id
                or receipt.operation_kind != "CONTEXT_READ"
                or receipt.input_fingerprint != expected_fingerprint
                or receipt.observation_name != prefix + ".context.json"
                or receipt.observation_size > max_bytes
                or receipt.lease_id is not None
            ):
                raise ValueError
            candidate = _guarded_read(root / receipt.observation_name, max_bytes)
            if (
                len(candidate) != receipt.observation_size
                or hashlib.sha256(candidate).hexdigest() != receipt.observation_sha256
            ):
                raise ValueError
            response = CodeContextResponse.model_validate_json(candidate)
            if canonical_bytes(response) != candidate:
                raise ValueError
            process_receipts: list[ProcessReceipt] = []
            for digest in receipt.process_receipt_hashes:
                if not re.fullmatch(r"[0-9a-f]{64}", digest):
                    raise ValueError
                process_raw = _guarded_read(
                    root / f"{digest}.process.json", _MAX_RECEIPT_BYTES
                )
                if hashlib.sha256(process_raw).hexdigest() != digest:
                    raise ValueError
                process_value = json.loads(process_raw)
                if not isinstance(process_value, dict) or set(process_value) != set(
                    ProcessReceipt.__dataclass_fields__
                ):
                    raise ValueError
                process_receipt = TypeAdapter(ProcessReceipt).validate_python(
                    process_value
                )
                if canonical_bytes(asdict(process_receipt)) != process_raw:
                    raise ValueError
                process_receipts.append(process_receipt)
            self._validate_process_receipts(
                str(action.action_id), attempt_id, tuple(process_receipts)
            )
            request = self.runtime.unit_of_work.records.get_exact(request_ref)
            if (
                not isinstance(request, CodeContextRequest)
                or response.code_request_id != request.code_request_id
                or response.meta.attempt_id != work.active_attempt_id
                or request.meta.attempt_id != work.active_attempt_id
                or any(
                    getattr(response.meta, name) != getattr(work.meta, name)
                    or getattr(request.meta, name) != getattr(work.meta, name)
                    for name in (
                        "analysis_id",
                        "workspace_id",
                        "commit_id",
                        "hypothesis_id",
                    )
                )
            ):
                raise ValueError
            returned_bytes = 0
            for fragment_ref in response.code_fragment_refs:
                if (
                    fragment_ref.record_id is not None
                    or fragment_ref.workspace_id != response.meta.workspace_id
                    or fragment_ref.commit_id != response.meta.commit_id
                ):
                    raise ValueError
                with self.runtime.unit_of_work.artifacts.open_verified(
                    fragment_ref
                ) as stream:
                    fragment = stream.read(max_bytes + 1)
                if len(fragment) > max_bytes:
                    raise ValueError
                returned_bytes += len(fragment)
            if (
                response.returned_fragment_count != len(response.code_fragment_refs)
                or response.returned_bytes != returned_bytes
                or returned_bytes > max_bytes
            ):
                raise ValueError
            return receipt, response, raw, tuple(process_receipts)
        except (
            AttributeError,
            OSError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            raise ValueError("CONTEXT_RECEIPT_INVALID") from error

    @staticmethod
    def _validate_process_receipts(
        action_id: str,
        attempt_id: str,
        process_receipts: tuple[ProcessReceipt, ...],
    ) -> None:
        kinds = tuple(item.command_kind for item in process_receipts)
        if kinds != _INTEGRITY_SEQUENCE + _INTEGRITY_SEQUENCE:
            raise ValueError("CONTEXT_RECEIPT_INVALID")
        check_ids = ("pre-read",) * len(_INTEGRITY_SEQUENCE) + ("post-read",) * len(
            _INTEGRITY_SEQUENCE
        )
        for item, check_id in zip(process_receipts, check_ids, strict=True):
            if (
                item.action_id != action_id
                or item.attempt_id != attempt_id
                or item.invocation_id
                != (
                    f"{action_id}:workspace-guard:{check_id}:"
                    f"{item.command_kind.removeprefix('guard-')}"
                )
                or item.outcome != "SUCCEEDED"
                or item.return_code != 0
                or not re.fullmatch(r"[0-9a-f]{64}", item.command_fingerprint)
                or not re.fullmatch(r"[0-9a-f]{64}", item.stdout_sha256)
                or not re.fullmatch(r"[0-9a-f]{64}", item.stderr_sha256)
                or Path(item.stdout_name).name != item.stdout_name
                or Path(item.stderr_name).name != item.stderr_name
            ):
                raise ValueError("CONTEXT_RECEIPT_INVALID")

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        if path.exists() or path.is_symlink():
            existing = _guarded_read(path, max(len(data), _MAX_RECEIPT_BYTES))
            if existing != data:
                raise ValueError("CONTEXT_RECEIPT_INVALID")
            return
        temporary = path.with_suffix(path.suffix + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            written = os.write(descriptor, data)
            if written != len(data):
                raise ValueError("CONTEXT_RECEIPT_INVALID")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)


def retrieve_fake_context(
    *,
    runtime: RuntimeServices,
    runner: WorkflowRunner,
    evidence: FakeEvidence,
    scope: StoredDataRef,
    identity: StoredDataRef,
    service_identity: StoredDataRef,
    metadata: RecordMetadata,
    hypothesis_id: str,
    generation: int,
    inputs: tuple[StoredDataRef, ...],
    location: CodeLocation,
    fragment_ref: StoredDataRef,
) -> tuple[CodeContextResponse, StoredDataRef]:
    evidence.bind_identity(identity, RequesterRole.VERIFICATION)
    limits = ContextRetrievalLimits(
        max_depth=1,
        max_fragments=1,
        max_bytes=4096,
        max_requests_per_hypothesis=1,
        timeout_ms=1000,
    )
    ceiling_ref = runtime.unit_of_work.artifacts.commit(
        runtime.unit_of_work.artifacts.stage_bytes(
            canonical_bytes(
                {
                    "kind": "context_ceiling_profile",
                    "schema_version": "1.0",
                    **limits.model_dump(),
                }
            ),
            "application/json",
        )
    )
    intent = ContextRetrievalIntent(
        proposal_ref=inputs[0],
        bundle_ref=inputs[1],
        requested_entities=(),
        requested_locations=(location,),
        relation_query=("CALLERS", "CALLEES"),
        reason="Retrieve fake same-commit context",
        requested_limits=limits,
    )
    plan = ContextReadPlan(
        intent_hash=context_intent_hash(intent),
        workspace_id=str(location.workspace_id),
        commit_id=str(location.commit_id),
        proposal_ref=intent.proposal_ref,
        bundle_ref=intent.bundle_ref,
        ceiling_profile_ref=ceiling_ref,
        requested_limits=limits,
        entities=(),
        locations=(location,),
        relations=(),
        file_paths=(str(location.file_path),),
        lineage_refs=(),
    )
    plan_ref = runtime.unit_of_work.artifacts.commit(
        runtime.unit_of_work.artifacts.stage_bytes(
            encode_context_read_plan(plan), "application/json"
        )
    )
    work = runner.start(
        scope,
        metadata,
        "CONTEXT_RETRIEVAL",
        "HYPOTHESIS",
        hypothesis_id,
        identity,
        role="VERIFICATION",
        inputs=(*inputs, ceiling_ref),
        generation=generation,
    )

    action = runner.action(
        work,
        identity,
        "VERIFICATION",
        "READ_CODE",
        input_refs=(*work.input_refs, plan_ref),
        file_paths=(str(location.file_path),),
        reason=intent.reason,
    )
    units = runner.units(elapsed_ms=1, cost_minor_units=1)
    reservation = runner.reserve(work, scope, action, units)
    decision = runner.authorize(work, action, reservation)
    used = runtime.validator.claim_external(
        str(work.work_id), decision, reference(reservation)
    )
    evidence.bind_identity(service_identity, RequesterRole.CONTEXT_RETRIEVAL_SERVICE)
    request = runtime.context.bind(
        str(work.work_id),
        used,
        requested_entities=(),
        requested_locations=(location,),
        relation_query=("CALLERS", "CALLEES"),
        limits=limits,
    )
    runtime.validator.mark_dispatched(decision, idempotency_key=str(action.action_id))
    runtime.validator.mark_returned(decision)
    runner.account(reservation, units)
    response = CodeContextResponse.model_validate_json(
        canonical_bytes(
            dict(
                meta=runner.metadata(
                    work.meta,
                    "code_context_response",
                    attempt_id=work.active_attempt_id,
                ),
                code_request_id=request.code_request_id,
                entities=(),
                locations=(location,),
                code_fragment_refs=(fragment_ref,),
                discovered_relations=(),
                gaps=(),
                errors=(),
                truncated=False,
                returned_fragment_count=1,
                returned_bytes=len(
                    runtime.unit_of_work.artifacts.open_verified(fragment_ref).read()
                ),
                consumed_token_estimate=1,
            )
        )
    )
    request_ref = reference(request)
    if not isinstance(used, StoredDataRef) or not isinstance(
        request_ref, StoredDataRef
    ):
        raise ValueError("FAKE_CONTEXT_OUTPUT_MISMATCH")
    receipt_ref = runtime.unit_of_work.artifacts.commit(
        runtime.unit_of_work.artifacts.stage_bytes(
            canonical_bytes(
                {
                    "kind": "fake_context_receipt",
                    "action_id": str(action.action_id),
                    "attempt_id": str(work.active_attempt_id),
                }
            ),
            "application/json",
        )
    )
    completed = ContextRetrievalService._complete(
        runtime=runtime,
        runner=runner,
        work=work,
        service_identity=service_identity,
        response=response,
        read_decision_ref=used,
        request_ref=request_ref,
        plan_ref=plan_ref,
        profile_ref=ceiling_ref,
        receipt_ref=receipt_ref,
        fragment_refs=(fragment_ref,),
    )
    output_ref = completed.output_refs[0]
    if not isinstance(output_ref, StoredDataRef) or output_ref != reference(response):
        raise ValueError("FAKE_CONTEXT_OUTPUT_MISMATCH")
    return response, output_ref
