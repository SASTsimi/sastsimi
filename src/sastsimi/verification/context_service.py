"""Deterministic READ_CODE orchestration through public runtime services."""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Protocol

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import ErrorId, GapId
from sastsimi.contracts.records import RecordMetadata
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.contracts.static import (
    AnalysisError,
    CodeContextResponse,
    CodeLocation,
    CodeWorkspace,
    ContextRetrievalLimits,
    DataGap,
    StaticFactBundle,
)
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.context import (
    ChainingContextRecords,
    ContextLineageReaderPort,
    ContextReadPlan,
    ContextRetrievalIntent,
)
from sastsimi.ports.dto import MonotonicActionDeadline, StaticActionReceipt, TrackedFile
from sastsimi.ports.workspace import WorkspaceLocatorPort
from sastsimi.runtime.fake_support import FakeEvidence
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.static_analysis.context_retrieval import (
    ContextReadObservation,
    context_intent_hash,
    plan_context_retrieval,
    read_context_files,
)
from sastsimi.storage.context_policy import resolve_context_ceiling


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
        current = self.runtime.work.get(str(work.work_id))
        if current != work or work.active_attempt_id is None:
            raise ValueError("ATTEMPT_NOT_ACTIVE")
        if (
            work.input_refs.count(intent.proposal_ref) != 1
            or work.input_refs.count(intent.bundle_ref) != 1
        ):
            raise ValueError("CONTEXT_INPUT_MISMATCH")
        ceilings = resolve_context_ceiling(self.runtime.unit_of_work.artifacts, work)
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
        plan_raw = canonical_bytes(plan)
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
        used_ref = self.runtime.validator.claim_external(
            str(work.work_id), decision_ref, reference(reservation)
        )
        request = self.runtime.context.bind(
            str(work.work_id),
            used_ref,
            requested_entities=plan.entities,
            requested_locations=plan.locations,
            relation_query=intent.relation_query,
            limits=intent.requested_limits,
        )
        self._require_unchanged(
            intent, bundle, workspace, work, ceilings, lineage, plan_raw
        )
        self.runtime.validator.mark_dispatched(
            decision_ref, idempotency_key=str(action.action_id)
        )
        started_ns = self.monotonic_ns()
        deadline = MonotonicActionDeadline(
            action_id=str(action.action_id),
            started_ns=started_ns,
            expires_ns=started_ns + intent.requested_limits.timeout_ms * 1_000_000,
        )
        self._require_unchanged(
            intent, bundle, workspace, work, ceilings, lineage, plan_raw
        )
        await self.workspace_locator.assert_unchanged(workspace, deadline)
        observation = read_context_files(
            plan=plan,
            workspace_root=self.workspace_locator.root_for(workspace),
            tracked_files=self.tracked_files_for(workspace),
            deadline=deadline,
            monotonic_ns=self.monotonic_ns,
        )
        await self.workspace_locator.assert_unchanged(workspace, deadline)
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
        request_ref = reference(request)
        action_ref = reference(action)
        if (
            not isinstance(request_ref, StoredDataRef)
            or not isinstance(action_ref, StoredDataRef)
            or not isinstance(used_ref, StoredDataRef)
        ):
            raise ValueError("CONTEXT_SCOPE_MISMATCH")
        self._write_receipt(
            action_id=str(action.action_id),
            action_ref=action_ref,
            work=work,
            attempt_id=str(work.active_attempt_id),
            decision_ref=used_ref,
            request_ref=request_ref,
            plan_ref=plan_ref,
            plan=plan,
            response=response,
            candidate=candidate,
            elapsed_ms=elapsed_ms,
        )
        self.checkpoint("RECEIPT_DURABLE")
        self.runtime.validator.mark_returned(decision_ref)
        self.checkpoint("RETURNED")
        self._account_once(reservation, elapsed_ms)
        self.checkpoint("ACCOUNTED")
        completed = self.runner.complete(
            work, service_identity, "CONTEXT_RETRIEVAL_SERVICE", (response,)
        )
        output_ref = completed.output_refs[0]
        if not isinstance(output_ref, StoredDataRef) or output_ref != reference(
            response
        ):
            raise ValueError("CONTEXT_RESPONSE_COMMIT_MISMATCH")
        return response, output_ref

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
        ceilings: object,
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
        if canonical_bytes(recomputed) != expected:
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
    ) -> Path:
        root = self.receipt_root.resolve()
        root.mkdir(parents=True, exist_ok=True)
        if self.receipt_root.is_symlink() or not root.is_dir():
            raise ValueError("CONTEXT_RECEIPT_INVALID")
        prefix = hashlib.sha256(str(action_ref.record_id).encode()).hexdigest()[:24]
        observation_name = prefix + ".context.json"
        self._atomic_write(root / observation_name, candidate)
        fingerprint = hashlib.sha256(
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
        receipt = StaticActionReceipt(
            action_id=action_id,
            attempt_id=attempt_id,
            operation_kind="CONTEXT_READ",
            input_fingerprint=fingerprint,
            process_receipt_hashes=(),
            observation_name=observation_name,
            observation_size=len(candidate),
            observation_sha256=hashlib.sha256(candidate).hexdigest(),
            elapsed_ms=elapsed_ms,
        )
        self._atomic_write(
            root / (prefix + ".receipt.json"), canonical_bytes(asdict(receipt))
        )
        if response.returned_fragment_count != len(response.code_fragment_refs):
            raise ValueError("CONTEXT_RECEIPT_INVALID")
        return root / (prefix + ".receipt.json")

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        if path.exists() or path.is_symlink():
            try:
                existing = path.read_bytes()
            except OSError as error:
                raise ValueError("CONTEXT_RECEIPT_INVALID") from error
            if existing != data:
                raise ValueError("CONTEXT_RECEIPT_INVALID")
            return
        temporary = path.with_suffix(path.suffix + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            os.write(descriptor, data)
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
            canonical_bytes(plan), "application/json"
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
    completed = runner.complete(
        work, service_identity, "CONTEXT_RETRIEVAL_SERVICE", (response,)
    )
    output_ref = completed.output_refs[0]
    if not isinstance(output_ref, StoredDataRef) or output_ref != reference(response):
        raise ValueError("FAKE_CONTEXT_OUTPUT_MISMATCH")
    return response, output_ref
