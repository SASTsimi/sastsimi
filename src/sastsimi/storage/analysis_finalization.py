"""Atomic, authority-derived AnalysisRunResult and terminal run closure."""

from collections import Counter
from collections.abc import Callable
from typing import cast

from sqlalchemy import Connection, insert, select

from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    Decision,
    RequesterRole,
    UseStatus,
)
from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.budget import BudgetLedgerEntry, ExecutionBudgetProfile
from sastsimi.contracts.chaining import Primitive, PrimitiveIndexState
from sastsimi.contracts.dynamic import DynamicReproductionResult
from sastsimi.contracts.evaluation import (
    RUN_INVENTORY_KINDS,
    AnalysisRunResult,
    ResolvedAnalysisInventory,
    validate_analysis_current,
)
from sastsimi.contracts.gates import TechnicalEvidenceReview
from sastsimi.contracts.hypothesis import (
    HypothesisDuplicateReview,
    HypothesisProcessState,
    HypothesisProposal,
)
from sastsimi.contracts.ids import ActionId, LogicalRecordId, RecordId
from sastsimi.contracts.policy import RunPolicyState
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, RunStoredDataRef
from sastsimi.contracts.reporting import FindingIndexState
from sastsimi.contracts.static import AnalysisError, CodeWorkspace, DataGap
from sastsimi.contracts.work import (
    TERMINAL_WORK_STATUSES,
    WorkAttempt,
    WorkExecutionState,
)
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import Record
from sastsimi.ports.id_generator import IdGenerator

from . import models
from .action_validator import RuntimeValidator
from .authorization import authorize
from .codec import REF_ADAPTER, encode, reference
from .records import next_meta
from .repositories import SQLiteRecordStore
from .run_states import get_run, save_run


def _walk_contract(value: object) -> tuple[object, ...]:
    values: list[object] = [value]
    if isinstance(value, ContractModel):
        for name in type(value).model_fields:
            values.extend(_walk_contract(getattr(value, name)))
    elif isinstance(value, (tuple, list)):
        for item in value:
            values.extend(_walk_contract(item))
    return tuple(values)


class AnalysisFinalizationService:
    def __init__(
        self,
        records: SQLiteRecordStore,
        clock: Clock,
        ids: IdGenerator,
        identity_ref: BudgetScopeRef | None,
        authorization: RuntimeValidator,
        checkpoint: Callable[[str], None] | None = None,
    ) -> None:
        self.records = records
        self.clock = clock
        self.ids = ids
        self.identity_ref = identity_ref
        self.authorization = authorization
        self.checkpoint = checkpoint or (lambda _name: None)

    def _finalization_action(
        self, result: AnalysisRunResult, candidate_ref: RunStoredDataRef
    ) -> ActionRequest:
        if self.identity_ref is None:
            raise ValueError("AUTHORITY_DENIED: trusted finalization identity required")
        record_id = self.ids.new(RecordId)
        return ActionRequest.model_validate(
            {
                "meta": result.meta.model_dump()
                | {
                    "record_id": record_id,
                    "logical_record_id": LogicalRecordId(str(record_id)),
                    "record_type": "action_request",
                    "revision_number": 1,
                    "previous_record_id": None,
                    "created_at": self.clock.now(),
                },
                "action_id": self.ids.new(ActionId),
                "requested_by": RequesterRole.ORCHESTRATION,
                "requester_identity_ref": self.identity_ref,
                "action_type": ActionType.SAVE_RESULT,
                "work_ref": None,
                "expected_state_version": None,
                "expected_verification_generation": None,
                "generation_restart_reason": None,
                "generation_restart_basis_refs": (),
                "input_refs": (),
                "dynamic_request_ref": None,
                "reproduction_plan_ref": None,
                "result_kind": "analysis_run_result",
                "candidate_result_ref": candidate_ref,
                "llm_call_spec_ref": None,
                "tool_name": None,
                "file_paths": (),
                "provider_profile_ref": None,
                "session_mode": None,
                "sandbox_profile_ref": None,
                "resource_profile_ref": None,
                "run_policy_state_ref": None,
                "image_digest": None,
                "network_targets": (),
                "resource_limits": None,
                "reason": "Commit the authoritative terminal analysis closure",
                "requested_at": self.clock.now(),
            }
        )

    def _claim_finalization(
        self,
        connection: Connection,
        decision: ActionDecision,
        action: ActionRequest,
        result_ref: RunStoredDataRef,
    ) -> None:
        if (
            decision.decision != Decision.ALLOW
            or decision.use_status != UseStatus.UNUSED
            or action.action_type != ActionType.SAVE_RESULT
            or action.candidate_result_ref != result_ref
            or action.requester_identity_ref != self.identity_ref
        ):
            raise ValueError("ANALYSIS_FINALIZATION_ACTION_MISMATCH")
        used = ActionDecision.model_validate(
            decision.model_dump()
            | {
                "meta": next_meta(decision.meta, self.clock, self.ids),
                "use_status": UseStatus.USED,
                "used_at": self.clock.now(),
            }
        )
        used_ref = self.records.stage(connection, used)
        self.records.publish(connection, used_ref)
        connection.execute(
            insert(models.action_decisions).values(
                decision_id=str(used.decision_id),
                action_id=str(action.action_id),
                payload=encode(used),
            )
        )
        self.authorization.record_outcome(connection, used, (result_ref,))

    def _current_records(
        self, connection: Connection, analysis_id: str
    ) -> tuple[Record, ...]:
        wires = connection.execute(
            select(models.records.c.ref)
            .join(
                models.current_records,
                models.current_records.c.record_id == models.records.c.record_id,
            )
            .order_by(models.records.c.record_id)
        ).scalars()
        current = tuple(
            self.records.resolve(connection, REF_ADAPTER.validate_json(wire))
            for wire in wires
        )
        return tuple(
            record
            for record in current
            if str(getattr(record.meta, "analysis_id", "")) == analysis_id
        )

    def _resolve_inventory(
        self,
        connection: Connection,
        result: AnalysisRunResult,
        current: tuple[Record, ...],
        state: AnalysisRunState,
    ) -> ResolvedAnalysisInventory:
        by_kind: dict[str, list[RecordRef]] = {}
        for record in current:
            by_kind.setdefault(record.meta.record_type, []).append(reference(record))
        published_rows = connection.execute(
            select(models.records.c.ref).join(models.record_revisions)
        ).scalars()
        latest: dict[tuple[str, str], Record] = {}
        for wire in published_rows:
            record = self.records.resolve(connection, REF_ADAPTER.validate_json(wire))
            if str(getattr(record.meta, "analysis_id", "")) != str(
                result.meta.analysis_id
            ):
                continue
            key = (record.meta.record_type, str(record.meta.logical_record_id))
            previous = latest.get(key)
            if (
                previous is None
                or record.meta.revision_number > previous.meta.revision_number
            ):
                latest[key] = record
        for kind in ("action_decision", "work_attempt", "transition_commit"):
            by_kind[kind] = [
                reference(record)
                for (record_kind, _), record in latest.items()
                if record_kind == kind
            ]
        expected: dict[str, tuple[RecordRef, ...]] = {}
        for field, kinds in RUN_INVENTORY_KINDS.items():
            refs = [ref for kind in sorted(kinds) for ref in by_kind.get(kind, ())]
            expected[field] = tuple(dict.fromkeys(refs))
        policy = next(
            (item for item in current if isinstance(item, RunPolicyState)), None
        )
        expected["policy_cache_refs"] = (
            ()
            if policy is None or policy.policy_cache_ref is None
            else (policy.policy_cache_ref,)
        )
        indexes = [item for item in current if isinstance(item, PrimitiveIndexState)]
        primitive_refs: list[RecordRef] = []
        for index in indexes:
            primitive_refs.append(reference(index))
            for primitive_ref in index.primitive_refs:
                primitive_refs.append(primitive_ref)
                primitive = self.records.resolve(connection, primitive_ref)
                if (
                    isinstance(primitive, Primitive)
                    and primitive.admission_decision_ref
                ):
                    primitive_refs.append(primitive.admission_decision_ref)
        chaining_refs = by_kind.get("chaining_result", ())
        expected["primitive_and_chaining_refs"] = tuple(
            dict.fromkeys((*primitive_refs, *chaining_refs))
        )
        expected["eval_config_refs"] = tuple(state.eval_config_refs)
        records = {
            ref: cast(ContractModel, self.records.resolve(connection, ref))
            for refs in expected.values()
            for ref in refs
        }
        verifications = {
            item.meta.hypothesis_id: item.verification_result_ref
            for item in current
            if isinstance(item, HypothesisProcessState)
            and item.status == "TERMINAL"
            and item.meta.hypothesis_id is not None
            and item.verification_result_ref is not None
        }
        generations = {
            item.meta.hypothesis_id: item.verification_generation
            for item in current
            if isinstance(item, HypothesisProcessState)
            and item.status == "TERMINAL"
            and item.meta.hypothesis_id is not None
        }
        return ResolvedAnalysisInventory(
            records=records,
            expected_refs=expected,
            current_verification_refs=verifications,
            verification_generations=generations,
        )

    def _validate_readiness_and_summaries(
        self,
        connection: Connection,
        result: AnalysisRunResult,
        current: tuple[Record, ...],
        inventory: ResolvedAnalysisInventory,
        state: AnalysisRunState,
    ) -> None:
        works = [item for item in current if isinstance(item, WorkExecutionState)]
        if connection.execute(
            select(models.external_dispatches.c.action_id).where(
                models.external_dispatches.c.dispatched_at.is_not(None),
                models.external_dispatches.c.returned_at.is_(None),
                models.external_dispatches.c.reconciled_at.is_(None),
            )
        ).first():
            raise ValueError("ANALYSIS_EXTERNAL_DISPATCH_UNRESOLVED")
        if connection.execute(
            select(models.transition_commits.c.transition_commit_id).where(
                models.transition_commits.c.state == "PREPARED"
            )
        ).first():
            raise ValueError("ANALYSIS_TRANSITION_UNRESOLVED")
        if any(work.status not in TERMINAL_WORK_STATUSES for work in works):
            raise ValueError("ANALYSIS_WORK_NOT_QUIESCENT")
        processes = [
            item for item in current if isinstance(item, HypothesisProcessState)
        ]
        hypothesis_counts = Counter(str(process.status) for process in processes)
        if processes:
            hypothesis_counts["TOTAL"] = len(processes)
            proposals = [
                item for item in current if isinstance(item, HypothesisProposal)
            ]
            duplicate_reviews = [
                item for item in current if isinstance(item, HypothesisDuplicateReview)
            ]
            hypothesis_counts.update(
                {
                    "PROPOSAL_TOTAL": len(proposals),
                    "REGISTERED": len(processes),
                    "DUPLICATE": 0,
                    "INVALID_OUTPUT": 0,
                    "CANCELLED": 0,
                    "DUPLICATE_UNIQUE": sum(
                        item.decision == "UNIQUE" for item in duplicate_reviews
                    ),
                    "DUPLICATE_UNCERTAIN": sum(
                        item.decision == "UNCERTAIN" for item in duplicate_reviews
                    ),
                    "CHECK_FAILED": 0,
                    "INVALID_DUPLICATE_TARGET": 0,
                }
            )
        if dict(hypothesis_counts) != dict(result.hypothesis_counts):
            raise ValueError("HYPOTHESIS_COUNTS_MISMATCH")
        gate_counts: Counter[str] = Counter()
        for wire in connection.execute(
            select(models.records.c.ref)
            .join(models.record_revisions)
            .where(models.records.c.kind == "technical_evidence_review")
        ).scalars():
            review = self.records.resolve(connection, REF_ADAPTER.validate_json(wire))
            if isinstance(review, TechnicalEvidenceReview) and str(
                review.meta.analysis_id
            ) == str(result.meta.analysis_id):
                gate_counts[str(review.status)] += 1
        if dict(gate_counts) != dict(result.gate_counts):
            raise ValueError("GATE_COUNTS_MISMATCH")
        attempts = [
            inventory.records[ref]
            for ref in inventory.expected_refs["work_attempt_refs"]
            if isinstance(inventory.records[ref], WorkAttempt)
        ]
        ledger = [
            BudgetLedgerEntry.model_validate_json(payload)
            for payload in connection.execute(
                select(models.budget_ledger_entries.c.payload).where(
                    models.budget_ledger_entries.c.analysis_id
                    == str(result.meta.analysis_id)
                )
            ).scalars()
        ]
        expected_resources = {
            "elapsed_ms": sum(item.actual_units.elapsed_ms for item in ledger),
            "work_count": len(works),
            "attempt_count": len(attempts),
            "retry_count": sum(item.actual_units.retry_count for item in ledger),
            "llm_call_count": sum(item.actual_units.llm_call_count for item in ledger),
            "dynamic_attempt_count": len(result.dynamic_result_refs),
            "cost_minor_units": (
                sum(item.actual_units.cost_minor_units for item in ledger)
                if ledger
                else None
            ),
        }
        for field, expected in expected_resources.items():
            if getattr(result.resources, field) != expected:
                raise ValueError("ANALYSIS_RESOURCE_SUMMARY_MISMATCH")
        expected_usage_refs = tuple(
            dict.fromkeys(ref for item in ledger for ref in item.usage_refs)
        )
        execution = self.records.resolve(connection, state.execution_budget_profile_ref)
        if not isinstance(execution, ExecutionBudgetProfile):
            raise ValueError("ANALYSIS_RESOURCE_SUMMARY_MISMATCH")
        expected_currency = execution.currency if ledger else None
        expected_pricing_refs = (execution.pricing_revision_ref,) if ledger else ()
        if (
            result.resources.usage_measurement_refs != expected_usage_refs
            or result.resources.currency != expected_currency
            or result.resources.pricing_revision_refs != expected_pricing_refs
            or result.resources.usage_complete != bool(ledger)
            or bool(result.resources.unavailable_reasons) == bool(ledger)
        ):
            raise ValueError("ANALYSIS_RESOURCE_SUMMARY_MISMATCH")
        history = tuple(
            self.records.resolve(connection, REF_ADAPTER.validate_json(wire))
            for wire in connection.execute(
                select(models.records.c.ref).join(models.record_revisions)
            ).scalars()
        )
        errors: dict[str, AnalysisError] = {}
        gaps: dict[str, DataGap] = {}
        for record in history:
            if str(getattr(record.meta, "analysis_id", "")) != str(
                result.meta.analysis_id
            ):
                continue
            for value in _walk_contract(record):
                if isinstance(value, AnalysisError):
                    errors[str(value.error_id)] = value
                elif isinstance(value, DataGap):
                    gaps[str(value.gap_id)] = value
        if {str(item.error_id): item for item in result.errors} != errors:
            raise ValueError("ANALYSIS_ERROR_CLOSURE_MISMATCH")
        if {str(item.gap_id): item for item in result.gaps} != gaps:
            raise ValueError("ANALYSIS_GAP_CLOSURE_MISMATCH")
        if result.elapsed_ms != int(
            (result.finished_at - result.started_at).total_seconds() * 1000
        ):
            raise ValueError("ANALYSIS_ELAPSED_MISMATCH")

    def finalize(self, result: AnalysisRunResult) -> RunStoredDataRef:
        result = AnalysisRunResult.model_validate(result)
        if (
            self.identity_ref is None
            or self.records.evidence.identity_role(self.identity_ref)
            != RequesterRole.ORCHESTRATION
        ):
            raise ValueError("AUTHORITY_DENIED: trusted finalization identity required")
        with self.records.database.write() as connection:
            state = get_run(connection, str(result.meta.analysis_id))
            result_ref = reference(result)
            if state.status != "RUNNING":
                if state.analysis_result_ref == result_ref:
                    assert isinstance(result_ref, RunStoredDataRef)
                    return result_ref
                raise ValueError("ANALYSIS_ALREADY_TERMINAL")
            if (
                result.program_id != state.program_id
                or result.purpose != state.purpose
                or result.started_at != state.started_at
            ):
                raise ValueError("ANALYSIS_RESULT_STATE_MISMATCH")
            workspace = (
                self.records.resolve(connection, state.workspace_ref)
                if state.workspace_ref is not None
                else None
            )
            policy = (
                self.records.resolve(connection, state.run_policy_state_ref)
                if state.run_policy_state_ref is not None
                else None
            )
            if workspace is not None and not isinstance(workspace, CodeWorkspace):
                raise ValueError("WORKSPACE_REFERENCE_REQUIRED")
            if policy is not None and not isinstance(policy, RunPolicyState):
                raise ValueError("RUN_POLICY_STATE_REQUIRED")
            current = self._current_records(connection, str(result.meta.analysis_id))
            indexes = tuple(
                item for item in current if isinstance(item, FindingIndexState)
            )
            dynamics = tuple(
                self.records.resolve(connection, ref)
                for ref in result.dynamic_result_refs
            )
            if any(
                not isinstance(item, DynamicReproductionResult) for item in dynamics
            ):
                raise ValueError("DYNAMIC_RESULT_CLOSURE_MISMATCH")
            failed = sum(
                item.status == "FAILED"
                for item in current
                if isinstance(item, HypothesisProcessState)
            )
            inventory = self._resolve_inventory(connection, result, current, state)
            self._validate_readiness_and_summaries(
                connection, result, current, inventory, state
            )
            validate_analysis_current(
                result,
                workspace,
                policy,
                indexes,
                tuple(
                    item
                    for item in dynamics
                    if isinstance(item, DynamicReproductionResult)
                ),
                pinned_eval_refs=state.eval_config_refs,
                expected_failed_hypothesis_count=failed,
                inventory=inventory,
            )
            staged = self.records.stage(connection, result)
            if not isinstance(staged, RunStoredDataRef):
                raise ValueError("ANALYSIS_RESULT_SCOPE_MISMATCH")
            action = self._finalization_action(result, staged)
            decision = authorize(
                self.authorization,
                action,
                None,
                None,
                _connection=connection,
            )
            self._claim_finalization(connection, decision, action, staged)
            self.records.publish(connection, staged)
            terminal = AnalysisRunState.model_validate(
                state.model_dump()
                | dict(
                    meta=next_meta(state.meta, self.clock, self.ids),
                    status=result.status,
                    analysis_result_ref=staged,
                    finished_at=result.finished_at,
                    elapsed_ms=result.elapsed_ms,
                )
            )
            save_run(self.records, connection, terminal, state)
            self.checkpoint("before_commit")
            return staged
