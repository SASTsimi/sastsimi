"""Public-port result aggregation for a quiescent production analysis."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import Protocol, cast

from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.budget import BudgetLedgerEntry, ExecutionBudgetProfile
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.chaining import Primitive, PrimitiveIndexState
from sastsimi.contracts.evaluation import (
    RUN_INVENTORY_KINDS,
    AnalysisRunResult,
    ResourceUsageSummary,
)
from sastsimi.contracts.gates import TechnicalEvidenceReview
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    ProposalProcessState,
)
from sastsimi.contracts.policy import RunPolicyState
from sastsimi.contracts.records import RunMeta
from sastsimi.contracts.refs import (
    RecordRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.reporting import ReportProcessState
from sastsimi.contracts.static import AnalysisError, CodeWorkspace, DataGap
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import (
    TERMINAL_WORK_STATUSES,
    WorkAttempt,
    WorkExecutionState,
)
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import Record
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort
from sastsimi.ports.runtime_store import BudgetRegistryPort
from sastsimi.ports.scheduler import RunDisposition


class ResultMetadataPort(Protocol):
    """Runtime-owned ID/revision allocation for one result candidate."""

    def create(self, state: AnalysisRunState) -> RunMeta: ...


class ResultAggregationPort(Protocol):
    """Build one candidate from exact durable state; never publish it."""

    def build(
        self,
        analysis_id: str,
        disposition: RunDisposition,
    ) -> AnalysisRunResult: ...


def _walk(value: object) -> Iterable[object]:
    yield value
    if isinstance(value, ContractModel):
        for name in type(value).model_fields:
            yield from _walk(getattr(value, name))
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from _walk(item)


def _unique[T](items: Iterable[T]) -> tuple[T, ...]:
    return tuple(dict.fromkeys(items))


class ResultAggregationService:
    """Build a complete exact-reference inventory without publishing records."""

    def __init__(
        self,
        *,
        states: BudgetRegistryPort,
        queries: RuntimeQueryPort,
        records: RecordStore,
        artifacts: ArtifactStore,
        clock: Clock,
        metadata: ResultMetadataPort,
    ) -> None:
        self._states = states
        self._queries = queries
        self._records = records
        self._artifacts = artifacts
        self._clock = clock
        self._metadata = metadata

    def build(
        self,
        analysis_id: str,
        disposition: RunDisposition,
    ) -> AnalysisRunResult:
        if disposition == "BLOCKED":
            raise ValueError("BLOCKED_ANALYSIS_RESULT_FORBIDDEN")
        state = self._states.current_state(analysis_id)
        run_input = self._states.current_input(analysis_id)
        if str(state.meta.analysis_id) != analysis_id or state.status != "RUNNING":
            raise ValueError("ANALYSIS_RESULT_STATE_MISMATCH")
        if (
            reference(run_input) != state.analysis_input_ref
            or run_input.program_id != state.program_id
            or run_input.purpose != state.purpose
        ):
            raise ValueError("ANALYSIS_INPUT_REFERENCE_MISMATCH")
        current = {
            kind: self._queries.current_records(analysis_id, kind)
            for kinds in RUN_INVENTORY_KINDS.values()
            for kind in kinds
        }
        for kind in (
            "hypothesis_process_state",
            "proposal_process_state",
            "report_process_state",
            "run_policy_state",
            "budget_ledger_entry",
        ):
            current[kind] = self._queries.current_records(analysis_id, kind)
        published = self._queries.published_records(analysis_id)
        works = tuple(
            item
            for item in current.get("work_execution_state", ())
            if isinstance(item, WorkExecutionState)
        )
        if any(item.status not in TERMINAL_WORK_STATUSES for item in works):
            raise ValueError("ANALYSIS_WORK_NOT_QUIESCENT")

        inventory = self._inventory(state, current, published)
        processes = tuple(
            item
            for item in current["hypothesis_process_state"]
            if isinstance(item, HypothesisProcessState)
        )
        proposals = tuple(
            item
            for item in current["proposal_process_state"]
            if isinstance(item, ProposalProcessState)
        )
        failed_hypotheses = sum(item.status == "FAILED" for item in processes)
        status = self._status(disposition, works, failed_hypotheses, inventory)
        workspace = self._workspace(state)
        if status in {"COMPLETE", "PARTIAL"} and workspace is None:
            raise ValueError("WORKSPACE_REFERENCE_REQUIRED")

        verifications = tuple(
            self._records.get_exact(ref) for ref in inventory["verification_refs"]
        )
        verdict_counts = Counter(
            item.verdict
            for item in verifications
            if isinstance(item, VerificationResult)
        )
        gate_counts = Counter(
            str(item.status)
            for item in published
            if isinstance(item, TechnicalEvidenceReview)
        )
        hypothesis_counts = self._hypothesis_counts(processes, proposals)
        resources = self._resources(state, works, inventory, published)
        errors, gaps = self._diagnostics(published)
        finished_at = self._clock.now()
        elapsed_ms = max(
            state.elapsed_ms,
            int((finished_at - state.started_at).total_seconds() * 1000),
        )
        debug = self._artifacts.commit_run(
            self._artifacts.stage_bytes(
                canonical_bytes(
                    {
                        "analysis_id": analysis_id,
                        "status": status,
                        "work_count": len(works),
                        "failed_hypothesis_count": failed_hypotheses,
                        "report_draft_count": len(inventory["report_draft_refs"]),
                    }
                ),
                "application/json",
            ),
            state.meta.analysis_id,
        )
        meta = self._metadata.create(state)
        if (
            type(meta) is not RunMeta
            or meta.analysis_id != state.meta.analysis_id
            or meta.record_type != "analysis_run_result"
        ):
            raise ValueError("ANALYSIS_RESULT_METADATA_INVALID")
        policy_states = tuple(
            item
            for item in current["run_policy_state"]
            if isinstance(item, RunPolicyState)
        )
        if len(policy_states) > 1:
            raise ValueError("RUN_POLICY_STATE_AMBIGUOUS")
        policy_ref = (
            cast(StoredDataRef, reference(policy_states[0])) if policy_states else None
        )
        if policy_ref != state.run_policy_state_ref:
            raise ValueError("RUN_POLICY_STATE_MISMATCH")

        values: dict[str, object] = {
            "meta": meta,
            "purpose": str(state.purpose),
            "repository_url": (
                workspace.repository_url if workspace else run_input.repository_ref
            ),
            "program_id": state.program_id,
            "workspace_id": state.workspace_id,
            "commit_id": state.commit_id,
            "workspace_ref": state.workspace_ref,
            "status": status,
            "hypothesis_counts": hypothesis_counts,
            "failed_hypothesis_count": failed_hypotheses,
            "verdict_counts": dict(verdict_counts),
            "gate_counts": dict(gate_counts),
            "run_policy_state_ref": policy_ref,
            "eval_config_refs": state.eval_config_refs,
            "stop_reasons": _unique(
                item.stop_reason for item in works if item.stop_reason is not None
            ),
            "errors": errors,
            "gaps": gaps,
            "resources": resources,
            "started_at": state.started_at,
            "finished_at": finished_at,
            "elapsed_ms": elapsed_ms,
            "debug_trace_ref": debug,
        }
        values.update(inventory)
        return AnalysisRunResult.model_validate(values)

    def _inventory(
        self,
        state: AnalysisRunState,
        current: dict[str, tuple[Record, ...]],
        published: tuple[Record, ...],
    ) -> dict[str, tuple[RecordRef, ...]]:
        inventory_kinds = {
            value for kinds in RUN_INVENTORY_KINDS.values() for value in kinds
        }
        refs_by_kind: dict[str, tuple[RecordRef, ...]] = {
            kind: _unique(reference(item) for item in records)
            for kind, records in current.items()
            if kind in inventory_kinds
        }
        latest: dict[tuple[str, str], Record] = {}
        for item in published:
            meta = getattr(item, "meta", None)
            if meta is None:
                continue
            key = (str(meta.record_type), str(meta.logical_record_id))
            previous = latest.get(key)
            if previous is None or meta.revision_number > previous.meta.revision_number:
                latest[key] = item
        for kind in ("action_decision", "work_attempt", "transition_commit"):
            refs_by_kind[kind] = _unique(
                reference(item)
                for (item_kind, _), item in latest.items()
                if item_kind == kind
            )
        inventory: dict[str, tuple[RecordRef, ...]] = {
            field: _unique(
                ref for kind in sorted(kinds) for ref in refs_by_kind.get(kind, ())
            )
            for field, kinds in RUN_INVENTORY_KINDS.items()
        }
        inventory["report_draft_refs"] = _unique(
            item.report_draft_ref
            for item in current["report_process_state"]
            if isinstance(item, ReportProcessState)
            and item.status == "DRAFTED"
            and item.report_draft_ref is not None
        )
        policies = tuple(
            item
            for item in current["run_policy_state"]
            if isinstance(item, RunPolicyState)
        )
        inventory["policy_cache_refs"] = (
            ()
            if not policies or policies[0].policy_cache_ref is None
            else (policies[0].policy_cache_ref,)
        )
        primitive_refs: list[RecordRef] = []
        for item in current.get("primitive_index_state", ()):
            if not isinstance(item, PrimitiveIndexState):
                continue
            primitive_refs.append(reference(item))
            for primitive_ref in item.primitive_refs:
                primitive_refs.append(primitive_ref)
                primitive = self._records.get_exact(primitive_ref)
                if (
                    isinstance(primitive, Primitive)
                    and primitive.admission_decision_ref
                ):
                    primitive_refs.append(primitive.admission_decision_ref)
        primitive_refs.extend(refs_by_kind.get("chaining_result", ()))
        inventory["primitive_and_chaining_refs"] = _unique(primitive_refs)
        inventory["eval_config_refs"] = tuple(state.eval_config_refs)
        return inventory

    def _workspace(self, state: AnalysisRunState) -> CodeWorkspace | None:
        if state.workspace_ref is None:
            return None
        workspace = self._records.get_exact(state.workspace_ref)
        if not isinstance(workspace, CodeWorkspace):
            raise ValueError("WORKSPACE_REFERENCE_REQUIRED")
        return workspace

    def _resources(
        self,
        state: AnalysisRunState,
        works: tuple[WorkExecutionState, ...],
        inventory: dict[str, tuple[RecordRef, ...]],
        published: tuple[Record, ...],
    ) -> ResourceUsageSummary:
        attempts = tuple(
            self._records.get_exact(ref) for ref in inventory["work_attempt_refs"]
        )
        ledgers = tuple(
            item for item in published if isinstance(item, BudgetLedgerEntry)
        )
        execution = self._records.get_exact(state.execution_budget_profile_ref)
        if not isinstance(execution, ExecutionBudgetProfile):
            raise ValueError("EXECUTION_PROFILE_REFERENCE_REQUIRED")
        return ResourceUsageSummary(
            elapsed_ms=sum(item.actual_units.elapsed_ms for item in ledgers),
            work_count=len(works),
            attempt_count=sum(isinstance(item, WorkAttempt) for item in attempts),
            retry_count=sum(item.actual_units.retry_count for item in ledgers),
            llm_call_count=sum(item.actual_units.llm_call_count for item in ledgers),
            dynamic_attempt_count=len(inventory["dynamic_result_refs"]),
            cost_minor_units=(
                sum(item.actual_units.cost_minor_units for item in ledgers)
                if ledgers
                else None
            ),
            currency=execution.currency if ledgers else None,
            pricing_revision_refs=(execution.pricing_revision_ref,) if ledgers else (),
            usage_measurement_refs=_unique(
                ref for item in ledgers for ref in item.usage_refs
            ),
            usage_complete=bool(ledgers),
            unavailable_reasons=() if ledgers else ("NO_COMMITTED_USAGE",),
        )

    @staticmethod
    def _hypothesis_counts(
        processes: tuple[HypothesisProcessState, ...],
        proposals: tuple[ProposalProcessState, ...],
    ) -> dict[str, int]:
        counts = Counter(str(item.status) for item in processes)
        if processes or proposals:
            counts.update(
                {
                    "TOTAL": len(processes),
                    "PROPOSAL_TOTAL": len(proposals),
                    "REGISTERED": len(processes),
                    "DUPLICATE": sum(item.status == "DUPLICATE" for item in proposals),
                    "INVALID_OUTPUT": sum(
                        item.status == "INVALID_OUTPUT" for item in proposals
                    ),
                    "CANCELLED": sum(item.status == "CANCELLED" for item in proposals),
                    "DUPLICATE_UNIQUE": sum(
                        item.registration_reason == "UNIQUE" for item in proposals
                    ),
                    "DUPLICATE_UNCERTAIN": sum(
                        item.registration_reason == "UNCERTAIN" for item in proposals
                    ),
                    "CHECK_FAILED": sum(
                        item.registration_reason == "CHECK_FAILED" for item in proposals
                    ),
                    "INVALID_DUPLICATE_TARGET": sum(
                        item.registration_reason == "INVALID_DUPLICATE_TARGET"
                        for item in proposals
                    ),
                }
            )
        return dict(counts)

    @staticmethod
    def _diagnostics(
        published: tuple[Record, ...],
    ) -> tuple[tuple[AnalysisError, ...], tuple[DataGap, ...]]:
        errors: dict[str, AnalysisError] = {}
        gaps: dict[str, DataGap] = {}
        for record in published:
            for value in _walk(record):
                if isinstance(value, AnalysisError):
                    errors[str(value.error_id)] = value
                elif isinstance(value, DataGap):
                    gaps[str(value.gap_id)] = value
        return tuple(errors.values()), tuple(gaps.values())

    @staticmethod
    def _status(
        disposition: RunDisposition,
        works: tuple[WorkExecutionState, ...],
        failed_hypotheses: int,
        inventory: dict[str, tuple[RecordRef, ...]],
    ) -> str:
        if disposition == "CANCELLED":
            return "CANCELLED"
        if failed_hypotheses:
            return "PARTIAL"
        degraded = any(
            item.status in {"PARTIAL", "FAILED", "CANCELLED"} for item in works
        )
        if disposition == "FAILED":
            has_domain_output = any(
                inventory[field]
                for field in ("verification_refs", "finding_refs", "report_draft_refs")
            )
            return "PARTIAL" if degraded and has_domain_output else "FAILED"
        return "PARTIAL" if degraded else "COMPLETE"


__all__ = ["ResultAggregationPort", "ResultAggregationService", "ResultMetadataPort"]
