"""Authoritative fake result assembly and finalization coordination."""

from collections import Counter
from typing import Any

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.budget import BudgetLedgerEntry, ExecutionBudgetProfile
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.chaining import (
    ChainingResult,
    Primitive,
)
from sastsimi.contracts.evaluation import RUN_INVENTORY_KINDS, AnalysisRunResult
from sastsimi.contracts.gates import (
    CWELabel,
    TechnicalEvidenceReview,
)
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    ProposalProcessState,
)
from sastsimi.contracts.policy import (
    RunPolicyState,
)
from sastsimi.contracts.refs import RecordRef, reference
from sastsimi.contracts.reporting import ReportDraft
from sastsimi.contracts.verification import (
    VerificationResult,
)
from sastsimi.orchestration.fake_base import ANALYSIS_ID, PROGRAM_ID, FakeStageService


class FakeFinalizationStages(FakeStageService):
    def _inventory(self, field: str) -> tuple[RecordRef, ...]:
        assert self.runtime is not None
        if field == "policy_cache_refs":
            state = self.runtime.budget_registry.current_state(str(ANALYSIS_ID))
            assert state.run_policy_state_ref is not None
            policy = self.runtime.unit_of_work.records.get_exact(
                state.run_policy_state_ref
            )
            assert isinstance(policy, RunPolicyState)
            return () if policy.policy_cache_ref is None else (policy.policy_cache_ref,)
        if field == "cwe_label_refs":
            labels = tuple(
                item
                for item in self.runtime.queries.current_records(
                    str(ANALYSIS_ID), "cwe_label"
                )
                if isinstance(item, CWELabel)
            )
            if not labels:
                return ()
            newest = max(labels, key=lambda item: item.verification_generation)
            return (reference(newest),)
        if field == "primitive_and_chaining_refs":
            indexes = self.runtime.queries.current_records(
                str(ANALYSIS_ID), "primitive_index_state"
            )
            if not indexes:
                return ()
            index = indexes[0]
            from sastsimi.contracts.chaining import PrimitiveIndexState

            assert isinstance(index, PrimitiveIndexState)
            primitive_inventory: list[RecordRef] = [
                reference(index),
                *index.primitive_refs,
            ]
            for primitive_ref in index.primitive_refs:
                primitive = self.runtime.unit_of_work.records.get_exact(primitive_ref)
                assert isinstance(primitive, Primitive)
                if primitive.admission_decision_ref is not None:
                    primitive_inventory.append(primitive.admission_decision_ref)
            for item in self.runtime.queries.current_records(
                str(ANALYSIS_ID), "chaining_result"
            ):
                if isinstance(item, ChainingResult) and set(
                    item.considered_primitive_refs
                ).issubset(index.primitive_refs):
                    primitive_inventory.append(reference(item))
            return tuple(primitive_inventory)
        kind_sets: dict[str, tuple[str, ...]] = {
            "verification_refs": ("verification_result",),
            "primitive_and_chaining_refs": (
                "primitive_admission_decision",
                "primitive_index_state",
                "primitive",
                "chaining_result",
            ),
            "action_decision_refs": ("action_decision",),
            "work_state_refs": ("work_execution_state",),
            "work_attempt_refs": ("work_attempt",),
            "transition_commit_refs": ("transition_commit",),
        }
        refs: list[RecordRef] = []
        for kind in kind_sets.get(
            field, tuple(sorted(RUN_INVENTORY_KINDS.get(field, ())))
        ):
            if kind in {"action_decision", "work_attempt", "transition_commit"}:
                revisions: dict[str, Any] = {}
                for candidate in self.runtime.queries.published_records(
                    str(ANALYSIS_ID)
                ):
                    if candidate.meta.record_type != kind:
                        continue
                    logical_id = str(candidate.meta.logical_record_id)
                    current = revisions.get(logical_id)
                    if (
                        current is None
                        or candidate.meta.revision_number > current.meta.revision_number
                    ):
                        revisions[logical_id] = candidate
                records = tuple(revisions.values())
            else:
                records = self.runtime.queries.current_records(str(ANALYSIS_ID), kind)
            for record in records:
                refs.append(reference(record))
        return tuple(refs)

    def _result_candidate(self, verdict: str) -> AnalysisRunResult:
        assert self.runtime is not None
        state = self.runtime.budget_registry.current_state(str(ANALYSIS_ID))
        inventory_fields = {
            name: self._inventory(name)
            for name in AnalysisRunResult.model_fields
            if name.endswith("_refs")
            and name
            not in {
                "eval_config_refs",
                "pricing_revision_refs",
                "usage_measurement_refs",
            }
        }
        current_work = self.runtime.queries.current_records(
            str(ANALYSIS_ID), "work_execution_state"
        )
        attempt_refs = self._inventory("work_attempt_refs")
        verdicts: Counter[str] = Counter()
        processes = tuple(
            item
            for item in self.runtime.queries.current_records(
                str(ANALYSIS_ID), "hypothesis_process_state"
            )
            if isinstance(item, HypothesisProcessState)
        )
        for process in processes:
            if (
                isinstance(process, HypothesisProcessState)
                and process.verification_result_ref is not None
            ):
                current_verification = self.runtime.unit_of_work.records.get_exact(
                    process.verification_result_ref
                )
                assert isinstance(current_verification, VerificationResult)
                verdicts[current_verification.verdict] += 1
        technical_reviews = tuple(
            item
            for item in self.runtime.queries.published_records(str(ANALYSIS_ID))
            if isinstance(item, TechnicalEvidenceReview)
        )
        gate_counts = Counter(item.status for item in technical_reviews)
        hypothesis_counts: Counter[str] = Counter(
            str(item.status) for item in processes
        )
        proposal_states = tuple(
            item
            for item in self.runtime.queries.current_records(
                str(ANALYSIS_ID), "proposal_process_state"
            )
            if isinstance(item, ProposalProcessState)
        )
        hypothesis_counts.update(
            {
                "TOTAL": len(processes),
                "PROPOSAL_TOTAL": len(proposal_states),
                "REGISTERED": len(processes),
                "DUPLICATE": sum(
                    item.status == "DUPLICATE" for item in proposal_states
                ),
                "INVALID_OUTPUT": sum(
                    item.status == "INVALID_OUTPUT" for item in proposal_states
                ),
                "CANCELLED": sum(
                    item.status == "CANCELLED" for item in proposal_states
                ),
                "DUPLICATE_UNIQUE": sum(
                    item.registration_reason == "UNIQUE" for item in proposal_states
                ),
                "DUPLICATE_UNCERTAIN": sum(
                    item.registration_reason == "UNCERTAIN" for item in proposal_states
                ),
                "CHECK_FAILED": sum(
                    item.registration_reason == "CHECK_FAILED"
                    for item in proposal_states
                ),
                "INVALID_DUPLICATE_TARGET": sum(
                    item.registration_reason == "INVALID_DUPLICATE_TARGET"
                    for item in proposal_states
                ),
            }
        )
        hypothesis_counts["CANCELLED"] = sum(
            item.status == "CANCELLED" for item in proposal_states
        )
        ledger = tuple(
            item
            for item in self.runtime.queries.published_records(str(ANALYSIS_ID))
            if isinstance(item, BudgetLedgerEntry)
        )
        used_elapsed = sum(item.actual_units.elapsed_ms for item in ledger)
        used_llm_calls = sum(item.actual_units.llm_call_count for item in ledger)
        used_retries = sum(item.actual_units.retry_count for item in ledger)
        used_cost = sum(item.actual_units.cost_minor_units for item in ledger)
        execution = self.runtime.unit_of_work.records.get_exact(
            state.execution_budget_profile_ref
        )
        assert isinstance(execution, ExecutionBudgetProfile)
        debug_trace_ref = self.runtime.unit_of_work.artifacts.commit_run(
            self.runtime.unit_of_work.artifacts.stage_bytes(
                canonical_bytes(
                    {
                        "analysis_id": str(ANALYSIS_ID),
                        "work_count": len(current_work),
                        "verdict_counts": dict(verdicts),
                    }
                ),
                "application/json",
            ),
            ANALYSIS_ID,
        )
        result = AnalysisRunResult.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self._run_meta("analysis_run_result"),
                    purpose="PRODUCTION",
                    repository_url="https://example.invalid/fake",
                    program_id=PROGRAM_ID,
                    workspace_id=state.workspace_id,
                    commit_id=state.commit_id,
                    workspace_ref=state.workspace_ref,
                    status="COMPLETE",
                    hypothesis_counts=dict(hypothesis_counts),
                    failed_hypothesis_count=0,
                    verdict_counts=dict(verdicts),
                    gate_counts=dict(gate_counts),
                    run_policy_state_ref=state.run_policy_state_ref,
                    eval_config_refs=(),
                    stop_reasons=(),
                    errors=(),
                    gaps=(),
                    resources=dict(
                        elapsed_ms=used_elapsed,
                        work_count=len(current_work),
                        attempt_count=len(attempt_refs),
                        retry_count=used_retries,
                        llm_call_count=used_llm_calls,
                        dynamic_attempt_count=len(
                            self._inventory("dynamic_result_refs")
                        ),
                        cost_minor_units=used_cost,
                        currency="USD",
                        pricing_revision_refs=(execution.pricing_revision_ref,)
                        if used_cost
                        else (),
                        usage_measurement_refs=(),
                        usage_complete=True,
                        unavailable_reasons=(),
                    ),
                    started_at=state.started_at,
                    finished_at=self.clock.now(),
                    elapsed_ms=0,
                    debug_trace_ref=debug_trace_ref,
                    **inventory_fields,
                )
            )
        )
        return result

    def _finish(self, verdict: str) -> AnalysisRunResult:
        assert self.runtime is not None
        result = self._result_candidate(verdict)
        # The configured finalizer identity is the verification owner.
        owner = next(
            ref
            for ref, role in self.evidence.identities.items()
            if ref.data_kind == "work_budget_profile"
        )
        self.evidence.identities[owner] = RequesterRole.ORCHESTRATION
        result_ref = self.runtime.finalization.finalize(result)
        persisted = self.runtime.unit_of_work.records.get_exact(result_ref)
        assert isinstance(persisted, AnalysisRunResult)
        result = persisted
        self._host._result = result
        self._host._reports = tuple(
            item
            for item in self.runtime.queries.current_records(
                str(ANALYSIS_ID), "report_draft"
            )
            if isinstance(item, ReportDraft)
        )
        return result
