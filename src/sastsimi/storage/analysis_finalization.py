"""Atomic exact AnalysisRunResult and AnalysisRunState terminal closure."""

from typing import cast

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.dynamic import DynamicReproductionResult
from sastsimi.contracts.evaluation import (
    RUN_INVENTORY_KINDS,
    AnalysisRunResult,
    ResolvedAnalysisInventory,
    validate_analysis_current,
)
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.policy import RunPolicyState
from sastsimi.contracts.refs import RecordRef, RunStoredDataRef, StoredDataRef
from sastsimi.contracts.reporting import FindingIndexState
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import Record
from sastsimi.ports.id_generator import IdGenerator

from . import models
from .codec import REF_ADAPTER, reference
from .records import next_meta
from .repositories import SQLiteRecordStore
from .run_states import get_run, save_run


class AnalysisFinalizationService:
    def __init__(
        self,
        records: SQLiteRecordStore,
        clock: Clock,
        ids: IdGenerator,
        identity_ref: StoredDataRef | None,
    ) -> None:
        self.records = records
        self.clock = clock
        self.ids = ids
        self.identity_ref = identity_ref

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
    ) -> ResolvedAnalysisInventory:
        expected: dict[str, tuple[RecordRef, ...]] = {
            field: tuple(getattr(result, field)) for field in RUN_INVENTORY_KINDS
        }
        expected["eval_config_refs"] = tuple(result.eval_config_refs)
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
                inventory=self._resolve_inventory(connection, result, current),
            )
            staged = self.records.stage(connection, result)
            if not isinstance(staged, RunStoredDataRef):
                raise ValueError("ANALYSIS_RESULT_SCOPE_MISMATCH")
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
            return staged
