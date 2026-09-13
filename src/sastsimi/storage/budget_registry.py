"""Trusted R8 publication and analysis-local immutable budget selection."""

from sqlalchemy import Connection, insert, select

from sastsimi.contracts.analysis import AnalysisRunInput, AnalysisRunState
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    DynamicReproductionLifecycleProfile,
    ExecutionBudgetProfile,
    ProfileStatus,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import BudgetScopeRef, RunStoredDataRef, StoredDataRef
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.storage import models
from sastsimi.storage.repositories import SQLiteRecordStore

from .codec import reference
from .records import next_meta
from .run_states import get_run, save_run


class BudgetProfileRegistry:
    def __init__(
        self, records: SQLiteRecordStore, clock: Clock, ids: IdGenerator
    ) -> None:
        self.records, self.clock, self.ids = records, clock, ids

    def current_state(self, analysis_id: str) -> AnalysisRunState:
        with self.records.database.engine.connect() as connection:
            return get_run(connection, analysis_id)

    def current_input(self, analysis_id: str) -> AnalysisRunInput:
        state = self.current_state(analysis_id)
        value = self.records.get_exact(state.analysis_input_ref)
        if (
            not isinstance(value, AnalysisRunInput)
            or reference(value) != state.analysis_input_ref
            or str(value.meta.analysis_id) != analysis_id
            or value.program_id != state.program_id
            or value.purpose != state.purpose
        ):
            raise ValueError("ANALYSIS_INPUT_REFERENCE_MISMATCH")
        return value

    def pin_execution(
        self,
        profile: ExecutionBudgetProfile,
        state: AnalysisRunState | None = None,
        run_input: AnalysisRunInput | None = None,
    ) -> RunStoredDataRef:
        profile = ExecutionBudgetProfile.model_validate(profile)
        if profile.status != ProfileStatus.ACTIVE:
            raise ValueError("BUDGET unavailable: execution profile is not ACTIVE")
        if not self.records.evidence.approved(
            profile
        ) or not self.records.evidence.pricing(profile):
            raise ValueError("BUDGET approval/pricing evidence is unavailable")
        if (
            state is None
            or state.execution_budget_profile_ref != reference(profile)
            or state.meta.analysis_id != profile.meta.analysis_id
            or state.purpose != profile.purpose
        ):
            raise ValueError("BUDGET requires exact analysis state and purpose")
        if run_input is not None and (
            reference(run_input) != state.analysis_input_ref
            or run_input.meta.analysis_id != state.meta.analysis_id
            or run_input.program_id != state.program_id
            or run_input.purpose != state.purpose
        ):
            raise ValueError("ANALYSIS_INPUT_REFERENCE_MISMATCH")
        with self.records.database.write() as connection:
            assert profile.approval_ref is not None
            # Governance provenance is opaque and may live outside this store.
            # The injected evidence port above binds the exact profile and refs.
            ref = self.records.stage(connection, profile)
            assert isinstance(ref, RunStoredDataRef)
            self.records.publish(connection, ref)
            if run_input is not None:
                input_ref = self.records.stage(connection, run_input)
                if input_ref != state.analysis_input_ref:
                    raise ValueError("ANALYSIS_INPUT_REFERENCE_MISMATCH")
                self.records.publish(connection, input_ref)
            else:
                persisted_input = self.records.resolve(
                    connection, state.analysis_input_ref
                )
                if (
                    not isinstance(persisted_input, AnalysisRunInput)
                    or persisted_input.meta.analysis_id != state.meta.analysis_id
                    or persisted_input.program_id != state.program_id
                    or persisted_input.purpose != state.purpose
                ):
                    raise ValueError("ANALYSIS_INPUT_REFERENCE_MISMATCH")
            self.pin(connection, ref, str(profile.meta.analysis_id))
            old = connection.execute(
                select(models.analysis_runs.c.payload).where(
                    models.analysis_runs.c.analysis_id == str(profile.meta.analysis_id)
                )
            ).scalar()
            if old is None:
                if state.status != "RUNNING" or any(
                    value is not None
                    for value in (
                        state.workspace_id,
                        state.commit_id,
                        state.workspace_ref,
                        state.budget_binding_ref,
                        state.run_policy_state_ref,
                    )
                ):
                    raise ValueError("BUDGET bootstrap cannot bypass workspace CAS")
                save_run(self.records, connection, state)
            elif (
                AnalysisRunState.model_validate_json(old).execution_budget_profile_ref
                != ref
                or AnalysisRunState.model_validate_json(old).analysis_input_ref
                != state.analysis_input_ref
            ):
                raise ValueError("BUDGET run state mismatch")
            return ref

    def pin(
        self, connection: Connection, ref: BudgetScopeRef, analysis_id: str
    ) -> None:
        table = models.budget_profiles
        old = connection.execute(
            select(table.c.ref).where(
                table.c.analysis_id == analysis_id, table.c.kind == ref.data_kind
            )
        ).scalar()
        payload = canonical_bytes(ref).decode()
        if old is not None:
            if old != payload:
                raise ValueError("BUDGET binding is already pinned for this analysis")
            return
        connection.execute(
            insert(table).values(
                analysis_id=analysis_id, kind=ref.data_kind, ref=payload
            )
        )

    def execution(
        self, connection: Connection, ref: BudgetScopeRef, analysis_id: str
    ) -> ExecutionBudgetProfile:
        table = models.budget_profiles
        pinned = connection.execute(
            select(table.c.ref).where(
                table.c.analysis_id == analysis_id, table.c.kind == ref.data_kind
            )
        ).scalar()
        if pinned != canonical_bytes(ref).decode():
            raise ValueError(
                "BUDGET unavailable: unpinned profile or consuming analysis mismatch"
            )
        profile = self.records.resolve(connection, ref)
        state = get_run(connection, analysis_id)
        expected = (
            state.budget_binding_ref
            if isinstance(profile, BudgetProfileBinding)
            else state.execution_budget_profile_ref
        )
        if expected != ref:
            raise ValueError("BUDGET exact run-state binding mismatch")
        if isinstance(profile, BudgetProfileBinding):
            self.validate_binding(connection, profile)
            return self.execution(
                connection, profile.execution_budget_profile_ref, analysis_id
            )
        if (
            not isinstance(profile, ExecutionBudgetProfile)
            or str(profile.meta.analysis_id) != analysis_id
            or profile.status != ProfileStatus.ACTIVE
        ):
            raise ValueError("BUDGET unavailable: ACTIVE execution profile required")
        return profile

    def validate_binding(
        self, connection: Connection, binding: BudgetProfileBinding
    ) -> None:
        if binding.status != ProfileStatus.ACTIVE:
            raise ValueError("BUDGET requires full ACTIVE binding")
        execution = self.execution(
            connection,
            binding.execution_budget_profile_ref,
            str(binding.meta.analysis_id),
        )
        if execution.purpose != binding.purpose:
            raise ValueError("BUDGET purpose mismatch")
        for ref, expected in (
            (binding.work_budget_profile_ref, WorkBudgetProfile),
            (binding.verification_budget_profile_ref, VerificationBudgetProfile),
            (
                binding.dynamic_lifecycle_profile_ref,
                DynamicReproductionLifecycleProfile,
            ),
        ):
            profile = self.records.resolve(connection, ref)
            if (
                not isinstance(profile, expected)
                or getattr(profile, "status", None) != ProfileStatus.ACTIVE
            ):
                raise ValueError("BUDGET requires all ACTIVE exact profiles")
            if (
                getattr(profile.meta, "analysis_id", None),
                getattr(profile.meta, "workspace_id", None),
                getattr(profile.meta, "commit_id", None),
            ) != (
                binding.meta.analysis_id,
                binding.meta.workspace_id,
                binding.meta.commit_id,
            ):
                raise ValueError("BUDGET profile scope mismatch")
            if (
                isinstance(profile, WorkBudgetProfile)
                and profile.purpose != binding.purpose
            ):
                raise ValueError("BUDGET purpose mismatch")

    def pin_binding(
        self,
        binding: BudgetProfileBinding,
        workspace_ref: RunStoredDataRef,
        analysis_state_ref: RunStoredDataRef | None = None,
    ) -> StoredDataRef:
        binding = BudgetProfileBinding.model_validate(binding)
        if not self.records.evidence.approved(binding):
            raise ValueError("BUDGET approval evidence is unavailable")
        with self.records.database.write() as connection:
            state = get_run(connection, str(binding.meta.analysis_id))
            if (
                analysis_state_ref != reference(state)
                or state.workspace_ref != workspace_ref
                or state.purpose != binding.purpose
            ):
                raise ValueError(
                    "STATE_VERSION_CONFLICT: workspace READY run state required"
                )
            self.validate_binding(connection, binding)
            workspace = self.records.resolve(connection, workspace_ref)
            if (
                not isinstance(workspace, CodeWorkspace)
                or workspace.status != "READY"
                or (workspace.analysis_id, workspace.workspace_id, workspace.commit_id)
                != (
                    binding.meta.analysis_id,
                    binding.meta.workspace_id,
                    binding.meta.commit_id,
                )
            ):
                raise ValueError("BUDGET requires a READY exact workspace")
            assert binding.approval_ref is not None
            ref = self.records.stage(connection, binding)
            assert isinstance(ref, StoredDataRef)
            self.records.publish(connection, ref)
            self.pin(connection, ref, str(binding.meta.analysis_id))
            updated = AnalysisRunState.model_validate(
                state.model_dump()
                | dict(
                    meta=next_meta(state.meta, self.clock, self.ids),
                    budget_binding_ref=ref,
                )
            )
            save_run(self.records, connection, updated, state)
            return ref
