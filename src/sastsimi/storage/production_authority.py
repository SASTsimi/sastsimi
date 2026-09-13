"""Exact authority closure inspection without a runtime, IDs or write methods."""

from datetime import datetime
from types import MappingProxyType

from sqlalchemy import Connection, select

from sastsimi.contracts.analysis import AnalysisRunInput, AnalysisRunState
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    DynamicReproductionLifecycleProfile,
    ExecutionBudgetProfile,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.production_authority import ProductionAuthorityCatalog
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.production_authority import ProductionAuthoritySnapshot

from . import models
from .repositories import SQLiteRecordStore
from .run_states import get_run


def load_authority_catalog(
    artifacts: ArtifactStore, run_input: AnalysisRunInput
) -> ProductionAuthorityCatalog:
    ref = run_input.production_authority_catalog_ref
    if ref is None:
        raise ValueError("PRODUCTION_AUTHORITY_CATALOG_REQUIRED")
    if ref.analysis_id != run_input.meta.analysis_id:
        raise ValueError("PRODUCTION_AUTHORITY_SCOPE_MISMATCH")
    with artifacts.open_verified(ref) as stream:
        data = stream.read()
    catalog = ProductionAuthorityCatalog.model_validate_json(data)
    if data != canonical_bytes(catalog):
        raise ValueError("PRODUCTION_AUTHORITY_CANONICAL_MISMATCH")
    if (
        catalog.analysis_id,
        catalog.workspace_id,
        catalog.commit_id,
        catalog.program_id,
        catalog.purpose,
        catalog.production_profile_ref,
        catalog.production_onboarding_ref,
    ) != (
        run_input.meta.analysis_id,
        run_input.workspace_id,
        run_input.commit_id,
        run_input.program_id,
        run_input.purpose,
        run_input.production_profile_ref,
        run_input.production_onboarding_ref,
    ):
        raise ValueError("PRODUCTION_AUTHORITY_SCOPE_MISMATCH")
    return catalog


def resolve_catalog_profiles(
    records: SQLiteRecordStore,
    connection: Connection,
    catalog: ProductionAuthorityCatalog,
) -> tuple[
    WorkBudgetProfile, VerificationBudgetProfile, DynamicReproductionLifecycleProfile
]:
    def resolve[
        T: WorkBudgetProfile
        | VerificationBudgetProfile
        | DynamicReproductionLifecycleProfile
    ](ref: StoredDataRef, expected: type[T]) -> T:
        record = records.resolve(connection, ref)
        if not isinstance(record, expected) or record.status != "ACTIVE":
            raise ValueError("PRODUCTION_AUTHORITY_PROFILE_NOT_ACTIVE")
        if (
            record.meta.analysis_id,
            record.meta.workspace_id,
            record.meta.commit_id,
        ) != (catalog.analysis_id, catalog.workspace_id, catalog.commit_id):
            raise ValueError("PRODUCTION_AUTHORITY_SCOPE_MISMATCH")
        if isinstance(record, WorkBudgetProfile) and record.purpose != catalog.purpose:
            raise ValueError("PRODUCTION_AUTHORITY_PURPOSE_MISMATCH")
        current = connection.execute(
            select(models.current_records.c.record_id).where(
                models.current_records.c.logical_record_id
                == str(record.meta.logical_record_id)
            )
        ).scalar()
        if current != str(ref.record_id):
            raise ValueError("PRODUCTION_AUTHORITY_PROFILE_STALE")
        return record

    work = resolve(catalog.work_budget_profile_ref, WorkBudgetProfile)
    verification = resolve(
        catalog.verification_budget_profile_ref, VerificationBudgetProfile
    )
    dynamic = resolve(
        catalog.dynamic_lifecycle_profile_ref, DynamicReproductionLifecycleProfile
    )
    if dynamic.preflight_budget_ref != catalog.work_budget_profile_ref:
        raise ValueError("PRODUCTION_AUTHORITY_PREFLIGHT_MISMATCH")
    for item in catalog.role_identities:
        if isinstance(item.identity_ref, StoredDataRef):
            resolve(item.identity_ref, WorkBudgetProfile)
    return work, verification, dynamic


def require_binding_catalog(
    catalog: ProductionAuthorityCatalog, binding: BudgetProfileBinding
) -> None:
    if (
        binding.meta.analysis_id,
        binding.meta.workspace_id,
        binding.meta.commit_id,
        binding.purpose,
        binding.execution_budget_profile_ref,
        binding.work_budget_profile_ref,
        binding.verification_budget_profile_ref,
        binding.dynamic_lifecycle_profile_ref,
    ) != (
        catalog.analysis_id,
        catalog.workspace_id,
        catalog.commit_id,
        catalog.purpose,
        catalog.execution_budget_profile_ref,
        catalog.work_budget_profile_ref,
        catalog.verification_budget_profile_ref,
        catalog.dynamic_lifecycle_profile_ref,
    ):
        raise ValueError("PRODUCTION_AUTHORITY_BINDING_MISMATCH")


class ProductionAuthorityInspector:
    """Resolve relational authority; composition checks onboarding approval."""

    def __init__(self, records: SQLiteRecordStore, artifacts: ArtifactStore) -> None:
        self._records = records
        self._artifacts = artifacts

    def inspect(
        self,
        analysis_id: str,
        *,
        now: datetime,
        expected_state: AnalysisRunState | None = None,
    ) -> ProductionAuthoritySnapshot:
        # An explicit BEGIN is necessary: this Database uses SQLite autocommit.
        # Every relational reference is resolved in the same read snapshot.
        with self._records.database.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN")
            state = get_run(connection, analysis_id)
            current_state = connection.execute(
                select(models.current_records.c.record_id).where(
                    models.current_records.c.logical_record_id
                    == str(state.meta.logical_record_id)
                )
            ).scalar()
            if current_state != str(state.meta.record_id):
                raise ValueError("PRODUCTION_AUTHORITY_STATE_STALE")
            if expected_state is not None and state != expected_state:
                raise ValueError("PRODUCTION_AUTHORITY_STATE_CHANGED")
            if (
                str(state.meta.analysis_id) != analysis_id
                or self._records.resolve(connection, reference(state)) != state
                or state.purpose != "PRODUCTION"
            ):
                raise ValueError("PRODUCTION_AUTHORITY_STATE_INVALID")
            run_input = self._records.resolve(connection, state.analysis_input_ref)
            if not isinstance(run_input, AnalysisRunInput):
                raise ValueError("PRODUCTION_AUTHORITY_INPUT_INVALID")
            catalog = load_authority_catalog(self._artifacts, run_input)
            if (
                catalog.analysis_id != state.meta.analysis_id
                or catalog.program_id != state.program_id
                or catalog.execution_budget_profile_ref
                != state.execution_budget_profile_ref
                or (
                    state.workspace_id is not None
                    and state.workspace_id != catalog.workspace_id
                )
                or (
                    state.commit_id is not None and state.commit_id != catalog.commit_id
                )
            ):
                raise ValueError("PRODUCTION_AUTHORITY_SCOPE_MISMATCH")
            self._require_pin(
                connection, state.execution_budget_profile_ref, analysis_id
            )
            execution = self._records.resolve(
                connection, state.execution_budget_profile_ref
            )
            if (
                not isinstance(execution, ExecutionBudgetProfile)
                or execution.purpose != "PRODUCTION"
            ):
                raise ValueError("PRODUCTION_AUTHORITY_EXECUTION_INVALID")
            self._approval(execution, now)
            work, verification, dynamic = resolve_catalog_profiles(
                self._records, connection, catalog
            )
            if state.budget_binding_ref is None:
                raise ValueError("PRODUCTION_AUTHORITY_BINDING_NOT_PINNED")
            self._require_pin(connection, state.budget_binding_ref, analysis_id)
            binding = self._records.resolve(connection, state.budget_binding_ref)
            if not isinstance(binding, BudgetProfileBinding):
                raise ValueError("PRODUCTION_AUTHORITY_BINDING_INVALID")
            self._approval(binding, now)
            require_binding_catalog(catalog, binding)
            return ProductionAuthoritySnapshot(
                catalog,
                execution,
                binding,
                work,
                verification,
                dynamic,
                MappingProxyType(
                    {item.role: item.identity_ref for item in catalog.role_identities}
                ),
            )

    @staticmethod
    def _require_pin(
        connection: Connection, ref: BudgetScopeRef, analysis_id: str
    ) -> None:
        pinned = connection.execute(
            select(models.budget_profiles.c.ref).where(
                models.budget_profiles.c.analysis_id == analysis_id,
                models.budget_profiles.c.kind == ref.data_kind,
            )
        ).scalar()
        if pinned != canonical_bytes(ref).decode():
            raise ValueError("PRODUCTION_AUTHORITY_PROFILE_NOT_PINNED")

    @staticmethod
    def _approval(
        profile: ExecutionBudgetProfile | BudgetProfileBinding, now: datetime
    ) -> None:
        if (
            profile.status != "ACTIVE"
            or profile.approved_at is None
            or profile.approval_ref is None
            or not profile.approved_by
            or profile.approved_at > now
            or profile.meta.created_at > now
        ):
            raise ValueError("PRODUCTION_AUTHORITY_APPROVAL_INVALID")
