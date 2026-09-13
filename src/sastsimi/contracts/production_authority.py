"""Immutable configuration artifact; neither a domain result nor execution authority."""

from typing import Literal, Self

from pydantic import model_validator

from .actions import RequesterRole
from .base import ContractModel
from .ids import AnalysisId, CommitId, ProgramId, WorkspaceId
from .refs import BudgetScopeRef, RunStoredDataRef, StoredDataRef, require_record_ref


class ProductionRoleIdentity(ContractModel):
    role: RequesterRole
    identity_ref: BudgetScopeRef


class ProductionAuthorityCatalog(ContractModel):
    schema_version: Literal["1"]
    artifact_scope: Literal["ANALYSIS_OPERATOR_AUTHORITY"]
    analysis_id: AnalysisId
    workspace_id: WorkspaceId
    commit_id: CommitId
    program_id: ProgramId
    purpose: Literal["PRODUCTION"]
    production_profile_ref: RunStoredDataRef
    production_onboarding_ref: RunStoredDataRef
    execution_budget_profile_ref: RunStoredDataRef
    work_budget_profile_ref: StoredDataRef
    verification_budget_profile_ref: StoredDataRef
    dynamic_lifecycle_profile_ref: StoredDataRef
    role_identities: tuple[ProductionRoleIdentity, ...]

    @model_validator(mode="after")
    def exact_closure(self) -> Self:
        if tuple(item.role for item in self.role_identities) != tuple(RequesterRole):
            raise ValueError("PRODUCTION_AUTHORITY_ROLE_SET_INVALID")
        refs = tuple(item.identity_ref for item in self.role_identities)
        if len(refs) != len(set(refs)) or self.work_budget_profile_ref in refs:
            raise ValueError("PRODUCTION_AUTHORITY_IDENTITY_DUPLICATED")
        for artifact_ref in (
            self.production_profile_ref,
            self.production_onboarding_ref,
        ):
            if (
                artifact_ref.data_kind != "artifact"
                or artifact_ref.record_id is not None
                or str(artifact_ref.stored_data_id) != artifact_ref.content_hash
                or artifact_ref.analysis_id != self.analysis_id
            ):
                raise ValueError("PRODUCTION_AUTHORITY_DESCRIPTOR_INVALID")
        require_record_ref(
            self.execution_budget_profile_ref, "execution_budget_profile"
        )
        if self.execution_budget_profile_ref.analysis_id != self.analysis_id:
            raise ValueError("PRODUCTION_AUTHORITY_SCOPE_MISMATCH")
        for ref, kind in (
            (self.work_budget_profile_ref, "work_budget_profile"),
            (self.verification_budget_profile_ref, "verification_budget_profile"),
            (
                self.dynamic_lifecycle_profile_ref,
                "dynamic_reproduction_lifecycle_profile",
            ),
        ):
            require_record_ref(ref, kind)
            self._code_scope(ref)
        for item in self.role_identities:
            if item.role == RequesterRole.REPOSITORY_LOADER:
                if item.identity_ref != self.execution_budget_profile_ref:
                    raise ValueError("PRODUCTION_AUTHORITY_LOADER_MISMATCH")
            elif isinstance(item.identity_ref, StoredDataRef):
                require_record_ref(item.identity_ref, "work_budget_profile")
                self._code_scope(item.identity_ref)
            else:
                raise ValueError("PRODUCTION_AUTHORITY_IDENTITY_SCOPE_INVALID")
        return self

    def _code_scope(self, ref: StoredDataRef) -> None:
        if (ref.workspace_id, ref.commit_id) != (self.workspace_id, self.commit_id):
            raise ValueError("PRODUCTION_AUTHORITY_SCOPE_MISMATCH")
