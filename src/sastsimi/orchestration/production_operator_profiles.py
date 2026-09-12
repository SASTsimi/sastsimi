"""Operator-owned production budgets, identities, and exact output closures."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from threading import RLock
from types import MappingProxyType
from typing import Protocol

from sastsimi.config.production_profile import ProductionBudgetSettings
from sastsimi.contracts.actions import ActionRequest, CheckType, RequesterRole
from sastsimi.contracts.analysis import AnalysisRunState, AnalysisStartRequest
from sastsimi.contracts.budget import (
    WORK_OPERATIONS,
    BudgetAgentRole,
    BudgetProfileBinding,
    DynamicReproductionLifecycleProfile,
    ExecutionBudgetProfile,
    OperationKind,
    ProfileStatus,
    Purpose,
    VerificationBudgetProfile,
    WorkBudgetLimit,
    WorkBudgetProfile,
)
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.ids import (
    LogicalRecordId,
    ProgramId,
    RecordId,
    StoredDataId,
)
from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.work import WorkExecutionState, WorkType
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.trusted_evidence import UnprovenEvidence

from .run_initialization import ActiveBudgetProfilesPort
from .run_scope_plan import PlannedRunScope


class BudgetConfigurationPublisher(Protocol):
    """Narrow configuration-registry seam required by the operator catalog."""

    def register_work_budget(self, record: WorkBudgetProfile) -> StoredDataRef: ...

    def register_verification_budget(
        self, record: VerificationBudgetProfile
    ) -> StoredDataRef: ...

    def register_dynamic_lifecycle(
        self, record: DynamicReproductionLifecycleProfile
    ) -> StoredDataRef: ...


@dataclass(frozen=True, slots=True)
class _OutputApproval:
    action_hash: str
    work_id: str
    attempt_id: str | None
    work_ref: BudgetScopeRef
    output_refs: tuple[RecordRef, ...]


class ProductionOperatorProfiles(ActiveBudgetProfilesPort):
    """Create one immutable budget/identity catalog from trusted CLI config."""

    def __init__(
        self,
        *,
        scope: PlannedRunScope,
        program_id: str,
        settings: ProductionBudgetSettings,
        clock: Clock,
        ids: IdGenerator,
    ) -> None:
        self.scope = scope
        self.program_id = ProgramId(program_id)
        self.settings = settings
        self._clock = clock
        self._ids = ids
        self._approved_at = clock.now()
        self._execution_approval_ref = self._run_provenance_ref(
            "operator_approval", settings.approval_key
        )
        self._binding_approval_ref = self._code_provenance_ref(
            "operator_approval", settings.approval_key
        )
        self._pricing_ref = self._run_provenance_ref(
            "pricing_revision", settings.pricing_revision
        )
        self.execution_profile = self._execution()
        self.work_profile = self._work_profile(settings.profile_key)
        self.verification_profile = self._verification_profile()
        self.dynamic_profile = self._dynamic_profile()
        role_profiles: dict[RequesterRole, WorkBudgetProfile] = {
            role: self._work_profile(
                f"{settings.profile_key}-identity-{role.value.lower()}"
            )
            for role in RequesterRole
            if role != RequesterRole.REPOSITORY_LOADER
        }
        self._role_profiles: Mapping[RequesterRole, WorkBudgetProfile] = (
            MappingProxyType(role_profiles)
        )
        self.binding = self._binding()
        self._published = False

    @property
    def role_profiles(self) -> Mapping[RequesterRole, WorkBudgetProfile]:
        return self._role_profiles

    def identity_ref(self, role: RequesterRole) -> BudgetScopeRef:
        if role == RequesterRole.REPOSITORY_LOADER:
            ref = reference(self.execution_profile)
            assert isinstance(ref, RunStoredDataRef)
            return ref
        ref = reference(self._role_profiles[role])
        assert isinstance(ref, StoredDataRef)
        return ref

    def publish_code_profiles(self, publisher: BudgetConfigurationPublisher) -> None:
        """Publish the exact pre-approved code-scoped profiles before work starts."""

        records = (self.work_profile, *self._role_profiles.values())
        for record in records:
            if publisher.register_work_budget(record) != reference(record):
                raise ValueError("OPERATOR_PROFILE_PUBLICATION_MISMATCH")
        if publisher.register_verification_budget(
            self.verification_profile
        ) != reference(
            self.verification_profile
        ) or publisher.register_dynamic_lifecycle(self.dynamic_profile) != reference(
            self.dynamic_profile
        ):
            raise ValueError("OPERATOR_PROFILE_PUBLICATION_MISMATCH")
        self._published = True

    def resolve_active_execution(
        self, request: AnalysisStartRequest
    ) -> ExecutionBudgetProfile:
        self._require_request(request)
        return self.execution_profile

    def require_current_execution(self, profile: ExecutionBudgetProfile) -> None:
        if profile != self.execution_profile:
            raise ValueError("OPERATOR_EXECUTION_PROFILE_NOT_CURRENT")

    def resolve_active_binding(
        self, request: AnalysisStartRequest, state: AnalysisRunState
    ) -> BudgetProfileBinding:
        self._require_request(request)
        execution_ref = reference(self.execution_profile)
        if (
            not self._published
            or state.meta.analysis_id != self.scope.analysis_id
            or state.workspace_id != self.scope.workspace_id
            or state.commit_id != self.scope.commit_id
            or state.program_id != self.program_id
            or state.purpose != Purpose.PRODUCTION
            or state.status != "RUNNING"
            or state.execution_budget_profile_ref != execution_ref
            or state.budget_binding_ref is not None
            or state.workspace_ref is None
        ):
            raise ValueError("OPERATOR_PROFILE_SCOPE_MISMATCH")
        return self.binding

    def require_current_binding(self, binding: BudgetProfileBinding) -> None:
        if not self._published or binding != self.binding:
            raise ValueError("OPERATOR_BUDGET_BINDING_NOT_CURRENT")

    def _require_request(self, request: AnalysisStartRequest) -> None:
        if (
            request.repository_ref != self.scope.repository_ref
            or request.requested_git_ref.lower() != str(self.scope.commit_id)
            or request.program_id != self.program_id
            or request.purpose != Purpose.PRODUCTION
        ):
            raise ValueError("OPERATOR_PROFILE_SCOPE_MISMATCH")

    def _run_meta(self, kind: str) -> RunMeta:
        record_id = self._ids.new(RecordId)
        return RunMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=kind,
            schema_version="1.0.0",
            revision_number=1,
            previous_record_id=None,
            created_at=self._approved_at,
            analysis_id=self.scope.analysis_id,
        )

    def _record_meta(self, kind: str) -> RecordMeta:
        record_id = self._ids.new(RecordId)
        return RecordMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=kind,
            schema_version="1.0.0",
            revision_number=1,
            previous_record_id=None,
            created_at=self._approved_at,
            analysis_id=self.scope.analysis_id,
            workspace_id=self.scope.workspace_id,
            commit_id=self.scope.commit_id,
            hypothesis_id=None,
            attempt_id=None,
        )

    def _run_provenance_ref(self, kind: str, key: str) -> RunStoredDataRef:
        digest = content_hash(
            ["operator-profile", kind, key, str(self.scope.analysis_id)]
        )
        record_id = self._ids.new(RecordId)
        return RunStoredDataRef(
            stored_data_id=StoredDataId(str(record_id)),
            data_kind=kind,
            content_hash=digest,
            analysis_id=self.scope.analysis_id,
            record_id=record_id,
        )

    def _code_provenance_ref(self, kind: str, key: str) -> StoredDataRef:
        digest = content_hash(
            [
                "operator-profile",
                kind,
                key,
                str(self.scope.analysis_id),
                str(self.scope.workspace_id),
                str(self.scope.commit_id),
            ]
        )
        record_id = self._ids.new(RecordId)
        return StoredDataRef(
            stored_data_id=StoredDataId(str(record_id)),
            data_kind=kind,
            content_hash=digest,
            workspace_id=self.scope.workspace_id,
            commit_id=self.scope.commit_id,
            record_id=record_id,
        )

    def _execution(self) -> ExecutionBudgetProfile:
        values = self.settings
        return ExecutionBudgetProfile(
            meta=self._run_meta("execution_budget_profile"),
            profile_key=values.profile_key,
            purpose=Purpose.PRODUCTION,
            max_analysis_elapsed_ms=values.max_analysis_elapsed_ms,
            max_total_cost_minor_units=values.max_total_cost_minor_units,
            currency=values.currency,
            pricing_revision_ref=self._pricing_ref,
            max_total_work=values.max_total_work,
            max_total_llm_calls=values.max_total_llm_calls,
            max_total_retries=values.max_total_retries,
            max_parallel_work=values.max_parallel_work,
            approval_ref=self._execution_approval_ref,
            approved_by=values.approved_by,
            approved_at=self._approved_at,
            status=ProfileStatus.ACTIVE,
        )

    def _limits(self) -> tuple[WorkBudgetLimit, ...]:
        values = self.settings
        limits = [
            WorkBudgetLimit(
                limit_key=f"{work.value.lower()}-{operation.value.lower()}",
                work_type=work,
                operation_kind=operation,
                agent_role=role,
                timeout_ms=values.work_timeout_ms,
                max_attempts=values.max_attempts_per_work,
                max_calls_per_work=values.max_calls_per_work,
                max_items_per_work=values.max_items_per_work,
            )
            for work, (operation, role) in WORK_OPERATIONS.items()
        ]
        limits.append(
            WorkBudgetLimit(
                limit_key="policy_fetch-policy_parse",
                work_type=WorkType.POLICY_FETCH,
                operation_kind=OperationKind.POLICY_PARSE,
                agent_role=BudgetAgentRole.POLICY_PARSER,
                timeout_ms=values.work_timeout_ms,
                max_attempts=values.max_attempts_per_work,
                max_calls_per_work=values.max_calls_per_work,
                max_items_per_work=values.max_items_per_work,
            )
        )
        return tuple(limits)

    def _work_profile(self, profile_key: str) -> WorkBudgetProfile:
        return WorkBudgetProfile(
            meta=self._record_meta("work_budget_profile"),
            profile_key=profile_key,
            purpose=Purpose.PRODUCTION,
            limits=self._limits(),
            unlisted_operation="DENY",
            status=ProfileStatus.ACTIVE,
        )

    def _verification_profile(self) -> VerificationBudgetProfile:
        values = self.settings
        return VerificationBudgetProfile(
            meta=self._record_meta("verification_budget_profile"),
            profile_key=f"{values.profile_key}-verification",
            max_verification_elapsed_ms=values.max_verification_elapsed_ms,
            max_work_per_verification=values.max_work_per_verification,
            max_llm_calls_per_verification=values.max_llm_calls_per_verification,
            max_retries_per_work=values.max_retries_per_work,
            max_parallel_evidence_calls=values.max_parallel_evidence_calls,
            status=ProfileStatus.ACTIVE,
        )

    def _dynamic_profile(self) -> DynamicReproductionLifecycleProfile:
        work_ref = reference(self.work_profile)
        assert isinstance(work_ref, StoredDataRef)
        return DynamicReproductionLifecycleProfile(
            meta=self._record_meta("dynamic_reproduction_lifecycle_profile"),
            profile_key=f"{self.settings.profile_key}-dynamic",
            preflight_budget_ref=work_ref,
            preflight_budget_source="WORK_REMAINING_TIME",
            max_new_attempts=self.settings.max_dynamic_attempts,
            status=ProfileStatus.ACTIVE,
            created_at=self._approved_at,
        )

    def _binding(self) -> BudgetProfileBinding:
        execution_ref = reference(self.execution_profile)
        work_ref = reference(self.work_profile)
        verification_ref = reference(self.verification_profile)
        dynamic_ref = reference(self.dynamic_profile)
        assert isinstance(execution_ref, RunStoredDataRef)
        assert isinstance(work_ref, StoredDataRef)
        assert isinstance(verification_ref, StoredDataRef)
        assert isinstance(dynamic_ref, StoredDataRef)
        return BudgetProfileBinding(
            meta=self._record_meta("budget_profile_binding"),
            binding_key=f"{self.settings.profile_key}-binding",
            purpose=Purpose.PRODUCTION,
            execution_budget_profile_ref=execution_ref,
            work_budget_profile_ref=work_ref,
            verification_budget_profile_ref=verification_ref,
            dynamic_lifecycle_profile_ref=dynamic_ref,
            approval_ref=self._binding_approval_ref,
            approved_by=self.settings.approved_by,
            approved_at=self._approved_at,
            status=ProfileStatus.ACTIVE,
        )


class ProductionTrustedEvidence(UnprovenEvidence):
    """Immutable operator authority plus attempt-local output closure evidence."""

    def __init__(self, profiles: ProductionOperatorProfiles) -> None:
        self._approved = frozenset(
            content_hash(item)
            for item in (profiles.execution_profile, profiles.binding)
        )
        self._budget_approved = frozenset(
            content_hash(item)
            for item in (
                profiles.work_profile,
                profiles.verification_profile,
                profiles.dynamic_profile,
                *profiles.role_profiles.values(),
            )
        )
        identities = {profiles.identity_ref(role): role for role in RequesterRole}
        self._identities: Mapping[BudgetScopeRef, RequesterRole] = MappingProxyType(
            identities
        )
        self._output_approvals: dict[str, _OutputApproval] = {}
        self._approval_lock = RLock()

    def identity_ref(self, role: RequesterRole) -> BudgetScopeRef:
        for ref, bound_role in self._identities.items():
            if bound_role == role:
                return ref
        raise LookupError("PRODUCTION_IDENTITY_NOT_BOUND")

    def identity_role(self, ref: BudgetScopeRef) -> RequesterRole | None:
        return self._identities.get(ref)

    def approved(self, profile: ExecutionBudgetProfile | BudgetProfileBinding) -> bool:
        return content_hash(profile) in self._approved

    def pricing(self, profile: ExecutionBudgetProfile) -> bool:
        return content_hash(profile) in self._approved

    def budget_configuration_approved(
        self,
        profile: WorkBudgetProfile
        | VerificationBudgetProfile
        | DynamicReproductionLifecycleProfile,
    ) -> bool:
        return content_hash(profile) in self._budget_approved

    @contextmanager
    def output_approval(
        self,
        action: ActionRequest,
        work: WorkExecutionState,
        output_refs: tuple[RecordRef, ...],
    ) -> Iterator[None]:
        if (
            action.work_ref is None
            or action.work_ref != reference(work)
            or not output_refs
            or len(output_refs) != len(set(output_refs))
        ):
            raise ValueError("PRODUCTION_OUTPUT_APPROVAL_SCOPE_MISMATCH")
        key = str(action.action_id)
        approval = _OutputApproval(
            action_hash=content_hash(action),
            work_id=str(work.work_id),
            attempt_id=(
                None if work.active_attempt_id is None else str(work.active_attempt_id)
            ),
            work_ref=action.work_ref,
            output_refs=output_refs,
        )
        with self._approval_lock:
            if key in self._output_approvals:
                raise ValueError("PRODUCTION_OUTPUT_APPROVAL_ALREADY_ACTIVE")
            self._output_approvals[key] = approval
        try:
            yield
        finally:
            with self._approval_lock:
                if self._output_approvals.get(key) == approval:
                    del self._output_approvals[key]

    def authorized_outputs(self, action: ActionRequest) -> tuple[RecordRef, ...] | None:
        with self._approval_lock:
            approval = self._output_approvals.get(str(action.action_id))
        attempt_id = getattr(action.meta, "attempt_id", None)
        if (
            approval is None
            or approval.action_hash != content_hash(action)
            or approval.work_ref != action.work_ref
            or approval.attempt_id != (None if attempt_id is None else str(attempt_id))
        ):
            return None
        return approval.output_refs

    def action_evidence(
        self, action: ActionRequest, check: CheckType
    ) -> tuple[BudgetScopeRef, ...] | None:
        if action.requester_identity_ref not in self._identities:
            return None
        refs: list[BudgetScopeRef] = [action.requester_identity_ref]
        if check in {CheckType.PROVIDER, CheckType.SESSION, CheckType.REDACTION}:
            if action.provider_profile_ref is not None:
                refs.append(action.provider_profile_ref)
            if action.llm_call_spec_ref is not None:
                refs.append(action.llm_call_spec_ref)
        return tuple(refs)

    def item_count(self, action: ActionRequest, work: WorkExecutionState) -> int:
        del work
        return max(1, len(action.input_refs))


__all__ = [
    "BudgetConfigurationPublisher",
    "ProductionOperatorProfiles",
    "ProductionTrustedEvidence",
]
