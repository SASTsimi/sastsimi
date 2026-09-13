"""Deterministic runtime support used by the local fake pipeline."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock

from sastsimi.contracts.actions import ActionRequest, CheckType, RequesterRole
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    DynamicReproductionLifecycleProfile,
    ExecutionBudgetProfile,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.capabilities import CapabilityApprovalEvidence
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.ids import (
    ActionId,
    AnalysisId,
    AttemptId,
    CommitId,
    LogicalRecordId,
    OpaqueId,
    ProgramId,
    RecordId,
    WorkId,
    WorkspaceId,
)
from sastsimi.contracts.llm import LLMRecord
from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
)
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.trusted_evidence import UnprovenEvidence
from sastsimi.runtime.services import RuntimeServices

ANALYSIS_ID = AnalysisId("fake-analysis")
WORKSPACE_ID = WorkspaceId("fake-workspace")
COMMIT_ID = CommitId("fake-commit")
PROGRAM_ID = ProgramId("fake-program")


class FakeClock:
    def __init__(self) -> None:
        self.wall_time = datetime(2026, 9, 8, tzinfo=UTC)
        self.tick = 0

    def now(self) -> datetime:
        return self.wall_time

    def monotonic_ms(self) -> int:
        return self.tick


class FakeIds:
    def __init__(self) -> None:
        self.index = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.index += 1
        return kind(f"fake-{kind.__name__.lower()}-{self.index}")


@dataclass(frozen=True)
class _OutputApproval:
    action_id: ActionId
    work_id: WorkId
    attempt_id: AttemptId | None
    work_ref: BudgetScopeRef
    output_refs: tuple[RecordRef, ...]


class FakeEvidence(UnprovenEvidence):
    """Evidence controlled by composition, never by workflow inputs."""

    def __init__(self) -> None:
        self.approvals: set[str] = set()
        self.budget_approvals: set[str] = set()
        self.playbook_approvals: set[str] = set()
        self.llm_approvals: set[str] = set()
        self.sandbox_approvals: set[str] = set()
        self.static_tool_approvals: set[str] = set()
        self.capability_approvals: set[str] = set()
        self.identities: dict[BudgetScopeRef, RequesterRole] = {}
        self._role_identities: dict[RequesterRole, BudgetScopeRef] = {}
        self._output_approvals: dict[ActionId, _OutputApproval] = {}
        self._approval_lock = RLock()

    def bind_identity(self, ref: BudgetScopeRef, role: RequesterRole) -> None:
        existing = self.identities.get(ref)
        if existing is not None and existing != role:
            raise ValueError("FAKE_IDENTITY_ROLE_IMMUTABLE")
        role_identity = self._role_identities.get(role)
        if role_identity is not None and role_identity != ref:
            raise ValueError("FAKE_ROLE_IDENTITY_IMMUTABLE")
        self.identities[ref] = role
        self._role_identities[role] = ref

    def identity(self, role: RequesterRole) -> BudgetScopeRef:
        try:
            return self._role_identities[role]
        except KeyError as error:
            raise LookupError(f"FAKE_IDENTITY_NOT_BOUND: {role.value}") from error

    def stored_identity(self, role: RequesterRole) -> StoredDataRef:
        ref = self.identity(role)
        if not isinstance(ref, StoredDataRef):
            raise TypeError(f"FAKE_STORED_IDENTITY_REQUIRED: {role.value}")
        return ref

    @contextmanager
    def output_approval(
        self,
        action: ActionRequest,
        work: WorkExecutionState,
        output_refs: tuple[RecordRef, ...],
    ) -> Iterator[None]:
        if action.work_ref is None:
            raise ValueError("FAKE_OUTPUT_APPROVAL_SCOPE_MISMATCH")
        approval = _OutputApproval(
            action_id=action.action_id,
            work_id=work.work_id,
            attempt_id=work.active_attempt_id,
            work_ref=action.work_ref,
            output_refs=output_refs,
        )
        with self._approval_lock:
            if action.action_id in self._output_approvals:
                raise ValueError("FAKE_OUTPUT_APPROVAL_ALREADY_ACTIVE")
            self._output_approvals[action.action_id] = approval
        try:
            yield
        finally:
            with self._approval_lock:
                if self._output_approvals.get(action.action_id) == approval:
                    del self._output_approvals[action.action_id]

    def authorized_outputs(self, action: ActionRequest) -> tuple[RecordRef, ...] | None:
        with self._approval_lock:
            approval = self._output_approvals.get(action.action_id)
        if (
            approval is None
            or action.work_ref != approval.work_ref
            or getattr(action.meta, "attempt_id", None) != approval.attempt_id
        ):
            return None
        return approval.output_refs

    def identity_role(self, ref: BudgetScopeRef) -> RequesterRole | None:
        return self.identities.get(ref)

    def approved(self, profile: ExecutionBudgetProfile | BudgetProfileBinding) -> bool:
        return content_hash(profile) in self.approvals

    def pricing(self, profile: ExecutionBudgetProfile) -> bool:
        return content_hash(profile) in self.approvals

    def budget_configuration_approved(
        self,
        profile: WorkBudgetProfile
        | VerificationBudgetProfile
        | DynamicReproductionLifecycleProfile,
    ) -> bool:
        return content_hash(profile) in self.budget_approvals

    def playbook_configuration_approved(
        self, record: VerificationPlaybook | PlaybookPolicy
    ) -> bool:
        return content_hash(record) in self.playbook_approvals

    def llm_configuration_approved(self, record: LLMRecord) -> bool:
        return content_hash(record) in self.llm_approvals

    def sandbox_configuration_approved(self, profile: SandboxProfile) -> bool:
        return content_hash(profile) in self.sandbox_approvals

    def static_tool_configuration_approved(self, profile: StaticToolProfile) -> bool:
        return content_hash(profile) in self.static_tool_approvals

    def capability_approval_authorized(
        self, evidence: CapabilityApprovalEvidence
    ) -> bool:
        return content_hash(evidence) in self.capability_approvals

    def action_evidence(
        self, action: ActionRequest, check: CheckType
    ) -> tuple[BudgetScopeRef, ...] | None:
        if action.requester_identity_ref not in self.identities:
            return None
        refs: list[BudgetScopeRef] = [action.requester_identity_ref]
        refs.extend(
            ref
            for ref in action.input_refs
            if isinstance(ref, StoredDataRef) and ref.data_kind == "static_tool_profile"
        )
        if check in {CheckType.PROVIDER, CheckType.SESSION, CheckType.REDACTION}:
            if action.provider_profile_ref is not None:
                refs.append(action.provider_profile_ref)
            if action.llm_call_spec_ref is not None:
                refs.append(action.llm_call_spec_ref)
        return tuple(refs)

    def item_count(self, action: ActionRequest, work: WorkExecutionState) -> int | None:
        return 1


class FakeRecordFactory:
    """Create deterministic metadata and artifacts without exposing scenario state."""

    def __init__(self, clock: FakeClock, ids: FakeIds) -> None:
        self.clock = clock
        self.ids = ids
        self._runtime: RuntimeServices | None = None
        self._artifact_refs: dict[str, StoredDataRef] = {}

    def attach_runtime(self, runtime: RuntimeServices) -> None:
        if self._runtime is not None and self._runtime is not runtime:
            raise ValueError("FAKE_RECORD_FACTORY_ALREADY_ATTACHED")
        self._runtime = runtime

    def run_meta(self, kind: str) -> RunMeta:
        record_id = self.ids.new(RecordId)
        return RunMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=kind,
            schema_version="1.0.0",
            analysis_id=ANALYSIS_ID,
            revision_number=1,
            previous_record_id=None,
            created_at=self.clock.now(),
        )

    def record_meta(
        self,
        kind: str,
        *,
        hypothesis_id: str | None = None,
        attempt_id: str | None = None,
    ) -> RecordMeta:
        record_id = self.ids.new(RecordId)
        return RecordMeta.model_validate_json(
            canonical_bytes(
                dict(
                    record_id=record_id,
                    logical_record_id=str(record_id),
                    record_type=kind,
                    schema_version="1.0.0",
                    analysis_id=ANALYSIS_ID,
                    revision_number=1,
                    previous_record_id=None,
                    created_at=self.clock.now(),
                    workspace_id=WORKSPACE_ID,
                    commit_id=COMMIT_ID,
                    hypothesis_id=hypothesis_id,
                    attempt_id=attempt_id,
                )
            )
        )

    def artifact(self, kind: str, *, record: bool = False) -> RecordRef:
        del record
        if self._runtime is None:
            raise RuntimeError("FAKE_ARTIFACT_STORE_NOT_READY")
        cached = self._artifact_refs.get(kind)
        if cached is not None:
            return cached
        data = f"sastsimi deterministic fake artifact: {kind}\n".encode()
        staged = self._runtime.unit_of_work.artifacts.stage_bytes(
            data, "application/octet-stream"
        )
        committed = self._runtime.unit_of_work.artifacts.commit(staged)
        self._artifact_refs[kind] = committed
        return committed

    def stored_artifact(self, kind: str) -> StoredDataRef:
        ref = self.artifact(kind)
        if not isinstance(ref, StoredDataRef):
            raise ValueError("FAKE_ARTIFACT_SCOPE_MISMATCH")
        return ref

    def opaque_run_ref(self, kind: str) -> RunStoredDataRef:
        return RunStoredDataRef.model_validate_json(
            canonical_bytes(
                dict(
                    stored_data_id=f"fake-{kind}",
                    data_kind=kind,
                    record_id=f"fake-{kind}-record",
                    content_hash=content_hash(["fake", kind]),
                    analysis_id=ANALYSIS_ID,
                )
            )
        )
