"""Shared deterministic state, metadata and persisted query facade."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Protocol

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.dynamic import (
    CleanupResult,
    SandboxCommandRecord,
    SandboxEnvironment,
)
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    LogicalRecordId,
    ProgramId,
    RecordId,
    WorkspaceId,
)
from sastsimi.contracts.llm import (
    LLMInvocationRequest,
    LLMInvocationResult,
    ProviderValidationEvidence,
)
from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import RecordRef, RunStoredDataRef, StoredDataRef
from sastsimi.contracts.reporting import ReportDraft
from sastsimi.contracts.static import ToolRunResult
from sastsimi.ports.dto import (
    ApprovedSandboxCommand,
    CapabilityProbeResult,
    SandboxCleanupRequest,
    SandboxPrepareRequest,
    StaticToolRequest,
)
from sastsimi.ports.verification_assembly import VerificationAssemblyPort
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .fake_support import FakeClock, FakeEvidence, FakeIds

ANALYSIS_ID = AnalysisId("fake-analysis")
WORKSPACE_ID = WorkspaceId("fake-workspace")
COMMIT_ID = CommitId("fake-commit")
PROGRAM_ID = ProgramId("fake-program")

type ProviderInvoker = Callable[
    [LLMInvocationRequest, LLMInvocationResult], Awaitable[LLMInvocationResult]
]
type ProviderProber = Callable[
    [ProviderValidationEvidence], Awaitable[CapabilityProbeResult]
]
type StaticInvoker = Callable[
    [StaticToolRequest, ToolRunResult], Awaitable[ToolRunResult]
]
type SandboxPreparer = Callable[
    [SandboxPrepareRequest, SandboxEnvironment], Awaitable[SandboxEnvironment]
]
type SandboxExecutor = Callable[
    [ApprovedSandboxCommand, SandboxCommandRecord], Awaitable[SandboxCommandRecord]
]
type SandboxCleaner = Callable[
    [SandboxCleanupRequest, CleanupResult], Awaitable[CleanupResult]
]
type PolicyFetcher = Callable[[StoredDataRef], Awaitable[StoredDataRef]]


class NoMatchBuilder(Protocol):
    def __call__(
        self,
        *,
        meta: dict[str, Any],
        primitive_ref: StoredDataRef | None = None,
        primitive_refs: tuple[StoredDataRef, ...] = (),
    ) -> ChainingResult: ...


class FakeStageService:
    """Typed access to the explicit scenario composition context."""

    def __init__(self, host: FakePipelineBase) -> None:
        self._host = host

    @property
    def runtime(self) -> RuntimeServices | None:
        return self._host.runtime

    @runtime.setter
    def runtime(self, value: RuntimeServices | None) -> None:
        self._host.runtime = value

    @property
    def runner(self) -> WorkflowRunner | None:
        return self._host.runner

    @runner.setter
    def runner(self, value: WorkflowRunner | None) -> None:
        self._host.runner = value

    @property
    def clock(self) -> FakeClock:
        return self._host.clock

    @property
    def ids(self) -> FakeIds:
        return self._host.ids

    @property
    def evidence(self) -> FakeEvidence:
        return self._host.evidence

    @property
    def data_dir(self) -> Path:
        return self._host.data_dir

    @property
    def runtime_builder(self) -> Callable[..., RuntimeServices]:
        return self._host.runtime_builder

    @property
    def database_upgrader(self) -> Callable[[Path], None]:
        return self._host.database_upgrader

    @property
    def provider_invoke(self) -> ProviderInvoker:
        return self._host.provider_invoke

    @provider_invoke.setter
    def provider_invoke(self, value: ProviderInvoker) -> None:
        self._host.provider_invoke = value

    @property
    def provider_probe(self) -> ProviderProber:
        return self._host.provider_probe

    @property
    def static_invoke(self) -> StaticInvoker:
        return self._host.static_invoke

    @property
    def sandbox_prepare(self) -> SandboxPreparer:
        return self._host.sandbox_prepare

    @property
    def sandbox_execute(self) -> SandboxExecutor:
        return self._host.sandbox_execute

    @sandbox_execute.setter
    def sandbox_execute(self, value: SandboxExecutor) -> None:
        self._host.sandbox_execute = value

    @property
    def sandbox_cleanup(self) -> SandboxCleaner:
        return self._host.sandbox_cleanup

    @property
    def policy_fetch(self) -> PolicyFetcher:
        return self._host.policy_fetch

    @property
    def no_match_builder(self) -> NoMatchBuilder:
        return self._host.no_match_builder

    @property
    def verification_assembly(self) -> VerificationAssemblyPort:
        return self._host.verification_assembly

    @property
    def context_service_identity_ref(self) -> StoredDataRef | None:
        return self._host.context_service_identity_ref

    @context_service_identity_ref.setter
    def context_service_identity_ref(self, value: StoredDataRef | None) -> None:
        self._host.context_service_identity_ref = value

    @property
    def _verification_work_ref(self) -> RecordRef | None:
        return self._host._verification_work_ref

    @_verification_work_ref.setter
    def _verification_work_ref(self, value: RecordRef | None) -> None:
        self._host._verification_work_ref = value

    def _run_meta(self, kind: str) -> RunMeta:
        return self._host._run_meta(kind)

    def _record_meta(
        self,
        kind: str,
        *,
        hypothesis_id: str | None = None,
        attempt_id: str | None = None,
    ) -> RecordMeta:
        return self._host._record_meta(
            kind, hypothesis_id=hypothesis_id, attempt_id=attempt_id
        )

    def _artifact(self, kind: str, *, record: bool = False) -> RecordRef:
        return self._host._artifact(kind, record=record)

    def _stored_artifact(self, kind: str) -> StoredDataRef:
        return self._host._stored_artifact(kind)

    def _opaque_run_ref(self, kind: str) -> RunStoredDataRef:
        return self._host._opaque_run_ref(kind)


class FakePipelineBase:
    def __init__(
        self,
        data_dir: Path,
        runtime_builder: Callable[..., RuntimeServices],
        database_upgrader: Callable[[Path], None],
        provider_invoke: ProviderInvoker,
        provider_probe: ProviderProber,
        static_invoke: StaticInvoker,
        sandbox_prepare: SandboxPreparer,
        sandbox_execute: SandboxExecutor,
        sandbox_cleanup: SandboxCleaner,
        policy_fetch: PolicyFetcher,
        no_match_builder: NoMatchBuilder,
        verification_assembly: VerificationAssemblyPort,
        persisted_result: AnalysisRunResult | None = None,
        persisted_reports: tuple[ReportDraft, ...] = (),
    ) -> None:
        self.data_dir = data_dir
        self.runtime_builder = runtime_builder
        self.database_upgrader = database_upgrader
        self.provider_invoke = provider_invoke
        self.provider_probe = provider_probe
        self.static_invoke = static_invoke
        self.sandbox_prepare = sandbox_prepare
        self.sandbox_execute = sandbox_execute
        self.sandbox_cleanup = sandbox_cleanup
        self.policy_fetch = policy_fetch
        self.no_match_builder = no_match_builder
        self.verification_assembly = verification_assembly
        self.clock = FakeClock()
        self.ids = FakeIds()
        self.evidence = FakeEvidence()
        self.runtime: RuntimeServices | None = None
        self.runner: WorkflowRunner | None = None
        self._verification_work_ref: RecordRef | None = None
        self.context_service_identity_ref: StoredDataRef | None = None
        self._artifact_refs: dict[str, StoredDataRef] = {}
        self._result = persisted_result
        self._reports = persisted_reports

    def _run_meta(self, kind: str) -> RunMeta:
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

    def _record_meta(
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

    def _artifact(self, kind: str, *, record: bool = False) -> RecordRef:
        del record  # Artifact/record ownership is expressed by the consuming contract.
        if self.runtime is None:
            raise RuntimeError("FAKE_ARTIFACT_STORE_NOT_READY")
        cached = self._artifact_refs.get(kind)
        if cached is not None:
            return cached
        data = f"sastsimi deterministic fake artifact: {kind}\n".encode()
        staged = self.runtime.unit_of_work.artifacts.stage_bytes(
            data, "application/octet-stream"
        )
        committed = self.runtime.unit_of_work.artifacts.commit(staged)
        self._artifact_refs[kind] = committed
        return committed

    def _opaque_run_ref(self, kind: str) -> RunStoredDataRef:
        """External approval/pricing record allowed by the frozen opaque-ref ruling."""
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

    def _stored_artifact(self, kind: str) -> StoredDataRef:
        ref = self._artifact(kind)
        if not isinstance(ref, StoredDataRef):
            raise ValueError("FAKE_ARTIFACT_SCOPE_MISMATCH")
        return ref

    def results(self) -> AnalysisRunResult:
        if self._result is None:
            raise LookupError("ANALYSIS_RESULT_NOT_FOUND")
        return self._result

    def reports(self) -> tuple[ReportDraft, ...]:
        return self._reports
