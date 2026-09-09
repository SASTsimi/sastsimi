"""Shared deterministic state, metadata and persisted query facade."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Protocol

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.dynamic import SandboxEnvironment
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    LogicalRecordId,
    ProgramId,
    RecordId,
    WorkspaceId,
)
from sastsimi.contracts.llm import LLMInvocationRequest, LLMInvocationResult
from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import RecordRef, RunStoredDataRef, StoredDataRef
from sastsimi.contracts.reporting import ReportDraft
from sastsimi.contracts.static import ToolRunResult
from sastsimi.ports.dto import SandboxPrepareRequest, StaticToolRequest
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
type StaticInvoker = Callable[
    [StaticToolRequest, ToolRunResult], Awaitable[ToolRunResult]
]
type SandboxPreparer = Callable[
    [SandboxPrepareRequest, SandboxEnvironment], Awaitable[SandboxEnvironment]
]
type PolicyFetcher = Callable[[StoredDataRef], Awaitable[StoredDataRef]]


class NoMatchBuilder(Protocol):
    def __call__(
        self, *, meta: dict[str, Any], primitive_ref: StoredDataRef
    ) -> ChainingResult: ...


class FakeStageService:
    """Delegate shared state and sibling-stage calls through one runtime host."""

    def __init__(self, host: FakePipelineBase) -> None:
        object.__setattr__(self, "_host", host)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._host, name)

    def __setattr__(self, name: str, value: object) -> None:
        setattr(self._host, name, value)


class FakePipelineBase:
    def __init__(
        self,
        data_dir: Path,
        runtime_builder: Callable[..., RuntimeServices],
        database_upgrader: Callable[[Path], None],
        provider_invoke: ProviderInvoker,
        static_invoke: StaticInvoker,
        sandbox_prepare: SandboxPreparer,
        policy_fetch: PolicyFetcher,
        no_match_builder: NoMatchBuilder,
        persisted_result: AnalysisRunResult | None = None,
        persisted_reports: tuple[ReportDraft, ...] = (),
    ) -> None:
        self.data_dir = data_dir
        self.runtime_builder = runtime_builder
        self.database_upgrader = database_upgrader
        self.provider_invoke = provider_invoke
        self.static_invoke = static_invoke
        self.sandbox_prepare = sandbox_prepare
        self.policy_fetch = policy_fetch
        self.no_match_builder = no_match_builder
        self.clock = FakeClock()
        self.ids = FakeIds()
        self.evidence = FakeEvidence()
        self.runtime: RuntimeServices | None = None
        self.runner: WorkflowRunner | None = None
        self._verification_work_ref: RecordRef | None = None
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

    def _artifact(
        self, kind: str, *, run: bool = False, record: bool = False
    ) -> RecordRef:
        if not run and self.runtime is not None:
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
        payload: dict[str, object] = dict(
            stored_data_id=f"fake-{kind}",
            data_kind=kind,
            record_id=f"fake-{kind}-record" if record else None,
            content_hash=content_hash(["fake", kind]),
        )
        if run:
            payload["analysis_id"] = ANALYSIS_ID
            return RunStoredDataRef.model_validate_json(canonical_bytes(payload))
        payload.update(workspace_id=WORKSPACE_ID, commit_id=COMMIT_ID)
        return StoredDataRef.model_validate_json(canonical_bytes(payload))

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
