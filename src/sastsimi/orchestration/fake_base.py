"""Shared deterministic state, metadata and persisted query facade."""

from collections.abc import Callable
from pathlib import Path

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    LogicalRecordId,
    ProgramId,
    RecordId,
    WorkspaceId,
)
from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import RecordRef, RunStoredDataRef, StoredDataRef
from sastsimi.contracts.reporting import ReportDraft
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .fake_support import FakeClock, FakeEvidence, FakeIds

ANALYSIS_ID = AnalysisId("fake-analysis")
WORKSPACE_ID = WorkspaceId("fake-workspace")
COMMIT_ID = CommitId("fake-commit")
PROGRAM_ID = ProgramId("fake-program")


class FakePipelineBase:
    def __init__(
        self,
        data_dir: Path,
        runtime_builder: Callable[..., RuntimeServices],
        database_upgrader: Callable[[Path], None],
        persisted_result: AnalysisRunResult | None = None,
        persisted_reports: tuple[ReportDraft, ...] = (),
    ) -> None:
        self.data_dir = data_dir
        self.runtime_builder = runtime_builder
        self.database_upgrader = database_upgrader
        self.clock = FakeClock()
        self.ids = FakeIds()
        self.evidence = FakeEvidence()
        self.runtime: RuntimeServices | None = None
        self.runner: WorkflowRunner | None = None
        self._verification_work_ref: RecordRef | None = None
        self._result = persisted_result or self._snapshot_result()
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

    def _snapshot_result(self) -> AnalysisRunResult:
        metadata = self._run_meta("analysis_run_result")
        empty_fields = {
            name: ()
            for name in AnalysisRunResult.model_fields
            if name.endswith("_refs")
        }
        return AnalysisRunResult.model_validate_json(
            canonical_bytes(
                dict(
                    meta=metadata,
                    purpose="PRODUCTION",
                    repository_url="https://example.invalid/fake",
                    program_id=PROGRAM_ID,
                    workspace_id=None,
                    commit_id=None,
                    workspace_ref=None,
                    status="FAILED",
                    hypothesis_counts={},
                    failed_hypothesis_count=0,
                    verdict_counts={},
                    gate_counts={},
                    run_policy_state_ref=None,
                    stop_reasons=(),
                    errors=(),
                    gaps=(),
                    resources=dict(
                        elapsed_ms=0,
                        work_count=0,
                        attempt_count=0,
                        retry_count=0,
                        llm_call_count=0,
                        dynamic_attempt_count=0,
                        cost_minor_units=0,
                        currency="USD",
                        pricing_revision_refs=(),
                        usage_measurement_refs=(),
                        usage_complete=True,
                        unavailable_reasons=(),
                    ),
                    started_at=self.clock.now(),
                    finished_at=self.clock.now(),
                    elapsed_ms=0,
                    debug_trace_ref=self._artifact("debug_trace", run=True),
                    **empty_fields,
                )
            )
        )

    def results(self) -> AnalysisRunResult:
        return self._result

    def reports(self) -> tuple[ReportDraft, ...]:
        return self._reports
