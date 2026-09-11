from datetime import UTC, datetime

from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    HypothesisId,
    LogicalRecordId,
    RecordId,
    WorkspaceId,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.reporting import ReportDraft, ReportProcessState
from sastsimi.reporting.queries import persisted_report_drafts


def meta(kind: str, suffix: str) -> RecordMeta:
    return RecordMeta(
        record_id=RecordId(f"{kind}-{suffix}"),
        logical_record_id=LogicalRecordId(f"{kind}-logical-{suffix}"),
        record_type=kind,
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=datetime(2026, 9, 12, tzinfo=UTC),
        analysis_id=AnalysisId("analysis"),
        workspace_id=WorkspaceId("workspace"),
        commit_id=CommitId("commit"),
        hypothesis_id=HypothesisId("hypothesis"),
        attempt_id=None,
    )


class Query:
    def __init__(
        self, drafts: tuple[ReportDraft, ...], state: ReportProcessState
    ) -> None:
        self.drafts = drafts
        self.state = state

    def current_records(self, analysis_id: str, kind: str) -> tuple[object, ...]:
        assert analysis_id == "analysis"
        return self.drafts if kind == "report_draft" else (self.state,)


def stored(kind: str) -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": f"{kind}-stored",
            "data_kind": kind,
            "record_id": f"{kind}-record",
            "content_hash": "a" * 64,
            "workspace_id": "workspace",
            "commit_id": "commit",
        }
    )


def draft(suffix: str) -> ReportDraft:
    return ReportDraft.model_construct(
        meta=meta("report_draft", suffix),
        action_decision_ref=stored("action_decision"),
        finding_ref=stored("finding"),
        verification_result_ref=stored("verification_result"),
        technical_review_ref=stored("technical_evidence_review"),
        rule_scope_impact_review_ref=stored("rule_scope_impact_review"),
        cwe_label_ref=stored("cwe_label"),
        run_policy_state_ref=stored("run_policy_state"),
        policy_record_ref=stored("program_policy_record"),
        dynamic_result_ref=stored("dynamic_reproduction_result"),
        poc_ref=stored("poc_bundle"),
        content_ref=stored("artifact"),
        restrictions=(),
        limitations=(),
        unresolved_conditions=(),
        redaction_status="PASSED",
        draft_status="DRAFTED",
    )


def test_only_report_process_state_pointer_enters_current_results() -> None:
    old = draft("old")
    current = draft("current")
    current_ref = reference(current)
    assert isinstance(current_ref, StoredDataRef)
    state = ReportProcessState.model_construct(
        meta=meta("report_process_state", "state"),
        status="DRAFTED",
        report_draft_ref=current_ref,
    )

    assert persisted_report_drafts(Query((old, current), state), "analysis") == (
        current,
    )
