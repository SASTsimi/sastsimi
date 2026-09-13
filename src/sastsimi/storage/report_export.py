"""SQLite read adapter for exact current Markdown report inputs."""

from __future__ import annotations

from pathlib import Path
from typing import TypeVar

from sqlalchemy import select

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.actions import ActionDecision, ActionRequest
from sastsimi.contracts.domain import DomainRecord, same_scope
from sastsimi.contracts.dynamic import (
    AgentLog,
    DynamicReproductionResult,
    PoCBundle,
    PoCCandidate,
    SandboxCommandRecord,
    validate_execution_support,
    validate_poc_candidate,
)
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
    validate_rule_scope_gate,
    validate_technical_gate,
)
from sastsimi.contracts.policy import (
    PolicyCollectionResult,
    ProgramPolicyRecord,
    RunPolicyState,
)
from sastsimi.contracts.refs import ReferencedRecord, StoredDataRef, reference
from sastsimi.contracts.reporting import (
    Finding,
    FindingIndexState,
    ReportDraft,
    ReportProcessState,
    validate_report_closure,
)
from sastsimi.contracts.verification import VerificationResult
from sastsimi.ports.report_export import (
    CurrentReport,
    ReportUnavailable,
)
from sastsimi.reporting.content_validation import read_validated_report_content

from . import models
from .artifact_store import LocalArtifactStore
from .codec import REF_ADAPTER
from .database import Database
from .repositories import SQLiteRecordStore

T = TypeVar("T", bound=ReferencedRecord)


class SQLiteCurrentReportSource:
    def __init__(self, data_dir: Path) -> None:
        path = RuntimePaths(data_dir).database
        if not path.exists():
            self._database: Database | None = None
            self._records: SQLiteRecordStore | None = None
            self._data_dir = data_dir
            return
        self._database = Database(path)
        self._database.check_ready()
        self._records = SQLiteRecordStore(self._database)
        self._data_dir = data_dir

    def list_current(self, analysis_id: str) -> tuple[CurrentReport, ...]:
        reports: list[CurrentReport] = []
        for state in self._current("report_process_state", ReportProcessState):
            if (
                state.meta.analysis_id != analysis_id
                or state.status != "DRAFTED"
                or state.report_draft_ref is None
            ):
                continue
            try:
                reports.append(self._resolve(state))
            except ReportUnavailable:
                continue
        return tuple(
            sorted(reports, key=lambda item: (item.analysis_id, item.finding_id))
        )

    def get_current(self, finding_id: str) -> CurrentReport:
        matched = []
        for state in self._current("report_process_state", ReportProcessState):
            if state.status != "DRAFTED" or state.report_draft_ref is None:
                continue
            draft = self._exact(state.report_draft_ref, ReportDraft)
            if str(draft.finding_ref.record_id) == finding_id:
                matched.append(state)
        if len(matched) != 1:
            raise ReportUnavailable("REPORT_NOT_FOUND")
        return self._resolve(matched[0])

    def _resolve(self, state: ReportProcessState) -> CurrentReport:
        if state.report_draft_ref is None:
            raise ReportUnavailable("REPORT_NOT_FOUND")
        try:
            draft = self._exact(state.report_draft_ref, ReportDraft)
            finding = self._exact(draft.finding_ref, Finding)
            indexes = tuple(
                item
                for item in self._current("finding_index_state", FindingIndexState)
                if item.meta.analysis_id == draft.meta.analysis_id
                and item.meta.hypothesis_id == draft.meta.hypothesis_id
            )
            if (
                len(indexes) != 1
                or indexes[0].status != "CURRENT"
                or indexes[0].finding_ref != draft.finding_ref
            ):
                raise ReportUnavailable("STALE_REPORT")
            verification = self._exact(
                draft.verification_result_ref, VerificationResult
            )
            cwe = self._exact(draft.cwe_label_ref, CWELabel)
            technical = self._exact(draft.technical_review_ref, TechnicalEvidenceReview)
            rule_scope = self._exact(
                draft.rule_scope_impact_review_ref, RuleScopeImpactReview
            )
            if draft.dynamic_result_ref is None or draft.poc_ref is None:
                raise ReportUnavailable("REPORT_TRUE_CLOSURE_MISSING")
            dynamic = self._exact(draft.dynamic_result_ref, DynamicReproductionResult)
            poc = self._exact(draft.poc_ref, PoCBundle)
            candidate = self._exact(poc.candidate_ref, PoCCandidate)
            policy_state = self._exact(draft.run_policy_state_ref, RunPolicyState)
            collection = self._exact(
                rule_scope.policy_collection_result_ref, PolicyCollectionResult
            )
            policy = (
                self._exact(draft.policy_record_ref, ProgramPolicyRecord)
                if draft.policy_record_ref is not None
                else None
            )
            artifacts = LocalArtifactStore(
                RuntimePaths(self._data_dir).artifacts,
                draft.meta.workspace_id,
                draft.meta.commit_id,
            )
            content = read_validated_report_content(
                artifacts,
                draft.content_ref,
                allowed_locations=tuple(
                    location
                    for claim in (
                        *verification.supporting_evidence,
                        *verification.counter_evidence,
                    )
                    for location in claim.code_locations
                ),
            )
            with artifacts.open_verified(candidate.content_ref) as stream:
                poc_bytes = stream.read()
            poc_text = poc_bytes.decode("utf-8")
            action, decision = self._report_authority(draft)
            condition_records = self._condition_records(finding)
            agent_log, execution_command = self._poc_execution(
                dynamic,
                poc,
                candidate,
                condition_records,
            )
            validate_report_closure(
                draft,
                finding,
                indexes[0],
                verification,
                technical,
                rule_scope,
                policy_state,
                content_locations=content.citations,
                condition_records=condition_records,
            )
            validate_technical_gate(
                technical,
                verification,
                cwe,
                dynamic,
                poc,
                current_generation=cwe.verification_generation,
            )
            validate_poc_candidate(poc, candidate)
            validate_rule_scope_gate(
                rule_scope, technical, policy_state, collection, policy
            )
            report = CurrentReport(
                draft=draft,
                finding=finding,
                verification=verification,
                cwe=cwe,
                technical=technical,
                rule_scope=rule_scope,
                dynamic=dynamic,
                poc=poc,
                poc_candidate=candidate,
                agent_log=agent_log,
                execution_command=execution_command,
                content=content,
                poc_text=poc_text,
                report_action=action,
                report_decision=decision,
            )
            return report
        except ReportUnavailable:
            raise
        except (LookupError, UnicodeDecodeError, ValueError) as error:
            raise ReportUnavailable("REPORT_EXACT_CLOSURE_INVALID") from error

    def _report_authority(
        self, draft: ReportDraft
    ) -> tuple[ActionRequest, ActionDecision]:
        initial = self._exact(draft.action_decision_ref, ActionDecision)
        if self._database is None:
            raise ReportUnavailable("REPORT_NOT_FOUND")
        with self._database.engine.connect() as connection:
            payload = connection.execute(
                select(models.action_decisions.c.payload).where(
                    models.action_decisions.c.decision_id == str(initial.decision_id)
                )
            ).scalar_one_or_none()
        if payload is None:
            raise ReportUnavailable("REPORT_REDACTION_NOT_PROVEN")
        decision = ActionDecision.model_validate_json(payload)
        if not isinstance(decision.action_ref, StoredDataRef):
            raise ReportUnavailable("REPORT_REDACTION_NOT_PROVEN")
        action = self._exact(decision.action_ref, ActionRequest)
        if (
            decision.decision_id != initial.decision_id
            or decision.meta.logical_record_id != initial.meta.logical_record_id
        ):
            raise ReportUnavailable("REPORT_REDACTION_NOT_PROVEN")
        return action, decision

    def _poc_execution(
        self,
        result: DynamicReproductionResult,
        poc: PoCBundle,
        candidate: PoCCandidate,
        evidence_records: tuple[tuple[StoredDataRef, DomainRecord], ...],
    ) -> tuple[AgentLog, SandboxCommandRecord]:
        if (
            result.agent_log_ref != poc.agent_log_ref
            or result.request_ref != poc.request_ref
            or result.environment_ref != poc.environment_ref
            or result.environment_recipe_ref != poc.environment_recipe_ref
            or result.poc_candidate_ref != poc.candidate_ref
        ):
            raise ReportUnavailable("REPORT_POC_EXECUTION_INVALID")
        log = self._exact(poc.agent_log_ref, AgentLog)
        executions = tuple(
            event
            for event in log.events
            if event.event_type == "POC_EXECUTION_FINISHED"
            and event.action_id == poc.execution_action_id
            and event.poc_candidate_ref == poc.candidate_ref
            and event.exit_code == 0
            and event.timed_out is False
        )
        if len(executions) != 1:
            raise ReportUnavailable("REPORT_POC_EXECUTION_INVALID")
        execution = executions[0]
        command_ref = execution.command_ref
        if command_ref is None:
            raise ReportUnavailable("REPORT_POC_EXECUTION_INVALID")
        command = self._exact(command_ref, SandboxCommandRecord)
        try:
            same_scope(result.meta, poc.meta, attempt=True)
            same_scope(result.meta, log.meta, attempt=True)
            same_scope(result.meta, command.meta, attempt=True)
        except ValueError as error:
            raise ReportUnavailable("REPORT_POC_EXECUTION_INVALID") from error
        if (
            command.action_id != execution.action_id
            or command.command_digest != execution.command_digest
            or command.environment_ref != result.environment_ref
            or command.environment_recipe_ref != result.environment_recipe_ref
            or command.request_ref != result.request_ref
            or log.request_ref != result.request_ref
        ):
            raise ReportUnavailable("REPORT_POC_EXECUTION_INVALID")
        validate_execution_support(
            result,
            poc,
            candidate,
            execution,
            log,
            (command,),
            dict(evidence_records),
        )
        return log, command

    def _condition_records(
        self, finding: Finding
    ) -> tuple[tuple[StoredDataRef, DomainRecord], ...]:
        refs = (
            finding.verification_result_ref,
            finding.dynamic_result_ref,
            finding.poc_ref,
            finding.cwe_label_ref,
            finding.technical_review_ref,
            finding.rule_scope_impact_review_ref,
            finding.policy_collection_result_ref,
            *finding.evidence_refs,
        )
        pairs: list[tuple[StoredDataRef, DomainRecord]] = []
        seen: set[StoredDataRef] = set()
        for ref in refs:
            if ref.record_id is None or ref in seen:
                continue
            pairs.append((ref, self._exact(ref, DomainRecord)))
            seen.add(ref)
        return tuple(pairs)

    def _exact(self, ref: StoredDataRef, expected: type[T]) -> T:
        if self._records is None:
            raise ReportUnavailable("REPORT_NOT_FOUND")
        record = self._records.get_exact(ref)
        if not isinstance(record, expected):
            raise ReportUnavailable("REPORT_EXACT_CLOSURE_INVALID")
        if reference(record) != ref:
            raise ReportUnavailable("REPORT_EXACT_CLOSURE_INVALID")
        return record

    def _current(self, kind: str, expected: type[T]) -> tuple[T, ...]:
        if self._database is None or self._records is None:
            return ()
        query = (
            select(models.records.c.ref)
            .join(
                models.current_records,
                models.current_records.c.record_id == models.records.c.record_id,
            )
            .join(
                models.record_revisions,
                models.record_revisions.c.record_id == models.records.c.record_id,
            )
            .where(models.records.c.kind == kind)
            .order_by(models.records.c.record_id)
        )
        records: list[T] = []
        with self._database.engine.connect() as connection:
            for wire in connection.execute(query).scalars():
                record = self._records.resolve(
                    connection, REF_ADAPTER.validate_json(wire)
                )
                if not isinstance(record, expected):
                    raise ReportUnavailable("REPORT_EXACT_CLOSURE_INVALID")
                records.append(record)
        return tuple(records)


__all__ = ["SQLiteCurrentReportSource"]
