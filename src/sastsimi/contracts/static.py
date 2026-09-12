"""Static observations and context contracts (§08); observations are not verdicts."""

import re
from collections.abc import Mapping
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, AwareDatetime, model_validator

from ._domain import DomainRecord, exact, exact_set, same_scope, unique
from ._domain import SafeDiagnostic as SafeDiagnostic
from .base import ContractModel, NonEmptyStr, NonNegativeInt, PositiveInt, Sha256
from .canonical_json import content_hash
from .closure import validate_committed_output
from .ids import AnalysisId, AttemptId, CommitId, ErrorId, GapId, WorkId, WorkspaceId
from .records import RunMeta
from .refs import (
    HostConfigurationRef,
    RunStoredDataRef,
    StoredDataRef,
    require_record_ref,
)
from .work import (
    TransitionCommit,
    WorkAttempt,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)


def git_path(value: str) -> str:
    if (
        "\\" in value
        or re.match(r"^[A-Za-z]:", value)
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ValueError("INVALID_GIT_PATH")
    return value


GitPath = Annotated[NonEmptyStr, AfterValidator(git_path)]


class StaticToolProfile(DomainRecord):
    """Exact immutable configuration for one static-tool adapter revision."""

    KIND = "static_tool_profile"
    HYPOTHESIS = False
    ATTEMPT = False
    host_id: NonEmptyStr | None = None
    profile_key: NonEmptyStr
    purpose: Literal["FIXTURE", "EVALUATION", "PRODUCTION"]
    status: Literal["DRAFT", "APPROVED", "ACTIVE", "RETIRED"]
    adapter_key: Literal["PYTHON_AST", "CODEQL", "OPENGREP"]
    tool_name: Literal["AST", "CODEQL", "OPENGREP"]
    tool_kind: Literal["STRUCTURE", "RULE_BASED"]
    executable_key: NonEmptyStr
    executable_sha256: Sha256
    expected_version: NonEmptyStr
    capability_evidence_ref: HostConfigurationRef | None
    probe_timeout_ms: PositiveInt
    run_timeout_ms: PositiveInt
    stdout_limit_bytes: PositiveInt
    stderr_limit_bytes: PositiveInt
    max_attempt_output_bytes: PositiveInt
    max_output_file_bytes: PositiveInt
    max_artifact_read_bytes: PositiveInt

    @model_validator(mode="after")
    def closed_profile(self) -> Self:
        valid = {
            ("PYTHON_AST", "AST", "STRUCTURE"),
            ("CODEQL", "CODEQL", "RULE_BASED"),
            ("OPENGREP", "OPENGREP", "RULE_BASED"),
        }
        if (self.adapter_key, self.tool_name, self.tool_kind) not in valid:
            raise ValueError("STATIC_TOOL_PROFILE_TUPLE_MISMATCH")
        if self.status == "ACTIVE":
            if (
                self.purpose != "PRODUCTION"
                or self.host_id is None
                or self.capability_evidence_ref is None
                or self.capability_evidence_ref.host_id != self.host_id
            ):
                raise ValueError("STATIC_TOOL_PROFILE_ACTIVATION_INVALID")
        elif self.status == "APPROVED":
            if (
                self.purpose not in {"FIXTURE", "EVALUATION"}
                or self.host_id is not None
                or self.capability_evidence_ref is not None
            ):
                raise ValueError("STATIC_TOOL_PROFILE_APPROVAL_INVALID")
        elif self.status == "RETIRED" and (
            self.purpose != "PRODUCTION"
            or self.host_id is None
            or self.capability_evidence_ref is None
            or self.capability_evidence_ref.host_id != self.host_id
        ):
            raise ValueError("STATIC_TOOL_PROFILE_RETIREMENT_INVALID")
        elif self.status == "DRAFT" and (
            self.host_id is not None or self.capability_evidence_ref is not None
        ):
            raise ValueError("STATIC_TOOL_PROFILE_DRAFT_INVALID")
        return self


class CodeWorkspace(ContractModel):
    meta: RunMeta
    workspace_id: WorkspaceId
    analysis_id: AnalysisId
    repository_url: NonEmptyStr
    commit_id: CommitId | None
    status: Literal["PREPARING", "READY", "FAILED", "REMOVED"]

    @model_validator(mode="after")
    def workspace_shape(self) -> Self:
        if (
            type(self.meta) is not RunMeta
            or self.meta.record_type != "code_workspace"
            or self.analysis_id != self.meta.analysis_id
        ):
            raise ValueError("METADATA_SCOPE_MISMATCH")
        if (self.status == "READY" and self.commit_id is None) or (
            self.status == "PREPARING" and self.commit_id is not None
        ):
            raise ValueError("WORKSPACE_NOT_READY")
        return self


class RepositoryTrackedFile(ContractModel):
    """One regular file from the exact safe Git manifest used for detection."""

    git_path: GitPath
    git_mode: Literal["100644", "100755"]
    blob_id: NonEmptyStr
    content_sha256: Sha256
    size_bytes: NonNegativeInt

    @model_validator(mode="after")
    def blob_shape(self) -> Self:
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", self.blob_id):
            raise ValueError("INVALID_GIT_BLOB_ID")
        return self


class RepositoryLanguage(ContractModel):
    name: Literal["PYTHON", "JAVASCRIPT", "TYPESCRIPT", "JAVA"]
    evidence_paths: tuple[GitPath, ...]

    @model_validator(mode="after")
    def evidence_required(self) -> Self:
        unique(self.evidence_paths)
        if not self.evidence_paths:
            raise ValueError("LANGUAGE_EVIDENCE_REQUIRED")
        return self


class RepositoryFramework(ContractModel):
    name: Literal["DJANGO", "FASTAPI", "FLASK", "EXPRESS", "NEXTJS", "NESTJS"]
    evidence_paths: tuple[GitPath, ...]

    @model_validator(mode="after")
    def evidence_required(self) -> Self:
        unique(self.evidence_paths)
        if not self.evidence_paths:
            raise ValueError("FRAMEWORK_EVIDENCE_REQUIRED")
        return self


class RepositoryConfigFile(ContractModel):
    path: GitPath
    kind: Literal[
        "REQUIREMENTS",
        "PYPROJECT",
        "PACKAGE_JSON",
        "DOCKERFILE",
        "DOCKER_COMPOSE",
        "MAVEN_POM",
        "GRADLE",
        "PACKAGE_LOCK",
        "YARN_LOCK",
        "PNPM_LOCK",
        "PYTHON_LOCK",
        "PIPFILE",
    ]


class RepositoryExecutionHint(ContractModel):
    """Tracked declaration that may be selected only by an ACTIVE capability."""

    path: GitPath
    kind: Literal["DOCKERFILE", "PACKAGE_SCRIPT", "PYTHON_SCRIPT"]
    name: NonEmptyStr


class RepositoryProfileLocation(ContractModel):
    """Source location retained from a repository-preparation gap."""

    file_path: GitPath
    start_line: PositiveInt
    start_column: PositiveInt | None
    end_line: PositiveInt
    end_column: PositiveInt | None

    @model_validator(mode="after")
    def range_shape(self) -> Self:
        if self.end_line < self.start_line or (self.start_column is None) != (
            self.end_column is None
        ):
            raise ValueError("INVALID_CODE_RANGE")
        if (
            self.start_line == self.end_line
            and self.start_column is not None
            and self.end_column is not None
            and self.end_column <= self.start_column
        ):
            raise ValueError("INVALID_CODE_RANGE")
        return self


class RepositoryProfileGap(ContractModel):
    code: NonEmptyStr
    reason: Literal[
        "MISSING", "FAILED", "TRUNCATED", "UNSUPPORTED", "BLOCKED", "TIMEOUT"
    ]
    description: NonEmptyStr
    affected_paths: tuple[GitPath, ...]
    affected_languages: tuple[NonEmptyStr, ...]
    affected_locations: tuple[RepositoryProfileLocation, ...]
    retryable: bool


class RepositoryProfileError(ContractModel):
    code: NonEmptyStr
    safe_message: SafeDiagnostic
    retryable: bool


class RepositoryProfile(DomainRecord):
    """Immutable detection result closed over one exact tracked-file manifest."""

    KIND = "repository_profile"
    HYPOTHESIS = False
    ATTEMPT = True
    workspace_id: WorkspaceId
    commit_id: CommitId
    workspace_ref: RunStoredDataRef
    action_decision_ref: StoredDataRef
    manifest_hash: Sha256
    tracked_files: tuple[RepositoryTrackedFile, ...]
    languages: tuple[RepositoryLanguage, ...]
    frameworks: tuple[RepositoryFramework, ...]
    config_files: tuple[RepositoryConfigFile, ...]
    execution_hints: tuple[RepositoryExecutionHint, ...]
    gaps: tuple[RepositoryProfileGap, ...]
    errors: tuple[RepositoryProfileError, ...]
    status: Literal["READY", "NEEDS_CONFIRMATION"]
    confirmation_reasons: tuple[NonEmptyStr, ...]

    @model_validator(mode="after")
    def profile_shape(self) -> Self:
        if (
            self.workspace_ref.data_kind != "code_workspace"
            or self.workspace_ref.record_id is None
            or self.action_decision_ref.data_kind != "action_decision"
            or self.action_decision_ref.record_id is None
        ):
            raise ValueError("REPOSITORY_PROFILE_WORKSPACE_INVALID")
        unique(item.git_path for item in self.tracked_files)
        unique(item.name for item in self.languages)
        unique(item.name for item in self.frameworks)
        unique(item.path for item in self.config_files)
        unique((item.path, item.kind, item.name) for item in self.execution_hints)
        unique((item.code, item.reason, item.description) for item in self.gaps)
        unique((item.code, item.safe_message) for item in self.errors)
        unique(self.confirmation_reasons)
        tracked = {item.git_path for item in self.tracked_files}
        evidence_paths = {
            path for item in self.languages for path in item.evidence_paths
        } | {path for item in self.frameworks for path in item.evidence_paths}
        declared_paths = {item.path for item in self.config_files} | {
            item.path for item in self.execution_hints
        }
        if (
            tuple(item.git_path for item in self.tracked_files)
            != tuple(sorted(tracked))
            or not evidence_paths <= tracked
            or not declared_paths <= tracked
            or self.manifest_hash
            != content_hash(
                tuple(item.model_dump(mode="json") for item in self.tracked_files)
            )
        ):
            raise ValueError("REPOSITORY_PROFILE_MANIFEST_MISMATCH")
        if self.status == "READY" and self.confirmation_reasons:
            raise ValueError("REPOSITORY_PROFILE_STATUS_MISMATCH")
        if self.status == "NEEDS_CONFIRMATION" and not self.confirmation_reasons:
            raise ValueError("REPOSITORY_PROFILE_STATUS_MISMATCH")
        return self


class CodeLocation(ContractModel):
    workspace_id: WorkspaceId
    commit_id: CommitId
    file_path: GitPath
    start_line: PositiveInt
    start_column: PositiveInt | None
    end_line: PositiveInt
    end_column: PositiveInt | None

    @model_validator(mode="after")
    def range_shape(self) -> Self:
        if self.end_line < self.start_line or (self.start_column is None) != (
            self.end_column is None
        ):
            raise ValueError("INVALID_CODE_RANGE")
        if (
            self.start_line == self.end_line
            and self.start_column is not None
            and self.end_column is not None
            and self.end_column <= self.start_column
        ):
            raise ValueError("INVALID_CODE_RANGE")
        return self


class CodeSymbol(ContractModel):
    symbol_id: NonEmptyStr
    symbol_kind: Literal[
        "FILE", "MODULE", "TYPE", "CALLABLE", "DATA", "ROUTE", "CONFIG"
    ]
    native_kind: NonEmptyStr | None
    name: NonEmptyStr
    location: CodeLocation


class DataGap(ContractModel):
    gap_id: GapId
    stage: Literal["REPOSITORY", "STATIC_ANALYSIS", "CONTEXT", "DYNAMIC", "POLICY"]
    code: NonEmptyStr
    reason: Literal[
        "MISSING", "FAILED", "TRUNCATED", "UNSUPPORTED", "BLOCKED", "TIMEOUT"
    ]
    description: NonEmptyStr
    affected_paths: tuple[GitPath, ...]
    affected_languages: tuple[NonEmptyStr, ...]
    affected_locations: tuple[CodeLocation, ...]
    retryable: bool
    related_record_ids: tuple[NonEmptyStr, ...]
    created_at: AwareDatetime


class AnalysisError(ContractModel):
    error_id: ErrorId
    stage: Literal[
        "INPUT",
        "REPOSITORY",
        "STATIC_ANALYSIS",
        "CONTEXT",
        "ORCHESTRATION",
        "AGENT",
        "PROVIDER",
        "SANDBOX",
        "POLICY",
        "GATE",
        "REPORT",
        "STATE",
        "STORAGE",
        "RECOVERY",
        "AUTHORITY",
    ]
    code: NonEmptyStr
    safe_message: SafeDiagnostic
    retryable: bool
    work_id: WorkId | None
    attempt_id: AttemptId | None
    related_record_ids: tuple[NonEmptyStr, ...]
    created_at: AwareDatetime


class RepositorySelectedTool(ContractModel):
    """One exact production static-tool revision selected for child work."""

    adapter_key: Literal["PYTHON_AST", "CODEQL", "OPENGREP"]
    operation: Literal["PARSE", "ANALYZE"]
    tool_profile_ref: HostConfigurationRef
    languages: tuple[Literal["PYTHON", "JAVASCRIPT"], ...]

    @model_validator(mode="after")
    def route_shape(self) -> Self:
        if (
            self.tool_profile_ref.data_kind != "static_tool_profile"
            or not self.languages
            or len(set(self.languages)) != len(self.languages)
            or self.operation
            != ("PARSE" if self.adapter_key == "PYTHON_AST" else "ANALYZE")
            or (self.adapter_key == "PYTHON_AST" and self.languages != ("PYTHON",))
        ):
            raise ValueError("REPOSITORY_TOOL_SELECTION_INVALID")
        return self


class RepositoryExecutionSelection(DomainRecord):
    """Durable exact capability closure for one repository profile attempt."""

    KIND = "repository_execution_selection"
    HYPOTHESIS = False
    ATTEMPT = True
    repository_profile_ref: StoredDataRef
    git_clone_profile_ref: HostConfigurationRef
    git_checkout_profile_ref: HostConfigurationRef
    languages: tuple[Literal["PYTHON", "JAVASCRIPT"], ...]
    selected_tools: tuple[RepositorySelectedTool, ...]
    gaps: tuple[DataGap, ...]
    errors: tuple[AnalysisError, ...]
    status: Literal["READY", "BLOCKED", "FAILED"]

    @model_validator(mode="after")
    def closed_selection(self) -> Self:
        require_record_ref(self.repository_profile_ref, "repository_profile")
        if any(
            ref.data_kind != "runtime_capability_profile"
            for ref in (self.git_clone_profile_ref, self.git_checkout_profile_ref)
        ):
            raise ValueError("REPOSITORY_GIT_SELECTION_INVALID")
        unique(self.languages)
        unique(
            (item.adapter_key, item.tool_profile_ref, item.languages)
            for item in self.selected_tools
        )
        unique(item.gap_id for item in self.gaps)
        unique(item.error_id for item in self.errors)
        expected_routes = {
            (adapter, language)
            for language in self.languages
            for adapter in (
                ("PYTHON_AST", "CODEQL", "OPENGREP")
                if language == "PYTHON"
                else ("CODEQL", "OPENGREP")
            )
        }
        actual_routes = {
            (item.adapter_key, language)
            for item in self.selected_tools
            for language in item.languages
        }
        if self.status == "READY":
            if (
                not self.languages
                or self.gaps
                or self.errors
                or actual_routes != expected_routes
            ):
                raise ValueError("REPOSITORY_EXECUTION_SELECTION_INCOMPLETE")
        elif self.status == "BLOCKED":
            if self.selected_tools or not self.gaps or self.errors:
                raise ValueError("REPOSITORY_EXECUTION_SELECTION_STATUS_MISMATCH")
        elif self.selected_tools or self.gaps or not self.errors:
            raise ValueError("REPOSITORY_EXECUTION_SELECTION_STATUS_MISMATCH")
        return self


class ToolSource(ContractModel):
    attempt_id: AttemptId
    tool_name: NonEmptyStr
    tool_version: NonEmptyStr
    rule_id: NonEmptyStr | None
    raw_result_ref: StoredDataRef


class CodeFact(ContractModel):
    fact_id: NonEmptyStr
    fact_kind: Literal[
        "SOURCE",
        "SINK",
        "SANITIZER",
        "VALIDATOR",
        "AUTH_CHECK",
        "PERMISSION_CHECK",
        "OTHER",
    ]
    symbol_id: NonEmptyStr | None
    location: CodeLocation
    producer: ToolSource


class CodeFactRef(ContractModel):
    bundle_ref: StoredDataRef
    fact_id: NonEmptyStr

    @model_validator(mode="after")
    def bundle_kind(self) -> Self:
        require_record_ref(self.bundle_ref, "static_fact_bundle")
        return self


class Restriction(ContractModel):
    restriction_id: NonEmptyStr
    statement: NonEmptyStr
    fact_refs: tuple[CodeFactRef, ...]
    evidence_refs: tuple[StoredDataRef, ...]

    @model_validator(mode="after")
    def supported(self) -> Self:
        if not self.fact_refs and not self.evidence_refs:
            raise ValueError("RESTRICTION_EVIDENCE_REQUIRED")
        unique(self.fact_refs)
        unique(self.evidence_refs)
        return self


class CodeRelation(ContractModel):
    relation_id: NonEmptyStr
    relation_kind: Literal[
        "CALL", "DATA_FLOW", "IMPORT", "INHERITANCE", "ROUTE_BINDING", "OTHER"
    ]
    from_symbol_id: NonEmptyStr | None
    from_location: CodeLocation
    to_symbol_id: NonEmptyStr | None
    to_location: CodeLocation
    producer: ToolSource


class ToolCoverage(ContractModel):
    analyzed_paths: tuple[GitPath, ...]
    skipped_paths: tuple[GitPath, ...]
    analyzed_languages: tuple[NonEmptyStr, ...]
    skipped_languages: tuple[NonEmptyStr, ...]
    notes: tuple[NonEmptyStr, ...]


class RuleExecutionItem(ContractModel):
    rule_id: NonEmptyStr
    selection_status: Literal["SELECTED", "NOT_SELECTED"]
    execution_status: Literal["EXECUTED", "NOT_EXECUTED", "UNKNOWN"]
    hit_count: NonNegativeInt | None
    reason: (
        Literal[
            "NOT_SELECTED",
            "TOOL_FAILURE",
            "UNSUPPORTED",
            "CANCELLED",
            "TELEMETRY_MISSING",
            "OTHER",
        ]
        | None
    )
    detail: NonEmptyStr | None

    @model_validator(mode="after")
    def execution_shape(self) -> Self:
        if self.selection_status == "NOT_SELECTED":
            valid = (
                self.execution_status == "NOT_EXECUTED"
                and self.hit_count is None
                and self.reason == "NOT_SELECTED"
            )
        elif self.execution_status == "EXECUTED":
            valid = self.hit_count is not None and self.reason is None
        else:
            reasons = (
                {"TOOL_FAILURE", "OTHER", "TELEMETRY_MISSING"}
                if self.execution_status == "UNKNOWN"
                else {"TOOL_FAILURE", "UNSUPPORTED", "CANCELLED", "OTHER"}
            )
            valid = self.hit_count is None and self.reason in reasons
        if (
            not valid
            or (self.reason is None and self.detail is not None)
            or (self.reason == "OTHER" and self.detail is None)
        ):
            raise ValueError("RULE_EXECUTION_INCONSISTENT")
        return self


class RuleExecutionRecord(DomainRecord):
    KIND = "rule_execution_record"
    HYPOTHESIS = False
    tool_name: NonEmptyStr
    tool_version: NonEmptyStr
    analysis_config_ref: StoredDataRef
    rule_catalog_ref: StoredDataRef
    selected_rule_packs: tuple[NonEmptyStr, ...]
    rules: tuple[RuleExecutionItem, ...]

    @model_validator(mode="after")
    def catalog_shape(self) -> Self:
        if not self.rules:
            raise ValueError("RULE_CATALOG_EMPTY")
        unique(rule.rule_id for rule in self.rules)
        return self


class ToolRunResult(DomainRecord):
    KIND = "tool_run_result"
    HYPOTHESIS = False
    tool_name: NonEmptyStr
    tool_version: NonEmptyStr
    tool_kind: Literal["STRUCTURE", "RULE_BASED"]
    status: Literal["SUCCEEDED", "PARTIAL", "FAILED", "SKIPPED"]
    coverage: ToolCoverage
    rule_execution_ref: StoredDataRef | None
    raw_result_ref: StoredDataRef | None
    gaps: tuple[DataGap, ...]
    errors: tuple[AnalysisError, ...]
    started_at: AwareDatetime
    finished_at: AwareDatetime
    elapsed_ms: NonNegativeInt

    @model_validator(mode="after")
    def result_shape(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("INVALID_TIME_RANGE")
        if self.tool_kind == "STRUCTURE" and self.rule_execution_ref is not None:
            raise ValueError("RULE_EXECUTION_INCONSISTENT")
        if (
            self.tool_kind == "RULE_BASED"
            and self.rule_execution_ref is None
            and self.status != "FAILED"
        ):
            raise ValueError("RULE_EXECUTION_REQUIRED")
        if self.rule_execution_ref is not None:
            require_record_ref(self.rule_execution_ref, "rule_execution_record")
        if self.status != "SUCCEEDED" and not self.gaps:
            raise ValueError("STATIC_COVERAGE_UNEXPLAINED")
        if self.status == "FAILED" and not self.errors:
            raise ValueError("STATIC_ERROR_REQUIRED")
        if self.status in {"SUCCEEDED", "PARTIAL"} and self.raw_result_ref is None:
            raise ValueError("RAW_RESULT_REQUIRED")
        return self


FACT_PARTITIONS = {
    "source_candidates": {"SOURCE"},
    "sink_candidates": {"SINK"},
    "sanitizer_candidates": {"SANITIZER"},
    "validator_candidates": {"VALIDATOR"},
    "auth_and_permission_checks": {"AUTH_CHECK", "PERMISSION_CHECK"},
    "other_facts": {"OTHER"},
}


class StaticFactBundle(DomainRecord):
    KIND = "static_fact_bundle"
    HYPOTHESIS = False
    ATTEMPT = False
    entities: tuple[CodeSymbol, ...]
    locations: tuple[CodeLocation, ...]
    source_candidates: tuple[CodeFact, ...]
    sink_candidates: tuple[CodeFact, ...]
    sanitizer_candidates: tuple[CodeFact, ...]
    validator_candidates: tuple[CodeFact, ...]
    auth_and_permission_checks: tuple[CodeFact, ...]
    other_facts: tuple[CodeFact, ...]
    call_edges: tuple[CodeRelation, ...]
    data_flow_candidates: tuple[CodeRelation, ...]
    route_bindings: tuple[CodeRelation, ...]
    tool_runs: tuple[ToolRunResult, ...]
    gaps: tuple[DataGap, ...]
    errors: tuple[AnalysisError, ...]

    def facts(self) -> tuple[CodeFact, ...]:
        return tuple(fact for name in FACT_PARTITIONS for fact in getattr(self, name))

    @model_validator(mode="after")
    def partition_and_provenance(self) -> Self:
        facts = self.facts()
        unique(fact.fact_id for fact in facts)
        unique(entity.symbol_id for entity in self.entities)
        unique(run.meta.attempt_id for run in self.tool_runs)
        for name, kinds in FACT_PARTITIONS.items():
            if any(fact.fact_kind not in kinds for fact in getattr(self, name)):
                raise ValueError("FACT_KIND_PARTITION")
        relations = (*self.call_edges, *self.data_flow_candidates, *self.route_bindings)
        unique(relation.relation_id for relation in relations)
        symbols = {entity.symbol_id for entity in self.entities}
        observations: tuple[CodeFact | CodeRelation, ...] = (*facts, *relations)
        for item in observations:
            ids = (
                (item.symbol_id,)
                if isinstance(item, CodeFact)
                else (item.from_symbol_id, item.to_symbol_id)
            )
            if any(sid is not None and sid not in symbols for sid in ids):
                raise ValueError("SYMBOL_REFERENCE_MISSING")
            runs = [
                run
                for run in self.tool_runs
                if run.meta.attempt_id == item.producer.attempt_id
            ]
            if len(runs) != 1:
                raise ValueError("PRODUCER_ATTEMPT_MISMATCH")
            run = runs[0]
            if (run.tool_name, run.tool_version, run.raw_result_ref) != (
                item.producer.tool_name,
                item.producer.tool_version,
                item.producer.raw_result_ref,
            ):
                raise ValueError("PRODUCER_REFERENCE_MISMATCH")
            if run.tool_kind == "STRUCTURE" and item.producer.rule_id is not None:
                raise ValueError("RULE_EXECUTION_INCONSISTENT")
        return self


def validate_rule_execution(
    run: ToolRunResult, record: RuleExecutionRecord, catalog_rule_ids: tuple[str, ...]
) -> None:
    if run.rule_execution_ref is None:
        raise ValueError("RULE_EXECUTION_REQUIRED")
    exact(run.rule_execution_ref, record, run.meta)
    same_scope(run.meta, record.meta, attempt=True)
    if (run.tool_name, run.tool_version) != (record.tool_name, record.tool_version):
        raise ValueError("PRODUCER_REFERENCE_MISMATCH")
    exact_set((rule.rule_id for rule in record.rules), catalog_rule_ids)
    selected = [rule for rule in record.rules if rule.selection_status == "SELECTED"]
    if run.status == "SUCCEEDED" and (
        not selected or any(rule.execution_status != "EXECUTED" for rule in selected)
    ):
        raise ValueError("RULE_EXECUTION_INCONSISTENT")
    if run.status == "SKIPPED" and any(
        rule.execution_status == "EXECUTED" for rule in record.rules
    ):
        raise ValueError("RULE_EXECUTION_INCONSISTENT")


def validate_static_current(
    bundle: StaticFactBundle,
    bundle_ref: StoredDataRef,
    workspace: CodeWorkspace,
    work: WorkExecutionState,
    commit: TransitionCommit,
    rule_records: tuple[RuleExecutionRecord, ...],
    *,
    attempt: WorkAttempt,
    rule_catalogs: Mapping[StoredDataRef, tuple[str, ...]] | None = None,
    analysis_config_ref: StoredDataRef | None = None,
) -> None:
    validate_committed_output(
        bundle,
        bundle_ref,
        work,
        attempt,
        commit,
        expected_work_type=WorkType.STATIC_NORMALIZE,
        allowed_statuses=frozenset({WorkStatus.SUCCEEDED, WorkStatus.PARTIAL}),
    )
    if workspace.status != "READY" or (
        workspace.analysis_id,
        workspace.workspace_id,
        workspace.commit_id,
    ) != (bundle.meta.analysis_id, bundle.meta.workspace_id, bundle.meta.commit_id):
        raise ValueError("WORKSPACE_NOT_READY")
    if (
        work.work_type != "STATIC_NORMALIZE"
        or work.status not in {"SUCCEEDED", "PARTIAL"}
        or commit.state != "COMMITTED"
        or commit.work_id != work.work_id
    ):
        raise ValueError("STATIC_NORMALIZATION_NOT_COMMITTED")
    if work.status == "PARTIAL" and not (
        bundle.gaps
        or bundle.errors
        or any(run.gaps or run.errors for run in bundle.tool_runs)
    ):
        raise ValueError("STATIC_COVERAGE_UNEXPLAINED")
    exact_set(work.output_refs, (bundle_ref,))
    exact_set(commit.output_refs, (bundle_ref,))
    for run in bundle.tool_runs:
        if run.rule_execution_ref is None:
            continue
        records = [
            record
            for record in rule_records
            if record.meta.record_id == run.rule_execution_ref.record_id
        ]
        if len(records) != 1:
            raise ValueError("RULE_EXECUTION_REQUIRED")
        record = records[0]
        if (
            rule_catalogs is None
            or record.rule_catalog_ref not in rule_catalogs
            or record.analysis_config_ref != analysis_config_ref
        ):
            raise ValueError("RULE_CATALOG_CLOSURE_MISMATCH")
        validate_rule_execution(run, record, rule_catalogs[record.rule_catalog_ref])
    for fact in bundle.facts():
        if fact.producer.rule_id is not None:
            records = [
                record
                for record in rule_records
                if record.meta.attempt_id == fact.producer.attempt_id
            ]
            if len(records) != 1:
                raise ValueError("RULE_EXECUTION_REQUIRED")
            record = records[0]
            run = next(
                run
                for run in bundle.tool_runs
                if run.meta.attempt_id == fact.producer.attempt_id
            )
            if run.rule_execution_ref is None:
                raise ValueError("RULE_EXECUTION_REQUIRED")
            exact(run.rule_execution_ref, record, bundle.meta)
            matches = [
                rule for rule in record.rules if rule.rule_id == fact.producer.rule_id
            ]
            if (
                len(matches) != 1
                or matches[0].execution_status != "EXECUTED"
                or not matches[0].hit_count
            ):
                raise ValueError("FACT_WITHOUT_RAW_HIT")


class ContextRetrievalLimits(ContractModel):
    max_depth: PositiveInt
    max_fragments: PositiveInt
    max_bytes: PositiveInt
    max_requests_per_hypothesis: PositiveInt
    timeout_ms: PositiveInt


class CodeContextRequest(DomainRecord):
    KIND = "code_context_request"
    HYPOTHESIS = True
    code_request_id: NonEmptyStr
    action_decision_ref: StoredDataRef
    requested_entities: tuple[CodeSymbol, ...]
    requested_locations: tuple[CodeLocation, ...]
    relation_query: tuple[
        Literal[
            "CALLERS", "CALLEES", "DATA_FLOW_NEIGHBORS", "AUTH_GUARDS", "ROUTE_BINDINGS"
        ],
        ...,
    ]
    reason: NonEmptyStr
    limits: ContextRetrievalLimits


class CodeContextResponse(DomainRecord):
    KIND = "code_context_response"
    HYPOTHESIS = True
    code_request_id: NonEmptyStr
    entities: tuple[CodeSymbol, ...]
    locations: tuple[CodeLocation, ...]
    code_fragment_refs: tuple[StoredDataRef, ...]
    discovered_relations: tuple[CodeRelation, ...]
    gaps: tuple[DataGap, ...]
    errors: tuple[AnalysisError, ...]
    truncated: bool
    returned_fragment_count: NonNegativeInt
    returned_bytes: NonNegativeInt
    consumed_token_estimate: NonNegativeInt | None

    @model_validator(mode="after")
    def coverage_shape(self) -> Self:
        if self.returned_fragment_count != len(self.code_fragment_refs):
            raise ValueError("FRAGMENT_COUNT_MISMATCH")
        if self.truncated and not any(
            gap.stage == "CONTEXT" and gap.code == "CONTEXT_TRUNCATED"
            for gap in self.gaps
        ):
            raise ValueError("CONTEXT_GAP_REQUIRED")
        if self.errors and not any(gap.stage == "CONTEXT" for gap in self.gaps):
            raise ValueError("CONTEXT_GAP_REQUIRED")
        return self
