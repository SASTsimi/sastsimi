"""Official-policy LLM parsing with a strict content-only trust boundary."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol, cast

from pydantic import JsonValue, ValidationError

from sastsimi.contracts.base import ContractModel, NonEmptyStr
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import ErrorId, LogicalRecordId, RecordId
from sastsimi.contracts.policy import PolicyArea, PolicyParserResult
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.llm_invocation import PersistedLLMInvocation


class PolicyParserInvocationPort(Protocol):
    """Trusted T09 composition seam for one already-authorized parser call."""

    async def invoke(
        self,
        *,
        work: WorkExecutionState,
        source_ref: StoredDataRef,
    ) -> PersistedLLMInvocation: ...


class PolicyItemContent(ContractModel):
    item_key: NonEmptyStr
    value: NonEmptyStr
    description: NonEmptyStr
    conditions: tuple[NonEmptyStr, ...]
    source_locator: NonEmptyStr


class PolicyMissingInfoContent(ContractModel):
    area: PolicyArea
    blocks_allow: bool
    description: NonEmptyStr
    policy_item_keys: tuple[NonEmptyStr, ...]


class ParsedPolicyContent(ContractModel):
    """Untrusted content proposal; runtime IDs, refs and conclusions are absent."""

    document_status: str
    policy_version: NonEmptyStr
    in_scope_assets: tuple[PolicyItemContent, ...]
    out_of_scope_assets: tuple[PolicyItemContent, ...]
    accepted_vulnerability_classes: tuple[PolicyItemContent, ...]
    excluded_vulnerability_classes: tuple[PolicyItemContent, ...]
    testing_restrictions: tuple[PolicyItemContent, ...]
    reward_conditions: tuple[PolicyItemContent, ...]
    impact_criteria: tuple[PolicyItemContent, ...]
    disclosure_requirements: tuple[PolicyItemContent, ...]
    missing_information: tuple[PolicyMissingInfoContent, ...]

    def require_document_status(self) -> None:
        if self.document_status not in {"FOUND", "ABSENT_CONFIRMED"}:
            raise ValueError("POLICY_DOCUMENT_STATUS_INVALID")


@dataclass(frozen=True, slots=True)
class PolicyParserAgentOutcome:
    result: PolicyParserResult
    content: ParsedPolicyContent | None
    invocation_refs: tuple[StoredDataRef, ...]


class PolicyParserAgent:
    """Consume only T09's persisted canonical output and inject trusted metadata."""

    def __init__(
        self,
        *,
        invocations: PolicyParserInvocationPort,
        artifacts: ArtifactStore,
        ids: IdGenerator,
        clock: Clock,
        parser_name: str,
        parser_version: str,
    ) -> None:
        self._invocations = invocations
        self._artifacts = artifacts
        self._ids = ids
        self._clock = clock
        self._parser_name = parser_name
        self._parser_version = parser_version

    async def parse(
        self,
        *,
        work: WorkExecutionState,
        source_ref: StoredDataRef,
    ) -> PolicyParserAgentOutcome:
        self._require_work(work, source_ref)
        invocation = await self._invocations.invoke(work=work, source_ref=source_ref)
        self._require_invocation(invocation, work, source_ref)
        content: ParsedPolicyContent | None = None
        status = "FAILED"
        error_ids: tuple[ErrorId, ...] = (self._ids.new(ErrorId),)
        parsed_output_ref = None
        if invocation.result.status == "SUCCEEDED":
            parsed_output_ref = invocation.result.parsed_output_ref
            try:
                content = self._read_content(parsed_output_ref)
                content.require_document_status()
            except ValueError:
                status = "INVALID_OUTPUT"
            else:
                status = "SUCCEEDED"
                error_ids = ()
        result = PolicyParserResult.model_validate(
            dict(
                meta=self._metadata(work),
                parser_result_id=str(self._ids.new(RecordId)),
                parser_name=self._parser_name,
                parser_version=self._parser_version,
                source_ref=source_ref,
                llm_invocation_ref=reference(invocation.request),
                parsed_output_ref=parsed_output_ref,
                status=status,
                error_ids=error_ids,
                completed_at=self._clock.now(),
            )
        )
        request_ref = reference(invocation.request)
        result_ref = reference(invocation.result)
        if not isinstance(request_ref, StoredDataRef) or not isinstance(
            result_ref, StoredDataRef
        ):
            raise ValueError("POLICY_PARSER_INVOCATION_MISMATCH")
        invocation_refs: tuple[StoredDataRef, ...] = (
            request_ref,
            result_ref,
            invocation.log_ref,
        )
        if parsed_output_ref is not None:
            invocation_refs += (parsed_output_ref,)
        return PolicyParserAgentOutcome(result, content, invocation_refs)

    def _metadata(self, work: WorkExecutionState) -> RecordMeta:
        if not isinstance(work.meta, RecordMeta) or work.active_attempt_id is None:
            raise ValueError("POLICY_PARSER_WORK_NOT_ACTIVE")
        record_id = self._ids.new(RecordId)
        return RecordMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type="policy_parser_result",
            schema_version=work.meta.schema_version,
            revision_number=1,
            previous_record_id=None,
            created_at=self._clock.now(),
            analysis_id=work.meta.analysis_id,
            workspace_id=work.meta.workspace_id,
            commit_id=work.meta.commit_id,
            hypothesis_id=None,
            attempt_id=work.active_attempt_id,
        )

    @staticmethod
    def _require_work(work: WorkExecutionState, source_ref: StoredDataRef) -> None:
        if (
            not isinstance(work.meta, RecordMeta)
            or work.work_type != WorkType.POLICY_FETCH
            or work.status != WorkStatus.RUNNING
            or work.meta.hypothesis_id is not None
            or work.active_attempt_id is None
            or source_ref.record_id is not None
            or source_ref.data_kind != "artifact"
            or (source_ref.workspace_id, source_ref.commit_id)
            != (work.meta.workspace_id, work.meta.commit_id)
        ):
            raise ValueError("POLICY_PARSER_SOURCE_MISMATCH")

    @staticmethod
    def _require_invocation(
        invocation: PersistedLLMInvocation,
        work: WorkExecutionState,
        source_ref: StoredDataRef,
    ) -> None:
        request, result = invocation.request, invocation.result
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("POLICY_PARSER_INVOCATION_MISMATCH")
        fields = ("analysis_id", "workspace_id", "commit_id", "hypothesis_id")
        if (
            request.agent_role != "POLICY_PARSER"
            or request.task_kind != "PARSE_OFFICIAL_POLICY"
            or request.session_policy != "NEW"
            or request.parent_session_ref is not None
            or request.context_refs != (source_ref,)
            or request.meta.attempt_id != work.active_attempt_id
            or any(
                getattr(request.meta, name) != getattr(work.meta, name)
                for name in fields
            )
            or result.llm_call_id != request.llm_call_id
            or result.purpose != request.purpose
            or result.model != request.model
            or any(
                getattr(result.meta, name) != getattr(request.meta, name)
                for name in (*fields, "attempt_id")
            )
            or invocation.log_ref.data_kind != "llm_invocation_log"
        ):
            raise ValueError("POLICY_PARSER_INVOCATION_MISMATCH")
        output_ref = result.parsed_output_ref
        if result.status == "SUCCEEDED":
            if (
                output_ref is None
                or result.response_ref != output_ref
                or output_ref.record_id is not None
                or output_ref.data_kind != "artifact"
                or (output_ref.workspace_id, output_ref.commit_id)
                != (work.meta.workspace_id, work.meta.commit_id)
            ):
                raise ValueError("POLICY_PARSER_OUTPUT_REFERENCE_MISMATCH")
        elif output_ref is not None or result.response_ref is not None:
            raise ValueError("POLICY_PARSER_OUTPUT_REFERENCE_MISMATCH")

    def _read_content(self, output_ref: StoredDataRef | None) -> ParsedPolicyContent:
        if output_ref is None:
            raise ValueError("POLICY_PARSER_OUTPUT_REFERENCE_MISMATCH")
        try:
            with self._artifacts.open_verified(output_ref) as stream:
                raw = stream.read()
            value = json.loads(raw)
            if canonical_bytes(value) != raw or not isinstance(value, dict):
                raise ValueError("POLICY_PARSER_OUTPUT_INVALID")
            _reject_runtime_authority(cast(JsonValue, value))
            return ParsedPolicyContent.model_validate_json(raw)
        except ValueError:
            raise
        except (OSError, TypeError, ValidationError, json.JSONDecodeError) as error:
            raise ValueError("POLICY_PARSER_OUTPUT_INVALID") from error


def _reject_runtime_authority(value: JsonValue) -> None:
    denied_exact = {
        "meta",
        "program_policy_record",
        "rule_scope_impact_review",
        "scope_verdict",
        "report_permission",
        "freshness_status",
        "freshness_checked_at",
        "freshness_valid_until",
        "current_pointer",
    }
    denied_suffixes = ("_id", "_ref", "_refs")

    def walk(item: JsonValue) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if key in denied_exact or key.endswith(denied_suffixes):
                    raise ValueError("OUTPUT_RUNTIME_AUTHORITY_DENIED")
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)


__all__ = [
    "ParsedPolicyContent",
    "PolicyItemContent",
    "PolicyMissingInfoContent",
    "PolicyParserAgent",
    "PolicyParserAgentOutcome",
    "PolicyParserInvocationPort",
]
