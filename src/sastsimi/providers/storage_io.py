"""Exact stored prompt I/O and safe normalized provider result persistence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Protocol, cast

from pydantic import JsonValue

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import AttemptId
from sastsimi.contracts.llm import (
    LLMInvocationRequest,
    LLMInvocationResult,
    LLMRole,
    OutputSchemaSpec,
    PromptPayload,
    SemanticValidatorSpec,
)
from sastsimi.contracts.prompt_redaction import (
    assert_safe_provider_text,
    redact_projected_json,
    render_provider_prompt,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.dto import Record
from sastsimi.ports.record_store import RecordStore

from .base import (
    InvocationResultBuilder,
    NormalizedProviderResult,
    OutputSchemaValidator,
    PromptInputResolver,
    ProviderInputMismatchError,
    ProviderInvalidOutputError,
    ResolvedPromptContext,
    ResolvedPromptInput,
    StructuredOutputValue,
)

type SemanticValidator = Callable[[StructuredOutputValue], None]


class StructuredOutputValidator(Protocol):
    """Injected trusted prompt-runtime validator (normally prompts.validate_output)."""

    def __call__(
        self,
        raw: bytes,
        *,
        json_schema: Mapping[str, object],
        result_kind: str,
        agent_role: LLMRole,
        semantic_validator: SemanticValidator,
    ) -> StructuredOutputValue: ...


class InvocationMetadataFactory(Protocol):
    """Issue immutable record metadata without hiding ID allocation in this lane."""

    def __call__(
        self,
        source: RecordMeta,
        record_type: str,
        attempt_id: AttemptId | None,
    ) -> RecordMeta: ...


class StoredPromptInputResolver(PromptInputResolver):
    """Resolve only the exact stored payload and verified artifact bytes."""

    def __init__(self, records: RecordStore, artifacts: ArtifactStore) -> None:
        self._records = records
        self._artifacts = artifacts

    async def resolve(self, request: LLMInvocationRequest) -> ResolvedPromptInput:
        try:
            payload = self._records.get_exact(request.prompt_payload_ref)
            output_schema = self._records.get_exact(request.output_schema_ref)
            if not isinstance(payload, PromptPayload) or not isinstance(
                output_schema, OutputSchemaSpec
            ):
                raise ProviderInputMismatchError
            self._require_exact_record(request.prompt_payload_ref, payload)
            self._require_exact_record(request.output_schema_ref, output_schema)
            self._require_payload_closure(request, payload, output_schema)

            template = self._read_artifact(request, payload.template_ref)
            rendered = self._read_artifact(request, payload.rendered_prompt_ref)
            schema_bytes = self._read_artifact(
                request, output_schema.schema_artifact_ref
            )
            contexts = tuple(
                ResolvedPromptContext(
                    slot=str(binding.slot),
                    projected_data_ref=binding.projected_data_ref,
                    data=self._read_artifact(request, binding.projected_data_ref),
                )
                for binding in payload.context_bindings
            )
            expected_rendered = render_provider_prompt(
                template,
                tuple((item.slot, item.data) for item in contexts),
            )
            schema_value = json.loads(schema_bytes.decode("utf-8"))
            if (
                not isinstance(schema_value, dict)
                or canonical_bytes(schema_value) != schema_bytes
                or request.output_schema.encode("utf-8") != schema_bytes
                or rendered != expected_rendered
            ):
                raise ProviderInputMismatchError
            return ResolvedPromptInput(
                payload=payload,
                template_bytes=template,
                rendered_prompt_bytes=rendered,
                projected_contexts=contexts,
                output_schema=output_schema,
                output_schema_bytes=schema_bytes,
            )
        except ProviderInputMismatchError:
            raise
        except Exception as error:
            raise ProviderInputMismatchError("PROVIDER_INPUT_MISMATCH") from error

    @staticmethod
    def _require_exact_record(ref: StoredDataRef, record: Record) -> None:
        exact = reference(record)
        if not isinstance(exact, StoredDataRef) or exact != ref:
            raise ProviderInputMismatchError("PROVIDER_INPUT_MISMATCH")

    @staticmethod
    def _require_payload_closure(
        request: LLMInvocationRequest,
        payload: PromptPayload,
        output_schema: OutputSchemaSpec,
    ) -> None:
        if (
            payload.meta.analysis_id != request.meta.analysis_id
            or payload.meta.workspace_id != request.meta.workspace_id
            or payload.meta.commit_id != request.meta.commit_id
            or payload.meta.hypothesis_id != request.meta.hypothesis_id
            or payload.meta.attempt_id != request.meta.attempt_id
            or payload.registry_entry_ref != request.prompt_registry_entry_ref
            or payload.prompt_key != request.prompt_key
            or payload.agent_role != request.agent_role
            or payload.task_kind != request.task_kind
            or payload.purpose != request.purpose
            or payload.template_ref != request.prompt_template_ref
            or payload.template_version != request.prompt_template_version
            or payload.output_schema_ref != request.output_schema_ref
            or tuple(binding.source_ref for binding in payload.context_bindings)
            != request.context_refs
            or output_schema.meta.analysis_id != request.meta.analysis_id
            or output_schema.meta.workspace_id != request.meta.workspace_id
            or output_schema.meta.commit_id != request.meta.commit_id
        ):
            raise ProviderInputMismatchError("PROVIDER_INPUT_MISMATCH")

    def _read_artifact(
        self, request: LLMInvocationRequest, ref: StoredDataRef
    ) -> bytes:
        if (
            ref.record_id is not None
            or ref.data_kind != "artifact"
            or ref.workspace_id != request.meta.workspace_id
            or ref.commit_id != request.meta.commit_id
            or str(ref.stored_data_id) != ref.content_hash
        ):
            raise ProviderInputMismatchError("PROVIDER_INPUT_MISMATCH")
        with self._artifacts.open_verified(ref) as stream:
            data = stream.read()
        if hashlib.sha256(data).hexdigest() != ref.content_hash:
            raise ProviderInputMismatchError("PROVIDER_INPUT_MISMATCH")
        return data


class StoredOutputValidator(OutputSchemaValidator):
    """Validate JSON without granting the Provider domain-record authority."""

    def __init__(
        self,
        records: RecordStore,
        semantic_validators: Mapping[StoredDataRef, SemanticValidator],
        validate_structured_output: StructuredOutputValidator,
    ) -> None:
        self._records = records
        self._semantic_validators = dict(semantic_validators)
        self._validate_structured_output = validate_structured_output

    def validate(
        self,
        raw: bytes,
        *,
        schema: dict[str, JsonValue],
        output_schema: OutputSchemaSpec,
        request: LLMInvocationRequest,
    ) -> StructuredOutputValue:
        try:
            stored_schema = self._records.get_exact(request.output_schema_ref)
            validator_spec = self._records.get_exact(request.semantic_validator_ref)
            if (
                not isinstance(stored_schema, OutputSchemaSpec)
                or stored_schema != output_schema
                or reference(stored_schema) != request.output_schema_ref
                or not isinstance(validator_spec, SemanticValidatorSpec)
                or reference(validator_spec) != request.semantic_validator_ref
                or canonical_bytes(schema).decode("utf-8") != request.output_schema
            ):
                raise ProviderInvalidOutputError
            semantic_validator = self._semantic_validators.get(
                request.semantic_validator_ref
            )
            if semantic_validator is None:
                raise ProviderInvalidOutputError
            if redact_projected_json(raw).categories:
                raise ProviderInvalidOutputError
            validated = self._validate_structured_output(
                raw,
                json_schema=cast(Mapping[str, object], schema),
                result_kind=output_schema.result_kind,
                agent_role=request.agent_role,
                semantic_validator=semantic_validator,
            )
            return validated
        except ProviderInvalidOutputError:
            raise
        except Exception as error:
            raise ProviderInvalidOutputError from error


class StoredInvocationResultBuilder(InvocationResultBuilder):
    """Persist validated provider JSON as an artifact, never as a domain record."""

    def __init__(
        self,
        records: RecordStore,
        artifacts: ArtifactStore,
        metadata_factory: InvocationMetadataFactory,
    ) -> None:
        self._artifacts = artifacts
        self._metadata_factory = metadata_factory

    def build(
        self,
        request: LLMInvocationRequest,
        outcome: NormalizedProviderResult,
    ) -> LLMInvocationResult:
        parsed_output_ref: StoredDataRef | None = None
        response_ref: StoredDataRef | None = None
        expected_session_mode = (
            "NEW"
            if request.session_policy == "NEW"
            or (request.session_policy == "AUTO" and request.parent_session_ref is None)
            else "RESUMED"
        )
        if (
            outcome.model != request.model
            or outcome.actual_session_mode != expected_session_mode
        ):
            raise ProviderInvalidOutputError
        if outcome.status == "SUCCEEDED":
            if (
                outcome.validated_output is None
                or outcome.parsed_output is None
                or outcome.response_text is None
                or outcome.safe_error is not None
            ):
                raise ProviderInvalidOutputError
            output = outcome.validated_output
            try:
                parsed_response = json.loads(outcome.response_text)
            except json.JSONDecodeError as error:
                raise ProviderInvalidOutputError from error
            if canonical_bytes(parsed_response) != canonical_bytes(
                outcome.parsed_output
            ) or canonical_bytes(output) != canonical_bytes(outcome.parsed_output):
                raise ProviderInvalidOutputError
            safe_response = redact_projected_json(canonical_bytes(output))
            if safe_response.categories:
                raise ProviderInvalidOutputError
            output_artifact = self._artifacts.commit(
                self._artifacts.stage_bytes(safe_response.data, "application/json")
            )
            parsed_output_ref = output_artifact
            response_ref = output_artifact
        elif (
            outcome.validated_output is not None
            or outcome.parsed_output is not None
            or outcome.response_text is not None
            or outcome.safe_error is None
        ):
            raise ProviderInvalidOutputError
        if outcome.safe_error is not None:
            try:
                assert_safe_provider_text(outcome.safe_error.encode("utf-8"))
            except ValueError as error:
                raise ProviderInvalidOutputError from error
        meta = self._metadata_factory(
            request.meta, "llm_invocation_result", request.meta.attempt_id
        )
        return LLMInvocationResult.model_validate(
            {
                "meta": meta,
                "llm_call_id": request.llm_call_id,
                "purpose": request.purpose,
                "status": outcome.status,
                "provider": outcome.provider,
                "model": outcome.model,
                "actual_session_mode": outcome.actual_session_mode,
                "session_ref": outcome.session_ref,
                "response_ref": response_ref,
                "parsed_output_ref": parsed_output_ref,
                "usage": outcome.usage,
                "started_at": outcome.started_at,
                "finished_at": outcome.finished_at,
                "elapsed_ms": outcome.elapsed_ms,
                "safe_error": outcome.safe_error,
            }
        )


__all__ = [
    "InvocationMetadataFactory",
    "SemanticValidator",
    "StructuredOutputValidator",
    "StoredInvocationResultBuilder",
    "StoredOutputValidator",
    "StoredPromptInputResolver",
]
