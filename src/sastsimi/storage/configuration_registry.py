"""Family-specific trusted configuration registries with exact closure."""

from collections.abc import Callable

from sqlalchemy import Connection, insert, select, update

from sastsimi.contracts.budget import (
    DynamicReproductionLifecycleProfile,
    ProfileStatus,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    ExecutionLimits,
    LLMCallSpec,
    LLMRetryPolicy,
    LLMToolPolicy,
    OutputSchemaSpec,
    PromptPayload,
    PromptRedactionPolicy,
    PromptRegistryEntry,
    ProviderProfile,
    ProviderValidationEvidence,
    SemanticValidatorSpec,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.ports.dto import Record

from . import models
from .codec import reference
from .repositories import SQLiteRecordStore


class ConfigurationRegistry:
    def __init__(self, records: SQLiteRecordStore) -> None:
        self.records = records

    def _publish[T: Record](
        self, record: T, approved: Callable[[T], bool]
    ) -> StoredDataRef:
        if not approved(record):
            raise ValueError("CONFIGURATION_APPROVAL_REQUIRED")
        if (
            getattr(record.meta, "hypothesis_id", None) is not None
            or getattr(record.meta, "attempt_id", None) is not None
        ):
            raise ValueError("CONFIGURATION_SCOPE_MISMATCH")
        ref = reference(record)
        if not isinstance(ref, StoredDataRef):
            raise ValueError("CONFIGURATION_SCOPE_MISMATCH")
        with self.records.database.write() as connection:
            staged = self.records.stage(connection, record)
            assert staged == ref
            self.records.publish(connection, ref)
            self._point(connection, record)
        return ref

    def _point(self, connection: Connection, record: Record) -> None:
        table = models.current_records
        logical_id = str(record.meta.logical_record_id)
        old = (
            connection.execute(
                select(table).where(table.c.logical_record_id == logical_id)
            )
            .mappings()
            .first()
        )
        if old is None:
            if record.meta.revision_number != 1:
                raise ValueError("RECORD_REVISION_MISMATCH")
            connection.execute(
                insert(table).values(
                    logical_record_id=logical_id,
                    record_id=str(record.meta.record_id),
                    state_version=1,
                )
            )
            return
        if old["record_id"] == str(record.meta.record_id):
            return
        if record.meta.previous_record_id != old["record_id"]:
            raise ValueError("STALE_CONFIGURATION_REVISION")
        changed = connection.execute(
            update(table)
            .where(
                table.c.logical_record_id == logical_id,
                table.c.state_version == old["state_version"],
            )
            .values(
                record_id=str(record.meta.record_id),
                state_version=old["state_version"] + 1,
            )
        )
        if changed.rowcount != 1:
            raise ValueError("STALE_CONFIGURATION_REVISION")

    def register_work_budget(self, record: WorkBudgetProfile) -> StoredDataRef:
        record = WorkBudgetProfile.model_validate(record)
        if record.status != ProfileStatus.ACTIVE:
            raise ValueError("BUDGET_CONFIGURATION_NOT_ACTIVE")
        approved = self.records.evidence.budget_configuration_approved
        return self._publish(record, approved)

    def register_verification_budget(
        self, record: VerificationBudgetProfile
    ) -> StoredDataRef:
        record = VerificationBudgetProfile.model_validate(record)
        if record.status != ProfileStatus.ACTIVE:
            raise ValueError("BUDGET_CONFIGURATION_NOT_ACTIVE")
        approved = self.records.evidence.budget_configuration_approved
        return self._publish(record, approved)

    def register_dynamic_lifecycle(
        self, record: DynamicReproductionLifecycleProfile
    ) -> StoredDataRef:
        record = DynamicReproductionLifecycleProfile.model_validate(record)
        if record.status != ProfileStatus.ACTIVE:
            raise ValueError("BUDGET_CONFIGURATION_NOT_ACTIVE")
        with self.records.database.engine.connect() as connection:
            profile = self.records.resolve(connection, record.preflight_budget_ref)
            if not isinstance(profile, WorkBudgetProfile):
                raise ValueError("BUDGET_CONFIGURATION_CLOSURE_MISMATCH")
            if profile.status != ProfileStatus.ACTIVE:
                raise ValueError("BUDGET_CONFIGURATION_CLOSURE_MISMATCH")
        approved = self.records.evidence.budget_configuration_approved
        return self._publish(record, approved)

    def register_playbook(self, record: VerificationPlaybook) -> StoredDataRef:
        record = VerificationPlaybook.model_validate(record)
        return self._publish(
            record, self.records.evidence.playbook_configuration_approved
        )

    def register_playbook_policy(self, record: PlaybookPolicy) -> StoredDataRef:
        record = PlaybookPolicy.model_validate(record)
        with self.records.database.engine.connect() as connection:
            refs = (record.common_playbook_ref,) + tuple(
                item.playbook_ref for item in record.type_playbooks
            )
            for ref in refs:
                book = self.records.resolve(connection, ref)
                if not isinstance(book, VerificationPlaybook):
                    raise ValueError("PLAYBOOK_POLICY_CLOSURE_MISMATCH")
        return self._publish(
            record, self.records.evidence.playbook_configuration_approved
        )

    def register_provider_validation(
        self, record: ProviderValidationEvidence
    ) -> StoredDataRef:
        record = ProviderValidationEvidence.model_validate(record)
        approved = self.records.evidence.llm_configuration_approved
        return self._publish(record, approved)

    def register_provider_profile(self, record: ProviderProfile) -> StoredDataRef:
        record = ProviderProfile.model_validate(record)
        with self.records.database.engine.connect() as connection:
            validation = self.records.resolve(
                connection, record.validation_evidence_ref
            )
            if not isinstance(validation, ProviderValidationEvidence):
                raise ValueError("PROVIDER_CONFIGURATION_CLOSURE_MISMATCH")
            identity = (
                "profile_key",
                "provider",
                "product",
                "transport",
                "model",
                "environment",
                "auth_mode",
                "client_name",
                "client_version",
            )
            if any(
                getattr(record, name) != getattr(validation, name) for name in identity
            ):
                raise ValueError("PROVIDER_CONFIGURATION_CLOSURE_MISMATCH")
        if record.support_status != "SUPPORTED":
            raise ValueError("PROVIDER_CONFIGURATION_NOT_SUPPORTED")
        approved = self.records.evidence.llm_configuration_approved
        return self._publish(record, approved)

    def _llm_leaf[
        T: (
            ClientExecutionProfile,
            ExecutionLimits,
            LLMRetryPolicy,
            LLMToolPolicy,
            OutputSchemaSpec,
            PromptRedactionPolicy,
            SemanticValidatorSpec,
        )
    ](self, record: T) -> StoredDataRef:
        approved = self.records.evidence.llm_configuration_approved
        return self._publish(record, approved)

    def register_client_execution(
        self, record: ClientExecutionProfile
    ) -> StoredDataRef:
        return self._llm_leaf(ClientExecutionProfile.model_validate(record))

    def register_execution_limits(self, record: ExecutionLimits) -> StoredDataRef:
        return self._llm_leaf(ExecutionLimits.model_validate(record))

    def register_retry_policy(self, record: LLMRetryPolicy) -> StoredDataRef:
        return self._llm_leaf(LLMRetryPolicy.model_validate(record))

    def register_tool_policy(self, record: LLMToolPolicy) -> StoredDataRef:
        return self._llm_leaf(LLMToolPolicy.model_validate(record))

    def register_redaction_policy(self, record: PromptRedactionPolicy) -> StoredDataRef:
        return self._llm_leaf(PromptRedactionPolicy.model_validate(record))

    def register_output_schema(self, record: OutputSchemaSpec) -> StoredDataRef:
        return self._llm_leaf(OutputSchemaSpec.model_validate(record))

    def register_semantic_validator(
        self, record: SemanticValidatorSpec
    ) -> StoredDataRef:
        return self._llm_leaf(SemanticValidatorSpec.model_validate(record))

    def _resolve_kinds(
        self, refs: tuple[StoredDataRef, ...], kinds: tuple[str, ...]
    ) -> None:
        with self.records.database.engine.connect() as connection:
            for ref, kind in zip(refs, kinds, strict=True):
                value = self.records.resolve(connection, ref)
                if value.meta.record_type != kind:
                    raise ValueError("LLM_CONFIGURATION_CLOSURE_MISMATCH")

    def register_prompt_entry(self, record: PromptRegistryEntry) -> StoredDataRef:
        record = PromptRegistryEntry.model_validate(record)
        if record.status != "ACTIVE":
            raise ValueError("PROMPT_CONFIGURATION_NOT_ACTIVE")
        refs = (
            *record.provider_profile_refs,
            record.output_schema_ref,
            record.execution_limits_ref,
            record.retry_policy_ref,
            record.semantic_validator_ref,
            record.tool_policy_ref,
            record.redaction_policy_ref,
        )
        kinds = (
            *("provider_profile" for _ in record.provider_profile_refs),
            "output_schema_spec",
            "execution_limits",
            "llm_retry_policy",
            "semantic_validator_spec",
            "llm_tool_policy",
            "prompt_redaction_policy",
        )
        self._resolve_kinds(refs, kinds)
        approved = self.records.evidence.llm_configuration_approved
        return self._publish(record, approved)

    def register_prompt_payload(self, record: PromptPayload) -> StoredDataRef:
        record = PromptPayload.model_validate(record)
        self._resolve_kinds(
            (record.registry_entry_ref, record.output_schema_ref),
            ("prompt_registry_entry", "output_schema_spec"),
        )
        approved = self.records.evidence.llm_configuration_approved
        return self._publish(record, approved)

    def register_call_spec(self, record: LLMCallSpec) -> StoredDataRef:
        record = LLMCallSpec.model_validate(record)
        refs = (
            record.provider_profile_ref,
            record.prompt_registry_entry_ref,
            record.prompt_payload_ref,
            record.execution_limits_ref,
            record.retry_policy_ref,
            record.tool_policy_ref,
            record.redaction_policy_ref,
            record.semantic_validator_ref,
            record.output_schema_ref,
        )
        kinds = (
            "provider_profile",
            "prompt_registry_entry",
            "prompt_payload",
            "execution_limits",
            "llm_retry_policy",
            "llm_tool_policy",
            "prompt_redaction_policy",
            "semantic_validator_spec",
            "output_schema_spec",
        )
        self._resolve_kinds(refs, kinds)
        approved = self.records.evidence.llm_configuration_approved
        return self._publish(record, approved)

    def register_sandbox_profile(self, record: SandboxProfile) -> StoredDataRef:
        record = SandboxProfile.model_validate(record)
        if record.network_mode != "DEFAULT_DENY":
            raise ValueError("SANDBOX_CONFIGURATION_DENIED")
        return self._publish(
            record, self.records.evidence.sandbox_configuration_approved
        )
