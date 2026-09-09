"""Family-specific trusted configuration registries with exact closure."""

from collections.abc import Callable
from typing import cast

from sqlalchemy import Connection, insert, select, update

from sastsimi.contracts.budget import (
    DynamicReproductionLifecycleProfile,
    ProfileStatus,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.evaluation import (
    EvaluationRecommendation,
    EvaluationRunConfig,
    EvaluationRunResult,
)
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
        if str(record.meta.previous_record_id) != old["record_id"]:
            raise ValueError(
                "STALE_CONFIGURATION_REVISION: expected "
                f"{record.meta.previous_record_id}, current {old['record_id']}"
            )
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
        by_id = {test.test_id: test for test in record.tests}
        required = {f"PVD-{index:02d}" for index in range(1, 16)}
        if (set(by_id) != required and set(by_id) != required | {"PVD-16"}) or any(
            test.result == "FAIL" or not test.evidence_refs for test in record.tests
        ):
            raise ValueError("PROVIDER_VALIDATION_INCOMPLETE")
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
            tests = {test.test_id: test for test in validation.tests}
            if record.capabilities.runtime_tool_loop == "SUPPORTED" and (
                "PVD-16" not in tests or tests["PVD-16"].result != "PASS"
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
        if record.status == "RETIRED":
            raise ValueError("PROMPT_CONFIGURATION_RETIRED")
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
        with self.records.database.engine.connect() as connection:
            providers = tuple(
                self.records.resolve(connection, ref)
                for ref in record.provider_profile_refs
            )
            schema = self.records.resolve(connection, record.output_schema_ref)
            if any(
                not isinstance(provider, ProviderProfile)
                or provider.support_status != "SUPPORTED"
                for provider in providers
            ) or not isinstance(schema, OutputSchemaSpec):
                raise ValueError("LLM_CONFIGURATION_CLOSURE_MISMATCH")
            if schema.result_kind != record.result_kind:
                raise ValueError("LLM_CONFIGURATION_CLOSURE_MISMATCH")
            if record.purpose == "PRODUCTION" and record.status == "ACTIVE":
                self._validate_production_activation(connection, record)
        approved = self.records.evidence.llm_configuration_approved
        return self._publish(record, approved)

    @staticmethod
    def _prompt_semantics(record: PromptRegistryEntry) -> tuple[object, ...]:
        return tuple(
            getattr(record, name)
            for name in (
                "agent_role",
                "task_kind",
                "template_ref",
                "template_version",
                "input_slots",
                "forbidden_context_kinds",
                "output_schema_ref",
                "session_policy",
                "provider_profile_refs",
                "execution_limits_ref",
                "retry_policy_ref",
                "semantic_validator_ref",
                "tool_policy_ref",
                "redaction_policy_ref",
                "result_kind",
            )
        )

    def _validate_production_activation(
        self, connection: Connection, record: PromptRegistryEntry
    ) -> None:
        if (
            record.meta.previous_record_id is None
            or record.quality_evaluation_ref is None
        ):
            raise ValueError("QUALITY_EVIDENCE_REQUIRED")
        previous_ref_raw = connection.execute(
            select(models.records.c.ref).where(
                models.records.c.record_id == str(record.meta.previous_record_id)
            )
        ).scalar_one_or_none()
        if previous_ref_raw is None:
            raise ValueError("QUALITY_EVIDENCE_REQUIRED")
        from .codec import REF_ADAPTER

        previous = self.records.resolve(
            connection, REF_ADAPTER.validate_json(previous_ref_raw)
        )
        recommendation = self.records.resolve(connection, record.quality_evaluation_ref)
        if (
            not isinstance(previous, PromptRegistryEntry)
            or previous.status != "DRAFT"
            or previous.purpose != "PRODUCTION"
            or previous.meta.logical_record_id != record.meta.logical_record_id
            or self._prompt_semantics(previous) != self._prompt_semantics(record)
            or not isinstance(recommendation, EvaluationRecommendation)
            or recommendation.decision != "ACCEPT_FOR_PRODUCTION"
        ):
            raise ValueError("QUALITY_EVIDENCE_MISMATCH")
        evaluation = self.records.resolve(
            connection, recommendation.evaluation_result_ref
        )
        target = self.records.resolve(
            connection, recommendation.target_prompt_registry_entry_ref
        )
        if (
            not isinstance(evaluation, EvaluationRunResult)
            or evaluation.status != "SUCCEEDED"
            or not isinstance(target, PromptRegistryEntry)
            or target.purpose != "EVALUATION"
            or target.status != "ACTIVE"
            or self._prompt_semantics(target) != self._prompt_semantics(record)
        ):
            raise ValueError("QUALITY_EVIDENCE_MISMATCH")
        config = self.records.resolve(connection, evaluation.config_ref)
        if (
            not isinstance(config, EvaluationRunConfig)
            or config.provider_profile_ref != recommendation.target_provider_profile_ref
            or config.model != recommendation.target_model
            or config.session_policy != recommendation.target_session_policy
            or config.prompt_registry_entry_ref
            != recommendation.target_prompt_registry_entry_ref
            or config.output_schema_ref != record.output_schema_ref
            or recommendation.target_provider_profile_ref
            not in record.provider_profile_refs
        ):
            raise ValueError("QUALITY_EVIDENCE_MISMATCH")

    def register_prompt_payload(self, record: PromptPayload) -> StoredDataRef:
        record = PromptPayload.model_validate(record)
        self._resolve_kinds(
            (record.registry_entry_ref, record.output_schema_ref),
            ("prompt_registry_entry", "output_schema_spec"),
        )
        with self.records.database.engine.connect() as connection:
            entry = self.records.resolve(connection, record.registry_entry_ref)
            if not isinstance(entry, PromptRegistryEntry) or any(
                getattr(record, left) != getattr(entry, right)
                for left, right in (
                    ("prompt_key", "prompt_key"),
                    ("agent_role", "agent_role"),
                    ("task_kind", "task_kind"),
                    ("purpose", "purpose"),
                    ("template_ref", "template_ref"),
                    ("template_version", "template_version"),
                    ("output_schema_ref", "output_schema_ref"),
                )
            ):
                raise ValueError("LLM_CONFIGURATION_CLOSURE_MISMATCH")
            slots = {slot.slot: slot for slot in entry.input_slots}
            seen: dict[str, int] = {}
            for binding in record.context_bindings:
                slot = slots.get(str(binding.slot))
                if slot is None or any(
                    getattr(binding, name) != getattr(slot, name)
                    for name in ("data_kind", "field_paths", "trust_class")
                ):
                    raise ValueError("LLM_CONFIGURATION_CLOSURE_MISMATCH")
                seen[str(binding.slot)] = seen.get(str(binding.slot), 0) + 1
            for slot in entry.input_slots:
                count = seen.get(str(slot.slot), 0)
                bounds = {
                    "REQUIRED_ONE": (1, 1),
                    "OPTIONAL_ONE": (0, 1),
                    "REQUIRED_MANY": (1, None),
                    "OPTIONAL_MANY": (0, None),
                }[slot.cardinality]
                if count < bounds[0] or (bounds[1] is not None and count > bounds[1]):
                    raise ValueError("LLM_CONFIGURATION_CLOSURE_MISMATCH")
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
        with self.records.database.engine.connect() as connection:
            provider = self.records.resolve(connection, record.provider_profile_ref)
            entry = self.records.resolve(connection, record.prompt_registry_entry_ref)
            payload = self.records.resolve(connection, record.prompt_payload_ref)
            limits = self.records.resolve(connection, record.execution_limits_ref)
            if (
                not isinstance(provider, ProviderProfile)
                or provider.support_status != "SUPPORTED"
                or provider.model != record.model
                or not isinstance(entry, PromptRegistryEntry)
                or entry.status != "ACTIVE"
                or record.provider_profile_ref not in entry.provider_profile_refs
                or not isinstance(payload, PromptPayload)
                or not isinstance(limits, ExecutionLimits)
            ):
                raise ValueError("LLM_CONFIGURATION_CLOSURE_MISMATCH")
            exact_pairs = (
                (record.agent_role, entry.agent_role),
                (record.task_kind, entry.task_kind),
                (record.purpose, entry.purpose),
                (record.session_policy, entry.session_policy),
                (record.prompt_key, entry.prompt_key),
                (record.prompt_template_ref, entry.template_ref),
                (record.prompt_template_version, entry.template_version),
                (record.execution_limits_ref, entry.execution_limits_ref),
                (record.retry_policy_ref, entry.retry_policy_ref),
                (record.tool_policy_ref, entry.tool_policy_ref),
                (record.redaction_policy_ref, entry.redaction_policy_ref),
                (record.semantic_validator_ref, entry.semantic_validator_ref),
                (record.output_schema_ref, entry.output_schema_ref),
                (record.prompt_registry_entry_ref, payload.registry_entry_ref),
                (record.prompt_key, payload.prompt_key),
                (record.agent_role, payload.agent_role),
                (record.task_kind, payload.task_kind),
                (record.purpose, payload.purpose),
                (record.prompt_template_ref, payload.template_ref),
                (record.prompt_template_version, payload.template_version),
                (record.output_schema_ref, payload.output_schema_ref),
                (record.token_budget, limits.token_budget),
                (record.timeout_ms, limits.timeout_ms),
            )
            payload_context = tuple(
                binding.source_ref for binding in payload.context_bindings
            )
            if any(left != right for left, right in exact_pairs) or set(
                record.context_refs
            ) != set(payload_context):
                raise ValueError("LLM_CONFIGURATION_CLOSURE_MISMATCH")
        approved = self.records.evidence.llm_configuration_approved
        return self._publish(record, approved)

    def register_evaluation_config(self, record: EvaluationRunConfig) -> StoredDataRef:
        record = EvaluationRunConfig.model_validate(record)
        self._resolve_kinds(
            (
                record.provider_profile_ref,
                record.prompt_registry_entry_ref,
                record.output_schema_ref,
            ),
            ("provider_profile", "prompt_registry_entry", "output_schema_spec"),
        )
        approved = cast(
            Callable[[EvaluationRunConfig], bool],
            self.records.evidence.llm_configuration_approved,
        )
        return self._publish(record, approved)

    def register_sandbox_profile(self, record: SandboxProfile) -> StoredDataRef:
        record = SandboxProfile.model_validate(record)
        if record.network_mode != "DEFAULT_DENY":
            raise ValueError("SANDBOX_CONFIGURATION_DENIED")
        return self._publish(
            record, self.records.evidence.sandbox_configuration_approved
        )
