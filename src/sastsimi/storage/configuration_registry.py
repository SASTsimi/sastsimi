"""Family-specific trusted configuration registries with exact closure."""

from collections.abc import Callable
from typing import cast

from sqlalchemy import Connection, delete, insert, select, update

from sastsimi.contracts.budget import (
    DynamicReproductionLifecycleProfile,
    ProfileStatus,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.capabilities import (
    CapabilityApprovalEvidence,
    CapabilityArchitecture,
    CapabilityKind,
    CapabilityLanguage,
    CapabilityOperatingSystem,
    CapabilityOperation,
    RuntimeCapabilityProfile,
    RuntimeCapabilitySelection,
    StaticToolCapabilitySelection,
    capability_target_hash,
)
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.evaluation import (
    EvaluationRecommendation,
    EvaluationRunConfig,
    EvaluationRunResult,
)
from sastsimi.contracts.llm import (
    Capability,
    ClientExecutionProfile,
    ExecutionLimits,
    LLMCallSpec,
    LLMInvocationRequest,
    LLMRetryPolicy,
    LLMToolPolicy,
    OutputSchemaSpec,
    PromptPayload,
    PromptRedactionPolicy,
    PromptRegistryEntry,
    ProviderCapabilities,
    ProviderProfile,
    ProviderValidationEvidence,
    SemanticValidatorSpec,
)
from sastsimi.contracts.prompt_projection import project_prompt_value
from sastsimi.contracts.prompt_redaction import (
    redact_projected_json,
    render_provider_prompt,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.dto import CapabilityProbeResult, Record

from . import models
from .codec import reference
from .repositories import SQLiteRecordStore


class ConfigurationRegistry:
    def __init__(self, records: SQLiteRecordStore, artifacts: ArtifactStore) -> None:
        self.records = records
        self.artifacts = artifacts

    def register_capability_approval(
        self, record: CapabilityApprovalEvidence
    ) -> StoredDataRef:
        """Publish immutable R8 probe evidence plus the human decision."""

        record = CapabilityApprovalEvidence.model_validate(record)
        if not self.records.evidence.capability_approval_authorized(record):
            raise ValueError("CAPABILITY_APPROVAL_REQUIRED")
        evidence_refs = record.probe_evidence_refs + tuple(
            item.evidence_ref for item in record.security_control_evidence
        )
        for evidence_ref in evidence_refs:
            if evidence_ref.record_id is None:
                try:
                    with self.artifacts.open_verified(evidence_ref) as stream:
                        stream.read()
                except (LookupError, OSError, ValueError) as error:
                    raise ValueError("CAPABILITY_PROBE_EVIDENCE_MISSING") from error
            else:
                with self.records.database.engine.connect() as connection:
                    evidence_record = self.records.resolve(connection, evidence_ref)
                evidence_meta = evidence_record.meta
                if (
                    not isinstance(evidence_meta, RecordMeta)
                    or evidence_meta.analysis_id != record.meta.analysis_id
                    or evidence_meta.workspace_id != record.meta.workspace_id
                    or evidence_meta.commit_id != record.meta.commit_id
                ):
                    raise ValueError("CAPABILITY_PROBE_EVIDENCE_SCOPE_MISMATCH")
        return self._publish(
            record, self.records.evidence.capability_approval_authorized
        )

    @staticmethod
    def _language_matches(
        supported: tuple[CapabilityLanguage, ...], requested: CapabilityLanguage
    ) -> bool:
        return requested in supported or "ANY" in supported

    @staticmethod
    def _language_routes_overlap(
        left: tuple[CapabilityLanguage, ...],
        right: tuple[CapabilityLanguage, ...],
    ) -> bool:
        return "ANY" in left or "ANY" in right or bool(set(left) & set(right))

    @staticmethod
    def _current_records(
        connection: Connection, kind: str
    ) -> tuple[tuple[str, str], ...]:
        rows = connection.execute(
            select(
                models.current_records.c.logical_record_id,
                models.records.c.payload,
            )
            .select_from(
                models.current_records.join(
                    models.records,
                    models.current_records.c.record_id == models.records.c.record_id,
                )
            )
            .where(models.records.c.kind == kind)
        ).all()
        return tuple((str(row.logical_record_id), str(row.payload)) for row in rows)

    def _require_capability_evidence(
        self,
        connection: Connection,
        profile: RuntimeCapabilityProfile | StaticToolProfile,
    ) -> CapabilityApprovalEvidence:
        capability_ref = profile.capability_evidence_ref
        if capability_ref is None:
            raise ValueError("CAPABILITY_EVIDENCE_REQUIRED")
        try:
            evidence = self.records.resolve(connection, capability_ref)
        except (LookupError, ValueError) as error:
            raise ValueError("CAPABILITY_EVIDENCE_REQUIRED") from error
        if not isinstance(evidence, CapabilityApprovalEvidence):
            raise ValueError("CAPABILITY_EVIDENCE_REQUIRED")
        current = (
            connection.execute(
                select(models.current_records.c.record_id).where(
                    models.current_records.c.logical_record_id
                    == str(evidence.meta.logical_record_id)
                )
            )
            .scalars()
            .first()
        )
        if current != str(evidence.meta.record_id):
            raise ValueError("CAPABILITY_EVIDENCE_NOT_CURRENT")
        if (
            evidence.meta.analysis_id != profile.meta.analysis_id
            or evidence.meta.workspace_id != profile.meta.workspace_id
            or evidence.meta.commit_id != profile.meta.commit_id
            or not self.records.evidence.capability_approval_authorized(evidence)
        ):
            raise ValueError("CAPABILITY_APPROVAL_REQUIRED")
        if evidence.approval_target_hash != capability_target_hash(profile):
            raise ValueError("CAPABILITY_APPROVAL_TARGET_MISMATCH")
        expected_decision = "ACTIVATE" if profile.status == "ACTIVE" else "RETIRE"
        if evidence.decision != expected_decision:
            raise ValueError("CAPABILITY_APPROVAL_DECISION_MISMATCH")
        if profile.status == "ACTIVE" and evidence.probe_status != "PASSED":
            raise ValueError("CAPABILITY_ACTIVATION_PROBE_NOT_PASSED")
        return evidence

    @staticmethod
    def _runtime_identity_matches(
        profile: RuntimeCapabilityProfile, evidence: CapabilityApprovalEvidence
    ) -> bool:
        return (
            profile.profile_key,
            profile.capability_kind,
            profile.subject_key,
            profile.expected_version,
            profile.subject_sha256,
            profile.operating_system,
            profile.architecture,
            profile.languages,
            profile.operations,
        ) == (
            evidence.profile_key,
            evidence.capability_kind,
            evidence.subject_key,
            evidence.observed_version,
            evidence.observed_sha256,
            evidence.operating_system,
            evidence.architecture,
            evidence.languages,
            evidence.operations,
        )

    def _require_runtime_retirement_predecessor(
        self, connection: Connection, record: RuntimeCapabilityProfile
    ) -> None:
        if record.status != "RETIRED":
            return
        candidates = tuple(
            RuntimeCapabilityProfile.model_validate_json(payload)
            for logical_id, payload in self._current_records(
                connection, RuntimeCapabilityProfile.KIND
            )
            if logical_id == str(record.meta.logical_record_id)
        )
        if len(candidates) != 1:
            raise ValueError("CAPABILITY_RETIREMENT_PREDECESSOR_MISSING")
        current = candidates[0]
        immutable = (
            "profile_key",
            "capability_kind",
            "subject_key",
            "expected_version",
            "subject_sha256",
            "operating_system",
            "architecture",
            "languages",
            "operations",
        )
        if (
            current.status != "ACTIVE"
            or record.meta.previous_record_id != current.meta.record_id
            or any(getattr(current, key) != getattr(record, key) for key in immutable)
        ):
            raise ValueError("CAPABILITY_RETIREMENT_IDENTITY_MISMATCH")

    def register_runtime_capability(
        self, record: RuntimeCapabilityProfile
    ) -> StoredDataRef:
        """Activate or retire one exact non-static production capability."""

        record = RuntimeCapabilityProfile.model_validate(record)
        ref = reference(record)
        if not isinstance(ref, StoredDataRef):
            raise ValueError("CAPABILITY_SCOPE_MISMATCH")
        with self.records.database.write() as connection:
            self._require_runtime_retirement_predecessor(connection, record)
            evidence = self._require_capability_evidence(connection, record)
            if not self._runtime_identity_matches(record, evidence):
                raise ValueError("CAPABILITY_EVIDENCE_IDENTITY_MISMATCH")
            if record.status == "ACTIVE":
                for logical_id, payload in self._current_records(
                    connection, RuntimeCapabilityProfile.KIND
                ):
                    current = RuntimeCapabilityProfile.model_validate_json(payload)
                    if logical_id == str(record.meta.logical_record_id) or (
                        current.status != "ACTIVE"
                    ):
                        continue
                    if (
                        current.capability_kind == record.capability_kind
                        and current.operating_system == record.operating_system
                        and current.architecture == record.architecture
                        and self._language_routes_overlap(
                            current.languages, record.languages
                        )
                        and bool(set(current.operations) & set(record.operations))
                    ):
                        raise ValueError("CAPABILITY_ACTIVE_ROUTE_CONFLICT")
            staged = self.records.stage(connection, record)
            assert staged == ref
            self.records.publish(connection, ref)
            self._point(connection, record)
            self._require_capability_evidence(connection, record)
        return ref

    def get_runtime_capability(
        self, profile_ref: StoredDataRef
    ) -> RuntimeCapabilityProfile:
        """Read one exact historical revision; this does not authorize execution."""

        if profile_ref.data_kind != RuntimeCapabilityProfile.KIND:
            raise ValueError("CAPABILITY_PROFILE_REFERENCE_MISMATCH")
        with self.records.database.engine.connect() as connection:
            record = self.records.resolve(connection, profile_ref)
        if not isinstance(record, RuntimeCapabilityProfile):
            raise ValueError("CAPABILITY_PROFILE_REFERENCE_MISMATCH")
        return record

    def resolve_active_capability(
        self,
        *,
        capability_kind: CapabilityKind,
        language: CapabilityLanguage,
        operation: CapabilityOperation,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
    ) -> RuntimeCapabilitySelection:
        """Resolve one trusted current ACTIVE route and return its exact ref."""

        if not operating_system.strip() or not architecture.strip():
            raise ValueError("CAPABILITY_ROUTE_INCOMPLETE")
        matches: list[RuntimeCapabilityProfile] = []
        with self.records.database.engine.connect() as connection:
            for _, payload in self._current_records(
                connection, RuntimeCapabilityProfile.KIND
            ):
                profile = RuntimeCapabilityProfile.model_validate_json(payload)
                if (
                    profile.status == "ACTIVE"
                    and profile.capability_kind == capability_kind
                    and profile.operating_system == operating_system
                    and profile.architecture == architecture
                    and self._language_matches(profile.languages, language)
                    and operation in profile.operations
                ):
                    evidence = self._require_capability_evidence(connection, profile)
                    if not self._runtime_identity_matches(profile, evidence):
                        raise ValueError("CAPABILITY_EVIDENCE_IDENTITY_MISMATCH")
                    matches.append(profile)
        if not matches:
            raise LookupError("CAPABILITY_ROUTE_NOT_ACTIVE")
        if len(matches) != 1:
            raise ValueError("CAPABILITY_ACTIVE_ROUTE_CONFLICT")
        profile = matches[0]
        profile_ref = reference(profile)
        assert isinstance(profile_ref, StoredDataRef)
        return RuntimeCapabilitySelection(profile_ref=profile_ref, profile=profile)

    @staticmethod
    def _static_identity_matches(
        profile: StaticToolProfile, evidence: CapabilityApprovalEvidence
    ) -> bool:
        kind = {
            "PYTHON_AST": "AST",
            "CODEQL": "CODEQL",
            "OPENGREP": "OPENGREP",
        }[profile.adapter_key]
        operation = "PARSE" if profile.adapter_key == "PYTHON_AST" else "ANALYZE"
        return (
            evidence.profile_key == profile.profile_key
            and evidence.capability_kind == kind
            and evidence.subject_key == profile.executable_key
            and evidence.observed_version == profile.expected_version
            and evidence.observed_sha256 == profile.executable_sha256
            and operation in evidence.operations
        )

    def register_production_static_tool_profile(
        self, record: StaticToolProfile
    ) -> StoredDataRef:
        """Publish an exact production static profile after trusted activation."""

        record = StaticToolProfile.model_validate(record)
        if record.purpose != "PRODUCTION" or record.status not in {
            "ACTIVE",
            "RETIRED",
        }:
            raise ValueError("STATIC_TOOL_PRODUCTION_PROFILE_INVALID")
        ref = reference(record)
        if not isinstance(ref, StoredDataRef):
            raise ValueError("CAPABILITY_SCOPE_MISMATCH")
        with self.records.database.write() as connection:
            self._require_static_retirement_predecessor(connection, record)
            evidence = self._require_capability_evidence(connection, record)
            if not self._static_identity_matches(record, evidence):
                raise ValueError("CAPABILITY_EVIDENCE_IDENTITY_MISMATCH")
            if record.status == "ACTIVE":
                for logical_id, payload in self._current_records(
                    connection, StaticToolProfile.KIND
                ):
                    current = StaticToolProfile.model_validate_json(payload)
                    if logical_id == str(record.meta.logical_record_id) or (
                        current.status != "ACTIVE"
                    ):
                        continue
                    current_evidence = self._require_capability_evidence(
                        connection, current
                    )
                    if (
                        current.adapter_key == record.adapter_key
                        and current_evidence.operating_system
                        == evidence.operating_system
                        and current_evidence.architecture == evidence.architecture
                        and self._language_routes_overlap(
                            current_evidence.languages, evidence.languages
                        )
                    ):
                        raise ValueError("STATIC_TOOL_ACTIVE_ROUTE_CONFLICT")
            staged = self.records.stage(connection, record)
            assert staged == ref
            self.records.publish(connection, ref)
            self._point(connection, record)
            self._require_capability_evidence(connection, record)
        return ref

    def _require_static_retirement_predecessor(
        self, connection: Connection, record: StaticToolProfile
    ) -> None:
        if record.status != "RETIRED":
            return
        candidates = tuple(
            StaticToolProfile.model_validate_json(payload)
            for logical_id, payload in self._current_records(
                connection, StaticToolProfile.KIND
            )
            if logical_id == str(record.meta.logical_record_id)
        )
        if len(candidates) != 1:
            raise ValueError("STATIC_TOOL_RETIREMENT_PREDECESSOR_MISSING")
        current = candidates[0]
        immutable = (
            "profile_key",
            "purpose",
            "adapter_key",
            "tool_name",
            "tool_kind",
            "executable_key",
            "executable_sha256",
            "expected_version",
            "probe_timeout_ms",
            "run_timeout_ms",
            "stdout_limit_bytes",
            "stderr_limit_bytes",
            "max_attempt_output_bytes",
            "max_output_file_bytes",
            "max_artifact_read_bytes",
        )
        if (
            current.status != "ACTIVE"
            or record.meta.previous_record_id != current.meta.record_id
            or any(getattr(current, key) != getattr(record, key) for key in immutable)
        ):
            raise ValueError("STATIC_TOOL_RETIREMENT_IDENTITY_MISMATCH")

    def resolve_production_static_tool_profile(
        self, profile_ref: StoredDataRef
    ) -> StaticToolProfile:
        """Resolve one exact current production profile for execution."""

        record = self.get_production_static_tool_profile(profile_ref)
        with self.records.database.engine.connect() as connection:
            current = (
                connection.execute(
                    select(models.current_records.c.record_id).where(
                        models.current_records.c.logical_record_id
                        == str(record.meta.logical_record_id)
                    )
                )
                .scalars()
                .first()
            )
            if current != str(record.meta.record_id):
                raise ValueError("STALE_CONFIGURATION_REVISION")
            evidence = self._require_capability_evidence(connection, record)
            if not self._static_identity_matches(record, evidence):
                raise ValueError("CAPABILITY_EVIDENCE_IDENTITY_MISMATCH")
        if record.purpose != "PRODUCTION" or record.status != "ACTIVE":
            raise ValueError("STATIC_TOOL_PROFILE_NOT_EXECUTABLE")
        return record

    def get_production_static_tool_profile(
        self, profile_ref: StoredDataRef
    ) -> StaticToolProfile:
        """Read one exact historical revision; this does not authorize execution."""

        if profile_ref.data_kind != StaticToolProfile.KIND:
            raise ValueError("STATIC_TOOL_PROFILE_REFERENCE_MISMATCH")
        with self.records.database.engine.connect() as connection:
            record = self.records.resolve(connection, profile_ref)
            if not isinstance(record, StaticToolProfile):
                raise ValueError("STATIC_TOOL_PROFILE_REFERENCE_MISMATCH")
        return record

    def resolve_active_static_tool(
        self,
        *,
        adapter_key: str,
        language: CapabilityLanguage,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
    ) -> StaticToolCapabilitySelection:
        """Select one current production static profile from trusted evidence."""

        if not operating_system.strip() or not architecture.strip():
            raise ValueError("CAPABILITY_ROUTE_INCOMPLETE")
        matches: list[tuple[StaticToolProfile, CapabilityApprovalEvidence]] = []
        with self.records.database.engine.connect() as connection:
            for _, payload in self._current_records(connection, StaticToolProfile.KIND):
                profile = StaticToolProfile.model_validate_json(payload)
                if profile.status != "ACTIVE" or profile.adapter_key != adapter_key:
                    continue
                evidence = self._require_capability_evidence(connection, profile)
                if (
                    not self._static_identity_matches(profile, evidence)
                    or evidence.operating_system != operating_system
                    or evidence.architecture != architecture
                    or not self._language_matches(evidence.languages, language)
                ):
                    continue
                matches.append((profile, evidence))
        if not matches:
            raise LookupError("STATIC_TOOL_ROUTE_NOT_ACTIVE")
        if len(matches) != 1:
            raise ValueError("STATIC_TOOL_ACTIVE_ROUTE_CONFLICT")
        profile, evidence = matches[0]
        profile_ref = reference(profile)
        assert isinstance(profile_ref, StoredDataRef)
        return StaticToolCapabilitySelection(
            profile_ref=profile_ref, profile=profile, evidence=evidence
        )

    def register_static_tool_profile(self, record: StaticToolProfile) -> StoredDataRef:
        record = StaticToolProfile.model_validate(record)
        if record.status != "APPROVED" or record.purpose not in {
            "FIXTURE",
            "EVALUATION",
        }:
            raise ValueError("STATIC_TOOL_PROFILE_NOT_EXECUTABLE")
        return self._publish(
            record, self.records.evidence.static_tool_configuration_approved
        )

    def resolve_static_tool_profile(
        self, profile_ref: StoredDataRef
    ) -> StaticToolProfile:
        if profile_ref.data_kind != StaticToolProfile.KIND:
            raise ValueError("STATIC_TOOL_PROFILE_REFERENCE_MISMATCH")
        with self.records.database.engine.connect() as connection:
            record = self.records.resolve(connection, profile_ref)
            if not isinstance(record, StaticToolProfile):
                raise ValueError("STATIC_TOOL_PROFILE_REFERENCE_MISMATCH")
            current = (
                connection.execute(
                    select(models.current_records).where(
                        models.current_records.c.logical_record_id
                        == str(record.meta.logical_record_id)
                    )
                )
                .mappings()
                .first()
            )
        if current is None or current["record_id"] != str(record.meta.record_id):
            raise ValueError("STALE_CONFIGURATION_REVISION")
        if record.status != "APPROVED" or record.purpose not in {
            "FIXTURE",
            "EVALUATION",
        }:
            raise ValueError("STATIC_TOOL_PROFILE_NOT_EXECUTABLE")
        if not self.records.evidence.static_tool_configuration_approved(record):
            raise ValueError("CONFIGURATION_APPROVAL_REQUIRED")
        return record

    def _publish[T: Record](
        self,
        record: T,
        approved: Callable[[T], bool],
        bind: Callable[[Connection, T], None] | None = None,
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
            if bind is not None:
                bind(connection, record)
            # Prompt configuration has no persisted human-approval reference in
            # the frozen contract. Re-check the injected authority immediately
            # before commit so an observed revocation rolls back every write.
            if not approved(record):
                raise ValueError("CONFIGURATION_APPROVAL_REQUIRED")
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

    @staticmethod
    def require_current_selection(
        connection: Connection,
        entry: PromptRegistryEntry,
        provider: ProviderProfile,
    ) -> None:
        """Fail closed unless both exact LLM selections remain current."""
        active_entry = (
            connection.execute(
                select(models.prompt_active_entries).where(
                    models.prompt_active_entries.c.agent_role == entry.agent_role,
                    models.prompt_active_entries.c.task_kind == entry.task_kind,
                    models.prompt_active_entries.c.purpose == entry.purpose,
                )
            )
            .mappings()
            .first()
        )
        current_provider_record_id = connection.execute(
            select(models.current_records.c.record_id).where(
                models.current_records.c.logical_record_id
                == str(provider.meta.logical_record_id)
            )
        ).scalar_one_or_none()
        current_entry_record_id = connection.execute(
            select(models.current_records.c.record_id).where(
                models.current_records.c.logical_record_id
                == str(entry.meta.logical_record_id)
            )
        ).scalar_one_or_none()
        if (
            entry.status != "ACTIVE"
            or provider.support_status != "SUPPORTED"
            or active_entry is None
            or active_entry["logical_record_id"] != str(entry.meta.logical_record_id)
            or active_entry["record_id"] != str(entry.meta.record_id)
            or current_entry_record_id != str(entry.meta.record_id)
            or current_provider_record_id != str(provider.meta.record_id)
        ):
            raise ValueError("LLM_CONTEXT_CONFIGURATION_NOT_CURRENT")

    def require_current(self, request: LLMInvocationRequest) -> None:
        """Recheck the exact prompt/profile selection immediately before I/O."""
        with self.records.database.engine.connect() as connection:
            spec = self.records.resolve(connection, request.call_spec_ref)
            if (
                not isinstance(spec, LLMCallSpec)
                or request.prompt_registry_entry_ref != spec.prompt_registry_entry_ref
                or request.provider_profile_ref != spec.provider_profile_ref
            ):
                raise ValueError("LLM_CONTEXT_CONFIGURATION_NOT_CURRENT")
            entry = self.records.resolve(connection, spec.prompt_registry_entry_ref)
            provider = self.records.resolve(connection, spec.provider_profile_ref)
            if not isinstance(entry, PromptRegistryEntry) or not isinstance(
                provider, ProviderProfile
            ):
                raise ValueError("LLM_CONTEXT_CONFIGURATION_NOT_CURRENT")
            self.require_current_selection(connection, entry, provider)

    def _publish_invocation_record[T: Record](
        self,
        record: T,
        bind: Callable[[Connection, T], None],
    ) -> StoredDataRef:
        """Publish an immutable attempt-owned record without a current pointer."""
        if (
            getattr(record.meta, "attempt_id", None) is None
            or record.meta.revision_number != 1
            or record.meta.previous_record_id is not None
        ):
            raise ValueError("LLM_INVOCATION_CONFIGURATION_SCOPE_MISMATCH")
        ref = reference(record)
        if not isinstance(ref, StoredDataRef):
            raise ValueError("LLM_INVOCATION_CONFIGURATION_SCOPE_MISMATCH")
        with self.records.database.write() as connection:
            staged = self.records.stage(connection, record)
            if staged != ref:
                raise ValueError("LLM_INVOCATION_CONFIGURATION_SCOPE_MISMATCH")
            self.records.publish(connection, ref)
            bind(connection, record)
        return ref

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
        allowed_na = {"PVD-13"} if record.auth_mode == "API_KEY" else set()
        if all(test.result == "NOT_APPLICABLE" for test in record.tests) or any(
            test.result == "NOT_APPLICABLE" and test.test_id not in allowed_na
            for test in record.tests
        ):
            raise ValueError("PROVIDER_VALIDATION_INCOMPLETE")
        approved = self.records.evidence.llm_configuration_approved
        return self._publish(record, approved, self._bind_provider_validation)

    def _bind_provider_validation(
        self, connection: Connection, record: ProviderValidationEvidence
    ) -> None:
        for test in record.tests:
            for evidence_ref in test.evidence_refs:
                self._require_exact_evidence(connection, record, evidence_ref)

    def _require_exact_evidence(
        self,
        connection: Connection,
        owner: Record,
        evidence_ref: StoredDataRef,
    ) -> Record | None:
        if evidence_ref.workspace_id != getattr(
            owner.meta, "workspace_id", None
        ) or evidence_ref.commit_id != getattr(owner.meta, "commit_id", None):
            raise ValueError("PROVIDER_CONFIGURATION_CLOSURE_MISMATCH")
        if evidence_ref.record_id is None:
            try:
                with self.artifacts.open_verified(evidence_ref) as evidence:
                    evidence.read()
            except (LookupError, OSError, ValueError) as error:
                raise ValueError("PROVIDER_CONFIGURATION_CLOSURE_MISMATCH") from error
            return None
        try:
            evidence_record = self.records.resolve(connection, evidence_ref)
        except (LookupError, ValueError) as error:
            raise ValueError("PROVIDER_CONFIGURATION_CLOSURE_MISMATCH") from error
        if any(
            getattr(evidence_record.meta, name, None) != getattr(owner.meta, name, None)
            for name in ("analysis_id", "workspace_id", "commit_id")
        ):
            raise ValueError("PROVIDER_CONFIGURATION_CLOSURE_MISMATCH")
        return evidence_record

    def derive_provider_capabilities(
        self, record: ProviderValidationEvidence
    ) -> ProviderCapabilities:
        """Derive the conservative capability set from exact PVD outcomes."""
        validation = ProviderValidationEvidence.model_validate(record)
        tests: dict[str, str] = {
            str(test.test_id): str(test.result) for test in validation.tests
        }

        def supported(test_id: str) -> Capability:
            return "SUPPORTED" if tests.get(test_id) == "PASS" else "UNVERIFIED"

        return ProviderCapabilities(
            non_interactive=supported("PVD-01"),
            structured_output=supported("PVD-03"),
            new_session=supported("PVD-04"),
            # PASS proves correct explicit behavior for unsupported RESUME,
            # cancellation and absent request IDs; it does not imply support.
            resume_session="UNSUPPORTED",
            parallel_calls=supported("PVD-06"),
            cancellation="UNSUPPORTED",
            timeout_detection=supported("PVD-07"),
            auth_expiry_detection=supported("PVD-08"),
            rate_limit_detection=supported("PVD-08"),
            request_id="UNSUPPORTED",
            token_usage=supported("PVD-12"),
            session_metadata=supported("PVD-12"),
            runtime_tool_loop=supported("PVD-16"),
        )

    def register_provider_profile(
        self, record: ProviderProfile, probe: CapabilityProbeResult
    ) -> StoredDataRef:
        record = ProviderProfile.model_validate(record)
        derived_capabilities = self.derive_provider_capabilities(probe.evidence)
        if (
            probe.evidence != ProviderValidationEvidence.model_validate(probe.evidence)
            or record.capabilities != derived_capabilities
            or record.validation_evidence_ref != reference(probe.evidence)
        ):
            raise ValueError("PROVIDER_CONFIGURATION_CLOSURE_MISMATCH")
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
            capability_tests = {
                "non_interactive": "PVD-04",
                "structured_output": "PVD-03",
                "new_session": "PVD-04",
                "resume_session": "PVD-05",
                "parallel_calls": "PVD-06",
                "cancellation": "PVD-07",
                "timeout_detection": "PVD-07",
                "auth_expiry_detection": "PVD-08",
                "rate_limit_detection": "PVD-08",
                "request_id": "PVD-12",
                "token_usage": "PVD-12",
                "session_metadata": "PVD-12",
                "runtime_tool_loop": "PVD-16",
            }
            if any(
                getattr(record.capabilities, capability) == "SUPPORTED"
                and (test_id not in tests or tests[test_id].result != "PASS")
                for capability, test_id in capability_tests.items()
            ):
                raise ValueError("PROVIDER_CONFIGURATION_CLOSURE_MISMATCH")
            if record.client_execution_profile_ref is not None:
                try:
                    client = self.records.resolve(
                        connection, record.client_execution_profile_ref
                    )
                except (LookupError, ValueError) as error:
                    raise ValueError(
                        "PROVIDER_CONFIGURATION_CLOSURE_MISMATCH"
                    ) from error
                if not isinstance(client, ClientExecutionProfile):
                    raise ValueError("PROVIDER_CONFIGURATION_CLOSURE_MISMATCH")
                client_validation = self._require_exact_evidence(
                    connection, client, client.verification_evidence_ref
                )
                if (
                    not isinstance(client_validation, ProviderValidationEvidence)
                    or client.verification_evidence_ref
                    != record.validation_evidence_ref
                    or not any(
                        test.test_id == "PVD-13" and test.result == "PASS"
                        for test in client_validation.tests
                    )
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
        record = ClientExecutionProfile.model_validate(record)
        approved = self.records.evidence.llm_configuration_approved
        return self._publish(record, approved, self._bind_client_execution)

    def _bind_client_execution(
        self, connection: Connection, record: ClientExecutionProfile
    ) -> None:
        self._require_exact_evidence(connection, record, record.network_policy_ref)
        validation = self._require_exact_evidence(
            connection, record, record.verification_evidence_ref
        )
        if not isinstance(validation, ProviderValidationEvidence) or not any(
            test.test_id == "PVD-13" and test.result == "PASS"
            for test in validation.tests
        ):
            raise ValueError("PROVIDER_CONFIGURATION_CLOSURE_MISMATCH")

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
        return self._publish(record, approved, self._bind_active_prompt)

    def _bind_active_prompt(
        self, connection: Connection, record: PromptRegistryEntry
    ) -> None:
        """Atomically select the one ACTIVE entry for a role/task/purpose."""
        self._require_prompt_selection_identity(connection, record)
        if record.status == "DRAFT":
            return
        if record.purpose == "PRODUCTION" and record.status == "ACTIVE":
            # Re-check R8 evidence and its exact evaluation target while this
            # publication holds the SQLite write lock. The earlier read is only
            # a fast rejection and must not be the authority boundary.
            self._validate_production_activation(connection, record)
        table = models.prompt_active_entries
        key = (
            table.c.agent_role == record.agent_role,
            table.c.task_kind == record.task_kind,
            table.c.purpose == record.purpose,
        )
        current = connection.execute(select(table).where(*key)).mappings().first()
        logical_id = str(record.meta.logical_record_id)
        record_id = str(record.meta.record_id)
        logical_active = (
            connection.execute(
                select(table).where(table.c.logical_record_id == logical_id)
            )
            .mappings()
            .first()
        )
        if logical_active is not None and any(
            logical_active[name] != value
            for name, value in (
                ("agent_role", record.agent_role),
                ("task_kind", record.task_kind),
                ("purpose", record.purpose),
            )
        ):
            raise ValueError("PROMPT_REGISTRY_SELECTION_MISMATCH")
        if record.status == "RETIRED":
            previous_record_id = record.meta.previous_record_id
            if previous_record_id is None:
                raise ValueError("PROMPT_REGISTRY_RETIREMENT_MISMATCH")
            previous_ref_raw = connection.execute(
                select(models.records.c.ref).where(
                    models.records.c.record_id == str(previous_record_id)
                )
            ).scalar_one_or_none()
            if previous_ref_raw is None:
                raise ValueError("PROMPT_REGISTRY_RETIREMENT_MISMATCH")
            from .codec import REF_ADAPTER

            previous = self.records.resolve(
                connection, REF_ADAPTER.validate_json(previous_ref_raw)
            )
            if (
                not isinstance(previous, PromptRegistryEntry)
                or previous.status != "ACTIVE"
                or previous.meta.logical_record_id != record.meta.logical_record_id
                or self._prompt_semantics(previous) != self._prompt_semantics(record)
            ):
                raise ValueError("PROMPT_REGISTRY_RETIREMENT_MISMATCH")
            if current is None:
                return
            if current["logical_record_id"] != logical_id or current[
                "record_id"
            ] != str(previous_record_id):
                raise ValueError("PROMPT_REGISTRY_RETIREMENT_MISMATCH")
            removed = connection.execute(
                delete(table).where(
                    *key,
                    table.c.logical_record_id == logical_id,
                    table.c.record_id == current["record_id"],
                    table.c.state_version == current["state_version"],
                )
            )
            if removed.rowcount != 1:
                raise ValueError("PROMPT_REGISTRY_RETIREMENT_MISMATCH")
            return
        if current is None:
            connection.execute(
                insert(table).values(
                    agent_role=record.agent_role,
                    task_kind=record.task_kind,
                    purpose=record.purpose,
                    logical_record_id=logical_id,
                    record_id=record_id,
                    state_version=1,
                )
            )
            return
        if current["record_id"] == record_id:
            if current["logical_record_id"] != logical_id:
                raise ValueError("PROMPT_REGISTRY_ACTIVE_CONFLICT")
            return
        if current["logical_record_id"] != logical_id:
            raise ValueError("PROMPT_REGISTRY_ACTIVE_CONFLICT")
        changed = connection.execute(
            update(table)
            .where(
                *key,
                table.c.logical_record_id == logical_id,
                table.c.record_id == current["record_id"],
                table.c.state_version == current["state_version"],
            )
            .values(
                record_id=record_id,
                state_version=current["state_version"] + 1,
            )
        )
        if changed.rowcount != 1:
            raise ValueError("PROMPT_REGISTRY_ACTIVE_CONFLICT")

    def _require_prompt_selection_identity(
        self, connection: Connection, record: PromptRegistryEntry
    ) -> None:
        previous_record_id = record.meta.previous_record_id
        if previous_record_id is None:
            return
        previous_ref_raw = connection.execute(
            select(models.records.c.ref).where(
                models.records.c.record_id == str(previous_record_id)
            )
        ).scalar_one_or_none()
        if previous_ref_raw is None:
            raise ValueError("PROMPT_REGISTRY_SELECTION_MISMATCH")
        from .codec import REF_ADAPTER

        previous = self.records.resolve(
            connection, REF_ADAPTER.validate_json(previous_ref_raw)
        )
        if not isinstance(previous, PromptRegistryEntry) or any(
            getattr(previous, name) != getattr(record, name)
            for name in ("agent_role", "task_kind", "purpose")
        ):
            raise ValueError("PROMPT_REGISTRY_SELECTION_MISMATCH")

    @staticmethod
    def _require_active_prompt_binding(
        connection: Connection, record: PromptRegistryEntry
    ) -> None:
        table = models.prompt_active_entries
        active = (
            connection.execute(
                select(table).where(
                    table.c.agent_role == record.agent_role,
                    table.c.task_kind == record.task_kind,
                    table.c.purpose == record.purpose,
                )
            )
            .mappings()
            .first()
        )
        if (
            record.status != "ACTIVE"
            or active is None
            or active["logical_record_id"] != str(record.meta.logical_record_id)
            or active["record_id"] != str(record.meta.record_id)
        ):
            raise ValueError("PROMPT_REGISTRY_NOT_CURRENT")

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
        provider = self.records.resolve(
            connection, recommendation.target_provider_profile_ref
        )
        if (
            not isinstance(config, EvaluationRunConfig)
            or not isinstance(provider, ProviderProfile)
            or config.provider_profile_ref != recommendation.target_provider_profile_ref
            or config.model != recommendation.target_model
            or config.session_policy != recommendation.target_session_policy
            or config.prompt_registry_entry_ref
            != recommendation.target_prompt_registry_entry_ref
            or config.output_schema_ref != record.output_schema_ref
            or recommendation.target_provider_profile_ref
            not in record.provider_profile_refs
            or recommendation.target_model != provider.model
            or recommendation.target_session_policy != record.session_policy
            or config.provider_profile_ref not in record.provider_profile_refs
            or config.model != provider.model
            or config.session_policy != record.session_policy
        ):
            raise ValueError("QUALITY_EVIDENCE_MISMATCH")
        self._require_active_prompt_binding(connection, target)

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
            self._require_active_prompt_binding(connection, entry)
            slots = {slot.slot: slot for slot in entry.input_slots}
            seen: dict[str, int] = {}
            projections: list[tuple[str, bytes]] = []
            source_refs: set[bytes] = set()
            for binding in record.context_bindings:
                slot = slots.get(str(binding.slot))
                if slot is None or any(
                    getattr(binding, name) != getattr(slot, name)
                    for name in ("data_kind", "field_paths", "trust_class")
                ):
                    raise ValueError("LLM_CONFIGURATION_CLOSURE_MISMATCH")
                seen[str(binding.slot)] = seen.get(str(binding.slot), 0) + 1
                source_ref = binding.source_ref
                source_key = canonical_bytes(source_ref)
                if source_key in source_refs:
                    raise ValueError("PROMPT_CONTEXT_DUPLICATE")
                source_refs.add(source_key)
                if source_ref.record_id is None:
                    with self.artifacts.open_verified(source_ref) as source:
                        source_value: object = source.read().decode("utf-8")
                else:
                    source_value = self.records.resolve(connection, source_ref)
                expected_projection = redact_projected_json(
                    project_prompt_value(source_value, binding.field_paths)
                ).data
                with self.artifacts.open_verified(
                    binding.projected_data_ref
                ) as projected:
                    if projected.read() != expected_projection:
                        raise ValueError("PROMPT_PROJECTION_MISMATCH")
                projections.append((binding.slot, expected_projection))
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
            with self.artifacts.open_verified(record.template_ref) as template:
                expected_render = render_provider_prompt(
                    template.read(), tuple(projections)
                )
            with self.artifacts.open_verified(record.rendered_prompt_ref) as rendered:
                if rendered.read() != expected_render:
                    raise ValueError("PROMPT_RENDER_MISMATCH")
        return self._publish_invocation_record(record, self._bind_prompt_payload)

    def _bind_prompt_payload(
        self, connection: Connection, record: PromptPayload
    ) -> None:
        entry = self.records.resolve(connection, record.registry_entry_ref)
        if not isinstance(entry, PromptRegistryEntry):
            raise ValueError("LLM_CONFIGURATION_CLOSURE_MISMATCH")
        self._require_active_prompt_binding(connection, entry)

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
            self._require_active_prompt_binding(connection, entry)
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
            if (
                any(left != right for left, right in exact_pairs)
                or (record.context_refs != payload_context)
                or any(
                    getattr(record.meta, name, None)
                    != getattr(payload.meta, name, None)
                    for name in (
                        "analysis_id",
                        "workspace_id",
                        "commit_id",
                        "hypothesis_id",
                        "attempt_id",
                    )
                )
            ):
                raise ValueError("LLM_CONFIGURATION_CLOSURE_MISMATCH")
        return self._publish_invocation_record(record, self._bind_call_spec)

    def _bind_call_spec(self, connection: Connection, record: LLMCallSpec) -> None:
        entry = self.records.resolve(connection, record.prompt_registry_entry_ref)
        if not isinstance(entry, PromptRegistryEntry):
            raise ValueError("LLM_CONFIGURATION_CLOSURE_MISMATCH")
        self._require_active_prompt_binding(connection, entry)

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
