"""Run-scoped safe defaults required by the local evaluation graph."""

from __future__ import annotations

from dataclasses import dataclass

from sastsimi.config.local_evaluation_profile import LocalEvaluationProfile
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.verification import (
    PlaybookPolicy,
    PlaybookQuestionTemplate,
    VerificationPlaybook,
)
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator


@dataclass(frozen=True, slots=True)
class LocalEvaluationRunConfiguration:
    playbook: VerificationPlaybook
    playbook_ref: StoredDataRef
    playbook_policy: PlaybookPolicy
    playbook_policy_ref: StoredDataRef
    sandbox_profile: SandboxProfile
    sandbox_profile_ref: StoredDataRef
    workspace_policy_ref: RunStoredDataRef

    @property
    def approval_records(
        self,
    ) -> tuple[VerificationPlaybook | PlaybookPolicy | SandboxProfile, ...]:
        return self.playbook, self.playbook_policy, self.sandbox_profile


def _meta(
    scope: PlannedRunScope,
    kind: str,
    *,
    ids: IdGenerator,
    clock: Clock,
) -> RecordMeta:
    record_id = ids.new(RecordId)
    return RecordMeta(
        record_id=record_id,
        logical_record_id=LogicalRecordId(str(record_id)),
        record_type=kind,
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=clock.now(),
        analysis_id=scope.analysis_id,
        workspace_id=scope.workspace_id,
        commit_id=scope.commit_id,
        hypothesis_id=None,
        attempt_id=None,
    )


def _stored_ref(value: object) -> StoredDataRef:
    value_ref = reference(value)  # type: ignore[arg-type]
    if not isinstance(value_ref, StoredDataRef):
        raise ValueError("LOCAL_EVALUATION_CONFIGURATION_SCOPE_INVALID")
    return value_ref


def build_local_evaluation_run_configuration(
    *,
    profile: LocalEvaluationProfile,
    scope: PlannedRunScope,
    artifacts: ArtifactStore,
    ids: IdGenerator,
    clock: Clock,
) -> LocalEvaluationRunConfiguration:
    """Create explicit local-only records; none of them claims Production approval."""

    playbook = VerificationPlaybook(
        meta=_meta(scope, VerificationPlaybook.KIND, ids=ids, clock=clock),
        scope="COMMON",
        vulnerability_type=None,
        prerequisites=("Use only exact records from the current analysis generation.",),
        source_checks=("Identify the externally influenced value and exact location.",),
        sink_checks=("Identify the security-sensitive operation and exact location.",),
        path_checks=("Confirm the source-to-sink path and relevant call edges.",),
        defense_checks=(
            "Check sanitizers, validators, authentication, and authorization.",
        ),
        falsification_question_templates=(
            PlaybookQuestionTemplate(
                template_key="common-falsification",
                question=(
                    "What exact code fact or successful reproduction would disprove "
                    "this vulnerability hypothesis?"
                ),
            ),
        ),
        static_evidence_requirements=(
            "Exact code locations and current static fact references are required.",
        ),
        dynamic_evidence_requirements=(
            "A final TRUE requires a successful current-attempt reproduction "
            "and validated PoC.",
        ),
        restriction_checks=(
            "Preserve testing restrictions and do not use prohibited methods.",
        ),
        hold_conditions=(
            "Use HOLD when material evidence is missing or inconclusive.",
        ),
    )
    playbook_ref = _stored_ref(playbook)
    policy = PlaybookPolicy(
        meta=_meta(scope, PlaybookPolicy.KIND, ids=ids, clock=clock),
        common_playbook_ref=playbook_ref,
        type_playbooks=(),
        approved_by="LOCAL_EVALUATION_OPERATOR",
        approved_at=clock.now(),
    )
    policy_ref = _stored_ref(policy)

    isolation_ref = artifacts.commit(
        artifacts.stage_bytes(
            canonical_bytes(
                {
                    "schema_version": 1,
                    "purpose": "LOCAL_EVALUATION",
                    "network": "DEFAULT_DENY",
                    "host_mount": "DENY",
                    "docker_socket": "DENY",
                    "secret_access": "DENY",
                    "other_workspace_access": "DENY",
                    "external_disclosure": "DENY",
                }
            ),
            "application/json",
        )
    )
    sandbox = SandboxProfile(
        meta=_meta(scope, SandboxProfile.KIND, ids=ids, clock=clock),
        network_mode="DEFAULT_DENY",
        allowed_egress_refs=(),
        isolation_policy_refs=(isolation_ref,),
        cpu_limit_millicores=1_000,
        memory_limit_bytes=1_073_741_824,
        disk_limit_bytes=2_147_483_648,
        pid_limit=256,
        max_requested_execution_ms=profile.timeouts.sandbox_ms,
        created_at=clock.now(),
    )
    sandbox_ref = _stored_ref(sandbox)

    limits = profile.workspace_limits
    workspace_policy_ref = artifacts.commit_run(
        artifacts.stage_bytes(
            canonical_bytes(
                {
                    "kind": "workspace_storage_policy",
                    "schema_version": "1.0",
                    "max_git_bytes": limits.max_git_bytes,
                    "max_checkout_bytes": limits.max_checkout_bytes,
                    "max_file_count": limits.max_file_count,
                    "min_free_bytes": limits.min_free_bytes,
                }
            ),
            "application/json",
        ),
        scope.analysis_id,
    )
    return LocalEvaluationRunConfiguration(
        playbook=playbook,
        playbook_ref=playbook_ref,
        playbook_policy=policy,
        playbook_policy_ref=policy_ref,
        sandbox_profile=sandbox,
        sandbox_profile_ref=sandbox_ref,
        workspace_policy_ref=workspace_policy_ref,
    )


__all__ = [
    "LocalEvaluationRunConfiguration",
    "build_local_evaluation_run_configuration",
]
