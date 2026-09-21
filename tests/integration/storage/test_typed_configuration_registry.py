"""Typed configuration publication is host-approved and exact-reference closed."""

from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from sqlalchemy import create_engine, insert, update

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import (
    REQUIRED_CHECKS,
    ActionCheck,
    ActionDecision,
    ActionRequest,
    ActionType,
    CheckResult,
)
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    PromptRegistryEntry,
    ProviderProfile,
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import CapabilityProbeResult, StaticToolRequest
from sastsimi.storage import models
from sastsimi.storage.codec import reference
from sastsimi.storage.configuration_registry import (
    ConfigurationRegistry as StorageConfigurationRegistry,
)
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta, ref
from tests.integration.runtime_support import Harness
from tests.integration.trusted_fixture import FixtureEvidence


def make_static_profile(**changes: object) -> StaticToolProfile:
    payload: dict[str, object] = {
        "meta": meta("static_tool_profile", attempt=None),
        "profile_key": "ast-fixture",
        "purpose": "FIXTURE",
        "status": "APPROVED",
        "adapter_key": "PYTHON_AST",
        "tool_name": "AST",
        "tool_kind": "STRUCTURE",
        "executable_key": "fixture-python",
        "executable_sha256": "a" * 64,
        "expected_version": "3.12",
        "capability_evidence_ref": None,
        "probe_timeout_ms": 1_000,
        "run_timeout_ms": 30_000,
        "stdout_limit_bytes": 1_024,
        "stderr_limit_bytes": 1_024,
        "max_attempt_output_bytes": 4_096,
        "max_output_file_bytes": 2_048,
        "max_artifact_read_bytes": 2_048,
    }
    return StaticToolProfile.model_validate_json(canonical_bytes(payload | changes))


def test_static_tool_profile_registry_is_exact_and_fail_closed(tmp_path: Path) -> None:
    class StaticEvidence(FixtureEvidence):
        def __init__(self) -> None:
            super().__init__()
            self.static_tool_approvals: set[str] = set()

        def static_tool_configuration_approved(
            self, profile: StaticToolProfile
        ) -> bool:
            return content_hash(profile) in self.static_tool_approvals

    h = Harness(tmp_path)
    evidence = StaticEvidence()
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=evidence)
    profile = make_static_profile()
    with pytest.raises(ValueError, match="CONFIGURATION_APPROVAL_REQUIRED"):
        runtime.configuration.register_static_tool_profile(profile)
    evidence.static_tool_approvals.add(content_hash(profile))
    profile_ref = runtime.configuration.register_static_tool_profile(profile)
    assert runtime.configuration.resolve_static_tool_profile(profile_ref) == profile

    wrong_hash = profile_ref.model_copy(update={"content_hash": "b" * 64})
    with pytest.raises(ValueError, match="RECORD_REVISION_MISMATCH"):
        runtime.configuration.resolve_static_tool_profile(wrong_hash)

    draft = make_static_profile(status="DRAFT")
    evidence.static_tool_approvals.add(content_hash(draft))
    with pytest.raises(ValueError, match="STATIC_TOOL_PROFILE_NOT_EXECUTABLE"):
        runtime.configuration.register_static_tool_profile(draft)


def test_static_action_binding_requires_same_exact_profile_everywhere() -> None:
    from sastsimi.ports.static_tool import validate_static_tool_profile_binding

    profile = make_static_profile()
    profile_ref = reference(profile)
    assert isinstance(profile_ref, StoredDataRef)
    workspace = CodeWorkspace.model_validate_json(
        canonical_bytes(make("CodeWorkspace") | {"status": "READY", "commit_id": "c1"})
    )
    work_data = make("WorkExecutionState", "work_execution_state")
    work = WorkExecutionState.model_validate_json(
        canonical_bytes(
            work_data
            | {
                "meta": work_data["meta"] | {"attempt_id": None, "hypothesis_id": None},
                "work_type": "STATIC_TOOL",
                "subject_type": "ANALYSIS",
                "subject_id": "a1",
                "input_refs": (profile_ref,),
                "input_hash": content_hash((profile_ref,)),
                "dedupe_key": content_hash(("static-tool", profile_ref)),
            }
        )
    )
    action_data = make("ActionRequest", "action_request")
    action = ActionRequest.model_validate_json(
        canonical_bytes(
            action_data
            | {
                "meta": action_data["meta"]
                | {"attempt_id": None, "hypothesis_id": None},
                "requested_by": "STATIC_ANALYSIS",
                "action_type": "RUN_TOOL",
                "work_ref": reference(work),
                "expected_state_version": work.state_version,
                "input_refs": (profile_ref,),
                "tool_name": "AST",
                "file_paths": ("src/app.py",),
            }
        )
    )
    checks = tuple(REQUIRED_CHECKS[ActionType.RUN_TOOL])
    decided_at = action.requested_at
    decision_data = make("ActionDecision", "action_decision")
    decision = ActionDecision.model_validate_json(
        canonical_bytes(
            decision_data
            | {
                "meta": decision_data["meta"]
                | {"attempt_id": None, "hypothesis_id": None},
                "action_ref": reference(action),
                "required_checks": checks,
                "check_results": tuple(
                    ActionCheck(
                        check_type=kind,
                        result=CheckResult.PASS,
                        reason_code="TEST_PASS",
                        safe_message="Trusted test evidence passed.",
                    )
                    for kind in checks
                ),
                "checked_state_version": work.state_version,
                "checked_config_refs": (profile_ref,),
                "valid_until": decided_at + timedelta(minutes=1),
                "decided_at": decided_at,
            }
        )
    )
    request = StaticToolRequest(
        action=action,
        workspace=workspace,
        tool_profile_ref=profile_ref,
        analysis_config_ref=profile_ref,
        rule_catalog_ref=None,
    )
    validate_static_tool_profile_binding(request, work, decision, profile)
    wrong_ref = profile_ref.model_copy(update={"content_hash": "b" * 64})
    with pytest.raises(ValueError, match="STATIC_TOOL_PROFILE_BINDING_MISMATCH"):
        validate_static_tool_profile_binding(
            StaticToolRequest(
                action=action,
                workspace=workspace,
                tool_profile_ref=wrong_ref,
                analysis_config_ref=profile_ref,
                rule_catalog_ref=None,
            ),
            work,
            decision,
            profile,
        )
    for changed_work, changed_action, changed_decision in (
        (work.model_copy(update={"input_refs": ()}), action, decision),
        (work, action.model_copy(update={"input_refs": ()}), decision),
        (work, action, decision.model_copy(update={"checked_config_refs": ()})),
    ):
        with pytest.raises(ValueError, match="STATIC_TOOL_PROFILE_BINDING_MISMATCH"):
            validate_static_tool_profile_binding(
                StaticToolRequest(
                    action=changed_action,
                    workspace=workspace,
                    tool_profile_ref=profile_ref,
                    analysis_config_ref=profile_ref,
                    rule_catalog_ref=None,
                ),
                changed_work,
                changed_decision,
                profile,
            )


def test_static_tool_request_rejects_removed_four_position_alias() -> None:
    constructor = cast(Any, StaticToolRequest)
    with pytest.raises(TypeError):
        constructor(object(), object(), object(), object())


def test_typed_registries_require_family_evidence_and_exact_closure(
    tmp_path: Path,
) -> None:
    h = Harness(tmp_path)
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    configs = getattr(runtime, "configuration", None)
    assert configs is not None, "Typed configuration registries are missing"

    book = VerificationPlaybook.model_validate_json(
        canonical_bytes(
            make("VerificationPlaybook")
            | {"meta": make("VerificationPlaybook")["meta"] | {"attempt_id": None}}
        )
    )
    policy = PlaybookPolicy.model_validate_json(
        canonical_bytes(
            make("PlaybookPolicy")
            | {
                "meta": make("PlaybookPolicy")["meta"] | {"attempt_id": None},
                "common_playbook_ref": reference(book),
            }
        )
    )
    with pytest.raises(ValueError, match="CONFIGURATION_APPROVAL_REQUIRED"):
        configs.register_playbook(book)
    h.evidence.playbook_approvals.add(content_hash(book))
    assert configs.register_playbook(book) == reference(book)
    h.evidence.playbook_approvals.add(content_hash(policy))
    assert configs.register_playbook_policy(policy) == reference(policy)

    validation = ProviderValidationEvidence.model_validate_json(
        canonical_bytes(make("ProviderValidationEvidence"))
    )
    h.evidence.llm_configuration_approvals.add(content_hash(validation))
    with pytest.raises(ValueError, match="PROVIDER_VALIDATION_INCOMPLETE"):
        configs.register_provider_validation(validation)
    validation = ProviderValidationEvidence.model_validate(
        validation.model_dump()
        | {
            "tests": tuple(
                dict(
                    test_id=f"PVD-{index:02d}",
                    result="PASS",
                    evidence_refs=(reference(book),),
                    safe_summary="Deterministic fake probe passed",
                )
                for index in range(1, 17)
            )
        }
    )
    missing_evidence_ref = reference(book).model_copy(
        update={"record_id": RecordId("missing-pvd-evidence")}
    )
    incomplete_closure = validation.model_copy(
        update={
            "tests": (
                validation.tests[0].model_copy(
                    update={"evidence_refs": (missing_evidence_ref,)}
                ),
                *validation.tests[1:],
            )
        }
    )
    h.evidence.llm_configuration_approvals.add(content_hash(incomplete_closure))
    with pytest.raises(ValueError, match="PROVIDER_CONFIGURATION_CLOSURE_MISMATCH"):
        configs.register_provider_validation(incomplete_closure)
    profile = ProviderProfile.model_validate_json(
        canonical_bytes(
            make("ProviderProfile")
            | {
                "validation_evidence_ref": reference(validation),
                "capabilities": configs.derive_provider_capabilities(validation),
            }
        )
    )
    h.evidence.llm_configuration_approvals.update(
        {content_hash(validation), content_hash(profile)}
    )
    probe = CapabilityProbeResult(validation)
    with pytest.raises(LookupError, match="Exact record is not published"):
        configs.register_provider_profile(profile, probe)
    assert configs.register_provider_validation(validation) == reference(validation)
    assert configs.register_provider_profile(profile, probe) == reference(profile)

    wrong_client = ClientExecutionProfile.model_validate_json(
        canonical_bytes(
            make("ClientExecutionProfile")
            | {
                "network_policy_ref": reference(book),
                "verification_evidence_ref": reference(validation),
            }
        )
    )
    h.evidence.llm_configuration_approvals.add(content_hash(wrong_client))
    assert configs.register_client_execution(wrong_client) == reference(wrong_client)
    subscription_validation = ProviderValidationEvidence.model_validate(
        validation.model_dump()
        | {
            "meta": validation.meta.model_copy(
                update={
                    "record_id": RecordId("subscription-validation"),
                    "logical_record_id": LogicalRecordId("subscription-validation"),
                }
            ),
            "product": "CODEX",
            "transport": "CODEX_CLIENT",
            "auth_mode": "SUBSCRIPTION_LOGIN",
        }
    )
    h.evidence.llm_configuration_approvals.add(content_hash(subscription_validation))
    assert configs.register_provider_validation(subscription_validation) == reference(
        subscription_validation
    )
    subscription_client = ClientExecutionProfile.model_validate(
        wrong_client.model_dump()
        | {
            "meta": wrong_client.meta.model_copy(
                update={
                    "record_id": RecordId("subscription-client"),
                    "logical_record_id": LogicalRecordId("subscription-client"),
                }
            ),
            "verification_evidence_ref": reference(subscription_validation),
        }
    )
    h.evidence.llm_configuration_approvals.add(content_hash(subscription_client))
    assert configs.register_client_execution(subscription_client) == reference(
        subscription_client
    )
    subscription_profile = ProviderProfile.model_validate(
        profile.model_dump()
        | {
            "meta": profile.meta.model_copy(
                update={
                    "record_id": RecordId("subscription-profile"),
                    "logical_record_id": LogicalRecordId("subscription-profile"),
                }
            ),
            "product": "CODEX",
            "transport": "CODEX_CLIENT",
            "auth_mode": "SUBSCRIPTION_LOGIN",
            "credential_source": "OFFICIAL_CLIENT_SESSION",
            "validation_evidence_ref": reference(subscription_validation),
            "client_execution_profile_ref": reference(wrong_client),
        }
    )
    subscription_probe = CapabilityProbeResult(subscription_validation)
    h.evidence.llm_configuration_approvals.add(content_hash(subscription_profile))
    with pytest.raises(ValueError, match="PROVIDER_CONFIGURATION_CLOSURE_MISMATCH"):
        configs.register_provider_profile(subscription_profile, subscription_probe)
    subscription_profile = ProviderProfile.model_validate(
        subscription_profile.model_dump()
        | {"client_execution_profile_ref": reference(subscription_client)}
    )
    h.evidence.llm_configuration_approvals.add(content_hash(subscription_profile))
    assert configs.register_provider_profile(
        subscription_profile, subscription_probe
    ) == reference(subscription_profile)

    all_na = validation.model_copy(
        update={
            "tests": tuple(
                test.model_copy(update={"result": "NOT_APPLICABLE"})
                for test in validation.tests
            )
        }
    )
    h.evidence.llm_configuration_approvals.add(content_hash(all_na))
    with pytest.raises(ValueError, match="PROVIDER_VALIDATION_INCOMPLETE"):
        configs.register_provider_validation(all_na)

    false_capability = profile.model_copy(
        update={
            "capabilities": profile.capabilities.model_copy(
                update={"cancellation": "SUPPORTED"}
            )
        }
    )
    h.evidence.llm_configuration_approvals.add(content_hash(false_capability))
    with pytest.raises(ValueError, match="PROVIDER_CONFIGURATION_CLOSURE_MISMATCH"):
        configs.register_provider_profile(false_capability, probe)

    sandbox = SandboxProfile.model_validate_json(
        canonical_bytes(make("SandboxProfile"))
    )
    h.evidence.sandbox_approvals.add(content_hash(sandbox))
    assert configs.register_sandbox_profile(sandbox) == reference(sandbox)


def test_llm_selection_requires_the_exact_current_active_prompt_revision() -> None:
    entry = PromptRegistryEntry.model_validate_json(
        canonical_bytes(
            make("PromptRegistryEntry")
            | {
                "provider_profile_refs": [ref("provider_profile")],
                "status": "ACTIVE",
            }
        )
    )
    provider = ProviderProfile.model_validate_json(
        canonical_bytes(
            make("ProviderProfile")
            | {"validation_evidence_ref": ref("provider_validation_evidence")}
        )
    )
    engine = create_engine("sqlite://")
    models.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            insert(models.prompt_active_entries).values(
                analysis_id=str(entry.meta.analysis_id),
                workspace_id=str(entry.meta.workspace_id),
                commit_id=str(entry.meta.commit_id),
                agent_role=entry.agent_role,
                task_kind=entry.task_kind,
                purpose=entry.purpose,
                logical_record_id=str(entry.meta.logical_record_id),
                record_id=str(entry.meta.record_id),
                state_version=1,
            )
        )
        connection.execute(
            insert(models.current_records),
            (
                {
                    "logical_record_id": str(entry.meta.logical_record_id),
                    "record_id": str(entry.meta.record_id),
                    "state_version": 1,
                },
                {
                    "logical_record_id": str(provider.meta.logical_record_id),
                    "record_id": str(provider.meta.record_id),
                    "state_version": 1,
                },
            ),
        )
        StorageConfigurationRegistry.require_current_selection(
            connection, entry, provider
        )
        connection.execute(
            update(models.current_records)
            .where(
                models.current_records.c.logical_record_id
                == str(entry.meta.logical_record_id)
            )
            .values(record_id="newer-draft-record", state_version=2)
        )
        with pytest.raises(ValueError, match="LLM_CONTEXT_CONFIGURATION_NOT_CURRENT"):
            StorageConfigurationRegistry.require_current_selection(
                connection, entry, provider
            )
