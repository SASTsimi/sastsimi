"""Typed configuration publication is host-approved and exact-reference closed."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from sastsimi.bootstrap import build_fake_pipeline, build_runtime
from sastsimi.contracts.actions import ActionDecision
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.evaluation import EvaluationRecommendation
from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.llm import (
    LLMCallSpec,
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    PromptPayload,
    PromptRegistryEntry,
    ProviderProfile,
    ProviderValidationEvidence,
)
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.ports.dto import CapabilityProbeResult
from sastsimi.storage.codec import reference
from tests.contract.domain.canonical_fixtures import make
from tests.integration.runtime_support import Harness


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


def test_llm_call_spec_rejects_every_cross_record_mismatch(tmp_path: Path) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    pipeline.analyze(scenario="FALSE")
    assert pipeline.runtime is not None
    calls = tuple(
        item
        for item in pipeline.runtime.queries.current_records(
            "fake-analysis", "llm_call_spec"
        )
        if isinstance(item, LLMCallSpec)
    )
    assert len(calls) >= 2
    target, foreign = calls[:2]
    mismatches = (
        {"model": "unsupported-model"},
        {"provider_profile_ref": foreign.provider_profile_ref},
        {"purpose": "EVALUATION"},
        {"prompt_payload_ref": foreign.prompt_payload_ref},
        {"output_schema_ref": foreign.output_schema_ref},
        {"execution_limits_ref": foreign.execution_limits_ref},
        {"context_refs": ()},
    )
    for changes in mismatches:
        with pytest.raises(ValueError, match="LLM_CONFIGURATION_CLOSURE_MISMATCH"):
            pipeline.runtime.configuration.register_call_spec(
                target.model_copy(update=changes)
            )

    active_entries = tuple(
        item
        for item in pipeline.runtime.queries.current_records(
            "fake-analysis", "prompt_registry_entry"
        )
        if isinstance(item, PromptRegistryEntry)
        and item.purpose == "PRODUCTION"
        and item.status == "ACTIVE"
    )
    first_entry, second_entry = active_entries[:2]
    assert second_entry.quality_evaluation_ref is not None
    with pytest.raises(ValueError, match="QUALITY_EVIDENCE_MISMATCH"):
        pipeline.runtime.configuration.register_prompt_entry(
            first_entry.model_copy(
                update={"quality_evaluation_ref": second_entry.quality_evaluation_ref}
            )
        )

    published = pipeline.runtime.queries.published_records("fake-analysis")
    requests = tuple(
        item for item in published if isinstance(item, LLMInvocationRequest)
    )
    results = tuple(item for item in published if isinstance(item, LLMInvocationResult))
    logs = tuple(item for item in published if isinstance(item, LLMInvocationLog))
    request = requests[0]
    result = next(item for item in results if item.llm_call_id == request.llm_call_id)
    log = next(item for item in logs if item.llm_call_id == request.llm_call_id)
    payload = pipeline.runtime.unit_of_work.records.get_exact(
        request.prompt_payload_ref
    )
    assert isinstance(payload, PromptPayload)
    binding = payload.context_bindings[0]
    source = pipeline.runtime.unit_of_work.records.get_exact(binding.source_ref)
    with pipeline.runtime.unit_of_work.artifacts.open_verified(
        binding.projected_data_ref
    ) as projected:
        assert projected.read() == canonical_bytes(source)
    with pipeline.runtime.unit_of_work.artifacts.open_verified(
        payload.rendered_prompt_ref
    ) as rendered:
        rendered_bytes = rendered.read()
    assert canonical_bytes(source) in rendered_bytes
    forged_projection = pipeline.runtime.unit_of_work.artifacts.commit(
        pipeline.runtime.unit_of_work.artifacts.stage_bytes(
            b'{"forged":true}', "application/json"
        )
    )
    wrong_payload = payload.model_copy(
        update={
            "context_bindings": (
                binding.model_copy(update={"projected_data_ref": forged_projection}),
                *payload.context_bindings[1:],
            )
        }
    )
    with pytest.raises(ValueError, match="PROMPT_PROJECTION_MISMATCH"):
        pipeline.runtime.configuration.register_prompt_payload(wrong_payload)
    with pytest.raises(ValueError, match="PROMPT_RENDER_MISMATCH"):
        pipeline.runtime.configuration.register_prompt_payload(
            payload.model_copy(update={"rendered_prompt_ref": forged_projection})
        )
    foreign_request = requests[1]
    assert result.parsed_output_ref is not None
    with pytest.raises(ValueError, match="INVOCATION_ACTION_MISMATCH"):
        pipeline.runtime.validator.record_invocation(
            request.model_copy(update={"call_spec_ref": foreign_request.call_spec_ref}),
            result,
            log,
        )
    # Exact action/spec/request equality cannot authorize another work's context.
    from typing import cast

    from sastsimi.contracts.actions import ActionDecision, ActionRequest
    from sastsimi.contracts.work import WorkExecutionState
    from sastsimi.storage.llm_context import check_llm_context
    from sastsimi.storage.repositories import SQLiteRecordStore

    records = cast(SQLiteRecordStore, pipeline.runtime.unit_of_work.records)
    decision = records.get_exact(request.action_decision_ref)
    policy_request = next(
        item for item in requests if item.agent_role == "POLICY_PARSER"
    )
    other_decision = records.get_exact(policy_request.action_decision_ref)
    assert isinstance(decision, ActionDecision) and isinstance(
        other_decision, ActionDecision
    )
    action = records.get_exact(decision.action_ref)
    other_action = records.get_exact(other_decision.action_ref)
    assert isinstance(action, ActionRequest) and isinstance(other_action, ActionRequest)
    assert other_action.work_ref is not None
    other_work = records.get_exact(other_action.work_ref)
    assert isinstance(other_work, WorkExecutionState)
    with records.database.engine.connect() as connection:
        with pytest.raises(ValueError, match="LLM_CONTEXT_WORK_MISMATCH"):
            check_llm_context(
                records,
                connection,
                action.model_copy(
                    update={
                        "work_ref": reference(other_work),
                        "expected_state_version": other_work.state_version,
                    }
                ),
                other_work,
            )
        # Isolate source ownership even when role, fixed-input order and spec agree.
        from sastsimi.contracts.ids import HypothesisId, WorkId

        pro_request = next(item for item in requests if item.agent_role == "PRO")
        pro_decision = records.get_exact(pro_request.action_decision_ref)
        assert isinstance(pro_decision, ActionDecision)
        pro_action = records.get_exact(pro_decision.action_ref)
        assert isinstance(pro_action, ActionRequest) and pro_action.work_ref is not None
        pro_work = records.get_exact(pro_action.work_ref)
        assert isinstance(pro_work, WorkExecutionState)
        foreign_work = pro_work.model_copy(
            update={
                "work_id": WorkId("foreign-pro-work"),
                "meta": pro_work.meta.model_copy(
                    update={"hypothesis_id": HypothesisId("foreign-hypothesis")}
                ),
            }
        )
        with pytest.raises(ValueError, match="LLM_CONTEXT_WORK_MISMATCH"):
            check_llm_context(
                records,
                connection,
                pro_action.model_copy(
                    update={
                        "work_ref": reference(foreign_work),
                    }
                ),
                foreign_work,
            )

    # A persisted invocation can be replayed after a crash without new IDs/outcomes.
    assert pipeline.runtime.validator.record_invocation(
        request, result, log
    ) == reference(log)

    # Production activation and replay re-check the exact ACTIVE evaluation
    # target inside the same write transaction as publication.
    assert first_entry.quality_evaluation_ref is not None
    recommendation = records.get_exact(first_entry.quality_evaluation_ref)
    assert isinstance(recommendation, EvaluationRecommendation)
    evaluation_entry = records.get_exact(
        recommendation.target_prompt_registry_entry_ref
    )
    assert isinstance(evaluation_entry, PromptRegistryEntry)
    from sqlalchemy import delete

    from sastsimi.storage import models

    with records.database.write() as connection:
        connection.execute(
            delete(models.prompt_active_entries).where(
                models.prompt_active_entries.c.agent_role
                == evaluation_entry.agent_role,
                models.prompt_active_entries.c.task_kind == evaluation_entry.task_kind,
                models.prompt_active_entries.c.purpose == evaluation_entry.purpose,
            )
        )
    with pytest.raises(ValueError, match="PROMPT_REGISTRY_NOT_CURRENT"):
        pipeline.runtime.configuration.register_prompt_entry(first_entry)

    # Storage publication must not accept an ACTIVE-looking but stale prompt
    # revision when callers bypass the higher-level PromptRegistry facade.
    target_entry = records.get_exact(target.prompt_registry_entry_ref)
    assert isinstance(target_entry, PromptRegistryEntry)
    replacement_entry = next(
        item
        for item in active_entries
        if item.meta.record_id != target_entry.meta.record_id
    )
    from sqlalchemy import update

    with records.database.write() as connection:
        connection.execute(
            update(models.prompt_active_entries)
            .where(
                models.prompt_active_entries.c.agent_role == target_entry.agent_role,
                models.prompt_active_entries.c.task_kind == target_entry.task_kind,
                models.prompt_active_entries.c.purpose == target_entry.purpose,
            )
            .values(
                logical_record_id=str(replacement_entry.meta.logical_record_id),
                record_id=str(replacement_entry.meta.record_id),
            )
        )
    with pytest.raises(ValueError, match="PROMPT_REGISTRY_NOT_CURRENT"):
        pipeline.runtime.configuration.register_prompt_payload(payload)
    with pytest.raises(ValueError, match="PROMPT_REGISTRY_NOT_CURRENT"):
        pipeline.runtime.configuration.register_call_spec(target)


def test_prompt_active_entry_is_selected_atomically_and_replay_is_idempotent(
    tmp_path: Path,
) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    pipeline.analyze(scenario="FALSE")
    assert pipeline.runtime is not None
    runtime = pipeline.runtime
    source = next(
        item
        for item in runtime.queries.current_records(
            "fake-analysis", "prompt_registry_entry"
        )
        if isinstance(item, PromptRegistryEntry) and item.purpose == "EVALUATION"
    )

    def candidate(name: str, *, status: str = "ACTIVE") -> PromptRegistryEntry:
        return PromptRegistryEntry.model_validate(
            source.model_dump()
            | {
                "meta": source.meta.model_dump()
                | {
                    "record_id": RecordId(f"atomic-{name}"),
                    "logical_record_id": LogicalRecordId(f"atomic-{name}"),
                    "revision_number": 1,
                    "previous_record_id": None,
                },
                "task_kind": "ATOMIC_ACTIVE_TEST",
                "status": status,
                "quality_evaluation_ref": None,
            }
        )

    first = candidate("first")
    second = candidate("second")
    draft = candidate("draft", status="DRAFT")
    approvals = runtime.unit_of_work.records.evidence.llm_approvals  # type: ignore[attr-defined]
    approvals.update(content_hash(item) for item in (first, second, draft))

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(
            executor.submit(runtime.configuration.register_prompt_entry, item)
            for item in (first, second)
        )
        outcomes: list[object] = []
        for future in futures:
            try:
                outcomes.append(future.result())
            except ValueError as error:
                outcomes.append(str(error))

    refs = [item for item in outcomes if not isinstance(item, str)]
    errors = [item for item in outcomes if isinstance(item, str)]
    assert len(refs) == 1
    assert errors == ["PROMPT_REGISTRY_ACTIVE_CONFLICT"]
    winner = first if reference(first) == refs[0] else second
    replacement = second if winner is first else first
    assert runtime.configuration.register_prompt_entry(winner) == refs[0]
    assert runtime.configuration.register_prompt_entry(draft) == reference(draft)
    next_revision = winner.model_copy(
        update={
            "meta": winner.meta.model_copy(
                update={
                    "record_id": RecordId("atomic-winner-v2"),
                    "revision_number": 2,
                    "previous_record_id": winner.meta.record_id,
                }
            )
        }
    )
    approvals.add(content_hash(next_revision))
    assert runtime.configuration.register_prompt_entry(next_revision) == reference(
        next_revision
    )
    retired = next_revision.model_copy(
        update={
            "meta": next_revision.meta.model_copy(
                update={
                    "record_id": RecordId("atomic-winner-retired"),
                    "revision_number": 3,
                    "previous_record_id": next_revision.meta.record_id,
                }
            ),
            "status": "RETIRED",
        }
    )
    approvals.add(content_hash(retired))
    assert runtime.configuration.register_prompt_entry(retired) == reference(retired)
    assert runtime.configuration.register_prompt_entry(replacement) == reference(
        replacement
    )

    from sqlalchemy import select

    from sastsimi.storage import models

    with runtime.unit_of_work.records.database.engine.connect() as connection:
        rows = connection.execute(
            select(models.prompt_active_entries).where(
                models.prompt_active_entries.c.task_kind == "ATOMIC_ACTIVE_TEST"
            )
        ).mappings()
        assert [row["record_id"] for row in rows] == [str(replacement.meta.record_id)]


def test_failed_invocation_persists_only_safe_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenario = build_fake_pipeline(tmp_path)._scenario
    invoke = scenario.provider_invoke
    captured: list[object] = []

    def stop_after_capture(*items: object) -> object:
        captured.extend(items)
        raise RuntimeError("capture unpersisted invocation")

    async def capture_invocation(
        request: LLMInvocationRequest, expected: LLMInvocationResult
    ) -> LLMInvocationResult:
        assert scenario.runtime is not None
        monkeypatch.setattr(
            scenario.runtime.validator, "record_invocation", stop_after_capture
        )
        return await invoke(request, expected)

    scenario.provider_invoke = capture_invocation
    with pytest.raises(RuntimeError, match="capture unpersisted invocation"):
        scenario.analyze(scenario="FALSE")
    monkeypatch.undo()
    assert scenario.runtime is not None
    runtime = scenario.runtime
    request, succeeded, succeeded_log = captured
    assert isinstance(request, LLMInvocationRequest)
    assert isinstance(succeeded, LLMInvocationResult)
    assert isinstance(succeeded_log, LLMInvocationLog)
    candidate_ref = succeeded.parsed_output_ref
    assert candidate_ref is not None
    safe_error = "AUTH_REQUIRED: provider credentials are unavailable"
    failed = succeeded.model_copy(
        update={
            "status": "AUTH_REQUIRED",
            "response_ref": None,
            "parsed_output_ref": None,
            "usage": None,
            "safe_error": safe_error,
        }
    )
    failed_log = succeeded_log.model_copy(
        update={
            "status": "AUTH_REQUIRED",
            "session_ref": failed.session_ref,
            "exposed_response_ref": None,
            "parsed_output_ref": None,
            "usage": None,
            "safe_error": safe_error,
        }
    )

    with pytest.raises(ValueError, match="INVOCATION_RESULT_MISMATCH"):
        runtime.validator.record_invocation(
            request,
            failed.model_copy(update={"response_ref": succeeded.response_ref}),
            failed_log,
        )

    log_ref = runtime.validator.record_invocation(request, failed, failed_log)
    assert log_ref == reference(failed_log)
    for item in (request, failed, failed_log):
        assert runtime.unit_of_work.records.get_exact(reference(item)) == item
    with pytest.raises(LookupError):
        runtime.unit_of_work.records.get_exact(candidate_ref)

    published = runtime.queries.published_records("fake-analysis")
    decisions = tuple(
        item
        for item in published
        if isinstance(item, ActionDecision)
        and item.decision_id
        == runtime.unit_of_work.records.get_exact(
            request.action_decision_ref
        ).decision_id
    )
    latest = max(decisions, key=lambda item: item.meta.revision_number)
    expected_outcomes = tuple(reference(item) for item in (request, failed, failed_log))
    assert latest.outcome_refs == expected_outcomes
    assert candidate_ref not in latest.outcome_refs
