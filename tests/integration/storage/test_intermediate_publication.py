"""Intermediate publication must retain one active work/attempt and ownership."""

import json
from pathlib import Path
from typing import Any

import pytest

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    DynamicReproductionLifecycleProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.policy import PolicyParserResult
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef
from sastsimi.runtime.workflow_runner import WorkflowRunner
from tests.contract.domain.canonical_fixtures import make
from tests.integration.runtime_support import Harness


def prepared_policy_parser(
    tmp_path: Path,
    *,
    context: bool = False,
    parallel: int = 1,
    prepare: bool = False,
) -> tuple[Any, ...]:
    h = Harness(tmp_path)
    execution = h.execution(max_work=20)
    execution = type(execution).model_validate(
        execution.model_dump() | dict(max_parallel_work=parallel)
    )
    assert execution.approval_ref is not None
    identity = execution.approval_ref
    h.evidence.identities[identity] = RequesterRole.ORCHESTRATION
    service_identity = h.records.stage_record(execution) if context else None
    if service_identity is not None:
        assert isinstance(service_identity, (RunStoredDataRef, StoredDataRef))
        h.evidence.identities[service_identity] = (
            RequesterRole.CONTEXT_RETRIEVAL_SERVICE
        )
    runtime = build_runtime(
        tmp_path,
        None,
        None,
        h.clock,
        h.ids,
        evidence=h.evidence,
        context_service_identity_ref=service_identity,
    )
    execution_ref = h.pin_execution(runtime.budget_registry, execution)
    binding, workspace_ref = h.binding(execution_ref.model_dump(mode="json"))
    profile = h.records.get_exact(binding.work_budget_profile_ref)
    assert isinstance(profile, WorkBudgetProfile)
    data = profile.model_dump(mode="json")
    data["meta"].update(record_id="policy-limits", logical_record_id="policy-limits")
    data["limits"] = [
        dict(
            limit_key="policy",
            work_type="POLICY_FETCH",
            operation_kind="POLICY_COLLECT",
            agent_role="POLICY_COLLECTOR",
            timeout_ms=1000,
            max_attempts=2,
            max_calls_per_work=10,
            max_items_per_work=20,
        )
    ]
    if context:
        data["limits"].append(
            dict(
                limit_key="context",
                work_type="CONTEXT_RETRIEVAL",
                operation_kind="CONTEXT_RETRIEVAL",
                agent_role=None,
                timeout_ms=1000,
                max_attempts=2,
                max_calls_per_work=10,
                max_items_per_work=20,
            )
        )
    data["limits"].append(
        dict(
            limit_key="verification",
            work_type="VERIFICATION",
            operation_kind="VERIFICATION_SYNTHESIS",
            agent_role="VERIFICATION",
            timeout_ms=1000,
            max_attempts=2,
            max_calls_per_work=20,
            max_items_per_work=20,
        )
    )
    for work_type, operation_kind, role in (
        ("STATIC_NORMALIZE", "STATIC_NORMALIZE", "STATIC_ANALYSIS"),
        ("HYPOTHESIS_PROPOSAL", "HYPOTHESIS_GENERATE", "HYPOTHESIS"),
        ("PRO_EVIDENCE", "PRO_EVIDENCE", "PRO"),
        ("CON_EVIDENCE", "CON_EVIDENCE", "CON"),
        ("DYNAMIC_REPRO", "DYNAMIC_REPRO", "DYNAMIC_REPRODUCTION"),
    ):
        data["limits"].append(
            dict(
                limit_key=work_type,
                work_type=work_type,
                operation_kind=operation_kind,
                agent_role=role,
                timeout_ms=1000,
                max_attempts=2,
                max_calls_per_work=20,
                max_items_per_work=20,
            )
        )
    policy_profile = WorkBudgetProfile.model_validate_json(json.dumps(data))
    policy_profile_ref = h.publish(policy_profile)
    lifecycle = h.records.get_exact(binding.dynamic_lifecycle_profile_ref)
    assert isinstance(lifecycle, DynamicReproductionLifecycleProfile)
    lifecycle_data = lifecycle.model_dump(mode="json")
    lifecycle_data["meta"].update(
        record_id="policy-dynamic-budget", logical_record_id="policy-dynamic-budget"
    )
    lifecycle_data["preflight_budget_ref"] = policy_profile_ref
    lifecycle = DynamicReproductionLifecycleProfile.model_validate_json(
        canonical_bytes(lifecycle_data)
    )
    binding = BudgetProfileBinding.model_validate_json(
        canonical_bytes(
            binding.model_dump()
            | dict(
                work_budget_profile_ref=policy_profile_ref,
                dynamic_lifecycle_profile_ref=h.publish(lifecycle),
            )
        )
    )
    scope = h.pin_binding(
        runtime.budget_registry,
        binding,
        RunStoredDataRef.model_validate_json(json.dumps(workspace_ref)),
    )
    runner = WorkflowRunner(runtime, h.clock, h.ids)
    if prepare:
        pending = runner.begin_policy(
            scope,
            binding.meta,
            identity,
            program_id="program",
            source_config_ref=identity,
            parser_name="fake",
            parser_version="1",
        ).work
        ready = runner.enqueue_registered(pending, scope, identity)
        work = runner.activate(ready, scope, identity)
    else:
        work = runner.start(
            scope,
            binding.meta,
            "POLICY_FETCH",
            "ANALYSIS",
            "a1",
            identity,
        )
    h.evidence.identities[identity] = RequesterRole.POLICY_PARSER
    metadata = runner.metadata(binding.meta, "policy_parser_result")
    metadata["attempt_id"] = work.active_attempt_id
    data = make("PolicyParserResult") | dict(meta=metadata)
    # Raw fake output stays an artifact reference; the parser result is the record.
    for field in ("source_ref", "parsed_output_ref", "llm_invocation_ref"):
        data[field]["workspace_id"] = "w1"
    result = PolicyParserResult.model_validate_json(canonical_bytes(data))
    result_ref = h.records.stage_record(result)
    action = runner.action(
        work,
        identity,
        "POLICY_PARSER",
        "SAVE_RESULT",
        result_kind="policy_parser_result",
        candidate_result_ref=result_ref,
    )
    decision = runner.authorize(work, action)
    return h, runtime, runner, work, result, decision


def test_intermediate_result_is_published_without_ending_attempt(
    tmp_path: Path,
) -> None:
    h, runtime, _, work, result, decision = prepared_policy_parser(tmp_path)
    refs = runtime.intermediate.publish(str(work.work_id), decision, (result,))
    assert h.records.get_exact(refs[0]) == result
    current = runtime.work.get(str(work.work_id))
    assert current == work
    assert current.status == "RUNNING"
    assert current.output_refs == ()
    with pytest.raises(ValueError, match="ACTION_ALREADY_USED"):
        runtime.intermediate.publish(str(work.work_id), decision, (result,))


def test_intermediate_result_rejects_other_attempt(tmp_path: Path) -> None:
    h, runtime, runner, work, result, _ = prepared_policy_parser(tmp_path)
    data = result.model_dump(mode="json")
    data["meta"].update(
        record_id="wrong-attempt", logical_record_id="wrong-attempt", attempt_id="other"
    )
    wrong = PolicyParserResult.model_validate_json(json.dumps(data))
    identity = next(
        ref
        for ref, role in h.evidence.identities.items()
        if role == RequesterRole.POLICY_PARSER
    )
    action = runner.action(
        work,
        identity,
        "POLICY_PARSER",
        "SAVE_RESULT",
        result_kind="policy_parser_result",
        candidate_result_ref=h.records.stage_record(wrong),
    )
    decision = runner.authorize(work, action)
    with pytest.raises(ValueError, match="ATTEMPT_NOT_ACTIVE"):
        runtime.intermediate.publish(str(work.work_id), decision, (wrong,))


def test_intermediate_rechecks_owner_at_publication(tmp_path: Path) -> None:
    h, runtime, _, work, result, decision = prepared_policy_parser(tmp_path)
    identity = next(
        ref
        for ref, role in h.evidence.identities.items()
        if role == RequesterRole.POLICY_PARSER
    )
    h.evidence.identities[identity] = RequesterRole.ORCHESTRATION
    with pytest.raises(ValueError, match="AUTHORITY_DENIED"):
        runtime.intermediate.publish(str(work.work_id), decision, (result,))
    with pytest.raises(LookupError):
        h.records.get_exact(h.records.stage_record(result))


def test_intermediate_rejects_wrong_work_and_result_kind(tmp_path: Path) -> None:
    from sastsimi.contracts.static import CodeWorkspace

    h, runtime, runner, work, result, _ = prepared_policy_parser(tmp_path)
    identity = next(
        ref
        for ref, role in h.evidence.identities.items()
        if role == RequesterRole.POLICY_PARSER
    )
    h.evidence.identities[identity] = RequesterRole.REPOSITORY_LOADER
    metadata = runner.metadata(result.meta, "code_workspace")
    for field in ("workspace_id", "commit_id", "hypothesis_id", "attempt_id"):
        metadata.pop(field)
    wrong = CodeWorkspace.model_validate_json(
        canonical_bytes(
            dict(
                meta=metadata,
                workspace_id="w1",
                analysis_id="a1",
                repository_url="https://example.invalid/fake",
                commit_id="c1",
                status="READY",
            )
        )
    )
    action = runner.action(
        work,
        identity,
        "REPOSITORY_LOADER",
        "SAVE_RESULT",
        result_kind="code_workspace",
        candidate_result_ref=h.records.stage_record(wrong),
    )
    decision = runner.authorize(work, action)
    with pytest.raises(ValueError, match="INTERMEDIATE_PUBLICATION_DENIED"):
        runtime.intermediate.publish(str(work.work_id), decision, (wrong,))


@pytest.mark.parametrize(
    "checkpoint", ["artifacts_promoted", "before_commit", "committed"]
)
def test_intermediate_crash_has_atomic_record_and_decision_visibility(
    tmp_path: Path,
    checkpoint: str,
) -> None:
    from typing import cast

    from sastsimi.storage.intermediate_publication import IntermediatePublicationService

    h, runtime, _, work, result, decision = prepared_policy_parser(tmp_path)

    class Crash(BaseException):
        pass

    def fail(stage: str) -> None:
        if stage == checkpoint:
            raise Crash

    service = cast(IntermediatePublicationService, runtime.intermediate.store)
    service.checkpoint = fail
    with pytest.raises(Crash):
        runtime.intermediate.publish(str(work.work_id), decision, (result,))
    service.checkpoint = lambda stage: None
    ref = h.records.stage_record(result)
    assert runtime.work.get(str(work.work_id)) == work
    if checkpoint == "committed":
        assert h.records.get_exact(ref) == result
        with pytest.raises(ValueError, match="ACTION_ALREADY_USED"):
            runtime.intermediate.publish(str(work.work_id), decision, (result,))
    else:
        with pytest.raises(LookupError):
            h.records.get_exact(ref)
        assert runtime.intermediate.publish(str(work.work_id), decision, (result,)) == (
            ref,
        )


def test_intermediate_stale_revision_cannot_replace_current(tmp_path: Path) -> None:
    h, runtime, runner, work, result, decision = prepared_policy_parser(tmp_path)
    runtime.intermediate.publish(str(work.work_id), decision, (result,))
    identity = next(
        ref
        for ref, role in h.evidence.identities.items()
        if role == RequesterRole.POLICY_PARSER
    )
    children = []
    for name in ("first-revision", "stale-sibling"):
        data = result.model_dump(mode="json")
        data["meta"].update(
            record_id=name,
            revision_number=2,
            previous_record_id=str(result.meta.record_id),
        )
        child = PolicyParserResult.model_validate_json(json.dumps(data))
        ref = h.records.stage_record(child)
        action = runner.action(
            work,
            identity,
            "POLICY_PARSER",
            "SAVE_RESULT",
            result_kind="policy_parser_result",
            candidate_result_ref=ref,
        )
        children.append((child, runner.authorize(work, action)))
    first, first_decision = children[0]
    stale, stale_decision = children[1]
    runtime.intermediate.publish(str(work.work_id), first_decision, (first,))
    with pytest.raises(ValueError, match="STALE_RESULT"):
        runtime.intermediate.publish(str(work.work_id), stale_decision, (stale,))
    with pytest.raises(LookupError):
        h.records.get_exact(h.records.stage_record(stale))


def test_terminal_output_includes_same_attempt_parser_without_reassigning_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy import select

    from sastsimi.contracts.policy import PolicyCollectionResult
    from sastsimi.storage import models

    h, runtime, runner, work, parser, decision = prepared_policy_parser(tmp_path)
    (parser_ref,) = runtime.intermediate.publish(str(work.work_id), decision, (parser,))
    identity = next(
        ref
        for ref, role in h.evidence.identities.items()
        if role == RequesterRole.POLICY_PARSER
    )
    h.evidence.identities[identity] = RequesterRole.POLICY_COLLECTOR
    data = json.loads(
        json.dumps(make("PolicyCollectionResult")).replace('"ws1"', '"w1"')
    )
    data.update(
        meta=runner.metadata(
            work.meta, "policy_collection_result", attempt_id=work.active_attempt_id
        ),
        parser_result_refs=[parser_ref.model_dump(mode="json")],
    )
    collection = PolicyCollectionResult.model_validate_json(canonical_bytes(data))
    refs = (h.records.stage_record(collection), parser_ref)
    monkeypatch.setattr(h.evidence, "authorized_outputs", lambda action: refs)
    completed = runner.complete(
        work, identity, "POLICY_COLLECTOR", (collection, parser)
    )
    assert completed.output_refs == refs
    assert completed.status == "SUCCEEDED"
    with h.database.engine.connect() as connection:
        assert connection.execute(
            select(models.current_records.c.record_id).where(
                models.current_records.c.logical_record_id
                == str(parser.meta.logical_record_id),
            )
        ).scalar_one() == str(parser.meta.record_id)
        assert (
            connection.execute(
                select(models.current_records.c.state_version).where(
                    models.current_records.c.logical_record_id
                    == str(parser.meta.logical_record_id),
                )
            ).scalar_one()
            == 1
        )
    assert h.records.get_exact(parser_ref) == parser


@pytest.mark.parametrize(
    "invalid", ["work", "attempt", "stale", "missing-outcome", "other-decision"]
)
def test_terminal_intermediate_requires_exact_current_owner_receipt(
    tmp_path: Path,
    invalid: str,
) -> None:
    from sqlalchemy import select, update

    from sastsimi.contracts.actions import ActionDecision
    from sastsimi.contracts.work import WorkExecutionState
    from sastsimi.storage import models
    from sastsimi.storage.codec import reference
    from sastsimi.storage.intermediate_policy import prepublished_output

    h, runtime, runner, work, parser, decision = prepared_policy_parser(tmp_path)
    (ref,) = runtime.intermediate.publish(str(work.work_id), decision, (parser,))
    identity = next(
        ref
        for ref, role in h.evidence.identities.items()
        if role == RequesterRole.POLICY_PARSER
    )
    if invalid in {"work", "attempt"}:
        data = work.model_dump(mode="json")
        data["work_id" if invalid == "work" else "active_attempt_id"] = "different"
        work = WorkExecutionState.model_validate_json(json.dumps(data))
    elif invalid == "stale":
        data = parser.model_dump(mode="json")
        data["meta"].update(
            record_id="next-parser",
            revision_number=2,
            previous_record_id=str(parser.meta.record_id),
        )
        newer = PolicyParserResult.model_validate_json(json.dumps(data))
        action = runner.action(
            work,
            identity,
            "POLICY_PARSER",
            "SAVE_RESULT",
            result_kind="policy_parser_result",
            candidate_result_ref=h.records.stage_record(newer),
        )
        runtime.intermediate.publish(
            str(work.work_id), runner.authorize(work, action), (newer,)
        )
    else:
        with h.database.write() as connection:
            payload = connection.execute(
                select(models.action_decisions.c.payload).where(
                    models.action_decisions.c.payload.contains(str(ref.record_id)),
                )
            ).scalar_one()
            used = ActionDecision.model_validate_json(payload)
            data = used.model_dump(mode="json")
            if invalid == "missing-outcome":
                data["outcome_refs"] = []
            else:
                data["decision_id"] = "different-decision"
            altered = ActionDecision.model_validate_json(json.dumps(data))
            connection.execute(
                update(models.action_decisions)
                .where(
                    models.action_decisions.c.decision_id == str(used.decision_id),
                )
                .values(payload=altered.model_dump_json())
            )
    with h.database.engine.connect() as connection:
        with pytest.raises(
            ValueError, match="INTERMEDIATE_RECEIPT_REQUIRED|STALE_RESULT"
        ):
            prepublished_output(h.records, connection, reference(parser), work)


def test_intermediate_rejects_nonactive_attempt_row(tmp_path: Path) -> None:
    from sqlalchemy import update

    from sastsimi.storage import models

    h, runtime, _, work, parser, decision = prepared_policy_parser(tmp_path)
    with h.database.write() as connection:
        connection.execute(
            update(models.work_attempts)
            .where(
                models.work_attempts.c.attempt_id == str(work.active_attempt_id),
            )
            .values(status="FAILED")
        )
    with pytest.raises(ValueError, match="ATTEMPT_NOT_ACTIVE"):
        runtime.intermediate.publish(str(work.work_id), decision, (parser,))
