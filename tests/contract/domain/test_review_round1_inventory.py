import pytest

from sastsimi.contracts.evaluation import AnalysisRunResult

from .canonical_fixtures import make
from .fixtures import meta, ref, wire
from .success_fixture import bound, dynamic_success


@pytest.mark.parametrize(
    "field",
    (
        "hypothesis_duplicate_review_refs finding_refs "
        "verification_refs cwe_label_refs "
        "technical_review_refs rule_scope_review_refs policy_collection_result_refs "
        "policy_parser_result_refs policy_record_refs "
        "dynamic_request_refs dynamic_result_refs "
        "environment_recipe_refs sandbox_environment_refs "
        "agent_log_refs dynamic_reproduction_conclusion_refs "
        "sandbox_policy_decision_refs cleanup_result_refs "
        "primitive_and_chaining_refs poc_candidate_refs "
        "poc_refs report_draft_refs llm_invocation_log_refs "
        "action_decision_refs work_state_refs "
        "work_attempt_refs transition_commit_refs"
    ).split(),
)
def test_r16_authoritative_inventory_rejects_unrelated_record_kind(field: str) -> None:
    value = make("AnalysisRunResult") | dict(
        workspace_id="ws1", commit_id="c1", run_policy_state_ref=ref("run_policy_state")
    )
    value[field] = [ref("unrelated")]
    with pytest.raises(ValueError, match="INVENTORY_KIND_MISMATCH"):
        wire(AnalysisRunResult, value)


def test_r16_resolves_full_inventory_and_current_verification_cwe() -> None:
    from sastsimi.contracts.base import ContractModel
    from sastsimi.contracts.evaluation import (
        ResolvedAnalysisInventory,
        validate_analysis_current,
    )
    from sastsimi.contracts.gates import CWELabel
    from sastsimi.contracts.refs import RecordRef, StoredDataRef
    from sastsimi.contracts.verification import VerificationResult
    from sastsimi.contracts.work import (
        TransitionCommit,
        WorkAttempt,
        WorkExecutionState,
    )

    from .canonical_fixtures import NOW

    chain = dynamic_success()
    verification = wire(
        VerificationResult,
        make("VerificationResult")
        | dict(
            verdict="TRUE",
            initial_verdict="TRUE",
            dynamic_request_ref=bound(chain["request"]),
            dynamic_result_ref=bound(chain["result"]),
            poc_ref=bound(chain["poc"]),
        ),
    )
    label = wire(
        CWELabel,
        make("CWELabel", "cwe_label")
        | dict(verification_result_ref=bound(verification)),
    )
    attempt = wire(
        WorkAttempt,
        make("WorkAttempt")
        | dict(
            meta=meta("work_attempt", hypothesis="h1"),
            work_id="cwe-work",
            attempt_id="at1",
            status="SUCCEEDED",
            output_refs=[bound(label)],
            input_hash="a" * 64,
            finished_at=NOW,
        ),
    )
    commit = wire(
        TransitionCommit,
        make("TransitionCommit")
        | dict(
            meta=meta("transition_commit", hypothesis="h1"),
            work_id="cwe-work",
            attempt_id="at1",
            state="COMMITTED",
            target_status="SUCCEEDED",
            expected_state_version=1,
            target_state_version=2,
            output_refs=[bound(label)],
            transition_ref=ref("state_transition"),
            committed_at=NOW,
        ),
    )
    work = wire(
        WorkExecutionState,
        make("WorkExecutionState")
        | dict(
            meta=meta("work_execution_state", hypothesis="h1", attempt=None),
            work_id="cwe-work",
            work_type="CWE_LABEL",
            subject_type="HYPOTHESIS",
            subject_id="h1",
            status="SUCCEEDED",
            state_version=2,
            parent_work_ref=ref("work_execution_state"),
            input_hash="a" * 64,
            dedupe_key="b" * 64,
            output_refs=[bound(label)],
            input_refs=[bound(verification)],
            last_transition_ref=ref("state_transition"),
            last_transition_commit_ref=bound(commit),
            finished_at=NOW,
            stop_reason="COMPLETED",
        ),
    )
    groups: dict[str, tuple[ContractModel, ...]] = {
        "verification_refs": (verification,),
        "cwe_label_refs": (label,),
        "dynamic_request_refs": (chain["request"],),
        "dynamic_result_refs": (chain["result"],),
        "environment_recipe_refs": (chain["recipe"],),
        "sandbox_environment_refs": (chain["environment"],),
        "agent_log_refs": (chain["log"],),
        "dynamic_reproduction_conclusion_refs": (chain["conclusion"],),
        "sandbox_policy_decision_refs": (chain["policy"],),
        "cleanup_result_refs": (chain["cleanup"],),
        "poc_candidate_refs": (chain["candidate"],),
        "poc_refs": (chain["poc"],),
        "work_state_refs": (work,),
        "work_attempt_refs": (attempt,),
        "transition_commit_refs": (commit,),
    }
    value = make("AnalysisRunResult") | dict(
        workspace_id="ws1", commit_id="c1", verdict_counts={"TRUE": 1}
    )
    expected = {
        name: tuple(wire(StoredDataRef, bound(item)) for item in groups.get(name, ()))
        for name in value
        if name.endswith("_refs")
    }
    value.update(
        {
            name: [item.model_dump(mode="json") for item in refs]
            for name, refs in expected.items()
        }
    )
    records: dict[RecordRef, ContractModel] = {
        wire(StoredDataRef, bound(item)): item
        for items in groups.values()
        for item in items
    }
    assert verification.meta.hypothesis_id is not None
    inventory = ResolvedAnalysisInventory(
        records=records,
        expected_refs=expected,
        current_verification_refs={
            verification.meta.hypothesis_id: wire(StoredDataRef, bound(verification))
        },
        verification_generations={verification.meta.hypothesis_id: 1},
    )
    result = wire(AnalysisRunResult, value)
    validate_analysis_current(
        result,
        None,
        None,
        (),
        (chain["result"],),
        pinned_eval_refs=(),
        expected_failed_hypothesis_count=0,
        inventory=inventory,
    )
    missing = dict(records)
    missing.pop(wire(StoredDataRef, bound(chain["recipe"])))
    with pytest.raises(ValueError, match="INVENTORY_RECORD_UNRESOLVED"):
        validate_analysis_current(
            result,
            None,
            None,
            (),
            (chain["result"],),
            pinned_eval_refs=(),
            expected_failed_hypothesis_count=0,
            inventory=ResolvedAnalysisInventory(
                records=missing,
                expected_refs=expected,
                current_verification_refs=inventory.current_verification_refs,
                verification_generations=inventory.verification_generations,
            ),
        )
    stale_label = wire(
        CWELabel, label.model_dump(mode="json") | dict(verification_generation=2)
    )
    stale_ref = wire(StoredDataRef, bound(stale_label))
    stale_records = dict(records)
    stale_records[stale_ref] = stale_label
    stale_expected = expected | {"cwe_label_refs": (stale_ref,)}
    with pytest.raises(ValueError, match="CURRENT_CWE_VERIFICATION_MISMATCH"):
        validate_analysis_current(
            wire(
                AnalysisRunResult,
                value | dict(cwe_label_refs=[stale_ref.model_dump(mode="json")]),
            ),
            None,
            None,
            (),
            (chain["result"],),
            pinned_eval_refs=(),
            expected_failed_hypothesis_count=0,
            inventory=ResolvedAnalysisInventory(
                records=stale_records,
                expected_refs=stale_expected,
                current_verification_refs=inventory.current_verification_refs,
                verification_generations=inventory.verification_generations,
            ),
        )
