"""Frozen run policy and its analysis pointer are one terminal commit."""

import json
from pathlib import Path

import pytest

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.policy import PolicyCollectionResult, RunPolicyState
from sastsimi.contracts.refs import reference
from tests.contract.domain.canonical_fixtures import make
from tests.integration.storage.test_intermediate_publication import (
    prepared_policy_parser,
)


@pytest.mark.parametrize(
    "invalid", [None, "program", "work", "PREPARED", "transaction_B", "COMMITTED"]
)
def test_policy_completion_atomically_pins_analysis_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str | None
) -> None:
    h, runtime, runner, work, parser, decision = prepared_policy_parser(
        tmp_path, prepare=True
    )
    preparing = runtime.policy.current_state("a1")
    assert preparing is not None
    (parser_ref,) = runtime.intermediate.publish(str(work.work_id), decision, (parser,))
    identity = next(
        ref
        for ref, role in h.evidence.identities.items()
        if role == RequesterRole.POLICY_PARSER
    )
    h.evidence.identities[identity] = RequesterRole.POLICY_COLLECTOR
    collection_data = json.loads(
        json.dumps(make("PolicyCollectionResult")).replace('"ws1"', '"w1"')
    )
    collection_data.update(
        meta=runner.metadata(
            work.meta, "policy_collection_result", attempt_id=work.active_attempt_id
        ),
        program_id="program",
        status="ABSENT_CONFIRMED",
        policy_record_ref=None,
        parser_result_refs=(parser_ref,),
        gap_ids=("policy-absence",),
    )
    collection = PolicyCollectionResult.model_validate_json(
        canonical_bytes(collection_data)
    )
    collection_ref = h.records.stage_record(collection)
    policy = RunPolicyState.model_validate_json(
        canonical_bytes(
            dict(
                meta=runner.revision_metadata(preparing.meta),
                program_id="program",
                status="UNVERIFIED",
                preparation_source="COLLECTED",
                source_config_ref=identity,
                parser_name="fake",
                parser_version="1",
                policy_work_ref=h.records.stage_record(work),
                policy_cache_ref=None,
                collection_result_ref=collection_ref,
                policy_record_ref=None,
                freshness_criterion_ref=None,
                freshness_checked_at=None,
                freshness_evidence_refs=(),
                freshness_valid_until=None,
            )
        )
    )
    refs = (h.records.stage_record(policy), collection_ref, parser_ref)
    if invalid in {"program", "work"}:
        data = policy.model_dump(mode="json")
        data["meta"]["record_id"] = f"invalid-{invalid}-policy"
        if invalid == "program":
            data["program_id"] = "another-program"
        else:
            data["policy_work_ref"]["record_id"] = "another-work"
        policy = RunPolicyState.model_validate_json(canonical_bytes(data))
        refs = (h.records.stage_record(policy), collection_ref, parser_ref)
    monkeypatch.setattr(h.evidence, "authorized_outputs", lambda action: refs)
    if invalid in {"program", "work"}:
        with pytest.raises(ValueError, match="POLICY_STATE_CLOSURE_MISMATCH"):
            runner.complete(
                work, identity, "POLICY_COLLECTOR", (policy, collection, parser)
            )
        assert (
            runtime.budget_registry.current_state("a1").run_policy_state_ref
            == reference(preparing)
        )
        return
    if invalid is not None:

        class Crash(BaseException):
            pass

        def crash(stage: str) -> None:
            if stage == invalid:
                raise Crash

        transitions = runtime.intermediate.store.transitions
        monkeypatch.setattr(transitions, "checkpoint", crash)
        with pytest.raises(Crash):
            runner.complete(
                work, identity, "POLICY_COLLECTOR", (policy, collection, parser)
            )
        state = runtime.budget_registry.current_state("a1")
        if invalid == "COMMITTED":
            assert state.run_policy_state_ref == refs[0]
            assert h.records.get_exact(refs[0]) == policy
            assert runtime.work.get(str(work.work_id)).status == "SUCCEEDED"
        else:
            assert state.run_policy_state_ref == reference(preparing)
            with pytest.raises(LookupError):
                h.records.get_exact(refs[0])
            assert runtime.work.get(str(work.work_id)).status == "RUNNING"
        return
    completed = runner.complete(
        work, identity, "POLICY_COLLECTOR", (policy, collection, parser)
    )
    assert completed.status == "SUCCEEDED"
    state = runtime.budget_registry.current_state("a1")
    assert state.run_policy_state_ref == refs[0]
    assert state.status == "RUNNING"
