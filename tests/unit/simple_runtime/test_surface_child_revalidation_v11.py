"""V11 child attempts must not rewrite historical verification checkpoints."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Literal, cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import AttackSurface, SurfaceIndex
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.runner import SimpleStageHandler, StageFailed
from sastsimi.simple_runtime.store import (
    ChildRevalidationProgressRecordV11,
    SimpleCheckpointStore,
)
from sastsimi.simple_runtime.surface_child_evidence_v11 import ChildHoldTargetV11
from sastsimi.simple_runtime.surface_child_revalidation_v11 import (
    revalidate_child_holds_v11,
)


def _identity(hypothesis_id: str | None = None) -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="a" * 40,
        hypothesis_id=hypothesis_id,
    )


def _index() -> SurfaceIndex:
    return SurfaceIndex(
        scope_fingerprint="scope",
        static_bundle_hash="static",
        ast_manifest_hash="ast",
        workspace_id="workspace",
        commit_id="a" * 40,
        candidate_inventory_hash="inventory",
        candidate_count=0,
        surfaces=(
            AttackSurface(
                surface_id="route",
                type="REQUEST_ENTRY",
                path="app.py",
                symbol="route",
                line=1,
                linked_candidate_ids=(),
                evidence_refs=(),
                detector="ast",
            ),
        ),
        static_gaps=(),
    )


def _checkpoint(
    stage: SimpleStage,
    output_refs: tuple[StoredDataRef, ...],
    *,
    verdict: Literal["TRUE", "FALSE", "HOLD"] | None = "HOLD",
    input_refs: tuple[StoredDataRef, ...] = (),
) -> StageCheckpoint:
    return StageCheckpoint(
        identity=_identity("h1"),
        stage=stage,
        stage_version=STAGE_VERSION[stage],
        status=StageStatus.SUCCEEDED,
        input_refs=input_refs,
        input_hash=input_reference_hash(input_refs),
        output_refs=output_refs,
        attempt_id="old-attempt",
        attempt_number=1,
        verdict=verdict,
        external_prerequisites_ref=(
            output_refs[0]
            if stage is SimpleStage.VERIFICATION_INITIAL_DONE and output_refs
            else None
        ),
    )


class _Store:
    def __init__(self, old: StageCheckpoint, pro_con: StageCheckpoint | None = None):
        self.old = old
        self.pro_con = pro_con
        self.additional: dict[SimpleStage, StageCheckpoint] = {}
        self.claims = 0
        self.finished: list[tuple[str, str, StoredDataRef]] = []
        self.state = "PENDING"

    def get(
        self, identity: CheckpointIdentity, stage: SimpleStage
    ) -> StageCheckpoint | None:
        if identity == self.old.identity and stage is self.old.stage:
            return self.old
        if (
            self.pro_con is not None
            and identity == self.pro_con.identity
            and stage is self.pro_con.stage
        ):
            return self.pro_con
        if identity == self.old.identity:
            return self.additional.get(stage)
        return None

    def prior(
        self, identity: CheckpointIdentity, stage: SimpleStage
    ) -> dict[SimpleStage, StageCheckpoint]:
        if self.pro_con is not None and identity == self.pro_con.identity:
            return {
                stage: checkpoint
                for stage, checkpoint in {
                    SimpleStage.PRO_CON_DONE: self.pro_con,
                    **self.additional,
                }.items()
                if list(SimpleStage).index(stage)
                < list(SimpleStage).index(self.old.stage)
            }
        return {}

    def list_surface_child_revalidation_v11(
        self, identity: CheckpointIdentity, scope: str, plan_ref: StoredDataRef
    ) -> dict[tuple[str, SimpleStage], ChildRevalidationProgressRecordV11]:
        assert identity == _identity() and scope == "scope"
        return {
            ("h1", self.old.stage): ChildRevalidationProgressRecordV11(
                hypothesis_id="h1",
                stage=self.old.stage,
                checkpoint_hash=hashlib.sha256(canonical_bytes(self.old)).hexdigest(),
                status=self.state,  # type: ignore[arg-type]
                reason_code=None,
                result_ref=None,
                attempt_id="already-running" if self.state == "RUNNING" else None,
            )
        }

    def claim_surface_child_revalidation_v11(self, *_args: object) -> bool:
        self.claims += 1
        assert self.state == "PENDING"
        self.state = "RUNNING"
        return True

    def finish_surface_child_revalidation_v11(self, *args: object) -> bool:
        status, reason_code, result_ref = args[-3:]
        assert isinstance(status, str) and isinstance(reason_code, str)
        assert isinstance(result_ref, StoredDataRef)
        self.finished.append((status, reason_code, result_ref))
        self.state = status
        return True


def _as_store(store: _Store) -> SimpleCheckpointStore:
    """Adapt the narrow in-memory fake at the test's production boundary."""

    return cast(SimpleCheckpointStore, store)


def _setup(
    tmp_path: Path, stage: SimpleStage
) -> tuple[
    SimpleArtifactRepository,
    StoredDataRef,
    StoredDataRef,
    _Store,
    ChildHoldTargetV11,
]:
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    proposal_ref = artifacts.put_json(
        {"kind": "simple_hypothesis_proposal", "hypothesis_id": "h1"}
    )
    source_ref = artifacts.put_json(
        {"kind": "simple_static_fact_bundle", "path": "app.py"}
    )
    pro_ref = artifacts.put_json({"kind": "simple_pro_evidence", "claims": []})
    con_ref = artifacts.put_json({"kind": "simple_con_evidence", "claims": []})
    pro_con = StageCheckpoint(
        identity=_identity("h1"),
        stage=SimpleStage.PRO_CON_DONE,
        stage_version=STAGE_VERSION[SimpleStage.PRO_CON_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref, source_ref),
        input_hash=input_reference_hash((proposal_ref, source_ref)),
        output_refs=(pro_ref, con_ref),
        attempt_id="pro-con-attempt",
    )
    old_output = artifacts.put_json(
        {"kind": "old_verification", "result": {"verdict": "HOLD"}}
    )
    old = _checkpoint(stage, (old_output,), input_refs=pro_con.output_refs)
    store = _Store(old, pro_con)
    digest = hashlib.sha256(canonical_bytes(old)).hexdigest()
    target = ChildHoldTargetV11("h1", stage, ("route",), digest)
    route_ref = artifacts.put_json(
        {
            "kind": "simple_attack_surface_coverage_v8",
            "scope_fingerprint": "scope",
            "index_hash": hashlib.sha256(
                canonical_bytes(_index().to_json())
            ).hexdigest(),
            "surfaces": [{"surface_id": "route", "coverage_status": "COVERED"}],
        }
    )
    plan_ref = artifacts.put_json(
        {
            "kind": "simple_surface_enrichment_plan_v11",
            "analysis_id": "analysis",
            "workspace_id": "workspace",
            "commit_id": "a" * 40,
            "scope_fingerprint": "scope",
            "index_hash": hashlib.sha256(
                canonical_bytes(_index().to_json())
            ).hexdigest(),
            "v10_coverage_ref": route_ref.model_dump(mode="json"),
            "targets": [
                {
                    "hypothesis_id": "h1",
                    "stage": stage.value,
                    "surface_ids": ["route"],
                    "checkpoint_hash": digest,
                }
            ],
        }
    )
    return artifacts, plan_ref, route_ref, store, target


@pytest.mark.asyncio
async def test_initial_hold_does_not_spend_on_unfinished_downstream_chain(
    tmp_path: Path,
) -> None:
    artifacts, plan_ref, route_ref, store, target = _setup(
        tmp_path, SimpleStage.VERIFICATION_INITIAL_DONE
    )
    factory_calls: list[CheckpointIdentity] = []

    async def handler(
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult:
        raise AssertionError(
            "initial HOLD cannot resolve without PoC and downstream gates"
        )

    def handlers_for_child(
        child: CheckpointIdentity,
    ) -> Mapping[SimpleStage, SimpleStageHandler]:
        factory_calls.append(child)
        return {SimpleStage.VERIFICATION_INITIAL_DONE: handler}

    await revalidate_child_holds_v11(
        _identity(),
        _index(),
        (target,),
        plan_ref,
        {"route": route_ref},
        _as_store(store),
        artifacts,
        handlers_for_child,
    )

    assert factory_calls == []
    assert store.old.verdict == "HOLD" and store.old.attempt_id == "old-attempt"
    assert store.finished[0][:2] == ("STILL_HOLD", "DOWNSTREAM_POC_REQUIRED")
    result = json.loads(artifacts.read(store.finished[0][2]))
    assert result["checkpoint_hash"] == target.checkpoint_hash
    assert result["new_checkpoint"] is None


@pytest.mark.asyncio
async def test_running_attempt_is_not_issued_again(tmp_path: Path) -> None:
    artifacts, plan_ref, route_ref, store, target = _setup(
        tmp_path, SimpleStage.VERIFICATION_INITIAL_DONE
    )
    store.state = "RUNNING"

    async def forbidden(
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult:
        raise AssertionError("in-flight attempt was duplicated")

    await revalidate_child_holds_v11(
        _identity(),
        _index(),
        (target,),
        plan_ref,
        {"route": route_ref},
        _as_store(store),
        artifacts,
        lambda _child: {SimpleStage.VERIFICATION_INITIAL_DONE: forbidden},
    )

    assert store.claims == 0 and store.finished == []


@pytest.mark.asyncio
async def test_poc_inconclusive_resolves_only_with_exact_old_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts, plan_ref, route_ref, store, target = _setup(
        tmp_path, SimpleStage.POC_EXECUTION_DONE
    )

    def exact_old_lineage(*_args: object) -> dict[str, object]:
        return {
            "checkpoint_sha256": target.checkpoint_hash,
            "output_refs": [
                ref.model_dump(mode="json") for ref in store.old.output_refs
            ],
        }

    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_child_revalidation_v11._completed_inconclusive_child",
        exact_old_lineage,
    )
    await revalidate_child_holds_v11(
        _identity(),
        _index(),
        (target,),
        plan_ref,
        {"route": route_ref},
        _as_store(store),
        artifacts,
        lambda _child: {},
    )

    assert store.finished[0][:2] == ("RESOLVED", "VERIFIED_POC_INCONCLUSIVE")
    result = json.loads(artifacts.read(store.finished[0][2]))
    assert result["evidence_refs"] == [
        ref.model_dump(mode="json") for ref in store.old.output_refs
    ]
    assert result["new_checkpoint"] is None


@pytest.mark.asyncio
async def test_final_hold_without_supported_poc_stays_unresolved(
    tmp_path: Path,
) -> None:
    artifacts, plan_ref, route_ref, store, target = _setup(
        tmp_path, SimpleStage.VERIFICATION_FINAL_DONE
    )

    async def forbidden(
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult:
        raise AssertionError("final verification needs an old supported PoC")

    await revalidate_child_holds_v11(
        _identity(),
        _index(),
        (target,),
        plan_ref,
        {"route": route_ref},
        _as_store(store),
        artifacts,
        lambda _child: {SimpleStage.VERIFICATION_FINAL_DONE: forbidden},
    )

    assert store.finished[0][:2] == ("STILL_HOLD", "SUPPORTED_POC_UNVERIFIED")


@pytest.mark.asyncio
async def test_provider_failure_is_error_not_refutation(tmp_path: Path) -> None:
    artifacts, plan_ref, route_ref, store, _target = _setup(
        tmp_path, SimpleStage.VERIFICATION_FINAL_DONE
    )
    _supported_poc_history(artifacts, store)
    target = ChildHoldTargetV11(
        "h1",
        store.old.stage,
        ("route",),
        hashlib.sha256(canonical_bytes(store.old)).hexdigest(),
    )
    plan = json.loads(artifacts.read(plan_ref))
    plan["targets"][0]["checkpoint_hash"] = target.checkpoint_hash
    plan_ref = artifacts.put_json(plan)

    async def failing(
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult:
        raise StageFailed(
            StageFailure(
                code="INVALID_OUTPUT",
                retryable=False,
                safe_message="schema mismatch",
            )
        )

    await revalidate_child_holds_v11(
        _identity(),
        _index(),
        (target,),
        plan_ref,
        {"route": route_ref},
        _as_store(store),
        artifacts,
        lambda _child: {SimpleStage.VERIFICATION_FINAL_DONE: failing},
    )

    assert store.finished[0][:2] == ("ERROR", "AGENT_EXECUTION_FAILED")


@pytest.mark.asyncio
async def test_unexpected_handler_error_is_fixed_code_without_sensitive_text(
    tmp_path: Path,
) -> None:
    artifacts, plan_ref, route_ref, store, _target = _setup(
        tmp_path, SimpleStage.VERIFICATION_FINAL_DONE
    )
    _supported_poc_history(artifacts, store)
    target = ChildHoldTargetV11(
        "h1",
        store.old.stage,
        ("route",),
        hashlib.sha256(canonical_bytes(store.old)).hexdigest(),
    )
    plan = json.loads(artifacts.read(plan_ref))
    plan["targets"][0]["checkpoint_hash"] = target.checkpoint_hash
    plan_ref = artifacts.put_json(plan)
    observed_children: list[CheckpointIdentity] = []

    async def failing(
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult:
        raise RuntimeError("sensitive_token_which_must_not_be_saved")

    def handlers_for_child(
        child: CheckpointIdentity,
    ) -> Mapping[SimpleStage, SimpleStageHandler]:
        observed_children.append(child)
        return {SimpleStage.VERIFICATION_FINAL_DONE: failing}

    await revalidate_child_holds_v11(
        _identity(),
        _index(),
        (target,),
        plan_ref,
        {"route": route_ref},
        _as_store(store),
        artifacts,
        handlers_for_child,
    )

    assert observed_children == [_identity("h1")]
    assert store.finished[0][:2] == ("ERROR", "AGENT_EXECUTION_FAILED")
    result_bytes = artifacts.read(store.finished[0][2])
    assert b"sensitive_token" not in result_bytes
    assert json.loads(result_bytes)["error_code"] == "AGENT_EXECUTION_FAILED"


@pytest.mark.asyncio
async def test_foreign_route_coverage_is_rejected_before_claim(tmp_path: Path) -> None:
    artifacts, plan_ref, _route_ref, store, target = _setup(
        tmp_path, SimpleStage.VERIFICATION_INITIAL_DONE
    )
    foreign_ref = artifacts.put_json(
        {
            "kind": "simple_attack_surface_coverage_v8",
            "scope_fingerprint": "scope",
            "index_hash": hashlib.sha256(
                canonical_bytes(_index().to_json())
            ).hexdigest(),
            "surfaces": [{"surface_id": "route", "coverage_status": "COVERED"}],
            "tampered": True,
        }
    )

    with pytest.raises(ValueError, match="SURFACE_CHILD_V11_ROUTE_UNBOUND"):
        await revalidate_child_holds_v11(
            _identity(),
            _index(),
            (target,),
            plan_ref,
            {"route": foreign_ref},
            _as_store(store),
            artifacts,
            lambda _child: {},
        )

    assert store.claims == 0


@pytest.mark.asyncio
async def test_plan_cannot_rebind_child_to_a_different_surface(tmp_path: Path) -> None:
    artifacts, plan_ref, route_ref, store, target = _setup(
        tmp_path, SimpleStage.VERIFICATION_INITIAL_DONE
    )
    plan = json.loads(artifacts.read(plan_ref))
    plan["targets"][0]["surface_ids"] = ["different-route"]
    modified_plan_ref = artifacts.put_json(plan)

    with pytest.raises(ValueError, match="SURFACE_CHILD_V11_PLAN_INVALID"):
        await revalidate_child_holds_v11(
            _identity(),
            _index(),
            (target,),
            modified_plan_ref,
            {"route": route_ref},
            _as_store(store),
            artifacts,
            lambda _child: {},
        )

    assert store.claims == 0


def _supported_poc_history(
    artifacts: SimpleArtifactRepository, store: _Store
) -> StoredDataRef:
    assert store.pro_con is not None
    initial_ref = artifacts.put_json(
        {
            "kind": "simple_initial_verification",
            "result": {"initial_assessment": "TRUE"},
        }
    )
    initial = _checkpoint(
        SimpleStage.VERIFICATION_INITIAL_DONE,
        (initial_ref,),
        verdict=None,
        input_refs=store.pro_con.output_refs,
    ).model_copy(update={"external_prerequisites_ref": None})
    content_ref = artifacts.put_bytes(
        b"#!/bin/sh\nprintf 'observed\\n'\n", "text/x-shellscript"
    )
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "content_ref": content_ref.model_dump(mode="json"),
            "attempt_id": "candidate-attempt",
        }
    )
    candidate_inputs = initial.output_refs
    candidate = StageCheckpoint(
        identity=_identity("h1"),
        stage=SimpleStage.POC_CANDIDATE_DONE,
        stage_version=STAGE_VERSION[SimpleStage.POC_CANDIDATE_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=candidate_inputs,
        input_hash=input_reference_hash(candidate_inputs),
        output_refs=(candidate_ref, content_ref),
        attempt_id="candidate-attempt",
    )
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": content_ref.model_dump(mode="json"),
            "attempt_id": "poc-attempt",
            "exit_code": 0,
            "timed_out": False,
        }
    )
    interpretation_ref = artifacts.put_json(
        {
            "kind": "simple_dynamic_interpretation",
            "execution_ref": execution_ref.model_dump(mode="json"),
            "result": {"outcome": "SUPPORTED"},
        }
    )
    validated_ref = artifacts.put_json(
        {
            "kind": "simple_validated_poc",
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": content_ref.model_dump(mode="json"),
            "execution_ref": execution_ref.model_dump(mode="json"),
            "interpretation_ref": interpretation_ref.model_dump(mode="json"),
            "attempt_id": "poc-attempt",
        }
    )
    cleanup_ref = artifacts.put_json(
        {
            "kind": "simple_container_cleanup",
            "attempt_id": "poc-attempt",
            "status": "REMOVED",
        }
    )
    dynamic_inputs = candidate.output_refs
    dynamic = StageCheckpoint(
        identity=_identity("h1"),
        stage=SimpleStage.POC_EXECUTION_DONE,
        stage_version=STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=dynamic_inputs,
        input_hash=input_reference_hash(dynamic_inputs),
        output_refs=(execution_ref, interpretation_ref, validated_ref, cleanup_ref),
        validated_poc_ref=validated_ref,
        attempt_id="poc-attempt",
    )
    store.additional = {
        SimpleStage.VERIFICATION_INITIAL_DONE: initial,
        SimpleStage.POC_CANDIDATE_DONE: candidate,
        SimpleStage.POC_EXECUTION_DONE: dynamic,
    }
    store.old = store.old.model_copy(
        update={
            "input_refs": dynamic.output_refs,
            "input_hash": input_reference_hash(dynamic.output_refs),
        }
    )
    return validated_ref


@pytest.mark.asyncio
async def test_supported_old_poc_and_new_true_still_require_downstream_gates(
    tmp_path: Path,
) -> None:
    artifacts, plan_ref, route_ref, store, _target = _setup(
        tmp_path, SimpleStage.VERIFICATION_FINAL_DONE
    )
    validated_ref = _supported_poc_history(artifacts, store)
    target = ChildHoldTargetV11(
        "h1",
        store.old.stage,
        ("route",),
        hashlib.sha256(canonical_bytes(store.old)).hexdigest(),
    )
    # The frozen plan must match the exact late-bound old final checkpoint.
    plan = json.loads(artifacts.read(plan_ref))
    plan["targets"][0]["checkpoint_hash"] = target.checkpoint_hash
    plan_ref = artifacts.put_json(plan)

    async def handler(
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult:
        dynamic = prior[SimpleStage.POC_EXECUTION_DONE]
        assert set(store.old.output_refs + dynamic.output_refs + (plan_ref,)) <= set(
            checkpoint.input_refs
        )
        output_ref = artifacts.put_json(
            {
                "kind": "simple_verification_result",
                "source_refs": [
                    ref.model_dump(mode="json")
                    for ref in (
                        *store.old.output_refs,
                        dynamic.output_refs[0],
                        validated_ref,
                    )
                ],
                "result": {"verdict": "TRUE", "unresolved_conditions": []},
                "attempt_id": checkpoint.attempt_id,
            }
        )
        return StageResult(
            output_refs=(output_ref,), verdict="TRUE", validated_poc_ref=validated_ref
        )

    await revalidate_child_holds_v11(
        _identity(),
        _index(),
        (target,),
        plan_ref,
        {"route": route_ref},
        _as_store(store),
        artifacts,
        lambda _child: {SimpleStage.VERIFICATION_FINAL_DONE: handler},
    )

    assert store.old.verdict == "HOLD" and store.old.attempt_id == "old-attempt"
    assert store.finished[0][:2] == ("STILL_HOLD", "DOWNSTREAM_GATES_REQUIRED")
    result = json.loads(artifacts.read(store.finished[0][2]))
    assert result["new_checkpoint"] is None
    assert validated_ref.model_dump(mode="json") in result["evidence_refs"]
