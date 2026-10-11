"""Only exact, source-bound evidence may suggest replaying a terminal HOLD."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    MAX_RECOVERY_ATTEMPTS,
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.surface_hold_replay_v5 import (
    HoldReplayDecision,
    classify_hold_replay,
)

SOURCE = b"def probe(value):\n    return value == 'fresh-input'\n"
PROOF_TYPES = {
    "initial": "PREREQUISITE_CONTRADICTION",
    "generated": "GENERATED_INPUT_TEST_PATH",
    "exhausted": "NEW_DECISIVE_TEST_PATH",
}


class FakeArtifacts:
    def __init__(self, identity: CheckpointIdentity) -> None:
        self.identity = identity
        self.payloads: dict[str, bytes] = {}
        self.terminal_verified = True

    def put_bytes(self, raw: bytes) -> StoredDataRef:
        digest = hashlib.sha256(raw).hexdigest()
        ref = StoredDataRef.model_validate(
            {
                "stored_data_id": digest,
                "data_kind": "artifact",
                "content_hash": digest,
                "workspace_id": self.identity.workspace_id,
                "commit_id": self.identity.commit_id,
                "record_id": None,
            }
        )
        self.payloads[digest] = raw
        return ref

    def put_json(self, value: object) -> StoredDataRef:
        return self.put_bytes(canonical_bytes(value))

    def read_bounded(self, ref: StoredDataRef, max_bytes: int) -> bytes:
        assert ref.workspace_id.root == self.identity.workspace_id
        assert ref.commit_id.root == self.identity.commit_id
        raw = self.payloads[ref.content_hash]
        assert len(raw) <= max_bytes
        assert hashlib.sha256(raw).hexdigest() == ref.content_hash
        return raw

    def verified_terminal_initial_outcome(self, child: StageCheckpoint) -> str | None:
        if not self.terminal_verified:
            raise ValueError("old evidence invalid")
        return "INCONCLUSIVE"

    def verified_terminal_poc_outcome(self, child: StageCheckpoint) -> str | None:
        if not self.terminal_verified:
            raise ValueError("old evidence invalid")
        return "INCONCLUSIVE"


def _classify_hold_replay(
    identity: CheckpointIdentity,
    child: StageCheckpoint,
    evidence: dict[str, object],
    artifacts: FakeArtifacts,
) -> HoldReplayDecision:
    # This in-memory double supplies exactly the methods used by the classifier.
    return classify_hold_replay(
        identity, child, evidence, cast(SimpleArtifactRepository, artifacts)
    )


def _repo(tmp_path: Path) -> tuple[Path, str]:
    workspace = tmp_path / "repo"
    (workspace / "pkg").mkdir(parents=True)
    (workspace / "pkg/probe.py").write_bytes(SOURCE)
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(
        ["git", "-C", str(workspace), "add", "--", "pkg/probe.py"], check=True
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "-C", str(workspace), "rev-parse", "HEAD"])
        .decode("ascii")
        .strip()
    )
    return workspace, commit


def _child(
    identity: CheckpointIdentity,
    artifacts: FakeArtifacts,
    category: str,
) -> tuple[StageCheckpoint, StoredDataRef]:
    if category == "initial":
        old_ref = artifacts.put_json(
            {
                "kind": "simple_initial_verification",
                "attempt_id": "try-1",
                "result": {
                    "unmet_external_prerequisites": ["fresh-input is unavailable"]
                },
            }
        )
        return (
            StageCheckpoint(
                identity=identity,
                stage=SimpleStage.VERIFICATION_INITIAL_DONE,
                stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                output_refs=(old_ref,),
                external_prerequisites_ref=old_ref,
                attempt_id="try-1",
                verdict="HOLD",
            ),
            old_ref,
        )
    prior_input_ref = artifacts.put_bytes(b"stale")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "content_ref": prior_input_ref.model_dump(mode="json"),
            "content_digest": prior_input_ref.content_hash,
        }
    )
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": prior_input_ref.model_dump(mode="json"),
        }
    )
    interpretation_ref = artifacts.put_json(
        {"kind": "simple_dynamic_interpretation", "outcome": "INCONCLUSIVE"}
    )
    stop_ref = (
        artifacts.put_json(
            {
                "kind": "simple_recovery_decision",
                "decision": {"action": "STOP", "category": "GENERATED_INPUT"},
            }
        )
        if category == "generated"
        else None
    )
    child = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_EXECUTION_DONE,
        stage_version=STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(candidate_ref, prior_input_ref),
        input_hash=input_reference_hash((candidate_ref, prior_input_ref)),
        output_refs=(execution_ref, interpretation_ref),
        poc_stop_decision_ref=stop_ref,
        attempt_id="try-1",
        attempt_number=1 if stop_ref else MAX_RECOVERY_ATTEMPTS,
        verdict="HOLD",
    )
    return child, stop_ref or interpretation_ref


def _evidence(
    workspace: Path,
    identity: CheckpointIdentity,
    child: StageCheckpoint,
    old_ref: StoredDataRef,
    artifacts: FakeArtifacts,
    category: str,
) -> dict[str, object]:
    checkpoint_sha256 = hashlib.sha256(canonical_bytes(child)).hexdigest()
    source_sha256 = hashlib.sha256(SOURCE).hexdigest()
    material_ref = (
        artifacts.put_json(
            {
                "kind": (
                    "simple_surface_replay_test_input_v1"
                    if category == "generated"
                    else "simple_surface_replay_execution_prerequisite_v1"
                ),
                "identity": identity.model_dump(mode="json"),
                "checkpoint_sha256": checkpoint_sha256,
                "source_sha256": source_sha256,
                "value": "fresh-input" if category == "generated" else "new test path",
            }
        )
        if category != "initial"
        else None
    )
    new_ref = artifacts.put_json(
        {
            "kind": "simple_surface_replay_new_evidence_v1",
            "identity": identity.model_dump(mode="json"),
            "checkpoint_sha256": checkpoint_sha256,
            "proof_type": PROOF_TYPES[category],
            "source_path": "pkg/probe.py",
            "source_sha256": source_sha256,
            "material_ref": material_ref.model_dump(mode="json")
            if material_ref
            else None,
        }
    )
    proof_ref = artifacts.put_json(
        {
            "kind": "simple_surface_hold_replay_proof_v1",
            "identity": identity.model_dump(mode="json"),
            "checkpoint_sha256": checkpoint_sha256,
            "proof_type": PROOF_TYPES[category],
            "old_output_refs": [
                ref.model_dump(mode="json") for ref in child.output_refs
            ],
            "old_evidence_ref": old_ref.model_dump(mode="json"),
            "new_evidence_ref": new_ref.model_dump(mode="json"),
            "source_path": "pkg/probe.py",
            "source_sha256": source_sha256,
            "source_sites": [
                {
                    "line": 2,
                    "sha256": hashlib.sha256(SOURCE.splitlines()[1]).hexdigest(),
                }
            ],
            "claim": "fresh-input is unavailable" if category == "initial" else None,
        }
    )
    return {
        "kind": "simple_surface_hold_replay_evidence_v1",
        "identity": identity.model_dump(mode="json"),
        "checkpoint_sha256": checkpoint_sha256,
        "workspace_path": str(workspace),
        "proof_ref": proof_ref.model_dump(mode="json"),
    }


@pytest.mark.parametrize(
    ("category", "action", "restart_stage"),
    [
        (
            "initial",
            "REPLAY_INITIAL_ONCE",
            SimpleStage.VERIFICATION_INITIAL_DONE,
        ),
        ("generated", "REGENERATE_POC_ONCE", SimpleStage.POC_CANDIDATE_DONE),
        ("exhausted", "REEXECUTE_POC_ONCE", SimpleStage.POC_EXECUTION_DONE),
    ],
)
def test_only_verified_source_bound_hold_categories_can_replay(
    tmp_path: Path, category: str, action: str, restart_stage: SimpleStage
) -> None:
    workspace, commit = _repo(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="A-001",
        workspace_id="workspace",
        commit_id=commit,
        hypothesis_id="hypothesis",
    )
    artifacts = FakeArtifacts(identity)
    child, old_ref = _child(identity, artifacts, category)
    evidence = _evidence(workspace, identity, child, old_ref, artifacts, category)

    decision = _classify_hold_replay(identity, child, evidence, artifacts)

    assert decision.action == action
    assert decision.restart_stage is restart_stage
    assert decision.reason == "SOURCE_BOUND_REPLAY_ELIGIBLE"
    assert (
        decision.checkpoint_sha256 == hashlib.sha256(canonical_bytes(child)).hexdigest()
    )
    assert old_ref in decision.evidence_refs
    assert len(decision.evidence_refs) >= 3
    serialized = json.dumps(decision.to_json())
    assert "fresh-input" not in serialized
    assert "new test path" not in serialized
    assert "fresh-input is unavailable" not in serialized


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_proof",
        "wrong_identity",
        "wrong_checkpoint",
        "changed_source",
        "wrong_source_site",
        "unverified_terminal",
        "no_new_ref",
        "wrong_claim",
        "no_test_material",
        "unchanged_test_material",
    ],
)
def test_missing_mutated_or_unverified_evidence_keeps_hold(
    tmp_path: Path, mutation: str
) -> None:
    workspace, commit = _repo(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="A-001",
        workspace_id="workspace",
        commit_id=commit,
        hypothesis_id="hypothesis",
    )
    artifacts = FakeArtifacts(identity)
    child, old_ref = _child(identity, artifacts, "initial")
    evidence = _evidence(workspace, identity, child, old_ref, artifacts, "initial")
    if mutation == "missing_proof":
        evidence.pop("proof_ref")
    elif mutation == "wrong_identity":
        evidence["identity"] = {"analysis_id": "another"}
    elif mutation == "wrong_checkpoint":
        evidence["checkpoint_sha256"] = "0" * 64
    elif mutation == "changed_source":
        (workspace / "pkg/probe.py").write_bytes(SOURCE + b"# changed\n")
    elif mutation == "unverified_terminal":
        artifacts.terminal_verified = False
    elif mutation in {"no_test_material", "unchanged_test_material"}:
        child, old_ref = _child(identity, artifacts, "generated")
        evidence = _evidence(
            workspace, identity, child, old_ref, artifacts, "generated"
        )
        proof_ref = StoredDataRef.model_validate(evidence["proof_ref"])
        proof = json.loads(artifacts.read_bounded(proof_ref, 65536))
        new_ref = StoredDataRef.model_validate(proof["new_evidence_ref"])
        new_record = json.loads(artifacts.read_bounded(new_ref, 65536))
        if mutation == "no_test_material":
            new_record.pop("material_ref")
        else:
            material_ref = StoredDataRef.model_validate(new_record["material_ref"])
            material = json.loads(artifacts.read_bounded(material_ref, 65536))
            material["value"] = "stale"
            new_record["material_ref"] = artifacts.put_json(material).model_dump(
                mode="json"
            )
        proof["new_evidence_ref"] = artifacts.put_json(new_record).model_dump(
            mode="json"
        )
        evidence["proof_ref"] = artifacts.put_json(proof).model_dump(mode="json")
    else:
        proof_ref = StoredDataRef.model_validate(evidence["proof_ref"])
        proof = json.loads(artifacts.read_bounded(proof_ref, 65536))
        if mutation == "wrong_source_site":
            proof["source_sites"][0]["sha256"] = "0" * 64
        elif mutation == "no_new_ref":
            proof.pop("new_evidence_ref")
        else:
            proof["claim"] = "a fabricated prerequisite"
        evidence["proof_ref"] = artifacts.put_json(proof).model_dump(mode="json")

    decision = _classify_hold_replay(identity, child, evidence, artifacts)

    assert decision.action == "KEEP_HOLD"
    assert decision.restart_stage is None
    assert decision.reason != "SOURCE_BOUND_REPLAY_ELIGIBLE"


def test_generated_input_stop_cannot_replay_as_exhausted_poc(tmp_path: Path) -> None:
    workspace, commit = _repo(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="A-001",
        workspace_id="workspace",
        commit_id=commit,
        hypothesis_id="hypothesis",
    )
    artifacts = FakeArtifacts(identity)
    child, old_ref = _child(identity, artifacts, "generated")
    evidence = _evidence(workspace, identity, child, old_ref, artifacts, "exhausted")

    decision = _classify_hold_replay(identity, child, evidence, artifacts)

    assert decision.action == "KEEP_HOLD"
    assert decision.restart_stage is None


def test_exhausted_poc_requires_original_candidate_and_content_binding(
    tmp_path: Path,
) -> None:
    workspace, commit = _repo(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="A-001",
        workspace_id="workspace",
        commit_id=commit,
        hypothesis_id="hypothesis",
    )
    artifacts = FakeArtifacts(identity)
    child, old_ref = _child(identity, artifacts, "exhausted")
    content_ref = child.input_refs[1]
    child = child.model_copy(
        update={
            "input_refs": (content_ref,),
            "input_hash": input_reference_hash((content_ref,)),
        }
    )
    evidence = _evidence(workspace, identity, child, old_ref, artifacts, "exhausted")

    decision = _classify_hold_replay(identity, child, evidence, artifacts)

    assert decision.action == "KEEP_HOLD"
    assert decision.restart_stage is None
