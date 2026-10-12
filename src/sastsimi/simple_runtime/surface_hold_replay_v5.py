"""Pure, fail-closed eligibility for one evidence-bound terminal HOLD replay.

The decision is advisory. The store must still compare-and-set the exact child
checkpoint, preserve its old outputs, and enforce a one-shot replay marker.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .models import (
    MAX_RECOVERY_ATTEMPTS,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    terminal_initial_outcome,
    terminal_poc_outcome,
)
from .operational_config_v5 import _Gap as _SourceGap
from .operational_config_v5 import _verified_blob, _verify_commit

type ReplayAction = Literal[
    "REPLAY_INITIAL_ONCE",
    "REGENERATE_POC_ONCE",
    "REEXECUTE_POC_ONCE",
    "KEEP_HOLD",
]
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROOF_KIND = "simple_surface_hold_replay_proof_v1"
_EVIDENCE_KIND = "simple_surface_hold_replay_evidence_v1"
_NEW_EVIDENCE_KIND = "simple_surface_replay_new_evidence_v1"
_MAX_PROOF_BYTES = 64 * 1024
_MAX_NEW_EVIDENCE_BYTES = 64 * 1024
_MAX_OLD_EVIDENCE_BYTES = 1024 * 1024
_MAX_SOURCE_BYTES = 256 * 1024


@dataclass(frozen=True, slots=True)
class HoldReplayDecision:
    action: ReplayAction
    restart_stage: SimpleStage | None
    evidence_refs: tuple[StoredDataRef, ...]
    reason: str
    checkpoint_sha256: str

    def to_json(self) -> dict[str, object]:
        return {
            "action": self.action,
            "restart_stage": self.restart_stage.value if self.restart_stage else None,
            "evidence_refs": [
                ref.model_dump(mode="json") for ref in self.evidence_refs
            ],
            "reason": self.reason,
            "checkpoint_sha256": self.checkpoint_sha256,
        }


class _HoldGap(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _scope_ref(value: object, identity: CheckpointIdentity) -> StoredDataRef:
    try:
        ref = StoredDataRef.model_validate(value)
    except (TypeError, ValueError) as error:
        raise _HoldGap("REPLAY_REFERENCE_INVALID") from error
    if (
        ref.workspace_id.root != identity.workspace_id
        or ref.commit_id.root != identity.commit_id
    ):
        raise _HoldGap("REPLAY_REFERENCE_INVALID")
    return ref


def _read_json(
    artifacts: SimpleArtifactRepository,
    ref: StoredDataRef,
    max_bytes: int,
) -> dict[str, object]:
    try:
        payload = json.loads(artifacts.read_bounded(ref, max_bytes))
    except (
        OSError,
        ValueError,
        TypeError,
        UnicodeError,
        KeyError,
        sqlite3.Error,
    ) as error:
        raise _HoldGap("REPLAY_ARTIFACT_UNVERIFIED") from error
    if not isinstance(payload, dict):
        raise _HoldGap("REPLAY_ARTIFACT_UNVERIFIED")
    return payload


def _require_source_site(
    workspace: Path,
    commit_id: str,
    proof: Mapping[str, object],
) -> None:
    path, expected_hash, sites = (
        proof.get("source_path"),
        proof.get("source_sha256"),
        proof.get("source_sites"),
    )
    if (
        not isinstance(path, str)
        or not isinstance(expected_hash, str)
        or not _SHA256.fullmatch(expected_hash)
        or not isinstance(sites, list)
        or not 1 <= len(sites) <= 8
    ):
        raise _HoldGap("PINNED_SOURCE_UNVERIFIED")
    try:
        _verify_commit(workspace, commit_id)
        source, actual_hash = _verified_blob(
            workspace, commit_id, path, _MAX_SOURCE_BYTES
        )
    except _SourceGap as error:
        raise _HoldGap("PINNED_SOURCE_UNVERIFIED") from error
    if actual_hash != expected_hash:
        raise _HoldGap("PINNED_SOURCE_UNVERIFIED")
    lines = source.splitlines()
    observed: set[int] = set()
    for site in sites:
        if not isinstance(site, dict) or set(site) != {"line", "sha256"}:
            raise _HoldGap("PINNED_SOURCE_UNVERIFIED")
        line, digest = site.get("line"), site.get("sha256")
        if (
            type(line) is not int
            or not 1 <= line <= len(lines)
            or line in observed
            or not isinstance(digest, str)
            or hashlib.sha256(lines[line - 1]).hexdigest() != digest
        ):
            raise _HoldGap("PINNED_SOURCE_UNVERIFIED")
        observed.add(line)


def _old_evidence_ref(
    child: StageCheckpoint,
    proof_type: str,
    artifacts: SimpleArtifactRepository,
) -> tuple[StoredDataRef, ReplayAction, SimpleStage]:
    if child.stage is SimpleStage.VERIFICATION_INITIAL_DONE:
        if (
            proof_type != "PREREQUISITE_CONTRADICTION"
            or terminal_initial_outcome(child) is None
            or child.external_prerequisites_ref is None
            or child.environment_block_ref is not None
        ):
            raise _HoldGap("REPLAY_CATEGORY_UNPROVEN")
        try:
            if artifacts.verified_terminal_initial_outcome(child) != "INCONCLUSIVE":
                raise _HoldGap("OLD_HOLD_UNVERIFIED")
        except (OSError, ValueError, TypeError, sqlite3.Error) as error:
            raise _HoldGap("OLD_HOLD_UNVERIFIED") from error
        old_ref = child.external_prerequisites_ref
        payload = _read_json(artifacts, old_ref, _MAX_OLD_EVIDENCE_BYTES)
        result = payload.get("result")
        claims = (
            result.get("unmet_external_prerequisites")
            if isinstance(result, dict)
            else None
        )
        if (
            payload.get("kind") != "simple_initial_verification"
            or payload.get("attempt_id") != child.attempt_id
            or not isinstance(claims, list)
            or not claims
            or any(not isinstance(item, str) or not item.strip() for item in claims)
        ):
            raise _HoldGap("OLD_HOLD_UNVERIFIED")
        return old_ref, "REPLAY_INITIAL_ONCE", SimpleStage.VERIFICATION_INITIAL_DONE
    if child.stage is not SimpleStage.POC_EXECUTION_DONE:
        raise _HoldGap("REPLAY_CATEGORY_UNPROVEN")
    if terminal_poc_outcome(child) is None:
        raise _HoldGap("OLD_HOLD_UNVERIFIED")
    try:
        if artifacts.verified_terminal_poc_outcome(child) != "INCONCLUSIVE":
            raise _HoldGap("OLD_HOLD_UNVERIFIED")
    except (OSError, ValueError, TypeError, sqlite3.Error) as error:
        raise _HoldGap("OLD_HOLD_UNVERIFIED") from error
    if child.poc_stop_decision_ref is not None:
        if proof_type != "GENERATED_INPUT_TEST_PATH":
            raise _HoldGap("REPLAY_CATEGORY_UNPROVEN")
        old_ref = child.poc_stop_decision_ref
        payload = _read_json(artifacts, old_ref, _MAX_OLD_EVIDENCE_BYTES)
        stop = payload.get("decision")
        if (
            payload.get("kind") != "simple_recovery_decision"
            or not isinstance(stop, dict)
            or stop.get("action") != "STOP"
            or stop.get("category") != "GENERATED_INPUT"
        ):
            raise _HoldGap("REPLAY_CATEGORY_UNPROVEN")
        return old_ref, "REGENERATE_POC_ONCE", SimpleStage.POC_CANDIDATE_DONE
    if (
        proof_type != "NEW_DECISIVE_TEST_PATH"
        or child.attempt_number < MAX_RECOVERY_ATTEMPTS
        or len(child.output_refs) < 2
    ):
        raise _HoldGap("REPLAY_CATEGORY_UNPROVEN")
    return child.output_refs[1], "REEXECUTE_POC_ONCE", SimpleStage.POC_EXECUTION_DONE


def _require_old_poc_candidate(
    identity: CheckpointIdentity,
    child: StageCheckpoint,
    artifacts: SimpleArtifactRepository,
) -> None:
    execution = _read_json(artifacts, child.output_refs[0], _MAX_OLD_EVIDENCE_BYTES)
    candidate_ref = _scope_ref(execution.get("candidate_ref"), identity)
    content_ref = _scope_ref(execution.get("content_ref"), identity)
    if candidate_ref not in child.input_refs or content_ref not in child.input_refs:
        raise _HoldGap("OLD_POC_CANDIDATE_UNVERIFIED")
    candidate = _read_json(artifacts, candidate_ref, _MAX_PROOF_BYTES)
    try:
        content = artifacts.read_bounded(content_ref, _MAX_OLD_EVIDENCE_BYTES)
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error) as error:
        raise _HoldGap("OLD_POC_CANDIDATE_UNVERIFIED") from error
    if (
        candidate.get("kind") != "simple_poc_candidate"
        or candidate.get("content_ref") != content_ref.model_dump(mode="json")
        or candidate.get("content_digest") != hashlib.sha256(content).hexdigest()
    ):
        raise _HoldGap("OLD_POC_CANDIDATE_UNVERIFIED")


def _classify(
    identity: CheckpointIdentity,
    child: StageCheckpoint,
    pinned_evidence: Mapping[str, object],
    artifacts: SimpleArtifactRepository,
) -> HoldReplayDecision:
    checkpoint_sha256 = hashlib.sha256(canonical_bytes(child)).hexdigest()
    if child.identity != identity or artifacts.identity != identity:
        raise _HoldGap("CHILD_IDENTITY_MISMATCH")
    if child.status is not StageStatus.SUCCEEDED or child.verdict != "HOLD":
        raise _HoldGap("CHILD_NOT_TERMINAL_HOLD")
    if (
        pinned_evidence.get("kind") != _EVIDENCE_KIND
        or pinned_evidence.get("identity") != identity.model_dump(mode="json")
        or pinned_evidence.get("checkpoint_sha256") != checkpoint_sha256
    ):
        raise _HoldGap("PINNED_EVIDENCE_MISSING")
    workspace_value = pinned_evidence.get("workspace_path")
    if not isinstance(workspace_value, str) or not Path(workspace_value).is_absolute():
        raise _HoldGap("PINNED_SOURCE_UNVERIFIED")
    proof_ref = _scope_ref(pinned_evidence.get("proof_ref"), identity)
    proof = _read_json(artifacts, proof_ref, _MAX_PROOF_BYTES)
    proof_type = proof.get("proof_type")
    if (
        proof.get("kind") != _PROOF_KIND
        or proof.get("identity") != identity.model_dump(mode="json")
        or proof.get("checkpoint_sha256") != checkpoint_sha256
        or proof.get("old_output_refs")
        != [ref.model_dump(mode="json") for ref in child.output_refs]
        or not isinstance(proof_type, str)
    ):
        raise _HoldGap("REPLAY_PROOF_UNBOUND")
    old_ref, action, restart_stage = _old_evidence_ref(child, proof_type, artifacts)
    if proof.get("old_evidence_ref") != old_ref.model_dump(mode="json"):
        raise _HoldGap("REPLAY_PROOF_UNBOUND")
    if action == "REEXECUTE_POC_ONCE":
        _require_old_poc_candidate(identity, child, artifacts)
    if action == "REPLAY_INITIAL_ONCE":
        prior = _read_json(artifacts, old_ref, _MAX_OLD_EVIDENCE_BYTES)
        result = prior.get("result")
        claims = (
            result.get("unmet_external_prerequisites")
            if isinstance(result, dict)
            else None
        )
        if not isinstance(claims, list) or proof.get("claim") not in claims:
            raise _HoldGap("PREREQUISITE_CONTRADICTION_UNPROVEN")
    elif proof.get("claim") is not None:
        raise _HoldGap("REPLAY_PROOF_UNBOUND")
    _require_source_site(Path(workspace_value), identity.commit_id, proof)
    new_ref = _scope_ref(proof.get("new_evidence_ref"), identity)
    if new_ref in (*child.output_refs, old_ref, proof_ref):
        raise _HoldGap("NEW_EVIDENCE_NOT_DISTINCT")
    new_evidence = _read_json(artifacts, new_ref, _MAX_NEW_EVIDENCE_BYTES)
    if (
        new_evidence.get("kind") != _NEW_EVIDENCE_KIND
        or new_evidence.get("identity") != identity.model_dump(mode="json")
        or new_evidence.get("checkpoint_sha256") != checkpoint_sha256
        or new_evidence.get("proof_type") != proof_type
        or new_evidence.get("source_path") != proof.get("source_path")
        or new_evidence.get("source_sha256") != proof.get("source_sha256")
    ):
        raise _HoldGap("NEW_EVIDENCE_UNBOUND")
    material_ref: StoredDataRef | None = None
    if action == "REPLAY_INITIAL_ONCE":
        if new_evidence.get("material_ref") is not None:
            raise _HoldGap("NEW_EVIDENCE_UNBOUND")
    else:
        material_ref = _scope_ref(new_evidence.get("material_ref"), identity)
        if material_ref in (
            *child.input_refs,
            *child.output_refs,
            old_ref,
            proof_ref,
            new_ref,
        ):
            raise _HoldGap("NEW_EVIDENCE_NOT_DISTINCT")
        material = _read_json(artifacts, material_ref, _MAX_NEW_EVIDENCE_BYTES)
        expected_kind = (
            "simple_surface_replay_test_input_v1"
            if action == "REGENERATE_POC_ONCE"
            else "simple_surface_replay_execution_prerequisite_v1"
        )
        value = material.get("value")
        if (
            material.get("kind") != expected_kind
            or material.get("identity") != identity.model_dump(mode="json")
            or material.get("checkpoint_sha256") != checkpoint_sha256
            or material.get("source_sha256") != proof.get("source_sha256")
            or not isinstance(value, str)
            or not 1 <= len(value) <= 4096
        ):
            raise _HoldGap("NEW_TEST_MATERIAL_UNPROVEN")
        if action == "REGENERATE_POC_ONCE":
            execution = _read_json(
                artifacts, child.output_refs[0], _MAX_OLD_EVIDENCE_BYTES
            )
            old_input_ref = _scope_ref(execution.get("content_ref"), identity)
            if (
                old_input_ref not in child.input_refs
                or hashlib.sha256(value.encode("utf-8")).hexdigest()
                == old_input_ref.content_hash
            ):
                raise _HoldGap("NEW_TEST_MATERIAL_UNPROVEN")
    evidence_refs = tuple(
        dict.fromkeys(
            (*child.output_refs, old_ref, proof_ref, new_ref)
            + ((material_ref,) if material_ref else ())
        )
    )
    return HoldReplayDecision(
        action=action,
        restart_stage=restart_stage,
        evidence_refs=evidence_refs,
        reason="SOURCE_BOUND_REPLAY_ELIGIBLE",
        checkpoint_sha256=checkpoint_sha256,
    )


def classify_hold_replay(
    identity: CheckpointIdentity,
    child: StageCheckpoint,
    pinned_evidence: Mapping[str, object],
    artifacts: SimpleArtifactRepository,
) -> HoldReplayDecision:
    """Classify one old terminal HOLD; never mutate it or infer a verdict.

    Source-line hashes are checked against both the pinned commit and checkout.
    The evidence record's semantic contradiction/test path must be produced by
    a trusted v5 evidence validator; this function checks its exact binding.
    The store remains responsible for one-shot CAS and replay-marker integrity.
    """

    checkpoint_sha256 = hashlib.sha256(canonical_bytes(child)).hexdigest()
    try:
        return _classify(identity, child, pinned_evidence, artifacts)
    except _HoldGap as gap:
        return HoldReplayDecision(
            action="KEEP_HOLD",
            restart_stage=None,
            evidence_refs=(),
            reason=gap.code,
            checkpoint_sha256=checkpoint_sha256,
        )
