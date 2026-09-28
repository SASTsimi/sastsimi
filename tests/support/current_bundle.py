"""Build a current simple-runtime report bundle for dashboard tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.bilingual_bundle import BundleFile
from sastsimi.reporting.bundle_files import PublishedBundle, publish_bundle
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def attach_current_bundle(
    data_dir: Path,
    identity: CheckpointIdentity,
    finding_ref: StoredDataRef,
    display_id: str,
) -> PublishedBundle:
    artifacts = SimpleArtifactRepository(data_dir, identity)
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    poc = b"#!/bin/sh\nprintf ok\n"
    poc_ref = artifacts.put_bytes(poc, "text/x-shellscript")
    stdout_ref = artifacts.put_bytes(b"ok\n", "text/plain")
    stderr_ref = artifacts.put_bytes(b"", "text/plain")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "content_ref": poc_ref.model_dump(mode="json"),
            "attempt_id": "candidate-attempt",
        }
    )
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": poc_ref.model_dump(mode="json"),
            "attempt_id": "dynamic-attempt",
            "stdout_ref": stdout_ref.model_dump(mode="json"),
            "stderr_ref": stderr_ref.model_dump(mode="json"),
        }
    )
    validated_ref = artifacts.put_json(
        {
            "kind": "simple_validated_poc",
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": poc_ref.model_dump(mode="json"),
            "execution_ref": execution_ref.model_dump(mode="json"),
            "attempt_id": "dynamic-attempt",
        }
    )
    scope_ref = artifacts.put_json({"result": {"status": "UNCERTAIN"}})
    for stage, outputs, attempt, validated in (
        (
            SimpleStage.POC_CANDIDATE_DONE,
            (candidate_ref, poc_ref),
            "candidate-attempt",
            None,
        ),
        (
            SimpleStage.POC_EXECUTION_DONE,
            (execution_ref,),
            "dynamic-attempt",
            validated_ref,
        ),
        (SimpleStage.SCOPE_GATE_DONE, (scope_ref,), "scope-attempt", None),
    ):
        store.save_checkpoint(
            StageCheckpoint(
                identity=identity,
                stage=stage,
                stage_version=STAGE_VERSION[stage],
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                output_refs=outputs,
                attempt_id=attempt,
                validated_poc_ref=validated,
            )
        )
    technical = store.require(identity, SimpleStage.TECH_GATE_DONE)
    finding = store.require(identity, SimpleStage.FINDING_DONE)
    store.save_checkpoint(
        finding.model_copy(update={"validated_poc_ref": validated_ref})
    )
    sources = {
        "finding": finding_ref,
        "poc": poc_ref,
        "validated_poc": validated_ref,
        "execution": execution_ref,
        "technical": technical.output_refs[0],
        "scope": scope_ref,
        "stdout": stdout_ref,
        "stderr": stderr_ref,
    }
    digest = hashlib.sha256(poc).hexdigest()
    provenance = canonical_bytes(
        {
            "scope_status": "UNCERTAIN",
            "sources": {
                name: ref.model_dump(mode="json") for name, ref in sources.items()
            },
            "poc": {
                "path": "poc.sh",
                "original_sha256": digest,
                "attachment_sha256": digest,
                "redacted": False,
            },
        }
    )
    bundle = publish_bundle(
        root=data_dir,
        analysis_id=identity.analysis_id,
        display_id=display_id,
        finding_ref=finding_ref,
        files=(
            BundleFile(
                "report_en.md", b"# English report\n", "text/markdown; charset=utf-8"
            ),
            BundleFile(
                "report_kr.md",
                "# 한국어 보고서\n".encode(),
                "text/markdown; charset=utf-8",
            ),
            BundleFile("poc.sh", poc, "text/x-shellscript; charset=utf-8"),
            BundleFile("evidence/provenance.json", provenance, "application/json"),
        ),
        put_artifact=artifacts.put_bytes,
    )
    report = store.require(identity, SimpleStage.REPORT_DONE)
    store.save_checkpoint(
        report.model_copy(
            update={
                "bundle_manifest_ref": bundle.manifest_ref,
                "bundle_archive_ref": bundle.archive_ref,
                "validated_poc_ref": validated_ref,
            }
        )
    )
    return bundle
