"""Small sequential local-evaluation command used to finish real E2E runs."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from sastsimi.composition.local_codex_binding import build_local_codex_binding
from sastsimi.config.local_evaluation_profile import load_local_evaluation_profile
from sastsimi.contracts.ids import AnalysisId, CommitId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.providers.codex_subscription import CodexCliProcessRunner
from sastsimi.runtime.system_support import SystemClock, UUIDIds
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.container import (
    SimpleLocalContainerFactory,
    build_simple_docker_adapter,
)
from sastsimi.simple_runtime.migration import import_existing_analysis
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleCodexClient
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner
from sastsimi.simple_runtime.scope_policy import (
    project_scope_review,
    safe_public_report,
)
from sastsimi.simple_runtime.stages import build_stage_handlers
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _report_path_for_result(
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
    identity: CheckpointIdentity,
    report: StageCheckpoint | None,
    *,
    policy_snapshot_ref: StoredDataRef | None,
    repository_url: str | None,
) -> str | None:
    """Only advertise a report path when its public projection is unchanged."""

    if (
        report is None
        or report.status is not StageStatus.SUCCEEDED
        or report.markdown_path is None
        or len(report.output_refs) < 2
    ):
        return None
    try:
        report_path = Path(report.markdown_path).resolve(strict=True)
        expected_parent = (
            artifacts.data_dir / "reports" / identity.analysis_id
        ).resolve()
        if report_path.parent != expected_parent or report_path.suffix != ".md":
            return None
        raw = artifacts.read(report.output_refs[1])
        review = project_scope_review(
            store.get(identity, SimpleStage.SCOPE_GATE_DONE),
            artifacts,
            policy_snapshot_ref=policy_snapshot_ref,
            repository_url=repository_url,
        )
        if safe_public_report(raw, review) != raw or report_path.read_bytes() != raw:
            return None
    except (OSError, ValueError, TypeError, sqlite3.Error):
        return None
    return report.markdown_path


async def resume(
    *,
    data_dir: Path,
    analysis_id: str,
    profile_path: Path,
    hypothesis_id: str | None = None,
) -> dict[str, object]:
    """Import immutable earlier results and resume only unfinished hypotheses."""

    profile = load_local_evaluation_profile(profile_path)
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    identities = import_existing_analysis(data_dir, analysis_id, store)
    repair_inputs: dict[str, tuple[StoredDataRef, ...]] = {}
    for identity in identities:
        execution = store.get(identity, SimpleStage.POC_EXECUTION_DONE)
        candidate = store.get(identity, SimpleStage.POC_CANDIDATE_DONE)
        if (
            execution is not None
            and execution.status is StageStatus.BLOCKED
            and execution.error_code == "POC_EXECUTION_FAILED"
            and candidate is not None
        ):
            repair_inputs[identity.hypothesis_id or ""] = tuple(
                dict.fromkeys(
                    candidate.input_refs + candidate.output_refs + execution.output_refs
                )
            )
            store.invalidate_from(
                identity,
                SimpleStage.POC_CANDIDATE_DONE,
                new_inputs=candidate.input_refs,
                force=True,
            )
    identities = import_existing_analysis(data_dir, analysis_id, store)
    for identity in identities:
        scope_gate = store.get(identity, SimpleStage.SCOPE_GATE_DONE)
        if (
            scope_gate is not None
            and scope_gate.status is StageStatus.BLOCKED
            and scope_gate.error_code == "RULE_SCOPE_NOT_ALLOWED"
            and len(scope_gate.output_refs) == 1
        ):
            artifacts = SimpleArtifactRepository(data_dir, identity)
            gate_record = artifacts.read(scope_gate.output_refs[0])
            gate_status = str(
                json.loads(gate_record).get("result", {}).get("status", "")
            )
            if gate_status in {"DENY", "UNCERTAIN"}:
                store.complete(
                    scope_gate,
                    StageResult(output_refs=scope_gate.output_refs),
                )
    for identity in identities:
        exact_inputs = repair_inputs.get(identity.hypothesis_id or "")
        candidate = store.get(identity, SimpleStage.POC_CANDIDATE_DONE)
        if exact_inputs is not None and candidate is not None:
            store.save_checkpoint(
                candidate.model_copy(
                    update={
                        "input_refs": exact_inputs,
                        "input_hash": input_reference_hash(exact_inputs),
                    }
                )
            )
    runnable = tuple(
        identity
        for identity in identities
        if (
            (hypothesis_id is None or identity.hypothesis_id == hypothesis_id)
            and (candidate := store.get(identity, SimpleStage.POC_CANDIDATE_DONE))
            is not None
            and candidate.image_digest is not None
            and candidate.recipe_ref is not None
        )
    )
    if not runnable:
        raise ValueError("SIMPLE_RUNTIME_NO_DYNAMIC_HYPOTHESES")

    try:
        run = store.require_analysis_run(analysis_id)
    except LookupError:
        run = None
    policy_snapshot_ref = run.policy_snapshot_ref if run else None
    repository_url = run.repository if run else None

    first = runnable[0]
    scope = PlannedRunScope(
        analysis_id=AnalysisId(first.analysis_id),
        workspace_id=WorkspaceId(first.workspace_id),
        commit_id=CommitId(first.commit_id),
        repository_ref="imported-local-evaluation",
    )
    bootstrap_artifacts = SimpleArtifactRepository(data_dir, first)
    binding = build_local_codex_binding(
        settings=profile.codex,
        scope=scope,
        artifacts=bootstrap_artifacts.artifacts,
        ids=UUIDIds(),
        clock=SystemClock(),
    )
    provider_ref = reference(binding.provider)
    if not isinstance(provider_ref, StoredDataRef):
        raise ValueError("SIMPLE_RUNTIME_PROVIDER_REFERENCE_INVALID")
    client = SimpleCodexClient(
        runner=CodexCliProcessRunner(binding=binding.binding),
        provider_profile_ref=provider_ref,
        model=profile.codex.model,
    )
    docker = build_simple_docker_adapter(profile, first)
    containers = SimpleLocalContainerFactory(docker=docker, profile=profile)

    results: list[dict[str, object]] = []
    for identity in runnable:
        artifacts = SimpleArtifactRepository(data_dir, identity)
        runner = SimpleRuntimeRunner(
            store,
            build_stage_handlers(
                client=client,
                artifacts=artifacts,
                docker=docker,
                containers=containers,
                store=store,
                security_policy_ref=run.security_policy_ref if run else None,
                policy_snapshot_ref=policy_snapshot_ref,
                repository_url=repository_url,
            ),
            policy_snapshot_ref=policy_snapshot_ref,
        )
        outcome = await runner.resume_hypothesis(identity)
        final = store.get(identity, outcome.current_stage)
        report = store.get(identity, SimpleStage.REPORT_DONE)
        results.append(
            {
                "hypothesis_id": identity.hypothesis_id,
                "stage": outcome.current_stage.value,
                "status": outcome.status.value,
                "error_code": outcome.error_code,
                "verdict": store.verdict(identity),
                "validated_poc": store.validated_poc(identity) is not None,
                "report_path": _report_path_for_result(
                    store,
                    artifacts,
                    identity,
                    report,
                    policy_snapshot_ref=policy_snapshot_ref,
                    repository_url=repository_url,
                ),
                "attempt_number": final.attempt_number if final else 0,
            }
        )

    blocked = any(item["status"] == StageStatus.BLOCKED.value for item in results)
    failed = any(item["status"] == StageStatus.FAILED.value for item in results)
    return {
        "analysis_id": analysis_id,
        "status": "FAILED" if failed else "BLOCKED" if blocked else "COMPLETE",
        "hypotheses": results,
    }


__all__ = ["resume"]
