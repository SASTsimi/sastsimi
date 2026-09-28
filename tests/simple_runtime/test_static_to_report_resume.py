"""A synthetic full-run fixture guards the static-to-report resume boundary.

The PoC and model outputs here are deterministic test data, not evidence of a
real vulnerability or permission to submit an advisory.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from pydantic import JsonValue

from sastsimi.simple_runtime.application import (
    HypothesisSeed,
    SimpleAnalysisApplication,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import StaticCoverageBlocked
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.recovery import (
    RecoveryAction,
    RecoveryCategory,
    RecoveryDecision,
    RecoveryResolution,
)
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner, StageBlocked
from sastsimi.simple_runtime.stages import (
    FindingStage,
    ReporterStage,
    RuleScopeGateStage,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


@pytest.mark.asyncio
async def test_synthetic_static_gap_then_poc_error_resumes_to_restricted_bundle(
    tmp_path: Path,
) -> None:
    """Unverified static coverage blocks agents; completed stages are reused."""

    calls: Counter[str] = Counter()
    repository = "https://example.invalid/repo.git"
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")

    class Static:
        async def run(
            self, request: SimpleAnalysisRequest, identity: CheckpointIdentity
        ) -> StaticBootstrapResult:
            assert request.repository == repository
            calls["static"] += 1
            artifacts = SimpleArtifactRepository(tmp_path, identity)
            if calls["static"] == 1:
                coverage_ref = artifacts.put_json(
                    {
                        "kind": "simple_static_coverage_v1",
                        "fingerprint": "synthetic-static-one",
                        "expected_count": 1,
                        "verified_count": 0,
                        "gaps": [
                            {
                                "path": "app.py",
                                "rule_id": "rule.test",
                                "reason": "scan_timeout",
                            }
                        ],
                    }
                )
                bundle_ref = artifacts.put_json(
                    {"kind": "simple_static_fact_bundle", "complete": False}
                )
                raise StaticCoverageBlocked(
                    "STATIC_COVERAGE_INCOMPLETE",
                    coverage_ref,
                    bundle_ref,
                    retryable=True,
                )
            profile_ref = artifacts.put_json({"kind": "simple_repository_profile"})
            bundle_ref = artifacts.put_json(
                {"kind": "simple_static_fact_bundle", "complete": True}
            )
            return StaticBootstrapResult(
                repository_profile_ref=profile_ref,
                static_bundle_ref=bundle_ref,
                workspace_path=tmp_path / "workspaces" / identity.workspace_id,
            )

    class Hypotheses:
        async def propose(
            self, identity: CheckpointIdentity, static: StaticBootstrapResult
        ) -> tuple[HypothesisSeed, ...]:
            calls["hypotheses"] += 1
            artifacts = SimpleArtifactRepository(tmp_path, identity)
            assert json.loads(artifacts.read(static.static_bundle_ref))["complete"]
            return (
                HypothesisSeed(
                    hypothesis_id="hypothesis-1",
                    proposal_ref=artifacts.put_json(
                        {
                            "kind": "simple_hypothesis_proposal",
                            "hypothesis_id": "hypothesis-1",
                            "static_bundle_ref": static.static_bundle_ref.model_dump(
                                mode="json"
                            ),
                            "proposal": {"title": "Synthetic validation fixture"},
                        }
                    ),
                ),
            )

    class StaticRecovery:
        async def decide(
            self, checkpoint: StageCheckpoint, failure: StageFailure
        ) -> RecoveryResolution:
            assert checkpoint.stage is SimpleStage.STATIC_DONE
            assert failure.code == "STATIC_COVERAGE_INCOMPLETE"
            artifacts = SimpleArtifactRepository(tmp_path, checkpoint.identity)
            decision = RecoveryDecision(
                category=RecoveryCategory.TRANSIENT_TOOL,
                action=RecoveryAction.RETRY_STAGE,
                diagnosis="Synthetic scanner timeout has cleared",
                guidance="Retry the exact scan",
                environment_patch="",
            )
            return RecoveryResolution(
                decision=decision,
                decision_ref=artifacts.put_json(
                    {
                        "kind": "simple_recovery_decision",
                        "decision": decision.model_dump(),
                    }
                ),
            )

    class ReporterClient:
        async def call(self, **_kwargs: Any) -> SimpleLLMCallResult:
            calls["reporter_model"] += 1
            fields: dict[str, JsonValue] = {
                "title": "Synthetic validation fixture",
                "summary": "A synthetic PoC exercises the report pipeline.",
                "details": "No real vulnerability is asserted by this fixture.",
                "impact": "This is test data only.",
                "recommendation": "Review the real target before reporting.",
                "limitations": ["The PoC was simulated."],
                "review_items": ["Obtain real dynamic evidence and policy approval."],
            }
            return SimpleLLMCallResult(
                value={
                    "schema_version": 2,
                    "en": fields,
                    "ko": fields,
                    "citations": [],
                },
                prompt_digest=hashlib.sha256(b"synthetic-prompt").hexdigest(),
                output_digest=hashlib.sha256(b"synthetic-output").hexdigest(),
            )

    reporter_client = ReporterClient()

    def runner_factory(
        current_store: SimpleCheckpointStore,
        identity: CheckpointIdentity,
        _static: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        artifacts = SimpleArtifactRepository(tmp_path, identity)

        async def handle(
            checkpoint: StageCheckpoint,
            prior: Mapping[SimpleStage, StageCheckpoint],
        ) -> StageResult:
            stage = checkpoint.stage
            calls[stage.value] += 1
            if stage is SimpleStage.POC_CANDIDATE_DONE:
                content_ref = artifacts.put_bytes(
                    b"#!/bin/sh\nprintf 'SYNTHETIC_SUPPORTED\\n'\n",
                    "text/x-shellscript",
                )
                candidate_ref = artifacts.put_json(
                    {
                        "kind": "simple_poc_candidate",
                        "content_ref": content_ref.model_dump(mode="json"),
                        "attempt_id": checkpoint.attempt_id,
                    }
                )
                return StageResult(output_refs=(candidate_ref, content_ref))
            if stage is SimpleStage.POC_EXECUTION_DONE:
                if calls[stage.value] == 1:
                    raise StageBlocked(
                        StageFailure(
                            code="POC_EXECUTION_FAILED",
                            retryable=True,
                            safe_message="Synthetic transient execution failure",
                        )
                    )
                candidate = prior[SimpleStage.POC_CANDIDATE_DONE]
                candidate_ref, content_ref = candidate.output_refs
                stdout_ref = artifacts.put_bytes(b"SYNTHETIC_SUPPORTED\n", "text/plain")
                stderr_ref = artifacts.put_bytes(b"", "text/plain")
                execution_ref = artifacts.put_json(
                    {
                        "kind": "simple_poc_execution",
                        "candidate_ref": candidate_ref.model_dump(mode="json"),
                        "content_ref": content_ref.model_dump(mode="json"),
                        "stdout_ref": stdout_ref.model_dump(mode="json"),
                        "stderr_ref": stderr_ref.model_dump(mode="json"),
                        "exit_code": 0,
                        "timed_out": False,
                        "attempt_id": checkpoint.attempt_id,
                    }
                )
                validated_ref = artifacts.put_json(
                    {
                        "kind": "simple_validated_poc",
                        "candidate_ref": candidate_ref.model_dump(mode="json"),
                        "content_ref": content_ref.model_dump(mode="json"),
                        "execution_ref": execution_ref.model_dump(mode="json"),
                        "attempt_id": checkpoint.attempt_id,
                    }
                )
                return StageResult(
                    output_refs=(execution_ref, validated_ref),
                    validated_poc_ref=validated_ref,
                )
            if stage is SimpleStage.VERIFICATION_FINAL_DONE:
                final_validated_ref = prior[
                    SimpleStage.POC_EXECUTION_DONE
                ].validated_poc_ref
                assert final_validated_ref is not None
                return StageResult(
                    output_refs=(artifacts.put_json({"result": {"verdict": "TRUE"}}),),
                    validated_poc_ref=final_validated_ref,
                    verdict="TRUE",
                )
            if stage is SimpleStage.CWE_DONE:
                return StageResult(
                    output_refs=(
                        artifacts.put_json({"result": {"primary_cwe": "CWE-79"}}),
                    )
                )
            if stage is SimpleStage.TECH_GATE_DONE:
                return StageResult(
                    output_refs=(artifacts.put_json({"result": {"status": "ACCEPT"}}),),
                    gate_decision="ACCEPT",
                )
            if stage is SimpleStage.SCOPE_GATE_DONE:
                return await RuleScopeGateStage(
                    reporter_client, artifacts, repository_url=repository
                )(checkpoint, prior)
            if stage is SimpleStage.FINDING_DONE:
                return await FindingStage(artifacts, repository_url=repository)(
                    checkpoint, prior
                )
            if stage is SimpleStage.REPORT_DONE:
                return await ReporterStage(
                    reporter_client,
                    artifacts,
                    store=current_store,
                    repository_url=repository,
                )(checkpoint, prior)
            return StageResult(
                output_refs=(
                    artifacts.put_json(
                        {
                            "kind": stage.value.lower(),
                            "result": {"status": "SYNTHETIC"},
                            "children": [],
                        }
                    ),
                )
            )

        handlers = {stage: handle for stage in tuple(SimpleStage)[2:]}
        return SimpleRuntimeRunner(current_store, handlers)

    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=Static(),
        hypothesis_bootstrap=Hypotheses(),
        runner_factory=runner_factory,
        recovery_factory=lambda _identity: StaticRecovery(),
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )
    request = SimpleAnalysisRequest(
        data_dir=tmp_path, repository=repository, commit="a" * 40
    )

    first = await application.analyze(request)
    assert first.status == "BLOCKED"
    assert first.current_stage is SimpleStage.STATIC_DONE
    assert calls == Counter({"static": 1})
    assert store.require(first.identity, SimpleStage.STATIC_DONE).output_refs

    second = await application.resume(first.display_analysis_id)
    assert second.status == "BLOCKED"
    assert second.current_stage is SimpleStage.POC_EXECUTION_DONE
    assert second.error_code == "POC_EXECUTION_FAILED"
    assert calls["static"] == 2
    assert calls["hypotheses"] == 1
    assert calls[SimpleStage.PRO_CON_DONE.value] == 1
    assert calls[SimpleStage.VERIFICATION_INITIAL_DONE.value] == 1
    assert calls[SimpleStage.POC_CANDIDATE_DONE.value] == 1
    assert calls[SimpleStage.POC_EXECUTION_DONE.value] == 1
    assert calls[SimpleStage.FINDING_DONE.value] == 0

    third = await application.resume(first.display_analysis_id)
    assert third.status == "COMPLETE"
    assert calls["static"] == 2
    assert calls["hypotheses"] == 1
    assert calls[SimpleStage.PRO_CON_DONE.value] == 1
    assert calls[SimpleStage.VERIFICATION_INITIAL_DONE.value] == 1
    assert calls[SimpleStage.POC_CANDIDATE_DONE.value] == 2
    assert calls[SimpleStage.POC_EXECUTION_DONE.value] == 2
    assert calls[SimpleStage.FINDING_DONE.value] == 1
    assert calls[SimpleStage.REPORT_DONE.value] == calls["reporter_model"] == 1

    hypothesis = first.identity.model_copy(update={"hypothesis_id": "hypothesis-1"})
    scope = store.require(hypothesis, SimpleStage.SCOPE_GATE_DONE)
    assert (
        json.loads(
            SimpleArtifactRepository(tmp_path, hypothesis).read(scope.output_refs[0])
        )["result"]["status"]
        == "UNCERTAIN"
    )
    finding = store.require(hypothesis, SimpleStage.FINDING_DONE)
    finding_value = json.loads(
        SimpleArtifactRepository(tmp_path, hypothesis).read(finding.output_refs[0])
    )
    assert finding_value["status"] == "CONFIRMED_RESTRICTED"
    assert finding_value["private_reporting_policy_passed"] is False
    report = store.require(hypothesis, SimpleStage.REPORT_DONE)
    assert report.status is StageStatus.SUCCEEDED
    assert report.bundle_manifest_ref is not None
    assert report.bundle_archive_ref is not None
    assert report.markdown_path is not None
    bundle = Path(report.markdown_path).with_suffix("")
    assert (bundle / "report_en.md").is_file()
    assert (bundle / "report_kr.md").is_file()
    assert (bundle / "poc.sh").is_file()
    assert (bundle / "evidence" / "provenance.json").is_file()

    repeat = await application.resume(first.display_analysis_id)
    assert repeat.status == "COMPLETE"
    assert calls["static"] == 2
    assert calls["hypotheses"] == 1
    assert calls[SimpleStage.REPORT_DONE.value] == 1
