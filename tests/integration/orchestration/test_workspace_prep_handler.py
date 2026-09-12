from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.ids import StoredDataId
from sastsimi.contracts.refs import RunStoredDataRef, reference
from sastsimi.orchestration.analysis_state_factory import AnalysisStateFactory
from sastsimi.orchestration.static_external_runner import StaticExternalRunner
from sastsimi.orchestration.workspace_prep_handler import (
    ExactWorkspacePrepCallResolver,
    WorkspacePrepWorkHandler,
)
from sastsimi.ports.dto import (
    ProcessReceipt,
    RepositoryPreparation,
    WorkContext,
)
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.static_analysis.process import process_command_fingerprint
from sastsimi.static_analysis.repository_loader import (
    canonicalize_repository_source,
    repository_process_specs,
)
from sastsimi.static_analysis.workspace_storage import (
    decode_workspace_storage_policy,
)
from tests.integration.runtime_support import Harness

COMMIT = "a" * 40


class _ExactLoader:
    def __init__(self, root: Path, expected_source: str) -> None:
        self.root = root
        self.expected_source = expected_source
        self.calls = 0
        self.process_receipts: tuple[ProcessReceipt, ...] = ()

    async def prepare(self, **values: Any) -> RepositoryPreparation:
        self.calls += 1
        assert values["submitted_source"] == self.expected_source
        assert values["requested_ref"] == COMMIT
        self.root.mkdir(parents=True)
        deadline = values["deadline"]
        attempt_id = str(values["attempt_id"])
        specs = repository_process_specs(
            git_executable=self.root.parent / "git.exe",
            root=self.root,
            output_dir=self.root.parent / "output",
            deadline=deadline,
            attempt_id=attempt_id,
            repository_url=self.expected_source,
            requested_ref=COMMIT,
            commit_id=COMMIT,
        )
        self.process_receipts = tuple(
            ProcessReceipt(
                action_id=deadline.action_id,
                invocation_id=spec.invocation_id,
                command_kind=spec.command_kind,
                attempt_id=attempt_id,
                command_fingerprint=process_command_fingerprint(spec),
                outcome="SUCCEEDED",
                return_code=0,
                stdout_name=f"{spec.command_kind}.stdout",
                stdout_size=0,
                stdout_sha256="e" * 64,
                stderr_name=f"{spec.command_kind}.stderr",
                stderr_size=0,
                stderr_sha256="e" * 64,
                elapsed_ms=1,
            )
            for spec in specs
        )
        return RepositoryPreparation(
            analysis_id=str(values["analysis_id"]),
            workspace_id=str(values["workspace_id"]),
            repository_url=self.expected_source,
            requested_ref=COMMIT,
            status="READY",
            resolved_commit_id=COMMIT,
            root=self.root,
            tracked_files=(),
            gaps=(),
            errors=(),
            lease_id="workspace-lease",
        )

    def verify_git_capability(self, *_: str) -> None:
        raise AssertionError("fixture has no configured Git capability")


def _setup(tmp_path: Path) -> tuple[Any, ...]:
    harness = Harness(tmp_path)
    execution = harness.execution(max_work=10)
    assert execution.approval_ref is not None
    harness.evidence.identities[execution.approval_ref] = RequesterRole.ORCHESTRATION
    runtime = build_runtime(
        tmp_path, None, None, harness.clock, harness.ids, evidence=harness.evidence
    )
    source = tmp_path / "source"
    source.mkdir()
    request = AnalysisStartRequest(
        repository_ref=source.as_uri(),
        requested_git_ref=COMMIT,
        program_id="program",
        purpose=Purpose.PRODUCTION,
    )
    harness.evidence.approvals.add(content_hash(execution))
    execution_ref = reference(execution)
    assert isinstance(execution_ref, RunStoredDataRef)
    bootstrap = AnalysisStateFactory(harness.clock, harness.ids).create(
        request, execution_ref
    )
    scope = runtime.budget_registry.pin_execution(
        execution, bootstrap.state, bootstrap.run_input
    )
    policy_raw = canonical_bytes(
        {
            "kind": "workspace_storage_policy",
            "schema_version": "1.0",
            "max_git_bytes": 10_000_000,
            "max_checkout_bytes": 10_000_000,
            "max_file_count": 100,
            "min_free_bytes": 1,
        }
    )
    policy_ref = runtime.unit_of_work.artifacts.commit_run(
        runtime.unit_of_work.artifacts.stage_bytes(policy_raw, "application/json"),
        execution.meta.analysis_id,
    )
    runner = WorkflowRunner(runtime, harness.clock, harness.ids)
    work = runner.start(
        scope,
        bootstrap.state.meta,
        "WORKSPACE_PREP",
        "ANALYSIS",
        str(bootstrap.state.meta.analysis_id),
        execution.approval_ref,
        inputs=(bootstrap.state.analysis_input_ref, policy_ref),
    )
    attempt = runtime.work.store.attempts_for_work(str(work.work_id))[-1]
    harness.evidence.identities[execution.approval_ref] = (
        RequesterRole.REPOSITORY_LOADER
    )
    loader = _ExactLoader(tmp_path / "lease", request.repository_ref)
    external = StaticExternalRunner(
        runner,
        tmp_path / "receipts",
        lambda value: canonicalize_repository_source(value, allow_local_file=True),
        decode_workspace_storage_policy,
        lease_root_resolver=lambda lease_id: (
            loader.root
            if lease_id == "workspace-lease"
            else tmp_path / "unknown-lease"
        ),
    )
    handler = WorkspacePrepWorkHandler(
        external=external,
        loader=loader,
        resolve_call=ExactWorkspacePrepCallResolver(runner),
        requester_identity_ref=execution.approval_ref,
        timeout_ms=500,
    )
    return (
        runtime,
        handler,
        external,
        loader,
        WorkContext(work, attempt),
        bootstrap.run_input,
        policy_ref,
    )


@pytest.mark.asyncio
async def test_workspace_handler_uses_exact_local_source_and_commit(
    tmp_path: Path,
) -> None:
    runtime, handler, _, loader, context, run_input, policy_ref = _setup(
        tmp_path
    )

    result = await handler.execute(context)

    completed = runtime.work.get(str(context.work.work_id))
    restarted = StaticExternalRunner(
        handler.external.runner,
        tmp_path / "receipts",
        lambda value: canonicalize_repository_source(value, allow_local_file=True),
        decode_workspace_storage_policy,
        lease_root_resolver=lambda lease_id: (
            loader.root
            if lease_id == "workspace-lease"
            else tmp_path / "unknown-lease"
        ),
    )
    preparation = restarted.resolve_repository_preparation(
        workspace_work=completed,
        run_input=run_input,
        policy_ref=policy_ref,
    )
    assert completed.status == "SUCCEEDED"
    assert result.output_refs == completed.output_refs
    assert preparation.repository_url == run_input.repository_ref
    assert preparation.requested_ref == COMMIT
    assert preparation.resolved_commit_id == COMMIT
    assert loader.calls == 1


@pytest.mark.asyncio
async def test_workspace_handler_rejects_substituted_run_input_before_loader(
    tmp_path: Path,
) -> None:
    _, handler, _, loader, context, _, _ = _setup(tmp_path)
    substitute = RunStoredDataRef(
        stored_data_id=StoredDataId("substituted-input"),
        data_kind="analysis_run_input",
        content_hash="f" * 64,
        analysis_id=context.work.meta.analysis_id,
        record_id="substituted-input",
    )
    input_refs = (substitute, *context.work.input_refs[1:])
    stale_work = context.work.model_copy(
        update={"input_refs": input_refs, "input_hash": content_hash(input_refs)}
    )
    stale_attempt = context.attempt.model_copy(
        update={"input_hash": content_hash(input_refs)}
    )

    with pytest.raises(ValueError, match="WORKSPACE_PREP_CONTEXT_INVALID"):
        await handler.execute(WorkContext(stale_work, stale_attempt))

    assert loader.calls == 0


@pytest.mark.asyncio
async def test_repository_receipt_rejects_substituted_run_request(
    tmp_path: Path,
) -> None:
    runtime, handler, external, _, context, run_input, policy_ref = _setup(tmp_path)
    await handler.execute(context)
    receipt_root = tmp_path / "receipts"
    receipt_path = next(receipt_root.glob("*.receipt.json"))
    receipt = json.loads(receipt_path.read_bytes())
    observation_path = receipt_root / receipt["observation_name"]
    observation = json.loads(observation_path.read_bytes())
    observation["requested_ref"] = "b" * 40
    raw = canonical_bytes(observation)
    observation_path.write_bytes(raw)
    receipt["observation_size"] = len(raw)
    receipt["observation_sha256"] = hashlib.sha256(raw).hexdigest()
    receipt_path.write_bytes(canonical_bytes(receipt))

    with pytest.raises(ValueError, match="REPOSITORY_PREPARATION_RECEIPT_MISMATCH"):
        external.resolve_repository_preparation(
            workspace_work=runtime.work.get(str(context.work.work_id)),
            run_input=run_input,
            policy_ref=policy_ref,
        )
