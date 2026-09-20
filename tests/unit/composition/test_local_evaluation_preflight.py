from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from sastsimi.composition.local_evaluation_preflight import (
    DeferredLocalEvaluationCalls,
    LocalUnavailableSandboxCancellation,
    _prepared_artifact_refs,
    _prepared_static_artifact_refs,
    _restore_completed_workspace_registration,
)
from sastsimi.composition.local_static_materials import (
    load_local_candidate_static_materials,
)
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.refs import (
    HostConfigurationRef,
    RunStoredDataRef,
    StoredDataRef,
)
from sastsimi.contracts.work import WorkStatus, WorkType
from sastsimi.storage.artifact_store import LocalArtifactStore

ROOT = Path(__file__).parents[3]
MATERIALS = ROOT / "config" / "static-analysis" / "candidate-v1"


def _artifact_ref(digit: str) -> StoredDataRef:
    digest = digit * 64
    return StoredDataRef.model_validate(
        dict(
            stored_data_id=digest,
            data_kind="artifact",
            content_hash=digest,
            workspace_id="workspace-1",
            commit_id="b" * 40,
            record_id=None,
        )
    )


def _run_ref(kind: str, digit: str, *, record: bool) -> RunStoredDataRef:
    return RunStoredDataRef(
        stored_data_id=StoredDataId(digit * 32),
        data_kind=kind,
        content_hash=digit * 64,
        analysis_id=AnalysisId("analysis-1"),
        record_id=RecordId(digit * 32) if record else None,
    )


def _host_ref(digit: str) -> HostConfigurationRef:
    return HostConfigurationRef(
        stored_data_id=StoredDataId(digit * 32),
        data_kind="runtime_capability_profile",
        content_hash=digit * 64,
        host_id="local-host",
        publication_analysis_id=AnalysisId("analysis-1"),
        publication_workspace_id=WorkspaceId("workspace-1"),
        publication_commit_id=CommitId("d" * 40),
        record_id=RecordId(digit * 32),
    )


class _Calls:
    def __init__(self) -> None:
        self.invocations: list[str] = []

    def resolve(self, **kwargs: Any) -> str:
        self.invocations.append("resolve")
        return "call"

    def settle(self, call: object, invocation: object) -> None:
        del call, invocation
        self.invocations.append("settle")


def test_deferred_call_port_is_one_time_and_fail_closed() -> None:
    calls = DeferredLocalEvaluationCalls()
    with pytest.raises(ValueError, match="LOCAL_EVALUATION_CALLS_NOT_BOUND"):
        calls.resolve()

    delegate = _Calls()
    calls.bind(delegate)  # type: ignore[arg-type]
    assert calls.resolve() == "call"
    calls.settle(object(), object())  # type: ignore[arg-type]
    assert delegate.invocations == ["resolve", "settle"]

    with pytest.raises(ValueError, match="LOCAL_EVALUATION_CALLS_ALREADY_BOUND"):
        calls.bind(delegate)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_unavailable_sandbox_cancellation_reports_no_external_resource() -> None:
    cancellation = LocalUnavailableSandboxCancellation()
    target = type("Target", (), {"target_kind": "SANDBOX"})()
    prepared = await cancellation.prepare(target)  # type: ignore[arg-type]
    assert prepared is target
    cancellation.validate_inventory("analysis", (target,))  # type: ignore[arg-type]
    observation = await cancellation.cancel(target)  # type: ignore[arg-type]
    assert observation.status == "ABSENT"
    assert observation.reason_code == "LOCAL_SANDBOX_NOT_STARTED"


def test_local_policy_boundary_is_protected_before_runtime_recovery() -> None:
    evidence = _artifact_ref("1")
    network = _artifact_ref("2")
    schema = _artifact_ref("3")
    implementation = _artifact_ref("4")
    semantic_test = _artifact_ref("5")
    template = _artifact_ref("6")
    isolation = _artifact_ref("7")
    workspace_policy = _artifact_ref("8")
    policy_boundary = _artifact_ref("9")
    prompt_plan = SimpleNamespace(
        local_evidence_ref=evidence,
        client_execution=SimpleNamespace(network_policy_ref=network),
        output_schemas=(SimpleNamespace(schema_artifact_ref=schema),),
        semantic_validators=(
            SimpleNamespace(
                implementation_ref=implementation,
                test_refs=(semantic_test,),
            ),
        ),
        prompt_entries=(SimpleNamespace(template_ref=template),),
    )
    run_configuration = SimpleNamespace(
        sandbox_profile=SimpleNamespace(isolation_policy_refs=(isolation,)),
        workspace_policy_ref=workspace_policy,
    )

    protected = _prepared_artifact_refs(
        prompt_plan=prompt_plan,
        run_configuration=run_configuration,
        policy_boundary_ref=policy_boundary,
    )

    assert protected[-1] == policy_boundary


def test_static_materials_are_protected_before_run_start_recovery(
    tmp_path: Path,
) -> None:
    artifacts = LocalArtifactStore(
        tmp_path / "artifacts",
        WorkspaceId("workspace-1"),
        CommitId("b" * 40),
    )
    materials = load_local_candidate_static_materials(MATERIALS)

    protected = _prepared_static_artifact_refs(
        materials=materials,
        artifacts=artifacts,
    )

    assert {item.content_hash for item in protected} == set(materials.evidence)
    assert all(
        artifacts.path_for(item.content_hash).is_file() for item in protected
    )


def test_resume_restores_exact_completed_workspace_without_clone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_ref = _run_ref("analysis_run_input", "a", record=True)
    policy_ref = _run_ref("artifact", "b", record=False)
    git_ref = _host_ref("e")
    workspace_ref = _artifact_ref("c").model_copy(
        update={"data_kind": "code_workspace"}
    )
    run_input = SimpleNamespace(requested_git_ref="d" * 40)
    work = SimpleNamespace(
        work_type=WorkType.WORKSPACE_PREP,
        status=WorkStatus.SUCCEEDED,
        input_refs=(input_ref, policy_ref, git_ref),
        output_refs=(workspace_ref,),
    )
    outcome = SimpleNamespace(status="READY")
    calls: list[tuple[object, ...]] = []

    class _External:
        def resolve_repository_preparation(self, **kwargs: object) -> object:
            calls.append(tuple(kwargs.values()))
            return outcome

    class _Locator:
        def register(self, value: object) -> None:
            calls.append((value,))

    context = SimpleNamespace(
        scope=SimpleNamespace(analysis_id="analysis-1"),
        runtime=SimpleNamespace(
            budget_registry=SimpleNamespace(
                current_state=lambda _analysis_id: SimpleNamespace(
                    workspace_ref=workspace_ref,
                    commit_id="d" * 40,
                ),
                current_input=lambda _analysis_id: run_input,
            )
        ),
        scheduler_store=SimpleNamespace(work_for_run=lambda _analysis_id: (work,)),
    )
    t08 = SimpleNamespace(
        workspace_prep=SimpleNamespace(external=_External()),
        workspace_locator=_Locator(),
    )
    monkeypatch.setattr(
        "sastsimi.composition.local_evaluation_preflight.reference",
        lambda value: input_ref if value is run_input else None,
    )

    assert _restore_completed_workspace_registration(context=context, t08=t08)
    assert calls[-1] == (outcome,)
    assert calls[0] == (work, run_input, policy_ref, git_ref, git_ref)


def test_resume_rejects_ambiguous_completed_workspace_receipts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_ref = _run_ref("analysis_run_input", "a", record=True)
    policy_ref = _run_ref("artifact", "b", record=False)
    workspace_ref = _artifact_ref("c").model_copy(
        update={"data_kind": "code_workspace"}
    )
    run_input = SimpleNamespace(requested_git_ref="d" * 40)
    work = SimpleNamespace(
        work_type=WorkType.WORKSPACE_PREP,
        status=WorkStatus.SUCCEEDED,
        input_refs=(input_ref, policy_ref),
        output_refs=(workspace_ref,),
    )
    context = SimpleNamespace(
        scope=SimpleNamespace(analysis_id="analysis-1"),
        runtime=SimpleNamespace(
            budget_registry=SimpleNamespace(
                current_state=lambda _analysis_id: SimpleNamespace(
                    workspace_ref=workspace_ref,
                    commit_id="d" * 40,
                ),
                current_input=lambda _analysis_id: run_input,
            )
        ),
        scheduler_store=SimpleNamespace(
            work_for_run=lambda _analysis_id: (work, work)
        ),
    )
    monkeypatch.setattr(
        "sastsimi.composition.local_evaluation_preflight.reference",
        lambda value: input_ref if value is run_input else None,
    )

    with pytest.raises(
        ValueError, match="LOCAL_RESUME_WORKSPACE_PREPARATION_AMBIGUOUS"
    ):
        _restore_completed_workspace_registration(
            context=context,
            t08=SimpleNamespace(
                workspace_prep=SimpleNamespace(external=SimpleNamespace()),
                workspace_locator=SimpleNamespace(),
            ),
        )
