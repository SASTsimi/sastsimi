"""Architecture checks for the deterministic vertical-slice composition."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.contracts.actions import ActionRequest, RequesterRole
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.ids import (
    ActionId,
    AttemptId,
    CommitId,
    RecordId,
    StoredDataId,
    WorkId,
    WorkspaceId,
)
from sastsimi.contracts.refs import RecordRef, StoredDataRef
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.evaluation.service import current_verdict_counts
from sastsimi.orchestration.fake_scenario_runtime import (
    FakeScenarioRuntime,
    WorkflowBundle,
)
from sastsimi.policy.service import PolicyPreparationService
from sastsimi.ports.dto import Record
from sastsimi.ports.fake_workflow import VerificationExecution
from sastsimi.reporting.service import validate_reporting_context
from sastsimi.reproduction.service import (
    DynamicReproductionService,
    ReproductionDependencies,
)
from sastsimi.runtime.fake_support import FakeEvidence
from sastsimi.runtime.services import RuntimeServices
from sastsimi.verification.service import select_revise_context

PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "src" / "sastsimi"


def _work_ref(value: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(f"stored-{value}"),
        data_kind="work_execution_state",
        content_hash=value * 64,
        workspace_id=WorkspaceId("workspace"),
        commit_id=CommitId("commit"),
        record_id=RecordId(f"record-{value}"),
    )


def _classes(path: Path) -> tuple[ast.ClassDef, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return tuple(node for node in ast.walk(tree) if isinstance(node, ast.ClassDef))


def test_domain_packages_own_reusable_fake_workflows() -> None:
    expected = {
        "policy/service.py": "PolicyPreparationService",
        "verification/debate_service.py": "DebateService",
        "verification/service.py": "VerificationService",
        "reproduction/service.py": "DynamicReproductionService",
        "chaining/service.py": "ChainingService",
        "reporting/service.py": "ReportingService",
        "evaluation/service.py": "EvaluationService",
    }

    missing: list[str] = []
    for relative, class_name in expected.items():
        path = PACKAGE_ROOT / relative
        if not path.is_file() or class_name not in {
            item.name for item in _classes(path)
        }:
            missing.append(f"{relative}:{class_name}")

    assert not missing, "Domain-owned fake workflows missing: " + ", ".join(missing)


def test_orchestration_has_no_shared_host_proxy_or_domain_stage_modules() -> None:
    orchestration = PACKAGE_ROOT / "orchestration"
    forbidden_modules = {
        "fake_dynamic.py",
        "fake_finalization.py",
        "fake_gates.py",
        "fake_verification.py",
        "fake_verification_initial.py",
    }
    remaining = sorted(
        path.name
        for path in orchestration.glob("*.py")
        if path.name in forbidden_modules
    )
    forbidden_classes = {
        item.name
        for path in orchestration.glob("*.py")
        for item in _classes(path)
        if item.name in {"FakePipelineBase", "FakeStageService"}
    }

    assert remaining == []
    assert forbidden_classes == set()


def test_domain_workflows_do_not_reach_back_into_orchestration() -> None:
    owners = (
        "policy",
        "verification",
        "reproduction",
        "chaining",
        "reporting",
        "evaluation",
    )
    violations: list[str] = []
    for owner in owners:
        for path in (PACKAGE_ROOT / owner).glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = tuple(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    names = (node.module or "",)
                else:
                    continue
                if any(name.startswith("sastsimi.orchestration") for name in names):
                    violations.append(str(path.relative_to(PACKAGE_ROOT)))

    assert violations == []


def test_composition_uses_typed_factory_instead_of_dynamic_service_lookup() -> None:
    bootstrap = (PACKAGE_ROOT / "bootstrap.py").read_text(encoding="utf-8")
    scenario = (PACKAGE_ROOT / "orchestration/fake_scenario_runtime.py").read_text(
        encoding="utf-8"
    )

    assert "**items" not in bootstrap
    assert 'items["' not in bootstrap
    assert "class WorkflowFactory(Protocol)" in scenario


def test_initial_and_revised_verification_share_generation_workflow() -> None:
    service = PACKAGE_ROOT / "verification/service.py"
    verification = next(
        item for item in _classes(service) if item.name == "VerificationService"
    )
    methods = {
        item.name: item
        for item in verification.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    for entrypoint in ("run_initial", "run_revised"):
        calls = {
            node.func.attr
            for node in ast.walk(methods[entrypoint])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert "_run_generation" in calls


def test_reporting_receives_the_exact_verification_work_for_each_call() -> None:
    """A later hypothesis must not overwrite an earlier reporting parent."""

    class RecordingReporting:
        def __init__(self) -> None:
            self.received: list[RecordRef] = []

        def _post_true(
            self,
            execution: VerificationExecution,
            **_: object,
        ) -> object:
            self.received.append(execution.work_ref)
            return object()

    first_ref = _work_ref("a")
    second_ref = _work_ref("b")
    reporting = RecordingReporting()
    scenario = object.__new__(FakeScenarioRuntime)
    scenario.workflows = cast(WorkflowBundle, SimpleNamespace(reporting=reporting))
    verification = cast(VerificationResult, object())

    hypothesis_ref = _work_ref("c").model_copy(
        update={"data_kind": "vulnerability_hypothesis"}
    )
    process_ref = _work_ref("d").model_copy(
        update={"data_kind": "hypothesis_process_state"}
    )
    first = VerificationExecution(
        verification, first_ref, hypothesis_ref, process_ref, 1
    )
    second = VerificationExecution(
        verification, second_ref, hypothesis_ref, process_ref, 2
    )

    scenario._post_true(first)
    scenario._post_true(second)

    assert reporting.received == [first_ref, second_ref]


def test_verification_execution_carries_exact_hypothesis_context() -> None:
    hypothesis_ref = _work_ref("c").model_copy(
        update={"data_kind": "vulnerability_hypothesis"}
    )
    process_ref = _work_ref("d").model_copy(
        update={"data_kind": "hypothesis_process_state"}
    )

    execution = VerificationExecution(
        result=cast(VerificationResult, object()),
        work_ref=_work_ref("e"),
        hypothesis_ref=hypothesis_ref,
        process_ref=process_ref,
        generation=2,
    )

    assert execution.hypothesis_ref == hypothesis_ref
    assert execution.process_ref == process_ref
    assert execution.generation == 2


def test_fake_evidence_scopes_outputs_and_rejects_identity_rebinding() -> None:
    evidence = FakeEvidence()
    identity = _work_ref("f")
    evidence.bind_identity(identity, RequesterRole.ORCHESTRATION)
    with pytest.raises(ValueError, match="FAKE_IDENTITY_ROLE_IMMUTABLE"):
        evidence.bind_identity(identity, RequesterRole.PRO)
    with pytest.raises(ValueError, match="FAKE_ROLE_IDENTITY_IMMUTABLE"):
        evidence.bind_identity(_work_ref("0"), RequesterRole.ORCHESTRATION)

    work = cast(
        WorkExecutionState,
        SimpleNamespace(
            work_id=WorkId("work-a"), active_attempt_id=AttemptId("attempt-a")
        ),
    )
    action = cast(
        ActionRequest,
        SimpleNamespace(
            action_id=ActionId("action-a"),
            work_ref=_work_ref("1"),
            meta=SimpleNamespace(attempt_id=AttemptId("attempt-a")),
        ),
    )
    other_action = cast(
        ActionRequest,
        SimpleNamespace(
            action_id=ActionId("action-b"),
            work_ref=action.work_ref,
            meta=SimpleNamespace(attempt_id=AttemptId("attempt-a")),
        ),
    )
    same_action_new_attempt = cast(
        ActionRequest,
        SimpleNamespace(
            action_id=action.action_id,
            work_ref=action.work_ref,
            meta=SimpleNamespace(attempt_id=AttemptId("attempt-b")),
        ),
    )
    same_action_other_work = cast(
        ActionRequest,
        SimpleNamespace(
            action_id=action.action_id,
            work_ref=_work_ref("9"),
            meta=SimpleNamespace(attempt_id=AttemptId("attempt-a")),
        ),
    )
    outputs = (_work_ref("2"),)
    other_outputs = (_work_ref("3"),)

    with evidence.output_approval(action, work, outputs):
        assert evidence.authorized_outputs(action) == outputs
        assert evidence.authorized_outputs(other_action) is None
        assert evidence.authorized_outputs(same_action_new_attempt) is None
        assert evidence.authorized_outputs(same_action_other_work) is None
        with evidence.output_approval(other_action, work, other_outputs):
            assert evidence.authorized_outputs(action) == outputs
            assert evidence.authorized_outputs(other_action) == other_outputs
    assert evidence.authorized_outputs(action) is None
    assert evidence.authorized_outputs(other_action) is None


def test_reproduction_owns_a_public_typed_workflow_and_publisher() -> None:
    assert hasattr(DynamicReproductionService, "run")
    assert not hasattr(DynamicReproductionService, "_dynamic_chain")
    assert not hasattr(DynamicReproductionService, "_evidence_result")
    assert "publish_intermediate" not in ReproductionDependencies.__dataclass_fields__
    assert not hasattr(PolicyPreparationService, "publish_intermediate")


def test_reproduction_publisher_rejects_unowned_kind_before_any_write() -> None:
    service = object.__new__(DynamicReproductionService)
    service.runtime = cast(
        RuntimeServices,
        SimpleNamespace(
            unit_of_work=SimpleNamespace(
                records=SimpleNamespace(
                    stage_record=lambda _record: pytest.fail(
                        "unowned result reached the record store"
                    )
                )
            )
        ),
    )
    record = cast(Record, SimpleNamespace(meta=SimpleNamespace(record_type="finding")))

    parameters = inspect.signature(service._publish_intermediate).parameters
    assert "role" not in parameters
    with pytest.raises(ValueError, match="REPRODUCTION_RESULT_KIND_NOT_ALLOWED"):
        service._publish_intermediate(cast(WorkExecutionState, object()), record)


def test_two_hypotheses_keep_revise_reporting_and_evaluation_context_isolated() -> None:
    """Cross-hypothesis state cannot be selected, reported or counted together."""

    def ref(value: str, kind: str) -> StoredDataRef:
        return _work_ref(value).model_copy(update={"data_kind": kind})

    hypothesis_a = cast(
        VulnerabilityHypothesis,
        SimpleNamespace(meta=SimpleNamespace(hypothesis_id="hyp-a")),
    )
    hypothesis_b = cast(
        VulnerabilityHypothesis,
        SimpleNamespace(meta=SimpleNamespace(hypothesis_id="hyp-b")),
    )
    result_ref_a = ref("4", "verification_result")
    result_ref_b = ref("5", "verification_result")
    process_a = cast(
        HypothesisProcessState,
        SimpleNamespace(
            meta=SimpleNamespace(hypothesis_id="hyp-a"),
            status="TERMINAL",
            verification_generation=2,
            verification_result_ref=result_ref_a,
        ),
    )
    process_b = cast(
        HypothesisProcessState,
        SimpleNamespace(
            meta=SimpleNamespace(hypothesis_id="hyp-b"),
            status="TERMINAL",
            verification_generation=1,
            verification_result_ref=result_ref_b,
        ),
    )

    selected_hypothesis, selected_process = select_revise_context(
        (hypothesis_b, hypothesis_a),
        (process_b, process_a),
        "hyp-a",
    )
    assert selected_hypothesis is hypothesis_a
    assert selected_process is process_a

    verification_a = VerificationResult.model_construct(
        meta=SimpleNamespace(hypothesis_id="hyp-a"), verdict="TRUE"
    )
    verification_b = VerificationResult.model_construct(
        meta=SimpleNamespace(hypothesis_id="hyp-b"), verdict="HOLD"
    )
    process_ref_a = ref("8", "hypothesis_process_state")
    execution_a = VerificationExecution(
        verification_a,
        ref("6", "work_execution_state"),
        ref("7", "vulnerability_hypothesis"),
        process_ref_a,
        2,
    )
    work_a = cast(
        WorkExecutionState,
        SimpleNamespace(
            meta=SimpleNamespace(hypothesis_id="hyp-a"),
            work_generation=2,
            status="SUCCEEDED",
            output_refs=(result_ref_a,),
        ),
    )
    validate_reporting_context(
        execution_a,
        hypothesis_a,
        process_a,
        work_a,
        result_ref_a,
        process_ref_a,
        process_ref_a,
    )
    with pytest.raises(ValueError, match="REPORTING_VERIFICATION_CONTEXT_MISMATCH"):
        validate_reporting_context(
            execution_a,
            hypothesis_b,
            process_b,
            work_a,
            result_ref_a,
            process_ref_a,
            process_ref_a,
        )

    stale_ref = ref("a", "hypothesis_process_state")
    same_hypothesis_negatives = (
        cast(
            HypothesisProcessState,
            SimpleNamespace(
                meta=SimpleNamespace(hypothesis_id="hyp-a"),
                status="RUNNING",
                verification_generation=2,
                verification_result_ref=result_ref_a,
            ),
        ),
        cast(
            HypothesisProcessState,
            SimpleNamespace(
                meta=SimpleNamespace(hypothesis_id="hyp-a"),
                status="TERMINAL",
                verification_generation=1,
                verification_result_ref=result_ref_a,
            ),
        ),
        cast(
            HypothesisProcessState,
            SimpleNamespace(
                meta=SimpleNamespace(hypothesis_id="hyp-a"),
                status="TERMINAL",
                verification_generation=2,
                verification_result_ref=result_ref_b,
            ),
        ),
    )
    for stale_process in same_hypothesis_negatives:
        with pytest.raises(ValueError, match="REPORTING_VERIFICATION_CONTEXT_MISMATCH"):
            validate_reporting_context(
                execution_a,
                hypothesis_a,
                stale_process,
                work_a,
                result_ref_a,
                process_ref_a,
                process_ref_a,
            )
    with pytest.raises(ValueError, match="REPORTING_VERIFICATION_CONTEXT_MISMATCH"):
        validate_reporting_context(
            execution_a,
            hypothesis_a,
            process_a,
            work_a,
            result_ref_a,
            process_ref_a,
            stale_ref,
        )
    with pytest.raises(ValueError, match="REPORTING_VERIFICATION_CONTEXT_MISMATCH"):
        validate_reporting_context(
            execution_a,
            hypothesis_a,
            process_a,
            work_a,
            result_ref_a,
            stale_ref,
            process_ref_a,
        )

    resolved = {result_ref_a: verification_a, result_ref_b: verification_b}

    def load(value: RecordRef) -> Any:
        assert isinstance(value, StoredDataRef)
        return resolved[value]

    assert current_verdict_counts((process_b, process_a), load) == {
        "TRUE": 1,
        "HOLD": 1,
    }
