"""Thin deterministic scenario sequencer over injected domain workflows."""

from collections.abc import Callable
from pathlib import Path
from typing import Literal, Protocol

from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.gates import TechnicalEvidenceReview
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import ReportDraft
from sastsimi.contracts.static import CodeLocation
from sastsimi.contracts.verification import VerificationResult
from sastsimi.ports.fake_workflow import (
    InitialVerificationInputs,
    NoMatchBuilder,
    PolicyFetcher,
    PolicyPreparationPort,
    ProviderInvoker,
    ProviderProber,
    SandboxCleaner,
    SandboxExecutor,
    SandboxPreparer,
    StaticInvoker,
    VerificationExecution,
)
from sastsimi.ports.verification_assembly import VerificationAssemblyPort
from sastsimi.runtime.fake_support import (
    FakeClock,
    FakeEvidence,
    FakeIds,
    FakeRecordFactory,
)
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .fake_setup import FakeSetupDependencies, FakeSetupStages


class VerificationWorkflow(Protocol):
    def run_initial(
        self,
        inputs: InitialVerificationInputs,
        verdict: str,
        *,
        invalid_poc: bool,
        material_child: bool,
    ) -> VerificationExecution: ...

    def run_revised(
        self, prior: VerificationResult, review: TechnicalEvidenceReview
    ) -> VerificationExecution: ...


class ReportingWorkflow(Protocol):
    def _post_true(
        self,
        execution: VerificationExecution,
        *,
        technical_status: Literal["ACCEPT", "REVISE"] = "ACCEPT",
        admission_decision: Literal["ALLOW", "DENY"] = "ALLOW",
        publish_denied_primitive: bool = False,
        stop_after_chaining: bool = False,
    ) -> TechnicalEvidenceReview: ...


class EvaluationWorkflow(Protocol):
    reports: tuple[ReportDraft, ...]

    def _result_candidate(self, verdict: str) -> AnalysisRunResult: ...

    def _finish(self, verdict: str) -> AnalysisRunResult: ...


class WorkflowBundle(Protocol):
    @property
    def policy(self) -> PolicyPreparationPort: ...

    @property
    def verification(self) -> VerificationWorkflow: ...

    @property
    def reporting(self) -> ReportingWorkflow: ...

    @property
    def evaluation(self) -> EvaluationWorkflow: ...


class WorkflowFactory(Protocol):
    def __call__(
        self,
        *,
        runtime: RuntimeServices,
        runner: WorkflowRunner,
        clock: FakeClock,
        ids: FakeIds,
        evidence: FakeEvidence,
        records: FakeRecordFactory,
        provider_invoke: ProviderInvoker,
        provider_probe: ProviderProber,
        sandbox_prepare: SandboxPreparer,
        sandbox_execute: SandboxExecutor,
        sandbox_cleanup: SandboxCleaner,
        policy_fetch: PolicyFetcher,
        no_match_builder: NoMatchBuilder,
        verification_assembly: VerificationAssemblyPort,
        context_service_identity_ref: StoredDataRef,
        location: Callable[[], CodeLocation],
    ) -> WorkflowBundle: ...


class FakeScenarioRuntime:
    """Register and sequence domain services while retaining public test seams."""

    def __init__(
        self,
        data_dir: Path,
        runtime_builder: Callable[..., RuntimeServices],
        database_upgrader: Callable[[Path], None],
        provider_invoke: ProviderInvoker,
        provider_probe: ProviderProber,
        static_invoke: StaticInvoker,
        sandbox_prepare: SandboxPreparer,
        sandbox_execute: SandboxExecutor,
        sandbox_cleanup: SandboxCleaner,
        policy_fetch: PolicyFetcher,
        no_match_builder: NoMatchBuilder,
        verification_assembly: VerificationAssemblyPort,
        workflow_factory: WorkflowFactory,
        persisted_result: AnalysisRunResult | None = None,
        persisted_reports: tuple[ReportDraft, ...] = (),
    ) -> None:
        self.data_dir = data_dir
        self.runtime_builder = runtime_builder
        self.database_upgrader = database_upgrader
        self.provider_invoke = provider_invoke
        self.provider_probe = provider_probe
        self.static_invoke = static_invoke
        self.sandbox_prepare = sandbox_prepare
        self.sandbox_execute = sandbox_execute
        self.sandbox_cleanup = sandbox_cleanup
        self.policy_fetch = policy_fetch
        self.no_match_builder = no_match_builder
        self.verification_assembly = verification_assembly
        self.workflow_factory = workflow_factory
        self.clock = FakeClock()
        self.ids = FakeIds()
        self.evidence = FakeEvidence()
        self.records = FakeRecordFactory(self.clock, self.ids)
        self.runtime: RuntimeServices | None = None
        self.runner: WorkflowRunner | None = None
        self._result = persisted_result
        self._reports = persisted_reports
        self.setup_stages: FakeSetupStages | None = None
        self.workflows: WorkflowBundle | None = None

    def _verification(
        self,
        verdict: str,
        *,
        invalid_poc: bool = False,
        material_child: bool = False,
    ) -> VerificationExecution:
        setup = FakeSetupStages(
            FakeSetupDependencies(
                data_dir=self.data_dir,
                runtime_builder=self.runtime_builder,
                database_upgrader=self.database_upgrader,
                provider_invoke=self.provider_invoke,
                provider_probe=self.provider_probe,
                policy_fetch=self.policy_fetch,
                clock=self.clock,
                ids=self.ids,
                evidence=self.evidence,
                records=self.records,
            )
        )
        scope, owner_ref, orchestrator_ref = setup._bootstrap()
        assert setup.runtime is not None and setup.runner is not None
        assert setup.context_service_identity_ref is not None
        self.runtime, self.runner = setup.runtime, setup.runner
        workflows = self.workflow_factory(
            runtime=self.runtime,
            runner=self.runner,
            clock=self.clock,
            ids=self.ids,
            evidence=self.evidence,
            records=self.records,
            provider_invoke=self.provider_invoke,
            provider_probe=self.provider_probe,
            sandbox_prepare=self.sandbox_prepare,
            sandbox_execute=self.sandbox_execute,
            sandbox_cleanup=self.sandbox_cleanup,
            policy_fetch=self.policy_fetch,
            no_match_builder=self.no_match_builder,
            verification_assembly=self.verification_assembly,
            context_service_identity_ref=setup.context_service_identity_ref,
            location=setup._location,
        )
        setup.bind_policy_service(workflows.policy)
        prepared = setup.prepare_initial(
            scope, owner_ref, orchestrator_ref, self.static_invoke
        )
        self.setup_stages = setup
        self.workflows = workflows
        return workflows.verification.run_initial(
            prepared,
            verdict,
            invalid_poc=invalid_poc,
            material_child=material_child,
        )

    def _revised_verification(
        self, prior: VerificationResult, review: TechnicalEvidenceReview
    ) -> VerificationExecution:
        if self.workflows is None:
            raise RuntimeError("FAKE_WORKFLOWS_NOT_READY")
        return self.workflows.verification.run_revised(prior, review)

    def _post_true(
        self,
        execution: VerificationExecution,
        *,
        technical_status: Literal["ACCEPT", "REVISE"] = "ACCEPT",
        admission_decision: Literal["ALLOW", "DENY"] = "ALLOW",
        publish_denied_primitive: bool = False,
        stop_after_chaining: bool = False,
    ) -> TechnicalEvidenceReview:
        if self.workflows is None:
            raise RuntimeError("FAKE_WORKFLOWS_NOT_READY")
        return self.workflows.reporting._post_true(
            execution,
            technical_status=technical_status,
            admission_decision=admission_decision,
            publish_denied_primitive=publish_denied_primitive,
            stop_after_chaining=stop_after_chaining,
        )

    def _result_candidate(self, verdict: str) -> AnalysisRunResult:
        if self.workflows is None:
            raise RuntimeError("FAKE_WORKFLOWS_NOT_READY")
        return self.workflows.evaluation._result_candidate(verdict)

    def _finish(self, verdict: str) -> AnalysisRunResult:
        if self.workflows is None:
            raise RuntimeError("FAKE_WORKFLOWS_NOT_READY")
        result = self.workflows.evaluation._finish(verdict)
        self._result = result
        self._reports = self.workflows.evaluation.reports
        return result

    def analyze(self, *, scenario: str = "TRUE") -> AnalysisRunResult:
        if self._result is not None and self._result.status == "COMPLETE":
            return self._result
        normalized = scenario.upper()
        if normalized not in {
            "TRUE",
            "FALSE",
            "HOLD",
            "REVISE",
            "CHAINING",
            "TRUE_WITHOUT_POC",
        }:
            raise ValueError(f"UNKNOWN_FAKE_SCENARIO: {scenario}")
        execution = self._verification(
            "TRUE"
            if normalized in {"TRUE", "REVISE", "CHAINING", "TRUE_WITHOUT_POC"}
            else normalized,
            invalid_poc=normalized == "TRUE_WITHOUT_POC",
        )
        verification = execution.result
        if normalized == "REVISE":
            revision = self._post_true(
                execution,
                technical_status="REVISE",
            )
            execution = self._revised_verification(verification, revision)
            verification = execution.result
            self._post_true(execution)
        elif normalized in {"TRUE", "CHAINING"}:
            self._post_true(execution)
        return self._finish("TRUE" if normalized == "CHAINING" else normalized)

    def results(self) -> AnalysisRunResult:
        if self._result is None:
            raise LookupError("ANALYSIS_RESULT_NOT_FOUND")
        return self._result

    def reports(self) -> tuple[ReportDraft, ...]:
        return self._reports
