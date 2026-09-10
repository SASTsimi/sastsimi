"""Thin public coordinator for deterministic fake analysis scenarios."""

from collections.abc import Callable
from pathlib import Path

from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.reporting import ReportDraft
from sastsimi.ports.fake_workflow import (
    NoMatchBuilder,
    PolicyFetcher,
    ProviderInvoker,
    ProviderProber,
    SandboxCleaner,
    SandboxExecutor,
    SandboxPreparer,
    StaticInvoker,
)
from sastsimi.ports.verification_assembly import VerificationAssemblyPort
from sastsimi.runtime.services import RuntimeServices

from .fake_scenario_runtime import FakeScenarioRuntime, WorkflowFactory


class FakePipeline:
    """Public query/command facade composed around the internal stage runtime."""

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
        self._scenario = FakeScenarioRuntime(
            data_dir,
            runtime_builder,
            database_upgrader,
            provider_invoke,
            provider_probe,
            static_invoke,
            sandbox_prepare,
            sandbox_execute,
            sandbox_cleanup,
            policy_fetch,
            no_match_builder,
            verification_assembly,
            workflow_factory,
            persisted_result=persisted_result,
            persisted_reports=persisted_reports,
        )

    @property
    def runtime(self) -> RuntimeServices | None:
        return self._scenario.runtime

    def analyze(self, *, scenario: str = "TRUE") -> AnalysisRunResult:
        return self._scenario.analyze(scenario=scenario)

    def results(self) -> AnalysisRunResult:
        return self._scenario.results()

    def reports(self) -> tuple[ReportDraft, ...]:
        return self._scenario.reports()
