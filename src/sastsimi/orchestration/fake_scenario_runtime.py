"""Internal deterministic scenario executor composed by the public coordinator."""

from typing import Any

from sastsimi.contracts.evaluation import AnalysisRunResult

from .fake_base import FakePipelineBase
from .fake_dynamic import FakeDynamicStages
from .fake_finalization import FakeFinalizationStages
from .fake_gates import FakeGateStages
from .fake_setup import FakeSetupStages
from .fake_verification import FakeVerificationStages
from .fake_verification_initial import FakeInitialVerificationStages


class FakeScenarioRuntime(FakePipelineBase):
    """Execute one scenario while stage services retain their narrow seams."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.setup_stages = FakeSetupStages(self)
        self.dynamic_stages = FakeDynamicStages(self, self.setup_stages)
        self.initial_verification_stages = FakeInitialVerificationStages(
            self, self.setup_stages, self.dynamic_stages
        )
        self.verification_stages = FakeVerificationStages(
            self, self.setup_stages, self.dynamic_stages
        )
        self.gate_stages = FakeGateStages(self)
        self.finalization_stages = FakeFinalizationStages(self)

    def _verification(self, *args: Any, **kwargs: Any) -> Any:
        return self.initial_verification_stages._verification(*args, **kwargs)

    def _post_true(self, *args: Any, **kwargs: Any) -> Any:
        return self.gate_stages._post_true(*args, **kwargs)

    def _result_candidate(self, *args: Any, **kwargs: Any) -> Any:
        return self.finalization_stages._result_candidate(*args, **kwargs)

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
        verification = self.initial_verification_stages._verification(
            (
                "TRUE"
                if normalized in {"TRUE", "REVISE", "CHAINING", "TRUE_WITHOUT_POC"}
                else normalized
            ),
            invalid_poc=normalized == "TRUE_WITHOUT_POC",
        )
        if normalized == "REVISE":
            revision = self.gate_stages._post_true(
                verification, technical_status="REVISE"
            )
            verification = self.verification_stages._revised_verification(
                verification, revision
            )
            self.gate_stages._post_true(verification)
        elif normalized in {"TRUE", "CHAINING"}:
            self.gate_stages._post_true(verification)
        return self.finalization_stages._finish(
            "TRUE" if normalized == "CHAINING" else normalized
        )
