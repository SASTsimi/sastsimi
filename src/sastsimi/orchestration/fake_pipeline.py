"""Thin public coordinator for deterministic fake analysis scenarios."""

from sastsimi.contracts.evaluation import AnalysisRunResult

from .fake_finalization import FakeFinalizationStages


class FakePipeline(FakeFinalizationStages):
    def analyze(self, *, scenario: str = "TRUE") -> AnalysisRunResult:
        if self._result.status == "COMPLETE":
            return self._result
        normalized = scenario.upper()
        if normalized == "TRUE_WITHOUT_POC":
            raise ValueError("POC current validated PoC is required for TRUE")
        if normalized not in {"TRUE", "FALSE", "HOLD", "REVISE", "CHAINING"}:
            raise ValueError(f"UNKNOWN_FAKE_SCENARIO: {scenario}")
        verification = self._verification(
            "TRUE" if normalized in {"TRUE", "REVISE", "CHAINING"} else normalized
        )
        if normalized == "REVISE":
            revision = self._post_true(verification, technical_status="REVISE")
            verification = self._revised_verification(verification, revision)
            self._post_true(verification)
        elif normalized in {"TRUE", "CHAINING"}:
            self._post_true(verification)
        return self._finish("TRUE" if normalized == "CHAINING" else normalized)
