"""Trusted terminal analysis projection port."""

from typing import Protocol

from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.refs import RunStoredDataRef


class AnalysisFinalizationPort(Protocol):
    def finalize(self, result: AnalysisRunResult) -> RunStoredDataRef: ...
