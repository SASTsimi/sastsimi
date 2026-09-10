"""Public trusted finalization facade."""

from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.refs import RunStoredDataRef
from sastsimi.ports.analysis_finalization import AnalysisFinalizationPort


class AnalysisFinalizationService:
    def __init__(self, store: AnalysisFinalizationPort) -> None:
        self.store = store

    def finalize(self, result: AnalysisRunResult) -> RunStoredDataRef:
        return self.store.finalize(result)
