"""Concrete production composition root.

This module intentionally has no Fake imports. The composition remains
fail-closed until every production dependency has been supplied behind this
single factory, so the CLI can never silently select demo behavior.
"""

from pathlib import Path

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.contracts.analysis import AnalysisStartRequest

from .production_entrypoint import ScopeOwnedProductionApplication
from .run_scope_plan import PlannedRunScope


class ConcreteProductionApplicationFactory:
    """Build one exact production run after its approved inputs are available."""

    def build(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: ProductionProfile,
        scope: PlannedRunScope,
    ) -> ScopeOwnedProductionApplication:
        del data_dir, request, profile, scope
        from sastsimi.interfaces.cli.analyze import ProductionAnalyzeUnavailable

        raise ProductionAnalyzeUnavailable("production composition is incomplete")


__all__ = ["ConcreteProductionApplicationFactory"]
