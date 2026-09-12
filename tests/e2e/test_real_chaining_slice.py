from __future__ import annotations

import pytest

from sastsimi.bootstrap import install_t13_services
from sastsimi.contracts.ids import AnalysisId
from sastsimi.contracts.work import WorkType
from tests.integration.chaining.test_t13_production_composition import (
    _build,
    _composition,
    _run_dir,
)
from tests.integration.chaining.test_true_hold_true_true import _as_ref, _context


@pytest.mark.asyncio
async def test_production_builder_exposes_handler_and_startup_recovery() -> None:
    services = _build(_composition(_run_dir("real-slice")))
    installation = install_t13_services(services)

    recovered = installation.reconcile_startup(AnalysisId("empty-analysis"))

    assert recovered.primitive_update_refs == ()
    assert recovered.chaining_result_refs == ()

    trigger = _as_ref("primitive", "trigger")
    context = _context((trigger,), trigger)
    with pytest.raises(LookupError, match="^Exact record is not published$"):
        await installation.work_handlers[WorkType.CHAINING].execute(context)
