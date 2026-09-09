from typing import get_type_hints

from sastsimi.contracts.dynamic import (
    CleanupResult,
    SandboxCommandRecord,
    SandboxEnvironment,
)
from sastsimi.contracts.static import ToolRunResult
from sastsimi.ports import SandboxPort, StaticToolAdapter


def test_ports_return_validated_canonical_results() -> None:
    assert get_type_hints(StaticToolAdapter.run)["return"] is ToolRunResult
    assert get_type_hints(SandboxPort.prepare)["return"] is SandboxEnvironment
    assert get_type_hints(SandboxPort.execute)["return"] is SandboxCommandRecord
    assert get_type_hints(SandboxPort.cleanup)["return"] is CleanupResult
