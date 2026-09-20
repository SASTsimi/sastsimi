from __future__ import annotations

from typing import cast

from sastsimi.capabilities.composition import ProductionCapabilityProbeService
from sastsimi.ports.trusted_evidence import TrustedEvidencePort


def test_facade_exposes_the_exact_read_only_evidence_authority() -> None:
    service = ProductionCapabilityProbeService.__new__(
        ProductionCapabilityProbeService
    )
    authority = object()
    service._ProductionCapabilityProbeService__evidence = authority

    assert service.trusted_evidence() is cast(TrustedEvidencePort, authority)
