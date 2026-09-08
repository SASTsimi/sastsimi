import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import Finding, condition_sources
from sastsimi.contracts.verification import VerificationResult

from .canonical_fixtures import make
from .fixtures import wire
from .success_fixture import bound


def test_finding_condition_paths_preserve_all_original_values() -> None:
    from sastsimi.contracts.reporting import validate_finding_conditions

    verification = wire(VerificationResult, make("VerificationResult"))
    reference = wire(StoredDataRef, bound(verification))
    sources = condition_sources(((reference, verification),))
    finding = wire(
        Finding,
        make("Finding")
        | dict(
            verification_result_ref=bound(verification),
            condition_sources=[item.model_dump(mode="json") for item in sources],
        ),
    )
    restrictions, limitations, unresolved = validate_finding_conditions(
        finding, ((reference, verification),)
    )
    assert restrictions == ()
    assert limitations == ()
    assert unresolved == ("Reachability",)
    with pytest.raises(ValueError, match="CONDITION_CLOSURE_MISMATCH"):
        validate_finding_conditions(
            wire(Finding, finding.model_dump(mode="json") | {"condition_sources": []}),
            ((reference, verification),),
        )
    changed = sources[0].model_dump(mode="json") | {
        "source_path": "/metrics/elapsed_ms"
    }
    with pytest.raises(ValueError, match="CONDITION_CLOSURE_MISMATCH"):
        validate_finding_conditions(
            wire(
                Finding,
                finding.model_dump(mode="json") | {"condition_sources": [changed]},
            ),
            ((reference, verification),),
        )
