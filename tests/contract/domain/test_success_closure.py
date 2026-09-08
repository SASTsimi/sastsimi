from typing import Any

import pytest

from sastsimi.contracts.dynamic import (
    DynamicReproductionResult,
    validate_dynamic_closure,
    validate_environment,
)
from sastsimi.contracts.gates import (
    CWELabel,
    TechnicalEvidenceReview,
    validate_technical_gate,
)
from sastsimi.contracts.verification import VerificationResult, validate_dynamic_verdict

from .canonical_fixtures import make
from .fixtures import wire
from .success_fixture import bound, dynamic_success


def check_dynamic(chain: dict[str, Any]) -> None:
    validate_dynamic_closure(
        chain["result"],
        chain["request"],
        chain["log"],
        generation=1,
        **{
            key: chain[key]
            for key in (
                "plan",
                "recipe",
                "environment",
                "candidate",
                "poc",
                "conclusion",
                "policy",
                "cleanup",
            )
        },
    )


def test_successful_executed_poc_and_environment_closure() -> None:
    chain = dynamic_success()
    check_dynamic(chain)
    validate_environment(
        chain["environment"], chain["requirements"], chain["plan"], chain["recipe"]
    )


@pytest.mark.parametrize(
    "key",
    [
        "plan",
        "recipe",
        "environment",
        "candidate",
        "poc",
        "conclusion",
        "policy",
        "cleanup",
        "log",
    ],
)
def test_same_attempt_artifacts_cannot_be_replaced_by_other_attempt(key: str) -> None:
    chain = dynamic_success()
    original = chain[key]
    payload = original.model_dump(mode="json")
    payload["meta"]["attempt_id"] = "previous-attempt"
    chain[key] = wire(type(original), payload)
    with pytest.raises(ValueError):
        check_dynamic(chain)


def test_conclusion_interpretation_cannot_be_rewritten_by_session_manager() -> None:
    chain = dynamic_success()
    chain["result"] = wire(
        DynamicReproductionResult,
        chain["result"].model_dump(mode="json")
        | {"hypothesis_linkage": "Changed interpretation"},
    )
    with pytest.raises(ValueError, match="DYNAMIC_CONCLUSION_DRIFT"):
        check_dynamic(chain)


def test_cwe_must_be_reevaluated_for_current_verification_revision() -> None:
    chain = dynamic_success()
    verification = wire(
        VerificationResult,
        make("VerificationResult")
        | dict(
            initial_verdict="TRUE",
            verdict="TRUE",
            dynamic_request_ref=bound(chain["request"]),
            dynamic_result_ref=bound(chain["result"]),
            poc_ref=bound(chain["poc"]),
        ),
    )
    validate_dynamic_verdict(
        verification, chain["request"], chain["result"], chain["poc"], generation=1
    )
    label = wire(
        CWELabel,
        make("CWELabel", "cwe_label")
        | dict(verification_result_ref=bound(verification)),
    )
    technical = wire(
        TechnicalEvidenceReview,
        make("TechnicalEvidenceReview")
        | dict(verification_result_ref=bound(verification), cwe_label_ref=bound(label)),
    )
    validate_technical_gate(
        technical,
        verification,
        label,
        chain["result"],
        chain["poc"],
        current_generation=1,
    )
    with pytest.raises(ValueError, match="STALE_RESULT"):
        validate_technical_gate(
            technical,
            verification,
            label,
            chain["result"],
            chain["poc"],
            current_generation=2,
        )
