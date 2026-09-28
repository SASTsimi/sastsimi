"""A model cannot silently omit policy limits or invent PoC compliance."""

from __future__ import annotations

from sastsimi.simple_runtime.scope_policy import validate_scope_decision

_POLICY = "\n".join(
    (
        "# Security policy",
        "Any researcher may report vulnerabilities.",
        "The application repository is in scope.",
        "Security vulnerabilities are eligible.",
        "Local proof-of-concept testing is permitted.",
        "Private reports are accepted.",
        "Do not scan production servers.",
    )
)
_POC = "#!/bin/sh\necho local proof\n"
_AXES = ("rules", "asset_scope", "impact", "testing", "reporting")


def _model() -> dict[str, object]:
    lines = _POLICY.splitlines()
    return {
        "rationale": "Local testing and private reporting meet the policy.",
        "restrictions": [],
        "testing_restriction_compliance": "PASS",
        "testing_poc_quote": "echo local proof",
        "axes": {
            name: {
                "status": "PASS",
                "line": index,
                "quote": lines[index - 1],
                "reason": "Applies to this local PoC.",
            }
            for index, name in enumerate(_AXES, start=2)
        },
    }


def test_omitted_explicit_testing_restriction_cannot_allow() -> None:
    result = validate_scope_decision(
        {"status": "FOUND"}, _POLICY, _model(), poc_evidence_text=_POC
    )

    assert result["status"] == "UNCERTAIN"
    assert "testing" in result["missing_information"]


def test_testing_pass_requires_exact_quote_from_validated_poc() -> None:
    model = _model()
    model["restrictions"] = ["Do not scan production servers."]
    model["testing_poc_quote"] = "a fabricated safe test"

    result = validate_scope_decision(
        {"status": "FOUND"}, _POLICY, model, poc_evidence_text=_POC
    )

    assert result["status"] == "UNCERTAIN"
    assert "testing" in result["missing_information"]


def test_exact_limit_and_actual_poc_quote_still_need_human_review() -> None:
    model = _model()
    model["restrictions"] = ["Do not scan production servers."]

    result = validate_scope_decision(
        {"status": "FOUND"}, _POLICY, model, poc_evidence_text=_POC
    )

    assert result["status"] == "UNCERTAIN"
    assert result["axes"]["testing"]["reason"] == (
        "POLICY_RESTRICTIONS_REQUIRE_HUMAN_REVIEW"
    )


def test_no_production_scans_is_a_restriction_candidate() -> None:
    result = validate_scope_decision(
        {"status": "FOUND"},
        _POLICY.replace("Do not scan production servers.", "No production scans."),
        _model(),
        poc_evidence_text=_POC,
    )

    assert result["status"] == "UNCERTAIN"


def test_safe_quote_does_not_override_other_unsafe_poc_lines() -> None:
    model = _model()
    model["restrictions"] = ["Do not scan production servers."]

    result = validate_scope_decision(
        {"status": "FOUND"},
        _POLICY,
        model,
        poc_evidence_text=_POC + "curl https://production.example.com/scan\n",
    )

    assert result["status"] == "UNCERTAIN"
