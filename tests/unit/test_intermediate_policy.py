"""Canonical intermediate ownership stays closed and separate from Agent registry."""

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.verification import VerificationInitialAssessment
from sastsimi.storage.codec import decode, encode
from sastsimi.storage.intermediate_policy import INTERMEDIATE_KINDS
from tests.contract.domain.canonical_fixtures import make


def test_exact_intermediate_inventory() -> None:
    assert INTERMEDIATE_KINDS == frozenset(
        {
            ("WORKSPACE_PREP", "code_workspace", "REPOSITORY_LOADER"),
            ("POLICY_FETCH", "policy_parser_result", "POLICY_PARSER"),
            ("VERIFICATION", "verification_initial_assessment", "VERIFICATION"),
            ("VERIFICATION", "dynamic_reproduction_request", "VERIFICATION"),
            ("DYNAMIC_REPRO", "environment_requirements", "DYNAMIC_REPRODUCTION"),
            ("DYNAMIC_REPRO", "reproduction_plan", "DYNAMIC_REPRODUCTION"),
            ("DYNAMIC_REPRO", "environment_recipe", "REPRODUCTION_SETUP_AUTOMATION"),
            ("DYNAMIC_REPRO", "sandbox_environment", "REPRODUCTION_SETUP_AUTOMATION"),
            ("DYNAMIC_REPRO", "cleanup_result", "REPRODUCTION_SETUP_AUTOMATION"),
            ("DYNAMIC_REPRO", "sandbox_policy_decision", "SANDBOX_CONTROLLER"),
            ("DYNAMIC_REPRO", "sandbox_command_record", "REPRODUCTION_SESSION_MANAGER"),
            ("DYNAMIC_REPRO", "poc_candidate", "DYNAMIC_REPRODUCTION"),
            (
                "DYNAMIC_REPRO",
                "dynamic_reproduction_conclusion",
                "DYNAMIC_REPRODUCTION",
            ),
            ("DYNAMIC_REPRO", "agent_log", "REPRODUCTION_SESSION_MANAGER"),
            ("DYNAMIC_REPRO", "poc_bundle", "REPRODUCTION_SESSION_MANAGER"),
            (
                "DYNAMIC_REPRO",
                "dynamic_reproduction_tool_request",
                "DYNAMIC_REPRODUCTION",
            ),
        }
    )


def test_initial_assessment_has_canonical_verification_owner() -> None:
    from sastsimi.contracts.result_registry import RESULT_REGISTRY

    assessment = VerificationInitialAssessment.model_validate_json(
        canonical_bytes(make("VerificationInitialAssessment")),
    )
    assert decode("verification_initial_assessment", encode(assessment)) == assessment
    assert RESULT_REGISTRY["verification_initial_assessment"].owner == "VERIFICATION"


def test_context_response_has_trusted_non_agent_owner() -> None:
    from sastsimi.contracts.result_registry import RESULT_REGISTRY

    assert RESULT_REGISTRY["code_context_response"].owner == "CONTEXT_RETRIEVAL_SERVICE"
