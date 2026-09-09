"""Typed configuration publication is host-approved and exact-reference closed."""

from pathlib import Path

import pytest

from sastsimi.bootstrap import build_fake_pipeline, build_runtime
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.llm import (
    LLMCallSpec,
    ProviderProfile,
    ProviderValidationEvidence,
)
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.storage.codec import reference
from tests.contract.domain.canonical_fixtures import make
from tests.integration.runtime_support import Harness


def test_typed_registries_require_family_evidence_and_exact_closure(
    tmp_path: Path,
) -> None:
    h = Harness(tmp_path)
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    configs = getattr(runtime, "configuration", None)
    assert configs is not None, "Typed configuration registries are missing"

    book = VerificationPlaybook.model_validate_json(
        canonical_bytes(
            make("VerificationPlaybook")
            | {"meta": make("VerificationPlaybook")["meta"] | {"attempt_id": None}}
        )
    )
    policy = PlaybookPolicy.model_validate_json(
        canonical_bytes(
            make("PlaybookPolicy")
            | {
                "meta": make("PlaybookPolicy")["meta"] | {"attempt_id": None},
                "common_playbook_ref": reference(book),
            }
        )
    )
    with pytest.raises(ValueError, match="CONFIGURATION_APPROVAL_REQUIRED"):
        configs.register_playbook(book)
    h.evidence.playbook_approvals.add(content_hash(book))
    assert configs.register_playbook(book) == reference(book)
    h.evidence.playbook_approvals.add(content_hash(policy))
    assert configs.register_playbook_policy(policy) == reference(policy)

    validation = ProviderValidationEvidence.model_validate_json(
        canonical_bytes(make("ProviderValidationEvidence"))
    )
    h.evidence.llm_configuration_approvals.add(content_hash(validation))
    with pytest.raises(ValueError, match="PROVIDER_VALIDATION_INCOMPLETE"):
        configs.register_provider_validation(validation)
    validation = ProviderValidationEvidence.model_validate(
        validation.model_dump()
        | {
            "tests": tuple(
                dict(
                    test_id=f"PVD-{index:02d}",
                    result="PASS",
                    evidence_refs=(reference(book),),
                    safe_summary="Deterministic fake probe passed",
                )
                for index in range(1, 17)
            )
        }
    )
    profile = ProviderProfile.model_validate_json(
        canonical_bytes(
            make("ProviderProfile") | {"validation_evidence_ref": reference(validation)}
        )
    )
    h.evidence.llm_configuration_approvals.update(
        {content_hash(validation), content_hash(profile)}
    )
    with pytest.raises(LookupError, match="Exact record is not published"):
        configs.register_provider_profile(profile)
    assert configs.register_provider_validation(validation) == reference(validation)
    assert configs.register_provider_profile(profile) == reference(profile)

    sandbox = SandboxProfile.model_validate_json(
        canonical_bytes(make("SandboxProfile"))
    )
    h.evidence.sandbox_approvals.add(content_hash(sandbox))
    assert configs.register_sandbox_profile(sandbox) == reference(sandbox)


def test_llm_call_spec_rejects_every_cross_record_mismatch(tmp_path: Path) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    pipeline.analyze(scenario="FALSE")
    assert pipeline.runtime is not None
    calls = tuple(
        item
        for item in pipeline.runtime.queries.current_records(
            "fake-analysis", "llm_call_spec"
        )
        if isinstance(item, LLMCallSpec)
    )
    assert len(calls) >= 2
    target, foreign = calls[:2]
    mismatches = (
        {"model": "unsupported-model"},
        {"provider_profile_ref": foreign.provider_profile_ref},
        {"purpose": "EVALUATION"},
        {"prompt_payload_ref": foreign.prompt_payload_ref},
        {"output_schema_ref": foreign.output_schema_ref},
        {"execution_limits_ref": foreign.execution_limits_ref},
        {"context_refs": ()},
    )
    for changes in mismatches:
        with pytest.raises(ValueError, match="LLM_CONFIGURATION_CLOSURE_MISMATCH"):
            pipeline.runtime.configuration.register_call_spec(
                target.model_copy(update=changes)
            )
