"""Typed configuration publication is host-approved and exact-reference closed."""

from pathlib import Path

import pytest

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.llm import ProviderProfile, ProviderValidationEvidence
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
