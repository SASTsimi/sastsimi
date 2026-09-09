"""Governance references are exact external provenance, not local result records."""

from pathlib import Path

import pytest

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.budget import ExecutionBudgetProfile
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.ids import RecordId
from sastsimi.storage.codec import reference
from tests.integration.runtime_support import Harness, metadata
from tests.unit.contracts.test_core_models import ref


@pytest.mark.parametrize("proof", ["exact", "absent", "mismatched_content"])
def test_execution_accepts_only_exact_trusted_opaque_evidence(
    tmp_path: Path, proof: str
) -> None:
    h = Harness(tmp_path)
    original = ExecutionBudgetProfile.model_validate_json(
        canonical_bytes(
            dict(
                meta=metadata("execution_budget_profile", "execution"),
                profile_key="opaque-approved",
                purpose="PRODUCTION",
                status="ACTIVE",
                max_analysis_elapsed_ms=1000,
                max_total_cost_minor_units=100,
                currency="USD",
                max_total_work=20,
                max_total_llm_calls=20,
                max_total_retries=2,
                max_parallel_work=4,
                approval_ref=ref("approval"),
                pricing_revision_ref=ref("pricing"),
                approved_by="R8",
                approved_at="2026-09-07T00:00:00Z",
            )
        )
    )
    assert original.approval_ref is not None
    opaque = original.approval_ref.model_copy(
        update=dict(
            record_id=RecordId("opaque-approval"),
            content_hash="a" * 64,
        )
    )
    pricing = opaque.model_copy(
        update=dict(record_id=RecordId("opaque-pricing"), content_hash="b" * 64)
    )
    profile = ExecutionBudgetProfile.model_validate(
        original.model_dump() | dict(approval_ref=opaque, pricing_revision_ref=pricing)
    )
    if proof == "exact":
        h.evidence.approvals.add(content_hash(profile))
    elif proof == "mismatched_content":
        h.evidence.approvals.add(content_hash(original))
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    if proof != "exact":
        with pytest.raises(ValueError, match="approval/pricing evidence"):
            runtime.budget_registry.pin_execution(profile, h.analysis(profile))
        return
    with pytest.raises(LookupError):
        runtime.unit_of_work.records.get_exact(opaque)
    with pytest.raises(LookupError):
        runtime.unit_of_work.records.get_exact(pricing)
    assert runtime.budget_registry.pin_execution(
        profile, h.analysis(profile)
    ) == reference(profile)
