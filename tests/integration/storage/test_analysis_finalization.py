"""Trusted exact terminal analysis projection."""

from pathlib import Path

import pytest

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.refs import StoredDataRef
from tests.contract.domain.canonical_fixtures import make
from tests.integration.runtime_support import Harness


def _result() -> AnalysisRunResult:
    return AnalysisRunResult.model_validate_json(
        canonical_bytes(
            make("AnalysisRunResult")
            | {
                "program_id": "program",
                "started_at": "2026-09-07T00:00:00Z",
                "finished_at": "2026-09-07T00:00:01Z",
            }
        )
    )


def test_finalization_validates_inventory_and_closes_run_atomically(
    tmp_path: Path,
) -> None:
    h = Harness(tmp_path)
    profile = h.execution()
    identity_ref = StoredDataRef.model_validate(
        {
            "stored_data_id": "analysis-finalizer",
            "data_kind": "analysis_finalizer_identity",
            "content_hash": "a" * 64,
            "record_id": "analysis-finalizer",
            "workspace_id": "w1",
            "commit_id": "c1",
        }
    )
    h.evidence.identities[identity_ref] = RequesterRole.ORCHESTRATION
    runtime = build_runtime(
        tmp_path,
        None,
        None,
        h.clock,
        h.ids,
        evidence=h.evidence,
        analysis_finalization_identity_ref=identity_ref,
    )
    h.pin_execution(runtime.budget_registry, profile)
    result = _result()

    result_ref = runtime.finalization.finalize(result)

    state = runtime.budget_registry.current_state("a1")
    assert state.status == "FAILED"
    assert state.analysis_result_ref == result_ref
    assert state in runtime.queries.published_records("a1")
    assert runtime.finalization.finalize(result) == result_ref


def test_finalization_denies_untrusted_callers(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    profile = h.execution()
    h.pin_execution(runtime.budget_registry, profile)
    result = _result()

    with pytest.raises(ValueError, match="trusted finalization identity"):
        runtime.finalization.finalize(result)
