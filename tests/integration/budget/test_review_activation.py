from pathlib import Path

import pytest

from sastsimi.bootstrap import build_runtime
from tests.integration.runtime_support import Harness


def test_registry_cannot_activate_unapproved_profile(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids)
    with pytest.raises(ValueError, match="BUDGET.*approval"):
        runtime.budget_registry.pin_execution(h.execution())


def test_execution_profile_and_analysis_state_are_atomically_pinned(
    tmp_path: Path,
) -> None:
    from sastsimi.contracts.canonical_json import content_hash

    h = Harness(tmp_path)
    profile = h.execution()
    h.evidence.approvals.add(content_hash(profile))
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    state = h.analysis(profile)
    runtime.budget_registry.pin_execution(profile, state)
    current = runtime.budget_registry.current_state("a1")
    assert current == state
    assert (
        runtime.unit_of_work.records.get_exact(current.execution_budget_profile_ref)
        == profile
    )


def test_bootstrap_cannot_inject_workspace_ready_identity(tmp_path: Path) -> None:
    from sastsimi.contracts.analysis import AnalysisRunState
    from sastsimi.contracts.canonical_json import content_hash

    h = Harness(tmp_path)
    profile = h.execution()
    h.evidence.approvals.add(content_hash(profile))
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    state = AnalysisRunState.model_validate(
        h.analysis(profile).model_dump() | dict(workspace_id="w1", commit_id="c1")
    )
    with pytest.raises(ValueError, match="BUDGET.*bootstrap"):
        runtime.budget_registry.pin_execution(profile, state)
