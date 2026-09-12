from __future__ import annotations

from types import SimpleNamespace

import pytest

from sastsimi.orchestration.production_composition import (
    ProductionCapabilityUnavailable,
)
from sastsimi.orchestration.production_feature_installer import (
    CombinedPostWorkspaceSeeder,
    ExactProductionReadiness,
)


class _Seeder:
    def __init__(self, work_id: str) -> None:
        self.work_id = work_id
        self.calls = 0

    def ensure_initial(self, *_args: object) -> tuple[object, ...]:
        self.calls += 1
        return (SimpleNamespace(work_id=self.work_id),)


def test_combined_seeder_starts_static_and_official_policy_once() -> None:
    static = _Seeder("repository-profile")
    policy = _Seeder("official-policy")

    seeded = CombinedPostWorkspaceSeeder(static, policy).ensure_initial(
        object(), object(), object()
    )

    assert tuple(item.work_id for item in seeded) == (
        "repository-profile",
        "official-policy",
    )
    assert static.calls == policy.calls == 1


def test_readiness_fails_closed_when_exact_commit_changes() -> None:
    checked: list[str] = []
    readiness = ExactProductionReadiness(
        "analysis", "workspace", "commit-a", (lambda: checked.append("ok"),)
    )

    with pytest.raises(
        ProductionCapabilityUnavailable, match="PRODUCTION_SCOPE_CHANGED"
    ):
        readiness.require_ready(
            request=object(),
            profile=object(),
            scope=SimpleNamespace(
                analysis_id="analysis", workspace_id="workspace", commit_id="commit-b"
            ),
        )

    assert checked == []
