from pathlib import Path

import pytest

from sastsimi.storage.codec import reference
from tests.integration.storage.restart_fixture import restart_fixture


@pytest.mark.parametrize("profile_change", [False, True])
@pytest.mark.parametrize(
    "invalid",
    [
        None,
        "process",
        "parent",
        "verification-parent-attempt",
        "dynamic-child-attempt",
        "dynamic-claim",
        "assignment",
        "evidence",
        "new-request",
    ],
)
def test_public_restart_requires_complete_current_closure(
    tmp_path: Path, invalid: str | None, profile_change: bool
) -> None:
    _, runtime, request, reservation, _, parent = restart_fixture(
        tmp_path, invalid, profile_change
    )
    decision = runtime.validator.authorize(request, parent, reference(reservation))
    assert decision.decision == ("ALLOW" if invalid is None else "DENY"), (
        decision.check_results
    )
