import json
from pathlib import Path

import pytest

from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from tests.contract.domain.canonical_fixtures import make
from tests.integration.runtime_support import Harness


@pytest.mark.parametrize(
    "model", [SandboxProfile, PlaybookPolicy, VerificationPlaybook]
)
def test_existing_sandbox_profile_is_exact_resolvable(
    tmp_path: Path,
    model: type[SandboxProfile] | type[PlaybookPolicy] | type[VerificationPlaybook],
) -> None:
    h = Harness(tmp_path)
    data = make(model.__name__)
    if model is PlaybookPolicy:
        data["common_playbook_ref"]["data_kind"] = "verification_playbook"
    profile = model.model_validate_json(json.dumps(data))
    ref = h.records.stage_record(profile)
    with h.database.write() as connection:
        h.records.publish(connection, ref)
    assert h.records.get_exact(ref) == profile
