import json
from pathlib import Path

from sastsimi.contracts.dynamic import SandboxProfile
from tests.contract.domain.canonical_fixtures import make
from tests.integration.runtime_support import Harness


def test_existing_sandbox_profile_is_exact_resolvable(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    profile = SandboxProfile.model_validate_json(json.dumps(make("SandboxProfile")))
    ref = h.records.stage_record(profile)
    with h.database.write() as connection:
        h.records.publish(connection, ref)
    assert h.records.get_exact(ref) == profile
