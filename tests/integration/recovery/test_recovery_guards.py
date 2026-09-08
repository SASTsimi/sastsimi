from pathlib import Path

import pytest

from sastsimi.storage.artifact_store import LocalArtifactStore
from tests.integration.recovery.test_transitions import completion


def test_run_scoped_workspace_result_can_commit_before_artifact_scope_is_bound(
    tmp_path: Path,
) -> None:
    h, service, request = completion(tmp_path)
    service.artifacts = LocalArtifactStore(tmp_path / "run-artifacts", None, None)
    assert service.commit(request).state == "COMMITTED"


def test_recovery_failure_blocks_new_registration_and_record_consumption(
    tmp_path: Path,
) -> None:
    h, service, request = completion(tmp_path)
    service.commit(request)
    h.database.recovery_failed = True
    with pytest.raises(ValueError, match="RECOVERY_FAILED"):
        h.records.get_exact(request.commit.output_refs[0])
