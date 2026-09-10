import json
from pathlib import Path

from sastsimi.contracts.actions import ActionRequest
from sastsimi.storage.recovery_service import RecoveryService
from tests.integration.recovery.test_transitions import completion
from tests.integration.runtime_support import metadata
from tests.unit.contracts.test_core_models import action


def test_recovery_preserves_and_verifies_nested_raw_artifact_provenance(
    tmp_path: Path,
) -> None:
    h, transitions, request = completion(tmp_path)
    transitions.commit(request)
    artifact = transitions.artifacts.commit(
        transitions.artifacts.stage_bytes(b"raw evidence", "text/plain")
    )
    record = ActionRequest.model_validate_json(
        json.dumps(
            action(
                meta=metadata("action_request", "raw-input"),
                input_refs=[artifact.model_dump(mode="json")],
            )
        )
    )
    h.publish(record)
    report = RecoveryService(transitions).recover()
    # PREPARING, READY and the nested raw input are all retained provenance.
    assert report.checked_artifacts == 3
    assert report.quarantined_artifacts == 0
    assert transitions.artifacts.open_verified(artifact).read() == b"raw evidence"
