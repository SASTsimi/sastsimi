from pathlib import Path

import pytest

from tests.integration.recovery.test_transitions import completion


def test_state_change_authority_does_not_authorize_domain_output(
    tmp_path: Path,
) -> None:
    h, service, request = completion(tmp_path, authorize_output=False)
    with pytest.raises(ValueError, match="ACTION_TYPE|OWNER"):
        service.commit(request)


def test_committed_transition_appends_exact_action_outcome(tmp_path: Path) -> None:
    from sqlalchemy import text

    from sastsimi.contracts.actions import ActionDecision

    h, service, request = completion(tmp_path)
    service.commit(request)
    with h.database.engine.connect() as connection:
        payload = connection.execute(
            text(
                "SELECT payload FROM action_decisions "
                "WHERE decision_id='finish-decision'"
            )
        ).scalar_one()
    decision = ActionDecision.model_validate_json(payload)
    assert decision.use_status == "USED"
    assert decision.outcome_refs == request.commit.output_refs
