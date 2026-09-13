from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reproduction.production import (
    DynamicSandboxAuthorization,
    RuntimeDynamicSandboxAuthorizationLifecycle,
)


def _ref(kind: str, marker: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(f"{marker}-stored"),
        data_kind=kind,
        content_hash=marker * 64,
        workspace_id=WorkspaceId("workspace"),
        commit_id=CommitId("c" * 40),
        record_id=RecordId(f"{marker}-record"),
    )


class _Authorization:
    def __init__(self) -> None:
        self.events: list[tuple[str, object]] = []
        self.claimed = _ref("action_decision", "c")

    def claim_external(
        self, work_id: str, decision_ref: object, reservation_ref: object
    ) -> StoredDataRef:
        self.events.append(("claim", (work_id, decision_ref, reservation_ref)))
        return self.claimed

    def mark_dispatched(
        self,
        decision_ref: object,
        provider_request_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        self.events.append(
            ("dispatch", (decision_ref, provider_request_id, idempotency_key))
        )

    def mark_returned(self, decision_ref: object) -> None:
        self.events.append(("return", decision_ref))


def _binding(*, reservation: bool = True) -> DynamicSandboxAuthorization:
    return DynamicSandboxAuthorization(
        action=cast(Any, SimpleNamespace(action_id="sandbox-action")),
        action_decision_ref=_ref("action_decision", "a"),
        sandbox_profile=cast(Any, object()),
        lifecycle_profile=cast(Any, object()),
        run_policy_state_ref=_ref("run_policy_state", "b"),
        run_spec=cast(Any, object()),
        reservation_ref=_ref("budget_reservation", "d") if reservation else None,
    )


@pytest.mark.asyncio
async def test_dynamic_authorization_claims_then_dispatches_then_returns() -> None:
    authorization = _Authorization()
    lifecycle = RuntimeDynamicSandboxAuthorizationLifecycle(cast(Any, authorization))
    work = cast(
        Any,
        SimpleNamespace(
            work_id="dynamic-work", status="RUNNING", active_attempt_id="attempt"
        ),
    )

    claimed = await lifecycle.claim(work, _binding())
    assert claimed.authorization.action_decision_ref == authorization.claimed
    assert [name for name, _value in authorization.events] == ["claim"]

    await claimed.dispatch()
    assert [name for name, _value in authorization.events] == ["claim", "dispatch"]

    await claimed.returned()
    assert [name for name, _value in authorization.events] == [
        "claim",
        "dispatch",
        "return",
    ]


@pytest.mark.asyncio
async def test_dynamic_authorization_rejects_missing_exact_reservation() -> None:
    authorization = _Authorization()
    lifecycle = RuntimeDynamicSandboxAuthorizationLifecycle(cast(Any, authorization))
    work = cast(
        Any,
        SimpleNamespace(
            work_id="dynamic-work", status="RUNNING", active_attempt_id="attempt"
        ),
    )

    with pytest.raises(
        ValueError,
        match="DYNAMIC_SANDBOX_RESERVATION_REQUIRED",
    ):
        await lifecycle.claim(work, _binding(reservation=False))

    assert authorization.events == []
