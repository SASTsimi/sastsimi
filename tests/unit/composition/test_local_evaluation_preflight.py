from __future__ import annotations

from typing import Any

import pytest

from sastsimi.composition.local_evaluation_preflight import (
    DeferredLocalEvaluationCalls,
    LocalUnavailableSandboxCancellation,
)


class _Calls:
    def __init__(self) -> None:
        self.invocations: list[str] = []

    def resolve(self, **kwargs: Any) -> str:
        self.invocations.append("resolve")
        return "call"

    def settle(self, call: object, invocation: object) -> None:
        del call, invocation
        self.invocations.append("settle")


def test_deferred_call_port_is_one_time_and_fail_closed() -> None:
    calls = DeferredLocalEvaluationCalls()
    with pytest.raises(ValueError, match="LOCAL_EVALUATION_CALLS_NOT_BOUND"):
        calls.resolve()

    delegate = _Calls()
    calls.bind(delegate)  # type: ignore[arg-type]
    assert calls.resolve() == "call"
    calls.settle(object(), object())  # type: ignore[arg-type]
    assert delegate.invocations == ["resolve", "settle"]

    with pytest.raises(ValueError, match="LOCAL_EVALUATION_CALLS_ALREADY_BOUND"):
        calls.bind(delegate)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_unavailable_sandbox_cancellation_reports_no_external_resource() -> None:
    cancellation = LocalUnavailableSandboxCancellation()
    target = type("Target", (), {"target_kind": "SANDBOX"})()
    prepared = await cancellation.prepare(target)  # type: ignore[arg-type]
    assert prepared is target
    cancellation.validate_inventory("analysis", (target,))  # type: ignore[arg-type]
    observation = await cancellation.cancel(target)  # type: ignore[arg-type]
    assert observation.status == "ABSENT"
    assert observation.reason_code == "LOCAL_SANDBOX_NOT_STARTED"
