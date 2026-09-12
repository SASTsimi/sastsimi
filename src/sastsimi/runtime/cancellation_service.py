"""Durable cancellation orchestration over exact persisted external targets."""

from __future__ import annotations

from typing import Protocol

from sastsimi.contracts.work import TERMINAL_WORK_STATUSES, WorkExecutionState
from sastsimi.ports.scheduler import (
    CancellationObservation,
    CancellationTarget,
    ExternalCancellationPort,
    RunControlPort,
)


class RunWorkReader(Protocol):
    """Read the exact durable work inventory for one analysis."""

    def work_for_run(self, analysis_id: str) -> tuple[WorkExecutionState, ...]: ...


class ExactCancellationRouter:
    """Route a store-derived target without accepting caller supplied IDs."""

    def __init__(
        self,
        *,
        static: ExternalCancellationPort,
        provider: ExternalCancellationPort,
        sandbox: ExternalCancellationPort,
    ) -> None:
        self._adapters = {
            "STATIC": static,
            "PROVIDER": provider,
            "SANDBOX": sandbox,
        }

    async def cancel(self, target: CancellationTarget) -> CancellationObservation:
        _validate_target(target, str(target.work.meta.analysis_id))
        try:
            observation = await self._adapters[target.target_kind].cancel(target)
        except Exception:
            # The dispatch may already have reached the external system.  Never
            # turn an adapter error into an affirmative cancellation claim.
            return CancellationObservation(
                target=target,
                status="UNRESOLVED",
                reason_code="CANCELLATION_ADAPTER_FAILED",
            )
        if observation.target != target:
            raise ValueError("CANCELLATION_OBSERVATION_TARGET_MISMATCH")
        return observation


class CancellationService:
    """Latch first, then stop only exact active targets and detect quiescence."""

    def __init__(
        self,
        controls: RunControlPort,
        works: RunWorkReader,
        external: ExternalCancellationPort,
    ) -> None:
        self._controls = controls
        self._works = works
        self._external = external

    async def request(
        self, analysis_id: str, reason_code: str
    ) -> tuple[CancellationObservation, ...]:
        if not analysis_id:
            raise ValueError("RUN_CONTROL_INPUT_INVALID")
        # This synchronous durable write must complete before the first await.
        self._controls.request_cancel(analysis_id, reason_code)
        return await self.drain_latched(analysis_id)

    async def drain_latched(
        self, analysis_id: str
    ) -> tuple[CancellationObservation, ...]:
        if not self._controls.cancel_requested(analysis_id):
            raise ValueError("CANCELLATION_LATCH_REQUIRED")
        targets = self._controls.cancellation_targets(analysis_id)
        # Validate the complete store projection before the first external I/O;
        # one corrupt/foreign row must not cause a partial broad cancellation.
        for target in targets:
            _validate_target(target, analysis_id)
        observations: list[CancellationObservation] = []
        for target in targets:
            observations.append(await self._external.cancel(target))
        if all(item.status != "UNRESOLVED" for item in observations) and all(
            item.status in TERMINAL_WORK_STATUSES
            for item in self._works.work_for_run(analysis_id)
        ):
            self._controls.mark_quiescent(analysis_id)
        return tuple(observations)


def _validate_target(target: CancellationTarget, analysis_id: str) -> None:
    work = target.work
    attempt = target.attempt
    if (
        str(work.meta.analysis_id) != analysis_id
        or str(attempt.meta.analysis_id) != analysis_id
        or work.status != "RUNNING"
        or work.active_attempt_id != attempt.attempt_id
        or work.work_id != attempt.work_id
        or work.input_hash != attempt.input_hash
        or attempt.status != "RUNNING"
        or target.action_request_ref.record_id is None
        or target.action_decision_ref.record_id is None
    ):
        raise ValueError("CANCELLATION_TARGET_SCOPE_MISMATCH")
    if target.target_kind == "PROVIDER" and target.call_spec_ref is None:
        raise ValueError("CANCELLATION_TARGET_SCOPE_MISMATCH")
    if target.target_kind != "SANDBOX" and target.sandbox_resource_refs:
        raise ValueError("CANCELLATION_TARGET_SCOPE_MISMATCH")


__all__ = ["CancellationService", "ExactCancellationRouter", "RunWorkReader"]
