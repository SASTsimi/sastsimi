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

    async def prepare(
        self, targets: tuple[CancellationTarget, ...]
    ) -> tuple[CancellationTarget, ...]:
        """Validate every adapter-owned inventory before any cancellation I/O."""
        prepared: list[CancellationTarget] = []
        for target in targets:
            adapter = self._adapters[target.target_kind]
            prepare = getattr(adapter, "prepare", None)
            value = await prepare(target) if callable(prepare) else target
            if not isinstance(value, CancellationTarget):
                raise ValueError("CANCELLATION_PREPARED_TARGET_INVALID")
            _validate_target(value, str(value.work.meta.analysis_id))
            prepared.append(value)
        return tuple(prepared)

    async def cancel(self, target: CancellationTarget) -> CancellationObservation:
        _validate_target(target, str(target.work.meta.analysis_id))
        try:
            observation = await self._adapters[target.target_kind].cancel(target)
        except Exception:
            # The dispatch may already have reached the external system.  Never
            # turn an adapter error into an affirmative cancellation claim.
            return CancellationObservation(
                target=target,
                status="UNKNOWN",
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
        prepare = getattr(self._external, "prepare", None)
        if callable(prepare):
            prepared = await prepare(targets)
            if prepared is not None:
                if not isinstance(prepared, tuple) or not all(
                    isinstance(item, CancellationTarget) for item in prepared
                ):
                    raise ValueError("CANCELLATION_PREPARED_TARGET_INVALID")
                targets = prepared
                for target in targets:
                    _validate_target(target, analysis_id)
        existing = self._controls.cancellation_observations(targets)
        if len(existing) != len(targets):
            raise ValueError("CANCELLATION_OBSERVATION_INVENTORY_MISMATCH")
        observations: list[CancellationObservation] = []
        for target, replay in zip(targets, existing, strict=True):
            if replay is not None:
                if replay.target != target:
                    raise ValueError("CANCELLATION_OBSERVATION_TARGET_MISMATCH")
                observations.append(replay)
                continue
            try:
                observed = await self._external.cancel(target)
            except Exception:
                observed = CancellationObservation(
                    target, "UNKNOWN", "CANCELLATION_ADAPTER_FAILED"
                )
            if observed.target != target or observed.status not in {
                "STOPPED",
                "ABSENT",
                "UNKNOWN",
                "PRESERVED",
            }:
                observed = CancellationObservation(
                    target, "UNKNOWN", "CANCELLATION_ADAPTER_INVALID"
                )
            self._controls.record_cancellation_observation(observed)
            observations.append(observed)
        self._controls.reconcile_cancellation(analysis_id, tuple(observations))
        if all(item.status != "UNKNOWN" for item in observations) and all(
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
    if target.target_kind != "SANDBOX" and (
        target.sandbox_resource_refs
        or target.sandbox_resources
        or target.sandbox_inventory_fingerprint is not None
    ):
        raise ValueError("CANCELLATION_TARGET_SCOPE_MISMATCH")
    if target.target_kind == "SANDBOX" and bool(target.sandbox_resources) != bool(
        target.sandbox_inventory_fingerprint
    ):
        raise ValueError("CANCELLATION_TARGET_SCOPE_MISMATCH")


__all__ = ["CancellationService", "ExactCancellationRouter", "RunWorkReader"]
