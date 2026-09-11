"""Trusted container health and conservative environment checks."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Literal

from sastsimi.contracts.dynamic import (
    EnvironmentCheck,
    EnvironmentRequirements,
)
from sastsimi.contracts.refs import StoredDataRef

from .docker_adapter import DockerContainerState

InspectContainer = Callable[[str], Awaitable[DockerContainerState]]


class SandboxHealthChecker:
    async def inspect_ready(
        self,
        inspect: InspectContainer,
        container_id: str,
    ) -> DockerContainerState:
        state = await inspect(container_id)
        if self.state_uncertain(state):
            raise ValueError("SANDBOX_STATE_UNCERTAIN")
        if (
            state.user in {"", "0", "root"}
            or state.network_mode != "none"
            or state.privileged
            or not state.read_only_rootfs
        ):
            raise ValueError("SANDBOX_ISOLATION_DRIFT")
        return state

    def requirement_checks(
        self,
        *,
        requirements: EnvironmentRequirements,
        state: DockerContainerState,
        evidence_ref: StoredDataRef,
    ) -> tuple[EnvironmentCheck, ...]:
        checks: list[EnvironmentCheck] = []
        for item in requirements.items:
            expected = {value for value in (item.expected, *item.alternatives) if value}
            if item.kind == "HEALTH_CHECK":
                actual = "healthy" if state.health_status in {None, "healthy"} else str(
                    state.health_status
                )
                status: Literal["MATCH", "MISMATCH"] = (
                    "MATCH" if not expected or actual in expected else "MISMATCH"
                )
                checks.append(
                    EnvironmentCheck(
                        requirement_id=item.requirement_id,
                        status=status,
                        actual=actual,
                        actual_ref=None,
                        difference=(
                            None
                            if status == "MATCH"
                            else "Container health differs from the requirement"
                        ),
                        evidence_refs=(evidence_ref,),
                        check_result_ref=None,
                    )
                )
                continue
            checks.append(
                EnvironmentCheck(
                    requirement_id=item.requirement_id,
                    status="NOT_CHECKED",
                    actual=None,
                    actual_ref=None,
                    difference="No trusted automatic check is available",
                    evidence_refs=(evidence_ref,),
                    check_result_ref=None,
                )
            )
        return tuple(checks)

    @staticmethod
    def state_uncertain(state: DockerContainerState) -> bool:
        return (
            not state.running
            or state.exit_code != 0
            or state.health_status in {"unhealthy", "starting"}
        )
