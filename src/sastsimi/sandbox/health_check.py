"""Trusted container health and conservative environment checks."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from typing import Literal

from sastsimi.contracts.dynamic import (
    EnvironmentCheck,
    EnvironmentRequirements,
)
from sastsimi.contracts.refs import StoredDataRef

from .docker_adapter import DockerCommandOutcome, DockerContainerState

InspectContainer = Callable[[str], Awaitable[DockerContainerState]]
ExecuteContainer = Callable[
    [str, tuple[str, ...], int, str], Awaitable[DockerCommandOutcome]
]
_SAFE_EXECUTABLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}\Z")
_VERSION = re.compile(r"(?<![0-9])([0-9]+(?:\.[0-9]+){0,3})(?![0-9])")


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

    async def requirement_checks(
        self,
        *,
        requirements: EnvironmentRequirements,
        state: DockerContainerState,
        evidence_ref: StoredDataRef,
        execute: ExecuteContainer | None = None,
        timeout_ms: int = 10_000,
    ) -> tuple[EnvironmentCheck, ...]:
        checks: list[EnvironmentCheck] = []
        for item in requirements.items:
            expected = {value for value in (item.expected, *item.alternatives) if value}
            if item.kind == "HEALTH_CHECK":
                if state.health_status is None:
                    checks.append(
                        EnvironmentCheck(
                            requirement_id=item.requirement_id,
                            status="NOT_CHECKED",
                            actual=None,
                            actual_ref=None,
                            difference="The image declares no Docker health check",
                            evidence_refs=(evidence_ref,),
                            check_result_ref=None,
                        )
                    )
                    continue
                actual = str(state.health_status)
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
            if item.kind == "VERSION":
                checks.append(
                    await self._version_check(
                        container_id=state.container_id,
                        name=item.name,
                        expected=tuple(expected),
                        evidence_ref=evidence_ref,
                        execute=execute,
                        timeout_ms=timeout_ms,
                        requirement_id=item.requirement_id,
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
    async def _version_check(
        *,
        container_id: str,
        name: str,
        expected: tuple[str, ...],
        evidence_ref: StoredDataRef,
        execute: ExecuteContainer | None,
        timeout_ms: int,
        requirement_id: str,
    ) -> EnvironmentCheck:
        expected_versions = {
            match.group(1)
            for value in expected
            for match in (_VERSION.search(value),)
            if match is not None
        }
        if (
            execute is None
            or timeout_ms <= 0
            or _SAFE_EXECUTABLE.fullmatch(name) is None
            or not expected
            or not expected_versions
        ):
            return EnvironmentCheck(
                requirement_id=requirement_id,
                status="NOT_CHECKED",
                actual=None,
                actual_ref=None,
                difference="A trusted version check could not be constructed",
                evidence_refs=(evidence_ref,),
                check_result_ref=None,
            )
        try:
            outcome = await execute(
                container_id,
                (name, "--version"),
                timeout_ms,
                "/",
            )
        except Exception:
            outcome = None
        if outcome is None or outcome.timed_out or outcome.exit_code != 0:
            return EnvironmentCheck(
                requirement_id=requirement_id,
                status="ERROR",
                actual=None,
                actual_ref=None,
                difference="The runtime version check failed",
                evidence_refs=(evidence_ref,),
                check_result_ref=None,
            )
        try:
            output = (outcome.stdout + b"\n" + outcome.stderr).decode("utf-8")
        except UnicodeDecodeError:
            output = ""
        observed_match = _VERSION.search(output)
        observed = observed_match.group(1) if observed_match is not None else None
        matched = observed is not None and any(
            observed == value or observed.startswith(value + ".")
            for value in expected_versions
        )
        primary_match = _VERSION.search(expected[0])
        primary = primary_match.group(1) if primary_match is not None else None
        return EnvironmentCheck(
            requirement_id=requirement_id,
            status="MATCH" if matched else "MISMATCH",
            actual=observed or "version unavailable",
            actual_ref=None,
            difference=(
                None
                if matched and observed == primary
                else "The runtime patch version differs from the requested version"
                if matched
                else "The runtime version differs from the requirement"
            ),
            evidence_refs=(evidence_ref,),
            check_result_ref=None,
        )

    @staticmethod
    def state_uncertain(state: DockerContainerState) -> bool:
        return (
            not state.running
            or state.exit_code != 0
            or state.health_status in {"unhealthy", "starting"}
        )
