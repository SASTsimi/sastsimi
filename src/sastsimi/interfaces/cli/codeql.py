"""Presentation wrappers for operator-only CodeQL actions.

Concrete configuration, registry, process, and Docker adapters are selected by
the composition root exposed through :mod:`sastsimi.bootstrap`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sastsimi import bootstrap
from sastsimi.interfaces.cli.capability import CapabilityCommandResult
from sastsimi.interfaces.cli.exit_codes import ExitCode


def _project(result: Any) -> CapabilityCommandResult:
    return CapabilityCommandResult(ExitCode[result.code], result.data)


def resolve_operator_executable(value: str) -> Path:
    return bootstrap.resolve_operator_executable(value)


def run_register(**kwargs: Any) -> CapabilityCommandResult:
    return _project(bootstrap.register_database(**kwargs))


def run_inspect(**kwargs: Any) -> CapabilityCommandResult:
    return _project(bootstrap.inspect_database(**kwargs))


def run_provision(**kwargs: Any) -> CapabilityCommandResult:
    return _project(bootstrap.provision_database(**kwargs))


__all__ = [
    "resolve_operator_executable",
    "run_inspect",
    "run_provision",
    "run_register",
]
