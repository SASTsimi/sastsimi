"""Ports used by orchestration to profile a prepared repository."""

from typing import Literal, Protocol

from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    HostConfigurationRef,
    RunStoredDataRef,
    StoredDataRef,
)
from sastsimi.contracts.static import RepositoryExecutionSelection, RepositoryProfile

from .dto import RepositoryPreparation


class RepositoryProfilerPort(Protocol):
    """Build repository facts without exposing the concrete detector layer."""

    def build(
        self,
        preparation: RepositoryPreparation,
        *,
        meta: RecordMeta,
        workspace_ref: RunStoredDataRef,
        action_decision_ref: StoredDataRef,
    ) -> RepositoryProfile: ...


class RepositoryExecutionSelectorPort(Protocol):
    """Select pinned production tools for one repository profile."""

    def git_executable_identity(
        self,
        profile_ref: HostConfigurationRef,
        operation: Literal["CLONE", "CHECKOUT"],
    ) -> tuple[str, str]: ...

    def select(
        self,
        repository: RepositoryProfile,
        *,
        meta: RecordMeta,
        repository_profile_ref: StoredDataRef,
        git_clone_profile_ref: HostConfigurationRef,
        git_checkout_profile_ref: HostConfigurationRef,
    ) -> RepositoryExecutionSelection: ...


__all__ = ["RepositoryExecutionSelectorPort", "RepositoryProfilerPort"]
