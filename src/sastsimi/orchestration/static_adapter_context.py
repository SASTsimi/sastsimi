"""Neutral, exact inputs consumed by production static adapter factories."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile
from sastsimi.orchestration.production_provisioning import StaticRouteProvisioning
from sastsimi.orchestration.static_work_handlers import StaticToolRoute
from sastsimi.ports.dto import StaticRuleMapping, TrackedFile
from sastsimi.ports.static_tool import StaticProcessAdapter
from sastsimi.ports.workspace import WorkspaceLocatorPort


@dataclass(frozen=True, slots=True)
class ApprovedStaticRuleClosure:
    """Typed interpretation explicitly approved with one rule-tool route."""

    catalog_sha256: str
    selection_sha256: str
    mapping_sha256: str
    catalog_rule_ids: tuple[str, ...]
    selected_rule_ids: tuple[str, ...]
    mappings: tuple[StaticRuleMapping, ...]

    def validate_for(self, route: StaticRouteProvisioning) -> None:
        mapping_ids = tuple(item.rule_id for item in self.mappings)
        if (
            route.tool == "AST"
            or (
                self.catalog_sha256,
                self.selection_sha256,
                self.mapping_sha256,
            )
            != (
                route.rule_catalog_sha256,
                route.rule_selection_sha256,
                route.rule_mapping_sha256,
            )
            or not self.catalog_rule_ids
            or len(self.catalog_rule_ids) != len(set(self.catalog_rule_ids))
            or len(self.selected_rule_ids) != len(set(self.selected_rule_ids))
            or not set(self.selected_rule_ids) <= set(self.catalog_rule_ids)
            or set(mapping_ids) != set(self.catalog_rule_ids)
            or len(mapping_ids) != len(set(mapping_ids))
        ):
            raise ValueError("PRODUCTION_STATIC_RULE_CLOSURE_INVALID")


@dataclass(frozen=True, slots=True)
class StaticAdapterBuildContext:
    """Exact inputs a compiled-in real adapter factory may consume."""

    data_dir: Path
    workspace_locator: WorkspaceLocatorPort
    tracked_files_for: Callable[[CodeWorkspace], tuple[TrackedFile, ...]]
    routes: Mapping[str, StaticToolRoute]
    profiles: Mapping[str, StaticToolProfile]
    evidence: Mapping[str, bytes]
    rule_closures: Mapping[str, ApprovedStaticRuleClosure]


class StaticAdapterFactory(Protocol):
    def __call__(
        self, context: StaticAdapterBuildContext
    ) -> Mapping[str, StaticProcessAdapter]: ...
