"""Port used by the small public CLI without importing a composition root."""

from __future__ import annotations

from typing import Protocol


class PublicCommandApplication(Protocol):
    def analyze(self, repository: str, commit: str) -> dict[str, object]: ...

    def status(self, analysis_id: str) -> dict[str, object]: ...

    def resume(
        self,
        analysis_id: str,
        *,
        repair_exhausted_hypothesis: str | None = None,
        repair_legacy_import_stop_hypothesis: str | None = None,
        repair_fallback_poc_stop_hypothesis: str | None = None,
        repair_poc_fixture_exhaustion_hypothesis: str | None = None,
        repair_poc_fixture_dependency_exhaustion_hypothesis: str | None = None,
        repair_poc_candidate_app_exhaustion_hypothesis: str | None = None,
        repair_poc_urlconf_exhaustion_hypothesis: str | None = None,
        repair_poc_candidate_constraint_hypothesis: str | None = None,
        repair_poc_urlconf_candidate_hypothesis: str | None = None,
        repair_poc_generated_input_hypothesis: str | None = None,
        repair_poc_source_gap_exhaustion_hypothesis: str | None = None,
        repair_poc_django_schema_exhaustion_hypothesis: str | None = None,
        repair_poc_django_settings_exhaustion_hypothesis: str | None = None,
        repair_poc_django_relation_settings_exhaustion_hypothesis: str | None = None,
        repair_poc_django_migration_settings_exhaustion_hypothesis: str | None = None,
        repair_poc_server_constructor_exhaustion_hypothesis: str | None = None,
        repair_poc_in_memory_storage_exhaustion_hypothesis: str | None = None,
        repair_initial_environment_exhaustion_hypothesis: str | None = None,
        repair_interrupted_initial_exhaustion_hypothesis: str | None = None,
        repair_docker_owned_list_exhaustion_hypothesis: str | None = None,
        repair_poc_placeholder_exhaustion_hypothesis: str | None = None,
        repair_poc_sensitive_content_hypothesis: str | None = None,
        repair_poc_anchor_hypothesis: str | None = None,
        repair_report_validator_hypothesis: str | None = None,
        repair_auth_required_hypothesis: str | None = None,
        supplement_saved_v2_ast_orphans: bool = False,
    ) -> dict[str, object]: ...

    def result(self, analysis_id: str) -> dict[str, object]: ...

    def poc(self, finding_id: str) -> str: ...

    def report(self, finding_id: str) -> str: ...

    def export_report(self, finding_id: str) -> str: ...


__all__ = ["PublicCommandApplication"]
