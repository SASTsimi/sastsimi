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
        repair_docker_owned_list_exhaustion_hypothesis: str | None = None,
        repair_poc_placeholder_exhaustion_hypothesis: str | None = None,
        repair_poc_sensitive_content_hypothesis: str | None = None,
        repair_report_validator_hypothesis: str | None = None,
    ) -> dict[str, object]: ...

    def result(self, analysis_id: str) -> dict[str, object]: ...

    def poc(self, finding_id: str) -> str: ...

    def report(self, finding_id: str) -> str: ...

    def export_report(self, finding_id: str) -> str: ...


__all__ = ["PublicCommandApplication"]
