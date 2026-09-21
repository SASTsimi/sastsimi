"""Port used by the small public CLI without importing a composition root."""

from __future__ import annotations

from typing import Protocol


class PublicCommandApplication(Protocol):
    def analyze(self, repository: str, commit: str) -> dict[str, object]: ...

    def status(self, analysis_id: str) -> dict[str, object]: ...

    def resume(self, analysis_id: str) -> dict[str, object]: ...

    def result(self, analysis_id: str) -> dict[str, object]: ...

    def poc(self, finding_id: str) -> str: ...

    def report(self, finding_id: str) -> str: ...

    def export_report(self, finding_id: str) -> str: ...


__all__ = ["PublicCommandApplication"]
