"""Human-readable current ReportDraft show/export commands."""

from pathlib import Path
from typing import Protocol, cast

from sastsimi import bootstrap


class ReportCommandError(ValueError):
    """A safe, expected report lookup or export failure."""


class ReportService(Protocol):
    """CLI view of the report application service."""

    def summaries(self, analysis_id: str) -> tuple[dict[str, str], ...]: ...

    def show(self, finding_id: str) -> str: ...

    def export(self, finding_id: str) -> Path: ...

    def bundle_reference(self, exported: Path) -> str | None: ...


def service(data_dir: Path) -> ReportService:
    return cast(ReportService, bootstrap.build_report_markdown_service(data_dir))


def show(data_dir: Path, finding_id: str) -> str:
    try:
        return service(data_dir).show(finding_id)
    except ValueError as error:
        raise ReportCommandError from error


def export(data_dir: Path, finding_id: str) -> Path:
    try:
        return service(data_dir).export(finding_id)
    except ValueError as error:
        raise ReportCommandError from error


def safe_export_reference(data_dir: Path, exported: Path) -> str:
    """Return a data-root-relative report path without disclosing its host path."""

    try:
        root = data_dir.resolve(strict=True)
        relative = exported.resolve(strict=True).relative_to(root)
    except (OSError, ValueError):
        raise ReportCommandError from None
    if not relative.parts or relative.parts[0] != "reports":
        raise ReportCommandError
    return relative.as_posix()


def bundle_reference(data_dir: Path, exported: Path) -> str | None:
    """Return the current v2 ZIP path through the report service."""

    relative = safe_export_reference(data_dir, exported)
    bundle = data_dir / Path(relative).parent / Path(relative).stem
    if not (bundle / "manifest.json").is_file():
        return None
    try:
        return service(data_dir).bundle_reference(exported)
    except ValueError as error:
        raise ReportCommandError from error
