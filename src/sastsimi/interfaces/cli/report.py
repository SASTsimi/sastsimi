"""Human-readable current ReportDraft show/export commands."""

from pathlib import Path

from sastsimi.reporting.markdown_export import ReportMarkdownService
from sastsimi.storage.report_export import SQLiteCurrentReportSource


def service(data_dir: Path) -> ReportMarkdownService:
    return ReportMarkdownService(data_dir, SQLiteCurrentReportSource(data_dir))


def show(data_dir: Path, finding_id: str) -> str:
    return service(data_dir).show(finding_id)


def export(data_dir: Path, finding_id: str) -> Path:
    return service(data_dir).export(finding_id)
