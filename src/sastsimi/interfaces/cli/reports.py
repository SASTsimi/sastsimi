"""List current, safe ReportDraft records; submission is intentionally absent."""

from pathlib import Path

from sastsimi.reporting.markdown_export import ReportMarkdownService
from sastsimi.storage.report_export import SQLiteCurrentReportSource


def run(data_dir: Path) -> dict[str, object]:
    reports = ReportMarkdownService(
        data_dir, SQLiteCurrentReportSource(data_dir)
    ).summaries()
    return {
        "count": len(reports),
        "reports": list(reports),
    }
