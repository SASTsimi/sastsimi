"""List current, safe ReportDraft records; submission is intentionally absent."""

from pathlib import Path

from sastsimi.interfaces.cli import report as report_command


def run(data_dir: Path, analysis_id: str) -> dict[str, object]:
    service = report_command.service(data_dir)
    try:
        reports = service.summaries(analysis_id)
    except ValueError as error:
        raise report_command.ReportCommandError from error
    return {
        "count": len(reports),
        "reports": list(reports),
    }
