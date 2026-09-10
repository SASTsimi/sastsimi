"""Read persisted ReportDraft records; submission is intentionally absent."""

from pathlib import Path

from sastsimi.bootstrap import build_fake_pipeline


def run(data_dir: Path) -> dict[str, object]:
    reports = build_fake_pipeline(data_dir).reports()
    return {
        "count": len(reports),
        "reports": [report.model_dump(mode="json") for report in reports],
    }
