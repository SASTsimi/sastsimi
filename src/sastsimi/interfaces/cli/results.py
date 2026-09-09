"""Read the persisted deterministic analysis result."""

from pathlib import Path

from sastsimi.bootstrap import build_fake_pipeline


def run(data_dir: Path) -> dict[str, object]:
    result = build_fake_pipeline(data_dir).results()
    return result.model_dump(mode="json")
