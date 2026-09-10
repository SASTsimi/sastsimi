"""Read the persisted deterministic analysis result."""

from pathlib import Path

from sastsimi.bootstrap import load_fake_progress


def run(data_dir: Path) -> dict[str, object]:
    return load_fake_progress(data_dir)
