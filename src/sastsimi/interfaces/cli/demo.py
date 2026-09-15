"""Explicit deterministic demo commands; never a production fallback."""

from pathlib import Path

from sastsimi.bootstrap import build_fake_pipeline, load_fake_progress


def analyze(data_dir: Path, scenario: str) -> dict[str, object]:
    result = build_fake_pipeline(data_dir).analyze(scenario=scenario)
    return {
        "analysis_id": str(result.meta.analysis_id),
        "status": result.status,
        "verdict_counts": dict(result.verdict_counts),
        "hypothesis_counts": dict(result.hypothesis_counts),
        "elapsed_ms": result.elapsed_ms,
    }


def results(data_dir: Path) -> dict[str, object]:
    return load_fake_progress(data_dir)


__all__ = ["analyze", "results"]
