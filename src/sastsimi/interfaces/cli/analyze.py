"""Start the deterministic fake analysis through the public composition root."""

from pathlib import Path

from sastsimi.bootstrap import build_fake_pipeline


def run(data_dir: Path, scenario: str) -> dict[str, object]:
    result = build_fake_pipeline(data_dir).analyze(scenario=scenario)
    return {
        "analysis_id": str(result.meta.analysis_id),
        "status": result.status,
        "verdict_counts": dict(result.verdict_counts),
        "hypothesis_counts": dict(result.hypothesis_counts),
        "elapsed_ms": result.elapsed_ms,
    }
