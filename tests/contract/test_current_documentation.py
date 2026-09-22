from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_repository_exposes_only_current_documentation_sets() -> None:
    required = {
        "docs/architecture/README.md",
        "docs/architecture/pipeline.md",
        "docs/architecture/runtime-and-recovery.md",
        "docs/architecture/agents-and-providers.md",
        "docs/architecture/contracts-and-storage.md",
        "docs/architecture/static-and-dynamic-analysis.md",
        "docs/architecture/gates-chaining-reporting.md",
        "docs/architecture/security-boundaries.md",
        "docs/architecture/implementation-map.md",
        "docs/decisions/README.md",
    }
    missing = sorted(path for path in required if not (ROOT / path).is_file())
    historical = sorted(
        path
        for path in (
            ".superpowers",
            "docs/architecture-v5",
            "docs/governance",
            "docs/handoff",
            "docs/review",
            "docs/superpowers",
        )
        if (ROOT / path).exists()
    )

    assert missing == []
    assert historical == []
