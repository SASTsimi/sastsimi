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


def test_documentation_ci_uses_only_the_current_validator() -> None:
    current = ROOT / "scripts/validate-current-docs.ps1"
    workflow = (ROOT / ".github/workflows/docs.yml").read_text(encoding="utf-8")

    assert current.is_file()
    assert not (ROOT / "scripts/validate-architecture-docs.ps1").exists()
    assert not (ROOT / "scripts/audit-doc-inventory.ps1").exists()
    assert "scripts/validate-current-docs.ps1" in workflow
    assert "validate-architecture-docs.ps1" not in workflow
    assert "audit-doc-inventory.ps1" not in workflow
