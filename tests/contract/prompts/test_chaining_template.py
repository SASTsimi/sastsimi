from pathlib import Path


def test_chaining_template_keeps_matching_content_only() -> None:
    root = Path(__file__).resolve().parents[3]
    template = (
        root / "src/sastsimi/prompts/templates/chaining/match-primitives/1.0.0.md"
    ).read_text(encoding="utf-8")

    for heading in (
        "# ROLE_AND_SCOPE",
        "# TRUSTED_RULES",
        "# UNTRUSTED_DATA_BOUNDARY",
        "# DECISION_CRITERIA",
        "# OUTPUT_SCHEMA",
        "# FORBIDDEN_BEHAVIOR",
    ):
        assert heading in template

    assert "upstream result" in template
    assert "downstream input" in template
    assert "MATCH" in template
    assert "NO_MATCH" in template
    assert "runtime-owned" in template
    assert "Do not issue a vulnerability verdict" in template
    assert "Do not run tools" in template
