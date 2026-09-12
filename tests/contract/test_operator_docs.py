from pathlib import Path

ROOT = Path(__file__).parents[2]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_operator_path_is_linked_and_separates_production_from_demo() -> None:
    readme = _read("README.md")
    guide = _read("docs/DOCUMENT_GUIDE.md")
    usage = _read("docs/usage.md")

    for path in (
        "docs/installation.md",
        "docs/provider-setup.md",
        "docs/usage.md",
        "docs/troubleshooting.md",
    ):
        assert path.removeprefix("docs/") in guide
        assert (ROOT / path).is_file()

    assert "docs/installation.md" in readme
    assert "analyze --repo <URL-or-local-path> --commit <exact-SHA>" in usage
    assert "status <analysis_id>" in usage
    assert "results <analysis_id>" in usage
    assert "reports <analysis_id>" in usage
    assert "report export <finding_id> --format markdown" in usage
    assert "demo analyze --scenario TRUE" in usage
    assert "Fake로 조용히 대체" in usage


def test_operator_docs_never_embed_a_credential_or_claim_preflight_is_active() -> None:
    installation = _read("docs/installation.md")
    provider = _read("docs/provider-setup.md")

    assert "sk-" not in provider
    assert "cookie를 읽거나" in provider
    assert 'reference = "env:OPENAI_API_KEY"' in provider
    assert "설치 사전 확인일 뿐" in installation
    assert "자동으로 승인되지는 않습니다" in installation

