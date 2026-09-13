import tomllib
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
        "docs/release-follow-ups.md",
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
    assert "Fake로 자동 대체하지 않습니다" in usage
    assert "Fake 없는 live E2E" in usage
    assert "PRODUCTION_E2E_NOT_YET_PROVEN" in readme


def test_operator_docs_never_embed_a_credential_or_claim_preflight_is_active() -> None:
    installation = _read("docs/installation.md")
    provider = _read("docs/provider-setup.md")

    assert "sk-" not in provider
    assert "cookie를 읽거나" in provider
    assert 'reference = "env:OPENAI_API_KEY"' in provider
    assert "설치나 `--version` 성공만으로" in installation
    assert "activation_supported=false" in installation
    assert "activation_supported=false" in provider
    assert "EXPERIMENTAL" in provider
    assert "production 자동 활성화가 금지" in provider


def test_production_profile_example_is_complete_and_contains_no_secret() -> None:
    path = ROOT / "config/profiles/production.example.toml"
    raw = path.read_text(encoding="utf-8")
    profile = tomllib.loads(raw)

    assert path.is_file()
    assert "sk-" not in raw
    assert profile["providers"] == [
        {
            "provider_profile_key": "approved-openai-profile",
            "product": "OPENAI_API",
            "environment": "PERSONAL_LOCAL",
            "client_name": "openai-python",
            "client_version": "replace-with-approved-client-version",
            "credential_ref": {"reference": "env:OPENAI_API_KEY"},
        }
    ]
    routes = {
        (item["role"], item["task_kind"]) for item in profile["llm_routes"]
    }
    assert routes == {
        ("HYPOTHESIS", "GENERATE_INITIAL"),
        ("PRO", "COLLECT_SUPPORT"),
        ("CON", "COLLECT_COUNTEREVIDENCE"),
        ("VERIFICATION", "ASSESS_INITIAL"),
        ("VERIFICATION", "CREATE_DYNAMIC_REQUEST"),
        ("VERIFICATION", "FINAL_VERDICT"),
        ("DYNAMIC_REPRODUCTION", "DERIVE_ENVIRONMENT"),
        ("DYNAMIC_REPRODUCTION", "PLAN_REPRODUCTION"),
        ("DYNAMIC_REPRODUCTION", "CREATE_POC_CANDIDATE"),
        ("DYNAMIC_REPRODUCTION", "EXECUTE_REPRODUCTION"),
        ("DYNAMIC_REPRODUCTION", "INTERPRET_ATTEMPT"),
        ("CWE_LABELING", "CLASSIFY_CWE"),
        ("TECHNICAL_GATE", "REVIEW_TECHNICAL"),
        ("RULE_SCOPE_GATE", "REVIEW"),
        ("REPORTER", "CREATE_DRAFT"),
        ("POLICY_PARSER", "PARSE_OFFICIAL_POLICY"),
        ("CHAINING", "MATCH_PRIMITIVES"),
    }
    assert all(
        item["model"] == "replace-with-approved-model-id"
        for item in profile["llm_routes"]
    )
