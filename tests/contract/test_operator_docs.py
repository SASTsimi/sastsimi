import tomllib
from pathlib import Path

from sastsimi.orchestration.production_onboarding import (
    ProductionProvisioningManifest,
)
from sastsimi.orchestration.production_provisioning import (
    VerificationPlaybooksProvisioningTemplate,
)

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
    assert "analyze --scenario TRUE" not in usage.replace(
        "demo analyze --scenario TRUE", ""
    )
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
    assert "codex login" in provider
    assert "codex login status" in provider
    assert "공식 Codex CLI adapter는 구현되어" in provider
    assert "`SUPPORTED`가 되기 전에는 production route에 선택되지 않습니다" in provider


def test_source_cli_and_onboarding_contract_are_documented() -> None:
    operator_paths = (
        "README.md",
        "docs/installation.md",
        "docs/provider-setup.md",
        "docs/usage.md",
        "docs/troubleshooting.md",
        "docs/onboarding-evidence.md",
    )
    combined = "\n".join(_read(path) for path in operator_paths)

    assert "\nsastsimi " not in combined
    assert "uv run sastsimi analyze --help" in combined
    assert "ProductionOnboardingManifest" in combined
    assert "ProductionProvisioningManifest" in combined
    assert "PVDObservation" in combined
    assert "onboarding init --profile" in combined
    for field in (
        "provisioning_manifest_sha256",
        "policy_artifact_sha256",
        "provider_approvals",
        "route_approvals",
        "evidence_sha256",
        "profile_ref",
        "content_sha256",
    ):
        assert field in combined
    assert "실제 값은 쓰지 않습니다" in combined


def test_provisioning_examples_use_pre_run_host_profile_templates() -> None:
    onboarding = _read("docs/onboarding-evidence.md")
    provisioning = onboarding.split(
        "## 3. `ProductionProvisioningManifest`", maxsplit=1
    )[1].split("## 4. `ProductionOnboardingManifest`", maxsplit=1)[0]

    assert '"schema_version": 2' in provisioning
    assert '"artifact_scope": "HOST_PROFILE_TEMPLATE"' in provisioning
    assert '"template_scope": "HOST_PROFILE"' in provisioning
    assert '"record_templates"' in provisioning
    assert '"analysis_id":' not in provisioning
    assert '"workspace_id":' not in provisioning
    assert '"commit_id":' not in provisioning
    assert '"record_refs":' not in provisioning
    assert "분석 접수 후 runtime이 세 ID를 발급" in provisioning

    assert {"schema_version", "artifact_scope", "profile_hash", "host_id"} <= set(
        ProductionProvisioningManifest.model_fields
    )
    assert {
        "schema_version",
        "template_scope",
        "profile_hash",
        "host_id",
        "record_templates",
    } <= set(VerificationPlaybooksProvisioningTemplate.model_fields)
    assert not {
        "analysis_id",
        "workspace_id",
        "commit_id",
        "record_refs",
    } & set(VerificationPlaybooksProvisioningTemplate.model_fields)


def test_production_profile_example_is_complete_and_contains_no_secret() -> None:
    path = ROOT / "config/profiles/production.example.toml"
    raw = path.read_text(encoding="utf-8")
    profile = tomllib.loads(raw)

    assert path.is_file()
    assert "sk-" not in raw
    assert profile["allow_local_repository"] is False
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
    routes = {(item["role"], item["task_kind"]) for item in profile["llm_routes"]}
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
