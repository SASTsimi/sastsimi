from pathlib import Path

import pytest


def _profile_text(workspace_root: Path) -> str:
    root = workspace_root.as_posix()
    return f'''\
schema_version = 1
program_id = "example-program"
host_id = "local-host"
workspace_root = "{root}"
taxonomy_version = "CWE-4.17"

[worker]
max_workers = 4
lease_ms = 30000
heartbeat_ms = 5000
poll_ms = 100

[timeouts]
workspace_ms = 120000
static_tool_ms = 300000
llm_ms = 120000
sandbox_ms = 600000
shutdown_ms = 5000

[tools]
git = "git"
python = "python"
codeql = "codeql"
opengrep = "opengrep"
docker = "docker"

[policy]
program_namespace = "example"
external_program_id = "example-program"
source_version = "2026-09-13"
official_endpoint = "https://security.example.test/policy"
publisher = "example"
parser_name = "default"
parser_version = "1.0.0"
freshness_ttl_seconds = 3600
timeout_seconds = 30
max_response_bytes = 1048576
allowed_content_types = ["text/html"]
allowed_redirect_hosts = []

[[providers]]
provider_profile_key = "openai-primary"
product = "OPENAI_API"
environment = "PERSONAL_LOCAL"
client_name = "openai-python"
client_version = "1"
credential_ref = {{ reference = "env:OPENAI_API_KEY" }}

[[llm_routes]]
role = "HYPOTHESIS"
task_kind = "GENERATE_INITIAL"
provider_profile_key = "openai-primary"
model = "configured-model"
prompt_key = "hypothesis.generate-initial.production-v1"
'''


def test_loads_explicit_production_profile_without_resolving_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sastsimi.config.production_profile import load_production_profile

    monkeypatch.setenv("OPENAI_API_KEY", "TEST_ONLY_MUST_NOT_APPEAR")
    workspace_root = tmp_path / "workspaces"
    path = tmp_path / "production.toml"
    path.write_text(_profile_text(workspace_root), encoding="utf-8")

    profile = load_production_profile(path)

    assert profile.program_id == "example-program"
    assert profile.workspace_root == workspace_root
    assert profile.worker.max_workers == 4
    assert profile.tools.codeql == "codeql"
    assert profile.llm_routes[0].model == "configured-model"
    assert profile.providers[0].credential_ref.reference == "env:OPENAI_API_KEY"
    assert "TEST_ONLY_MUST_NOT_APPEAR" not in profile.model_dump_json()


@pytest.mark.parametrize(
    "invalid_line,secret",
    [
        ('api_key = "sk-test-only-inline"', "sk-test-only-inline"),
        (
            'credential_ref = { reference = "sk-test-only-inline" }',
            "sk-test-only-inline",
        ),
    ],
)
def test_rejects_unknown_keys_and_inline_secrets_without_echoing_them(
    tmp_path: Path, invalid_line: str, secret: str
) -> None:
    from sastsimi.config.production_profile import (
        ProductionProfileError,
        load_production_profile,
    )

    source = _profile_text(tmp_path / "workspaces")
    if invalid_line.startswith("credential_ref"):
        source = source.replace(
            'credential_ref = { reference = "env:OPENAI_API_KEY" }', invalid_line
        )
    else:
        source = source.replace(
            "schema_version = 1", "schema_version = 1\n" + invalid_line
        )
    path = tmp_path / "invalid.toml"
    path.write_text(source, encoding="utf-8")

    with pytest.raises(ProductionProfileError) as captured:
        load_production_profile(path)

    assert secret not in str(captured.value)
