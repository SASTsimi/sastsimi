from pathlib import Path

import pytest


def _profile_text(workspace_root: Path) -> str:
    root = workspace_root.as_posix()
    return f'''\
schema_version = 1
program_id = "example-program"
host_id = "local-host"
workspace_root = "{root}"
allow_local_repository = true
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

[workspace_limits]
max_git_bytes = 1073741824
max_checkout_bytes = 2147483648
max_file_count = 100000
min_free_bytes = 536870912

[budget]
profile_key = "operator-default"
approval_key = "security-team-approved-v1"
approved_by = "security-team"
pricing_revision = "pricing-2026-09"
currency = "USD"
max_analysis_elapsed_ms = 3600000
max_total_cost_minor_units = 100000
max_total_work = 1000
max_total_llm_calls = 500
max_total_retries = 100
max_parallel_work = 8
work_timeout_ms = 600000
max_attempts_per_work = 3
max_calls_per_work = 10
max_items_per_work = 1000
max_verification_elapsed_ms = 900000
max_work_per_verification = 100
max_llm_calls_per_verification = 50
max_retries_per_work = 3
max_parallel_evidence_calls = 2
max_dynamic_attempts = 3

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


def _with_codeql_container(
    source: str, tmp_path: Path, *, image: str | None = None
) -> str:
    configured_image = image or ("ghcr.io/sastsimi/codeql@sha256:" + "a" * 64)
    table = f'''\
[codeql_container]
schema_version = 1
image = "{configured_image}"
expected_codeql_version = "2.27.0"
database_registry_root = "{(tmp_path / "codeql-databases").as_posix()}"
query_pack_root = "{(tmp_path / "codeql-query-pack").as_posix()}"
query_pack_sha256 = "{"b" * 64}"
database_provider_key = "approved-codeql-db-provider"
database_provider_revision = "2026-09-19-r1"
database_provider_evidence_sha256 = "{"c" * 64}"
database_limit_bytes = 4294967296
output_limit_bytes = 268435456
pids_limit = 256
memory_limit_bytes = 8589934592
nano_cpus = 2000000000
container_uid = 65532
container_gid = 65532

'''
    return source.replace("[policy]\n", table + "[policy]\n")


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
    assert profile.allow_local_repository is True
    assert profile.worker.max_workers == 4
    assert profile.workspace_limits.max_file_count == 100_000
    assert profile.budget.max_parallel_work == 8
    assert profile.tools.codeql == "codeql"
    assert profile.llm_routes[0].model == "configured-model"
    assert profile.providers[0].credential_ref.reference == "env:OPENAI_API_KEY"
    assert profile.codeql_container is None
    assert "TEST_ONLY_MUST_NOT_APPEAR" not in profile.model_dump_json()


def test_rejects_parallel_budget_that_cannot_start_pro_and_con_children(
    tmp_path: Path,
) -> None:
    from sastsimi.config.production_profile import (
        ProductionProfileError,
        load_production_profile,
    )

    source = _profile_text(tmp_path / "workspaces").replace(
        "max_parallel_work = 8", "max_parallel_work = 5"
    )
    path = tmp_path / "deadlocking-parallel-budget.toml"
    path.write_text(source, encoding="utf-8")

    with pytest.raises(ProductionProfileError):
        load_production_profile(path)


def test_loads_optional_codeql_container_table(tmp_path: Path) -> None:
    from sastsimi.config.production_profile import load_production_profile

    path = tmp_path / "production.toml"
    path.write_text(
        _with_codeql_container(_profile_text(tmp_path / "workspaces"), tmp_path),
        encoding="utf-8",
    )

    profile = load_production_profile(path)

    assert profile.codeql_container is not None
    assert profile.codeql_container.image.endswith("@sha256:" + "a" * 64)
    assert profile.codeql_container.expected_codeql_version == "2.27.0"
    assert profile.codeql_container.container_user == "65532:65532"


def test_rejects_unpinned_codeql_container_image(tmp_path: Path) -> None:
    from sastsimi.config.production_profile import (
        ProductionProfileError,
        load_production_profile,
    )

    path = tmp_path / "invalid.toml"
    path.write_text(
        _with_codeql_container(
            _profile_text(tmp_path / "workspaces"),
            tmp_path,
            image="ghcr.io/sastsimi/codeql:2.27.0",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ProductionProfileError):
        load_production_profile(path)


def test_omitted_codeql_container_remains_compatible(tmp_path: Path) -> None:
    from sastsimi.config.production_profile import load_production_profile

    path = tmp_path / "production.toml"
    path.write_text(_profile_text(tmp_path / "workspaces"), encoding="utf-8")

    profile = load_production_profile(path)

    assert profile.codeql_container is None


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
