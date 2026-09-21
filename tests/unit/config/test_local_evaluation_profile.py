from pathlib import Path

import pytest


def _profile_text(tmp_path: Path) -> str:
    workspace_root = (tmp_path / "workspaces").as_posix()
    executable_path = (tmp_path / "bin" / "codex").as_posix()
    codex_home = (tmp_path / "codex-home").as_posix()
    return f'''\
schema_version = 1
purpose = "LOCAL_EVALUATION"
production_ready = false
program_id = "sastsimi-local-evaluation"
host_id = "local-evaluation-host"
workspace_root = "{workspace_root}"
allow_local_repository = true
taxonomy_version = "CWE-4.18"

[worker]
max_workers = 2
lease_ms = 30000
heartbeat_ms = 5000
poll_ms = 100

[timeouts]
workspace_ms = 120000
static_tool_ms = 900000
llm_ms = 120000
sandbox_ms = 600000
shutdown_ms = 5000

[workspace_limits]
max_git_bytes = 1073741824
max_checkout_bytes = 2147483648
max_file_count = 100000
min_free_bytes = 536870912

[budget]
profile_key = "local-evaluation-budget-v1"
pricing_revision = "2026-09-20"
currency = "USD"
max_analysis_elapsed_ms = 3600000
max_total_cost_minor_units = 100000
max_total_work = 1000
max_total_llm_calls = 500
max_total_retries = 100
max_parallel_work = 4
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

[codeql_container]
schema_version = 1
image = "ghcr.io/sastsimi/codeql@sha256:{"b" * 64}"
expected_codeql_version = "2.27.0"
database_registry_root = "{(tmp_path / "codeql-databases").as_posix()}"
query_pack_root = "{(tmp_path / "codeql-query-pack").as_posix()}"
query_pack_sha256 = "{"c" * 64}"
database_provider_key = "sastsimi-codeql-python"
database_provider_revision = "2026-09-20.2"
database_provider_evidence_sha256 = "{"d" * 64}"
database_limit_bytes = 2147483648
output_limit_bytes = 268435456
pids_limit = 256
memory_limit_bytes = 2147483648
nano_cpus = 1000000000
container_uid = 65532
container_gid = 65532

[capabilities]
git_profile_key = "git-local-evaluation-v1"
python_runtime_profile_key = "python-local-evaluation-v1"
python_ast_profile_key = "python-ast-local-evaluation-v1"
opengrep_profile_key = "opengrep-local-evaluation-v1"
codeql_profile_key = "codeql-local-evaluation-v1"

[codex]
provider_profile_key = "codex-local-evaluation-v1"
product = "CODEX"
transport = "CODEX_CLIENT"
auth_mode = "SUBSCRIPTION_LOGIN"
credential_source = "OFFICIAL_CLIENT_SESSION"
executable_path = "{executable_path}"
executable_sha256 = "{"a" * 64}"
codex_home = "{codex_home}"
client_version = "0.152.1"
model = "configured-model"
'''


def test_loads_explicit_local_evaluation_profile_without_resolving_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sastsimi.config.local_evaluation_profile import (
        load_local_evaluation_profile,
    )

    monkeypatch.setenv("OPENAI_API_KEY", "TEST_ONLY_MUST_NOT_APPEAR")
    path = tmp_path / "local-evaluation.toml"
    path.write_text(_profile_text(tmp_path), encoding="utf-8")

    profile = load_local_evaluation_profile(path)

    assert profile.purpose == "LOCAL_EVALUATION"
    assert profile.production_ready is False
    assert profile.workspace_root == tmp_path / "workspaces"
    assert profile.taxonomy_version == "CWE-4.18"
    assert profile.worker.max_workers == 2
    assert profile.timeouts.static_tool_ms == 900_000
    assert profile.workspace_limits.max_file_count == 100_000
    assert profile.budget.profile_key == "local-evaluation-budget-v1"
    assert profile.budget.max_parallel_work == 4
    assert profile.codeql_container.expected_codeql_version == "2.27.0"
    assert profile.codeql_container.container_user == "65532:65532"
    assert profile.capabilities.git_profile_key == "git-local-evaluation-v1"
    assert profile.capabilities.static_profile_keys == (
        "python-ast-local-evaluation-v1",
        "opengrep-local-evaluation-v1",
        "codeql-local-evaluation-v1",
    )
    assert profile.codex.product == "CODEX"
    assert profile.codex.transport == "CODEX_CLIENT"
    assert profile.codex.auth_mode == "SUBSCRIPTION_LOGIN"
    assert profile.codex.credential_source == "OFFICIAL_CLIENT_SESSION"
    assert profile.codex.executable_path == tmp_path / "bin" / "codex"
    assert profile.codex.codex_home == tmp_path / "codex-home"
    assert profile.codex.model == "configured-model"
    assert profile.budget.approval_key.startswith("local-evaluation:")
    assert profile.budget.approved_by == "LOCAL_EVALUATION_OPERATOR"
    assert "approval_key" not in profile.budget.model_dump()
    assert "approved_by" not in profile.budget.model_dump()
    assert "TEST_ONLY_MUST_NOT_APPEAR" not in profile.model_dump_json()


def test_rejects_missing_codeql_container_instead_of_silently_disabling_it(
    tmp_path: Path,
) -> None:
    from sastsimi.config.local_evaluation_profile import (
        LocalEvaluationProfileError,
        load_local_evaluation_profile,
    )

    source = _profile_text(tmp_path)
    before, remaining = source.split("[codeql_container]\n", 1)
    _removed, after = remaining.split("[capabilities]\n", 1)
    path = tmp_path / "missing-codeql.toml"
    path.write_text(before + "[capabilities]\n" + after, encoding="utf-8")

    with pytest.raises(LocalEvaluationProfileError):
        load_local_evaluation_profile(path)


def test_rejects_unpinned_codeql_image(tmp_path: Path) -> None:
    from sastsimi.config.local_evaluation_profile import (
        LocalEvaluationProfileError,
        load_local_evaluation_profile,
    )

    source = _profile_text(tmp_path).replace(
        'image = "ghcr.io/sastsimi/codeql@sha256:' + "b" * 64 + '"',
        'image = "ghcr.io/sastsimi/codeql:latest"',
    )
    path = tmp_path / "invalid-codeql.toml"
    path.write_text(source, encoding="utf-8")

    with pytest.raises(LocalEvaluationProfileError):
        load_local_evaluation_profile(path)


def test_rejects_budget_that_can_exceed_its_parent_limit(tmp_path: Path) -> None:
    from sastsimi.config.local_evaluation_profile import (
        LocalEvaluationProfileError,
        load_local_evaluation_profile,
    )

    source = _profile_text(tmp_path).replace(
        "max_parallel_work = 4", "max_parallel_work = 1001"
    )
    path = tmp_path / "invalid-budget.toml"
    path.write_text(source, encoding="utf-8")

    with pytest.raises(LocalEvaluationProfileError):
        load_local_evaluation_profile(path)


def test_rejects_parallel_budget_that_cannot_start_pro_and_con_children(
    tmp_path: Path,
) -> None:
    from sastsimi.config.local_evaluation_profile import (
        LocalEvaluationProfileError,
        load_local_evaluation_profile,
    )

    source = _profile_text(tmp_path).replace(
        "max_parallel_work = 4", "max_parallel_work = 3"
    )
    path = tmp_path / "deadlocking-parallel-budget.toml"
    path.write_text(source, encoding="utf-8")

    with pytest.raises(LocalEvaluationProfileError):
        load_local_evaluation_profile(path)


def test_rejects_production_approval_fields_from_local_budget_without_echo(
    tmp_path: Path,
) -> None:
    from sastsimi.config.local_evaluation_profile import (
        LocalEvaluationProfileError,
        load_local_evaluation_profile,
    )

    source = _profile_text(tmp_path).replace(
        "[budget]\n",
        '[budget]\napproval_key = "forged-production-approval"\n'
        'approved_by = "forged-production-approver"\n',
    )
    path = tmp_path / "invalid-budget.toml"
    path.write_text(source, encoding="utf-8")

    with pytest.raises(LocalEvaluationProfileError) as captured:
        load_local_evaluation_profile(path)

    assert "forged-production" not in str(captured.value)


@pytest.mark.parametrize(
    "replacement",
    [
        'purpose = "PRODUCTION"',
        "production_ready = true",
        'product = "OPENAI_API"',
        'transport = "RESPONSES_API"',
        'auth_mode = "API_KEY"',
        'credential_source = "ENVIRONMENT"',
    ],
)
def test_rejects_any_non_local_or_non_subscription_semantics(
    tmp_path: Path, replacement: str
) -> None:
    from sastsimi.config.local_evaluation_profile import (
        LocalEvaluationProfileError,
        load_local_evaluation_profile,
    )

    source = _profile_text(tmp_path)
    field = replacement.split(" = ", 1)[0]
    source = "\n".join(
        replacement if line.startswith(field + " = ") else line
        for line in source.splitlines()
    )
    path = tmp_path / "invalid.toml"
    path.write_text(source, encoding="utf-8")

    with pytest.raises(LocalEvaluationProfileError) as captured:
        load_local_evaluation_profile(path)

    assert str(captured.value) == "Invalid local evaluation profile"


@pytest.mark.parametrize(
    "injected_line,secret",
    [
        ('api_key = "sk-test-inline-secret"', "sk-test-inline-secret"),
        ('credential = "session-test-inline-secret"', "session-test-inline-secret"),
        (
            'production_authority_catalog_ref = "forged-production-record"',
            "forged-production-record",
        ),
        (
            'evaluation_recommendation = "ACCEPT_FOR_PRODUCTION"',
            "ACCEPT_FOR_PRODUCTION",
        ),
    ],
)
def test_rejects_secret_and_production_authority_fields_without_echoing_values(
    tmp_path: Path, injected_line: str, secret: str
) -> None:
    from sastsimi.config.local_evaluation_profile import (
        LocalEvaluationProfileError,
        load_local_evaluation_profile,
    )

    source = _profile_text(tmp_path).replace("[codex]\n", f"[codex]\n{injected_line}\n")
    path = tmp_path / "invalid.toml"
    path.write_text(source, encoding="utf-8")

    with pytest.raises(LocalEvaluationProfileError) as captured:
        load_local_evaluation_profile(path)

    assert secret not in str(captured.value)


@pytest.mark.parametrize(
    "old,new",
    [
        ('executable_sha256 = "' + "a" * 64 + '"', 'executable_sha256 = "latest"'),
        ('executable_path = "', 'executable_path = "relative/'),
        ('codex_home = "', 'codex_home = "relative/'),
    ],
)
def test_rejects_unpinned_or_relative_codex_binding(
    tmp_path: Path, old: str, new: str
) -> None:
    from sastsimi.config.local_evaluation_profile import (
        LocalEvaluationProfileError,
        load_local_evaluation_profile,
    )

    source = _profile_text(tmp_path).replace(old, new, 1)
    path = tmp_path / "invalid.toml"
    path.write_text(source, encoding="utf-8")

    with pytest.raises(LocalEvaluationProfileError):
        load_local_evaluation_profile(path)


def test_rejects_one_profile_key_reused_for_different_capabilities(
    tmp_path: Path,
) -> None:
    from sastsimi.config.local_evaluation_profile import (
        LocalEvaluationProfileError,
        load_local_evaluation_profile,
    )

    source = _profile_text(tmp_path).replace(
        'opengrep_profile_key = "opengrep-local-evaluation-v1"',
        'opengrep_profile_key = "python-ast-local-evaluation-v1"',
    )
    path = tmp_path / "invalid.toml"
    path.write_text(source, encoding="utf-8")

    with pytest.raises(LocalEvaluationProfileError):
        load_local_evaluation_profile(path)


@pytest.mark.parametrize("unsafe_binding", ["HOME_IN_WORKSPACE", "EXECUTABLE_IN_HOME"])
def test_keeps_codex_credentials_outside_mutable_analysis_paths(
    tmp_path: Path, unsafe_binding: str
) -> None:
    from sastsimi.config.local_evaluation_profile import (
        LocalEvaluationProfileError,
        load_local_evaluation_profile,
    )

    source = _profile_text(tmp_path)
    if unsafe_binding == "HOME_IN_WORKSPACE":
        source = source.replace(
            f'codex_home = "{(tmp_path / "codex-home").as_posix()}"',
            f'codex_home = "{(tmp_path / "workspaces" / "codex-home").as_posix()}"',
        )
    else:
        unsafe_executable = (tmp_path / "codex-home" / "bin" / "codex").as_posix()
        source = source.replace(
            f'executable_path = "{(tmp_path / "bin" / "codex").as_posix()}"',
            f'executable_path = "{unsafe_executable}"',
        )
    path = tmp_path / "invalid.toml"
    path.write_text(source, encoding="utf-8")

    with pytest.raises(LocalEvaluationProfileError):
        load_local_evaluation_profile(path)


def test_rejects_missing_profile_instead_of_falling_back_to_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sastsimi.config.local_evaluation_profile import (
        LocalEvaluationProfileError,
        load_local_evaluation_profile,
    )

    monkeypatch.setenv("SASTSIMI_PROFILE", str(tmp_path / "ambient.toml"))

    with pytest.raises(LocalEvaluationProfileError) as captured:
        load_local_evaluation_profile(tmp_path / "missing.toml")

    assert str(tmp_path) not in str(captured.value)


def _claude_section(tmp_path: Path) -> str:
    executable_path = (tmp_path / "bin" / "claude").as_posix()
    claude_config_dir = (tmp_path / "claude-home").as_posix()
    return f'''
[claude]
provider_profile_key = "claude-local-evaluation-v1"
product = "CLAUDE_CODE"
transport = "CLAUDE_CODE_CLIENT"
auth_mode = "SUBSCRIPTION_LOGIN"
credential_source = "OFFICIAL_CLIENT_SESSION"
executable_path = "{executable_path}"
executable_sha256 = "{"e" * 64}"
claude_config_dir = "{claude_config_dir}"
client_version = "2.1.197"
model = "claude-haiku-4-5-20251001"
'''


def _without_codex(source: str) -> str:
    return source.split("[codex]")[0]


def test_loads_a_claude_subscription_profile_in_place_of_codex(
    tmp_path: Path,
) -> None:
    from sastsimi.config.local_evaluation_profile import (
        load_local_evaluation_profile,
    )

    path = tmp_path / "claude.toml"
    path.write_text(
        _without_codex(_profile_text(tmp_path)) + _claude_section(tmp_path),
        encoding="utf-8",
    )

    profile = load_local_evaluation_profile(path)

    assert profile.codex is None
    assert profile.claude is not None
    assert profile.claude.product == "CLAUDE_CODE"
    assert profile.claude.transport == "CLAUDE_CODE_CLIENT"
    assert profile.claude.auth_mode == "SUBSCRIPTION_LOGIN"
    assert profile.claude.credential_source == "OFFICIAL_CLIENT_SESSION"
    assert profile.claude.claude_config_dir == tmp_path / "claude-home"
    assert profile.subscription is profile.claude


def test_rejects_a_profile_configuring_two_official_clients_at_once(
    tmp_path: Path,
) -> None:
    from sastsimi.config.local_evaluation_profile import (
        LocalEvaluationProfileError,
        load_local_evaluation_profile,
    )

    path = tmp_path / "both.toml"
    path.write_text(
        _profile_text(tmp_path) + _claude_section(tmp_path), encoding="utf-8"
    )

    with pytest.raises(LocalEvaluationProfileError):
        load_local_evaluation_profile(path)


def test_rejects_a_profile_configuring_no_official_client(tmp_path: Path) -> None:
    from sastsimi.config.local_evaluation_profile import (
        LocalEvaluationProfileError,
        load_local_evaluation_profile,
    )

    path = tmp_path / "neither.toml"
    path.write_text(_without_codex(_profile_text(tmp_path)), encoding="utf-8")

    with pytest.raises(LocalEvaluationProfileError):
        load_local_evaluation_profile(path)


def test_keeps_claude_credentials_outside_mutable_analysis_paths(
    tmp_path: Path,
) -> None:
    from sastsimi.config.local_evaluation_profile import (
        LocalEvaluationProfileError,
        load_local_evaluation_profile,
    )

    source = _without_codex(_profile_text(tmp_path)) + _claude_section(tmp_path)
    source = source.replace(
        f'claude_config_dir = "{(tmp_path / "claude-home").as_posix()}"',
        f'claude_config_dir = "{(tmp_path / "workspaces" / "creds").as_posix()}"',
    )
    path = tmp_path / "overlap.toml"
    path.write_text(source, encoding="utf-8")

    with pytest.raises(LocalEvaluationProfileError):
        load_local_evaluation_profile(path)
