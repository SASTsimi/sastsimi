from pathlib import Path

import pytest


def test_precedence_and_local_path(tmp_path: Path) -> None:
    from sastsimi.config.loader import load_config

    path = tmp_path / "approved.toml"
    path.write_text(
        'schema_version = 1\nlog_level = "WARNING"\noutput_format = "json"\n',
        encoding="utf-8",
    )
    defaults = load_config(environ={})
    assert defaults.log_level == "INFO"
    assert defaults.output_format == "text"
    assert defaults.data_dir.is_absolute()
    assert load_config(config_path=path, environ={}).log_level == "WARNING"
    assert (
        load_config(config_path=path, environ={"SASTSIMI_LOG_LEVEL": "ERROR"}).log_level
        == "ERROR"
    )
    config = load_config(
        config_path=path,
        environ={
            "SASTSIMI_LOG_LEVEL": "ERROR",
            "SASTSIMI_DATA_DIR": str(tmp_path / "state"),
        },
        cli={"log_level": "DEBUG"},
    )
    assert config.log_level == "DEBUG"
    assert config.output_format == "json"
    assert config.data_dir == tmp_path / "state"
    assert not config.data_dir.exists()
    assert "data_dir" not in config.model_dump()
    assert str(tmp_path) not in repr(config)


@pytest.mark.parametrize(
    "source",
    [
        'schema_version = 1\nunknown = "x"',
        "schema_version = 2",
        "schema_version = true",
        'log_level = "INFO"',
        'schema_version = 1\nlog_level = "oops"',
        "schema_version = 1\noutput_format = 42",
        'schema_version = 1\ndata_dir = ""',
        'schema_version = 1\napi_key = "TEST_ONLY_KEY"',
        "schema_version = ",
    ],
)
def test_invalid_toml_is_not_masked_by_cli(tmp_path: Path, source: str) -> None:
    from sastsimi.config.loader import ConfigError, load_config

    path = tmp_path / "approved.toml"
    path.write_text(source, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(config_path=path, environ={}, cli={"log_level": "INFO"})


@pytest.mark.parametrize(
    "environ",
    [
        {"SASTSIMI_UNKNOWN": "x"},
        {"SASTSIMI_LOG_LEVEL": "oops"},
        {"SASTSIMI_SCHEMA_VERSION": "1"},
        {"SASTSIMI_DATA_DIR": ""},
    ],
)
def test_invalid_environment_fails_before_override(environ: dict[str, str]) -> None:
    from sastsimi.config.loader import ConfigError, load_config

    with pytest.raises(ConfigError):
        load_config(environ=environ, cli={"log_level": "INFO"})


@pytest.mark.parametrize(
    "cli", [{"schema_version": 1}, {"secret": "x"}, {"output_format": "yaml"}]
)
def test_non_allowlisted_or_invalid_cli(cli: dict[str, object]) -> None:
    from sastsimi.config.loader import ConfigError, load_config

    with pytest.raises(ConfigError):
        load_config(environ={}, cli=cli)


def test_explicit_missing_file_and_no_repository_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sastsimi.config.loader import ConfigError, load_config

    monkeypatch.chdir(tmp_path)
    (tmp_path / "sastsimi.toml").write_text(
        'schema_version=1\nlog_level="ERROR"', encoding="utf-8"
    )
    assert load_config(environ={}).log_level == "INFO"
    with pytest.raises(ConfigError):
        load_config(config_path=tmp_path / "absent.toml", environ={})


@pytest.mark.parametrize(
    "value", ["env:TEST_ONLY_API_KEY", "handle:00000000-0000-4000-8000-000000000001"]
)
def test_secret_reference_does_not_resolve(
    value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sastsimi.config.secrets import SecretReference

    monkeypatch.setenv("TEST_ONLY_API_KEY", "TEST_ONLY_NEVER_RESOLVE")
    ref = SecretReference.model_validate({"reference": value})
    assert ref.reference == value
    assert "TEST_ONLY_NEVER_RESOLVE" not in ref.model_dump_json()


@pytest.mark.parametrize(
    "value",
    [
        "sk-test-only-key",
        "cookie=a",
        "token=test",
        "password=test",
        "env:a=b",
        "env:lowercase",
        "handle:raw-password",
        "env:",
    ],
)
def test_literal_secret_rejected(value: str) -> None:
    from pydantic import ValidationError

    from sastsimi.config.secrets import SecretReference

    with pytest.raises(ValidationError):
        SecretReference.model_validate({"reference": value})
