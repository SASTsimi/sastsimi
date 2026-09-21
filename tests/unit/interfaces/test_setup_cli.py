# mypy: disable-error-code="no-untyped-def"
from __future__ import annotations

import json
from pathlib import Path

from sastsimi.config.user_config import UserConfigStore
from sastsimi.interfaces.cli.main import main
from sastsimi.setup.service import (
    SetupChoices,
    SetupService,
    ToolInspection,
)


class _Discovery:
    def __init__(self, missing: frozenset[str] = frozenset()) -> None:
        self._missing = missing

    def inspect(self) -> tuple[ToolInspection, ...]:
        return tuple(
            ToolInspection(
                name=name,
                available=name not in self._missing,
                executable=None if name in self._missing else Path(f"C:/{name}.exe"),
                version=None if name in self._missing else "1.0.0",
                executable_sha256=None if name in self._missing else "a" * 64,
            )
            for name in ("git", "python", "opengrep", "codeql", "docker", "codex")
        )


def _service(tmp_path: Path, *, missing: frozenset[str] = frozenset()):
    return SetupService(
        config_store=UserConfigStore(tmp_path / "config.toml"),
        discovery=_Discovery(missing),
        profile_path=tmp_path / "profile.toml",
        auth_checker=lambda _choices, _tools: True,
    )


def test_setup_cli_writes_ready_secret_free_configuration(
    tmp_path: Path, capsys
) -> None:
    service = _service(tmp_path)

    code = main(
        [
            "setup",
            "--non-interactive",
            "--data-dir",
            str(tmp_path / "data"),
            "--auth",
            "subscription",
            "--provider",
            "codex",
            "--model",
            "configured-model",
            "--profile",
            "full",
            "--docker-network",
            "none",
            "--format",
            "json",
        ],
        setup_service=service,
    )

    assert code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["data"]["status"] == "READY"
    assert output["data"]["missing_tools"] == []
    saved = service.config_store.load()
    assert saved.credential_ref == "OFFICIAL_CLIENT_SESSION"
    assert saved.setup_ready is True
    raw = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert "access_token" not in raw
    assert "refresh_token" not in raw
    assert "sk-" not in raw


def test_setup_cli_blocks_full_profile_when_codeql_is_missing(
    tmp_path: Path, capsys
) -> None:
    service = _service(tmp_path, missing=frozenset({"codeql"}))

    code = main(
        [
            "setup",
            "--non-interactive",
            "--data-dir",
            str(tmp_path / "data"),
            "--auth",
            "api-key",
            "--provider",
            "openai",
            "--model",
            "configured-model",
            "--profile",
            "full",
            "--docker-network",
            "none",
            "--format",
            "json",
        ],
        setup_service=service,
    )

    assert code == 4
    output = json.loads(capsys.readouterr().err)
    assert output["data"]["status"] == "BLOCKED"
    assert output["data"]["missing_tools"] == ["codeql"]
    assert service.config_store.load().setup_ready is False


def test_setup_service_accepts_explicit_choices_without_cli(tmp_path: Path) -> None:
    service = _service(tmp_path)
    result = service.configure(
        SetupChoices(
            data_dir=tmp_path / "data",
            auth_mode="API_KEY",
            provider="openai",
            model="configured-model",
            credential_ref="env:OPENAI_API_KEY",
            execution_profile="LIGHTWEIGHT",
            max_cost_minor_units=10_000,
            max_tokens=500_000,
            max_elapsed_seconds=3_600,
            docker_network="NONE",
        )
    )

    assert result.status == "READY"
    assert result.profile_path.is_file()
