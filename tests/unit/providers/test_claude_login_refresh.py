import json
from pathlib import Path

import pytest

from sastsimi.providers.claude_subscription import _refresh_lapsing_login


def _client(tmp_path: Path) -> tuple[Path, Path]:
    record = tmp_path / "called.txt"
    executable = tmp_path / "claude"
    executable.write_text(f'#!/bin/sh\necho "$@" > {record}\n')
    executable.chmod(0o755)
    return executable, record


def _login(config_dir: Path, expires_at: int) -> None:
    config_dir.mkdir()
    (config_dir / ".credentials.json").write_text(
        json.dumps({"claudeAiOauth": {"expiresAt": expires_at}})
    )


@pytest.mark.asyncio
async def test_a_lapsed_login_is_renewed_through_the_plain_client(
    tmp_path: Path,
) -> None:
    executable, record = _client(tmp_path)
    _login(tmp_path / "config", expires_at=0)

    await _refresh_lapsing_login(executable, tmp_path / "config")

    called = record.read_text()
    assert called.startswith("-p --model claude-haiku")
    assert called.rstrip().endswith("ok")


@pytest.mark.asyncio
async def test_a_current_login_is_left_alone(tmp_path: Path) -> None:
    executable, record = _client(tmp_path)
    _login(tmp_path / "config", expires_at=99_999_999_999_999)

    await _refresh_lapsing_login(executable, tmp_path / "config")

    assert not record.exists()
