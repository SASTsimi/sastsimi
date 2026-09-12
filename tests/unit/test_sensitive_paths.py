"""Shared sensitive-path policy behavior at every source-code boundary."""

from __future__ import annotations

import pytest

from sastsimi.security.sensitive_paths import DEFAULT_SENSITIVE_PATH_POLICY


def test_sensitive_path_policy_allows_regular_source() -> None:
    assert not DEFAULT_SENSITIVE_PATH_POLICY.is_sensitive("src/app.py")


@pytest.mark.parametrize(
    "git_path",
    (
        "config/.NPMRC",
        "deploy/service-account.json",
        "maven/settings.xml",
        ".env.production",
        "keys/client.pem",
        ".aws/credentials",
        ".docker/config.json",
    ),
)
def test_sensitive_path_policy_blocks_known_credential_files(git_path: str) -> None:
    assert DEFAULT_SENSITIVE_PATH_POLICY.is_sensitive(git_path)
