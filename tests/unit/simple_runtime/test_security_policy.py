"""A project's own statement of what it accepts as a report is policy.

Every run so far ended "no official policy, internal review only" because the
gate looked only for published program records, and the SimpleRuntime database
has no such table.  Meanwhile open-webui shipped a 21 KB SECURITY.md saying
configuration options are not vulnerabilities - which is exactly what one run
judged TRUE and wrote a report for.
"""

from __future__ import annotations

from pathlib import Path

from sastsimi.simple_runtime.bootstrap_stages import _security_policy


def _repo(tmp_path: Path, name: str, body: str = "# Security Policy\n") -> Path:
    workspace = tmp_path / "repo"
    target = workspace / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    return workspace


def test_a_policy_in_the_checkout_is_collected(tmp_path: Path) -> None:
    workspace = _repo(
        tmp_path,
        "docs/SECURITY.md",
        "Configuration options are not vulnerabilities.\n",
    )

    policy = _security_policy(workspace, ("docs/SECURITY.md", "app.py"))

    assert policy is not None
    assert policy["path"] == "docs/SECURITY.md"
    assert "not vulnerabilities" in str(policy["content"])


def test_the_root_policy_wins_when_more_than_one_exists(tmp_path: Path) -> None:
    workspace = _repo(tmp_path, "SECURITY.md", "root\n")
    (workspace / "docs").mkdir()
    (workspace / "docs" / "SECURITY.md").write_text("docs\n", encoding="utf-8")

    policy = _security_policy(workspace, ("docs/SECURITY.md", "SECURITY.md"))

    assert policy is not None
    assert policy["path"] == "SECURITY.md"


def test_a_repository_without_a_policy_says_so_rather_than_inventing_one(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()

    assert _security_policy(workspace, ("app.py", "README.md")) is None


def test_an_empty_policy_file_is_not_a_policy(tmp_path: Path) -> None:
    workspace = _repo(tmp_path, "SECURITY.md", "   \n\n")

    assert _security_policy(workspace, ("SECURITY.md",)) is None


def test_a_long_policy_is_read_whole(tmp_path: Path) -> None:
    """An exclusion near the end of a policy is still an exclusion."""

    workspace = _repo(
        tmp_path, "SECURITY.md", "x" * 100_000 + "\nConfiguration is not a bug.\n"
    )

    policy = _security_policy(workspace, ("SECURITY.md",))

    assert policy is not None
    assert "Configuration is not a bug." in str(policy["content"])


def test_a_file_only_on_disk_is_not_read(tmp_path: Path) -> None:
    """The tracked list is the checkout; anything else is not part of it."""

    workspace = _repo(tmp_path, "SECURITY.md", "untracked\n")

    assert _security_policy(workspace, ("app.py",)) is None
