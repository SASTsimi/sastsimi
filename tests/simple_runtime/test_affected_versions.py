import subprocess
from pathlib import Path

from sastsimi.simple_runtime.affected_versions import find_affected_versions

_VULNERABLE = """def pick(line_id, lines):
    if not lines:
        return None
    found = [x for x in lines if x.pk == line_id]
    return found[0].variant_id
"""


def _commit(repo: Path, text: str, tag: str) -> str:
    (repo / "app.py").write_text(text)
    subprocess.run(["git", "add", "app.py"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", tag],
        cwd=repo,
        check=True,
    )
    subprocess.run(["git", "tag", tag], cwd=repo, check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True
    ).stdout.strip()


def test_releases_are_graded_exact_similar_or_unmatched(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    _commit(tmp_path, "def pick():\n    pass\n", "1.0.0")
    _commit(tmp_path, _VULNERABLE.replace("return None", "return"), "1.1.0")
    head = _commit(tmp_path, _VULNERABLE, "1.2.0")

    found = find_affected_versions(tmp_path, head, [("app.py", 1, 5)])

    assert found is not None
    assert found.exact == ("1.2.0",)
    assert found.similar == ("1.1.0",)
    assert "1.0.0" not in found.affected_line()


def test_a_whole_file_location_is_not_used(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    head = _commit(tmp_path, _VULNERABLE * 30, "1.0.0")

    assert find_affected_versions(tmp_path, head, [("app.py", 1, 150)]) is None
