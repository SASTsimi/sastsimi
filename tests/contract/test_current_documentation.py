import importlib.util
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[2]
FRAGMENT_SCRIPT = ROOT / "scripts" / "validate_doc_fragments.py"


def _load_fragment_validator() -> Callable[[Path, list[Path]], list[str]]:
    assert FRAGMENT_SCRIPT.is_file(), "local Markdown fragment validator is missing"
    spec = importlib.util.spec_from_file_location(
        "validate_doc_fragments", FRAGMENT_SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return cast(
        Callable[[Path, list[Path]], list[str]], module.validate_local_fragments
    )


def test_local_fragments_accept_unicode_duplicate_and_explicit_id(
    tmp_path: Path,
) -> None:
    validate = _load_fragment_validator()
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "target.md").write_text(
        '# 분석 방법\n\n## 결과\n\n## 결과\n\n<a id="manual"></a>\n',
        encoding="utf-8",
    )
    (docs / "source.md").write_text(
        "[한글](target.md#분석-방법) [중복](target.md#결과-1) "
        "[명시](target.md#manual)\n\n```md\n[예시](target.md#없는-제목)\n```\n",
        encoding="utf-8",
    )

    assert validate(tmp_path, [Path("docs/source.md")]) == []


def test_local_fragments_reject_missing_target(tmp_path: Path) -> None:
    validate = _load_fragment_validator()
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "target.md").write_text("# 있는 제목\n", encoding="utf-8")
    (docs / "source.md").write_text(
        "[없는 곳](target.md#없는-제목)\n", encoding="utf-8"
    )

    assert validate(tmp_path, [Path("docs/source.md")]) == [
        "docs/source.md -> target.md#없는-제목"
    ]


def test_legacy_public_doc_fragments_remain_valid(tmp_path: Path) -> None:
    validate = _load_fragment_validator()
    docs = tmp_path / "docs"
    (docs / "architecture").mkdir(parents=True)
    (docs / "decisions").mkdir()
    for relative in (
        Path("architecture/README.md"),
        Path("decisions/README.md"),
    ):
        source = ROOT / "docs" / relative
        (docs / relative).write_text(
            source.read_text(encoding="utf-8"), encoding="utf-8"
        )
    (docs / "source.md").write_text(
        "[옛 시작점](architecture/README.md#먼저-읽을-문서) "
        "[옛 결정 제목](decisions/README.md#현재-설계-결정) "
        "[옛 결정 목록](decisions/README.md#결정-목록)\n",
        encoding="utf-8",
    )

    assert validate(tmp_path, [Path("docs/source.md")]) == []


def test_fragment_cli_ignores_untracked_test_artifacts(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "target.md").write_text("# 유효\n", encoding="utf-8")
    (docs / "source.md").write_text("[좋음](target.md#유효)\n", encoding="utf-8")
    subprocess.run(("git", "init", "-q", str(tmp_path)), check=True)
    subprocess.run(
        ("git", "-C", str(tmp_path), "add", "docs/source.md", "docs/target.md"),
        check=True,
    )
    (tmp_path / ".pytest-artifact.md").write_text(
        "[나쁨](docs/target.md#없는-제목)\n", encoding="utf-8"
    )

    result = subprocess.run(
        (sys.executable, str(FRAGMENT_SCRIPT), "--root", str(tmp_path)),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_repository_exposes_only_current_documentation_sets() -> None:
    required = {
        "docs/architecture/README.md",
        "docs/architecture/pipeline.md",
        "docs/architecture/runtime-and-recovery.md",
        "docs/architecture/agents-and-providers.md",
        "docs/architecture/contracts-and-storage.md",
        "docs/architecture/static-and-dynamic-analysis.md",
        "docs/architecture/gates-chaining-reporting.md",
        "docs/architecture/security-boundaries.md",
        "docs/architecture/implementation-map.md",
        "docs/decisions/README.md",
        "docs/plans/2026-10-11-a001-versioned-surface-evidence-design.md",
        "docs/plans/2026-10-11-a001-versioned-surface-evidence.md",
    }
    missing = sorted(path for path in required if not (ROOT / path).is_file())
    historical = sorted(
        path
        for path in (
            "docs/architecture-v5",
            "docs/governance",
            "docs/handoff",
            "docs/review",
            "docs/superpowers",
        )
        if (ROOT / path).exists()
    )
    # Developer-local SDD ledgers are ignored; only committed history is a
    # repository documentation contract violation.
    tracked_sdd = subprocess.run(
        ("git", "ls-files", "-z", "--", ".superpowers"),
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout
    if tracked_sdd:
        historical.append(".superpowers")

    assert missing == []
    assert historical == []


def test_documentation_ci_uses_only_the_current_validator() -> None:
    current = ROOT / "scripts/validate-current-docs.ps1"
    workflow = (ROOT / ".github/workflows/docs.yml").read_text(encoding="utf-8")

    assert current.is_file()
    assert not (ROOT / "scripts/validate-architecture-docs.ps1").exists()
    assert not (ROOT / "scripts/audit-doc-inventory.ps1").exists()
    assert "scripts/validate-current-docs.ps1" in workflow
    assert "validate-architecture-docs.ps1" not in workflow
    assert "audit-doc-inventory.ps1" not in workflow
