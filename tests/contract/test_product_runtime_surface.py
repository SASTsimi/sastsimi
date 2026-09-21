from __future__ import annotations

import ast
from pathlib import Path


def _fake_imports(source_root: Path) -> list[str]:
    violations: list[str] = []
    for path in sorted(source_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            modules: tuple[str, ...]
            if isinstance(node, ast.Import):
                modules = tuple(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                modules = (node.module or "",)
            else:
                continue
            for module in modules:
                if any(part.startswith("fake") for part in module.split(".")):
                    violations.append(f"{path.as_posix()}:{node.lineno}:{module}")
    return violations


def test_bootstrap_does_not_export_fake_pipeline() -> None:
    import sastsimi.bootstrap as bootstrap

    assert not hasattr(bootstrap, "build_fake_pipeline")
    assert not hasattr(bootstrap, "load_fake_progress")


def test_product_source_contains_no_fake_pipeline_modules_or_imports() -> None:
    source_root = Path("src/sastsimi")
    fake_files = sorted(path.as_posix() for path in source_root.rglob("fake*.py"))

    assert fake_files == []
    assert _fake_imports(source_root) == []
