from pathlib import Path

from sastsimi.static_analysis.file_scope import build_static_file_scope


def _scope(root: Path, files: dict[str, str]):
    for name, contents in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
    return build_static_file_scope(root, tuple(files))


def test_declared_python_product_entry_under_test_tree_is_scanned(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "pyproject.toml": '[project.scripts]\napp = "tests.app:main"\n',
            "tests/app.py": "def main(): pass\n",
            "tests/test_app.py": "def test_app(): pass\n",
            "src/core.py": "def core(): pass\n",
        },
    )
    assert scope.selected_paths == ("src/core.py", "tests/app.py")
    assert all(path != "tests/app.py" for path, _ in scope.excluded_test_files)
    assert any(path == "tests/test_app.py" for path, _ in scope.excluded_test_files)


def test_invalid_manifest_marks_ambiguous_test_tree_source_unverified(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "pyproject.toml": "[project.scripts\n",
            "tests/product.py": "def serve(): pass\n",
            "src/core.py": "def core(): pass\n",
        },
    )
    assert scope.selected_paths == ("src/core.py",)
    assert (
        "tests/product.py",
        "manifest_unverified_possible_product",
    ) in scope.out_of_scope_product_files
    assert all(path != "tests/product.py" for path, _ in scope.excluded_test_files)
