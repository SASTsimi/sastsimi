"""The product-code scope must never count test-only files as scanned."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import sastsimi.static_analysis as static_analysis


def _scope(root: Path, paths: dict[str, str], *, include_tests: bool = False):
    for relative, contents in paths.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
    builder = getattr(static_analysis, "build_static_file_scope", None)
    assert callable(builder), "the shared static file scope builder is missing"
    return builder(root, tuple(paths), include_tests=include_tests)


def test_exact_test_directory_components_do_not_match_product_substrings(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "tests/test_api.py": "def test_api(): pass\n",
            "frontend/__tests__/api.test.ts": "test('api', () => {})\n",
            "backend/Test/service.py": "def test_service(): pass\n",
            "src/contest.py": "def run_contest(): pass\n",
            "src/testimonials.ts": "export const testimonials = [];\n",
            "src/test_client.py": "class TestClient: pass\n",
        },
    )

    assert scope.selected_paths == (
        "src/contest.py",
        "src/test_client.py",
        "src/testimonials.ts",
    )
    assert [(item.path, item.reason) for item in scope.excluded_test_files] == [
        ("backend/Test/service.py", "test-directory:test"),
        ("frontend/__tests__/api.test.ts", "test-directory:__tests__"),
        ("tests/test_api.py", "test-directory:tests"),
    ]


def test_test_basename_requires_content_evidence_outside_test_directory(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "src/test_math.py": "import pytest\ndef test_sum(): assert 1 + 1 == 2\n",
            "src/math_test.py": (
                "import unittest\nclass MathTest(unittest.TestCase): pass\n"
            ),
            "web/api.test.ts": (
                "import { test } from 'vitest';\ntest('api', () => {});\n"
            ),
            "web/api.spec.js": (
                "import { describe } from 'vitest';\ndescribe('api', () => {});\n"
            ),
            "src/test_client.py": "class TestClient: pass\n",
            "web/specification.ts": "export const specification = 'public';\n",
        },
    )

    assert scope.selected_paths == ("src/test_client.py", "web/specification.ts")
    assert {item.path for item in scope.excluded_test_files} == {
        "src/test_math.py",
        "src/math_test.py",
        "web/api.test.ts",
        "web/api.spec.js",
    }
    assert {item.reason for item in scope.excluded_test_files} == {
        "test-basename+content:python",
        "test-basename+content:javascript-typescript",
    }


def test_declared_product_entry_points_are_never_excluded(tmp_path: Path) -> None:
    package = json.dumps({"bin": {"my-tool": "./web/__tests__/cli.js"}})
    scope = _scope(
        tmp_path,
        {
            "pyproject.toml": '[project.scripts]\nproduct = "tests.cli:main"\n',
            "package.json": package,
            "tests/cli.py": "def main(): pass\n",
            "web/__tests__/cli.js": "export function main() {}\n",
            "tests/test_cli.py": "def test_cli(): pass\n",
        },
    )

    assert {"tests/cli.py", "web/__tests__/cli.js"}.issubset(scope.selected_paths)
    assert [item.path for item in scope.excluded_test_files] == ["tests/test_cli.py"]


def test_include_tests_mode_keeps_every_tracked_file_and_changes_identity(
    tmp_path: Path,
) -> None:
    paths = {
        "src/app.py": "def run(): pass\n",
        "tests/test_app.py": "def test_app(): pass\n",
    }
    product = _scope(tmp_path, paths)
    all_files = _scope(tmp_path, paths, include_tests=True)

    assert all_files.selected_paths == ("src/app.py", "tests/test_app.py")
    assert all_files.excluded_test_files == ()
    assert all_files.fingerprint != product.fingerprint


def test_tracked_paths_are_validated_instead_of_silently_normalized(
    tmp_path: Path,
) -> None:
    builder = getattr(static_analysis, "build_static_file_scope", None)
    assert callable(builder), "the shared static file scope builder is missing"
    with pytest.raises(ValueError, match="STATIC_SCOPE_TRACKED_PATH_INVALID"):
        builder(tmp_path, ("tests\\test_bad.py",), include_tests=False)


def test_unreadable_entry_manifest_keeps_ambiguous_test_directory_selected(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "apps/web/package.json": "{not-json",
            "apps/web/tests/cli.ts": "export const main = 1;\n",
            "backend/tests/test_api.py": "def test_api(): pass\n",
        },
    )
    assert "apps/web/tests/cli.ts" in scope.selected_paths
    assert [item.path for item in scope.excluded_test_files] == [
        "backend/tests/test_api.py"
    ]


def test_unexpected_manifest_structure_does_not_crash_or_exclude(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "pyproject.toml": '[tool]\npoetry = "not-a-table"\n',
            "tests/product.py": "def run(): pass\n",
        },
    )
    assert "tests/product.py" in scope.selected_paths
    assert scope.excluded_test_files == ()
