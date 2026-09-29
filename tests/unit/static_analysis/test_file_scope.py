"""The product-code scope must never count test-only files as scanned."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

import sastsimi.static_analysis as static_analysis
from sastsimi.static_analysis.file_scope import StaticFileScope


def _scope(root: Path, paths: dict[str, str]) -> StaticFileScope:
    for relative, contents in paths.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
    return static_analysis.build_static_file_scope(root, tuple(paths))


def test_product_scope_cannot_opt_into_test_files(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    test = tmp_path / "tests" / "test_app.py"
    test.parent.mkdir()
    app.write_text("def run(): pass\n", encoding="utf-8")
    test.write_text("def test_run(): pass\n", encoding="utf-8")

    scope = static_analysis.build_static_file_scope(
        tmp_path, ("app.py", "tests/test_app.py")
    )

    assert scope.selected_paths == ("app.py",)
    assert scope.excluded_test_files == (("tests/test_app.py", "test-directory:tests"),)
    assert not hasattr(scope, "all_tracked")
    with pytest.raises(TypeError):
        cast(Any, static_analysis.build_static_file_scope)(
            tmp_path, ("app.py", "tests/test_app.py"), include_tests=True
        )


def test_test_only_paths_do_not_change_product_scope_fingerprint(
    tmp_path: Path,
) -> None:
    product = _scope(tmp_path, {"app.py": "def run(): pass\n"})
    with_test = _scope(
        tmp_path,
        {
            "app.py": "def run(): pass\n",
            "tests/test_app.py": "def test_run(): pass\n",
        },
    )

    assert with_test.selected_paths == product.selected_paths
    assert with_test.fingerprint == product.fingerprint


def test_non_python_paths_do_not_change_python_scope_fingerprint(
    tmp_path: Path,
) -> None:
    product = _scope(tmp_path, {"src/app.py": "def run(): pass\n"})
    mixed = _scope(
        tmp_path,
        {
            "src/app.py": "def run(): pass\n",
            "src/client.ts": "export const client = true;\n",
            "src/types.pyi": "def run() -> None: ...\n",
            "README.md": "# project\n",
        },
    )

    assert mixed.selected_paths == ("src/app.py",)
    assert mixed.fingerprint == product.fingerprint


def test_scope_records_excluded_tests_and_out_of_scope_product_sources(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "api/app.py": "def run(): pass\n",
            "api/test_client.py": "class TestClient: pass\n",
            "api/test_math.py": "import pytest\ndef test_sum(): pass\n",
            "tests/test_app.py": "def test_run(): pass\n",
            "web/app.ts": "export const app = true;\n",
            "web/view.jsx": "export const view = true;\n",
            "web/app.test.ts": "import { test } from 'vitest'; test('x', () => {});\n",
            "api/types.pyi": "def run() -> None: ...\n",
            "README.md": "# docs\n",
        },
    )

    assert scope.selected_paths == ("api/app.py", "api/test_client.py")
    assert scope.excluded_test_files == (
        ("api/test_math.py", "test-basename+content:python"),
        ("tests/test_app.py", "test-directory:tests"),
        ("web/app.test.ts", "test-basename+content:javascript-typescript"),
    )
    assert scope.out_of_scope_product_files == (
        ("api/types.pyi", "python_stub_not_scanned"),
        ("web/app.ts", "non_python_product_source"),
        ("web/view.jsx", "non_python_product_source"),
    )


def test_mixed_language_product_sources_are_explicitly_out_of_scope(
    tmp_path: Path,
) -> None:
    python_only = _scope(tmp_path, {"api/app.py": "def run(): pass\n"})
    mixed = _scope(
        tmp_path,
        {
            "api/app.py": "def run(): pass\n",
            "api/src/main/java/App.java": "class App {}\n",
            "engine/src/lib.rs": "pub fn run() {}\n",
            "service/main.go": "package main\n",
            "web/assets/runtime.js": "export const run = true;\n",
            "workers/Worker.cs": "class Worker {}\n",
            "docs/reference/tutorial.go": "package docs\n",
            "docs/tools/illustration.py": "def draw(): pass\n",
            "examples/worker.rs": "pub fn example() {}\n",
            "assets/logo.svg": "<svg/>\n",
            "assets/site.css": ".app {}\n",
            "tests/helper.go": "package tests\n",
            "src/test/Helper.java": "class Helper {}\n",
            "engine/tests/helper.rs": "fn test() {}\n",
            "service/parser_test.go": "package main\n",
        },
    )

    assert mixed.selected_paths == ("api/app.py",)
    assert mixed.fingerprint == python_only.fingerprint
    assert mixed.out_of_scope_product_files == (
        ("api/src/main/java/App.java", "non_python_product_source"),
        ("engine/src/lib.rs", "non_python_product_source"),
        ("service/main.go", "non_python_product_source"),
        ("web/assets/runtime.js", "non_python_product_source"),
        ("workers/Worker.cs", "non_python_product_source"),
    )
    assert mixed.excluded_test_files == (
        ("engine/tests/helper.rs", "test-directory:tests"),
        ("service/parser_test.go", "test-basename:go"),
        ("src/test/Helper.java", "test-directory:test"),
        ("tests/helper.go", "test-directory:tests"),
    )


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

    assert scope.selected_paths == ("src/contest.py", "src/test_client.py")


def test_common_e2e_and_specification_trees_are_test_only(tmp_path: Path) -> None:
    scope = _scope(
        tmp_path,
        {
            "app.py": "def run(): pass\n",
            "e2e/features/login.feature": "Feature: Login\n  Scenario: valid user\n",
            "e2e/fixtures/sound.wav": "fixture\n",
            "spec/models/user_spec.rb": "describe User do\nend\n",
            "testdata/cases.json": "{}\n",
            "integration_tests/flows.py": "def test_flow(): pass\n",
            "src/e2e_service.py": "def run(): pass\n",
        },
    )

    assert scope.selected_paths == ("app.py", "src/e2e_service.py")


def test_benchmark_trees_and_linter_rule_fixtures_are_test_only(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "src/fixtures/default-theme.css": ".app { color: black; }\n",
            "src/fixtures/eslint/rules.ts": "export const rules = {};\n",
            "src/benchmarking.py": "def measure_latency(): pass\n",
            "src/stress_test_service.py": "def serve(): pass\n",
            "web/plugins/eslint/rules/fixtures/truncation.module.css": (
                ".truncated { overflow: hidden; }\n"
            ),
            "scripts/stress-test/run_load_test.sh": "#!/bin/sh\nexit 0\n",
            "benchmarks/measure.py": "def benchmark(): pass\n",
        },
    )

    assert scope.selected_paths == ("src/benchmarking.py", "src/stress_test_service.py")


def test_shell_tests_and_test_runner_assets_are_test_only(tmp_path: Path) -> None:
    scope = _scope(
        tmp_path,
        {
            "src/vitest_theme.css": ".app { color: black; }\n",
            "src/contest.sh": "#!/bin/sh\nprintf 'ready\\n'\n",
            "docker/proxy/test_allowlist.sh": "#!/bin/sh\nassert_contains() { :; }\n",
            "docker/proxy/config_test.sh": "#!/bin/sh\nexit 0\n",
            "packages/ui/vitest.css": "@import './src/styles.css';\n",
            "packages/ui/vitest.setup.ts": "import './vitest.css'\n",
            "cli/vitest.e2e.config.ts": "export default {}\n",
        },
    )

    assert scope.selected_paths == ()


def test_declared_shell_entry_does_not_enter_python_scope(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "package.json": json.dumps({"bin": {"health": "./bin/test_health.sh"}}),
            "bin/test_health.sh": "#!/bin/sh\ncurl localhost/health\n",
            "bin/test_health_probe.sh": "#!/bin/sh\nexit 0\n",
        },
    )

    assert scope.selected_paths == ()


def test_pytest_convention_files_are_test_only(tmp_path: Path) -> None:
    scope = _scope(
        tmp_path,
        {
            "api/conftest.py": "import pytest\n",
            "api/pytest.ini": "[pytest]\ntestpaths = tests\n",
            "api/configtest.py": "def run(): pass\n",
            "api/pytest_runner.py": "def run(): pass\n",
        },
    )

    assert scope.selected_paths == ("api/configtest.py", "api/pytest_runner.py")


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
            "web/api.test.mts": (
                "import { test } from 'vitest';\ntest('api', () => {});\n"
            ),
            "web/api.spec.cts": "test('api', () => {});\n",
            "src/test_client.py": "class TestClient: pass\n",
            "web/specification.ts": "export const specification = 'public';\n",
        },
    )

    assert scope.selected_paths == ("src/test_client.py",)


def test_large_test_named_source_uses_bounded_content_evidence(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "web/client.spec.ts": (
                "import { describe } from 'vitest';\n"
                + "const fixture = '"
                + "x" * 70_000
                + "';\n"
            ),
            "web/client_test.py": ("import pytest\n" + "#" + "x" * 70_000 + "\n"),
            "web/product.spec.ts": "export const specification = '"
            + "x" * 70_000
            + "';\n",
        },
    )

    assert scope.selected_paths == ()


def test_large_test_named_source_can_find_test_calls_near_tail(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "web/client.spec.ts": (
                "export const fixture = '" + "x" * 70_000 + "';\n"
                "describe('client', () => {});\n"
            ),
        },
    )

    assert scope.selected_paths == ()


def test_large_product_named_spec_does_not_gain_a_fake_word_boundary(
    tmp_path: Path,
) -> None:
    tail = "test() {};" + "x" * (64 * 1024 - len("test() {};"))
    scope = _scope(
        tmp_path,
        {"web/contest.spec.ts": "export function con" + tail},
    )

    assert scope.selected_paths == ()


def test_go_test_suffix_is_excluded_without_content_evidence(tmp_path: Path) -> None:
    scope = _scope(
        tmp_path,
        {
            "runtime/main.go": "package main\nfunc main() {}\n",
            "runtime/parser_test.go": "package main\n",
            "runtime/pretest.go": "package main\n",
            "runtime/parser_TEST.go": "package main\n",
        },
    )

    assert scope.selected_paths == ()


def test_declared_test_tree_entry_points_are_not_mistaken_for_test_fixtures(
    tmp_path: Path,
) -> None:
    package = json.dumps(
        {"main": "tests/cli.js", "bin": {"my-tool": "./web/__tests__/cli.js"}}
    )
    scope = _scope(
        tmp_path,
        {
            "pyproject.toml": '[project.scripts]\nproduct = "tests.cli:main"\n',
            "package.json": package,
            "tests/cli.py": "def main(): pass\n",
            "tests/cli.js": "export function main() {}\n",
            "web/__tests__/cli.js": "export function main() {}\n",
            "tests/test_cli.py": "def test_cli(): pass\n",
        },
    )

    assert scope.selected_paths == ("tests/cli.py",)
    assert (
        "tests/cli.js",
        "declared_non_python_entry",
    ) in scope.out_of_scope_product_files
    assert (
        "web/__tests__/cli.js",
        "declared_non_python_entry",
    ) in scope.out_of_scope_product_files
    assert all(path != "tests/cli.py" for path, _ in scope.excluded_test_files)


def test_invalid_test_only_manifests_do_not_block_product_scope(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "src/app.py": "def run(): pass\n",
            "tests/package.json": "{not-json",
            "tests/cli.js": "export function main() {}\n",
            "spec/pyproject.toml": '[tool]\npoetry = "not-a-table"\n',
            "spec/fixture.py": "def fixture(): pass\n",
        },
    )

    assert scope.selected_paths == ("src/app.py",)


def test_valid_test_only_manifest_cannot_reinclude_test_tree_file(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "src/app.ts": "export const app = true;\n",
            "tests/package.json": json.dumps({"main": "./fixture.js"}),
            "tests/fixture.js": "export const fixture = true;\n",
        },
    )

    assert scope.selected_paths == ()


def test_tracked_paths_are_validated_instead_of_silently_normalized(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="STATIC_SCOPE_TRACKED_PATH_INVALID"):
        static_analysis.build_static_file_scope(tmp_path, ("tests\\test_bad.py",))


def test_unreadable_js_entry_manifest_does_not_block_python_scope(
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
    assert scope.selected_paths == ()


def test_unexpected_manifest_structure_does_not_restore_test_tree(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "pyproject.toml": '[tool]\npoetry = "not-a-table"\n',
            "tests/product.py": "def run(): pass\n",
        },
    )
    assert scope.selected_paths == ()


def test_oversized_root_manifest_does_not_restore_test_tree(tmp_path: Path) -> None:
    scope = _scope(
        tmp_path,
        {
            "package.json": "{" + " " * 70_000 + "}",
            "src/app.ts": "export const app = 1;\n",
            "tests/test_app.py": "def test_app(): pass\n",
        },
    )
    assert scope.selected_paths == ()
    assert "tests/test_app.py" not in scope.selected_paths


def test_large_valid_manifest_cannot_restore_non_python_entry(tmp_path: Path) -> None:
    manifest = json.dumps({"main": "./tests/cli.js", "description": "x" * 70_000})
    scope = _scope(
        tmp_path,
        {
            "package.json": manifest,
            "tests/cli.js": "export function main() {}\n",
            "tests/cli.test.js": (
                "import { test } from 'vitest';\ntest('cli', () => {});\n"
            ),
        },
    )
    assert scope.selected_paths == ()


def test_package_export_pattern_does_not_restore_js_test_tree_file(
    tmp_path: Path,
) -> None:
    scope = _scope(
        tmp_path,
        {
            "package.json": json.dumps({"exports": {"./feature/*": "./tests/*.js"}}),
            "tests/feature.js": "export const feature = true;\n",
            "tests/test_feature.py": "def test_feature(): pass\n",
        },
    )
    assert scope.selected_paths == ()
