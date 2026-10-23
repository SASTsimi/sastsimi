"""Fail-closed checks for the pinned six-repository static benchmark."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scripts import run_six_repo_static_benchmark as benchmark

RULES = b"""rules:
  - id: demo.one
    languages: [python]
    message: one
    severity: INFO
    pattern: foo(...)
  - id: demo.two
    languages: [python]
    message: two
    severity: INFO
    pattern: bar(...)
"""


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def _checkout(tmp_path: Path) -> tuple[benchmark.Target, Path]:
    root = tmp_path / "checkout"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Benchmark Test")
    _git(root, "config", "user.email", "benchmark@example.invalid")
    (root / "app.py").write_text("foo()\n", encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_app.py").write_text(
        "def test_app(): pass\n", encoding="utf-8"
    )
    (root / "app.js").write_text("foo();\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "pinned")
    _git(root, "remote", "add", "origin", "https://github.com/example/project.git")
    return (
        benchmark.Target(
            name="demo",
            url="https://github.com/example/project.git",
            commit=_git(root, "rev-parse", "HEAD"),
        ),
        root,
    )


def _scan_json(
    *,
    scanned: list[str],
    results: list[dict[str, object]] | None = None,
    errors: list[dict[str, object]] | None = None,
) -> bytes:
    return json.dumps(
        {
            "results": results or [],
            "errors": errors or [],
            "paths": {"scanned": scanned, "skipped": []},
        }
    ).encode()


def test_manifest_names_and_commits_are_unique() -> None:
    path = (
        Path(__file__).resolve().parents[3]
        / "docs/validation/data/six-educational-targets.json"
    )
    targets = benchmark.load_targets(path)
    assert len(targets) == 6
    assert len({target.name for target in targets}) == 6
    assert len({target.commit for target in targets}) == 6


def test_historical_presentation_aggregate_is_not_an_answer_ledger() -> None:
    project = Path(__file__).resolve().parents[3]
    record = json.loads(
        (
            project / "docs/validation/data/six-educational-historical-aggregate.json"
        ).read_text(encoding="utf-8")
    )
    rows = record["rows"]
    assert len(rows) == 6
    for field in ("gt", "tp", "fp", "fn"):
        assert sum(row[field] for row in rows) == record["totals"][field]
    assert record["totals"] == {"gt": 53, "tp": 50, "fp": 0, "fn": 3}
    assert record["case_to_finding_mapping"] == "unavailable"
    assert record["presentation_target_commits"] == "unavailable"


def test_measured_static_summary_is_distinct_from_presentation_result() -> None:
    project = Path(__file__).resolve().parents[3]
    measured = json.loads(
        (
            project
            / "docs/validation/data/six-educational-measured-static-summary.json"
        ).read_text(encoding="utf-8")
    )
    targets = benchmark.load_targets(
        project / "docs/validation/data/six-educational-targets.json"
    )
    assert [(row["name"], row["commit"]) for row in measured["results"]] == [
        (target.name, target.commit) for target in targets
    ]
    for field in (
        "python_files",
        "ast_parsed",
        "verified_pairs",
        "expected_pairs",
        "static_hints",
        "scanner_errors",
        "excluded_tests",
        "out_of_scope_product",
    ):
        assert (
            sum(row[field] for row in measured["results"]) == measured["totals"][field]
        )
    assert measured["totals"]["verified_pairs"] == 1343
    assert sum(
        row["first_scan_elapsed_seconds"] for row in measured["results"]
    ) == pytest.approx(measured["totals"]["first_scan_elapsed_seconds"])
    assert all(len(row["source_content_sha256"]) == 64 for row in measured["results"])
    assert "recall" in measured["not_measured"]


def test_manifest_rejects_target_name_as_path(tmp_path: Path) -> None:
    source = (
        Path(__file__).resolve().parents[3]
        / "docs/validation/data/six-educational-targets.json"
    )
    document = json.loads(source.read_text(encoding="utf-8"))
    document["targets"][0]["name"] = "../outside"
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="BENCHMARK_MANIFEST_INVALID"):
        benchmark.load_targets(manifest)


def test_direct_script_loads_this_checkout_not_an_installed_release() -> None:
    project = Path(__file__).resolve().parents[3]
    script = project / "scripts/run_six_repo_static_benchmark.py"
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    program = (
        "import inspect, runpy; "
        f"module = runpy.run_path({str(script)!r}); "
        "print(inspect.getfile(module['build_static_file_scope']))"
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        cwd=project,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert (
        Path(result.stdout.strip()).resolve()
        == (project / "src/sastsimi/static_analysis/file_scope.py").resolve()
    )


def test_inspect_checkout_rejects_wrong_sha_and_uses_product_python_only(
    tmp_path: Path,
) -> None:
    target, root = _checkout(tmp_path)
    scope = benchmark.inspect_checkout(target, root)
    assert scope.files.selected_paths == ("app.py",)
    assert scope.files.excluded_test_files == (
        ("tests/test_app.py", "test-directory:tests"),
    )
    assert scope.files.out_of_scope_product_files == (
        ("app.js", "non_python_product_source"),
    )
    wrong = benchmark.Target(target.name, target.url, "a" * 40)
    with pytest.raises(ValueError, match="BENCHMARK_COMMIT_MISMATCH"):
        benchmark.inspect_checkout(wrong, root)
    with pytest.raises(ValueError, match="BENCHMARK_NOT_REPOSITORY_ROOT"):
        benchmark.inspect_checkout(target, root / "tests")
    (root / "app.py").write_text("different()\n", encoding="utf-8")
    with pytest.raises(ValueError, match="BENCHMARK_CHECKOUT_DIRTY"):
        benchmark.inspect_checkout(target, root)


def test_hidden_modified_source_cannot_reuse_pinned_commit_evidence(
    tmp_path: Path,
) -> None:
    target, root = _checkout(tmp_path)
    _git(root, "update-index", "--assume-unchanged", "app.py")
    (root / "app.py").write_text("changed()\n", encoding="utf-8")
    assert _git(root, "status", "--porcelain=v1", "--untracked-files=no") == ""
    with pytest.raises(ValueError, match="BENCHMARK_CONTENT_MISMATCH"):
        benchmark.inspect_checkout(target, root)


def test_normalized_git_blob_does_not_reuse_different_raw_source_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, root = _checkout(tmp_path)
    (root / ".gitattributes").write_text("*.py text eol=lf\n", encoding="utf-8")
    _git(root, "add", ".gitattributes")
    _git(root, "commit", "-qm", "normalize Python source")
    target = benchmark.Target(target.name, target.url, _git(root, "rev-parse", "HEAD"))
    original = benchmark.inspect_checkout(target, root)
    rules = tmp_path / "rules.yml"
    rules.write_bytes(RULES)
    scanner = tmp_path / "opengrep.exe"
    scanner.write_bytes(b"scanner")
    calls = 0

    def scan(**_: object) -> benchmark.ScanAttempt:
        nonlocal calls
        calls += 1
        return benchmark.ScanAttempt(
            returncode=0, raw=_scan_json(scanned=["app.py"]), elapsed_seconds=0.1
        )

    monkeypatch.setattr(benchmark, "_scan_batch", scan)
    benchmark.run_static_target(
        original,
        rules,
        scanner,
        tmp_path / "raw",
        timeout_seconds=10,
        tool_version="1.30.0",
    )
    _git(root, "update-index", "--assume-unchanged", "app.py")
    existing = (root / "app.py").read_bytes()
    alternate = b"foo()\r\n" if existing == b"foo()\n" else b"foo()\n"
    (root / "app.py").write_bytes(alternate)
    indexed = _git(root, "rev-parse", "HEAD:app.py")
    normalized = _git(root, "hash-object", "--path=app.py", "--", "app.py")
    assert normalized == indexed
    changed = benchmark.inspect_checkout(target, root)
    assert changed.scan_scope_fingerprint != original.scan_scope_fingerprint
    second = benchmark.run_static_target(
        changed,
        rules,
        scanner,
        tmp_path / "raw",
        timeout_seconds=10,
        tool_version="1.30.0",
    )
    assert calls == 2
    assert second["reused_batches"] == 0


def test_successful_scan_counts_coverage_and_hints_separately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, root = _checkout(tmp_path)
    scope = benchmark.inspect_checkout(target, root)
    rules = tmp_path / "rules.yml"
    rules.write_bytes(RULES)
    scanner = tmp_path / "opengrep.exe"
    scanner.write_bytes(b"scanner")
    calls: list[tuple[str, ...]] = []

    def fake_scan(*, targets: tuple[str, ...], **_: object) -> benchmark.ScanAttempt:
        calls.append(targets)
        return benchmark.ScanAttempt(
            returncode=0,
            raw=_scan_json(
                scanned=["app.py"],
                results=[
                    {"check_id": "demo.one", "path": "app.py", "start": {"line": 1}}
                ],
            ),
            elapsed_seconds=0.1,
        )

    monkeypatch.setattr(benchmark, "_scan_batch", fake_scan)
    first = benchmark.run_static_target(
        scope,
        rules,
        scanner,
        tmp_path / "raw",
        timeout_seconds=10,
        tool_version="1.30.0",
    )
    second = benchmark.run_static_target(
        scope,
        rules,
        scanner,
        tmp_path / "raw",
        timeout_seconds=10,
        tool_version="1.30.0",
    )
    assert first["coverage"] == {"expected": 2, "verified": 2, "gaps": []}
    assert first["status"] == "AST_OPENGREP_COMPLETE"
    assert len(calls) == 1
    assert calls[0] == ("app.py",)
    assert first["static_hints"] == 1
    assert first["excluded_tests"] == 1
    assert first["out_of_scope_product"] == 1
    assert second["static_hints"] == 1
    assert second["coverage"] == first["coverage"]


def test_nonzero_exit_with_complete_json_cannot_be_reused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, root = _checkout(tmp_path)
    scope = benchmark.inspect_checkout(target, root)
    rules = tmp_path / "rules.yml"
    rules.write_bytes(RULES)
    scanner = tmp_path / "opengrep.exe"
    scanner.write_bytes(b"scanner")
    calls = 0

    def scan(**_: object) -> benchmark.ScanAttempt:
        nonlocal calls
        calls += 1
        return benchmark.ScanAttempt(
            returncode=2 if calls == 1 else 0,
            raw=_scan_json(scanned=["app.py"]),
            elapsed_seconds=0.1,
        )

    monkeypatch.setattr(benchmark, "_scan_batch", scan)
    first = benchmark.run_static_target(
        scope,
        rules,
        scanner,
        tmp_path / "raw",
        timeout_seconds=10,
        tool_version="1.30.0",
    )
    second = benchmark.run_static_target(
        scope,
        rules,
        scanner,
        tmp_path / "raw",
        timeout_seconds=10,
        tool_version="1.30.0",
    )
    assert first["status"] == "AST_OPENGREP_PARTIAL"
    assert second["status"] == "AST_OPENGREP_COMPLETE"
    assert calls == 2


def test_complete_raw_without_success_marker_cannot_be_reused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, root = _checkout(tmp_path)
    scope = benchmark.inspect_checkout(target, root)
    rules = tmp_path / "rules.yml"
    rules.write_bytes(RULES)
    scanner = tmp_path / "opengrep.exe"
    scanner.write_bytes(b"scanner")
    calls = 0

    def scan(**_: object) -> benchmark.ScanAttempt:
        nonlocal calls
        calls += 1
        return benchmark.ScanAttempt(
            returncode=0, raw=_scan_json(scanned=["app.py"]), elapsed_seconds=0.1
        )

    monkeypatch.setattr(benchmark, "_scan_batch", scan)
    first = benchmark.run_static_target(
        scope,
        rules,
        scanner,
        tmp_path / "raw",
        timeout_seconds=10,
        tool_version="1.30.0",
    )
    assert first["status"] == "AST_OPENGREP_COMPLETE"
    marker = next((tmp_path / "raw").rglob("*.success.json"))
    marker.unlink()
    second = benchmark.run_static_target(
        scope,
        rules,
        scanner,
        tmp_path / "raw",
        timeout_seconds=10,
        tool_version="1.30.0",
    )
    assert calls == 2
    assert second["reused_batches"] == 0


def test_source_change_during_scan_cannot_publish_success_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, root = _checkout(tmp_path)
    scope = benchmark.inspect_checkout(target, root)
    rules = tmp_path / "rules.yml"
    rules.write_bytes(RULES)
    scanner = tmp_path / "opengrep.exe"
    scanner.write_bytes(b"scanner")

    def changed_scan(**_: object) -> benchmark.ScanAttempt:
        (root / "app.py").write_bytes(b"bar()\n")
        return benchmark.ScanAttempt(
            returncode=0, raw=_scan_json(scanned=["app.py"]), elapsed_seconds=0.1
        )

    monkeypatch.setattr(benchmark, "_scan_batch", changed_scan)
    output = tmp_path / "raw"
    with pytest.raises(RuntimeError, match="BENCHMARK_SOURCE_CHANGED_DURING_SCAN"):
        benchmark.run_static_target(
            scope,
            rules,
            scanner,
            output,
            timeout_seconds=10,
            tool_version="1.30.0",
        )
    assert not list(output.rglob("*.success.json"))


@pytest.mark.parametrize("failure", ["nonzero", "timeout", "located_error"])
def test_incomplete_scan_never_earns_full_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    target, root = _checkout(tmp_path)
    scope = benchmark.inspect_checkout(target, root)
    rules = tmp_path / "rules.yml"
    rules.write_bytes(RULES)
    scanner = tmp_path / "opengrep.exe"
    scanner.write_bytes(b"scanner")

    def fake_scan(**_: object) -> benchmark.ScanAttempt:
        if failure == "timeout":
            raise subprocess.TimeoutExpired("opengrep", 10)
        raw = _scan_json(
            scanned=["app.py"],
            errors=(
                [{"path": "app.py", "type": "ParseError"}]
                if failure == "located_error"
                else []
            ),
        )
        return benchmark.ScanAttempt(
            returncode=2 if failure == "nonzero" else 0,
            raw=raw,
            elapsed_seconds=0.1,
        )

    monkeypatch.setattr(benchmark, "_scan_batch", fake_scan)
    result = benchmark.run_static_target(
        scope,
        rules,
        scanner,
        tmp_path / "raw",
        timeout_seconds=10,
        tool_version="1.30.0",
    )
    coverage = result["coverage"]
    assert isinstance(coverage, dict)
    assert coverage["expected"] == 2
    assert coverage["verified"] == 0
    assert len(coverage["gaps"]) == 2
    assert result["status"] == "AST_OPENGREP_PARTIAL"


def test_located_parser_error_preserves_other_file_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, root = _checkout(tmp_path)
    (root / "helper.py").write_text("bar()\n", encoding="utf-8")
    _git(root, "add", "helper.py")
    _git(root, "commit", "-qm", "more source")
    target = benchmark.Target(target.name, target.url, _git(root, "rev-parse", "HEAD"))
    scope = benchmark.inspect_checkout(target, root)
    rules = tmp_path / "rules.yml"
    rules.write_bytes(RULES)
    scanner = tmp_path / "opengrep.exe"
    scanner.write_bytes(b"scanner")

    def fake_scan(**_: object) -> benchmark.ScanAttempt:
        return benchmark.ScanAttempt(
            returncode=0,
            raw=_scan_json(
                scanned=["app.py", "helper.py"],
                errors=[{"path": "app.py", "type": "ParseError"}],
            ),
            elapsed_seconds=0.1,
        )

    monkeypatch.setattr(benchmark, "_scan_batch", fake_scan)
    result = benchmark.run_static_target(
        scope,
        rules,
        scanner,
        tmp_path / "raw",
        timeout_seconds=10,
        tool_version="1.30.0",
    )
    coverage = result["coverage"]
    assert isinstance(coverage, dict)
    assert coverage["expected"] == 4
    assert coverage["verified"] == 2
    assert {gap["path"] for gap in coverage["gaps"]} == {"app.py"}
    assert result["scanner_error_count"] == 1


def test_timeout_charges_elapsed_wall_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, root = _checkout(tmp_path)
    scope = benchmark.inspect_checkout(target, root)
    rules = tmp_path / "rules.yml"
    rules.write_bytes(RULES)
    scanner = tmp_path / "opengrep.exe"
    scanner.write_bytes(b"scanner")

    def timeout_scan(**_: object) -> benchmark.ScanAttempt:
        time.sleep(0.05)
        raise subprocess.TimeoutExpired("opengrep", 1)

    monkeypatch.setattr(benchmark, "_scan_batch", timeout_scan)
    result = benchmark.run_static_target(
        scope,
        rules,
        scanner,
        tmp_path / "raw",
        timeout_seconds=1,
        tool_version="1.30.0",
    )
    elapsed = result["scan_elapsed_seconds"]
    assert isinstance(elapsed, float)
    assert elapsed >= 0.04
    coverage = result["coverage"]
    assert isinstance(coverage, dict)
    assert coverage["verified"] == 0


def test_python_repo_without_applicable_rules_is_not_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, root = _checkout(tmp_path)
    scope = benchmark.inspect_checkout(target, root)
    rules = tmp_path / "javascript-only.yml"
    rules.write_bytes(
        b"rules:\n  - id: demo.js\n    languages: [javascript]\n"
        b"    message: test\n    severity: INFO\n    pattern: foo(...)\n"
    )
    scanner = tmp_path / "opengrep.exe"
    scanner.write_bytes(b"scanner")

    def no_scan(**_: object) -> benchmark.ScanAttempt:
        raise AssertionError("Python file must not be sent to JavaScript rule")

    monkeypatch.setattr(benchmark, "_scan_batch", no_scan)
    result = benchmark.run_static_target(
        scope,
        rules,
        scanner,
        tmp_path / "raw",
        timeout_seconds=1,
        tool_version="1.30.0",
    )
    coverage = result["coverage"]
    assert isinstance(coverage, dict)
    assert coverage["expected"] == 0
    assert result["status"] == "AST_OPENGREP_PARTIAL"
    assert result["scope_issue"] == "no_applicable_python_rule"
