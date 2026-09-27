"""Coverage is earned per applicable rule and tracked file, never inferred from hits."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastsimi.simple_runtime.opengrep_rule_batches import plan_rule_batches
from sastsimi.simple_runtime.static_coverage import (
    assess_scan,
    finish_coverage,
    plan_static_coverage,
)


def _rules() -> bytes:
    return b"""rules:
  - id: rule.js
    languages: [javascript]
    message: test
    severity: INFO
    pattern: foo(...)
  - id: rule.py
    languages: [python]
    message: test
    severity: INFO
    pattern: foo(...)
"""


def _plan(root: Path, tracked: list[str] | None = None):
    files = tracked or ["app.ts", "other.js", "helper.py", "main.go"]
    for name in files:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("foo()\n", encoding="utf-8")
    rules = plan_rule_batches(
        _rules(), tool_version="1.30.0", executable_sha256="a" * 64, batch_size=1
    )
    return plan_static_coverage(root, files, "b" * 40, rules), rules


def _raw(
    *,
    scanned: list[str],
    errors: list[object] | None = None,
    skipped: list[str] | None = None,
    results: list[object] | None = None,
) -> bytes:
    return json.dumps(
        {
            "results": results or [],
            "errors": errors or [],
            "paths": {"scanned": scanned, "skipped": skipped or []},
        }
    ).encode()


def _gaps(report) -> set[tuple[str, str]]:
    return {(gap.path, gap.rule_id) for gap in report.gaps}


def test_javascript_catalog_includes_typescript_targets(tmp_path: Path) -> None:
    plan, _ = _plan(tmp_path)
    assert plan.expected_pairs == frozenset(
        {
            ("app.ts", "rule.js"),
            ("other.js", "rule.js"),
            ("helper.py", "rule.py"),
        }
    )
    assert plan.unsupported == ((".go", 1),)


def test_zero_hit_scanned_file_is_verified(tmp_path: Path) -> None:
    plan, rules = _plan(tmp_path)
    slice_ = assess_scan(
        plan, rules.batches[0], _raw(scanned=["app.ts", "other.js"]), engine="opengrep"
    )
    report = finish_coverage(plan, [slice_])
    assert report.expected_count == 3
    assert report.verified_count == 2
    assert _gaps(report) == {("helper.py", "rule.py")}


def test_scanned_file_with_parse_warning_remains_gap(tmp_path: Path) -> None:
    plan, rules = _plan(tmp_path)
    raw = _raw(
        scanned=["app.ts", "other.js"],
        errors=[
            {
                "type": "PartialParsing",
                "path": str(tmp_path / "app.ts"),
                "message": "parser warning",
            }
        ],
    )
    report = finish_coverage(
        plan, [assess_scan(plan, rules.batches[0], raw, engine="opengrep")]
    )
    assert report.verified_count == 1
    assert _gaps(report) == {("app.ts", "rule.js"), ("helper.py", "rule.py")}


@pytest.mark.parametrize(
    "error",
    [
        {"type": "InternalError", "message": "no file"},
        {"type": "Syntax error", "path": "C:/outside/repo/app.ts"},
    ],
)
def test_pathless_or_outside_error_invalidates_batch(
    tmp_path: Path, error: object
) -> None:
    plan, rules = _plan(tmp_path)
    raw = _raw(scanned=["app.ts", "other.js"], errors=[error])
    report = finish_coverage(
        plan, [assess_scan(plan, rules.batches[0], raw, engine="opengrep")]
    )
    assert report.verified_count == 0
    assert _gaps(report) >= {("app.ts", "rule.js"), ("other.js", "rule.js")}


def test_symlink_does_not_count_as_in_root_coverage(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-static-coverage.py"
    outside.write_text("foo()\n", encoding="utf-8")
    try:
        (tmp_path / "link.py").symlink_to(outside)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip("Windows symlink privilege is unavailable")
        raise
    rules = plan_rule_batches(
        _rules(), tool_version="1.30.0", executable_sha256="a" * 64, batch_size=1
    )
    plan = plan_static_coverage(tmp_path, ["link.py"], "b" * 40, rules)
    assert ("link.py", "rule.py") not in plan.expected_pairs
    assert plan.excluded_paths == ("link.py",)


def test_skipped_file_and_rule_leave_gaps(tmp_path: Path) -> None:
    plan, rules = _plan(tmp_path)
    raw = _raw(scanned=["app.ts", "other.js"], skipped=["other.js"])
    report = finish_coverage(
        plan, [assess_scan(plan, rules.batches[0], raw, engine="opengrep")]
    )
    assert report.verified_count == 1
    assert ("other.js", "rule.js") in _gaps(report)


def test_fallback_closes_only_targeted_gap(tmp_path: Path) -> None:
    plan, rules = _plan(tmp_path)
    first = assess_scan(
        plan,
        rules.batches[0],
        _raw(
            scanned=["app.ts", "other.js"],
            errors=[{"path": "app.ts", "type": "PartialParsing"}],
        ),
        engine="opengrep",
    )
    fallback = assess_scan(
        plan,
        rules.batches[0],
        _raw(scanned=["app.ts"]),
        engine="semgrep",
        targets=["app.ts"],
    )
    report = finish_coverage(plan, [first, fallback])
    assert report.verified_count == 2
    assert _gaps(report) == {("helper.py", "rule.py")}


def test_fallback_cannot_credit_non_targeted_file(tmp_path: Path) -> None:
    plan, rules = _plan(tmp_path)
    fallback = assess_scan(
        plan,
        rules.batches[0],
        _raw(scanned=["app.ts", "other.js"]),
        engine="semgrep",
        targets=["app.ts"],
    )
    report = finish_coverage(plan, [fallback])
    assert report.verified_count == 1
    assert ("other.js", "rule.js") in _gaps(report)


def test_fingerprint_changes_with_tracked_files_and_rules(tmp_path: Path) -> None:
    first, rules = _plan(tmp_path)
    second = plan_static_coverage(tmp_path, ["app.ts"], "b" * 40, rules)
    third = plan_static_coverage(
        tmp_path, ["app.ts", "other.js", "helper.py", "main.go"], "c" * 40, rules
    )
    assert len({first.fingerprint, second.fingerprint, third.fingerprint}) == 3
