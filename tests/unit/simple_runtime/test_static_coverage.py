"""Coverage is earned per applicable rule and tracked file, never inferred from hits."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.simple_runtime import static_coverage as coverage_module
from sastsimi.simple_runtime.opengrep_rule_batches import (
    RuleBatchPlan,
    plan_rule_batches,
)
from sastsimi.simple_runtime.static_coverage import (
    StaticCoveragePlan,
    StaticCoverageReport,
    assess_scan,
    finish_coverage,
    merge_static_candidates,
    plan_static_coverage,
)
from sastsimi.static_analysis.file_scope import build_static_file_scope


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


def _plan(
    root: Path, tracked: list[str] | None = None
) -> tuple[StaticCoveragePlan, RuleBatchPlan]:
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


def _gaps(report: StaticCoverageReport) -> set[tuple[str, str]]:
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


def test_unknown_product_source_extension_blocks_without_flagging_docs(
    tmp_path: Path,
) -> None:
    plan, _ = _plan(
        tmp_path,
        [
            "app.py",
            "analysis.R",
            "processor.customlang",
            "README.md",
            "api/.env.example",
            "api/.env",
            "api/.env.production",
            "go.mod",
            "go.sum",
            "pkg/py.typed",
            "Dockerfile.dockerignore",
        ],
    )

    assert plan.expected_pairs == frozenset({("app.py", "rule.py")})
    assert plan.unsupported == ((".customlang", 1), (".r", 1))


def test_non_python_product_paths_are_ignored_without_test_files(
    tmp_path: Path,
) -> None:
    for name in ("app.py", "bin/launcher", "src/worker.r", "tests/test_worker.r"):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("source\n", encoding="utf-8")
    rules = plan_rule_batches(
        _rules(), tool_version="1.30.0", executable_sha256="a" * 64
    )
    product = build_static_file_scope(
        tmp_path, ("app.py", "bin/launcher", "src/worker.r", "tests/test_worker.r")
    )
    assert product.selected_paths == ("app.py",)
    plan = plan_static_coverage(
        tmp_path,
        product.selected_paths,
        "b" * 40,
        rules,
        scope_fingerprint=product.fingerprint,
    )

    report = finish_coverage(plan, [])
    assert report.to_json()["unsupported"] == []
    assert report.to_json()["unsupported_files"] == []


def test_product_scope_excludes_tests_from_rule_pairs_and_cache_identity(
    tmp_path: Path,
) -> None:
    for name in ("app.py", "tests/test_app.py"):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("foo()\n", encoding="utf-8")
    rules = plan_rule_batches(
        _rules(), tool_version="1.30.0", executable_sha256="a" * 64
    )
    product = build_static_file_scope(tmp_path, ("app.py", "tests/test_app.py"))
    product_plan = plan_static_coverage(
        tmp_path,
        product.selected_paths,
        "b" * 40,
        rules,
        scope_fingerprint=product.fingerprint,
    )
    old_full_scope_plan = plan_static_coverage(
        tmp_path, ("app.py", "tests/test_app.py"), "b" * 40, rules
    )
    assert product_plan.expected_pairs == frozenset({("app.py", "rule.py")})
    assert old_full_scope_plan.expected_pairs == frozenset(
        {("app.py", "rule.py"), ("tests/test_app.py", "rule.py")}
    )
    assert product_plan.fingerprint != old_full_scope_plan.fingerprint


def test_targeted_scan_rejects_unrequested_test_path_even_when_app_scanned(
    tmp_path: Path,
) -> None:
    plan, rules = _plan(tmp_path, ["app.py"])
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("foo()\n", encoding="utf-8")
    with pytest.raises(ValueError, match="STATIC_SCAN_SCOPE_MISMATCH"):
        assess_scan(
            plan,
            rules.batches[1],
            _raw(scanned=["app.py", "tests/test_app.py"]),
            engine="opengrep",
            targets=("app.py",),
        )


def test_zero_hit_scanned_file_is_verified(tmp_path: Path) -> None:
    plan, rules = _plan(tmp_path)
    slice_ = assess_scan(
        plan, rules.batches[0], _raw(scanned=["app.ts", "other.js"]), engine="opengrep"
    )
    report = finish_coverage(plan, [slice_])
    assert report.expected_count == 3
    assert report.verified_count == 2
    assert _gaps(report) == {("helper.py", "rule.py")}


def test_targeted_scan_uses_pair_membership_without_walking_whole_plan(
    tmp_path: Path,
) -> None:
    plan, rules = _plan(tmp_path)

    class MembershipOnlyPairs(frozenset[tuple[str, str]]):
        def __iter__(self) -> Iterator[tuple[str, str]]:
            raise AssertionError("targeted scan iterated every expected pair")

    targeted = replace(plan, expected_pairs=MembershipOnlyPairs(plan.expected_pairs))
    slice_ = assess_scan(
        targeted,
        rules.batches[0],
        _raw(scanned=["app.ts"]),
        engine="semgrep",
        targets=["app.ts"],
    )

    assert slice_.verified_pairs == frozenset({("app.ts", "rule.js")})


def test_coverage_plan_resolves_workspace_root_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tracked = [f"file-{index}.ts" for index in range(4)]
    for path in tracked:
        (tmp_path / path).write_text("foo()\n", encoding="utf-8")
    rules = plan_rule_batches(
        _rules(),
        tool_version="1.30.0",
        executable_sha256="a" * 64,
        batch_size=1,
    )
    original_resolve = Path.resolve
    root_resolutions = 0

    def counting_resolve(self: Path, strict: bool = False) -> Path:
        nonlocal root_resolutions
        if self == tmp_path:
            root_resolutions += 1
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", counting_resolve)
    plan = plan_static_coverage(tmp_path, tracked, "b" * 40, rules)

    assert len(plan.expected_pairs) == 4
    assert root_resolutions <= 2


def test_absolute_scanner_paths_are_normalized_on_all_platforms(tmp_path: Path) -> None:
    plan, rules = _plan(tmp_path)
    absolute_path = str((tmp_path / "app.ts").resolve())
    raw = _raw(
        scanned=[absolute_path],
        results=[{"check_id": "rule.js", "path": absolute_path, "start": {"line": 1}}],
    )

    slice_ = assess_scan(plan, rules.batches[0], raw, engine="opengrep")

    assert slice_.verified_pairs == frozenset({("app.ts", "rule.js")})
    assert slice_.normalized_results[0]["path"] == "app.ts"


def test_assessed_slice_keeps_scan_metadata_without_duplicate_raw_hits(
    tmp_path: Path,
) -> None:
    plan, rules = _plan(tmp_path)
    hit = {
        "check_id": "rule.js",
        "path": "app.ts",
        "start": {"line": 1},
        "extra": {"message": "source evidence"},
    }
    raw = json.dumps(
        {
            "results": [hit],
            "errors": [],
            "paths": {"scanned": ["app.ts"], "skipped": []},
            "skipped_rules": [],
            "stats": {"duration": 1},
        }
    ).encode()

    slice_ = assess_scan(plan, rules.batches[0], raw, engine="opengrep")

    assert slice_.parsed["results"] == []
    assert slice_.parsed["paths"] == {"scanned": ["app.ts"], "skipped": []}
    assert slice_.parsed["errors"] == []
    assert slice_.parsed["skipped_rules"] == []
    assert slice_.parsed["stats"] == {"duration": 1}
    assert slice_.normalized_results == ({**hit, "scan_incomplete": False},)


def test_default_candidate_budget_has_no_cumulative_result_ceiling() -> None:
    budget = coverage_module.StaticCandidateBudget()

    budget.claim_results(500_000)
    budget.claim_results(1)

    assert budget.used_results == 500_001


def test_shared_candidate_budget_rejects_cumulative_hits_without_dropping_them(
    tmp_path: Path,
) -> None:
    plan, rules = _plan(tmp_path)
    budget = coverage_module.StaticCandidateBudget(max_results=2)

    def scan(line: int) -> bytes:
        return _raw(
            scanned=["app.ts"],
            results=[
                {"check_id": "rule.js", "path": "app.ts", "start": {"line": line}}
            ],
        )

    first = assess_scan(
        plan, rules.batches[0], scan(1), engine="semgrep", candidate_budget=budget
    )
    second = assess_scan(
        plan, rules.batches[0], scan(2), engine="semgrep", candidate_budget=budget
    )

    starts = [
        hit["start"] for slice_ in (first, second) for hit in slice_.normalized_results
    ]
    assert starts == [
        {"line": 1},
        {"line": 2},
    ]
    with pytest.raises(
        coverage_module.StaticCandidateLimitError,
        match="STATIC_CANDIDATES_TOO_LARGE",
    ):
        assess_scan(
            plan,
            rules.batches[0],
            scan(3),
            engine="semgrep",
            candidate_budget=budget,
        )


def test_shared_candidate_budget_rejects_cumulative_raw_bytes_before_parse(
    tmp_path: Path,
) -> None:
    plan, rules = _plan(tmp_path)
    first_raw = _raw(scanned=["app.ts"])
    budget = coverage_module.StaticCandidateBudget(
        max_raw_bytes=len(first_raw) + len(b"not-json") - 1
    )

    assess_scan(
        plan,
        rules.batches[0],
        first_raw,
        engine="semgrep",
        candidate_budget=budget,
    )

    # The second input is malformed. The budget must reject it before parsing.
    with pytest.raises(
        coverage_module.StaticCandidateLimitError,
        match="STATIC_CANDIDATES_TOO_LARGE",
    ):
        assess_scan(
            plan,
            rules.batches[0],
            b"not-json",
            engine="semgrep",
            candidate_budget=budget,
        )


def test_failed_scan_releases_shared_candidate_raw_byte_reservation(
    tmp_path: Path,
) -> None:
    plan, rules = _plan(tmp_path)
    valid_raw = _raw(scanned=["app.ts"])
    budget = coverage_module.StaticCandidateBudget(max_raw_bytes=len(valid_raw))

    with pytest.raises(ValueError, match="OPENGREP_RESULT_INVALID"):
        assess_scan(
            plan,
            rules.batches[0],
            b"bad",
            engine="semgrep",
            candidate_budget=budget,
        )

    slice_ = assess_scan(
        plan,
        rules.batches[0],
        valid_raw,
        engine="semgrep",
        candidate_budget=budget,
    )
    assert slice_.verified_pairs == frozenset({("app.ts", "rule.js")})


def test_failed_scan_after_a_hit_does_not_claim_shared_candidate_capacity(
    tmp_path: Path,
) -> None:
    plan, rules = _plan(tmp_path)
    hit = {"check_id": "rule.js", "path": "app.ts", "start": {"line": 1}}
    invalid_raw = _raw(
        scanned=["app.ts"],
        results=[
            hit,
            {"check_id": "rule.js", "path": "outside.ts", "start": {"line": 2}},
        ],
    )
    valid_raw = _raw(scanned=["app.ts"], results=[hit])
    budget = coverage_module.StaticCandidateBudget(
        max_results=1, max_raw_bytes=len(invalid_raw)
    )

    with pytest.raises(ValueError, match="STATIC_SCAN_RESULT_PATH_INVALID"):
        assess_scan(
            plan,
            rules.batches[0],
            invalid_raw,
            engine="semgrep",
            candidate_budget=budget,
        )
    assert budget.used_results == 0
    assert budget.used_raw_bytes == 0

    slice_ = assess_scan(
        plan,
        rules.batches[0],
        valid_raw,
        engine="semgrep",
        candidate_budget=budget,
    )
    assert len(slice_.normalized_results) == 1
    assert budget.used_results == 1
    assert budget.used_raw_bytes == len(valid_raw)


def test_repeated_result_path_is_resolved_once_per_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, rules = _plan(tmp_path)
    path = tmp_path / "app.ts"
    original_resolve = Path.resolve
    path_resolutions = 0

    def counting_resolve(self: Path, strict: bool = False) -> Path:
        nonlocal path_resolutions
        if self == path:
            path_resolutions += 1
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", counting_resolve)
    raw = _raw(
        scanned=["app.ts"],
        results=[
            {
                "check_id": "rule.js",
                "path": "app.ts",
                "start": {"line": 1, "col": column},
                "end": {"line": 1, "col": column + 1},
            }
            for column in range(40)
        ],
    )

    slice_ = assess_scan(plan, rules.batches[0], raw, engine="opengrep")

    assert len(slice_.normalized_results) == 40
    assert all(result["path"] == "app.ts" for result in slice_.normalized_results)
    assert slice_.verified_pairs == frozenset({("app.ts", "rule.js")})
    assert path_resolutions <= 3


def test_repeated_result_path_is_rechecked_after_normalization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, rules = _plan(tmp_path)
    path = tmp_path / "app.ts"
    outside = tmp_path.parent / f"{tmp_path.name}-redirect.ts"
    outside.write_text("foo()\n", encoding="utf-8")
    original_resolve = Path.resolve
    path_resolutions = 0

    def redirected_resolve(self: Path, strict: bool = False) -> Path:
        nonlocal path_resolutions
        if self == path:
            path_resolutions += 1
            if path_resolutions >= 3:
                return outside
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", redirected_resolve)
    raw = _raw(
        scanned=["app.ts"],
        results=[
            {"check_id": "rule.js", "path": "app.ts", "start": {"line": 1}}
            for _ in range(20)
        ],
    )

    with pytest.raises(ValueError, match="STATIC_SCAN_RESULT_PATH_INVALID"):
        assess_scan(plan, rules.batches[0], raw, engine="opengrep")


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


def test_unrecognized_error_rule_invalidates_its_file(tmp_path: Path) -> None:
    plan, rules = _plan(tmp_path)
    raw = _raw(
        scanned=["app.ts", "other.js"],
        errors=[{"path": "app.ts", "check_id": "unknown-rule", "type": "ParseError"}],
    )
    report = finish_coverage(
        plan, [assess_scan(plan, rules.batches[0], raw, engine="opengrep")]
    )
    assert ("app.ts", "rule.js") in _gaps(report)
    assert report.verified_count == 1


def test_parser_error_with_rule_id_invalidates_every_rule_on_file(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.ts").write_text("foo()\n", encoding="utf-8")
    rules = plan_rule_batches(
        b"rules:\n  - id: rule.one\n    languages: [javascript]\n"
        b"  - id: rule.two\n    languages: [javascript]\n",
        tool_version="1.30.0",
        executable_sha256="a" * 64,
        batch_size=2,
    )
    plan = plan_static_coverage(tmp_path, ["app.ts"], "b" * 40, rules)
    raw = _raw(
        scanned=["app.ts"],
        errors=[
            {
                "path": "app.ts",
                "check_id": "rule.one",
                "type": "PartialParsing",
            }
        ],
    )
    report = finish_coverage(
        plan, [assess_scan(plan, rules.batches[0], raw, engine="opengrep")]
    )
    assert _gaps(report) == {
        ("app.ts", "rule.one"),
        ("app.ts", "rule.two"),
    }


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
    assert ("link.py", "rule.py") in plan.expected_pairs
    assert plan.excluded_paths == ("link.py",)
    report = finish_coverage(plan, [])
    assert [(gap.path, gap.rule_id, gap.reason) for gap in report.gaps] == [
        ("link.py", "rule.py", "source_unavailable")
    ]


def test_missing_tracked_source_is_not_silently_excluded(tmp_path: Path) -> None:
    rules = plan_rule_batches(
        _rules(), tool_version="1.30.0", executable_sha256="a" * 64, batch_size=1
    )
    plan = plan_static_coverage(tmp_path, ["missing.py"], "b" * 40, rules)
    report = finish_coverage(plan, [])
    assert plan.expected_pairs == frozenset({("missing.py", "rule.py")})
    assert [(gap.path, gap.rule_id, gap.reason) for gap in report.gaps] == [
        ("missing.py", "rule.py", "source_unavailable")
    ]


def test_unknown_rule_language_cannot_silently_complete(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
    rules = plan_rule_batches(
        b"rules:\n  - id: rule.go\n    languages: [go]\n",
        tool_version="1.30.0",
        executable_sha256="a" * 64,
    )
    with pytest.raises(ValueError, match="STATIC_COVERAGE_LANGUAGE_UNSUPPORTED"):
        plan_static_coverage(tmp_path, ["main.go"], "b" * 40, rules)


def test_same_line_distinct_columns_keep_both_candidates(tmp_path: Path) -> None:
    plan, rules = _plan(tmp_path)
    raw = _raw(
        scanned=["app.ts"],
        results=[
            {
                "check_id": "rule.js",
                "path": "app.ts",
                "start": {"line": 1, "col": column},
                "end": {"line": 1, "col": column + 3},
            }
            for column in (3, 18)
        ],
    )
    slice_ = assess_scan(plan, rules.batches[0], raw, engine="opengrep")
    merged = json.loads(merge_static_candidates(rules, [slice_]))
    assert len(merged["results"]) == 2


def test_same_location_distinct_dataflow_paths_remain_separate(tmp_path: Path) -> None:
    plan, rules = _plan(tmp_path)
    raw = _raw(
        scanned=["app.ts"],
        results=[
            {
                "check_id": "rule.js",
                "path": "app.ts",
                "start": {"line": 3, "col": 1},
                "end": {"line": 3, "col": 8},
                "extra": {
                    "source": "request",
                    "sink": "exec",
                    "dataflow_trace": {"path": path},
                },
            }
            for path in (["route_a", "helper"], ["route_b", "helper"])
        ],
    )
    slice_ = assess_scan(plan, rules.batches[0], raw, engine="opengrep")

    results = json.loads(merge_static_candidates(rules, [slice_]))["results"]
    assert len(results) == 2
    assert {tuple(hit["extra"]["dataflow_trace"]["path"]) for hit in results} == {
        ("route_a", "helper"),
        ("route_b", "helper"),
    }


def test_merge_does_not_apply_an_arbitrary_global_candidate_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, rules = _plan(tmp_path)
    slice_ = assess_scan(
        plan,
        rules.batches[0],
        _raw(
            scanned=["app.ts"],
            results=[
                {"check_id": "rule.js", "path": "app.ts", "start": {"line": line}}
                for line in (1, 2, 3)
            ],
        ),
        engine="opengrep",
    )
    monkeypatch.setattr(coverage_module, "_MAX_STATIC_CANDIDATES", 2)

    assert len(json.loads(merge_static_candidates(rules, [slice_]))["results"]) == 3


def test_bounded_candidate_preview_keeps_rules_and_cross_engine_origin(
    tmp_path: Path,
) -> None:
    plan, rules = _plan(tmp_path)
    first_hit = {
        "check_id": "rule.js",
        "path": "app.ts",
        "start": {"line": 1, "col": 1},
    }
    js_hits = [
        {
            "check_id": "rule.js",
            "path": "app.ts",
            "start": {"line": 1, "col": column},
        }
        for column in range(1, 602)
    ]
    js = assess_scan(
        plan,
        rules.batches[0],
        _raw(scanned=["app.ts"], results=js_hits),
        engine="opengrep",
    )
    py = assess_scan(
        plan,
        rules.batches[1],
        _raw(
            scanned=["helper.py"],
            results=[
                {
                    "check_id": "rule.py",
                    "path": "helper.py",
                    "start": {"line": 1, "col": 1},
                }
            ],
        ),
        engine="opengrep",
    )
    fallback = assess_scan(
        plan,
        rules.batches[0],
        _raw(scanned=["app.ts"], results=[first_hit]),
        engine="semgrep",
        targets=["app.ts"],
    )

    preview = json.loads(
        coverage_module.merge_static_candidates_preview(rules, [js, py, fallback])
    )
    results = preview["results"]
    assert len(results) == 500
    assert preview["candidate_snippet_limit"] == 500
    assert preview["candidate_snippets_truncated"] is True
    assert {item["check_id"] for item in results} == {"rule.js", "rule.py"}
    same_hit = next(
        item
        for item in results
        if item["check_id"] == "rule.js" and item["start"]["col"] == 1
    )
    assert same_hit["engines"] == ["opengrep", "semgrep"]
    assert len(preview["batches"]) == 3


def test_preview_bounds_large_hit_details_and_rule_metadata(tmp_path: Path) -> None:
    plan, rules = _plan(tmp_path)
    hit = {
        "check_id": "rule.js",
        "path": "app.ts",
        "start": {"line": 1},
        "extra": {"large_trace": "x" * 100_000},
    }
    slice_ = assess_scan(
        plan,
        rules.batches[0],
        _raw(scanned=["app.ts"], results=[hit]),
        engine="opengrep",
    )
    preview_bytes = coverage_module.merge_static_candidates_preview(rules, [slice_])
    assert len(preview_bytes) < 10_000
    preview = json.loads(preview_bytes)
    assert preview["results"][0]["candidate_digest"]
    assert "extra" not in preview["results"][0]

    large_catalog = RuleBatchPlan(
        fingerprint="a" * 64,
        rule_ids=tuple(f"rule.{index}" for index in range(501)),
        rule_languages=(("python",),) * 501,
        batches=(),
    )
    capped = json.loads(
        coverage_module.merge_static_candidates_preview(large_catalog, [])
    )
    assert len(capped["rule_ids"]) == 500
    assert capped["rule_ids_truncated"] is True
    assert capped["results"] == []


def test_partial_parse_hit_is_not_an_agent_candidate(tmp_path: Path) -> None:
    plan, rules = _plan(tmp_path)
    hit = {
        "check_id": "rule.js",
        "path": "app.ts",
        "start": {"line": 1, "col": 3},
        "end": {"line": 1, "col": 8},
    }
    partial = assess_scan(
        plan,
        rules.batches[0],
        _raw(
            scanned=["app.ts"],
            errors=[{"type": "PartialParsing", "path": "app.ts"}],
            results=[hit],
        ),
        engine="opengrep",
    )
    merged = json.loads(merge_static_candidates(rules, [partial]))
    assert merged["results"] == []
    assert len(partial.normalized_results) == 1
    assert partial.normalized_results[0]["scan_incomplete"] is True


def test_fallback_hit_is_only_verified_origin_of_duplicate(tmp_path: Path) -> None:
    plan, rules = _plan(tmp_path)
    hit = {
        "check_id": "rule.js",
        "path": "app.ts",
        "start": {"line": 1, "col": 3},
        "end": {"line": 1, "col": 8},
    }
    partial = assess_scan(
        plan,
        rules.batches[0],
        _raw(
            scanned=["app.ts"],
            errors=[{"type": "PartialParsing", "path": "app.ts"}],
            results=[hit],
        ),
        engine="opengrep",
    )
    fallback = assess_scan(
        plan,
        rules.batches[0],
        _raw(scanned=["app.ts"], results=[hit]),
        engine="semgrep",
        targets=["app.ts"],
    )
    merged = json.loads(merge_static_candidates(rules, [partial, fallback]))
    assert len(merged["results"]) == 1
    assert merged["results"][0]["engine"] == "semgrep"
    assert merged["results"][0]["engines"] == ["semgrep"]
    assert merged["results"][0]["scan_incomplete"] is False


@pytest.mark.parametrize("error_type", ["PartialParsing", "Timeout"])
def test_later_clean_zero_hit_does_not_promote_earlier_unverified_hit(
    tmp_path: Path, error_type: str
) -> None:
    plan, rules = _plan(tmp_path)
    hit = {"check_id": "rule.js", "path": "app.ts", "start": {"line": 1}}
    incomplete = assess_scan(
        plan,
        rules.batches[0],
        _raw(
            scanned=["app.ts"],
            errors=[{"type": error_type, "path": "app.ts"}],
            results=[hit],
        ),
        engine="opengrep",
    )
    clean = assess_scan(
        plan,
        rules.batches[0],
        _raw(scanned=["app.ts"]),
        engine="semgrep",
        targets=["app.ts"],
    )

    assert finish_coverage(plan, [incomplete, clean]).verified_count == 1
    merged = json.loads(merge_static_candidates(rules, [incomplete, clean]))
    assert merged["results"] == []


def test_two_verified_engines_deduplicate_hit_with_both_origins(tmp_path: Path) -> None:
    plan, rules = _plan(tmp_path)
    hit = {"check_id": "rule.js", "path": "app.ts", "start": {"line": 1}}
    first = assess_scan(
        plan,
        rules.batches[0],
        _raw(scanned=["app.ts"], results=[hit]),
        engine="opengrep",
    )
    second = assess_scan(
        plan,
        rules.batches[0],
        _raw(scanned=["app.ts"], results=[hit]),
        engine="semgrep",
        targets=["app.ts"],
    )

    results = json.loads(merge_static_candidates(rules, [first, second]))["results"]
    assert len(results) == 1
    assert results[0]["engines"] == ["opengrep", "semgrep"]


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
    with pytest.raises(ValueError, match="STATIC_SCAN_SCOPE_MISMATCH"):
        assess_scan(
            plan,
            rules.batches[0],
            _raw(scanned=["app.ts", "other.js"]),
            engine="semgrep",
            targets=["app.ts"],
        )


def test_fingerprint_changes_with_tracked_files_and_rules(tmp_path: Path) -> None:
    first, rules = _plan(tmp_path)
    second = plan_static_coverage(tmp_path, ["app.ts"], "b" * 40, rules)
    third = plan_static_coverage(
        tmp_path, ["app.ts", "other.js", "helper.py", "main.go"], "c" * 40, rules
    )
    assert len({first.fingerprint, second.fingerprint, third.fingerprint}) == 3


def test_pure_coverage_fingerprint_preserves_saved_plan_identity(
    tmp_path: Path,
) -> None:
    plan, rules = _plan(tmp_path)
    tracked = ["app.ts", "other.js", "helper.py", "main.go"]
    with_fallback = plan_static_coverage(
        tmp_path,
        tracked,
        "b" * 40,
        rules,
        fallback_tool_fingerprint="tool-binding-v1",
    )

    assert (
        coverage_module.static_coverage_fingerprint(
            tracked,
            "b" * 40,
            rules,
            fallback_tool_fingerprint="tool-binding-v1",
        )
        == with_fallback.fingerprint
        == "f22cec076f5a0ca75cd73ddd44c71aeda80b1a1badcbed65a4c51e9762dc3017"
    )
    assert plan.fingerprint != with_fallback.fingerprint
