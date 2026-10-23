"""Measure pinned educational repositories' Python static scope, not recall.

This intentionally does not invoke agents, PoCs, or report generation. Its
aggregate output cannot be used as a true-positive or recall numerator.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from sastsimi.simple_runtime.opengrep_rule_batches import (  # noqa: E402
    RuleBatch,
    plan_rule_batches,
)
from sastsimi.simple_runtime.static_coverage import (  # noqa: E402
    CoverageSlice,
    assess_scan,
    finish_coverage,
    plan_static_coverage,
)
from sastsimi.static_analysis.file_scope import (  # noqa: E402
    StaticFileScope,
    build_static_file_scope,
)

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_URL = re.compile(r"https://github\.com/[^/]+/[^/]+(?:\.git)?\Z", re.IGNORECASE)
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9 _-]{0,63}\Z")


@dataclass(frozen=True, slots=True)
class Target:
    name: str
    url: str
    commit: str


@dataclass(frozen=True, slots=True)
class CheckoutScope:
    target: Target
    root: Path
    tracked: tuple[str, ...]
    files: StaticFileScope
    source_content_sha256: str
    scan_scope_fingerprint: str


@dataclass(frozen=True, slots=True)
class ScanAttempt:
    returncode: int
    raw: bytes
    elapsed_seconds: float


def load_targets(path: Path) -> tuple[Target, ...]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("schema") != "sastsimi_six_educational_targets_v1"
    ):
        raise ValueError("BENCHMARK_MANIFEST_INVALID")
    rows = value.get("targets")
    if not isinstance(rows, list) or len(rows) != 6:
        raise ValueError("BENCHMARK_MANIFEST_INVALID")
    targets: list[Target] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("BENCHMARK_MANIFEST_INVALID")
        name, url, commit = row.get("name"), row.get("url"), row.get("commit")
        if (
            not isinstance(name, str)
            or _NAME.fullmatch(name) is None
            or not isinstance(url, str)
            or _URL.fullmatch(url) is None
            or not isinstance(commit, str)
            or _SHA.fullmatch(commit) is None
        ):
            raise ValueError("BENCHMARK_MANIFEST_INVALID")
        targets.append(Target(name, url, commit))
    if (
        len({item.name.casefold() for item in targets}) != 6
        or len({item.url.casefold() for item in targets}) != 6
    ):
        raise ValueError("BENCHMARK_MANIFEST_DUPLICATE")
    return tuple(targets)


def _git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.run(
            ["git", *args], cwd=root, check=True, capture_output=True, timeout=30
        ).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
        raise ValueError("BENCHMARK_CHECKOUT_INVALID") from error


def _canonical_url(value: str) -> str:
    return value.rstrip("/").removesuffix(".git").casefold()


def _source_content_sha256(root: Path, paths: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for relative in paths:
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(hashlib.sha256((root / relative).read_bytes()).digest())
    return digest.hexdigest()


def _ensure_source_unchanged(scope: CheckoutScope) -> None:
    try:
        current = _source_content_sha256(scope.root, scope.files.selected_paths)
    except OSError as error:
        raise RuntimeError("BENCHMARK_SOURCE_CHANGED_DURING_SCAN") from error
    if current != scope.source_content_sha256:
        raise RuntimeError("BENCHMARK_SOURCE_CHANGED_DURING_SCAN")


def inspect_checkout(target: Target, root: Path) -> CheckoutScope:
    root = root.resolve(strict=True)
    git_root = Path(
        _git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    ).resolve(strict=True)
    if git_root != root:
        raise ValueError("BENCHMARK_NOT_REPOSITORY_ROOT")
    actual_commit = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    if actual_commit != target.commit:
        raise ValueError("BENCHMARK_COMMIT_MISMATCH")
    remote = _git(root, "remote", "get-url", "origin").decode("utf-8").strip()
    if _canonical_url(remote) != _canonical_url(target.url):
        raise ValueError("BENCHMARK_REMOTE_MISMATCH")
    if _git(root, "status", "--porcelain=v1", "--untracked-files=no"):
        raise ValueError("BENCHMARK_CHECKOUT_DIRTY")
    tracked = tuple(
        raw.decode("utf-8")
        for raw in _git(root, "ls-files", "--cached", "-z").split(b"\0")
        if raw
    )
    files = build_static_file_scope(root, tracked)
    # Git's status may hide files marked assume-unchanged/skip-worktree. Verify
    # the bytes that select the scope and the source actually sent to OpenGrep.
    staged = _git(root, "ls-files", "--stage", "-z")
    indexed: dict[str, str] = {}
    for record in staged.split(b"\0"):
        if not record:
            continue
        metadata, _, raw_path = record.partition(b"\t")
        fields = metadata.decode("ascii").split(" ")
        if len(fields) != 3 or fields[2] != "0" or not raw_path:
            raise ValueError("BENCHMARK_CONTENT_MISMATCH")
        indexed[raw_path.decode("utf-8")] = fields[1]
    source_paths = set(files.selected_paths)
    source_paths.update(
        path
        for path in tracked
        if path.endswith((".py", ".pyi"))
        or Path(path).name in {"pyproject.toml", "package.json"}
    )
    for relative in sorted(source_paths):
        expected = indexed.get(relative)
        if expected is None:
            raise ValueError("BENCHMARK_CONTENT_MISMATCH")
        actual = _git(root, "hash-object", f"--path={relative}", "--", relative)
        if actual.decode("ascii").strip() != expected:
            raise ValueError("BENCHMARK_CONTENT_MISMATCH")
    try:
        content_sha256 = _source_content_sha256(root, files.selected_paths)
    except OSError as error:
        raise ValueError("BENCHMARK_CONTENT_MISMATCH") from error
    scan_scope_fingerprint = hashlib.sha256(
        f"{files.fingerprint}\0{content_sha256}".encode("ascii")
    ).hexdigest()
    return CheckoutScope(
        target=target,
        root=root,
        tracked=tracked,
        files=files,
        source_content_sha256=content_sha256,
        scan_scope_fingerprint=scan_scope_fingerprint,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _scan_batch(
    *,
    scope: CheckoutScope,
    batch: RuleBatch,
    rules: Path,
    tool: Path,
    targets: tuple[str, ...],
    raw_path: Path,
    timeout_seconds: int,
) -> ScanAttempt:
    handle, temporary = tempfile.mkstemp(
        prefix=f"batch-{batch.index:02d}-", suffix=".json", dir=raw_path.parent
    )
    temporary_path = Path(temporary)
    # OpenGrep creates the output itself. A unique path avoids treating an old
    # partial artifact as the result of this invocation.
    os.close(handle)
    temporary_path.unlink()
    command = [
        str(tool),
        "scan",
        "--json",
        "--disable-version-check",
        "--no-rewrite-rule-ids",
        "--config",
        str(rules),
        "--output",
        str(temporary_path),
    ]
    for rule_id in batch.excluded_rule_ids:
        command.extend(("--exclude-rule", rule_id))
    command.extend(targets)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=scope.root,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        return ScanAttempt(
            returncode=completed.returncode,
            raw=temporary_path.read_bytes() if temporary_path.is_file() else b"",
            elapsed_seconds=time.monotonic() - started,
        )
    finally:
        temporary_path.unlink(missing_ok=True)


def _ast_status(scope: CheckoutScope) -> dict[str, object]:
    parsed = 0
    failed: list[dict[str, str]] = []
    for relative in scope.files.selected_paths:
        path = scope.root / relative
        try:
            ast.parse(path.read_bytes(), filename=relative)
            parsed += 1
        except (OSError, SyntaxError, ValueError) as error:
            failed.append({"path": relative, "reason": type(error).__name__})
    return {"parsed": parsed, "failed": failed}


def run_static_target(
    scope: CheckoutScope,
    rules: Path,
    tool: Path,
    output: Path,
    *,
    timeout_seconds: int,
    tool_version: str,
) -> dict[str, object]:
    if timeout_seconds < 1:
        raise ValueError("BENCHMARK_TIMEOUT_INVALID")
    if not scope.files.selected_paths:
        raise ValueError("BENCHMARK_NO_PRODUCT_PYTHON")
    _ensure_source_unchanged(scope)
    rules = rules.resolve(strict=True)
    tool = tool.resolve(strict=True)
    rule_raw = rules.read_bytes()
    rule_plan = plan_rule_batches(
        rule_raw,
        tool_version=tool_version,
        executable_sha256=_sha256_file(tool),
        batch_size=3,
    )
    coverage_plan = plan_static_coverage(
        scope.root,
        scope.files.selected_paths,
        scope.target.commit,
        rule_plan,
        scope_fingerprint=scope.scan_scope_fingerprint,
    )
    raw_dir = output / scope.target.name.replace(" ", "-") / coverage_plan.fingerprint
    raw_dir.mkdir(parents=True, exist_ok=True)
    slices: list[CoverageSlice] = []
    scanner_errors: list[dict[str, object]] = []
    extra_gap_reasons: dict[tuple[str, str], str] = {}
    attempts = 0
    reused = 0
    elapsed = 0.0
    for batch in rule_plan.batches:
        applicable = coverage_plan.expected_pairs & {
            (path, rule_id)
            for path in scope.files.selected_paths
            for rule_id in batch.rule_ids
        }
        if not applicable:
            continue
        _ensure_source_unchanged(scope)
        targets = tuple(sorted({path for path, _ in applicable}))
        # The parent directory already carries the complete plan fingerprint;
        # shorter leaf names avoid Windows MAX_PATH failures in test/work trees.
        raw_path = raw_dir / f"batch-{batch.index:02d}.json"
        marker_path = raw_dir / f"batch-{batch.index:02d}.success.json"
        if raw_path.is_file() and marker_path.is_file():
            try:
                marker = json.loads(marker_path.read_text(encoding="utf-8"))
                raw = raw_path.read_bytes()
                if not isinstance(marker, dict) or marker != {
                    "schema": "verified_opengrep_batch_v1",
                    "coverage_fingerprint": coverage_plan.fingerprint,
                    "batch_key": batch.key,
                    "raw_sha256": hashlib.sha256(raw).hexdigest(),
                    "exit_code": 0,
                }:
                    raise ValueError("BENCHMARK_CACHE_UNVERIFIED")
                cached = assess_scan(
                    coverage_plan, batch, raw, engine="opengrep", targets=targets
                )
            except (OSError, ValueError, json.JSONDecodeError):
                cached = None
            if cached is not None and cached.verified_pairs == applicable:
                slices.append(cached)
                reused += 1
                continue
        scan_started = time.monotonic()
        try:
            attempts += 1
            attempt = _scan_batch(
                scope=scope,
                batch=batch,
                rules=rules,
                tool=tool,
                targets=targets,
                raw_path=raw_path,
                timeout_seconds=timeout_seconds,
            )
            elapsed += attempt.elapsed_seconds
            if attempt.returncode != 0:
                if attempt.raw:
                    (raw_dir / f"batch-{batch.index:02d}.failed.json").write_bytes(
                        attempt.raw
                    )
                raise ValueError(f"scanner_exit_{attempt.returncode}")
            slice_ = assess_scan(
                coverage_plan,
                batch,
                attempt.raw,
                engine="opengrep",
                targets=targets,
            )
            _ensure_source_unchanged(scope)
            if slice_.verified_pairs == applicable:
                raw_path.write_bytes(attempt.raw)
                marker_path.write_text(
                    json.dumps(
                        {
                            "schema": "verified_opengrep_batch_v1",
                            "coverage_fingerprint": coverage_plan.fingerprint,
                            "batch_key": batch.key,
                            "raw_sha256": hashlib.sha256(attempt.raw).hexdigest(),
                            "exit_code": 0,
                        },
                        sort_keys=True,
                    ),
                    encoding="utf-8",
                )
            else:
                (raw_dir / f"batch-{batch.index:02d}.incomplete.json").write_bytes(
                    attempt.raw
                )
            slices.append(slice_)
        except subprocess.TimeoutExpired:
            elapsed += time.monotonic() - scan_started
            reason = "scan_timeout"
        except (OSError, ValueError) as error:
            reason = (
                str(error)
                if str(error).startswith("scanner_exit_")
                else "scan_output_invalid"
            )
        else:
            continue
        for pair in applicable:
            extra_gap_reasons[pair] = reason
        scanner_errors.append({"batch": batch.index, "reason": reason})
    report = finish_coverage(coverage_plan, slices)
    gaps = [
        {
            "path": gap.path,
            "rule_id": gap.rule_id,
            "reason": extra_gap_reasons.get((gap.path, gap.rule_id), gap.reason),
        }
        for gap in report.gaps
    ]
    verified_hints = sum(
        1
        for slice_ in slices
        for hit in slice_.normalized_results
        if (hit.get("path"), hit.get("check_id")) in slice_.verified_pairs
    )
    ast_result = _ast_status(scope)
    _ensure_source_unchanged(scope)
    complete = (
        report.expected_count > 0
        and report.verified_count == report.expected_count
        and not ast_result["failed"]
    )
    scanner_error_count = len(scanner_errors)
    for slice_ in slices:
        parsed_errors = slice_.parsed.get("errors")
        if isinstance(parsed_errors, list):
            scanner_error_count += len(parsed_errors)
    return {
        "name": scope.target.name,
        "repository": scope.target.url,
        "commit": scope.target.commit,
        "status": ("AST_OPENGREP_COMPLETE" if complete else "AST_OPENGREP_PARTIAL"),
        "scope_fingerprint": scope.scan_scope_fingerprint,
        "source_content_sha256": scope.source_content_sha256,
        "coverage_fingerprint": report.fingerprint,
        "rules_sha256": hashlib.sha256(rule_raw).hexdigest(),
        "tool_sha256": _sha256_file(tool),
        "tool_version": tool_version,
        "product_python_files": len(scope.files.selected_paths),
        "excluded_tests": len(scope.files.excluded_test_files),
        "out_of_scope_product": len(scope.files.out_of_scope_product_files),
        "ast": ast_result,
        "coverage": {
            "expected": report.expected_count,
            "verified": report.verified_count,
            "gaps": gaps,
        },
        "static_hints": verified_hints,
        "scanner_errors": scanner_errors,
        "scanner_error_count": scanner_error_count,
        "scope_issue": (
            "no_applicable_python_rule" if report.expected_count == 0 else None
        ),
        "scan_attempts": attempts,
        "reused_batches": reused,
        "scan_elapsed_seconds": round(elapsed, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=_ROOT / "docs/validation/data/six-educational-targets.json",
    )
    parser.add_argument("--targets-root", type=Path, required=True)
    parser.add_argument(
        "--rules",
        type=Path,
        default=_ROOT / "config/static-analysis/candidate-v1/opengrep/rules.yml",
    )
    parser.add_argument("--tool", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--target", action="append", default=[])
    args = parser.parse_args()
    version = subprocess.run(
        [str(args.tool), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    results: list[dict[str, object]] = []
    for target in load_targets(args.manifest):
        if args.target and target.name not in args.target:
            continue
        checkout = inspect_checkout(
            target, args.targets_root / target.name.replace(" ", "-")
        )
        result = run_static_target(
            checkout,
            args.rules,
            args.tool,
            args.output_dir,
            timeout_seconds=args.timeout_seconds,
            tool_version=version,
        )
        results.append(result)
        coverage_result = result["coverage"]
        assert isinstance(coverage_result, dict)
        print(
            f"{target.name}: {result['status']} "
            f"{coverage_result['verified']}/{coverage_result['expected']} pairs, "
            f"{result['static_hints']} hints",
            flush=True,
        )
    summary: dict[str, Any] = {
        "kind": "six_repository_python_static_benchmark_v1",
        "interpretation": (
            "Static hints and file-rule coverage only; not final Findings or recall"
        ),
        "results": results,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return 0 if len(results) == (len(args.target) if args.target else 6) else 2


if __name__ == "__main__":
    raise SystemExit(main())
