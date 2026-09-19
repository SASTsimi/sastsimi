"""Run the fake-free LOCAL_EVALUATION acceptance targets.

Keep the selected profile under ignored ``runtime-data``.  The profile owns
the current capability keys, Codex executable/session paths, model, and CodeQL
container pins; this script neither embeds nor discovers those host values.

Example::

    python scripts/run_local_evaluation_smoke.py \
      --profile runtime-data/local-evaluation.toml \
      --data-dir runtime-data/live-evaluation-smoke \
      --target all
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

TargetName = Literal["pygoat", "itsdangerous"]
type CommandExecutor = Callable[[list[str], int], dict[str, object]]


@dataclass(frozen=True, slots=True)
class Target:
    name: TargetName
    repository: str
    commit: str


TARGETS = (
    Target(
        name="pygoat",
        repository="https://github.com/adeyosemanputra/pygoat.git",
        commit="19d17cc8874861142b330636d068bbde54e86b85",
    ),
    Target(
        name="itsdangerous",
        repository="https://github.com/pallets/itsdangerous.git",
        commit="096c8d42545d3b68ea21a4f890fb2b2d8979c0bd",
    ),
)


class SmokeFailure(RuntimeError):
    """A safe acceptance failure that does not disclose local configuration."""


def _data(envelope: Mapping[str, object], command: str) -> Mapping[str, object]:
    if (
        envelope.get("command") != command
        or envelope.get("status") != "ok"
        or envelope.get("code") != "OK"
    ):
        raise SmokeFailure("CLI_ENVELOPE_INVALID")
    value = envelope.get("data")
    if not isinstance(value, Mapping):
        raise SmokeFailure("CLI_DATA_INVALID")
    return value


def _non_negative_int(value: object, reason: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SmokeFailure(reason)
    return value


def _verdict_counts(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise SmokeFailure("RESULT_VERDICT_COUNTS_INVALID")
    counts: dict[str, int] = {}
    for key, count in value.items():
        if not isinstance(key, str):
            raise SmokeFailure("RESULT_VERDICT_COUNTS_INVALID")
        counts[key] = _non_negative_int(count, "RESULT_VERDICT_COUNTS_INVALID")
    return counts


def validate_run(
    *,
    target: Target,
    evaluate: Mapping[str, object],
    result: Mapping[str, object],
    reports: Mapping[str, object],
    exported_reports: Mapping[str, Path],
    data_dir: Path,
) -> dict[str, object]:
    """Validate terminal records and exported reports for one real target."""

    evaluation_data = _data(evaluate, "evaluate analyze")
    analysis_id = evaluation_data.get("analysis_id")
    if (
        not isinstance(analysis_id, str)
        or not analysis_id
        or evaluation_data.get("status") != "TERMINAL"
        or evaluation_data.get("purpose") != "LOCAL_EVALUATION"
        or evaluation_data.get("production_ready") is not False
    ):
        raise SmokeFailure("EVALUATE_RESULT_INVALID")

    result_data = _data(result, "results")
    if (
        result_data.get("analysis_id") != analysis_id
        or result_data.get("status") != "COMPLETE"
        or result_data.get("purpose") != "LOCAL_EVALUATION"
        or result_data.get("production_ready") is not False
    ):
        raise SmokeFailure("TERMINAL_RESULT_INVALID")
    finding_count = _non_negative_int(
        result_data.get("finding_count"), "RESULT_FINDING_COUNT_INVALID"
    )
    report_count = _non_negative_int(
        result_data.get("report_count"), "RESULT_REPORT_COUNT_INVALID"
    )
    verdict_counts = _verdict_counts(result_data.get("verdict_counts"))

    report_data = _data(reports, "reports")
    listed_count = _non_negative_int(
        report_data.get("count"), "REPORT_LIST_COUNT_INVALID"
    )
    listed = report_data.get("reports")
    if not isinstance(listed, list) or listed_count != len(listed):
        raise SmokeFailure("REPORT_LIST_INVALID")
    if report_count != listed_count or finding_count < report_count:
        raise SmokeFailure("RESULT_REPORT_COUNT_MISMATCH")

    root = data_dir.resolve()
    relative_reports: list[str] = []
    finding_ids: set[str] = set()
    for item in listed:
        if not isinstance(item, Mapping):
            raise SmokeFailure("REPORT_SUMMARY_INVALID")
        finding_id = item.get("finding_id")
        if (
            not isinstance(finding_id, str)
            or not finding_id
            or finding_id in finding_ids
            or item.get("analysis_id") != analysis_id
            or item.get("purpose") != "LOCAL_EVALUATION"
            or item.get("production_ready") != "false"
        ):
            raise SmokeFailure("REPORT_SUMMARY_INVALID")
        finding_ids.add(finding_id)
        exported = exported_reports.get(finding_id)
        if exported is None:
            raise SmokeFailure("REPORT_EXPORT_MISSING")
        try:
            relative = exported.resolve(strict=True).relative_to(root)
            markdown = exported.read_text(encoding="utf-8")
        except (OSError, UnicodeError, ValueError):
            raise SmokeFailure("REPORT_EXPORT_INVALID") from None
        if (
            not relative.parts
            or relative.parts[0] != "reports"
            or "`LOCAL_EVALUATION`" not in markdown
            or "`NOT_PRODUCTION_READY`" not in markdown
        ):
            raise SmokeFailure("REPORT_EXPORT_INVALID")
        relative_reports.append(relative.as_posix())
    if set(exported_reports) != finding_ids:
        raise SmokeFailure("REPORT_EXPORT_INVENTORY_MISMATCH")

    if target.name == "pygoat" and (
        finding_count < 1
        or report_count < 1
        or verdict_counts.get("TRUE", 0) < 1
    ):
        raise SmokeFailure("PYGOAT_TRUE_REPORT_REQUIRED")

    return {
        "target": target.name,
        "repository": target.repository,
        "commit": target.commit,
        "analysis_id": analysis_id,
        "result_status": result_data["status"],
        "finding_count": finding_count,
        "report_count": report_count,
        "verdict_counts": verdict_counts,
        "reports": relative_reports,
    }


def _evaluate_command(target: Target, profile: Path, data_dir: Path) -> list[str]:
    return [
        sys.executable,
        "-m",
        "sastsimi",
        "--data-dir",
        str(data_dir),
        "evaluate",
        "analyze",
        "--repo",
        target.repository,
        "--commit",
        target.commit,
        "--profile",
        str(profile),
        "--format",
        "json",
    ]


def _query_command(data_dir: Path, *arguments: str) -> list[str]:
    return [
        sys.executable,
        "-m",
        "sastsimi",
        "--data-dir",
        str(data_dir),
        *arguments,
    ]


def _run_json(command: list[str], timeout_seconds: int) -> dict[str, object]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise SmokeFailure("CLI_EXECUTION_UNAVAILABLE") from None
    if completed.returncode != 0:
        raise SmokeFailure("CLI_COMMAND_FAILED")
    try:
        value: object = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise SmokeFailure("CLI_OUTPUT_NOT_JSON") from None
    if not isinstance(value, dict) or any(
        not isinstance(key, str) for key in value
    ):
        raise SmokeFailure("CLI_OUTPUT_NOT_OBJECT")
    return cast(dict[str, object], value)


def _export_path(
    payload: Mapping[str, object], *, finding_id: str, data_dir: Path
) -> Path:
    value = payload.get("data", payload)
    if not isinstance(value, Mapping):
        raise SmokeFailure("REPORT_EXPORT_OUTPUT_INVALID")
    path_value = value.get("path")
    if value.get("finding_id") != finding_id or not isinstance(path_value, str):
        raise SmokeFailure("REPORT_EXPORT_OUTPUT_INVALID")
    relative = Path(path_value)
    if (
        relative.is_absolute()
        or not relative.parts
        or relative.parts[0] != "reports"
        or ".." in relative.parts
    ):
        raise SmokeFailure("REPORT_EXPORT_OUTPUT_INVALID")
    return data_dir / relative


def run_target(
    *,
    target: Target,
    profile: Path,
    data_dir: Path,
    timeout_seconds: int,
    execute: CommandExecutor = _run_json,
) -> dict[str, object]:
    """Execute one pinned repository and verify its persisted result closure."""

    evaluate = execute(
        _evaluate_command(target, profile, data_dir), timeout_seconds
    )
    evaluation_data = _data(evaluate, "evaluate analyze")
    analysis_id = evaluation_data.get("analysis_id")
    if not isinstance(analysis_id, str) or not analysis_id:
        raise SmokeFailure("EVALUATE_RESULT_INVALID")
    result = execute(
        _query_command(data_dir, "results", analysis_id, "--format", "json"),
        timeout_seconds,
    )
    reports = execute(
        _query_command(data_dir, "reports", analysis_id, "--format", "json"),
        timeout_seconds,
    )
    report_data = _data(reports, "reports")
    listed = report_data.get("reports")
    if not isinstance(listed, list):
        raise SmokeFailure("REPORT_LIST_INVALID")
    exported: dict[str, Path] = {}
    for item in listed:
        if not isinstance(item, Mapping) or not isinstance(
            item.get("finding_id"), str
        ):
            raise SmokeFailure("REPORT_SUMMARY_INVALID")
        finding_id = cast(str, item["finding_id"])
        export_payload = execute(
            _query_command(
                data_dir,
                "report",
                "export",
                finding_id,
                "--format",
                "markdown",
            ),
            timeout_seconds,
        )
        exported[finding_id] = _export_path(
            export_payload, finding_id=finding_id, data_dir=data_dir
        )
    return validate_run(
        target=target,
        evaluate=evaluate,
        result=result,
        reports=reports,
        exported_reports=exported,
        data_dir=data_dir,
    )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run pinned real repositories through LOCAL_EVALUATION."
    )
    parser.add_argument(
        "--profile",
        required=True,
        type=Path,
        help="explicit LOCAL_EVALUATION profile (normally under runtime-data)",
    )
    parser.add_argument(
        "--data-dir",
        required=True,
        type=Path,
        help="ignored local runtime root for records and exported reports",
    )
    parser.add_argument(
        "--target", choices=["pygoat", "itsdangerous", "all"], default="all"
    )
    parser.add_argument("--timeout-seconds", type=_positive_int, default=7200)
    parser.add_argument(
        "--print-plan",
        action="store_true",
        help="print exact fake-free CLI commands without executing them",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    profile = args.profile.resolve()
    data_dir = args.data_dir.resolve()
    selected = tuple(
        target
        for target in TARGETS
        if args.target == "all" or target.name == args.target
    )
    plan = {
        "schema_version": 1,
        "runs": [
            {
                "target": target.name,
                "repository": target.repository,
                "commit": target.commit,
                "command": _evaluate_command(target, profile, data_dir),
            }
            for target in selected
        ],
    }
    if args.print_plan:
        print(json.dumps(plan, sort_keys=True))
        return 0
    summaries: list[dict[str, object]] = []
    try:
        if not profile.is_file():
            raise SmokeFailure("LOCAL_EVALUATION_PROFILE_NOT_FOUND")
        data_dir.mkdir(parents=True, exist_ok=True)
        for target in selected:
            summary = run_target(
                target=target,
                profile=profile,
                data_dir=data_dir,
                timeout_seconds=args.timeout_seconds,
            )
            summary_dir = data_dir / "live-evaluation-smoke" / target.name
            summary_dir.mkdir(parents=True, exist_ok=True)
            (summary_dir / "summary.json").write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            summaries.append(summary)
    except SmokeFailure as error:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "failed",
                    "reason_code": str(error),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(
            {"schema_version": 1, "status": "passed", "runs": summaries},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
