"""Analyze an exact prebuilt CodeQL database and decode bounded SARIF evidence."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import time
from collections import Counter
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol, cast
from urllib.parse import unquote, urlsplit

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.ports.dto import (
    CancellationResult,
    CandidateError,
    CandidateFact,
    CandidateGap,
    CandidateLocation,
    CandidateRelation,
    CandidateRule,
    MonotonicActionDeadline,
    PrebuiltCodeQLDatabase,
    ProcessResult,
    ProcessSpec,
    StaticCapabilityObservation,
    StaticRuleMapping,
    StaticToolObservation,
    StaticToolRequest,
    TrackedFile,
)


class CodeQLProcessRunner(Protocol):
    async def run(self, spec: ProcessSpec) -> ProcessResult: ...

    async def cancel(self, attempt_id: str) -> CancellationResult: ...


class CodeQLRunnerFactory(Protocol):
    def __call__(
        self,
        *,
        action_id: str,
        attempt_id: str,
        workspace_root: Path,
        output_root: Path,
        executable: Path,
        output_limit_bytes: int,
    ) -> CodeQLProcessRunner: ...


@dataclass(frozen=True)
class CodeQLExecutionInputs:
    """Exact non-persisted inputs already resolved by the trusted coordinator."""

    database: PrebuiltCodeQLDatabase
    query_pack_root: Path
    query_pack_digest: str
    rule_catalog: tuple[StaticRuleMapping, ...]
    selected_rule_ids: tuple[str, ...]
    selected_rule_packs: tuple[str, ...]
    tracked_files: tuple[TrackedFile, ...]
    attempt_root: Path
    attempt_id: str

    def __post_init__(self) -> None:
        rule_ids = tuple(item.rule_id for item in self.rule_catalog)
        tracked = tuple(item.git_path for item in self.tracked_files)
        if (
            not self.rule_catalog
            or len(set(rule_ids)) != len(rule_ids)
            or len(set(self.selected_rule_ids)) != len(self.selected_rule_ids)
            or not set(self.selected_rule_ids).issubset(rule_ids)
            or len(set(tracked)) != len(tracked)
            or not self.selected_rule_packs
            or not self.query_pack_digest
            or not self.attempt_id
        ):
            raise ValueError("CODEQL_INPUT_CLOSURE_INVALID")
        for git_path in tracked:
            _safe_git_path(git_path)


def _link_like(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _assert_path_chain_safe(path: Path) -> None:
    candidate = path.absolute()
    for part in (candidate, *candidate.parents):
        if part.exists() and _link_like(part):
            raise ValueError("CODEQL_PATH_LINK_FORBIDDEN")


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_path(path: Path) -> str:
    """Hash one regular file or a symlink-free tree with stable relative names."""

    _assert_path_chain_safe(path)
    resolved = path.resolve(strict=True)
    if resolved.is_file():
        return _file_digest(resolved)
    if not resolved.is_dir():
        raise ValueError("CODEQL_INPUT_NOT_REGULAR")
    entries: list[tuple[str, int, str]] = []
    for candidate in sorted(resolved.rglob("*"), key=lambda item: item.as_posix()):
        if _link_like(candidate):
            raise ValueError("CODEQL_PATH_LINK_FORBIDDEN")
        if candidate.is_dir():
            continue
        info = candidate.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("CODEQL_INPUT_NOT_REGULAR")
        relative = candidate.relative_to(resolved).as_posix()
        entries.append((relative, info.st_size, _file_digest(candidate)))
    return hashlib.sha256(canonical_bytes(entries)).hexdigest()


def _safe_git_path(value: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise ValueError("CODEQL_LOCATION_UNSAFE")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("CODEQL_LOCATION_UNSAFE")
    return pure.as_posix()


def validate_codeql_command(
    argv: tuple[str, ...],
    executable: Path,
    database_root: Path,
    query_pack_root: Path,
    output_path: Path,
) -> None:
    """Allow only the two closed process families owned by this adapter."""

    version = (str(executable), "version", "--format=json")
    analyze = (
        str(executable),
        "database",
        "analyze",
        str(database_root),
        str(query_pack_root),
        "--format=sarifv2.1.0",
        f"--output={output_path}",
    )
    if argv not in {version, analyze}:
        raise ValueError("CODEQL_COMMAND_FORBIDDEN")


class _OutputBoundaryError(ValueError):
    pass


class _MalformedSarif(ValueError):
    pass


def _directory_size(root: Path, cap: int) -> int:
    _assert_path_chain_safe(root)
    if not root.is_dir():
        raise _OutputBoundaryError("CODEQL_OUTPUT_DIRECTORY_INVALID")
    total = 0
    with os.scandir(root) as entries:
        for entry in entries:
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                raise _OutputBoundaryError("CODEQL_OUTPUT_NOT_REGULAR")
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise _OutputBoundaryError("CODEQL_OUTPUT_NOT_REGULAR")
            total += info.st_size
            if total > cap:
                raise _OutputBoundaryError("CODEQL_ATTEMPT_OUTPUT_LIMIT")
    return total


def _read_bounded_regular(
    path: Path, root: Path, *, file_cap: int, read_cap: int
) -> bytes:
    _assert_path_chain_safe(path)
    resolved_root = root.resolve(strict=True)
    if (
        path.resolve(strict=True).parent != resolved_root
        or path.name != "codeql-result.sarif"
    ):
        raise _OutputBoundaryError("CODEQL_OUTPUT_ESCAPE")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > file_cap
            or before.st_size > read_cap
        ):
            raise _OutputBoundaryError("CODEQL_OUTPUT_LIMIT")
        data = os.read(descriptor, read_cap + 1)
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        identity_current = (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
        )
        if (
            len(data) != before.st_size
            or len(data) > read_cap
            or identity_before != identity_after
            or identity_before != identity_current
        ):
            raise _OutputBoundaryError("CODEQL_OUTPUT_CHANGED")
        return data
    finally:
        os.close(descriptor)


def _mapping_by_id(inputs: CodeQLExecutionInputs) -> Mapping[str, StaticRuleMapping]:
    return {item.rule_id: item for item in inputs.rule_catalog}


def _location(value: object, tracked: frozenset[str]) -> CandidateLocation:
    if not isinstance(value, dict):
        raise ValueError("CODEQL_LOCATION_UNRESOLVED")
    physical = value.get("physicalLocation")
    if not isinstance(physical, dict):
        raise ValueError("CODEQL_LOCATION_UNRESOLVED")
    artifact = physical.get("artifactLocation")
    region = physical.get("region")
    if not isinstance(artifact, dict) or not isinstance(region, dict):
        raise ValueError("CODEQL_LOCATION_UNRESOLVED")
    uri = artifact.get("uri")
    if not isinstance(uri, str):
        raise ValueError("CODEQL_LOCATION_UNRESOLVED")
    split = urlsplit(uri)
    if split.scheme or split.netloc or split.query or split.fragment:
        raise ValueError("CODEQL_LOCATION_UNSAFE")
    file_path = _safe_git_path(unquote(split.path))
    if file_path not in tracked:
        raise ValueError("CODEQL_LOCATION_FOREIGN")
    start_line = region.get("startLine")
    end_line = region.get("endLine", start_line)
    start_column = region.get("startColumn")
    end_column = region.get("endColumn")
    if (
        not isinstance(start_line, int)
        or isinstance(start_line, bool)
        or start_line <= 0
        or not isinstance(end_line, int)
        or isinstance(end_line, bool)
        or end_line < start_line
        or (start_column is None) != (end_column is None)
        or (
            start_column is not None
            and (
                not isinstance(start_column, int)
                or isinstance(start_column, bool)
                or start_column <= 0
                or not isinstance(end_column, int)
                or isinstance(end_column, bool)
                or end_column <= 0
                or (start_line == end_line and end_column <= start_column)
            )
        )
    ):
        raise ValueError("CODEQL_LOCATION_RANGE_INVALID")
    return CandidateLocation(file_path, start_line, start_column, end_line, end_column)


def _gap(
    code: str, reason: str, description: str, *, paths: tuple[str, ...] = ()
) -> CandidateGap:
    return CandidateGap(
        stage="STATIC_ANALYSIS",
        code=code,
        reason=reason,
        description=description,
        affected_paths=paths,
        affected_languages=(),
        affected_locations=(),
        retryable=False,
    )


def _error(code: str, message: str, *, retryable: bool = False) -> CandidateError:
    return CandidateError("STATIC_ANALYSIS", code, message, retryable)


def _rules(
    inputs: CodeQLExecutionInputs,
    metadata_ids: list[str],
    hit_counts: Counter[str],
) -> tuple[CandidateRule, ...]:
    metadata = Counter(metadata_ids)
    selected = set(inputs.selected_rule_ids)
    result: list[CandidateRule] = []
    for mapping in sorted(inputs.rule_catalog, key=lambda item: item.rule_id):
        if mapping.rule_id not in selected:
            result.append(
                CandidateRule(
                    mapping.rule_id,
                    "NOT_SELECTED",
                    "NOT_EXECUTED",
                    None,
                    "NOT_SELECTED",
                    None,
                )
            )
        elif metadata[mapping.rule_id] != 1:
            result.append(
                CandidateRule(
                    mapping.rule_id,
                    "SELECTED",
                    "UNKNOWN",
                    None,
                    "TELEMETRY_MISSING",
                    "CodeQL rule metadata was absent or ambiguous.",
                )
            )
        else:
            result.append(
                CandidateRule(
                    mapping.rule_id,
                    "SELECTED",
                    "EXECUTED",
                    hit_counts[mapping.rule_id],
                    None,
                    None,
                )
            )
    return tuple(result)


def _decode_sarif(
    raw: bytes,
    inputs: CodeQLExecutionInputs,
    expected_version: str,
    loader: Callable[[bytes], object],
) -> tuple[
    tuple[CandidateRule, ...],
    tuple[CandidateFact, ...],
    tuple[CandidateRelation, ...],
    tuple[CandidateGap, ...],
]:
    try:
        document = loader(raw)
        if not isinstance(document, dict) or document.get("version") != "2.1.0":
            raise _MalformedSarif
        runs = document.get("runs")
        if (
            not isinstance(runs, list)
            or len(runs) != 1
            or not isinstance(runs[0], dict)
        ):
            raise _MalformedSarif
        run = runs[0]
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        if (
            not isinstance(driver, dict)
            or driver.get("name") != "CodeQL"
            or driver.get("version") != expected_version
        ):
            raise _MalformedSarif
        metadata_raw = driver.get("rules")
        results_raw = run.get("results")
        if not isinstance(metadata_raw, list) or not isinstance(results_raw, list):
            raise _MalformedSarif
        metadata_ids: list[str] = []
        for item in metadata_raw:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                metadata_ids.append(cast(str, item["id"]))
        if len(metadata_ids) != len(metadata_raw):
            raise _MalformedSarif
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise _MalformedSarif("STATIC_OUTPUT_MALFORMED") from error

    catalog = _mapping_by_id(inputs)
    tracked = frozenset(item.git_path for item in inputs.tracked_files)
    hit_counts: Counter[str] = Counter()
    facts: list[CandidateFact] = []
    relations: list[CandidateRelation] = []
    gaps: list[CandidateGap] = []
    for result_index, result in enumerate(results_raw):
        if not isinstance(result, dict) or not isinstance(result.get("ruleId"), str):
            gaps.append(
                _gap(
                    "STATIC_RULE_TELEMETRY_MISSING",
                    "MISSING",
                    "A SARIF result did not identify one catalog rule.",
                )
            )
            continue
        rule_id = cast(str, result["ruleId"])
        mapping = catalog.get(rule_id)
        if mapping is None:
            gaps.append(
                _gap(
                    "STATIC_RULE_TELEMETRY_MISSING",
                    "UNSUPPORTED",
                    "A SARIF result referenced a rule outside the exact catalog.",
                )
            )
            continue
        hit_counts[rule_id] += 1
        result_location: CandidateLocation | None = None
        locations = result.get("locations")
        if isinstance(locations, list) and locations:
            try:
                result_location = _location(locations[0], tracked)
            except ValueError:
                gaps.append(
                    _gap(
                        "STATIC_LOCATION_UNRESOLVED",
                        "UNSUPPORTED",
                        "A CodeQL result location was unsafe or outside the manifest.",
                    )
                )
        flow_first: CandidateLocation | None = None
        flow_last: CandidateLocation | None = None
        valid_required_flow = False
        flow_issue = False
        code_flows = result.get("codeFlows")
        if mapping.requires_code_flow:
            if isinstance(code_flows, list):
                for flow_index, code_flow in enumerate(code_flows):
                    thread_flows = (
                        code_flow.get("threadFlows")
                        if isinstance(code_flow, dict)
                        else None
                    )
                    if not isinstance(thread_flows, list):
                        flow_issue = True
                        continue
                    for thread_index, thread_flow in enumerate(thread_flows):
                        raw_locations = (
                            thread_flow.get("locations")
                            if isinstance(thread_flow, dict)
                            else None
                        )
                        if not isinstance(raw_locations, list):
                            flow_issue = True
                            continue
                        try:
                            decoded = tuple(
                                _location(item, tracked) for item in raw_locations
                            )
                        except ValueError:
                            flow_issue = True
                            continue
                        distinct: list[CandidateLocation] = []
                        for item in decoded:
                            if not distinct or item != distinct[-1]:
                                distinct.append(item)
                        if len(distinct) < 2:
                            flow_issue = True
                            continue
                        valid_required_flow = True
                        flow_first = flow_first or distinct[0]
                        flow_last = distinct[-1]
                        for edge_index, (earlier, later) in enumerate(
                            zip(distinct, distinct[1:], strict=False)
                        ):
                            relations.append(
                                CandidateRelation(
                                    source_key=(
                                        f"codeql:{rule_id}:result:{result_index}:"
                                        f"flow:{flow_index}:{thread_index}:edge:{edge_index}"
                                    ),
                                    relation_kind="DATA_FLOW",
                                    from_symbol_source_key=None,
                                    from_location=earlier,
                                    to_symbol_source_key=None,
                                    to_location=later,
                                    rule_id=rule_id,
                                )
                            )
            if not valid_required_flow or flow_issue:
                gaps.append(
                    _gap(
                        "STATIC_DATA_FLOW_UNRESOLVED",
                        "MISSING" if not code_flows else "UNSUPPORTED",
                        "The required CodeQL flow was absent or contained "
                        "an unsafe step.",
                    )
                )
        endpoint = result_location or flow_last
        if endpoint is not None:
            facts.append(
                CandidateFact(
                    f"codeql:{rule_id}:result:{result_index}:endpoint",
                    mapping.result_fact_kind,
                    None,
                    endpoint,
                    rule_id,
                )
            )
        if mapping.flow_start_fact_kind is not None and flow_first is not None:
            facts.append(
                CandidateFact(
                    f"codeql:{rule_id}:result:{result_index}:flow-start",
                    mapping.flow_start_fact_kind,
                    None,
                    flow_first,
                    rule_id,
                )
            )
    return (
        _rules(inputs, metadata_ids, hit_counts),
        tuple(facts),
        tuple(relations),
        tuple(gaps),
    )


class CodeQLProcessAdapter:
    """Lower CodeQL adapter; it cannot build databases or publish records."""

    def __init__(
        self,
        *,
        executable: Path,
        executable_key: str,
        inputs: CodeQLExecutionInputs,
        runner_factory: CodeQLRunnerFactory,
        sarif_loader: Callable[[bytes], object] = json.loads,
        monotonic_ms: Callable[[], int] = lambda: time.monotonic_ns() // 1_000_000,
        quota_poll_seconds: float = 0.01,
    ) -> None:
        self.executable = executable
        self.executable_key = executable_key
        self.inputs = inputs
        self.runner_factory = runner_factory
        self.sarif_loader = sarif_loader
        self.monotonic_ms = monotonic_ms
        self.quota_poll_seconds = quota_poll_seconds
        self._active: dict[str, CodeQLProcessRunner] = {}

    def _profile_error(self, profile: StaticToolProfile) -> str | None:
        if (
            profile.status != "APPROVED"
            or profile.purpose not in {"FIXTURE", "EVALUATION"}
            or profile.adapter_key != "CODEQL"
            or profile.tool_name != "CODEQL"
            or profile.tool_kind != "RULE_BASED"
            or profile.executable_key != self.executable_key
        ):
            return "CODEQL_PROFILE_MISMATCH"
        try:
            _assert_path_chain_safe(self.executable)
            if (
                not self.executable.is_absolute()
                or not self.executable.is_file()
                or _link_like(self.executable)
                or _file_digest(self.executable) != profile.executable_sha256
            ):
                return "CODEQL_EXECUTABLE_MISMATCH"
        except (OSError, ValueError):
            return "CODEQL_EXECUTABLE_UNAVAILABLE"
        return None

    def _capability(
        self,
        profile: StaticToolProfile,
        *,
        available: bool,
        version: str | None,
        reason: str | None,
    ) -> StaticCapabilityObservation:
        return StaticCapabilityObservation(
            available=available,
            tool_name="CODEQL",
            tool_kind="RULE_BASED",
            executable_key=self.executable_key,
            observed_executable_sha256=(
                _file_digest(self.executable) if self.executable.is_file() else None
            ),
            observed_version=version,
            expected_version=profile.expected_version,
            reason_code=reason,
        )

    def _make_runner(
        self,
        *,
        action_id: str,
        attempt_id: str,
        cwd: Path,
        output: Path,
        profile: StaticToolProfile,
    ) -> CodeQLProcessRunner:
        runner = self.runner_factory(
            action_id=action_id,
            attempt_id=attempt_id,
            workspace_root=cwd,
            output_root=output,
            executable=self.executable,
            output_limit_bytes=profile.max_attempt_output_bytes,
        )
        self._active[attempt_id] = runner
        return runner

    def _spec(
        self,
        *,
        action_id: str,
        attempt_id: str,
        argv: tuple[str, ...],
        cwd: Path,
        output: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
        suffix: str,
    ) -> ProcessSpec:
        if deadline.action_id != action_id:
            raise ValueError("CODEQL_ACTION_DEADLINE_MISMATCH")
        return ProcessSpec(
            invocation_id=f"{action_id}:codeql:{suffix}",
            attempt_id=attempt_id,
            argv=argv,
            cwd=cwd,
            env=(),
            attempt_output_dir=output,
            stdout_limit_bytes=profile.stdout_limit_bytes,
            stderr_limit_bytes=profile.stderr_limit_bytes,
            attempt_output_limit_bytes=profile.max_attempt_output_bytes,
            deadline=deadline,
        )

    async def probe(
        self, profile: StaticToolProfile, deadline: MonotonicActionDeadline
    ) -> StaticCapabilityObservation:
        error = self._profile_error(profile)
        if error is not None:
            return self._capability(
                profile, available=False, version=None, reason=error
            )
        output = self.inputs.attempt_root / "codeql-probe"
        cwd = self.inputs.attempt_root / "codeql-probe-cwd"
        try:
            _assert_path_chain_safe(self.inputs.attempt_root)
            output.mkdir(mode=0o700)
            cwd.mkdir(mode=0o700)
        except (OSError, ValueError):
            return self._capability(
                profile,
                available=False,
                version=None,
                reason="CODEQL_PROBE_ROOT_INVALID",
            )
        attempt_id = "codeql-probe"
        runner = self._make_runner(
            action_id=deadline.action_id,
            attempt_id=attempt_id,
            cwd=cwd,
            output=output,
            profile=profile,
        )
        argv = (str(self.executable), "version", "--format=json")
        validate_codeql_command(
            argv,
            self.executable,
            self.inputs.database.database_root,
            self.inputs.query_pack_root,
            output / "codeql-result.sarif",
        )
        try:
            result = await runner.run(
                self._spec(
                    action_id=deadline.action_id,
                    attempt_id=attempt_id,
                    argv=argv,
                    cwd=cwd,
                    output=output,
                    profile=profile,
                    deadline=deadline,
                    suffix="version",
                )
            )
        finally:
            self._active.pop(attempt_id, None)
        if result.outcome != "SUCCEEDED" or result.return_code != 0:
            return self._capability(
                profile, available=False, version=None, reason="CODEQL_PROBE_FAILED"
            )
        try:
            value = json.loads(result.stdout)
            version = value.get("version") if isinstance(value, dict) else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            version = None
        if version != profile.expected_version:
            return self._capability(
                profile,
                available=False,
                version=version if isinstance(version, str) else None,
                reason="CODEQL_VERSION_MISMATCH",
            )
        return self._capability(profile, available=True, version=version, reason=None)

    def _empty_rules(self, reason: str) -> tuple[CandidateRule, ...]:
        selected = set(self.inputs.selected_rule_ids)
        return tuple(
            CandidateRule(
                item.rule_id,
                "SELECTED" if item.rule_id in selected else "NOT_SELECTED",
                "NOT_EXECUTED",
                None,
                reason if item.rule_id in selected else "NOT_SELECTED",
                None,
            )
            for item in sorted(
                self.inputs.rule_catalog, key=lambda value: value.rule_id
            )
        )

    def _observation(
        self,
        profile: StaticToolProfile,
        *,
        status: str,
        started: int,
        raw: bytes | None = None,
        rules: tuple[CandidateRule, ...] | None = None,
        facts: tuple[CandidateFact, ...] = (),
        relations: tuple[CandidateRelation, ...] = (),
        gaps: tuple[CandidateGap, ...] = (),
        errors: tuple[CandidateError, ...] = (),
    ) -> StaticToolObservation:
        return StaticToolObservation(
            tool_name="CODEQL",
            tool_version=profile.expected_version,
            tool_kind="RULE_BASED",
            status=status,  # type: ignore[arg-type]
            raw_output=raw,
            raw_media_type="application/sarif+json" if raw is not None else None,
            analyzed_paths=(
                tuple(sorted(item.git_path for item in self.inputs.tracked_files))
                if status in {"SUCCEEDED", "PARTIAL"}
                else ()
            ),
            skipped_paths=(),
            analyzed_languages=(self.inputs.database.language,)
            if status in {"SUCCEEDED", "PARTIAL"}
            else (),
            skipped_languages=(),
            notes=("Analyze-only prebuilt CodeQL database; no build or autobuild.",),
            selected_rule_packs=self.inputs.selected_rule_packs,
            rules=rules if rules is not None else self._empty_rules("TOOL_FAILURE"),
            symbols=(),
            facts=facts,
            relations=relations,
            gaps=gaps,
            errors=errors,
            started_monotonic_ms=started,
            finished_monotonic_ms=self.monotonic_ms(),
        )

    def _preflight(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
    ) -> tuple[str, str] | None:
        profile_error = self._profile_error(profile)
        if profile_error is not None:
            return "FAILED", profile_error
        workspace = request.workspace
        database = self.inputs.database
        if (
            request.action.action_type != "RUN_TOOL"
            or request.action.tool_name != "CODEQL"
        ):
            return "FAILED", "CODEQL_REQUEST_MISMATCH"
        if workspace.status != "READY" or workspace.commit_id is None:
            return "SKIPPED", "CODEQL_WORKSPACE_NOT_READY"
        if (
            not workspace_root.is_absolute()
            or not self.inputs.attempt_root.is_absolute()
            or not database.database_root.is_absolute()
            or not self.inputs.query_pack_root.is_absolute()
            or str(workspace.workspace_id) != database.workspace_id
            or str(workspace.commit_id) != database.commit_id
        ):
            return "SKIPPED", "CODEQL_DATABASE_SCOPE_MISMATCH"
        try:
            _assert_path_chain_safe(workspace_root)
            _assert_path_chain_safe(self.inputs.attempt_root)
            if (
                not workspace_root.resolve(strict=True).is_dir()
                or not self.inputs.attempt_root.resolve(strict=True).is_dir()
                or _inside(
                    self.inputs.attempt_root.resolve(strict=True),
                    workspace_root.resolve(strict=True),
                )
            ):
                return "FAILED", "CODEQL_OUTPUT_ROOT_INVALID"
            if digest_path(database.database_root) != database.database_digest:
                return "FAILED", "CODEQL_DATABASE_DIGEST_MISMATCH"
            if (
                digest_path(self.inputs.query_pack_root)
                != self.inputs.query_pack_digest
            ):
                return "FAILED", "CODEQL_QUERY_PACK_DIGEST_MISMATCH"
        except (OSError, ValueError):
            return "FAILED", "CODEQL_INPUT_INTEGRITY_FAILED"
        return None

    async def _watch_quota(
        self, root: Path, cap: int, process_done: asyncio.Event
    ) -> bool:
        while not process_done.is_set():
            try:
                _directory_size(root, cap)
            except (OSError, ValueError):
                return True
            await asyncio.sleep(self.quota_poll_seconds)
        return False

    async def execute(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticToolObservation:
        started = self.monotonic_ms()
        preflight = self._preflight(request, workspace_root, profile)
        if preflight is not None:
            status, code = preflight
            gap_reason = "UNSUPPORTED" if status == "SKIPPED" else "FAILED"
            return self._observation(
                profile,
                status=status,
                started=started,
                rules=self._empty_rules(
                    "UNSUPPORTED" if status == "SKIPPED" else "TOOL_FAILURE"
                ),
                gaps=(_gap(code, gap_reason, "CodeQL input preflight failed."),),
                errors=()
                if status == "SKIPPED"
                else (_error(code, "CodeQL input integrity failed."),),
            )
        action_id = str(request.action.action_id)
        attempt_id = self.inputs.attempt_id
        if deadline.action_id != action_id:
            raise ValueError("CODEQL_ACTION_DEADLINE_MISMATCH")
        output = self.inputs.attempt_root / "codeql-run"
        try:
            output.mkdir(mode=0o700)
            _assert_path_chain_safe(output)
        except (OSError, ValueError):
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                gaps=(
                    _gap(
                        "STATIC_OUTPUT_LIMIT",
                        "TRUNCATED",
                        "CodeQL output root was unsafe.",
                    ),
                ),
                errors=(
                    _error("STATIC_OUTPUT_LIMIT", "CodeQL output root was unsafe."),
                ),
            )
        sarif_path = output / "codeql-result.sarif"
        if sarif_path.exists() or _link_like(sarif_path):
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                gaps=(
                    _gap(
                        "STATIC_OUTPUT_LIMIT",
                        "TRUNCATED",
                        "CodeQL output already existed.",
                    ),
                ),
                errors=(
                    _error("STATIC_OUTPUT_LIMIT", "CodeQL output already existed."),
                ),
            )
        runner = self._make_runner(
            action_id=action_id,
            attempt_id=attempt_id,
            cwd=workspace_root,
            output=output,
            profile=profile,
        )
        version_argv = (str(self.executable), "version", "--format=json")
        validate_codeql_command(
            version_argv,
            self.executable,
            self.inputs.database.database_root,
            self.inputs.query_pack_root,
            sarif_path,
        )
        version_result = await runner.run(
            self._spec(
                action_id=action_id,
                attempt_id=attempt_id,
                argv=version_argv,
                cwd=workspace_root,
                output=output,
                profile=profile,
                deadline=deadline,
                suffix="version",
            )
        )
        try:
            version_value = json.loads(version_result.stdout)
            observed_version = (
                version_value.get("version")
                if isinstance(version_value, dict)
                else None
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            observed_version = None
        if (
            version_result.outcome != "SUCCEEDED"
            or version_result.return_code != 0
            or observed_version != profile.expected_version
        ):
            self._active.pop(attempt_id, None)
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                gaps=(
                    _gap(
                        "STATIC_TOOL_VERSION",
                        "FAILED",
                        "CodeQL version verification failed.",
                    ),
                ),
                errors=(
                    _error(
                        "STATIC_TOOL_VERSION", "CodeQL version verification failed."
                    ),
                ),
            )
        argv = (
            str(self.executable),
            "database",
            "analyze",
            str(self.inputs.database.database_root),
            str(self.inputs.query_pack_root),
            "--format=sarifv2.1.0",
            f"--output={sarif_path}",
        )
        validate_codeql_command(
            argv,
            self.executable,
            self.inputs.database.database_root,
            self.inputs.query_pack_root,
            sarif_path,
        )
        spec = self._spec(
            action_id=action_id,
            attempt_id=attempt_id,
            argv=argv,
            cwd=workspace_root,
            output=output,
            profile=profile,
            deadline=deadline,
            suffix="analyze",
        )
        done = asyncio.Event()
        process_task = asyncio.create_task(runner.run(spec))
        watcher = asyncio.create_task(
            self._watch_quota(output, profile.max_attempt_output_bytes, done)
        )
        quota_exceeded = False
        try:
            completed, _ = await asyncio.wait(
                (process_task, watcher), return_when=asyncio.FIRST_COMPLETED
            )
            if watcher in completed and watcher.result():
                quota_exceeded = True
                await runner.cancel(attempt_id)
            result = await process_task
        finally:
            done.set()
            watcher.cancel()
            with suppress(asyncio.CancelledError):
                await watcher
            self._active.pop(attempt_id, None)
        if quota_exceeded:
            return self._output_failure(profile, started)
        if result.outcome == "CANCELLED":
            return self._observation(
                profile,
                status="SKIPPED",
                started=started,
                rules=self._empty_rules("CANCELLED"),
                gaps=(
                    _gap("STATIC_TOOL_CANCELLED", "BLOCKED", "CodeQL was cancelled."),
                ),
            )
        if result.outcome == "TIMED_OUT":
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                gaps=(_gap("STATIC_TOOL_TIMEOUT", "TIMEOUT", "CodeQL timed out."),),
                errors=(
                    _error("STATIC_TOOL_TIMEOUT", "CodeQL timed out.", retryable=True),
                ),
            )
        try:
            _directory_size(output, profile.max_attempt_output_bytes)
            raw = _read_bounded_regular(
                sarif_path,
                output,
                file_cap=profile.max_output_file_bytes,
                read_cap=profile.max_artifact_read_bytes,
            )
        except (OSError, ValueError):
            return self._output_failure(profile, started)
        if result.outcome != "SUCCEEDED" or result.return_code != 0:
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                raw=raw,
                gaps=(
                    _gap(
                        "STATIC_TOOL_FAILED",
                        "FAILED",
                        "CodeQL returned a nonzero exit.",
                    ),
                ),
                errors=(
                    _error("STATIC_TOOL_FAILED", "CodeQL returned a nonzero exit."),
                ),
            )
        try:
            rules, facts, relations, gaps = _decode_sarif(
                raw, self.inputs, profile.expected_version, self.sarif_loader
            )
        except _MalformedSarif:
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                raw=raw,
                gaps=(
                    _gap(
                        "STATIC_OUTPUT_MALFORMED",
                        "FAILED",
                        "CodeQL SARIF was malformed.",
                    ),
                ),
                errors=(
                    _error("STATIC_OUTPUT_MALFORMED", "CodeQL SARIF was malformed."),
                ),
            )
        return self._observation(
            profile,
            status="PARTIAL" if gaps else "SUCCEEDED",
            started=started,
            raw=raw,
            rules=rules,
            facts=facts,
            relations=relations,
            gaps=gaps,
        )

    def _output_failure(
        self, profile: StaticToolProfile, started: int
    ) -> StaticToolObservation:
        return self._observation(
            profile,
            status="FAILED",
            started=started,
            gaps=(
                _gap(
                    "STATIC_OUTPUT_LIMIT",
                    "TRUNCATED",
                    "CodeQL output was unsafe or over limit.",
                ),
            ),
            errors=(
                _error(
                    "STATIC_OUTPUT_LIMIT", "CodeQL output was unsafe or over limit."
                ),
            ),
        )

    async def cancel(self, attempt_id: str) -> CancellationResult:
        runner = self._active.get(attempt_id)
        if runner is None:
            return CancellationResult(False, "Attempt is not active")
        return await runner.cancel(attempt_id)
