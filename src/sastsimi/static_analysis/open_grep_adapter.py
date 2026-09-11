"""Run OpenGrep over an exact safe manifest and retain non-verdict evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference, require_record_ref
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.ports.dto import (
    CancellationResult,
    CandidateError,
    CandidateFact,
    CandidateGap,
    CandidateLocation,
    CandidateRule,
    MonotonicActionDeadline,
    ProcessResult,
    ProcessSpec,
    StaticCapabilityObservation,
    StaticRuleMapping,
    StaticToolObservation,
    StaticToolRequest,
    TrackedFile,
)
from sastsimi.static_analysis.normalizer import StaticRawReplayInput

_WINDOWS_COMMAND_LIMIT_BYTES = 32_767 * 2
_POSIX_SAFETY_MARGIN_BYTES = 8_192
_POINTER_BYTES = 8
_REGULAR_GIT_MODES = frozenset({"100644", "100755"})


class _WindowsFunction(Protocol):
    argtypes: list[object]
    restype: object

    def __call__(self, *args: object) -> int | None: ...


class _Kernel32(Protocol):
    CreateFileW: _WindowsFunction
    CloseHandle: _WindowsFunction


def _platform_attribute(owner: object, name: str) -> object:
    return getattr(owner, name)


class OpenGrepProcessRunner(Protocol):
    async def run(self, spec: ProcessSpec) -> ProcessResult: ...

    async def cancel(self, attempt_id: str) -> CancellationResult: ...


class OpenGrepRunnerFactory(Protocol):
    def __call__(
        self,
        *,
        action_id: str,
        attempt_id: str,
        workspace_root: Path,
        output_root: Path,
        executable: Path,
        output_limit_bytes: int,
    ) -> OpenGrepProcessRunner: ...


@dataclass(frozen=True)
class OpenGrepExecutionInputs:
    """Exact non-persisted configuration already resolved by trusted composition."""

    config_path: Path
    config_digest: str
    analysis_config_ref: StoredDataRef
    rule_catalog_ref: StoredDataRef
    rule_catalog: tuple[StaticRuleMapping, ...]
    selected_rule_ids: tuple[str, ...]
    selected_rule_packs: tuple[str, ...]
    tracked_files: tuple[TrackedFile, ...]
    attempt_root: Path
    attempt_id: str

    def __post_init__(self) -> None:
        catalog_ids = tuple(item.rule_id for item in self.rule_catalog)
        tracked_paths = tuple(item.git_path for item in self.tracked_files)
        try:
            require_record_ref(self.analysis_config_ref, "analysis_config")
            require_record_ref(self.rule_catalog_ref, "rule_catalog")
        except ValueError as error:
            raise ValueError("OPENGREP_INPUT_CLOSURE_INVALID") from error
        if (
            not self.config_path.is_absolute()
            or not self.attempt_root.is_absolute()
            or not self.config_digest
            or not self.attempt_id
            or not self.rule_catalog
            or not self.selected_rule_ids
            or len(set(catalog_ids)) != len(catalog_ids)
            or len(set(self.selected_rule_ids)) != len(self.selected_rule_ids)
            or not set(self.selected_rule_ids).issubset(catalog_ids)
            or len(set(self.selected_rule_packs)) != len(self.selected_rule_packs)
            or len(set(tracked_paths)) != len(tracked_paths)
        ):
            raise ValueError("OPENGREP_INPUT_CLOSURE_INVALID")
        for item in self.tracked_files:
            _safe_git_path(item.git_path)


@dataclass(frozen=True)
class _BoundFile:
    git_path: str
    absolute_path: Path
    size: int
    device: int
    inode: int
    modified_ns: int
    digest: str


@dataclass(frozen=True)
class _FileIdentity:
    path: Path
    size: int
    device: int
    inode: int
    modified_ns: int
    digest: str


_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _safe_regular(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and not (
            int(getattr(info, "st_file_attributes", 0)) & _FILE_ATTRIBUTE_REPARSE_POINT
        )
        and int(getattr(info, "st_reparse_tag", 0)) == 0
    )


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        int(getattr(info, "st_file_attributes", 0)),
        int(getattr(info, "st_reparse_tag", 0)),
    )


def _open_read_descriptor(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if os.name != "nt":
        flags |= getattr(os, "O_NOFOLLOW", 0)
        return os.open(path, flags)

    import ctypes
    import msvcrt

    load_library = cast(Callable[..., object], _platform_attribute(ctypes, "WinDLL"))
    kernel32 = cast(_Kernel32, load_library("kernel32", use_last_error=True))
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    handle = create_file(
        str(path),
        0x80000000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x00000080 | 0x00200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle is None or handle == invalid_handle:
        get_last_error = cast(
            Callable[[], int], _platform_attribute(ctypes, "get_last_error")
        )
        error = get_last_error()
        raise OSError(error, "OPENGREP_INPUT_OPEN_FAILED", str(path))
    try:
        open_osfhandle = cast(
            Callable[[int, int], int],
            _platform_attribute(msvcrt, "open_osfhandle"),
        )
        return open_osfhandle(int(handle), flags)
    except BaseException:
        close_handle(handle)
        raise


@dataclass(frozen=True)
class _DecodedBatch:
    paths: tuple[str, ...]
    raw: bytes
    unknown_rules: frozenset[str]
    hit_counts: Counter[str]
    facts: tuple[CandidateFact, ...]
    gaps: tuple[CandidateGap, ...]


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
        if _link_like(part):
            raise ValueError("OPENGREP_PATH_LINK_FORBIDDEN")


def _safe_git_path(value: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise ValueError("OPENGREP_PATH_UNSAFE")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("OPENGREP_PATH_UNSAFE")
    return pure.as_posix()


def _read_regular(
    path: Path, *, max_bytes: int | None = None
) -> tuple[bytes, os.stat_result]:
    _assert_path_chain_safe(path)
    before = path.stat(follow_symlinks=False)
    if not _safe_regular(before) or _link_like(path):
        raise ValueError("OPENGREP_INPUT_NOT_REGULAR")
    if max_bytes is not None and before.st_size > max_bytes:
        raise ValueError("OPENGREP_INPUT_TOO_LARGE")
    descriptor = _open_read_descriptor(path)
    try:
        opened = os.fstat(descriptor)
        if not _safe_regular(opened) or _stat_identity(opened) != _stat_identity(
            before
        ):
            raise ValueError("OPENGREP_INPUT_CHANGED")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise ValueError("OPENGREP_INPUT_TOO_LARGE")
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    after = path.stat(follow_symlinks=False)
    if (
        not _safe_regular(after)
        or _stat_identity(after) != _stat_identity(opened)
        or _link_like(path)
    ):
        raise ValueError("OPENGREP_INPUT_CHANGED")
    return b"".join(chunks), after


def _file_identity(path: Path, *, max_bytes: int | None = None) -> _FileIdentity:
    data, info = _read_regular(path, max_bytes=max_bytes)
    return _FileIdentity(
        path=path.resolve(strict=True),
        size=info.st_size,
        device=info.st_dev,
        inode=info.st_ino,
        modified_ns=info.st_mtime_ns,
        digest=hashlib.sha256(data).hexdigest(),
    )


def _assert_identity(
    identity: _FileIdentity,
    expected_digest: str,
    *,
    max_bytes: int | None = None,
) -> None:
    current = _file_identity(identity.path, max_bytes=max_bytes)
    if current != identity or current.digest != expected_digest:
        raise ValueError("OPENGREP_INPUT_CHANGED")


def encoded_command_cost(
    argv: tuple[str, ...],
    env: tuple[tuple[str, str], ...],
    *,
    platform: Literal["win32", "posix"] | str,
) -> int:
    """Return the bytes consumed by the exact shell-free process boundary."""

    if platform == "win32":
        return len(subprocess.list2cmdline(list(argv)).encode("utf-16-le")) + 2
    strings = (*argv, *(f"{key}={value}" for key, value in env))
    payload = sum(len(value.encode()) + 1 for value in strings)
    return payload + (len(strings) + 2) * _POINTER_BYTES


def _production_command_limit(platform: str) -> int:
    if platform == "win32":
        return _WINDOWS_COMMAND_LIMIT_BYTES
    try:
        sysconf = cast(Callable[[str], int], _platform_attribute(os, "sysconf"))
        arg_max = int(sysconf("SC_ARG_MAX"))
    except (AttributeError, OSError, TypeError, ValueError):
        arg_max = 131_072
    return max(1, arg_max - _POSIX_SAFETY_MARGIN_BYTES)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _gap(
    code: str,
    reason: str,
    description: str,
    *,
    paths: tuple[str, ...] = (),
) -> CandidateGap:
    return CandidateGap(
        "STATIC_ANALYSIS",
        code,
        reason,
        description,
        paths,
        (),
        (),
        False,
    )


def _error(code: str, message: str, *, retryable: bool = False) -> CandidateError:
    return CandidateError("STATIC_ANALYSIS", code, message, retryable)


def _location(value: object, allowed_paths: frozenset[str]) -> CandidateLocation:
    if not isinstance(value, dict):
        raise ValueError("OPENGREP_RESULT_MALFORMED")
    path = value.get("path")
    start = value.get("start")
    end = value.get("end")
    if (
        not isinstance(path, str)
        or not isinstance(start, dict)
        or not isinstance(end, dict)
    ):
        raise ValueError("OPENGREP_RESULT_MALFORMED")
    path = _safe_git_path(path)
    if path not in allowed_paths:
        raise ValueError("OPENGREP_RESULT_FOREIGN_PATH")
    start_line, start_column = start.get("line"), start.get("col")
    end_line, end_column = end.get("line"), end.get("col")
    values = (start_line, start_column, end_line, end_column)
    if (
        any(
            not isinstance(item, int) or isinstance(item, bool) or item <= 0
            for item in values
        )
        or cast(int, end_line) < cast(int, start_line)
        or (end_line == start_line and cast(int, end_column) <= cast(int, start_column))
    ):
        raise ValueError("OPENGREP_RESULT_RANGE_INVALID")
    return CandidateLocation(
        path,
        cast(int, start_line),
        cast(int, start_column),
        cast(int, end_line),
        cast(int, end_column),
    )


def _telemetry_unknown(
    value: object, selected: frozenset[str], catalog: frozenset[str]
) -> frozenset[str]:
    if not isinstance(value, list):
        return selected
    identifiers: list[str] = []
    malformed = False
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            malformed = True
            continue
        identifiers.append(cast(str, item["id"]))
    counts = Counter(identifiers)
    if malformed or any(identifier not in selected for identifier in identifiers):
        return selected
    if any(identifier not in catalog for identifier in identifiers):
        return selected
    return frozenset(identifier for identifier in selected if counts[identifier] != 1)


def _decode_batch(
    raw: bytes,
    paths: tuple[str, ...],
    rule_catalog: tuple[StaticRuleMapping, ...],
    selected_rule_ids: tuple[str, ...],
    expected_version: str,
) -> _DecodedBatch:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("OPENGREP_OUTPUT_MALFORMED") from error
    if not isinstance(value, dict):
        raise ValueError("OPENGREP_OUTPUT_MALFORMED")
    results = value.get("results")
    errors = value.get("errors")
    path_info = value.get("paths")
    timing = value.get("time")
    if (
        not isinstance(results, list)
        or not isinstance(errors, list)
        or not isinstance(path_info, dict)
        or not isinstance(timing, dict)
        or value.get("version") != expected_version
    ):
        raise ValueError("OPENGREP_OUTPUT_MALFORMED")
    scanned = path_info.get("scanned")
    skipped = path_info.get("skipped")
    if (
        not isinstance(scanned, list)
        or not all(isinstance(item, str) for item in scanned)
        or len(set(scanned)) != len(scanned)
        or set(scanned) != set(paths)
        or not isinstance(skipped, list)
        or skipped
    ):
        raise ValueError("OPENGREP_OUTPUT_SCOPE_MISMATCH")
    selected = frozenset(selected_rule_ids)
    catalog = frozenset(item.rule_id for item in rule_catalog)
    unknown = _telemetry_unknown(timing.get("rules"), selected, catalog)
    mapping = {item.rule_id: item for item in rule_catalog}
    hits: Counter[str] = Counter()
    facts: list[CandidateFact] = []
    gaps: list[CandidateGap] = []
    for index, item in enumerate(results):
        if not isinstance(item, dict) or not isinstance(item.get("check_id"), str):
            unknown = selected
            gaps.append(
                _gap(
                    "STATIC_RESULT_MALFORMED",
                    "MISSING",
                    "An OpenGrep result was malformed and was not normalized.",
                    paths=paths,
                )
            )
            continue
        rule_id = cast(str, item["check_id"])
        if rule_id not in selected or rule_id not in mapping:
            unknown = selected
            gaps.append(
                _gap(
                    "STATIC_RULE_TELEMETRY_MISSING",
                    "MISSING",
                    "OpenGrep returned an unselected or unknown rule.",
                    paths=paths,
                )
            )
            continue
        hits[rule_id] += 1
        try:
            location = _location(item, frozenset(paths))
        except ValueError:
            gaps.append(
                _gap(
                    "STATIC_RESULT_LOCATION_INVALID",
                    "MISSING",
                    "An OpenGrep location was outside the authorized batch.",
                    paths=paths,
                )
            )
            continue
        if rule_id not in unknown:
            facts.append(
                CandidateFact(
                    source_key=f"opengrep:{_digest(raw)}:{index}",
                    fact_kind=mapping[rule_id].result_fact_kind,
                    symbol_source_key=None,
                    location=location,
                    rule_id=rule_id,
                )
            )
    if unknown:
        gaps.append(
            _gap(
                "STATIC_RULE_TELEMETRY_MISSING",
                "MISSING",
                "OpenGrep rule execution telemetry was absent or ambiguous.",
                paths=paths,
            )
        )
    if errors:
        gaps.append(
            _gap(
                "STATIC_TOOL_REPORTED_ERROR",
                "FAILED",
                "OpenGrep reported one or more bounded tool errors.",
                paths=paths,
            )
        )
    return _DecodedBatch(
        paths,
        raw,
        unknown,
        hits,
        tuple(facts),
        tuple(gaps),
    )


def replay_opengrep_raw(
    raw: bytes, replay: StaticRawReplayInput
) -> StaticToolObservation:
    """Purely decode a verified OpenGrep envelope and its exact rule context."""

    result, profile, execution = (
        replay.result,
        replay.profile,
        replay.rule_execution,
    )
    raw_ref = result.raw_result_ref
    mapping_ids = tuple(item.rule_id for item in replay.rule_mappings)
    rule_ids = tuple(item.rule_id for item in execution.rules) if execution else ()
    authorized = tuple(replay.authorized_paths)
    if (
        execution is None
        or profile.status != "APPROVED"
        or profile.purpose not in {"FIXTURE", "EVALUATION"}
        or (profile.adapter_key, profile.tool_name, profile.tool_kind)
        != ("OPENGREP", "OPENGREP", "RULE_BASED")
        or (result.tool_name, result.tool_version, result.tool_kind)
        != ("OPENGREP", profile.expected_version, "RULE_BASED")
        or result.status not in {"SUCCEEDED", "PARTIAL"}
        or raw_ref is None
        or hashlib.sha256(raw).hexdigest() != raw_ref.content_hash
        or result.rule_execution_ref != reference(execution)
        or (execution.tool_name, execution.tool_version)
        != (result.tool_name, result.tool_version)
        or len(mapping_ids) != len(set(mapping_ids))
        or set(mapping_ids) != set(rule_ids)
        or len(authorized) != len(set(authorized))
        or set(result.coverage.analyzed_paths).intersection(
            result.coverage.skipped_paths
        )
        or set(result.coverage.analyzed_paths).union(result.coverage.skipped_paths)
        != set(authorized)
    ):
        raise ValueError("STATIC_RAW_REPLAY_CATALOG_MISMATCH")
    selected = tuple(
        item.rule_id for item in execution.rules if item.selection_status == "SELECTED"
    )
    try:
        value = json.loads(raw.decode("utf-8"))
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "tool_name", "tool_version", "batches"}
            or value.get("schema_version") != 1
            or value.get("tool_name") != "OPENGREP"
            or value.get("tool_version") != profile.expected_version
            or canonical_bytes(value) != raw
            or not isinstance(value.get("batches"), list)
            or not value["batches"]
        ):
            raise ValueError
        complete: list[_DecodedBatch] = []
        seen: set[str] = set()
        for batch_value in value["batches"]:
            if (
                not isinstance(batch_value, dict)
                or set(batch_value) != {"paths", "stdout_base64", "stdout_sha256"}
                or not isinstance(batch_value.get("paths"), list)
                or not all(isinstance(path, str) for path in batch_value["paths"])
                or not isinstance(batch_value.get("stdout_base64"), str)
                or not isinstance(batch_value.get("stdout_sha256"), str)
            ):
                raise ValueError
            paths = tuple(_safe_git_path(path) for path in batch_value["paths"])
            if not paths or len(paths) != len(set(paths)) or seen.intersection(paths):
                raise ValueError
            seen.update(paths)
            batch_raw = base64.b64decode(batch_value["stdout_base64"], validate=True)
            if _digest(batch_raw) != batch_value["stdout_sha256"]:
                raise ValueError
            complete.append(
                _decode_batch(
                    batch_raw,
                    paths,
                    replay.rule_mappings,
                    selected,
                    profile.expected_version,
                )
            )
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        raise ValueError("STATIC_RAW_REPLAY_ENVELOPE_INVALID") from error
    analyzed = tuple(path for batch in complete for path in batch.paths)
    if analyzed != tuple(result.coverage.analyzed_paths) or not set(analyzed).issubset(
        authorized
    ):
        raise ValueError("STATIC_RAW_REPLAY_SCOPE_MISMATCH")
    unknown = frozenset().union(*(batch.unknown_rules for batch in complete))
    hits: Counter[str] = Counter()
    facts: list[CandidateFact] = []
    gaps: list[CandidateGap] = []
    for batch in complete:
        hits.update(batch.hit_counts)
        facts.extend(batch.facts)
        gaps.extend(batch.gaps)
    if unknown:
        facts = [fact for fact in facts if fact.rule_id not in unknown]
    selected_set = set(selected)
    rules = tuple(
        CandidateRule(
            item.rule_id,
            "SELECTED" if item.rule_id in selected_set else "NOT_SELECTED",
            "UNKNOWN"
            if item.rule_id in unknown
            else "EXECUTED"
            if item.rule_id in selected_set
            else "NOT_EXECUTED",
            None
            if item.rule_id in unknown or item.rule_id not in selected_set
            else hits[item.rule_id],
            "TELEMETRY_MISSING"
            if item.rule_id in unknown
            else "NOT_SELECTED"
            if item.rule_id not in selected_set
            else None,
            "OpenGrep timing telemetry was absent or ambiguous."
            if item.rule_id in unknown
            else None,
        )
        for item in sorted(replay.rule_mappings, key=lambda value: value.rule_id)
    )
    if (
        tuple(item.__dict__ for item in rules)
        != tuple(item.model_dump(mode="python") for item in execution.rules)
        or (result.status == "SUCCEEDED" and gaps)
        or (result.status == "PARTIAL" and not result.gaps)
    ):
        raise ValueError("STATIC_RAW_REPLAY_RESULT_MISMATCH")
    return StaticToolObservation(
        tool_name="OPENGREP",
        tool_version=profile.expected_version,
        tool_kind="RULE_BASED",
        status=result.status,
        raw_output=raw,
        raw_media_type="application/json",
        analyzed_paths=tuple(result.coverage.analyzed_paths),
        skipped_paths=tuple(result.coverage.skipped_paths),
        analyzed_languages=tuple(result.coverage.analyzed_languages),
        skipped_languages=tuple(result.coverage.skipped_languages),
        notes=tuple(result.coverage.notes),
        selected_rule_packs=tuple(execution.selected_rule_packs),
        rules=rules,
        symbols=(),
        facts=tuple(facts),
        relations=(),
        gaps=tuple(gaps),
        errors=(),
        started_monotonic_ms=0,
        finished_monotonic_ms=0,
    )


def _empty_rules(
    inputs: OpenGrepExecutionInputs, reason: str
) -> tuple[CandidateRule, ...]:
    selected = set(inputs.selected_rule_ids)
    return tuple(
        CandidateRule(
            item.rule_id,
            "SELECTED" if item.rule_id in selected else "NOT_SELECTED",
            "NOT_EXECUTED",
            None,
            reason if item.rule_id in selected else "NOT_SELECTED",
            None,
        )
        for item in sorted(inputs.rule_catalog, key=lambda value: value.rule_id)
    )


class OpenGrepProcessAdapter:
    """Lower OpenGrep adapter; it owns no storage or vulnerability verdict."""

    def __init__(
        self,
        *,
        executable: Path,
        executable_key: str,
        inputs: OpenGrepExecutionInputs,
        runner_factory: OpenGrepRunnerFactory,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        monotonic_ms: Callable[[], int] = lambda: time.monotonic_ns() // 1_000_000,
        _test_command_limit_bytes: int | None = None,
        platform: str | None = None,
    ) -> None:
        self.executable = executable
        self.executable_key = executable_key
        self.inputs = inputs
        self.runner_factory = runner_factory
        self.monotonic_ns = monotonic_ns
        self.monotonic_ms = monotonic_ms
        self.platform = platform or ("win32" if sys.platform == "win32" else "posix")
        production_limit = _production_command_limit(self.platform)
        if _test_command_limit_bytes is not None and _test_command_limit_bytes <= 0:
            raise ValueError("OPENGREP_COMMAND_LIMIT_INVALID")
        self.command_limit_bytes = min(
            production_limit,
            _test_command_limit_bytes
            if _test_command_limit_bytes is not None
            else production_limit,
        )
        self._active: dict[str, OpenGrepProcessRunner] = {}

    def _profile_error(self, profile: StaticToolProfile) -> str | None:
        if (
            profile.status != "APPROVED"
            or profile.purpose not in {"FIXTURE", "EVALUATION"}
            or (profile.adapter_key, profile.tool_name, profile.tool_kind)
            != ("OPENGREP", "OPENGREP", "RULE_BASED")
            or profile.executable_key != self.executable_key
        ):
            return "OPENGREP_PROFILE_MISMATCH"
        try:
            identity = _file_identity(self.executable)
        except (OSError, ValueError):
            return "OPENGREP_EXECUTABLE_UNAVAILABLE"
        if (
            not self.executable.is_absolute()
            or identity.digest != profile.executable_sha256
        ):
            return "OPENGREP_EXECUTABLE_MISMATCH"
        return None

    def _capability(
        self,
        profile: StaticToolProfile,
        *,
        available: bool,
        version: str | None,
        reason: str | None,
    ) -> StaticCapabilityObservation:
        try:
            digest = _file_identity(self.executable).digest
        except (OSError, ValueError):
            digest = None
        return StaticCapabilityObservation(
            available,
            "OPENGREP",
            "RULE_BASED",
            self.executable_key,
            digest,
            version,
            profile.expected_version,
            reason,
        )

    def _make_runner(
        self,
        *,
        action_id: str,
        attempt_id: str,
        root: Path,
        output: Path,
        profile: StaticToolProfile,
    ) -> OpenGrepProcessRunner:
        runner = self.runner_factory(
            action_id=action_id,
            attempt_id=attempt_id,
            workspace_root=root,
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
        root: Path,
        output: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
        suffix: str,
    ) -> ProcessSpec:
        if deadline.action_id != action_id:
            raise ValueError("OPENGREP_ACTION_DEADLINE_MISMATCH")
        return ProcessSpec(
            f"{action_id}:opengrep:{suffix}",
            f"opengrep-{suffix}",
            attempt_id,
            argv,
            root,
            (),
            output,
            profile.stdout_limit_bytes,
            profile.stderr_limit_bytes,
            profile.max_attempt_output_bytes,
            deadline,
        )

    async def probe(
        self, profile: StaticToolProfile, deadline: MonotonicActionDeadline
    ) -> StaticCapabilityObservation:
        error = self._profile_error(profile)
        if error is not None:
            return self._capability(
                profile, available=False, version=None, reason=error
            )
        root = self.inputs.attempt_root / "opengrep-probe-cwd"
        output = self.inputs.attempt_root / "opengrep-probe"
        try:
            _assert_path_chain_safe(self.inputs.attempt_root)
            root.mkdir()
            output.mkdir()
        except (OSError, ValueError):
            return self._capability(
                profile,
                available=False,
                version=None,
                reason="OPENGREP_PROBE_ROOT_INVALID",
            )
        attempt_id = deadline.action_id
        runner = self._make_runner(
            action_id=deadline.action_id,
            attempt_id=attempt_id,
            root=root,
            output=output,
            profile=profile,
        )
        try:
            result = await runner.run(
                self._spec(
                    action_id=deadline.action_id,
                    attempt_id=attempt_id,
                    argv=(str(self.executable), "--version"),
                    root=root,
                    output=output,
                    profile=profile,
                    deadline=deadline,
                    suffix="version",
                )
            )
        finally:
            self._active.pop(attempt_id, None)
        if result.outcome == "CANCELLED":
            return self._capability(
                profile,
                available=False,
                version=None,
                reason="OPENGREP_PROBE_CANCELLED",
            )
        if result.outcome == "TIMED_OUT":
            return self._capability(
                profile,
                available=False,
                version=None,
                reason="OPENGREP_PROBE_TIMEOUT",
            )
        if result.stdout_truncated or result.stderr_truncated:
            return self._capability(
                profile,
                available=False,
                version=None,
                reason="OPENGREP_PROBE_OUTPUT_TRUNCATED",
            )
        if result.outcome != "SUCCEEDED" or result.return_code != 0:
            return self._capability(
                profile,
                available=False,
                version=None,
                reason="OPENGREP_PROBE_FAILED",
            )
        try:
            version = result.stdout.decode(errors="strict").strip()
        except UnicodeDecodeError:
            version = ""
        if not version:
            return self._capability(
                profile,
                available=False,
                version=None,
                reason="OPENGREP_VERSION_INVALID",
            )
        if version != profile.expected_version:
            return self._capability(
                profile,
                available=False,
                version=None,
                reason="OPENGREP_VERSION_MISMATCH",
            )
        return self._capability(profile, available=True, version=version, reason=None)

    def _preflight(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> tuple[str, str] | None:
        error = self._profile_error(profile)
        if error is not None:
            return "FAILED", error
        workspace = request.workspace
        action = request.action
        action_meta = action.meta
        try:
            profile_ref = cast(StoredDataRef, reference(profile))
            if (
                not isinstance(action_meta, RecordMeta)
                or request.tool_profile_ref != profile_ref
                or request.analysis_config_ref != self.inputs.analysis_config_ref
                or request.rule_catalog_ref != self.inputs.rule_catalog_ref
                or action.input_refs.count(profile_ref) != 1
                or action.input_refs.count(self.inputs.analysis_config_ref) != 1
                or action.input_refs.count(self.inputs.rule_catalog_ref) != 1
            ):
                return "FAILED", "OPENGREP_REFERENCE_MISMATCH"
        except ValueError:
            return "FAILED", "OPENGREP_REFERENCE_MISMATCH"
        if workspace.status != "READY" or workspace.commit_id is None:
            return "SKIPPED", "OPENGREP_WORKSPACE_NOT_READY"
        if (
            action.action_type != "RUN_TOOL"
            or action.tool_name != "OPENGREP"
            or action_meta.analysis_id != workspace.analysis_id
            or action_meta.workspace_id != workspace.workspace_id
            or action_meta.commit_id != workspace.commit_id
            or str(action_meta.attempt_id) != self.inputs.attempt_id
            or deadline.action_id != str(action.action_id)
        ):
            return "FAILED", "OPENGREP_REQUEST_MISMATCH"
        try:
            if (
                not workspace_root.is_absolute()
                or not self.inputs.attempt_root.is_absolute()
                or not workspace_root.resolve(strict=True).is_dir()
                or not self.inputs.attempt_root.resolve(strict=True).is_dir()
                or _link_like(workspace_root)
                or _inside(
                    self.inputs.attempt_root.resolve(strict=True),
                    workspace_root.resolve(strict=True),
                )
                or _inside(
                    self.inputs.config_path.resolve(strict=True),
                    workspace_root.resolve(strict=True),
                )
            ):
                return "FAILED", "OPENGREP_PATH_BOUNDARY_INVALID"
            config = _file_identity(
                self.inputs.config_path, max_bytes=profile.max_artifact_read_bytes
            )
            if config.digest != self.inputs.config_digest:
                return "FAILED", "OPENGREP_CONFIG_DIGEST_MISMATCH"
        except (OSError, ValueError):
            return "FAILED", "OPENGREP_CONFIG_INVALID"
        return None

    def _bind_files(
        self, request: StaticToolRequest, workspace_root: Path
    ) -> tuple[tuple[_BoundFile, ...], tuple[str, ...], tuple[CandidateGap, ...]]:
        tracked = {item.git_path: item for item in self.inputs.tracked_files}
        if len(request.action.file_paths) != len(set(request.action.file_paths)):
            raise ValueError("OPENGREP_MANIFEST_DUPLICATE")
        root = workspace_root.resolve(strict=True)
        bound: list[_BoundFile] = []
        skipped: list[str] = []
        gaps: list[CandidateGap] = []
        for git_path in sorted(request.action.file_paths):
            item = tracked.get(git_path)
            if item is None or item.git_mode not in _REGULAR_GIT_MODES:
                skipped.append(git_path)
                gaps.append(
                    _gap(
                        "STATIC_TARGET_UNSUPPORTED",
                        "UNSUPPORTED",
                        "Target was not a tracked regular file.",
                        paths=(git_path,),
                    )
                )
                continue
            try:
                pure = PurePosixPath(_safe_git_path(git_path))
                candidate = root.joinpath(*pure.parts)
                _assert_path_chain_safe(candidate)
                data, info = _read_regular(candidate)
                resolved = candidate.resolve(strict=True)
                if (
                    not _inside(resolved, root)
                    or info.st_size != item.size_bytes
                    or data.startswith(b"version https://git-lfs.github.com/spec/v1")
                ):
                    raise ValueError("OPENGREP_MANIFEST_MISMATCH")
            except (OSError, ValueError):
                skipped.append(git_path)
                gaps.append(
                    _gap(
                        "STATIC_TARGET_UNSAFE",
                        "BLOCKED",
                        "Target failed the tracked regular-file boundary.",
                        paths=(git_path,),
                    )
                )
                continue
            bound.append(
                _BoundFile(
                    git_path,
                    resolved,
                    info.st_size,
                    info.st_dev,
                    info.st_ino,
                    info.st_mtime_ns,
                    _digest(data),
                )
            )
        return tuple(bound), tuple(skipped), tuple(gaps)

    def _assert_bound(self, files: Sequence[_BoundFile], root: Path) -> None:
        resolved_root = root.resolve(strict=True)
        for item in files:
            candidate = resolved_root.joinpath(*PurePosixPath(item.git_path).parts)
            try:
                _assert_path_chain_safe(candidate)
                resolved = candidate.resolve(strict=True)
                identity = _file_identity(candidate)
            except (OSError, ValueError) as error:
                raise ValueError("OPENGREP_MANIFEST_CHANGED") from error
            if (
                resolved != item.absolute_path
                or not _inside(resolved, resolved_root)
                or _link_like(candidate)
                or (
                    identity.size,
                    identity.device,
                    identity.inode,
                    identity.modified_ns,
                    identity.digest,
                )
                != (
                    item.size,
                    item.device,
                    item.inode,
                    item.modified_ns,
                    item.digest,
                )
            ):
                raise ValueError("OPENGREP_MANIFEST_CHANGED")

    def _base_argv(self) -> tuple[str, ...]:
        return (
            str(self.executable),
            "scan",
            "--config",
            str(self.inputs.config_path),
            "--json",
            "--time",
            "--disable-version-check",
            "--",
        )

    def _batches(self, paths: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
        base = self._base_argv()
        if (
            encoded_command_cost(base, (), platform=self.platform)
            > self.command_limit_bytes
        ):
            raise ValueError("OPENGREP_COMMAND_TOO_LONG")
        batches: list[tuple[str, ...]] = []
        current: tuple[str, ...] = ()
        for path in sorted(paths):
            candidate = (*current, path)
            if (
                encoded_command_cost((*base, *candidate), (), platform=self.platform)
                <= self.command_limit_bytes
            ):
                current = candidate
                continue
            if not current:
                raise ValueError("OPENGREP_TARGET_TOO_LONG")
            batches.append(current)
            current = (path,)
            if (
                encoded_command_cost((*base, *current), (), platform=self.platform)
                > self.command_limit_bytes
            ):
                raise ValueError("OPENGREP_TARGET_TOO_LONG")
        if current:
            batches.append(current)
        return tuple(batches)

    def _observation(
        self,
        profile: StaticToolProfile,
        *,
        status: str,
        started: int,
        raw: bytes | None = None,
        analyzed: tuple[str, ...] = (),
        skipped: tuple[str, ...] = (),
        rules: tuple[CandidateRule, ...] | None = None,
        facts: tuple[CandidateFact, ...] = (),
        gaps: tuple[CandidateGap, ...] = (),
        errors: tuple[CandidateError, ...] = (),
    ) -> StaticToolObservation:
        return StaticToolObservation(
            "OPENGREP",
            profile.expected_version,
            "RULE_BASED",
            status,  # type: ignore[arg-type]
            raw,
            "application/json" if raw is not None else None,
            analyzed,
            skipped,
            (),
            (),
            ("OpenGrep findings are static candidates, not vulnerability verdicts.",),
            self.inputs.selected_rule_packs,
            rules if rules is not None else _empty_rules(self.inputs, "TOOL_FAILURE"),
            (),
            facts,
            (),
            gaps,
            errors,
            started,
            self.monotonic_ms(),
        )

    async def execute(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticToolObservation:
        started = self.monotonic_ms()
        preflight = self._preflight(request, workspace_root, profile, deadline)
        if preflight is not None:
            status, code = preflight
            reason = "UNSUPPORTED" if status == "SKIPPED" else "FAILED"
            return self._observation(
                profile,
                status=status,
                started=started,
                rules=_empty_rules(
                    self.inputs,
                    "UNSUPPORTED" if status == "SKIPPED" else "TOOL_FAILURE",
                ),
                gaps=(_gap(code, reason, "OpenGrep preflight failed."),),
                errors=()
                if status == "SKIPPED"
                else (_error(code, "OpenGrep preflight failed."),),
            )
        try:
            bound, skipped, initial_gaps = self._bind_files(request, workspace_root)
        except ValueError:
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                gaps=(
                    _gap(
                        "STATIC_MANIFEST_MISMATCH",
                        "BLOCKED",
                        "Target manifest was invalid.",
                    ),
                ),
                errors=(
                    _error("STATIC_MANIFEST_MISMATCH", "Target manifest was invalid."),
                ),
            )
        if not bound:
            return self._observation(
                profile,
                status="SKIPPED",
                started=started,
                skipped=skipped,
                rules=_empty_rules(self.inputs, "UNSUPPORTED"),
                gaps=initial_gaps,
            )
        try:
            batches = self._batches(tuple(item.git_path for item in bound))
        except ValueError as error:
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                skipped=skipped,
                gaps=(
                    *initial_gaps,
                    _gap(
                        str(error),
                        "BLOCKED",
                        "OpenGrep command exceeded the trusted boundary.",
                    ),
                ),
                errors=(
                    _error(
                        str(error), "OpenGrep command exceeded the trusted boundary."
                    ),
                ),
            )
        output = self.inputs.attempt_root / "opengrep-run"
        try:
            _assert_path_chain_safe(output)
            output.mkdir()
        except (OSError, ValueError):
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                gaps=(
                    _gap(
                        "STATIC_OUTPUT_LIMIT",
                        "BLOCKED",
                        "OpenGrep output root was unsafe.",
                    ),
                ),
                errors=(
                    _error("STATIC_OUTPUT_LIMIT", "OpenGrep output root was unsafe."),
                ),
            )
        try:
            config_identity = _file_identity(
                self.inputs.config_path,
                max_bytes=profile.max_artifact_read_bytes,
            )
        except (OSError, ValueError):
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                gaps=(
                    _gap(
                        "OPENGREP_CONFIG_CHANGED",
                        "BLOCKED",
                        "The exact trusted OpenGrep configuration changed.",
                    ),
                ),
                errors=(
                    _error(
                        "OPENGREP_CONFIG_CHANGED",
                        "The exact trusted OpenGrep configuration changed.",
                    ),
                ),
            )
        action_id = str(request.action.action_id)
        runner = self._make_runner(
            action_id=action_id,
            attempt_id=self.inputs.attempt_id,
            root=workspace_root,
            output=output,
            profile=profile,
        )
        complete: list[_DecodedBatch] = []
        termination: str | None = None
        process_error = False
        try:
            if deadline.remaining_ms(self.monotonic_ns()) == 0:
                termination = "TIMED_OUT"
            else:
                version_result = await runner.run(
                    self._spec(
                        action_id=action_id,
                        attempt_id=self.inputs.attempt_id,
                        argv=(str(self.executable), "--version"),
                        root=workspace_root,
                        output=output,
                        profile=profile,
                        deadline=deadline,
                        suffix="version",
                    )
                )
                if version_result.outcome in {"CANCELLED", "TIMED_OUT"}:
                    termination = version_result.outcome
                elif version_result.stdout_truncated or version_result.stderr_truncated:
                    termination = "OUTPUT_TRUNCATED"
                elif (
                    version_result.outcome != "SUCCEEDED"
                    or version_result.return_code != 0
                ):
                    termination = "PROCESS_FAILED"
                else:
                    try:
                        observed_version = version_result.stdout.decode(
                            errors="strict"
                        ).strip()
                    except UnicodeDecodeError:
                        observed_version = ""
                    if not observed_version:
                        termination = "VERSION_INVALID"
                    elif observed_version != profile.expected_version:
                        termination = "VERSION_MISMATCH"
            if termination is None:
                for index, batch in enumerate(batches):
                    if deadline.remaining_ms(self.monotonic_ns()) == 0:
                        termination = "TIMED_OUT"
                        break
                    self._assert_bound(bound, workspace_root)
                    _assert_identity(
                        config_identity,
                        self.inputs.config_digest,
                        max_bytes=profile.max_artifact_read_bytes,
                    )
                    result = await runner.run(
                        self._spec(
                            action_id=action_id,
                            attempt_id=self.inputs.attempt_id,
                            argv=(*self._base_argv(), *batch),
                            root=workspace_root,
                            output=output,
                            profile=profile,
                            deadline=deadline,
                            suffix=f"batch-{index:04d}",
                        )
                    )
                    if result.outcome in {"CANCELLED", "TIMED_OUT"}:
                        termination = result.outcome
                        break
                    if result.stdout_truncated or result.stderr_truncated:
                        termination = "OUTPUT_TRUNCATED"
                        break
                    if len(result.stdout) > min(
                        profile.max_output_file_bytes,
                        profile.max_artifact_read_bytes,
                    ):
                        termination = "OUTPUT_TRUNCATED"
                        break
                    try:
                        decoded = _decode_batch(
                            result.stdout,
                            batch,
                            self.inputs.rule_catalog,
                            self.inputs.selected_rule_ids,
                            profile.expected_version,
                        )
                    except ValueError:
                        termination = "OUTPUT_MALFORMED"
                        break
                    complete.append(decoded)
                    self._assert_bound(bound, workspace_root)
                    _assert_identity(
                        config_identity,
                        self.inputs.config_digest,
                        max_bytes=profile.max_artifact_read_bytes,
                    )
                    if result.outcome != "SUCCEEDED" or result.return_code != 0:
                        termination = "PROCESS_FAILED"
                        process_error = True
                        break
        except (OSError, ValueError):
            termination = "MANIFEST_CHANGED"
            complete.clear()
        finally:
            self._active.pop(self.inputs.attempt_id, None)

        if not complete:
            code = {
                "CANCELLED": "STATIC_TOOL_CANCELLED",
                "TIMED_OUT": "STATIC_TOOL_TIMEOUT",
                "OUTPUT_TRUNCATED": "STATIC_OUTPUT_LIMIT",
                "OUTPUT_MALFORMED": "STATIC_OUTPUT_MALFORMED",
                "MANIFEST_CHANGED": "STATIC_MANIFEST_CHANGED",
                "VERSION_INVALID": "STATIC_TOOL_VERSION",
                "VERSION_MISMATCH": "STATIC_TOOL_VERSION",
            }.get(termination or "", "STATIC_TOOL_FAILED")
            reason = (
                "BLOCKED"
                if termination == "CANCELLED"
                else "TIMEOUT"
                if termination == "TIMED_OUT"
                else "FAILED"
            )
            return self._observation(
                profile,
                status="SKIPPED" if termination == "CANCELLED" else "FAILED",
                started=started,
                skipped=tuple(sorted((*skipped, *(item.git_path for item in bound)))),
                rules=_empty_rules(
                    self.inputs,
                    "CANCELLED" if termination == "CANCELLED" else "TOOL_FAILURE",
                ),
                gaps=(
                    *initial_gaps,
                    _gap(code, reason, "OpenGrep produced no complete batch."),
                ),
                errors=()
                if termination == "CANCELLED"
                else (
                    _error(
                        code,
                        "OpenGrep produced no complete batch.",
                        retryable=termination == "TIMED_OUT",
                    ),
                ),
            )

        unknown = frozenset().union(*(batch.unknown_rules for batch in complete))
        hits: Counter[str] = Counter()
        all_facts: list[CandidateFact] = []
        batch_gaps: list[CandidateGap] = []
        analyzed: list[str] = []
        for decoded_batch in complete:
            hits.update(decoded_batch.hit_counts)
            analyzed.extend(decoded_batch.paths)
            batch_gaps.extend(decoded_batch.gaps)
            all_facts.extend(decoded_batch.facts)
        if unknown:
            all_facts = [fact for fact in all_facts if fact.rule_id not in unknown]
        selected = set(self.inputs.selected_rule_ids)
        rules = tuple(
            CandidateRule(
                item.rule_id,
                "SELECTED" if item.rule_id in selected else "NOT_SELECTED",
                "UNKNOWN"
                if item.rule_id in unknown
                else "EXECUTED"
                if item.rule_id in selected
                else "NOT_EXECUTED",
                None
                if item.rule_id in unknown or item.rule_id not in selected
                else hits[item.rule_id],
                "TELEMETRY_MISSING"
                if item.rule_id in unknown
                else "NOT_SELECTED"
                if item.rule_id not in selected
                else None,
                "OpenGrep timing telemetry was absent or ambiguous."
                if item.rule_id in unknown
                else None,
            )
            for item in sorted(
                self.inputs.rule_catalog, key=lambda value: value.rule_id
            )
        )
        remaining = tuple(path for batch in batches[len(complete) :] for path in batch)
        terminal_gaps: list[CandidateGap] = []
        terminal_errors: list[CandidateError] = []
        if termination is not None:
            code = {
                "CANCELLED": "STATIC_TOOL_CANCELLED",
                "TIMED_OUT": "STATIC_TOOL_TIMEOUT",
                "PROCESS_FAILED": "STATIC_TOOL_FAILED",
                "OUTPUT_TRUNCATED": "STATIC_OUTPUT_LIMIT",
            }.get(termination, "STATIC_TOOL_FAILED")
            reason = (
                "BLOCKED"
                if termination == "CANCELLED"
                else "TIMEOUT"
                if termination == "TIMED_OUT"
                else "FAILED"
            )
            terminal_gaps.append(
                _gap(
                    code,
                    reason,
                    "OpenGrep stopped after complete earlier batches.",
                    paths=remaining,
                )
            )
            if termination != "CANCELLED":
                terminal_errors.append(
                    _error(
                        code,
                        "OpenGrep stopped after complete earlier batches.",
                        retryable=termination == "TIMED_OUT",
                    )
                )
        envelope = canonical_bytes(
            {
                "schema_version": 1,
                "tool_name": "OPENGREP",
                "tool_version": profile.expected_version,
                "batches": [
                    {
                        "paths": list(batch.paths),
                        "stdout_base64": base64.b64encode(batch.raw).decode("ascii"),
                        "stdout_sha256": _digest(batch.raw),
                    }
                    for batch in complete
                ],
            }
        )
        if len(envelope) > min(
            profile.max_output_file_bytes,
            profile.max_artifact_read_bytes,
        ):
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                skipped=tuple(sorted((*skipped, *(item.git_path for item in bound)))),
                rules=_empty_rules(self.inputs, "TOOL_FAILURE"),
                gaps=(
                    *initial_gaps,
                    _gap(
                        "STATIC_OUTPUT_LIMIT",
                        "FAILED",
                        "The complete OpenGrep raw envelope exceeded its trusted cap.",
                    ),
                ),
                errors=(
                    _error(
                        "STATIC_OUTPUT_LIMIT",
                        "The complete OpenGrep raw envelope exceeded its trusted cap.",
                    ),
                ),
            )
        gaps = (*initial_gaps, *batch_gaps, *terminal_gaps)
        status = "PARTIAL" if gaps or process_error or skipped else "SUCCEEDED"
        return self._observation(
            profile,
            status=status,
            started=started,
            raw=envelope,
            analyzed=tuple(analyzed),
            skipped=tuple(sorted((*skipped, *remaining))),
            rules=rules,
            facts=tuple(all_facts),
            gaps=gaps,
            errors=tuple(terminal_errors),
        )

    async def cancel(self, attempt_id: str) -> CancellationResult:
        runner = self._active.get(attempt_id)
        if runner is None:
            return CancellationResult(False, "Attempt is not active")
        return await runner.cancel(attempt_id)
