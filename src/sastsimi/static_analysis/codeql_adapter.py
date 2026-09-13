"""Analyze an exact prebuilt CodeQL database and decode bounded SARIF evidence."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import stat
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol, cast
from urllib.parse import unquote, urlsplit

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    HostConfigurationRef,
    StoredDataRef,
    reference,
    require_record_ref,
)
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
    StaticOutputQuotaBinding,
    StaticRuleMapping,
    StaticToolObservation,
    StaticToolRequest,
    TrackedFile,
)
from sastsimi.ports.static_tool import StaticOutputQuotaPort
from sastsimi.static_analysis.normalizer import StaticRawReplayInput


async def _await_task_during_cancellation[ResultT](
    task: asyncio.Task[ResultT],
) -> ResultT:
    """Settle one child even if this task receives repeated cancellation."""

    while True:
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.done():
                return task.result()


class _WindowsFunction(Protocol):
    argtypes: list[object]
    restype: object

    def __call__(self, *args: object) -> int | None: ...


class _Kernel32(Protocol):
    CreateFileW: _WindowsFunction
    CloseHandle: _WindowsFunction


def _platform_attribute(owner: object, name: str) -> object:
    return getattr(owner, name)


def _codeql_version_result(
    result: ProcessResult, expected_version: str
) -> tuple[str | None, str | None]:
    """Return the observed version and one exact version-stage failure kind."""

    if result.outcome == "CANCELLED":
        return None, "CANCELLED"
    if result.outcome == "TIMED_OUT":
        return None, "TIMED_OUT"
    if result.stdout_truncated or result.stderr_truncated:
        return None, "OUTPUT_TRUNCATED"
    if result.outcome != "SUCCEEDED" or result.return_code != 0:
        return None, "PROCESS_FAILED"
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "VERSION_INVALID"
    version = value.get("version") if isinstance(value, dict) else None
    if not isinstance(version, str) or not version:
        return None, "VERSION_INVALID"
    if version != expected_version:
        return version, "VERSION_MISMATCH"
    return version, None


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
    analysis_config_ref: StoredDataRef
    rule_catalog_ref: StoredDataRef
    rule_catalog: tuple[StaticRuleMapping, ...]
    selected_rule_ids: tuple[str, ...]
    selected_rule_packs: tuple[str, ...]
    tracked_files: tuple[TrackedFile, ...]
    attempt_root: Path
    attempt_id: str
    output_quota_lease_id: str
    probe_root: Path
    probe_output_quota_lease_id: str
    output_quota: StaticOutputQuotaPort

    def __post_init__(self) -> None:
        rule_ids = tuple(item.rule_id for item in self.rule_catalog)
        tracked = tuple(item.git_path for item in self.tracked_files)
        try:
            require_record_ref(self.analysis_config_ref, "analysis_config")
            require_record_ref(self.rule_catalog_ref, "rule_catalog")
        except ValueError as error:
            raise ValueError("CODEQL_INPUT_CLOSURE_INVALID") from error
        if (
            not self.rule_catalog
            or len(set(rule_ids)) != len(rule_ids)
            or len(set(self.selected_rule_ids)) != len(self.selected_rule_ids)
            or len(set(self.selected_rule_packs)) != len(self.selected_rule_packs)
            or not set(self.selected_rule_ids).issubset(rule_ids)
            or len(set(tracked)) != len(tracked)
            or not self.selected_rule_packs
            or not self.query_pack_digest
            or not self.attempt_id
            or not self.output_quota_lease_id
            or not self.probe_output_quota_lease_id
            or self.output_quota_lease_id == self.probe_output_quota_lease_id
        ):
            raise ValueError("CODEQL_INPUT_CLOSURE_INVALID")
        try:
            _assert_path_chain_safe(self.attempt_root)
            _assert_path_chain_safe(self.probe_root)
            attempt_root = self.attempt_root.resolve(strict=True)
            probe_root = self.probe_root.resolve(strict=True)
            if (
                not self.attempt_root.is_absolute()
                or not self.probe_root.is_absolute()
                or not attempt_root.is_dir()
                or not probe_root.is_dir()
                or attempt_root == probe_root
                or _inside(attempt_root, probe_root)
                or _inside(probe_root, attempt_root)
            ):
                raise ValueError
        except (OSError, ValueError) as error:
            raise ValueError("CODEQL_INPUT_CLOSURE_INVALID") from error
        for git_path in tracked:
            _safe_git_path(git_path)

    def output_quota_binding(
        self,
        *,
        action_id: str,
        attempt_id: str,
        profile_ref: StoredDataRef | HostConfigurationRef,
        root: Path,
        lease_id: str,
        limit_bytes: int,
    ) -> StaticOutputQuotaBinding:
        """Fail closed unless the trusted lease enforces this exact cap."""

        try:
            if not attempt_id or not lease_id:
                raise ValueError
            if not root.is_absolute():
                raise ValueError
            _assert_path_chain_safe(root)
            exact_root = root.resolve(strict=True)
            if not exact_root.is_dir() or _link_like(root):
                raise ValueError
            binding = self.output_quota.verify(
                lease_id=lease_id,
                action_id=action_id,
                attempt_id=attempt_id,
                profile_ref=profile_ref,
                root=exact_root,
                limit_bytes=limit_bytes,
            )
            _assert_path_chain_safe(binding.root)
            if (
                not binding.hard_enforced
                or binding.lease_id != lease_id
                or binding.action_id != action_id
                or binding.attempt_id != attempt_id
                or binding.profile_ref != profile_ref
                or binding.root.resolve(strict=True) != exact_root
                or binding.effective_limit_bytes != limit_bytes
                or not binding.binding_id
                or not binding.backend_key
                or not binding.enforcement_evidence
                or type(binding.limit_breached) is not bool
                or (binding.limit_breached and not binding.breach_evidence)
                or (not binding.limit_breached and binding.breach_evidence is not None)
            ):
                raise ValueError
            return binding
        except (OSError, ValueError) as error:
            raise ValueError("CODEQL_OUTPUT_QUOTA_UNENFORCEABLE") from error


def _link_like(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _probe_directory_identity(path: Path) -> tuple[int, ...]:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or _link_like(path) or _reparse_like_stat(info):
        raise ValueError("CODEQL_PROBE_ROOT_INVALID")
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        int(getattr(info, "st_file_attributes", 0)),
        int(getattr(info, "st_reparse_tag", 0)),
    )


def _remove_owned_probe_directory(
    path: Path, parent: Path, identity: tuple[int, ...]
) -> None:
    try:
        if (
            path.resolve(strict=True).parent != parent.resolve(strict=True)
            or _probe_directory_identity(path) != identity
        ):
            raise ValueError("CODEQL_PROBE_ROOT_CHANGED")
        shutil.rmtree(path)
    except (OSError, ValueError) as error:
        raise ValueError("CODEQL_PROBE_CLEANUP_FAILED") from error


def _assert_path_chain_safe(path: Path) -> None:
    candidate = path.absolute()
    for part in (candidate, *candidate.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if _link_like(part) or _reparse_like_stat(info):
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
    common_cache_root: Path | None = None,
    log_root: Path | None = None,
    max_disk_cache_mb: int | None = None,
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
        f"--common-caches={common_cache_root}",
        f"--logdir={log_root}",
        f"--max-disk-cache={max_disk_cache_mb}",
    )
    if argv != version and (
        common_cache_root is None
        or log_root is None
        or max_disk_cache_mb is None
        or argv != analyze
    ):
        raise ValueError("CODEQL_COMMAND_FORBIDDEN")


class _OutputBoundaryError(ValueError):
    pass


class _MalformedSarif(ValueError):
    pass


_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _reparse_like_stat(info: os.stat_result) -> bool:
    return (
        bool(
            int(getattr(info, "st_file_attributes", 0)) & _FILE_ATTRIBUTE_REPARSE_POINT
        )
        or int(getattr(info, "st_reparse_tag", 0)) != 0
    )


def _safe_regular_file(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and not _reparse_like_stat(info)
    )


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    """Return identity and mutation-sensitive metadata for one regular file."""

    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        int(getattr(info, "st_file_attributes", 0)),
        int(getattr(info, "st_reparse_tag", 0)),
    )


def _open_bounded_read_descriptor(path: Path) -> int:
    """Open without following a final reparse point and permit identity checks."""

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if os.name != "nt":
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        return os.open(path, flags)

    import ctypes
    import msvcrt

    generic_read = 0x80000000
    share_read_write_delete = 0x00000001 | 0x00000002 | 0x00000004
    open_existing = 3
    file_attribute_normal = 0x00000080
    file_flag_open_reparse_point = 0x00200000
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
        generic_read,
        share_read_write_delete,
        None,
        open_existing,
        file_attribute_normal | file_flag_open_reparse_point,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle is None or handle == invalid_handle:
        get_last_error = cast(
            Callable[[], int], _platform_attribute(ctypes, "get_last_error")
        )
        error = get_last_error()
        raise OSError(error, "CODEQL_OUTPUT_OPEN_FAILED", str(path))
    try:
        open_osfhandle = cast(
            Callable[[int, int], int],
            _platform_attribute(msvcrt, "open_osfhandle"),
        )
        return open_osfhandle(int(handle), flags)
    except BaseException:
        close_handle(handle)
        raise


def _directory_size(root: Path, cap: int) -> int:
    _assert_path_chain_safe(root)
    root_info = os.stat(root, follow_symlinks=False)
    if not stat.S_ISDIR(root_info.st_mode) or _reparse_like_stat(root_info):
        raise _OutputBoundaryError("CODEQL_OUTPUT_DIRECTORY_INVALID")
    total = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        directory_info = os.stat(directory, follow_symlinks=False)
        if not stat.S_ISDIR(directory_info.st_mode) or _reparse_like_stat(
            directory_info
        ):
            raise _OutputBoundaryError("CODEQL_OUTPUT_NOT_REGULAR")
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.is_symlink():
                    raise _OutputBoundaryError("CODEQL_OUTPUT_NOT_REGULAR")
                # On Windows ``DirEntry.stat`` can report ``st_nlink=0`` for
                # ordinary files.  A direct non-following stat supplies the
                # link count used by the hard-link boundary check.
                info = os.stat(Path(entry.path), follow_symlinks=False)
                if _reparse_like_stat(info):
                    raise _OutputBoundaryError("CODEQL_OUTPUT_NOT_REGULAR")
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(entry.path))
                    continue
                if not _safe_regular_file(info):
                    raise _OutputBoundaryError("CODEQL_OUTPUT_NOT_REGULAR")
                total += info.st_size
                if total > cap:
                    raise _OutputBoundaryError("CODEQL_ATTEMPT_OUTPUT_LIMIT")
    return total


def _same_quota_identity(
    initial: StaticOutputQuotaBinding, current: StaticOutputQuotaBinding
) -> bool:
    """Compare immutable lease identity while treating breach as live status."""

    return (
        current.binding_id == initial.binding_id
        and current.lease_id == initial.lease_id
        and current.backend_key == initial.backend_key
        and current.enforcement_evidence == initial.enforcement_evidence
        and current.root == initial.root
        and current.action_id == initial.action_id
        and current.attempt_id == initial.attempt_id
        and current.profile_ref == initial.profile_ref
        and current.effective_limit_bytes == initial.effective_limit_bytes
        and current.hard_enforced == initial.hard_enforced
    )


def _quota_allows_result(
    initial: StaticOutputQuotaBinding, current: StaticOutputQuotaBinding
) -> bool:
    return _same_quota_identity(initial, current) and not current.limit_breached


def _read_bounded_regular(
    path: Path,
    root: Path,
    *,
    file_cap: int,
    read_cap: int,
    expected_name: str = "codeql-result.sarif",
) -> bytes:
    _assert_path_chain_safe(path)
    resolved_root = root.resolve(strict=True)
    if path.resolve(strict=True).parent != resolved_root or path.name != expected_name:
        raise _OutputBoundaryError("CODEQL_OUTPUT_ESCAPE")
    path_before = os.stat(path, follow_symlinks=False)
    if not _safe_regular_file(path_before):
        raise _OutputBoundaryError("CODEQL_OUTPUT_LIMIT")
    descriptor = _open_bounded_read_descriptor(path)
    try:
        before = os.fstat(descriptor)
        if (
            not _safe_regular_file(before)
            or _file_identity(path_before) != _file_identity(before)
            or before.st_size > file_cap
            or before.st_size > read_cap
        ):
            raise _OutputBoundaryError("CODEQL_OUTPUT_LIMIT")
        data = os.read(descriptor, read_cap + 1)
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        if (
            len(data) != before.st_size
            or len(data) > read_cap
            or not _safe_regular_file(after)
            or not _safe_regular_file(current)
            or _file_identity(before) != _file_identity(after)
            or _file_identity(before) != _file_identity(current)
        ):
            raise _OutputBoundaryError("CODEQL_OUTPUT_CHANGED")
        return data
    finally:
        os.close(descriptor)


def _selection_manifest_matches(inputs: CodeQLExecutionInputs) -> bool:
    manifest_name = "sastsimi-selection.json"
    raw = _read_bounded_regular(
        inputs.query_pack_root / manifest_name,
        inputs.query_pack_root,
        file_cap=64 * 1024,
        read_cap=64 * 1024,
        expected_name=manifest_name,
    )
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "rule_ids",
        "rule_packs",
    }:
        return False
    rule_ids = value.get("rule_ids")
    rule_packs = value.get("rule_packs")
    schema_version = value.get("schema_version")
    return (
        type(schema_version) is int
        and schema_version == 1
        and isinstance(rule_ids, list)
        and all(isinstance(item, str) for item in rule_ids)
        and tuple(rule_ids) == inputs.selected_rule_ids
        and isinstance(rule_packs, list)
        and all(isinstance(item, str) for item in rule_packs)
        and tuple(rule_packs) == inputs.selected_rule_packs
    )


def _mapping_by_id(
    rule_catalog: tuple[StaticRuleMapping, ...],
) -> Mapping[str, StaticRuleMapping]:
    return {item.rule_id: item for item in rule_catalog}


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
    rule_catalog: tuple[StaticRuleMapping, ...],
    selected_rule_ids: tuple[str, ...],
    metadata_ids: list[str],
    hit_counts: Counter[str],
) -> tuple[CandidateRule, ...]:
    metadata = Counter(metadata_ids)
    selected = set(selected_rule_ids)
    result: list[CandidateRule] = []
    for mapping in sorted(rule_catalog, key=lambda item: item.rule_id):
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
    rule_catalog: tuple[StaticRuleMapping, ...],
    selected_rule_ids: tuple[str, ...],
    tracked_paths: tuple[str, ...],
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

    catalog = _mapping_by_id(rule_catalog)
    selected = frozenset(selected_rule_ids)
    if any(rule_id not in selected for rule_id in metadata_ids):
        raise _MalformedSarif("STATIC_OUTPUT_MALFORMED")
    tracked = frozenset(tracked_paths)
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
        if rule_id not in selected:
            raise _MalformedSarif("STATIC_OUTPUT_MALFORMED")
        mapping = catalog.get(rule_id)
        if mapping is None:
            raise _MalformedSarif("STATIC_OUTPUT_MALFORMED")
        hit_counts[rule_id] += 1
        result_locations: list[CandidateLocation] = []
        location_issue = False
        locations = result.get("locations")
        if isinstance(locations, list) and locations:
            for raw_location in locations:
                try:
                    result_locations.append(_location(raw_location, tracked))
                except ValueError:
                    location_issue = True
        else:
            location_issue = True
        if location_issue or not result_locations:
            gaps.append(
                _gap(
                    "STATIC_LOCATION_UNRESOLVED",
                    "MISSING" if not locations else "UNSUPPORTED",
                    "A CodeQL hit lacked a safe location in the tracked manifest.",
                )
            )
        for location_index, location in enumerate(result_locations):
            facts.append(
                CandidateFact(
                    (
                        f"codeql:{rule_id}:result:{result_index}:"
                        f"location:{location_index}:endpoint"
                    ),
                    mapping.result_fact_kind,
                    None,
                    location,
                    rule_id,
                )
            )
        valid_flows: list[tuple[int, int, tuple[CandidateLocation, ...]]] = []
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
                        valid_flows.append((flow_index, thread_index, tuple(distinct)))
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
            if not valid_flows or flow_issue:
                gaps.append(
                    _gap(
                        "STATIC_DATA_FLOW_UNRESOLVED",
                        "MISSING" if not code_flows else "UNSUPPORTED",
                        "The required CodeQL flow was absent or contained "
                        "an unsafe step.",
                    )
                )
        for flow_index, thread_index, flow_locations in valid_flows:
            facts.append(
                CandidateFact(
                    (
                        f"codeql:{rule_id}:result:{result_index}:"
                        f"flow:{flow_index}:{thread_index}:endpoint"
                    ),
                    mapping.result_fact_kind,
                    None,
                    flow_locations[-1],
                    rule_id,
                )
            )
            if mapping.flow_start_fact_kind is not None:
                facts.append(
                    CandidateFact(
                        (
                            f"codeql:{rule_id}:result:{result_index}:"
                            f"flow:{flow_index}:{thread_index}:start"
                        ),
                        mapping.flow_start_fact_kind,
                        None,
                        flow_locations[0],
                        rule_id,
                    )
                )
    return (
        _rules(rule_catalog, selected_rule_ids, metadata_ids, hit_counts),
        tuple(facts),
        tuple(relations),
        tuple(gaps),
    )


def replay_codeql_raw(
    raw: bytes, replay: StaticRawReplayInput
) -> StaticToolObservation:
    """Purely decode verified SARIF against its exact persisted rule context."""

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
        != ("CODEQL", "CODEQL", "RULE_BASED")
        or (result.tool_name, result.tool_version, result.tool_kind)
        != ("CODEQL", profile.expected_version, "RULE_BASED")
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
        rules, facts, relations, gaps = _decode_sarif(
            raw,
            replay.rule_mappings,
            selected,
            tuple(result.coverage.analyzed_paths),
            profile.expected_version,
            json.loads,
        )
    except _MalformedSarif as error:
        raise ValueError("STATIC_RAW_REPLAY_OUTPUT_INVALID") from error
    if (
        tuple(item.__dict__ for item in rules)
        != tuple(item.model_dump(mode="python") for item in execution.rules)
        or (result.status == "SUCCEEDED" and gaps)
        or (result.status == "PARTIAL" and not result.gaps)
    ):
        raise ValueError("STATIC_RAW_REPLAY_RESULT_MISMATCH")
    return StaticToolObservation(
        tool_name="CODEQL",
        tool_version=profile.expected_version,
        tool_kind="RULE_BASED",
        status=result.status,
        raw_output=raw,
        raw_media_type="application/sarif+json",
        analyzed_paths=tuple(result.coverage.analyzed_paths),
        skipped_paths=tuple(result.coverage.skipped_paths),
        analyzed_languages=tuple(result.coverage.analyzed_languages),
        skipped_languages=tuple(result.coverage.skipped_languages),
        notes=tuple(result.coverage.notes),
        selected_rule_packs=tuple(execution.selected_rule_packs),
        rules=rules,
        symbols=(),
        facts=facts,
        relations=relations,
        gaps=gaps,
        errors=(),
        started_monotonic_ms=0,
        finished_monotonic_ms=0,
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
        if attempt_id in self._active:
            raise ValueError("CODEQL_ATTEMPT_ALREADY_ACTIVE")
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

    def _release_runner(self, attempt_id: str, runner: CodeQLProcessRunner) -> None:
        if self._active.get(attempt_id) is runner:
            self._active.pop(attempt_id, None)

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
        env: tuple[tuple[str, str], ...] = (),
    ) -> ProcessSpec:
        if deadline.action_id != action_id:
            raise ValueError("CODEQL_ACTION_DEADLINE_MISMATCH")
        return ProcessSpec(
            invocation_id=f"{action_id}:codeql:{suffix}",
            command_kind=f"codeql-{suffix}",
            attempt_id=attempt_id,
            argv=argv,
            cwd=cwd,
            env=env,
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
        attempt_id = deadline.action_id
        profile_ref = cast(StoredDataRef, reference(profile))
        try:
            quota_binding = self.inputs.output_quota_binding(
                action_id=attempt_id,
                attempt_id=attempt_id,
                profile_ref=profile_ref,
                root=self.inputs.probe_root,
                lease_id=self.inputs.probe_output_quota_lease_id,
                limit_bytes=profile.max_attempt_output_bytes,
            )
        except ValueError:
            return self._capability(
                profile,
                available=False,
                version=None,
                reason="CODEQL_OUTPUT_QUOTA_UNENFORCEABLE",
            )
        if quota_binding.limit_breached:
            return self._capability(
                profile,
                available=False,
                version=None,
                reason="CODEQL_OUTPUT_QUOTA_UNENFORCEABLE",
            )
        if attempt_id in self._active:
            return self._capability(
                profile,
                available=False,
                version=None,
                reason="CODEQL_PROBE_ALREADY_ACTIVE",
            )
        probe_root: Path | None = None
        probe_identity: tuple[int, ...] | None = None
        try:
            _assert_path_chain_safe(self.inputs.probe_root)
            action_key = hashlib.sha256(attempt_id.encode("utf-8")).hexdigest()[:16]
            probe_root = Path(
                tempfile.mkdtemp(
                    prefix=f"codeql-probe-{action_key}-",
                    dir=self.inputs.probe_root,
                )
            )
            _assert_path_chain_safe(probe_root)
            probe_identity = _probe_directory_identity(probe_root)
            output = probe_root / "output"
            cwd = probe_root / "cwd"
            temporary = probe_root / "tmp"
            output.mkdir(mode=0o700)
            cwd.mkdir(mode=0o700)
            temporary.mkdir(mode=0o700)
        except (OSError, ValueError):
            if probe_root is not None and probe_identity is not None:
                _remove_owned_probe_directory(
                    probe_root, self.inputs.probe_root, probe_identity
                )
            return self._capability(
                profile,
                available=False,
                version=None,
                reason="CODEQL_PROBE_ROOT_INVALID",
            )
        try:
            try:
                runner = self._make_runner(
                    action_id=deadline.action_id,
                    attempt_id=attempt_id,
                    cwd=cwd,
                    output=output,
                    profile=profile,
                )
            except ValueError as error:
                if str(error) != "CODEQL_ATTEMPT_ALREADY_ACTIVE":
                    raise
                return self._capability(
                    profile,
                    available=False,
                    version=None,
                    reason="CODEQL_PROBE_ALREADY_ACTIVE",
                )
            try:
                argv = (str(self.executable), "version", "--format=json")
                validate_codeql_command(
                    argv,
                    self.executable,
                    self.inputs.database.database_root,
                    self.inputs.query_pack_root,
                    output / "codeql-result.sarif",
                )
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
                        env=(
                            ("TEMP", str(temporary)),
                            ("TMP", str(temporary)),
                            ("TMPDIR", str(temporary)),
                        ),
                    )
                )
            finally:
                self._release_runner(attempt_id, runner)
        finally:
            _remove_owned_probe_directory(
                probe_root, self.inputs.probe_root, probe_identity
            )
        try:
            if not _quota_allows_result(
                quota_binding,
                self.inputs.output_quota_binding(
                    action_id=attempt_id,
                    attempt_id=attempt_id,
                    profile_ref=profile_ref,
                    root=self.inputs.probe_root,
                    lease_id=self.inputs.probe_output_quota_lease_id,
                    limit_bytes=profile.max_attempt_output_bytes,
                ),
            ):
                raise ValueError
        except ValueError:
            return self._capability(
                profile,
                available=False,
                version=None,
                reason="CODEQL_OUTPUT_QUOTA_UNENFORCEABLE",
            )
        version, version_failure = _codeql_version_result(
            result, profile.expected_version
        )
        if version_failure is not None:
            reason = {
                "CANCELLED": "CODEQL_PROBE_CANCELLED",
                "TIMED_OUT": "CODEQL_PROBE_TIMEOUT",
                "OUTPUT_TRUNCATED": "CODEQL_PROBE_OUTPUT_TRUNCATED",
                "VERSION_INVALID": "CODEQL_VERSION_INVALID",
                "VERSION_MISMATCH": "CODEQL_VERSION_MISMATCH",
            }.get(version_failure, "CODEQL_PROBE_FAILED")
            return self._capability(
                profile,
                available=False,
                # The coordinator accepts the expected version or no version on
                # failure; the reason code preserves invalid versus mismatched.
                version=None,
                reason=reason,
            )
        assert version is not None
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
            skipped_paths=(
                ()
                if status in {"SUCCEEDED", "PARTIAL"}
                else tuple(sorted(item.git_path for item in self.inputs.tracked_files))
            ),
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
        if request.tool_profile_ref != reference(profile):
            return "FAILED", "CODEQL_PROFILE_REFERENCE_MISMATCH"
        workspace = request.workspace
        database = self.inputs.database
        action = request.action
        action_meta = action.meta
        requested_paths = action.file_paths
        tracked_paths = tuple(item.git_path for item in self.inputs.tracked_files)
        if (
            not isinstance(action_meta, RecordMeta)
            or request.analysis_config_ref != self.inputs.analysis_config_ref
            or request.rule_catalog_ref != self.inputs.rule_catalog_ref
            or action.input_refs.count(self.inputs.analysis_config_ref) != 1
            or action.input_refs.count(self.inputs.rule_catalog_ref) != 1
            or action.action_type != "RUN_TOOL"
            or action.tool_name != "CODEQL"
            or action_meta.analysis_id != workspace.analysis_id
            or action_meta.workspace_id != workspace.workspace_id
            or action_meta.commit_id != workspace.commit_id
            or str(action_meta.attempt_id) != self.inputs.attempt_id
            or len(requested_paths) != len(set(requested_paths))
            or set(requested_paths) != set(tracked_paths)
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
            if not _selection_manifest_matches(self.inputs):
                return "FAILED", "CODEQL_SELECTION_MANIFEST_MISMATCH"
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
        action_id = str(request.action.action_id)
        try:
            quota_binding = self.inputs.output_quota_binding(
                action_id=action_id,
                attempt_id=self.inputs.attempt_id,
                profile_ref=request.tool_profile_ref,
                root=self.inputs.attempt_root,
                lease_id=self.inputs.output_quota_lease_id,
                limit_bytes=profile.max_attempt_output_bytes,
            )
        except ValueError:
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                rules=self._empty_rules("TOOL_FAILURE"),
                gaps=(
                    _gap(
                        "CODEQL_OUTPUT_QUOTA_UNENFORCEABLE",
                        "FAILED",
                        "CodeQL hard output quota was unavailable.",
                    ),
                ),
                errors=(
                    _error(
                        "CODEQL_OUTPUT_QUOTA_UNENFORCEABLE",
                        "CodeQL hard output quota was unavailable.",
                    ),
                ),
            )
        if quota_binding.limit_breached:
            return self._output_failure(profile, started)
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
        attempt_id = self.inputs.attempt_id
        if deadline.action_id != action_id:
            raise ValueError("CODEQL_ACTION_DEADLINE_MISMATCH")
        execution_root = self.inputs.attempt_root / "codeql-run"
        cwd = execution_root / "cwd"
        output = execution_root / "output"
        working_database = execution_root / "database"
        working_query_pack = execution_root / "query-pack"
        common_cache = execution_root / "common-cache"
        logs = execution_root / "logs"
        temporary = execution_root / "tmp"
        try:
            execution_root.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            cwd.mkdir(mode=0o700)
            common_cache.mkdir(mode=0o700)
            logs.mkdir(mode=0o700)
            temporary.mkdir(mode=0o700)
            shutil.copytree(self.inputs.database.database_root, working_database)
            shutil.copytree(self.inputs.query_pack_root, working_query_pack)
            for root in (
                execution_root,
                cwd,
                output,
                working_database,
                working_query_pack,
                common_cache,
                logs,
                temporary,
            ):
                _assert_path_chain_safe(root)
                root.resolve(strict=True).relative_to(
                    self.inputs.attempt_root.resolve(strict=True)
                )
            if (
                digest_path(working_database) != self.inputs.database.database_digest
                or digest_path(working_query_pack) != self.inputs.query_pack_digest
                or not _quota_allows_result(
                    quota_binding,
                    self.inputs.output_quota_binding(
                        action_id=action_id,
                        attempt_id=self.inputs.attempt_id,
                        profile_ref=request.tool_profile_ref,
                        root=self.inputs.attempt_root,
                        lease_id=self.inputs.output_quota_lease_id,
                        limit_bytes=profile.max_attempt_output_bytes,
                    ),
                )
            ):
                raise ValueError
            _directory_size(self.inputs.attempt_root, profile.max_attempt_output_bytes)
        except (OSError, ValueError):
            return self._output_failure(profile, started)
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
            cwd=cwd,
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
        try:
            version_result = await runner.run(
                self._spec(
                    action_id=action_id,
                    attempt_id=attempt_id,
                    argv=version_argv,
                    cwd=cwd,
                    output=output,
                    profile=profile,
                    deadline=deadline,
                    suffix="version",
                    env=(
                        ("TEMP", str(temporary)),
                        ("TMP", str(temporary)),
                        ("TMPDIR", str(temporary)),
                    ),
                )
            )
        finally:
            self._release_runner(attempt_id, runner)
        _, version_failure = _codeql_version_result(
            version_result, profile.expected_version
        )
        try:
            if not _quota_allows_result(
                quota_binding,
                self.inputs.output_quota_binding(
                    action_id=action_id,
                    attempt_id=self.inputs.attempt_id,
                    profile_ref=request.tool_profile_ref,
                    root=self.inputs.attempt_root,
                    lease_id=self.inputs.output_quota_lease_id,
                    limit_bytes=profile.max_attempt_output_bytes,
                ),
            ):
                raise ValueError
        except ValueError:
            return self._output_failure(profile, started)
        if version_failure is not None:
            code = {
                "CANCELLED": "STATIC_TOOL_CANCELLED",
                "TIMED_OUT": "STATIC_TOOL_TIMEOUT",
                "OUTPUT_TRUNCATED": "STATIC_OUTPUT_LIMIT",
                "PROCESS_FAILED": "STATIC_TOOL_FAILED",
                "VERSION_INVALID": "STATIC_TOOL_VERSION_INVALID",
                "VERSION_MISMATCH": "STATIC_TOOL_VERSION_MISMATCH",
            }[version_failure]
            reason = (
                "BLOCKED"
                if version_failure == "CANCELLED"
                else "TIMEOUT"
                if version_failure == "TIMED_OUT"
                else "TRUNCATED"
                if version_failure == "OUTPUT_TRUNCATED"
                else "FAILED"
            )
            message = {
                "CANCELLED": "CodeQL version check was cancelled.",
                "TIMED_OUT": "CodeQL version check timed out.",
                "OUTPUT_TRUNCATED": "CodeQL version output was truncated.",
                "PROCESS_FAILED": "CodeQL version command failed.",
            }.get(version_failure, "CodeQL version verification failed.")
            return self._observation(
                profile,
                status="SKIPPED" if version_failure == "CANCELLED" else "FAILED",
                started=started,
                rules=self._empty_rules(
                    "CANCELLED" if version_failure == "CANCELLED" else "TOOL_FAILURE"
                ),
                gaps=(_gap(code, reason, message),),
                errors=()
                if version_failure == "CANCELLED"
                else (
                    _error(
                        code,
                        message,
                        retryable=version_failure == "TIMED_OUT",
                    ),
                ),
            )
        argv = (
            str(self.executable),
            "database",
            "analyze",
            str(working_database),
            str(working_query_pack),
            "--format=sarifv2.1.0",
            f"--output={sarif_path}",
            f"--common-caches={common_cache}",
            f"--logdir={logs}",
            f"--max-disk-cache={profile.max_attempt_output_bytes // (1024 * 1024)}",
        )
        validate_codeql_command(
            argv,
            self.executable,
            working_database,
            working_query_pack,
            sarif_path,
            common_cache,
            logs,
            profile.max_attempt_output_bytes // (1024 * 1024),
        )
        spec = self._spec(
            action_id=action_id,
            attempt_id=attempt_id,
            argv=argv,
            cwd=cwd,
            output=output,
            profile=profile,
            deadline=deadline,
            suffix="analyze",
            env=(
                ("TEMP", str(temporary)),
                ("TMP", str(temporary)),
                ("TMPDIR", str(temporary)),
            ),
        )
        done = asyncio.Event()
        process_task = asyncio.create_task(runner.run(spec))
        watcher = asyncio.create_task(
            self._watch_quota(
                self.inputs.attempt_root,
                profile.max_attempt_output_bytes,
                done,
            )
        )
        self._active[attempt_id] = runner
        quota_exceeded = False
        try:
            completed, _ = await asyncio.wait(
                (process_task, watcher), return_when=asyncio.FIRST_COMPLETED
            )
            if watcher in completed and watcher.result():
                quota_exceeded = True
                await runner.cancel(attempt_id)
            result = await process_task
        except asyncio.CancelledError as cancellation:
            if process_task.done() and not process_task.cancelled():
                # The process and its durable receipt won the race. Complete
                # normal decoding/publication rather than inventing a trailing
                # cancellation receipt for work that already finished.
                result = process_task.result()
            else:
                cleanup_error: BaseException | None = None
                cancel_task = asyncio.create_task(runner.cancel(attempt_id))
                try:
                    cancellation_result = await _await_task_during_cancellation(
                        cancel_task
                    )
                    if not cancellation_result.cancelled:
                        process_task.cancel()
                except BaseException as error:
                    cleanup_error = error
                    process_task.cancel()
                try:
                    await _await_task_during_cancellation(process_task)
                except asyncio.CancelledError:
                    pass
                except BaseException as error:
                    if cleanup_error is None:
                        cleanup_error = error
                if cleanup_error is not None:
                    raise cleanup_error from cancellation
                raise
        finally:
            done.set()
            watcher.cancel()
            with suppress(asyncio.CancelledError):
                await _await_task_during_cancellation(watcher)
            self._release_runner(attempt_id, runner)
        if quota_exceeded:
            return self._output_failure(profile, started)
        try:
            if not _quota_allows_result(
                quota_binding,
                self.inputs.output_quota_binding(
                    action_id=action_id,
                    attempt_id=self.inputs.attempt_id,
                    profile_ref=request.tool_profile_ref,
                    root=self.inputs.attempt_root,
                    lease_id=self.inputs.output_quota_lease_id,
                    limit_bytes=profile.max_attempt_output_bytes,
                ),
            ):
                raise ValueError
        except ValueError:
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
        postflight = self._preflight(request, workspace_root, profile)
        if postflight is not None:
            _, code = postflight
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                rules=self._empty_rules("TOOL_FAILURE"),
                gaps=(
                    _gap(
                        code,
                        "FAILED",
                        "CodeQL inputs changed during analysis.",
                    ),
                ),
                errors=(_error(code, "CodeQL inputs changed during analysis."),),
            )
        try:
            if digest_path(working_query_pack) != self.inputs.query_pack_digest:
                raise ValueError
        except (OSError, ValueError):
            return self._observation(
                profile,
                status="FAILED",
                started=started,
                rules=self._empty_rules("TOOL_FAILURE"),
                gaps=(
                    _gap(
                        "CODEQL_QUERY_PACK_DIGEST_MISMATCH",
                        "FAILED",
                        "The attempt-owned CodeQL query pack changed during analysis.",
                    ),
                ),
                errors=(
                    _error(
                        "CODEQL_QUERY_PACK_DIGEST_MISMATCH",
                        "The attempt-owned CodeQL query pack changed during analysis.",
                    ),
                ),
            )
        try:
            _directory_size(self.inputs.attempt_root, profile.max_attempt_output_bytes)
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
                raw,
                self.inputs.rule_catalog,
                self.inputs.selected_rule_ids,
                tuple(item.git_path for item in self.inputs.tracked_files),
                profile.expected_version,
                self.sarif_loader,
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
