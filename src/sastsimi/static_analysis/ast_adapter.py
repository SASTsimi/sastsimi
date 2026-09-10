"""Safe process adapter for parse-only Python AST observations."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, cast

from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.ports.dto import (
    CancellationResult,
    CandidateError,
    CandidateFact,
    CandidateGap,
    CandidateLocation,
    CandidateRelation,
    CandidateRule,
    CandidateSymbol,
    MonotonicActionDeadline,
    ProcessResult,
    ProcessSpec,
    StaticCapabilityObservation,
    StaticToolObservation,
    StaticToolRequest,
    TrackedFile,
)
from sastsimi.ports.workspace import WorkspaceLocatorPort


class ProcessRunner(Protocol):
    attempt_id: str
    output_root: Path
    workspace_root: Path

    async def run(self, spec: ProcessSpec) -> ProcessResult: ...
    async def cancel(self, attempt_id: str) -> CancellationResult: ...


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _link_like(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _closed(value: object, fields: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("STATIC_AST_OUTPUT_INVALID")
    return cast(Mapping[str, Any], value)


def _items(value: object) -> tuple[object, ...]:
    if not isinstance(value, list):
        raise ValueError("STATIC_AST_OUTPUT_INVALID")
    return tuple(value)


def _strings(value: object) -> tuple[str, ...]:
    values = _items(value)
    if any(not isinstance(item, str) or not item for item in values):
        raise ValueError("STATIC_AST_OUTPUT_INVALID")
    return cast(tuple[str, ...], values)


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("STATIC_AST_OUTPUT_INVALID")
    return value


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    return _text(value)


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError("STATIC_AST_OUTPUT_INVALID")
    return value


def _optional_integer(value: object) -> int | None:
    if value is None:
        return None
    return _integer(value)


LOCATION_FIELDS = frozenset(
    {"file_path", "start_line", "start_column", "end_line", "end_column"}
)


def _location(value: object) -> CandidateLocation:
    item = _closed(value, LOCATION_FIELDS)
    location = CandidateLocation(
        file_path=_text(item["file_path"]),
        start_line=_integer(item["start_line"]),
        start_column=_optional_integer(item["start_column"]),
        end_line=_integer(item["end_line"]),
        end_column=_optional_integer(item["end_column"]),
    )
    if (
        location.end_line < location.start_line
        or (location.start_column is None) != (location.end_column is None)
        or (
            location.start_line == location.end_line
            and location.start_column is not None
            and location.end_column is not None
            and location.end_column <= location.start_column
        )
    ):
        raise ValueError("STATIC_AST_OUTPUT_INVALID")
    return location


def _symbols(value: object) -> tuple[CandidateSymbol, ...]:
    fields = frozenset({"source_key", "symbol_kind", "native_kind", "name", "location"})
    result = []
    for raw in _items(value):
        item = _closed(raw, fields)
        result.append(
            CandidateSymbol(
                source_key=_text(item["source_key"]),
                symbol_kind=_text(item["symbol_kind"]),
                native_kind=_optional_text(item["native_kind"]),
                name=_text(item["name"]),
                location=_location(item["location"]),
            )
        )
    keys = [item.source_key for item in result]
    if len(keys) != len(set(keys)):
        raise ValueError("STATIC_AST_OUTPUT_INVALID")
    return tuple(result)


def _facts(value: object) -> tuple[CandidateFact, ...]:
    fields = frozenset(
        {"source_key", "fact_kind", "symbol_source_key", "location", "rule_id"}
    )
    return tuple(
        CandidateFact(
            source_key=_text(item["source_key"]),
            fact_kind=_text(item["fact_kind"]),
            symbol_source_key=_optional_text(item["symbol_source_key"]),
            location=_location(item["location"]),
            rule_id=_optional_text(item["rule_id"]),
        )
        for item in (_closed(raw, fields) for raw in _items(value))
    )


def _relations(value: object) -> tuple[CandidateRelation, ...]:
    fields = frozenset(
        {
            "source_key",
            "relation_kind",
            "from_symbol_source_key",
            "from_location",
            "to_symbol_source_key",
            "to_location",
            "rule_id",
        }
    )
    result = tuple(
        CandidateRelation(
            source_key=_text(item["source_key"]),
            relation_kind=_text(item["relation_kind"]),
            from_symbol_source_key=_optional_text(item["from_symbol_source_key"]),
            from_location=_location(item["from_location"]),
            to_symbol_source_key=_optional_text(item["to_symbol_source_key"]),
            to_location=_location(item["to_location"]),
            rule_id=_optional_text(item["rule_id"]),
        )
        for item in (_closed(raw, fields) for raw in _items(value))
    )
    if any(item.rule_id is not None for item in result):
        raise ValueError("STATIC_AST_OUTPUT_INVALID")
    return result


def _gaps(value: object) -> tuple[CandidateGap, ...]:
    fields = frozenset(
        {
            "stage",
            "code",
            "reason",
            "description",
            "affected_paths",
            "affected_languages",
            "affected_locations",
            "retryable",
        }
    )
    result = []
    for raw in _items(value):
        item = _closed(raw, fields)
        retryable = item["retryable"]
        if not isinstance(retryable, bool):
            raise ValueError("STATIC_AST_OUTPUT_INVALID")
        result.append(
            CandidateGap(
                stage=_text(item["stage"]),
                code=_text(item["code"]),
                reason=_text(item["reason"]),
                description=_text(item["description"]),
                affected_paths=_strings(item["affected_paths"]),
                affected_languages=_strings(item["affected_languages"]),
                affected_locations=tuple(
                    _location(location)
                    for location in _items(item["affected_locations"])
                ),
                retryable=retryable,
            )
        )
    return tuple(result)


def _errors(value: object) -> tuple[CandidateError, ...]:
    fields = frozenset({"stage", "code", "safe_message", "retryable"})
    result = []
    for raw in _items(value):
        item = _closed(raw, fields)
        retryable = item["retryable"]
        if not isinstance(retryable, bool):
            raise ValueError("STATIC_AST_OUTPUT_INVALID")
        result.append(
            CandidateError(
                stage=_text(item["stage"]),
                code=_text(item["code"]),
                safe_message=_text(item["safe_message"]),
                retryable=retryable,
            )
        )
    return tuple(result)


class PythonAstProcessAdapter:
    """Parse a fixed tracked-file manifest through an isolated Python worker."""

    def __init__(
        self,
        *,
        executable: Path,
        worker_path: Path,
        process_runner: ProcessRunner,
        workspace_locator: WorkspaceLocatorPort,
        tracked_files: Sequence[TrackedFile],
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        if _link_like(executable) or _link_like(worker_path):
            raise ValueError("STATIC_AST_TRUSTED_PATH_INVALID")
        self.executable = executable.resolve(strict=True)
        self.worker_path = worker_path.resolve(strict=True)
        if not self.executable.is_file() or not self.worker_path.is_file():
            raise ValueError("STATIC_AST_TRUSTED_PATH_INVALID")
        paths = [item.git_path for item in tracked_files]
        if len(paths) != len(set(paths)):
            raise ValueError("STATIC_AST_MANIFEST_DUPLICATE")
        self.process_runner = process_runner
        self.workspace_locator = workspace_locator
        self.tracked_files = {item.git_path: item for item in tracked_files}
        self.monotonic_ns = monotonic_ns

    async def probe(
        self, profile: StaticToolProfile, deadline: MonotonicActionDeadline
    ) -> StaticCapabilityObservation:
        digest = _digest(self.executable)
        if not self._profile_tuple(profile) or digest != profile.executable_sha256:
            return self._capability(
                profile, digest, None, "STATIC_AST_PROFILE_MISMATCH"
            )
        spec = ProcessSpec(
            invocation_id=f"{deadline.action_id}:ast-probe",
            attempt_id=self.process_runner.attempt_id,
            argv=(
                str(self.executable),
                "-I",
                "-S",
                "-c",
                "import platform;print(platform.python_version())",
            ),
            cwd=self.process_runner.workspace_root,
            env=(),
            attempt_output_dir=self.process_runner.output_root,
            stdout_limit_bytes=profile.stdout_limit_bytes,
            stderr_limit_bytes=profile.stderr_limit_bytes,
            attempt_output_limit_bytes=profile.max_attempt_output_bytes,
            deadline=deadline,
        )
        result = await self.process_runner.run(spec)
        version = result.stdout.decode("utf-8", errors="replace").strip() or None
        reason = None
        if (
            result.outcome != "SUCCEEDED"
            or result.stdout_truncated
            or version != profile.expected_version
        ):
            reason = "STATIC_AST_CAPABILITY_UNAVAILABLE"
        return self._capability(profile, digest, version, reason)

    async def execute(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticToolObservation:
        started = self.monotonic_ns() // 1_000_000
        self._validate_execution(request, workspace_root, profile, deadline)
        await self.workspace_locator.assert_unchanged(request.workspace, deadline)
        worker_paths, preflight_gaps = self._worker_manifest(
            request.action.file_paths, workspace_root
        )
        if not worker_paths:
            await self.workspace_locator.assert_unchanged(request.workspace, deadline)
            return self._observation(
                profile=profile,
                status="SKIPPED",
                raw=None,
                analyzed=(),
                skipped=tuple(
                    sorted(
                        {path for gap in preflight_gaps for path in gap.affected_paths}
                    )
                ),
                symbols=(),
                facts=(),
                relations=(),
                gaps=preflight_gaps,
                errors=(),
                started=started,
            )
        spec = ProcessSpec(
            invocation_id=f"{request.action.action_id}:python-ast",
            attempt_id=self.process_runner.attempt_id,
            argv=(
                str(self.executable),
                "-I",
                "-S",
                str(self.worker_path),
                *worker_paths,
            ),
            cwd=workspace_root,
            env=(),
            attempt_output_dir=self.process_runner.output_root,
            stdout_limit_bytes=profile.stdout_limit_bytes,
            stderr_limit_bytes=profile.stderr_limit_bytes,
            attempt_output_limit_bytes=profile.max_attempt_output_bytes,
            deadline=deadline,
        )
        result = await self.process_runner.run(spec)
        if result.outcome != "SUCCEEDED" or result.stdout_truncated:
            await self.workspace_locator.assert_unchanged(request.workspace, deadline)
            return self._process_failure(profile, result, preflight_gaps, started)
        try:
            decoded = self._decode(result.stdout)
        except (UnicodeError, json.JSONDecodeError, KeyError, ValueError, TypeError):
            await self.workspace_locator.assert_unchanged(request.workspace, deadline)
            return self._decode_failure(profile, result.stdout, preflight_gaps, started)
        if decoded["parser_version"] != profile.expected_version:
            await self.workspace_locator.assert_unchanged(request.workspace, deadline)
            return self._decode_failure(profile, result.stdout, preflight_gaps, started)
        await self.workspace_locator.assert_unchanged(request.workspace, deadline)
        gaps = (*preflight_gaps, *cast(tuple[CandidateGap, ...], decoded["gaps"]))
        analyzed = cast(tuple[str, ...], decoded["analyzed_paths"])
        skipped = tuple(
            sorted(
                {
                    *cast(tuple[str, ...], decoded["skipped_paths"]),
                    *(path for gap in preflight_gaps for path in gap.affected_paths),
                }
            )
        )
        status = "SUCCEEDED" if not gaps else "PARTIAL"
        return self._observation(
            profile=profile,
            status=status,
            raw=result.stdout,
            analyzed=analyzed,
            skipped=skipped,
            symbols=cast(tuple[CandidateSymbol, ...], decoded["symbols"]),
            facts=cast(tuple[CandidateFact, ...], decoded["facts"]),
            relations=cast(tuple[CandidateRelation, ...], decoded["relations"]),
            gaps=gaps,
            errors=cast(tuple[CandidateError, ...], decoded["errors"]),
            started=started,
        )

    async def cancel(self, attempt_id: str) -> CancellationResult:
        return await self.process_runner.cancel(attempt_id)

    def _validate_execution(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> None:
        if not isinstance(request.action.meta, RecordMeta):
            raise ValueError("STATIC_AST_EXECUTION_MISMATCH")
        attempt_id = request.action.meta.attempt_id
        located = self.workspace_locator.root_for(request.workspace).resolve(
            strict=True
        )
        supplied = workspace_root.resolve(strict=True)
        if (
            not self._profile_tuple(profile)
            or _digest(self.executable) != profile.executable_sha256
            or attempt_id is None
            or str(attempt_id) != self.process_runner.attempt_id
            or str(request.action.action_id) != deadline.action_id
            or request.action.tool_name != "AST"
            or supplied != located
            or _link_like(workspace_root)
        ):
            raise ValueError("STATIC_AST_EXECUTION_MISMATCH")

    def _worker_manifest(
        self, requested_paths: Sequence[str], workspace_root: Path
    ) -> tuple[tuple[str, ...], tuple[CandidateGap, ...]]:
        worker_paths = []
        gaps = []
        root = workspace_root.resolve(strict=True)
        for path in sorted(set(requested_paths)):
            if path not in self.tracked_files:
                gaps.append(self._gap("STATIC_MANIFEST_MISMATCH", "BLOCKED", path))
                continue
            if not path.endswith(".py"):
                gaps.append(
                    self._gap("STATIC_LANGUAGE_UNSUPPORTED", "UNSUPPORTED", path)
                )
                continue
            pure = PurePosixPath(path)
            candidate = root.joinpath(*pure.parts)
            if (
                not path
                or "\\" in path
                or pure.is_absolute()
                or any(part in {"", ".", ".."} for part in pure.parts)
                or _link_like(candidate)
            ):
                gaps.append(self._gap("STATIC_PATH_UNSAFE", "BLOCKED", path))
                continue
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                gaps.append(self._gap("STATIC_PATH_UNSAFE", "BLOCKED", path))
                continue
            if not _inside(resolved, root) or not resolved.is_file():
                gaps.append(self._gap("STATIC_PATH_UNSAFE", "BLOCKED", path))
                continue
            worker_paths.append(path)
        return tuple(worker_paths), tuple(gaps)

    @staticmethod
    def _gap(code: str, reason: str, path: str) -> CandidateGap:
        return CandidateGap(
            stage="STATIC_ANALYSIS",
            code=code,
            reason=reason,
            description="File was not passed to the Python AST worker.",
            affected_paths=(path,),
            affected_languages=("Python",),
            affected_locations=(),
            retryable=False,
        )

    @staticmethod
    def _profile_tuple(profile: StaticToolProfile) -> bool:
        return (
            profile.adapter_key,
            profile.tool_name,
            profile.tool_kind,
        ) == ("PYTHON_AST", "AST", "STRUCTURE")

    @staticmethod
    def _capability(
        profile: StaticToolProfile,
        digest: str | None,
        version: str | None,
        reason: str | None,
    ) -> StaticCapabilityObservation:
        return StaticCapabilityObservation(
            available=reason is None,
            tool_name="AST",
            tool_kind="STRUCTURE",
            executable_key=profile.executable_key,
            observed_executable_sha256=digest,
            observed_version=version,
            expected_version=profile.expected_version,
            reason_code=reason,
        )

    def _decode(self, raw: bytes) -> Mapping[str, object]:
        value = json.loads(raw.decode("utf-8"))
        fields = frozenset(
            {
                "schema_version",
                "parser_version",
                "files",
                "analyzed_paths",
                "skipped_paths",
                "symbols",
                "facts",
                "relations",
                "gaps",
                "errors",
            }
        )
        item = _closed(value, fields)
        if item["schema_version"] != 1:
            raise ValueError("STATIC_AST_OUTPUT_INVALID")
        return {
            "parser_version": _text(item["parser_version"]),
            "files": _strings(item["files"]),
            "analyzed_paths": _strings(item["analyzed_paths"]),
            "skipped_paths": _strings(item["skipped_paths"]),
            "symbols": _symbols(item["symbols"]),
            "facts": _facts(item["facts"]),
            "relations": _relations(item["relations"]),
            "gaps": _gaps(item["gaps"]),
            "errors": _errors(item["errors"]),
        }

    def _process_failure(
        self,
        profile: StaticToolProfile,
        result: ProcessResult,
        existing_gaps: tuple[CandidateGap, ...],
        started: int,
    ) -> StaticToolObservation:
        code = {
            "TIMED_OUT": "STATIC_AST_TIMEOUT",
            "CANCELLED": "STATIC_AST_CANCELLED",
        }.get(result.outcome, "STATIC_AST_PROCESS_FAILED")
        reason = "TIMEOUT" if result.outcome == "TIMED_OUT" else "FAILED"
        gap = self._gap(code, reason, "<python-manifest>")
        return self._observation(
            profile=profile,
            status="SKIPPED" if result.outcome == "CANCELLED" else "FAILED",
            raw=None,
            analyzed=(),
            skipped=tuple(sorted(self.tracked_files)),
            symbols=(),
            facts=(),
            relations=(),
            gaps=(*existing_gaps, gap),
            errors=(),
            started=started,
        )

    def _decode_failure(
        self,
        profile: StaticToolProfile,
        raw: bytes,
        existing_gaps: tuple[CandidateGap, ...],
        started: int,
    ) -> StaticToolObservation:
        return self._observation(
            profile=profile,
            status="FAILED",
            raw=raw,
            analyzed=(),
            skipped=tuple(sorted(self.tracked_files)),
            symbols=(),
            facts=(),
            relations=(),
            gaps=existing_gaps,
            errors=(
                CandidateError(
                    stage="STATIC_ANALYSIS",
                    code="STATIC_AST_OUTPUT_INVALID",
                    safe_message=(
                        "Python AST worker returned unusable structured output."
                    ),
                    retryable=False,
                ),
            ),
            started=started,
        )

    def _observation(
        self,
        *,
        profile: StaticToolProfile,
        status: str,
        raw: bytes | None,
        analyzed: tuple[str, ...],
        skipped: tuple[str, ...],
        symbols: tuple[CandidateSymbol, ...],
        facts: tuple[CandidateFact, ...],
        relations: tuple[CandidateRelation, ...],
        gaps: tuple[CandidateGap, ...],
        errors: tuple[CandidateError, ...],
        started: int,
    ) -> StaticToolObservation:
        valid_statuses = {"SUCCEEDED", "PARTIAL", "FAILED", "SKIPPED"}
        if status not in valid_statuses:
            raise ValueError("STATIC_AST_STATUS_INVALID")
        return StaticToolObservation(
            tool_name="AST",
            tool_version=profile.expected_version,
            tool_kind="STRUCTURE",
            status=cast(Any, status),
            raw_output=raw,
            raw_media_type="application/json" if raw is not None else None,
            analyzed_paths=analyzed,
            skipped_paths=skipped,
            analyzed_languages=("Python",) if analyzed else (),
            skipped_languages=("Python",) if skipped else (),
            notes=("Parse-only Python AST; no vulnerability verdict.",),
            selected_rule_packs=(),
            rules=cast(tuple[CandidateRule, ...], ()),
            symbols=symbols,
            facts=facts,
            relations=relations,
            gaps=gaps,
            errors=errors,
            started_monotonic_ms=started,
            finished_monotonic_ms=self.monotonic_ns() // 1_000_000,
        )
