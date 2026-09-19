"""Attempt-bound real static adapters built after repository preparation."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile
from sastsimi.ports.dto import (
    CancellationResult,
    CandidateError,
    CandidateGap,
    CandidateRule,
    MonotonicActionDeadline,
    PrebuiltCodeQLDatabase,
    StaticCapabilityObservation,
    StaticOutputQuotaBinding,
    StaticRuleMapping,
    StaticToolObservation,
    StaticToolRequest,
    TrackedFile,
)
from sastsimi.ports.production_analysis import ProductionAnalyzeUnavailable
from sastsimi.ports.static_tool import (
    PrebuiltCodeQLDatabasePort,
    StaticProcessAdapter,
)
from sastsimi.ports.static_tool import (
    ProductionStaticOutputQuotaPort as ProductionStaticOutputQuotaPort,
)
from sastsimi.ports.static_tool import StaticOutputPurpose as StaticOutputPurpose
from sastsimi.ports.workspace import WorkspaceLocatorPort
from sastsimi.static_analysis.ast_adapter import PythonAstProcessAdapter
from sastsimi.static_analysis.codeql_adapter import (
    CodeQLExecutionInputs,
    CodeQLProcessAdapter,
    digest_path,
)
from sastsimi.static_analysis.open_grep_adapter import (
    OpenGrepExecutionInputs,
    OpenGrepProcessAdapter,
)
from sastsimi.static_analysis.process import AttemptOutputBudget, SafeProcessRunner

if TYPE_CHECKING:
    from sastsimi.orchestration.static_adapter_context import StaticAdapterBuildContext

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_PYTHON_SUFFIXES = frozenset({".py", ".pyi"})
_JAVASCRIPT_SUFFIXES = frozenset(
    {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
)

type CodeQLLanguage = Literal["python", "javascript-typescript"]


@dataclass(frozen=True, slots=True)
class StaticAttemptAdapterDispatch:
    """Durable projection fixing one live attempt to one approved adapter."""

    action_id: str
    attempt_id: str
    adapter_key: str
    tool_profile_ref: HostConfigurationRef
    state: Literal["PREPARED", "DISPATCHED", "RETURNED"]


type StaticAttemptDispatchReader = Callable[[str], StaticAttemptAdapterDispatch | None]


class StaticAdapterCancellationRouter:
    """Cancel only the adapter named by an exact durable dispatch projection."""

    def __init__(
        self,
        *,
        adapters: Mapping[str, StaticProcessAdapter],
        profiles: Mapping[str, StaticToolProfile],
        dispatch_for_attempt: StaticAttemptDispatchReader,
    ) -> None:
        self._adapters = dict(adapters)
        self._profiles = dict(profiles)
        self._dispatch_for_attempt = dispatch_for_attempt

    def validate_cancellation(self, attempt_id: str) -> None:
        self._resolve(attempt_id)

    async def cancel(self, attempt_id: str) -> CancellationResult:
        try:
            adapter, _profile = self._resolve(attempt_id)
        except ValueError:
            return CancellationResult(False, "STATIC_DISPATCH_NOT_ACTIVE")
        return await adapter.cancel(attempt_id)

    def _resolve(
        self, attempt_id: str
    ) -> tuple[StaticProcessAdapter, StaticToolProfile]:
        dispatch = self._dispatch_for_attempt(attempt_id)
        if dispatch is None or dispatch.state != "DISPATCHED":
            raise ValueError("STATIC_CANCELLATION_DISPATCH_NOT_ACTIVE")
        try:
            adapter = self._adapters[dispatch.adapter_key]
            profile = self._profiles[dispatch.adapter_key]
        except KeyError as error:
            raise ValueError("STATIC_CANCELLATION_ADAPTER_NOT_EXACT") from error
        if (
            not dispatch.action_id
            or dispatch.attempt_id != attempt_id
            or dispatch.adapter_key != profile.adapter_key
            or dispatch.tool_profile_ref != reference(profile)
        ):
            raise ValueError("STATIC_CANCELLATION_ADAPTER_NOT_EXACT")
        return adapter, profile


@dataclass(frozen=True, slots=True)
class _StaticMaterialFile:
    relative_path: str
    content_sha256: str


@dataclass(frozen=True, slots=True)
class _CodeQLMaterial:
    query_pack_sha256: str
    files: tuple[_StaticMaterialFile, ...]


@dataclass(frozen=True, slots=True)
class _StaticMaterialManifest:
    opengrep_config_sha256: str | None
    codeql: _CodeQLMaterial | None


@dataclass(frozen=True, slots=True)
class _RuleMaterial:
    mappings: tuple[StaticRuleMapping, ...]
    selected_rule_ids: tuple[str, ...]
    selected_rule_packs: tuple[str, ...]


def classify_codeql_language(paths: tuple[str, ...]) -> CodeQLLanguage:
    """Resolve only a homogeneous Python or JavaScript/TypeScript request."""

    suffixes = {PurePosixPath(path).suffix.lower() for path in paths}
    if suffixes and suffixes <= _PYTHON_SUFFIXES:
        return "python"
    if suffixes and suffixes <= _JAVASCRIPT_SUFFIXES:
        return "javascript-typescript"
    raise ValueError("CODEQL_LANGUAGE_SCOPE_AMBIGUOUS")


def codeql_database_create_argv(
    *,
    executable: Path,
    database_root: Path,
    workspace_root: Path,
    language: CodeQLLanguage,
) -> tuple[str, ...]:
    """Reject the retired host database-creation API before constructing argv."""

    raise ProductionAnalyzeUnavailable(
        "PRODUCTION_CODEQL_HOST_DATABASE_CREATE_FORBIDDEN"
    )


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def _payload_for(evidence: Mapping[str, bytes], digest: str, code: str) -> bytes:
    try:
        payload = evidence[digest]
    except KeyError:
        raise ValueError(code) from None
    if hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError(code)
    return payload


def _json_for(evidence: Mapping[str, bytes], digest: str, code: str) -> object:
    try:
        return json.loads(_payload_for(evidence, digest, code))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(code) from error


def _parse_material_manifest(
    evidence: Mapping[str, bytes], digest: str
) -> _StaticMaterialManifest:
    value = _json_for(evidence, digest, "STATIC_MATERIAL_MANIFEST_INVALID")
    if not isinstance(value, dict) or set(value) != {"schema_version", "tools"}:
        raise ValueError("STATIC_MATERIAL_MANIFEST_INVALID")
    tools = value.get("tools")
    if value.get("schema_version") != 1 or not isinstance(tools, dict):
        raise ValueError("STATIC_MATERIAL_MANIFEST_INVALID")
    if not set(tools) <= {"OPENGREP", "CODEQL"}:
        raise ValueError("STATIC_MATERIAL_MANIFEST_INVALID")
    opengrep_digest: str | None = None
    opengrep = tools.get("OPENGREP")
    if opengrep is not None:
        if not isinstance(opengrep, dict) or set(opengrep) != {"config_sha256"}:
            raise ValueError("STATIC_MATERIAL_MANIFEST_INVALID")
        raw_digest = opengrep.get("config_sha256")
        if not isinstance(raw_digest, str) or len(raw_digest) != 64:
            raise ValueError("STATIC_MATERIAL_MANIFEST_INVALID")
        _payload_for(evidence, raw_digest, "OPENGREP_CONFIG_EVIDENCE_INVALID")
        opengrep_digest = raw_digest
    codeql_material: _CodeQLMaterial | None = None
    codeql = tools.get("CODEQL")
    if codeql is not None:
        if not isinstance(codeql, dict) or set(codeql) != {
            "query_pack_sha256",
            "files",
        }:
            raise ValueError("STATIC_MATERIAL_MANIFEST_INVALID")
        query_digest = codeql.get("query_pack_sha256")
        files = codeql.get("files")
        if (
            not isinstance(query_digest, str)
            or len(query_digest) != 64
            or not isinstance(files, list)
            or not files
        ):
            raise ValueError("STATIC_MATERIAL_MANIFEST_INVALID")
        parsed_files: list[_StaticMaterialFile] = []
        for item in files:
            if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
                raise ValueError("STATIC_MATERIAL_MANIFEST_INVALID")
            path = item.get("path")
            file_digest = item.get("sha256")
            if (
                not isinstance(path, str)
                or not isinstance(file_digest, str)
                or len(file_digest) != 64
            ):
                raise ValueError("STATIC_MATERIAL_MANIFEST_INVALID")
            _safe_relative_material_path(path)
            if path == "sastsimi-selection.json":
                raise ValueError("STATIC_MATERIAL_MANIFEST_INVALID")
            _payload_for(evidence, file_digest, "CODEQL_QUERY_EVIDENCE_INVALID")
            parsed_files.append(_StaticMaterialFile(path, file_digest))
        paths = tuple(item.relative_path for item in parsed_files)
        if len(paths) != len(set(paths)):
            raise ValueError("STATIC_MATERIAL_MANIFEST_INVALID")
        codeql_material = _CodeQLMaterial(query_digest, tuple(parsed_files))
    return _StaticMaterialManifest(opengrep_digest, codeql_material)


def _parse_rule_material(
    context: StaticAdapterBuildContext, tool: str
) -> _RuleMaterial:
    closure = context.rule_closures[tool]
    catalog = _json_for(
        context.evidence,
        closure.catalog_sha256,
        "STATIC_RULE_CATALOG_EVIDENCE_INVALID",
    )
    selection = _json_for(
        context.evidence,
        closure.selection_sha256,
        "STATIC_RULE_SELECTION_EVIDENCE_INVALID",
    )
    mapping = _json_for(
        context.evidence,
        closure.mapping_sha256,
        "STATIC_RULE_MAPPING_EVIDENCE_INVALID",
    )
    if (
        not isinstance(catalog, dict)
        or set(catalog) != {"schema_version", "rule_ids"}
        or catalog.get("schema_version") != 1
        or not isinstance(catalog.get("rule_ids"), list)
        or not all(isinstance(item, str) for item in catalog["rule_ids"])
        or tuple(catalog["rule_ids"]) != closure.catalog_rule_ids
    ):
        raise ValueError("STATIC_RULE_CATALOG_EVIDENCE_INVALID")
    if (
        not isinstance(selection, dict)
        or set(selection) != {"schema_version", "rule_ids", "rule_packs"}
        or selection.get("schema_version") != 1
        or not isinstance(selection.get("rule_ids"), list)
        or not all(isinstance(item, str) for item in selection["rule_ids"])
        or tuple(selection["rule_ids"]) != closure.selected_rule_ids
        or not isinstance(selection.get("rule_packs"), list)
        or not all(isinstance(item, str) for item in selection["rule_packs"])
        or len(selection["rule_packs"]) != len(set(selection["rule_packs"]))
    ):
        raise ValueError("STATIC_RULE_SELECTION_EVIDENCE_INVALID")
    if (
        not isinstance(mapping, dict)
        or set(mapping) != {"schema_version", "mappings"}
        or mapping.get("schema_version") != 1
        or not isinstance(mapping.get("mappings"), list)
    ):
        raise ValueError("STATIC_RULE_MAPPING_EVIDENCE_INVALID")
    try:
        mappings = tuple(
            StaticRuleMapping(
                rule_id=item["rule_id"],
                result_fact_kind=item["result_fact_kind"],
                flow_start_fact_kind=item["flow_start_fact_kind"],
                requires_code_flow=item["requires_code_flow"],
            )
            for item in mapping["mappings"]
            if isinstance(item, dict)
            and set(item)
            == {
                "rule_id",
                "result_fact_kind",
                "flow_start_fact_kind",
                "requires_code_flow",
            }
        )
    except (KeyError, TypeError) as error:
        raise ValueError("STATIC_RULE_MAPPING_EVIDENCE_INVALID") from error
    if len(mappings) != len(mapping["mappings"]) or mappings != closure.mappings:
        raise ValueError("STATIC_RULE_MAPPING_EVIDENCE_INVALID")
    return _RuleMaterial(
        mappings=mappings,
        selected_rule_ids=closure.selected_rule_ids,
        selected_rule_packs=tuple(cast(list[str], selection["rule_packs"])),
    )


def _safe_relative_material_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or path.as_posix() != value
        or ".." in path.parts
        or "." in path.parts
        or "\\" in value
    ):
        raise ValueError("STATIC_MATERIAL_PATH_INVALID")
    return path


def _materialize_file(
    root: Path, relative: str, payload: bytes, expected_digest: str
) -> Path:
    if hashlib.sha256(payload).hexdigest() != expected_digest:
        raise ValueError("STATIC_MATERIAL_DIGEST_MISMATCH")
    path = root.joinpath(*_safe_relative_material_path(relative).parts)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = _safe_existing_directory(path.parent, "STATIC_MATERIAL_ROOT_INVALID")
    try:
        path.resolve(strict=False).relative_to(parent)
        with path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        pass
    except OSError as error:
        raise ValueError("STATIC_MATERIAL_WRITE_FAILED") from error
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or _is_link_like(path)
            or _digest(path) != expected_digest
        ):
            raise ValueError
    except (OSError, ValueError) as error:
        raise ValueError("STATIC_MATERIAL_DIGEST_MISMATCH") from error
    return path.resolve(strict=True)


def _materialize_codeql_query_pack(
    *,
    root: Path,
    material: _CodeQLMaterial,
    evidence: Mapping[str, bytes],
    rules: _RuleMaterial,
) -> Path:
    # ``root`` is already keyed by the immutable analysis-config digest. Keep
    # the child name short enough for native Windows path limits.
    pack = _safe_root(root, "codeql/query-pack")
    for item in material.files:
        _materialize_file(
            pack,
            item.relative_path,
            _payload_for(
                evidence,
                item.content_sha256,
                "CODEQL_QUERY_EVIDENCE_INVALID",
            ),
            item.content_sha256,
        )
    selection = canonical_bytes(
        {
            "schema_version": 1,
            "rule_ids": list(rules.selected_rule_ids),
            "rule_packs": list(rules.selected_rule_packs),
        }
    )
    _materialize_file(
        pack,
        "sastsimi-selection.json",
        selection,
        hashlib.sha256(selection).hexdigest(),
    )
    if digest_path(pack) != material.query_pack_sha256:
        raise ValueError("CODEQL_QUERY_PACK_DIGEST_MISMATCH")
    return pack


def _is_link_like(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _safe_existing_directory(path: Path, error_code: str) -> Path:
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ValueError(error_code) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or _is_link_like(path)
        or int(getattr(info, "st_file_attributes", 0)) & _FILE_ATTRIBUTE_REPARSE_POINT
        or resolved != path.absolute()
    ):
        raise ValueError(error_code)
    return resolved


def _safe_root(data_dir: Path, relative: str) -> Path:
    base = _safe_existing_directory(data_dir, "STATIC_ATTEMPT_ROOT_INVALID")
    target = base.joinpath(*relative.split("/"))
    try:
        target.relative_to(base)
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
    except (OSError, ValueError) as error:
        raise ValueError("STATIC_ATTEMPT_ROOT_INVALID") from error
    return _safe_existing_directory(target, "STATIC_ATTEMPT_ROOT_INVALID")


def _bound_attempt_root(
    root: Path,
    *,
    tool: str,
    workspace_id: str,
    commit_id: str,
    action_id: str,
    attempt_id: str,
) -> Path:
    binding = {
        "schema_version": 1,
        "tool": tool,
        "workspace_id": workspace_id,
        "commit_id": commit_id,
        "action_id": action_id,
        "attempt_id": attempt_id,
    }
    key = hashlib.sha256(canonical_bytes(binding)).hexdigest()
    attempt_root = root / tool.lower() / key
    try:
        attempt_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        exact = _safe_existing_directory(attempt_root, "STATIC_ATTEMPT_ROOT_INVALID")
        marker = exact / "sastsimi-attempt.json"
        payload = canonical_bytes(binding)
        try:
            with marker.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            if marker.read_bytes() != payload:
                raise ValueError("STATIC_ATTEMPT_BINDING_MISMATCH") from None
        marker_info = marker.lstat()
        if (
            not stat.S_ISREG(marker_info.st_mode)
            or marker_info.st_nlink != 1
            or _is_link_like(marker)
        ):
            raise ValueError("STATIC_ATTEMPT_BINDING_MISMATCH")
    except OSError as error:
        raise ValueError("STATIC_ATTEMPT_ROOT_INVALID") from error
    return exact


def _runner(
    *,
    action_id: str,
    attempt_id: str,
    workspace_root: Path,
    output_root: Path,
    executable: Path,
    output_limit_bytes: int,
) -> SafeProcessRunner:
    return SafeProcessRunner(
        action_id=action_id,
        attempt_id=attempt_id,
        workspace_root=workspace_root,
        output_root=output_root,
        executable=executable,
        output_budget=AttemptOutputBudget(
            attempt_id=attempt_id,
            limit_bytes=output_limit_bytes,
        ),
    )


class _LazyPythonAstAdapter:
    def __init__(
        self,
        *,
        executable: Path,
        worker_path: Path,
        worker_sha256: str,
        output_root: Path,
        workspace_locator: WorkspaceLocatorPort,
        tracked_files_for: Callable[[CodeWorkspace], tuple[TrackedFile, ...]],
    ) -> None:
        self.executable = executable
        self._worker_path = worker_path
        self._worker_sha256 = worker_sha256
        self._output_root = output_root
        self._workspace_locator = workspace_locator
        self._tracked_files_for = tracked_files_for
        self._active: dict[str, PythonAstProcessAdapter] = {}

    def _verify_static_inputs(self, profile: StaticToolProfile) -> None:
        try:
            executable = self.executable.resolve(strict=True)
            worker = self._worker_path.resolve(strict=True)
        except OSError as error:
            raise ValueError("STATIC_AST_APPROVED_INPUT_CHANGED") from error
        if (
            not executable.is_file()
            or not worker.is_file()
            or _digest(executable) != profile.executable_sha256
            or _digest(worker) != self._worker_sha256
            or profile.adapter_key != "PYTHON_AST"
            or profile.tool_name != "AST"
        ):
            raise ValueError("STATIC_AST_APPROVED_INPUT_CHANGED")

    def _new_lower(
        self,
        *,
        workspace: CodeWorkspace,
        workspace_root: Path,
        profile: StaticToolProfile,
        action_id: str,
        attempt_id: str,
        tracked_files: tuple[TrackedFile, ...],
    ) -> PythonAstProcessAdapter:
        attempt_root = _bound_attempt_root(
            self._output_root,
            tool="AST",
            workspace_id=str(workspace.workspace_id),
            commit_id=str(workspace.commit_id),
            action_id=action_id,
            attempt_id=attempt_id,
        )
        process = _runner(
            action_id=action_id,
            attempt_id=attempt_id,
            workspace_root=workspace_root,
            output_root=attempt_root,
            executable=self.executable,
            output_limit_bytes=profile.max_attempt_output_bytes,
        )

        def probe_runner_factory(
            *,
            action_id: str,
            attempt_id: str,
            workspace_root: Path,
            output_root: Path,
            executable: Path,
            output_limit_bytes: int,
        ) -> SafeProcessRunner:
            return _runner(
                action_id=action_id,
                attempt_id=attempt_id,
                workspace_root=workspace_root,
                output_root=output_root,
                executable=executable,
                output_limit_bytes=output_limit_bytes,
            )

        return PythonAstProcessAdapter(
            executable=self.executable,
            worker_path=self._worker_path,
            process_runner=process,
            probe_runner_factory=probe_runner_factory,
            probe_root=_safe_root(self._output_root, "probes/ast"),
            workspace_locator=self._workspace_locator,
            tracked_files=tracked_files,
        )

    async def probe(
        self,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticCapabilityObservation:
        self._verify_static_inputs(profile)
        probe_workspace = _safe_root(self._output_root, "probe-shell/ast/workspace")
        probe_output = _safe_root(self._output_root, "probe-shell/ast/output")
        lower = PythonAstProcessAdapter(
            executable=self.executable,
            worker_path=self._worker_path,
            process_runner=_runner(
                action_id=deadline.action_id,
                attempt_id=deadline.action_id,
                workspace_root=probe_workspace,
                output_root=probe_output,
                executable=self.executable,
                output_limit_bytes=profile.max_attempt_output_bytes,
            ),
            probe_runner_factory=_runner,
            probe_root=_safe_root(self._output_root, "probes/ast"),
            workspace_locator=self._workspace_locator,
            tracked_files=(),
        )
        self._active[deadline.action_id] = lower
        try:
            return await lower.probe(profile, deadline)
        finally:
            self._active.pop(deadline.action_id, None)

    async def execute(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticToolObservation:
        self._verify_static_inputs(profile)
        action_meta = request.action.meta
        if (
            not isinstance(action_meta, RecordMeta)
            or action_meta.attempt_id is None
            or request.tool_profile_ref != reference(profile)
            or workspace_root.resolve(strict=True)
            != self._workspace_locator.root_for(request.workspace).resolve(strict=True)
        ):
            raise ValueError("STATIC_AST_REQUEST_BINDING_INVALID")
        attempt_id = str(action_meta.attempt_id)
        if attempt_id in self._active:
            raise ValueError("STATIC_AST_ATTEMPT_ALREADY_ACTIVE")
        resolver = self._tracked_files_for
        tracked = resolver(request.workspace)
        if not isinstance(tracked, tuple) or any(
            not isinstance(item, TrackedFile) for item in tracked
        ):
            raise ValueError("STATIC_MANIFEST_RESOLVER_INVALID")
        lower = self._new_lower(
            workspace=request.workspace,
            workspace_root=workspace_root,
            profile=profile,
            action_id=str(request.action.action_id),
            attempt_id=attempt_id,
            tracked_files=tracked,
        )
        self._active[attempt_id] = lower
        try:
            return await lower.execute(request, workspace_root, profile, deadline)
        finally:
            self._active.pop(attempt_id, None)

    async def cancel(self, attempt_id: str) -> CancellationResult:
        active = self._active.get(attempt_id)
        if active is None:
            return CancellationResult(False, "Attempt is not active")
        return await active.cancel(attempt_id)


class _LazyOpenGrepAdapter:
    def __init__(
        self,
        *,
        executable: Path,
        config_path: Path,
        config_digest: str,
        route_analysis_config_ref: StoredDataRef,
        route_rule_catalog_ref: StoredDataRef,
        rule_material: _RuleMaterial,
        output_root: Path,
        workspace_locator: WorkspaceLocatorPort,
        tracked_files_for: Callable[[CodeWorkspace], tuple[TrackedFile, ...]],
    ) -> None:
        self.executable = executable
        self._config_path = config_path
        self._config_digest = config_digest
        self._analysis_config_ref = route_analysis_config_ref
        self._rule_catalog_ref = route_rule_catalog_ref
        self._rules = rule_material
        self._output_root = output_root
        self._workspace_locator = workspace_locator
        self._tracked_files_for = tracked_files_for
        self._active: dict[str, OpenGrepProcessAdapter] = {}

    def _verify(self, profile: StaticToolProfile) -> None:
        try:
            executable = self.executable.resolve(strict=True)
            config = self._config_path.resolve(strict=True)
        except OSError as error:
            raise ValueError("OPENGREP_APPROVED_INPUT_CHANGED") from error
        if (
            profile.adapter_key != "OPENGREP"
            or profile.tool_name != "OPENGREP"
            or not executable.is_file()
            or _digest(executable) != profile.executable_sha256
            or not config.is_file()
            or _digest(config) != self._config_digest
        ):
            raise ValueError("OPENGREP_APPROVED_INPUT_CHANGED")

    def _lower(
        self,
        *,
        profile: StaticToolProfile,
        tracked: tuple[TrackedFile, ...],
        action_id: str,
        attempt_id: str,
        workspace: CodeWorkspace,
    ) -> OpenGrepProcessAdapter:
        attempt_root = _bound_attempt_root(
            self._output_root,
            tool="OPENGREP",
            workspace_id=str(workspace.workspace_id),
            commit_id=str(workspace.commit_id),
            action_id=action_id,
            attempt_id=attempt_id,
        )
        return OpenGrepProcessAdapter(
            executable=self.executable,
            executable_key=str(profile.executable_key),
            inputs=OpenGrepExecutionInputs(
                config_path=self._config_path,
                config_digest=self._config_digest,
                analysis_config_ref=self._analysis_config_ref,
                rule_catalog_ref=self._rule_catalog_ref,
                rule_catalog=self._rules.mappings,
                selected_rule_ids=self._rules.selected_rule_ids,
                selected_rule_packs=self._rules.selected_rule_packs,
                tracked_files=tracked,
                attempt_root=attempt_root,
                attempt_id=attempt_id,
            ),
            runner_factory=_runner,
        )

    async def probe(
        self,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticCapabilityObservation:
        self._verify(profile)
        lower = OpenGrepProcessAdapter(
            executable=self.executable,
            executable_key=str(profile.executable_key),
            inputs=OpenGrepExecutionInputs(
                config_path=self._config_path,
                config_digest=self._config_digest,
                analysis_config_ref=self._analysis_config_ref,
                rule_catalog_ref=self._rule_catalog_ref,
                rule_catalog=self._rules.mappings,
                selected_rule_ids=self._rules.selected_rule_ids,
                selected_rule_packs=self._rules.selected_rule_packs,
                tracked_files=(),
                attempt_root=_safe_root(self._output_root, "probes/opengrep"),
                attempt_id=deadline.action_id,
            ),
            runner_factory=_runner,
        )
        self._active[deadline.action_id] = lower
        try:
            return await lower.probe(profile, deadline)
        finally:
            self._active.pop(deadline.action_id, None)

    async def execute(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticToolObservation:
        self._verify(profile)
        action_meta = request.action.meta
        if (
            not isinstance(action_meta, RecordMeta)
            or action_meta.attempt_id is None
            or request.tool_profile_ref != reference(profile)
            or request.analysis_config_ref != self._analysis_config_ref
            or request.rule_catalog_ref != self._rule_catalog_ref
            or workspace_root.resolve(strict=True)
            != self._workspace_locator.root_for(request.workspace).resolve(strict=True)
        ):
            raise ValueError("OPENGREP_REQUEST_BINDING_INVALID")
        attempt_id = str(action_meta.attempt_id)
        if attempt_id in self._active:
            raise ValueError("OPENGREP_ATTEMPT_ALREADY_ACTIVE")
        tracked = self._tracked_files_for(request.workspace)
        lower = self._lower(
            profile=profile,
            tracked=tracked,
            action_id=str(request.action.action_id),
            attempt_id=attempt_id,
            workspace=request.workspace,
        )
        self._active[attempt_id] = lower
        try:
            return await lower.execute(request, workspace_root, profile, deadline)
        finally:
            self._active.pop(attempt_id, None)

    async def cancel(self, attempt_id: str) -> CancellationResult:
        active = self._active.get(attempt_id)
        if active is None:
            return CancellationResult(False, "Attempt is not active")
        return await active.cancel(attempt_id)


class _LazyCodeQLAdapter:
    """Resolve one exact prebuilt database only after the attempt is known."""

    def __init__(
        self,
        *,
        executable: Path,
        query_pack_root: Path,
        query_pack_digest: str,
        route_analysis_config_ref: StoredDataRef,
        route_rule_catalog_ref: StoredDataRef,
        rule_material: _RuleMaterial,
        output_root: Path,
        workspace_locator: WorkspaceLocatorPort,
        tracked_files_for: Callable[[CodeWorkspace], tuple[TrackedFile, ...]],
        output_quota: ProductionStaticOutputQuotaPort,
        database_provider: PrebuiltCodeQLDatabasePort,
        database_limit_bytes: int,
    ) -> None:
        self.executable = executable
        self._query_pack_root = query_pack_root
        self._query_pack_digest = query_pack_digest
        self._analysis_config_ref = route_analysis_config_ref
        self._rule_catalog_ref = route_rule_catalog_ref
        self._rules = rule_material
        self._output_root = output_root
        self._workspace_locator = workspace_locator
        self._tracked_files_for = tracked_files_for
        self._quota = output_quota
        self._databases = database_provider
        self._database_limit_bytes = database_limit_bytes
        self._active: dict[str, CodeQLProcessAdapter] = {}

    def _empty_rules(self, reason: str) -> tuple[CandidateRule, ...]:
        selected = set(self._rules.selected_rule_ids)
        return tuple(
            CandidateRule(
                item.rule_id,
                "SELECTED" if item.rule_id in selected else "NOT_SELECTED",
                "NOT_EXECUTED",
                None,
                reason if item.rule_id in selected else "NOT_SELECTED",
                None,
            )
            for item in sorted(self._rules.mappings, key=lambda item: item.rule_id)
        )

    def _failure(
        self,
        profile: StaticToolProfile,
        tracked: tuple[TrackedFile, ...],
        *,
        status: Literal["FAILED", "SKIPPED"],
        code: str,
        reason: Literal["FAILED", "UNSUPPORTED", "BLOCKED"],
        retryable: bool = False,
    ) -> StaticToolObservation:
        now = time.monotonic_ns() // 1_000_000
        return StaticToolObservation(
            tool_name="CODEQL",
            tool_version=profile.expected_version,
            tool_kind="RULE_BASED",
            status=status,
            raw_output=None,
            raw_media_type=None,
            analyzed_paths=(),
            skipped_paths=tuple(sorted(item.git_path for item in tracked)),
            analyzed_languages=(),
            skipped_languages=(),
            notes=("Exact prebuilt CodeQL database was not analyzed.",),
            selected_rule_packs=self._rules.selected_rule_packs,
            rules=self._empty_rules(
                "UNSUPPORTED" if status == "SKIPPED" else "TOOL_FAILURE"
            ),
            symbols=(),
            facts=(),
            relations=(),
            gaps=(
                CandidateGap(
                    stage="STATIC_ANALYSIS",
                    code=code,
                    reason=reason,
                    description=(
                        "CodeQL could not use the exact approved prebuilt database."
                    ),
                    affected_paths=(),
                    affected_languages=(),
                    affected_locations=(),
                    retryable=retryable,
                ),
            ),
            errors=(
                ()
                if status == "SKIPPED"
                else (
                    CandidateError(
                        stage="STATIC_ANALYSIS",
                        code=code,
                        safe_message="CodeQL database provisioning failed.",
                        retryable=retryable,
                    ),
                )
            ),
            started_monotonic_ms=now,
            finished_monotonic_ms=now,
        )

    @staticmethod
    def _tracked_manifest_sha256(tracked: tuple[TrackedFile, ...]) -> str:
        return hashlib.sha256(
            canonical_bytes(
                [
                    {
                        "git_path": item.git_path,
                        "git_mode": item.git_mode,
                        "blob_id": item.blob_id,
                        "size_bytes": item.size_bytes,
                    }
                    for item in sorted(tracked, key=lambda item: item.git_path)
                ]
            )
        ).hexdigest()

    @staticmethod
    def _require_quota_binding(
        binding: object,
        *,
        action_id: str,
        attempt_id: str,
        profile_ref: HostConfigurationRef,
        limit_bytes: int,
    ) -> None:
        if not isinstance(binding, StaticOutputQuotaBinding):
            raise ValueError("CODEQL_OUTPUT_QUOTA_UNENFORCEABLE")
        try:
            root = _safe_existing_directory(
                binding.root, "CODEQL_OUTPUT_QUOTA_UNENFORCEABLE"
            )
        except ValueError as error:
            raise ValueError("CODEQL_OUTPUT_QUOTA_UNENFORCEABLE") from error
        if (
            not binding.binding_id
            or not binding.lease_id
            or not binding.backend_key
            or not binding.enforcement_evidence
            or binding.action_id != action_id
            or binding.attempt_id != attempt_id
            or binding.profile_ref != profile_ref
            or binding.effective_limit_bytes != limit_bytes
            or binding.hard_enforced is not True
            or binding.limit_breached
            or binding.breach_evidence is not None
            or root != binding.root
            or any(root.iterdir())
        ):
            raise ValueError("CODEQL_OUTPUT_QUOTA_UNENFORCEABLE")

    @staticmethod
    def _paths_overlap(left: Path, right: Path) -> bool:
        exact_left = left.resolve(strict=True)
        exact_right = right.resolve(strict=True)
        return (
            exact_left == exact_right
            or exact_left.is_relative_to(exact_right)
            or exact_right.is_relative_to(exact_left)
        )

    def _lower(
        self,
        *,
        profile: StaticToolProfile,
        database: PrebuiltCodeQLDatabase,
        tracked: tuple[TrackedFile, ...],
        attempt_root: Path,
        attempt_id: str,
        execution_lease_id: str,
        probe_root: Path,
        probe_lease_id: str,
    ) -> CodeQLProcessAdapter:
        return CodeQLProcessAdapter(
            executable=self.executable,
            executable_key=str(profile.executable_key),
            inputs=CodeQLExecutionInputs(
                database=database,
                query_pack_root=self._query_pack_root,
                query_pack_digest=self._query_pack_digest,
                analysis_config_ref=self._analysis_config_ref,
                rule_catalog_ref=self._rule_catalog_ref,
                rule_catalog=self._rules.mappings,
                selected_rule_ids=self._rules.selected_rule_ids,
                selected_rule_packs=self._rules.selected_rule_packs,
                tracked_files=tracked,
                attempt_root=attempt_root,
                attempt_id=attempt_id,
                output_quota_lease_id=execution_lease_id,
                probe_root=probe_root,
                probe_output_quota_lease_id=probe_lease_id,
                output_quota=self._quota,
            ),
            runner_factory=_runner,
        )

    async def probe(
        self,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticCapabilityObservation:
        profile_ref = reference(profile)
        if not isinstance(profile_ref, HostConfigurationRef):
            raise ValueError("CODEQL_PRODUCTION_PROFILE_REQUIRED")
        binding = self._quota.allocate(
            purpose="PROBE",
            action_id=deadline.action_id,
            attempt_id=deadline.action_id,
            profile_ref=profile_ref,
            limit_bytes=profile.max_attempt_output_bytes,
        )
        outcome = "PROBE_FAILED"
        try:
            self._require_quota_binding(
                binding,
                action_id=deadline.action_id,
                attempt_id=deadline.action_id,
                profile_ref=profile_ref,
                limit_bytes=profile.max_attempt_output_bytes,
            )
            placeholder = _safe_root(self._output_root, "probes/codeql-placeholder")
            database_root = _safe_root(placeholder, "database")
            attempt_root = _safe_root(placeholder, "execution")
            if self._paths_overlap(binding.root, placeholder):
                raise ValueError("CODEQL_OUTPUT_QUOTA_TOPOLOGY_INVALID")
            database = PrebuiltCodeQLDatabase(
                workspace_id="probe-workspace",
                commit_id="probe-commit",
                language="python",
                database_root=database_root,
                database_digest=digest_path(database_root),
            )
            lower = self._lower(
                profile=profile,
                database=database,
                tracked=(),
                attempt_root=attempt_root,
                attempt_id=deadline.action_id,
                execution_lease_id="unused-execution-" + binding.lease_id,
                probe_root=binding.root,
                probe_lease_id=binding.lease_id,
            )
            self._active[deadline.action_id] = lower
            observed = await lower.probe(profile, deadline)
            outcome = "PROBE_SUCCEEDED" if observed.available else "PROBE_FAILED"
            return observed
        except ValueError:
            return StaticCapabilityObservation(
                available=False,
                tool_name="CODEQL",
                tool_kind="RULE_BASED",
                executable_key=str(profile.executable_key),
                observed_executable_sha256=(
                    _digest(self.executable) if self.executable.is_file() else None
                ),
                observed_version=None,
                expected_version=profile.expected_version,
                reason_code="CODEQL_OUTPUT_QUOTA_UNENFORCEABLE",
            )
        finally:
            self._active.pop(deadline.action_id, None)
            self._quota.finalize(lease_id=binding.lease_id, outcome=outcome)

    async def execute(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticToolObservation:
        meta = request.action.meta
        profile_ref = request.tool_profile_ref
        if (
            not isinstance(meta, RecordMeta)
            or meta.attempt_id is None
            or not isinstance(profile_ref, HostConfigurationRef)
            or profile_ref != reference(profile)
            or request.analysis_config_ref != self._analysis_config_ref
            or request.rule_catalog_ref != self._rule_catalog_ref
            or request.workspace.commit_id is None
            or workspace_root.resolve(strict=True)
            != self._workspace_locator.root_for(request.workspace).resolve(strict=True)
        ):
            raise ValueError("CODEQL_REQUEST_BINDING_INVALID")
        attempt_id = str(meta.attempt_id)
        action_id = str(request.action.action_id)
        if attempt_id in self._active:
            raise ValueError("CODEQL_ATTEMPT_ALREADY_ACTIVE")
        tracked = self._tracked_files_for(request.workspace)
        try:
            language = classify_codeql_language(
                tuple(item.git_path for item in tracked)
            )
        except ValueError:
            return self._failure(
                profile,
                tracked,
                status="SKIPPED",
                code="CODEQL_LANGUAGE_SCOPE_AMBIGUOUS",
                reason="UNSUPPORTED",
            )
        bindings = []
        outcome = "FAILED"
        try:
            database_binding = self._quota.allocate(
                purpose="DATABASE",
                action_id=action_id,
                attempt_id=attempt_id,
                profile_ref=profile_ref,
                limit_bytes=self._database_limit_bytes,
            )
            bindings.append(database_binding)
            self._require_quota_binding(
                database_binding,
                action_id=action_id,
                attempt_id=attempt_id,
                profile_ref=profile_ref,
                limit_bytes=self._database_limit_bytes,
            )
            execution_binding = self._quota.allocate(
                purpose="EXECUTION",
                action_id=action_id,
                attempt_id=attempt_id,
                profile_ref=profile_ref,
                limit_bytes=profile.max_attempt_output_bytes,
            )
            bindings.append(execution_binding)
            self._require_quota_binding(
                execution_binding,
                action_id=action_id,
                attempt_id=attempt_id,
                profile_ref=profile_ref,
                limit_bytes=profile.max_attempt_output_bytes,
            )
            if (
                database_binding.backend_key != execution_binding.backend_key
                or database_binding.binding_id == execution_binding.binding_id
                or database_binding.lease_id == execution_binding.lease_id
                or self._paths_overlap(database_binding.root, execution_binding.root)
                or self._paths_overlap(database_binding.root, workspace_root)
                or self._paths_overlap(execution_binding.root, workspace_root)
                or self._paths_overlap(database_binding.root, self._query_pack_root)
                or self._paths_overlap(execution_binding.root, self._query_pack_root)
            ):
                raise ValueError("CODEQL_OUTPUT_QUOTA_TOPOLOGY_INVALID")
            database = self._databases.materialize(
                workspace_id=str(request.workspace.workspace_id),
                repository_url=str(request.workspace.repository_url),
                commit_id=str(request.workspace.commit_id),
                language=language,
                tracked_manifest_sha256=self._tracked_manifest_sha256(tracked),
                profile_ref=profile_ref,
                quota_binding=database_binding,
            )
            if database is None:
                outcome = "SKIPPED"
                return self._failure(
                    profile,
                    tracked,
                    status="SKIPPED",
                    code="CODEQL_PREBUILT_DATABASE_UNAVAILABLE",
                    reason="UNSUPPORTED",
                )
            verified_database = self._quota.verify(
                lease_id=database_binding.lease_id,
                action_id=action_id,
                attempt_id=attempt_id,
                profile_ref=profile_ref,
                root=database_binding.root,
                limit_bytes=self._database_limit_bytes,
            )
            database_root = database.database_root.resolve(strict=True)
            if (
                verified_database.limit_breached
                or database.workspace_id != str(request.workspace.workspace_id)
                or database.commit_id != str(request.workspace.commit_id)
                or database.language != language
                or not database_root.is_relative_to(
                    database_binding.root.resolve(strict=True)
                )
                or database_root == database_binding.root.resolve(strict=True)
                or database_root.is_relative_to(workspace_root.resolve(strict=True))
                or digest_path(database_root) != database.database_digest
            ):
                raise ValueError("CODEQL_PREBUILT_DATABASE_BINDING_INVALID")
            placeholder = _safe_root(self._output_root, "probes/codeql-unused")
            lower = self._lower(
                profile=profile,
                database=database,
                tracked=tracked,
                attempt_root=execution_binding.root,
                attempt_id=attempt_id,
                execution_lease_id=execution_binding.lease_id,
                probe_root=placeholder,
                probe_lease_id="unused-probe-" + execution_binding.lease_id,
            )
            self._active[attempt_id] = lower
            observed = await lower.execute(request, workspace_root, profile, deadline)
            outcome = observed.status
            return observed
        except (OSError, ValueError):
            return self._failure(
                profile,
                tracked,
                status="FAILED",
                code="CODEQL_PREBUILT_DATABASE_INVALID",
                reason="FAILED",
            )
        finally:
            self._active.pop(attempt_id, None)
            for binding in reversed(bindings):
                self._quota.finalize(lease_id=binding.lease_id, outcome=outcome)

    async def cancel(self, attempt_id: str) -> CancellationResult:
        active = self._active.get(attempt_id)
        if active is None:
            return CancellationResult(False, "Attempt is not active")
        return await active.cancel(attempt_id)


class ProductionStaticAdapterFactory:
    """Build only configured real adapters; unsupported closures fail closed."""

    def __init__(
        self,
        *,
        executables: Mapping[str, Path],
        python_ast_worker: Path,
        python_ast_worker_sha256: str,
        output_quota: ProductionStaticOutputQuotaPort | None = None,
        codeql_database_provider: PrebuiltCodeQLDatabasePort | None = None,
        codeql_database_limit_bytes: int | None = None,
    ) -> None:
        self._executables = MappingProxyType(dict(executables))
        self._worker = python_ast_worker
        self._worker_sha256 = python_ast_worker_sha256
        self._output_quota = output_quota
        self._codeql_database_provider = codeql_database_provider
        self._codeql_database_limit_bytes = codeql_database_limit_bytes

    @property
    def codeql_safe_prerequisites_ready(self) -> bool:
        return (
            self._output_quota is not None
            and self._codeql_database_provider is not None
            and isinstance(self._codeql_database_limit_bytes, int)
            and not isinstance(self._codeql_database_limit_bytes, bool)
            and self._codeql_database_limit_bytes > 0
        )

    def __call__(
        self,
        context: StaticAdapterBuildContext,
    ) -> Mapping[str, StaticProcessAdapter]:
        codeql_requested = "CODEQL" in context.routes or any(
            profile.adapter_key == "CODEQL" for profile in context.profiles.values()
        )
        if codeql_requested and not self.codeql_safe_prerequisites_ready:
            raise ProductionAnalyzeUnavailable(
                "PRODUCTION_CODEQL_SAFE_PREREQUISITES_UNAVAILABLE"
            )
        output_root = _safe_root(context.data_dir, "static-execution")
        configured_rule_tools = set(context.routes) - {"AST"}
        material: _StaticMaterialManifest | None = None
        material_root: Path | None = None
        if configured_rule_tools:
            config_refs = {
                route.analysis_config_ref for route in context.routes.values()
            }
            if len(config_refs) != 1:
                raise ValueError("PRODUCTION_STATIC_ANALYSIS_CONFIG_MISMATCH")
            config_ref = next(iter(config_refs))
            material = _parse_material_manifest(
                context.evidence, config_ref.content_hash
            )
            material_tools = {
                *(("OPENGREP",) if material.opengrep_config_sha256 else ()),
                *(("CODEQL",) if material.codeql else ()),
            }
            if material_tools != configured_rule_tools:
                raise ValueError("STATIC_MATERIAL_TOOL_SET_MISMATCH")
            material_root = _safe_root(
                context.data_dir, f"static-material/{config_ref.content_hash}"
            )
        adapters: dict[str, StaticProcessAdapter] = {}
        for tool, route in context.routes.items():
            profile = context.profiles[tool]
            try:
                executable = self._executables[profile.adapter_key].resolve(strict=True)
            except (KeyError, OSError) as error:
                raise ValueError("PRODUCTION_STATIC_EXECUTABLE_MISSING") from error
            if _digest(executable) != profile.executable_sha256:
                raise ValueError("PRODUCTION_STATIC_EXECUTABLE_CHANGED")
            if route.tool_profile_ref != reference(profile):
                raise ValueError("PRODUCTION_STATIC_PROFILE_ROUTE_MISMATCH")
            if profile.adapter_key == "PYTHON_AST":
                adapters[profile.adapter_key] = _LazyPythonAstAdapter(
                    executable=executable,
                    worker_path=self._worker,
                    worker_sha256=self._worker_sha256,
                    output_root=output_root,
                    workspace_locator=context.workspace_locator,
                    tracked_files_for=context.tracked_files_for,
                )
                continue
            if profile.adapter_key == "OPENGREP":
                if (
                    material is None
                    or material_root is None
                    or material.opengrep_config_sha256 is None
                    or route.rule_catalog_ref is None
                ):
                    raise ValueError("PRODUCTION_OPENGREP_MATERIAL_MISSING")
                config_digest = material.opengrep_config_sha256
                config_path = _materialize_file(
                    material_root,
                    "opengrep/config.yml",
                    _payload_for(
                        context.evidence,
                        config_digest,
                        "OPENGREP_CONFIG_EVIDENCE_INVALID",
                    ),
                    config_digest,
                )
                adapters[profile.adapter_key] = _LazyOpenGrepAdapter(
                    executable=executable,
                    config_path=config_path,
                    config_digest=config_digest,
                    route_analysis_config_ref=route.analysis_config_ref,
                    route_rule_catalog_ref=route.rule_catalog_ref,
                    rule_material=_parse_rule_material(context, tool),
                    output_root=output_root,
                    workspace_locator=context.workspace_locator,
                    tracked_files_for=context.tracked_files_for,
                )
                continue
            if profile.adapter_key == "CODEQL":
                if (
                    material is None
                    or material_root is None
                    or material.codeql is None
                    or route.rule_catalog_ref is None
                    or self._output_quota is None
                    or self._codeql_database_provider is None
                    or self._codeql_database_limit_bytes is None
                ):
                    raise ValueError("PRODUCTION_CODEQL_MATERIAL_MISSING")
                rules = _parse_rule_material(context, tool)
                query_pack = _materialize_codeql_query_pack(
                    root=material_root,
                    material=material.codeql,
                    evidence=context.evidence,
                    rules=rules,
                )
                adapters[profile.adapter_key] = _LazyCodeQLAdapter(
                    executable=executable,
                    query_pack_root=query_pack,
                    query_pack_digest=material.codeql.query_pack_sha256,
                    route_analysis_config_ref=route.analysis_config_ref,
                    route_rule_catalog_ref=route.rule_catalog_ref,
                    rule_material=rules,
                    output_root=output_root,
                    workspace_locator=context.workspace_locator,
                    tracked_files_for=context.tracked_files_for,
                    output_quota=self._output_quota,
                    database_provider=self._codeql_database_provider,
                    database_limit_bytes=self._codeql_database_limit_bytes,
                )
                continue
            raise ValueError("PRODUCTION_STATIC_ADAPTER_NOT_CONFIGURED")
        return MappingProxyType(adapters)


__all__ = [
    "ProductionStaticAdapterFactory",
    "ProductionStaticOutputQuotaPort",
    "StaticAdapterCancellationRouter",
    "StaticAttemptAdapterDispatch",
    "StaticAttemptDispatchReader",
    "classify_codeql_language",
    "codeql_database_create_argv",
]
