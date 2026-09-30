"""Direct repository, static-fact, and Hypothesis Agent bootstrap stages."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, replace
from itertools import combinations
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Protocol, cast
from urllib.parse import unquote, urlsplit
from uuid import uuid4

import yaml  # type: ignore[import-untyped]

from sastsimi.config.user_config import (
    SimpleExecutionProfile,
    SimpleToolBinding,
    finite_call_timeout,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.static_analysis.file_scope import (
    build_static_file_scope,
    is_test_only_path,
)

from .application import (
    HypothesisSeed,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from .artifacts import SimpleArtifactRepository
from .ast_facts import collect_python_ast
from .github_policy import DiscoveredPolicy
from .hypothesis_pages import (
    MIN_PAGE_BUDGET_BYTES,
    PAGE_HYPOTHESIS_LIMIT,
    PAGE_OUTPUT_SCHEMA,
    SourcePageError,
    build_source_page,
)
from .models import CheckpointIdentity, StageFailure
from .opengrep_rule_batches import (
    RuleBatch,
    RuleBatchPlan,
    plan_rule_batches,
)
from .proposals import validate_proposal
from .provider import SimpleLLMCallResult, SimpleLLMClient
from .semgrep_fallback import (
    SemgrepFallbackError,
    _verified_target,
    build_semgrep_argv,
    build_semgrep_argv_prefix,
    require_semgrep_tool,
    run_semgrep_fallback,
)
from .semgrep_fallback_plan import (
    MAX_SEMGREP_COMMAND_UTF16_UNITS,
    plan_semgrep_target_chunks,
    semgrep_command_utf16_units,
    split_target_chunks_by_source_bytes,
)
from .static_coverage import (
    CoverageSlice,
    StaticCandidateBudget,
    StaticCandidateLimitError,
    StaticCoveragePlan,
    StaticCoverageReport,
    assess_scan,
    finish_coverage,
    merge_static_candidates_preview,
    plan_static_coverage,
    static_coverage_fingerprint,
)
from .static_scan_provenance import enrich_gap_provenance
from .store import SimpleCheckpointStore, StaticScanAttempt, StaticScanExecution
from .survey import HypothesisSurvey

_MAX_TRACKED_FILES = 200_000
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_POLICY_BYTES = 256 * 1024
_MAX_STATIC_SCAN_OUTPUT_BYTES = 64 * 1024 * 1024
_MAX_STATIC_SCAN_REQUEST_BYTES = 1024 * 1024


def _engine_raw_sources(slices: Sequence[CoverageSlice]) -> list[dict[str, object]]:
    """Bind each raw scan to only its proven file/rule pairs, per engine."""
    grouped: dict[tuple[str, str], tuple[StoredDataRef, set[tuple[str, str]]]] = {}
    for item in slices:
        ref = item.raw_ref
        if ref is None:
            continue
        key = (ref.content_hash, item.engine)
        if key not in grouped:
            grouped[key] = (ref, set())
        grouped[key][1].update(item.verified_pairs)
    return [
        {
            "ref": ref.model_dump(mode="json"),
            "engine": engine,
            "verified_pairs": [
                {"path": path, "rule_id": rule_id} for path, rule_id in sorted(pairs)
            ],
        }
        for (_, engine), (ref, pairs) in grouped.items()
    ]


def _codeql_pack_tree_digest(root: Path) -> str | None:
    """Hash the resolved pack contents; refuse unstable or unusually large trees."""
    digest = hashlib.sha256()
    total_bytes = 0
    entries = sorted(root.rglob("*"))
    if len(entries) > 100_000:
        return None
    for path in entries:
        if path.is_symlink():
            return None
        if path.is_dir():
            continue
        before = path.stat()
        if not stat.S_ISREG(before.st_mode):
            return None
        total_bytes += before.st_size
        if total_bytes > 512 * 1024 * 1024:
            return None
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as stream:
            file_hash = hashlib.file_digest(stream, "sha256").digest()
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            return None
        digest.update(file_hash)
    return digest.hexdigest()


_OPENGREP_FALLBACK_BATCH_TIMEOUT_SECONDS = 120
_OPENGREP_RECOVERY_MAX_TARGETS = 64
_OPENGREP_RECOVERY_MAX_SOURCE_BYTES = 512 * 1024
_OPENGREP_RECOVERY_MAX_SPLIT_DEPTH = 6
_SEMGREP_NODE_TIMEOUT_SECONDS = 120
_WORKSPACE_INTEGRITY_ERRORS = frozenset(
    {
        "WORKSPACE_DIRTY",
        "WORKSPACE_IDENTITY_CONFLICT",
        "GIT_COMMIT_MISMATCH",
        "GIT_STATUS_FAILED",
        "GIT_IGNORED_FILES_FAILED",
        "OPENGREP_TOOL_CHANGED",
    }
)


def _read_static_scan_output(path: Path) -> bytes:
    """Read scanner-owned output with a finite size and regular-file check."""

    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_file_attributes", 0)) & 0x400
        ):
            raise RuntimeError("STATIC_SCAN_OUTPUT_INVALID")
        if before.st_size > _MAX_STATIC_SCAN_OUTPUT_BYTES:
            raise RuntimeError("STATIC_SCAN_OUTPUT_TOO_LARGE")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            current = os.fstat(stream.fileno())
            if not stat.S_ISREG(current.st_mode) or (before.st_dev, before.st_ino) != (
                current.st_dev,
                current.st_ino,
            ):
                raise RuntimeError("STATIC_SCAN_OUTPUT_INVALID")
            if current.st_size > _MAX_STATIC_SCAN_OUTPUT_BYTES:
                raise RuntimeError("STATIC_SCAN_OUTPUT_TOO_LARGE")
            raw = stream.read(_MAX_STATIC_SCAN_OUTPUT_BYTES + 1)
        if len(raw) > _MAX_STATIC_SCAN_OUTPUT_BYTES:
            raise RuntimeError("STATIC_SCAN_OUTPUT_TOO_LARGE")
        return raw
    except OSError as error:
        raise RuntimeError("STATIC_SCAN_OUTPUT_INVALID") from error


def _known_located_parser_error(error: object) -> bool:
    if not isinstance(error, dict) or not isinstance(error.get("path"), str):
        return False
    error_type = error.get("type")
    if isinstance(error_type, str):
        return error_type in {"PartialParsing", "Syntax error"}
    return bool(
        isinstance(error_type, list)
        and len(error_type) == 2
        and error_type[0] == "PartialParsing"
        and isinstance(error_type[1], list)
        and all(isinstance(item, dict) for item in error_type[1])
    )


class PolicyDiscovery(Protocol):
    async def discover(self, repository_url: str) -> DiscoveredPolicy: ...


def _security_policy(
    workspace: Path,
    tracked: Sequence[str],
) -> dict[str, object] | None:
    """Read one tracked repository policy without following it outside checkout."""

    root = workspace.resolve()
    available = set(tracked)
    for name in (".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md"):
        if name not in available:
            continue
        candidate = root / name
        try:
            if candidate.is_symlink():
                continue
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
            if not resolved.is_file() or resolved.stat().st_size > _MAX_POLICY_BYTES:
                continue
            raw = resolved.read_bytes()
            if len(raw) > _MAX_POLICY_BYTES:
                continue
            content = raw.decode("utf-8")
        except (OSError, RuntimeError, UnicodeError, ValueError):
            continue
        if content.strip():
            return {
                "kind": "simple_repository_security_policy",
                "path": name,
                "byte_count": len(raw),
                "content": content,
            }
    return None


@dataclass(frozen=True, slots=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class ProcessExecutor(Protocol):
    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout_seconds: int,
    ) -> ProcessResult: ...


class StaticCoverageBlocked(RuntimeError):
    """A static stage retained its partial bundle and exact coverage evidence."""

    def __init__(
        self,
        code: str,
        coverage_ref: StoredDataRef,
        bundle_ref: StoredDataRef,
        *,
        retryable: bool,
    ) -> None:
        super().__init__(code)
        self.coverage_ref = coverage_ref
        self.bundle_ref = bundle_ref
        self.retryable = retryable


class DirectStaticBootstrap:
    """Run clone, AST, OpenGrep and optional CodeQL without the lease runtime."""

    def __init__(
        self,
        *,
        profile: SimpleExecutionProfile,
        process: ProcessExecutor,
        store: SimpleCheckpointStore,
        static_material_root: Path | None = None,
        policy_discovery: PolicyDiscovery | None = None,
    ) -> None:
        self._profile = profile
        self._process = process
        self._store = store
        self._materials = static_material_root or self._static_material_root()
        self._policy_discovery = policy_discovery

    @staticmethod
    def _static_material_root() -> Path:
        packaged = Path(__file__).resolve().parents[1] / "_static" / "candidate-v1"
        if packaged.is_dir():
            return packaged
        source_checkout = (
            Path(__file__).resolve().parents[3]
            / "config"
            / "static-analysis"
            / "candidate-v1"
        )
        if source_checkout.is_dir():
            return source_checkout
        raise RuntimeError("STATIC_ANALYSIS_MATERIALS_MISSING")

    async def run(
        self,
        request: SimpleAnalysisRequest,
        identity: CheckpointIdentity,
    ) -> StaticBootstrapResult:
        workspace = self._profile.workspace_root / identity.workspace_id
        await self._prepare_repository(request, workspace)
        await self._verify_opengrep_workspace(workspace, request)
        tracked = await self._tracked_files(workspace)
        scope = build_static_file_scope(workspace, tracked)
        repository_profile = self._repository_profile(
            scope.selected_paths, metadata_paths=tracked, workspace=workspace
        )
        artifacts = SimpleArtifactRepository(request.data_dir, identity)
        repository_ref = artifacts.put_json(repository_profile)

        ast_result = self._python_ast(workspace, scope.selected_paths, artifacts)
        ast_ref = artifacts.put_json(ast_result)
        rule_plan = None
        coverage_plan = None
        slices: list[CoverageSlice] = []
        engine_refs: list[StoredDataRef] = []
        scan_errors: list[str] = []
        candidate_budget = StaticCandidateBudget()
        candidate_limited = False
        rules = self._materials / "opengrep" / "rules.yml"
        try:
            if scope.selected_paths:
                binding = self._profile.tools.get("opengrep")
                if binding is None:
                    raise RuntimeError("OPENGREP_TOOL_NOT_CONFIGURED")
                rule_plan = plan_rule_batches(
                    rules.read_bytes(),
                    tool_version=binding.version,
                    executable_sha256=binding.executable_sha256,
                )
                coverage_plan = plan_static_coverage(
                    workspace,
                    scope.selected_paths,
                    request.commit,
                    rule_plan,
                    fallback_tool_fingerprint=self._fallback_fingerprint(),
                    scope_fingerprint=scope.fingerprint,
                )
                await self._collect_opengrep(
                    workspace,
                    request,
                    identity,
                    rule_plan,
                    coverage_plan,
                    scope.selected_paths,
                    scope.fingerprint,
                    artifacts,
                    candidate_budget,
                    slices,
                    engine_refs,
                    scan_errors,
                )
        except StaticCandidateLimitError as error:
            scan_errors.append(str(error))
            candidate_limited = True
        except (OSError, RuntimeError, ValueError) as error:
            code = self._safe_static_error(error, "OPENGREP_EXECUTION_FAILED")
            if code in _WORKSPACE_INTEGRITY_ERRORS:
                raise RuntimeError(code) from error
            scan_errors.append(code)
        codeql_ref: StoredDataRef | None = None
        codeql_findings: list[dict[str, object]] = []
        codeql_error: str | None = None
        if "codeql" in self._profile.tools and any(
            path.lower().endswith((".py", ".pyi")) for path in scope.selected_paths
        ):
            try:
                codeql_raw = await self._codeql_with_reuse(
                    workspace,
                    request,
                    identity,
                    scope.fingerprint,
                    scope.selected_paths,
                    artifacts,
                )
                codeql_ref = artifacts.put_bytes(codeql_raw, "application/sarif+json")
                codeql_findings = self._codeql_findings(workspace, codeql_raw)
            except (OSError, RuntimeError, ValueError) as error:
                codeql_error = self._safe_static_error(error, "CODEQL_EXECUTION_FAILED")
        coverage_report: StaticCoverageReport | None = None
        fallback_errors: list[str] = []
        if rule_plan is not None and coverage_plan is not None:
            if self._profile.semgrep_fallback and not candidate_limited:
                fallback_slices: list[CoverageSlice] = []
                fallback_refs: list[StoredDataRef] = []
                try:
                    await self._collect_semgrep(
                        workspace,
                        request,
                        identity,
                        rule_plan,
                        coverage_plan,
                        slices,
                        rules,
                        artifacts,
                        candidate_budget,
                        fallback_slices,
                        fallback_refs,
                        fallback_errors,
                    )
                except StaticCandidateLimitError as error:
                    scan_errors.append(str(error))
                    candidate_limited = True
                slices.extend(fallback_slices)
                engine_refs.extend(fallback_refs)
                scan_errors.extend(fallback_errors)
            coverage_report = finish_coverage(coverage_plan, slices)
            coverage_data = coverage_report.to_json()
            coverage_data["unavailable_paths"] = (
                [
                    {"path": path, "reason": "NO_PYTHON_RULES"}
                    for path in scope.selected_paths
                ]
                if coverage_report.expected_count == 0
                else []
            )
            if coverage_report.gaps:
                prior_fingerprints = self._prior_fallback_coverage_fingerprints(
                    workspace,
                    scope.selected_paths,
                    request.commit,
                    rule_plan,
                    scope_fingerprint=scope.fingerprint,
                )
                legacy_history_incomplete = False
                executions: list[StaticScanExecution] = []
                try:
                    for fingerprint in (
                        coverage_plan.fingerprint,
                        *sorted(prior_fingerprints - {coverage_plan.fingerprint}),
                    ):
                        scoped = self._store.list_static_scan_executions(
                            identity, request.repository, fingerprint
                        )
                        executions.extend(scoped)
                        legacy_history_incomplete |= (
                            self._store.static_scan_legacy_history_incomplete(
                                identity, request.repository, fingerprint
                            )
                        )
                        if fingerprint != coverage_plan.fingerprint:
                            recorded = {(item.tool, item.run_key) for item in scoped}
                            prior_attempts = self._store.list_static_scan_attempts(
                                identity, request.repository, fingerprint
                            )
                            legacy_history_incomplete |= any(
                                attempt.raw_ref is not None
                                and (attempt.tool, attempt.run_key) not in recorded
                                for attempt in prior_attempts
                            )
                except ValueError:
                    executions = []
                    legacy_history_incomplete = True
                    scan_errors.append("STATIC_SCAN_EXECUTION_HISTORY_INVALID")
                coverage_data["gaps"] = enrich_gap_provenance(
                    cast(list[dict[str, object]], coverage_data["gaps"]),
                    executions,
                    artifacts,
                    batch_rules={
                        batch.key: batch.rule_ids for batch in rule_plan.batches
                    },
                    expected_pairs=coverage_plan.expected_pairs,
                    legacy_history_incomplete=legacy_history_incomplete,
                )
            try:
                opengrep_raw = merge_static_candidates_preview(rule_plan, slices)
            except StaticCandidateLimitError as error:
                scan_errors.append(str(error))
                candidate_limited = True
                opengrep_raw = b'{"results": [], "errors": []}'
        else:
            coverage_data = {
                "kind": "simple_static_coverage_v1",
                "fingerprint": scope.fingerprint,
                "expected_count": 0,
                "verified_count": 0,
                "gaps": [],
                "unsupported": [],
                "excluded_paths": [],
                "unavailable": bool(scope.selected_paths),
                "unavailable_paths": [
                    {
                        "path": path,
                        "reason": (
                            scan_errors[0]
                            if scan_errors
                            else "OPENGREP_EXECUTION_FAILED"
                        ),
                    }
                    for path in scope.selected_paths
                ],
            }
            opengrep_raw = b'{"results": [], "errors": []}'
        coverage_data.update(
            {
                "analysis_id": identity.analysis_id,
                "workspace_id": identity.workspace_id,
                "commit_id": identity.commit_id,
                "ast_parse_error_count": ast_result.get("parse_error_count", 0),
                "ast_parse_errors": ast_result.get("parse_errors", []),
                "ast_parsed_file_count": ast_result.get("parsed_file_count", 0),
                "ast_truncated": ast_result.get("truncated", False),
                "ast_oversize_count": ast_result.get("oversize_count", 0),
                "ast_oversize_paths": ast_result.get("oversize_paths", []),
                "codeql_configured": "codeql" in self._profile.tools,
                "codeql_executed": codeql_ref is not None,
                "codeql_scope": "python_only"
                if "codeql" in self._profile.tools
                else None,
                "codeql_error": codeql_error,
                "engine_errors": sorted(set(scan_errors)),
                "excluded_test_files": [
                    {"path": path, "reason": reason}
                    for path, reason in scope.excluded_test_files
                ],
                "out_of_scope_product_files": [
                    {"path": path, "reason": reason}
                    for path, reason in scope.out_of_scope_product_files
                ],
                "engine_verified_counts": {
                    engine: len(
                        set().union(
                            *(
                                item.verified_pairs
                                for item in slices
                                if item.engine == engine
                            )
                        )
                    )
                    for engine in ("opengrep", "semgrep")
                },
            }
        )
        coverage_ref = artifacts.put_json(coverage_data)
        if coverage_plan is not None:
            for attempt in self._store.list_static_scan_attempts(
                identity, request.repository, coverage_plan.fingerprint
            ):
                self._store.save_static_scan_attempt(
                    identity,
                    request.repository,
                    coverage_plan.fingerprint,
                    attempt.tool,
                    attempt.run_key,
                    attempt.status,
                    attempt.raw_ref,
                    coverage_ref,
                    attempt.error_code,
                )
        opengrep_ref = artifacts.put_bytes(opengrep_raw, "application/json")
        snippets = self._opengrep_snippets(workspace, opengrep_raw)
        policy = _security_policy(workspace, tracked)
        policy_ref = artifacts.put_json(policy) if policy is not None else None
        policy_snapshot_ref = await self._capture_policy_snapshot(
            request, identity, artifacts
        )
        source_manifest_ref = artifacts.put_json(
            {"kind": "simple_tracked_sources", "paths": list(scope.selected_paths)}
        )
        excluded_tests = {path for path, _reason in scope.excluded_test_files}
        poc_paths = [path for path in tracked if path not in excluded_tests]
        poc_source_manifest_ref = artifacts.put_json(
            {"kind": "simple_tracked_sources", "paths": poc_paths}
        )
        bundle_ref = artifacts.put_json(
            {
                "kind": "simple_static_fact_bundle",
                "analysis_id": identity.analysis_id,
                "workspace_id": identity.workspace_id,
                "commit_id": identity.commit_id,
                "repository_profile_ref": repository_ref.model_dump(mode="json"),
                "source_manifest_ref": source_manifest_ref.model_dump(mode="json"),
                "poc_source_manifest_ref": poc_source_manifest_ref.model_dump(
                    mode="json"
                ),
                "static_coverage_ref": coverage_ref.model_dump(mode="json"),
                "policy_snapshot_ref": policy_snapshot_ref.model_dump(mode="json")
                if policy_snapshot_ref is not None
                else None,
                "tool_result_refs": [
                    ast_ref.model_dump(mode="json"),
                    opengrep_ref.model_dump(mode="json"),
                    *(
                        [codeql_ref.model_dump(mode="json")]
                        if codeql_ref is not None
                        else []
                    ),
                ],
                "ast_summary": ast_result,
                "engine_raw_refs": [ref.model_dump(mode="json") for ref in engine_refs],
                "engine_raw_sources": _engine_raw_sources(slices),
                "opengrep_findings": snippets,
                "codeql_findings": codeql_findings,
                "codeql_executed": codeql_ref is not None,
            }
        )
        if not scope.selected_paths:
            raise StaticCoverageBlocked(
                "NO_PYTHON_SOURCE",
                coverage_ref,
                bundle_ref,
                retryable=False,
            )
        if candidate_limited:
            raise StaticCoverageBlocked(
                "STATIC_CANDIDATES_TOO_LARGE",
                coverage_ref,
                bundle_ref,
                retryable=False,
            )
        if (
            any(
                gap.get("reason") == "source_unavailable"
                or gap.get("history_status") == "INVALID"
                for gap in cast(list[dict[str, object]], coverage_data["gaps"])
            )
            or "STATIC_SCAN_EXECUTION_HISTORY_INVALID" in scan_errors
            or "STATIC_SCAN_LEDGER_FINALIZATION_FAILED" in scan_errors
        ):
            raise StaticCoverageBlocked(
                "STATIC_EVIDENCE_INTEGRITY_FAILED",
                coverage_ref,
                bundle_ref,
                retryable=False,
            )
        independent_verified = bool(
            ast_result.get("parsed_file_count", 0) or codeql_ref is not None
        )
        if coverage_data.get("unavailable") is True and not independent_verified:
            raise StaticCoverageBlocked(
                scan_errors[0] if scan_errors else "OPENGREP_EXECUTION_FAILED",
                coverage_ref,
                bundle_ref,
                retryable=True,
            )
        if coverage_data["expected_count"] == 0 and not independent_verified:
            raise StaticCoverageBlocked(
                "NO_PYTHON_RULES",
                coverage_ref,
                bundle_ref,
                retryable=False,
            )
        if coverage_data["verified_count"] == 0 and not independent_verified:
            raise StaticCoverageBlocked(
                "STATIC_COVERAGE_NO_VERIFIED_RESULTS",
                coverage_ref,
                bundle_ref,
                retryable=True,
            )
        partial = bool(
            coverage_data["gaps"]
            or coverage_data["unsupported"]
            or coverage_data.get("unavailable")
            or coverage_data["unavailable_paths"]
            or coverage_data["expected_count"] == 0
            or coverage_data["verified_count"] == 0
            or codeql_error is not None
            or ast_result.get("parse_error_count", 0)
            or ast_result.get("oversize_count", 0)
            or ast_result.get("truncated", False)
            or scope.out_of_scope_product_files
        )
        return StaticBootstrapResult(
            repository_profile_ref=repository_ref,
            static_bundle_ref=bundle_ref,
            workspace_path=workspace,
            static_coverage_ref=coverage_ref,
            static_disposition="PARTIAL" if partial else "FULL",
            security_policy_ref=policy_ref,
            policy_snapshot_ref=policy_snapshot_ref,
        )

    @staticmethod
    def _safe_static_error(error: Exception, fallback: str) -> str:
        value = str(error)
        if value and all(
            character.isupper() or character.isdigit() or character == "_"
            for character in value
        ):
            return value[:160]
        return fallback

    @staticmethod
    def _opengrep_execution_error_ref(
        artifacts: SimpleArtifactRepository,
        code: str,
        raw_ref: StoredDataRef | None,
        raw: bytes | None,
        stderr: bytes | None,
    ) -> StoredDataRef:
        if raw is not None:
            try:
                parsed = json.loads(raw)
            except ValueError:
                pass
            else:
                if isinstance(parsed, dict) and parsed.get("errors"):
                    return raw_ref or artifacts.put_bytes(raw, "application/json")
        if stderr:
            return artifacts.put_bytes(stderr[: 64 * 1024], "application/octet-stream")
        return artifacts.put_json(
            {"kind": "opengrep_execution_error_v1", "error_code": code}
        )

    def _fallback_fingerprint(self) -> str:
        bindings = {}
        for name in ("semgrep", "codeql"):
            binding = self._profile.tools.get(name)
            bindings[name] = (
                {"version": binding.version, "sha256": binding.executable_sha256}
                if binding is not None
                else None
            )
        return hashlib.sha256(
            canonical_bytes(
                {
                    "semgrep_enabled": self._profile.semgrep_fallback,
                    "bindings": bindings,
                }
            )
        ).hexdigest()

    def _prior_fallback_coverage_fingerprints(
        self,
        workspace: Path,
        tracked: Sequence[str],
        commit_id: str,
        rule_plan: RuleBatchPlan,
        *,
        scope_fingerprint: str | None = None,
    ) -> frozenset[str]:
        """Reuse only the same product scope's earlier opt-out OpenGrep proof."""

        del workspace
        if not self._profile.semgrep_fallback or scope_fingerprint is None:
            return frozenset()
        codeql = self._profile.tools.get("codeql")
        semgrep = self._profile.tools.get("semgrep")
        fingerprints: set[str] = set()
        for prior_semgrep in (None, semgrep):
            bindings = {
                "semgrep": (
                    {
                        "version": prior_semgrep.version,
                        "sha256": prior_semgrep.executable_sha256,
                    }
                    if prior_semgrep is not None
                    else None
                ),
                "codeql": (
                    {
                        "version": codeql.version,
                        "sha256": codeql.executable_sha256,
                    }
                    if codeql is not None
                    else None
                ),
            }
            fallback_fingerprint = hashlib.sha256(
                canonical_bytes({"semgrep_enabled": False, "bindings": bindings})
            ).hexdigest()
            fingerprints.add(
                static_coverage_fingerprint(
                    tracked,
                    commit_id,
                    rule_plan,
                    fallback_tool_fingerprint=fallback_fingerprint,
                    scope_fingerprint=scope_fingerprint,
                )
            )
        return frozenset(fingerprints)

    async def coverage_fingerprint(
        self, request: SimpleAnalysisRequest, identity: CheckpointIdentity
    ) -> str:
        workspace = self._profile.workspace_root / identity.workspace_id
        await self._verify_opengrep_workspace(workspace, request)
        tracked = await self._tracked_files(workspace)
        scope = build_static_file_scope(workspace, tracked)
        binding = self._profile.tools["opengrep"]
        rules = self._materials / "opengrep" / "rules.yml"
        rule_plan = plan_rule_batches(
            rules.read_bytes(),
            tool_version=binding.version,
            executable_sha256=binding.executable_sha256,
        )
        return plan_static_coverage(
            workspace,
            scope.selected_paths,
            request.commit,
            rule_plan,
            fallback_tool_fingerprint=self._fallback_fingerprint(),
            scope_fingerprint=scope.fingerprint,
        ).fingerprint

    async def _capture_policy_snapshot(
        self,
        request: SimpleAnalysisRequest,
        identity: CheckpointIdentity,
        artifacts: SimpleArtifactRepository,
    ) -> StoredDataRef | None:
        if self._policy_discovery is None:
            return None
        discovered = await self._policy_discovery.discover(request.repository)
        body = discovered.body if discovered.status == "FOUND" else None
        verified_body = (
            body is not None
            and discovered.sha256 == hashlib.sha256(body).hexdigest()
            and discovered.source_url is not None
            and discovered.blob_sha is not None
            and discovered.publisher is not None
        )
        status = discovered.status
        reason = discovered.reason_code
        if status == "FOUND" and not verified_body:
            status = "UNVERIFIED"
            reason = "POLICY_DISCOVERY_INCONSISTENT"
            body = None
        body_ref = (
            artifacts.put_bytes(body, "text/markdown")
            if body is not None and status == "FOUND"
            else None
        )
        return artifacts.put_json(
            {
                "kind": "simple_policy_snapshot",
                "version": 1,
                "analysis_id": identity.analysis_id,
                "workspace_id": identity.workspace_id,
                "commit_id": identity.commit_id,
                "target_repository": request.repository,
                "status": status,
                "reason_code": reason,
                "source_kind": "github_contents_api" if status == "FOUND" else None,
                "owner": discovered.owner,
                "repo": discovered.repo,
                "publisher": discovered.publisher,
                "source_url": discovered.source_url,
                "source_path": discovered.source_path,
                "blob_sha": discovered.blob_sha,
                "etag": discovered.etag,
                "content_type": discovered.content_type,
                "checked_at": discovered.checked_at,
                "body_sha256": discovered.sha256 if status == "FOUND" else None,
                "body_ref": body_ref.model_dump(mode="json")
                if body_ref is not None
                else None,
            }
        )

    async def _prepare_repository(
        self,
        request: SimpleAnalysisRequest,
        workspace: Path,
    ) -> None:
        ready = workspace / ".sastsimi-ready.json"
        if ready.is_file():
            try:
                value = json.loads(ready.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                value = {}
            if value == {
                "repository": request.repository,
                "commit": request.commit.lower(),
            }:
                return
            raise RuntimeError("WORKSPACE_IDENTITY_CONFLICT")
        if workspace.exists():
            raise RuntimeError("WORKSPACE_NOT_EMPTY")
        workspace.parent.mkdir(parents=True, exist_ok=True)
        git = self._tool("git")
        clone = await self._process.run(
            (
                git,
                "clone",
                "--no-checkout",
                "--config",
                "core.autocrlf=false",
                "--",
                request.repository,
                str(workspace),
            ),
            timeout_seconds=finite_call_timeout(self._profile.max_elapsed_seconds, 900),
        )
        if clone.returncode != 0:
            raise RuntimeError("GIT_CLONE_FAILED")
        checkout = await self._process.run(
            (
                git,
                "-c",
                "core.longpaths=true",
                "checkout",
                "--detach",
                request.commit.lower(),
            ),
            cwd=workspace,
            timeout_seconds=300,
        )
        if checkout.returncode != 0:
            raise RuntimeError("GIT_CHECKOUT_FAILED")
        verified = await self._process.run(
            (git, "rev-parse", "HEAD"),
            cwd=workspace,
            timeout_seconds=30,
        )
        if (
            verified.returncode != 0
            or verified.stdout_truncated
            or verified.stdout.decode("ascii", errors="ignore").strip().lower()
            != request.commit.lower()
        ):
            raise RuntimeError("GIT_COMMIT_MISMATCH")
        ready.write_text(
            json.dumps(
                {"repository": request.repository, "commit": request.commit.lower()},
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    async def _tracked_files(self, workspace: Path) -> tuple[str, ...]:
        result = await self._process.run(
            (self._tool("git"), "ls-files", "-z"),
            cwd=workspace,
            timeout_seconds=60,
        )
        if (
            result.returncode != 0
            or result.stdout_truncated
            or (result.stdout and not result.stdout.endswith(b"\0"))
        ):
            raise RuntimeError("GIT_TRACKED_FILES_FAILED")
        values = tuple(
            item.decode("utf-8", errors="strict")
            for item in result.stdout.split(b"\0")
            if item
        )
        if len(values) > _MAX_TRACKED_FILES or any(
            not value or value.startswith(("/", "\\")) or ".." in Path(value).parts
            for value in values
        ):
            raise RuntimeError("TRACKED_FILE_SET_INVALID")
        return values

    @staticmethod
    def _repository_profile(
        tracked: tuple[str, ...],
        *,
        metadata_paths: tuple[str, ...] = (),
        workspace: Path | None = None,
    ) -> dict[str, object]:
        python_paths = tuple(path for path in tracked if path.endswith(".py"))
        languages = ("PYTHON",) if python_paths else ()
        metadata = metadata_paths or tracked
        config_names = {
            "requirements.txt",
            "pyproject.toml",
            "pipfile",
            "poetry.lock",
            "uv.lock",
            "setup.cfg",
            "dockerfile",
            "compose.yaml",
            "compose.yml",
            "docker-compose.yaml",
            "docker-compose.yml",
        }
        manifests = tuple(
            value
            for value in metadata
            if Path(value).name.lower() in config_names
            and (workspace is None or not is_test_only_path(workspace, value))
        )
        return {
            "kind": "simple_repository_profile",
            "languages": languages,
            "manifests": manifests,
            "tracked_file_count": len(python_paths),
            "needs_confirmation": not languages,
        }

    def _python_ast(
        self,
        workspace: Path,
        tracked: tuple[str, ...],
        artifacts: SimpleArtifactRepository,
    ) -> dict[str, object]:
        return collect_python_ast(
            workspace,
            tracked,
            artifacts,
            max_source_bytes=_MAX_SOURCE_BYTES,
        )

    async def _collect_opengrep(
        self,
        workspace: Path,
        request: SimpleAnalysisRequest,
        identity: CheckpointIdentity,
        rule_plan: RuleBatchPlan,
        coverage_plan: StaticCoveragePlan,
        tracked: Sequence[str],
        scope_fingerprint: str,
        artifacts: SimpleArtifactRepository,
        candidate_budget: StaticCandidateBudget | None = None,
        collected_slices: list[CoverageSlice] | None = None,
        collected_refs: list[StoredDataRef] | None = None,
        collected_errors: list[str] | None = None,
    ) -> tuple[list[CoverageSlice], list[StoredDataRef], list[str]]:
        budget = candidate_budget or StaticCandidateBudget()
        await self._verify_opengrep_workspace(workspace, request)
        if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identity.analysis_id) is None:
            raise RuntimeError("OPENGREP_ANALYSIS_ID_INVALID")
        binding = self._profile.tools["opengrep"]
        self._require_opengrep_tool(binding)
        rules = self._materials / "opengrep" / "rules.yml"
        output_root = (
            request.data_dir / "process-output" / "simple-static" / identity.analysis_id
        )
        output_root.mkdir(parents=True, exist_ok=True)
        slices: list[CoverageSlice] = (
            collected_slices if collected_slices is not None else []
        )
        refs: list[StoredDataRef] = collected_refs if collected_refs is not None else []
        errors: list[str] = collected_errors if collected_errors is not None else []
        compatible = self._prior_fallback_coverage_fingerprints(
            workspace,
            tracked,
            request.commit,
            rule_plan,
            scope_fingerprint=scope_fingerprint,
        )
        attempts: dict[str, StaticScanAttempt] = {}
        replay_attempts: list[StaticScanAttempt] = []
        for fingerprint in (*sorted(compatible), coverage_plan.fingerprint):
            attempts.update(
                (item.run_key, item)
                for item in self._store.list_static_scan_attempts(
                    identity, request.repository, fingerprint
                )
                if item.tool == "opengrep"
            )
            replay_attempts.extend(
                self._store.list_static_scan_replay_attempts(
                    identity, request.repository, fingerprint, tool="opengrep"
                )
            )
        semgrep_verified = self._replayed_semgrep_verified_pairs(
            request, identity, rule_plan, coverage_plan, artifacts
        )

        for batch in rule_plan.batches:
            expected = frozenset(
                pair
                for pair in coverage_plan.expected_pairs
                if pair[1] in batch.rule_ids
            )
            if not expected:
                continue
            (
                chunk_slices,
                chunk_refs,
                chunk_errors,
            ) = await self._recover_opengrep_timeout_chunks(
                workspace,
                request,
                identity,
                coverage_plan,
                batch,
                expected,
                rules,
                output_root,
                artifacts,
                attempts,
                replay_attempts,
                budget,
                semgrep_verified,
            )
            slices.extend(chunk_slices)
            refs.extend(chunk_refs)
            errors.extend(chunk_errors)
        return slices, refs, errors

    def _replayed_semgrep_verified_pairs(
        self,
        request: SimpleAnalysisRequest,
        identity: CheckpointIdentity,
        rule_plan: RuleBatchPlan,
        coverage_plan: StaticCoveragePlan,
        artifacts: SimpleArtifactRepository,
    ) -> frozenset[tuple[str, str]]:
        """Read exact successful fallback proof before retrying OpenGrep gaps."""

        if not self._profile.semgrep_fallback:
            return frozenset()
        batches = {batch.key: batch for batch in rule_plan.batches}
        verified: set[tuple[str, str]] = set()
        for attempt in self._store.list_static_scan_replay_attempts(
            identity,
            request.repository,
            coverage_plan.fingerprint,
            tool="semgrep",
        ):
            if (
                attempt.tool != "semgrep"
                or attempt.status != "SUCCEEDED"
                or attempt.error_code is not None
                or attempt.raw_ref is None
                or attempt.request_ref is None
            ):
                continue
            try:
                descriptor = json.loads(
                    artifacts.read_bounded(
                        attempt.request_ref, _MAX_STATIC_SCAN_REQUEST_BYTES
                    )
                )
                raw = artifacts.read_bounded(
                    attempt.raw_ref, _MAX_STATIC_SCAN_OUTPUT_BYTES
                )
            except (OSError, ValueError):
                continue
            if not isinstance(descriptor, dict):
                continue
            source_key = descriptor.get("batch_key")
            original = batches.get(source_key) if isinstance(source_key, str) else None
            rules = descriptor.get("rule_ids")
            targets = descriptor.get("targets")
            timeout = descriptor.get("per_file_timeout_seconds")
            if (
                descriptor.get("kind") != "semgrep_scan_request_v1"
                or descriptor.get("raw_content_hash") != attempt.raw_ref.content_hash
                or original is None
                or not isinstance(rules, list)
                or not rules
                or not all(isinstance(rule, str) for rule in rules)
                or tuple(rules) != tuple(sorted(set(rules)))
                or not set(rules) <= set(original.rule_ids)
                or not isinstance(targets, list)
                or not targets
                or not all(isinstance(path, str) for path in targets)
                or targets != sorted(set(targets))
                or not all(
                    any((path, rule) in coverage_plan.expected_pairs for rule in rules)
                    for path in targets
                )
                or timeout not in (None, 30)
            ):
                continue
            expected = frozenset(
                (path, rule)
                for path in targets
                for rule in rules
                if (path, rule) in coverage_plan.expected_pairs
                and (path, rule) not in coverage_plan.unavailable_pairs
            )
            if not expected:
                continue
            key_data: dict[str, object] = {
                "batch": original.key,
                "rules": tuple(rules),
                "targets": tuple(targets),
                "adaptive": 1,
            }
            if timeout is not None:
                key_data["per_file_timeout_seconds"] = timeout
            key = hashlib.sha256(canonical_bytes(key_data)).hexdigest()
            if key != attempt.run_key:
                continue
            batch = RuleBatch(
                original.index,
                tuple(rules),
                tuple(rule for rule in rule_plan.rule_ids if rule not in rules),
                key,
            )
            try:
                slice_ = assess_scan(
                    coverage_plan,
                    batch,
                    raw,
                    engine="semgrep",
                    targets=tuple(targets),
                    candidate_budget=StaticCandidateBudget(),
                )
            except (OSError, RuntimeError, StaticCandidateLimitError, ValueError):
                continue
            if expected.issubset(slice_.verified_pairs):
                verified.update(slice_.verified_pairs)
        return frozenset(verified)

    async def _recover_opengrep_timeout_chunks(
        self,
        workspace: Path,
        request: SimpleAnalysisRequest,
        identity: CheckpointIdentity,
        coverage_plan: StaticCoveragePlan,
        batch: RuleBatch,
        expected: frozenset[tuple[str, str]],
        rules: Path,
        output_root: Path,
        artifacts: SimpleArtifactRepository,
        attempts: dict[str, StaticScanAttempt],
        replay_attempts: Sequence[StaticScanAttempt],
        candidate_budget: StaticCandidateBudget,
        semgrep_verified: frozenset[tuple[str, str]],
    ) -> tuple[list[CoverageSlice], list[StoredDataRef], list[str]]:
        """Recover only timed-out full scans, proving each explicit target chunk."""

        binding = self._profile.tools["opengrep"]
        slices: list[CoverageSlice] = []
        refs: list[StoredDataRef] = []
        errors: list[str] = []
        available = expected - coverage_plan.unavailable_pairs
        rules_by_path: dict[str, set[str]] = defaultdict(set)
        for path, rule_id in available:
            rules_by_path[path].add(rule_id)
        paths = frozenset(rules_by_path)

        def chunk_key(targets: tuple[str, ...]) -> str:
            return hashlib.sha256(
                canonical_bytes(
                    {
                        "kind": "opengrep_scan_request_v1",
                        "batch_key": batch.key,
                        "rule_ids": batch.rule_ids,
                        "targets": targets,
                    }
                )
            ).hexdigest()

        def chunk_pairs(targets: tuple[str, ...]) -> frozenset[tuple[str, str]]:
            return frozenset(
                (path, rule_id) for path in targets for rule_id in rules_by_path[path]
            )

        def record_gap(targets: tuple[str, ...], code: str) -> None:
            self._record_gap_slice(
                RuleBatch(
                    batch.index,
                    batch.rule_ids,
                    batch.excluded_rule_ids,
                    chunk_key(targets),
                ),
                chunk_pairs(targets),
                code,
                slices,
            )
            errors.append(code)

        def request_data(targets: tuple[str, ...]) -> dict[str, object]:
            return {
                "kind": "opengrep_scan_request_v1",
                "batch_key": batch.key,
                "rule_ids": list(batch.rule_ids),
                "targets": list(targets),
            }

        def replay_bytes(ref: StoredDataRef) -> bytes | None:
            try:
                return artifacts.read_bounded(ref, _MAX_STATIC_SCAN_OUTPUT_BYTES)
            except (OSError, ValueError):
                if (
                    ref.record_id is None
                    and ref.data_kind == "artifact"
                    and str(ref.stored_data_id) == ref.content_hash
                ):
                    artifacts.quarantine_corrupt(
                        ref, max_bytes=_MAX_STATIC_SCAN_OUTPUT_BYTES
                    )
                return None

        def valid_request(
            attempt: StaticScanAttempt,
        ) -> tuple[tuple[str, ...], dict[str, object]] | None:
            if attempt.request_ref is None:
                return None
            raw = replay_bytes(attempt.request_ref)
            if raw is None:
                return None
            try:
                data = json.loads(raw)
            except ValueError:
                return None
            if not isinstance(data, dict):
                return None
            targets = data.get("targets")
            if (
                data.get("kind") != "opengrep_scan_request_v1"
                or data.get("batch_key") != batch.key
                or data.get("rule_ids") != list(batch.rule_ids)
                or not isinstance(targets, list)
                or not targets
                or not all(isinstance(path, str) for path in targets)
                or targets != sorted(set(targets))
                or not set(targets) <= paths
                or chunk_key(tuple(targets)) != attempt.run_key
            ):
                return None
            return tuple(targets), data

        replayed_verified: set[tuple[str, str]] = set()
        for attempt in replay_attempts:
            if attempt.raw_ref is None or attempt.error_code not in {
                None,
                "OPENGREP_PARTIAL_SCAN",
            }:
                continue
            valid = valid_request(attempt)
            if valid is None:
                continue
            targets, descriptor = valid
            if descriptor.get("raw_content_hash") != attempt.raw_ref.content_hash:
                continue
            raw = replay_bytes(attempt.raw_ref)
            if raw is None:
                continue
            try:
                slice_ = assess_scan(
                    coverage_plan,
                    batch,
                    raw,
                    engine="opengrep",
                    targets=targets,
                    candidate_budget=candidate_budget,
                )
            except (OSError, ValueError):
                continue
            if attempt.status == "SUCCEEDED" and not chunk_pairs(targets).issubset(
                slice_.verified_pairs
            ):
                continue
            slices.append(replace(slice_, raw_ref=attempt.raw_ref))
            refs.append(attempt.raw_ref)
            replayed_verified.update(slice_.verified_pairs)

        # Complementary partial artifacts can jointly verify a file's rules.
        # Retry only paths that still have an unproved pair after their union.
        verified = replayed_verified | semgrep_verified
        attempted = {
            path
            for path in paths
            if all((path, rule_id) in verified for rule_id in rules_by_path[path])
        }

        pending_paths = tuple(sorted(paths - attempted))
        if not pending_paths:
            return slices, refs, errors
        placeholder = output_root / f"opengrep-chunk-{'0' * 32}.json"
        prefix = (
            self._tool("opengrep"),
            "scan",
            "--json",
            "--disable-version-check",
            "--no-rewrite-rule-ids",
            "--config",
            str(rules),
            "--output",
            str(placeholder),
            *(
                value
                for rule_id in batch.excluded_rule_ids
                for value in ("--exclude-rule", rule_id)
            ),
        )

        def command_for(targets: tuple[str, ...]) -> tuple[str, ...]:
            return (*prefix, *targets)

        def source_size(path: str) -> int:
            # Planning reads metadata only. Invalid or changing targets
            # still reach the regular path verifier as singletons.
            candidate = Path(path)
            if (
                not path
                or "\\" in path
                or candidate.drive
                or candidate.is_absolute()
                or ".." in candidate.parts
            ):
                return _OPENGREP_RECOVERY_MAX_SOURCE_BYTES + 1
            try:
                info = (workspace / candidate).lstat()
            except OSError:
                return _OPENGREP_RECOVERY_MAX_SOURCE_BYTES + 1
            if (
                not stat.S_ISREG(info.st_mode)
                or int(getattr(info, "st_file_attributes", 0)) & 0x400
            ):
                return _OPENGREP_RECOVERY_MAX_SOURCE_BYTES + 1
            return info.st_size

        try:
            roots = plan_semgrep_target_chunks(
                pending_paths,
                command_for,
                max_targets=_OPENGREP_RECOVERY_MAX_TARGETS,
            )
        except RuntimeError as error:
            if str(error) != "SEMGREP_COMMAND_TOO_LONG":
                self._record_gap_slice(batch, available, str(error), slices)
                errors.append(str(error))
                return slices, refs, errors
            feasible: list[str] = []
            for path in pending_paths:
                try:
                    plan_semgrep_target_chunks(
                        (path,),
                        command_for,
                        max_targets=_OPENGREP_RECOVERY_MAX_TARGETS,
                    )
                except RuntimeError:
                    record_gap((path,), "OPENGREP_COMMAND_TOO_LONG")
                else:
                    feasible.append(path)
            if not feasible:
                return slices, refs, errors
            try:
                roots = plan_semgrep_target_chunks(
                    tuple(feasible),
                    command_for,
                    max_targets=_OPENGREP_RECOVERY_MAX_TARGETS,
                )
            except RuntimeError as group_error:
                self._record_gap_slice(
                    batch,
                    chunk_pairs(tuple(feasible)),
                    self._safe_static_error(group_error, "OPENGREP_COMMAND_TOO_LONG"),
                    slices,
                )
                errors.append("OPENGREP_COMMAND_TOO_LONG")
                return slices, refs, errors
        try:
            roots = split_target_chunks_by_source_bytes(
                roots,
                source_size,
                max_bytes=_OPENGREP_RECOVERY_MAX_SOURCE_BYTES,
            )
        except RuntimeError as error:
            self._record_gap_slice(
                batch,
                chunk_pairs(tuple(path for root in roots for path in root)),
                self._safe_static_error(error, "OPENGREP_TARGET_SIZE_INVALID"),
                slices,
            )
            errors.append("OPENGREP_TARGET_SIZE_INVALID")
            return slices, refs, errors

        async def run_chunk(targets: tuple[str, ...], depth: int) -> None:
            key = chunk_key(targets)
            previous = attempts.get(key)
            if (
                previous is not None
                and previous.status == "BLOCKED"
                and previous.error_code == "EXTERNAL_TOOL_TIMEOUT"
                and previous.raw_ref is None
                and (validated := valid_request(previous)) is not None
                and validated[0] == targets
                and len(targets) > 1
                and depth < _OPENGREP_RECOVERY_MAX_SPLIT_DEPTH
            ):
                midpoint = len(targets) // 2
                await run_chunk(targets[:midpoint], depth + 1)
                await run_chunk(targets[midpoint:], depth + 1)
                return
            data = request_data(targets)
            # Each node gets one finite call per run. A timed-out multi-file
            # node is divided into deterministic halves before fallback.
            call_timeout = _OPENGREP_FALLBACK_BATCH_TIMEOUT_SECONDS
            request_ref = artifacts.put_json(data)
            raw_ref: StoredDataRef | None = None
            raw: bytes | None = None
            result: ProcessResult | None = None
            output: Path | None = None
            execution_id: int | None = None
            ledger_code: str | None = "OPENGREP_EXECUTION_INTERRUPTED"
            code: str | None = None
            try:
                try:
                    safe_targets = tuple(
                        _verified_target(workspace, path) for path in targets
                    )
                    if safe_targets != targets:
                        raise RuntimeError("OPENGREP_TARGET_INVALID")
                    output = output_root / f"opengrep-chunk-{uuid4().hex}.json"
                    argv = (
                        *prefix[: prefix.index("--output") + 1],
                        str(output),
                        *prefix[prefix.index("--output") + 2 :],
                        *targets,
                    )
                    if (
                        semgrep_command_utf16_units(argv)
                        > MAX_SEMGREP_COMMAND_UTF16_UNITS
                    ):
                        raise RuntimeError("OPENGREP_COMMAND_TOO_LONG")
                    self._require_opengrep_tool(binding)
                    execution_id = self._store.begin_static_scan_execution(
                        identity,
                        request.repository,
                        coverage_plan.fingerprint,
                        "opengrep",
                        key,
                        request_ref,
                        timeout_seconds=call_timeout,
                    )
                    result = await self._process.run(
                        argv, cwd=workspace, timeout_seconds=call_timeout
                    )
                    self._require_opengrep_tool(binding)
                    if output.is_file():
                        raw = _read_static_scan_output(output)
                        raw_ref = artifacts.put_bytes(raw, "application/json")
                        refs.append(raw_ref)
                    if result.returncode != 0 or raw is None:
                        raise RuntimeError("OPENGREP_EXECUTION_FAILED")
                    slice_ = assess_scan(
                        coverage_plan,
                        batch,
                        raw,
                        engine="opengrep",
                        targets=targets,
                        candidate_budget=candidate_budget,
                    )
                    slices.append(replace(slice_, raw_ref=raw_ref))
                    code = (
                        None
                        if chunk_pairs(targets).issubset(slice_.verified_pairs)
                        else "OPENGREP_PARTIAL_SCAN"
                    )
                    ledger_code = code
                except StaticCandidateLimitError as error:
                    ledger_code = str(error)
                    raise
                except (OSError, RuntimeError, ValueError) as error:
                    code = (
                        "EXTERNAL_TOOL_TIMEOUT"
                        if isinstance(error, TimeoutError)
                        else self._safe_static_error(error, "OPENGREP_RESULT_INVALID")
                    )
                    ledger_code = code
                    if raw is None and output is not None and output.is_file():
                        try:
                            raw = _read_static_scan_output(output)
                        except (OSError, RuntimeError):
                            pass
                    if raw is not None and raw_ref is None:
                        raw_ref = artifacts.put_bytes(raw, "application/json")
                        refs.append(raw_ref)
                    if raw is not None and raw_ref is not None:
                        try:
                            provisional = assess_scan(
                                coverage_plan,
                                batch,
                                raw,
                                engine="opengrep",
                                targets=targets,
                                candidate_budget=candidate_budget,
                            )
                        except (OSError, ValueError):
                            pass
                        else:
                            slices.append(
                                replace(
                                    provisional,
                                    verified_pairs=frozenset(),
                                    gap_reasons=tuple(
                                        (path, rule_id, code)
                                        for path, rule_id in sorted(
                                            chunk_pairs(targets)
                                        )
                                    ),
                                    normalized_results=tuple(
                                        {**item, "scan_incomplete": True}
                                        for item in provisional.normalized_results
                                    ),
                                    raw_ref=raw_ref,
                                )
                            )
                if raw_ref is not None:
                    request_ref = artifacts.put_json(
                        {**data, "raw_content_hash": raw_ref.content_hash}
                    )
                self._store.save_static_scan_attempt(
                    identity,
                    request.repository,
                    coverage_plan.fingerprint,
                    "opengrep",
                    key,
                    "SUCCEEDED" if code is None else "BLOCKED",
                    raw_ref,
                    None,
                    code,
                    request_ref,
                )
            finally:
                if execution_id is not None:
                    error_ref = (
                        self._opengrep_execution_error_ref(
                            artifacts,
                            ledger_code,
                            raw_ref,
                            raw,
                            result.stderr if result is not None else None,
                        )
                        if ledger_code is not None
                        else None
                    )
                    try:
                        self._store.finish_static_scan_execution(
                            execution_id,
                            identity,
                            "SUCCEEDED" if ledger_code is None else "BLOCKED",
                            raw_ref,
                            ledger_code,
                            request_ref,
                            error_ref,
                        )
                    except (OSError, ValueError) as error:
                        raise RuntimeError(
                            "STATIC_SCAN_LEDGER_FINALIZATION_FAILED"
                        ) from error
            if (
                code == "EXTERNAL_TOOL_TIMEOUT"
                and len(targets) > 1
                and depth < _OPENGREP_RECOVERY_MAX_SPLIT_DEPTH
            ):
                midpoint = len(targets) // 2
                await run_chunk(targets[:midpoint], depth + 1)
                await run_chunk(targets[midpoint:], depth + 1)
            elif code is not None and code != "OPENGREP_PARTIAL_SCAN":
                record_gap(targets, code)
            elif code is not None:
                errors.append(code)

        for root in roots:
            await run_chunk(root, 0)
        return slices, refs, errors

    @staticmethod
    def _reusable_parse_warning(
        slice_: CoverageSlice,
        expected: frozenset[tuple[str, str]],
        *,
        allow_unscanned: bool = False,
    ) -> bool:
        missing = expected - slice_.verified_pairs
        parser_gaps = {
            (path, rule_id)
            for path, rule_id, reason in slice_.gap_reasons
            if reason == "parse_or_scan_error"
        }
        explicit_gaps = {
            (path, rule_id) for path, rule_id, _reason in slice_.gap_reasons
        }
        errors = slice_.parsed.get("errors")
        return bool(
            missing
            and parser_gaps
            and parser_gaps <= missing
            and explicit_gaps == parser_gaps
            # With fallback enabled, any remaining pairs are still unverified
            # and must be passed to Semgrep rather than rescanning the whole repo.
            and (allow_unscanned or missing == parser_gaps)
            and isinstance(errors, list)
            and errors
            and all(_known_located_parser_error(error) for error in errors)
        )

    @staticmethod
    def _known_semgrep_parser_pairs(
        slices: Sequence[CoverageSlice],
    ) -> set[tuple[str, str]]:
        pairs: set[tuple[str, str]] = set()
        nonparser_pairs: set[tuple[str, str]] = set()
        for slice_ in slices:
            if slice_.engine != "semgrep":
                continue
            raw_errors = slice_.parsed.get("errors")
            parser_only = (
                isinstance(raw_errors, list)
                and bool(raw_errors)
                and all(_known_located_parser_error(error) for error in raw_errors)
            )
            target = pairs if parser_only else nonparser_pairs
            target.update(
                (path, rule_id)
                for path, rule_id, reason in slice_.gap_reasons
                if reason == "parse_or_scan_error"
            )
        return pairs - nonparser_pairs

    @staticmethod
    def _record_gap_slice(
        batch: RuleBatch,
        expected: frozenset[tuple[str, str]],
        reason: str,
        slices: list[CoverageSlice],
    ) -> None:
        slices.append(
            CoverageSlice(
                engine="opengrep",
                batch_key=batch.key,
                rule_ids=batch.rule_ids,
                verified_pairs=frozenset(),
                gap_reasons=tuple(
                    (path, rule_id, reason) for path, rule_id in sorted(expected)
                ),
                parsed={"results": [], "errors": [], "paths": {}},
                normalized_results=(),
            )
        )

    def _record_static_failure(
        self,
        identity: CheckpointIdentity,
        request: SimpleAnalysisRequest,
        coverage_plan: StaticCoveragePlan,
        tool: str,
        run_key: str,
        expected: frozenset[tuple[str, str]],
        code: str,
        slices: list[CoverageSlice],
    ) -> None:
        self._store.save_static_scan_attempt(
            identity,
            request.repository,
            coverage_plan.fingerprint,
            tool,
            run_key,
            "BLOCKED",
            None,
            None,
            code,
        )
        self._record_gap_slice(
            RuleBatch(
                index=0,
                rule_ids=tuple(sorted({rule for _, rule in expected})),
                excluded_rule_ids=(),
                key=run_key,
            ),
            expected,
            code,
            slices,
        )

    async def _collect_semgrep(
        self,
        workspace: Path,
        request: SimpleAnalysisRequest,
        identity: CheckpointIdentity,
        rule_plan: RuleBatchPlan,
        coverage_plan: StaticCoveragePlan,
        opengrep_slices: Sequence[CoverageSlice],
        rules: Path,
        artifacts: SimpleArtifactRepository,
        candidate_budget: StaticCandidateBudget | None = None,
        collected_slices: list[CoverageSlice] | None = None,
        collected_refs: list[StoredDataRef] | None = None,
        collected_errors: list[str] | None = None,
    ) -> tuple[list[CoverageSlice], list[StoredDataRef], list[str]]:
        budget = candidate_budget or StaticCandidateBudget()
        slices: list[CoverageSlice] = (
            collected_slices if collected_slices is not None else []
        )
        refs: list[StoredDataRef] = collected_refs if collected_refs is not None else []
        errors: list[str] = collected_errors if collected_errors is not None else []
        missing = tuple(
            gap
            for gap in finish_coverage(coverage_plan, opengrep_slices).gaps
            if gap.reason != "source_unavailable"
        )
        if not missing:
            return slices, refs, errors
        binding = self._profile.tools.get("semgrep")
        if binding is None:
            errors.append("SEMGREP_TOOL_UNAVAILABLE")
            return slices, refs, errors
        try:
            require_semgrep_tool(binding)
        except RuntimeError as error:
            errors.append(self._safe_static_error(error, "SEMGREP_TOOL_UNAVAILABLE"))
            return slices, refs, errors
        if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identity.analysis_id) is None:
            raise RuntimeError("OPENGREP_ANALYSIS_ID_INVALID")
        output_dir = (
            request.data_dir / "process-output" / "simple-static" / identity.analysis_id
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        attempts = {
            item.run_key: item
            for item in self._store.list_static_scan_attempts(
                identity, request.repository, coverage_plan.fingerprint
            )
            if item.tool == "semgrep"
        }

        def make_batch(
            original: RuleBatch,
            selected: tuple[str, ...],
            targets: tuple[str, ...],
            *,
            legacy: bool = False,
            per_file_timeout_seconds: int | None = None,
        ) -> RuleBatch:
            key_data: dict[str, object] = {
                "batch": original.key,
                "rules": selected,
                "targets": targets,
            }
            if not legacy:
                key_data["adaptive"] = 1
            if per_file_timeout_seconds is not None:
                key_data["per_file_timeout_seconds"] = per_file_timeout_seconds
            return RuleBatch(
                index=original.index,
                rule_ids=selected,
                excluded_rule_ids=tuple(
                    rule_id for rule_id in rule_plan.rule_ids if rule_id not in selected
                ),
                key=hashlib.sha256(canonical_bytes(key_data)).hexdigest(),
            )

        def expected_for(
            targets: tuple[str, ...], selected: tuple[str, ...]
        ) -> frozenset[tuple[str, str]]:
            return frozenset(
                (path, rule_id)
                for path in targets
                for rule_id in selected
                if (path, rule_id) in coverage_plan.expected_pairs
                and (path, rule_id) not in coverage_plan.unavailable_pairs
            )

        def record_unproved(
            batch: RuleBatch, pending: frozenset[tuple[str, str]], code: str
        ) -> None:
            explained = {
                (path, rule_id)
                for slice_ in slices
                for path, rule_id, _reason in slice_.gap_reasons
            }
            unexplained = pending - explained
            if unexplained:
                slices.append(
                    CoverageSlice(
                        engine="semgrep",
                        batch_key=batch.key,
                        rule_ids=batch.rule_ids,
                        verified_pairs=frozenset(),
                        gap_reasons=tuple(
                            (path, rule_id, code)
                            for path, rule_id in sorted(unexplained)
                        ),
                        parsed={"results": [], "errors": [], "paths": {}},
                        normalized_results=(),
                    )
                )
            errors.append(code)

        def replay(
            batch: RuleBatch,
            targets: tuple[str, ...],
            ref: StoredDataRef,
            request_ref: StoredDataRef | None,
        ) -> CoverageSlice | None:
            if request_ref is not None:
                try:
                    request_data = json.loads(
                        artifacts.read_bounded(
                            request_ref, _MAX_STATIC_SCAN_REQUEST_BYTES
                        )
                    )
                except (OSError, ValueError):
                    artifacts.quarantine_corrupt(
                        request_ref, max_bytes=_MAX_STATIC_SCAN_REQUEST_BYTES
                    )
                    return None
                if not isinstance(request_data, dict):
                    return None
                raw_rules = request_data.get("rule_ids")
                raw_targets = request_data.get("targets")
                timeout = request_data.get("per_file_timeout_seconds")
                source_key = request_data.get("batch_key")
                source_batch = (
                    batches_by_key.get(source_key)
                    if isinstance(source_key, str)
                    else None
                )
                if (
                    request_data.get("kind") != "semgrep_scan_request_v1"
                    or request_data.get("raw_content_hash") != ref.content_hash
                    or not isinstance(raw_rules, list)
                    or tuple(raw_rules) != batch.rule_ids
                    or not isinstance(raw_targets, list)
                    or tuple(raw_targets) != targets
                    or (timeout is not None and timeout != 30)
                    or source_batch is None
                    or make_batch(
                        source_batch,
                        batch.rule_ids,
                        targets,
                        per_file_timeout_seconds=timeout,
                    ).key
                    != batch.key
                ):
                    return None
            try:
                raw = artifacts.read_bounded(ref, _MAX_STATIC_SCAN_OUTPUT_BYTES)
            except (OSError, ValueError):
                artifacts.quarantine_corrupt(
                    ref, max_bytes=_MAX_STATIC_SCAN_OUTPUT_BYTES
                )
                return None
            try:
                return replace(
                    assess_scan(
                        coverage_plan,
                        batch,
                        raw,
                        engine="semgrep",
                        targets=targets,
                        candidate_budget=budget,
                    ),
                    raw_ref=ref,
                )
            except ValueError:
                return None

        # A saved successful chunk remains proof even when a later OpenGrep
        # result changes the missing set and therefore the Semgrep chunk keys.
        # The request artifact binds the raw output to its exact rule selection.
        replayed_verified: set[tuple[str, str]] = set()
        batches_by_key = {batch.key: batch for batch in rule_plan.batches}
        for attempt in self._store.list_static_scan_replay_attempts(
            identity,
            request.repository,
            coverage_plan.fingerprint,
            tool="semgrep",
        ):
            if attempt.raw_ref is None or attempt.error_code not in {
                None,
                "SEMGREP_PARTIAL_SCAN",
            }:
                continue
            if attempt.request_ref is None:
                # Old successful rows have no request descriptor. Only an exact
                # run-key match reconstructed from every scanned path and a
                # complete reassessment can prove their original selection.
                if attempt.status != "SUCCEEDED":
                    continue
                try:
                    legacy_raw = json.loads(
                        artifacts.read_bounded(
                            attempt.raw_ref, _MAX_STATIC_SCAN_OUTPUT_BYTES
                        )
                    )
                    raw_paths = legacy_raw["paths"]["scanned"]
                    if not isinstance(raw_paths, list) or not raw_paths:
                        continue
                    if not all(isinstance(path, str) for path in raw_paths):
                        continue
                    normalized = tuple(
                        sorted(_verified_target(workspace, path) for path in raw_paths)
                    )
                except (OSError, ValueError, RuntimeError, TypeError, KeyError):
                    continue
                if len(normalized) != len(set(normalized)):
                    continue
                for original in rule_plan.batches:
                    for count in range(1, len(original.rule_ids) + 1):
                        for combination in combinations(original.rule_ids, count):
                            selected = tuple(sorted(combination))
                            for legacy in (True, False):
                                for timeout in (None, 30):
                                    candidate = make_batch(
                                        original,
                                        selected,
                                        normalized,
                                        legacy=legacy,
                                        per_file_timeout_seconds=timeout,
                                    )
                                    if candidate.key != attempt.run_key:
                                        continue
                                    cached = replay(
                                        candidate, normalized, attempt.raw_ref, None
                                    )
                                    expected = expected_for(normalized, selected)
                                    if cached is not None and expected.issubset(
                                        cached.verified_pairs
                                    ):
                                        slices.append(cached)
                                        refs.append(attempt.raw_ref)
                                        replayed_verified.update(cached.verified_pairs)
                continue
            try:
                descriptor = json.loads(
                    artifacts.read_bounded(
                        attempt.request_ref, _MAX_STATIC_SCAN_REQUEST_BYTES
                    )
                )
            except (OSError, ValueError):
                artifacts.quarantine_corrupt(
                    attempt.request_ref, max_bytes=_MAX_STATIC_SCAN_REQUEST_BYTES
                )
                continue
            if (
                not isinstance(descriptor, dict)
                or descriptor.get("kind") != "semgrep_scan_request_v1"
                or descriptor.get("raw_content_hash") != attempt.raw_ref.content_hash
            ):
                continue
            descriptor_batch_key = descriptor.get("batch_key")
            candidate_original = (
                batches_by_key.get(descriptor_batch_key)
                if isinstance(descriptor_batch_key, str)
                else None
            )
            raw_rules = descriptor.get("rule_ids")
            raw_targets = descriptor.get("targets")
            timeout = descriptor.get("per_file_timeout_seconds")
            if (
                candidate_original is None
                or not isinstance(raw_rules, list)
                or not raw_rules
                or not all(isinstance(rule, str) for rule in raw_rules)
                or not isinstance(raw_targets, list)
                or not raw_targets
                or not all(isinstance(path, str) for path in raw_targets)
                or (timeout is not None and timeout != 30)
            ):
                continue
            selected = tuple(raw_rules)
            targets = tuple(raw_targets)
            if (
                len(selected) != len(set(selected))
                or not set(selected) <= set(candidate_original.rule_ids)
                or targets != tuple(sorted(set(targets)))
                or not expected_for(targets, selected)
            ):
                continue
            batch = make_batch(
                candidate_original,
                selected,
                targets,
                per_file_timeout_seconds=timeout,
            )
            if batch.key != attempt.run_key:
                continue
            cached = replay(batch, targets, attempt.raw_ref, attempt.request_ref)
            if cached is None:
                continue
            slices.append(cached)
            refs.append(attempt.raw_ref)
            replayed_verified.update(cached.verified_pairs)

        for original in rule_plan.batches:
            by_path: dict[str, set[str]] = defaultdict(set)
            for gap in missing:
                if (
                    gap.rule_id in original.rule_ids
                    and (gap.path, gap.rule_id) not in replayed_verified
                ):
                    by_path[gap.path].add(gap.rule_id)
            grouped: dict[tuple[str, ...], list[str]] = defaultdict(list)
            for path, rule_ids in sorted(by_path.items()):
                grouped[tuple(sorted(rule_ids))].append(path)
            for selected, all_targets in sorted(grouped.items()):
                legacy_verified: set[tuple[str, str]] = set()
                for start in range(0, len(all_targets), 32):
                    targets = tuple(all_targets[start : start + 32])
                    batch = make_batch(original, selected, targets, legacy=True)
                    previous = attempts.get(batch.key)
                    if (
                        previous is None
                        or previous.status != "SUCCEEDED"
                        or previous.raw_ref is None
                    ):
                        continue
                    cached = replay(
                        batch, targets, previous.raw_ref, previous.request_ref
                    )
                    expected = expected_for(targets, selected)
                    if cached is not None and expected.issubset(cached.verified_pairs):
                        slices.append(cached)
                        refs.append(previous.raw_ref)
                        legacy_verified.update(expected)

                already_verified = replayed_verified | legacy_verified
                stable_targets = tuple(
                    path
                    for path in all_targets
                    if any(
                        (path, rule_id) not in already_verified for rule_id in selected
                    )
                )
                if not stable_targets:
                    continue
                placeholder = output_dir / f"semgrep-{'0' * 32}.json"

                def planning_gap(
                    failed_targets: tuple[str, ...],
                    error: Exception,
                    _original: RuleBatch = original,
                    _selected: tuple[str, ...] = selected,
                    _legacy_verified: set[tuple[str, str]] = legacy_verified,
                ) -> None:
                    code = self._safe_static_error(error, "SEMGREP_RESULT_INVALID")
                    failed = make_batch(_original, _selected, failed_targets)
                    record_unproved(
                        failed,
                        expected_for(failed_targets, _selected) - _legacy_verified,
                        code,
                    )
                    self._store.save_static_scan_attempt(
                        identity,
                        request.repository,
                        coverage_plan.fingerprint,
                        "semgrep",
                        failed.key,
                        "BLOCKED",
                        None,
                        None,
                        code,
                    )

                try:
                    command_prefix = build_semgrep_argv_prefix(
                        binding,
                        rules,
                        tuple(
                            rule_id
                            for rule_id in rule_plan.rule_ids
                            if rule_id not in selected
                        ),
                        placeholder,
                        None,
                    )
                except (OSError, RuntimeError, ValueError) as error:
                    planning_gap(stable_targets, error)
                    continue

                def command_for(
                    chunk: tuple[str, ...], prefix: tuple[str, ...] = command_prefix
                ) -> tuple[str, ...]:
                    return (*prefix, *chunk)

                def source_size(path: str) -> int:
                    candidate = Path(path)
                    if (
                        not path
                        or "\\" in path
                        or candidate.drive
                        or candidate.is_absolute()
                        or ".." in candidate.parts
                    ):
                        return _OPENGREP_RECOVERY_MAX_SOURCE_BYTES + 1
                    try:
                        info = (workspace / candidate).lstat()
                    except OSError:
                        return _OPENGREP_RECOVERY_MAX_SOURCE_BYTES + 1
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or int(getattr(info, "st_file_attributes", 0)) & 0x400
                    ):
                        return _OPENGREP_RECOVERY_MAX_SOURCE_BYTES + 1
                    return info.st_size

                try:
                    roots = plan_semgrep_target_chunks(stable_targets, command_for)
                except (OSError, RuntimeError, ValueError) as error:
                    if (
                        str(error) != "SEMGREP_COMMAND_TOO_LONG"
                        or len(stable_targets) == 1
                    ):
                        planning_gap(stable_targets, error)
                        continue
                    feasible: list[str] = []
                    for target in stable_targets:
                        try:
                            plan_semgrep_target_chunks((target,), command_for)
                        except (OSError, RuntimeError, ValueError) as target_error:
                            planning_gap((target,), target_error)
                        else:
                            feasible.append(target)
                    if not feasible:
                        continue
                    try:
                        roots = plan_semgrep_target_chunks(tuple(feasible), command_for)
                    except (OSError, RuntimeError, ValueError) as group_error:
                        planning_gap(tuple(feasible), group_error)
                        continue
                roots = split_target_chunks_by_source_bytes(roots, source_size)
                verified = set(already_verified)
                node_budget = 3 * len(stable_targets) + len(roots)

                async def run_node(
                    targets: tuple[str, ...],
                    rule_ids: tuple[str, ...],
                    *,
                    retry_timeout: bool = False,
                    _original: RuleBatch = original,
                    _verified: set[tuple[str, str]] = verified,
                    _placeholder: Path = placeholder,
                ) -> None:
                    nonlocal node_budget
                    batch = make_batch(
                        _original,
                        rule_ids,
                        targets,
                        per_file_timeout_seconds=30 if retry_timeout else None,
                    )
                    pending = expected_for(targets, rule_ids) - _verified
                    if not pending:
                        return
                    if node_budget < 1:
                        record_unproved(batch, pending, "SEMGREP_RETRY_BUDGET_EXCEEDED")
                        return
                    node_budget -= 1
                    request_data = {
                        "kind": "semgrep_scan_request_v1",
                        "batch_key": _original.key,
                        "rule_ids": list(rule_ids),
                        "targets": list(targets),
                        "per_file_timeout_seconds": 30 if retry_timeout else None,
                    }
                    request_ref = artifacts.put_json(request_data)

                    previous = attempts.get(batch.key)
                    if (
                        previous is not None
                        and previous.status == "BLOCKED"
                        and previous.error_code == "EXTERNAL_TOOL_TIMEOUT"
                        and len(targets) > 1
                    ):
                        # This exact chunk already exhausted a finite subprocess
                        # timeout. It supplied no reusable coverage proof, so
                        # rescan its pending pairs in smaller bounded chunks.
                        if previous.raw_ref is not None:
                            refs.append(previous.raw_ref)
                        midpoint = len(targets) // 2
                        await run_node(
                            targets[:midpoint],
                            rule_ids,
                            retry_timeout=retry_timeout,
                        )
                        await run_node(
                            targets[midpoint:],
                            rule_ids,
                            retry_timeout=retry_timeout,
                        )
                        return
                    code: str | None = None
                    cached: CoverageSlice | None = None
                    current_slice: CoverageSlice | None = None
                    if (
                        previous is not None
                        and previous.raw_ref is not None
                        and (
                            (
                                previous.status == "SUCCEEDED"
                                and previous.error_code is None
                            )
                            or (
                                previous.request_ref is None
                                and previous.error_code == "SEMGREP_PARTIAL_SCAN"
                            )
                        )
                    ):
                        cached = replay(
                            batch, targets, previous.raw_ref, previous.request_ref
                        )
                    if cached is not None:
                        assert previous is not None and previous.raw_ref is not None
                        current_slice = cached
                        slices.append(cached)
                        refs.append(previous.raw_ref)
                        _verified.update(cached.verified_pairs)
                        code = previous.error_code
                    else:
                        # A failed attempt is not proof about this file/rule pair.
                        # Explicit resume retries unresolved pairs. The per-run
                        # node budget and finite call timeouts bound failures.
                        if previous is not None and previous.raw_ref is not None:
                            refs.append(previous.raw_ref)
                        try:
                            planned_argv = build_semgrep_argv(
                                binding,
                                workspace,
                                rules,
                                targets,
                                batch.excluded_rule_ids,
                                _placeholder,
                                30 if retry_timeout else None,
                                targets_verified=True,
                            )
                            if (
                                semgrep_command_utf16_units(planned_argv)
                                > MAX_SEMGREP_COMMAND_UTF16_UNITS
                            ):
                                raise RuntimeError("SEMGREP_COMMAND_TOO_LONG")
                        except (OSError, RuntimeError, ValueError) as error:
                            code = self._safe_static_error(
                                error, "SEMGREP_RESULT_INVALID"
                            )
                            if code == "SEMGREP_COMMAND_TOO_LONG" and len(targets) > 1:
                                midpoint = len(targets) // 2
                                await run_node(
                                    targets[:midpoint],
                                    rule_ids,
                                    retry_timeout=retry_timeout,
                                )
                                await run_node(
                                    targets[midpoint:],
                                    rule_ids,
                                    retry_timeout=retry_timeout,
                                )
                            else:
                                record_unproved(batch, pending, code)
                                self._store.save_static_scan_attempt(
                                    identity,
                                    request.repository,
                                    coverage_plan.fingerprint,
                                    "semgrep",
                                    batch.key,
                                    "BLOCKED",
                                    None,
                                    None,
                                    code,
                                    request_ref,
                                )
                            return
                        raw_ref: StoredDataRef | None = None
                        execution_id: int | None = None
                        ledger_code: str | None = "SEMGREP_EXECUTION_INTERRUPTED"
                        call_timeout = _SEMGREP_NODE_TIMEOUT_SECONDS

                        def mark_invoked() -> None:
                            nonlocal execution_id
                            execution_id = self._store.begin_static_scan_execution(
                                identity,
                                request.repository,
                                coverage_plan.fingerprint,
                                "semgrep",
                                batch.key,
                                request_ref,
                                timeout_seconds=call_timeout,
                            )

                        try:
                            try:
                                raw = await run_semgrep_fallback(
                                    self._process,
                                    binding,
                                    workspace,
                                    rules,
                                    targets,
                                    batch.excluded_rule_ids,
                                    call_timeout,
                                    output_dir=output_dir,
                                    per_file_timeout_seconds=(
                                        30 if retry_timeout else None
                                    ),
                                    on_invocation=mark_invoked,
                                )
                                raw_ref = artifacts.put_bytes(raw, "application/json")
                                slice_ = assess_scan(
                                    coverage_plan,
                                    batch,
                                    raw,
                                    engine="semgrep",
                                    targets=targets,
                                    candidate_budget=budget,
                                )
                                current_slice = slice_
                                slices.append(replace(slice_, raw_ref=raw_ref))
                                refs.append(raw_ref)
                                _verified.update(slice_.verified_pairs)
                                code = (
                                    None
                                    if expected_for(targets, rule_ids).issubset(
                                        slice_.verified_pairs
                                    )
                                    else "SEMGREP_PARTIAL_SCAN"
                                )
                                ledger_code = code
                            except StaticCandidateLimitError as error:
                                ledger_code = str(error)
                                raise
                            except (OSError, RuntimeError, ValueError) as error:
                                if (
                                    isinstance(error, SemgrepFallbackError)
                                    and error.raw_output is not None
                                ):
                                    raw_ref = artifacts.put_bytes(
                                        error.raw_output, "application/octet-stream"
                                    )
                                    refs.append(raw_ref)
                                code = self._safe_static_error(
                                    error, "SEMGREP_RESULT_INVALID"
                                )
                                ledger_code = code
                            if raw_ref is not None:
                                request_ref = artifacts.put_json(
                                    {
                                        **request_data,
                                        "raw_content_hash": raw_ref.content_hash,
                                    }
                                )
                            self._store.save_static_scan_attempt(
                                identity,
                                request.repository,
                                coverage_plan.fingerprint,
                                "semgrep",
                                batch.key,
                                "SUCCEEDED" if code is None else "BLOCKED",
                                raw_ref,
                                None,
                                code,
                                request_ref,
                            )
                        finally:
                            if execution_id is not None:
                                error_ref = (
                                    raw_ref
                                    or artifacts.put_json(
                                        {
                                            "kind": "semgrep_execution_error_v1",
                                            "error_code": ledger_code,
                                        }
                                    )
                                    if ledger_code is not None
                                    else None
                                )
                                self._store.finish_static_scan_execution(
                                    execution_id,
                                    identity,
                                    "SUCCEEDED" if ledger_code is None else "BLOCKED",
                                    raw_ref,
                                    ledger_code,
                                    request_ref,
                                    error_ref,
                                )

                    pending = expected_for(targets, rule_ids) - _verified
                    if not pending:
                        return
                    if len(targets) == 1:
                        reported_timeout = current_slice is not None and any(
                            path == targets[0] and reason == "scan_timeout"
                            for path, _rule_id, reason in current_slice.gap_reasons
                        )
                        if (
                            code == "EXTERNAL_TOOL_TIMEOUT" or reported_timeout
                        ) and not retry_timeout:
                            await run_node(targets, rule_ids, retry_timeout=True)
                        else:
                            record_unproved(
                                batch, pending, code or "SEMGREP_PARTIAL_SCAN"
                            )
                        return

                    grouped_pending: dict[tuple[str, ...], list[str]] = defaultdict(
                        list
                    )
                    for path in targets:
                        remaining_rules = tuple(
                            rule_id
                            for rule_id in rule_ids
                            if (path, rule_id) in pending
                        )
                        if remaining_rules:
                            grouped_pending[remaining_rules].append(path)
                    for child_rules, child_targets_list in sorted(
                        grouped_pending.items()
                    ):
                        child_targets = tuple(child_targets_list)
                        if child_targets == targets and child_rules == rule_ids:
                            midpoint = len(targets) // 2
                            await run_node(targets[:midpoint], rule_ids)
                            await run_node(targets[midpoint:], rule_ids)
                        else:
                            await run_node(child_targets, child_rules)

                for root in roots:
                    await run_node(root, selected)
        return slices, refs, errors

    @staticmethod
    def _require_opengrep_tool(binding: SimpleToolBinding) -> None:
        try:
            with binding.executable_path.open("rb") as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
        except OSError as error:
            raise RuntimeError("OPENGREP_TOOL_UNAVAILABLE") from error
        if actual != binding.executable_sha256:
            raise RuntimeError("OPENGREP_TOOL_CHANGED")

    async def _verify_opengrep_workspace(
        self, workspace: Path, request: SimpleAnalysisRequest
    ) -> None:
        ready = workspace / ".sastsimi-ready.json"
        try:
            if ready.is_symlink() or json.loads(ready.read_text(encoding="utf-8")) != {
                "repository": request.repository,
                "commit": request.commit.lower(),
            }:
                raise RuntimeError("WORKSPACE_IDENTITY_CONFLICT")
        except (OSError, ValueError) as error:
            raise RuntimeError("WORKSPACE_IDENTITY_CONFLICT") from error
        git = self._tool("git")
        head = await self._process.run(
            (git, "rev-parse", "HEAD"), cwd=workspace, timeout_seconds=30
        )
        if (
            head.returncode != 0
            or head.stdout_truncated
            or head.stdout.decode("ascii", errors="ignore").strip().lower()
            != request.commit.lower()
        ):
            raise RuntimeError("GIT_COMMIT_MISMATCH")
        status = await self._process.run(
            (git, "status", "--porcelain=v1", "-z", "--untracked-files=all"),
            cwd=workspace,
            timeout_seconds=60,
        )
        if (
            status.returncode != 0
            or status.stdout_truncated
            or (status.stdout and not status.stdout.endswith(b"\0"))
        ):
            raise RuntimeError("GIT_STATUS_FAILED")
        if any(
            entry != b"?? .sastsimi-ready.json"
            for entry in status.stdout.split(b"\0")
            if entry
        ):
            raise RuntimeError("WORKSPACE_DIRTY")
        ignored = await self._process.run(
            (
                git,
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "-z",
            ),
            cwd=workspace,
            timeout_seconds=60,
        )
        if (
            ignored.returncode != 0
            or ignored.stdout_truncated
            or (ignored.stdout and not ignored.stdout.endswith(b"\0"))
        ):
            raise RuntimeError("GIT_IGNORED_FILES_FAILED")
        for entry in ignored.stdout.split(b"\0"):
            leaf = entry.replace(b"\\", b"/").rsplit(b"/", 1)[-1].lower()
            if leaf in {b".semgrepignore", b".gitignore"}:
                raise RuntimeError("WORKSPACE_DIRTY")

    async def _codeql_with_reuse(
        self,
        workspace: Path,
        request: SimpleAnalysisRequest,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        selected_paths: tuple[str, ...],
        artifacts: SimpleArtifactRepository,
    ) -> bytes:
        binding = self._profile.tools["codeql"]
        query_suite = self._materials / "codeql" / "python-security.qls"
        local_qlpack = query_suite.parent / "qlpack.yml"
        try:
            with query_suite.open("rb") as stream:
                suite_digest = hashlib.file_digest(stream, "sha256").hexdigest()
            with local_qlpack.open("rb") as stream:
                local_pack_digest = hashlib.file_digest(stream, "sha256").hexdigest()
            with binding.executable_path.open("rb") as stream:
                executable_digest = hashlib.file_digest(stream, "sha256").hexdigest()
        except OSError:
            suite_digest = ""
            local_pack_digest = ""
            executable_digest = ""
        descriptor: dict[str, object] | None = None
        resolved_packs = (
            await self._resolved_codeql_packs(workspace, query_suite)
            if suite_digest
            and local_pack_digest
            and executable_digest == binding.executable_sha256
            else None
        )
        if resolved_packs is not None:
            descriptor = {
                "kind": "codeql_successful_sarif_v2",
                "repository": request.repository,
                "commit": request.commit,
                "scope_fingerprint": scope_fingerprint,
                "codeql_version": binding.version,
                "codeql_executable_sha256": executable_digest,
                "query_suite_sha256": suite_digest,
                "local_qlpack_sha256": local_pack_digest,
                "resolved_packs": resolved_packs,
            }
            fingerprint = hashlib.sha256(canonical_bytes(descriptor)).hexdigest()
            for attempt in self._store.list_static_scan_attempts(
                identity, request.repository, fingerprint
            ):
                if (
                    attempt.tool != "codeql"
                    or attempt.run_key != "sarif"
                    or attempt.status != "SUCCEEDED"
                    or attempt.error_code is not None
                    or attempt.raw_ref is None
                    or attempt.request_ref is None
                ):
                    continue
                try:
                    request_raw = artifacts.read_bounded(
                        attempt.request_ref, _MAX_STATIC_SCAN_REQUEST_BYTES
                    )
                except (OSError, ValueError):
                    artifacts.quarantine_corrupt(
                        attempt.request_ref, max_bytes=_MAX_STATIC_SCAN_REQUEST_BYTES
                    )
                    continue
                try:
                    recorded = json.loads(request_raw)
                except ValueError:
                    continue
                if recorded != descriptor:
                    continue
                try:
                    raw = artifacts.read_bounded(
                        attempt.raw_ref, _MAX_STATIC_SCAN_OUTPUT_BYTES
                    )
                    self._require_codeql_sarif_scope(json.loads(raw), selected_paths)
                except (OSError, RuntimeError, ValueError):
                    artifacts.quarantine_corrupt(
                        attempt.raw_ref, max_bytes=_MAX_STATIC_SCAN_OUTPUT_BYTES
                    )
                    continue
                return raw
        raw = await self._run_codeql(
            workspace,
            request.data_dir,
            request.repository,
            request.commit,
            identity.analysis_id,
        )
        if descriptor is not None:
            raw_ref = artifacts.put_bytes(raw, "application/sarif+json")
            request_ref = artifacts.put_json(descriptor)
            self._store.save_static_scan_attempt(
                identity,
                request.repository,
                fingerprint,
                "codeql",
                "sarif",
                "SUCCEEDED",
                raw_ref,
                None,
                None,
                request_ref,
            )
        return raw

    async def _resolved_codeql_packs(
        self, workspace: Path, query_suite: Path
    ) -> list[dict[str, str]] | None:
        """Bind reuse to the actual resolved query pack and dependency contents."""
        codeql = self._tool("codeql")
        try:
            queries = await self._process.run(
                (codeql, "resolve", "queries", "--format=json", "--", str(query_suite)),
                cwd=workspace,
                timeout_seconds=60,
            )
            packs = await self._process.run(
                (codeql, "resolve", "packs", "--format=json"),
                cwd=workspace,
                timeout_seconds=60,
            )
            if queries.returncode != 0 or packs.returncode != 0:
                return None
            if len(queries.stdout) > 1024 * 1024 or len(packs.stdout) > 4 * 1024 * 1024:
                return None
            paths = json.loads(queries.stdout)
            listing = json.loads(packs.stdout)
            if (
                not isinstance(paths, list)
                or not paths
                or not isinstance(listing, dict)
            ):
                return None
            available: dict[tuple[str, str], Path] = {}
            steps = listing.get("steps")
            if not isinstance(steps, list):
                return None
            for step in steps:
                if not isinstance(step, dict):
                    return None
                scans = step.get("scans", [step])
                if not isinstance(scans, list):
                    return None
                for scan in scans:
                    if not isinstance(scan, dict):
                        return None
                    found = scan.get("found", {})
                    if not isinstance(found, dict):
                        return None
                    for name, entries in found.items():
                        for entry in (
                            entries if isinstance(entries, list) else [entries]
                        ):
                            if not isinstance(name, str) or not isinstance(entry, dict):
                                return None
                            version, manifest = entry.get("version"), entry.get("path")
                            if not isinstance(version, str) or not isinstance(
                                manifest, str
                            ):
                                return None
                            location = Path(manifest).resolve(strict=True)
                            if location.name != "qlpack.yml" or not location.is_file():
                                return None
                            previous = available.setdefault(
                                (name, version), location.parent
                            )
                            if previous != location.parent:
                                return None
            roots: set[Path] = set()
            for item in paths:
                if not isinstance(item, str):
                    return None
                query = Path(item).resolve(strict=True)
                if query.suffix != ".ql" or not query.is_file():
                    return None
                roots.add(
                    next(
                        parent
                        for parent in query.parents
                        if (parent / "qlpack.yml").is_file()
                    )
                )
            if not roots:
                return None
            pending = list(roots)
            inspected: set[Path] = set()
            resolved: list[dict[str, str]] = []
            while pending:
                root = pending.pop().resolve(strict=True)
                if root in inspected:
                    continue
                if len(inspected) >= 64:
                    return None
                inspected.add(root)
                manifest = yaml.safe_load((root / "qlpack.yml").read_bytes())
                if not isinstance(manifest, dict):
                    return None
                name, version = manifest.get("name"), manifest.get("version")
                if not isinstance(name, str) or not isinstance(version, str):
                    return None
                if available.get((name, version)) != root:
                    return None
                dependencies = manifest.get("dependencies", {})
                if not isinstance(dependencies, dict):
                    return None
                for dependency, required_version in dependencies.items():
                    if not isinstance(dependency, str) or not isinstance(
                        required_version, str
                    ):
                        return None
                    dependency_root = available.get((dependency, required_version))
                    if dependency_root is None:
                        return None
                    pending.append(dependency_root)
                tree_digest = _codeql_pack_tree_digest(root)
                if tree_digest is None:
                    return None
                resolved.append(
                    {
                        "name": name,
                        "version": version,
                        "path": str(root),
                        "sha256": tree_digest,
                    }
                )
            return sorted(resolved, key=lambda item: (item["name"], item["path"]))
        except (OSError, RuntimeError, StopIteration, ValueError, yaml.YAMLError):
            return None

    async def _run_codeql(
        self,
        workspace: Path,
        data_dir: Path,
        repository: str,
        commit: str,
        analysis_id: str,
    ) -> bytes:
        request = SimpleAnalysisRequest(
            data_dir=data_dir, repository=repository, commit=commit
        )
        await self._verify_opengrep_workspace(workspace, request)
        tracked = await self._tracked_files(workspace)
        scope = build_static_file_scope(workspace, tracked)
        if not any(
            path.lower().endswith((".py", ".pyi")) for path in scope.selected_paths
        ):
            raise RuntimeError("CODEQL_PRODUCT_SOURCE_EMPTY")
        key = hashlib.sha256(
            f"{repository}\0{commit}\0{scope.fingerprint}".encode()
        ).hexdigest()[:24]
        analysis_key = hashlib.sha256(analysis_id.encode()).hexdigest()[:24]
        root = data_dir / "codeql" / key
        database = root / "database"
        output = root / f"results-{analysis_key}.sarif"
        completion = root / f"r-{analysis_key[:12]}.json"
        root.mkdir(parents=True, exist_ok=True)
        codeql = self._tool("codeql")
        # Leave headroom within the process runner's 4 GiB memory ceiling.
        codeql_resource_limits = ("--threads=1", "--ram=2048")
        binding = self._profile.tools["codeql"]
        cache_fingerprint = hashlib.sha256(
            canonical_bytes(
                {
                    "kind": "simple_codeql_database_v1",
                    "repository": repository,
                    "commit": commit,
                    "scope_fingerprint": scope.fingerprint,
                    "codeql_version": binding.version,
                    "codeql_executable_sha256": binding.executable_sha256,
                }
            )
        ).hexdigest()
        database_ready = False
        try:
            if not completion.is_symlink():
                recorded_raw = completion.read_bytes()
                if len(recorded_raw) <= 4096:
                    recorded = json.loads(recorded_raw)
                    if (
                        isinstance(recorded, dict)
                        and recorded.get("fingerprint") == cache_fingerprint
                    ):
                        name = recorded.get("database")
                        if isinstance(name, str) and (
                            name == "database" or re.fullmatch(r"db-[0-9a-f]{12}", name)
                        ):
                            candidate = root / name
                            if not candidate.is_symlink():
                                database_ready = await self._codeql_database_ready(
                                    codeql, candidate, workspace
                                )
                                if database_ready:
                                    database = candidate
        except (OSError, ValueError):
            pass
        if not database_ready:
            if database.exists():
                database = root / f"db-{uuid4().hex[:12]}"
            workspace_root = workspace.resolve(strict=True)
            database_root = root.resolve(strict=True)
            if (
                database_root == workspace_root
                or database_root.is_relative_to(workspace_root)
                or workspace_root.is_relative_to(database_root)
            ):
                raise RuntimeError("CODEQL_SOURCE_SCOPE_INVALID")
            with TemporaryDirectory(prefix="sastsimi-codeql-source-", dir=root) as name:
                source_root = Path(name).resolve(strict=True)
                for relative in scope.selected_paths:
                    source = workspace_root.joinpath(*relative.split("/"))
                    try:
                        exact = source.resolve(strict=True)
                        exact.relative_to(workspace_root)
                        before = source.lstat()
                        if (
                            source.is_symlink()
                            or not stat.S_ISREG(before.st_mode)
                            or before.st_nlink != 1
                        ):
                            raise ValueError
                        target = source_root.joinpath(*relative.split("/"))
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with source.open("rb") as reader, target.open("xb") as writer:
                            shutil.copyfileobj(reader, writer, length=1024 * 1024)
                        after = source.lstat()
                        if (
                            before.st_dev,
                            before.st_ino,
                            before.st_size,
                            before.st_mtime_ns,
                        ) != (
                            after.st_dev,
                            after.st_ino,
                            after.st_size,
                            after.st_mtime_ns,
                        ) or target.stat().st_size != before.st_size:
                            raise ValueError
                    except (OSError, ValueError):
                        raise RuntimeError("CODEQL_SOURCE_SCOPE_INVALID") from None
                await self._verify_opengrep_workspace(workspace, request)
                created = await self._process.run(
                    (
                        codeql,
                        "database",
                        "create",
                        str(database),
                        "--language=python",
                        f"--source-root={source_root}",
                        *codeql_resource_limits,
                    ),
                    cwd=source_root,
                    timeout_seconds=finite_call_timeout(
                        self._profile.max_elapsed_seconds,
                        1800,
                    ),
                )
                if created.returncode != 0:
                    raise RuntimeError("CODEQL_DATABASE_CREATE_FAILED")
            if completion.is_symlink():
                raise RuntimeError("CODEQL_DATABASE_CREATE_FAILED")
            try:
                completion.write_bytes(
                    canonical_bytes(
                        {
                            "database": database.name,
                            "fingerprint": cache_fingerprint,
                        }
                    )
                )
            except OSError:
                raise RuntimeError("CODEQL_DATABASE_CREATE_FAILED") from None
        output.unlink(missing_ok=True)
        analyzed = await self._process.run(
            (
                codeql,
                "database",
                "analyze",
                str(database),
                str(self._materials / "codeql" / "python-security.qls"),
                "--format=sarif-latest",
                f"--output={output}",
                *codeql_resource_limits,
            ),
            cwd=workspace,
            timeout_seconds=finite_call_timeout(
                self._profile.max_elapsed_seconds,
                1800,
            ),
        )
        if analyzed.returncode != 0 or not output.is_file():
            raise RuntimeError("CODEQL_ANALYZE_FAILED")
        raw = _read_static_scan_output(output)
        self._require_codeql_sarif_scope(json.loads(raw), scope.selected_paths)
        return raw

    async def _codeql_database_ready(
        self, codeql: str, database: Path, workspace: Path
    ) -> bool:
        if not (database / "codeql-database.yml").is_file():
            return False
        try:
            resolved = await self._process.run(
                (codeql, "resolve", "database", "--format=json", str(database)),
                cwd=workspace,
                timeout_seconds=60,
            )
            if resolved.returncode != 0 or len(resolved.stdout) > 1024 * 1024:
                return False
            metadata = json.loads(resolved.stdout)
            if not isinstance(metadata, dict):
                return False
            folder = metadata.get("datasetFolder")
            if not isinstance(folder, str):
                return False
            dataset = Path(folder).resolve(strict=True)
            dataset.relative_to(database.resolve(strict=True))
            return dataset.is_dir() and dataset != database.resolve(strict=True)
        except (OSError, RuntimeError, TypeError, ValueError):
            return False

    @staticmethod
    def _require_codeql_sarif_scope(
        value: object, selected_paths: tuple[str, ...]
    ) -> None:
        selected = frozenset(selected_paths)

        def check_location(value: object) -> bool:
            found = False
            if isinstance(value, dict):
                if "artifactLocation" in value:
                    artifact = value["artifactLocation"]
                    uri = artifact.get("uri") if isinstance(artifact, dict) else None
                    if not isinstance(uri, str):
                        raise RuntimeError("CODEQL_SOURCE_SCOPE_INVALID")
                    parsed = urlsplit(uri)
                    if (
                        parsed.scheme
                        or parsed.netloc
                        or parsed.query
                        or parsed.fragment
                        or unquote(parsed.path) not in selected
                    ):
                        raise RuntimeError("CODEQL_SOURCE_SCOPE_INVALID")
                    found = True
                for child in value.values():
                    found = check_location(child) or found
            elif isinstance(value, list):
                for child in value:
                    found = check_location(child) or found
            return found

        if not isinstance(value, dict) or not isinstance(value.get("runs"), list):
            raise RuntimeError("CODEQL_SOURCE_SCOPE_INVALID")
        for run in value["runs"]:
            if not isinstance(run, dict) or not isinstance(
                run.get("results", []), list
            ):
                raise RuntimeError("CODEQL_SOURCE_SCOPE_INVALID")
            for result in run.get("results", []):
                if not check_location(result):
                    raise RuntimeError("CODEQL_SOURCE_SCOPE_INVALID")

    @staticmethod
    def _opengrep_snippets(
        workspace: Path,
        raw: bytes,
    ) -> list[dict[str, object]]:
        try:
            values = json.loads(raw).get("results", [])
        except (AttributeError, json.JSONDecodeError):
            return []
        output: list[dict[str, object]] = []
        root = workspace.resolve()
        for item in values[:500]:
            try:
                raw_path = Path(str(item["path"]))
                path = raw_path if raw_path.is_absolute() else root / raw_path
                resolved = path.resolve(strict=True)
                relative = resolved.relative_to(root).as_posix()
                line = int(item["start"]["line"])
                lines = resolved.read_text(encoding="utf-8").splitlines()
                start = max(0, line - 4)
                snippet = "\n".join(lines[start : min(len(lines), line + 3)])
                output.append(
                    {
                        "rule_id": item.get("check_id"),
                        "engine": item.get("engine", "opengrep"),
                        "engines": item.get("engines", ["opengrep"]),
                        "scan_incomplete": item.get("scan_incomplete", False),
                        "path": relative,
                        "line": line,
                        "snippet": snippet[:8000],
                    }
                )
            except (KeyError, OSError, UnicodeError, ValueError):
                continue
        return output

    @staticmethod
    def _codeql_findings(
        workspace: Path,
        raw: bytes,
    ) -> list[dict[str, object]]:
        try:
            runs = json.loads(raw).get("runs", [])
        except (AttributeError, json.JSONDecodeError):
            return []
        root = workspace.resolve()
        output: list[dict[str, object]] = []
        for run in runs:
            if not isinstance(run, dict):
                continue
            for item in run.get("results", []):
                if not isinstance(item, dict):
                    continue
                locations = item.get("locations", [])
                location = (
                    locations[0] if isinstance(locations, list) and locations else {}
                )
                physical = (
                    location.get("physicalLocation", {})
                    if isinstance(location, dict)
                    else {}
                )
                artifact = (
                    physical.get("artifactLocation", {})
                    if isinstance(physical, dict)
                    else {}
                )
                region = (
                    physical.get("region", {}) if isinstance(physical, dict) else {}
                )
                uri = artifact.get("uri") if isinstance(artifact, dict) else None
                try:
                    candidate = (root / str(uri)).resolve(strict=True)
                    relative = candidate.relative_to(root).as_posix()
                except (OSError, ValueError):
                    relative = str(uri or "")
                message = item.get("message", {})
                text = message.get("text", "") if isinstance(message, dict) else ""
                output.append(
                    {
                        "rule_id": str(item.get("ruleId", "")),
                        "path": relative,
                        "line": int(region.get("startLine", 0))
                        if isinstance(region, dict)
                        else 0,
                        "message": str(text)[:2000],
                    }
                )
                if len(output) >= 500:
                    return output
        return output

    def _tool(self, name: str) -> str:
        try:
            return str(self._profile.tools[name].executable_path)
        except KeyError:
            raise RuntimeError(f"REQUIRED_TOOL_MISSING:{name}") from None


class DirectHypothesisBootstrap:
    def __init__(
        self,
        *,
        data_dir: Path,
        client_factory: SimpleClientFactory,
        max_hypotheses: int = 12,
        feed: str = "current",
        store: SimpleCheckpointStore | None = None,
    ) -> None:
        self._data_dir = data_dir
        self._client_factory = client_factory
        self._max_hypotheses = max_hypotheses
        if feed not in {"current", "facts_survey"}:
            raise ValueError("HYPOTHESIS_FEED_INVALID")
        self._feed = feed
        self._store = store

    async def propose_page(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        *,
        after_cursor: str | None,
        page_budget_bytes: int = 32_768,
    ) -> tuple[tuple[HypothesisSeed, ...], str | None] | StageFailure:
        """Survey one bounded Python source page without the legacy global cap."""

        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        try:
            bundle = json.loads(artifacts.read(static.static_bundle_ref))
            if (
                not isinstance(bundle, dict)
                or bundle.get("kind") != "simple_static_fact_bundle"
            ):
                raise ValueError("bundle kind")
            manifest_ref = StoredDataRef.model_validate(bundle["source_manifest_ref"])
            manifest = json.loads(artifacts.read(manifest_ref))
            if (
                not isinstance(manifest, dict)
                or manifest.get("kind") != "simple_tracked_sources"
            ):
                raise ValueError("manifest kind")
            paths = manifest.get("paths")
            if not isinstance(paths, list):
                raise ValueError("manifest paths")
        except (OSError, ValueError, TypeError, KeyError):
            return StageFailure(
                code="HYPOTHESIS_PAGE_STATIC_INVALID",
                retryable=False,
                safe_message="Source manifest or static bundle is unavailable",
            )

        client = self._client_factory(identity, artifacts)
        budget = page_budget_bytes
        attempt_refs: list[StoredDataRef] = []
        while True:
            try:
                page = build_source_page(
                    workspace=static.workspace_path,
                    paths=paths,
                    bundle_hash=static.static_bundle_ref.content_hash,
                    manifest_hash=manifest_ref.content_hash,
                    after_cursor=after_cursor,
                    page_budget_bytes=budget,
                )
            except SourcePageError as exc:
                return StageFailure(
                    code=exc.code,
                    retryable=False,
                    safe_message="Source page cannot be built without omitting code",
                    evidence_refs=tuple(attempt_refs),
                )
            except OSError:
                return StageFailure(
                    code="HYPOTHESIS_PAGE_SOURCE_UNAVAILABLE",
                    retryable=False,
                    safe_message="Source file is unavailable",
                    evidence_refs=tuple(attempt_refs),
                )
            if page is None:
                return (), None
            input_ref = artifacts.put_json(
                {
                    "kind": "simple_hypothesis_source_page",
                    "analysis_id": identity.analysis_id,
                    "cursor": after_cursor,
                    "next_cursor": page.next_cursor,
                    "static_bundle_ref": static.static_bundle_ref.model_dump(
                        mode="json"
                    ),
                    "source_manifest_ref": manifest_ref.model_dump(mode="json"),
                    "page": page.payload,
                    "prompt": page.prompt.decode("utf-8"),
                }
            )
            attempt_refs.append(input_ref)
            result = await client.call(
                prompt=page.prompt,
                output_schema=PAGE_OUTPUT_SCHEMA,
                timeout_ms=180_000,
                agent_name="hypothesis_page",
            )
            if isinstance(result, StageFailure):
                if (
                    result.code == "CONTEXT_LIMIT_EXCEEDED"
                    and budget > MIN_PAGE_BUDGET_BYTES
                ):
                    budget = max(MIN_PAGE_BUDGET_BYTES, budget // 2)
                    continue
                return result.model_copy(
                    update={"evidence_refs": (*result.evidence_refs, *attempt_refs)}
                )
            assert isinstance(result, SimpleLLMCallResult)
            raw = result.value.get("hypotheses")
            ranges = page.ranges
            valid = False
            if isinstance(raw, list) and len(raw) <= PAGE_HYPOTHESIS_LIMIT:
                valid = True
                for item in raw:
                    proposal, errors = validate_proposal(
                        item, lines={path: end for path, (_, end) in ranges.items()}
                    )
                    if (
                        proposal is None
                        or errors
                        or set(proposal)
                        != {
                            "title",
                            "vulnerability_type",
                            "summary",
                            "code_locations",
                            "source",
                            "sink",
                            "rationale",
                        }
                    ):
                        valid = False
                        break
                    for location in proposal["code_locations"]:
                        path, line_text = location.rsplit(":", 1)
                        start, end = ranges[path]
                        if not start <= int(line_text) <= end:
                            valid = False
                            break
                    if not valid:
                        break
            page_result_ref = artifacts.put_json(
                {
                    "kind": "simple_hypothesis_page_result",
                    "analysis_id": identity.analysis_id,
                    "cursor": after_cursor,
                    "next_cursor": page.next_cursor,
                    "page_input_ref": input_ref.model_dump(mode="json"),
                    "attempt_input_refs": [
                        ref.model_dump(mode="json") for ref in attempt_refs
                    ],
                    "hypotheses": raw,
                    "validation_status": "VALID" if valid else "INVALID",
                    "llm_request_ref": (
                        result.request_ref.model_dump(mode="json")
                        if result.request_ref is not None
                        else None
                    ),
                    "llm_response_ref": (
                        result.response_ref.model_dump(mode="json")
                        if result.response_ref is not None
                        else None
                    ),
                    "llm_raw_output_ref": (
                        result.raw_output_ref.model_dump(mode="json")
                        if result.raw_output_ref is not None
                        else None
                    ),
                }
            )
            if not valid:
                return StageFailure(
                    code="HYPOTHESIS_PAGE_OUTPUT_INVALID",
                    retryable=True,
                    safe_message="Hypothesis output is invalid or outside the source",
                    evidence_refs=(input_ref, page_result_ref),
                )
            assert isinstance(raw, list)
            seeds: list[HypothesisSeed] = []
            seen: set[str] = set()
            for value in raw:
                assert isinstance(value, dict)
                hypothesis_id = (
                    "hypothesis-"
                    + hashlib.sha256(
                        static.static_bundle_ref.content_hash.encode()
                        + canonical_bytes(value)
                    ).hexdigest()[:32]
                )
                if hypothesis_id in seen:
                    continue
                seen.add(hypothesis_id)
                proposal_ref = artifacts.put_prompt_proposal(
                    {
                        "kind": "simple_hypothesis_proposal",
                        "analysis_id": identity.analysis_id,
                        "hypothesis_id": hypothesis_id,
                        "static_bundle_ref": static.static_bundle_ref.model_dump(
                            mode="json"
                        ),
                        "proposal": value,
                        "page_input_ref": input_ref.model_dump(mode="json"),
                        "page_result_ref": page_result_ref.model_dump(mode="json"),
                        "prompt_digest": result.prompt_digest,
                        "output_digest": result.output_digest,
                        "llm_request_ref": (
                            result.request_ref.model_dump(mode="json")
                            if result.request_ref is not None
                            else None
                        ),
                        "llm_response_ref": (
                            result.response_ref.model_dump(mode="json")
                            if result.response_ref is not None
                            else None
                        ),
                    },
                )
                seeds.append(
                    HypothesisSeed(
                        hypothesis_id=hypothesis_id, proposal_ref=proposal_ref
                    )
                )
            return tuple(seeds), page.next_cursor

    async def propose(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> tuple[HypothesisSeed, ...] | StageFailure:
        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        client = self._client_factory(identity, artifacts)
        if self._feed == "facts_survey":
            if self._store is None:
                raise RuntimeError("HYPOTHESIS_SURVEY_STORE_REQUIRED")
            return await HypothesisSurvey(
                artifacts=artifacts,
                store=self._store,
                client=client,
                max_hypotheses=self._max_hypotheses,
            ).run(identity, static)
        bundle = json.loads(artifacts.read(static.static_bundle_ref))
        candidate_focused = isinstance(bundle, dict) and isinstance(
            bundle.get("candidate_focus"), dict
        )
        schema: dict[str, Any] = {
            "type": "object",
            "properties": {
                "hypotheses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "vulnerability_type": {"type": "string"},
                            "summary": {"type": "string"},
                            "code_locations": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "source": {"type": "string"},
                            "sink": {"type": "string"},
                            "rationale": {"type": "string"},
                        },
                        "required": [
                            "title",
                            "vulnerability_type",
                            "summary",
                            "code_locations",
                            "source",
                            "sink",
                            "rationale",
                        ],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["hypotheses"],
            "additionalProperties": False,
        }
        if candidate_focused:
            schema["properties"]["hypotheses"]["maxItems"] = self._max_hypotheses
        context = artifacts.prompt_context((static.static_bundle_ref,))
        prompt = (
            b"You are the Hypothesis Agent. Use only the supplied static facts and "
            b"code snippets. Return concrete web-security hypotheses with exact code "
            b"locations. Static tool hits are facts, not vulnerability verdicts. "
            b"Do not invent missing code. Return at most "
            + str(self._max_hypotheses).encode()
            + b" hypotheses.\n<UNTRUSTED_EXACT_INPUTS>\n"
            + context
            + b"\n</UNTRUSTED_EXACT_INPUTS>\n"
        )
        result = await client.call(
            prompt=prompt,
            output_schema=schema,
            timeout_ms=180_000,
            agent_name="hypothesis",
        )
        if isinstance(result, StageFailure):
            return result
        assert isinstance(result, SimpleLLMCallResult)
        raw = result.value.get("hypotheses", [])
        if not isinstance(raw, list):
            raise RuntimeError("HYPOTHESIS_OUTPUT_INVALID")
        if candidate_focused and len(raw) > self._max_hypotheses:
            overflow_ref = artifacts.put_json(
                {
                    "kind": "simple_candidate_hypothesis_overflow",
                    "analysis_id": identity.analysis_id,
                    "static_bundle_ref": static.static_bundle_ref.model_dump(
                        mode="json"
                    ),
                    "limit": self._max_hypotheses,
                    "returned_hypotheses": raw,
                }
            )
            return StageFailure(
                code="CANDIDATE_HYPOTHESIS_BATCH_OVERFLOW",
                retryable=True,
                safe_message="Candidate hypothesis response exceeded one-call limit",
                evidence_refs=(overflow_ref,),
            )
        seeds: list[HypothesisSeed] = []
        seen: set[bytes] = set()
        for index, value in enumerate(raw[: self._max_hypotheses]):
            if not isinstance(value, dict):
                continue
            canonical = canonical_bytes(value)
            if canonical in seen:
                continue
            seen.add(canonical)
            hypothesis_id = (
                "hypothesis-"
                + hashlib.sha256(
                    static.static_bundle_ref.content_hash.encode()
                    + index.to_bytes(4, "big")
                    + canonical
                ).hexdigest()[:32]
            )
            proposal_ref = artifacts.put_prompt_proposal(
                {
                    "kind": "simple_hypothesis_proposal",
                    "analysis_id": identity.analysis_id,
                    "hypothesis_id": hypothesis_id,
                    "static_bundle_ref": static.static_bundle_ref.model_dump(
                        mode="json"
                    ),
                    "proposal": value,
                    "prompt_digest": result.prompt_digest,
                    "output_digest": result.output_digest,
                    "llm_request_ref": (
                        result.request_ref.model_dump(mode="json")
                        if result.request_ref is not None
                        else None
                    ),
                    "llm_response_ref": (
                        result.response_ref.model_dump(mode="json")
                        if result.response_ref is not None
                        else None
                    ),
                },
            )
            seeds.append(
                HypothesisSeed(
                    hypothesis_id=hypothesis_id,
                    proposal_ref=proposal_ref,
                )
            )
        return tuple(seeds)


class SimpleClientFactory(Protocol):
    def __call__(
        self,
        identity: CheckpointIdentity,
        artifacts: SimpleArtifactRepository,
    ) -> SimpleLLMClient: ...


__all__ = [
    "DirectHypothesisBootstrap",
    "DirectStaticBootstrap",
    "ProcessExecutor",
    "ProcessResult",
]
