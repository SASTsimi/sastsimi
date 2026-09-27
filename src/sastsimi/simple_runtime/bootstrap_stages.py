"""Direct repository, static-fact, and Hypothesis Agent bootstrap stages."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import time
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

from sastsimi.config.user_config import SimpleExecutionProfile, SimpleToolBinding
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .application import (
    HypothesisSeed,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from .artifacts import SimpleArtifactRepository
from .github_policy import DiscoveredPolicy
from .models import CheckpointIdentity, StageFailure
from .opengrep_rule_batches import (
    RuleBatch,
    RuleBatchPlan,
    aggregate_rule_batches,
    merge_static_candidates,
    parse_rule_batch,
    plan_rule_batches,
)
from .provider import SimpleLLMCallResult, SimpleLLMClient
from .semgrep_fallback import SemgrepFallbackError, run_semgrep_fallback
from .static_coverage import (
    CoverageSlice,
    StaticCoveragePlan,
    assess_scan,
    finish_coverage,
    plan_static_coverage,
)
from .store import SimpleCheckpointStore
from .survey import HypothesisSurvey

_MAX_TRACKED_FILES = 200_000
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_FACTS = 10_000
_MAX_POLICY_BYTES = 256 * 1024


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
        tracked = await self._tracked_files(workspace)
        repository_profile = self._repository_profile(tracked)
        artifacts = SimpleArtifactRepository(request.data_dir, identity)
        repository_ref = artifacts.put_json(repository_profile)

        ast_result = self._python_ast(workspace, tracked)
        ast_ref = artifacts.put_json(ast_result)
        rule_plan = None
        coverage_plan = None
        slices: list[CoverageSlice] = []
        engine_refs: list[StoredDataRef] = []
        scan_errors: list[str] = []
        rules = self._materials / "opengrep" / "rules.yml"
        try:
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
                tracked,
                request.commit,
                rule_plan,
                fallback_tool_fingerprint=self._fallback_fingerprint(),
            )
            slices, engine_refs, scan_errors = await self._collect_opengrep(
                workspace,
                request,
                identity,
                rule_plan,
                coverage_plan,
                artifacts,
            )
        except (OSError, RuntimeError, ValueError) as error:
            scan_errors.append(
                self._safe_static_error(error, "OPENGREP_EXECUTION_FAILED")
            )
        codeql_ref: StoredDataRef | None = None
        codeql_findings: list[dict[str, object]] = []
        codeql_error: str | None = None
        if "codeql" in self._profile.tools:
            try:
                codeql_raw = await self._run_codeql(
                    workspace,
                    request.data_dir,
                    request.repository,
                    request.commit,
                    identity.analysis_id,
                )
                codeql_ref = artifacts.put_bytes(codeql_raw, "application/sarif+json")
                codeql_findings = self._codeql_findings(workspace, codeql_raw)
            except (OSError, RuntimeError, ValueError) as error:
                codeql_error = self._safe_static_error(error, "CODEQL_EXECUTION_FAILED")
        if rule_plan is not None and coverage_plan is not None:
            if self._profile.semgrep_fallback:
                (
                    fallback_slices,
                    fallback_refs,
                    fallback_errors,
                ) = await self._collect_semgrep(
                    workspace,
                    request,
                    identity,
                    rule_plan,
                    coverage_plan,
                    slices,
                    rules,
                    artifacts,
                )
                slices.extend(fallback_slices)
                engine_refs.extend(fallback_refs)
                scan_errors.extend(fallback_errors)
            coverage = finish_coverage(coverage_plan, slices)
            coverage_data = coverage.to_json()
            opengrep_raw = merge_static_candidates(rule_plan, slices)
        else:
            coverage_data = {
                "kind": "simple_static_coverage_v1",
                "fingerprint": None,
                "expected_count": None,
                "verified_count": None,
                "gaps": [],
                "unsupported": [],
                "excluded_paths": [],
                "unavailable": True,
            }
            opengrep_raw = b'{"results": [], "errors": []}'
        coverage_data.update(
            {
                "analysis_id": identity.analysis_id,
                "workspace_id": identity.workspace_id,
                "commit_id": identity.commit_id,
                "ast_parse_error_count": ast_result.get("parse_error_count", 0),
                "ast_truncated": ast_result.get("truncated", False),
                "ast_oversize_count": ast_result.get("oversize_count", 0),
                "codeql_configured": "codeql" in self._profile.tools,
                "codeql_executed": codeql_ref is not None,
                "codeql_scope": "python_only"
                if "codeql" in self._profile.tools
                else None,
                "codeql_error": codeql_error,
                "engine_errors": sorted(set(scan_errors)),
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
            {"kind": "simple_tracked_sources", "paths": list(tracked)}
        )
        bundle_ref = artifacts.put_json(
            {
                "kind": "simple_static_fact_bundle",
                "analysis_id": identity.analysis_id,
                "workspace_id": identity.workspace_id,
                "commit_id": identity.commit_id,
                "repository_profile_ref": repository_ref.model_dump(mode="json"),
                "source_manifest_ref": source_manifest_ref.model_dump(mode="json"),
                "static_coverage_ref": coverage_ref.model_dump(mode="json"),
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
                "opengrep_findings": snippets,
                "codeql_findings": codeql_findings,
                "codeql_executed": codeql_ref is not None,
            }
        )
        if coverage_data.get("unavailable") is True:
            raise StaticCoverageBlocked(
                scan_errors[0] if scan_errors else "OPENGREP_EXECUTION_FAILED",
                coverage_ref,
                bundle_ref,
                retryable=True,
            )
        if coverage_data["gaps"]:
            blocking_error = next(
                (code for code in scan_errors if not code.endswith("PARTIAL_SCAN")),
                None,
            )
            raise StaticCoverageBlocked(
                blocking_error or "STATIC_COVERAGE_INCOMPLETE",
                coverage_ref,
                bundle_ref,
                retryable=bool(
                    blocking_error
                    and (
                        blocking_error.endswith("EXECUTION_FAILED")
                        or blocking_error.endswith("TIMEOUT")
                    )
                ),
            )
        if codeql_error is not None:
            raise StaticCoverageBlocked(
                codeql_error,
                coverage_ref,
                bundle_ref,
                retryable=True,
            )
        return StaticBootstrapResult(
            repository_profile_ref=repository_ref,
            static_bundle_ref=bundle_ref,
            workspace_path=workspace,
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

    async def coverage_fingerprint(
        self, request: SimpleAnalysisRequest, identity: CheckpointIdentity
    ) -> str:
        workspace = self._profile.workspace_root / identity.workspace_id
        tracked = await self._tracked_files(workspace)
        binding = self._profile.tools["opengrep"]
        rules = self._materials / "opengrep" / "rules.yml"
        rule_plan = plan_rule_batches(
            rules.read_bytes(),
            tool_version=binding.version,
            executable_sha256=binding.executable_sha256,
        )
        return plan_static_coverage(
            workspace,
            tracked,
            request.commit,
            rule_plan,
            fallback_tool_fingerprint=self._fallback_fingerprint(),
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
            timeout_seconds=min(self._profile.max_elapsed_seconds, 900),
        )
        if clone.returncode != 0:
            raise RuntimeError("GIT_CLONE_FAILED")
        checkout = await self._process.run(
            (git, "checkout", "--detach", request.commit.lower()),
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
        if result.returncode != 0:
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
    def _repository_profile(tracked: tuple[str, ...]) -> dict[str, object]:
        suffixes = {Path(value).suffix.lower() for value in tracked}
        languages = tuple(
            language
            for language, extensions in (
                ("PYTHON", {".py", ".pyi"}),
                ("JAVASCRIPT_TYPESCRIPT", {".js", ".jsx", ".ts", ".tsx"}),
            )
            if suffixes & extensions
        )
        manifests = tuple(
            value
            for value in tracked
            if Path(value).name
            in {
                "requirements.txt",
                "pyproject.toml",
                "Pipfile",
                "package.json",
                "package-lock.json",
                "Dockerfile",
            }
        )
        return {
            "kind": "simple_repository_profile",
            "languages": languages,
            "manifests": manifests,
            "tracked_file_count": len(tracked),
            "needs_confirmation": not languages,
        }

    def _python_ast(
        self,
        workspace: Path,
        tracked: tuple[str, ...],
    ) -> dict[str, object]:
        facts: list[dict[str, object]] = []
        parse_errors: list[str] = []
        oversize_count = 0
        for relative in tracked:
            if not relative.endswith(".py") or len(facts) >= _MAX_FACTS:
                continue
            path = workspace / relative
            try:
                if path.stat().st_size > _MAX_SOURCE_BYTES:
                    oversize_count += 1
                    continue
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (OSError, UnicodeError, SyntaxError):
                parse_errors.append(relative)
                continue
            for node in ast.walk(tree):
                if isinstance(
                    node,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                ):
                    facts.append(
                        {
                            "kind": type(node).__name__,
                            "path": relative,
                            "line": node.lineno,
                            "name": node.name,
                        }
                    )
                elif isinstance(node, ast.Call):
                    name = self._call_name(node.func)
                    if name:
                        facts.append(
                            {
                                "kind": "Call",
                                "path": relative,
                                "line": node.lineno,
                                "name": name,
                            }
                        )
                if len(facts) >= _MAX_FACTS:
                    break
        return {
            "kind": "simple_python_ast",
            "facts": facts,
            "parse_errors": parse_errors[:100],
            "parse_error_count": len(parse_errors),
            "oversize_count": oversize_count,
            "truncated": len(facts) >= _MAX_FACTS,
        }

    @staticmethod
    def _call_name(node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = DirectStaticBootstrap._call_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return None

    async def _run_opengrep(
        self,
        workspace: Path,
        request: SimpleAnalysisRequest,
        identity: CheckpointIdentity,
    ) -> bytes:
        await self._verify_opengrep_workspace(workspace, request)
        if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identity.analysis_id) is None:
            raise RuntimeError("OPENGREP_ANALYSIS_ID_INVALID")
        binding = self._profile.tools.get("opengrep")
        if binding is None:
            raise RuntimeError("OPENGREP_TOOL_NOT_CONFIGURED")
        self._require_opengrep_tool(binding)
        rules = self._materials / "opengrep" / "rules.yml"
        plan = plan_rule_batches(
            rules.read_bytes(),
            tool_version=binding.version,
            executable_sha256=binding.executable_sha256,
        )
        output_root = (
            request.data_dir / "process-output" / "simple-static" / identity.analysis_id
        )
        output_root.mkdir(parents=True, exist_ok=True)
        artifacts = SimpleArtifactRepository(request.data_dir, identity)
        deadline = time.monotonic() + min(self._profile.max_elapsed_seconds, 3600)
        accepted: list[tuple[RuleBatch, StoredDataRef, dict[str, object]]] = []
        for batch in plan.batches:
            previous = self._store.opengrep_batch_ref(
                identity, request.repository, plan.fingerprint, batch.key
            )
            if previous is not None:
                try:
                    cached = artifacts.read(previous)
                    parsed = parse_rule_batch(cached, batch)
                except (OSError, ValueError):
                    artifacts.quarantine_corrupt(previous)
                else:
                    accepted.append((batch, previous, parsed))
                    continue
            remaining = int(deadline - time.monotonic())
            if remaining < 1:
                raise RuntimeError("EXTERNAL_TOOL_TIMEOUT")
            self._require_opengrep_tool(binding)
            output = output_root / f"opengrep-{batch.index:03d}-{batch.key[:12]}.json"
            output.unlink(missing_ok=True)
            argv = (
                self._tool("opengrep"),
                "scan",
                "--json",
                "--disable-version-check",
                "--no-rewrite-rule-ids",
                "--config",
                str(rules),
                "--output",
                str(output),
                *(
                    value
                    for rule_id in batch.excluded_rule_ids
                    for value in ("--exclude-rule", rule_id)
                ),
                str(workspace),
            )
            result = await self._process.run(
                argv, cwd=workspace, timeout_seconds=remaining
            )
            self._require_opengrep_tool(binding)
            if result.returncode != 0 or not output.is_file():
                raise RuntimeError("OPENGREP_EXECUTION_FAILED")
            raw = output.read_bytes()
            parsed = parse_rule_batch(raw, batch)
            ref = artifacts.put_bytes(raw, "application/json")
            self._store.save_opengrep_batch(
                identity,
                request.repository,
                plan.fingerprint,
                batch.key,
                ref,
                replaces=previous,
            )
            accepted.append((batch, ref, parsed))
        return aggregate_rule_batches(plan, accepted)

    async def _collect_opengrep(
        self,
        workspace: Path,
        request: SimpleAnalysisRequest,
        identity: CheckpointIdentity,
        rule_plan: RuleBatchPlan,
        coverage_plan: StaticCoveragePlan,
        artifacts: SimpleArtifactRepository,
    ) -> tuple[list[CoverageSlice], list[StoredDataRef], list[str]]:
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
        deadline = time.monotonic() + min(self._profile.max_elapsed_seconds, 3600)
        slices: list[CoverageSlice] = []
        refs: list[StoredDataRef] = []
        errors: list[str] = []
        attempts = {
            item.run_key: item
            for item in self._store.list_static_scan_attempts(
                identity, request.repository, coverage_plan.fingerprint
            )
            if item.tool == "opengrep"
        }
        for batch in rule_plan.batches:
            expected = frozenset(
                pair
                for pair in coverage_plan.expected_pairs
                if pair[1] in batch.rule_ids
            )
            previous = self._store.opengrep_batch_ref(
                identity, request.repository, rule_plan.fingerprint, batch.key
            )
            cached_refs = [
                ref
                for ref in (
                    previous,
                    attempts[batch.key].raw_ref if batch.key in attempts else None,
                )
                if ref is not None
            ]
            reused = False
            for ref in cached_refs:
                try:
                    raw = artifacts.read(ref)
                    parsed = parse_rule_batch(raw, batch, allow_errors=True)
                    slice_ = assess_scan(coverage_plan, batch, raw, engine="opengrep")
                except (OSError, ValueError):
                    artifacts.quarantine_corrupt(ref)
                    continue
                if ref == previous and parsed.get("errors"):
                    continue
                self._require_opengrep_tool(binding)
                slices.append(replace(slice_, raw_ref=ref))
                refs.append(ref)
                if not expected.issubset(slice_.verified_pairs):
                    errors.append("OPENGREP_PARTIAL_SCAN")
                reused = True
                break
            if reused:
                continue
            remaining = int(deadline - time.monotonic())
            if remaining < 1:
                code = "EXTERNAL_TOOL_TIMEOUT"
                errors.append(code)
                self._record_static_failure(
                    identity,
                    request,
                    coverage_plan,
                    "opengrep",
                    batch.key,
                    expected,
                    code,
                    slices,
                )
                continue
            output = output_root / f"opengrep-{batch.index:03d}-{batch.key[:12]}.json"
            output.unlink(missing_ok=True)
            argv = (
                self._tool("opengrep"),
                "scan",
                "--json",
                "--disable-version-check",
                "--no-rewrite-rule-ids",
                "--config",
                str(rules),
                "--output",
                str(output),
                *(
                    value
                    for rule_id in batch.excluded_rule_ids
                    for value in ("--exclude-rule", rule_id)
                ),
                str(workspace),
            )
            raw_ref: StoredDataRef | None = None
            try:
                self._require_opengrep_tool(binding)
                result = await self._process.run(
                    argv, cwd=workspace, timeout_seconds=remaining
                )
                self._require_opengrep_tool(binding)
                if output.is_file():
                    raw = output.read_bytes()
                    raw_ref = artifacts.put_bytes(raw, "application/json")
                    refs.append(raw_ref)
                if result.returncode != 0 or raw_ref is None:
                    raise RuntimeError("OPENGREP_EXECUTION_FAILED")
                slice_ = assess_scan(coverage_plan, batch, raw, engine="opengrep")
                slices.append(replace(slice_, raw_ref=raw_ref))
                complete = expected.issubset(slice_.verified_pairs)
                scan_code: str | None = (
                    None if complete else "OPENGREP_PARTIAL_SCAN"
                )
                if scan_code is not None:
                    errors.append(scan_code)
                self._store.save_static_scan_attempt(
                    identity,
                    request.repository,
                    coverage_plan.fingerprint,
                    "opengrep",
                    batch.key,
                    "SUCCEEDED" if complete else "BLOCKED",
                    raw_ref,
                    None,
                    scan_code,
                )
                if complete and not slice_.parsed.get("errors"):
                    self._store.save_opengrep_batch(
                        identity,
                        request.repository,
                        rule_plan.fingerprint,
                        batch.key,
                        raw_ref,
                        replaces=previous,
                    )
            except (OSError, RuntimeError, ValueError) as error:
                code = self._safe_static_error(error, "OPENGREP_RESULT_INVALID")
                errors.append(code)
                self._store.save_static_scan_attempt(
                    identity,
                    request.repository,
                    coverage_plan.fingerprint,
                    "opengrep",
                    batch.key,
                    "BLOCKED",
                    raw_ref,
                    None,
                    code,
                )
                self._record_gap_slice(batch, expected, code, slices)
        return slices, refs, errors

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
    ) -> tuple[list[CoverageSlice], list[StoredDataRef], list[str]]:
        missing = finish_coverage(coverage_plan, opengrep_slices).gaps
        if not missing:
            return [], [], []
        binding = self._profile.tools.get("semgrep")
        if binding is None:
            return [], [], ["SEMGREP_TOOL_UNAVAILABLE"]
        attempts = {
            item.run_key: item
            for item in self._store.list_static_scan_attempts(
                identity, request.repository, coverage_plan.fingerprint
            )
            if item.tool == "semgrep"
        }
        slices: list[CoverageSlice] = []
        refs: list[StoredDataRef] = []
        errors: list[str] = []
        for original in rule_plan.batches:
            by_path: dict[str, set[str]] = defaultdict(set)
            for gap in missing:
                if gap.rule_id in original.rule_ids:
                    by_path[gap.path].add(gap.rule_id)
            grouped: dict[tuple[str, ...], list[str]] = defaultdict(list)
            for path, rule_ids in sorted(by_path.items()):
                grouped[tuple(sorted(rule_ids))].append(path)
            for selected, all_targets in sorted(grouped.items()):
                for start in range(0, len(all_targets), 32):
                    targets = tuple(all_targets[start : start + 32])
                    run_key = hashlib.sha256(
                        canonical_bytes(
                            {
                                "batch": original.key,
                                "rules": selected,
                                "targets": targets,
                            }
                        )
                    ).hexdigest()
                    batch = RuleBatch(
                        index=original.index,
                        rule_ids=selected,
                        excluded_rule_ids=tuple(
                            rule_id
                            for rule_id in rule_plan.rule_ids
                            if rule_id not in selected
                        ),
                        key=run_key,
                    )
                    previous = attempts.get(run_key)
                    if (
                        previous is not None
                        and previous.status == "SUCCEEDED"
                        and previous.raw_ref is not None
                    ):
                        try:
                            cached = artifacts.read(previous.raw_ref)
                            slice_ = assess_scan(
                                coverage_plan,
                                batch,
                                cached,
                                engine="semgrep",
                                targets=targets,
                            )
                            expected = {
                                (path, rule_id)
                                for path in targets
                                for rule_id in selected
                            }
                            if expected.issubset(slice_.verified_pairs):
                                slices.append(replace(slice_, raw_ref=previous.raw_ref))
                                refs.append(previous.raw_ref)
                                continue
                        except (OSError, ValueError):
                            artifacts.quarantine_corrupt(previous.raw_ref)
                    raw_ref: StoredDataRef | None = None
                    try:
                        raw = await run_semgrep_fallback(
                            self._process,
                            binding,
                            workspace,
                            rules,
                            targets,
                            batch.excluded_rule_ids,
                            min(self._profile.max_elapsed_seconds, 3600),
                        )
                        raw_ref = artifacts.put_bytes(raw, "application/json")
                        refs.append(raw_ref)
                        slice_ = assess_scan(
                            coverage_plan,
                            batch,
                            raw,
                            engine="semgrep",
                            targets=targets,
                        )
                        slices.append(replace(slice_, raw_ref=raw_ref))
                        expected = {
                            (path, rule_id) for path in targets for rule_id in selected
                        }
                        complete = expected.issubset(slice_.verified_pairs)
                        code = None if complete else "SEMGREP_PARTIAL_SCAN"
                        if code is not None:
                            errors.append(code)
                    except (OSError, RuntimeError, ValueError) as error:
                        if (
                            isinstance(error, SemgrepFallbackError)
                            and error.raw_output is not None
                        ):
                            raw_ref = artifacts.put_bytes(
                                error.raw_output, "application/octet-stream"
                            )
                            refs.append(raw_ref)
                        code = self._safe_static_error(error, "SEMGREP_RESULT_INVALID")
                        errors.append(code)
                    self._store.save_static_scan_attempt(
                        identity,
                        request.repository,
                        coverage_plan.fingerprint,
                        "semgrep",
                        run_key,
                        "SUCCEEDED" if code is None else "BLOCKED",
                        raw_ref,
                        None,
                        code,
                    )
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
            or head.stdout.decode("ascii", errors="ignore").strip().lower()
            != request.commit.lower()
        ):
            raise RuntimeError("GIT_COMMIT_MISMATCH")
        status = await self._process.run(
            (git, "status", "--porcelain=v1", "-z", "--untracked-files=all"),
            cwd=workspace,
            timeout_seconds=60,
        )
        if status.returncode != 0:
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
        if ignored.returncode != 0:
            raise RuntimeError("GIT_IGNORED_FILES_FAILED")
        for entry in ignored.stdout.split(b"\0"):
            leaf = entry.replace(b"\\", b"/").rsplit(b"/", 1)[-1].lower()
            if leaf in {b".semgrepignore", b".gitignore"}:
                raise RuntimeError("WORKSPACE_DIRTY")

    async def _run_codeql(
        self,
        workspace: Path,
        data_dir: Path,
        repository: str,
        commit: str,
        analysis_id: str,
    ) -> bytes:
        key = hashlib.sha256(f"{repository}\0{commit}".encode()).hexdigest()[:24]
        analysis_key = hashlib.sha256(analysis_id.encode()).hexdigest()[:24]
        root = data_dir / "codeql" / key
        database = root / "database"
        output = root / f"results-{analysis_key}.sarif"
        root.mkdir(parents=True, exist_ok=True)
        codeql = self._tool("codeql")
        if not (database / "codeql-database.yml").is_file():
            created = await self._process.run(
                (
                    codeql,
                    "database",
                    "create",
                    str(database),
                    "--language=python",
                    f"--source-root={workspace}",
                    "--overwrite",
                    "--threads=2",
                ),
                cwd=workspace,
                timeout_seconds=min(self._profile.max_elapsed_seconds, 1800),
            )
            if created.returncode != 0:
                raise RuntimeError("CODEQL_DATABASE_CREATE_FAILED")
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
                "--threads=2",
            ),
            cwd=workspace,
            timeout_seconds=min(self._profile.max_elapsed_seconds, 1800),
        )
        if analyzed.returncode != 0 or not output.is_file():
            raise RuntimeError("CODEQL_ANALYZE_FAILED")
        raw = output.read_bytes()
        json.loads(raw)
        return raw

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
        schema = {
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
        seeds: list[HypothesisSeed] = []
        seen: set[str] = set()
        for index, value in enumerate(raw[: self._max_hypotheses]):
            if not isinstance(value, dict):
                continue
            canonical = canonical_bytes(value)
            hypothesis_id = (
                "hypothesis-"
                + hashlib.sha256(
                    static.static_bundle_ref.content_hash.encode()
                    + index.to_bytes(4, "big")
                    + canonical
                ).hexdigest()[:32]
            )
            if hypothesis_id in seen:
                continue
            seen.add(hypothesis_id)
            proposal_ref = artifacts.put_json(
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
                }
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
