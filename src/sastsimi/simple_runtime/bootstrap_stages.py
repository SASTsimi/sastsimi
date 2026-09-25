"""Direct repository, static-fact, and Hypothesis Agent bootstrap stages."""

from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import os
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sastsimi.config.user_config import SimpleExecutionProfile
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .application import (
    HypothesisSeed,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from .artifacts import SimpleArtifactRepository
from .models import CheckpointIdentity, StageFailure
from .provider import SimpleLLMCallResult, SimpleLLMClient

_MAX_TRACKED_FILES = 200_000
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
# Every tracked Python file is parsed.  The old ten-thousand-fact cut stopped
# part-way through the file list, so a repository's later directories were
# absent from the evidence entirely - one run reached only 70 of 225 files and
# never saw the routers the target defect lived in.  Parsing all of them was
# measured at 1.3 seconds for 3.1 MB, and what the prompt can carry is decided
# separately when the bundle is rendered.  This ceiling only stops a runaway.
_MAX_FACTS = 2_000_000
# How many files the index may name.  A repository larger than this is summarised
# by its busiest files; the count says how many were left out rather than hiding
# them.
_MAX_INDEXED_FILES = 1_500
# A constant longer than this is prose or a template, not a decision.
_MAX_LITERAL_CHARS = 60
# Which callee names are worth naming in the index.  Counting facts says how
# much a file does, not what it does, and the name is what tells an agent a
# file is worth asking for: measured on open-webui, ``unquote`` together with a
# path normaliser appears in two of two hundred and twenty three files, and
# those two are the pair the advisory's fix touched.  Static tools said nothing
# about either, because both already had a sanitiser and only its loop bound
# was wrong.
#
# This is a hint, never a verdict, and the list is knowingly incomplete: a name
# that is missing costs a hint, and the facts themselves stay retrievable.
_NOTABLE_CALLS = frozenset(
    {
        # taking apart a name the caller supplied
        "unquote",
        "unquote_plus",
        "urlparse",
        "urlsplit",
        "urljoin",
        "normpath",
        "realpath",
        "abspath",
        "relpath",
        "expanduser",
        "resolve",
        "commonpath",
        "commonprefix",
        "samefile",
        "basename",
        "dirname",
        # the checks meant to make that safe
        "startswith",
        "endswith",
        "match",
        "fullmatch",
        "search",
        # what a bypass reaches
        "open",
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
        "unlink",
        "rmtree",
        "copy",
        "move",
        "send_file",
        "FileResponse",
        "redirect",
        "RedirectResponse",
        "urlopen",
        "request",
        "eval",
        "exec",
        "system",
        "popen",
        "Popen",
        "check_output",
        "call",
        "literal_eval",
        "loads",
        "load",
        "execute",
        "executescript",
        "raw",
    }
)


def _is_notable(name: str) -> bool:
    return name.rsplit(".", 1)[-1] in _NOTABLE_CALLS


def _ast_index(ast_result: dict[str, object]) -> dict[str, object]:
    """Describe the AST facts without carrying them.

    An agent needs to know which file holds what before it can ask for
    anything, so the index keeps every file's name, how many facts it has and
    which kinds they are.  The facts stay where they were written; this is the
    map that says which ones are worth reading.
    """

    facts = ast_result.get("facts")
    facts = facts if isinstance(facts, list) else []
    per_file: dict[str, Counter[str]] = defaultdict(Counter)
    notable: dict[str, set[str]] = defaultdict(set)
    for fact in facts:
        if not isinstance(fact, dict):
            continue
        path = fact.get("path")
        kind = fact.get("kind")
        if not isinstance(path, str) or not isinstance(kind, str):
            continue
        per_file[path][kind] += 1
        name = fact.get("name")
        if kind == "Call" and isinstance(name, str) and _is_notable(name):
            notable[path].add(name)
    ordered = sorted(
        per_file.items(), key=lambda item: (-sum(item[1].values()), item[0])
    )
    return {
        "kind": "simple_python_ast_index",
        "total_facts": len(facts),
        "indexed_files": min(len(ordered), _MAX_INDEXED_FILES),
        "omitted_files": max(0, len(ordered) - _MAX_INDEXED_FILES),
        "python_files": ast_result.get("python_files"),
        "covered_files": ast_result.get("covered_files"),
        "truncated": ast_result.get("truncated"),
        "skipped_count": ast_result.get("skipped_count"),
        "skipped_files": ast_result.get("skipped_files"),
        "parse_errors": ast_result.get("parse_errors"),
        "files": [
            {
                "path": path,
                "facts": sum(kinds.values()),
                "kinds": dict(sorted(kinds.items())),
                **(
                    {"notable_calls": sorted(notable[path])}
                    if notable.get(path)
                    else {}
                ),
            }
            for path, kinds in ordered[:_MAX_INDEXED_FILES]
        ],
    }


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


class LocalProcessExecutor:
    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout_seconds: int,
    ) -> ProcessResult:
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._environment(),
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout_seconds
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            raise RuntimeError("EXTERNAL_TOOL_TIMEOUT") from None
        return ProcessResult(
            returncode=process.returncode or 0,
            stdout=stdout[: 32 * 1024 * 1024],
            stderr=stderr[: 1024 * 1024],
        )

    @staticmethod
    def _environment() -> dict[str, str]:
        allowed = {
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "TMPDIR",
            "HOME",
            "USERPROFILE",
            "LANG",
            "LC_ALL",
        }
        return {key: value for key, value in os.environ.items() if key in allowed}


class DirectStaticBootstrap:
    """Run clone, AST, OpenGrep and optional CodeQL without the lease runtime."""

    def __init__(
        self,
        *,
        profile: SimpleExecutionProfile,
        process: ProcessExecutor | None = None,
        static_material_root: Path | None = None,
    ) -> None:
        self._profile = profile
        self._process = process or LocalProcessExecutor()
        self._materials = static_material_root or self._static_material_root()

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
        opengrep_raw = await self._run_opengrep(
            workspace,
            request.data_dir,
            identity.analysis_id,
        )
        opengrep_ref = artifacts.put_bytes(opengrep_raw, "application/json")
        codeql_ref: StoredDataRef | None = None
        codeql_findings: list[dict[str, object]] = []
        if "codeql" in self._profile.tools:
            codeql_raw = await self._run_codeql(
                workspace,
                request.data_dir,
                request.repository,
                request.commit,
            )
            codeql_ref = artifacts.put_bytes(codeql_raw, "application/sarif+json")
            codeql_findings = self._codeql_findings(workspace, codeql_raw)
        snippets = self._opengrep_snippets(workspace, opengrep_raw)
        bundle_ref = artifacts.put_json(
            {
                "kind": "simple_static_fact_bundle",
                "analysis_id": identity.analysis_id,
                "workspace_id": identity.workspace_id,
                "commit_id": identity.commit_id,
                "repository_profile_ref": repository_ref.model_dump(mode="json"),
                "tool_result_refs": [
                    ast_ref.model_dump(mode="json"),
                    opengrep_ref.model_dump(mode="json"),
                    *(
                        [codeql_ref.model_dump(mode="json")]
                        if codeql_ref is not None
                        else []
                    ),
                ],
                # The facts themselves are three megabytes for a mid-sized
                # repository and were the reason a prompt reached half a
                # million tokens.  They stay in their own artifact, which
                # ``tool_result_refs`` already names, and the bundle carries
                # the map an agent needs to decide what to ask for.
                "ast_index": _ast_index(ast_result),
                "opengrep_findings": snippets,
                "codeql_findings": codeql_findings,
                "codeql_executed": codeql_ref is not None,
            }
        )
        return StaticBootstrapResult(
            repository_profile_ref=repository_ref,
            static_bundle_ref=bundle_ref,
            workspace_path=workspace,
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
            (git, "clone", "--no-checkout", "--", request.repository, str(workspace)),
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
        # The design requires an omission to be recorded, not merely counted:
        # a file that is missing from the evidence and missing from the record
        # reads to an agent as a file that does not exist.
        skipped: list[dict[str, str]] = []
        for relative in tracked:
            if not relative.endswith(".py"):
                continue
            if len(facts) >= _MAX_FACTS:
                skipped.append({"path": relative, "reason": "FACT_BUDGET_EXHAUSTED"})
                continue
            path = workspace / relative
            try:
                if path.stat().st_size > _MAX_SOURCE_BYTES:
                    skipped.append({"path": relative, "reason": "FILE_TOO_LARGE"})
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
                        fact: dict[str, object] = {
                            "kind": "Call",
                            "path": relative,
                            "line": node.lineno,
                            "name": name,
                        }
                        literals = self._literal_arguments(node)
                        if literals:
                            fact["args"] = literals
                        facts.append(fact)
                if len(facts) >= _MAX_FACTS:
                    skipped.append(
                        {"path": relative, "reason": "FACT_BUDGET_EXHAUSTED"}
                    )
                    break
        return {
            "kind": "simple_python_ast",
            "facts": facts,
            "parse_errors": parse_errors[:100],
            "skipped_files": skipped[:500],
            "skipped_count": len(skipped),
            "python_files": sum(1 for value in tracked if value.endswith(".py")),
            "covered_files": len({str(fact["path"]) for fact in facts}),
            "truncated": bool(skipped),
        }

    @staticmethod
    def _literal_arguments(node: ast.Call) -> list[object]:
        """Return the constants written out at the call site.

        The name of a call says what is being done; a constant written beside
        it is often the whole decision.  ``range(8)`` in open-webui's
        ``_sanitize_proxy_path`` is the advisory's entire subject - a path
        encoded more times than the cap leaves the loop still encoded - and
        without the ``8`` nothing downstream can see it.  Only numbers and
        short strings are kept, so the cost measured about seven percent.
        """

        literals: list[object] = []
        for argument in node.args:
            if not isinstance(argument, ast.Constant):
                continue
            value = argument.value
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                continue
            literals.append(
                value[:_MAX_LITERAL_CHARS] if isinstance(value, str) else value
            )
        return literals

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
        data_dir: Path,
        analysis_id: str,
    ) -> bytes:
        output = (
            data_dir
            / "process-output"
            / "simple-static"
            / analysis_id
            / "opengrep.json"
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        rules = self._materials / "opengrep" / "rules.yml"
        result = await self._process.run(
            (
                self._tool("opengrep"),
                "scan",
                "--json",
                "--config",
                str(rules),
                "--output",
                str(output),
                str(workspace),
            ),
            timeout_seconds=min(self._profile.max_elapsed_seconds, 900),
        )
        if result.returncode not in {0, 1} or not output.is_file():
            raise RuntimeError("OPENGREP_EXECUTION_FAILED")
        raw = output.read_bytes()
        json.loads(raw)
        return raw

    async def _run_codeql(
        self,
        workspace: Path,
        data_dir: Path,
        repository: str,
        commit: str,
    ) -> bytes:
        key = hashlib.sha256(f"{repository}\0{commit}".encode()).hexdigest()[:24]
        root = data_dir / "codeql" / key
        database = root / "database"
        output = root / "results.sarif"
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
        # Proposing hypotheses reads the whole static bundle, so it needs the
        # same elapsed share the later stages get rather than a fixed three
        # minutes a large repository routinely exceeds.
        call_timeout_ms: int = 180_000,
    ) -> None:
        self._data_dir = data_dir
        self._client_factory = client_factory
        self._max_hypotheses = max_hypotheses
        self._call_timeout_ms = call_timeout_ms

    async def propose(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> tuple[HypothesisSeed, ...]:
        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        # Proposing the hypotheses is the reasoning the whole run is built on.
        client = self._client_factory(identity, artifacts, deep=True)
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
            timeout_ms=self._call_timeout_ms,
        )
        if isinstance(result, StageFailure):
            raise RuntimeError(result.code)
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
        *,
        deep: bool = False,
    ) -> SimpleLLMClient: ...


__all__ = [
    "DirectHypothesisBootstrap",
    "DirectStaticBootstrap",
    "LocalProcessExecutor",
    "ProcessExecutor",
    "ProcessResult",
]
