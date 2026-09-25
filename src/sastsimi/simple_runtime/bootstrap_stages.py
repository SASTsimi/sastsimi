"""Direct repository, static-fact, and Hypothesis Agent bootstrap stages."""

from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from sastsimi.config.user_config import SimpleExecutionProfile
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .application import (
    HypothesisSeed,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from .artifacts import SimpleArtifactRepository
from .exploration import MAX_ROUNDS, Exploration, render_round
from .facts import extract_flows
from .feeding import (
    Batch,
    Feeding,
    fenced,
    plan_fact_feeding,
    plan_feeding,
    render_batch,
)
from .models import CheckpointIdentity, StageFailure
from .proposals import (
    PROPOSAL_INSTRUCTIONS,
    PROPOSAL_ITEM_SCHEMA,
    Registry,
    validate_proposal,
)
from .provider import (
    SimpleConversation,
    SimpleLLMCallResult,
    SimpleLLMClient,
    conversation_with,
)
from .retrieval import collect_requested_ast, collect_requested_sources

_MAX_TRACKED_FILES = 200_000
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
# Every tracked Python file is parsed.  The old ten-thousand-fact cut stopped
# part-way through the file list, so a repository's later directories were
# absent from the evidence entirely - one run reached only 70 of 225 files and
# never saw the routers the target defect lived in.  Parsing all of them was
# measured at 1.3 seconds for 3.1 MB, and what the prompt can carry is decided
# separately when the bundle is rendered.  This ceiling only stops a runaway.
_MAX_FACTS = 2_000_000
# A constant longer than this is prose or a template, not a decision.
_MAX_LITERAL_CHARS = 60
# Which files an agent may ask for.  This is the checkout's own list, not a
# judgement about what matters: deciding that in advance is what a static rule
# does, and the point of asking an agent is that it decides.  Everything else
# about a file - its facts, its text - is served when it is requested.
_SOURCE_SUFFIXES = (".py", ".pyi", ".js", ".jsx", ".ts", ".tsx")


type _Provenance = tuple[int, SimpleLLMCallResult, list[dict[str, object]]]

_HYPOTHESIS_INSTRUCTIONS = """# Role: Hypothesis Agent

You are reading one batch of this repository's source in full. Every file of
the checkout is read in exactly one batch, and the repository map names every
definition in the others. Each line of code is shown after its real line
number and a `|`.

## What to return

- Every concrete web-security hypothesis this code supports - as many as the
  code gives, and none when it gives none.
- Static tool hits are facts, not verdicts. A defect a tool is silent about is
  the one worth finding: a guard that is present but subtly wrong produces no
  finding at all.
- Do not invent missing code.

## Guards are candidates, not proof

A sanitizer, validator or permission check is a candidate defence, not proof
of safety.

- When input reaches a sink through one, do not drop the flow because the guard
  exists, and do not cite it as the reason another flow is safe.
- Read the guard itself: its loop bounds, the order of decoding and checking,
  what it does when a bound is reached, what it normalises and what it
  compares.
- Propose the hypothesis that it can be bypassed, stating how. Verification
  decides whether it holds.

## Following a flow out of this batch

Name in `requested_paths` the files you need to follow it, or in
`requested_ast_paths` those you only need the shape of, and you will be asked
again with them. Leave both empty when you have what you need.

## Form of each hypothesis

"""


_FOLLOW_UP = (
    b"Continue with these files. Return the complete list of hypotheses for "
    b"this batch again - every earlier one that still holds, corrected where "
    b"these files change it, and any new ones - because only this answer is "
    b"kept. Request more files only if a flow still leaves what you have.\n"
)


def _required(result: SimpleLLMCallResult | StageFailure) -> SimpleLLMCallResult:
    if isinstance(result, StageFailure):
        raise RuntimeError(result.code)
    return result


_FACT_INSTRUCTIONS = """# Role: Hypothesis Agent

You are reading one batch of this repository's fact bundle. Every entry point of
the checkout - a route, websocket or event handler - is in exactly one batch.
For each one you have its inputs and every call its input reaches, in order,
with the line, the arguments that carry input and, where the callee is defined
in this repository, where. The repository map names every definition.

You have not read the code yet. Read it before you decide:

- Ask in `requested_paths` for a whole file (`path`) or for lines
  (`path:start-end`); you will be asked again with them.
- Read every repository-defined step on a flow that reaches something that
  matters - a request, a file, a query, a redirect, a template, a command - and
  the handler around it.
- A requested file comes with the static tool hits recorded for it.
- `requested_ast_paths` gives a file's parsed definitions and calls instead.
- Leave both empty when you have read what you need.

## What to return

- Every concrete web-security hypothesis these flows and the code you read
  support - as many as they give, and none when they give none.
- Static tool hits are facts, not verdicts. A defect a tool is silent about is
  the one worth finding.
- Do not invent missing code.

## Guards are candidates, not proof

A repository function on a flow - a sanitizer, a validator, a permission check -
is a candidate defence, not proof of safety. Read it: its loop bounds, the
order of decoding and checking, what it does when a bound is reached, what it
normalises and what it compares. Propose the hypothesis that it can be
bypassed, stating how; verification decides whether it holds.

## Form of each hypothesis

"""


def _findings_by_file(bundle: dict[str, object]) -> dict[str, list[dict[str, object]]]:
    by_file: dict[str, list[dict[str, object]]] = {}
    for key in ("codeql_findings", "opengrep_findings"):
        values = bundle.get(key)
        for value in values if isinstance(values, list) else []:
            if isinstance(value, dict) and value.get("path"):
                path = str(value["path"]).lstrip("/")
                by_file.setdefault(path, []).append({"tool": key[:-9], **value})
    return by_file


def _attach_findings(
    sources: dict[str, object], findings: dict[str, list[dict[str, object]]]
) -> None:
    """Give each served file the tool hits recorded for it, within its lines."""

    served = sources.get("served")
    for item in served if isinstance(served, list) else []:
        path, _, span = str(item.get("path", "")).partition(":")
        hits = findings.get(path, [])
        if span:
            start, _, end = span.partition("-")
            low, high = int(start), int(end or start)
            hits = [
                hit
                for hit in hits
                if isinstance(line := hit.get("line"), int) and low <= line <= high
            ]
        if hits:
            item["tool_findings"] = hits


# Bodies of rejected proposals, held only until the one repair call reads them.
_REJECTED_BODIES: dict[str, object] = {}


def _line_counts(workspace: Path, sources: Sequence[str]) -> dict[str, int]:
    """Every file a proposal may name, with how many lines it has."""

    counts: dict[str, int] = {}
    for path in sources:
        try:
            counts[path] = len(
                (workspace / path).read_text(encoding="utf-8").splitlines()
            )
        except (OSError, UnicodeError):
            continue
    return counts


def _reading_record(history: Exploration) -> list[dict[str, object]]:
    """Name what each round asked for, got and was refused - not the text."""

    rounds: list[dict[str, object]] = []
    for entry in history.rounds:
        served: list[str] = []
        refused: list[object] = []
        for batch in (entry.sources, entry.ast):
            if not batch:
                continue
            served.extend(
                str(item.get("path"))
                for item in batch.get("served", ())
                if isinstance(item, dict)
            )
            refused.extend(batch.get("refused", ()))
        rounds.append(
            {
                "round": entry.number,
                "requested": list(entry.requested_paths),
                "served": served,
                "refused": refused,
            }
        )
    return rounds


def _count(value: object) -> int:
    return len(value) if isinstance(value, list) else 0


# Where a project writes down what it will and will not accept as a report.
# Ordered by how authoritative the location is when more than one exists.
_POLICY_FILENAMES = (
    "SECURITY.md",
    ".github/SECURITY.md",
    "docs/SECURITY.md",
    "SECURITY.rst",
    ".github/SECURITY.rst",
    ".well-known/security.txt",
)


def _security_policy(
    workspace: Path, tracked: Sequence[str]
) -> dict[str, object] | None:
    """Return the repository's own reporting policy, if it states one.

    Without it the scope gate has nothing to judge against and every run ends
    "no official policy, internal review only" - while the project has often
    said plainly what it does not consider a vulnerability.  Open-webui's says
    configuration options are not vulnerabilities, which is exactly what one
    run reported.
    """

    available = {value.lstrip("./") for value in tracked}
    for name in _POLICY_FILENAMES:
        if name not in available:
            continue
        path = workspace / name
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if not text.strip():
            continue
        return {
            "kind": "simple_repository_security_policy",
            "path": name,
            "byte_count": len(raw),
            "content": text,
        }
    return None


def _string_list(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str) and item.strip())


def _source_listing(tracked: Sequence[str]) -> list[str]:
    return sorted(
        value for value in tracked if value.lower().endswith(_SOURCE_SUFFIXES)
    )


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
        # Kept out of the bundle itself: the bundle is quoted into every later
        # prompt, and the flows of a mid-sized repository are over half a
        # megabyte.  The hypothesis stage reads them by reference.
        flows = extract_flows(workspace, tracked)
        flows_ref = artifacts.put_json(flows)
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
                # The facts are three megabytes for a mid-sized repository and
                # were the reason a prompt reached half a million tokens.  They
                # stay in their own artifact, which ``tool_result_refs`` names,
                # and are served for the files an agent asks about.
                "source_files": _source_listing(tracked),
                "route_flows_ref": flows_ref.model_dump(mode="json"),
                "route_flow_summary": {
                    "entry_points": len(flows["entry_points"]),
                    "files_with_entry_points": flows["files_with_entry_points"],
                    "python_files": flows["python_files"],
                },
                "security_policy": _security_policy(workspace, tracked),
                "ast_fact_count": len(ast_result["facts"]),  # type: ignore[arg-type]
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
            "parse_errors": parse_errors,
            "skipped_files": skipped,
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
        for item in values:
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
                        "snippet": snippet,
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
                        "message": str(text),
                    }
                )
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
        # Proposing hypotheses reads the whole static bundle, so it needs the
        # same elapsed share the later stages get rather than a fixed three
        # minutes a large repository routinely exceeds.
        call_timeout_ms: int = 180_000,
        # ``code``: every source file is read.  ``facts``: the fact bundle's
        # entry points are read and source is fetched on request.
        feed: str = "code",
    ) -> None:
        self._data_dir = data_dir
        self._client_factory = client_factory
        self._call_timeout_ms = call_timeout_ms
        self._facts_cache: dict[str, Sequence[object]] = {}
        self._feed = feed

    async def _read_then_propose(
        self,
        talk: SimpleConversation,
        instructions: bytes,
        context: bytes,
        static: StaticBootstrapResult,
        artifacts: SimpleArtifactRepository,
        findings: dict[str, list[dict[str, object]]] | None = None,
    ) -> tuple[SimpleLLMCallResult, Exploration]:
        """Ask, serve what was asked for, ask again - in one conversation.

        Each follow-up turn carries only the files just served; the batch and
        everything read before are already in the conversation and are read
        from the prompt cache rather than sent again.
        """

        history = Exploration()
        result = _required(
            await talk.ask(
                instructions
                + b"<UNTRUSTED_EXACT_INPUTS>\n"
                + context
                + b"\n</UNTRUSTED_EXACT_INPUTS>\n"
            )
        )
        for _ in range(MAX_ROUNDS - 1):
            wanted = _string_list(result.value.get("requested_paths"))
            wanted_ast = _string_list(result.value.get("requested_ast_paths"))
            if not wanted and not wanted_ast:
                break
            sources = (
                collect_requested_sources(wanted, workspace=static.workspace_path)
                if wanted
                else None
            )
            if sources is not None and findings:
                _attach_findings(sources, findings)
            ast = (
                collect_requested_ast(
                    wanted_ast, facts=self._ast_facts(artifacts, static)
                )
                if wanted_ast
                else None
            )
            history.record(
                requested_paths=(*wanted, *wanted_ast),
                sources=sources,
                ast=ast,
                notes={"proposed_so_far": _count(result.value.get("hypotheses"))},
            )
            result = _required(
                await talk.ask(
                    b"<UNTRUSTED_EXACT_INPUTS>\n"
                    + render_round(history.as_prompt_document()).encode("utf-8")
                    + b"\n</UNTRUSTED_EXACT_INPUTS>\n"
                    + _FOLLOW_UP
                )
            )
        return result, history

    def _ast_facts(
        self, artifacts: SimpleArtifactRepository, static: StaticBootstrapResult
    ) -> Sequence[object]:
        """Read the parsed facts only once, and only if something asked."""

        cached = self._facts_cache.get(str(static.static_bundle_ref.content_hash))
        if cached is not None:
            return cached
        facts: Sequence[object] = ()
        try:
            bundle = json.loads(artifacts.read(static.static_bundle_ref))
            for raw in bundle.get("tool_result_refs", ()):
                document = json.loads(artifacts.read(StoredDataRef.model_validate(raw)))
                if document.get("kind") == "simple_python_ast":
                    facts = document.get("facts") or ()
                    break
        except (OSError, ValueError, KeyError):
            facts = ()
        self._facts_cache[str(static.static_bundle_ref.content_hash)] = facts
        return facts

    @staticmethod
    def _batch_context(
        bundle: dict[str, object], feeding: Feeding, batch: Batch
    ) -> bytes:
        """Everything one call reads: its code, the map of the rest, the hits.

        Tool findings go with the batch that holds their file, so a hit is read
        beside its code; a finding in a file no batch holds goes with the first.
        """

        fed = {path for each in feeding.batches for path in each.paths}
        mine = set(batch.paths)

        def findings(key: str) -> list[object]:
            values = bundle.get(key)
            if not isinstance(values, list):
                return []
            chosen: list[object] = []
            for value in values:
                path = value.get("path") if isinstance(value, dict) else None
                path = str(path).lstrip("/") if path else ""
                # With the code feed, only excluded files lie outside every
                # batch.  With the fact feed most files do, and their hits -
                # measured at over two megabytes - arrive with the file when
                # the agent asks for it instead.
                if path in mine or (
                    feeding.kind == "code" and batch.number == 1 and path not in fed
                ):
                    chosen.append(value)
            return chosen

        header = {
            "batch": batch.number,
            "batches": len(feeding.batches),
            "files_in_this_batch": list(batch.paths),
            "excluded_from_every_batch": feeding.excluded,
            **(
                {"files_with_no_entry_point_read_on_request": feeding.unfed}
                if feeding.kind == "facts"
                else {}
            ),
            "codeql_findings": findings("codeql_findings"),
            "opengrep_findings": findings("opengrep_findings"),
        }
        document = "\n\n".join(
            (
                f"# Batch {batch.number} of {len(feeding.batches)}",
                "## Batch facts and tool findings for these files",
                fenced(json.dumps(header, ensure_ascii=False, indent=1), "json"),
                "## Repository map (every definition in the checkout)",
                fenced(feeding.signature_map, "text"),
                "## Source of this batch"
                if feeding.kind == "code"
                else "## Entry points in these files and the calls their input reaches",
                render_batch(batch),
            )
        )
        return document.encode("utf-8")

    async def propose(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> tuple[HypothesisSeed, ...]:
        artifacts = SimpleArtifactRepository(self._data_dir, identity)
        # Proposing the hypotheses is the reasoning the whole run is built on.
        client = self._client_factory(identity, artifacts, deep=True)
        schema: dict[str, object] = {
            "type": "object",
            "properties": {
                "hypotheses": {"type": "array", "items": PROPOSAL_ITEM_SCHEMA},
                "requested_paths": {"type": "array", "items": {"type": "string"}},
                "requested_ast_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": ["hypotheses", "requested_paths", "requested_ast_paths"],
            "additionalProperties": False,
        }
        bundle = json.loads(artifacts.read(static.static_bundle_ref))
        if not isinstance(bundle, dict):
            raise RuntimeError("HYPOTHESIS_BUNDLE_INVALID")
        listed = bundle.get("source_files")
        sources = (
            [path for path in listed if isinstance(path, str)]
            if isinstance(listed, list)
            else []
        )
        # Every source file goes into exactly one batch; nothing is chosen for
        # the agent, because one that chose by name never opened the router
        # the target defect was in.
        feeding = plan_feeding(static.workspace_path, sources)
        flows_ref = bundle.get("route_flows_ref")
        if self._feed == "facts" and isinstance(flows_ref, dict):
            # The fact bundle's entry points are read first; source is read on
            # request, a file or a line range at a time.
            flows = json.loads(artifacts.read(StoredDataRef.model_validate(flows_ref)))
            feeding = plan_fact_feeding(flows, feeding)
        feeding_ref = artifacts.put_json(feeding.coverage())
        lines = _line_counts(static.workspace_path, sources)
        opening = (
            _FACT_INSTRUCTIONS if feeding.kind == "facts" else _HYPOTHESIS_INSTRUCTIONS
        )
        instructions = (opening + PROPOSAL_INSTRUCTIONS + "\n").encode("utf-8")
        registry = Registry(bundle_hash=str(static.static_bundle_ref.content_hash))
        findings = _findings_by_file(bundle)
        provenance: dict[
            str, tuple[int, SimpleLLMCallResult, list[dict[str, object]]]
        ] = {}

        async def read_batch(batch: Batch) -> None:
            context = self._batch_context(bundle, feeding, batch)
            async with conversation_with(
                client, output_schema=schema, timeout_ms=self._call_timeout_ms
            ) as talk:
                result, history = await self._read_then_propose(
                    talk,
                    instructions,
                    context,
                    static,
                    artifacts,
                    findings if feeding.kind == "facts" else None,
                )
                proposed = result.value.get("hypotheses", [])
                proposed = list(proposed) if isinstance(proposed, list) else []
                valid, rejected = self._validate_all(proposed, lines, batch.number)
                if rejected:
                    # The design allows a bounded repair before INVALID_OUTPUT.
                    repaired = await self._repair(talk, rejected)
                    again, still = self._validate_all(repaired, lines, batch.number)
                    valid.extend(again)
                    for proposal_id, errors in still:
                        registry.record_invalid(proposal_id, batch.number, errors)
            reading = _reading_record(history)
            # Registered after the conversation closes, so a batch never holds
            # its slot while waiting on a duplicate review's slot.
            for proposal_id, proposal in valid:
                entry = await registry.consider(
                    proposal,
                    proposal_id=proposal_id,
                    batch=batch.number,
                    client=client,
                    timeout_ms=self._call_timeout_ms,
                )
                if entry is not None:
                    provenance[entry.hypothesis_id] = (batch.number, result, reading)

        await asyncio.gather(*(read_batch(batch) for batch in feeding.batches))
        states_ref = artifacts.put_json(registry.record())
        seeds: list[HypothesisSeed] = []
        for entry in registry.registered:
            batch_number, result, reading = provenance[entry.hypothesis_id]
            proposal_ref = artifacts.put_json(
                {
                    "kind": "simple_hypothesis_proposal",
                    "analysis_id": identity.analysis_id,
                    "hypothesis_id": entry.hypothesis_id,
                    "static_bundle_ref": static.static_bundle_ref.model_dump(
                        mode="json"
                    ),
                    "proposal": entry.proposal,
                    "batch": batch_number,
                    "feeding_ref": feeding_ref.model_dump(mode="json"),
                    "process_states_ref": states_ref.model_dump(mode="json"),
                    "reading": reading,
                    "prompt_digest": result.prompt_digest,
                    "output_digest": result.output_digest,
                }
            )
            seeds.append(
                HypothesisSeed(
                    hypothesis_id=entry.hypothesis_id,
                    proposal_ref=proposal_ref,
                )
            )
        return tuple(seeds)

    @staticmethod
    def _validate_all(
        proposed: Sequence[object], lines: dict[str, int], batch: int
    ) -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, list[str]]]]:
        valid: list[tuple[str, dict[str, Any]]] = []
        rejected: list[tuple[str, list[str]]] = []
        for index, value in enumerate(proposed, start=1):
            proposal_id = (
                f"B{batch}-P{index}-"
                + hashlib.sha256(
                    canonical_bytes(
                        value if isinstance(value, (dict, list)) else str(value)
                    )
                ).hexdigest()[:8]
            )
            normalized, errors = validate_proposal(value, lines=lines)
            if normalized is None:
                rejected.append((proposal_id, errors))
                _REJECTED_BODIES[proposal_id] = value
            else:
                valid.append((proposal_id, normalized))
        return valid, rejected

    async def _repair(
        self, talk: SimpleConversation, rejected: list[tuple[str, list[str]]]
    ) -> list[object]:
        """Ask once more, in the same conversation, for the rejected proposals."""

        listing = [
            {"proposal": _REJECTED_BODIES.pop(pid, None), "errors": errors}
            for pid, errors in rejected
        ]
        answer = await talk.ask(
            b"## Rejected proposals\n\nThese proposals were rejected for the "
            b"reasons given. Return each corrected in `hypotheses`, or leave it "
            b"out if it cannot be corrected from the code; leave both request "
            b"lists empty. Return only these corrected proposals.\n\n```json\n"
            + canonical_bytes(listing)
            + b"\n```\n"
        )
        if not isinstance(answer, SimpleLLMCallResult):
            return []
        repaired = answer.value.get("hypotheses", [])
        return list(repaired) if isinstance(repaired, list) else []


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
