# Task 8 Real Static Fact Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare an exact Git commit, run AST, CodeQL, and OpenGrep through safe process boundaries, publish their exact attempt-scoped evidence, normalize it into one deterministic `StaticFactBundle`, and return bounded code context from that same workspace and commit.

**Architecture:** Keep the approved Pydantic contracts and the T07 fake vertical slice unchanged. Real process adapters return non-persisted typed observations and raw bytes; a trusted application coordinator supplies IDs, metadata, artifact storage, action/work transitions, and exact result publication through injected ports. `static_analysis/` imports only `contracts`, `ports`, and `config`; it never imports concrete `runtime` or `storage` modules.

**Tech Stack:** CPython `>=3.12,<3.13`, asyncio subprocesses, Git CLI, Python `ast`, CodeQL CLI, OpenGrep CLI, Pydantic 2 contracts, existing SQLite/content-addressed artifact ports, pytest, Ruff, and strict mypy.

**Spec:** `docs/architecture-v5/02-static-fact-layer.md`, `docs/architecture-v5/08-lightweight-data-contracts.md`, `docs/architecture-v5/10-security-boundaries.md`, `docs/architecture-v5/implementation/01-module-map.md`, and `docs/superpowers/plans/2026-09-08-sastsimi-complete-implementation.md` Task 8.

## Global Constraints

- Base implementation commit is `b3b2d9918ea815b9b936c09c98e4c53fd54937dc`.
- Do not change fields, enums, validators, result ownership, or reference meaning in `src/sastsimi/contracts/` or regenerate schemas with different content.
- Retain T07 `FakeStaticToolAdapter`, fake workspace setup, and deterministic 22-step scenarios as regression fixtures; real adapters are additive and are not selected by the CLI in this task.
- `CodeWorkspace.status=READY` is required before any code-scoped artifact, `STATIC_TOOL`, `STATIC_NORMALIZE`, or `CONTEXT_RETRIEVAL` work is accepted.
- The requested Git ref is resolved to one commit object, checked out detached, and verified against `HEAD`; branch names are never retained as the code identity.
- Repository source, destination, tool executable, query/rule catalog, timeout, environment, and file list come from trusted configuration or a claimed action, never from LLM output.
- Every process uses `asyncio.create_subprocess_exec(*argv)` with an argument tuple. No shell string, `shell=True`, command interpolation, repository executable, or executable discovered inside the analyzed workspace is allowed.
- Process environment is constructed from an allowlist. Git prompts, Git LFS smudge, external protocols, and repository hooks are disabled by default.
- A process writes only to an attempt-owned output directory outside the analyzed checkout. The analyzed checkout is never a build output directory.
- CodeQL may analyze an exact prebuilt database. T08 must not invoke `codeql database create`, `--command`, autobuild, build scripts, package installation, or repository code on the host.
- AST and OpenGrep receive only the validated tracked regular-file manifest. Git symlinks, submodules, LFS pointers, unsafe paths, sensitive paths, and unsupported languages are omitted and represented as `DataGap` candidates.
- A tool adapter does not allocate SASTSIMI IDs, construct `RecordMeta`, write artifacts or records, move current pointers, or decide work status. It returns typed observations, raw bytes, safe diagnostics, and measured timing only.
- The trusted application coordinator binds raw artifact, optional `RuleExecutionRecord`, and exactly one `ToolRunResult` to the current `STATIC_TOOL` attempt and publishes them through the existing action/transition boundary.
- `SELECTED + EXECUTED + hit_count=0` means executed with zero raw hits. Missing telemetry, skipped rules, timeout, cancellation, and parse failure never become zero hits.
- A normalizer consumes only COMMITTED outputs for the expected tool works. It never combines attempts, workspaces, commits, analysis configurations, or rule catalogs.
- Tool failure does not discard usable output from other tools and does not mean safe code or a vulnerability verdict.
- Context retrieval accepts only a claimed exact `READ_CODE` request and returns code from the same `workspace_id + commit_id`. It enforces depth, fragment, byte, request-count, and timeout limits.
- Verify `HEAD`, tracked-file cleanliness, and safe path identity immediately before and after every static tool execution and context read. If they change, discard newly produced evidence and report `WORKSPACE_CHANGED`.
- Local absolute paths, credentials, environment secrets, raw authorization material, and unrestricted stderr never enter `safe_message`, domain records, or ordinary logs.
- Capability observations in T08 are technical, non-persisted evidence only. Real Git/tool profiles remain non-`ACTIVE` until T16 capability and evaluation approval.
- Use focused tests after each RED/GREEN step. Run the complete pytest suite exactly once, after the final T08 candidate is assembled.

---

## Baseline Inspection and Incremental Rule

The implementer must begin by checking current code instead of recreating T07 services.

- `src/sastsimi/contracts/static.py` already defines `CodeWorkspace`, `CodeLocation`, `DataGap`, `AnalysisError`, `ToolSource`, `CodeFact`, `CodeRelation`, `RuleExecutionRecord`, `ToolRunResult`, `StaticFactBundle`, `CodeContextRequest`, and `CodeContextResponse` plus current-result validators.
- `src/sastsimi/ports/static_tool.py` already exposes the frozen outer `StaticToolAdapter` protocol.
- `src/sastsimi/orchestration/fake_static_runtime.py` already proves authorized `RUN_TOOL`, external dispatch, budget accounting, exact attempt output, and transition publication with a fake adapter.
- `src/sastsimi/orchestration/fake_setup.py` already proves `WORKSPACE_PREP`, two fake static works, `STATIC_NORMALIZE`, and downstream use of the resulting bundle.
- `src/sastsimi/storage/context_binding.py` and `src/sastsimi/storage/context_policy.py` already bind an exact claimed `READ_CODE` action to one request/response pair.
- `src/sastsimi/storage/transition_service.py` already owns atomic output publication and current-pointer movement.

For each planned interface below, search the current tree first. If the exact signature and invariant already exist, add or strengthen the named regression test and leave production code unchanged. Do not create a second record writer, transition service, context request binder, fake adapter, schema, current pointer, or workspace identity. The new lower process seam is additive: the outer `StaticToolAdapter` remains compatible with T07, while `StaticToolCoordinator` uses the lower seam to implement real tools without giving them storage authority.

Run the baseline-only checks before the first production edit:

```powershell
git status --short
git rev-parse HEAD
uv run pytest tests/contract/domain/test_static.py tests/contract/test_core_ports.py tests/contract/test_architecture_imports.py tests/unit/test_fake_adapters.py -q
```

Expected: clean branch at the base commit and all selected tests pass. If a selected test fails before T08 edits, record the failure as a prerequisite rather than weakening that test.

## Planned File Map

### Inward ports and non-persisted transport

- Modify `src/sastsimi/ports/dto.py`: add frozen transport DTOs for repository preparation, process results, capability observations, raw static observations, and published tool material. These are not domain schemas.
- Modify `src/sastsimi/ports/static_tool.py`: retain `StaticToolAdapter`; add `StaticProcessAdapter` and `StaticAttemptPublisherPort` lower seams.
- Create `src/sastsimi/ports/workspace.py`: exact local workspace lookup, integrity check, and repository publication protocols without exposing paths in persisted contracts.
- Modify `src/sastsimi/ports/__init__.py`: export only public protocol and DTO names used by composition/tests.

### Real static layer

- Create `src/sastsimi/static_analysis/process.py`: bounded process execution, process-group cancellation, output caps, and redacted diagnostics.
- Create `src/sastsimi/static_analysis/repository_loader.py`: trusted URL/destination checks, clone without checkout, exact commit resolution, detached checkout, tracked-file manifest, and workspace integrity guard.
- Create `src/sastsimi/static_analysis/ast_adapter.py`: safe Python AST worker invocation and raw observation decoder.
- Create `src/sastsimi/static_analysis/python_ast_worker.py`: isolated parse-only worker; it never imports target code.
- Create `src/sastsimi/static_analysis/codeql_adapter.py`: version probe and SARIF analysis of an already prepared CodeQL database; no host build/autobuild path.
- Create `src/sastsimi/static_analysis/open_grep_adapter.py`: version probe and JSON scan over an explicit safe file manifest.
- Create `src/sastsimi/static_analysis/coordinator.py`: real outer `StaticToolAdapter`, same-attempt materialization request, cancellation routing, and expected-tool fan-out/fan-in orchestration.
- Create `src/sastsimi/static_analysis/normalizer.py`: deterministic mapping and merge into the existing `StaticFactBundle` contract.
- Create `src/sastsimi/static_analysis/context_retrieval.py`: bounded, exact-workspace code and graph lookup returning the existing request/response contracts.
- Modify `src/sastsimi/static_analysis/__init__.py`: export stable service/adapter entrypoints while retaining `FakeStaticToolAdapter`.

### Trusted publication and composition seam

- Create `src/sastsimi/orchestration/static_publication.py`: implement `WorkspacePreparationPublisherPort` and `StaticAttemptPublisherPort` with existing `WorkflowRunner`, `RuntimeServices`, exact `SAVE_RESULT`, artifact store, IDs, and clock. This is the trusted application-side writer; repository/process adapters never import it.
- Modify `src/sastsimi/bootstrap.py`: add a private factory that composes real static components for tests and future activation, but do not select it from `analyze` or mark profiles `ACTIVE`.

### Tests and fixtures

- Create `tests/unit/static_analysis/conftest.py`: immutable process, raw output, manifest, and metadata fixtures.
- Create `tests/unit/static_analysis/test_process.py`.
- Create `tests/unit/static_analysis/test_repository_loader.py`.
- Create `tests/unit/static_analysis/test_ast_adapter.py`.
- Create `tests/unit/static_analysis/test_codeql_adapter.py`.
- Create `tests/unit/static_analysis/test_open_grep_adapter.py`.
- Create `tests/unit/static_analysis/test_normalizer.py`.
- Create `tests/unit/static_analysis/test_context_retrieval.py`.
- Create `tests/integration/static_analysis/conftest.py`: local Git repository and fake executable fixtures; no network or host CodeQL/OpenGrep installation required.
- Create `tests/integration/static_analysis/test_repository_prepare.py`.
- Create `tests/integration/static_analysis/test_tool_attempt_publication.py`.
- Create `tests/integration/static_analysis/test_static_join.py`.
- Create `tests/integration/static_analysis/test_context_retrieval.py`.
- Create `tests/security_negative/test_code_path_escape.py`.
- Modify `tests/contract/test_architecture_imports.py`: explicitly reject concrete runtime/storage imports and unsafe process APIs in `static_analysis`.
- Modify `tests/unit/test_fake_adapters.py` and selected T07 E2E tests only to assert compatibility; do not rewrite fake behavior around the real adapters.

---

### Task 1: Freeze Existing Contracts and Add the Lower Raw-Process Seam

**Files:**
- Modify: `src/sastsimi/ports/dto.py`
- Modify: `src/sastsimi/ports/static_tool.py`
- Create: `src/sastsimi/ports/workspace.py`
- Modify: `src/sastsimi/ports/__init__.py`
- Modify: `tests/contract/test_core_ports.py`
- Modify: `tests/contract/test_architecture_imports.py`
- Test: `tests/unit/static_analysis/conftest.py`

**Interfaces:**
- Consumes: existing `StaticToolRequest`, `StaticToolAdapter`, `CodeWorkspace`, `ToolCoverage`, and static closed-enum values.
- Produces: non-persisted `ProcessResult`, `StaticCapabilityObservation`, `StaticToolObservation`, `PublishedStaticToolMaterial`, `PrebuiltCodeQLDatabase`, `StaticProcessAdapter`, `StaticAttemptPublisherPort`, `WorkspacePreparationPublisherPort`, and `WorkspaceLocatorPort`.

Use these transport shapes. They may echo trusted correlation IDs supplied by the caller, but must not allocate IDs, subclass `DomainRecord`, carry `RecordMeta`, or move current pointers. They carry `StoredDataRef` only where the trusted publisher returns already committed canonical material.

```python
@dataclass(frozen=True)
class ProcessResult:
    outcome: Literal["SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED"]
    return_code: int | None
    stdout: bytes
    stderr_tail: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    elapsed_ms: int

@dataclass(frozen=True)
class StaticCapabilityObservation:
    available: bool
    executable: str
    observed_version: str | None
    expected_version: str
    reason_code: str | None

@dataclass(frozen=True)
class CandidateLocation:
    file_path: str
    start_line: int
    start_column: int | None
    end_line: int
    end_column: int | None

@dataclass(frozen=True)
class CandidateSymbol:
    source_key: str
    symbol_kind: str
    native_kind: str | None
    name: str
    location: CandidateLocation

@dataclass(frozen=True)
class CandidateFact:
    source_key: str
    fact_kind: str
    symbol_source_key: str | None
    location: CandidateLocation
    rule_id: str | None

@dataclass(frozen=True)
class CandidateRelation:
    source_key: str
    relation_kind: str
    from_symbol_source_key: str | None
    from_location: CandidateLocation
    to_symbol_source_key: str | None
    to_location: CandidateLocation

@dataclass(frozen=True)
class CandidateGap:
    stage: str
    code: str
    reason: str
    description: str
    affected_paths: tuple[str, ...]
    affected_languages: tuple[str, ...]
    affected_locations: tuple[CandidateLocation, ...]
    retryable: bool

@dataclass(frozen=True)
class CandidateError:
    stage: str
    code: str
    safe_message: str
    retryable: bool

@dataclass(frozen=True)
class CandidateRule:
    rule_id: str
    selection_status: str
    execution_status: str
    hit_count: int | None
    reason: str | None
    detail: str | None

@dataclass(frozen=True)
class TrackedFile:
    git_path: str
    git_mode: str
    blob_id: str
    size_bytes: int

@dataclass(frozen=True)
class RepositoryPreparation:
    analysis_id: str
    workspace_id: str
    repository_url: str
    requested_ref: str
    resolved_commit_id: str
    root: Path
    tracked_files: tuple[TrackedFile, ...]
    gaps: tuple[CandidateGap, ...]
    errors: tuple[CandidateError, ...]

@dataclass(frozen=True)
class StaticToolObservation:
    tool_name: str
    tool_version: str
    tool_kind: Literal["STRUCTURE", "RULE_BASED"]
    status: Literal["SUCCEEDED", "PARTIAL", "FAILED", "SKIPPED"]
    raw_output: bytes | None
    raw_media_type: str | None
    analyzed_paths: tuple[str, ...]
    skipped_paths: tuple[str, ...]
    analyzed_languages: tuple[str, ...]
    skipped_languages: tuple[str, ...]
    notes: tuple[str, ...]
    selected_rule_packs: tuple[str, ...]
    rules: tuple[CandidateRule, ...]
    symbols: tuple[CandidateSymbol, ...]
    facts: tuple[CandidateFact, ...]
    relations: tuple[CandidateRelation, ...]
    gaps: tuple[CandidateGap, ...]
    errors: tuple[CandidateError, ...]
    started_monotonic_ms: int
    finished_monotonic_ms: int

@dataclass(frozen=True)
class PublishedStaticToolMaterial:
    result: ToolRunResult
    result_ref: StoredDataRef
    rule_execution: RuleExecutionRecord | None
    rule_execution_ref: StoredDataRef | None
    observation: StaticToolObservation

@dataclass(frozen=True)
class PrebuiltCodeQLDatabase:
    workspace_id: str
    commit_id: str
    language: str
    database_root: Path
    database_digest: str
```

The lower protocols are:

```python
class StaticProcessAdapter(Protocol):
    async def probe(self) -> StaticCapabilityObservation: ...
    async def execute(
        self, request: StaticToolRequest, workspace_root: Path
    ) -> StaticToolObservation: ...
    async def cancel(self, attempt_id: str) -> CancellationResult: ...

class StaticAttemptPublisherPort(Protocol):
    def publish(
        self, request: StaticToolRequest, observation: StaticToolObservation
    ) -> PublishedStaticToolMaterial: ...

class WorkspaceLocatorPort(Protocol):
    def root_for(self, workspace: CodeWorkspace) -> Path: ...
    def assert_unchanged(self, workspace: CodeWorkspace) -> None: ...

class WorkspacePreparationPublisherPort(Protocol):
    def publish(self, preparation: RepositoryPreparation) -> CodeWorkspace: ...
```

- [ ] **Step 1: Write failing port and architecture tests.** Assert that `StaticToolAdapter.run` keeps its existing `ToolRunResult` return, the lower adapter has no storage methods, transport DTOs have no `meta` field, `static_analysis` cannot import `sastsimi.runtime` or `sastsimi.storage`, and subprocess calls using `subprocess.run`, `Popen`, `create_subprocess_shell`, `os.system`, or `shell=True` are rejected by the architecture check.
- [ ] **Step 2: Run the focused RED test.**

```powershell
uv run pytest tests/contract/test_core_ports.py tests/contract/test_architecture_imports.py -q
```

Expected: fail only because the lower DTOs/protocols and new boundary assertions do not exist.

- [ ] **Step 3: Add the frozen DTOs and protocols.** Keep all DTOs non-persisted and immutable. Do not modify `contracts/static.py`, generated schemas, or the old fake adapter signature.
- [ ] **Step 4: Run the focused GREEN test and fake compatibility test.**

```powershell
uv run pytest tests/contract/test_core_ports.py tests/contract/test_architecture_imports.py tests/unit/test_fake_adapters.py -q
```

Expected: pass; the T07 fake adapter remains runtime-checkable as `StaticToolAdapter`.

- [ ] **Step 5: Commit this independently reviewable seam.**

```powershell
git add src/sastsimi/ports/dto.py src/sastsimi/ports/static_tool.py src/sastsimi/ports/workspace.py src/sastsimi/ports/__init__.py tests/contract/test_core_ports.py tests/contract/test_architecture_imports.py tests/unit/static_analysis/conftest.py
git commit -m "feat: add raw static process boundary"
```

### Task 2: Implement the Bounded Safe Process Runner

**Files:**
- Create: `src/sastsimi/static_analysis/process.py`
- Create: `tests/unit/static_analysis/test_process.py`
- Create: `tests/integration/static_analysis/conftest.py`

**Interfaces:**
- Consumes: trusted immutable `ProcessSpec(argv, cwd, env, timeout_ms, stdout_limit_bytes, stderr_limit_bytes, attempt_id)` created inside real adapters.
- Produces: `ProcessResult`; `cancel(attempt_id)` is idempotent and affects only the registered process group for that attempt.

The implementation must use `asyncio.create_subprocess_exec(*spec.argv, cwd=spec.cwd, env=dict(spec.env), stdout=PIPE, stderr=PIPE)`. On POSIX set `start_new_session=True` and terminate/kill the process group with `killpg`. On Windows create a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, assign the child before allowing normal execution, and close/terminate that job on cancellation; `CREATE_NEW_PROCESS_GROUP` alone is not accepted as descendant cleanup. Stream stdout/stderr concurrently with hard byte caps. When a cap, timeout, or caller cancellation occurs, terminate the process group/job, wait a bounded grace period, then force-kill it. Remove the attempt from the live-process registry in `finally`.

- [ ] **Step 1: Write RED tests for argument integrity and environment isolation.** Use a fixture executable that echoes argv and selected environment keys. Assert metacharacters remain one argument, the shell is never invoked, unapproved parent environment keys are absent, `cwd` is exact, and an executable path inside `workspace_root` is rejected.
- [ ] **Step 2: Add RED tests for timeout, output caps, and cancel.** The fixture starts a child process and waits. Assert timeout and explicit cancellation terminate parent and child, output is capped, stderr is retained only as a bounded tail, repeated cancel returns `cancelled=False`, and another attempt is not affected.
- [ ] **Step 3: Run RED.**

```powershell
uv run pytest tests/unit/static_analysis/test_process.py -q
```

Expected: fail because `SafeProcessRunner` does not exist.

- [ ] **Step 4: Implement the minimal cross-platform runner.** Validate non-empty argv, absolute trusted executable outside the workspace, allowed cwd roots, positive timeout/caps, unique active attempt, and monotonic elapsed time before spawning. Return safe outcome values instead of raising for process exit, timeout, or cancellation; raise before spawn only for invalid trusted configuration.
- [ ] **Step 5: Run GREEN and architecture checks.**

```powershell
uv run pytest tests/unit/static_analysis/test_process.py tests/contract/test_architecture_imports.py -q
uv run ruff check src/sastsimi/static_analysis/process.py tests/unit/static_analysis/test_process.py
uv run mypy --strict src/sastsimi/static_analysis/process.py tests/unit/static_analysis/test_process.py
```

Expected: all commands pass.

- [ ] **Step 6: Commit.**

```powershell
git add src/sastsimi/static_analysis/process.py tests/unit/static_analysis/test_process.py tests/integration/static_analysis/conftest.py
git commit -m "feat: run static tools through bounded processes"
```

### Task 3: Prepare and Guard an Exact Git Workspace

**Files:**
- Create: `src/sastsimi/static_analysis/repository_loader.py`
- Create: `src/sastsimi/orchestration/static_publication.py`
- Modify: `src/sastsimi/bootstrap.py`
- Create: `tests/unit/static_analysis/test_repository_loader.py`
- Create: `tests/integration/static_analysis/test_repository_prepare.py`
- Create: `tests/security_negative/test_code_path_escape.py`

**Interfaces:**
- Consumes: validated repository URL, requested Git ref, allocated `analysis_id`, allocated `workspace_id`, attempt-owned destination, and injected process runner/clock.
- Produces: `RepositoryPreparation(repository_url, workspace_id, resolved_commit_id, root, tracked_files, gaps, errors)` for the trusted workspace publisher, one COMMITTED existing `CodeWorkspace` from that publisher, and `WorkspaceGuard` implementing `WorkspaceLocatorPort`.

The production source policy accepts `https` repository URLs only in this task. Tests may explicitly enable `file://` for an isolated temporary fixture; that flag must default to false and must not be available from an Agent or repository file. Reject URLs beginning with `-`, scp-like syntax, `ext::`, `file://` without the test-only flag, credentials in the authority component, fragments, and control characters.

Git invocation uses a sanitized environment containing `GIT_TERMINAL_PROMPT=0`, `GIT_LFS_SKIP_SMUDGE=1`, `GIT_CONFIG_NOSYSTEM=1`, an empty global config, and no inherited `GIT_SSH_COMMAND`, credential helper, or protocol override. Invoke clone as `git -c protocol.allow=never -c protocol.https.allow=always -c protocol.ext.allow=never -c protocol.file.allow=never -c http.followRedirects=initial -c core.hooksPath=<empty-dir> clone --no-checkout --no-recurse-submodules -- <url> <destination>`. In the isolated local fixture only, switch `protocol.file.allow` to `always` through the trusted test configuration.

Resolve with `git -C <root> rev-parse --verify --end-of-options <requested-ref>^{commit}`, validate exactly one lowercase/uppercase hexadecimal object ID, then checkout only that resolved ID with `git -C <root> checkout --detach <commit-id>`. Confirm `git rev-parse HEAD` equals it.

Build the manifest from `git ls-files --stage -z`. Accept only regular blobs (`100644` or `100755`) whose normalized Git path passes the existing `GitPath` validator and whose real parent and file stay inside the workspace. Represent mode `120000` as `SYMLINK_EXCLUDED`, mode `160000` as `SUBMODULE_UNAVAILABLE`, LFS pointer content as `LFS_POINTER_ONLY`, sensitive paths as a configured exclusion, and unsupported file types as gaps. Do not follow or fetch them. Do not initialize submodules or run Git LFS in T08 because no approved isolated execution boundary exists.

`WorkspaceGuard.assert_unchanged` verifies exact HEAD, `git diff --quiet HEAD --`, `git diff --cached --quiet HEAD --`, and the tracked manifest fingerprint. Untracked tool-output files do not become analysis inputs because tools receive the frozen manifest, but creation of a tracked-path replacement or manifest drift fails the guard.

- [ ] **Step 1: Write RED URL and destination tests.** Cover option injection, `ext::`, unauthorized `file://`, credential-bearing URL, existing/non-empty destination, destination traversal, and destination symlink/junction escape.
- [ ] **Step 2: Write RED exact-checkout tests.** Create two commits and a branch that moves after preparation starts. Assert the returned commit is the initially resolved object, checkout is detached, `READY` cannot be proposed on clone/checkout/HEAD mismatch, and no static process starts before readiness.
- [ ] **Step 3: Write RED manifest and mutation tests.** Include a regular file, Git symlink, submodule entry fixture, LFS pointer, `../` request, absolute path, Windows drive path, mixed separators, post-checkout edit, index change, and HEAD move. Assert unsafe entries never enter the safe manifest and each omission has a candidate gap.
- [ ] **Step 4: Write RED publication-authority tests.** Assert the loader returns only a typed preparation candidate, cannot allocate `RecordMeta` or write storage, and the trusted `REPOSITORY_LOADER` publisher is the only component that can commit `CodeWorkspace`. Reject a candidate whose resolved commit, allocated workspace, repository URL, work, attempt, or claimed `SAVE_RESULT` action differs from the current `WORKSPACE_PREP` execution. Assert no local root path is persisted in `CodeWorkspace`.
- [ ] **Step 5: Run RED.**

```powershell
uv run pytest tests/unit/static_analysis/test_repository_loader.py tests/integration/static_analysis/test_repository_prepare.py tests/security_negative/test_code_path_escape.py -q
```

Expected: fail because loader and guard do not exist.

- [ ] **Step 6: Implement prepare, manifest, guard, and the thin trusted publisher.** Clean a partially created attempt destination after a failed clone only when its resolved path is inside the configured workspace base and matches the allocated workspace path. Do not recursively delete a caller-supplied or unresolved path. Return safe candidate diagnostics without local absolute paths. The application-side publisher allocates metadata and commits the existing `CodeWorkspace` with `status=READY` only after the final guard succeeds; failures close the work without publishing a READY workspace.
- [ ] **Step 7: Run GREEN plus focused static analysis.**

```powershell
uv run pytest tests/unit/static_analysis/test_repository_loader.py tests/integration/static_analysis/test_repository_prepare.py tests/security_negative/test_code_path_escape.py -q
uv run ruff check src/sastsimi/static_analysis/repository_loader.py src/sastsimi/orchestration/static_publication.py src/sastsimi/bootstrap.py tests/unit/static_analysis/test_repository_loader.py tests/integration/static_analysis/test_repository_prepare.py tests/security_negative/test_code_path_escape.py
uv run mypy --strict src/sastsimi/static_analysis/repository_loader.py src/sastsimi/orchestration/static_publication.py src/sastsimi/bootstrap.py tests/unit/static_analysis/test_repository_loader.py tests/integration/static_analysis/test_repository_prepare.py tests/security_negative/test_code_path_escape.py
```

Expected: pass on Windows and POSIX path semantics represented by fixtures.

- [ ] **Step 8: Commit.**

```powershell
git add src/sastsimi/static_analysis/repository_loader.py src/sastsimi/orchestration/static_publication.py src/sastsimi/bootstrap.py tests/unit/static_analysis/test_repository_loader.py tests/integration/static_analysis/test_repository_prepare.py tests/security_negative/test_code_path_escape.py
git commit -m "feat: prepare exact guarded git workspaces"
```

### Task 4: Implement the Parse-Only AST Adapter

**Files:**
- Create: `src/sastsimi/static_analysis/python_ast_worker.py`
- Create: `src/sastsimi/static_analysis/ast_adapter.py`
- Create: `tests/unit/static_analysis/test_ast_adapter.py`

**Interfaces:**
- Consumes: safe tracked `.py` files from `RepositoryPreparation`, exact workspace guard, trusted parser version/profile, and current `StaticToolRequest`.
- Produces: `StaticToolObservation(tool_kind="STRUCTURE")` with JSON raw output, Python file/module/type/callable/data symbols, call/import relations where statically observable, route-binding candidates for literal recognized decorators, and explicit unsupported/parse gaps.

The worker parses source text with `ast.parse` and never imports, compiles, evaluates, or runs target modules. The parent starts it with the safe process runner and an explicit file manifest. Worker output uses Git-relative paths and 1-based Unicode-code-point positions. Missing end positions produce line-only ranges with both columns `None`; the adapter never invents precision.

- [ ] **Step 1: Write RED parser tests.** Cover functions, async functions, methods, classes, imports, direct calls, literal route decorators, Unicode columns, syntax error in one file, unsupported extension, and a file whose top level would raise if executed. Assert the sentinel side effect never occurs.
- [ ] **Step 2: Write RED boundary tests.** Assert the worker receives only manifest entries, a symlink is not opened, parse error yields `PARTIAL` plus `STATIC_PARSE_FAILED`, all `rule_id` values are null, and empty successful parsing is not a vulnerability verdict.
- [ ] **Step 3: Run RED.**

```powershell
uv run pytest tests/unit/static_analysis/test_ast_adapter.py -q
```

Expected: fail because the AST adapter and worker do not exist.

- [ ] **Step 4: Implement the worker and decoder.** Sort files and emitted candidate keys deterministically. Treat dynamic dispatch, reflection, unresolved imports, and unsupported syntax as limitations/gaps rather than invented call edges. Verify workspace integrity before spawn and after decoding; discard the observation on post-run mutation.
- [ ] **Step 5: Run GREEN and focused checks.**

```powershell
uv run pytest tests/unit/static_analysis/test_ast_adapter.py tests/security_negative/test_code_path_escape.py -q
uv run ruff check src/sastsimi/static_analysis/ast_adapter.py src/sastsimi/static_analysis/python_ast_worker.py tests/unit/static_analysis/test_ast_adapter.py
uv run mypy --strict src/sastsimi/static_analysis/ast_adapter.py src/sastsimi/static_analysis/python_ast_worker.py tests/unit/static_analysis/test_ast_adapter.py
```

Expected: pass.

- [ ] **Step 6: Commit.**

```powershell
git add src/sastsimi/static_analysis/ast_adapter.py src/sastsimi/static_analysis/python_ast_worker.py tests/unit/static_analysis/test_ast_adapter.py
git commit -m "feat: extract parse-only python ast facts"
```

### Task 5: Implement the Analyze-Only CodeQL Adapter

**Files:**
- Create: `src/sastsimi/static_analysis/codeql_adapter.py`
- Create: `tests/unit/static_analysis/test_codeql_adapter.py`

**Interfaces:**
- Consumes: trusted absolute CodeQL executable, exact expected CLI version, `PrebuiltCodeQLDatabase` bound to the current workspace/commit, exact query-pack path/digest, complete rule catalog, selected rule IDs/packs, safe process runner, and current request.
- Produces: `StaticCapabilityObservation` and SARIF-backed `StaticToolObservation(tool_kind="RULE_BASED")`.

Only these process families are allowed: version probe and `codeql database analyze` of the trusted prebuilt database into an attempt-owned SARIF file. Before execution, require the database descriptor's `workspace_id + commit_id` to equal the current READY workspace and verify its digest. Reject any configured argv containing `database create`, `database trace-command`, `--command`, `autobuild`, a build tool, package installer, workspace executable, or output path under the analyzed checkout. A missing, stale, or digest-mismatched database/query pack yields unavailable capability or `SKIPPED/FAILED` candidate evidence; it never triggers a build. SARIF locations must map back to the safe tracked manifest; foreign or unsafe paths become gaps and cannot produce normalized facts.

The SARIF decoder maps result `ruleId` counts to catalog rules. Every catalog rule appears once in `CandidateRule`. Selected rules with trustworthy execution telemetry use `EXECUTED` and the raw hit count, including zero. Unselected rules use `NOT_SELECTED + NOT_EXECUTED`. Missing/ambiguous telemetry uses `UNKNOWN + TELEMETRY_MISSING`; malformed SARIF is not zero hits.

- [ ] **Step 1: Write RED capability and command-policy tests.** Assert exact version match, missing executable, wrong version, database/query-pack digest mismatch, and every prohibited build/autobuild command. Use a fake executable; do not require host CodeQL.
- [ ] **Step 2: Write RED SARIF tests.** Cover one hit, selected zero-hit rule, unselected rule, duplicate result rule IDs, missing rule metadata, malformed JSON, nonzero exit with partial SARIF, timeout, cancellation, and raw output preservation.
- [ ] **Step 3: Run RED.**

```powershell
uv run pytest tests/unit/static_analysis/test_codeql_adapter.py -q
```

Expected: fail because `CodeQLProcessAdapter` does not exist.

- [ ] **Step 4: Implement probe, analyze-only command builder, and SARIF decoder.** Derive fact candidates only from actual SARIF results. Preserve rule messages and severity only inside raw output or non-verdict notes; do not map them to `TRUE`, `FALSE`, or CWE.
- [ ] **Step 5: Run GREEN and focused checks.**

```powershell
uv run pytest tests/unit/static_analysis/test_codeql_adapter.py tests/unit/static_analysis/test_process.py -q
uv run ruff check src/sastsimi/static_analysis/codeql_adapter.py tests/unit/static_analysis/test_codeql_adapter.py
uv run mypy --strict src/sastsimi/static_analysis/codeql_adapter.py tests/unit/static_analysis/test_codeql_adapter.py
```

Expected: pass and no process contains a host database-build operation.

- [ ] **Step 6: Commit.**

```powershell
git add src/sastsimi/static_analysis/codeql_adapter.py tests/unit/static_analysis/test_codeql_adapter.py
git commit -m "feat: analyze prebuilt codeql evidence safely"
```

### Task 6: Implement the Explicit-Manifest OpenGrep Adapter

**Files:**
- Create: `src/sastsimi/static_analysis/open_grep_adapter.py`
- Create: `tests/unit/static_analysis/test_open_grep_adapter.py`

**Interfaces:**
- Consumes: trusted absolute OpenGrep executable, exact expected version, trusted rule catalog/config path and digest, selected rules/packs, safe tracked regular-file manifest, and current request.
- Produces: `StaticCapabilityObservation` and JSON-backed `StaticToolObservation(tool_kind="RULE_BASED")`.

The command builder passes the trusted config and explicit safe target files as separate arguments. It must not use a repository-provided config, command string, response file from the repository, recursive workspace root target, shell glob, or rule supplied by an Agent. If the safe target list would exceed the configured command-size bound, split it into deterministic batches and merge raw batch envelopes without changing per-rule hit counts.

- [ ] **Step 1: Write RED probe and target-boundary tests.** Cover correct/wrong version, config digest mismatch, option-looking file name, spaces/metacharacters, excluded symlink/LFS/submodule, deterministic batching, timeout, cancellation, and attempt-owned output.
- [ ] **Step 2: Write RED result tests.** Cover source, sink, sanitizer, validator, auth, permission, and other mappings from trusted rule metadata; selected zero hits; unselected rules; missing execution telemetry; malformed JSON; nonzero exit with usable partial JSON; and duplicate raw findings whose raw count must not be reduced by normalized deduplication.
- [ ] **Step 3: Run RED.**

```powershell
uv run pytest tests/unit/static_analysis/test_open_grep_adapter.py -q
```

Expected: fail because `OpenGrepProcessAdapter` does not exist.

- [ ] **Step 4: Implement command building and JSON decoding.** Use only catalog-owned mapping from rule ID to `fact_kind`; an unknown rule is retained as raw evidence and `OTHER` only when the trusted catalog explicitly permits that mapping. Missing mapping is a gap, not an inferred vulnerability type.
- [ ] **Step 5: Run GREEN and focused checks.**

```powershell
uv run pytest tests/unit/static_analysis/test_open_grep_adapter.py tests/unit/static_analysis/test_process.py tests/security_negative/test_code_path_escape.py -q
uv run ruff check src/sastsimi/static_analysis/open_grep_adapter.py tests/unit/static_analysis/test_open_grep_adapter.py
uv run mypy --strict src/sastsimi/static_analysis/open_grep_adapter.py tests/unit/static_analysis/test_open_grep_adapter.py
```

Expected: pass.

- [ ] **Step 6: Commit.**

```powershell
git add src/sastsimi/static_analysis/open_grep_adapter.py tests/unit/static_analysis/test_open_grep_adapter.py
git commit -m "feat: scan safe files with OpenGrep evidence"
```

### Task 7: Materialize One Exact Static Tool Attempt

**Files:**
- Create: `src/sastsimi/static_analysis/coordinator.py`
- Modify: `src/sastsimi/orchestration/static_publication.py`
- Create: `tests/integration/static_analysis/test_tool_attempt_publication.py`
- Modify: `src/sastsimi/static_analysis/__init__.py`
- Modify: `src/sastsimi/bootstrap.py`

**Interfaces:**
- Consumes: real `StaticProcessAdapter`, `WorkspaceLocatorPort`, current `StaticToolRequest`, trusted `StaticAttemptPublisherPort`, current work/attempt, exact analysis configuration, and optional exact rule catalog.
- Produces: existing `StaticToolAdapter` behavior and `PublishedStaticToolMaterial` whose result is the only canonical tool result for that attempt.

`StaticToolCoordinator.run` performs this sequence:

1. Resolve a READY workspace root and verify exact commit/cleanliness.
2. Invoke one lower adapter through the already authorized external-call boundary.
3. Verify exact commit/cleanliness again.
4. Ask the trusted publisher to stage raw bytes as a code-scoped artifact.
5. Allocate `gap_id`/`error_id`, timestamps, and `RecordMeta` from the current work/attempt.
6. For `RULE_BASED`, build and stage exactly one `RuleExecutionRecord`, then build `ToolRunResult.rule_execution_ref` from that exact candidate. For `STRUCTURE`, keep it null.
7. Authorize one output closure containing exactly one `ToolRunResult` and, when required, its exact `RuleExecutionRecord`; commit both in the same transition and claim `SAVE_RESULT` once.
8. Return the exact committed `ToolRunResult`. Raw bytes and typed in-memory observations remain available to the normalizer through `PublishedStaticToolMaterial` and verified artifact reopen.

The publisher validates catalog set equality, configuration/catalog refs, tool name/version/kind, attempt identity, raw reference, timestamps, rule combinations, gap/error requirements, and work target status before publication. It selects work status from evidence: `SUCCEEDED` only for complete successful execution; `PARTIAL` when usable raw results coexist with gaps/errors; `FAILED` when no usable result exists after an actual error; `CANCELLED` only on caller cancellation; `SKIPPED` is represented in `ToolRunResult` with the work terminal status required by the existing work contract and its gap IDs.

- [ ] **Step 1: Write RED authority tests.** A malicious lower adapter attempts to supply record IDs, metadata, stored refs, a different attempt, absolute paths, or a `SUCCEEDED` status with missing telemetry. Assert the DTO or trusted publisher rejects it before publication.
- [ ] **Step 2: Write RED atomicity and lifecycle tests.** Inject crashes after raw artifact staging and between candidate staging/transition commit. Assert no partial `RuleExecutionRecord` becomes current, restart uses the existing transition recovery rules, late old-attempt output is rejected, and exactly one `ToolRunResult` is committed.
- [ ] **Step 3: Write RED semantic tests.** Assert raw artifact, rule record, and tool result share workspace/commit/attempt/tool/config/catalog; zero hits and not-run stay different; timeout/cancel/failure never becomes zero hits or a verdict.
- [ ] **Step 4: Run RED.**

```powershell
uv run pytest tests/integration/static_analysis/test_tool_attempt_publication.py tests/contract/domain/test_static.py -q
```

Expected: fail because the coordinator and trusted publisher do not exist.

- [ ] **Step 5: Implement coordinator and publisher using injected public runtime services.** `static_analysis/` may import the publisher protocol but not `orchestration/static_publication.py`; only `bootstrap.py` and tests compose the concrete pair. Keep the factory private and unselected by the CLI.
- [ ] **Step 6: Run GREEN plus fake regression.**

```powershell
uv run pytest tests/integration/static_analysis/test_tool_attempt_publication.py tests/contract/domain/test_static.py tests/unit/test_fake_adapters.py tests/e2e/test_fake_true_pipeline.py -q
uv run ruff check src/sastsimi/static_analysis/coordinator.py src/sastsimi/orchestration/static_publication.py src/sastsimi/bootstrap.py tests/integration/static_analysis/test_tool_attempt_publication.py
uv run mypy --strict src/sastsimi/static_analysis/coordinator.py src/sastsimi/orchestration/static_publication.py src/sastsimi/bootstrap.py tests/integration/static_analysis/test_tool_attempt_publication.py
```

Expected: pass; fake flow remains unchanged and real profiles remain inactive.

- [ ] **Step 7: Commit.**

```powershell
git add src/sastsimi/static_analysis/coordinator.py src/sastsimi/static_analysis/__init__.py src/sastsimi/orchestration/static_publication.py src/sastsimi/bootstrap.py tests/integration/static_analysis/test_tool_attempt_publication.py
git commit -m "feat: publish exact static tool attempts"
```

### Task 8: Deterministically Fan In Static Facts

**Files:**
- Create: `src/sastsimi/static_analysis/normalizer.py`
- Create: `tests/unit/static_analysis/test_normalizer.py`
- Create: `tests/integration/static_analysis/test_static_join.py`

**Interfaces:**
- Consumes: expected tool-work refs, each work's COMMITTED current `ToolRunResult`, optional exact `RuleExecutionRecord`, verified raw artifact, decoder, READY `CodeWorkspace`, current `STATIC_NORMALIZE` work, exact analysis config, and exact catalogs.
- Produces: one existing `StaticFactBundle` and its COMMITTED output ref, or a terminal failed normalization work with no misleading empty bundle when no usable observation exists.

Deterministic normalization rules:

- Sort tool materials by `(tool_name, tool_version, attempt_id, result record_id)` and reject duplicate tool attempts.
- Reopen and hash-verify every raw artifact; decode from those bytes rather than trusting an unpersisted object after restart.
- Map candidate paths through `GitPath` and bind every `CodeLocation` to the bundle workspace/commit.
- Create stable `symbol_id`, `fact_id`, and `relation_id` from canonical normalized identity plus source provenance. Exact duplicates collapse; raw hit counts remain unchanged.
- If two observations claim the same logical identity with different content, retain separately identifiable candidates where the contract permits and add `STATIC_NORMALIZATION_CONFLICT`; never silently choose one claim.
- Partition all facts exactly into SOURCE, SINK, SANITIZER, VALIDATOR, AUTH/PERMISSION, and OTHER lists. Preserve defensive candidates as candidates rather than proof of safety.
- A fact's `ToolSource` points to its exact result attempt, tool version, raw ref, and optional actually executed positive-hit rule. Structure observations always use `rule_id=None`.
- Relations reference only symbols included in the same bundle. Unresolved endpoints produce a gap rather than a dangling ID.
- Include every expected terminal tool run, including failed/skipped runs, and propagate all tool gaps/errors plus normalization gaps/errors without replacing them.
- The `STATIC_NORMALIZE` work is `SUCCEEDED` only when every expected tool result succeeded and normalization has no known gap/error. It is `PARTIAL` when at least one usable observation exists and any expected scope is missing. If no usable observation exists, fail normalization without publishing a bundle. `StaticFactBundle` itself has no separate status field.

- [ ] **Step 1: Write RED deterministic and partition tests.** Feed inputs in every ordering and assert identical canonical bundle bytes/hash. Cover all six fact lists, exact duplicate collapse, symbol/relation linkage, conflicting candidates, raw hit count preservation, and sanitizer/validator non-verdict semantics.
- [ ] **Step 2: Write RED provenance and failure tests.** Cover stale attempts, another commit, another workspace, wrong raw hash, wrong tool version, unknown rule, zero-hit rule producing a fact, partial AST plus successful OpenGrep, failed CodeQL plus usable AST, and all tools failed.
- [ ] **Step 3: Run RED.**

```powershell
uv run pytest tests/unit/static_analysis/test_normalizer.py tests/integration/static_analysis/test_static_join.py -q
```

Expected: fail because normalizer and fan-in service do not exist.

- [ ] **Step 4: Implement pure normalization first, then the thin trusted fan-in publication method.** Reuse `validate_rule_execution` and `validate_static_current`; do not reproduce or weaken their checks. Use the existing `STATIC_ANALYSIS` result owner and `SAVE_RESULT` path.
- [ ] **Step 5: Run GREEN and focused schema regression.**

```powershell
uv run pytest tests/unit/static_analysis/test_normalizer.py tests/integration/static_analysis/test_static_join.py tests/contract/domain/test_static.py tests/unit/contracts/test_schema_export.py -q
uv run ruff check src/sastsimi/static_analysis/normalizer.py tests/unit/static_analysis/test_normalizer.py tests/integration/static_analysis/test_static_join.py
uv run mypy --strict src/sastsimi/static_analysis/normalizer.py tests/unit/static_analysis/test_normalizer.py tests/integration/static_analysis/test_static_join.py
```

Expected: pass and generated schema files remain byte-identical.

- [ ] **Step 6: Commit.**

```powershell
git add src/sastsimi/static_analysis/normalizer.py tests/unit/static_analysis/test_normalizer.py tests/integration/static_analysis/test_static_join.py
git commit -m "feat: normalize deterministic static fact bundles"
```

### Task 9: Return Bounded Same-Commit Code Context

**Files:**
- Create: `src/sastsimi/static_analysis/context_retrieval.py`
- Create: `tests/unit/static_analysis/test_context_retrieval.py`
- Create: `tests/integration/static_analysis/test_context_retrieval.py`
- Extend: `tests/security_negative/test_code_path_escape.py`

**Interfaces:**
- Consumes: exact claimed `CodeContextRequest`, its current `CONTEXT_RETRIEVAL` work/attempt, READY `CodeWorkspace`, exact current `StaticFactBundle`, `WorkspaceLocatorPort`, `ArtifactStore`, clock/ID ports, and a trusted request-count/fingerprint ledger.
- Produces: exact `CodeContextResponse`, verified fragment artifact refs, bounded discovered relations, gaps/errors, and a COMMITTED context work output.

Retrieval algorithm:

1. Verify request/work/attempt/action decision and bundle share analysis/workspace/commit/hypothesis scope.
2. Check request count and normalized request fingerprint through the injected ledger before reading.
3. Resolve requested entity locations and requested locations against the same bundle. Reject a caller-supplied symbol body or location from another workspace/commit.
4. Traverse only requested relation kinds up to `max_depth`, using a visited set keyed by normalized symbol/location identity.
5. Sort locations by Git path/start/end position, coalesce overlapping line ranges for the same file, and stop before exceeding `max_fragments` or `max_bytes`.
6. Before each open, validate the Git path, ensure it remains a tracked regular file, reject Git symlink/submodule/LFS/sensitive paths, and verify the resolved handle is under the workspace root. Open without following links where the OS supports it and recheck file identity after open.
7. Read UTF-8 with explicit replacement reporting. Line bounds are inclusive; provided columns are 1-based Unicode code points with start inclusive/end exclusive. Do not invent missing columns.
8. Store each exact returned fragment as a content-addressed code-scoped artifact and retain only its ref in the response.
9. Enforce monotonic `timeout_ms`; on any limit add `CONTEXT_TRUNCATED`, set `truncated=True`, and report actual count/bytes. On read failure add both `AnalysisError(stage=CONTEXT)` and the affected `DataGap(stage=CONTEXT)`.
10. Verify workspace integrity after reads. On change, discard fragment refs from this execution and fail with `WORKSPACE_CHANGED`; never publish stale code.

`max_requests_per_hypothesis` counts distinct claimed `code_request_id` values across generations for that hypothesis as required by the current contract. A repeated normalized fingerprint is recorded by the ledger; it may return the exact previously committed response only when request scope, limits, action authorization, artifact hashes, and current workspace/commit all match. Otherwise it consumes a request slot and executes normally; it never silently widens the limits.

- [ ] **Step 1: Write RED scope and authorization tests.** Cover another workspace, commit, analysis, hypothesis, attempt, unclaimed/unused decision, non-current bundle, and action paths that do not cover requested locations.
- [ ] **Step 2: Write RED bound tests.** Cover depth, fragment, byte, request count, timeout, cyclic graph, overlapping ranges, empty results, invalid line/column ranges, and deterministic ordering.
- [ ] **Step 3: Write RED filesystem security tests.** Cover `..`, absolute and drive paths, mixed separators, Git symlink to outside, ordinary filesystem symlink/junction, post-validation replacement, LFS pointer, sensitive path, HEAD move, tracked-file edit during read, and fragment hash verification.
- [ ] **Step 4: Run RED.**

```powershell
uv run pytest tests/unit/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_context_retrieval.py tests/security_negative/test_code_path_escape.py -q
```

Expected: fail because real context retrieval does not exist.

- [ ] **Step 5: Implement pure selection and filesystem reading separately.** The selection function receives only contracts and returns ordered locations/relations. The reader receives the guarded workspace handle and returns bytes plus candidate diagnostics. The service combines them and delegates publication through the existing claimed action/transition path.
- [ ] **Step 6: Run GREEN plus existing storage context tests.**

```powershell
uv run pytest tests/unit/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_context_retrieval.py tests/security_negative/test_code_path_escape.py tests/integration/storage/test_context_publication.py tests/e2e/test_fake_true_pipeline.py -q
uv run ruff check src/sastsimi/static_analysis/context_retrieval.py tests/unit/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_context_retrieval.py tests/security_negative/test_code_path_escape.py
uv run mypy --strict src/sastsimi/static_analysis/context_retrieval.py tests/unit/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_context_retrieval.py tests/security_negative/test_code_path_escape.py
```

Expected: pass; fake context remains compatible and no new context schema or state is introduced.

- [ ] **Step 7: Commit.**

```powershell
git add src/sastsimi/static_analysis/context_retrieval.py tests/unit/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_context_retrieval.py tests/security_negative/test_code_path_escape.py
git commit -m "feat: retrieve bounded exact code context"
```

### Task 10: Integrate the Real Static Slice Without Activating It

**Files:**
- Modify: `src/sastsimi/bootstrap.py`
- Modify: `src/sastsimi/static_analysis/__init__.py`
- Modify: `tests/integration/static_analysis/conftest.py`
- Create: `tests/integration/static_analysis/test_real_static_slice.py`
- Modify: `tests/contract/test_architecture_imports.py`
- Modify: `tests/unit/test_fake_adapters.py`
- Modify: `docs/superpowers/plans/implementation/08-static-fact-layer.md` only to append observed evidence after implementation.

**Interfaces:**
- Consumes: local fixture Git repository, fake CodeQL/OpenGrep executables with real process behavior, real AST worker, current runtime services, and the private real-static composition factory.
- Produces: exact READY workspace, three terminal tool results, rule records for both rule-based tools, one COMMITTED bundle, and one bounded context response, while the public CLI still selects only the fake pipeline.

- [ ] **Step 1: Write the RED vertical integration test.** Prepare a two-commit local repository containing one source/sink path, a sanitizer/validator candidate, an auth check, and a route. Run AST, fake-executable CodeQL SARIF, and fake-executable OpenGrep JSON concurrently through the real process boundary; normalize them; request one bounded context fragment. Assert exact commit, tool attempts, raw refs, rule refs, all fact partitions, gap/error closure, deterministic bundle hash, and context artifact hash.
- [ ] **Step 2: Add integration-negative cases.** Mutate HEAD during one tool, time out another tool, omit execution telemetry from one rule, and return usable output from the remaining tool. Assert the changed-workspace run is discarded, timeout is not zero hits, the `STATIC_NORMALIZE` work is partial only when exact usable evidence remains, and no vulnerability verdict is created anywhere in this package.
- [ ] **Step 3: Run the focused integration candidate.**

```powershell
uv run pytest tests/integration/static_analysis tests/unit/static_analysis tests/security_negative/test_code_path_escape.py tests/contract/domain/test_static.py tests/contract/test_architecture_imports.py tests/unit/test_fake_adapters.py tests/e2e/test_fake_true_pipeline.py -q
```

Expected: pass.

- [ ] **Step 4: Prove non-activation and import boundaries.** Assert the CLI/bootstrap production selection contains no real tool profile, no environment-based implicit activation, no host CodeQL database builder, and no `static_analysis -> runtime/storage` import. The private factory may be imported explicitly by integration tests and T16 only.
- [ ] **Step 5: Run format/lint/type and contract drift checks.** These are focused/static checks, not another pytest full-suite run.

```powershell
uv run ruff format --check .
uv run ruff check .
uv run mypy --strict src tests
uv run pytest tests/unit/contracts/test_schema_export.py tests/contract/domain/test_static.py tests/contract/test_architecture_imports.py -q
powershell -NoProfile -File scripts/validate-architecture-docs.ps1
powershell -NoProfile -File scripts/audit-doc-inventory.ps1 -RepositoryRoot . -CheckLinks
git diff --check
```

Expected: all commands pass; generated schema and canonical architecture documents are unchanged except for this implementation plan/evidence record.

- [ ] **Step 6: Run the one and only final complete test suite.** Do not run this command in earlier tasks or repeat it after an unchanged final candidate.

```powershell
uv run pytest tests -q
```

Expected: every test passes. Record the exact test count, duration, OS, Python version, base SHA, and candidate SHA in an `## Implementation Evidence` appendix in this file.

- [ ] **Step 7: Commit the final integration candidate.**

```powershell
git add src/sastsimi/bootstrap.py src/sastsimi/static_analysis/__init__.py tests/integration/static_analysis/conftest.py tests/integration/static_analysis/test_real_static_slice.py tests/contract/test_architecture_imports.py tests/unit/test_fake_adapters.py docs/superpowers/plans/implementation/08-static-fact-layer.md
git commit -m "feat: complete real static fact layer"
```

- [ ] **Step 8: Inspect the exact candidate before review.**

```powershell
git status --short
git log --oneline b3b2d9918ea815b9b936c09c98e4c53fd54937dc..HEAD
git diff --stat b3b2d9918ea815b9b936c09c98e4c53fd54937dc..HEAD
git diff --check b3b2d9918ea815b9b936c09c98e4c53fd54937dc..HEAD
```

Expected: clean worktree, only T08 files/intent in the range, and no whitespace errors.

---

## Acceptance Criteria

- A repository ref is cloned into a newly allocated workspace directory, resolved once to an exact commit, checked out detached, and published READY only after exact HEAD confirmation.
- Unsafe repository URLs, destination escapes, Git symlinks, filesystem symlinks/junctions, submodules, LFS pointers, path traversal, drive paths, and tracked-file/HEAD mutation cannot become code evidence.
- AST, CodeQL, and OpenGrep have real version probes, timeout, cancellation, bounded output, safe argv/environment handling, and no shell execution.
- Python AST parsing never imports or executes analyzed code.
- CodeQL never builds/autobuilds or executes repository build commands on the host; only an exact trusted prebuilt database is analyzed.
- OpenGrep scans only the validated explicit file manifest and trusted exact rule configuration.
- Real process adapters return typed candidates and raw bytes only. SASTSIMI IDs, metadata, references, artifact commits, output ownership, and transitions are produced by the trusted application side.
- Every terminal `STATIC_TOOL` attempt has exactly one canonical `ToolRunResult`; rule-based succeeded/partial/skipped results have the exact same-attempt `RuleExecutionRecord`; the raw artifact ref matches the evidence actually decoded.
- Executed zero-hit rules, unselected rules, selected-but-not-executed rules, unknown telemetry, timeout, cancellation, and failure are distinguishable and cannot be rewritten as one another.
- Static fan-in is deterministic, accepts only expected COMMITTED current attempts, preserves usable partial evidence and all gaps/errors, rejects cross-workspace/commit/attempt/config/catalog inputs, and never interprets missing facts as safety.
- All six fact partitions are present and correct, identifiers are deterministic/unique, producer refs are exact, and relations do not dangle.
- Context retrieval uses a claimed exact request, stays in the same workspace/commit, respects all five limit dimensions, returns verified content-addressed fragments, records truncation/failure accurately, and discards output after workspace mutation.
- T07 fake scenarios and existing contracts continue to pass without schema changes or fake-to-real rewrites.
- `static_analysis/` has no concrete runtime/storage import, no adapter-to-adapter dependency, and no dynamic import/process escape.
- No real tool profile is made operationally ACTIVE and no public CLI path selects the real adapters before T16.
- Focused tests, Ruff format/lint, strict mypy, schema/static contract checks, architecture/doc checks, `git diff --check`, and exactly one final full pytest run are green at the exact review SHA.

## Explicit Scope Exclusions

- No LLM Provider, prompt, Hypothesis, Verification, dynamic reproduction, CWE, Gate, Finding, Reporter, Chaining, or evaluation behavior is added or changed.
- No domain schema, enum, result-owner mapping, action type, work type, budget rule, or migration is changed merely to simplify adapter implementation.
- No real Provider/tool/Docker profile is approved or activated; T16 owns capability evidence, evaluation, approval, and production registry activation.
- No CodeQL database construction, repository build, dependency installation, package-manager invocation, generated-code build, submodule initialization, or Git LFS fetch occurs on the host in T08.
- No remote network test is required. Integration tests use isolated local Git and fake executables while exercising the real process, parsing, storage, and transition boundaries.
- No automatic language coverage claim beyond the implemented Python AST worker and exact installed rule-based tools. Unsupported languages and missing tool capability remain explicit gaps.
- No Chaining-origin lineage recovery is invented here. T08 retrieves direct exact entities/locations and relations; T13 supplies and validates chained-child starting provenance before calling the same bounded retrieval service.
- No Web UI, external queue, multi-host scheduler, external disclosure, or snapshot module is introduced.

## Self-Review Checklist

- [ ] Map every Task 8 requirement in the master plan to at least one RED test and one acceptance criterion above.
- [ ] Confirm no step asks an adapter to create metadata, IDs, stored references, work status, or database state.
- [ ] Confirm all proposed persisted objects already exist in `contracts/static.py`; transport DTOs are explicitly non-persisted.
- [ ] Confirm `StaticToolAdapter` and T07 fake signatures remain backward-compatible.
- [ ] Confirm CodeQL command policy has no host build/autobuild escape.
- [ ] Confirm path checks cover both lexical traversal and resolved symlink/junction/Git-mode escape.
- [ ] Confirm every failure path distinguishes missing evidence from executed zero-hit evidence.
- [ ] Confirm only Task 10 Step 6 runs the complete pytest suite.
- [ ] Confirm no placeholder text, unresolved type name, mismatched function signature, or unowned output remains.
