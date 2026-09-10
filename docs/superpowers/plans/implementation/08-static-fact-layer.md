# Task 8 Real Static Fact Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare an exact Git commit, run AST, CodeQL, and OpenGrep through safe process boundaries, publish their exact attempt-scoped evidence, normalize it into one deterministic `StaticFactBundle`, and return bounded code context from that same workspace and commit.

**Architecture:** Keep the approved Pydantic contracts and the T07 fake vertical slice unchanged except for the one load-bearing `StaticToolProfile` contract and `StaticToolRequest.tool_profile_ref` extension described in Task 1. Real process adapters return non-persisted typed observations and raw bytes; a trusted application coordinator supplies IDs, metadata, artifact storage, action/work transitions, and exact result publication through injected ports. `static_analysis/` imports only `contracts`, `ports`, and `config`; it never imports concrete `runtime` or `storage` modules.

**Tech Stack:** CPython `>=3.12,<3.13`, POSIX asyncio subprocesses, a typed Win32 suspended-process/Job Object backend, Git CLI, Python `ast`, CodeQL CLI, OpenGrep CLI, Pydantic 2 contracts, existing SQLite/content-addressed artifact ports, pytest, Ruff, and strict mypy.

**Spec:** `docs/architecture-v5/02-static-fact-layer.md`, `docs/architecture-v5/08-lightweight-data-contracts.md`, `docs/architecture-v5/10-security-boundaries.md`, `docs/architecture-v5/implementation/01-module-map.md`, and `docs/superpowers/plans/2026-09-08-sastsimi-complete-implementation.md` Task 8.

## Global Constraints

### 2026-09-10 repository-lane security review amendment

The Wave 1A repository lane may additionally make only these foundation-seam
changes required by the independent C1/I1/I2/I3 security findings:

- `src/sastsimi/ports/workspace.py` may require an active `enforce` operation so
  repository Git execution can monitor the exact lease and cancel the existing
  POSIX process group or Windows Job Object immediately on quota violation.
- `src/sastsimi/ports/dto.py` may make failed `RepositoryPreparation.root`
  optional for allocation failures that never obtained a lease, and may add an
  optional opaque `lease_id` to repository preparation/action-receipt transport.
  Receipts still must not persist an absolute root: recovery resolves the exact
  root from the trusted lease identity/locator and validates it before use.
- `src/sastsimi/static_analysis/process.py` and the non-persisted
  `ProcessSpec`/`ProcessReceipt` transport in `ports/dto.py` may add exact
  action and command-kind binding plus a bounded no-follow receipt reader.
  This is limited to resolving and validating every repository process receipt
  during recovery; it does not change a persisted contract or activate a tool.
  Its constructor conformance updates may touch only
  `tests/unit/static_analysis/test_process.py` and
  `tests/unit/static_analysis/test_process_windows.py`.

No persisted contract, enum, schema, public CLI activation, or other Wave 1
lane ownership changes are authorized by this amendment.

### 2026-09-11 Context integrity receipt seam amendment

Task 9 requires a durable `CONTEXT_READ` receipt to bind the ordered process
receipts proving that the workspace did not change around the read. The frozen
`WorkspaceLocatorPort.assert_unchanged` previously discarded those receipts,
so the integration agent may make this one additive, transport-only seam before
accepting the Wave 2C lane:

- `WorkspaceLocatorPort.assert_unchanged` requires the real work `attempt_id`
  and a caller-owned unique `check_id`, then returns
  `tuple[ProcessReceipt, ...]` in execution order.
- `WorkspaceGuard` binds both identities into each `ProcessSpec` and returns the
  already-produced accepted integrity-check receipts. It performs no additional
  command and changes no validation decision. Pre-read and post-read checks use
  different `check_id` values, so their receipts cannot overwrite or alias.
- Existing AST and CodeQL callers may ignore the return value. Context Retrieval
  must bind the exact receipt hashes into its same-attempt `CONTEXT_READ`
  receipt; it may not invent or reconstruct them after the read.
- `WorkspaceLocatorPort.validate_integrity_receipts` is a no-process recovery
  check. It recomputes the trusted expected Git `ProcessSpec` sequence for the
  exact action, attempt, and ordered check IDs and rejects any count, order,
  identity, outcome, or command-fingerprint mismatch. Recovery uses this check
  with separately no-follow/hash-verified receipt files; it never reruns Git
  after a complete `CONTEXT_READ` receipt exists.
- Only `src/sastsimi/ports/workspace.py`,
  `src/sastsimi/static_analysis/repository_loader.py`, their existing focused
  unit tests, and this plan may change for this serial seam. No persisted
  contract, schema, authority, current pointer, or tool behavior changes.

- Base implementation commit is `b3b2d9918ea815b9b936c09c98e4c53fd54937dc`.
- Do not change existing fields, enums, validators, result ownership, or reference meaning in `src/sastsimi/contracts/`. The sole permitted domain-contract extension is the narrow `StaticToolProfile` record plus the transport-level `StaticToolRequest.tool_profile_ref` required to close exact adapter selection; export and inventory its generated schema in Task 1. No other schema may change.
- Retain T07 `FakeStaticToolAdapter`, fake workspace setup, and deterministic 22-step scenarios as regression fixtures; real adapters are additive and are not selected by the CLI in this task.
- `CodeWorkspace.status=READY` is required before any code-scoped artifact, `STATIC_TOOL`, `STATIC_NORMALIZE`, or `CONTEXT_RETRIEVAL` work is accepted.
- The requested Git ref is resolved to one commit object, checked out detached, and verified against `HEAD`; branch names are never retained as the code identity.
- `CodeWorkspace` begins as an append-only `PREPARING` revision and ends as a new `READY` or `FAILED` revision of the same logical record. Its exact current ref, `WORKSPACE_PREP` work/attempt state, and `AnalysisRunState.workspace_ref` projection must never disagree.
- Repository source, destination, tool executable, query/rule catalog, timeout, environment, and file list come from trusted configuration or a claimed action, never from LLM output. Repository input is canonicalized before the first record or argv is built: reject all userinfo, query, and fragment components and use only the resulting secret-free `CanonicalRepositorySource.url` in `CodeWorkspace`, actions, diagnostics, logs, and Git argv.
- POSIX processes use `asyncio.create_subprocess_exec(*argv)`. Windows uses the trusted shell-free suspended Win32 launcher defined in Task 2: create suspended, attach to a kill-on-close Job Object, then resume. No shell string, `shell=True`, command interpolation, repository executable, or executable discovered inside the analyzed workspace is allowed.
- Process environment is constructed from an allowlist. Git prompts, Git LFS smudge, external protocols, and repository hooks are disabled by default.
- A process writes only to an attempt-owned output directory outside the analyzed checkout. The analyzed checkout is never a build output directory.
- Clone and checkout storage is allocated only through an attempt-owned `WorkspaceStoragePort` lease backed by enforceable byte/file-count quota controls. Because no commit exists before clone, the exact immutable quota-policy artifact uses `RunStoredDataRef` scoped by `analysis_id`; that exact ref/hash is fixed in the `WORKSPACE_PREP` work and Git `RUN_TOOL` action inputs. If the backend cannot enforce every configured limit or reserve requirement, fail closed before starting Git; there is no unbounded directory fallback.
- One monotonic deadline is created for each claimed external action and shared by every subprocess in that action. Git subcommands and OpenGrep batches receive only the remaining time; cancellation terminates the current process tree and prevents every later subprocess or batch.
- CodeQL may analyze an exact prebuilt database. T08 must not invoke `codeql database create`, `--command`, autobuild, build scripts, package installation, or repository code on the host.
- CodeQL output is confined to a guarded attempt directory with trusted total-directory, individual-file, and read-size limits. Oversized or non-regular SARIF is never partially parsed.
- AST and OpenGrep receive only the validated tracked regular-file manifest. Git symlinks, submodules, LFS pointers, unsafe paths, sensitive paths, and unsupported languages are omitted and represented as `DataGap` candidates.
- A tool adapter does not allocate SASTSIMI IDs, construct `RecordMeta`, write artifacts or records, move current pointers, or decide work status. It returns typed observations, raw bytes, safe diagnostics, and measured timing only.
- The trusted application-side `StaticExternalRunner` is the only real-tool entry to `ExternalCallService`. It reserves budget, obtains ALLOW, durably claims dispatch, invokes one lower adapter, records return and measured use, then asks the publisher to bind the raw artifact, optional `RuleExecutionRecord`, and exactly one `ToolRunResult` to the current `STATIC_TOOL` attempt.
- `SELECTED + EXECUTED + hit_count=0` means executed with zero raw hits. Missing telemetry, skipped rules, timeout, cancellation, and parse failure never become zero hits.
- A normalizer consumes only COMMITTED outputs for the expected tool works. It never combines attempts, workspaces, commits, analysis configurations, or rule catalogs.
- Tool failure does not discard usable output from other tools and does not mean safe code or a vulnerability verdict.
- At least one implemented evidence path must produce real `CodeRelation(relation_kind="DATA_FLOW")`: T08 decodes ordered CodeQL SARIF `codeFlows`; missing or unsafe flow steps become `DataGap` rather than invented reachability.
- Context retrieval is two phase: a non-persisted intent is expanded without file reads into a trusted graph/lineage plan, whose canonical bytes and hash are stored as an exact artifact input to `READ_CODE`; only after that exact action is authorized and claimed may the service recompute the plan and read files from the same `workspace_id + commit_id`.
- Context limits are caller requests bounded by an injected trusted runtime/profile ceiling. A caller can request less, never more. Every explicit entity/location path and every relation- or lineage-expanded path must be authorized before the first file read.
- The trusted ceiling is canonical JSON stored as an immutable content-addressed configuration artifact. Its exact artifact identity is `StoredDataRef(data_kind="artifact", stored_data_id=<sha256>, content_hash=<same sha256>, workspace_id, commit_id, record_id=null)`. That ref is fixed once in the `CONTEXT_RETRIEVAL` work, the plan artifact, and the `READ_CODE` action `input_refs`; the Runtime Validator exact-resolves and hash-verifies it from those inputs. It is deliberately absent from `ActionDecision.checked_config_refs`, whose existing contract requires record-backed refs. Replay never substitutes any different profile artifact, even one with higher limits.
- For a Chaining-origin proposal with no direct start location, the T08 Context Retrieval Service—not T13—validates the exact proposal/match/parent-Primitive provenance and recovers the allowed starting entities and locations. T13 only produces the records consumed through the port.
- Verify `HEAD`, tracked-file cleanliness, and safe path identity immediately before and after every static tool execution and context read. If they change, discard newly produced evidence and report `WORKSPACE_CHANGED`.
- Local absolute paths, credentials, environment secrets, raw authorization material, and unrestricted stderr never enter `safe_message`, domain records, or ordinary logs.
- Capability observations in T08 are technical, non-persisted evidence only. Every real adapter resolves one exact `StaticToolProfile` revision, executable digest, version, and approval state; it never selects by tool name, PATH, or a current-profile lookup. T08 exercises approved fixture/evaluation profiles only. T16 exclusively records capability evidence and activates production profiles.
- Use focused tests after each RED/GREEN step. Commit the immutable T08 implementation candidate first, then run the complete pytest suite exactly once on that recorded candidate SHA. Record results afterward in a separate evidence-only documentation commit.

---

## Baseline Inspection and Incremental Rule

The implementer must begin by checking current code instead of recreating T07 services.

- `src/sastsimi/contracts/static.py` already defines `CodeWorkspace`, `CodeLocation`, `DataGap`, `AnalysisError`, `ToolSource`, `CodeFact`, `CodeRelation`, `RuleExecutionRecord`, `ToolRunResult`, `StaticFactBundle`, `CodeContextRequest`, and `CodeContextResponse` plus current-result validators.
- `src/sastsimi/ports/static_tool.py` already exposes the frozen outer `StaticToolAdapter` protocol.
- `src/sastsimi/orchestration/fake_static_runtime.py` already proves authorized `RUN_TOOL`, external dispatch, budget accounting, exact attempt output, and transition publication with a fake adapter.
- `src/sastsimi/orchestration/fake_setup.py` already proves `WORKSPACE_PREP`, two fake static works, `STATIC_NORMALIZE`, and downstream use of the resulting bundle.
- `src/sastsimi/storage/context_binding.py` and `src/sastsimi/storage/context_policy.py` already bind an exact claimed `READ_CODE` action to one request/response pair.
- `src/sastsimi/storage/transition_service.py` already owns atomic output publication and current-pointer movement.
- `src/sastsimi/ports/dto.py` currently aliases `ToolCapabilityResult` to a one-ref `BoundaryRecord`; T08 must preserve the public `probe(profile_ref) -> ToolCapabilityResult` signature while replacing that placeholder transport shape with a conformance-tested bridge to the lower probe observation.

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

- Modify `src/sastsimi/contracts/static.py`: add the sole new persisted contract, `StaticToolProfile`, with exact adapter/tool/executable/version/digest/purpose/status and bounded execution fields.
- Modify `src/sastsimi/contracts/schema_export.py` and create `schemas/generated/static_tool_profile/1.schema.json`: export and inventory that one new contract; assert no unrelated generated schema drift.
- Modify `src/sastsimi/ports/dto.py`: add `StaticToolRequest.tool_profile_ref` plus frozen transport DTOs for canonical repository input, action deadline, repository preparation, process results, capability observations, raw static observations, Context intent/plan, and published tool material. Apart from the referenced domain profile, these DTOs are not domain schemas.
- Modify `src/sastsimi/ports/static_tool.py`: retain `StaticToolAdapter`; add `StaticProcessAdapter` and `StaticAttemptPublisherPort` lower seams.
- Create `src/sastsimi/ports/workspace.py`: attempt-owned quota-enforced workspace allocation, exact local workspace lookup, integrity check, and repository publication protocols without exposing paths in persisted contracts.
- Create `src/sastsimi/ports/context.py`: trusted Context ceilings and read-only exact lineage-record resolver ports.
- Modify `src/sastsimi/ports/configuration_registry.py` and `src/sastsimi/ports/trusted_evidence.py`: add typed static-tool profile registration/resolution and exact trusted approval seams.
- Modify `src/sastsimi/ports/__init__.py`: export only public protocol and DTO names used by composition/tests.

### Real static layer

- Create `src/sastsimi/static_analysis/process.py`: common bounded process facade plus the POSIX `asyncio` backend, process-group cancellation, output caps, durable attempt receipts, and redacted diagnostics.
- Create `src/sastsimi/static_analysis/process_windows.py`: shell-free Win32 `CreateProcessW(CREATE_SUSPENDED)` launcher, pipe capture, Job Object assignment before resume, wait, cancellation, and handle cleanup.
- Create `src/sastsimi/static_analysis/workspace_storage.py`: trusted attempt lease adapter with enforceable Git-object, checkout-byte, file-count, and minimum-free-space bounds and fail-closed cleanup/quarantine.
- Create `src/sastsimi/static_analysis/repository_loader.py`: trusted URL/destination checks, clone without checkout, exact commit resolution, detached checkout, tracked-file manifest, and workspace integrity guard.
- Create `src/sastsimi/static_analysis/ast_adapter.py`: safe Python AST worker invocation and raw observation decoder.
- Create `src/sastsimi/static_analysis/python_ast_worker.py`: isolated parse-only worker; it never imports target code.
- Create `src/sastsimi/static_analysis/codeql_adapter.py`: version probe and SARIF analysis of an already prepared CodeQL database; no host build/autobuild path.
- Create `src/sastsimi/static_analysis/open_grep_adapter.py`: version probe and JSON scan over an explicit safe file manifest.
- Create `src/sastsimi/static_analysis/coordinator.py`: real outer `StaticToolAdapter`, same-attempt materialization request, cancellation routing, and expected-tool fan-out/fan-in orchestration.
- Create `src/sastsimi/static_analysis/normalizer.py`: deterministic mapping and merge into the existing `StaticFactBundle` contract.
- Create `src/sastsimi/static_analysis/context_retrieval.py`: bounded, exact-workspace code and graph lookup returning the existing request/response contracts.
- Modify `src/sastsimi/verification/context_service.py`: preserve the T07 fake entrypoint and add the trusted two-phase application handler that turns intent into an exact plan artifact, READ_CODE action, request, and response publication.
- Modify `src/sastsimi/static_analysis/__init__.py`: export stable service/adapter entrypoints while retaining `FakeStaticToolAdapter`.

### Trusted publication and composition seam

- Create `src/sastsimi/orchestration/static_publication.py`: implement `WorkspacePreparationPublisherPort`, `StaticAttemptPublisherPort`, and the Task 8 trusted normalization publisher with existing `WorkflowRunner`, `RuntimeServices`, exact `SAVE_RESULT`, artifact store, IDs, and clock. This is the trusted application-side writer; repository/process adapters and the pure normalizer never import concrete runtime or storage modules.
- Create `src/sastsimi/orchestration/static_external_runner.py`: own the real static `RUN_TOOL` action, reservation, `ExternalCallService` dispatch, shared monotonic deadline, measured accounting, receipt-based recovery, and handoff to `StaticAttemptPublisherPort`.
- Modify `src/sastsimi/bootstrap.py`: add a private factory that composes real static components for tests and future activation, but do not select it from `analyze` or mark profiles `ACTIVE`.
- Modify `src/sastsimi/storage/intermediate_policy.py`, `intermediate_publication.py`, and `transition_service.py`: support the canonical append-only workspace lifecycle and exact run-state projection without adding a second storage mechanism.
- Modify `src/sastsimi/storage/context_binding.py`, `context_policy.py`, and `action_validator.py`, and create `src/sastsimi/storage/context_lineage.py`: bind the exact plan/profile/request, enforce all requested paths and immutable trusted ceiling, derive the durable request-count/fingerprint view from existing records and artifacts, and resolve exact records for validation by the Context Retrieval Service. Do not add a Context ledger table or schema.
- Modify `src/sastsimi/storage/codec.py`, `configuration_registry.py`, `src/sastsimi/runtime/configuration_registry.py`, and `src/sastsimi/runtime/fake_support.py`: register, exact-resolve, and test the immutable `StaticToolProfile`; no new table or migration is needed because the generic record store remains authoritative.

### Tests and fixtures

- Create `tests/unit/static_analysis/conftest.py`: immutable process, raw output, manifest, and metadata fixtures.
- Create `tests/unit/static_analysis/test_process.py`.
- Create `tests/unit/static_analysis/test_process_windows.py`.
- Create `tests/unit/static_analysis/test_repository_loader.py`.
- Create `tests/unit/static_analysis/test_workspace_storage.py`.
- Create `tests/unit/static_analysis/test_ast_adapter.py`.
- Create `tests/unit/static_analysis/test_codeql_adapter.py`.
- Create `tests/unit/static_analysis/test_open_grep_adapter.py`.
- Create `tests/unit/static_analysis/test_normalizer.py`.
- Create `tests/unit/static_analysis/test_context_retrieval.py`.
- Create `tests/contract/test_static_tool_conformance.py`: generic coordinator/public-port conformance using injected fake lower adapters only.
- Create at integration checkpoint I2 `tests/contract/test_static_tool_real_adapter_conformance.py`: actual AST/CodeQL/OpenGrep bridge conformance after every real adapter has been merged.
- Create `tests/integration/static_analysis/conftest.py`: local Git repository and fake executable fixtures; no network or host CodeQL/OpenGrep installation required.
- Create `tests/integration/static_analysis/test_repository_prepare.py`.
- Create `tests/integration/static_analysis/test_tool_attempt_publication.py`.
- Create `tests/integration/recovery/test_static_external_recovery.py`.
- Create `tests/integration/static_analysis/test_static_join.py`.
- Create `tests/integration/static_analysis/test_context_retrieval.py`.
- Create `tests/integration/static_analysis/test_chained_child_context.py`.
- Create `tests/integration/recovery/test_static_workspace_recovery.py`.
- Modify `tests/integration/storage/test_typed_configuration_registry.py`.
- Create `tests/integration/recovery/test_context_external_recovery.py`.
- Create `tests/security_negative/test_code_path_escape.py`.
- Modify `tests/contract/domain/test_static.py` and `tests/unit/contracts/test_schema_export.py`: validate the sole contract/schema extension and reject profile closure mismatches.
- Modify `tests/contract/test_architecture_imports.py`: explicitly reject concrete runtime/storage imports and unsafe process APIs in `static_analysis`.
- Modify `tests/unit/test_fake_adapters.py` and selected T07 E2E tests only to assert compatibility; do not rewrite fake behavior around the real adapters.

---

## Parallel Execution DAG and File Ownership

Use one integration worktree rooted at the reviewed base plus isolated lane worktrees. The integration agent alone creates lane worktrees, cherry-picks reviewed lane commits, resolves conflicts, and edits shared composition files. A lane must stop and request an integration decision rather than editing outside its allowlist. Contracts, ports, shared process code, and architecture boundary tests are frozen after the serial foundation; no parallel lane may change them. A no-op lane still adds or strengthens only its named tests, records the already-satisfied invariant, and returns a reviewable commit (or an explicit no-change report when even a test already exists).

```text
Serial Foundation: Task 1 -> Task 2 -> freeze SHA F
                              |
              +---------------+----------------+
              |               |                |
Wave 1A: Task 3        Wave 1B: Task 4   Wave 1C: Task 5
Repository Loader      AST + conservative CodeQL + SARIF
                       data flow
              |               |                |
              +------- Integration checkpoint I1 -------+
                                      |
              +-----------------------+-----------------------+
              |                       |                       |
Wave 2A: Task 6             Wave 2B: Tasks 7 -> 8     Wave 2C: Task 9
OpenGrep batching           Generic coordinator +      Context Retrieval
                            fan-in with fake adapters
              |                       |                       |
              +------- I2 merge + real 3-adapter conformance --+
                                      |
                       Serial Task 10 bootstrap/workflow
                                      |
                 candidate commit -> one full suite on its SHA
                                      |
                    evidence-only docs commit -> review
```

### Serial foundation allowlist

- Task 1 owns only `src/sastsimi/contracts/{static.py,schema_export.py}`, `schemas/generated/static_tool_profile/1.schema.json`, `src/sastsimi/ports/{dto.py,static_tool.py,workspace.py,context.py,configuration_registry.py,trusted_evidence.py,__init__.py}`, `src/sastsimi/storage/{codec.py,configuration_registry.py}`, `src/sastsimi/runtime/{configuration_registry.py,fake_support.py}`, `src/sastsimi/static_analysis/fake.py`, `tests/contract/{test_core_ports.py,test_architecture_imports.py}`, `tests/contract/domain/test_static.py`, `tests/unit/contracts/test_schema_export.py`, `tests/integration/storage/test_typed_configuration_registry.py`, `tests/unit/test_fake_adapters.py`, and `tests/unit/static_analysis/conftest.py`. This is the only pre-freeze lane allowed to extend a domain contract or generated schema.
- Task 2 owns only `src/sastsimi/static_analysis/{process.py,process_windows.py}`, `tests/unit/static_analysis/{test_process.py,test_process_windows.py}`, and the initial shared `tests/integration/static_analysis/conftest.py`.
- Review Task 1 and Task 2, run their focused tests, and record the resulting immutable foundation commit as SHA `F` in the execution record before creating Wave 1 worktrees. From `F` onward, lane commits that touch `src/sastsimi/contracts/**`, `src/sastsimi/ports/**`, either process module, the shared integration conftest, or the architecture import test are rejected.

### Wave 1 lane allowlists

- **1A Repository Loader:** only `src/sastsimi/static_analysis/{repository_loader.py,workspace_storage.py}`, `src/sastsimi/orchestration/{static_external_runner.py,static_publication.py}`, `src/sastsimi/runtime/workflow_runner.py`, `src/sastsimi/storage/{action_validator.py,authorization.py,current_inputs.py,intermediate_policy.py,intermediate_publication.py,transition_service.py}`, `tests/unit/static_analysis/{test_repository_loader.py,test_workspace_storage.py}`, `tests/integration/static_analysis/test_repository_prepare.py`, `tests/integration/storage/{test_intermediate_publication.py,test_workflow_runner.py}`, `tests/integration/recovery/test_static_workspace_recovery.py`, and the first edit to `tests/security_negative/test_code_path_escape.py`. The storage edits are limited to two implementation-discovered pre-clone seams. First, an unresolved input may bypass record lookup only when it is a current-analysis `RunStoredDataRef(data_kind="artifact", record_id=null, stored_data_id=content_hash)`; the Repository Loader must still `open_verified` and validate the exact canonical quota artifact before authorization/dispatch. Every other unresolved reference remains fail closed. Second, a `CodeWorkspace(status="PREPARING")` may pass current-input checks only for `RUN_TOOL + REPOSITORY_LOADER + WORKSPACE_PREP`, including both authorization and claim/dispatch rechecks; the default and every other context remain `READY` only.
- **1B AST + conservative data flow:** only `static_analysis/{python_ast_worker.py,ast_adapter.py}` and `tests/unit/static_analysis/test_ast_adapter.py`.
- **1C CodeQL + SARIF:** only `static_analysis/codeql_adapter.py` and `tests/unit/static_analysis/test_codeql_adapter.py`.

Each Wave 1 lane branches from `F`, runs only its task's focused RED/GREEN tests plus directly named regressions, and submits one or more small commits for review. After all three reviews, the integration agent cherry-picks 1A, 1B, then 1C into the integration worktree, resolves any unexpected conflict there without asking a lane to broaden ownership, runs the union of their focused tests, and records checkpoint SHA `I1`. Failure at this checkpoint is fixed serially before Wave 2 begins.

```powershell
uv run pytest tests/unit/static_analysis/test_process.py tests/unit/static_analysis/test_process_windows.py tests/unit/static_analysis/test_repository_loader.py tests/unit/static_analysis/test_workspace_storage.py tests/unit/static_analysis/test_ast_adapter.py tests/unit/static_analysis/test_codeql_adapter.py tests/integration/static_analysis/test_repository_prepare.py tests/integration/storage/test_intermediate_publication.py tests/integration/storage/test_workflow_runner.py tests/integration/recovery/test_static_workspace_recovery.py tests/security_negative/test_code_path_escape.py tests/contract/test_architecture_imports.py -q
git diff --check F..HEAD
```

Expected at `I1`: all Wave 1 focused tests pass, no lane changed a frozen/shared file outside its allowlist, and the range has no whitespace error. Replace `F` with the recorded full foundation SHA rather than creating a Git tag.

### Wave 2 lane allowlists

- **2A OpenGrep batching:** only `static_analysis/open_grep_adapter.py` and `tests/unit/static_analysis/test_open_grep_adapter.py`.
- **2B Coordinator + deterministic fan-in:** only `src/sastsimi/static_analysis/{coordinator.py,normalizer.py}`, `src/sastsimi/orchestration/{static_external_runner.py,static_publication.py}`, `tests/integration/static_analysis/{test_tool_attempt_publication.py,test_static_join.py}`, `tests/integration/recovery/test_static_external_recovery.py`, `tests/contract/test_static_tool_conformance.py`, and `tests/unit/static_analysis/test_normalizer.py`. This lane alone may extend the Wave 1A-owned runner/publisher after `I1`, and it executes Tasks 7 then 8 in that order. Its conformance file uses injected fake lower adapters only; it must not import or instantiate the real AST, CodeQL, or not-yet-merged OpenGrep adapter.
- **2C Context Retrieval:** only `src/sastsimi/static_analysis/context_retrieval.py`, `src/sastsimi/verification/context_service.py`, `src/sastsimi/storage/{context_lineage.py,context_binding.py,context_policy.py,action_validator.py}`, `tests/unit/static_analysis/test_context_retrieval.py`, `tests/integration/static_analysis/{test_context_retrieval.py,test_chained_child_context.py}`, `tests/integration/storage/test_context_publication.py`, `tests/integration/recovery/test_context_external_recovery.py`, and the second edit to `tests/security_negative/test_code_path_escape.py`.

Each Wave 2 lane branches from `I1`; 2B executes Tasks 7 then 8 serially inside its own worktree because publication precedes fan-in. Review every lane commit before the integration agent cherry-picks 2A, 2B, then 2C. Only after 2A's real OpenGrep implementation and 2B's generic coordinator bridge coexist does the integration agent create `tests/contract/test_static_tool_real_adapter_conformance.py`; that serial checkpoint test instantiates the actual AST, CodeQL, and OpenGrep adapters behind the coordinator using only exact `APPROVED` fixture/evaluation `StaticToolProfile` revisions and trusted fake executables. It covers their public probe/run/cancel bridge, exact request/work/action/profile binding, digest/version checks, absent/stale/mismatched profile fail-closed behavior, and exact-profile selection of the public pure raw-replay decoder defined in Task 8. A concrete adapter module may receive only a narrow named public pure replay-decoder wrapper in this serial integration commit when its Wave 1 implementation exposes the same logic only through a private method; the wrapper must not start a process, read mutable configuration, allocate IDs, or publish state. It never creates or accepts a production `ACTIVE` profile. The test is not delegated back to any parallel lane. Run it alone first. If it fails, the integration agent makes the smallest serial fix in the already merged adapter/coordinator owner files and reruns only this focused test. After it passes, commit the test and any serial fix, obtain review of that integration commit, run the combined focused tests below without further edits, and record the resulting full SHA as `I2`. No Wave 2 lane edits frozen foundation or shared composition files.

```powershell
uv run pytest tests/contract/test_static_tool_real_adapter_conformance.py -q
git add tests/contract/test_static_tool_real_adapter_conformance.py src/sastsimi/static_analysis/ast_adapter.py src/sastsimi/static_analysis/codeql_adapter.py src/sastsimi/static_analysis/open_grep_adapter.py src/sastsimi/static_analysis/coordinator.py
git commit -m "test: verify real static adapter conformance"
uv run pytest tests/unit/static_analysis/test_open_grep_adapter.py tests/unit/static_analysis/test_normalizer.py tests/unit/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_tool_attempt_publication.py tests/integration/static_analysis/test_static_join.py tests/integration/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_chained_child_context.py tests/integration/storage/test_context_publication.py tests/integration/recovery/test_static_external_recovery.py tests/integration/recovery/test_context_external_recovery.py tests/contract/test_static_tool_conformance.py tests/contract/test_static_tool_real_adapter_conformance.py tests/contract/domain/test_static.py tests/security_negative/test_code_path_escape.py tests/unit/test_fake_adapters.py tests/e2e/test_fake_true_pipeline.py -q
git diff --check I1..HEAD
```

Expected at `I2`: all Wave 2 focused, actual three-adapter conformance, Context recovery, and T07 compatibility tests pass; every cherry-picked commit was reviewed; and only the integration agent resolved cross-lane conflicts or authored the post-merge conformance file. Replace `I1` with the recorded full checkpoint SHA.

### Final serial integration rule

Only Task 10 may edit `src/sastsimi/bootstrap.py`, `src/sastsimi/static_analysis/__init__.py`, the shared integration conftest after `F`, shared architecture tests after the lane freeze is lifted, or this plan's implementation-evidence appendix. The integration agent composes all real components privately, resolves conflicts, and runs focused lint/type/schema/architecture/document/link/diff checks until they are green. It then commits the implementation/test candidate and runs `uv run pytest tests -q` exactly once on that immutable recorded SHA. Only after the run may it append the observed result to this plan and create a separate evidence-only documentation commit. That second commit receives only document/link/report-format/diff checks, never another full-suite run. If the supposed evidence commit changes production code, tests, dependency or lock files, generated schemas, runtime configuration, or anything other than the declared evidence document, it is not evidence-only: discard that classification, form and record a new candidate SHA, and run the full suite once on the new candidate before writing a replacement evidence commit.

---

### Task 1: Freeze Existing Semantics and Add the Exact Profile/Raw-Process Seam

**Files:**
- Modify: `src/sastsimi/contracts/static.py`
- Modify: `src/sastsimi/contracts/schema_export.py`
- Create: `schemas/generated/static_tool_profile/1.schema.json`
- Modify: `src/sastsimi/ports/dto.py`
- Modify: `src/sastsimi/ports/static_tool.py`
- Create: `src/sastsimi/ports/workspace.py`
- Create: `src/sastsimi/ports/context.py`
- Modify: `src/sastsimi/ports/configuration_registry.py`
- Modify: `src/sastsimi/ports/trusted_evidence.py`
- Modify: `src/sastsimi/ports/__init__.py`
- Modify: `src/sastsimi/storage/codec.py`
- Modify: `src/sastsimi/storage/configuration_registry.py`
- Modify: `src/sastsimi/runtime/configuration_registry.py`
- Modify: `src/sastsimi/runtime/fake_support.py`
- Modify: `src/sastsimi/static_analysis/fake.py`
- Modify: `tests/contract/test_core_ports.py`
- Modify: `tests/contract/test_architecture_imports.py`
- Modify: `tests/contract/domain/test_static.py`
- Modify: `tests/unit/contracts/test_schema_export.py`
- Modify: `tests/integration/storage/test_typed_configuration_registry.py`
- Modify: `tests/unit/test_fake_adapters.py`
- Test: `tests/unit/static_analysis/conftest.py`

**Interfaces:**
- Consumes: existing public `StaticToolAdapter` method signatures, `CodeWorkspace`, `ToolCoverage`, generic record/configuration storage, and static closed-enum values.
- Produces: the sole new domain record `StaticToolProfile`; `StaticToolRequest.tool_profile_ref`; its generated schema and typed registry/resolver; non-persisted `CanonicalRepositorySource`, `MonotonicActionDeadline`, `ProcessSpec`, `ProcessReceipt`, `StaticActionReceipt`, `ProcessResult`, `StaticRuleMapping`, concrete transport `ToolCapabilityResult`, `StaticCapabilityObservation`, `StaticToolObservation`, `PublishedWorkspaceMaterial`, `PublishedStaticToolMaterial`, `PrebuiltCodeQLDatabase`, workspace storage lease/policy projections, `StaticProcessAdapter`, `StaticExternalExecutionPort`, `StaticToolProfileResolverPort`, `StaticAttemptPublisherPort`, `WorkspaceStoragePort`, `WorkspacePreparationPublisherPort`, and `WorkspaceLocatorPort`.

`StaticToolProfile` is the only domain-contract extension allowed in T08. Add it to `contracts/static.py`, `CORE_SCHEMAS`, the generated-schema inventory, codec coverage, typed configuration registry facade/protocol, and trusted-evidence boundary. It is immutable, `HYPOTHESIS=False`, `ATTEMPT=False`, and has these closed fields and invariants (use the repository's existing constrained string/integer/hash types):

```python
class StaticToolProfile(DomainRecord):
    KIND = "static_tool_profile"
    HYPOTHESIS = False
    ATTEMPT = False
    profile_key: NonEmptyStr
    purpose: Literal["FIXTURE", "EVALUATION", "PRODUCTION"]
    status: Literal["DRAFT", "APPROVED", "ACTIVE", "RETIRED"]
    adapter_key: Literal["PYTHON_AST", "CODEQL", "OPENGREP"]
    tool_name: Literal["AST", "CODEQL", "OPENGREP"]
    tool_kind: Literal["STRUCTURE", "RULE_BASED"]
    executable_key: NonEmptyStr
    executable_sha256: Sha256
    expected_version: NonEmptyStr
    capability_evidence_ref: StoredDataRef | None
    probe_timeout_ms: PositiveInt
    run_timeout_ms: PositiveInt
    stdout_limit_bytes: PositiveInt
    stderr_limit_bytes: PositiveInt
    max_attempt_output_bytes: PositiveInt
    max_output_file_bytes: PositiveInt
    max_artifact_read_bytes: PositiveInt
```

The only valid adapter tuple is `PYTHON_AST + AST + STRUCTURE`, `CODEQL + CODEQL + RULE_BASED`, or `OPENGREP + OPENGREP + RULE_BASED`. `DRAFT` and `RETIRED` are never executable. T08 may resolve `APPROVED` records only when `purpose` is `FIXTURE` or `EVALUATION` and the injected trusted-evidence port approves that exact record revision/content hash. `ACTIVE` is reserved for `purpose=PRODUCTION`, requires exact `capability_evidence_ref`, and may be produced/promoted only by T16 after capability and evaluation evidence. T08 does not create or activate it. Historical profile revisions remain readable for audit, but execution requires the supplied ref to equal the registry's current exact approved revision; stale refs fail closed.

`executable_key` is resolved only by an injected, host-owned executable registry. It is not a path, PATH lookup, workspace-relative name, or Agent value. Before every probe/run, the resolver verifies a regular executable outside the analyzed workspace, recomputes its SHA-256, and checks both `executable_sha256` and `expected_version`. Profile tool name/kind/adapter tuple, request action tool name, lower observation tool/version, and executable digest must all agree; absent, duplicate, stale, wrong-hash, unapproved, wrong-purpose/status, version-mismatched, or composition-mismatched profiles cause zero process calls and no fallback to any “current” or same-name profile.

Extend the existing transport request exactly as follows; this is not a second domain schema:

```python
@dataclass(frozen=True)
class StaticToolRequest:
    action: ActionRequest
    workspace: CodeWorkspace
    tool_profile_ref: StoredDataRef
    analysis_config_ref: StoredDataRef
    rule_catalog_ref: StoredDataRef | None
```

For every `STATIC_TOOL` operation the same exact `tool_profile_ref` must occur once in current work `input_refs`, once in `ActionRequest.input_refs`, and in `StaticToolRequest.tool_profile_ref`; it is also eligible for `ActionDecision.checked_config_refs` because it is a record-backed configuration ref. Exact resolution and authorization reject absence, duplicates, different `record_id`/`content_hash`, stale current pointer, and any request/action/work mismatch before adapter selection or spawn.

All shapes below other than `StaticToolProfile` are transport-only. They may echo trusted correlation IDs supplied by the caller, but must not allocate IDs, subclass `DomainRecord`, carry `RecordMeta`, or move current pointers. They carry `StoredDataRef` only where an exact canonical input is bound or the trusted publisher returns already committed material.

```python
@dataclass(frozen=True)
class CanonicalRepositorySource:
    # The only repository string permitted after validation. It contains an
    # https scheme, IDNA-normalized host, optional non-default port, and path;
    # it can never contain userinfo, query, fragment, or control characters.
    url: str
    host: str
    repository_path: str

@dataclass(frozen=True)
class MonotonicActionDeadline:
    action_id: str
    started_ns: int
    expires_ns: int

    def remaining_ms(self, now_ns: int) -> int:
        return max(0, (self.expires_ns - now_ns) // 1_000_000)

@dataclass(frozen=True)
class ProcessSpec:
    invocation_id: str
    attempt_id: str
    argv: tuple[str, ...]
    cwd: Path
    env: tuple[tuple[str, str], ...]
    attempt_output_dir: Path
    stdout_limit_bytes: int
    stderr_limit_bytes: int
    attempt_output_limit_bytes: int
    deadline: MonotonicActionDeadline

@dataclass(frozen=True)
class ProcessReceipt:
    invocation_id: str
    attempt_id: str
    command_fingerprint: str
    outcome: Literal["SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED"]
    return_code: int | None
    stdout_name: str
    stdout_size: int
    stdout_sha256: str
    stderr_name: str
    stderr_size: int
    stderr_sha256: str
    elapsed_ms: int

@dataclass(frozen=True)
class StaticActionReceipt:
    action_id: str
    attempt_id: str
    operation_kind: Literal["REPOSITORY_PREPARE", "STATIC_TOOL", "CONTEXT_READ"]
    input_fingerprint: str
    process_receipt_hashes: tuple[str, ...]
    observation_name: str
    observation_size: int
    observation_sha256: str
    elapsed_ms: int

@dataclass(frozen=True)
class ProcessResult:
    outcome: Literal["SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED"]
    return_code: int | None
    stdout: bytes
    stderr_tail: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    elapsed_ms: int
    receipt: ProcessReceipt
    receipt_path: Path

@dataclass(frozen=True)
class StaticCapabilityObservation:
    available: bool
    tool_name: str
    tool_kind: Literal["STRUCTURE", "RULE_BASED"]
    executable_key: str
    observed_executable_sha256: str | None
    observed_version: str | None
    expected_version: str
    reason_code: str | None

@dataclass(frozen=True)
class ToolCapabilityResult:
    # `ref` preserves the T07 public attribute while the other fields expose
    # the checked lower observation without pretending it is a domain record.
    ref: StoredDataRef
    available: bool
    tool_name: str
    tool_kind: Literal["STRUCTURE", "RULE_BASED"]
    executable_key: str
    observed_executable_sha256: str | None
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
    rule_id: str | None

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
class StaticRuleMapping:
    rule_id: str
    result_fact_kind: str
    flow_start_fact_kind: str | None
    requires_code_flow: bool

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
    # This is CanonicalRepositorySource.url, never the submitted raw string.
    repository_url: str
    requested_ref: str
    status: Literal["READY", "FAILED"]
    resolved_commit_id: str | None
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
class PublishedWorkspaceMaterial:
    workspace: CodeWorkspace
    workspace_ref: RunStoredDataRef
    work: WorkExecutionState
    analysis_state: AnalysisRunState

@dataclass(frozen=True)
class PrebuiltCodeQLDatabase:
    workspace_id: str
    commit_id: str
    language: str
    database_root: Path
    database_digest: str

@dataclass(frozen=True)
class WorkspaceStoragePolicy:
    # Decoded projection of one immutable canonical JSON artifact, not a new
    # domain record. All arithmetic is overflow checked.
    schema_version: Literal["1.0"]
    max_git_bytes: int
    max_checkout_bytes: int
    max_file_count: int
    min_free_bytes: int

@dataclass(frozen=True)
class WorkspaceStorageLease:
    lease_id: str
    attempt_id: str
    workspace_id: str
    root: Path
    backend_key: str
    policy_ref: RunStoredDataRef
    enforcement_evidence: str

@dataclass(frozen=True)
class WorkspaceStorageUsage:
    git_bytes: int
    checkout_bytes: int
    file_count: int
    free_bytes: int
```

`StaticActionReceipt.observation_name` is a validated relative leaf under the allocated attempt directory, never an absolute path. The receipt payload for repository preparation is a closed canonical projection of `RepositoryPreparation` that omits `root` and the submitted source; recovery obtains the trusted root again from `WorkspaceLocatorPort` by workspace identity and reruns the guard. A static-tool receipt may serialize only the closed `StaticToolObservation` fields after every path/diagnostic has passed the safe transport validator. A `CONTEXT_READ` receipt binds the exact unpublished `CodeContextResponse` candidate bytes to the READ_CODE action/input fingerprint, same-attempt `CodeContextRequest` already recorded in the claimed decision outcomes, ordered workspace-integrity process receipts, and exact fragment refs; it is recovery evidence, not a published response. Before atomic rename, the runner rejects a symlink/reparse point/non-regular observation file, bytes above the trusted action/profile output cap, a hash/size mismatch, absolute local paths, credentials, or unknown fields. Recovery applies the same validation before decoding; it never parses truncated receipt payload bytes.

The lower protocols are:

```python
class StaticProcessAdapter(Protocol):
    async def probe(
        self, profile: StaticToolProfile, deadline: MonotonicActionDeadline
    ) -> StaticCapabilityObservation: ...
    async def execute(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticToolObservation: ...
    async def cancel(self, attempt_id: str) -> CancellationResult: ...

class StaticExternalExecutionPort(Protocol):
    async def invoke(
        self,
        request: StaticToolRequest,
        profile: StaticToolProfile,
        operation: Callable[[MonotonicActionDeadline], Awaitable[StaticToolObservation]],
    ) -> ToolRunResult: ...

class StaticToolProfileResolverPort(Protocol):
    def resolve(self, profile_ref: StoredDataRef) -> StaticToolProfile: ...

class WorkspaceStoragePort(Protocol):
    def allocate(
        self,
        *,
        attempt_id: str,
        workspace_id: str,
        policy_ref: RunStoredDataRef,
        policy: WorkspaceStoragePolicy,
    ) -> WorkspaceStorageLease: ...

    def measure(self, lease: WorkspaceStorageLease) -> WorkspaceStorageUsage: ...
    def seal(self, lease: WorkspaceStorageLease, reason: str) -> None: ...
    def cleanup_or_quarantine(self, lease: WorkspaceStorageLease) -> None: ...

class StaticAttemptPublisherPort(Protocol):
    def publish(
        self, request: StaticToolRequest, observation: StaticToolObservation
    ) -> PublishedStaticToolMaterial: ...

class WorkspaceLocatorPort(Protocol):
    def root_for(self, workspace: CodeWorkspace) -> Path: ...
    async def assert_unchanged(
        self,
        workspace: CodeWorkspace,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_id: str,
    ) -> tuple[ProcessReceipt, ...]: ...
    def validate_integrity_receipts(
        self,
        workspace: CodeWorkspace,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_ids: tuple[str, ...],
        receipts: tuple[ProcessReceipt, ...],
    ) -> None: ...

class WorkspacePreparationPublisherPort(Protocol):
    def begin(
        self,
        work: WorkExecutionState,
        repository_url: str,
        workspace_id: WorkspaceId,
    ) -> PublishedWorkspaceMaterial: ...

    def finish(
        self,
        work: WorkExecutionState,
        preparing: PublishedWorkspaceMaterial,
        outcome: RepositoryPreparation,
    ) -> PublishedWorkspaceMaterial: ...
```

- [ ] **Step 1: Write failing profile/schema, port, and architecture tests.** In `tests/contract/domain/test_static.py`, cover all valid profile tuples and reject invalid adapter/tool/kind combinations, missing digest/version, invalid limits, invalid status/purpose/capability combinations, and attempt/hypothesis-scoped metadata. In schema tests, assert exactly one new generated document `static_tool_profile/1.schema.json`, codec round-trip, registry/inventory inclusion, and no unrelated schema drift. In typed-registry tests, prove exact APPROVED fixture/evaluation registration and resolution; reject absent, duplicate key/current, stale/wrong-hash, unapproved, RETIRED/DRAFT, wrong-purpose, wrong executable digest/version, and any name/adapter mismatch before invocation. Assert the trusted approval default is false and fake approval is keyed by exact ref/hash. Assert that `StaticToolRequest.tool_profile_ref` must equal the one exact record-backed ref in work/action inputs and is included in `checked_config_refs` only after exact resolution. Also assert that public `StaticToolAdapter.probe(profile_ref) -> ToolCapabilityResult`, `run(request) -> ToolRunResult`, and `cancel(attempt_id)` signatures remain unchanged; `ToolCapabilityResult.ref` remains available to T07; the lower adapter has no storage methods; transport DTOs except the domain profile have no `meta`; `static_analysis` cannot import `sastsimi.runtime` or `sastsimi.storage`; and `subprocess.run`, `Popen`, `create_subprocess_shell`, `os.system`, and `shell=True` are rejected. Permit direct `CreateProcessW` only in `process_windows.py`, whose tests enforce `CREATE_SUSPENDED` and Job assignment before resume. Assert the old `ToolCapabilityResult = BoundaryRecord` placeholder is gone.
- [ ] **Step 2: Run the focused RED test.**

```powershell
uv run pytest tests/contract/domain/test_static.py tests/unit/contracts/test_schema_export.py tests/integration/storage/test_typed_configuration_registry.py tests/contract/test_core_ports.py tests/contract/test_architecture_imports.py -q
```

Expected: fail only because the one profile contract/schema/registry path, exact request binding, lower DTOs/protocols, and new boundary assertions do not exist.

- [ ] **Step 3: Add the one profile contract and freeze DTOs/protocols.** Implement exactly the `StaticToolProfile` and `StaticToolRequest.tool_profile_ref` closure above; register it in schema export/codec/typed configuration registry and trusted-evidence ports; generate only its schema. Keep every other new DTO non-persisted and immutable. Replace only the port-local `ToolCapabilityResult = BoundaryRecord` alias with the concrete transport DTO above, and update `FakeStaticToolAdapter.probe`/contract fixtures to populate it while preserving `.ref` and the public signature. Add and freeze the attempt-owned workspace storage policy/lease, Context intent/plan, ceiling, lineage-reader, and limit-policy port shapes used later so parallel lanes do not edit shared ports. Do not add a table/migration, profile-name lookup, PATH lookup, or a second registry.
- [ ] **Step 4: Run the focused GREEN test and fake compatibility test.**

```powershell
uv run pytest tests/contract/domain/test_static.py tests/unit/contracts/test_schema_export.py tests/integration/storage/test_typed_configuration_registry.py tests/contract/test_core_ports.py tests/contract/test_architecture_imports.py tests/unit/test_fake_adapters.py -q
```

Expected: pass; the sole schema addition is deterministic, exact fixture/evaluation profile closure is fail closed, and the T07 fake adapter remains runtime-checkable as `StaticToolAdapter`.

- [ ] **Step 5: Commit this independently reviewable seam.**

```powershell
git add src/sastsimi/contracts/static.py src/sastsimi/contracts/schema_export.py schemas/generated/static_tool_profile/1.schema.json src/sastsimi/ports/dto.py src/sastsimi/ports/static_tool.py src/sastsimi/ports/workspace.py src/sastsimi/ports/context.py src/sastsimi/ports/configuration_registry.py src/sastsimi/ports/trusted_evidence.py src/sastsimi/ports/__init__.py src/sastsimi/storage/codec.py src/sastsimi/storage/configuration_registry.py src/sastsimi/runtime/configuration_registry.py src/sastsimi/runtime/fake_support.py src/sastsimi/static_analysis/fake.py tests/contract/domain/test_static.py tests/unit/contracts/test_schema_export.py tests/integration/storage/test_typed_configuration_registry.py tests/contract/test_core_ports.py tests/contract/test_architecture_imports.py tests/unit/test_fake_adapters.py tests/unit/static_analysis/conftest.py
git commit -m "feat: close static tool profile boundary"
```

### Task 2: Implement the Bounded Safe Process Runner

**Files:**
- Create: `src/sastsimi/static_analysis/process.py`
- Create: `src/sastsimi/static_analysis/process_windows.py`
- Create: `tests/unit/static_analysis/test_process.py`
- Create: `tests/unit/static_analysis/test_process_windows.py`
- Create: `tests/integration/static_analysis/conftest.py`

**Interfaces:**
- Consumes: trusted immutable `ProcessSpec` created inside a real adapter. Every spec for one action carries the same `MonotonicActionDeadline` object and attempt output root.
- Produces: `ProcessResult` plus an atomically renamed, bounded `ProcessReceipt`; `cancel(attempt_id)` is idempotent, sets a per-attempt cancellation latch, terminates only that attempt's registered process tree, and prevents subsequent specs for the attempt from spawning.

The facade validates `deadline.action_id`, attempt ownership, non-empty argv, exact executable, cwd/output roots, caps, and cancellation state before choosing a platform backend. It computes `remaining_ms=deadline.remaining_ms(monotonic_ns())` immediately before every spawn. Zero remaining time returns `TIMED_OUT` without invoking the backend. A subprocess never receives a fresh per-command timeout.

On POSIX, `process.py` uses `asyncio.create_subprocess_exec(*spec.argv, cwd=..., env=..., stdout=PIPE, stderr=PIPE, start_new_session=True)` and terminates/kills the process group with `killpg`. On Windows, `process_windows.py` must not promise pre-execution containment through bare `asyncio`: it calls `CreateProcessW` through a small typed `ctypes` wrapper with the exact trusted executable as `lpApplicationName` and a mutable command line built from validated argv with Python's Windows quoting algorithm (`subprocess.list2cmdline`, not `Popen` or a shell). Reject NUL in argv/env first. Create explicit stdin/stdout/stderr pipe handles, mark parent ends non-inheritable, and pass only child standard handles through `STARTUPINFOEX.PROC_THREAD_ATTRIBUTE_HANDLE_LIST`; use `bInheritHandles=True` with `CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP | EXTENDED_STARTUPINFO_PRESENT`. Before `ResumeThread`, create a Job Object, apply `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, and successfully call `AssignProcessToJobObject`. Any pipe/attribute/create/job/configure/assign failure terminates the still-suspended process where one exists, deletes the attribute list, closes every process/thread/job/pipe handle, and never resumes it. Only after assignment succeeds may it call `ResumeThread`; waiting and bounded pipe reads run through `asyncio.to_thread` so the public API stays async. Cancellation/timeout calls `TerminateJobObject`, waits a bounded grace interval, closes the Job, and proves the process and child fixture are gone. `subprocess.Popen(..., CREATE_SUSPENDED)` is explicitly forbidden because it does not retain a supported main-thread handle for the required resume ordering.

Both backends stream stdout/stderr to exclusive files inside the attempt-owned output directory while maintaining byte counters and hashes. They expose at most the configured bounded stdout and stderr tail in memory. Before returning, the runner fsyncs the files and atomically renames a canonical receipt containing invocation/attempt IDs, command fingerprint, outcome, return code, file names/sizes/hashes, and monotonic elapsed time. It never stores argv, environment values, repository URL, or absolute host paths in that receipt. An incomplete temporary receipt is not proof of return and recovery must not rerun a durably dispatched action from it.

- [ ] **Step 1: Write RED tests for argument integrity and environment isolation.** Use a fixture executable that echoes argv and selected environment keys. Assert metacharacters remain one argument, the shell is never invoked, unapproved parent environment keys are absent, `cwd` is exact, and an executable path inside `workspace_root` is rejected.
- [ ] **Step 2: Add RED shared-deadline, receipt, output-cap, and cancel tests.** Use a fake monotonic clock and two sequential specs with the same deadline. Assert the second receives only the first process's remaining time, zero remaining time causes zero backend calls, cancellation kills the active parent/child and latches the attempt so the next command is not spawned, output is capped, stderr is a bounded tail, a complete receipt hash-checks, a torn receipt is rejected, repeated cancel returns `cancelled=False`, and another attempt is unaffected.
- [ ] **Step 3: Add RED Windows launch-order contract tests.** With an injected Win32 API fake on every OS, assert restricted inherited-handle setup and the strict order `CreateProcessW(CREATE_SUSPENDED) -> CreateJobObject -> SetInformationJobObject(KILL_ON_JOB_CLOSE) -> AssignProcessToJobObject -> ResumeThread`; inject failure at pipe/attribute/create/job/configure/assign/resume and assert no premature resume plus complete handle/attribute/process cleanup. Reject NUL argv/env and assert an unrelated inheritable sentinel handle is absent in the child. On Windows, run a real child-spawning fixture and assert cancellation removes parent and child. On POSIX, assert this module is not selected. The test must fail if the implementation substitutes `asyncio.create_subprocess_exec`, ordinary `Popen`, or assign-after-resume on Windows.
- [ ] **Step 4: Run RED.**

```powershell
uv run pytest tests/unit/static_analysis/test_process.py tests/unit/static_analysis/test_process_windows.py -q
```

Expected: fail because `SafeProcessRunner` does not exist.

- [ ] **Step 5: Implement the minimal facade, POSIX backend, and suspended Win32 backend.** Keep Win32 constants, structures, quoting, handle ownership, launch sequencing, and cleanup in `process_windows.py`; keep platform selection, deadline/cancellation registry, bounded hashing/spooling, and canonical receipt validation in `process.py`. Return safe outcome values instead of raising for process exit, timeout, or cancellation; raise before spawn only for invalid trusted configuration.
- [ ] **Step 6: Run GREEN and architecture checks.**

```powershell
uv run pytest tests/unit/static_analysis/test_process.py tests/unit/static_analysis/test_process_windows.py tests/contract/test_architecture_imports.py -q
uv run ruff check src/sastsimi/static_analysis/process.py src/sastsimi/static_analysis/process_windows.py tests/unit/static_analysis/test_process.py tests/unit/static_analysis/test_process_windows.py
uv run mypy --strict src/sastsimi/static_analysis/process.py src/sastsimi/static_analysis/process_windows.py tests/unit/static_analysis/test_process.py tests/unit/static_analysis/test_process_windows.py
```

Expected: all commands pass.

- [ ] **Step 7: Commit.**

```powershell
git add src/sastsimi/static_analysis/process.py src/sastsimi/static_analysis/process_windows.py tests/unit/static_analysis/test_process.py tests/unit/static_analysis/test_process_windows.py tests/integration/static_analysis/conftest.py
git commit -m "feat: run static tools through bounded processes"
```

### Task 3: Prepare and Guard an Exact Git Workspace

**Files:**
- Create: `src/sastsimi/static_analysis/repository_loader.py`
- Create: `src/sastsimi/static_analysis/workspace_storage.py`
- Create: `src/sastsimi/orchestration/static_external_runner.py`
- Create: `src/sastsimi/orchestration/static_publication.py`
- Modify: `src/sastsimi/runtime/workflow_runner.py`
- Modify: `src/sastsimi/storage/intermediate_policy.py`
- Modify: `src/sastsimi/storage/intermediate_publication.py`
- Modify: `src/sastsimi/storage/transition_service.py`
- Create: `tests/unit/static_analysis/test_repository_loader.py`
- Create: `tests/unit/static_analysis/test_workspace_storage.py`
- Create: `tests/integration/static_analysis/test_repository_prepare.py`
- Modify: `tests/integration/storage/test_intermediate_publication.py`
- Modify: `tests/integration/storage/test_workflow_runner.py`
- Create: `tests/integration/recovery/test_static_workspace_recovery.py`
- Create: `tests/security_negative/test_code_path_escape.py`

**Interfaces:**
- Consumes: current `WORKSPACE_PREP` work/attempt, submitted repository reference immediately converted to `CanonicalRepositorySource`, requested Git ref, allocated `analysis_id`, allocated `workspace_id`, exact immutable workspace-quota artifact ref/hash, `REPOSITORY_LOADER` identity, execution-budget scope, and injected process runner/clock plus `WorkspaceStoragePort`.
- Produces: append-only `CodeWorkspace(PREPARING -> READY | FAILED)` revisions, atomically matching `AnalysisRunState.workspace_ref`, terminal work/attempt outputs, `RepositoryPreparation(repository_url, workspace_id, resolved_commit_id, root, tracked_files, gaps, errors)`, and `WorkspaceGuard` implementing `WorkspaceLocatorPort`.

Use the existing transition, intermediate-publication, budget, and external-dispatch services. Do not add a workspace table, current pointer, or alternate journal. `WorkspacePreparationPublisherPort` has two application-side operations:

```python
class WorkspacePreparationPublisherPort(Protocol):
    def begin(
        self,
        work: WorkExecutionState,
        repository_url: str,
        workspace_id: WorkspaceId,
    ) -> PublishedWorkspaceMaterial: ...

    def finish(
        self,
        work: WorkExecutionState,
        preparing: PublishedWorkspaceMaterial,
        outcome: RepositoryPreparation,
    ) -> PublishedWorkspaceMaterial: ...
```

Before `begin` or any Git dispatch, exact-resolve and hash-verify one immutable canonical JSON workspace storage policy artifact with precisely `kind="workspace_storage_policy"`, `schema_version="1.0"`, `max_git_bytes`, `max_checkout_bytes`, `max_file_count`, and `min_free_bytes`, all positive bounded integers. A code-scoped `StoredDataRef` is impossible here because `commit_id` is deliberately unknown until clone/resolve succeeds. Its identity is therefore exactly `RunStoredDataRef(data_kind="artifact", stored_data_id=<sha256>, content_hash=<same sha256>, analysis_id=<current analysis>, record_id=null)`. Require `stored_data_id == content_hash`, the exact data kind, canonical bytes, schema version, and current `analysis_id`. The trusted run builder—not the repository caller, Agent, repository, or adapter—fixes that exact ref once in the `WORKSPACE_PREP` work `input_refs`; the Git `RUN_TOOL` action repeats the same `RunStoredDataRef` in `input_refs`, and the dispatch/receipt input fingerprint covers it. Because it is artifact-backed with `record_id=null`, it is deliberately excluded from record-only `ActionDecision.checked_config_refs`; validation occurs against exact work/action inputs and canonical artifact bytes. Recovery rejects a missing, duplicate, substituted, wrong-analysis, wrong-kind, wrong-hash, noncanonical, or caller-increased policy before allocation or Git.

`WorkspaceStoragePort.allocate` is the only source of the clone destination. It returns a private lease bound to exact `analysis_id + workspace_id + attempt_id + policy_ref`; the root is never caller supplied, persisted, or reused by a different attempt. Allocation succeeds only when the selected host/container/filesystem backend can hard-enforce all four limits before writes: `.git` storage at or below `max_git_bytes`, non-`.git` checkout storage at or below `max_checkout_bytes`, non-`.git` checkout entries at or below `max_file_count`, and free capacity remaining at or above `min_free_bytes`. Use overflow-safe arithmetic and require initial allocatable capacity of at least `max_git_bytes + max_checkout_bytes + min_free_bytes`. Runtime measurement before/between/after Git commands is defense in depth; it is not a substitute for a write-denying quota. If any limit cannot be enforced on the current OS/backend, allocation fails closed before clone with zero Git calls and a FAILED workspace. There is no ordinary-directory fallback. T08 integration tests use an enforceable fixture backend; production backend selection/activation remains T16.

Run every Git process inside the lease boundary. A backend quota denial or measured cap violation immediately latches cancellation, kills the current Git process tree, prevents the next subcommand, seals the lease, and calls `cleanup_or_quarantine` using only the exact lease identity. Successful cleanup removes only that attempt-owned root; failed cleanup leaves a sealed, non-reusable quarantine for trusted later recovery. No quota failure may publish READY, a tracked-file manifest, or downstream static work. The terminal CodeWorkspace is FAILED with a safe storage-limit error; raw pack/tree data and local paths are not persisted. Recovery must re-resolve the same policy ref/hash and lease identity and may never resume under larger caller limits.

`begin` is called only after the `WORKSPACE_PREP` attempt is RUNNING. It creates revision 1 with `status=PREPARING`, `commit_id=null`, and a new logical record. A narrow extension to `IntermediatePublicationService` permits only `(WORKSPACE_PREP, code_workspace, REPOSITORY_LOADER)` and binds this RunMeta record to the current work, active attempt, unused exact `SAVE_RESULT` decision, and current `AnalysisRunState`. Publishing the PREPARING revision and updating `AnalysisRunState.workspace_ref + workspace_id` happen in the same database transaction; the attempt ID is proven by the work, action decision, and publication receipt rather than added to the unchanged `CodeWorkspace` schema.

`finish` creates exactly revision 2 with the same `logical_record_id`, `previous_record_id=PREPARING.meta.record_id`, and `revision_number=2`. Success uses `status=READY` and the verified commit; failure uses `status=FAILED`, the exact commit only when it was resolved and verified, and real error IDs. The terminal `TransitionCommit` atomically publishes that revision, completes the `WorkAttempt` and `WorkExecutionState`, and moves `AnalysisRunState.workspace_ref`, `workspace_id`, and `commit_id` to the same exact revision. A READY workspace maps to work/attempt `SUCCEEDED`; a FAILED workspace maps to work/attempt `FAILED` and never starts static work. Neither revision stores the local root.

`canonicalize_repository_source(submitted: str) -> CanonicalRepositorySource` is the first operation, before `begin`, metadata construction, action construction, logging, or argv construction. Production accepts `https` only. Parse with `urllib.parse.urlsplit`; reject a leading `-`, scp-like syntax, `ext::`, empty hostname/path, invalid port, literal or parsed userinfo, every non-empty query (including token, access-token, key, auth, and signed-URL fields), every fragment, backslash, decoded `.`/`..` path segments, percent-decoded control characters, and malformed percent/IDNA encoding. Normalize scheme and IDNA hostname to lowercase, omit port 443, retain a validated non-default port, normalize percent escapes to uppercase, and build one `https://host[:port]/path` value. Do not trim and continue after finding a secret-bearing component: reject the submission so a signed or credentialed URL cannot silently change repository identity. Tests may explicitly enable canonical local `file://` fixtures through an injected test policy; that flag defaults false and is unavailable to Agents and repository content.

Only `CanonicalRepositorySource.url` may populate `CodeWorkspace.repository_url`, `RepositoryPreparation.repository_url`, Git argv, an action reason/input, or a diagnostic. The submitted string is an ephemeral ingress value and must not reach the record store, artifact store, external-dispatch row, process receipt, structured log, exception text, or safe message. Redaction is defense in depth, not the canonicalization mechanism. Re-parse and equality-check the canonical source immediately before Git argv construction; no later layer may append query parameters or credentials.

Git invocation uses a sanitized environment containing `GIT_TERMINAL_PROMPT=0`, `GIT_LFS_SKIP_SMUDGE=1`, `GIT_CONFIG_NOSYSTEM=1`, an empty global config, and no inherited `GIT_SSH_COMMAND`, credential helper, askpass, proxy credential, or protocol override. Invoke clone as `git -c credential.helper= -c core.askPass= -c protocol.allow=never -c protocol.https.allow=always -c protocol.ext.allow=never -c protocol.file.allow=never -c http.followRedirects=false -c core.hooksPath=<empty-dir> clone --no-checkout --no-recurse-submodules -- <canonical-url> <destination>`. In the isolated local fixture only, switch `protocol.file.allow` to `always` through the trusted test configuration.

Resolve with `git -C <root> rev-parse --verify --end-of-options <requested-ref>^{commit}`, validate exactly one lowercase/uppercase hexadecimal object ID, then checkout only that resolved ID with `git -C <root> checkout --detach <commit-id>`. Confirm `git rev-parse HEAD` equals it.

Build the manifest from `git ls-files --stage -z`. Accept only regular blobs (`100644` or `100755`) whose normalized Git path passes the existing `GitPath` validator and whose real parent and file stay inside the workspace. Represent mode `120000` as `SYMLINK_EXCLUDED`, mode `160000` as `SUBMODULE_UNAVAILABLE`, LFS pointer content as `LFS_POINTER_ONLY`, sensitive paths as a configured exclusion, and unsupported file types as gaps. Do not follow or fetch them. Do not initialize submodules or run Git LFS in T08 because no approved isolated execution boundary exists.

`WorkspaceGuard.assert_unchanged` verifies exact HEAD, `git diff --quiet HEAD --`, `git diff --cached --quiet HEAD --`, and the tracked manifest fingerprint. Untracked tool-output files do not become analysis inputs because tools receive the frozen manifest, but creation of a tracked-path replacement or manifest drift fails the guard.

All clone, rev-parse, checkout, manifest, and integrity Git invocations run under one authorized external-call envelope created with `ActionType.RUN_TOOL`, `requested_by=REPOSITORY_LOADER`, `tool_name="git"`, the exact PREPARING workspace ref and exact quota-policy artifact ref in `input_refs`, and a trusted logical `file_paths=("workspace/<workspace_id>",)` value that never exposes the host destination. Reserve approved elapsed/cost units before claim and let `StaticExternalRunner` persist dispatch before calling the loader operation. The runner creates one `MonotonicActionDeadline` from the approved work timeout and passes that same object to clone, rev-parse, checkout, `ls-files`, and every integrity command. Each command recomputes remaining time; cancel kills the current Git process tree and latches the attempt so no next Git command starts. Account measured units on return, and release a denied or undispatched reservation. The adapter cannot allocate the lease or call the process runner until the decision is ALLOW and durably claimed; allocation and every receipt are bound to the claimed exact policy.

Before the Git operation callback returns, `StaticExternalRunner` writes the bounded canonical receipt projection of `RepositoryPreparation` (explicitly excluding `root` and all raw ingress) and atomically renames one `StaticActionReceipt(operation_kind=REPOSITORY_PREPARE)` containing the exact action/attempt/input fingerprint and ordered hashes of every Git `ProcessReceipt`. Recovery exact-resolves the root through `WorkspaceLocatorPort`, validates the guarded relative observation file and aggregate receipt, and reruns workspace integrity before publication; it never treats one completed subcommand receipt as proof that the whole repository operation returned.

- [ ] **Step 1: Write RED canonical source and destination tests.** Accept a mixed-case host/default-port URL and assert one normalized secret-free value is used in workspace, preparation result, action, log capture, and clone argv. Reject `https://user:pass@host/repo`, percent-encoded userinfo, every URL with a query such as `?token=secret` or `?x=1`, fragments, percent-encoded controls/dot segments, option injection, `ext::`, unauthorized `file://`, existing/non-empty destination, traversal, and symlink/junction escape. Seed a distinctive secret in each rejected URL, then search staged records, artifacts, dispatch rows, receipts, captured argv/environment, diagnostics, and logs and assert it appears nowhere. Assert rejection causes zero Git/process calls. Decode a successful preparation receipt and prove it contains canonical repository identity but no `root`, raw ingress, absolute local path, credential field, or unknown key.
- [ ] **Step 2: Write RED exact-checkout tests.** Create two commits and a branch that moves after preparation starts. Assert the returned commit is the initially resolved object, checkout is detached, `READY` cannot be proposed on clone/checkout/HEAD mismatch, and no static process starts before readiness.
- [ ] **Step 3: Write RED hard-quota allocation and cleanup tests.** In `test_workspace_storage.py`, use an enforceable fixture backend and assert the quota artifact is exactly a `RunStoredDataRef` with current `analysis_id`, `record_id=null`, exact `data_kind`, `stored_data_id == content_hash`, canonical bytes, and exact schema; explicitly reject a pre-clone `StoredDataRef`, another analysis, wrong kind/hash, duplicate input, and caller substitution. Assert exact attempt ownership, overflow-safe reserve arithmetic, private empty roots, separate `.git`/checkout/file-count counters, and write denial at each limit+1. In repository integration, test a giant pack/object set above `max_git_bytes`, one giant checked-out blob/tree above `max_checkout_bytes`, and a tree above `max_file_count`; each must terminate the process tree, prevent later Git commands, publish no READY/manifest/static work, and either delete the exact lease root or leave it sealed/quarantined and non-reusable. Also test insufficient `min_free_bytes`, an OS/backend reporting any limit unenforceable, caller-supplied destinations, and plain-directory fallback: all fail before clone with zero Git calls. Crash/replay tests substitute a larger policy or another lease and must fail before resumption; exact same run-scoped ref/hash/lease may recover idempotently.
- [ ] **Step 4: Write RED manifest and mutation tests.** Include a regular file, Git symlink, submodule entry fixture, LFS pointer, `../` request, absolute path, Windows drive path, mixed separators, post-checkout edit, index change, and HEAD move. Assert unsafe entries never enter the safe manifest and each omission has a candidate gap.
- [ ] **Step 5: Write RED append-only lifecycle tests.** Assert PREPARING is revision 1 and the terminal READY/FAILED record is revision 2 of the same logical record. At each publication boundary, `AnalysisRunState.workspace_ref` resolves to the current exact revision. At terminal commit, attempt output, work output, transition output, commit output, and run-state workspace ref all equal the terminal revision. Reject READY without exact HEAD, a direct READY revision 1, a second PREPARING revision, READY->FAILED overwrite, mismatched repository/workspace/commit, wrong predecessor, and local path persistence.
- [ ] **Step 6: Write RED action/budget/deadline/authority tests.** Assert every Git subprocess is inside one durably claimed `RUN_TOOL(requested_by=REPOSITORY_LOADER, tool_name="git")`; the exact PREPARING ref, exact quota-policy artifact ref/hash, lease identity, and current work/attempt are bound; reservation occurs before dispatch; actual usage is committed after return; and denied identity, exhausted budget, stale attempt, substituted policy, or unclaimed/ambiguous decision invokes no Git command. Advance a fake monotonic clock between Git subcommands and prove their allowed time strictly decreases; expire or cancel during checkout and assert `ls-files` and later integrity commands are never spawned. Assert the raw loader returns only a typed candidate and cannot allocate metadata or access storage.
- [ ] **Step 7: Write RED crash-recovery tests.** Inject failures after PREPARING publication, after lease allocation, after external claim but before dispatch, after dispatch before return, at quota denial, after Git return before terminal staging, at `TransitionCommit.PREPARED`, and after COMMITTED marker before projection replay. Undispatched work may resume only with the exact policy/lease; an ambiguous dispatched clone is marked uncertain and cannot be silently rerun; a partial destination is reused only after exact guard and quota validation or removed/quarantined only through the exact lease; terminal journal replay converges work, attempt, workspace pointer, and `AnalysisRunState` on one READY or FAILED revision.
- [ ] **Step 8: Run RED.**

```powershell
uv run pytest tests/unit/static_analysis/test_repository_loader.py tests/unit/static_analysis/test_workspace_storage.py tests/integration/static_analysis/test_repository_prepare.py tests/integration/storage/test_intermediate_publication.py tests/integration/storage/test_workflow_runner.py tests/integration/recovery/test_static_workspace_recovery.py tests/security_negative/test_code_path_escape.py -q
```

Expected: fail only on the missing hard-quota lease backend, real loader, workspace lifecycle bridge, Git external envelope, or new recovery closure.

- [ ] **Step 9: Implement the quota adapter, loader, application external runner, and trusted lifecycle bridge.** Keep lease enforcement in `workspace_storage.py` and filesystem/process work in `repository_loader.py`; neither may import concrete storage/runtime. Implement repository reserve/authorize/`ExternalCallService`/deadline/quota/account/recovery in `static_external_runner.py`, and keep metadata/storage publication in `static_publication.py`. Task 7 extends the same runner with `StaticExternalExecutionPort.invoke`; it must not create a second external runner. Extend existing intermediate/transition paths only for the exact workspace rules above. Cleanup goes only through a validated lease; do not recursively delete a caller-supplied or unresolved path. If this OS lacks an enforceable production quota backend, keep production composition unavailable rather than weakening enforcement. Return safe diagnostics without local absolute paths.
- [ ] **Step 10: Run GREEN plus focused static analysis.**

```powershell
uv run pytest tests/unit/static_analysis/test_repository_loader.py tests/unit/static_analysis/test_workspace_storage.py tests/integration/static_analysis/test_repository_prepare.py tests/integration/storage/test_intermediate_publication.py tests/integration/storage/test_workflow_runner.py tests/integration/recovery/test_static_workspace_recovery.py tests/security_negative/test_code_path_escape.py -q
uv run ruff check src/sastsimi/static_analysis/repository_loader.py src/sastsimi/static_analysis/workspace_storage.py src/sastsimi/orchestration/static_external_runner.py src/sastsimi/orchestration/static_publication.py src/sastsimi/runtime/workflow_runner.py src/sastsimi/storage/intermediate_policy.py src/sastsimi/storage/intermediate_publication.py src/sastsimi/storage/transition_service.py tests/unit/static_analysis/test_repository_loader.py tests/unit/static_analysis/test_workspace_storage.py tests/integration/static_analysis/test_repository_prepare.py tests/integration/recovery/test_static_workspace_recovery.py tests/security_negative/test_code_path_escape.py
uv run mypy --strict src/sastsimi/static_analysis/repository_loader.py src/sastsimi/static_analysis/workspace_storage.py src/sastsimi/orchestration/static_external_runner.py src/sastsimi/orchestration/static_publication.py src/sastsimi/runtime/workflow_runner.py src/sastsimi/storage/intermediate_policy.py src/sastsimi/storage/intermediate_publication.py src/sastsimi/storage/transition_service.py tests/unit/static_analysis/test_repository_loader.py tests/unit/static_analysis/test_workspace_storage.py tests/integration/static_analysis/test_repository_prepare.py tests/integration/recovery/test_static_workspace_recovery.py tests/security_negative/test_code_path_escape.py
```

Expected: pass on Windows and POSIX path semantics represented by fixtures; no Git process exists outside the authorized/budgeted dispatch path.

- [ ] **Step 11: Commit.**

```powershell
git add src/sastsimi/static_analysis/repository_loader.py src/sastsimi/static_analysis/workspace_storage.py src/sastsimi/orchestration/static_external_runner.py src/sastsimi/orchestration/static_publication.py src/sastsimi/runtime/workflow_runner.py src/sastsimi/storage/intermediate_policy.py src/sastsimi/storage/intermediate_publication.py src/sastsimi/storage/transition_service.py tests/unit/static_analysis/test_repository_loader.py tests/unit/static_analysis/test_workspace_storage.py tests/integration/static_analysis/test_repository_prepare.py tests/integration/storage/test_intermediate_publication.py tests/integration/storage/test_workflow_runner.py tests/integration/recovery/test_static_workspace_recovery.py tests/security_negative/test_code_path_escape.py
git commit -m "feat: prepare exact guarded git workspaces"
```

### Task 4: Implement the Parse-Only AST and Conservative Local Data-Flow Adapter

**Files:**
- Create: `src/sastsimi/static_analysis/python_ast_worker.py`
- Create: `src/sastsimi/static_analysis/ast_adapter.py`
- Create: `tests/unit/static_analysis/test_ast_adapter.py`

**Interfaces:**
- Consumes: safe tracked `.py` files from `RepositoryPreparation`, exact workspace guard, trusted parser version/profile, the action's shared deadline, and current `StaticToolRequest`.
- Produces: `StaticToolObservation(tool_kind="STRUCTURE")` with JSON raw output, Python file/module/type/callable/data symbols, call/import relations where statically observable, route-binding candidates for literal recognized decorators, conservative intra-callable `DATA_FLOW` candidates, and explicit unsupported/parse gaps. `CALL` direction is caller -> callee; `ROUTE_BINDING` direction is route symbol -> handler callable; `DATA_FLOW` direction is earlier producer/definition -> later target/use.

The worker parses source text with `ast.parse` and never imports, compiles, evaluates, or runs target modules. The parent starts it with the safe process runner and an explicit file manifest. Worker output uses Git-relative paths and 1-based Unicode-code-point positions. Missing end positions produce line-only ranges with both columns `None`; the adapter never invents precision.

The conservative Python flow is a syntactic may-flow, not a vulnerability verdict. Inside one callable's straight-line statement list, a simple `name = expression` emits an expression-location -> target-definition relation. A later `Name(..., Load)` emits the unique last target-definition -> use-location relation while that definition remains unambiguous. Simple annotated assignments follow the same rule. Reassignment replaces the tracked definition after emitting its incoming relation. On a branch, loop, exception region, context manager, comprehension scope, `global`/`nonlocal`, destructuring, attribute/subscript write, dynamic execution, or ambiguous alias, the visitor emits `STATIC_DATA_FLOW_INCOMPLETE`, skips flow traversal inside that construct, and clears the callable's reaching-definition map before continuing. It never joins branches, crosses a call boundary, guesses a return value, or bridges an invalidated step. All AST flow relations have `rule_id=null`, stay inside one file/callable, and retain exact expression/definition/use locations. CodeQL `codeFlows` remains the stronger interprocedural/rule-backed path.

- [ ] **Step 1: Write RED parser and conservative-flow tests.** Cover functions, async functions, methods, classes, imports, direct calls, literal route decorators, Unicode columns, syntax error in one file, unsupported extension, and a file whose top level would raise if executed. For `value = source(); sink(value)`, assert expression -> definition -> use is exactly two forward `DATA_FLOW` relations with exact locations; cover annotated assignment and deterministic reassignment. Assert `CALL` is caller -> callee, `ROUTE_BINDING` is route -> handler, all AST relation `rule_id` values are null, and the sentinel side effect never occurs.
- [ ] **Step 2: Write RED boundary and uncertainty tests.** Assert the worker receives only manifest entries, a symlink is not opened, parse error yields `PARTIAL` plus `STATIC_PARSE_FAILED`, and empty successful parsing is not a vulnerability verdict. Cover branch/loop/try/with/comprehension scope, destructuring, attribute/subscript assignment, `global`/`nonlocal`, alias mutation, and dynamic execution; each ambiguous case must add `STATIC_DATA_FLOW_INCOMPLETE` and must not create a cross-branch, cross-callable, or jump edge.
- [ ] **Step 3: Run RED.**

```powershell
uv run pytest tests/unit/static_analysis/test_ast_adapter.py -q
```

Expected: fail because the AST adapter and worker do not exist.

- [ ] **Step 4: Implement the worker and decoder.** Implement the straight-line definition/use rules above as a small explicit visitor separate from symbol/call extraction. Sort files and emitted candidate keys deterministically. Treat dynamic dispatch, reflection, unresolved imports, control-flow ambiguity, and unsupported syntax as limitations/gaps rather than invented call or data-flow edges. Verify workspace integrity before spawn and after decoding; discard the observation on post-run mutation.
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
- Consumes: trusted absolute CodeQL executable, exact expected CLI version, `PrebuiltCodeQLDatabase` bound to the current workspace/commit, exact query-pack path/digest, complete rule catalog, selected rule IDs/packs, guarded attempt output directory, `StaticToolProfile.max_attempt_output_bytes + max_output_file_bytes + max_artifact_read_bytes`, the action's shared deadline, safe process runner, and current request.
- Produces: `StaticCapabilityObservation` and SARIF-backed `StaticToolObservation(tool_kind="RULE_BASED")`, including ordered `CandidateRelation(relation_kind="DATA_FLOW")` edges from trustworthy SARIF `codeFlows`.

Only these process families are allowed: version probe and `codeql database analyze` of the trusted prebuilt database into an attempt-owned SARIF file. Before execution, require the database descriptor's `workspace_id + commit_id` to equal the current READY workspace and verify its digest. Reject any configured argv containing `database create`, `database trace-command`, `--command`, `autobuild`, a build tool, package installer, workspace executable, or output path under the analyzed checkout. A missing, stale, or digest-mismatched database/query pack yields unavailable capability or `SKIPPED/FAILED` candidate evidence; it never triggers a build. SARIF locations must map back to the safe tracked manifest; foreign or unsafe paths become gaps and cannot produce normalized facts.

Create the attempt output directory with exclusive ownership outside the checkout, reject symlink/junction/reparse components, and pass exactly `<attempt-output>/codeql-result.sarif` after proving it does not exist. A concurrent quota watcher sums only regular files without following links and cancels the process as soon as total size exceeds `max_attempt_output_bytes`; after process exit, repeat the resolved-root/type/count/size checks. The SARIF path must be one regular file inside that directory, not a hard link to an existing external file, and no larger than `max_output_file_bytes`; the whole directory must remain within `max_attempt_output_bytes`. Read at most `max_artifact_read_bytes + 1` bytes and require the SARIF to fit both the output-file and read caps. Compare pre-open/post-open identity and size, and parse only if the complete file fits. Never truncate JSON and attempt to parse it. Oversize, quota violation, replacement, or short/changed read yields `ToolRunResult.status=FAILED` with `DataGap(stage=STATIC_ANALYSIS, code=STATIC_OUTPUT_LIMIT, reason=TRUNCATED)` and `AnalysisError(stage=STATIC_ANALYSIS, code=STATIC_OUTPUT_LIMIT)` because no CodeQL finding is usable; `PARTIAL` is permitted only if another independently complete, bounded adapter output has already been validated, which this single-SARIF CodeQL path does not produce. The oversized SARIF is not stored as a raw artifact.

The SARIF decoder maps result `ruleId` counts to catalog rules. Every catalog rule appears once in `CandidateRule`. Selected rules with trustworthy execution telemetry use `EXECUTED` and the raw hit count, including zero. Unselected rules use `NOT_SELECTED + NOT_EXECUTED`. Missing/ambiguous telemetry uses `UNKNOWN + TELEMETRY_MISSING`; malformed SARIF is not zero hits.

For a catalog entry with `requires_code_flow=true`, decode every `result.codeFlows[].threadFlows[].locations[]` in array order. Normalize each physical location through the safe tracked manifest, then emit one `DATA_FLOW` relation for every consecutive distinct pair, from earlier flow step to later flow step, carrying that exact `rule_id`. The catalog's `flow_start_fact_kind` may label the first valid location (normally `SOURCE`), and `result_fact_kind` labels the result/final valid location (normally `SINK`); never infer endpoint roles from message text or severity. Preserve separate SARIF flows as separate raw candidates until deterministic normalization. If a required flow is absent, has fewer than two valid distinct locations, crosses an unsafe/foreign path, or contains an unresolved step, retain any independently supported endpoint facts but add `DataGap(code=STATIC_DATA_FLOW_UNRESOLVED, reason=MISSING|UNSUPPORTED)` for the missing reachability. Never bridge over a bad step or invent an edge.

- [ ] **Step 1: Write RED capability, command-policy, and output-boundary tests.** Assert exact version match, missing executable, wrong version, database/query-pack digest mismatch, and every prohibited build/autobuild command. Use a fake executable; do not require host CodeQL. Cover attempt-directory escape, pre-existing output, symlink/junction/reparse output, hard-link replacement where supported, directory quota overflow during execution, SARIF at exactly and one byte above `max_output_file_bytes`, exactly and one byte above `max_artifact_read_bytes`, size/identity change during read, and a second unexpected file that pushes total size over `max_attempt_output_bytes`. Assert every cap is independent, over-limit content is never passed to the JSON parser or artifact store, and the exact gap/error/status above is produced.
- [ ] **Step 2: Write RED SARIF and data-flow tests.** Cover one hit, selected zero-hit rule, unselected rule, duplicate result rule IDs, missing rule metadata, malformed JSON, nonzero exit with complete usable SARIF, timeout, cancellation, and raw output preservation. Add a three-location codeFlow and assert exactly two directed `DATA_FLOW` candidates plus catalog-declared SOURCE/SINK endpoints. Add missing, one-location, unsafe-path, and unresolved-middle-step flows and assert `STATIC_DATA_FLOW_UNRESOLVED` with no fabricated jump edge. A truncated or partly written SARIF is always unusable rather than `PARTIAL` evidence.
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

The command builder passes the trusted config and explicit safe target files as separate arguments and fixes JSON output plus timing telemetry in every invocation. It must not use a repository-provided config, command string, response file from the repository, recursive workspace root target, shell glob, rule supplied by an Agent, or caller/profile-provided command-size limit. The batching limit is an immutable hard ceiling owned by the trusted adapter composition: production derives it from the real platform process boundary and computes the exact encoded argv length that the selected process backend will launch, including Windows `CreateProcessW` quoting/UTF-16 length or POSIX argv/environment byte cost and its required safety margin. Only tests may inject a smaller ceiling. If the next safe target would exceed that ceiling, split the sorted manifest into deterministic batches before spawn; one target that cannot fit fails closed. Merge only complete raw batch envelopes without changing per-rule hit counts. All batches receive the same `MonotonicActionDeadline`; immediately before each batch, use only `remaining_ms`, and stop without spawning the next batch after timeout or cancellation. Earlier complete bounded batch envelopes may support `PARTIAL`; an incomplete current batch is never decoded as complete JSON.

Every invocation fixes the CLI's JSON and timing options, and only the closed `time.rules` telemetry from that exact batch proves which selected catalog rules actually executed. A fully completed batch must contain exactly one timing entry for every selected rule and none for an unselected or unknown rule; merge those entries by the deterministic batch order. Only that complete, catalog-consistent telemetry permits `EXECUTED` and a raw hit count, including zero. A missing, duplicate, malformed, unknown, unselected, or cross-batch-inconsistent timing entry yields `UNKNOWN + TELEMETRY_MISSING + hit_count=null` for the identifiable affected selected rule, or for every selected rule in that batch when the affected rule cannot be identified, plus a coverage gap; the absence of findings alone never proves zero hits. Partial multi-batch runs keep facts and raw counts only from independently complete batches and separately report the unexecuted paths/batches.

- [ ] **Step 1: Write RED probe, deadline, and target-boundary tests.** Cover correct/wrong version, config digest mismatch, option-looking file name, spaces/metacharacters, excluded symlink/LFS/submodule, deterministic batching, timeout, cancellation, and attempt-owned output. Assert every command fixes the JSON and timing options. Exercise exact platform argv-size accounting at the boundary, multibyte and quoted Windows arguments, POSIX argv/environment cost, an overlong single target, caller/profile attempts to widen the limit, and the test-only smaller ceiling. Advance a fake monotonic clock per batch and assert decreasing remaining time; cancel or expire during batch 2 and prove batch 3 has zero process calls while complete batch 1 remains identifiable as partial evidence.
- [ ] **Step 2: Write RED result tests.** Cover source, sink, sanitizer, validator, auth, permission, and other mappings from trusted rule metadata; selected zero hits proven by exact `time.rules`; unselected rules; missing, duplicate, malformed, unknown, unselected, and cross-batch-inconsistent timing entries; malformed JSON; nonzero exit with usable partial JSON; and duplicate raw findings whose raw count must not be reduced by normalized deduplication. Assert missing findings without complete trustworthy timing never become a zero hit and affected rules use `UNKNOWN + TELEMETRY_MISSING + hit_count=null` with a gap.
- [ ] **Step 3: Run RED.**

```powershell
uv run pytest tests/unit/static_analysis/test_open_grep_adapter.py -q
```

Expected: fail because `OpenGrepProcessAdapter` does not exist.

- [ ] **Step 4: Implement command building and JSON decoding.** Keep the production command-size hard ceiling inside the trusted adapter composition, use the selected process backend's real encoded-length calculation, expose only a test-only smaller-limit injection, and fix JSON plus timing telemetry options in the closed argv. Use only catalog-owned mapping from rule ID to `fact_kind`; an unknown rule is retained as raw evidence and `OTHER` only when the trusted catalog explicitly permits that mapping. Prove selected-rule execution and zero hits only from the exact complete `time.rules` closure described above. Missing mapping or telemetry is a gap, not an inferred vulnerability type or zero hit.
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
- Modify: `src/sastsimi/orchestration/static_external_runner.py`
- Modify: `src/sastsimi/orchestration/static_publication.py`
- Create: `tests/integration/static_analysis/test_tool_attempt_publication.py`
- Create: `tests/integration/recovery/test_static_external_recovery.py`
- Create: `tests/contract/test_static_tool_conformance.py`

**Interfaces:**
- Consumes: exact `StaticToolProfileResolverPort`, a trusted immutable `adapter_key -> StaticProcessAdapter` map, injected `StaticExternalExecutionPort`, `WorkspaceLocatorPort`, current `StaticToolRequest`, trusted `StaticAttemptPublisherPort`, current work/attempt, exact `BudgetProfileBinding`/`WorkBudgetLimit`, exact analysis configuration, and optional exact rule catalog.
- Produces: public `StaticToolAdapter` behavior, non-persisted `ToolCapabilityResult`, and `PublishedStaticToolMaterial` whose result is the only canonical tool result for that attempt.

The public/lower probe bridge is fixed here. `StaticToolCoordinator.probe(profile_ref)` exact-resolves the supplied record revision/hash from the typed registry, requires the T08-allowed `APPROVED + FIXTURE|EVALUATION` state and exact trusted approval, resolves `executable_key` through the host registry, verifies the executable is a regular non-workspace file and recomputes its digest, selects exactly one lower adapter by the profile's closed `adapter_key`, and creates one bounded probe deadline from `probe_timeout_ms` through its injected monotonic deadline factory. It calls `adapter.probe(profile, deadline)` and rejects any returned executable key/digest, tool name, or expected/observed version that does not match the exact profile. It returns `ToolCapabilityResult(ref=profile_ref, ...)` without persisting or activating anything. Probe timeout/cancellation produces `available=false` with a closed safe reason and terminates the probe process tree. An absent, duplicate, stale, wrong-hash, unapproved, inactive-for-T08, unknown-adapter, executable-digest, version, or observation mismatch fails before spawn where detectable and never falls back to PATH, another revision, another tool, or a name-based/current lookup. This technical probe has no repository access and runs only in the private T08 fixture/evaluation composition and the later T16 capability harness; it is not a substitute for a `RUN_TOOL` action, does not publish an operational result, and cannot activate a profile. T16 alone consumes capability/evaluation evidence and publishes the production `ACTIVE` revision.

`StaticToolCoordinator.run` resolves the exact profile and lower adapter, then gives `StaticExternalExecutionPort.invoke` a cold operation factory. Constructing this callable has no side effect and must not construct an awaitable, touch the workspace, call the adapter, or start a process. The application-side implementation is `StaticExternalRunner`; it alone imports `WorkflowRunner`, `RuntimeServices`, `ExternalCallService`, storage-backed profile/evidence resolution, and the trusted publisher. The exact sequence is:

1. Exact-resolve `request.action`, current RUNNING `STATIC_TOOL` work/attempt, READY workspace, `request.tool_profile_ref`, analysis config/catalog, budget binding, and its one matching `WorkBudgetLimit(operation_kind=TOOL, agent_role=STATIC_ANALYSIS)`. Require the same profile ref exactly once in work `input_refs` and action `input_refs`, require it in the record-backed `ActionDecision.checked_config_refs`, and require exact request/action/work workspace/commit scope. Reapply the approved fixture/evaluation status, trusted approval, closed adapter/name/kind tuple, host executable key/digest, and version checks before selecting exactly one adapter. Reject absence, duplication, stale/wrong ref/hash, caller substitution, action tool-name mismatch, or any closure mismatch before invoking the operation factory.
2. Reserve `BudgetUnits(elapsed_ms=approved timeout, work_count=0, llm_call_count=0, retry_count=0, cost_minor_units=0, currency=<binding currency>)` through `WorkflowRunner.reserve`. Obtain exact `ActionDecision=ALLOW` through `authorize`; DENY releases the reservation and returns without calling `ExternalCallService` or the operation factory.
3. Call `ExternalCallService.invoke_bound(work_id, decision_ref, reservation_ref, cold_operation, idempotency_key=action_id)`. That service atomically claims the ALLOW decision/reservation and durably creates `ExternalDispatch`, then marks it dispatched before it calls `cold_operation(claimed_decision_ref)`. The callback creates the one shared monotonic deadline from the trusted timeout, verifies workspace integrity, invokes exactly one lower `adapter.execute(request, root, profile, deadline)`, verifies workspace integrity again, passes the closed observation through the safe transport validator, serializes it to a regular bounded attempt-owned file, and atomically publishes one `StaticActionReceipt` binding the action/attempt/input fingerprint, every ordered process-receipt hash, and observation file size/hash. Tool observations use the exact `StaticToolProfile.max_attempt_output_bytes`; repository observations use the same trusted `ProcessSpec.attempt_output_limit_bytes` fixed for every Git command in that action. The total includes process files and the receipt observation, so projected cap+1 is rejected rather than truncated and parsed. Process/decode outcomes are data, not uncaught exceptions.
4. `ExternalCallService` marks the dispatch returned. `StaticExternalRunner` calculates actual monotonic elapsed units and idempotently commits the reservation ledger entry. It never releases a reservation after dispatch, timeout, caller cancellation, or unknown outcome.
5. Apply the exact outcome mapping below. Ask the publisher to store bounded raw bytes as a code-scoped artifact, allocate gap/error IDs and `RecordMeta` from the current work/attempt, optionally create the same-attempt `RuleExecutionRecord`, create exactly one `ToolRunResult`, and stage one terminal transition.
6. For `RULE_BASED`, build and stage exactly one `RuleExecutionRecord` whenever the exact config and catalog were resolved, including SKIPPED/FAILED executions; selected rules that did not run use the actual NOT_EXECUTED/UNKNOWN reason. A FAILED result may keep `rule_execution_ref=null` only when failure happened before config/catalog identity could be established, matching the existing contract. Bind any rule ref exactly; `STRUCTURE` always keeps it null. Authorize one `SAVE_RESULT` closure and commit result, optional rule record, attempt, work, transition, and output refs atomically.
7. Return the exact committed `ToolRunResult`. The normalizer reopens and hash-verifies the committed raw artifact; it never trusts only the in-memory observation after restart.

Recovery uses the existing `ExternalDispatch`, reservation/ledger, and transition journals plus the attempt-owned `ProcessReceipt` set and its single aggregate `StaticActionReceipt`; it adds no database table. A prepared but undispatched claim may resume only while the same action, attempt, reservation, profiles, and inputs remain valid. For `DISPATCHED` without `returned_at`, an exact complete action receipt with matching action/attempt/input fingerprint, ordered process-receipt hashes, guarded relative observation path, bounded observation size/hash, and a successfully decoded closed typed observation may recover the old attempt only while its work is still RUNNING and before any BLOCKED transition is committed; recovery then marks returned and continues accounting/publication without running the operation again. This works for one-process CodeQL/AST, multi-batch OpenGrep, and multi-command Git.

A missing, temporary, torn, stale, oversized, symlinked, path-escaping, or mismatched receipt/payload is categorized in prose as an ambiguous external outcome; it does not introduce a new enum and is not caller cancellation. Call the existing uncertain-dispatch guard and use the current canonical transition `work: RUNNING -> BLOCKED`, `waiting_for=(INPUT,)`, `stop_reason=RECOVERY_FAILED`; the current attempt ends `CANCELLED` only as required bookkeeping for that nonterminal work transition. No `ToolRunResult` or rule record is published while the actual external outcome is unknowable, and neither operation factory nor tool is invoked again. Once this BLOCKED transition commits, any later receipt or output for the old attempt is stale: quarantine it, never mark the old dispatch returned from it, never reattach it, and never use it to publish an old-attempt result.

The work remains BLOCKED and is excluded from normalizer fan-in. Explicit trusted reconciliation may authorize only the existing recovery transition `BLOCKED -> READY` after proving retry safety (including external side-effect disposition and exact unchanged work inputs); it then creates a new authorized attempt. That new attempt alone executes and must produce its canonical `ToolRunResult` before the work reaches a terminal status. Reconciliation never makes a late old receipt valid, publishes a result for the cancelled old attempt, guesses the old outcome, treats ambiguity as ordinary caller cancellation, or retries without authorization. For RETURNED plus RESERVED before a BLOCKED transition, commit measured action-receipt usage once; for COMMITTED reservation without output, rebuild the typed observation only from the already verified pre-BLOCKED receipt/files and publish once; for PREPARED/COMMITTED transition, use the existing transition journal. A stale/denied/unclaimed decision, mismatched reservation, or ambiguous dispatch always produces zero new adapter/process invocations.

The mapping is closed and does not invent `WorkStatus.SKIPPED` (that enum does not exist):

- Process `SUCCEEDED`, return code 0, complete valid decoding/coverage/telemetry: `ToolRunResult=SUCCEEDED`, `WorkAttempt=SUCCEEDED`, `WorkExecutionState=SUCCEEDED`, `stop_reason=COMPLETED`, no gaps/errors, and a required bounded `raw_result_ref`.
- Process `SUCCEEDED`, return code 0, and at least one complete usable result plus explained missing coverage/telemetry: `ToolRunResult=PARTIAL`, `WorkAttempt=PARTIAL`, and `WorkExecutionState=PARTIAL`; include the required bounded `raw_result_ref`, usable output, at least one `DataGap`, and any real `AnalysisError`.
- Process `FAILED`/nonzero or `TIMED_OUT` with at least one independently complete, bounded, format-valid result (for example an earlier OpenGrep batch): the result/attempt/work triple is `PARTIAL`; bind `raw_result_ref` only to the canonical envelope of complete batches, keep only their evidence, and add both an affected gap and error. Incomplete current output is not parsed or included in that artifact.
- Process `FAILED`, decode failure, output-limit failure, or `TIMED_OUT` with no usable complete evidence: the result/attempt/work triple is `FAILED`, with at least one affected gap and `AnalysisError`; a safely bounded diagnostic raw artifact may be referenced but is never required or normalized. Timeout uses gap reason `TIMEOUT` and error code `STATIC_TOOL_TIMEOUT`, not cancellation.
- Trusted preflight `NOT_APPLICABLE` before spawn (unsupported language, no safe target, or unavailable exact prebuilt database): no `ProcessResult` and zero process calls, although the cold operation returns a typed skipped observation through the claimed external envelope. Use `ToolRunResult=SKIPPED` with `raw_result_ref=null`; attempt/work are `PARTIAL` with output refs, gap IDs, and `stop_reason=NOT_APPLICABLE`. A rule-based record marks selected rules `NOT_EXECUTED` with `UNSUPPORTED` or the actual closed reason. This path is not a successful zero-hit execution.
- Caller cancellation before trusted execution (before external claim, after claim but before spawn, or before any independently complete usable output): process/operation counters remain zero where spawn has not happened, and incomplete bytes are quarantined. The cancellation handler still exact-resolves the request/profile/config/catalog and atomically publishes exactly one `ToolRunResult=SKIPPED` with `raw_result_ref=null`, a required `DataGap(stage=STATIC_ANALYSIS, code=STATIC_TOOL_CANCELLED, reason=BLOCKED)`, `WorkAttempt=CANCELLED`, `WorkExecutionState=CANCELLED`, and `stop_reason=CALLER_CANCELLED`. For `RULE_BASED`, the same atomic closure always includes exactly one same-attempt `RuleExecutionRecord`: every selected rule is `NOT_EXECUTED` with `hit_count=null` and `reason=CANCELLED`, while not-selected rules retain `NOT_SELECTED`. `STRUCTURE` keeps `rule_execution_ref=null`. No pre-execution cancellation may commit empty outputs.
- Caller cancellation after at least one independently complete, bounded, format-valid usable output (including an earlier OpenGrep batch or a complete returned observation before publication): atomically publish exactly one `ToolRunResult=PARTIAL` with a required `raw_result_ref` containing only the complete usable canonical output plus the required cancellation `DataGap`; `WorkAttempt` and `WorkExecutionState` are nevertheless `CANCELLED` with `stop_reason=CALLER_CANCELLED`. For `RULE_BASED`, its exact same-attempt `RuleExecutionRecord` preserves every actually executed rule and raw `hit_count`, and marks each selected unfinished rule `NOT_EXECUTED + CANCELLED`; missing telemetry is not converted to zero. Incomplete current bytes are excluded. Add an `AnalysisError` only if an independent real error occurred—caller cancellation alone is not a fabricated tool failure.
- Cancellation and normal publication use one compare-and-swap terminal closure. If normal SUCCEEDED/PARTIAL/FAILED publication wins, the later cancel is rejected because work is terminal. If cancellation wins, the publisher chooses SKIPPED or PARTIAL solely from already validated usable output and atomically commits the result, optional exact rule record, attempt/work cancellation, transition, and output refs. Late receipts/results from the losing path are quarantined. Cancellation is never relabeled timeout, failure, FALSE, HOLD, or zero hits, and there is no caller-cancellation path without one canonical result.

The publisher checks that every ordinary terminal `STATIC_TOOL` work closure—including every caller-cancellation closure—has exactly one `ToolRunResult` and that each result/attempt/work combination matches exactly one publishing row above. The solely nonterminal exception is the ambiguous external outcome category: work is `BLOCKED` with `waiting_for=(INPUT,)` and `stop_reason=RECOVERY_FAILED`, the current attempt is bookkeeping-CANCELLED, and no result is permitted until a newly authorized attempt completes after reconciliation. The publisher rejects a nonexistent `WorkStatus.SKIPPED`, `SUCCEEDED` with gaps/errors/incomplete rule telemetry, `PARTIAL` without usable committed evidence and gaps, `FAILED` without errors, ordinary caller-cancelled work with anything other than the declared SKIPPED-without-usable-output or PARTIAL-with-usable-output result, ambiguity mislabeled as caller cancellation, timeout represented as cancellation, any empty-output ordinary cancellation, and any late receipt/result attached to the cancelled old attempt. It validates catalog equality, exact profile/configuration refs, tool/version/kind, attempt identity, bounded raw reference, timestamps, and output closure before the atomic publication.

No caller or adapter selects a work status independently. The publisher derives and verifies the exact ToolRunResult/attempt/work triple from the closed mapping, then validates catalog equality, configuration refs, tool/version/kind, attempt identity, bounded raw reference, timestamps, rule combinations, gaps/errors, and output closure before committing it.

- [ ] **Step 1: Write RED external ordering, profile closure, and authority tests.** Record calls and assert `exact profile resolve/approve/executable digest -> reserve -> ALLOW with checked profile -> claim -> durable mark_dispatched -> cold factory invocation -> adapter/process -> receipt -> mark_returned -> measured ledger commit -> raw/rule/result publication -> transition commit`. Test exact equality of request/work/action/decision profile refs and action tool name. For absent/duplicate/stale/wrong-hash profile refs, DRAFT/RETIRED/PRODUCTION-in-T08, missing approval, unknown/duplicate adapter, executable-key/path/digest/version mismatch, name/kind mismatch, and lower observation mismatch, assert zero cold-factory and process calls and no fallback lookup. A malicious lower adapter attempts to supply record IDs, metadata, stored refs, a different attempt, absolute paths, or `SUCCEEDED` with missing telemetry; reject it before publication. For DENY, stale action/input/attempt/profile, exhausted budget, unclaimed decision, reservation mismatch, or `mark_dispatched` failure, assert both counters remain zero.
- [ ] **Step 2: Write RED receipt and lifecycle recovery tests.** Inject crashes after claim, after dispatch before spawn, after process exit before receipt rename, after receipt rename, after returned marker, after ledger commit, after raw artifact staging, and between candidate staging/transition commit. Prepared/undispatched resumes only when exact inputs remain valid. An exact receipt recovered while work is still RUNNING and before the BLOCKED CAS performs no second process call and converges accounting/publication. An absent/torn/mismatched receipt after dispatch must become `work=BLOCKED + waiting_for=(INPUT,) + stop_reason=RECOVERY_FAILED + attempt=CANCELLED`, with zero new calls, zero `ToolRunResult`, zero rule record, and zero fan-in eligibility. Race exact-receipt discovery against BLOCKED commit: receipt-before-BLOCKED may close the old attempt; BLOCKED-before-receipt makes that receipt permanently stale/quarantined, with no return marker, attachment, or old-attempt publication. Explicit reconciliation must prove retry safety, authorize `BLOCKED -> READY`, and create a new attempt; assert only the new attempt can execute/publish and the work cannot become terminal until its canonical result commits. Separately issue ordinary caller cancellation at the same apparent timing and assert it publishes exactly one SKIPPED/PARTIAL result and exact RULE_BASED record as applicable, proving the two paths cannot be conflated. Replace the observation with a symlink/reparse point, absolute/path-escaping name, unknown field, secret-bearing diagnostic, wrong hash/size, or cap+1 bytes and assert no decode/publication/reinvocation. Assert no partial rule record becomes current and exactly one result/ledger/transition is committed after the valid pre-BLOCKED or new-attempt closure.
- [ ] **Step 3: Write RED closed status-mapping tests.** Parameterize every ordinary terminal mapping row above, including exit 0 complete, exit 0 with gaps, nonzero with/without complete earlier batch, timeout with/without earlier batch, malformed/oversized output, preflight not applicable, caller cancellation before claim, after claim before spawn, during the first process before usable output, after one complete OpenGrep batch, after a complete observation before publication, and the cancellation/publication race in both atomic orders. Every ordinary terminal row asserts exactly one `ToolRunResult` plus exact presence/absence of `StaticActionReceipt` and `RuleExecutionRecord`, exact `WorkAttempt`, `WorkExecutionState`, stop reason, gap/error, raw-ref, and output-ref values. Add a separate ambiguous-outcome row that asserts nonterminal `BLOCKED + waiting_for=INPUT + stop_reason=RECOVERY_FAILED`, bookkeeping-CANCELLED old attempt, no result/rule record/fan-in, late-receipt quarantine, and no invocation until explicit retry-safe reconciliation creates a new authorized attempt. For each ordinary RULE_BASED caller cancellation, assert one exact same-attempt rule record: pre-execution selected rules are all `NOT_EXECUTED/CANCELLED`; partial cancellation preserves executed hit counts and marks only unfinished selected rules cancelled. Assert SKIPPED cancellation has no raw ref, PARTIAL cancellation has a complete bounded raw ref, result/rule/work/attempt transition is atomic, no code references nonexistent `WorkStatus.SKIPPED`, timeout never maps to CANCELLED, and caller cancellation never maps to FALSE, HOLD, failure, or zero hits. Crash at each staging/commit boundary and concurrent cancel-vs-publish retries must converge to one result and one terminal transition with no empty-output terminal work state; ambiguous recovery remains blocked until reconciled into a new attempt.
- [ ] **Step 4: Write RED generic public-port conformance tests.** Put three injected fake lower adapters with distinct exact approved fixture/evaluation profile refs and adapter keys behind `StaticToolCoordinator`; do not import the concrete AST, CodeQL, or OpenGrep classes in this Wave 2B test. Assert the exact public `probe(profile_ref) -> ToolCapabilityResult`, `run(request) -> ToolRunResult`, and `cancel(attempt_id)` behavior independent of tool implementation. Probe tests cover exact success, missing executable observation, wrong digest/version, stale/wrong profile ref, unapproved/status mismatch, unknown adapter key, and lower observation executable/name/version mismatch. Run tests assert the request/work/action/decision exact profile closure and that `action.tool_name` selects only the adapter named by that profile, then the trusted publisher—not the lower adapter—returns the canonical result. Retain the T07 fake as a fourth structural implementation. Actual AST/CodeQL/OpenGrep conformance is intentionally deferred to the serial I2 checkpoint after Wave 2A is merged.
- [ ] **Step 5: Run RED.**

```powershell
uv run pytest tests/integration/static_analysis/test_tool_attempt_publication.py tests/integration/recovery/test_static_external_recovery.py tests/contract/test_static_tool_conformance.py tests/contract/domain/test_static.py -q
```

Expected: fail because the coordinator and trusted publisher do not exist.

- [ ] **Step 6: Implement coordinator, application runner, probe bridge, recovery, and publisher using injected public runtime services.** `static_analysis/` may import `StaticExternalExecutionPort` and publisher/profile protocols but not `orchestration/static_external_runner.py`, `orchestration/static_publication.py`, or concrete profile storage. The application runner must use `ExternalCallService`; it must not duplicate claim/dispatch semantics. Tests may compose the concrete pair directly; Task 10 alone adds the private `bootstrap.py` composition. Keep it unselected by the CLI.
- [ ] **Step 7: Run GREEN plus fake regression.**

```powershell
uv run pytest tests/integration/static_analysis/test_tool_attempt_publication.py tests/integration/recovery/test_static_external_recovery.py tests/contract/test_static_tool_conformance.py tests/contract/domain/test_static.py tests/unit/test_fake_adapters.py tests/e2e/test_fake_true_pipeline.py -q
uv run ruff check src/sastsimi/static_analysis/coordinator.py src/sastsimi/orchestration/static_external_runner.py src/sastsimi/orchestration/static_publication.py tests/integration/static_analysis/test_tool_attempt_publication.py tests/integration/recovery/test_static_external_recovery.py tests/contract/test_static_tool_conformance.py
uv run mypy --strict src/sastsimi/static_analysis/coordinator.py src/sastsimi/orchestration/static_external_runner.py src/sastsimi/orchestration/static_publication.py tests/integration/static_analysis/test_tool_attempt_publication.py tests/integration/recovery/test_static_external_recovery.py tests/contract/test_static_tool_conformance.py
```

Expected: pass; fake flow remains unchanged and real profiles remain inactive.

- [ ] **Step 8: Commit.**

```powershell
git add src/sastsimi/static_analysis/coordinator.py src/sastsimi/orchestration/static_external_runner.py src/sastsimi/orchestration/static_publication.py tests/integration/static_analysis/test_tool_attempt_publication.py tests/integration/recovery/test_static_external_recovery.py tests/contract/test_static_tool_conformance.py
git commit -m "feat: publish exact static tool attempts"
```

### Task 8: Deterministically Fan In Static Facts

**Files:**
- Create: `src/sastsimi/static_analysis/normalizer.py`
- Modify: `src/sastsimi/orchestration/static_publication.py`
- Create: `tests/unit/static_analysis/test_normalizer.py`
- Create: `tests/integration/static_analysis/test_static_join.py`

**Interfaces:**
- Consumes: expected tool-work refs, each work's COMMITTED current `ToolRunResult`, optional exact `RuleExecutionRecord`, verified raw artifact, decoder, READY `CodeWorkspace`, current `STATIC_NORMALIZE` work, exact analysis config, and exact catalogs.
- Produces: one pure `StaticFactBundle` candidate followed by one existing `StaticFactBundle` and its COMMITTED output ref through the trusted application-side normalization publisher, or a terminal failed normalization work with no misleading empty bundle when no usable observation exists.

Raw replay uses no new domain schema or frozen shared port. `normalizer.py` defines a non-persisted structural raw-decoder callable that receives verified raw bytes, the exact `ToolRunResult`, exact resolved `StaticToolProfile`, and the exact trusted catalog/config projection captured for that expected work, and returns a closed `StaticToolObservation` without filesystem, process, ID, metadata, storage, or current-pointer authority. The trusted application composition supplies one immutable registry keyed by the full exact profile ref (`record_id + content_hash`) plus `tool_name + tool_version`; name-only, version-only, current-profile, private-method, or in-memory-observation fallback is forbidden. The fan-in service exact-resolves the one profile ref fixed in each expected tool work, verifies the result/profile/tool tuple, reopens and hash-verifies `raw_result_ref`, selects exactly one registered decoder, and verifies that the decoder returns those same raw bytes and tuple before normalization. Missing, duplicate, stale, or mismatched registry entries fail that material without guessing. Concrete AST, CodeQL, and OpenGrep modules own named public pure replay entrypoints; I2 adds only a narrow public wrapper when an accepted Wave 1 adapter currently exposes identical decoding solely through a private method.

Deterministic normalization rules:

- Sort tool materials by `(tool_name, tool_version, attempt_id, result record_id)` and reject duplicate tool attempts.
- Reopen and hash-verify every raw artifact; decode from those bytes rather than trusting an unpersisted object after restart.
- Map candidate paths through `GitPath` and bind every `CodeLocation` to the bundle workspace/commit.
- Create stable `symbol_id`, `fact_id`, and `relation_id` from canonical normalized identity plus source provenance. Exact duplicates collapse; raw hit counts remain unchanged.
- Resolve a candidate fact/relation endpoint to its same-observation symbol first. Otherwise use a cross-tool AST symbol only when there is exactly one narrowest symbol range containing the endpoint in the same file. If none or a tie exists, keep the exact location with `symbol_id=null` and add `STATIC_SYMBOL_UNRESOLVED`; never guess by name alone.
- If two observations claim the same logical identity with different content, retain separately identifiable candidates where the contract permits and add `STATIC_NORMALIZATION_CONFLICT`; never silently choose one claim.
- Partition all facts exactly into SOURCE, SINK, SANITIZER, VALIDATOR, AUTH/PERMISSION, and OTHER lists. Preserve defensive candidates as candidates rather than proof of safety.
- A fact's `ToolSource` points to its exact result attempt, tool version, raw ref, and optional actually executed positive-hit rule. Structure observations always use `rule_id=None`.
- Relations reference only symbols included in the same bundle. Unresolved endpoints produce a gap rather than a dangling ID.
- Preserve relation direction exactly: AST `CALL` is caller -> callee, SARIF `DATA_FLOW` is earlier step -> later step, and AST `ROUTE_BINDING` is route -> handler. Do not turn proximity into reachability. A route can reach a source/sink chain only when the route binding reaches the unique containing handler/source location and ordered `DATA_FLOW` edges continue to the sink.
- Include every expected terminal tool run, including failed/skipped runs, and propagate all tool gaps/errors plus normalization gaps/errors without replacing them.
- The `STATIC_NORMALIZE` work is `SUCCEEDED` only when every expected tool result succeeded and normalization has no known gap/error. It is `PARTIAL` when at least one usable observation exists and any expected scope is missing. If no usable observation exists, fail normalization without publishing a bundle. `StaticFactBundle` itself has no separate status field.
- `normalizer.py` remains pure and imports no concrete runtime or storage module. `StaticNormalizationPublisher` in `orchestration/static_publication.py` alone rechecks the expected-work/current-result closure, authorizes `SAVE_RESULT`, stages the candidate and terminal transition together, and commits exactly one bundle/output ref through the existing transition transaction. A retry returns that exact committed bundle or loses the terminal compare-and-swap; it never publishes a second current bundle.

- [ ] **Step 1: Write RED deterministic and partition tests.** Feed inputs in every ordering and assert identical canonical bundle bytes/hash. Cover all six fact lists, exact duplicate collapse, unique narrowest enclosing-symbol linkage, ambiguous/no-symbol gaps, conflicting candidates, raw hit count preservation, and sanitizer/validator non-verdict semantics. Cover exact-profile raw-decoder registry selection, successful restart replay from verified bytes, and zero decoder calls for an absent/duplicate/stale/mismatched profile/tool/version key; reject a decoder that returns different raw bytes, tool identity, or untrusted stored metadata.
- [ ] **Step 2: Write RED provenance, reachability, and failure tests.** Cover stale attempts, another commit, another workspace, wrong raw hash, wrong tool version, unknown rule, zero-hit rule producing a fact, partial AST plus successful OpenGrep, failed CodeQL plus usable AST, and all tools failed. Add one fixture with AST `ROUTE_BINDING(route -> handler)`, a catalog-declared SOURCE inside that handler, and ordered CodeQL `DATA_FLOW(source -> transform -> sink)`; assert the bundle preserves the exact route-to-source-to-sink evidence chain. Remove the middle flow location and assert `STATIC_DATA_FLOW_UNRESOLVED`, no source-to-sink jump edge, and a PARTIAL normalization work rather than a false reachability claim.
- [ ] **Step 3: Run RED.**

```powershell
uv run pytest tests/unit/static_analysis/test_normalizer.py tests/integration/static_analysis/test_static_join.py -q
```

Expected: fail because normalizer and fan-in service do not exist.

- [ ] **Step 4: Implement pure normalization first, then `StaticNormalizationPublisher` in `orchestration/static_publication.py`.** The normalizer receives only already exact-resolved immutable inputs and the closed decoder registry; it never imports runtime/storage or publishes. The publisher owns exact current-work/result/profile/catalog resolution, `SAVE_RESULT`, IDs/meta, transition compare-and-swap, and current output visibility. Reuse `validate_rule_execution` and `validate_static_current`; do not reproduce or weaken their checks. Use the existing `STATIC_ANALYSIS` result owner and `SAVE_RESULT` path.
- [ ] **Step 5: Run GREEN and focused schema regression.**

```powershell
uv run pytest tests/unit/static_analysis/test_normalizer.py tests/integration/static_analysis/test_static_join.py tests/contract/domain/test_static.py tests/unit/contracts/test_schema_export.py -q
uv run ruff check src/sastsimi/static_analysis/normalizer.py src/sastsimi/orchestration/static_publication.py tests/unit/static_analysis/test_normalizer.py tests/integration/static_analysis/test_static_join.py
uv run mypy --strict src/sastsimi/static_analysis/normalizer.py src/sastsimi/orchestration/static_publication.py tests/unit/static_analysis/test_normalizer.py tests/integration/static_analysis/test_static_join.py
```

Expected: pass and generated schema files remain byte-identical.

- [ ] **Step 6: Commit.**

```powershell
git add src/sastsimi/static_analysis/normalizer.py src/sastsimi/orchestration/static_publication.py tests/unit/static_analysis/test_normalizer.py tests/integration/static_analysis/test_static_join.py
git commit -m "feat: normalize deterministic static fact bundles"
```

### Task 9: Return Bounded Same-Commit Code Context

**Files:**
- Create: `src/sastsimi/static_analysis/context_retrieval.py`
- Modify: `src/sastsimi/verification/context_service.py`
- Create: `src/sastsimi/storage/context_lineage.py`
- Modify: `src/sastsimi/storage/context_binding.py`
- Modify: `src/sastsimi/storage/context_policy.py`
- Modify: `src/sastsimi/storage/action_validator.py`
- Create: `tests/unit/static_analysis/test_context_retrieval.py`
- Create: `tests/integration/static_analysis/test_context_retrieval.py`
- Create: `tests/integration/static_analysis/test_chained_child_context.py`
- Modify: `tests/integration/storage/test_context_publication.py`
- Create: `tests/integration/recovery/test_context_external_recovery.py`
- Extend: `tests/security_negative/test_code_path_escape.py`

**Interfaces:**
- Consumes: non-persisted `ContextRetrievalIntent`, current `CONTEXT_RETRIEVAL` work/attempt with exact proposal/bundle/workspace/ceiling-profile inputs, READY `CodeWorkspace`, exact current `StaticFactBundle`, `WorkspaceLocatorPort`, `ContextLineageReaderPort`, `ContextLimitPolicyPort`, existing content-addressed `ArtifactStore`, public `WorkflowRunner`/action authorization services, exact budget binding/work limit, clock/ID ports, and a trusted request-count/fingerprint ledger.
- Produces: canonical pre-read `ContextReadPlan` and exact plan artifact ref, an exactly authorized/claimed `READ_CODE` action, exact `CodeContextRequest`, verified fragment artifacts, a durable same-attempt `StaticActionReceipt(operation_kind=CONTEXT_READ)`, measured usage accounting, bounded `CodeContextResponse`, gaps/errors, and one atomically COMMITTED context work output.

The new ports return records/configuration but do not make semantic decisions:

```python
@dataclass(frozen=True)
class ContextRetrievalIntent:
    proposal_ref: StoredDataRef
    bundle_ref: StoredDataRef
    requested_entities: tuple[CodeSymbol, ...]
    requested_locations: tuple[CodeLocation, ...]
    relation_query: tuple[
        Literal[
            "CALLERS", "CALLEES", "DATA_FLOW_NEIGHBORS", "AUTH_GUARDS", "ROUTE_BINDINGS"
        ],
        ...,
    ]
    reason: str
    requested_limits: ContextRetrievalLimits

@dataclass(frozen=True)
class ContextCeilingProfile:
    # `ref` points to canonical JSON in the existing content-addressed
    # artifact store; ref.content_hash is the immutable profile hash.
    ref: StoredDataRef
    limits: ContextRetrievalLimits

@dataclass(frozen=True)
class ChainingContextRecords:
    proposal_ref: StoredDataRef
    proposal: HypothesisProposal
    chaining_result_ref: StoredDataRef
    chaining_result: ChainingResult
    upstream_ref: StoredDataRef
    upstream: Primitive
    downstream_ref: StoredDataRef
    downstream: Primitive

@dataclass(frozen=True)
class ContextReadPlan:
    intent_hash: str
    workspace_id: str
    commit_id: str
    proposal_ref: StoredDataRef
    bundle_ref: StoredDataRef
    ceiling_profile_ref: StoredDataRef
    requested_limits: ContextRetrievalLimits
    entities: tuple[CodeSymbol, ...]
    locations: tuple[CodeLocation, ...]
    relations: tuple[CodeRelation, ...]
    file_paths: tuple[str, ...]
    lineage_refs: tuple[StoredDataRef, ...]

class ContextLineageReaderPort(Protocol):
    def read_for(
        self, proposal_ref: StoredDataRef, source_primitive_match_id: str
    ) -> ChainingContextRecords: ...

class ContextLimitPolicyPort(Protocol):
    def ceilings_for(self, work: WorkExecutionState) -> ContextCeilingProfile: ...
```

The ceiling profile uses no new domain schema. It is canonical JSON with exactly `kind="context_ceiling_profile"`, `schema_version="1.0"`, and the five existing `ContextRetrievalLimits` integer fields, stored through the existing content-addressed artifact port. Its exact ref has `data_kind="artifact"`, `record_id=null`, and `stored_data_id == content_hash == sha256(canonical bytes)` in the same workspace/commit; it is not a record revision and must never be passed to `require_record_ref`. The trusted run setup fixes that exact artifact ref once in `CONTEXT_RETRIEVAL.work.input_refs`; name-only lookup and mutable in-memory defaults are forbidden. `ContextLimitPolicyPort` exact-resolves it with `ArtifactStore.open_verified`, verifies the closed JSON shape, and returns the frozen projection above. For `CONTEXT_READ`, the same exact profile's `max_bytes` is also the caller-invariant hard cap on the serialized `CodeContextResponse` recovery candidate; exceeding it fails closed without decoding or publication, so no sixth ceiling field or mutable process-local cap is introduced.

The request-count/fingerprint ledger is a durable derived view over existing published records and content-addressed artifacts; Task 9 adds no table, domain schema, migration, or mutable in-memory counter. `context_policy.py` counts distinct published `CodeContextRequest.code_request_id` values whose exact origin decision/action/dispatch belongs to the same `analysis_id + hypothesis_id`, across all attempts and generations. A claimed dispatch that has not yet bound a request has no `code_request_id` and is recovered through the claim path below rather than guessed into the count. Its normalized fingerprint is `sha256(canonical bytes)` of the versioned tuple `("context_request_v1", analysis_id, hypothesis_id, workspace_id, commit_id, intent_hash, proposal_ref, bundle_ref, ceiling_profile_ref, requested_limits, entities, locations, relation_query, file_paths, lineage_refs)` from the exact canonical plan. Reuse is permitted only after exact resolution of the prior claimed request, its plan artifact, returned/accounted dispatch, COMMITTED response and fragment artifacts, and equality of every tuple member with the current inputs; otherwise the new claimed request consumes one slot. A retry or new generation cannot reset the derived count.

`storage/context_lineage.py` only exact-resolves the requested records and proves that each returned ref hashes to the returned record and is COMMITTED/current where the canonical input rule requires it. It does not choose start locations. `ContextRetrievalService` performs the following Chaining-origin validation before planning a read:

1. The exact `HypothesisProposal` is present once in current `CONTEXT_RETRIEVAL.work.input_refs`, shares analysis/workspace/commit/hypothesis scope, has `origin=CHAINING`, and its non-null `source_primitive_match_id` equals the requested match.
2. Exactly one exact COMMITTED `ChainingResult` contains that ID and the proposal derived from it; the `PrimitiveMatchCandidate.workspace_id + commit_id` and parent hypothesis set match the proposal.
3. `upstream_result_ref` and `downstream_input_ref` exact-resolve to the two returned Primitive records in the same workspace/commit. Their source hypothesis IDs and source Verification refs are set-equal to the match parent fields. The upstream has a result, and `matched_input_id` names exactly one downstream input.
4. Recover start entities from upstream `result.entity_refs`, all upstream `inputs[].entity_refs`, the matched downstream input, and all remaining downstream inputs. Deduplicate by canonical value and take their locations. Any direct proposal entity/location/path must be a subset of this lineage. Broken refs, stale hashes, a different commit, a missing matched input, or zero valid start locations fails the Context work before filesystem access; it is never delegated to T13 or converted to a verdict.

T13 is limited to producing `Primitive`, `PrimitiveMatchCandidate` inside `ChainingResult`, and Chaining-origin proposals. T08 imports no concrete T13 service and performs no new match or Primitive creation.

Retrieval and authorization algorithm:

1. Accept `ContextRetrievalIntent`, not a pre-authorized `CodeContextRequest`. Exact-resolve the current RUNNING `CONTEXT_RETRIEVAL` work/attempt, proposal, current COMMITTED bundle, READY workspace, WorkBudget limit, and the one ceiling-profile artifact ref already fixed in `work.input_refs`. Verify shared analysis/workspace/commit/hypothesis scope and hash-check the profile bytes.
2. Validate every requested limit is less than or equal to the exact profile ceiling and that `timeout_ms` is also within the active WorkBudget timeout. Reject an increase instead of clamping. Check cumulative distinct-request/fingerprint accounting. Canonicalize the intent and calculate `intent_hash`.
3. Build seeds from exact requested entities/locations and, for a Chaining-origin proposal, the provenance-validated starts. Traverse only the requested mappings below with no file opens. Compute every explicit/entity/lineage/fact/relation-expanded path and create a deterministic `ContextReadPlan` containing the exact proposal, bundle, ceiling profile ref, requested limits, entities, locations, relations, paths, lineage refs, and intent hash. The plan contains no self-referential hash field.
4. Serialize the entire plan as closed canonical JSON, set `plan_hash=sha256(canonical plan bytes)` outside the DTO, and reject it before staging if its byte length exceeds the already validated `requested_limits.max_bytes`. Store those exact bytes through the existing content-addressed artifact port and obtain exact `plan_ref`; require `plan_ref.data_kind == "artifact"`, `plan_ref.record_id is null`, and `str(plan_ref.stored_data_id) == plan_ref.content_hash == plan_hash`. Create a new `ActionRequest(action_type=READ_CODE)` whose current work/version and code-scoped metadata carry the exact workspace/commit, `file_paths` is set-equal to `plan.file_paths`, and `input_refs` contains the proposal, bundle, all code-scoped lineage refs, `ceiling_profile.ref`, and `plan_ref` exactly once. The run-scoped `CodeWorkspace` ref is verified through current `AnalysisRunState.workspace_ref` rather than illegally inserted into a code-scoped action. The Runtime Validator exact-resolves both artifacts with `ArtifactStore.open_verified`, verifies their hashes and that both are the exact refs already fixed in the work/plan/action closure, and leaves `ceiling_profile.ref` out of `ActionDecision.checked_config_refs` because `record_id=null` artifacts fail that record-only field's existing validator. `checked_config_refs` contains only the already required record-backed budget/configuration refs. Reserve the exact approved READ_CODE budget, authorize, and claim this exact action; a denied/stale decision releases an undispatched reservation and causes zero file opens.
5. Only after the ALLOW decision and reservation are durably claimed, let the trusted `ContextBindingService` create the persisted `CodeContextRequest` from the unchanged intent/plan and exact claimed decision ref. Before `mark_dispatched`, exact-resolve every action input, recompute the lineage/graph plan from current records, reserialize it, and require byte/hash equality with `plan_ref`, equality with the persisted request, exact `file_paths`, and exact ceiling-profile ref/hash. A mismatch expires/rejects the action, releases the still-undispatched reservation, and reports `CONTEXT_PLAN_CHANGED` or `CONTEXT_PROFILE_CHANGED` with zero reads; do not silently replan under the old authorization. After `mark_dispatched`, create one `MonotonicActionDeadline` from the authorized request timeout, repeat the exact non-filesystem input/plan comparison, and pass that same deadline to workspace integrity Git checks and every file read.
6. Sort authorized locations by Git path/start/end position, coalesce overlapping line ranges for the same file, and stop before exceeding the already validated `max_fragments` or `max_bytes`.
7. Before each open, validate the Git path, ensure it remains a tracked regular file, reject Git symlink/submodule/LFS/sensitive paths, and verify the resolved handle is under the workspace root. Open without following links where the OS supports it and recheck file identity after open.
8. Read UTF-8 with explicit replacement reporting. Line bounds are inclusive; provided columns are 1-based Unicode code points with start inclusive/end exclusive. Do not invent missing columns.
9. Store each exact returned fragment as a content-addressed code-scoped artifact and retain only its ref in the response.
10. Enforce the authorized request's one shared monotonic deadline; every integrity subprocess and read receives only its remaining time, and expiry prevents the next open. On a runtime size/time limit add `CONTEXT_TRUNCATED`, set `truncated=True`, and report actual count/bytes. A request above the trusted ceiling is rejected before dispatch and is not reported as ordinary truncation. On read failure add both `AnalysisError(stage=CONTEXT)` and the affected `DataGap(stage=CONTEXT)`.
11. Verify workspace integrity after reads. On change, discard fragment refs from this execution and fail with `WORKSPACE_CHANGED`; never publish stale code.
12. Build the exact `CodeContextResponse` candidate in memory and write its closed canonical bytes to a guarded bounded regular attempt-owned file. For `CONTEXT_READ`, `StaticActionReceipt.input_fingerprint` is the SHA-256 of the versioned canonical tuple `("context_read_v1", action_ref, action.work_ref, attempt_id, claimed_decision_ref, request_ref, plan_ref, ceiling_profile_ref, proposal_ref, bundle_ref, lineage_refs, sorted file_paths)`; the exact request ref already binds limits and requested entities/locations/queries. The response candidate contains the exact fragment refs plus `returned_fragment_count` and `returned_bytes`, and `observation_size + observation_sha256` binds those closed bytes. Recovery and publication must reject candidate canonical bytes above the exact ceiling profile's `max_bytes` before decoding, `open_verified` every fragment, require its scope/hash, and require the count and summed fragment bytes to match the candidate and stay within the same limit. Atomically rename the one `StaticActionReceipt(operation_kind=CONTEXT_READ)` binding that input fingerprint, ordered integrity-process receipt hashes, response candidate size/hash, and measured monotonic elapsed time. No new receipt field or schema is added. At this point the candidate is recovery evidence only: do not stage, publish, return, cache, or expose it as a positive response.
13. Only after the complete receipt is durable, call `mark_returned` for the READ_CODE dispatch and idempotently commit the exact measured elapsed units against its reservation. Timeout, cancellation, and bounded partial reads follow the same returned/accounted closure before any response is eligible for publication; an ambiguous dispatched operation with no complete receipt remains blocked and publishes no response.
14. Create and claim a separate exact `SAVE_RESULT` action owned by `CONTEXT_RETRIEVAL_SERVICE`. Its input closure contains the returned READ_CODE decision, exact request, plan/profile artifacts, receipt, and verified fragment refs. In one existing transition transaction, revalidate `returned_at`, committed measured accounting, same attempt/scope/hashes, and response closure; then stage/publish the `CodeContextResponse`, complete the attempt/work, and commit its output refs. Return the response only after `TransitionCommit=COMMITTED`. There is no positive or negative `CodeContextResponse`, current pointer, or reusable cache entry before this step.

Recovery is closed and idempotent at every boundary. Before claim, no persisted `CodeContextRequest` exists: recovery resolves the same exact still-valid action, intent, canonical plan/profile artifacts, reservation, and work version without reading code; an expired or semantically changed input requires a new action rather than reuse. After claim and before dispatch, bind or exact-resolve exactly one request through `ContextBindingService`, then require the unchanged action/plan/profile/request closure. A claimed but undispatched action may resume only after that exact closure still validates. `DISPATCHED` without a complete valid `CONTEXT_READ` receipt is an ambiguous external outcome: transition to the existing blocked/uncertain-dispatch path, do not reread automatically, and publish no response. `DISPATCHED` with an exact complete receipt skips every file/process read and proceeds once through `mark_returned`. `RETURNED` with a reserved ledger commits the receipt's measured use once. Accounted-but-unpublished work reconstructs the candidate only from the verified receipt/file and fragment artifacts, then performs one `SAVE_RESULT`; PREPARED/COMMITTED transition recovery uses the existing transition journal. A torn, stale, oversized, symlinked, wrong-attempt, wrong-plan/profile/request, or hash-mismatched receipt/candidate is never decoded or published and never triggers an automatic reread. Concurrent recovery and live completion use the existing unique action/dispatch, idempotent accounting key, one SAVE_RESULT decision, and transition CAS so exactly one response becomes current.

Relation and fact selection is exact and deterministic:

- `CALLERS`: for each seed, select existing `CALL` relations whose `to_symbol_id` equals the seed symbol, or whose `to_location` exactly equals a location-only seed; traverse in reverse to the `from` endpoint. Return the original relation orientation unchanged.
- `CALLEES`: select existing `CALL` relations whose `from_symbol_id`/`from_location` matches the seed and traverse forward to `to`.
- `DATA_FLOW_NEIGHBORS`: select existing `DATA_FLOW` relations incident to the seed and traverse both upstream and downstream, preserving each stored earlier-step -> later-step direction. At reached nodes select exact `SOURCE`, `SINK`, `SANITIZER`, `VALIDATOR`, and `OTHER` fact locations/symbols; do not include AUTH/PERMISSION facts through this query and do not infer an edge from proximity.
- `AUTH_GUARDS`: select exact `AUTH_CHECK` and `PERMISSION_CHECK` facts whose symbol equals a seed or whose location is contained by the seed callable range. Also follow an outgoing `CALL` only when its target symbol/range contains one of those guard facts. Include the guard entity/location and that existing CALL relation; never label an arbitrary callee as a guard or synthesize a new relation.
- `ROUTE_BINDINGS`: select existing `ROUTE_BINDING` relations incident to the seed and traverse either direction so route -> handler and handler -> route lookups work, while returning the stored route -> handler orientation.

The seed set is conceptual depth 0, but the persisted `ContextRetrievalLimits.max_depth` remains the existing `PositiveInt` and therefore has a minimum of 1. `max_depth=N` permits at most N stored-relation traversals after the seeds. A seed-only request uses an empty `relation_query`; it does not encode `max_depth=0`. Every query returns entities/locations/relations in canonical sorted order. Because `CodeContextResponse` has no fact field, fact selection contributes its exact entity/location and the bundle remains the provenance source; no competing fact schema is created.

`max_requests_per_hypothesis` uses the derived durable view above to count distinct claimed `code_request_id` values across generations for that hypothesis. A repeated normalized fingerprint may return the exact previously committed response only when request scope, limits, action authorization, plan/profile/lineage hashes, fragment hashes, and current workspace/commit all match. Otherwise it consumes a request slot and executes normally; it never silently widens the limits or relies on process memory.

- [ ] **Step 1: Write RED relation semantics tests.** Build one bundle containing caller/callee calls, ordered data flow, route binding, direct and called auth/permission facts, unrelated facts, cycles, and ambiguous location-only endpoints. Assert each of the five relation queries follows only the mapping/direction above, preserves stored direction, obeys depth, selects only the declared fact kinds, and returns deterministic deduplicated results.
- [ ] **Step 2: Write RED Chaining-origin provenance tests.** Cover a valid empty-target child and assert the service recovers all specified parent Primitive entity locations. Negatives cover missing/wrong `source_primitive_match_id`, non-COMMITTED or duplicate match, proposal not fixed in work input, parent set mismatch, wrong upstream/downstream refs, wrong workspace/commit/hash, missing upstream result, missing/duplicate matched input, direct target outside lineage, and no start entity. Assert zero code opens and no call into a T13 service.
- [ ] **Step 3: Write RED two-phase authorization and complete-path tests.** Assert the complete order `intent -> pure expand -> canonical plan/hash -> artifact -> exact READ_CODE action -> reserve -> ALLOW/claim -> persisted request -> recompute -> mark_dispatched -> reads -> durable CONTEXT_READ receipt -> mark_returned -> measured accounting -> exact SAVE_RESULT -> COMMITTED response`. Prove pre-claim recovery uses action+intent+plan/profile with no request, and post-claim/pre-dispatch recovery binds or exact-resolves one request without opening code. Cover a location-only request, entity-only request, lineage-only start, caller expansion, data-flow expansion, auth fact/callee, and route binding. Omit each expanded path or required ref from the action, inject one unrelated extra path, alter a relation/entity/lineage input or plan byte between authorization and execution, and substitute another plan artifact with a different hash; assert `CONTEXT_PATH_MISMATCH` or `CONTEXT_PLAN_CHANGED` before any open. Also reject another analysis/hypothesis/attempt, unclaimed/unused decision, and non-current bundle. Assert no response/current pointer/cache value is visible before return, accounting, and the SAVE_RESULT transaction all close.
- [ ] **Step 4: Write RED immutable trusted-ceiling and derived-ledger tests.** Use lower/equal limits as valid. Raise each of `max_depth`, `max_fragments`, `max_bytes`, `max_requests_per_hypothesis`, and `timeout_ms` above the exact profile one at a time; assert pre-dispatch rejection. Also assert WorkBudget timeout is the tighter ceiling, repeated/new request accounting cannot reset on retry/generation, and caller limits never replace the profile. Derive the exact cross-generation count from published requests and their origin closures, prove a claimed-but-not-yet-bound dispatch is recovered rather than invented as an ID, and test exact fingerprint reuse versus one-at-a-time changes to every tuple member. Reject missing/duplicate ceiling artifact refs in work/action, a ceiling ref missing from either `work.input_refs` or `ActionRequest.input_refs`, changed profile bytes, ref/hash mismatch, wrong JSON kind/version/field, a different profile ref with higher limits, and replay with a substitute profile; all cause zero reads. Assert the valid `record_id=null` ceiling artifact is absent from `ActionDecision.checked_config_refs`, while required record-backed budget/config refs remain present and valid.
- [ ] **Step 5: Write RED Context closure and crash-recovery tests.** In `test_context_external_recovery.py`, inject a crash before claim, after claim before request bind, after request bind before dispatch, after dispatch before receipt, after complete receipt before `mark_returned`, after return before accounting, after accounting before SAVE_RESULT, at transition PREPARED, and immediately after COMMITTED. Assert the closed recovery mapping above, zero rereads for every post-receipt case, blocked/no response for ambiguous dispatch, idempotent measured accounting, one SAVE_RESULT decision, one current response, and no early response/cache exposure. Assert the receipt's exact versioned input tuple, canonical observation size/hash, fragment refs/count/summed bytes, and guarded cap; change or omit each action/work/attempt/decision/request/plan/profile/proposal/bundle/lineage/path/fragment component independently and require no decode, reread, accounting from untrusted bytes, or publication. Race recovery against live completion and assert exactly one transition wins.
- [ ] **Step 6: Write RED bounded/filesystem tests.** Cover depth, fragments, bytes, timeout, cyclic graph, overlapping ranges, empty results, invalid line/column ranges, deterministic ordering, `..`, absolute/drive/mixed paths, Git symlink, filesystem symlink/junction, post-validation replacement, LFS pointer, sensitive path, HEAD move, tracked-file edit, and fragment hash verification.
- [ ] **Step 7: Run RED.**

```powershell
uv run pytest tests/unit/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_chained_child_context.py tests/integration/storage/test_context_publication.py tests/integration/recovery/test_context_external_recovery.py tests/security_negative/test_code_path_escape.py -q
```

Expected: fail because real context retrieval does not exist.

- [ ] **Step 8: Implement planning, execution closure, recovery, and publication as separate layers.** The pure planner receives contracts/resolved lineage and returns canonical `ContextReadPlan`; the storage adapter only exact-resolves records/artifacts and derives the request-count/fingerprint view from the existing request/action/plan/response closure. The trusted application handler stores the plan, reserves budget, builds/authorizes/claims the exact action, and only then asks `ContextBindingService` to create or exact-resolve the one request before dispatch. The reader receives only the recomputed authorized plan plus guarded workspace. Extend `ContextBindingService`, READ_CODE validator checks, and response policy to require entity/explicit/expanded paths, exact plan/ceiling artifacts in work/action inputs, record-only `checked_config_refs`, and the same authorization closure. Encode and validate the versioned Context fingerprint and receipt tuples exactly as specified; bind fragment refs/count/bytes through the bounded canonical response candidate and existing receipt hash rather than extending the frozen receipt DTO. Add durable receipt validation, returned-dispatch recovery, measured accounting, and SAVE_RESULT publication without giving `static_analysis` concrete runtime/storage imports. No file API is reachable from intent/planning, and no response is reachable from a public return/current pointer before closure.
- [ ] **Step 9: Run GREEN plus existing context/fake regressions.**

```powershell
uv run pytest tests/unit/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_chained_child_context.py tests/integration/storage/test_context_publication.py tests/integration/recovery/test_context_external_recovery.py tests/security_negative/test_code_path_escape.py tests/e2e/test_fake_true_pipeline.py -q
uv run ruff check src/sastsimi/static_analysis/context_retrieval.py src/sastsimi/verification/context_service.py src/sastsimi/storage/context_lineage.py src/sastsimi/storage/context_binding.py src/sastsimi/storage/context_policy.py src/sastsimi/storage/action_validator.py tests/unit/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_chained_child_context.py tests/integration/storage/test_context_publication.py tests/integration/recovery/test_context_external_recovery.py tests/security_negative/test_code_path_escape.py
uv run mypy --strict src/sastsimi/static_analysis/context_retrieval.py src/sastsimi/verification/context_service.py src/sastsimi/storage/context_lineage.py src/sastsimi/storage/context_binding.py src/sastsimi/storage/context_policy.py src/sastsimi/storage/action_validator.py tests/unit/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_chained_child_context.py tests/integration/storage/test_context_publication.py tests/integration/recovery/test_context_external_recovery.py tests/security_negative/test_code_path_escape.py
```

Expected: pass; fake context remains compatible and no new context schema or state is introduced.

- [ ] **Step 10: Commit.**

```powershell
git add src/sastsimi/static_analysis/context_retrieval.py src/sastsimi/verification/context_service.py src/sastsimi/storage/context_lineage.py src/sastsimi/storage/context_binding.py src/sastsimi/storage/context_policy.py src/sastsimi/storage/action_validator.py tests/unit/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_context_retrieval.py tests/integration/static_analysis/test_chained_child_context.py tests/integration/storage/test_context_publication.py tests/integration/recovery/test_context_external_recovery.py tests/security_negative/test_code_path_escape.py
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
- Modify after the tested candidate only: `docs/superpowers/plans/implementation/08-static-fact-layer.md`, appending the observed evidence in a separate documentation-only commit.

**Interfaces:**
- Consumes: local fixture Git repository, fake CodeQL/OpenGrep executables with real process behavior, real AST worker, current runtime services, and the private real-static composition factory.
- Produces: exact PREPARING -> READY workspace lifecycle, three conforming public tool adapters and terminal tool results, rule records for both rule-based tools, one COMMITTED bundle with real route/data-flow reachability, one bounded ordinary context response, and one provenance-recovered Chaining-child context response, while the public CLI still selects only the fake pipeline.

- [ ] **Step 1: Write the RED vertical integration test.** Prepare a two-commit local repository containing one route handler, source, transform, sink, sanitizer/validator candidate, and auth check. Canonicalize its source before PREPARING and allocate it through an enforceable attempt-owned fixture quota lease; prove exact quota artifact/work/action binding and AnalysisRunState binding. Probe all three tools through the public port using the actual adapter conformance assembled at I2 and exact approved fixture/evaluation `StaticToolProfile` revisions; run AST, fake-executable CodeQL SARIF with an ordered codeFlow, and multi-batch fake OpenGrep JSON through `StaticExternalRunner`; normalize them; plan/authorize/recompute ordinary bounded Context and an empty-target Chaining-child Context. Assert one shared deadline per action, exact dispatch/receipt/accounting order, exact commit, profile/executable closure, status and cancellation mappings, raw/rule refs, all fact partitions, route -> handler/source -> transform -> sink evidence, recovered parent Primitive starts, relation directions, exact quota/context/profile refs and hashes in work/action inputs, correct record-backed-only decision config refs, authorized actual paths, gap/error closure, deterministic bundle hash, Context receipt/return/account/SAVE_RESULT ordering, and Context artifact hashes.
- [ ] **Step 2: Add integration-negative cases.** Supply query/userinfo credentials; an unenforceable/substituted workspace policy; insufficient reserve; giant Git pack, checkout tree/blob, and file-count inputs; stale/unapproved/wrong-digest static profiles; mutate HEAD during one tool; cancel before spawn and after one usable OpenGrep batch; expire between Git or OpenGrep subprocesses; exceed CodeQL attempt/read caps; omit rule telemetry; break a required SARIF flow step; crash at each static and Context external receipt/return/account/publication boundary; substitute a stale parent Primitive/match or Context ceiling profile; alter a plan after authorization; omit a relation-expanded file; and request limits above the trusted ceiling while other tools return usable evidence. Assert secrets are absent from every sink; quota/profile closure failures spawn nothing or terminate/clean the exact lease without READY; no later subprocess/batch starts after deadline/cancel; every ordinary caller-cancellation closure has exactly one SKIPPED-or-PARTIAL result and exact rule record where rule-based, while an ambiguous external outcome uses canonical `BLOCKED + waiting_for=INPUT + stop_reason=RECOVERY_FAILED` with a bookkeeping-CANCELLED old attempt, no result/fan-in, permanent quarantine of late old receipts, and a new result-producing attempt only after explicit retry-safe reconciliation; oversized/truncated SARIF is never parsed; ambiguous dispatch never reinvokes; exact status mapping holds; unresolved flow has no jump edge; bad lineage/plan/profile/path authorization performs zero reads; no Context response/current pointer/cache value appears before returned+accounted+SAVE_RESULT closure; normalization is partial only with exact usable evidence; and no vulnerability verdict is created anywhere in this package.
- [ ] **Step 3: Run the focused integration candidate.**

```powershell
uv run pytest tests/integration/static_analysis tests/integration/recovery/test_static_workspace_recovery.py tests/integration/recovery/test_static_external_recovery.py tests/integration/recovery/test_context_external_recovery.py tests/unit/static_analysis tests/security_negative/test_code_path_escape.py tests/contract/domain/test_static.py tests/contract/test_static_tool_conformance.py tests/contract/test_static_tool_real_adapter_conformance.py tests/contract/test_architecture_imports.py tests/unit/test_fake_adapters.py tests/e2e/test_fake_true_pipeline.py -q
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

Expected: all commands pass; generated schemas and canonical architecture documents are unchanged. Do not append observed full-suite evidence yet because no immutable tested candidate SHA exists until the next step.

- [ ] **Step 6: Commit and freeze the implementation candidate before the full suite.** Stage every production/test integration file and no evidence edit. Commit, require a clean worktree, and record the full 40-character output of `git rev-parse HEAD` as `TESTED_CANDIDATE_SHA`. That SHA—not the later evidence commit—is the test subject.

```powershell
git add src/sastsimi/bootstrap.py src/sastsimi/static_analysis/__init__.py tests/integration/static_analysis/conftest.py tests/integration/static_analysis/test_real_static_slice.py tests/contract/test_architecture_imports.py tests/unit/test_fake_adapters.py
git commit -m "feat: complete real static fact layer"
git status --short
git rev-parse HEAD
```

Expected: the commit succeeds, `git status --short` is empty, and the recorded SHA identifies the exact immutable implementation candidate.

- [ ] **Step 7: Run the one and only final complete test suite on the frozen SHA.** Immediately before running, require `git rev-parse HEAD` to equal `TESTED_CANDIDATE_SHA` and the worktree to be clean. Run this command exactly once. Do not edit, amend, rebase, merge, or commit between the SHA check and test completion.

```powershell
$t08TestedCandidateSha = git rev-parse HEAD
Write-Output $t08TestedCandidateSha
git status --short
uv run pytest tests -q
```

Expected: the first output equals `TESTED_CANDIDATE_SHA`, status is empty, and every test passes. Capture the exact command, exit code, test count, duration, OS, Python version, base SHA, and tested candidate SHA outside Git until the evidence step. A failure blocks this candidate. Any implementation/test/configuration fix creates a new candidate commit and SHA; only that new SHA receives the next single full-suite run.

- [ ] **Step 8: Append and commit evidence without changing the tested candidate.** Add an `## Implementation Evidence` appendix to this file with exact lines for `Tested candidate SHA`, `Full-suite command`, `Exit code`, `Test count`, `Duration`, `OS`, `Python`, `Base SHA`, and `Evidence commit full-suite tested: no`. Use the captured 40-character SHA value, not the variable name or a placeholder; the last line explicitly states that the evidence commit itself was not the full-suite test subject. Do not edit any production file, test, dependency or lock file, generated schema, runtime configuration, CI workflow, or other document. Before commit, require the working diff name set to equal this one plan path and run only the report-format, architecture-document, link, and diff checks below—do not rerun pytest.

```powershell
$t08TestedCandidateSha = git rev-parse HEAD
git diff --name-only
$t08Evidence = Get-Content -LiteralPath docs/superpowers/plans/implementation/08-static-fact-layer.md -Raw
if ($t08Evidence -notmatch [regex]::Escape("Tested candidate SHA: $t08TestedCandidateSha")) { exit 1 }
$t08RequiredEvidence = @('(?m)^## Implementation Evidence$', '(?m)^Full-suite command: uv run pytest tests -q$', '(?m)^Exit code: 0$', '(?m)^Test count: .+$', '(?m)^Duration: .+$', '(?m)^OS: .+$', '(?m)^Python: .+$', '(?m)^Base SHA: [0-9a-f]{40}$', '(?m)^Evidence commit full-suite tested: no$')
foreach ($t08Pattern in $t08RequiredEvidence) { if ($t08Evidence -notmatch $t08Pattern) { exit 1 } }
powershell -NoProfile -File scripts/validate-architecture-docs.ps1
powershell -NoProfile -File scripts/audit-doc-inventory.ps1 -RepositoryRoot . -CheckLinks
git diff --check
git add docs/superpowers/plans/implementation/08-static-fact-layer.md
git commit -m "docs: record T08 implementation evidence"
```

Expected: before staging, `git diff --name-only` contains exactly `docs/superpowers/plans/implementation/08-static-fact-layer.md`; the report check finds every required evidence field; document/link/diff checks pass; and the commit contains only that file. After the evidence commit, rerun the same report-format, document, link, and commit-range diff checks—still no pytest. If the recorded tested-candidate-to-HEAD name set contains any path other than this plan, the evidence-only invariant failed: do not claim the old full-suite result for HEAD. Commit/fix a new implementation candidate as needed, run the full suite once on its new SHA, and replace the evidence with a new evidence-only commit.

```powershell
$t08TestedCandidateSha = git rev-parse HEAD^
$t08Evidence = Get-Content -LiteralPath docs/superpowers/plans/implementation/08-static-fact-layer.md -Raw
if ($t08Evidence -notmatch [regex]::Escape("Tested candidate SHA: $t08TestedCandidateSha")) { exit 1 }
$t08RequiredEvidence = @('(?m)^## Implementation Evidence$', '(?m)^Full-suite command: uv run pytest tests -q$', '(?m)^Exit code: 0$', '(?m)^Test count: .+$', '(?m)^Duration: .+$', '(?m)^OS: .+$', '(?m)^Python: .+$', '(?m)^Base SHA: [0-9a-f]{40}$', '(?m)^Evidence commit full-suite tested: no$')
foreach ($t08Pattern in $t08RequiredEvidence) { if ($t08Evidence -notmatch $t08Pattern) { exit 1 } }
powershell -NoProfile -File scripts/validate-architecture-docs.ps1
powershell -NoProfile -File scripts/audit-doc-inventory.ps1 -RepositoryRoot . -CheckLinks
git diff --check HEAD^..HEAD
git diff --name-only HEAD^..HEAD
```

- [ ] **Step 9: Inspect the candidate/evidence pair before review.**

```powershell
git status --short
git log --oneline b3b2d9918ea815b9b936c09c98e4c53fd54937dc..HEAD
git diff --stat b3b2d9918ea815b9b936c09c98e4c53fd54937dc..HEAD
git diff --check b3b2d9918ea815b9b936c09c98e4c53fd54937dc..HEAD
git diff --name-only HEAD^..HEAD
```

Expected: clean worktree; only T08 files/intent in the base range; no whitespace errors; the final command shows exactly the evidence plan; and review can distinguish the tested implementation SHA from the later evidence-only commit SHA.

---

## Acceptance Criteria

- A repository ref is cloned into a newly allocated workspace directory, resolved once to an exact commit, checked out detached, and published READY only after exact HEAD confirmation.
- The clone root comes only from an exact attempt-owned `WorkspaceStoragePort` lease whose immutable pre-clone policy is a `RunStoredDataRef` bound to the current `analysis_id` with exact artifact kind/hash and `record_id=null`; it fixes maximum Git bytes, checkout bytes, checkout file count, and minimum free reserve. A code-scoped `StoredDataRef`, wrong-analysis/hash/type policy, unenforceable backend, insufficient reserve, giant pack/tree/blob, or file-count overflow fails closed before or during Git, terminates later work, and cleans or seals/quarantines only the exact lease; it can never publish READY.
- Repository userinfo/query/fragment input is rejected before persistence and argv construction; only one normalized, secret-free canonical source can reach workspace records, actions, Git, receipts, diagnostics, or logs.
- The workspace is first published as PREPARING and ends as an append-only READY or FAILED revision; current workspace, work/attempt/transition outputs, and `AnalysisRunState.workspace_ref` converge atomically on the same exact revision, including after crash replay.
- Every Git operation uses an allowed, budget-reserved, durably claimed `RUN_TOOL` action owned by `REPOSITORY_LOADER`; denied, stale, or ambiguous dispatch cannot execute or silently repeat it.
- Every multi-process action has one shared monotonic deadline; Git subcommands and OpenGrep batches consume its remaining time, and timeout/cancel prevents later starts.
- Unsafe repository URLs, destination escapes, Git symlinks, filesystem symlinks/junctions, submodules, LFS pointers, path traversal, drive paths, and tracked-file/HEAD mutation cannot become code evidence.
- AST, CodeQL, and OpenGrep have real version probes, timeout, cancellation, bounded output, safe argv/environment handling, and no shell execution.
- Windows execution is suspended until kill-on-close Job assignment succeeds; POSIX uses `asyncio.create_subprocess_exec`, and both paths have process-tree and launch-order tests.
- The public `StaticToolAdapter` probe/run/cancel contract is implemented by AST, CodeQL, and OpenGrep through the explicit lower-observation bridge. The exact record-backed `StaticToolProfile` ref is identical in work/action/request (and the authorized decision's checked record refs), and exact approved fixture/evaluation status, adapter/tool/kind, executable key/digest, and version are checked before spawn. `.probe(profile_ref)` returns the non-persisted checked `ToolCapabilityResult`; absent/stale/mismatched refs fail closed without fallback, and production activation remains exclusively T16.
- Python AST parsing never imports or executes analyzed code; its bounded straight-line def/use extractor emits only conservative intra-callable DATA_FLOW and records every declared ambiguity instead of joining or bridging it.
- CodeQL never builds/autobuilds or executes repository build commands on the host; only an exact trusted prebuilt database is analyzed.
- CodeQL SARIF and its attempt directory obey separate exact trusted total-directory, output-file, and read caps; cap+1, replaced, partial, or truncated content is never parsed or stored as usable raw evidence.
- OpenGrep scans only the validated explicit file manifest and trusted exact rule configuration.
- Real process adapters return typed candidates and raw bytes only. SASTSIMI IDs, metadata, references, artifact commits, output ownership, and transitions are produced by the trusted application side.
- `StaticExternalRunner` is the only real static external-call path and enforces reserve -> ALLOW -> durable dispatch -> execute -> return -> measured accounting -> publication/recovery; denial, staleness, missing claim, or ambiguous dispatch has zero tool invocations.
- Every ordinary terminal `STATIC_TOOL` work closure has exactly one canonical `ToolRunResult`, including caller cancellation before trusted execution and cancellation-won races. Cancellation without usable output publishes SKIPPED plus a required gap; cancellation after complete usable output publishes PARTIAL plus its exact raw ref and gap, while attempt/work remain CANCELLED. Every ordinary RULE_BASED caller cancellation has the exact same-attempt `RuleExecutionRecord`, with selected unexecuted rules marked `NOT_EXECUTED/CANCELLED`; result/rule/attempt/work/output refs commit atomically. An ambiguous external outcome is distinct and adds no enum: work stays nonterminal `BLOCKED` with `waiting_for=INPUT` and `stop_reason=RECOVERY_FAILED`, its current attempt is bookkeeping-CANCELLED with no result/fan-in, late old receipts are permanently stale, and explicit retry-safe reconciliation must authorize READY plus a new result-producing attempt.
- Process, tool, attempt, and work outcomes follow the closed mapping in Task 7; `WorkStatus.SKIPPED` is never referenced because it does not exist.
- Executed zero-hit rules, unselected rules, selected-but-not-executed rules, unknown telemetry, timeout, cancellation, and failure are distinguishable and cannot be rewritten as one another.
- Static fan-in is deterministic, accepts only expected COMMITTED current attempts, preserves usable partial evidence and all gaps/errors, rejects cross-workspace/commit/attempt/config/catalog inputs, and never interprets missing facts as safety.
- Ordered trustworthy SARIF codeFlows become directed DATA_FLOW relations; a route -> handler/source -> transform -> sink chain is preserved, while missing/unsafe flow steps create DataGap and never a synthetic jump edge.
- All six fact partitions are present and correct, identifiers are deterministic/unique, producer refs are exact, and relations do not dangle.
- Context retrieval turns an untrusted intent into a canonical pre-read plan, authorizes and claims its exact action, then binds the exact request; it stays in the same workspace/commit, rejects caller limits above all five trusted ceilings, authorizes explicit/entity/lineage/relation-expanded paths before any read, returns verified content-addressed fragments, records truncation/failure accurately, and discards output after workspace mutation.
- Context follows intent -> canonical graph/lineage plan artifact -> exact READ_CODE authorization -> recomputation -> read -> durable receipt -> returned dispatch -> measured accounting -> exact SAVE_RESULT -> COMMITTED response. The exact immutable ceiling-profile artifact ref/hash is fixed in work/plan/action inputs and validated there, is excluded from record-only `checked_config_refs`, and cannot be replaced on replay. No response or cache entry is visible before the full closure.
- CALLERS, CALLEES, DATA_FLOW_NEIGHBORS, AUTH_GUARDS, and ROUTE_BINDINGS have tested exact edge direction, fact selection, depth, and deterministic ordering rules.
- For Chaining-origin children, the Context Retrieval Service validates the exact proposal -> match -> parent Primitive provenance and recovers the canonical start locations; T13 is not called and only produces the records.
- T07 fake scenarios and all existing contract meanings continue to pass; the only schema addition is the reviewed `StaticToolProfile`, with no fake-to-real rewrite.
- `static_analysis/` has no concrete runtime/storage import, no adapter-to-adapter dependency, and no dynamic import/process escape.
- No real tool profile is made operationally ACTIVE and no public CLI path selects the real adapters before T16.
- Focused tests, Ruff format/lint, strict mypy, schema/static contract checks, architecture/doc checks, and `git diff --check` are green before candidate freeze; exactly one final full pytest run is green at the recorded immutable implementation candidate SHA; and the later evidence-only SHA passes only its report-format, document, link, and diff checks.

## Explicit Scope Exclusions

- No LLM Provider, prompt, Hypothesis, Verification, dynamic reproduction, CWE, Gate, Finding, Reporter, Chaining, or evaluation behavior is added or changed.
- No domain schema other than the load-bearing `StaticToolProfile`, and no existing enum, result-owner mapping, action type, work type, budget rule, or migration is changed merely to simplify adapter implementation.
- No real production Provider/tool/Docker profile is approved or activated; T08 may register only approved fixture/evaluation static-tool profiles, while T16 owns capability evidence, production approval, and `ACTIVE` registry activation.
- No CodeQL database construction, repository build, dependency installation, package-manager invocation, generated-code build, submodule initialization, or Git LFS fetch occurs on the host in T08.
- No remote network test is required. Integration tests use isolated local Git and fake executables while exercising the real process, parsing, storage, and transition boundaries.
- No automatic language coverage claim beyond the implemented Python AST worker and exact installed rule-based tools. Unsupported languages and missing tool capability remain explicit gaps.
- No new Primitive, match, Chaining proposal, or T13 runtime behavior is added. T08 only exact-resolves existing Chaining records through a read-only port and owns their required provenance validation/start-location recovery before code reads.
- No Web UI, external queue, multi-host scheduler, external disclosure, or snapshot module is introduced.

## Self-Review Checklist

- [ ] Map every Task 8 requirement in the master plan to at least one RED test and one acceptance criterion above.
- [ ] Confirm no step asks an adapter to create metadata, IDs, stored references, work status, or database state.
- [ ] Confirm `StaticToolProfile` is the only new persisted object, its generated schema/codec/inventory/typed registry are exact with no unrelated drift, and all other new DTOs are explicitly non-persisted.
- [ ] Confirm every static probe/run resolves the exact request/work/action/profile revision and trusted approval; executable digest/version and closed adapter tuple are checked before spawn; T08 accepts fixture/evaluation profiles only and T16 alone activates production profiles.
- [ ] Confirm `StaticToolAdapter` and T07 fake signatures remain backward-compatible.
- [ ] Confirm PREPARING -> READY/FAILED workspace revisions, Git RUN_TOOL authority/budget, and all named crash checkpoints have focused tests.
- [ ] Confirm the pre-clone quota artifact is an exact current-analysis `RunStoredDataRef` rather than impossible code-scoped `StoredDataRef`; workspace allocation has no plain-directory fallback, all four quota/reserve limits are hard-enforced before clone, giant pack/tree/file-count cases stop and clean/quarantine safely, and recovery cannot substitute a higher policy or another lease.
- [ ] Confirm repository userinfo/query/fragment secrets are rejected before every persistence, argv, receipt, diagnostic, and log sink.
- [ ] Confirm Windows create-suspended -> Job assign -> resume ordering and POSIX asyncio process-group behavior have focused tests.
- [ ] Confirm Git subcommands and OpenGrep batches share one monotonic deadline and cancellation prevents the next process.
- [ ] Confirm CodeQL attempt directory, SARIF file, and bounded read caps reject complete and race/replacement overflow cases without truncated parsing.
- [ ] Confirm a real route/data-flow path exists and unresolved SARIF flow cannot become reachability.
- [ ] Confirm all five Context relation queries have exact direction/fact/depth semantics and tests.
- [ ] Confirm Chaining-child Context recovery is owned by T08 and T13 remains producer-only.
- [ ] Confirm explicit, entity, lineage, and relation-expanded paths are authorized before reads and caller limits cannot exceed trusted ceilings.
- [ ] Confirm Context plan bytes/hash and the exact ceiling-profile artifact ref/hash are fixed before READ_CODE authorization and recomputed before all reads.
- [ ] Confirm the ceiling artifact stays in exact work/plan/action inputs, never enters record-only `ActionDecision.checked_config_refs`, and substitution fails before reads.
- [ ] Confirm Context crash tests cover claim, dispatch, receipt, return, accounting, SAVE_RESULT, and transition boundaries with no reread after a complete receipt, no publication for ambiguity, and one current response after replay/races.
- [ ] Confirm `StaticExternalRunner` owns the exact external-call/account/publish sequence and all ambiguous recovery paths have zero reinvocation.
- [ ] Confirm every ProcessResult/tool/attempt/work outcome maps to one declared row without a nonexistent work status.
- [ ] Confirm every ordinary terminal STATIC_TOOL work closure—including all caller-cancellation races—atomically publishes exactly one ToolRunResult; RULE_BASED caller cancellation always publishes its exact RuleExecutionRecord, and usable partial cancellation retains only complete raw evidence. Confirm ambiguous external outcomes add no enum and use `BLOCKED + waiting_for=INPUT + stop_reason=RECOVERY_FAILED`, quarantine every late old-attempt receipt, publish no old-attempt result/fan-in, and permit only an explicitly authorized new attempt after retry-safety reconciliation.
- [ ] Confirm Wave 2B tests only the generic public/lower bridge with fake adapters, and the serial I2 checkpoint tests actual AST, CodeQL, and OpenGrep conformance only after Wave 2A is merged; T07 fake compatibility remains covered without production activation.
- [ ] Confirm CodeQL command policy has no host build/autobuild escape.
- [ ] Confirm path checks cover both lexical traversal and resolved symlink/junction/Git-mode escape.
- [ ] Confirm every failure path distinguishes missing evidence from executed zero-hit evidence.
- [ ] Confirm the foundation freezes all shared contracts/ports/process authority before Wave 1 and every parallel lane diff stays inside its explicit source/test allowlist.
- [ ] Confirm Wave 1 and Wave 2 start from their recorded full SHAs, only reviewed commits are cherry-picked, and the integration agent alone resolves conflicts or edits final shared composition.
- [ ] Confirm Task 10 Step 6 commits the candidate, only Step 7 runs the complete pytest suite, and Step 8 changes only the evidence plan and never reruns pytest.
- [ ] Confirm no placeholder text, unresolved type name, mismatched function signature, or unowned output remains.
