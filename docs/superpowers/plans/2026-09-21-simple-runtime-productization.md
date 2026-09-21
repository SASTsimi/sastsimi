# SimpleRuntime Productization Implementation Plan

> **For implementation:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` task-by-task. Use TDD for each behavior change. Do not run the full suite until Task 9.

**Goal:** Make SimpleRuntime the default user-facing analysis path, restore exact-contract chaining, add one-time setup and simple CLI commands, expose truthful animated progress in CLI/dashboard, support native Windows control, and publish a polished README without removing legacy commands or data.

**Architecture:** Add a local-first application façade in front of existing adapters and contracts. `sastsimi setup` writes a secret-free user configuration and exact host profile. Public commands resolve defaults at the CLI boundary and call a new SimpleRuntime application service. Existing full Runtime and advanced commands remain available. Chaining reuses existing Primitive admission and Chaining contracts through an adapter; it is not reimplemented as ad-hoc JSON. CLI and dashboard share one progress projector over durable checkpoints.

**Tech Stack:** Python 3.12, Pydantic 2, SQLite, platformdirs, argparse, existing Git/OpenGrep/CodeQL/Docker/Codex adapters, stdlib HTTP dashboard, pytest, Ruff, mypy.

**Spec:** `docs/superpowers/specs/2026-09-21-simple-runtime-productization-design.md`

## Global Constraints

- Keep the exact-reference, attempt isolation, redaction, validated PoC, stale-report and error-not-FALSE rules.
- Keep existing full Runtime, `evaluate`, `results`, legacy report commands, explicit `--data-dir` and `--profile` paths.
- Public commands default to SimpleRuntime and user config; legacy explicit commands keep their behavior.
- Do not store API keys, access/refresh tokens, sessions or browser cookies.
- Do not silently skip required OpenGrep or CodeQL in the full profile.
- Do not invent progress. Only committed work units count.
- Dashboard remains loopback-only and read-only.
- Development runs focused normal/failure tests. Full suite and CI run once after all tasks.
- Defer unrelated refactoring and Medium/Low findings.

---

### Task 1: Secret-free user configuration and `sastsimi setup`

**Files:**
- Create: `src/sastsimi/config/user_config.py`
- Create: `src/sastsimi/setup/__init__.py`
- Create: `src/sastsimi/setup/service.py`
- Create: `src/sastsimi/interfaces/cli/setup.py`
- Modify: `src/sastsimi/interfaces/cli/main.py`
- Test: `tests/unit/config/test_user_config.py`
- Test: `tests/unit/interfaces/test_setup_cli.py`

**Contract:**
- `UserConfigStore.load() -> UserConfig`
- `UserConfigStore.save(config) -> Path`
- `SetupService.inspect() -> SetupInspection`
- `SetupService.configure(SetupChoices) -> SetupResult`

- [ ] Write failing tests proving platform-specific config paths, atomic TOML save, environment-variable credential references, and rejection of embedded secret values.
- [ ] Write failing CLI tests for interactive choices and JSON output. Inject input/tool discovery in tests; never call real Docker or Provider.
- [ ] Implement `UserConfig` with `data_dir`, `profile_path`, `auth_mode`, `provider`, `model`, budget/time/token limits, Docker network mode and enabled static tools.
- [ ] Implement executable discovery with `shutil.which`, bounded `--version` calls and safe version projection for Git, Python, OpenGrep, CodeQL, Docker and Codex CLI.
- [ ] Reuse existing capability probe services to create current probe receipts. One explicit setup confirmation may approve the exact detected executable/digest for local use; setup must not fabricate a successful probe.
- [ ] Generate a host-local `local-evaluation.toml` using package resource paths and detected executable paths. Remove repository-worktree and WSL-only hard-coded paths.
- [ ] If required tools or login are absent, save a disabled capability and print the exact next action. Do not mark the setup ready.
- [ ] Add `sastsimi setup [--format json]` while keeping `onboarding` and `capability` commands intact.
- [ ] Run:

```powershell
uv run pytest -q tests/unit/config/test_user_config.py tests/unit/interfaces/test_setup_cli.py -p no:cacheprovider
uv run ruff check src/sastsimi/config/user_config.py src/sastsimi/setup src/sastsimi/interfaces/cli/setup.py tests/unit/config/test_user_config.py tests/unit/interfaces/test_setup_cli.py
```

- [ ] Commit: `feat: add one-time local setup`

### Task 2: Human analysis IDs and truthful shared progress

**Files:**
- Create: `src/sastsimi/reporting/analysis_display_id.py`
- Create: `src/sastsimi/progress/__init__.py`
- Create: `src/sastsimi/progress/models.py`
- Create: `src/sastsimi/progress/projector.py`
- Modify: `src/sastsimi/simple_runtime/store.py`
- Test: `tests/unit/reporting/test_analysis_display_id.py`
- Test: `tests/unit/progress/test_progress_projector.py`

**Contract:**
- `AnalysisDisplayIdStore.get_or_allocate(exact_analysis_id) -> str`
- `AnalysisDisplayIdStore.resolve(display_id) -> str`
- `ProgressProjector.snapshot(analysis_id) -> ProgressSnapshot`

- [ ] Write failing tests for stable `A-001` allocation, analysis separation, concurrent allocation and exact-ID round trip.
- [ ] Write progress tests for running, terminal TRUE, terminal FALSE, BLOCKED, FAILED and a newly registered chaining child.
- [ ] Define progress units from current registered analysis/hypothesis stages. `SUCCEEDED` and projection-only `SKIPPED` count; `RUNNING | BLOCKED | FAILED` do not.
- [ ] Make `COMPLETE` the only state that reports 100%. Store `completed_units`, `known_units`, `percent`, current stage, current hypothesis and denominator-change reason.
- [ ] Add list/query helpers to `SimpleCheckpointStore`; do not expose mutable DB rows.
- [ ] Ensure adding a child hypothesis can increase the denominator and lower the percentage without corrupting prior checkpoints.
- [ ] Run focused tests and Ruff.
- [ ] Commit: `feat: project durable analysis progress`

### Task 3: Public CLI façade and animated progress bar

**Files:**
- Create: `src/sastsimi/interfaces/cli/public.py`
- Create: `src/sastsimi/interfaces/cli/progress.py`
- Modify: `src/sastsimi/interfaces/cli/main.py`
- Modify: `src/sastsimi/interfaces/cli/output.py`
- Modify: `src/sastsimi/interfaces/cli/report.py`
- Modify: `src/sastsimi/interfaces/cli/result.py`
- Test: `tests/unit/interfaces/test_public_simple_cli.py`
- Test: `tests/unit/interfaces/test_progress_cli.py`
- Modify: `tests/unit/interfaces/test_report_cli.py`

- [ ] Write parser tests for the nine approved public commands and legacy equivalents.
- [ ] Make global `--data-dir` and explicit profile override user-config defaults without becoming required.
- [ ] Support new `analyze <repo> --commit`, while `analyze --repo ... --profile ...` remains a legacy explicit path.
- [ ] Make `status` and `resume` resolve `A-###` or exact IDs. If the ID belongs only to the full Runtime, fall back to the legacy query/validation path.
- [ ] Add singular `result` without removing `results`.
- [ ] Add `poc <finding_id>` and new `report <finding_id> [--export markdown]`; keep `report show` and `report export` syntax.
- [ ] Implement a TTY progress renderer that polls `ProgressProjector`, redraws one bar line and shows an activity spinner when the numeric value is unchanged.
- [ ] In non-TTY mode print only stage transitions. `--no-progress` disables polling. `--format json` emits no ANSI or animation.
- [ ] On BLOCKED/FAILED, print the failing stage and `sastsimi resume <A-ID>`.
- [ ] Run focused tests and Ruff.
- [ ] Commit: `feat: add simple public CLI`

### Task 4: Start a new SimpleRuntime analysis from repository input

**Files:**
- Create: `src/sastsimi/simple_runtime/application.py`
- Create: `src/sastsimi/simple_runtime/bootstrap_stages.py`
- Create: `src/sastsimi/composition/simple_runtime_composition.py`
- Modify: `src/sastsimi/simple_runtime/models.py`
- Modify: `src/sastsimi/simple_runtime/runner.py`
- Modify: `src/sastsimi/simple_runtime/store.py`
- Modify: `src/sastsimi/interfaces/cli/public.py`
- Test: `tests/simple_runtime/test_simple_analysis_application.py`
- Test: `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`

**Contract:**
- `SimpleAnalysisApplication.analyze(request) -> SimpleAnalysisOutcome`
- `SimpleAnalysisApplication.resume(analysis_id) -> SimpleAnalysisOutcome`

- [ ] Write a normal test proving repository prepare, `RepositoryProfile`, AST/OpenGrep/CodeQL normalization, `StaticFactBundle`, Hypothesis Agent outputs and hypothesis checkpoints are stored before per-hypothesis execution.
- [ ] Write failure tests proving repository/tool/Provider errors create a visible BLOCKED/FAILED checkpoint and never a vulnerability `FALSE`.
- [ ] Allocate exact analysis/workspace IDs and `A-###` before external tool execution so status/dashboard can show preflight failures.
- [ ] Reuse the existing repository loader, `LocalEvaluationStaticServices`, `StaticNormalizer`, package prompt registry and Provider adapter. Do not use Fake adapters.
- [ ] Build a narrow composition from setup-generated approved capability refs. Do not invoke the distributed worker/lease/dispatch Runtime.
- [ ] Store the analysis-level `STATIC_DONE` and `HYPOTHESIS_DONE` checkpoints and register one hypothesis identity per exact proposal.
- [ ] Process registered hypotheses sequentially through existing `build_stage_handlers()`.
- [ ] Make resume load the same profile/config, preserve success checkpoints and rerun only the first non-reusable stage.
- [ ] Connect public `analyze` and `resume` to this application.
- [ ] Run the two targeted normal/failure tests and Ruff.
- [ ] Commit: `feat: run repository analysis with SimpleRuntime`

### Task 5: Exact Primitive admission and Chaining in SimpleRuntime

**Files:**
- Create: `src/sastsimi/simple_runtime/chaining.py`
- Modify: `src/sastsimi/simple_runtime/models.py`
- Modify: `src/sastsimi/simple_runtime/runner.py`
- Modify: `src/sastsimi/simple_runtime/stages.py`
- Modify: `src/sastsimi/simple_runtime/store.py`
- Test: `tests/simple_runtime/test_simple_chaining.py`
- Test: `tests/integration/chaining/test_simple_runtime_chaining.py`

- [ ] Add `PRIMITIVE_ADMISSION_DONE` and `CHAINING_DONE` to the stage graph and activity role mapping. Increment stage versions only where old checkpoints must be recomputed.
- [ ] Write a normal test where eligible TRUE/HOLD primitives produce a material child, store parent/primitive lineage and enqueue the child once.
- [ ] Write failure tests for cross-analysis refs, cross-attempt refs, denied testing methods, duplicate match identity and depth/count limit.
- [ ] Implement `SimpleChainingAdapter` over existing `PrimitiveAdmissionDecision`, primitive publication, pinned input universe, Chaining Agent and child-registration contracts.
- [ ] Persist the exact considered Primitive list even for `NO_MATERIAL_CHILD`.
- [ ] For a registered child, save parent hypothesis IDs, primitive refs, proposal ref and depth; append it to the durable analysis queue.
- [ ] Run the child from Pro·Con through Verification, PoC, Gates, Primitive/Chaining, Finding and Report. Do not trust inherited verdicts.
- [ ] Preserve current Rule Scope admission behavior: forbidden testing evidence is excluded; other scope outcomes follow the existing admission decision.
- [ ] Run focused chaining tests and Ruff.
- [ ] Commit: `feat: add exact chaining to SimpleRuntime`

### Task 6: Dashboard progress and chaining visualization

**Files:**
- Modify: `src/sastsimi/dashboard/models.py`
- Modify: `src/sastsimi/dashboard/query.py`
- Modify: `src/sastsimi/dashboard/server.py`
- Modify: `src/sastsimi/dashboard/static/index.html`
- Modify: `src/sastsimi/dashboard/static/app.js`
- Modify: `src/sastsimi/dashboard/static/app.css`
- Modify: `src/sastsimi/interfaces/cli/dashboard.py`
- Test: `tests/unit/dashboard/test_query.py`
- Modify: `tests/integration/dashboard/test_server.py`
- Modify: `tests/unit/interfaces/test_dashboard_cli.py`

- [ ] Write projection tests proving CLI and dashboard receive exactly the same `completed_units`, `known_units` and percentage.
- [ ] Add progress and chain fields to the safe public view: display analysis ID, current unit, parent/child hypothesis links, depth, admitted/excluded primitive count and child count.
- [ ] Resolve `A-###` routes to exact IDs before querying while preventing traversal and cross-analysis access.
- [ ] Add an accessible percentage bar with CSS transition, numeric percentage and completed/known counts.
- [ ] Add a chain section showing parent → child relationships and Chaining status. Do not expose code, prompts, secrets or local paths.
- [ ] Keep GET/HEAD-only, loopback-only behavior and 2-second polling.
- [ ] Make `sastsimi dashboard` use the configured data dir by default.
- [ ] Run focused query/server tests and Ruff.
- [ ] Commit: `feat: show progress and chaining in dashboard`

### Task 7: Native Windows portability

**Files:**
- Create: `src/sastsimi/platform/__init__.py`
- Create: `src/sastsimi/platform/tool_discovery.py`
- Create: `src/sastsimi/platform/docker_host.py`
- Modify: `src/sastsimi/config/local_evaluation_profile.py`
- Modify: `src/sastsimi/simple_runtime/container.py`
- Modify: `src/sastsimi/providers/codex_subscription.py`
- Modify: `src/sastsimi/static_analysis/process_windows.py`
- Test: `tests/unit/platform/test_tool_discovery.py`
- Test: `tests/unit/platform/test_docker_host.py`
- Modify: `tests/unit/providers/test_local_evaluation_codex.py`
- Modify: `tests/unit/static_analysis/test_process_windows.py`

- [ ] Write Windows-mode tests for `.exe/.cmd` discovery, paths containing spaces/non-ASCII, Docker Desktop default context and Codex CLI invocation without shell interpolation.
- [ ] Move platform branching behind small adapters. Keep Linux behavior unchanged.
- [ ] Use argument arrays, `pathlib` and configured working directories; remove WSL `/mnt/...` assumptions from generated profiles.
- [ ] Run dynamic PoC inside Linux Docker containers on Windows; never execute POSIX PoC directly in PowerShell.
- [ ] Keep Docker endpoint selection delegated to Docker client defaults unless an explicit safe endpoint is configured.
- [ ] Run focused Windows-mode tests and Ruff/mypy for touched modules.
- [ ] Commit: `feat: support native Windows host control`

### Task 8: README and operator documentation

**Files:**
- Rewrite: `README.md`
- Create: `docs/USER_GUIDE.md`
- Create: `docs/TROUBLESHOOTING.md`
- Modify: `docs/DOCUMENT_GUIDE.md`
- Modify: `docs/superpowers/specs/2026-09-21-korean-reports-agent-dashboard-design.md`
- Test: `tests/contract/test_operator_docs.py`

- [ ] Mark the old WSL-only support statement as superseded by this design; do not delete historical design records.
- [ ] Rewrite the README first screen with project purpose, verified/missing capabilities, Windows/Linux/WSL requirements, one-time install, `setup`, first analysis, status/resume, dashboard, PoC and report commands.
- [ ] Put `uv tool install .` or wheel installation only in the one-time installation section. Runtime examples use plain `sastsimi`.
- [ ] Document API Key environment variables and official subscription CLI login without secret examples.
- [ ] Document full vs lightweight static profiles and state that full requires AST, OpenGrep and CodeQL.
- [ ] Add exact failure guidance for missing setup, Provider auth, capability probe, Docker daemon/build and stale report.
- [ ] Generate CLI help in a test and assert every README command parses.
- [ ] Commit: `docs: publish simple cross-platform usage`

### Task 9: Focused smoke, real E2E, final verification and one PR

**Files:**
- Modify only Blocker/High defects found by this task.
- Record deferred Medium/Low items in the PR body, not as scope expansion.

- [ ] Build a wheel and install it in a clean Windows virtual environment.
- [ ] Run Windows smoke: `sastsimi --help`, `setup` with injected/non-secret test choices, DB initialization, dashboard query and report commands.
- [ ] Run Linux/WSL wheel smoke using the same public commands and config schema.
- [ ] Run one normal and one failure-focused SimpleRuntime test group.
- [ ] Run PyGoat actual E2E with real LLM, AST, OpenGrep, CodeQL and Docker. Verify at least one path reaches validated PoC, both Gates, Finding and Korean `F-###.md`.
- [ ] Verify a failed or blocked hypothesis resumes at the failed stage and does not repeat clone/static/Pro/Con.
- [ ] Verify a chaining child appears in CLI progress and dashboard and undergoes full revalidation.
- [ ] Run final checks once:

```powershell
uv run ruff check src tests
uv run mypy src
uv run pytest -q
```

- [ ] Fix only Blocker/High regressions and rerun the failing check plus the final gate once.
- [ ] Commit verification evidence/doc updates, push `feat/simple-runtime-product`, open one PR, run CI once and attach the PR to the task.
- [ ] Merge only after CI is green and no Blocker/High remains.

## Expected Commit Sequence

1. `docs: define SimpleRuntime productization design` — already `43e9f31`
2. `docs: define durable analysis progress` — already `74257dc`
3. `feat: add one-time local setup`
4. `feat: project durable analysis progress`
5. `feat: add simple public CLI`
6. `feat: run repository analysis with SimpleRuntime`
7. `feat: add exact chaining to SimpleRuntime`
8. `feat: show progress and chaining in dashboard`
9. `feat: support native Windows host control`
10. `docs: publish simple cross-platform usage`
11. Final Blocker/High-only verification commit if required

## Stop Conditions

- Do not claim Windows support until the clean wheel smoke passes.
- Do not claim real analysis completion unless Fake adapters are absent from the selected profile.
- Do not report 100% unless the analysis is terminal `COMPLETE`.
- Do not merge if a failure becomes `FALSE`, an exact reference crosses analysis/attempt boundaries, a non-executed PoC is validated, secrets/host paths are exposed, or the dashboard can mutate state.
