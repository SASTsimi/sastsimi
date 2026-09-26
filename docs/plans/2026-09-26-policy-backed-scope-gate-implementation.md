# Policy-backed Scope Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make public SimpleRuntime discover attributable GitHub security policies and base Scope Gate decisions on exact policy evidence while preserving `UNCERTAIN` when authorization cannot be established.

**Architecture:** A run-scoped GitHub discovery adapter obtains a bounded policy snapshot during static bootstrap; the run and each new Scope Gate checkpoint retain exact snapshot refs. Scope Gate validates provenance and complete context, requests structured per-axis judgments, then computes the final status deterministically. Reports and dashboard expose the source and reasons without granting external-report permission to old or unverified results.

**Tech Stack:** Python 3.12, Pydantic, SQLite artifact/checkpoint store, stdlib HTTPS transport, pytest, PowerShell.

**Spec:** `docs/plans/2026-09-26-policy-backed-scope-gate-design.md`

## Global Constraints

- Only derive automatic sources from a canonical public GitHub repository and the same owner's inherited `.github` repository; no free-form URL crawling or new `--policy-url`.
- Keep one immutable policy snapshot for the run and never refetch it on `resume`.
- Only exact, complete, verified policy evidence can yield `ALLOW`; missing, ambiguous, failed, oversized, or unverified input yields `UNCERTAIN`.
- Technical verdicts, PoC execution, existing provider behavior, and internal Finding generation remain unchanged.
- No automatic external disclosure; private-reporting availability alone is not a policy pass.
- Keep all tests network-free except a separately bounded, read-only discovery smoke check.

## Review Focus

- A GitHub fork's upstream policy must never be treated as the fork owner's authorization (Task 1 test).
- A confirmed 404 for a policy file differs from rate limit, timeout, or malformed API response (Task 1 test).
- An inherited owner policy is used only when the target repository has no own policy, with GitHub's `.github`, root, `docs` precedence (Task 1 test).
- A policy that would be truncated from the LLM context must never support `ALLOW` (Task 3 test).
- A legacy `ALLOW` artifact with no verified source must never become publicly report-ready on read/export (Task 4 test).

---

### Task 1: GitHub source discovery and immutable snapshot

**Files:** Create `src/sastsimi/simple_runtime/github_policy.py`; modify `src/sastsimi/policy/adapters/official_http.py` only if extracting its reusable pinned-HTTPS guard; create `tests/unit/simple_runtime/test_github_policy.py`; update `tests/unit/simple_runtime/test_security_policy.py` for GitHub precedence.

**Interfaces:** `GitHubPolicyDiscovery.__init__(transport: PolicyHttpTransport, resolver: HostResolver, clock: Clock)` and `async discover(repository_url: str) -> DiscoveredPolicy`; `DiscoveredPolicy` is a frozen value with `status: Literal["FOUND", "ABSENT", "UNVERIFIED", "FETCH_FAILED"]`, `reason_code`, canonical owner/repo, publisher, source URL/path/blob SHA, ETag/content type, checked time, SHA-256, and optional complete UTF-8 body. The adapter calls only `api.github.com` endpoints derived from the validated repository identity, using `PinnedHttpsTransport` and the existing globally-routable IP/peer-IP checks; response size is at most 256 KiB.

- [ ] **Step 1: Write failing tests.** Assert own `.github/SECURITY.md` wins over root/docs; owner `.github` fallback works; fork upstream is not followed; per-file 404 continues search; 403/429/timeout/invalid JSON/oversized/symlink/unexpected redirect become `FETCH_FAILED` or `UNVERIFIED` without policy bytes.
- [ ] **Step 2: Confirm RED.** Run `& .\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_github_policy.py tests/unit/simple_runtime/test_security_policy.py -q`; expect the new interface/precedence tests to fail.
- [ ] **Step 3: Implement the minimal discovery adapter.** Normalize only `https://github.com/{owner}/{repo}` or its `.git` form; verify GitHub repository metadata matches owner/repo; fetch the default-branch contents through documented REST endpoints, decode base64 file bodies, retain the Git blob SHA, then query the same owner's `.github` repo only after confirmed absence. Never use `download_url` or repository-authored links.
- [ ] **Step 4: Confirm GREEN and security regression.** Run `& .\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_github_policy.py tests/unit/simple_runtime/test_security_policy.py tests/security_negative/test_policy_source_boundary.py -q`; expect PASS.
- [ ] **Step 5: Commit Task 1.** Stage only Task 1 files and commit `feat: discover attributable GitHub security policy`.

### Task 2: Bind the snapshot to a SimpleRuntime run and resume

**Files:** Modify `src/sastsimi/simple_runtime/bootstrap_stages.py`, `application.py`, `models.py`, `runner.py`, `store.py`, and `src/sastsimi/composition/simple_runtime_composition.py`; test `tests/simple_runtime/test_simple_analysis_application.py` and `tests/unit/simple_runtime/test_security_policy.py`.

**Interfaces:** `StaticBootstrapResult.policy_snapshot_ref: StoredDataRef | None` and `SimpleAnalysisRun.policy_snapshot_ref: StoredDataRef | None` default to `None` for old JSON. Bootstrap stores body and snapshot as separate exact artifacts and passes the snapshot ref through the existing run save/restore path. For new runs, `SCOPE_GATE_DONE` checkpoint inputs include the snapshot ref in addition to upstream refs; legacy runs retain their existing inputs.

- [ ] **Step 1: Write failing tests.** A new run calls discovery once and saves `FOUND`/`ABSENT`/`FETCH_FAILED` snapshot refs; multiple hypotheses share the same ref; `resume` calls discovery zero additional times; old run JSON without the field loads and remains restricted.
- [ ] **Step 2: Confirm RED.** Run `& .\.venv\Scripts\python.exe -m pytest tests/simple_runtime/test_simple_analysis_application.py tests/unit/simple_runtime/test_security_policy.py -q`; expect the new snapshot assertions to fail.
- [ ] **Step 3: Implement bootstrap and exact input wiring.** Inject a discovery port into static bootstrap; commit the body and snapshot artifacts before saving the run reference; make the runner/store include it only for newly created Scope Gate checkpoints. Do not mutate completed PoC or verification checkpoints and do not call the network on resume.
- [ ] **Step 4: Confirm GREEN.** Run `& .\.venv\Scripts\python.exe -m pytest tests/simple_runtime/test_simple_analysis_application.py tests/unit/simple_runtime/test_security_policy.py -q`; expect PASS.
- [ ] **Step 5: Commit Task 2.** Stage only Task 2 files and commit `feat: pin run policy snapshot across resume`.

### Task 3: Evidence-backed Scope Gate and deterministic status

**Files:** Create `src/sastsimi/simple_runtime/scope_policy.py`; modify `src/sastsimi/simple_runtime/stages.py` and `artifacts.py`; test `tests/unit/simple_runtime/test_rule_scope_gate.py` and a new `tests/unit/simple_runtime/test_scope_policy.py`.

**Interfaces:** `validate_scope_decision(snapshot: dict[str, object], policy_text: str, model_result: dict[str, object]) -> dict[str, object]` returns the canonical gate result. Its five axes are `rules`, `asset_scope`, `impact`, `testing`, and `reporting`; each has `status: PASS|FAIL|UNCERTAIN`, a source line, exact quote, and reason. `SimpleArtifactRepository.prompt_context_strict(refs: tuple[StoredDataRef, ...]) -> bytes` raises before any ref is truncated. Only a verified `FOUND` snapshot for the current run may reach the LLM; the reducer sets `ALLOW` only when all axes pass, `DENY` on an explicitly evidenced failure, otherwise `UNCERTAIN`.

- [ ] **Step 1: Write failing tests.** Cover a fully cited allow, explicit deny, missing axis, forged/incorrect citation, contradictory testing restriction, ABSENT/UNVERIFIED/FETCH_FAILED, unrelated target/snapshot ref, arbitrary published policy-kind artifact, prompt-injection text within a policy, and over-budget context.
- [ ] **Step 2: Confirm RED.** Run `& .\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_scope_policy.py tests/unit/simple_runtime/test_rule_scope_gate.py -q`; expect new assertions to fail.
- [ ] **Step 3: Implement strict context and gate evaluation.** Place policy source bytes before optional evidence, require the whole context, validate source hash/owner/repo/blob and exact checkpoint ref, treat policy Markdown as untrusted data, and have deterministic code compute final status. Remove the `published_refs()`-presence shortcut for granting `ALLOW` in public SimpleRuntime.
- [ ] **Step 4: Confirm GREEN.** Run `& .\.venv\Scripts\python.exe -m pytest tests/unit/simple_runtime/test_scope_policy.py tests/unit/simple_runtime/test_rule_scope_gate.py tests/contract/domain/test_policy_gates.py -q`; expect PASS.
- [ ] **Step 5: Commit Task 3.** Stage only Task 3 files and commit `feat: validate policy-backed scope decisions`.

### Task 4: Safe legacy reads and explanatory report/dashboard output

**Files:** Modify `src/sastsimi/simple_runtime/stages.py`, `src/sastsimi/composition/simple_runtime_composition.py`, `src/sastsimi/dashboard/models.py`, `query.py`, `static/app.js`, and any report/export guard actually used by the public CLI; test `tests/simple_runtime/test_simple_report.py`, `tests/unit/dashboard/test_query.py`, and `tests/integration/dashboard/test_server.py`.

**Interfaces:** The gate artifact includes snapshot source URL/revision, collection status, axis results/citations, final status, and missing-information reasons. Public `report show`/`export` and dashboard projections expose those fields; a result lacking verified provenance is restricted even if a legacy artifact says `ALLOW`. Existing A-005 `UNCERTAIN` report remains readable and unchanged.

- [ ] **Step 1: Write failing tests.** Assert `ALLOW` with citations appears in report/dashboard, `DENY` and `UNCERTAIN` retain reasons, unavailable policy is labeled as unverified rather than explicitly forbidden, and legacy unverified `ALLOW` is not externally report-ready through show/export/dashboard.
- [ ] **Step 2: Confirm RED.** Run `& .\.venv\Scripts\python.exe -m pytest tests/simple_runtime/test_simple_report.py tests/unit/dashboard/test_query.py tests/integration/dashboard/test_server.py -q`; expect new projection assertions to fail.
- [ ] **Step 3: Implement projection and report wording.** Read only exact snapshot/gate refs; preserve old missing fields as `UNCERTAIN` and keep technical verdict text separate. Never present a private-report button as testing permission.
- [ ] **Step 4: Confirm GREEN.** Run `& .\.venv\Scripts\python.exe -m pytest tests/simple_runtime/test_simple_report.py tests/unit/dashboard/test_query.py tests/integration/dashboard/test_server.py -q`; expect PASS.
- [ ] **Step 5: Commit Task 4.** Stage only Task 4 files and commit `feat: show scope evidence and restrict legacy reports`.

### Task 5: Documentation, full regression, and bounded smoke

**Files:** Modify `README.md`, `docs/usage.md`, `docs/architecture/gates-chaining-reporting.md`, `docs/troubleshooting.md`, and `docs/release-follow-ups.md` only where actual behavior changes; add a short validation note under `docs/validation/`.

**Interfaces:** Document public GitHub automatic discovery, non-GitHub fail-closed behavior, policy-source/status display, `resume` pinning, no auto-submission, and why changedetection.io may still be `UNCERTAIN` without a policy.

- [ ] **Step 1: Update docs against implemented CLI/UI and add a focused docs check.** Do not claim arbitrary bug-bounty source discovery or live analysis where none was run.
- [ ] **Step 2: Run project checks.** `& .\.venv\Scripts\python.exe -m pytest -q`; `& .\.venv\Scripts\ruff.exe check .`; `& .\.venv\Scripts\mypy.exe src`; `& powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate-current-docs.ps1`; expect every command to exit 0.
- [ ] **Step 3: Bounded live discovery smoke.** If network access is available, fetch one public GitHub policy without invoking an LLM or full `analyze`; verify source identity/hash and missing-policy behavior. Record whether the smoke ran or was unavailable.
- [ ] **Step 4: Review and commit.** Compare the complete diff with the spec, run `git diff --check`, stage only task files, and commit `docs: explain policy-backed scope review`.
