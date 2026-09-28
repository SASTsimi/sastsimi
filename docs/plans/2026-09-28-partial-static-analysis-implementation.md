# Partial Static Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce trustworthy partial Dify and other repository analyses without presenting unverified static work as complete.

**Architecture:** Keep existing OpenGrep, Semgrep, AST, and CodeQL evidence collection. Publish a validated partial static bundle after a bounded pass, filter Agent-visible candidates to proven file/rule pairs, persist exact limitations, and compute a terminal PARTIAL state only after downstream Agents finish. Resume reuses identical evidence and completed Agent inputs, then retries gaps.

**Tech Stack:** Python 3.12, Pydantic, SQLite checkpoint store, pytest, vanilla-JS dashboard.

**Spec:** `docs/plans/2026-09-28-partial-static-analysis-design.md`

## Global Constraints

- Preserve all existing user edits, analyses, attempt artifacts, and PR work; never reset the worktree or erase the Dify v4/v5 trials.
- Scope identity is the pinned commit plus selected product scope plus exact rules/tools; completed proof from another identity is not reusable.
- A timeout, parser warning, or unsupported product path is never evidence of a negative scan.
- Raw incomplete hits stay auditable but never enter Agent candidate facts.
- A trusted partial static result may end PARTIAL only after all required Agents finish; checkout/integrity/Agent failures retain BLOCKED or FAILED.
- Keep the existing unlimited cumulative analysis budget. Any short first-pass scan budget is independent and configurable.
- Report bundles remain bounded; full gap lists live in the hash-checked coverage artifact, with paginated dashboard access.

## Review Focus

- A partial OpenGrep hit on an unverified pair must be absent from Agent input even when another engine later verifies that pair with no hit (Task 1).
- A raw artifact with a wrong hash or a changed scope fingerprint must not be reused or converted to PARTIAL (Tasks 1–2).
- An Agent failure must outrank a partial static disposition in both API and dashboard (Task 2).
- Resume after a changed static bundle must not silently reuse an Agent result for different inputs or duplicate a completed job (Task 3).
- A large gap ledger and an extensionless unsupported path must remain inspectable without overflowing a report bundle (Task 4).

---

### Task 1: Exact static evidence and a bounded pass

**Files:** Modify `src/sastsimi/simple_runtime/static_coverage.py`, `bootstrap_stages.py`, `application.py` (result model only), `src/sastsimi/config/user_config.py`; tests in `tests/unit/simple_runtime/test_static_coverage.py`, `test_bootstrap_process.py`, `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`.

**Interfaces:** Define and produce `StaticBootstrapResult.static_coverage_ref` and `static_disposition: Literal["FULL", "PARTIAL"]` in Task 1; Task 2 consumes them. Add `unsupported_files` path/reason rows to coverage JSON. A pass uses a configurable `static_scan_pass_seconds` without changing cumulative `max_elapsed_seconds`.

- [ ] Write tests for verified-only merged hits, partial parser output, timeout, fallback success/failure, unsupported paths, finite budget, and corrupt/incomplete artifacts; run each red.
- [ ] Filter merged candidates by their own slice's `verified_pairs`; keep unfiltered raw evidence in CAS.
- [ ] Add exact unsupported path/reason rows and an auditable `not_attempted_budget` gap reason while retaining aggregate counts.
- [ ] Return FULL/PARTIAL after both OpenGrep and Semgrep attempts if a valid bundle has at least one verified pair; keep invalid source, missing proof, candidate-limit and integrity failures BLOCKED.
- [ ] Run focused static tests, Ruff, mypy, and `git diff --check`; inspect outputs.

### Task 2: Runtime PARTIAL status and failure precedence

**Files:** Modify `src/sastsimi/simple_runtime/application.py`, `models.py`, `src/sastsimi/progress/projector.py`, `progress/models.py`, `src/sastsimi/composition/simple_runtime_composition.py`; tests in `tests/simple_runtime/test_simple_analysis_application.py` and progress/composition tests.

**Interfaces:** Persist `SimpleAnalysisRun.static_coverage_ref` and `static_disposition` atomically with the successful static checkpoint. `SimpleAnalysisOutcome.status` and `ProgressSnapshot.status` accept PARTIAL; failure statuses still win.

- [ ] Write and run red tests: fully covered run COMPLETE, validated partial run reaches hypotheses and ends PARTIAL, Agent BLOCKED/FAILED overrides PARTIAL, invalid static evidence stays BLOCKED.
- [ ] Implement the atomic static-result update and status projection without calling an incomplete static scan SUCCEEDED in coverage wording.
- [ ] Keep legacy full runs readable; validate exact coverage identity and hash when resuming.
- [ ] Run focused application/progress tests, Ruff, mypy, and diff check.

### Task 3: Resume only missing proof and genuinely new Agent work

**Files:** Modify `src/sastsimi/simple_runtime/application.py`, `store.py` only if needed, `bootstrap_stages.py` hypothesis append path; tests in `tests/simple_runtime/test_simple_analysis_application.py` and integration resume tests.

**Interfaces:** A PARTIAL resume calls the existing exact-scope scan replay for unresolved pairs; old hypothesis checkpoints keep their original `static_bundle_ref`; new proof may append only new hypothesis jobs. COMPLETE is reconsidered only after coverage is full and any new jobs finish.

- [ ] Write red tests for interruption, same-scope proof reuse, unchanged completed Agent jobs, new static candidate delta, and changed scope rejection.
- [ ] Add explicit partial-static retry path and safe old/new bundle comparison; do not silently substitute a new bundle into old Agent inputs.
- [ ] Deduplicate appended hypotheses using canonical proposal content/evidence identity, preserve old stage inputs, and run only new jobs.
- [ ] Run focused resume tests, Ruff, mypy, and diff check.

### Task 4: Dashboard and bilingual disclosure

**Files:** Modify `src/sastsimi/dashboard/query.py`, `models.py`, `server.py`, `static/app.js`; `src/sastsimi/reporting/bilingual_bundle.py`, `markdown_export.py`, `src/sastsimi/simple_runtime/stages.py`; corresponding dashboard and reporting tests.

**Interfaces:** Existing coverage artifact is the source of truth. Dashboard provides counts/reasons and paginated full gaps/unsupported paths. Both report languages show identical factual coverage fields and a PARTIAL warning; no large ledger is embedded in size-limited bundles.

- [ ] Write red tests for PARTIAL rendering, extensionless unsupported files, pagination, bilingual parity, legacy report compatibility, and confirmed Finding independent of full coverage.
- [ ] Add validated query/read-only pagination and clear UI labels; include coverage digest and reason totals in both report languages and provenance.
- [ ] Run focused dashboard/report tests, Ruff, mypy, and diff check.

### Task 5: Real Dify proof, full regression, and PR

**Files:** Update `README.md`, `docs/usage.md`, troubleshooting/validation notes only after the real result. No production code outside a reproduced blocker.

- [ ] Run a short-budget Dify resume on pinned commit `8387590ace4a094de812b7847fc6a4c3a27cd52b`, check same-scope proof reuse, exact verified/missing counts, hypothesis entry, and final PARTIAL/BLOCKED distinction.
- [ ] If one blocker appears, reproduce it with a failing test, make the smallest fix, and resume; leave any unresolved path/reason ledger intact.
- [ ] Run the complete test suite and static checks, synchronize documentation with observed evidence, review the diff, then push the existing PR branch without including secrets or unrelated scratch files.
