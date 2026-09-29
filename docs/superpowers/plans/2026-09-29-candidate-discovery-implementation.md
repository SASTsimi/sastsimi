# Candidate Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Process every collected static candidate through explicit Discovery and downstream status without truncation or legacy-resume regression.

**Architecture:** Add a versioned, persisted candidate ledger between static bootstrap and the existing Hypothesis pipeline. Consume raw verified artifacts in pages, review bounded candidate batches, then reuse existing per-hypothesis stages. Keep old runs on their old route.

**Tech Stack:** Python 3.12, Pydantic, SQLite, pytest, vanilla dashboard JS.

**Spec:** `docs/superpowers/specs/2026-09-29-candidate-discovery-design.md`

## Global Constraints

- Python product code remains the only static-scan input.
- No fixed total candidate or hypothesis cap; per-call sizes, depth, concurrency, timeout, and retries stay finite.
- Never silently truncate candidate evidence or count unverified file-rule pairs as verified.
- Existing DB rows, artifacts, in-progress runs, and user files are preserved.
- Discovery is triage; only downstream evidence can confirm a Finding.
- Existing runs without the candidate-discovery version use legacy resume semantics.

## Review Focus

- Two different source-to-sink traces sharing endpoints stay separate: Task 1 regression test.
- One oversized candidate is explicitly ERROR while other candidates survive: Task 3 regression test.
- No candidates still permit a terminal non-finding outcome: Task 4 regression test.
- Resume at an unchanged exhausted budget does not submit another LLM request: Task 4 regression test.
- Mixed Python/JS/TS plus excluded tests never report whole-repository COMPLETE: Task 5 regression test.

---

### Task 1: Candidate normalization and durable ledger

**Files:**
- Create: `src/sastsimi/simple_runtime/candidates.py`
- Modify: `src/sastsimi/simple_runtime/store.py`
- Test: `tests/unit/simple_runtime/test_candidates.py`

**Interfaces:**
- Produce `iter_raw_candidate_pages(identity, artifact_ref, after_offset, page_size)` and `normalize_candidate_page(...) -> bounded tuple[StaticCandidate, ...]`, `StaticCandidate(candidate_id, kind, path, line, evidence_ref, origins, flow_identity)`.
- Produce store methods `upsert_candidate_page(identity, scope_fingerprint, artifact_ref, end_offset, candidates)` atomically advancing a durable raw-artifact high-watermark, `list_candidates(identity, status=None, after_id=None, limit=...)`, `save_candidate_decision(identity, candidate_id, decision, reason, evidence_refs, attempt_ref)`, `candidate_counts(identity)`.
- Stable IDs include analysis-independent scope/commit and normalized evidence; scope identity remains a DB key.

- [ ] Write tests for 600 raw hits, duplicate engine provenance, same endpoints/different traces, exact refs, PENDING defaults, and idempotent upsert; derive expected IDs from fixed fixture digests.
- [ ] Run the focused test and confirm missing API/behavior causes RED.
- [ ] Implement normalized candidates and additive SQLite candidate/cursor tables; commit page and cursor atomically, never infer a FLOW without trace evidence, and never materialize all candidates.
- [ ] Run focused tests GREEN and existing static-coverage/store tests.
- [ ] Commit the tested unit.

### Task 2: Complete static candidate ingestion and exclusion evidence

**Files:**
- Modify: `src/sastsimi/simple_runtime/static_coverage.py`, `src/sastsimi/simple_runtime/bootstrap_stages.py`, `src/sastsimi/static_analysis/file_scope.py`
- Test: `tests/unit/simple_runtime/test_opengrep_rule_batches.py`, `tests/unit/static_analysis/test_file_scope.py`

**Interfaces:**
- Produce full candidate source refs in static bundle; preserve exact raw engine artifacts.
- Extend `StaticFileScope` with `excluded_tests: tuple[(path, reason), ...]` and `out_of_scope_sources: tuple[(path, reason), ...]` without changing selected Python paths.

- [ ] Add failing tests proving all 600 results survive candidate ingestion, file-rule counts stay separate, large outputs are not silently clipped, and test/JS/TS paths have reasons.
- [ ] Run tests RED.
- [ ] Ingest raw artifacts before location-only static merge, preserving distinct traces; remove 500-result projections as candidate source and total candidate-count rejection; use bounded pages, explicit resource errors, and scope metadata. AST facts beyond 10,000 must be paged or become an explicit PARTIAL gap.
- [ ] Run focused tests GREEN and existing static-scan/scope tests.
- [ ] Commit the tested unit.

### Task 3: Discovery schema, adaptive batches, and checkpoints

**Files:**
- Create: `src/sastsimi/simple_runtime/discovery.py`
- Modify: `src/sastsimi/simple_runtime/provider.py`, `src/sastsimi/simple_runtime/call_queue.py` for context-limit and budget handling
- Test: `tests/unit/simple_runtime/test_discovery.py`

**Interfaces:**
- Produce `Discovery.run_page(identity, static_ref, after_id, page_size) -> DiscoveryPageOutcome` with exact INCLUDE/EXCLUDE/UNDECIDED/PENDING/ERROR decisions.
- Consume persisted candidate list and `SimpleLLMClient`; persist each completed batch and original responses through existing artifact/call ledgers.

- [ ] Add failing tests for >256 KiB projected inputs, model-dependent payload allowances, exact-ID/schema validation, uncertain results, bounded retries, one oversized item, cancellation, and checkpoint reuse.
- [ ] Run tests RED.
- [ ] Implement byte-safe serialization and adaptive splitting, classify context-limit separately from unsupported-model errors, bounded JSON/schema retry, durable per-candidate decisions, and explicit error/pending distinctions.
- [ ] Run focused tests GREEN and provider/queue tests.
- [ ] Commit the tested unit.

### Task 4: Pipeline, budget pause, and unlimited aggregate hypotheses

**Files:**
- Modify: `src/sastsimi/simple_runtime/application.py`, `src/sastsimi/simple_runtime/models.py`, `src/sastsimi/simple_runtime/store.py`, `src/sastsimi/simple_runtime/bootstrap_stages.py`, `src/sastsimi/composition/simple_runtime_composition.py`
- Test: `tests/unit/simple_runtime/test_candidate_pipeline.py`, existing resume/chaining suites

**Interfaces:**
- New runs carry `candidate_pipeline_version=1`; old runs remain legacy.
- Aggregate outcome adds PAUSED with budget guidance; additive hypothesis rows and candidate↔hypothesis link rows (zero/one/many) replace new-run JSON growth while old `hypothesis_ids` stays readable. A reviewed candidate with no valid hypothesis receives explicit `NO_HYPOTHESIS`.
- Per-batch hypothesis bounds and chaining depth remain; total hypothesis count has no fixed 12/32 ceiling.

- [ ] Add failing tests for INCLUDE/UNDECIDED deep work, EXCLUDE skip, free exploration, 40+ hypotheses, zero candidates, INCONCLUSIVE terminal, budget PAUSED/unchanged resume/raised resume, old-run resume, and no duplicate completed work.
- [ ] Run tests RED.
- [ ] Integrate Discovery with existing stage runner and checkpoint logic, eliminate aggregate caps and one-shot 12/128/256 KiB source prefixes in both free-exploration modes, reserve concurrent token/cost budget before calls, and enforce COMPLETE/PARTIAL/BLOCKED/PAUSED conditions.
- [ ] Run focused tests GREEN and complete simple-runtime regression suites.
- [ ] Commit the tested unit.

### Task 5: Status, dashboard, report, and documentation

**Files:**
- Modify: `src/sastsimi/progress/models.py`, `src/sastsimi/progress/projector.py`, `src/sastsimi/dashboard/models.py`, `src/sastsimi/dashboard/query.py`, `src/sastsimi/dashboard/static/app.js`, `src/sastsimi/interfaces/cli/main.py`, reporting coverage disclosures, `README.md`, `docs/usage.md`, `docs/troubleshooting.md`
- Test: progress/dashboard/CLI/report suites

**Interfaces:**
- Status projection provides separate static pair counts, candidate decision counts, deep counts, hypothesis/Finding counts, excluded tests and out-of-scope product files, and resume action.

- [ ] Add failing tests for exact counts, paging, PAUSED vs BLOCKED, PARTIAL with static/JS/TS gaps, excluded tests, and idempotent resume progress.
- [ ] Run tests RED.
- [ ] Implement compatible status/API/UI/report projections and update docs from verified behavior.
- [ ] Run focused tests GREEN plus JS dashboard tests.
- [ ] Commit the tested unit.

### Task 6: End-to-end and live validation

**Files:**
- Add integration tests in `tests/integration/simple_runtime/` as needed
- Add `docs/validation/2026-09-29-candidate-discovery-trial.md`

- [ ] Add failing integration tests for hundreds of candidates, mixed language, complete/partial/paused/resumed flows, and unchanged legacy data.
- [ ] Run tests RED, implement only missing glue, then GREEN.
- [ ] Run complete pytest, Ruff, mypy, and dashboard tests; record exact output.
- [ ] Run low-cost PyJWT smoke pinned to `a4e1a3d1218b01c5806420b8f16d9308ac4adc30` and Dify pinned to the tested SHA. Record actual candidate/status/static-gap counts; do not equate old GHSA with new confirmed findings.
- [ ] Update validation notes and README if observed behavior differs, rerun affected tests, and commit.
