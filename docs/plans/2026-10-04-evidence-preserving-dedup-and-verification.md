# Evidence-preserving Deduplication and Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Review each proven static alert once, display one report for each proven verified root cause, and prevent final verification from losing its exact hypothesis and pinned source.

**Architecture:** Static normalization uses a versioned exact-evidence identity for new scopes while legacy scopes retain their persisted candidate IDs. A family-specific pinned-source resolver extends the existing read-only verified Finding projection; unknowns remain separate. A shared, bounded hypothesis/source anchor is prepended to downstream verification prompts, and only affected stale Final checkpoints are re-evaluated.

**Tech Stack:** Python 3.12, SQLite checkpoint store, Pydantic, pytest, Ruff, mypy.

**Spec:** `docs/decisions/2026-10-04-evidence-preserving-dedup-and-verification-design.md`

## Global Constraints

- Preserve raw tool results, original Finding/PoC/report artifacts, stable IDs, and user analysis data; do not rewrite existing scopes.
- A different input, path, branch, affected resource, sink, or security control is not an automatic duplicate.
- No fuzzy grouping and no automatic TRUE verdict from a validated PoC alone.
- Required hypothesis, pinned source, Gate feedback, and current PoC evidence may not be silently truncated.
- An ambiguous static or verified Finding match remains independently reviewable.
- The whole analysis remains PARTIAL when product-code static coverage is unverified; dedup never upgrades scope or reportability.

## Review Focus

1. Same CWE and sink line but distinct request parameters: two candidate reviews and two Finding cards.
2. Same CodeQL alert with two trace threads: distinct paths survive normalization.
3. Legacy interrupted scope with decisions: candidate IDs, counts, and resume unchanged.
4. Oversized optional prompt context: required proposal/source/PoC still present or explicit failure.
5. Existing GNU stored-XSS HOLD: re-evaluation uses saved PoC and can remain HOLD if substantive evidence is still insufficient.

---

### Task 1: Exact static candidate identity with legacy resume

**Files:** `src/sastsimi/simple_runtime/candidates.py`, `src/sastsimi/simple_runtime/application.py`, `src/sastsimi/simple_runtime/store.py` if necessary; `tests/unit/simple_runtime/test_candidates.py`, `tests/unit/simple_runtime/test_candidate_pipeline.py`.

**Interfaces:** `normalize_candidate_page(..., identity_version: str = "legacy") -> tuple[StaticCandidate, ...]`; `ingest_static_candidates(..., identity_version: str = "legacy") -> int`. New analysis scopes select `exact-v2`; persisted legacy scopes retain `legacy`. No database migration is permitted solely for this change.

- [ ] Add failing tests: identical normalized OpenGrep/Semgrep alerts yield one candidate with both origins; distinct match, source key, trace thread, branch or sink argument yield distinct IDs; verified file/rule proof remains required.
- [ ] Add failing resume test: saved legacy candidate decisions keep their IDs and are not re-reviewed after upgrade; an interrupted new scope continues with `exact-v2`.
- [ ] Implement a versioned fingerprint over complete normalized evidence, excluding only scanner provenance and scan bookkeeping; preserve all origin `(engine, rule_id, artifact_ref, result_index)` entries in atomic upsert.
- [ ] Run focused candidate and resume tests, Ruff on changed files, then commit this task.

### Task 2: Required hypothesis and pinned source through final verification

**Files:** `src/sastsimi/simple_runtime/stages.py`, `src/sastsimi/simple_runtime/artifacts.py` if needed, `src/sastsimi/simple_runtime/models.py`; `tests/unit/simple_runtime/test_gate_context_priority.py`, `tests/unit/simple_runtime/test_candidate_pipeline.py`.

**Interfaces:** A shared helper returns validated `(proposal_ref, focused_source_ref)` for one child checkpoint. Initial, PoC interpretation, Final, and Technical Gate prepend these refs before optional history. Final stage version changes only after a regression test proves legacy HOLD resume behavior.

- [ ] Add a failing test with Pro/Con `requested_paths=[]`, saved exact proposal, pinned source context, and oversized optional prior output: captured Final and Gate prompts include the exact proposal, cited source, current PoC result, and Gate revision feedback.
- [ ] Add failing tests for wrong analysis/hypothesis/commit, corrupt CAS, missing cited source, and prompt overflow; require a named context failure, not silent truncation or FALSE.
- [ ] Add failing resume test: stale Final HOLD is selected, saved Pro/Con and validated PoC stay complete, and no verdict is pre-upgraded.
- [ ] Implement the bounded, line-numbered source projection and strict priority/size behavior; change only the necessary stage version and downstream invalidation.
- [ ] Run focused gate/resume tests and commit this task.

### Task 3: Verified root-cause certificates for common Python families

**Files:** `src/sastsimi/simple_runtime/finding_flow.py` or a focused sibling resolver module, `src/sastsimi/simple_runtime/finding_group_projection.py`, `src/sastsimi/simple_runtime/finding_groups.py`; `tests/unit/simple_runtime/test_finding_flow.py`, `tests/simple_runtime/test_finding_group_projection.py`.

**Interfaces:** `resolve_root_cause_anchor(...) -> RootCauseAnchor | None` takes the same pinned source, proposal, CWE, and optional trace inputs as the existing command resolver; a non-`None` result certifies exact entry/input/path/operation/sink/control equivalence. The versioned group key hashes this certificate plus analysis/workspace/commit.

- [ ] Add failing positives for duplicate SQL injection, reflected/stored XSS, SSRF, code evaluation, and supported file/path operations from independent engines or hypotheses.
- [ ] Add failing negatives for differing input keys, source/sink paths, branches, sink arguments, resources, sanitizer/guard state, CWE family, source hash, and unsupported constructs. Unknowns remain singleton.
- [ ] Implement small family resolvers with shared pinned-source guard and no LLM duplicate vote; retain existing CWE-78 behavior.
- [ ] Verify original Finding/PoC/report refs remain unchanged and replay saved Antony/GNU data read-only; commit this task.

### Task 4: Canonical reader/export view without destroying originals

**Files:** `src/sastsimi/dashboard/query.py`, `src/sastsimi/dashboard/static/app.js`, `src/sastsimi/interfaces/cli/public.py`, existing report ZIP composition/query path; related dashboard/CLI tests.

**Interfaces:** Default report list/export uses the proven group representative once; a group's members and their original direct links remain accessible. `finding_count` stays raw and `finding_group_count` stays distinct from proven-unique count.

- [ ] Add failing tests for one representative in list/ZIP with all member links, separate unknowns, mixed member scope, and direct access to every original report and PoC.
- [ ] Implement the read-only projection in public list/export; never delete or rewrite historic bundles.
- [ ] Run focused dashboard/CLI/export tests and commit this task.

### Task 5: Integration, documentation, and final verification

**Files:** `README.md`, `docs/architecture/gates-chaining-reporting.md`, decision/spec/plan files, targeted integration tests.

- [ ] Run focused candidate, gate, grouping, dashboard, and resume tests; record read-only saved-fixture raw/group counts and whether GNU stored-XSS replay produces a report only after TRUE and Technical Gate ACCEPT.
- [ ] Run full pytest suite under a writable temporary directory, Ruff, and mypy; distinguish pre-existing environment/baseline failures.
- [ ] Request independent code review, fix material findings, and document residual undetermined duplicate classes and missed-vulnerability limits.
- [ ] Update README and architecture docs with raw vs canonical counts, proof/abstain rules, exact resume behavior, and validated outcomes; commit.
