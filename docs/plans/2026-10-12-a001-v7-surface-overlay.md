# Same-ID v7 Surface Evidence Overlay Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` task by task. Each behavior starts with a failing test.

**Goal:** Re-evaluate every indexed Python attack surface under the same analysis ID after graph semantics change, without altering v6 evidence or promoting unresolved gaps.

**Architecture:** An explicit `--enrich-saved-surface-evidence` resume pins an immutable v7 plan to the exact v6 terminal coverage, v6 plan, graph revision, source scope, prior progress bytes, and missing v6 part set. V7 contexts, results, progress rows, and coverage are distinct. Preflight reconstructs and verifies the plan before any Agent call; completed v7 parts and child jobs are reused. A v5 coverage certificate retains raw gaps and prior evidence, and resolves a prior graph reason only for validated source-bound paths with no other same-sink path or attributable unmaterialized gap left unresolved.

**Tech Stack:** Python 3.12, Pydantic, SQLite, content-addressed JSON artifacts, pytest.

**Spec:** `docs/plans/2026-10-12-live-analysis-proof-recovery-design.md` plus the requested additive v7 overlay for an already completed v6 round.

## Global Constraints

- Keep the analysis ID, commit, scope, v4-v6 plans, old progress, Agent outputs, children, and artifacts unchanged.
- Fail closed on source/commit/scope/ref/content/hash mismatch, changed parent progress, or missing v6 parts.
- A v7 review can be `COVERED` only with connected validated roles and no remaining reasons. A second relevant path or an unmaterialized route gap on the indexed sink/known route remains `INSUFFICIENT`; unrelated raw graph gaps remain provenance. Raw static gaps remain `PARTIAL`.
- Repeated resume cannot repin a different plan or rerun a completed Agent/child job with the same evidence version.
- `COVERED` means a source-bound navigation path was reviewed for that indexed surface. `REQUEST_CONTEXT` marks the request/route boundary; it does not prove parameter taint into the sink, exploitability, or vulnerability absence. A `NO_HYPOTHESIS` response is a reviewed hypothesis decision for the pinned path, not a safety verdict for other paths.
- A saved v6 missing part remains `SURFACE_PART_PENDING` and `PRIOR_V6_PART_MISSING` in v7 coverage; the runtime refuses a first v7 pin until every expected v6 part is present. A-001's ten pending v6 parts must finish first.
- All inherited v4 `COVERED` rows and prior `HYPOTHESES` rows require independent rev4 route review. Existing child hypotheses are surface-bound, not proven equivalent to any new input→sink path: keep their pinned history and current child status, but do not suppress deep review of new paths. A new path may create a separate child; the new v7 context ID and CAS prevent rerunning the same v7 part on resume. Split relevant same-sink paths into separate parts with complete source/edge/node support; an oversized atomic path remains unavailable and `PARTIAL`.
- Do not access the live A-001 database in implementation or tests.

## Review Focus

- Prior v6 progress changes between calculation and pin: transactional CAS rejects it.
- Existing v6 part absent before v7 planning: missing set is pinned and no false completion follows.
- A graph/source revision or content hash changes: saved v7 replay blocks before Agent work.
- A v7 response cites disconnected roles: coverage keeps the prior gap.
- A clean XML route path with unrelated graph gaps may support path-local review, while another same-sink path or unmaterialized gap attributable to the sink/known route blocks positive proof; neither proves `handler.params` data flow.
- An Agent part or child already completed on restart: replay reuses it and does not issue another call.

---

### Task 1: Immutable v7 plan and context

**Files:** Create `surface_enrichment_v7.py` and `test_surface_enrichment_v7.py`.

**Interfaces:** `prepare_surface_enrichment_v7(identity, scope, index, index_ref, v6_plan_ref, v6_plan, prior_v4_ref, prior_v4, prior_progress, graphs, *, required_graph_revision) -> tuple[dict, tuple[V7Part, ...]]`.

- [ ] Write tests for exact successor targets and distinct context IDs, old artifact immutability, source/revision mismatch, progress/missing-set binding, and 64 KiB whole-item chunking.
- [ ] Run the new tests and observe expected failures.
- [ ] Implement deterministic plan, part, and hash validation with the new graph revision.
- [ ] Run the tests and observe green.

### Task 2: v7 response and coverage proof

**Files:** Create `surface_coverage_v5.py` and `test_surface_coverage_v5.py`; modify v5 evidence validation and Agent result handling only as necessary for a distinct v7 context/result contract.

**Interfaces:** `validate_surface_plan_v7(...)`, `evaluate_surface_coverage_v5(...)`, and `verified_saved_coverage_v5(...)` consume the pinned plan and saved progress, and return a typed coverage proof.

- [ ] Write failing tests for connected/disconnected roles, source and result mismatch, unchanged raw gaps, child `HOLD`, missing parts, corrupt saved proof, and idempotent replay.
- [ ] Implement validation and proof derivation using the existing source-bound role validator, retaining every unresolved parent reason unless new verified evidence resolves it.
- [ ] Run focused tests and observe green.

### Task 3: Transactional pin, explicit resume, and read-side integration

**Files:** Modify `models.py`, `store.py`, `application.py`, `bootstrap_stages.py`, `surface_proof_read.py`, `stages.py`, and `dashboard/query.py`; add focused integration tests.

**Interfaces:** `pin_surface_enrichment_v7_plan(expected_run, plan_ref, prior_progress_hash, missing_v6_parts)` performs a SQLite `BEGIN IMMEDIATE` CAS against exact parent run, root output, and old progress. Existing explicit enrichment resume prepares or reuses v7 and runs only missing v7 parts. Terminal proof version 5 points to its own coverage ref.

- [ ] Write failing tests for stale run/root/progress CAS, completed v7 reuse, crash/restart, changed source or scope, and read-side proof verification.
- [ ] Implement the minimal integration and preserve old version dispatch.
- [ ] Run focused tests, then the full project test command; report any failures precisely.
