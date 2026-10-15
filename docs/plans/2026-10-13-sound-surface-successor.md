# Sound Surface Successor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-evaluate the existing A-001 partial coverage from new, source-bound evidence without changing its v4–v8 history or falsely marking unknown Python paths complete.

**Architecture:** Pure proof modules first establish optional-analyzer applicability, intrinsic AST facts, and connected-path completeness from the pinned commit. A new immutable v9 plan and coverage certificate bind those proofs to the saved v8 terminal. Only independently verified surface rows may replace `INSUFFICIENT`; unchanged evidence and failed parts remain partial.

**Tech Stack:** Python 3.12, Pydantic contracts, SQLite checkpoint store, SHA-256 content-addressed artifacts, pytest, Ruff, mypy.

**Spec:** `docs/plans/2026-10-13-sound-surface-successor-design.md`

## Global Constraints

- Do not rewrite, reinterpret, or delete any pinned v4–v8 plan, progress row, artifact, or finding.
- Do not hardcode repository name, commit, A-001 ID, Flask-only scanning, or the observed count 43 into the runtime.
- A proof is about one exact surface/commit/scope; lack of proof never means vulnerability absence.
- Existing `CHILD_HOLD`, static gaps, candidate pending/error, and genuine path gaps still block `COMPLETE`.
- No credentials, full prompts, or unredacted source are added to routine logs or dashboard payloads.

## Review Focus

- Mixed Flask and stdlib HTTP modules: applicable stdlib evidence must not be suppressed because Flask is present; Task 1 tests both.
- Dynamic imports, parser errors, budget exhaustion, or source hash mismatch: applicability must be `UNKNOWN`; Task 1 tests each.
- Same-line decoy literal beside dynamic SQL sink: intrinsic proof must reject it; Task 2 tests it.
- One verified path plus one unresolved alternate path: coverage stays insufficient; Task 3 and Task 4 test it.
- Interrupted resume, changed source, or mismatched plan/child checkpoint: v9 rejects or resumes exactly once without modifying v8; Task 4 tests it.

---

### Task 1: Pure optional-analyzer applicability

**Files:**
- Create: `src/sastsimi/simple_runtime/surface_applicability_v9.py`
- Test: `tests/unit/simple_runtime/test_surface_applicability_v9.py`

**Interfaces:**
- Consumes: pinned workspace/commit, `SurfaceIndex.ast_source_hashes`, exact tracked launcher/config entries.
- Produces: `assess_optional_analyzers(index: SurfaceIndex, workspace: Path) -> AnalyzerApplicabilityV9`, whose per-analyzer status is `APPLICABLE | NOT_APPLICABLE | UNKNOWN` with source hashes and reason codes; `validate_analyzer_applicability(...)` rechecks the proof.

- [ ] **Step 1: Write failing tests** for a complete Flask-only manifest, an actual `http.server.BaseHTTPRequestHandler` subclass, a supported XML parser/launcher, mixed frameworks, dynamic/aliased import, source hash mismatch, parse error, and scan limits. Assert `NOT_APPLICABLE` affects only the matching optional analyzer.
- [ ] **Step 2: Run** `pytest -q tests/unit/simple_runtime/test_surface_applicability_v9.py`; expect the new tests to fail before implementation.
- [ ] **Step 3: Implement** the two interfaces in the new module using the existing safe tracked-file and pinned-blob readers; ambiguous or incomplete scans return `UNKNOWN`, never `NOT_APPLICABLE`.
- [ ] **Step 4: Run** that pytest file, Ruff, and mypy; expect all pass.

### Task 2: Exact intrinsic AST proofs

**Files:**
- Modify: `src/sastsimi/simple_runtime/surface_safe_sql_literal.py`
- Create: `src/sastsimi/simple_runtime/surface_intrinsic_proof_v9.py`
- Test: `tests/unit/simple_runtime/test_surface_intrinsic_proof_v9.py`

**Interfaces:**
- Consumes: one indexed surface, its original candidate refs, pinned graph AST facts, source hash and exact commit.
- Produces: `prove_intrinsic_surface(index: SurfaceIndex, surface: AttackSurface, workspace: Path, graph: Mapping[str, object]) -> IntrinsicProofV9 | None` for `FIXED_SQL_LITERAL` or `ROUTE_DECLARATION`; `validate_intrinsic_proof(...)` recomputes it.

- [ ] **Step 1: Write failing tests** for seven fixed SQL calls, an actual Flask route decorator, same-line decoy, variable/f-string SQL, multiple calls, object rebinding, altered candidate ID/rule/line, and source SHA mismatch. A literal call proof must not assert other calls or route safety.
- [ ] **Step 2: Run** the new test file and confirm the negative cases fail before implementation.
- [ ] **Step 3: Implement** exact candidate→AST→source binding. Keep the helper conservative; never accept a caller-supplied method name or column as proof without checking the pinned candidate and AST location.
- [ ] **Step 4: Run** the new test file plus `test_surface_safe_sql_literal.py`, Ruff, and mypy; expect all pass.

### Task 3: Source-bound path and complete-context certificate

**Files:**
- Create: `src/sastsimi/simple_runtime/surface_path_proof_v9.py`
- Test: `tests/unit/simple_runtime/test_surface_path_proof_v9.py`

**Interfaces:**
- Consumes: saved inherited graph, pinned AST manifest, Task 1 applicability, exact source files and route bindings.
- Produces: `certify_surface_paths(index: SurfaceIndex, surface: AttackSurface, graph: Mapping[str, object], applicability: AnalyzerApplicabilityV9, workspace: Path) -> PathCertificateV9`; incomplete certificates enumerate unresolved gap codes and path IDs. `validate_path_certificate(...)` recomputes it.

- [ ] **Step 1: Write failing tests** for a real Flask route→request→sink inherited path with missing historical `blocking_gaps`, an unrelated optional-analyzer gap, a relevant unknown gap, two paths with one unresolved, SHA/edge mutation, truncated function, and missing/cross-ordered context part.
- [ ] **Step 2: Run** the new test file and confirm failures.
- [ ] **Step 3: Implement** exact route/node/edge proof and gap attribution. Read entire pinned function/callee in bounded ordered chunks; no dropped source line may be called complete. Absence or ambiguity of provenance yields an incomplete certificate.
- [ ] **Step 4: Run** the new tests and existing v8 graph/coverage tests, Ruff, and mypy; expect all pass.

### Task 4: Immutable v9 plan, resume, and coverage evaluation

**Files:**
- Create: `src/sastsimi/simple_runtime/surface_enrichment_v9.py`
- Create: `src/sastsimi/simple_runtime/surface_evidence_validation_v9.py`
- Create: `src/sastsimi/simple_runtime/surface_coverage_v7.py`
- Modify: `src/sastsimi/simple_runtime/models.py`
- Modify: `src/sastsimi/simple_runtime/store.py`
- Modify: `src/sastsimi/simple_runtime/application.py`
- Modify: `src/sastsimi/simple_runtime/bootstrap_stages.py`
- Test: `tests/simple_runtime/test_surface_enrichment_v9.py`
- Test: `tests/simple_runtime/test_surface_v9_resume.py`

**Interfaces:**
- Consumes: saved v8 plan/terminal, Task 1–3 proof objects, existing artifact repository and transactional store.
- Produces: `prepare_surface_enrichment_v9(...)` with a pinned expected-part inventory; `validate_v9_response(...)` binding an Agent review to complete source/path evidence; `evaluate_surface_coverage_v7(...)` with per-surface status/reasons; one same-ID resume branch for proposal version 9. A `surface_enrichment_v9_plan_ref` is optional in `SimpleAnalysisRun`, so old rows load unchanged.

- [ ] **Step 1: Write failing tests** that pin v8 bytes and source identity, save one v9 part, resume idempotently, reject tampered plan/progress/source, and keep a surface insufficient for unresolved paths/children/static gaps. Include one completed intrinsic surface and one connected surface reviewed by the existing hypothesis Agent; schema-invalid, no-role, and incomplete-source replies must fail or remain insufficient.
- [ ] **Step 2: Run** both new test files and confirm the expected failures.
- [ ] **Step 3: Implement** v9 only behind the explicit enrichment resume path, with CAS artifacts and transactional checkpoint registration. Send complete bounded path/context parts to the existing hypothesis Agent, validate its v9 response and exact reviewed roles, and register any new hypotheses as children of the pinned surface. Do not change v8 legacy replay. Model output cannot override a failed deterministic proof.
- [ ] **Step 4: Run** new tests, v4–v8 replay/coverage suites, Ruff, and mypy; expect all pass.

### Task 5: Live same-ID validation and documentation

**Files:**
- Modify: `docs/usage.md`
- Modify: `docs/dashboard-demo.md`
- Test: `tests/simple_runtime/test_surface_v9_resume.py`

- [ ] **Step 1: Verify** the exact A-001 commit, workspace, v8 terminal, and no active worker before a write-capable resume.
- [ ] **Step 2: Resume** the same A-001 ID with `--enrich-saved-surface-evidence`; do not recreate analysis or edit SQLite directly.
- [ ] **Step 3: Measure** covered/insufficient surfaces, static gaps, pending candidates/children, findings, and actual status from saved certificates. If any evidence remains missing, preserve `PARTIAL` and list the reason rather than reporting 100%.
- [ ] **Step 4: Run** focused regression, full test suite where the Windows runner allows, Ruff, mypy, and `git diff --check`. Document any suite interruption as unverified.
- [ ] **Step 5: Update** usage/dashboard docs only to reflect tested behavior and current limitations.

## Self-review result

The tasks cover each spec contract and retain legacy replay. Every positive path has a tampering and incomplete-evidence counterexample. The plan deliberately does not promise that A-001 reaches 100%; only the live certificate can establish that outcome.
