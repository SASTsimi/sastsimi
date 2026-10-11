# A-001 V5 Surface Proof and HOLD Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-examine A-001's 36 insufficient Python surfaces and 33 linked `HOLD` children with new, source-bound evidence while preserving its saved v4 analysis and truthful completion status.

**Architecture:** Add opt-in v5 route/config evidence, a deterministic plan and progress version, and a new terminal proof reader instead of changing the pinned v4 plan. Separate source-verified graph work from child-HOLD eligibility and bounded replay. Existing analyses keep v1/v2 proof semantics; 100% requires an actual all-covered v3 certificate.

**Tech Stack:** Python 3.12 AST, bounded XML parsing, Git pinned blobs, Pydantic, SQLite/CAS, pytest, Ruff, mypy, Windows PowerShell.

**Spec:** `docs/superpowers/specs/2026-10-12-live-analysis-proof-recovery-design.md` (A-001 section).

## Global Constraints

- Keep A-001's exact ID and pinned checkout/commit, static 85/85, index, v1-v4 plans/results, existing children, PoCs, Findings, and policy decisions unchanged.
- No hardcoded `dsvpwa` path, XML tag, route, class or vulnerability label. A mapping must be derived from pinned source/config and uniquely resolve.
- XML is operational evidence only: serialize route/class bindings, never `good_path`, `evil_path`, `source`, `sink`, objectives, descriptions or other answer-key fields into an Agent context or graph proof.
- A relative config path without source-bound runtime working-directory proof is an explicit gap. Reject DTD/entities, oversized XML, ambiguous class names and dynamic dispatch that cannot be resolved.
- `COMPLETE`/100% requires zero effective Python static gaps, no pending/error child work and every indexed surface `COVERED`. No model assertion, missing route path, or terminal `HOLD` is silently converted to coverage.
- Execute from the existing isolated worktree with `..\..\.venv\Scripts\python.exe`. Use named-file staging only; preserve all untracked test data.

## Review Focus

1. A fake local class named `BaseHTTPRequestHandler` must not become a network entry; Task 1 tests import identity and alias/shadowing.
2. A forged or moved XML file must not provide a graph edge; Task 2 tests commit/blob/workdir binding.
3. Answer-key fields in educational XML must not leak into prompts or artifacts; Task 2 and Task 3 test exact serialized keys.
4. A completed v4 part or child must never be rerun just because a v5 plan exists; Task 3 and Task 5 test replay counts and old ref hashes.
5. A source-proven initialization/return-only surface that lacks the three connected roles remains insufficient; Task 4 tests it cannot flip the v3 terminal to `COMPLETE`.

## File map

- `src/sastsimi/simple_runtime/http_route_facts_v5.py`: opt-in stdlib HTTP entry and branch-scoped local-constructor call facts.
- `src/sastsimi/simple_runtime/operational_config_v5.py`: bounded, pinned XML route/class bindings without answer-key content.
- `src/sastsimi/simple_runtime/surface_evidence_graph_v5.py`, `surface_enrichment_v5.py`: merge only verified paths, build exact-source v5 context/manifest.
- `src/sastsimi/simple_runtime/surface_evidence_validation_v5.py`, `surface_coverage_v3.py`: validate per-part claims and final versioned proof.
- `src/sastsimi/simple_runtime/surface_hold_replay_v1.py`: source/old-output-based eligibility and one-shot child replay requests.
- `src/sastsimi/simple_runtime/models.py`, `store.py`, `application.py`, `surface_proof_read.py`: optional v5 plan ref, proposal version 5 CAS, explicit same-ID resume and v3 terminal.
- `src/sastsimi/progress/projector.py`, `composition/simple_runtime_composition.py`, `dashboard/query.py`, `reporting/bilingual_bundle.py`, `reporting/coverage_disclosure.py`: verify/read v3 proof and show reviewed versus covered counts without changing old runs.
- Focused tests in `tests/unit/simple_runtime/`, `tests/simple_runtime/`, `tests/unit/progress/`, dashboard/report tests; update `docs/architecture/runtime-and-recovery.md`.

---

### Task 1: Opt-in, source-bound standard-library HTTP paths

**Files:** Create `src/sastsimi/simple_runtime/http_route_facts_v5.py`; test `tests/unit/simple_runtime/test_http_route_facts_v5.py`.

**Interfaces:** Define `verified_http_paths(workspace: Path, tracked_hashes: Mapping[str, str], surface: AttackSurface, *, max_hops: int = 6, max_paths: int = 4) -> CandidateCallPaths` (existing `CandidateCallPaths` type). It resolves `from http.server import BaseHTTPRequestHandler` or an exact imported alias, subclasses, `do_` uppercase verb methods, branch-local object construction and unique direct method calls. The same imported-handler identity and source location must bind reads of `self.path`, `self.headers` or `self.rfile` to request input; namesake classes or reassigned `self` do not qualify. Output path steps include exact source locations and `SYNTACTIC_REACHABILITY`; unresolved aliases/branches become gaps, not edges. No existing v4 call-index default changes.

- [ ] **Step 1: Write failing fixtures** for a real imported handler with `do_GET` to a constructed local handler method and a bound `self.path`/`self.headers`/`self.rfile` read, alias import, nonstandard `do_BDR`, fake/shadowed handler, fake or reassigned `self`, two branch assignments, a reassigned local and a cycle. Assert only unambiguous source-bound paths and trust-boundary facts appear; false cases have explicit gaps.
- [ ] **Step 2: Run RED:** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_http_route_facts_v5.py -q -p no:cacheprovider`; expected missing module/functions fail.
- [ ] **Step 3: Implement `verified_http_paths`** with AST/import identity and bounded branch-local constructor resolution; compare each tracked file SHA-256 before using it.
- [ ] **Step 4: Run GREEN** with the same command and existing `tests/unit/simple_runtime/test_call_path_facts.py`; expected all pass, including unchanged legacy behavior.
- [ ] **Step 5: Commit only new module/test** as `feat: prove opt-in Python HTTP entry paths`.

### Task 2: Pinned operational XML mapping, never an answer key

**Files:** Create `src/sastsimi/simple_runtime/operational_config_v5.py`; test `tests/unit/simple_runtime/test_operational_config_v5.py`.

**Interfaces:** Define immutable `OperationalRouteBinding(route: str, module_path: str, class_symbol: str, config_path: str, config_sha256: str, parser_path: str, parser_sha256: str, parser_sites: tuple[int, ...], target_path: str, target_sha256: str, launcher_path: str, launcher_sha256: str)`, `OperationalRouteMap(bindings: tuple[OperationalRouteBinding, ...], gaps: tuple[str, ...])`, and `load_operational_routes(workspace: Path, commit_id: str, parser_path: str, parser_source: bytes, launcher_path: str, *, runtime_workdir: str | None, max_bytes: int = 131072) -> OperationalRouteMap`. Verify parser, launcher, configuration and uniquely resolved target blobs against the pinned commit before interpreting the `ET.parse` literal, iterative `findtext`-to-`getattr` use, and append/use chain. A pinned launcher must connect its entrypoint and `WORKDIR` to the parser; a matching workdir string alone is insufficient. Keep XML provenance distinct from Python AST provenance. Return no bindings and an explicit gap for any uncertain component, not empty success.

- [ ] **Step 1: Write failing tests** with renamed module/loop/XML tags (genericity), matching pinned parser/launcher/XML/target blobs and entrypoint/workdir, and negative cases for missing workdir or launcher link, changed blob, duplicate class/route, DTD, oversized input and unresolved `getattr`. Assert exact AST sites/hashes in bindings and that serialized context contains none of `good_path`, `evil_path`, `source`, `sink`, description or objective even when XML includes them.
- [ ] **Step 2: Run RED:** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_operational_config_v5.py -q -p no:cacheprovider`; expected missing module/functions fail.
- [ ] **Step 3: Implement the result object and loader above** with bounded ElementTree parsing, exact tracked Git blob and source hash, structural AST matching and whitelist-only serialization. Do not parse or transmit vulnerability-answer fields.
- [ ] **Step 4: Run GREEN** with the same command; expected all cases pass.
- [ ] **Step 5: Commit only new module/test** as `feat: bind operational route config without answer keys`.

### Task 3: Immutable v5 plan, context, progress and review

**Files:** Create `src/sastsimi/simple_runtime/surface_evidence_graph_v5.py`, `surface_enrichment_v5.py`, `surface_evidence_validation_v5.py`; modify `src/sastsimi/simple_runtime/models.py:93-145`, `store.py:1790-2165`, `application.py:766-1028,3190-3470`; test `tests/unit/simple_runtime/test_surface_enrichment_v5.py`, `tests/simple_runtime/test_saved_surface_enrichment_v5_resume.py`.

**Interfaces:** `prepare_surface_enrichment_v5(identity: CheckpointIdentity, scope: str, index: SurfaceIndex, index_ref: StoredDataRef, v4_plan_ref: StoredDataRef, v2_coverage_ref: StoredDataRef, current_coverage: SurfaceCoverageV2, prior_progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord], graphs: Mapping[str, Mapping[str, object]]) -> tuple[dict[str, object], tuple[V5Part, ...]]` targets exactly the currently insufficient surfaces and pins **baseline** prior refs, child checkpoint hashes, source/config hashes and reasons once. Subsequent child state is verified through CAS events, never used to rederive the immutable plan bytes. `extract_surface_graph_v5(index: SurfaceIndex, surface: AttackSurface, ast_summary: Mapping[str, object], manifest_index: Mapping[str, Mapping[str, object]], workspace: Path, artifacts: SimpleArtifactRepository, route_map: OperationalRouteMap) -> dict[str, object]` combines Task-1 paths and Task-2 bindings only where the AST proves the full chain. `validate_v5_response(context: Mapping[str, object], response: Mapping[str, object]) -> V5ValidatedResponse` requires the three roles on one verified path. `SimpleAnalysisRun.surface_enrichment_v5_plan_ref: StoredDataRef | None` is optional; progress `proposal_version=5` is accepted with the same atomic result+registration CAS as v4. Once v5 exists, application routing must prioritize the v5 path and validate the saved v2 certificate without re-running the v4 calculator or v2 evaluator (both reject v5 progress). The existing explicit `--enrich-saved-surface-evidence` starts v5 only after a terminal pinned v4 plan, and ordinary resume reuses the pinned v5 plan.

- [ ] **Step 1: Write failing tests** for 36-target derivation from a v2 partial certificate, plan byte equality, old v4 ref preservation, source/config mutation failure, 64-KiB whole-item chunks, corrupt/missing part, all-three-role same-path validation, restart/competing-resume reuse without duplicate child registration, and strict v5-first routing that never feeds v5 rows to the v4 calculator or v2 evaluator.
- [ ] **Step 2: Run RED:** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_surface_enrichment_v5.py tests/simple_runtime/test_saved_surface_enrichment_v5_resume.py -q -p no:cacheprovider`; expected missing v5 interfaces fail.
- [ ] **Step 3: Implement graph/plan/validator and minimal model/store/application wiring.** Reuse v4 helpers only when their legacy output bytes and semantics remain unchanged; add optional v5 state rather than rewriting old plan/result/CAS rows.
- [ ] **Step 4: Run GREEN** with the same command plus `tests/unit/simple_runtime/test_surface_enrichment_v4.py tests/simple_runtime/test_saved_surface_enrichment_resume.py`; expected v4 and v5 pass.
- [ ] **Step 5: Commit only these named source/tests** as `feat: pin and resume v5 surface evidence`.

### Task 4: Versioned v3 proof and fail-closed readers

**Files:** Create `src/sastsimi/simple_runtime/surface_coverage_v3.py`; modify `src/sastsimi/simple_runtime/models.py:71-91`, `application.py:3480-3555`, `surface_proof_read.py`, `src/sastsimi/progress/projector.py`, `src/sastsimi/composition/simple_runtime_composition.py`, `src/sastsimi/dashboard/query.py`, `src/sastsimi/reporting/bilingual_bundle.py`, `coverage_disclosure.py`; test `tests/unit/simple_runtime/test_surface_coverage_v3.py`, `tests/unit/progress/test_surface_v3_projection.py`, relevant dashboard/report tests.

**Interfaces:** `evaluate_surface_coverage_v3(identity: CheckpointIdentity, index: SurfaceIndex, prior: SurfaceCoverageV2, plan: Mapping[str, object], progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord], store: SimpleCheckpointStore, artifacts: SimpleArtifactRepository) -> SurfaceCoverageV3` consumes and verifies pinned v2 proof plus v5 progress/child transitions, never changes the v2 artifact. Re-evaluate only replaceable graph and child-HOLD reasons against new source-bound proof/current verified child state; retain unrelated v2 gaps and the original v2 certificate. `CandidateTerminal.surface_proof_version` accepts `3`; `verified_surface_coverage_counts(...)` validates the v3 certificate/CAS refs, all 56 indexed IDs and counts before read-side use. `complete` is true only when effective Python gaps, pending/error work and insufficient/uncovered surfaces are all zero. Surface-level non-request classification is recorded but does not become `COVERED`.

- [ ] **Step 1: Write failing tests** for 20 covered/36 insufficient preserved with zero new proof, one newly connected path becoming covered only without `HOLD`, a `HOLD`-only surface remaining insufficient, class-load/return-only surfaces remaining insufficient, mutated v3 refs failing closed, and old v1/v2 readers unchanged. Assert CLI/dashboard/English/Korean report separate `reviewed` from `covered` and keep `PARTIAL` when any gap remains.
- [ ] **Step 2: Run RED:** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_surface_coverage_v3.py tests/unit/progress/test_surface_v3_projection.py -q -p no:cacheprovider`; expected missing v3 interface fails.
- [ ] **Step 3: Implement v3 evaluator and strict read-side projection**, then update only the version discriminators/labels in composition, dashboard and bilingual reports. Do not mark an unverified path as no finding.
- [ ] **Step 4: Run GREEN** with new tests plus `tests/unit/simple_runtime/test_surface_coverage_v2.py tests/unit/progress/test_surface_v2_projection.py`; expected old and new pass.
- [ ] **Step 5: Commit only named files/tests** as `feat: certify v5 surface proof without masking gaps`.

### Task 5: Evidence-bound `HOLD` eligibility and one-shot child replay

**Files:** Create `src/sastsimi/simple_runtime/surface_hold_replay_v1.py`; modify `src/sastsimi/simple_runtime/store.py`, `application.py`; test `tests/simple_runtime/test_surface_hold_replay_v1.py`.

**Interfaces:** `classify_hold_replay(identity: CheckpointIdentity, child: StageCheckpoint, pinned_evidence: Mapping[str, object], artifacts: SimpleArtifactRepository) -> HoldReplayDecision` with `action: Literal["REPLAY_INITIAL_ONCE", "REGENERATE_POC_ONCE", "REEXECUTE_POC_ONCE", "KEEP_HOLD"]`, exact `restart_stage`, evidence refs and a closed reason. `SimpleCheckpointStore.prepare_surface_hold_replay(self, child: StageCheckpoint, decision: HoldReplayDecision, artifacts: SimpleArtifactRepository, *, fail_before_commit: bool = False) -> StageCheckpoint | None` takes only an evidence-bound `REPLAY_*`/`REGENERATE_*`/`REEXECUTE_*` decision under a lease/transaction, saves the old successful-HOLD checkpoint/CAS ref and one-shot marker, and reopens exactly the matching child stage. A narrow v5 reader validates that new input binding against the original v4 seed plus the explicit v5 replay event; generic failed-checkpoint recovery is not reused. `KEEP_HOLD` is saved as review evidence but does not change the child or v3 coverage.

- [ ] **Step 1: Write failing tests** for all 25/4/4 categories with synthetic pinned evidence: Agent-declared prerequisite without contradiction stays `HOLD`, contradicted prerequisite reopens initial once, generated-input STOP with source-bound new input regenerates the PoC candidate once, unchanged valid PoC with new execution-only prerequisite reexecutes only that PoC once, max-attempt inconclusive without new path stays `HOLD`, second replay/stale state/source mutation/process unconfirmed fail closed. Verify v4 integrity still reads and the v5 child binding accepts only the recorded transition. Assert prior PoC/artifacts and findings unchanged.
- [ ] **Step 2: Run RED:** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/simple_runtime/test_surface_hold_replay_v1.py -q -p no:cacheprovider`; expected missing module/method fail.
- [ ] **Step 3: Implement the classifier and CAS replay with deterministic markers**; the v5 application calls it only for linked terminal `HOLD` children with newly cited source/PoC evidence. Preserve existing retry caps for ordinary errors and cap each new recovery marker at one.
- [ ] **Step 4: Run GREEN** with the same command and v5 resume tests; expected no blind replay, no duplicates.
- [ ] **Step 5: Commit only named files/tests** as `fix: replay only evidence-bound surface HOLD children`.

### Task 6: Full regression, docs and real same-ID A-001 result

**Files:** Modify `docs/architecture/runtime-and-recovery.md`; test existing CLI/dashboard/report integration suites (add narrowly focused assertions where missing).

**Interfaces:** Existing `resume A-001 --enrich-saved-surface-evidence` prepares an immutable v5 plan only after v4; ordinary `resume A-001` uses the plan and completed parts. The dashboard/CLI/report show raw/effective Python gaps, reviewed/covered/insufficient surfaces, child `HOLD` reasons, and actual status.

- [ ] **Step 1: Add a failing public integration test** for explicit v5 preparation, ordinary resume, and idempotent repeated status reads; assert completed v4 parts/static work are never called again.
- [ ] **Step 2: Run RED:** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/simple_runtime/test_saved_surface_enrichment_v5_resume.py -q -p no:cacheprovider`; expected new public case fails.
- [ ] **Step 3: Finish only needed CLI/status/docs wiring** and document the proof-versus-review distinction and honest `PARTIAL` outcome.
- [ ] **Step 4: Run GREEN**, full `& '..\..\.venv\Scripts\python.exe' -m pytest tests -q -p no:cacheprovider`, `& '..\..\.venv\Scripts\python.exe' -m ruff check src tests`, `& '..\..\.venv\Scripts\python.exe' -m mypy src`; expected exit 0 and recorded skip count.
- [ ] **Step 5: Commit named changes** as `docs: explain v5 surface and HOLD evidence`.
- [ ] **Step 6: Snapshot A-001 refs/status and live processes before writes.** Under normal lease, prepare and resume exact ID `d01477b233df4d82bae5b727390484a9`; compare the 85/85 static checks, 56 surface IDs, 33 saved v4 parts, child attempts, CAS hashes, new coverage counts, PoC/Finding status and LLM use. Run only incomplete v5 parts/eligible children. If any of the 36 surfaces remains insufficient, retain `PARTIAL` and show its exact reason; never paint 100% or claim a new confirmed finding without its own evidence.

