# AST, Surface, and Context Refinement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve syntax-faithful Python security-surface evidence and give an insufficient surface one bounded second look without invalidating existing analyses.

**Architecture:** Write new, versioned AST and surface artifacts while retaining exact readers for prior formats. Keep the first 64 KiB surface context and its decision immutable; only an omitted-evidence `INSUFFICIENT` decision may trigger one separately checkpointed, redacted same-file expansion. Static candidates, surface hints, hypothesis decisions, and findings remain distinct.

**Tech Stack:** Python 3.12, `ast`, Pydantic, SQLite checkpoints, content-addressed artifacts, pytest.

**Spec:** `docs/superpowers/specs/2026-10-02-real-repository-e2e-hardening-design.md`

## Global Constraints

- Work on `codex/streaming-pipeline-optimization` for PR #209; preserve the dirty main checkout and original Dify/Flask/simpleeval data.
- Keep Agent roles and the Python-only streaming candidate pipeline; no full-source prompt fallback or fabricated findings.
- Bound each surface request to 64 KiB, redact before persistence/prompting, and never byte-truncate an oversized source line.
- Preserve v1/v2 artifact and checkpoint readers; new records have disjoint versions/fingerprints and do not reclassify an old terminal run.
- A surface is a review hint, not a vulnerability verdict; missing evidence remains explicit `INSUFFICIENT`/`PARTIAL`.

## Review Focus

1. `eval(x)` versus `super().eval(x)` must not share a builtin-execution identity; `Path(...).write_text(x)` must remain detectable (Tasks 1–2).
2. `getattr(obj, variable)` must be reviewable while `getattr(ast, "Num", None)` remains only a literal compatibility probe (Tasks 1–2).
3. Oversized lines, secret-like strings, and required code outside the same file must not be silently cut, leaked, or marked reviewed (Task 3).
4. Crash after the first or second decision must not duplicate LLM work or count the first insufficient decision against a successful second one (Task 4).
5. A v1/v2 checkpoint must resume under its original meaning, not acquire new surfaces or change its expected context set (Tasks 2 and 4).

## File map

- `src/sastsimi/simple_runtime/ast_facts.py`: versioned AST file facts and legacy validation.
- `src/sastsimi/simple_runtime/attack_surfaces.py`: syntax-aware surface classification/index and old-index reader.
- `src/sastsimi/simple_runtime/surface_contexts.py`, `file_context.py`: bounded same-file expansion and redacted context artifacts.
- `src/sastsimi/simple_runtime/bootstrap_stages.py`, `stages.py`: accept and validate both context versions without relaxing source-location proof.
- `src/sastsimi/simple_runtime/application.py`, `store.py`: one-time expansion decision, resume validation, and effective final coverage.
- Tests live beside existing `tests/unit/simple_runtime/test_ast_facts.py`, `test_attack_surfaces.py`, `test_surface_contexts.py`, `test_surface_proposal.py`, `test_surface_progress_store.py`, `test_candidate_pipeline.py`, plus `tests/integration/orchestration/test_streaming_candidate_pipeline.py`.

---

### Task 1: Versioned call facts with receiver and argument identity

**Files:** Modify `src/sastsimi/simple_runtime/ast_facts.py`; test `tests/unit/simple_runtime/test_ast_facts.py`.

**Interfaces:** Produce `_call_fact(node: ast.Call, path: str) -> dict[str, object] | None` with `name`, `callee_kind` (`DIRECT`/`ATTRIBUTE`), `receiver_kind` (`NAME`/`ATTRIBUTE`/`CALL_RESULT`/`OTHER` or null), and `attribute_arg_kind` (`STRING_LITERAL`/`NONLITERAL` or null). New `collect_python_ast` emits `simple_python_ast_file_v2` / manifest v2 / summary `format_version=3`, including source SHA-256 per file; `read_ast_file_facts` accepts that pair and the existing v1/format-2 pair unchanged.

- [ ] **Step 1: Write failing tests** `test_direct_and_call_receiver_are_distinct`, `test_call_receiver_file_write_preserved`, `test_getattr_argument_kind`, and `test_legacy_ast_manifest_readable`; assert exact fact fields for `eval(x)`, `super().eval(x)`, `Path(p).write_text(x)`, literal and nonliteral `getattr`.
- [ ] **Step 2: Verify red** with `& 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_ast_facts.py -q`; expect new assertions to fail.
- [ ] **Step 3: Implement** `_call_fact` and v2 manifest/file writing plus strict version-paired reading; retain the old record bytes and their interpretation on resume.
- [ ] **Step 4: Verify green** with the same command; expect all tests to pass.
- [ ] **Step 5: Commit** only this task's code and tests with `git commit -m "feat: retain structured Python call facts"`.

### Task 2: Evidence-level-safe surface indexing

**Files:** Modify `src/sastsimi/simple_runtime/attack_surfaces.py`, `src/sastsimi/simple_runtime/application.py`; test `tests/unit/simple_runtime/test_attack_surfaces.py`.

**Interfaces:** Add `_ast_call_type(fact: Mapping[str, object], *, legacy: bool) -> str | None` and version-aware `build_attack_surface_index(...)`. New index kind `simple_attack_surface_index_v2` binds fact/source hashes; `surface_index_from_json` continues strict exact validation of v1 and v2. Direct `getattr` with a nonliteral second positional argument yields `REFLECTION`; literal compatibility checks yield no reflection surface. Existing static-rule candidates remain separate and their source/flow identities are not merged merely by similar names.

- [ ] **Step 1: Write failing tests** `test_direct_eval_not_super_eval`, `test_dynamic_getattr_not_literal_getattr`, `test_call_result_write_text_still_indexed`, `test_distinct_flow_identities_stay_distinct`, and `test_v1_index_round_trip`; assert exact path, line, symbol, detector, source hash, and candidate links.
- [ ] **Step 2: Verify red** with `& 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_attack_surfaces.py -q`.
- [ ] **Step 3: Implement** structured classification and v2 serialization; choose old classification only for old fact/index versions. Ensure `_ensure_attack_surface_index` reuses an already saved legacy index before considering new detection.
- [ ] **Step 4: Verify green** with the same command, then `& 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_candidate_pipeline.py -q`.
- [ ] **Step 5: Commit** with `git commit -m "feat: classify versioned Python attack surfaces"`.

### Task 3: One bounded same-file expansion context

**Files:** Modify `src/sastsimi/simple_runtime/surface_contexts.py`, `file_context.py`, `bootstrap_stages.py`, `stages.py`; test `tests/unit/simple_runtime/test_surface_contexts.py`, `test_surface_proposal.py`.

**Interfaces:** Produce `expanded_surface_contexts(index: SurfaceIndex, surface: AttackSurface, *, artifacts: SimpleArtifactRepository, ast_summary: Mapping[str, object], workspace: Path, budget_bytes: int = 64 * 1024) -> tuple[SurfaceContext, ...]`. Its `simple_surface_context_v2` payload selects the enclosing same-file function/class and directly referenced same-file implementation; a small entire file is allowed only when it fits 64 KiB with metadata headroom. Every part includes the original surface line, records omitted/unavailable evidence, and splits deterministically without truncation. Existing v1 context validation stays exact; proposal and trusted-evidence readers accept v2 only with matching context hash and location proof. The second proposal result is `simple_surface_hypothesis_result_v2`, explicitly bound to context v2.

- [ ] **Step 1: Write failing tests** `test_enclosing_function_changes_context`, `test_expansion_stays_within_budget_and_splits`, `test_oversized_line_and_external_file_remain_insufficient`, `test_expansion_redacts_secrets`, and `test_v1_and_v2_proposals_require_exact_source_location`.
- [ ] **Step 2: Verify red** with `& 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_surface_contexts.py tests/unit/simple_runtime/test_surface_proposal.py -q`.
- [ ] **Step 3: Implement** the expansion builder and strict dual-version validation. Do not extend the single-file `path:line` evidence claim to another file; if a required implementation is elsewhere, retain explicit missing evidence.
- [ ] **Step 4: Verify green** with the same command.
- [ ] **Step 5: Commit** with `git commit -m "feat: add bounded second-look surface context"`.

### Task 4: One-time retry, durable resume, and honest coverage

**Files:** Modify `src/sastsimi/simple_runtime/application.py`, `store.py`; test `tests/unit/simple_runtime/test_surface_progress_store.py`, `test_candidate_pipeline.py`, `tests/integration/orchestration/test_streaming_candidate_pipeline.py`.

**Interfaces:** `_run_targeted_surface_exploration` invokes `expanded_surface_contexts` only for a new-format first decision that is `INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS` **and** has omitted source lines or AST facts that the same-file expansion can supply. All deterministically split parts count as one second look; there is no third pass. Persist each part under its own deterministic context ID with surface ID, commit, static bundle, proposal version, and context/source hashes. `_final_surface_coverage` treats a valid second decision as the effective decision while preserving the first for audit; old scopes compute the original expected context set.

- [ ] **Step 1: Write failing tests** `test_insufficient_with_omission_expands_once`, `test_insufficient_without_omission_does_not_repeat`, `test_resume_after_each_commit_reuses_response`, `test_second_decision_can_cover_first_insufficient`, `test_second_insufficient_stays_partial`, and `test_old_checkpoint_context_set_unchanged`; assert no duplicate Agent call and no `confirmed` from a surface review alone.
- [ ] **Step 2: Verify red** with `& 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_surface_progress_store.py tests/unit/simple_runtime/test_candidate_pipeline.py tests/integration/orchestration/test_streaming_candidate_pipeline.py -q`.
- [ ] **Step 3: Implement** deterministic expansion state in `application.py`/`store.py`; update exploration and final-coverage expected-key checks together, fail closed on mismatched hashes, and preserve successful child checkpoints.
- [ ] **Step 4: Verify green** with the same pytest command and `& 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe' -m mypy src/sastsimi/simple_runtime`.
- [ ] **Step 5: Commit** with `git commit -m "feat: checkpoint one-time surface evidence refinement"`.

**Handoff:** Continue with `2026-10-02-offline-poc-and-e2e-verification.md` in the same PR. Do not claim a real finding or general reliability from these unit tests alone.
