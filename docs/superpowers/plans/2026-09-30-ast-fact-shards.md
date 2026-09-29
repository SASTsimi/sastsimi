# File-Scoped AST Facts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve every fact from each successfully parsed Python product file and pass only relevant, bounded AST context to the hypothesis Agent.

**Architecture:** Write one content-addressed AST artifact per parsed file, then an index manifest and compact summary. Read the manifest to select nearby facts for one candidate; preserve exact references and counts so omitted prompt context is not confused with omitted stored data.

**Tech Stack:** Python 3.12, pytest, Pydantic `StoredDataRef`, existing `SimpleArtifactRepository`.

**Spec:** `docs/superpowers/specs/2026-09-30-ast-fact-shards-design.md`

## Global Constraints

- Preserve Python product-only static scope, excluded test-file policy, existing candidate and Agent roles.
- No aggregate AST fact limit; retain the existing 2 MiB per-source safety limit and disclose failures as partial coverage.
- No unbounded Agent input, silent 256 KiB clipping, false `COMPLETE`, or false `confirmed`.
- Preserve legacy checkpoints, user profile, database, artifacts, and unrelated checkout changes.
- Do not make live LLM calls in tests. Run Dify once only after full verification, with cumulative token/time limits unlimited and bounded individual calls.

## Review Focus

- A parsed file with zero facts still has a verified file artifact and count zero; test in Task 1.
- Exactly 10,000 facts must not imply truncation; test in Task 1.
- Corrupt or absent file artifact must fail new-manifest validation, not silently produce empty context; test in Task 2.
- One candidate in a very large file must get a bounded nearby excerpt with an explicit omitted count; test in Task 2.
- Legacy inline AST bundles must remain readable on resume without interpreting them as new manifests; test in Task 2.

---

### Task 1: Persist a complete per-file AST manifest

**Files:**
- Create: `src/sastsimi/simple_runtime/ast_facts.py` — safe AST extraction and file/manifest artifacts.
- Modify: `src/sastsimi/simple_runtime/bootstrap_stages.py` — replace the 10,000-fact collector with the new collector and keep a small `ast_summary`.
- Create: `tests/unit/simple_runtime/test_ast_facts.py` — >10,000 facts, exact-boundary, empty file, error and oversize cases.
- Modify: `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py` — assert manifest references instead of inline facts and remove assertions that treat the old cap as desired behavior.

**Interfaces:**
- Consumes: `SimpleArtifactRepository.put_json(value: object) -> StoredDataRef` and `read(ref: StoredDataRef) -> bytes`.
- Produces: `collect_python_ast(workspace: Path, tracked: Sequence[str], artifacts: SimpleArtifactRepository, *, max_source_bytes: int) -> dict[str, object]`; result has `kind="simple_python_ast"`, `format_version=2`, `manifest_ref`, `fact_count`, `parsed_file_count`, `parse_errors`, `parse_error_count`, `oversize_paths`, `oversize_count`, `truncated=False`. Manifest has `kind="simple_python_ast_manifest_v1"`, sorted entries `{path, fact_count, ref}` and matching totals. File artifact has `kind="simple_python_ast_file_v1"`, `path`, and all `facts`.

- [ ] **Step 1: Write failing tests.** Test 10,001 call facts spanning files; exact 10,000 has `truncated=False`; empty parsed file has one entry; errors and oversize paths remain explicit. Update existing cap tests to the new expected FULL/PARTIAL behavior.
- [ ] **Step 2: Verify RED.** Run `python -m pytest tests/unit/simple_runtime/test_ast_facts.py tests/integration/orchestration/test_simple_runtime_static_bootstrap.py -q --maxfail=1 --tb=short`; expected: failure because `collect_python_ast`/manifest is absent or the old cap truncates.
- [ ] **Step 3: Implement the exact Task 1 interfaces.** Preserve existing safe regular-file and path checks, fact fields, and deterministic traversal order; write each file before the manifest. Never copy all facts into the bundle.
- [ ] **Step 4: Verify GREEN.** Run the same targeted pytest command; expected: all selected tests pass.
- [ ] **Step 5: Commit.** `feat: preserve complete AST facts per Python file`.

### Task 2: Bounded candidate context and manifest integrity

**Files:**
- Modify: `src/sastsimi/simple_runtime/ast_facts.py` — manifest reader, verifier, and location-focused fact excerpt.
- Modify: `src/sastsimi/simple_runtime/application.py` — verify new manifest on static evidence validation and add excerpt to candidate-focused bundle.
- Modify: `tests/unit/simple_runtime/test_ast_facts.py` — near/far selection, UTF-8 byte budget, missing/corrupt reference, legacy no-manifest behavior.
- Modify: `tests/simple_runtime/test_simple_analysis_application.py` — candidate-focused hypothesis receives AST excerpt while old inline checkpoints still resume.

**Interfaces:**
- Consumes: Task 1 summary, manifest, file artifact formats.
- Produces: `validate_ast_manifest(artifacts: SimpleArtifactRepository, summary: Mapping[str, object]) -> None` and `focus_ast_facts(artifacts: SimpleArtifactRepository, summary: Mapping[str, object], *, path: str, line: int, max_bytes: int = 8192) -> dict[str, object]`. Focus returns selected facts, `total_count`, `omitted_count`, and exact file ref; it errors rather than silently dropping malformed data. Legacy summaries without `format_version=2` are accepted only through the existing legacy validation path.

- [ ] **Step 1: Write failing tests.** Prove a >256 KiB manifest is never in candidate prompt, focused excerpt is <=8192 serialized bytes, selected facts are near the line, omitted count is honest, and corrupted/missing refs fail.
- [ ] **Step 2: Verify RED.** Run `python -m pytest tests/unit/simple_runtime/test_ast_facts.py tests/simple_runtime/test_simple_analysis_application.py -q --maxfail=1 --tb=short`; expected: new focused/integrity assertions fail on missing behavior.
- [ ] **Step 3: Implement bounded focus and validation.** Use `StoredDataRef.model_validate` and verified artifact reads; check all file refs/count totals before FULL/PARTIAL classification; candidate bundle carries only one bounded excerpt, never the manifest or full file facts.
- [ ] **Step 4: Verify GREEN.** Run the same targeted pytest command; expected: all selected tests pass.
- [ ] **Step 5: Commit.** `feat: feed bounded AST context to candidate hypotheses`.

### Task 3: Regression, documentation and one Dify validation

**Files:**
- Modify: `README.md` — AST file completeness versus prompt excerpts and precise `PARTIAL` semantics.
- Create: `docs/validation/2026-09-30-ast-facts-dify.md` — fixed commit, commands, preflight, AST and scan counts, candidate/hypothesis/Finding counts, remaining errors, final state.
- Modify: additional tests only when Task 1–2 regression reveals a concrete gap.

**Interfaces:** Consumes Task 1–2 API and the existing CLI; produces no new runtime interface.

- [ ] **Step 1: Add a failing regression for any newly found compatibility defect.** Run it and confirm expected RED before fixing production code.
- [ ] **Step 2: Run focused suites, full `pytest`, Ruff and mypy.** Expected: zero failures; report skipped tests and any warnings separately.
- [ ] **Step 3: Review diff against spec and record validation instructions in README/note.** Expected: no secret or local path in committed docs.
- [ ] **Step 4: Commit tests/docs.** `docs: explain file-scoped AST coverage and Dify verification`.
- [ ] **Step 5: Only after tests pass, start one new Dify analysis at a pinned commit using a separate profile with cumulative limits set to `unlimited`.** Do not run additional live LLM tests. Record actual status and counts, not an assumed COMPLETE/finding.

