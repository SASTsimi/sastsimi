# Verified Finding Grouping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Present one group for Findings proven to share the same Python input-to-sink root cause while retaining every original Finding, PoC, report, candidate origin, and direct link.

**Architecture:** Derive a conservative, versioned Python AST flow key from pinned source and verified proposal evidence. Project groups from current successful Finding checkpoints at read time; do not add a stage, migrate the DB, rewrite reports, or change verdicts. CLI and dashboard gain additive group fields while raw Finding/report collections stay intact.

**Tech Stack:** Python 3.12, `ast`, Pydantic contracts, SQLite read-only queries, pytest, PowerShell.

**Spec:** `docs/decisions/ADR-018-verified-finding-grouping.md`

## Global Constraints

- No new LLM call, dependency, pipeline stage, checkpoint version, or DB migration.
- Only current `TRUE` Finding closures with validated PoC and accepted technical gate may be grouped.
- Exact tested workspace/commit and AST-manifest source SHA-256 are required for automatic matching.
- Different input keys, sink callsites/arguments, routes, or proven def-use paths remain separate. Ambiguous or unsupported flows remain singleton with `GROUPING_UNDETERMINED`.
- Preserve old Finding IDs, raw counts, PoC/report bundles, direct URLs, ZIP export, candidate origins, and resume data.
- Grouping never changes `COMPLETE`, `PARTIAL`, `BLOCKED`, `confirmed`, scope permission, or external disclosure status.
- Run PowerShell tests using the project `.venv`, `PYTHONPATH=src`, and a short `build/.t` pytest base directory to avoid Windows path-length failures.

## File map

- `finding_flow.py`: guarded Python source read and narrow AST flow identity, no DB access.
- `finding_groups.py`: immutable grouping of already verified evidence, no filesystem or DB access.
- `finding_group_projection.py`: read-only loading and exact closure checks for CLI/dashboard callers.
- CLI composition and dashboard query/JS: additive projection and visual grouping; keep raw report routes/export.

## Review Focus

1. Same sink and CWE reached from two request keys must remain two groups (Task 1 test).
2. A nearby surface context naming a different route must resolve to the *actual cited* input and sink, not its seed route (Task 1 test).
3. Changed pinned source or a missing AST-manifest hash must abstain, never merge (Task 1 test).
4. Repeated read/resume must keep group IDs and counts stable without touching checkpoints (Task 2 test).
5. Dashboard ZIP and direct F-NNN URLs must still expose every member report and PoC (Task 4 test).

---

### Task 1: Resolve an exact Python flow identity

**Files:**
- Create: `src/sastsimi/simple_runtime/finding_flow.py`
- Modify: `src/sastsimi/simple_runtime/ast_facts.py` only if a shared guarded source reader is needed
- Test: `tests/unit/simple_runtime/test_finding_flow.py`
- Test fixture: `tests/fixtures/finding_groups/` with minimal, non-secret route/function snippets from the two saved trials

**Interfaces:**
- Produce `FlowAnchor` (frozen value: route/function, source file/line/access/key, ordered def-use nodes, sink file/line/callee/argument, CWE) and `resolve_flow_anchor(workspace: Path, path: str, expected_sha256: str, proposal: Mapping[str, object], cwe: str, flow_trace: Mapping[str, object] | None = None) -> FlowAnchor | None`.
- `None` means unsupported, ambiguous, or unproven; source integrity mismatch raises `FlowEvidenceInvalid`. The caller converts either into an undetermined singleton, never an equality key.
- Reuse the AST manifest's per-file `source_sha256` from `index_ast_manifest`; verify a regular, non-symlink, contained file and its bytes before parsing.

- [ ] **Step 1: Write failing tests** using hand-checked minimal fixture source for Antony-style `/ping` proposals with different wording and code-location subsets resolving to equal anchors; GNU-style JSON `cmd` assignment chain resolving equally; distinct query keys, branches, sink arguments/callsites, and neighboring `/upload` surface anchors resolving separately or to the actual `/ping` code; unrecognized/multiple reaching sources or a contradictory CodeQL trace returning `None`; mismatched source SHA raising `FlowEvidenceInvalid`.
- [ ] **Step 2: Run `test_finding_flow.py` and observe the expected missing-interface failure.** Use `python -m pytest -q tests/unit/simple_runtime/test_finding_flow.py -p no:cacheprovider --basetemp build/.t --tb=short` with `PYTHONPATH=src` and the project `.venv`.
- [ ] **Step 3: Implement the minimal bounded AST backward def-use walk.** Anchor the sink at a cited callsite inside the actual containing function, trace one sink argument through preceding local assignments to one request access or endpoint parameter, and include relevant branch identities in the path. Do not infer across dynamic dispatch, unresolved calls, multiple reaching definitions, or source/sink text alone. Check any available CodeQL trace for contradictory endpoints; disagreement returns `None`.
- [ ] **Step 4: Run the focused test and existing `tests/unit/simple_runtime/test_ast_facts.py`; require all pass.**
- [ ] **Step 5: Commit the resolver and tests.**

### Task 2: Group only current verified Findings and preserve provenance

**Files:**
- Create: `src/sastsimi/simple_runtime/finding_groups.py`
- Test: `tests/unit/simple_runtime/test_finding_groups.py`

**Interfaces:**
- Consume `FlowAnchor` from Task 1 and immutable `VerifiedFindingMember` values: analysis/workspace/commit, display ID, Finding ref, hypothesis ID, validated PoC ref, proposal ref, CWE ref, candidate IDs/origins, scope status, and anchor or undetermined reason.
- Produce `FindingGroupProjection(groups: tuple[FindingGroup, ...], raw_count: int, visible_group_count: int, undetermined_count: int)` via `group_verified_findings(members: Sequence[VerifiedFindingMember]) -> FindingGroupProjection`.
- `FindingGroup` carries a versioned SHA-256 ID, smallest-numbered representative F-NNN, sorted member IDs and provenance, and `PROVEN_SAME_FLOW` or `GROUPING_UNDETERMINED`. Never mutate member evidence.

- [ ] **Step 1: Write failing tests** for equivalent cross-engine/attack-surface anchors grouping, distinct anchors remaining separate, undetermined members remaining singleton, candidate origins and PoC refs surviving in members, mixed scope statuses not upgrading permission, stable group IDs/order when input order changes, and repeated projection having no stateful accumulation.
- [ ] **Step 2: Run `test_finding_groups.py` and observe failure because projection is absent.**
- [ ] **Step 3: Implement immutable grouping.** Key only by the versioned exact `FlowAnchor` plus workspace/commit/CWE; use a per-Finding singleton key for `None`; choose the lowest F-NNN as representative. Do not use title, sink name, CWE, or line alone.
- [ ] **Step 4: Run Task 1 and Task 2 tests; require all pass.**
- [ ] **Step 5: Commit the grouping model and tests.**

### Task 3: Load exact eligible members from current checkpoints

**Files:**
- Create: `src/sastsimi/simple_runtime/finding_group_projection.py`
- Test: `tests/simple_runtime/test_finding_group_projection.py`

**Interfaces:**
- Produce `project_current_finding_groups(run: SimpleAnalysisRun, checkpoints: Sequence[StageCheckpoint], eligible: Mapping[str, StoredDataRef], *, data_dir: Path, database_path: Path) -> FindingGroupProjection` for both CLI and dashboard.
- `eligible` is the caller's already-current F-NNN→Finding-ref mapping. The loader rechecks exact Finding/verification/PoC/technical-gate closure and original proposal references; resolves candidate origins from `simple_static_candidates` by scoped candidate ID using SQLite `mode=ro`; looks up per-file SHA in the validated AST manifest. Use `FindingDisplayIdStore.resolve_existing`, not its allocating method, on dashboard reads. Legacy/missing provenance remains singleton.

- [ ] **Step 1: Write failing integration tests** with real artifact/checkpoint records for two independently verified hypotheses on one flow, stale/failed/non-TRUE/gate-rejected members excluded, old proposal without candidate ID kept singleton, changed AST bytes kept undetermined, repeated projection and resume producing identical groups, and a corrupt required Finding ref failing closed without turning it into a match.
- [ ] **Step 2: Run `test_finding_group_projection.py` and observe the expected missing-interface failure.**
- [ ] **Step 3: Implement the loader using bounded artifact reads and scoped read-only SQL.** Reuse `SimpleArtifactRepository`, `index_ast_manifest`, `FindingDisplayIdStore` resolution, and existing stage validation; no new writes or schema. Source-path errors and absent proof become undetermined; corrupt Finding closure cannot be presented as a valid group.
- [ ] **Step 4: Run Tasks 1–3 tests plus `tests/simple_runtime/test_static_to_report_resume.py`; require all pass.**
- [ ] **Step 5: Commit loader and tests.**

### Task 4: Add CLI and dashboard group presentation without hiding raw artifacts

**Files:**
- Modify: `src/sastsimi/composition/simple_runtime_composition.py` (`result`)
- Modify: `src/sastsimi/interfaces/cli/public.py` (text result/status display)
- Modify: `src/sastsimi/dashboard/models.py` (`AnalysisSummaryView`, `AnalysisDetailView`)
- Modify: `src/sastsimi/dashboard/query.py` (`_reports`, analysis detail projection)
- Modify: `src/sastsimi/dashboard/static/app.js` (grouped report cards)
- Test: `tests/unit/interfaces/test_public_simple_cli.py`
- Test: `tests/unit/dashboard/test_query.py`
- Test: `tests/unit/dashboard/test_frontend.py`
- Test: `tests/integration/dashboard/test_server.py`

**Interfaces:**
- Keep `finding_count` and `findings` as raw exact Finding counts/IDs. Add `finding_group_count`, `finding_group_undetermined_count`, and `finding_groups` with representative/member F-NNN IDs and provenance to the public result and dashboard detail. A summary lacking an eligible report may expose `None` rather than claim zero groups.
- Keep `AnalysisDetailView.reports`, `_reports()`, `report_path()`, and bundle ZIP membership raw and unchanged. JavaScript visually folds only proven members beneath the representative card, with direct links to every member's report, PoC, and attachments; older responses without `finding_groups` keep the current list.

- [ ] **Step 1: Write failing CLI and dashboard tests** for separate raw/group/undetermined counts, one visible card with all member links, singleton uncertainty, every F-NNN direct report path, all raw reports in ZIP export, and legacy dashboard JSON fallback.
- [ ] **Step 2: Run those exact tests and observe failures for missing group fields/presentation.**
- [ ] **Step 3: Wire Task 3 projection into public result and dashboard detail using each caller's already-current eligible Finding/report set.** Keep existing gate/currentness filters authoritative and avoid new allocation during dashboard read.
- [ ] **Step 4: Update text CLI and browser view, without changing underlying report/bundle routes.**
- [ ] **Step 5: Run the focused CLI/dashboard/integration tests; require all pass.**
- [ ] **Step 6: Commit presentation and tests.**

### Task 5: Replay, document, and verify before PR

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture/gates-chaining-reporting.md`

**Interfaces:**
- The read-only trial replay reports raw/group/undetermined counts from saved Antony and GNU analyses; it never modifies their DB or artifacts. Committed focused fixture tests from Task 1 cover behavior in CI. Do not hard-code repository-specific routes in production code.

- [ ] **Step 1: Run the read-only projection against the saved Antony and GNU trial IDs** and record raw/group/undetermined counts. If a member lacks proof, retain singleton status rather than broadening the key to hit a target count.
- [ ] **Step 2: Document raw versus grouped counts, preserved attachments, abstention, and non-equivalence to reportability/coverage.**
- [ ] **Step 3: Run `ruff check`, `mypy`, focused tests, then bare project `pytest` with short pytest base path and record exact pass/fail/skip totals.** Investigate regressions before claiming success.
- [ ] **Step 4: Perform independent review focused on false merges, read-only behavior, and old-data/resume compatibility.** Resolve findings and rerun affected tests.
- [ ] **Step 5: Commit docs, push the branch, create the PR against current `main`, attach it to this chat, and report CI status.** Do not merge unless separately requested.

## Self-review notes

- Each spec section maps to Tasks 1–5; no stage/version/DB change is planned.
- The five Review Focus conditions have explicit tests in Tasks 1, 2, 3, or 4.
- The plan favors conservative under-grouping over a false merge; trial replay cannot override that safety rule.
