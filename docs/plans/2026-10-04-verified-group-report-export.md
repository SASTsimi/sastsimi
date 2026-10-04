# Verified Group Report Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Export one submission-review bundle per provably identical Finding flow while preserving every original Finding, PoC, report and direct link.

**Architecture:** Reuse PR #213's read-only verified Finding groups and the existing per-Finding bundle integrity checks. A pure builder creates a bounded deterministic bilingual group archive from independently validated member bundles; shared projection serves CLI and dashboard without changing checkpoints or verdicts. The main branch's tabbed dashboard outputs tab exposes group exports and keeps raw member links.

**Tech Stack:** Python 3.12, SQLite, Pydantic contracts, ZIP, pytest, vanilla dashboard JS, PowerShell.

**Spec:** `docs/plans/2026-10-04-recall-first-grouped-reports-design.md`

## Global Constraints

- Bring fetched `origin/main` (includes dashboard #212) into the isolated branch before product edits, resolve only actual conflicts, and run baseline focused tests.
- A group archive requires current `PROVEN_SAME_FLOW` members, valid per-Finding bilingual bundles, matching structured target/CWE/package/version/severity/scope/permission facts, and no stale or corrupt closure.
- Never delete, overwrite, or hide original F-NNN, individual ZIPs, PoCs or evidence; an undetermined group remains a singleton.
- Grouping does not change `COMPLETE`/`PARTIAL`/`BLOCKED`, confirmed, or disclosure permission.
- A group archive is a human-review draft, not automatic permission to report.
- Use `.venv` from the repository root and a short `build/.t` pytest temp path on Windows.

## File map

- `src/sastsimi/reporting/grouped_bundle.py`: pure validated group-report ZIP builder; no DB or filesystem write.
- `src/sastsimi/simple_runtime/group_report_projection.py`: collect current eligible member bundles with existing integrity checks.
- `src/sastsimi/composition/simple_runtime_composition.py`: group export method and atomic local output.
- `src/sastsimi/interfaces/cli/main.py`: `report export-group` command.
- `src/sastsimi/dashboard/models.py`, `query.py`, `server.py`, `static/app.js`: additive group bundle URL and outputs-tab access on current main UI.
- Focused unit, integration, CLI and dashboard tests; `README.md` and `docs/usage.md`.

## Review Focus

1. Same sink/CWE but different request key or branch: separate reports, no group archive (Task 2 test).
2. Member metadata disagree on severity/version/scope or lack a required fact: explicit unavailable reason, no chosen more-permissive value (Task 1 test).
3. One member ZIP/PoC/ref is stale or altered after resume: no group archive; original safe member access remains (Task 2 test).
4. Main #212 outputs tab and presentation ZIP: group links and paths agree with its summary, while explicit raw report selection is unchanged (Task 4 test).
5. Legacy analysis without a verified anchor: individual report still exports and no group archive is advertised (Task 2/3 tests).

---

### Task 1: Deterministic group bundle contract

**Files:**
- Create: `src/sastsimi/reporting/grouped_bundle.py`
- Test: `tests/unit/reporting/test_grouped_bundle.py`

**Interfaces:**
- `GroupSourceBundle(display_id: str, files: Mapping[str, bytes], provenance: Mapping[str, object])` contains bytes already checked by `verified_report_bundle`.
- `build_group_bundle(group_id: str, members: Sequence[GroupSourceBundle]) -> bytes` requires two or more distinct sorted F-NNN IDs and returns a deterministic ZIP with root `report_en.md`, `report_kr.md`, `evidence/group-manifest.json`, and member files under `members/<F-NNN>/`. The representative is the lowest F-NNN. The manifest records member IDs, source hashes and exact group ID, but no prompt or private local path. It appends the same factual membership appendix to both root reports; it never combines member impact prose.
- `GroupBundleUnavailable(code: str)` is the typed fail-closed result for fact conflicts, missing files, unsafe path/content and size overflow. Set explicit limits of 1 MiB per member file and 32 MiB for the complete uncompressed group; overflow never silently drops a member.

- [ ] **Step 1: Write failing tests** for compatible members producing one bilingual ZIP, stable bytes regardless of input order, each PoC/evidence retaining its member path, conflicting structured provenance, missing mandatory report/PoC, unsafe paths/local URLs, and size overflow.
- [ ] **Step 2: Run `test_grouped_bundle.py`; require the missing interface failure.**
- [ ] **Step 3: Implement the pure builder.** Use `ReportBundleManifest`/`read_bundle_file` outputs supplied by Task 2, deterministic ZIP metadata, bounded in-memory assembly, and `assert_safe_provider_text`/public report projection as appropriate. Do not infer missing severity or affected versions.
- [ ] **Step 4: Run the focused tests and existing per-Finding bundle tests; require all pass.**
- [ ] **Step 5: Commit the builder and tests.**

### Task 2: Recheck current members before group export

**Files:**
- Create: `src/sastsimi/simple_runtime/group_report_projection.py`
- Test: `tests/simple_runtime/test_group_report_projection.py`

**Interfaces:**
- `current_group_bundle(run: SimpleAnalysisRun, checkpoints: Sequence[StageCheckpoint], group: FindingGroup, *, data_dir: Path, database_path: Path) -> bytes` recomputes the trusted group and requires `group.status == "PROVEN_SAME_FLOW"`, at least two identical current members and current `REPORT_DONE` closures. For each member, reuse `SimpleArtifactRepository.verified_report_bundle`, exact Finding/PoC/technical/scope closure, and `safe_public_report`; convert verified member files/provenance into Task 1 `GroupSourceBundle`.
- A failure is `GroupBundleUnavailable` with a stable code; it never edits a checkpoint or returns an incomplete archive.

- [ ] **Step 1: Write failing integration tests** using real checkpoints/artifact refs for two current members, same sink with different input key/branch, a stale `REPORT_DONE`, changed report hash, missing manifest, changed source hash, scope conflict, and legacy singleton. Check DB/checkpoint bytes unchanged.
- [ ] **Step 2: Run the focused test; confirm expected failure.**
- [ ] **Step 3: Implement `current_group_bundle` with the existing per-Finding verifier.** Do not trust group rows from client input; use server-side projection and exact ref matching.
- [ ] **Step 4: Run Task 1–2 and existing resume/report integrity tests; require all pass.**
- [ ] **Step 5: Commit projection and tests.**

### Task 3: CLI group export without changing individual commands

**Files:**
- Modify: `src/sastsimi/composition/simple_runtime_composition.py`
- Modify: `src/sastsimi/interfaces/cli/main.py`
- Test: `tests/unit/interfaces/test_public_simple_cli.py`
- Test: `tests/simple_runtime/test_static_to_report_resume.py`

**Interfaces:**
- `SimpleRuntimePublicApplication.export_report_group(analysis_id: str, group_id: str) -> str` recomputes the eligible group for that analysis, invokes Task 2, and atomically writes under `reports/<analysis-id>/groups/<group-id>/<archive-sha256>/bundle.zip`; return only the relative safe path.
- CLI `sastsimi report export-group <analysis-id> <group-id> --format json` returns `analysis_id`, `group_id`, `bundle_path`. Existing `report show/export F-NNN` behavior is unchanged.

- [ ] **Step 1: Write failing CLI/composition tests** for valid group ZIP, unknown/undetermined group, path traversal ID, repeat export stable bytes, stale member after resume, and original F-NNN export unchanged.
- [ ] **Step 2: Run focused tests; confirm missing command/method failure.**
- [ ] **Step 3: Add the method and parser dispatch.** Validate IDs, keep writes inside `data_dir/reports`, use atomic replacement, and do not allocate new F-NNN IDs.
- [ ] **Step 4: Run CLI and resume tests; require all pass.**
- [ ] **Step 5: Commit CLI/composition changes and tests.**

### Task 4: Adapt the merged tabbed dashboard

**Files:**
- Modify: `src/sastsimi/dashboard/models.py`
- Modify: `src/sastsimi/dashboard/query.py`
- Modify: `src/sastsimi/dashboard/server.py`
- Modify: `src/sastsimi/dashboard/static/app.js`
- Test: `tests/unit/dashboard/test_query.py`
- Test: `tests/unit/dashboard/test_frontend_contract.py`
- Test: `tests/integration/dashboard/test_server.py`

**Interfaces:**
- `DashboardQuery.group_bundle_bytes(analysis_id: str, group_id: str) -> bytes` invokes the same current group projection and builder but performs no disk write; serve through `/api/analyses/<id>/groups/<group-id>/bundle.zip` with attachment MIME type.
- The `outputs` tab JSON includes verified groups and a group URL only when Task 2 succeeds. Raw report URLs remain present. `presentation/summary.json` and the default analysis ZIP selection list the same representative/member paths; explicit report-ID ZIP selection stays raw.

- [ ] **Step 1: Write failing query/server/JS contract tests** for group endpoint, tabs output payload, default and explicit ZIPs, presentation summary consistency, legacy fallback, and denial of stale/unknown group IDs.
- [ ] **Step 2: Run focused tests; confirm missing group URL/endpoint failure.**
- [ ] **Step 3: Wire the shared builder into query/server and pass groups to merged `renderOutputs`/`renderReports`.** Avoid a second independent grouping rule or report eligibility calculation.
- [ ] **Step 4: Run focused dashboard and integration tests; require all pass.**
- [ ] **Step 5: Commit dashboard changes and tests.**

### Task 5: Documentation and final verification

**Files:**
- Modify: `README.md`
- Modify: `docs/usage.md`
- Create: `docs/validation/2026-10-04-grouped-report-replay.md`

- [ ] **Step 1: Replay saved verified Findings read-only** and record raw Finding count, proven groups, exportable groups and abstentions. Do not force a group to improve the count.
- [ ] **Step 2: Document one-line PowerShell CLI export, dashboard group download, original member links, and the distinction between grouped reports and reportability.**
- [ ] **Step 3: Run Ruff, mypy, focused suite and full pytest; record exact totals.**
- [ ] **Step 4: Request independent review focused on false merges, group ZIP safety and merged dashboard compatibility; fix findings and rerun affected tests.**
- [ ] **Step 5: Push only after verification and update the existing PR or create a stacked PR according to the resulting main/branch relationship; attach any newly created PR.** Do not merge unless separately authorized.

## Self-review

- Every spec requirement for report consolidation maps to Tasks 1–5; recall measurement is separately planned.
- Old reports and direct links remain authoritative; no new DB migration or analysis stage is introduced.
- The five Review Focus cases each have a named test in the owning task.
