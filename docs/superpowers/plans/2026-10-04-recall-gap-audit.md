# Recall Gap Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Locate the first pipeline stage that misses each code-vetted Python vulnerability, without telling the analysis Agent the answer or altering saved analyses.

**Architecture:** A standalone, read-only evaluator loads a pinned oracle outside the target checkout, joins candidate decisions and candidate→hypothesis links with exact checkpoints, and emits per-case stage states and aggregate counts. It does not make an LLM call or infer a vulnerability from a report title. A measured product fix gets its own concrete follow-up task/plan once the first missing stage is known.

**Tech Stack:** Python 3.12, SQLite read-only URI, Pydantic stage/candidate contracts, pytest, PowerShell.

**Spec:** `docs/superpowers/specs/2026-10-04-recall-first-grouped-reports-design.md`

## Global Constraints

- Treat Python product code only; excluded tests and out-of-scope code are not negative evidence.
- Never mutate existing DB/artifacts, start an analysis, or send oracle descriptions to an Agent prompt.
- Use a separate, manually code-vetted oracle at a pinned commit; incomplete analysis means `INCOMPLETE`, not a measured miss.
- Keep raw candidate/Finding counts distinct from unique vulnerability recall and grouped report counts.
- Use the repository `.venv` and short `build/.t` pytest temp path on Windows.

## File map

- `src/sastsimi/evaluation/recall_audit.py`: typed oracle and read-only stage attribution; no runtime writes.
- `src/sastsimi/evaluation/__init__.py`: package marker.
- `tools/recall_audit.py`: one-line PowerShell-friendly CLI wrapper for JSON output.
- `tests/unit/evaluation/test_recall_audit.py`: synthetic DB cases for all stage boundaries.
- `docs/validation/2026-10-04-recall-gap-baseline.md`: vetted oracle and measured baseline, including limitations.

## Review Focus

1. Candidate exists but is `EXCLUDE`: attribute the gap to Discovery, not static collection (Task 1 test).
2. Candidate and hypothesis exist but PoC/execution fails: report execution error, not false negative (Task 1 test).
3. A partially completed analysis: report `INCOMPLETE`, never a recall denominator (Task 1 test).
4. Multiple candidates refer to one oracle flaw: count one ground-truth case (Task 1 test).
5. Oracle commit differs from analyzed commit: refuse comparison, not zero detected (Task 1 test).

---

### Task 1: Read-only, stage-attributed evaluator

**Files:**
- Create: `src/sastsimi/evaluation/__init__.py`
- Create: `src/sastsimi/evaluation/recall_audit.py`
- Test: `tests/unit/evaluation/test_recall_audit.py`

**Interfaces:**
- `OracleCase(case_id: str, cwe: str, path: str, source_line: int | None, sink_line: int, rationale: str)` and `Oracle(repository: str, commit: str, cases: tuple[OracleCase, ...])` are immutable typed inputs. Each case may additionally carry manually vetted candidate/hypothesis IDs and `finding_inventory_reviewed`. The rationale is output-only and never handed to the runtime. The flag is true only after checking all Finding paths, including free exploration, against that case.
- `audit_analysis(data_dir: Path, analysis_id: str, oracle: Oracle) -> dict[str, object]` opens the existing SQLite DB in `mode=ro`, paginates `simple_static_candidates`, reads candidate links and checkpoints, and returns each case's matched and vetted IDs, decisions, first missing/failing stage, and completion status. File/line proximity is only `POSSIBLE`; `DETECTED` needs a manually vetted hypothesis plus current, hash-verified Finding/PoC/report closure. `MISSED` additionally needs complete static/product scope evidence and reviewed free-exploration Finding inventory.

- [ ] **Step 1: Write failing tests** for FLOW at a pinned sink, HINT at the sink and ENTRY_POINT at a pinned source, `EXCLUDE`, `UNDECIDED`, linked hypothesis, verified Finding, failed PoC, partial/static gap, commit mismatch, two candidates for one case, and a missing DB table. Assert that a lone entry point is only `POSSIBLE`, the audit leaves the DB byte-for-byte unchanged, and absent closure returns `INCOMPLETE`.
- [ ] **Step 2: Run the focused test.** ` $env:PYTHONPATH='src'; ..\..\.venv\Scripts\python.exe -m pytest -q tests/unit/evaluation/test_recall_audit.py -p no:cacheprovider --basetemp build/.t --tb=short ` must fail on the absent evaluator.
- [ ] **Step 3: Implement the immutable oracle parser and `audit_analysis` interface.** Use SQLite URI `mode=ro`; do not construct `SimpleCheckpointStore` because its initializer writes. Parse existing contract JSON, require exact analysis/commit identity, and emit explicit `UNKNOWN` where evidence cannot be linked safely.
- [ ] **Step 4: Run the focused test and existing candidate/resume tests; require all pass.**
- [ ] **Step 5: Commit the evaluator and tests.**

### Task 2: Safe CLI and code-vetted baseline

**Files:**
- Create: `tools/recall_audit.py`
- Test: `tests/unit/evaluation/test_recall_audit_cli.py`
- Create: `docs/validation/2026-10-04-recall-gap-baseline.md`

**Interfaces:**
- CLI usage: `python tools/recall_audit.py --data-dir PATH --analysis-id ID --oracle JSON_PATH`; stdout is JSON containing `analysis_id`, `oracle_commit`, `cases`, and `counts`. It never prints source snippets or prompt text.
- The saved Antony Flask and Python Vulns GNU trials are candidate sources for the baseline, not automatically accepted truth. Verify each claimed case against the pinned source and existing PoC/result before adding it to an oracle stored outside analyzed checkouts.

- [ ] **Step 1: Write failing CLI tests** for valid oracle JSON, mismatched commit, missing analysis, malformed oracle, and zero writes to a read-only database copy.
- [ ] **Step 2: Run those tests; confirm missing CLI behavior fails.**
- [ ] **Step 3: Implement CLI wrapper and validate oracle schema.** Run no LLM or scanner; exit nonzero on identity mismatch/corrupt data.
- [ ] **Step 4: Vet the two pinned trial sources and run the audit read-only.** Record exact case-level state, candidate/decision/hypothesis counts, earliest observed gap, and whether each analysis is complete; do not label incomplete trial outcomes as false negatives.
- [ ] **Step 5: Commit the CLI, tests, and evidence-based baseline.**

## Self-review

- The evaluator itself cannot claim improved recall. Once Task 2 identifies a reproducible product-code miss, a separate concrete TDD plan names that exact stage and fix, then implementation and holdout measurement follow in the same user-authorized workflow.
- Every case is tied to a pinned commit and source proof; incomplete analyses stay outside the recall denominator.
- The plan touches no saved analysis and sends no oracle to the runtime.
