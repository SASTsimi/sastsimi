# Versioned child-evidence revalidation implementation plan

**Goal:** Revisit linked terminal `HOLD` children after a verified v10 Python
surface certificate without altering old checkpoints or manufacturing 100%.

**Spec:** `docs/plans/2026-10-15-versioned-child-evidence-revalidation-design.md`

**Working branch:** `codex/hold-child-evidence`, isolated from the live A-001
worker. Use the repository Python 3.12 `.venv`, pytest, Ruff and mypy.

## Invariants

- Do not mutate the live A-001 DB or old v9/v10/child artifacts while coding.
- A saved LLM response or source navigation alone cannot resolve a HOLD.
- Terminal `TRUE` requires the existing supported execution and validated PoC
  lineage. A provider/tool failure is `ERROR`, not `FALSE` or `STILL_HOLD`.
- Every linked old HOLD is an obligation even if v10 calls its surface covered.
- Changed child/source/commit/scope/progress leaves explicit pending/blocking
  evidence; no fallback to old COMPLETE or static-only report.
- Add tests before each production change; verify RED then GREEN.

## Task 1 — Inventory, frozen plan and fail-closed progress

**Files:** new `surface_child_evidence_v11.py`; `models.py`, `store.py`;
unit tests for inventory/store.

1. Write tests for all linked initial/PoC/final HOLDs, multiple children on
   one surface, an already-COVERED parent, an unrelated child, and a child
   appearing or changing after pin. RED.
2. Reuse `_related_child_ids` to enumerate all linked checkpoint identities.
   Hash canonical old checkpoints/refs, v10 predecessor and source; create a
   content-addressed plan. A distinct progress table keys analysis/scope,
   plan, child ID, stage and old checkpoint hash with CAS state
   `PENDING/RUNNING/RESOLVED/STILL_HOLD/ERROR`.
3. Pin and set `RUNNING` successor state in one transaction. Reject changed
   parent, duplicate writer, wrong scope, or missing refs. GREEN.

## Task 2 — Bounded evidence attempt, no verdict laundering

**Files:** new `surface_child_revalidation_v11.py`; minimal adapter in
`stages.py` or `application.py`; focused mock-provider tests.

1. RED tests: old prerequisite merely repeated, free-text LLM assertion,
   missing local runtime proof, unsupported PoC, and a false `TRUE` all stay
   unresolved. A source-bound local fixture plus exact supported PoC/final
   evidence may resolve. Final FALSE requires independent code/negative
   evidence; an existing terminal PoC INCONCLUSIVE retains its verified
   non-reportable semantics. Test timeout/auth/output-schema errors as ERROR.
2. Reuse the existing Verification Agent schemas and provider timeout/retry
   rather than adding another provider role. Give it bounded old claims,
   source/route proof and exact refs. Validate output and classify against
   deterministic artifact/source/runtime checks. Execute only safe local
   fixture/test steps already supported by PoC infrastructure; if a required
   step cannot be completed, save `STILL_HOLD` with reason, not RESOLVED.
3. Save separately keyed attempt artifacts and metadata-only call logs. A
   `RUNNING` attempt with uncertain child-process cleanup is blocked, never
   automatically duplicated. Resume skips successful attempts. GREEN.

## Task 3 — Successor coverage and independent replay

**Files:** new `surface_coverage_v9.py`, `surface_coverage_v9_read.py`;
`surface_coverage_v8_read.py`, `surface_proof_read.py`; unit/integration tests.

1. RED tests: 42/43 covered plus one unresolved HOLD stays PARTIAL; a v10
   COVERED row with an old HOLD still has a child obligation; two children
   need two verified resolutions; tampered refs or a new child fail closed.
2. Allow v8 reader to replay a *paired* frozen predecessor terminal/root
   from the v11 plan, like v7 reader. Verify exact pinned v9 progress and
   reject new/changed progress. Recompute v8, then v11 from saved children;
   never trust stored counts. Preserve every unrelated gap. GREEN.

## Task 4 — Resume, dashboard, CLI and bilingual reports

**Files:** `application.py`, `store.py`, `progress/projector.py`,
`dashboard/query.py`, `artifacts.py`, `stages.py`,
`reporting/coverage_disclosure.py`, `reporting/bilingual_bundle.py`;
consumer tests.

1. RED tests: pinning a successor suspends old 100%/COMPLETE and old report;
   partial child work shows pending/resolved/HOLD/ERROR counts; an unknown
   proof version fails closed; repeated resume does not duplicate work.
2. Route the existing `--enrich-saved-surface-evidence` entry after v10 to
   v11. Promote terminal/root only after independent read replay. Surface
   parent may be COMPLETE, but child obligations control final COMPLETE.
   Reports and dashboard distinguish Python coverage from child disposition
   and retain old reports as historical, not current. GREEN.

## Task 5 — Verification, live observation and integration

1. Run focused suites, then entire pytest, Ruff, mypy, docs validation and
   source-secret scan. Obtain independent code review; address real issues.
2. Before same-ID A-001 resume, confirm the existing worker finished or is
   safely stopped, its Codex child process cleanup is proven, and Docker/auth
   are available. Never duplicate the live lease or edit SQLite directly.
3. Resume the same ID only from the saved checkpoint. Report exact v9/v10/v11
   counts, PoC and child outcomes. If evidence remains insufficient, leave
   PARTIAL and explain which obligations remain. Do not claim confirmed
   findings absent validated PoC, gates and report evidence.
4. Rebase/cherry-pick the completed branch onto latest `main` without
   overwriting user changes, then create a PR only after checks pass. Attach
   the PR artifact and report the CI state accurately. No automatic main
   merge unless the previously requested conditions are genuinely met.
