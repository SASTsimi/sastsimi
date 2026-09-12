# T12 CWE, Gates, Finding and Reporter Completion Record

- Status: `IMPLEMENTATION_COMPLETE`
- Branch: `impl/t12-gates-reporting`
- Parent plan: [Complete Implementation Plan Task 12](../2026-09-08-sastsimi-complete-implementation.md#task-12-cwe-two-gates-finding-and-reporter)
- Delivery: [PR #164](https://github.com/SASTsimi/sastsimi/pull/164)

## Goal

Run policy preparation from an exact Program Catalog selection, then turn a current
validated TRUE result into a current CWE label, Technical review, Rule Scope review,
Finding, and redacted `ReportDraft`. Automation stops at the draft; submission remains
outside T12.

## Implemented boundary

- `PolicyPreparationService` fixes one run-local `RunPolicyState` through the official
  source, parser, collection, and exact cache provenance. The production HTTP adapter
  enforces pinned HTTPS source and response limits before parsing.
- CWE, Technical, Rule Scope, Finding normalization, and Reporter execute as typed work
  with current attempt, verification generation, exact input, action, and invocation
  provenance checks.
- Technical `REVISE` preserves the verdict and returns the same owner to a fresh
  generation. Stale gate, policy, Finding, and report inputs fail closed.
- Reporter content is an immutable canonical artifact. A successful hypothesis-scoped
  report transition atomically publishes the exact `ReportDraft` and advances its
  `ReportProcessState` to `DRAFTED`.
- Final analysis inventory derives `report_draft_refs` from current `DRAFTED`
  `ReportProcessState` records; callers cannot omit or fabricate the exact set.
- A post-T12 output extension renders the exact current closure as human-readable
  Markdown at `<data-dir>/reports/<analysis_id>/<finding_id>.md`. The `reports`,
  `report show`, and `report export --format markdown` commands never treat an old
  file as current data; each read rechecks the database pointers and redaction proof.

## Safety and correctness boundary

- Provider output cannot mint runtime metadata, identifiers, work state, or current
  pointers. Trusted services revalidate exact artifacts and publish domain records.
- Policy source content or source-check substitution is rejected before parser, policy,
  or report publication. The exact `PREPARING` head is withdrawn with a state-version
  CAS while its immutable audit history remains retained.
- Rule Scope restrictions are preserved as evidence-backed review output; they are not
  silently converted into primitive admission or discarded from the report closure.
- `ReportDraft` requires current TRUE verification, validated PoC, accepted Technical
  review, current Rule Scope result, policy closure, finding index, redaction, and exact
  evidence locations. No submit action is produced.
- Markdown export resolves those same exact records, the validated PoC candidate, its
  exact successful `AgentLog` event and `SandboxCommandRecord`, and the used
  `CREATE_REPORT_DRAFT` decision with `REDACTION=PASS`. Candidate content and the
  actual execution command are shown separately. Missing/stale refs, unsafe text,
  broken execution provenance, or a path/symlink escape fails closed before terminal
  output or write.
- Fake and production paths share the public runtime, storage, action, work, and
  invocation boundaries. Fake-only output construction does not bypass publication
  authority.

## Focused verification

The Ubuntu and Windows CI failure set was reproduced and then rerun as the same seven
focused cases:

- TRUE pipeline exact report closure
- chaining no-match finalization
- Technical REVISE generation finalization
- persisted result and report reload
- finalization omission rejection and exact retry
- policy source content mismatch
- policy source-check mismatch

Result: `7 passed in 1517.22s`.

Changed-file quality gates:

- Ruff lint: `All checks passed!`
- Ruff format: `6 files already formatted`
- mypy strict configuration: `Success: no issues found in 6 source files`

The complete repository suite is intentionally left to the PR CI gate; it was not
rerun locally during this focused Blocker/High correction.
