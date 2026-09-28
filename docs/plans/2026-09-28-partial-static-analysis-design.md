# Partial static analysis without false completion

## Intent and scope

Large repositories must reach hypothesis, Pro/Con, PoC, and reporting when a
trustworthy *subset* of the configured static scan has completed. Unverified
file/rule combinations and unsupported product files remain explicit, durable
unknowns. A confirmed Finding never means that the repository-wide scan is
complete. This is a bounded change to the existing simple runtime; it does
not replace OpenGrep, Semgrep fallback, CodeQL, AST, or Agent prompts.

## Static evidence boundary

- Keep the pinned commit, selected product scope, rule-plan fingerprint, and
  exact per-attempt execution ledger. Reuse only hash-validated evidence with
  the same identity and fingerprint. Retry only unverified pairs on resume.
- Run OpenGrep and its existing Semgrep fallback before publishing a pass.
  A finite *per-pass* static-work budget permits an early partial pass without
  reintroducing a cumulative analysis lifetime limit. Exhausted work is
  recorded as `not_attempted_budget`, never as a clean scan. The budget is
  configurable; every individual tool still has its own timeout.
- The coverage artifact keeps exact verified/expected counts, full gap
  path/rule/reason rows, engine errors, and a full unsupported product-file
  path/reason list. Existing aggregate extension counts remain compatible.
- Only candidates whose own engine slice verified their `(path, rule_id)` may
  enter the merged candidate bundle or Agent snippets. Partial raw tool
  output remains in CAS for audit but not as positive Agent evidence.
- A typed partial static result requires a valid, identity-bound bundle and
  coverage artifact, at least one verified pair, and no integrity failure.
  Invalid checkout, corrupt/missing evidence, empty usable source, or a
  truncated candidate set remain BLOCKED/FAILED. A localized parser error,
  exhausted per-file timeout, unavailable supplementary engine, or unsupported
  product file may produce PARTIAL only when the proven subset remains usable;
  each limitation is recorded. No error is converted to “no finding.”

## Runtime state and resume

- Persist a static disposition (`FULL` or `PARTIAL`) and coverage ref together
  with the successful static checkpoint/run update. `STATIC_DONE` success
  means trustworthy evidence was published, not that coverage is complete.
- Agent failure still outranks static partiality. If every required Agent
  reaches its normal terminal condition, return `COMPLETE` only for FULL
  coverage and `PARTIAL` for any residual gap/unsupported/engine limitation.
- Resume an unfinished Agent against its original exact input refs; never
  silently substitute a newer static bundle. A PARTIAL run can retry its
  static gaps with the same scope identity. Keep completed Agent checkpoints
  for the exact inputs they used, and enqueue only genuinely new hypotheses
  from newly verified evidence. If static proof becomes full, re-evaluate the
  final status only after all required new Agent work is terminal. Changed
  commit/scope/rules require a new analysis instead of cross-scope reuse.

## Presentation

- Dashboard and CLI distinguish PARTIAL from COMPLETE/BLOCKED. Show verified
  versus expected file/rule pairs, unsupported product-file count, reason
  totals, and a prominent incomplete-analysis warning. A paginated read-only
  view exposes the complete path/rule/reason ledger without a huge page.
- English and Korean Finding reports use the same factual coverage snapshot:
  counts, principal limitation reasons, artifact digest, and explicit wording
  that a confirmed Finding is independent of overall scan completeness.
  Keep full large ledgers in the separate coverage artifact instead of
  duplicating them into size-limited report attachments. Existing reports
  with no coverage metadata remain readable and do not claim full coverage.

## Proof obligations

Test full coverage, partial parser output, timeout, fallback recovery/failure,
unsupported paths, corrupt evidence, interruption/resume, unchanged completed
Agent inputs, new evidence, dashboard/report text, and terminal status
precedence. Run the complete suite and a bounded Dify pass through the
hypothesis stage; do not call Dify COMPLETE or a Finding confirmed without
their actual evidence.
