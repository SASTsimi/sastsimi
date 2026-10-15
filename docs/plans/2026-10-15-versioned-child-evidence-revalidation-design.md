# Versioned child-evidence revalidation after route-bound coverage

## Problem and success condition

The running educational Python A-001 has legacy verification children in
`HOLD`. Their count can change while v9 is still producing hypotheses. The
v10 route-bound certificate can discharge a route gap but cannot resolve a
child's unmet external prerequisite or final verification condition. A v10
`COVERED` row is therefore not proof that every linked child was resolved.

Success means a new, independently replayable certificate distinguishes
verified child dispositions from unresolved children. The original child
checkpoints, PoCs, findings, v9/v10 certificates and report bytes remain
unchanged. `COMPLETE` and 100% are allowed only when all scoped Python
surfaces, linked children and other existing pipeline obligations are
verified. A still-unmet prerequisite, ambiguous response, missing PoC,
provider error or scope gap remains `PARTIAL` or the appropriate failure.
This is not a promise that the current run will reach 100%.

## Options considered

1. **Versioned child successor after v10 (chosen).** Snapshot every linked
   `HOLD` after v10 is verified, revisit only those children using the
   existing Verification Agent role and exact pinned source/route evidence,
   and save separate results. Overlay only validated dispositions on v10.
2. Reopen the old child with the v5 one-shot replay mechanism. This works
   for an independently proven narrow category, but overwrites the current
   stage checkpoint, makes the frozen v9/v10 reader stale, and cannot handle
   final-verification HOLD. Do not invoke it on this successor path.
3. Treat source navigation or an LLM assertion as resolution. It does not
   prove the original unmet condition and could create false coverage.

## Frozen plan and per-child work

The successor begins only when v9 and v10 have replayable terminals. Pin a
content-addressed plan with analysis/workspace/commit, Python scope and
index, v10 plan/coverage and exact terminal/root snapshots, source hashes,
each linked child ID/stage/checkpoint hash/output refs, and a stable ordered
worklist. Do not hardcode the current HOLD count. A changed or newly linked
child invalidates the plan and leaves explicit pending work; it is never
silently excluded. Freeze the exact v9 progress snapshot for v10 predecessor
replay, rather than reading newer progress. Resolve child-to-surface links
from saved candidate and progress records and verify them independently.
Plan pin atomically sets a durable successor-in-progress state so readers
cannot continue to present an old v10 `COMPLETE` or report as current.

For each work item, the existing Verification Agent receives the original
hypothesis, verified old checkpoint/evidence, and bounded source-bound v10
route proof. The prompt explicitly identifies the old unmet claim or final
condition and asks for new evidence, not a restatement. Use the existing
structured-output schema, timeout and bounded retry. Save the request input
refs, model/attempt metadata and validated response as distinct artifacts;
normal logs retain metadata only. Limit concurrent work and use the existing
analysis lease. Store progress with a unique child/checkpoint/plan key and
compare-and-set transitions, so completed work is reused on resume and an
interrupted in-flight call cannot be issued twice without reliable cleanup.

A new assessment alone never produces a finding or a `TRUE` verdict. For an
initial HOLD, only a source-bound contradiction of the recorded external
prerequisite followed by a separately validated final `FALSE` may close the
child without a PoC. A supported attack must still traverse the existing
PoC and final-verification requirements before it can be closed or promoted.
For a final HOLD, `TRUE` needs the exact prior validated, supported PoC;
`FALSE` needs code/negative evidence; otherwise retain `HOLD`. A validated
terminal PoC `INCONCLUSIVE` can retain the existing completed-inconclusive
semantics, never a vulnerability confirmation. If the current implementation
cannot safely execute a required downstream step, record `STILL_HOLD` with
reason and do not count it complete. Provider/tool failures use `ERROR`, not
`STILL_HOLD` or a vulnerability refutation.

## Certificate, read path, and user-visible state

Introduce successor proof version 9 (internal v11 plan/coverage). Preserve
the v10 row and add child revalidation refs/status per surface. Remove
`CHILD_HOLD` only when **all** linked HOLD children have a verified terminal
disposition under the exact pinned plan. Retain every unrelated v10 reason,
static gap, pending/error candidate, route gap and source limitation. The
new `complete` predicate checks both surface coverage and an independent
obligation for **every linked historical HOLD**, even if the v10 row was
already `COVERED` or listed a completed inconclusive child. The existing
completed-inconclusive semantics are accepted only after exact terminal PoC
lineage is reverified. The read verifier replays the frozen v10 predecessor
using paired saved terminal/root overrides, revalidates child checkpoint
hashes/artifacts and result schemas, and recomputes successor coverage.
Saved counts are claims, not authority. A tampered or missing child result
fails closed.

CLI, dashboard, English/Korean reports and artifact currentness must recognize
proof version 9 and show resolved/still-HOLD/error/pending children separately
from Python surface coverage. Unknown proof versions fail closed; no report
may fall back to static-only disclosure. Existing reports are preserved but
not presented as current if a newer pinned successor is incomplete. Every
CLI/dashboard/report reader checks the durable successor-in-progress state
before using an old terminal.

## Verification

Use test-first changes. Cover initial/final/PoC HOLD, multiple linked children,
new child after plan pin, changed commit/source/checkpoint, tampered artifacts,
wrong PoC lineage, false `TRUE`, LLM error/timeout, interruption and resume,
and a non-HOLD v10 parent. Verify one child remaining HOLD keeps `PARTIAL`
even if 42 other surfaces are covered. Check old v9/v10 reads still work,
dashboard/report/CLI cannot present a false 100%, and full regression tests.
Only after the live worker is safely idle and code is verified may the same
A-001 ID be resumed. Never directly rewrite its SQLite rows.
