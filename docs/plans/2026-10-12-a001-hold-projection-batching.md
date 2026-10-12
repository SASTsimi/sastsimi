# A-001 HOLD projection batching implementation plan

**Goal:** Finish the existing A-001 v5 HOLD review without repeatedly rebuilding the entire dashboard index, while preserving every checkpoint and the rule that insufficient evidence cannot yield `COMPLETE`.

**Observed bottleneck:** Each new `KEEP_HOLD` marker is committed, then `prepare_surface_hold_replay` rebuilds the dashboard projection. The review has 33 child decisions, so a full rebuild after each marker delays progress without adding evidence.

## Implementation

1. Add failing store and application tests for multiple `KEEP_HOLD` markers. Require each marker to commit independently, but only one projection after the batch. Keep `REPLAY` and non-batch callers' immediate projection behavior.
2. Mark the existing dashboard index `INCOMPLETE` in the same transaction as the first new deferred marker. A crash must leave an explicit dirty state, not stale data labeled ready. On same-ID resume, refresh a dirty index even if no new marker is needed. Guard against a concurrent projection that read an older snapshot and writes `READY` after the marker; wall-clock timestamp comparison alone is not a sufficient freshness proof.
3. Wrap only the v5 HOLD review loop in the deferred-projection context. Always attempt the final projection on normal exit or exception; never roll back already committed child decisions because projection fails.
4. Make dashboard reads of the known in-progress index show an explicit updating state or safe fallback. A durable dirty state after process exit must explain that resume or index rebuild is needed, not promise that retrying the page alone will fix it. Do not reinterpret unreviewed children as covered.
5. Run focused store, application, and dashboard tests; verify duplicate decisions, simulated crash, exception, and resume. Run Ruff, mypy, relevant regression tests, and an independent review.
6. Stop only the identified live analysis process after confirming its identity and absence of in-flight Codex calls. Integrate the reviewed change into the PR branch, then resume the exact A-001 ID from its saved marker count. Do not restart static analysis or A-002.
7. Verify the terminal state and evidence counts. `PARTIAL` remains correct if surface gaps or HOLD decisions remain. Push PR updates only after local checks and inspect CI; do not merge on an unproven completion claim.

## Self-review before implementation

- **Scope:** This is a projection scheduling change, not a change to candidate, PoC, or vulnerability verdicts.
- **Crash consistency:** The dirty marker and child checkpoint must be atomic; a process exit may delay the projection but cannot convert missing work into success. The independent review identified an external-projection race, now included in the required interleaving test.
- **Compatibility:** Existing analyses and direct callers keep their current behavior. The new context affects only this v5 review loop.
- **Safety:** Work is prepared in an isolated worktree while A-001 is running; the live worker's code is not changed in place.
- **Decision:** Approved for implementation with the above tests and safe handoff.
