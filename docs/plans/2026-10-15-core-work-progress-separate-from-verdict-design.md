# Core-work progress separate from analysis verdict

Date: 2026-10-15

## Intent and success criteria

The overall percentage answers **how much of the planned base analysis work has reached a verified terminal evaluation**, not whether every security claim was proved or a report is ready. A completed base run may therefore show `100%` and `PARTIAL` together. The dashboard and CLI must explain that distinction. New successor work proposed for historical `HOLD` hypotheses—an additional PoC and any subsequent final-`TRUE` gate/report chain—is tracked separately and never enlarges the base percentage denominator.

This change must not turn an `INSUFFICIENT` surface into `COVERED`, promote a `HOLD` to `TRUE`, mark a report current, or change `COMPLETE`/`PARTIAL`/`BLOCKED` decisions. Existing analysis IDs, checkpoints, artifacts, and resume behavior are preserved. The live A-001 worker and database are not modified during implementation.

## Current behavior and selected approach

`ProgressProjector` currently counts the original 12 hypothesis stages, candidate selection and deep work, and only `COVERED` security surfaces. It forces `100%` when status is `COMPLETE` and caps every other status at `99%`. This couples a work-progress indicator to the evidence verdict. V11 successor attempt records are separate from the original hypothesis checkpoints, but unresolved successor obligations indirectly hold the surface count below `COVERED`.

The selected approach retains the original base-stage checkpoint accounting and changes only the meaning of the aggregate percentage for candidate pipeline v2 analyses with independently verified surface terminal data. It counts a surface evaluation as finished when the bound terminal proof says `COVERED` **or** `INSUFFICIENT`, but not `UNCOVERED`. `INSUFFICIENT` remains an explicit failed-to-prove outcome, never a coverage success. It does not use the `REVIEWED` context count as a universal numerator: some valid surface outcomes lack a context record. Successor PoC/gate/report attempts remain outside the base denominator and have their own counts/status.

Alternatives considered: keeping the old aggregate and adding a second donut would preserve old semantics but not satisfy the requested 100% base-work indicator; treating unresolved proof as complete analysis would misstate findings and is rejected.

## Data flow and contracts

1. The verified terminal projection and surface proof reader remain the only sources for surface outcome counts. A terminal hash, scope binding, and count mismatch yield no new surface-progress credit.
2. `ProgressProjector` emits the base-work numerator and denominator and a versioned percentage-kind value that means **base work fraction**. The surface phase keeps its existing `completed`/`covered` count for proven coverage and adds an `evaluated` count (`COVERED + INSUFFICIENT`). `UNCOVERED` and unknown terminal data receive no evaluation credit.
3. The aggregate percentage is computed from those base-work units, independent of the terminal verdict. It reaches `100` only when every known base unit has a verified terminal result and the candidate terminal is valid. Pending candidate decisions, deep work, hypotheses, uncovered surfaces, or invalid terminal evidence keep it below `100`. Ordinary non-v2 analyses retain their existing percentage behavior.
4. Status remains derived from the existing candidate-terminal, static-disposition, child-obligation, and operational-error checks. In particular, unresolved `HOLD`, static gaps, or inadequate route evidence may leave `PARTIAL` at `100%` base-work progress. An active or failed successor chain is not silently presented as successful proof.
5. The CLI and dashboard consume the shared projection, label it `기본 분석 작업 진행률`, and state that `100%` does not mean full coverage, confirmed findings, or a submission-ready report. The surface detail continues to display proven, insufficient, and uncovered counts separately. Reports keep the evidence/status wording; they do not infer a verdict from the percentage.

## Compatibility and failure behavior

No checkpoint, database schema, or artifact migration is required. The projection is recalculated from saved evidence, so resume cannot double-count. Existing base-hypothesis PoC/report stages remain in the base graph; only **new, versioned successor work** for historical `HOLD` is separate. If successor lineage cannot be identified unambiguously, it must not be folded into base units. Invalid or absent terminal proof keeps the prior incomplete percentage behavior and does not produce a false `100%`.

Implementing the proposed V12 PoC/gate/report successor chain is out of scope for this percentage change. Existing V11 successor attempt counts remain visible; no new PoC or report is invented to increase progress.

## Verification

Unit tests cover: complete base work with `PARTIAL` status and `100%`; `INSUFFICIENT` evaluated but not covered; `UNCOVERED` still below `100%`; invalid/stale terminal proof below `100%`; unchanged legacy percentage behavior; and added/resumed successor attempts not changing the base denominator or numerator. CLI and dashboard tests assert the new label and simultaneous `100%`/`PARTIAL` display. Focused V9–V11 resume/coverage tests and the repository regression suite must pass before claiming completion. A-001 may be inspected read-only after its worker finishes, but its value must not be assumed from the design.
