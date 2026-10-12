# A-001 generic proof replay

## Goal and boundary

Improve the source-bound Python route-to-operation proof used for A-001 and
other repositories with the same *code shape*. Do not encode DSVPWA names,
routes, vulnerability labels or XML answer-key fields. Reuse successful static
work and child checkpoints. A graph path is not a confirmed vulnerability, and
neither a new path nor a completed review clears an unrelated child HOLD.

## Evidence and current failure

The pinned A-001 run has 85/85 static jobs complete and 20/56 surfaces covered.
Its 36 insufficient surfaces have completed v5 reviews, but their saved graphs
predate the current source-bound revision. The current graph extractor recognizes
the class-body XML registry as a route/class binding but does not connect it to
the HTTP handler, instance dispatch, inherited method and override. Graph gaps
are also aggregated across unrelated branches, so a valid path can be obscured.
Old graphs cannot be relabeled with a new revision or silently promoted.

## Implementation slices

1. Add a synthetic, pinned, generic fixture for an imported stdlib HTTP handler,
   class-body XML registry, request route comparison, inherited dispatcher and
   selected override. Write negative cases for missing runtime entry, ambiguous
   or rebound names, changed pinned blobs, wrong route/class and uncalled
   registry. Extend only the exact-source proof bridge; unresolved code shapes
   remain explicit gaps.
2. Introduce a new graph semantics revision with path-scoped blocking gaps.
   Keep all graph-wide gaps in evidence and reports. A positive review may cite
   only a path whose complete ordered edges and source hashes are verified and
   whose blocking-gap list is empty. `NO_HYPOTHESIS` still requires full graph
   context. Existing revisions remain fail-closed.
3. Re-evaluate the saved analysis only through an additive successor review
   round. Pin the predecessor plan and terminal proof hashes, original commit,
   scope, index and source hashes. Target only the currently insufficient rows;
   new context IDs must differ from old IDs. Preserve every old artifact,
   checkpoint and result, and resume only missing successor parts. A successor
   proof may clear only reasons supported by its new evidence and current child
   verdict. Never overwrite an old proof pointer with an unbound plan.
4. Run focused RED/GREEN tests, full regression tests, and a read-only graph
   extraction against the pinned A-001 checkout before an opt-in same-ID resume.
   Report actual covered/insufficient/HOLD counts after resume. Keep `PARTIAL`
   unless the existing strict complete predicate is genuinely satisfied.

## Decisions

- The tool is Python-only; this change does not treat unscanned code as clean.
- XML route/class tags may prove operational selection but not vulnerability
  truth. All descriptive/answer fields stay out of Agent input.
- A legacy graph's plain `{path, reason}` gap rows cannot be reclassified as
  unrelated. Only newly extracted, source-bound paths may use path-scoped gaps.
- If an immutable successor round cannot be implemented and verified safely,
  do not delete, mutate or reset A-001 to make it rerun; ship the graph fix and
  leave A-001 truthful `PARTIAL` with the remaining reason counts.
