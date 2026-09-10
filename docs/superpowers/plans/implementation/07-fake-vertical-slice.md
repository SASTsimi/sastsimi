# Task 7: deterministic fake vertical slice

The task brief and Architecture v5 are authoritative. This document is a local
execution map, not a competing contract or source of schema values.

## Boundary inspection

Use the public `RuntimeServices`, `RecordStore`, `UnitOfWork`, budget registry,
Action validator, work/attempt services and external dispatch service. Fake
external adapters return deterministic data; they do not own IDs, database
connections, current pointers, authorization decisions, or budget reservations.

Inspection found prerequisites that need a trusted implementation before the
full slice can be wired:

- Finding admission has a contract-level trusted normalizer identity requirement,
  but storage calls that validator without its identity/assignment arguments.
- Canonical state records such as PrimitiveIndexState, FindingIndexState,
  DynamicReproductionState and PlaybookApplication are not storage-decodable.
- Transition publication supports CodeWorkspace run-state updates, but does not
  yet compose frozen policy or terminal result updates into the run state.

These observations were escalated before production changes. Contract fields,
enums, role ownership and exact-reference semantics must remain unchanged.

## TDD execution order

1. Add the failing TRUE end-to-end case: missing/current-generation invalid PoC
   must prevent final TRUE and report publication.
2. Add FALSE evidence and HOLD unresolved-condition negative cases.
3. Build trusted setup, bounded work execution and deterministic external calls
   through ACTIVE profile binding, reservations, Action checks and durable usage.
4. Wire canonical stages 1–13: start, workspace, parallel static/policy preparation,
   facts, proposal, registration, owner, retrieval, parallel Pro/Con, initial
   verdict, dynamic execution, final verdict.
5. Wire stages 14–22: CWE, Technical Gate, same-owner generation restart, Rule
   Scope, Primitive admission/index, Chaining no-match, Finding, Reporter and
   AnalysisRunResult closure. The no-match branch satisfies optional child flow.
6. Connect analyze, progress/results and report-draft CLI operations to persisted
   fake execution. Automation ends at ReportDraft.
7. Exercise failure injection, current generation and exact output closure;
   review role/import boundaries. Run focused tests after each change and the
   full suite before committing.

## Evidence

RED/GREEN commands, observed results and final self-review will be recorded in
the task report. No production implementation or test evidence is claimed by
this plan alone.
