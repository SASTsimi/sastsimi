# Terminal Gate Outcomes and PoC Revision Design

## Intent and success criteria

An analysis is `COMPLETE` when every generated hypothesis has reached a recorded,
terminal analytical outcome, even if some outcomes are inconclusive and produce no
Finding. `COMPLETE` never means every hypothesis is vulnerable, and it never makes
an inconclusive hypothesis reportable. An actual provider, Docker, authentication,
database, cancellation, or other execution failure remains `BLOCKED` or `FAILED`
with its own error code. The runtime must not claim that every arbitrary repository
can complete despite unavailable external capabilities.

The motivating changedetection.io A-004 run had eight successful PoC execution
stages but stopped at `TECH_GATE_DONE`: the Gate requested a production-route PoC
and commit-pinned source-flow evidence, while the retry only reran final
Verification. A second Gate review therefore repeated the same evidence gap. The
PoC candidate had received a requested-source artifact, but that artifact was not
an explicit downstream Gate input.

## Decision and data flow

1. A well-formed Technical Gate `ACCEPT`, `REVISE`, or `REJECT` is an analytical
   decision, not a provider/runtime exception. Persist its exact result artifact
   and decision in the checkpoint. An invalid response or tool failure still uses
   the existing bounded operational-recovery path.
2. `ACCEPT` continues to Scope Gate and possible Finding. `REJECT` ends the
   hypothesis as non-reportable. `REVISE` atomically restarts at PoC candidate so
   a new candidate, Docker execution, final Verification, CWE, and Gate review can
   address requests for new dynamic evidence. Keep the prepared environment when
   its recipe and image are still valid; do not change host files or credentials.
3. Carry the exact Gate request into the restarted candidate and downstream
   Verification/Gate context. Carry bounded, commit-pinned requested-source
   evidence into downstream contexts as a direct reference. Put revision feedback
   and relevant source before bulk prior artifacts in prompts, preserving the
   existing redaction and size limits.
4. Permit at most three Technical Gate decisions per hypothesis in one recovery
   lineage, including across process restarts. If the last result is still
   `REVISE`, finish that hypothesis as `INCONCLUSIVE`, not as an accepted Finding
   and not as an operational `RECOVERY_EXHAUSTED` error. Preserve every attempt,
   request, execution, and decision in artifacts and activity history. Keep the
   final Verification verdict unchanged; the separate Gate disposition prevents
   reporting.
5. A final `FALSE` and `HOLD` continue to use their existing terminal paths.
   Valid Gate `REJECT` and exhausted `REVISE` are additional non-reportable
   terminal paths. No path converts an execution error into `FALSE` or fabricates
   a validated PoC.

## Safety and durable state

The Gate decision and bounded revision count must survive `resume` without
repeating completed work or restarting a terminal outcome. Restarting at PoC
candidate must atomically invalidate all downstream checkpoints; a crash cannot
leave a new candidate paired with old PoC execution or Gate evidence. A TRUE
Finding, Primitive, or report requires an explicit Technical Gate `ACCEPT` in
addition to the existing final TRUE, same-attempt validated PoC, and Scope Gate
requirements. A `REVISE` or `REJECT` artifact must never pass that guard even if
a caller bypasses the normal runner.

The analysis aggregator, CLI result/status, progress projector, and dashboard
must use the same terminal-hypothesis rule. They credit skipped downstream work
for a terminal non-reportable Gate decision, show the decision as inconclusive or
rejected, count no Finding/report for it, and allow aggregate `COMPLETE` only when
no hypothesis has an operational `BLOCKED`/`FAILED` outcome. The UI must not
offer `resume` for a terminal analytical decision. Legacy blocked analyses are
not silently rewritten; a new run validates the changed semantics.

## Verification and rollout

Use test-first cases for `ACCEPT`, `REJECT`, first and repeated `REVISE`, restart
atomicity, feedback/source delivery, resume idempotence, Finding/Primitive guards,
mixed-hypothesis aggregation, CLI/progress/dashboard consistency, and true
operational failures. Run focused tests, the full suite, Ruff, mypy, documentation
validation, and Linux/Windows CI. Then start a fresh analysis of the same pinned
changedetection.io commit with Codex `gpt-6-sol`; inspect the stored Gate decisions,
PoC attempts, final status, Finding count, and artifacts. Do not label a run
successful until the actual result command reports `COMPLETE`. Record honest
limitations and update README, architecture, troubleshooting, and the existing
trial log in PR #200.
