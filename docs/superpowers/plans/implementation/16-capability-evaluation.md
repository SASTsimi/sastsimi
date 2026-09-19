# Production capability and real E2E completion plan

## Goal

Ship one maintainable production path that executes Python AST, OpenGrep, and
CodeQL before the LLM pipeline, and then completes dynamic reproduction, both
gates, Finding creation, and Markdown export without a fake adapter.

OpenGrep and CodeQL are complementary inputs.  A production profile used for
the final proof must enable both.  A missing or failed CodeQL run is recorded as
a static-analysis gap/error and must never be converted into a zero-hit result
or a vulnerability `FALSE` verdict.

## CodeQL safety boundary

The existing analyze-only `CodeQLProcessAdapter` remains the semantic reference.
Production activation requires all of the following before the first CodeQL
process starts:

1. An exact ACTIVE CodeQL capability revision.
2. A trusted prebuilt-database provider bound to repository identity, commit,
   language, tracked-file manifest, provider revision, and database digest.
3. Separate hard write limits for database material and execution output.
4. A real cap-plus-one denial with sticky breach evidence from the approved
   quota backend. Directory-size polling is only defence in depth.
5. An immutable query pack and exact rule catalog/selection/mapping closure.
6. One language per CodeQL work item. Mixed Python and JavaScript input is
   split before dispatch or fails closed.

The production analysis path never runs `codeql database create`, autobuild,
package installation, build scripts, or repository executables. Database
creation belongs to a separate controlled provisioning step and its output is
not usable until the exact provider and capability evidence is approved.

## Implementation sequence

1. Add typed prebuilt-database and CodeQL-boundary ports and bind their identities
   and byte limits to capability approval evidence.
2. Add a real hard-quota backend and prove cap-plus-one denial plus sticky breach
   state. Unsupported hosts remain fail-closed.
3. Add a lazy production CodeQL adapter that resolves one exact database,
   allocates separate database/execution leases, delegates analysis and SARIF
   normalization, and finalizes every lease on success, failure, timeout, or
   cancellation.
4. Replace unconditional CodeQL rejection with exact prerequisite checks.
5. Extend setup/onboarding so a profile can only activate CodeQL after the
   executable, database provider, quota backend, query material, and human
   approval all match.
6. Add focused tests for identity substitution, stale database, quota breach,
   mixed languages, timeout, and failure-to-verdict isolation.
7. Run one real repository through AST + OpenGrep + CodeQL + LLM + Docker +
   gates + Finding + Markdown. The launch proof must use the public production
   CLI and no fake/scripted adapter.

## Verification policy

During implementation, run only the directly affected unit, contract, and
integration tests. Run the complete repository CI once at the final integration
PR SHA. Blocker/High failures are fixed immediately; Medium/Low cleanup is
recorded for follow-up.

