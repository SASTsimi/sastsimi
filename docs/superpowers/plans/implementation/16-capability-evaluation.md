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

## Pinned real-repository validation matrix

The fake-free validation uses the following two repositories.  Each run uses
the full commit SHA below; a moving branch name or abbreviated SHA is not an
acceptable analysis input.

### 1. Known-vulnerability path: OWASP PyGoat

- Repository: `https://github.com/adeyosemanputra/pygoat.git`
- Pinned commit: `19d17cc8874861142b330636d068bbde54e86b85`
- Purpose: prove at least one known, authorized vulnerability can complete the
  `Hypothesis -> Verification -> validated PoC -> two Gates -> Finding ->
  Markdown report` path.
- Static requirement: Python AST, OpenGrep, and CodeQL must all execute for the
  exact commit.  A missing CodeQL database or failed CodeQL attempt blocks this
  acceptance run; it cannot be reported as zero hits.
- Dynamic requirement: reuse the repository's tracked Docker and dependency
  declarations as inputs, but run the PoC only inside the approved Sandbox.
  The repository's intentionally vulnerable behavior is not permission to
  access external targets or widen network policy.

### 2. Small real-project path: ItsDangerous 2.2.0

- Repository: `https://github.com/pallets/itsdangerous.git`
- Release tag: `2.2.0`
- Pinned commit: `096c8d42545d3b68ea21a4f890fb2b2d8979c0bd`
- Purpose: exercise the same AST + OpenGrep + CodeQL + LLM path on a small,
  real Python security library that was not created as a vulnerable lab.
- Acceptance focus: preserve honest zero-hit, FALSE, HOLD, BLOCKED, and tool
  failure distinctions; do not require a TRUE finding merely to make the run
  appear successful.
- Dynamic reproduction and PoC are required only if Verification reaches the
  normal dynamic-request conditions.  A final TRUE still requires a validated
  PoC under the common contract.

For both repositories, record the exact Provider profile, model, prompt
revisions, static-tool capability revisions, CodeQL database digest, Sandbox
profile, analysis ID, and report path.  Compare detection quality separately;
PyGoat is the positive-path target, while ItsDangerous is the realistic
small-project and false-positive-control target.
