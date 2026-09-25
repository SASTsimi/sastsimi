# Pipeline-Wide Automatic Recovery Design

## Status

Approved direction: add a small, generic recovery loop to the existing
SimpleRuntime. Recovery changes analysis-local inputs and disposable Docker
environments only. It never edits SASTSIMI source code, host configuration, or
the checked-out target repository.

## Problem

SimpleRuntime already records retryable failures and can feed failed PoC
artifacts into a later manual `resume`. That is insufficient for unattended
analysis:

- execution stops until the user runs `resume`;
- environment failures and generated-script failures are not classified
  consistently;
- there is no bounded automatic repair loop;
- one blocked hypothesis can make the whole analysis appear stopped; and
- repeated errors are stored, but not summarized as an exhausted recovery.

The Paperless run demonstrates the gap. Docker built and started correctly,
while generated PoCs failed before testing their hypotheses because of missing
Django setup, module paths, environment values, and incomplete mocks. Those
errors must remain execution errors; they must never become vulnerability
`FALSE` verdicts.

## Goals

1. Automatically repair any **retryable** pipeline-stage failure, not only PoC
   execution failures.
2. Use repository facts, the exact failure, sanitized stdout/stderr, and prior
   attempts to select the next bounded action.
3. Retry at most three attempts for one exact stage and failure lineage.
4. Keep all repair work inside analysis-local artifacts and disposable Docker
   environments.
5. Preserve exact attempt lineage and evidence in the existing checkpoint,
   activity, and artifact stores.
6. Continue independent hypotheses after one hypothesis exhausts recovery.
7. Keep implementation small and avoid repository-specific adapters.

## Non-Goals

- Editing SASTSIMI's own source during an analysis.
- Editing or committing changes to the target repository checkout.
- Bypassing authentication, policy, scope, capability, or resource limits.
- Guaranteeing recovery from every failure.
- Treating a runtime error as counterevidence.
- Adding an unrestricted autonomous shell agent.

## Selected Approach

Add one `SimpleRecoveryCoordinator` around the existing stage execution paths.
It consumes a normalized failure context and returns one strictly validated
decision:

- `RETRY_STAGE`: rerun the same stage with repair guidance;
- `REBUILD_ENVIRONMENT`: invalidate the disposable reproduction environment,
  retain the diagnosis as input, and rebuild before retrying;
- `REGENERATE_INPUT`: invalidate the current generated artifact, retain the
  diagnosis and execution evidence, and ask the owning LLM stage for a corrected
  artifact;
- `STOP`: do not retry because the failure is terminal or unsafe to repair.

The coordinator does not execute arbitrary LLM commands. The existing Runtime
remains the authority that validates a decision, invalidates checkpoints,
creates a new attempt, builds a disposable environment, and executes a stage.
This follows the existing boundary in which Agents propose and non-LLM Runtime
code authorizes actions.

## Failure Classification

The recovery request contains the stage, error code, retryable flag, attempt
number, repository profile references, exact input/output references, sanitized
stdout/stderr, and prior recovery decisions. The LLM returns a strict JSON
object containing:

- `category`: `TRANSIENT_TOOL`, `GENERATED_INPUT`, `ENVIRONMENT`, or `TERMINAL`;
- `action`: one of the four allowed actions;
- `diagnosis`: a concise explanation grounded in supplied evidence;
- `guidance`: bounded instructions for the next owning stage.

Runtime validation enforces these mappings:

- non-retryable failures always become `STOP`;
- authentication, policy, scope, cancellation, resource exhaustion, and DB
  integrity failures always become `STOP`;
- generated output or PoC failures may use `REGENERATE_INPUT`;
- Docker/build/dependency/bootstrap failures may use
  `REBUILD_ENVIRONMENT`;
- transient tool failures may use `RETRY_STAGE`;
- an actual successful counterexample is interpreted normally and is not sent
  to recovery.

Unknown or invalid recovery output becomes `STOP`; it does not grant new
authority.

## Retry and Exhaustion Rules

- Attempt 1 is the original execution; attempts 2 and 3 are automatic repair
  attempts.
- Every attempt gets a new `attempt_id` and increments the existing
  `attempt_number`.
- The next attempt receives the prior candidate, execution record,
  stdout/stderr, and recovery-decision artifact as exact inputs.
- A successful stage exits the recovery loop immediately.
- A non-retryable failure exits immediately.
- Three unsuccessful attempts produce `RECOVERY_EXHAUSTED` with
  `retryable=False` for that exact stage lineage.
- Exhaustion never produces a `FALSE` verification verdict.
- Exhaustion of one hypothesis does not prevent later independent hypotheses
  from running. The completed analysis reports the hypothesis as blocked and
  requiring manual review.
- Manual resume may start a new recovery cycle only after relevant inputs,
  environment recipe, commit, configuration, or tool version changed. An
  unchanged exhausted lineage is not retried indefinitely.

## Repair Scope and Network Policy

Permitted changes:

- regenerated structured LLM output;
- regenerated PoC script;
- generated repair guidance artifact;
- generated temporary Dockerfile overlay or environment bootstrap script;
- disposable container/image state for the current analysis.

Forbidden changes:

- SASTSIMI source and `.git` state;
- target checkout contents;
- host files outside the configured data directory;
- host credentials and Docker socket mounts;
- policy, scope, or capability approvals.

Environment construction may use the configured package sources needed by the
repository. PoC execution has no public Internet access. Loopback and an
analysis-private Docker network remain available for the target application,
databases, queues, and local simulated services. Network-dependent security
tests use a local simulated peer rather than a real third-party endpoint.

## Persistence and Observability

No new database table is required. Recovery uses existing immutable artifacts,
checkpoint JSON, and agent activity:

- each decision is stored as a `simple_recovery_decision` JSON artifact;
- the decision artifact becomes an exact input to the next attempt;
- attempt-specific execution, stdout, stderr, environment recipe, and generated
  input remain separate artifacts;
- activity records show diagnosis, selected action, attempt count, and terminal
  exhaustion without exposing hidden reasoning or secrets;
- `status`, dashboard, and result projection display `attempt N/3` and the
  final safe error code.

Existing SQLite schema remains compatible because checkpoint and artifact
payloads already carry attempt numbers, errors, and exact references.

## Integration Points

- `simple_runtime/recovery.py`: recovery request/decision models, policy
  validation, failure fingerprinting, and coordinator.
- `simple_runtime/runner.py`: bounded automatic stage retry and checkpoint
  invalidation.
- `simple_runtime/application.py`: apply the same coordinator to retryable
  repository/bootstrap failures that occur outside hypothesis stages.
- `simple_runtime/stages.py`: pass recovery guidance into owning LLM stages and
  environment preparation.
- `simple_runtime/portable_docker.py`: rebuild disposable environments from a
  validated temporary overlay without changing the target checkout.
- `composition/simple_runtime_composition.py`: construct one coordinator and
  inject it into the application and runner.
- dashboard/status projections: expose attempt and exhaustion state.

The implementation may keep models beside `recovery.py`; it must not introduce
language- or repository-specific recovery modules.

## Data Flow

1. A stage raises `StageBlocked` or returns a retryable failure.
2. Runtime stores the failed checkpoint and exact evidence as it does today.
3. Runtime builds a sanitized recovery request from stored evidence.
4. Recovery Agent returns a strict decision; Runtime validates it.
5. Runtime stores the decision artifact and either stops or creates a new
   attempt with that artifact as input.
6. The owning stage consumes the guidance and regenerates its output or
   environment.
7. Runtime executes the new attempt and repeats until success, terminal
   failure, or three attempts.
8. Independent hypotheses continue after exhausted hypotheses.

## Testing

Tests must cover:

- a generated PoC failure repaired on attempt 2;
- an environment failure rebuilt and repaired on attempt 2;
- a transient external-tool failure retried without changing inputs;
- three identical failures becoming `RECOVERY_EXHAUSTED`;
- a non-retryable policy/auth/DB failure never reaching the LLM;
- invalid recovery JSON failing closed;
- an exit-1 counterexample remaining `DISPROVED`, not entering recovery;
- prior failure evidence and the recovery artifact reaching the next attempt;
- independent hypotheses continuing after exhaustion;
- no host environment secrets or paths entering prompts or containers;
- restart/resume preserving the attempt budget and exact lineage.

Focused tests run first, followed by the full repository suite.

## Acceptance Criteria

- A recoverable failure is diagnosed and retried automatically without a
  manual `resume` between attempts.
- Repairs remain generic across repositories and contain no Paperless-specific
  branches or environment names.
- No stage receives more than three attempts for unchanged exact inputs.
- Runtime errors cannot become vulnerability `FALSE` verdicts.
- Every repair decision and attempt is inspectable through stored artifacts and
  activity records.
- One exhausted hypothesis does not stop independent hypotheses.
- Existing manual resume, successful analysis, reporting, and safety behavior
  remain backward compatible.

## Delivery

Work is delivered from branch `codex/automatic-recovery` to `main` in one PR.
The existing uncommitted portability and PoC-safety fixes are retained as
prerequisite commits because this recovery flow depends on their corrected
Docker and candidate behavior.
