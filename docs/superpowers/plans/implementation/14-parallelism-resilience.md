# Task 14 Production Composition, Parallelism, Cancellation, and Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans` to
> implement this plan. Use `superpowers:test-driven-development` for each lane
> and `superpowers:verification-before-completion` before claiming the candidate
> is ready.

**Goal:** Connect the completed T08-T13 services to one production CLI flow,
execute ready work with bounded concurrency, make cancellation and same-input
resume durable, and restart without duplicating external calls or inventing
domain results.

**Architecture:** SASTSIMI remains one CPython process with bounded `asyncio`
tasks and a SQLite-backed work table. There is no queue server, daemon, or
in-process LLM authority. The production composition root maps each `WorkType`
to one `WorkHandler`; the worker pool only claims, invokes, and observes those
handlers. Domain services still own result creation. Runtime/storage still own
IDs, authorization, work transitions, exact references, budget accounting, and
recovery. `run` and `resume` drive the pool in the foreground; `status`,
`cancel`, and `result` operate only on durable state.

**Tech Stack:** CPython `>=3.12,<3.13`, `asyncio`, Pydantic 2, SQLAlchemy,
SQLite, Alembic, argparse, pytest, Ruff, and strict mypy.

**Spec:** Canonical documents:

- `docs/architecture-v5/01-system-overview.md`
- `docs/architecture-v5/03-agent-roles-and-orchestration.md`
- `docs/architecture-v5/04-verification-and-dynamic-reproduction.md`
- `docs/architecture-v5/05-llm-gate-and-reporting.md`
- `docs/architecture-v5/06-chaining.md`
- `docs/architecture-v5/07-results-and-observability.md`
- `docs/architecture-v5/08-lightweight-data-contracts.md`
- `docs/architecture-v5/09-llm-provider-session-and-logging.md`
- `docs/architecture-v5/10-security-boundaries.md`
- `docs/architecture-v5/implementation/01-module-map.md`
- `docs/architecture-v5/implementation/03-recovery-test-plan.md`
- `docs/architecture-v5/implementation/06-implementation-baseline.md`
- `docs/superpowers/plans/2026-09-08-sastsimi-complete-implementation.md`
  Task 14

**Planning baseline (2026-09-12):** `origin/main` is
`342fcfa2b8cc06900897a0afb06c71ec32af4f6e` (T08 merged). The approved T13
planning commit is `28e446146ec7ddd72e42903efb4d0e7013e3219d`; it is a plan, not an
implementation dependency that T14 may import. T09-T13 are not in this baseline.
T14 implementation must therefore branch from a later reviewed main commit that
contains their final production implementations. S0 records that full SHA and
adapts only names/signatures after reading the merged code; it does not infer an
API from a planning branch.

### Verified API inventory on the planning baseline

The following names exist on `342fcfa` and are the starting seams T14 extends:

- `ports.work_handler.WorkHandler.execute(WorkContext) -> WorkHandlerResult`,
  where `WorkContext` contains exact `work` and `attempt` records;
- `runtime.work_service.WorkService.get/register/make_ready`, backed by
  `storage.work_service.WorkService`;
- `runtime.attempt_service.AttemptService.start(...)`, backed by
  `storage.attempt_service.AttemptService.start(...)`;
- `runtime.workflow_runner.WorkflowRunner.start(...)`, which currently performs
  register -> READY -> RUNNING synchronously;
- `runtime.recovery_service.RecoveryService.recover() -> RecoveryReport`, backed
  by `storage.recovery_service.RecoveryService`;
- `runtime.budget_service.BudgetService.reserve/commit_usage/release/remaining`,
  backed by `storage.budget_service.BudgetService`;
- `runtime.budget_registry.BudgetProfileRegistry.pin_execution/pin_binding`;
- `runtime.analysis_finalization.AnalysisFinalizationService.finalize(...)`;
- `contracts.budget.ExecutionBudgetProfile.max_parallel_work`;
- `interfaces.cli.main.main(...)`, which currently exposes only foundation DB
  commands and the deterministic fake `analyze/results/reports` path.

The following required T14 seams do **not** exist on the planning baseline:
`runtime/worker_pool.py`, durable cancellation state, ready-work query/atomic
claim, exact external cancellation-target rehydration, lease renewal, production
`run/status/cancel/resume/result`, a complete production handler registry, and a
production result-aggregation service. Their absence is planned T14 work, but
the absence of final T09-T13 handlers is a predecessor Blocker and must be closed
before any T14 implementation lane starts.

---

## 1. Speed-first scope and non-negotiable safety

During T14, run only the focused normal-flow test and the named critical
failure/race test for each step. Run the complete suite once on the immutable
candidate SHA. Do not add unrelated refactors, new distributed infrastructure,
or Medium/Low improvements.

The following Blocker/High properties are never skipped:

- one READY work can be claimed by at most one active attempt;
- a late prior-attempt result never changes current work or current pointers;
- a durable cancellation request prevents all new work/attempt dispatch;
- cancellation keeps committed usage and releases only proven-unused,
  unclaimed reservations;
- an uncertain external dispatch is never automatically sent again;
- restart resolves PREPARED transitions, leases, exact output references, and
  external dispatch state before scheduling anything;
- failure of one hypothesis does not manufacture a verdict for it and does not
  cancel independent hypotheses;
- `ExecutionBudgetProfile.max_parallel_work` is the one analysis-wide work
  concurrency limit and applies to every work type, including `DYNAMIC_REPRO`.
  Provider and Pro/Con sub-boundaries keep their own already-approved limits;
  no separate `max_parallel_sandboxes` setting is introduced;
- a live exact attempt renews its durable lease, while a stale worker can never
  renew or publish for a replacement attempt;
- terminal analysis finalization happens only after every work is terminal and
  no PREPARED transition or uncertain external dispatch remains.

T14 does not alter vulnerability verdict rules, Gate order, Chaining admission,
validated PoC requirements, or T08-T13 result ownership.

---

## 2. Mandatory preflight and API freeze

Implementation starts only after T08-T13 are merged into the selected base and
the following APIs are frozen. If any item is missing, stop before parallel lane
creation and close the seam serially. Do not let a lane invent an adapter by
reaching into another module's storage.

### 2.1 Required upstream APIs

1. **Complete handler registry input**
   - Every production `WorkType` has exactly one injected
     `WorkHandler.execute(WorkContext) -> WorkHandlerResult` implementation.
   - The handler consumes the already-claimed current attempt. It does not claim
     another attempt and does not recursively run a worker loop.
   - A handler that creates downstream work enqueues it as READY; it does not
     execute the child inline.

2. **T08 static boundary**
   - Record the final public handler names for workspace preparation, static
     tool, normalization, and context retrieval from the merged base. Each must
     accept an exact already-claimed `WorkContext`.
   - Record the actual exact-attempt/process cancellation method exposed by the
     merged static adapter. Current main only proves the lower-level
     `StaticToolAdapter.cancel(attempt_id) -> CancellationResult`; T14 must not
     guess a higher-level wrapper.

3. **T09 Provider boundary**
   - Locate the merged production invocation service and record its exact public
     call and cancellation signatures. Do not copy a name from the T09 plan or
     branch.
   - The located service must resolve one exact `ProviderProfile`, `model`,
     `ExecutionLimits`, retry policy, prompt entry, and tool policy; expose exact
     invocation cancellation; and enforce `ExecutionLimits.max_parallel_calls`
     across concurrent works.
   - Its persisted dispatch state must distinguish returned from unresolved.
     A dispatched call with unknown outcome is never silently retried.

4. **T10 verification boundary**
   - Enumerate the merged Hypothesis, independent Pro/Con, Verification,
     verdict-routing, and REVISE-generation handlers and record their real
     public entry points.
   - Pro/Con scheduling preserves independent NEW sessions and enforces
     `VerificationBudgetProfile.max_parallel_evidence_calls`.

5. **T11 reproduction boundary**
   - Locate and record the merged public dynamic-reproduction handler/service
     that consumes one exact claimed `WorkContext`. Do not assume an
     `execute(context, request_ref)` signature.
   - T11's committed `DynamicReproductionRequest`, `AgentLog`,
     `SandboxEnvironment`, action decision, resource reference, and cleanup
     records expose enough exact attempt/action provenance for T14 to rehydrate
     a cancellation target after restart.
   - T14 S1 owns the cancellation/recovery adapter that consumes those exact
     persisted references. It never enumerates Docker resources and does not
     require T11 to add a second resource registry or concurrency setting.
   - `ExecutionBudgetProfile.max_parallel_work` bounds `DYNAMIC_REPRO` claims in
     the same trusted scheduler transaction as every other work type. Container
     CPU, memory, PID, time, and network bounds remain T11 responsibilities;
     they are not concurrency limits.

6. **T12 policy/Gate/reporting boundary**
   - `POLICY_FETCH`, `CWE_LABEL`, `TECHNICAL_GATE`, `RULE_SCOPE_GATE`,
     `FINDING_NORMALIZE`, and `REPORT_DRAFT` each have one handler.
   - Record each merged handler's public entry point and downstream ready-only
     handoff name. Reporter remains TRUE-only and Gate REVISE creates the
     approved new Verification generation; neither behavior is reimplemented in
     the pool.

7. **T13 Primitive/Chaining boundary**
   - The updated T13 implementation plan is a strict predecessor to T14 and
     must deliver claimed-context `PRIMITIVE_UPDATE` and `CHAINING` handlers
     before the T14 base SHA is recorded.
   - Locate the final `PRIMITIVE_UPDATE`, `CHAINING`, and chained-child proposal
     handlers from the merged implementation; the planning commit is not API
     evidence.
   - Those handlers use the exact frozen Primitive index and register accepted
     child proposals through the merged ready-only handoff.
   - Each handler accepts only the exact current already-claimed
     `WorkContext`, does not call `start`, `activate`, or `AttemptService.start`,
     and enqueues child work as READY without running it inline.

8. **Final result assembly boundary**
   - Orchestration exposes a pure/current-state result aggregator that builds an
     `AnalysisRunResult` candidate with exact inventory, counters, errors, gaps,
     usage, and debug trace.
   - Existing `AnalysisFinalizationService.finalize` remains the sole terminal
     publisher and validator.

### 2.2 Required T14 inward ports

Freeze these transport-only APIs in the serial foundation. Exact DTO names may
be adjusted to an already-existing equivalent, but there must be one meaning
and one owner.

```python
@dataclass(frozen=True)
class CancellationTarget:
    target_kind: Literal["STATIC", "PROVIDER", "SANDBOX"]
    work: WorkExecutionState
    attempt: WorkAttempt
    action_request_ref: RecordRef
    action_decision_ref: RecordRef
    call_spec_ref: StoredDataRef | None
    sandbox_resource_refs: tuple[StoredDataRef, ...]

@dataclass(frozen=True)
class CancellationObservation:
    target: CancellationTarget
    status: Literal["STOPPED", "ALREADY_TERMINAL", "UNRESOLVED"]
    reason_code: str | None

class SchedulerStorePort(Protocol):
    def ready_work(self, analysis_id: str, limit: int) -> tuple[WorkExecutionState, ...]: ...
    def work_for_run(self, analysis_id: str) -> tuple[WorkExecutionState, ...]: ...
    def attempts_for_work(self, work_id: str) -> tuple[WorkAttempt, ...]: ...
    def try_claim_ready(
        self,
        analysis_id: str,
        work_id: str,
        expected_state_version: int,
        worker_id: str,
        lease_expires_at: datetime,
    ) -> WorkContext | None: ...
    def renew_lease(
        self,
        context: WorkContext,
        worker_id: str,
        lease_expires_at: datetime,
        elapsed_ms: int,
    ) -> WorkContext: ...

class RunControlPort(Protocol):
    def request_cancel(self, analysis_id: str, reason: str) -> None: ...
    def cancel_requested(self, analysis_id: str) -> bool: ...
    def mark_quiescent(self, analysis_id: str) -> None: ...
    def cancellation_targets(self, analysis_id: str) -> tuple[CancellationTarget, ...]: ...

class ExternalCancellationPort(Protocol):
    async def cancel(self, target: CancellationTarget) -> CancellationObservation: ...

RunDisposition = Literal["TERMINAL", "BLOCKED", "CANCELLED", "FAILED"]

@dataclass(frozen=True)
class RunOutcome:
    analysis_id: str
    disposition: RunDisposition
    result_ref: RunStoredDataRef | None

@dataclass(frozen=True)
class AnalysisStatusView:
    analysis_id: str
    run_status: str
    work_counts: tuple[tuple[str, int], ...]
    cancel_requested: bool
    waiting_for: tuple[str, ...]
    result_ref: RunStoredDataRef | None

class HandlerRegistryPort(Protocol):
    def validate_complete(self, required: tuple[WorkType, ...]) -> None: ...
    def resolve(self, work_type: WorkType) -> WorkHandler: ...

class WorkSchedulerPort(Protocol):
    async def drain(self, analysis_id: str) -> RunOutcome: ...

class AnalysisApplicationPort(Protocol):
    async def run(self, request: AnalysisStartRequest) -> RunOutcome: ...
    def status(self, analysis_id: str) -> AnalysisStatusView: ...
    async def cancel(self, analysis_id: str) -> AnalysisStatusView: ...
    async def resume(self, analysis_id: str) -> RunOutcome: ...
    def result(self, analysis_id: str) -> AnalysisRunResult: ...

```

`RunOutcome` and `AnalysisStatusView` are non-persisted, frozen transport DTOs.
They contain IDs, safe counts/status, and exit classification only. They are not
new domain records, verdicts, or current-pointer authorities.

`CancellationTarget` and `CancellationObservation` are also non-persisted,
frozen transport DTOs. A target contains the exact current work and attempt
references plus the exact action request/decision and type-specific Provider,
static-process, or persisted Sandbox resource references. The storage adapter
derives it from committed state; callers cannot submit IDs to widen the target.
An observation reports only whether the exact target was stopped, was already
terminal, or remains unresolved. It never creates a verdict or releases usage
whose execution is uncertain.

`try_claim_ready` is the only production READY-to-RUNNING entry point. Inside
one SQLite `BEGIN IMMEDIATE` transaction it re-reads the cancel latch, exact run
and work state/version/input hash, the run-pinned ACTIVE
`ExecutionBudgetProfile`, committed ledger and active reservations, and current
RUNNING count. Only then may it create/claim the START_ATTEMPT reservation,
insert the new attempt and lease, and CAS the work to RUNNING. A race loser or
full/zero capacity returns no claim and leaves no active reservation. No public
caller supplies or overrides `max_parallel_work`.

### 2.3 Enqueue/claim split

Current `WorkflowRunner.start` registers, makes READY, and immediately claims an
attempt with worker ID `local-workflow`. Production scheduling cannot use that
combined operation.

The serial foundation must add two explicit operations while retaining `start`
temporarily for deterministic fake/T08 regression callers:

- `enqueue(...) -> WorkExecutionState`: register and move PENDING to READY only;
- `claim_ready(...) -> WorkContext | None`: delegate to the atomic
  `SchedulerStorePort.try_claim_ready` operation above.

`start` may delegate to `enqueue` then `claim_ready` for existing tests, but no
production handler or production composition path may call it. The worker pool
is the only production attempt claimant.

Registration, PENDING/BLOCKED-to-READY enqueue, READY-to-RUNNING claim, and the
final CAS phase of result publication each read the cancellation latch inside
their own write transaction. If cancellation commits first, new registration,
READY dispatch, and result publication are rejected; cancellation-owned state
transitions remain allowed. If result publication commits first, its immutable
record, usage, and pointer are retained before cancellation proceeds. Run-level
`AnalysisRunResult` publication applies the same rule: a latched cancellation
may finalize only as `CANCELLED`, while an already committed terminal result is
immutable.

### 2.4 Serial S0 merge/API gate

Before creating an implementation lane, the integration owner runs the
following on the candidate main commit and records the full SHA and output in
the T14 PR. A missing item stops T14; the lane must not create a substitute API
inside its own module.

```powershell
git status --short
git rev-parse HEAD
git log --merges --oneline --decorate -20
rg -n "class .*Handler|async def execute\(" src/sastsimi
rg -n "WorkflowRunner\.start|\.activate\(|AttemptService\.start" src/sastsimi
rg -n "READY|enqueue|register" src/sastsimi/orchestration src/sastsimi/runtime src/sastsimi/ports
rg -n "cancel|UNRESOLVED|max_parallel_calls|max_parallel_evidence_calls" src/sastsimi
uv run alembic heads
```

S0 passes only when:

- every `WorkType` has exactly one production handler implementing the existing
  `WorkHandler.execute(WorkContext) -> WorkHandlerResult` contract;
- handlers consume an already-claimed current attempt and register children
  only through the actual merged READY-only handoff;
- production handlers contain no call to `WorkflowRunner.start`, `activate`,
  `AttemptService.start`, another handler, or a worker loop;
- T09 cancellation/unresolved dispatch, T10 Pro/Con capacity, T11 exact Sandbox
  resource provenance, T12 Gate/report routing, and T13 Primitive/Chaining
  reconciliation are present under their real merged public names;
- Alembic reports one head.

For each T09-T13 merge shown by the log, copy its reviewed implementation SHA
from the merged PR review record and run
`git merge-base --is-ancestor $reviewedSha HEAD`; every invocation must return
zero. If final public names differ from this plan, S0 updates only the call-site
names after reading the merged code and preserves the authority and
exact-reference meanings.

### 2.5 Blocker/High findings on `342fcfa`

1. **Blocker — production predecessors are absent.** Current main contains T08
   but not the reviewed T09-T13 implementations. In particular, it cannot prove
   complete production handler coverage or the T13 READY-only boundary. Close
   S0 on the final merged base before writing scheduler code.
2. **High — claim and capacity are not one atomic admission.** The existing
   `WorkflowRunner.activate` creates a START_ATTEMPT reservation before
   `storage.attempt_service.AttemptService.start` checks
   `max_parallel_work`. A full-capacity rejection can therefore leave a
   reserved row. S1 moves reservation creation/claim, capacity check, attempt
   insert, lease, and READY -> RUNNING CAS into one write transaction.
3. **High — cancellation is not durable.** Current work registration,
   PENDING/BLOCKED -> READY, attempt start, work result commit, and run
   finalization have no shared cancel latch. S1 owns this cross-table invariant;
   no parallel lane may patch one call site independently.
4. **High — recovery cannot yet close exact cancellation targets.** Current
   recovery handles PREPARED transitions and expired leases, and correctly
   detects an unresolved external dispatch, but it has no exact persisted
   Provider/static/Sandbox target rehydration or cancellation-first restart
   ordering. Lane C implements this only through the frozen S1 ports.
5. **High — no production application path exists.** Current CLI routes
   `analyze/results/reports` to the deterministic fake pipeline and there is no
   `runtime/worker_pool.py`, production handler registry, or result aggregator.
   Lane D plus the serial integration owner replace the public production path
   without deleting fake regression fixtures.

---

## 3. Fixed production behavior

### 3.1 `run`

```text
parse trusted input
  -> build runtime and adapters
  -> run startup recovery to completion
  -> reject RECOVERY_FAILED / migration / integrity errors
  -> create AnalysisRunState and pin its exact ACTIVE run-level
     ExecutionBudgetProfile in the same durable initialization boundary
  -> enqueue WORKSPACE_PREP only after that pin commits
  -> after workspace READY, pin the exact ACTIVE full BudgetProfileBinding
     before enqueueing any non-WORKSPACE_PREP work
  -> worker pool drains bounded READY work
  -> downstream handlers enqueue subsequent work
  -> stop when terminal, cancelled, or only BLOCKED work remains
  -> if and only if every work is terminal and no PREPARED/unresolved state
     remains, build and atomically finalize AnalysisRunResult
  -> if only BLOCKED work remains, return the recoverable blocked outcome
     without creating AnalysisRunResult
  -> print safe analysis_id and status
```

The repository input is `run <repository> --revision <commit> --program
<program-id> [--profile <profile-key>]`. Branch/ref resolution still belongs to
T08; the durable code identity is the resolved commit.

### 3.2 `status`

`status <analysis-id> [--watch]` is read-only. It reports the current run state,
work counts by status/type, retry/attempt counts, safe stop reasons, elapsed
time, and whether cancel or operator input is pending. `--watch` polls; it does
not start workers or recover external calls.

Because `AnalysisRunState` deliberately has no BLOCKED state, the CLI derives a
display-only `BLOCKED` condition when the run remains RUNNING, no work is
RUNNING/READY, and at least one work is BLOCKED. Do not add a contradictory
domain status merely for display.

### 3.3 `cancel`

`cancel <analysis-id>` first atomically writes the durable cancellation latch.
After the latch is visible:

1. work registration and READY-to-RUNNING claim reject new dispatch;
2. PENDING/READY/BLOCKED work transition to CANCELLED;
3. the worker process polls the latch, resolves each RUNNING work's exact
   current attempt/action target from committed state, and invokes the matching
   T08/T09/T11 cancellation adapter;
4. already committed output/history and actual usage stay committed;
5. only unclaimed, proven-unused reservations are released;
6. ambiguous external outcome remains BLOCKED/RECOVERY_FAILED until reconciled;
7. the run becomes terminal CANCELLED only after all works are quiescent.

Cancel racing with result publication has only two valid atomic outcomes:

- result publication commits first, and that committed result/usage is kept;
- cancel commits first, and the stale publication is rejected.

Neither outcome invents FALSE, HOLD, TRUE, PoC, Finding, or ReportDraft.

The `cancel` command may run in a different process from the foreground `run`.
It therefore never claims that an in-memory Provider task or child process was
stopped merely because it wrote the latch. The owning worker observes the
latch at every scheduling/heartbeat wait and performs exact local cancellation.
If that process has already died, the next startup recovery rehydrates only the
persisted exact targets and either reconciles them or keeps them unresolved;
there is no broad process, Provider, container, or Docker-resource scan.

### 3.4 `resume`

`resume <analysis-id>` always runs startup recovery first. It is allowed only
for the same stored repository/program/workspace/commit and a nonterminal run
whose remaining work is BLOCKED for a retryable or operator-resolvable reason.
It moves eligible BLOCKED work to READY and creates a new `RESUME` attempt when
claimed. It rejects terminal runs, changed inputs/config refs, exhausted
budgets, unresolved external outcomes, and non-retryable failures.

### 3.5 `result`

`result <analysis-id> --format json|summary` reads the exact terminal
`AnalysisRunResult`. It never assembles a provisional result from partial
records. A nonterminal run returns exit code 8 and safe progress guidance.

### 3.6 Windows foreground interruption

`run` and `resume` use one cross-platform async shutdown path. On Windows,
`KeyboardInterrupt` or `asyncio.CancelledError` first persists the same durable
cancellation latch through a shielded bounded call, then asks the owner worker
to cancel exact active targets and waits for a bounded drain. The implementation
does not depend on POSIX-only `loop.add_signal_handler`. If the process is hard
killed before the latch or drain commits, the next command runs startup recovery
before scheduling and never resends an unresolved external action.

### 3.7 Exit codes

Extend the existing enum and map errors once at the CLI boundary:

- `0`: successful command;
- `2`: invalid input;
- `3`: configuration or migration required;
- `4`: unsupported capability or authentication;
- `5`: recoverable blocked state;
- `6`: unrecoverable run failure;
- `7`: cancelled;
- `8`: incomplete/nonterminal result;
- `9`: integrity, stale reference, or unsafe recovery state;
- `10`: unexpected internal failure.

Exit classification is process state, never a vulnerability verdict.

---

## 4. Concurrency and failure isolation

The pool maintains one `asyncio.Task` per claimed work and waits for completions
without serializing independent hypotheses. Capacity is acquired in this order:

1. durable analysis-wide attempt claim under the exact ACTIVE
   `ExecutionBudgetProfile.max_parallel_work`, for every work type including
   `DYNAMIC_REPRO`;
2. provider invocation capacity under exact
   `ExecutionLimits.max_parallel_calls`, inside T09;
3. Verification Pro/Con capacity under exact
   `VerificationBudgetProfile.max_parallel_evidence_calls`, inside T10.

There is no fourth, Sandbox-specific concurrency setting. A dynamic work first
occupies one analysis-wide work claim and then T11 applies its existing exact
container resource and policy bounds. The scheduler never derives concurrency
from an LLM response, CPU quota, PID quota, or timeout.

`max_parallel_work=0` starts no attempt or external action and leaves no active
reservation. A value of `1` permits exactly one RUNNING work across all worker
instances for the analysis. Values of `2` or greater permit that many exact
current attempts, never a separate quota per work type or process.

Do not hold Provider capacity or create a Sandbox environment while a work is
merely waiting in READY/BLOCKED. Release process-local task capacity in
`finally`; durable dispatch, reservation, ledger, and work state still
determine restart safety.

The pool catches a handler failure at the individual task boundary, asks the
work/result owner to persist the permitted FAILED/BLOCKED state, and continues
unrelated work. It never creates a generic vulnerability verdict. Dependency
failure may block descendants through existing workflow rules, but it cannot
cancel sibling hypotheses by exception propagation.

For every live task the owner worker renews the durable lease at a fixed
interval shorter than the lease duration. Renewal succeeds only when
`worker_id`, exact current `attempt_id`, work `state_version`, and input hash
still match. A stale task stops immediately after a failed renewal and cannot
publish output. Heartbeats update only lease/elapsed accounting; they never
create domain output or a verdict. This is local durable heartbeat support, not
a distributed lease coordinator.

The worker also polls the durable cancellation latch before each claim, during
heartbeat waits, and before accepting handler completion. Once latched, it
stops claiming, routes exact active targets to cancellation, and rejects any
late handler result whose attempt/action closure is no longer current.

Fairness for v1 is deterministic round-robin by `(work_type, work_id)` among
READY rows after respecting the overall cap. No priority scheduler, queue
broker, autoscaling, or distributed lease coordinator is added in T14.

---

## 5. Deterministic startup recovery

No production command that can schedule work runs before this sequence:

1. verify schema/migration state and DB integrity;
2. hash-check committed artifacts and quarantine invalid artifacts;
3. resolve every PREPARED transition into the already-provable COMMITTED state
   or ABORTED state without manufacturing output;
4. inspect RUNNING leases and exact external dispatch receipts;
5. treat a lease as live only when its exact worker/attempt heartbeat remains
   current; close expired local attempts and move safely retryable work to
   BLOCKED;
6. leave dispatched-but-unreconciled external actions BLOCKED with
   `RECOVERY_FAILED`; do not resend them;
7. rebuild Provider/static/Sandbox cancellation targets only from the exact
   committed work, attempt, action decision, dispatch, `AgentLog`,
   `SandboxEnvironment`, resource, and cleanup references. Never enumerate
   Provider sessions, host processes, containers, or Docker resources;
8. verify work output refs, domain projections, and current pointers agree;
9. isolate late prior-attempt events/results using attempt ID and state-version
   CAS;
10. re-read the durable cancel latch and finish cancellation before scheduling;
11. only then return recoverable READY/BLOCKED work to the application service.

Recovery is idempotent: running it twice against unchanged storage produces the
same durable state and no new Provider, static tool, policy, or Sandbox call.

---

## 6. Planned file map

### Serial predecessor S0: merged production-handler baseline

S0 changes no T14 implementation file. The integration lead first records one
post-T13 commit that contains T09, T10, T11, T12, and the updated T13 plan's
claimed-context, READY-only `PRIMITIVE_UPDATE` and `CHAINING` handlers. On that
same commit, enumerate every `WorkType` and prove there is exactly one
production `WorkHandler`; prove no handler calls `WorkflowRunner.start`,
`activate`, `AttemptService.start`, another handler, or a worker loop. Record the
single Alembic head and stop if the graph or migration history is incomplete.

### Serial foundation S1: atomic scheduler and cancellation seam

One integration owner makes all S1 changes before any parallel T14 lane. This
ownership is intentionally wider than a conventional port-only seam because
the cancellation latch, capacity decision, reservation, attempt insert,
READY-to-RUNNING CAS, and result-commit latch recheck must share SQLite write
transactions.

- Create `src/sastsimi/ports/scheduler.py` for the four transport protocols and
  frozen claim, cancellation-target, observation, status, and outcome DTOs.
- Modify `src/sastsimi/ports/runtime_store.py` to expose read-only ready/run work
  queries required by the scheduler adapter.
- Modify `src/sastsimi/ports/__init__.py` only for public protocol exports.
- Modify `src/sastsimi/runtime/workflow_runner.py` to add `enqueue` and
  `claim_ready`, retaining the fake-compatible `start` wrapper.
- Modify `src/sastsimi/storage/models.py` for internal durable run-control and
  exact scheduling state.
- Create `src/sastsimi/storage/run_control.py`.
- Create `src/sastsimi/storage/work_dispatch.py`.
- Create `src/sastsimi/storage/cancellation_targets.py` to rehydrate only exact
  persisted T08/T09/T11 targets without external resource discovery.
- Modify `src/sastsimi/storage/work_service.py` so registration and READY
  enqueue check the latch inside their write transactions.
- Modify `src/sastsimi/storage/attempt_service.py` so one transaction resolves
  the exact pinned ACTIVE execution profile, enforces analysis-wide
  `max_parallel_work`, handles capacity without leaking a reservation, inserts
  the attempt/lease, and claims RUNNING.
- Modify `src/sastsimi/storage/transition_service.py` so the final result CAS
  rechecks the latch while cancellation-owned state transitions remain legal.
- Modify `src/sastsimi/storage/analysis_finalization.py` so run-level terminal
  publication resolves the latch in the same transaction: latched runs can
  finalize only as `CANCELLED`; an already committed result remains immutable.
- Modify `src/sastsimi/storage/budget_service.py` only as needed to let the S1
  transaction reserve/claim or leave zero active reservation atomically.
- Create exactly one run-control migration under
  `src/sastsimi/storage/alembic/versions/`. At S0, derive its concrete revision
  and filename as the next unused value after the one actual post-T13 Alembic
  head and record that exact path before editing. Never create a parallel head
  or assume the current planning baseline's `0003` head.
- Create `tests/contract/test_scheduler_ports.py`.
- Create `tests/integration/storage/test_run_control_migration.py`.
- Create `tests/integration/concurrency/test_atomic_dispatch.py` with one normal
  atomic claim test and one parameterized critical failure test covering
  cancel/claim, cancel/result ordering, zero-capacity reservation safety, and a
  stale claimant.

The run-control table is internal runtime state keyed by `analysis_id`, with
cancel request time, safe reason code, and optional quiescent time. It is not a
new public/domain schema and does not carry a verdict.

### Lane A: worker pool, bounded claims, and heartbeat

- Create `src/sastsimi/runtime/handler_registry.py`.
- Create `src/sastsimi/runtime/worker_pool.py`.
- Create `src/sastsimi/runtime/lease_heartbeat.py`.
- Modify `src/sastsimi/runtime/work_service.py`.
- Create `tests/integration/concurrency/test_worker_pool.py`.

### Lane B: durable run control and CLI leaf commands

- Create `src/sastsimi/runtime/run_control.py`.
- Create `src/sastsimi/runtime/cancellation_service.py` to poll the durable latch
  in the owner process and route exact S1 targets to T08/T09/T11 adapters.
- Create `src/sastsimi/interfaces/cli/run.py`.
- Create `src/sastsimi/interfaces/cli/status.py`.
- Create `src/sastsimi/interfaces/cli/cancel.py`.
- Create `src/sastsimi/interfaces/cli/resume.py`.
- Create `src/sastsimi/interfaces/cli/result.py`.
- Create `tests/integration/cli/test_run_control.py`.

Lane B does not edit `interfaces/cli/main.py`, `output.py`, or `exit_codes.py`.

### Lane C: recovery convergence

- Modify `src/sastsimi/runtime/recovery_service.py`.
- Modify `src/sastsimi/storage/recovery_service.py`.
- Modify `src/sastsimi/storage/lease_recovery.py`.
- Create `tests/integration/recovery/test_full_restart.py`.

### Lane D: production orchestration and handler adapters

- Create `src/sastsimi/orchestration/analysis_service.py`.
- Create `src/sastsimi/orchestration/run_initialization.py`.
- Create `src/sastsimi/orchestration/result_aggregation.py`.
- Create `src/sastsimi/orchestration/production_handlers.py`.
- Create `src/sastsimi/orchestration/production_pipeline.py`.
- Create `tests/integration/orchestration/test_production_pipeline.py`.

Lane D calls T08-T13 public services and ports only. It does not import concrete
SQLite adapters, allocate LLM/Gate/domain outputs, or edit T10/T11 modules.
It initializes a run only by atomically pinning the exact ACTIVE run-level
execution budget before the first WORKSPACE_PREP enqueue, and pins the full
ACTIVE binding before any later enqueue. A BLOCKED-only run produces a blocked
transport outcome, never a terminal `AnalysisRunResult`.

### Serial integration owner

- Modify `src/sastsimi/bootstrap.py`.
- Modify `src/sastsimi/runtime/services.py`.
- Modify `src/sastsimi/interfaces/cli/main.py`.
- Modify `src/sastsimi/interfaces/cli/output.py`.
- Modify `src/sastsimi/interfaces/cli/exit_codes.py`.
- Modify package `__init__.py` files only where an integration import requires
  an export.
- Create `tests/e2e/test_production_cli.py`.
- Modify `tests/contract/test_architecture_imports.py`.

The existing `.github/workflows/ci.yml` already runs Ruff, strict mypy, the full
test suite, document validation, and diff checking on Ubuntu and Windows. T14
does not edit that workflow merely to repeat tests. Its one final PR CI run is
the acceptance run. CI action pinning and broader security hardening remain T15.

The integration owner is the only writer of these shared files. It composes the
concrete SQLite adapters, exact handler registry, provider registry, Sandbox
boundary, worker pool, application service, and CLI. The deterministic fake
pipeline remains test-only and is not the implementation behind production
`run`.

---

## 7. Parallel execution DAG and ownership

```text
T08-T13 merged, including T13 ready-only handlers (S0)
                    |
 Serial S1 atomic latch/claim/result/cancel-target seam
                    |
       +------------+------------+------------+
       |                         |            |
Lane A pool/heartbeat   Lane B cancel/CLI   Lane C recovery
       |                         |            |
       +------------ checkpoint I1 ----------+
                    |
          Lane D production composition
                    |
        Serial CLI/bootstrap integration
                    |
       focused E2E + immutable candidate SHA
                    |
           one complete CI suite
```

Lane D may begin in parallel with A/B/C only after S0 has all exact production
handlers and S1 protocols are frozen. Its commit is integrated after I1 so it
cannot guess pool/recovery behavior.
Each lane branches from S1 and edits only its listed files. A lane that needs a
shared file or an upstream API stops and reports the seam; it does not broaden
its allowlist. The integration owner cherry-picks reviewed commits and resolves
all conflicts serially.

No T14 lane modifies T10 Verification implementation files or T11 Sandbox,
reproduction, and session-manager implementation files. S1 and Lane C consume
T11's persisted exact references through storage/read ports; they do not reopen
T11 or create a broad Docker inventory.

---

## 8. TDD implementation tasks

### Task 1: Freeze scheduling and run-control ports

- [ ] S0: record the post-T13 merged base SHA and single migration head; verify
  every T08-T13 `WorkType`, including `PRIMITIVE_UPDATE` and `CHAINING`, has one
  claimed-context, READY-only production handler.
- [ ] RED normal: one READY work is atomically claimed into one exact
  `WorkContext`; its START_ATTEMPT reservation, attempt row, lease, and RUNNING
  work revision are all visible together.
- [ ] RED critical failure: one parameterized test races cancellation against
  claim, work-result commit, and run finalization; include zero capacity and a
  stale claimant. Assert no forbidden attempt, dispatch, active reservation,
  pointer update, or non-CANCELLED run result survives.
- [ ] Write one contract test that checks immutable DTOs, complete handler
  mapping, exact cancellation targets, and no production use of combined
  `start`.
- [ ] Add the minimal ports, `enqueue`/atomic `claim_ready` split, run-control
  table, exact target rehydration query, result-commit latch guard, and
  single-head migration.
- [ ] Run:

```powershell
uv run python -m pytest tests/contract/test_scheduler_ports.py tests/integration/storage/test_run_control_migration.py tests/integration/concurrency/test_atomic_dispatch.py -q
uv run ruff check src/sastsimi/ports/scheduler.py src/sastsimi/runtime/workflow_runner.py src/sastsimi/storage/run_control.py src/sastsimi/storage/work_dispatch.py src/sastsimi/storage/cancellation_targets.py src/sastsimi/storage/work_service.py src/sastsimi/storage/attempt_service.py src/sastsimi/storage/transition_service.py src/sastsimi/storage/budget_service.py src/sastsimi/storage/models.py tests/contract/test_scheduler_ports.py tests/integration/storage/test_run_control_migration.py tests/integration/concurrency/test_atomic_dispatch.py
uv run mypy src/sastsimi/ports/scheduler.py src/sastsimi/runtime/workflow_runner.py src/sastsimi/storage/run_control.py src/sastsimi/storage/work_dispatch.py src/sastsimi/storage/cancellation_targets.py
```

- [ ] Commit S1 and branch all lanes from that exact SHA.

### Task 2A: Implement bounded worker scheduling and heartbeat

- [ ] RED normal: use an `asyncio.Barrier` to run two independent READY works
  with `max_parallel_work=2`; assert both overlap and each completes through its
  registered handler.
- [ ] RED critical failure: one parameterized test covers two workers racing for
  one READY row, caps `0` and `1`, a stale heartbeat, and one handler failure.
  Assert at most one claim, no capacity leak, no stale publish, and the unrelated
  work remains runnable without an invented verdict.
- [ ] GREEN: implement complete registry validation, deterministic ready-work
  selection through the S1 atomic claim port, per-work exception isolation,
  durable heartbeat, cancellation-latch polling, and clean shutdown.
- [ ] In the same focused tests, assert T09 Provider and T10 Pro/Con inner caps
  remain enforced and `DYNAMIC_REPRO` consumes the same analysis-wide work cap;
  do not add a Sandbox-specific cap.
- [ ] Run only Lane A tests, Ruff, and mypy; commit the lane.

### Task 2B: Implement cancel, resume, and CLI leaf services

- [ ] RED normal: `cancel` in a second process writes the latch, the owner worker
  observes it, cancels only the exact persisted target, reaches quiescence, and
  a same-input eligible BLOCKED run later resumes through a new `RESUME` attempt.
- [ ] RED critical failure: one parameterized test rejects cross-run/cross-
  attempt targets, terminal or changed-input resume, exhausted budgets, and
  unresolved external dispatch. Simulate Windows `KeyboardInterrupt` and assert
  the latch is durable before bounded drain and restart performs zero duplicate
  sends.
- [ ] GREEN: add runtime run-control and exact T08/T09/T11 cancellation routing
  over the frozen S1 storage ports. Never enumerate broad external resources.
- [ ] Add read-only status/result projections and safe command responses.
- [ ] Run only Lane B tests, Ruff, and mypy; commit the lane.

### Task 2C: Implement deterministic scheduler recovery

- [ ] RED normal: recover one PREPARED transition and one expired lease, then run
  recovery again and assert identical records/pointers and zero external calls.
- [ ] RED critical failure: one parameterized test covers a dispatched/unreturned
  external action, a stale prior-attempt event, and a foreign or missing
  Provider/static/Sandbox resource ref. Assert BLOCKED/RECOVERY_FAILED, no
  resend, no broad discovery/cancel, and no current pointer movement.
- [ ] GREEN: extend startup recovery in the fixed order from Section 5.
- [ ] Assert a pre-crash cancellation latch completes before any scheduling.
- [ ] Run only Lane C tests, Ruff, and mypy; commit the lane.

### Task 3: Integrate and verify checkpoint I1

- [ ] Cherry-pick A, then B, then C onto S1.
- [ ] Run the union of their focused tests once.
- [ ] Resolve only Blocker/High failures in the owning files and record I1 SHA.

### Task 4: Compose T08-T13 into the production application

- [ ] RED normal: a local fake-provider/fake-tool production run reaches one terminal
  ReportDraft through the production handler registry, not `FakePipeline`.
- [ ] RED critical failure: one parameterized test covers one hypothesis handler
  failure, a BLOCKED-only quiescent run, and missing/duplicate handler mapping.
  Assert independent work continues, PARTIAL contains exact failure inventory,
  BLOCKED produces no terminal result, and registry defects fail before run
  creation.
- [ ] GREEN: implement initialization, downstream enqueue routing, pool drive,
  result aggregation, and finalization through public services only.
- [ ] Assert run initialization pins the exact ACTIVE run-level execution
  profile before WORKSPACE_PREP, and full binding before later work.
- [ ] Assert a BLOCKED-only quiescent run returns the blocked transport outcome
  and has no terminal `AnalysisRunResult`.
- [ ] Run only Lane D tests, Ruff, and mypy; commit the lane.

### Task 5: Wire public CLI commands serially

- [ ] Replace the public fake `analyze/results/reports` route with the approved
  `run/status/cancel/resume/result` command set. Keep fake helpers importable by
  tests but not advertised or selected by production CLI.
- [ ] Ensure bootstrap runs recovery before returning the application service.
- [ ] Map the exit codes from Section 3.7 without echoing secrets, host paths, or
  raw provider/tool errors.
- [ ] RED/GREEN E2E normal path: `run` then `status` then `result` returns one
  exact terminal result.
- [ ] RED/GREEN one parameterized critical path: unresolved-dispatch crash and
  Windows foreground interrupt both leave restart-safe durable state; `resume`
  stays blocked and performs zero duplicate calls.
- [ ] Run:

```powershell
uv run python -m pytest tests/e2e/test_production_cli.py tests/integration/recovery/test_full_restart.py -q
uv run ruff check src/sastsimi tests/e2e/test_production_cli.py tests/integration/concurrency tests/integration/recovery/test_full_restart.py
uv run mypy src/sastsimi
```

### Task 6: Candidate and one complete CI run

- [ ] Review diff ownership, migration head, generated files, and secret/path
  safety; fix only Blocker/High issues.
- [ ] Commit the immutable T14 candidate and record its SHA.
- [ ] Run the complete repository CI exactly once on that SHA.
- [ ] If CI finds a Blocker/High issue, make the smallest fix, record a new
  candidate SHA, and run complete CI once on that new candidate.
- [ ] Record Medium/Low observations in the follow-up list without expanding
  T14.

---

## 9. Required acceptance scenarios

These are assertions inside the normal and parameterized critical tests named
above, not seventeen new standalone test modules. Add another test only when a
Blocker/High behavior cannot be expressed safely in those two focused shapes.

1. **Normal production flow:** one repository and one hypothesis finish through
   ReportDraft, quiesce, and finalize once.
2. **Duplicate claim:** two workers race at a barrier; only one attempt starts.
3. **Late result:** attempt 1 expires, attempt 2 starts, and attempt 1's output is
   rejected without moving a pointer.
4. **Cancel/result race:** both atomic orders preserve valid committed facts and
   never create a verdict from cancellation.
5. **Reservation accounting:** unused unclaimed reservation is released;
   claimed or unknown-use reservation remains accounted/reserved for recovery.
6. **Independent failure:** one hypothesis fails and another finishes; analysis
   is PARTIAL, not globally aborted.
7. **Concurrency:** `max_parallel_work=0` starts nothing, `1` never overlaps,
   and `2+` bounds all work types including dynamic reproduction across worker
   instances; Provider and Pro/Con sub-limits are each reached but never
   exceeded.
8. **Lease heartbeat:** the exact live attempt renews; a prior worker/attempt
   cannot renew or publish after replacement.
9. **Full restart:** PREPARED transition and expired lease converge; a second
   recovery pass is a no-op.
10. **External uncertainty:** dispatched/unreturned Provider or Sandbox action is
   blocked with no automatic resend.
11. **Exact cancellation:** a separate cancel process writes the latch, the owner
    worker cancels only exact persisted attempt/action targets, and restart
    rehydrates Sandbox targets without Docker enumeration.
12. **Resume:** eligible same-input BLOCKED work creates a RESUME attempt;
    terminal or stale work is rejected.
13. **Blocked is not terminal:** a BLOCKED-only quiescent run returns progress
    and creates no `AnalysisRunResult`.
14. **Terminal result:** finalization rejects any nonterminal work, PREPARED
    transition, unresolved dispatch, stale reference, or mismatched inventory.
15. **Run budget pin:** WORKSPACE_PREP has the exact run-level ACTIVE profile;
    every later work has the exact full ACTIVE binding before READY registration.
16. **Windows interruption:** interrupt records cancel intent before bounded
    drain; hard-stop restart performs recovery and zero duplicate dispatches.
17. **CLI safety:** output contains no credential, session, raw stderr, or host
    absolute path.

---

## 10. Definition of done

- The production CLI no longer depends on the deterministic fake pipeline.
- Every T08-T13 work type, including T13 `PRIMITIVE_UPDATE` and `CHAINING`, is
  reachable only through one claimed-context, READY-only registered handler.
- READY work is claimed atomically with latch, pinned profile, capacity,
  reservation, attempt, and RUNNING CAS. The final result CAS rechecks the same
  latch.
- Exact ACTIVE `ExecutionBudgetProfile.max_parallel_work` bounds every work type
  analysis-wide; no separate Sandbox concurrency setting exists.
- Cancel intent is durable and prevents new work before adapter cancellation.
- Cancellation and restart resolve only exact persisted attempt/action/resource
  targets and never enumerate Docker or other external resources.
- Resume never revives terminal/stale work or resends an uncertain action.
- Startup recovery runs before scheduling and is idempotent.
- Exact live attempts renew durable leases; stale workers cannot renew or
  publish.
- One hypothesis failure is isolated and represented without an invented
  verdict.
- BLOCKED-only quiescence never finalizes. Analysis finalization is exactly once
  and only after all work is terminal with no PREPARED or unresolved state.
- Windows foreground interruption persists the latch before bounded drain, and
  hard-stop restart follows the same deterministic recovery boundary.
- Focused tests, Ruff, and strict mypy pass; complete CI is run once on the
  recorded candidate SHA.
- No T10/T11 implementation file was edited by a parallel T14 lane.
