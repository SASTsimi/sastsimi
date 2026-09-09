# Task 6 — persistent runtime and recovery

Implements the local storage foundation from [R3-06 sections 6 and 10](../../../architecture-v5/implementation/06-implementation-baseline.md), [the recovery test plan](../../../architecture-v5/implementation/03-recovery-test-plan.md), and [ADR-015](../../../review/decisions/ADR-015-r3-implementation-baseline.md). Domain names and payloads remain the T04/T05 contracts. Role review and integration are separate from this implementation commit.

## Composition and public boundaries

`bootstrap.build_runtime` composes the concrete adapters, checks the migration revision, and runs recovery before returning `RuntimeServices`. It accepts injected `Clock` and `IdGenerator` ports. Workspace/commit can be absent during run bootstrap; canonical record files can be published before code-scoped artifact references are available.

`runtime/` imports contracts and ports only. `ports/runtime_store.py` adds transaction-level work, attempt, action authorization, registry, and recovery interfaces without exposing a SQLAlchemy connection. SQLite implementations live in `storage/`. The existing `RecordStore`, `ArtifactStore`, `UnitOfWork`, and `BudgetLedgerPort` contracts remain unchanged.

The public `authorize(ActionRequest)` operation derives required checks from current state, exact configuration and a bootstrap-injected `TrustedEvidencePort`. The default evidence implementation denies unproven identity, approval, pricing, policy and item quantities. Immutable caller-published PASS decisions are not issued authorizations. Request/check/decision projections are persisted together; workflows cannot supply their own PASS checks through the authorization API.

External invocation uses `ExternalCallService.invoke`: the authorization port checks and commits its action/reservation claim, then durably marks dispatch before the callable constructs an awaitable. Pre-dispatch claims can resume only while the decision, reservation and pricing/capacity proof remain valid. Dispatched requests retain exact request/idempotency metadata; an unknown outcome blocks another invocation, even under a new action. Usage remains reserved until explicit ledger commit; cancellation or an unknown external outcome never implies zero usage or release.

## SQLite and migration

CPython 3.12, SQLAlchemy 2, Alembic, local SQLite, and no external queue are used. Every new connection sets foreign keys ON, WAL, synchronous FULL, and a 5000 ms busy timeout. `Database.write()` uses `BEGIN IMMEDIATE`, commits on success, and rolls back on every exception, including process-interruption fixtures.

Packaged Alembic resources contain `0001_runtime` and `0002_authorization`; the latter adds request/check/dispatch projections and nullable historical item accounting. Startup checks rather than applies migrations. Explicit operator commands are:

```text
sastsimi --data-dir <local-runtime-directory> db current
sastsimi --data-dir <local-runtime-directory> db upgrade [revision]
sastsimi --data-dir <local-runtime-directory> db downgrade <revision>
```

Empty downgrade and re-upgrade are supported. A downgrade with any persisted application data is refused; this implementation has no implicit lossy rollback or inferred backfill. Unknown/pending revisions raise `MigrationRequired` with exit-code semantics 3. The migration interruption test proves partial DDL rolls back before a subsequent upgrade succeeds.

Physical tables cover immutable candidates/revisions, current pointers, work/attempt leases, single-use action decisions, transition journals, artifact hashes, pinned budget profiles, reservations, and append-only ledger entries. The migration and persistence models are separate from Pydantic domain models. Later workflow-owned projections are not pre-created as empty competing schemas.

`RuntimePaths` centralizes `db/sastsimi.sqlite3`, top-level `staging/` and `quarantine/`, and `artifacts/sha256/<first-2>/<remaining>`. Installed-wheel smoke tests resolve migrations without a repository checkout. CLI results identify their actual database command, including JSON envelopes and migration-required exit code 3.

## Record and artifact publication

Canonical JSON v1 and SHA-256 are calculated from validated registered contract models. Nested reference `content_hash` fields remain part of the bytes as provenance. A persisted record does not carry its own top-level hash; the exact reference and storage envelope carry it. The existing canonical helper continues to reject self-referential top-level hashes.

Candidate records are immutable and invisible to ordinary exact-record reads until publication. Record IDs are globally unique, logical revision numbers cannot fork, and a successor must resolve its exact published predecessor. Exact reads verify the complete reference and recompute the payload hash.

Publication proceeds through these durable boundaries:

1. Stage validated canonical candidate files; flush and sync file contents.
2. Transaction A publishes the immutable transition/PREPARED audit record and journal binding.
3. Recheck active attempt, state version, pinned inputs, and unused action authorization.
4. Atomically rename candidate files into the SHA-256 directory.
5. Transaction B repeats CAS, claims the action, publishes all output revisions/pointers, closes the attempt/work, appends action outcomes, and marks the journal COMMITTED together.

Only the complete transaction exposes domain output. A state-change decision alone cannot publish a domain result: output publication requires SAVE_RESULT and the canonical result owner. Candidate records must exactly match authorized output closure; arbitrary same-owner extras are rejected. Current-sensitive state inputs are rechecked before PREPARED replay and transaction-B CAS; historical non-state provenance remains resolvable. A changed candidate binding cannot replay an existing journal. Late/stale results cannot advance current pointers.

`SQLiteUnitOfWork.rollback()` preserves invisible staging and durable PREPARED journals; the object holds no long-lived SQL transaction. Replaying the same committed request returns its already committed result.

## Budget and attempts

The registry atomically pins one trusted-approved/priced ACTIVE execution profile with the canonical `AnalysisRunState` for WORKSPACE_PREP. Bootstrap cannot prepopulate workspace identity or bypass its transition. A committed workspace output advances that run state; full binding activation requires its exact READY run-state CAS and trusted approval. All four binding references resolve to active profiles in the same scope; purpose must match. Public action decisions record the bootstrap execution profile or the full checked binding and selected work/verification/dynamic profiles; the binding retains its exact execution profile provenance.

Reservations count active reservations and committed usage in one transaction, aggregate run-bootstrap and code-scoped usage in the same analysis, reject currency/scope mismatches, and enforce approved total elapsed/work/call/retry/cost limits. Work operation selection is trusted and unlisted operations are denied. Per-work timeout, attempt, and external-call ceilings are checked without caller-provided operation aliases. Applicable Verification ancestor elapsed/work/call limits, per-work retry limits, and dynamic attempt limits are checked in that same transaction. Registration must reserve a work unit, and LLM execution must reserve a call unit.

External execution requires positive applicable elapsed/cost/call capacity and trusted pricing; zero-unit requests do not bypass exhaustion. Dynamic INITIAL does not consume a retry/resume slot. Dynamic preflight resolves the exact work profile and `WORK_REMAINING_TIME`, subtracting committed and reserved elapsed usage. Trusted per-action item quantities are recorded and accumulated per work; unknown historical quantities fail closed. Evidence-call reservations atomically enforce the verification-root parallel cap.

Reservation IDs have at most one ledger entry; changing an entry ID cannot debit twice. Identical commit/release calls are idempotent. Unclaimed pre-execution reservations can be released. Claimed reservations cannot be released as unused; unresolved usage remains RESERVED across restart. Work dedupe returns the existing work without claiming another action, and a partial unique index prevents two RUNNING attempts for one work. Analysis-wide parallel-work capacity is checked in the same attempt-claim transaction.

Starting a later attempt requires at least one reserved retry unit; a zero-quantity reservation cannot bypass the aggregate retry ceiling, including after an uncertain lease was recovered as BLOCKED.

## Recovery and verification

Recovery checks migration/integrity, replays PREPARED journals, verifies every tracked artifact and published record, compares every current pointer's logical identity/revision and committed output closure, and quarantines orphan files without exposing them. RUNNING work must have a RUNNING active attempt; terminal attempts cannot start. Unresolved corruption blocks consumers with RECOVERY_FAILED. Unknown dispatched calls and expired uncertain leases are closed conservatively as BLOCKED/INPUT through a publicly authorized recovery-owned transition when trusted recovery identity evidence is supplied. Reservations are preserved and external calls are never automatically replayed.

Tests live under `tests/integration/storage/`, `tests/integration/budget/`, `tests/integration/recovery/`, and `tests/security_negative/test_budget_double_debit.py`. They cover staging, PREPARED, CAS, rename, transaction-B rollback, COMMITTED replay, stale CAS, corrupt files/pointers, orphan quarantine, migration interruption, concurrent reservations and attempts, once-only usage, scoped profile authorization, and a second SQLite connection writing while the generic external invocation boundary is suspended in the LLM/static/policy/Docker scenarios.

Windows does not expose POSIX directory `fsync`; files are synced and recovery verifies hashes, but no unsupported directory-durability capability is claimed. The checkpoint tests simulate process interruption at explicit boundaries; physical power-loss and real provider/Docker capability tests belong to deployment/adapter validation. Workflow item counts and approval/pricing provenance must be supplied by the trusted host evidence adapter; missing evidence fails closed. Monotonic usage samples and supported exact-request provider reconciliation belong to executing adapters; this foundation persists dispatch identity and blocks unknown outcomes without claiming a real reconciliation capability.
