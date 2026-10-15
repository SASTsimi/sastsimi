# V9 dashboard projection batching without stale completion

## Intent and boundaries

The live A-001 Python analysis has 36 pinned V9 surface-context parts. A
single part can create several child hypotheses. Today the checkpoint store
rebuilds all five indexed dashboard tabs after checkpoint and LLM-attempt
writes. Repeating that work inside one part dominates elapsed time while
adding no new security evidence. The requested outcome is fewer full index
rebuilds, with unchanged source commits, Agent decisions, PoC execution,
resume semantics, and honest `PARTIAL`/`COMPLETE` conditions. This design does
not pause or modify the currently running A-001 process or its SQLite data.

The default boundary is **one V9 context iteration**, not the entire V9 run.
The proposal call, its atomic progress/registration commit, and child drain
share one task-local projection scope. At the scope exit, including failure
or cancellation, the dashboard is rebuilt once from committed source data.
Progress and logs continue to use their existing source-backed paths;
indexed detail tabs may say “index updating” until that part ends. An optional
future finer boundary per child/stage is outside this change unless the
measured V9 context becomes too long for practical dashboard use.

## Alternatives considered

1. **Context-scoped synchronous batching (chosen).** Reuse the current
   post-commit projector, suppress intermediate rebuilds, and publish once
   per part. It changes a narrow execution boundary while retaining durable
   source writes and recovery behavior. Detailed indexed tabs update less
   frequently during a long part.
2. **Per-stage batching.** Keeps detailed tabs fresher, but each hypothesis
   still causes several full rebuilds and saves less time. Use it only if a
   measured context duration makes the chosen UI interval unacceptable.
3. **Background projection worker or SQLite triggers.** Could index
   asynchronously or cover every writer centrally, but requires new worker,
   migration, and lifecycle machinery. It is too broad for this fix.

## Durable state and writer rules

The source database and dashboard read model are tables in the same SQLite
file. Source transactions must remain independent and durable; projection
failure never rolls back a successful analysis step. A small shared
projection-scope dispatcher, keyed by resolved data directory and analysis
ID in a `ContextVar`, is visible to both the application checkpoint store
and the LLM-attempt store. Nested scopes flush only on the outer exit;
different analyses do not suppress one another's projection.

Every dashboard-relevant source write reached by this V9 boundary must set
`dashboard_index_state` to `INCOMPLETE` **in the same source transaction**.
This includes checkpoint `_write`, LLM-attempt recording, direct store writes
that currently call `_project_after_direct_commit`, and
`commit_surface_exploration` (which currently has no projection callback).
The implementation will audit those writers rather than assuming the two
most obvious paths are sufficient. If the dashboard schema is absent, source
writes still succeed; an explicit rebuild can initialize the index later.
The dirty marker has a distinct, safe update reason and may not overwrite a
newer `READY` index after a competing successful projection.
Each dirty transition receives a fresh opaque `source_marker` token; the
published `READY` marker keeps the existing checkpoint/HOLD marker format.

Outside a deferral scope, relevant commits retain the existing immediate
projection behavior. Inside it, callbacks only record that a flush is due.
On outer scope exit, one rebuild runs even if a resumed part made no new
writes but inherited an `INCOMPLETE` index. If that rebuild fails, the source
results remain intact and the index stays `INCOMPLETE`; later resume or
explicit `dashboard-index rebuild` may retry. An interrupted or killed
process leaves a durable dirty index, never a stale successful index.

## Race-free publication and reads

The existing checkpoint/HOLD `source_marker` does not cover LLM-attempt and
several direct writes. Therefore a before-scan marker alone cannot prove
that a collected snapshot is current. The projector will open a guard SQLite
connection before collecting source pages, capture its `PRAGMA data_version`,
then acquire `BEGIN IMMEDIATE` on that same connection before publication.
If the version changed, or the dirty/index state was superseded, it aborts
publication and leaves or restores `INCOMPLETE`; it must not publish a stale
`READY`. The accepted page replacement and final `READY` transition occur
under that write transaction. Any source commit after it necessarily dirties
the index again in its own transaction. A competing failed/stale projector
cannot overwrite a newer successful projection with an old failure marker:
its failure update compares the dirty token captured before collection and
does nothing when that token has changed. Explicit rebuild from an existing
`READY` row uses the same compare-and-swap rule against that row's marker.
Existing content-addressed artifact verification remains in force.

An indexed page request uses one explicit SQLite read transaction for state,
HOLD generation, summary, and items, preventing a mixed old/new response.
While the index is dirty and the analysis lease is active, the API returns
the existing 409 `index_updating`; if the lease is gone, it returns 409
`index_resume_required`. The browser labels this generically as dashboard
index work, not specifically HOLD review. It never serves old detail rows as
current. Source-mode fallback remains an explicit operator option rather
than an automatic expensive or misleading fallback.

## Compatibility, tests, and acceptance

No original analysis checkpoint, artifact, or finding is rewritten for this
optimization. Existing index rows can be rebuilt; no source-data migration
or new worker is required. An old A-001 process uses its already imported
code until it naturally exits; only a later safe resume can load the new
batching code. The new branch is based on current `main` and leaves the live
worktree untouched.

Test-first verification covers: exactly one rebuild per V9 context with
multiple child writes; all source commits remaining durable; nested scopes
and task/analysis isolation; LLM and direct writes; no-new-write resume of a
dirty index; exception/cancellation/crash leaving `INCOMPLETE`; a stale
projector attempting to publish after a newer source commit; competing
failure not clobbering `READY`; coherent concurrent page reads; active and
idle 409 responses; unchanged unbatched behavior and HOLD-only batching.
Run focused dashboard/runtime suites, full regression, lint/type checks, and
measure before/after rebuild counts and wall time on a bounded local fixture.
Do not report a speed percentage for A-001 until measured on its actual
subsequent execution. A-001 coverage and vulnerability verdicts do not
change merely because its dashboard became faster.
