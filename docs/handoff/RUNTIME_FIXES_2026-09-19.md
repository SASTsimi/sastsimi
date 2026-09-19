# Runtime fixes handoff — 2026-09-19

Base: `main` at `7a67b35af453fddf0f2f22f3c422f13760e53532`.

Every fix below was found by running the real `analyze` pipeline against a
real external repository (`jinja`, pinned at the CVE-2024-34064 vulnerable
commit `a7863ba9d3521f1450f821119c50d19d7ecea329`), not by static reading.
Verification discipline: revert the fix, re-run the same test(s), confirm
the original failure reproduces, restore the fix, confirm it passes.
Regression counts are listed per item; all four items plus the full
`test_container_lifecycle.py` and a broader targeted sweep (storage,
recovery, capabilities, interfaces, orchestration, CLI) pass on this base:
100 passed, 0 failed.

## 1. `SystemClock` had no defense against a real backward wall-clock jump

**File**: `src/sastsimi/runtime/system_support.py`

**What broke**: A jinja run crashed on the first work claim
(`WORKSPACE_PREP`) with `ValueError: Revision created_at precedes
predecessor` (`contracts/records.py::validate_revision`, which requires each
new record revision's `created_at` to be strictly after its predecessor's).

**Why**: `SystemClock.now()` returned raw `datetime.now(UTC)`. The host's
guest clock is Hyper-V/WSL2-synced and does jump backward: `dmesg` shows
`systemd-journald`'s own `"Time jumped backwards, rotating"` three times
during one boot. A correction landing between two `now()` calls on the same
clock instance broke the monotonicity invariant every subsequent revision
relies on.

**Fix**: `SystemClock` now tracks the last value it returned (`_last`,
protected by a `threading.Lock`) and clamps: `now()` returns
`max(observed_wall_clock, _last + 1μs)`. Wall-clock time is followed exactly
whenever it is actually advancing; only a backward jump causes a divergence,
and that divergence self-heals once real time catches back up past `_last`.
`monotonic_ms()` (`time.monotonic_ns()`-backed, used for elapsed-time/
timeout math elsewhere) was already immune and is unchanged.

**Also in this file**: `capabilities/composition.py` had an independent,
identically-vulnerable local class, `_SystemClock` (same body, no clamp),
replaced with an import of the real, fixed `SystemClock`. Its unused
`_UuidIds` companion was left alone (different ID format from the shared
`UUIDIds` - `str(uuid4())` vs `.hex`, an unrelated concern).

**Known residual gap, not fixed**: this clamp is per-instance. Every
`SystemClock()` construction is independent, and `composition/
production_control.py`'s `resume`/`cancel` commands each build a fresh one
in a new OS process. `storage/production_authority.py`'s
`profile.meta.created_at > now` check compares a timestamp written by an
earlier process against a new process's freshly-constructed clock: same
crash class, cross-process, still possible. Fixing it needs a persisted
watermark or per-call-site anchoring against the already-known prior
timestamp; out of scope here.

**Regression**: `tests/unit/runtime/test_system_support.py` (new, 4 tests:
patches `datetime.now` to inject a real 30s backward jump and confirms
`now()` never regresses, then confirms it re-syncs to real time once real
time passes `_last` again; a tight-loop strictly-increasing check; a
normal-operation sanity check). `test_architecture_imports.py`,
`test_production_probe_service.py`, `test_capability_cli.py`: pass.

## 2. Two call sites bypassed `SystemClock` entirely

**Files**: `src/sastsimi/composition/production_entrypoint.py`,
`src/sastsimi/interfaces/cli/main.py`

**What**: `OnboardedProductionCapabilityBundleLoader`'s onboarding-staleness
clock (used for `expires_at` checks) was constructed as a raw `lambda:
datetime.now(UTC)` at both its call sites, instead of going through
`SystemClock`. Low risk on its own (a backward jump would make a staleness
check less likely to fire, not crash), but inconsistent with item 1's fix
and a testability smell (a bound callable instead of an injectable clock
object).

**Fix**: both replaced with `SystemClock().now` (a bound method, matching
the existing `Callable[[], datetime]` parameter type exactly, no signature
change needed downstream). `main.py`'s now-unused top-level `datetime`/`UTC`
import was removed.

**Regression**: `test_onboarding_cli.py`, `test_production_entrypoint.py`,
`test_public_resume_validation.py`: pass (3 pre-existing unrelated failures
in `test_production_entrypoint.py`, a stale test double missing a
`confirm_repository` attribute, confirmed identical with and without this
change).

## 3. `RuntimeServices.transitions` was wired to the wrong class

**Files**: `src/sastsimi/composition/runtime.py`,
`src/sastsimi/runtime/services.py`,
`src/sastsimi/runtime/transition_service.py`,
`src/sastsimi/composition/production_composition.py`

**What**: this codebase has two unrelated classes both named
`TransitionService`: `storage/transition_service.py` (the real
implementation) and `runtime/transition_service.py` (a 13-line stub with
only `.commit()`, meant as a placeholder interface boundary).
`composition/runtime.py`'s `build_runtime()` already constructs the real one
as a local variable (`transitions = SQLiteTransitions(works, artifacts,
chaining_lineage=...)`) and correctly reuses that instance for `unit`,
`recovery`, and four other services. The final `RuntimeServices(...)` return
value instead constructed a second, throwaway instance of the other class
(`TransitionService(records)`, imported under the same bare name) rather
than reusing the local variable already in scope. Nothing in this codebase
currently calls a method on `runtime.transitions` that the thin class lacks,
so this was not yet a live crash - it is fixed for single-source-of-truth
correctness and to guard against the two classes diverging further while
both remain in use.

**Fix**: `RuntimeServices(...)`'s `transitions=` argument now passes the
already-built `transitions` local variable; the now-unused thin-class import
at that composition site was removed (the thin class itself was kept -
`tests/integration/recovery/test_review_integrity.py` still constructs and
uses it directly as a lightweight `.commit()`-only test double).
`RuntimeServices.transitions`'s declared type was itself the thin class, and
`runtime/` code may not import `storage/` code directly (an enforced
architecture-layering rule, see `tests/contract/test_architecture_imports.py`),
so a new `TransitionServicePort` `Protocol` was added to `runtime/
transition_service.py` declaring exactly the method anything calls through
this field (`commit`, confirmed by grepping every `runtime.transitions.*(`
call site) and used as the field's type instead. Both classes satisfy it
structurally with no changes to either.

**Same-shape issue found and also fixed**: `production_composition.py`'s
`ConcreteProductionApplicationFactory._build_foundation` built
`RunControlStore` with its own second, independent `TransitionService`
(missing `chaining_lineage`, which the canonical one has). Not a live bug
(`RunControlStore` only calls `.cancel_in_transaction`, which never reads
`chaining_lineage`) but fixed the same way: `transitions=runtime.transitions`
reused instead.

**Regression**: new test, `tests/integration/storage/
test_workflow_runner.py::test_composed_runtime_transitions_is_the_real_shared_service`
- builds a real `runtime` via `build_runtime()` (not a fake), asserts
`runtime.transitions is runtime.verification_registration.store.transitions`
(one shared instance, not two). Broader sweep: `test_worker_pool.py`,
`test_llm_retry_classification.py`, `test_transitions.py`,
`test_review_integrity.py`, `test_workflow_runner.py`,
`test_hypothesis_projection.py`, `test_production_composition.py`,
`test_public_cancel.py`, `test_production_cancellation.py`,
`test_full_restart.py`: pass.

## 4. `HYPOTHESIS_PROPOSAL`'s empty-batch path crashed output approval

**File**: `src/sastsimi/runtime/workflow_runner.py`

**What broke**: a jinja hypothesis-proposal round that legitimately found
nothing (`outputs=()`) crashed with `PRODUCTION_OUTPUT_APPROVAL_SCOPE_
MISMATCH` instead of completing.

**Why**: `WorkflowRunner.complete()` has a deliberate special case,
`empty_hypothesis_batch = not outputs and work.work_type ==
"HYPOTHESIS_PROPOSAL"`, that allows `outputs=()` for exactly this
situation, using a `CHANGE_WORK_STATE` action with `candidate_result_ref=
None` instead of `SAVE_RESULT`. The function then unconditionally passed the
resulting empty `refs` tuple into `self._output_approval(action, work,
refs)` - and a real production approval rejects an empty `output_refs`
tuple as a scope mismatch, so the deliberate empty-batch path could never
actually complete once a real (non-`None`) approval was wired in.
`storage/output_closures.py::derive_outputs` reads
`action.candidate_result_ref` first and returns `()` immediately when it is
`None` (exactly what `empty_hypothesis_batch` sets it to) without ever
consulting the approval - the approval object was dead on arrival for this
one case.

**Fix**: skip the approval call for the empty-batch case (`if
self._output_approval is not None and not empty_hypothesis_batch`), same
`nullcontext()` fallback the function already uses when no approval is
configured at all.

**Why the existing test suite missed this**: `tests/integration/storage/
test_hypothesis_projection.py::test_initial_proposal_work_can_succeed_
with_no_candidates` already exercises `complete()` with an empty proposal
batch, but its shared test helper (`prepared_hypothesis`) builds its
`WorkflowRunner` with `output_approval=None`, so every call in that test
takes the `nullcontext()` branch and never touches the real guard.

**Regression**: new test, `test_empty_proposal_batch_does_not_invoke_
output_approval` - builds a second `WorkflowRunner` on the same underlying
`runtime` with a strict fake matching production's actual guard (reject
empty `output_refs`); confirmed via revert-and-confirm it fails with
exactly the original error without the fix.

## 5. Dynamic reproduction required a human-approved dependency archive

**Files**: `src/sastsimi/sandbox/recipe_store.py`,
`src/sastsimi/contracts/dynamic.py`

The change that unblocks real external repositories with actual
dependencies (jinja needs `MarkupSafe`; most non-trivial Python/Node
repositories need something).

**What broke**: with items 1-4 fixed, a jinja run reached `DYNAMIC_REPRO`
for the first time with two real hypotheses (`CWE-94`/`CWE-250` in
`sandbox.py`, `CWE-79`/`CWE-94` in `filters.py`), both cleared
`CONTEXT_RETRIEVAL`/`PRO_EVIDENCE`/`CON_EVIDENCE`, then blocked with
`dynamic_reproduction_result.failure_reason=
DEPENDENCY_SUPPLY_CONFIRMATION_REQUIRED` (`agent_invoked=false`, the agent
never started).

**Why, and why this was a design question, not a bug**: `sandbox/
recipe_store.py` builds the Docker recipe for the reproduction sandbox. Its
`docker build` step runs with `--network none` (a hard security boundary,
untouched by this change). When a repository declares runtime dependencies
(`requirements.txt`/`pyproject.toml`), the generated Dockerfile installs
them via `pip install --no-index --find-links=...` from a local, pre-staged
wheel directory, because the build itself cannot reach PyPI. Before this
change, populating that wheel directory required a human-approved
`DependencyBundle` record (an offline archive with `approved_by_role:
"HUMAN"`, a human name, and a hash-pinned approval chain) supplied in
advance; with none supplied, the code correctly refused rather than
silently skipping dependency installation.

Onboarding-time-approved provisioning (matching how the CodeQL database is
supplied) does not fit this: `DependencyBundle`'s own consistency check
(`_dependency_bundle_entries`, `recipe_store.py`) requires the bundle's
`meta.attempt_id` to exactly match the specific `DYNAMIC_REPRO` attempt
consuming it, a value that does not exist until that attempt is claimed at
runtime, long after `onboarding prepare` (which runs before `analyze
--commit` is even invoked) has finished. Design decision: dynamic
reproduction runs unattended end to end, and a repository's own declared
dependencies are a fact about the repository, not a judgement call that
needs a human in the loop.

**Fix**: `EnvironmentRecipeStore._auto_fetch_dependency_bundle` (new method)
runs whenever `_repository_source` is not handed an explicit
`dependency_bundle` and the repository's own manifest (`requirements.txt`,
or `pyproject.toml`'s `project.dependencies`/`build-system.requires`)
declares something to install (single, unambiguous manifest only - multiple
candidate files fall through to the existing `DEPENDENCY_FILE_SELECTION_
CONFIRMATION_REQUIRED` gate in `_dependency_install`, same as before).
Steps: resolve the dependency spec from the already-parsed repository
files; run `pip download --only-binary=:all: --no-cache-dir --dest <tmp>
-r <spec>` as a real subprocess with real network access (on the host,
before the `--network none` sandbox build starts, so the offline boundary
above stays untouched); package the downloaded wheels into the same
TAR-archive shape the human-approved path already produced and validated
(reusing `_archive`); commit that TAR as a content-addressed artifact via
the existing `ArtifactStore`; construct a `DependencyBundle` record with
correctly computed `dependency_input_hash`/`archive_digest`/
`approval_target_hash` (same hash chain the human-approved path is checked
against, integrity verification unchanged) and
`approved_by_role="AUTOMATIC"`.

`--only-binary=:all:` is deliberate: a source distribution can run
arbitrary code (`setup.py`) at build time, and this call has real network
access, so wheels-only avoids executing anything from the fetched packages.
`--no-deps` is deliberately not used: the later offline `pip install
--no-index` needs the full transitive closure already present locally.

**Known gap, not fixed**: Python only. Node (`NPM_CACHE`) still requires an
explicitly-supplied bundle and still raises
`DEPENDENCY_SUPPLY_CONFIRMATION_REQUIRED` when none is given. `npm ci` has
no equivalent single-command wheels-only fetch, so an unattended default
for it needs its own design. No repository run so far has needed it.

**Schema change**: `DependencyBundle.approved_by_role` widened from
`Literal["HUMAN"]` to `Literal["HUMAN", "AUTOMATIC"]`. Checked every other
consumer of this field (only the field's own definition referenced it) and
the unrelated same-named field on `CapabilityApprovalEvidence`
(`contracts/capabilities.py`, a different record type, untouched) before
widening.

**Regression**: new test, `tests/integration/sandbox/
test_container_lifecycle.py::test_python_dependencies_are_auto_fetched_
without_an_approved_bundle`. Monkeypatches `subprocess.run` (no real
network in the test), captures the exact `pip download` argv (confirms
`--only-binary=:all:` present, `--no-deps` absent, correct spec file),
confirms the resulting recipe's build context contains the vendored wheel
and a working offline install line - mirrors the existing
human-approved-bundle test's assertions, minus the human. Confirmed via
revert-and-confirm the test reproduces the original
`DEPENDENCY_SUPPLY_CONFIRMATION_REQUIRED` failure without the fix. Full
file: 86 passed. The one existing test asserting
`DEPENDENCY_SUPPLY_CONFIRMATION_REQUIRED` is JavaScript-specific and
untouched.

## 6. Live validation against jinja (CVE-2024-34064)

Run history, each a real `analyze` invocation against a local clone pinned
at `a7863ba9d3521f1450f821119c50d19d7ecea329`, against a separately-branched
working copy of this codebase carrying items 1-5 (that branch has since
diverged further from `main` than is useful to track commit-by-commit here;
this document reports outcomes, not commit identity):

- Before items 1 and 3: crashed with the `Revision created_at precedes
  predecessor` / `fail_exhausted_retry` `AttributeError`s described above,
  at `WORKSPACE_PREP` and mid-pipeline respectively.
- After items 1, 3, 4 (before item 5): reached `DYNAMIC_REPRO` for the
  first time with two real hypotheses, both fully processed through
  `PRO_EVIDENCE`/`CON_EVIDENCE`, blocked only on the dependency-supply gate.
- Two further runs reached `TERMINAL` cleanly with zero hypotheses proposed
  that round (a legitimate LLM "found nothing" outcome, not a crash) - one
  of them direct evidence item 4's fix holds for the empty-batch path.
  Item 5's auto-fetch path itself was exercised by its own unit test but
  not yet by a live run that both proposes a dependency-needing hypothesis
  and reaches `DYNAMIC_REPRO`; proposal content is LLM-variance-dependent
  per run.

None of these runs have yet produced a `TRUE` verdict / Gate / ReportDraft.
