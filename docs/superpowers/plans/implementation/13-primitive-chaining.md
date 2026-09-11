# Task 13 Primitive Admission and Chaining Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use
> `superpowers:test-driven-development` for each behavior change and
> `superpowers:verification-before-completion` before every candidate commit.
> Independent lanes may use `superpowers:subagent-driven-development`, but each
> lane must use its own worktree and the exact file ownership below.

**Goal:** Convert final HOLD conditions and policy-allowed final TRUE capabilities
into exact immutable Primitive records, publish an atomic per-hypothesis
`PrimitiveIndexState`, and use one newly admitted Primitive against the exact
Primitive universe pinned at work registration to produce evidence-backed
TRUE+HOLD and TRUE+TRUE child hypotheses without changing any parent verdict.

**Architecture:** `Primitive Admission Runtime` is trusted non-LLM code in
`reporting/`; it maps already-committed Gate/policy results through the approved
decision table and atomically publishes only eligible Primitive records. The
`Chaining Agent` is an LLM role that judges directional result-to-input
compatibility. `ChainingService` pins work input, invokes that Agent through the
shared Provider/Prompt Runtime, submits the result to trusted structural and
provenance validation, and hands accepted child proposals to the global
hypothesis registry. Storage owns immutable revisions, current indexes, global
match uniqueness, and crash-safe publication. No component in T13 creates a
verdict, Finding, Gate result, CWE label, policy interpretation, or shortcut
Verification result.

**Speed policy:** Implement only the approved Architecture v5 behavior and the
Blocker/High correctness boundaries in this plan. During a lane, run one focused
normal-flow test and the named critical failure tests plus focused Ruff/mypy.
Do not repeatedly run the complete suite. Run the complete suite once in the
final PR CI after the integrated candidate SHA is frozen. Record Medium/Low
cleanup without expanding T13.

**Authoritative specification:**

- `docs/architecture-v5/03-agent-roles-and-orchestration.md`
- `docs/architecture-v5/06-chaining.md`
- `docs/architecture-v5/07-results-and-observability.md`
- `docs/architecture-v5/08-lightweight-data-contracts.md`
- `docs/architecture-v5/10-security-boundaries.md`
- `docs/architecture-v5/implementation/01-module-map.md`
- `docs/architecture-v5/implementation/02-contract-test-plan.md`, CHN-001..009
- `docs/architecture-v5/implementation/03-recovery-test-plan.md`, FLW-006..007
- `docs/superpowers/plans/2026-09-08-sastsimi-complete-implementation.md`, Task 13

---

## 1. Frozen behavior and non-negotiable invariants

### 1.1 Admission is not a second policy Gate

- Final `FALSE` never produces a Primitive or `CHAINING` work.
- Final `HOLD` with an empty `required_primitive_candidates` list ends normally
  without `PRIMITIVE_UPDATE`, Primitive, index append, or `CHAINING` work.
- Final `HOLD` with one or more required candidates produces exactly one
  inputs-only Primitive. It has `result=null`, no Technical review reference,
  no admission decision reference, and preserves the complete ordered required
  candidate list and all `Restriction` objects from the exact Verification.
- Final `TRUE` reaches T13 only after the T10/T11/T12 exact chain establishes a
  current final TRUE, successful supported dynamic result, validated PoC,
  current CWE label, and Technical `ACCEPT`.
- For `FOUND | ABSENT_CONFIRMED`, one current exact `RuleScopeImpactReview` is
  required. Its independent `testing_restriction_compliance` maps as follows:
  `PASS -> ALLOW`, `UNCERTAIN -> ALLOW`, `FAIL -> DENY`.
- For exact `PolicyCollectionResult.status=COLLECTION_FAILED`, no Rule Scope
  review is allowed and the runtime records `NOT_EVALUATED + ALLOW` with
  `POLICY_COLLECTION_FAILED`.
- If `RunPolicyState.collection_result_ref` is null, no admission decision,
  Primitive, index revision, or Chaining work is created.
- `rule_compliance`, `scope_compliance`, `security_impact`, and
  `report_permission` do not decide Primitive eligibility. In particular, an
  out-of-scope but technically confirmed capability may remain chaining input.
- A confirmed forbidden testing-method violation is the only Rule Scope policy
  value that denies admission. A denied result is not converted to `FALSE`.
- Admission is decided once when a Primitive is published. Chaining never reads
  policy records to reinterpret or revoke an already indexed Primitive.

### 1.2 Primitive and index publication is one atomic fact

- TRUE produces one Primitive per `provided_primitive_candidates` element;
  every Primitive copies the same required inputs and restrictions and points
  to its exact TRUE Verification, Technical review, and ALLOW decision.
- HOLD produces one Primitive containing the complete required-input list.
- Decision, eligible Primitive records, and the new index revision are one
  `PRIMITIVE_UPDATE` `TransitionCommit`; a consumer must see all or none.
- DENY commits the decision without a result Primitive or index append.
- Index append is monotonic. It never removes or replaces an admitted Primitive.
- The new `CHAINING` work is registered only after the Primitive/index commit is
  visible. A PREPARED or partially projected update is not consumable.
- Replaying the same committed update returns the same outcome and does not
  append duplicate Primitive references or create duplicate Chaining work.

### 1.3 The work input is the complete, exact comparison universe

- Each newly committed Primitive is the `trigger_primitive_ref` for one
  analysis-scoped `CHAINING` work.
- At registration, trusted runtime reads every current per-hypothesis
  `PrimitiveIndexState` in the same analysis/workspace/commit, pins those exact
  index revisions, expands all referenced valid Primitive records, removes only
  exact duplicate refs, and pins the complete set in `WorkExecutionState.input_refs`.
- `considered_primitive_refs` equals that complete Primitive set before lineage
  exclusion. It is not the subset used by successful matches.
- The trigger appears exactly once in both work input and considered refs.
- An index append after work registration does not stale the in-flight work.
  The new Primitive belongs to the next Chaining work. A result that injects a
  Primitive or index never pinned by this work is rejected as `STALE_RESULT`.
- Source hypotheses may have different Verification generations. A Chaining
  work's own `work_generation` must never be compared to every parent
  hypothesis generation. Exact source Verification and current index linkage,
  not numeric generation equality across parents, proves freshness.

### 1.4 Direction, ownership, TRUE+HOLD, and TRUE+TRUE

- Every match is directional: an upstream Primitive must have a non-null
  `result`; a downstream Primitive must have at least one `input`; and
  `matched_input_id` names exactly one downstream input.
- A Primitive with inputs and a result can be upstream in one candidate and
  downstream in another. No global role is attached to a Primitive.
- A work compares its trigger with every other considered Primitive in each
  eligible direction and per downstream input. It never compares a Primitive
  with itself.
- If only one trigger work's pinned pool contains the pair, that work owns it.
  If both pools contain each other, the work whose trigger Primitive has the
  lexicographically larger `record_id` owns it. A non-owner emits neither match
  nor no-match output for that pair.
- A result-bearing upstream plus inputs-only downstream produces TRUE+HOLD.
  A result-bearing upstream plus result-bearing downstream produces TRUE+TRUE.
  Match kind is derived from downstream `result` and is not stored separately.
- Neither path auto-promotes the child to TRUE. It creates only
  `HypothesisProposal(origin=CHAINING)`, which enters global registration and a
  complete independent Verification lifecycle.

### 1.5 Semantic matching and child derivation

- The Agent may accept a match only with actual code/verification evidence for
  entity or code-flow connection, required privilege, execution order, and a
  restriction-compatible path. String equality and a global privilege ladder
  are insufficient.
- A reviewed but incompatible owned triple produces exactly one structured
  `NoMatchReason`. A non-owner, lineage-excluded item, budget stop, timeout, or
  provider error does not become a no-match.
- The child keeps the exact match ID and both parent hypothesis IDs. It carries
  no new `observed_facts`.
- Optional target entity/location/path values must be derivable from the two
  exact parent Primitives. The global registry/T08 Context lineage boundary
  performs the final exact lookup before registration/use.
- Child `assumptions` are the descriptions of all upstream inputs plus all
  downstream inputs except the matched input, with multiplicity preserved.
- Child restrictions are the canonical-content-preserving union of both parent
  restriction sets. The same `restriction_id` with different content is a hard
  rejection, not a last-write-wins merge.
- Every child contains at least one falsification question aimed at the new
  connection point and at least one validation check. Runtime checks presence;
  later Verification/Technical Gate checks semantic adequacy.

### 1.6 Approved ancestor exclusion and DAG handling

The approved policy is the deepest-successful-match policy, not blanket
exclusion and not pre-filtering:

1. For the trigger work, calculate each non-trigger candidate's lineage from
   its `source_hypothesis_id -> source_primitive_match_id`.
2. Follow the referenced committed match in both directions through its
   `upstream_result_ref` and `downstream_input_ref`; recurse with a visited set.
3. Review candidates from deepest lineage to shallowest.
4. Only after a match with a candidate actually succeeds, exclude that
   candidate's ancestor Primitives from the remainder of this work.
5. Record each exclusion as `(ancestor, successful candidate,
   ANCESTOR_REUSE)`. The successful candidate is `excluded_by_ref`, remains a
   real match input, and cannot itself be excluded.
6. If the deepest candidate does not match, exclude nothing and continue with
   shallower candidates.

The immutable, time-directed source links are expected to form a DAG, so T13
does not add an arbitrary chaining depth cap. Nevertheless, trusted lineage
reading must fail closed on a broken reference, a reference outside the pinned
analysis/workspace/commit, a self-link, or a repeated node encountered by the
active recursion path. Corrupt lineage must never cause an infinite traversal
or be silently treated as no-match.

At `SAVE_RESULT`, trusted code independently recomputes the expected exclusion
pairs from the pinned universe, trigger, committed lineage, and successful
match candidates. Passing `result.excluded_lineage_refs` back as the expected
value is forbidden. The submitted set must be exactly equal to the recomputed
set. Excluded refs cannot also appear in `input_primitive_refs` or any match;
the excluding ref must be in a successful match and in the same work's
considered set.

### 1.7 Duplicate and budget boundaries

- `(analysis_id, upstream_result_ref, downstream_input_ref, matched_input_id)`
  is a storage-enforced global unique key. All triples in a ChainingResult are
  reserved atomically with the result commit. Any collision rejects the whole
  result as an implementation error; it is not a normal no-match and not
  retryable with identical input.
- `primitive_match_id` is globally unique inside an analysis and is allocated
  by trusted output validation, not accepted blindly from model text.
- Proposal/global hypothesis duplicate handling remains the existing registry's
  responsibility. T13 must not create a second duplicate algorithm.
- Do not add chaining-only depth, hypothesis-count, call-count, combination, or
  token caps. Apply the current R8 analysis/work/time/cost/attempt limits before
  registering work and before each LLM action.
- Token usage is observed but token-plan excess alone is not a deny condition.
  A real budget stop blocks or fails the work using existing runtime policy,
  records the stop in `AnalysisRunResult.stop_reasons`, creates no unchecked
  match/child, and never changes a parent verdict.

---

## 2. Prerequisite APIs from T10-T12

T13 implementation starts only after these boundaries are present on the
integration base. Adapt to their final public names rather than creating a
parallel current-pointer or result writer.

### T10 — Verification and child registration boundary

- `VerificationService.finalize(...)` publishes one current exact
  `VerificationResult` through the existing atomic Verification transition.
- `VerdictRouter.route(...)` exposes the current final result by exact reference
  and requests `PRIMITIVE_UPDATE` only for non-empty HOLD candidates. TRUE does
  not directly call Chaining; it continues through CWE and the two Gates.
- The trusted proposal/hypothesis registry exposes one child-registration entry
  that accepts a COMMITTED `ChainingResult` reference plus one nested proposal
  identity, verifies `origin=CHAINING` and exact match lineage, preserves the
  proposal/question/validation IDs issued once by trusted output validation,
  and returns the registered proposal/hypothesis/process refs. T13 calls this
  public entry and does not write hypothesis tables itself.
- Child registration/assignment returns without inheriting a parent verdict and
  sends the child to the normal `VerificationRegistrationPort` path.

### T11 — validated dynamic proof boundary

- A final TRUE consumed by T13 must already point to one current
  `DynamicReproductionResult(status=SUCCEEDED,
  hypothesis_outcome=SUPPORTED)` and one validated `PoCBundle` for the same
  request/generation/attempt evidence chain.
- T11's `DynamicReproductionResult` and `PoCBundle` are resolved through exact
  refs by T10/T12 validators. T13 has no Sandbox or Docker API and must not
  re-run or reinterpret dynamic reproduction.
- `BLOCKED | FAILED | CANCELLED`, `DISPROVED | INCONCLUSIVE`, or a null validated
  PoC cannot produce a final TRUE and therefore cannot reach TRUE admission.

### T12 — Gate and frozen-policy boundary

- `PolicyAndScopeWorkflow.evaluate(...)` (or its final public service name)
  exposes exact current refs for the final TRUE's `CWELabel`, Technical review,
  frozen run `RunPolicyState`, its exact `PolicyCollectionResult`, and the
  optional Rule Scope review.
- Technical status must be `ACCEPT` and must point to the same exact
  Verification/CWE pair. `REVISE | REJECT` produces no TRUE admission request.
- For `FOUND | ABSENT_CONFIRMED`, the Rule Scope review must point to that same
  Verification/Technical/CWE/frozen-policy collection chain. For
  `COLLECTION_FAILED`, the service passes no Rule Scope review and preserves the
  exact collection failure reference. With no collection result it emits no
  admission trigger.
- T12 passes structured values and refs only. It must not precompute or store a
  `PrimitiveAdmissionDecision`; the T13 trusted runtime owns that mechanical
  mapping.

---

## 3. Baseline inspection and known High gaps

Before editing, inspect rather than recreate the T04-T07 foundations:

- `contracts/chaining.py` already defines the approved persisted schemas and
  several pure validators. Do not rename fields, add match-kind/depth fields,
  or regenerate schemas unless an independently reviewed Blocker proves the
  canonical contract cannot express the behavior.
- `storage/primitive_projection.py` currently requires one
  `PrimitiveAdmissionDecision` for every Primitive output; this incorrectly
  rejects the approved HOLD-without-admission path.
- `chaining/service.py` is a fake vertical-slice service that currently owns
  admission, only publishes the first TRUE capability, and accepts a caller's
  allow/deny flag. Production T13 must separate that authority.
- `storage/chaining_projection.py` currently compares one analysis-scoped
  Chaining work generation to every source hypothesis generation. That rejects
  valid parents from different generations and must be removed.
- The same projection currently calls `validate_chaining_closure(...,
  result.excluded_lineage_refs)`, which compares the submitted exclusion set to
  itself. Replace it with an independently derived expected set.
- Current storage has no global physical unique key for nested match triples.
  Add one migration-backed index table; do not rely on an in-memory scan.
- Existing fake no-match behavior remains a regression fixture, but production
  code must not use fake IDs, caller-supplied admission decisions, or synthetic
  self-comparisons.

Run this baseline once after T10-T12 merge and before the first T13 edit:

```powershell
git status --short
git rev-parse HEAD
uv run python -m pytest tests/contract/domain/test_chaining.py tests/contract/domain/test_review_round1_chaining.py tests/e2e/test_fake_chaining_pipeline.py -q
```

If the base fails, record it as a prerequisite defect. Do not weaken a test to
make the lane green.

---

## 4. Parallel lane map and strict file ownership

Create one worktree/branch per lane from the same post-T12 full SHA. Do not let
agents share an editable worktree. The integration owner cherry-picks only
reviewed lane commits in dependency order.

### Serial seam S0 — freeze ports and fixture vocabulary

Owner: integration lead. This short seam lands before parallel lanes.

Owned files only:

- `src/sastsimi/ports/chaining.py`
- `src/sastsimi/ports/__init__.py`
- `tests/contract/test_chaining_ports.py`
- `tests/support/chaining_fixtures.py`

Define non-persisted frozen DTOs/protocols for:

- exact admission source closure returned by T10/T12 readers;
- primitive update outcome containing committed decision/Primitive/index refs;
- pinned Chaining universe containing trigger, exact index refs, and exact
  considered Primitive refs;
- read-only lineage resolution by exact ref;
- global match-triple reservation inside the result transaction;
- child proposal handoff to the existing trusted hypothesis registry.

These ports carry exact domain records/refs and do not introduce new Pydantic
domain schemas or persistence authority. Test Protocol signatures and import
direction before lanes begin.

### Parallel lane A — admission and atomic Primitive index

Owned files only:

- `src/sastsimi/reporting/primitive_admission.py`
- `src/sastsimi/storage/primitive_projection.py`
- `tests/integration/chaining/test_primitive_admission.py`
- `tests/security_negative/test_primitive_admission.py`

Responsibilities:

- implement trusted HOLD and TRUE source resolution;
- apply the four-row admission table without LLM or policy reinterpretation;
- create all eligible Primitive records with trusted IDs/metadata;
- validate exact Verification/Technical/frozen-policy/Rule Scope closure;
- publish decision, Primitive records, and index revision atomically;
- make replay idempotent and emit committed Primitive refs only after commit;
- preserve deny/no-collection/empty-HOLD outcomes without false verdicts.

The lane must not register Chaining work, invoke a Provider, or register child
hypotheses.

### Parallel lane B — exact input universe, storage uniqueness, and recovery

Owned files only:

- `src/sastsimi/runtime/chaining_registration.py`
- `src/sastsimi/storage/chaining_registration.py`
- `src/sastsimi/storage/chaining_projection.py`
- `src/sastsimi/storage/models.py`
- `src/sastsimi/storage/schema_version.py`
- `src/sastsimi/storage/alembic/versions/0004_chaining_matches.py`
- `tests/integration/chaining/test_input_universe.py`
- `tests/integration/chaining/test_match_uniqueness.py`
- `tests/integration/recovery/test_chaining_commit.py`
- `tests/integration/storage/test_migration_cli.py`
- `tests/security_negative/test_chaining_provenance.py`

Responsibilities:

- register one deduplicated work from a committed trigger and all current exact
  per-hypothesis indexes in the same analysis/workspace/commit;
- bind exact index refs and complete Primitive refs into work input/hash/key;
- verify trigger membership exactly once;
- preserve the start-time universe after unrelated later index appends;
- remove the incorrect cross-parent numeric generation equality check;
- resolve every submitted ref from the pinned set and validate exact scope;
- independently calculate expected lineage exclusions through the read port;
- add an analysis-scoped match reservation table with canonical serialized
  upstream/downstream refs and matched input ID under a unique constraint;
- reserve all triples and commit the ChainingResult atomically;
- on collision or provenance failure publish neither result nor child pointer;
- recover COMMITTED work without reserving or publishing a duplicate match.

The migration must be additive and upgrade-tested. Downgrade remains subject to
the repository's existing non-empty database safety rule.

### Parallel lane C — lineage traversal and Chaining Agent boundary

Owned files only:

- `src/sastsimi/agents/chaining.py`
- `src/sastsimi/chaining/lineage.py`
- `src/sastsimi/chaining/matching.py`
- `tests/unit/chaining/test_lineage.py`
- `tests/unit/chaining/test_matching.py`
- `tests/security_negative/test_chaining_agent_output.py`

Responsibilities:

- derive pair ownership from trigger and pinned pool history;
- derive both eligible directions and each downstream input without self-pairs;
- traverse committed source match lineage with active-path cycle detection;
- order non-trigger candidates deepest first;
- prepare the minimum exact Prompt payload through T09 APIs;
- parse only the approved `ChainingResult` output shape;
- ensure normal mismatch produces structured `NoMatchReason`, while unreviewed,
  non-owner, excluded, timeout, and budget-stopped pairs do not;
- build TRUE+HOLD and TRUE+TRUE proposal candidates with exact remaining
  assumptions, restriction union, empty observed facts, and non-empty checks;
- reject authority-expanding outputs and ungrounded entity/location/path claims;
- produce the independently recomputable exclusion intent from successful
  deepest candidates, not a blanket ancestor filter.

This lane is pure/provider-facing logic. It imports only contracts and ports and
does not write DB state, allocate global hypothesis IDs, or change verdicts.

### Parallel lane D — workflow composition and child handoff

Owned files only:

- `src/sastsimi/chaining/service.py`
- `src/sastsimi/chaining/__init__.py`
- `tests/integration/chaining/test_true_hold_true_true.py`
- `tests/integration/chaining/test_chaining_errors.py`
- `tests/e2e/test_chaining_child_full_revalidation.py`

Responsibilities:

- consume committed trigger refs from lane A through the S0 port;
- ask lane B to pin/register the full input universe;
- reserve R8 budget and perform one authorized CHAINING `CALL_LLM` using T09;
- call lane C for ownership, lineage order, output parsing, and derivation;
- submit one exact `SAVE_RESULT` and wait for COMMITTED publication;
- hand each nested proposal to T10's global child registry only after the source
  ChainingResult commit;
- ensure child registration is idempotent and runs the normal assignment /
  Verification path without inheriting parent TRUE/HOLD;
- distinguish valid no-match success from Provider, budget, provenance, or
  storage failure; all failures leave parent verdicts untouched.

This lane uses ports only and must not import concrete `storage`, Provider
adapter, reporting admission implementation, or T08 Context implementation.

### Serial integration I0 — composition only

Owned by the integration lead after A-D are reviewed:

- `src/sastsimi/bootstrap.py`
- `src/sastsimi/runtime/services.py`
- `src/sastsimi/runtime/__init__.py`
- `src/sastsimi/reporting/__init__.py`
- `config/prompts/registry.yaml`
- `src/sastsimi/prompts/templates/chaining.md`
- `tests/contract/test_architecture_imports.py`
- `tests/e2e/test_real_chaining_slice.py`
- this plan's `Implementation Evidence` section only

The integrator wires already-implemented ports/services, registers the CHAINING
prompt entry and worker, updates imports, and resolves conflicts. No lane may
edit these shared composition files. If T09 already owns the exact canonical
template/registry entry, I0 references it and does not create a duplicate.

---

## 5. Implementation tasks and TDD checkpoints

### Task 1 — land S0 ports before parallel work

- [ ] Write `tests/contract/test_chaining_ports.py` first. It must prove exact
  refs are required, DTOs are immutable/non-persisted, and no port returns a
  raw SQL connection or grants Agent storage authority.
- [ ] Run the test and confirm RED because the ports are absent.
- [ ] Add only the minimum protocols/DTOs in `ports/chaining.py`; re-export them.
- [ ] Run the focused test, architecture import test, Ruff, and mypy for those
  files.
- [ ] Commit only S0 files: `feat: define primitive chaining ports`.

### Task 2A — implement HOLD and TRUE admission

- [ ] RED normal test: non-empty final HOLD commits one inputs-only Primitive
  and an appended index without any admission decision.
- [ ] RED normal test: allowed final TRUE with two provided drafts commits one
  decision, two Primitives, and one index revision containing both refs.
- [ ] RED critical test: FALSE, empty HOLD, Gate-before-ACCEPT, Technical
  REVISE/REJECT, no collection result, and DENY publish no Primitive.
- [ ] RED critical test: testing restriction FAIL denies while out-of-scope,
  insufficient impact, or report DENY with testing PASS/UNCERTAIN does not.
- [ ] RED critical test: `COLLECTION_FAILED` only permits
  `NOT_EVALUATED+ALLOW` with no Rule Scope review and the exact frozen collection
  ref; FOUND/ABSENT require the exact current review.
- [ ] RED atomic/replay test: crash at decision/Primitive/index checkpoints
  exposes all-or-none, and replay does not double append.
- [ ] Implement the minimum runtime/projection changes and make tests GREEN.
- [ ] Run focused Ruff/mypy and commit only lane A files:
  `feat: admit exact hold and true primitives`.

### Task 2B — pin and persist the full universe

- [ ] RED normal test: one trigger pins all current indexes and their complete
  deduplicated Primitive set; `considered_primitive_refs` is exactly that set.
- [ ] RED normal test: a later index append does not invalidate the work and is
  absent from its result; a later work sees the appended Primitive.
- [ ] RED critical test: uncommitted trigger, foreign scope, missing index,
  duplicated trigger, injected/unpinned Primitive, and unpinned index are denied
  before result publication.
- [ ] RED regression test: parents from Verification generations 1 and 3 are
  accepted when each exact source Verification is current for its own index.
- [ ] RED critical test: wrong/omitted/extra exclusion pair is rejected after
  runtime independently recomputes the expected set.
- [ ] RED critical concurrency test: two transactions attempt the same global
  match triple; exactly one commits and no partial nested match rows remain.
- [ ] RED recovery test: crash before/after match reservation and result commit
  converges to one result/triple without re-running the Agent.
- [ ] Add migration and storage/runtime code; make focused tests GREEN.
- [ ] Run migration upgrade test once, focused Ruff/mypy, and commit only lane B
  files: `feat: enforce exact chaining snapshots and unique matches`.

### Task 2C — implement ownership, lineage, and output derivation

- [ ] RED table test for trigger/new-vs-existing ownership and the larger
  `record_id` tie-break when both pools contain each other.
- [ ] RED directional test: result->input only; TRUE+HOLD and TRUE+TRUE; a
  result-bearing Primitive may also be downstream; self-pairs forbidden.
- [ ] RED lineage test using B, BC, BCD, BCDE and new A: if A matches BCDE,
  record B/BC/BCD excluded by BCDE; if BCDE does not match, exclude none and
  continue with BCD/BC/B.
- [ ] RED lineage test: broken refs, cross-scope refs, self-link, repeated active
  recursion node, and non-COMMITTED source match fail closed without looping.
- [ ] RED derivation test: matched input removed, all remaining input
  descriptions retained, restriction union exact, conflicting restriction ID
  rejected, no new observed fact, and required falsification/validation present.
- [ ] RED error test: Provider timeout/budget stop cannot be emitted as an empty
  successful ChainingResult or `NoMatchReason`.
- [ ] Implement pure traversal/matching and thin Agent wrapper; make tests GREEN.
- [ ] Run focused Ruff/mypy and commit only lane C files:
  `feat: derive evidence bound chained proposals`.

### Task 2D — compose the Chaining workflow

- [ ] RED normal integration: committed allowed TRUE trigger plus HOLD candidate
  produces one TRUE+HOLD proposal, COMMITTED ChainingResult, registered child,
  and a normal Verification assignment with no inherited verdict.
- [ ] RED normal integration: two allowed TRUE Primitives produce a TRUE+TRUE
  child using the same path and no extra match-kind field.
- [ ] RED critical error: no budget or denied/stale LLM action causes zero
  Provider invocations, no result/child, and no parent verdict change.
- [ ] RED critical error: result commit failure prevents child registration;
  child registration failure preserves the committed source result and is
  safely retryable without another Agent call or match row.
- [ ] RED no-match: an actually reviewed incompatible owned triple commits a
  structured reason and no child; timeout remains a failed/blocked work.
- [ ] Implement orchestration against S0 ports; make tests GREEN.
- [ ] Run focused Ruff/mypy and commit only lane D files:
  `feat: orchestrate primitive chaining and child handoff`.

### Task 3 — integrate reviewed lane commits

- [ ] Create the integration branch from the recorded post-T12 SHA.
- [ ] Cherry-pick S0, then A/B/C/D reviewed commits. Do not merge worktrees or
  copy uncommitted files.
- [ ] Resolve only genuine shared-boundary conflicts. Preserve the final T10,
  T11, and T12 public APIs and current main contracts.
- [ ] Wire services in bootstrap, Prompt Registry, and worker registry.
- [ ] Remove production use of fake caller-supplied admission flags while
  retaining fake vertical-slice fixtures as tests.
- [ ] Run focused integration/security tests named in Task 4.
- [ ] Commit composition only: `feat: integrate primitive chaining workflow`.

### Task 4 — focused candidate verification

Run this set once on the integrated candidate before opening the PR:

```powershell
uv run python -m pytest tests/contract/domain/test_chaining.py tests/contract/domain/test_review_round1_chaining.py tests/contract/test_chaining_ports.py tests/integration/chaining tests/security_negative/test_primitive_admission.py tests/security_negative/test_chaining_provenance.py tests/security_negative/test_chaining_agent_output.py tests/e2e/test_chaining_child_full_revalidation.py tests/e2e/test_real_chaining_slice.py -q
uv run ruff check src/sastsimi/agents/chaining.py src/sastsimi/chaining src/sastsimi/reporting/primitive_admission.py src/sastsimi/runtime/chaining_registration.py src/sastsimi/storage/chaining_registration.py src/sastsimi/storage/chaining_projection.py tests/integration/chaining tests/security_negative/test_primitive_admission.py tests/security_negative/test_chaining_provenance.py tests/security_negative/test_chaining_agent_output.py
uv run mypy --strict src/sastsimi/agents/chaining.py src/sastsimi/chaining src/sastsimi/reporting/primitive_admission.py src/sastsimi/runtime/chaining_registration.py src/sastsimi/storage/chaining_registration.py src/sastsimi/storage/chaining_projection.py
powershell -NoProfile -File scripts/validate-architecture-docs.ps1
git diff --check
```

Required focused outcomes:

- at least one TRUE+HOLD and one TRUE+TRUE child reaches normal Verification
  registration but has no verdict before its independent Verification;
- forbidden-test DENY produces no result Primitive;
- HOLD remains inputs-only and keeps restrictions;
- different parent generations do not cause a false stale rejection;
- unpinned refs, wrong exclusions, cyclic/corrupt lineage, and duplicate global
  match triples fail before child registration;
- budget/provider/storage failures never become FALSE, HOLD, or normal no-match.

### Task 5 — one final CI run and merge

- [ ] Freeze the implementation candidate SHA before CI.
- [ ] Open one T13 PR with R1, R3, R4, R5, R6, and R8 review scope.
- [ ] Let PR CI run the complete test suite exactly once for that candidate.
- [ ] If CI exposes a Blocker/High issue, fix only that issue, freeze a new SHA,
  and rerun CI. Record Medium/Low findings in the follow-up list.
- [ ] Merge only if focused checks, complete CI, migration upgrade, and all
  required role reviews pass at the final SHA.

---

## 6. Acceptance criteria

- HOLD with requirements and every policy-allowed final TRUE capability are
  published as exact immutable Primitive records with no denied or invalid
  result entering an index.
- Admission and index publication are atomic, append-only, replay-safe, and
  occur before Chaining registration.
- Chaining input contains every and only Primitive in the exact current index
  revisions pinned at work start; later appends do not mutate that universe.
- Directional TRUE+HOLD and TRUE+TRUE matching works, and children always start
  an independent full Verification lifecycle.
- Parent restrictions, remaining inputs, exact source refs, and evidence are
  preserved; no ungrounded fact or path is invented.
- The deepest-successful-match ancestor exclusion is independently recomputed;
  no-match at depth preserves shallower candidates.
- Corrupt lineage cannot loop, cross scope, or silently become a match/no-match.
- Match triples are globally unique per analysis and atomically bound to their
  ChainingResult.
- Existing proposal duplicate logic is reused; no parallel duplicate authority
  or second hypothesis writer exists.
- R8 global work/time/cost/attempt budgets cover Chaining, token usage remains
  observational, and all budget stops preserve parent verdicts.
- T13 imports through approved ports, keeps concrete storage/provider wiring in
  bootstrap, and does not change Architecture v5 field or authority meaning.

## 7. Explicitly deferred Medium/Low work

- Chaining-result UI visualization, graph layout, and report nesting.
- Performance caches for lineage depth or Primitive expansion.
- Additional vulnerability-specific matching heuristics beyond the approved
  evidence axes.
- New depth/count/combination/token knobs, distributed queues, or multi-host
  scheduling.
- Refactoring fake fixtures unrelated to removing production authority leaks.
- Additional metrics dashboards beyond recording existing work/budget usage.

Do not implement a deferred item in T13 unless it becomes a demonstrated
Blocker/High correctness or security defect.

## 8. Implementation evidence

Plan only. Implementation, PR creation, CI, and merge have not been performed.
The implementing PR must replace this paragraph with the frozen candidate SHA,
focused command results, one full-CI run reference, migration result, and final
review SHA.
