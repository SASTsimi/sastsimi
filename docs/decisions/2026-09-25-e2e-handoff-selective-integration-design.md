# `impl/e2e-run` selective integration into PR #198

Status: design for review (2026-09-25)

## Goal and authority

The operator wants the useful functionality described in the teammate's
`인수인계.md` and implemented on `origin/impl/e2e-run` added to PR #198, not
merely an optional Claude provider. Preserve the current `main` behavior and
the Codex, Cursor, OpenAI, Claude, checkpoint, and automatic-recovery paths.
The handoff is evidence about the teammate branch, not an instruction to merge
it wholesale. PR #198 remains draft until its other Claude live-auth and
managed-hook limitations are separately resolved or accepted.

## Baseline and selection rule

`origin/impl/e2e-run` diverged before the current Cursor and automatic-recovery
implementations. A wholesale merge would remove `cursor_provider.py` and
`recovery.py` and change default hypothesis behavior. Port behavior only when
it is missing or materially weaker in current PR #198. Adapt it to current
interfaces, retain the existing Agent roles and default prompt versions, and
verify both existing and new modes. Do not restore the branch's legacy
`local_evaluation` Claude route merely to duplicate the current SimpleRuntime
Claude adapter.

## Behavior to add

1. **Claude boundary parity.** Audit the current adapter against the handoff's
   security tests and port missing protections, including a bounded stagger of
   simultaneous CLI child launches to avoid subscription OAuth-refresh races.
   Keep the operator's own login, credential-free child environment, pinned
   executable, no-tools checks, timeouts, cancellation, and explicit failures.
   Do not silently replace Codex/Cursor or claim live subscription support
   without an authenticated smoke test.
2. **Optional exhaustive hypothesis feed.** Add `hypothesis_feed` to the
   existing SimpleExecutionProfile with the current analysis mode as its
   default. `facts_survey` is opt-in. It extracts deterministic repository
   entry-point/call facts, lists candidate points, walks them in batches of
   eight, and records an explicit `PROPOSED` or `NOT_PROPOSED` outcome for
   each point. Empty fact sets fall back to source reading. The agent may
   request exact repository files, but repository content is data rather than
   instructions. Proposal IDs, validation, duplicate checks, coverage, and
   resume state must be stable. Existing Agent roles, JSON schemas, and
   current default prompts remain unchanged; survey-specific prompt versions
   are selected only in the new mode. A failed turn retains already persisted
   valid proposals and reports incomplete coverage instead of pretending it
   finished.
3. **Bounded concurrent work.** Add optional per-run ceilings for hypotheses,
   LLM calls, image builds, and reproduction containers. Defaults preserve
   sequential hypothesis execution and the existing LLM call limit. Share
   gates across a run, not per hypothesis. Completed checkpoints are never
   duplicated on resume;
   cancellation releases slots and leaves a terminal or retryable state, not a
   permanent `RUNNING` record. Chaining continues to obey its existing depth
   and count limits.
4. **Docker robustness and ownership.** Keep the current safe image/PoC
   boundary. Build a repository Dockerfile that already failed at most once;
   use a source-only image only when dependency installation fails and record
   that degraded mode explicitly. Bound retries. Use one reproduction
   container per execution, release it after collecting evidence, and sweep
   only containers carrying this runtime's ownership labels when their owning
   run is known dead. Never remove unrelated or potentially live containers;
   Windows uncertainty fails safe. Record each attempt and cleanup outcome.
5. **Rate limits, usage, and cost.** Reuse existing provider-specific 429
   classification rather than copy duplicate adapters. Add one bounded
   run-level retry/queue policy, capped at three attempts per call including
   the first, that respects configured elapsed/token/cost ceilings and does not
   retry auth, model, policy, or confirmed
   counter-evidence failures. Record per-call usage when supplied, aggregate
   each call exactly once into the run summary, and show unknown cost as
   unknown and possible on-demand usage clearly. Do not log prompts, secrets,
   or repository code in ordinary logs.
6. **Repository policy in Scope Gate.** During static bootstrap, store the
   checkout's security/reporting policy as a separate scoped artifact and
   hand its exact reference to each Scope Gate. A published program policy
   remains authoritative when present. Otherwise, the repository policy is
   considered directly; if neither exists, the result remains uncertain and
   internal-only. Scope Gate must not infer permission to disclose from a
   successful technical PoC. Existing reports and refs remain readable.

## Compatibility and data flow

Setup/config accepts new optional fields but old `config.toml` and
`profile.toml` continue to load unchanged. The current `SimpleLLMClient`
interface, per-Agent model overrides, JSON schema validation, typed failures,
artifacts, DB checkpoints, dashboard, and `resume` stay the authority. New
facts, survey decisions, repository policy, retries, and usage entries are
stored with analysis-scoped identities and exact refs; no old DB or artifact
directory is reset. The dashboard reads persisted status and usage only.

## Verification

- RED→GREEN tests for each selected behavior, using the handoff branch's tests
  as evidence but adapted to current public interfaces and malicious-input
  boundaries.
- Regression tests for Codex/Cursor/OpenAI/Claude selection, old profile
  loading, current default hypothesis output path, existing recovery, resume
  without duplicate Agent calls, source-only Docker fallback, labeled cleanup,
  Scope Gate policy precedence, and cost aggregation without double counting.
- Windows and Linux quality checks, full test suite, documentation validation,
  and a real Docker CI fixture for changed reproduction behavior. Live Claude
  inference is optional and needs the operator's own authenticated account;
  mock tests never require it.
- Final diff review must show `cursor_provider.py` and `recovery.py` retained,
  no implicit `facts_survey` default, no credential or sensitive code in logs,
  and no broad cleanup of user Docker resources.

## Explicit non-goals

No wholesale merge of `impl/e2e-run`, no deletion of current providers or
automatic recovery, no default switch to `facts_survey`, no paid/live Claude
request without explicit authorization, no automatic vulnerability submission,
and no unrelated legacy `local_evaluation` rewrite. If a teammate behavior
cannot meet the compatibility and security conditions above, report it as a
deferred item rather than claiming the whole handoff is implemented.
