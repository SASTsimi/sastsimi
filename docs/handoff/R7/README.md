# R7 Dynamic Reproduction Agent Prompt Draft

This is a review draft for the R7 Dynamic Reproduction Agent. It is not yet an
ACTIVE Prompt Registry template.

Implementation handoff: [`handoff.md`](./handoff.md)

## Prompts

Each R7 task has an independent, complete, versioned template. The Prompt
Runtime selects exactly one Registry entry and supplies only that task's input
slots and output schema.

- [`DERIVE_ENVIRONMENT`](./prompts/derive-environment/1.0.0.md)
- [`PLAN_REPRODUCTION`](./prompts/plan-reproduction/1.0.0.md)
- [`CREATE_POC_CANDIDATE`](./prompts/create-poc-candidate/1.0.0.md)
- [`EXECUTE_REPRODUCTION`](./prompts/execute-reproduction/1.0.0.md)
- [`INTERPRET_ATTEMPT`](./prompts/interpret-attempt/1.0.0.md)

No template contains another task's instructions or output schema.

## Invocation order

1. `DERIVE_ENVIRONMENT`
2. `PLAN_REPRODUCTION`
3. Sandbox admission and environment preparation by trusted non-LLM components
4. `CREATE_POC_CANDIDATE`
5. `EXECUTE_REPRODUCTION`, repeated one tool
   request per turn in the same logical session and attempt
6. `INTERPRET_ATTEMPT`, only after `FINISH`

## Validation drafts

[`validation/README.md`](./validation/README.md) describes one reusable local-only code fixture and
paired input/expected JSON cases for environment readiness, environment setup
failure, execution cancellation, and post-run cleanup state. The expected files
fix stable schema and ownership conditions while expressing variable natural
language through required evidence and prohibited-claim assertions.

[`validation/prompt-tasks/README.md`](./validation/prompt-tasks/README.md) adds five cases for each
task: normal output, schema error, semantic error, prompt injection, and stale
or cross-attempt input. `scripts/validate-r7-handoff.py` executes these checks in
CI through `tests/contract/test_r7_handoff_validation.py`.

## Review points

- Confirm the repeated role and Sandbox boundaries in each standalone template
  without reducing execution-stage autonomy.
- Confirm each task receives only the input slots listed in the current prompt
  runtime design.
- Confirm each invocation returns exactly one artifact of its registered result
  kind.
- Confirm `ReproductionPlan` remains a strategy rather than a command allowlist.
- Confirm `EXECUTE_REPRODUCTION` action-specific nullability and one-action-per-
  turn behavior.
- Confirm `SUPPORTED | DISPROVED | INCONCLUSIVE` remains separate from R6's
  final `TRUE | FALSE | HOLD` verdict.
- Resolve how trusted runtime persistence supplies `PoCCandidate.content_ref`,
  `content_digest`, `llm_call_id`, and other runtime-owned metadata without the
  Agent inventing them.
- Confirm how `CREATE_POC_CANDIDATE` receives the actual code context needed to
  author a code-specific candidate. The current prompt-runtime slot contract
  supplies request references, plan, and environment, but no dereferenced code
  fragments or previous candidate content. This is tracked in
  [#162](https://github.com/SASTsimi/sastsimi/issues/162), together with Runtime
  ownership of candidate persistence metadata. Do not activate the R7 Registry
  entries until that contract is resolved.
- Confirm the runtime-owned failure channel for contradictory request and
  requirement inputs because `ReproductionPlan` has no error or limitation
  fields and the Agent must not invent them.

## Canonical design references

- `docs/architecture-v5/implementation/05-prompt-runtime.md`
- `docs/architecture-v5/04-verification-and-dynamic-reproduction.md`
- `docs/architecture-v5/08-lightweight-data-contracts.md`
- `docs/review/decisions/ADR-007-r7-autonomous-reproduction-session.md`
