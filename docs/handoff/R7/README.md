# R7 Dynamic Reproduction Agent Prompt Drafts

These files are review drafts for the R7 Dynamic Reproduction Agent. They are
not yet ACTIVE Prompt Registry templates.

Implementation handoff: [`handoff.md`](./handoff.md)

## Composition

Each task-specific prompt is composed with
[`common-agent-prompt.md`](./common-agent-prompt.md). The runtime supplies the
exact `task_kind`, authorized input slots, output schema, tool policy, execution
limits, retry policy, and redaction policy.

## Invocation order

1. [`DERIVE_ENVIRONMENT`](./derive-environment.md)
2. [`PLAN_REPRODUCTION`](./plan-reproduction.md)
3. Sandbox admission and environment preparation by trusted non-LLM components
4. [`CREATE_POC_CANDIDATE`](./create-poc-candidate.md)
5. [`EXECUTE_REPRODUCTION`](./execute-reproduction.md), repeated one tool
   request per turn in the same logical session and attempt
6. [`INTERPRET_ATTEMPT`](./interpret-attempt.md), only after `FINISH`

## Validation drafts

[`validation/`](./validation/) contains one reusable local-only code fixture and
paired input/expected JSON cases for environment readiness, environment setup
failure, execution cancellation, and post-run cleanup state. The expected files
fix stable schema and ownership conditions while expressing variable natural
language through required evidence and prohibited-claim assertions.

## Review points

- Confirm the common role and Sandbox boundary without reducing execution-stage
  autonomy.
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
  fragments or previous candidate content.
- Confirm the runtime-owned failure channel for contradictory request and
  requirement inputs because `ReproductionPlan` has no error or limitation
  fields and the Agent must not invent them.

## Canonical design references

- `docs/architecture-v5/implementation/05-prompt-runtime.md`
- `docs/architecture-v5/04-verification-and-dynamic-reproduction.md`
- `docs/architecture-v5/08-lightweight-data-contracts.md`
- `docs/review/decisions/ADR-007-r7-autonomous-reproduction-session.md`
