# T09 Provider and Prompt Runtime Implementation Plan

- Status: `IN_PROGRESS`
- Base: latest `main` after T08 merge
- Parent plan: [Complete Implementation Plan](../2026-09-08-sastsimi-complete-implementation.md#task-9-provider-and-prompt-runtime)
- Canonical design: [R3-04 Provider decision](../../../architecture-v5/implementation/04-provider-decision.md), [R3-05 Prompt Runtime](../../../architecture-v5/implementation/05-prompt-runtime.md)

## 1. Goal

Implement the provider-neutral call boundary and trusted Prompt Registry path without changing Architecture v5 contracts. An Agent invocation must use one exact `ProviderProfile`, one exact ACTIVE `PromptRegistryEntry`, one immutable `PromptPayload`, and the matching schema and validator references. Names such as `profile_key` and `prompt_key` remain review labels and are never runtime lookup keys.

## 2. Speed-first execution rule

T09 implements only the approved first-version path. Each lane runs its direct unit or contract tests with one successful path and one important fail-closed path. Do not repeat the full suite during lane work. The final PR CI runs the complete suite once. Fix Blocker/High findings immediately; record Medium/Low items as follow-ups without expanding this task.

The following checks are never skipped: exact-reference mismatch, evaluation/production mixing, approval bypass, secret persistence, prompt-injection authority changes, silent Provider/model fallback, and failure-result loss.

## 3. Fixed boundaries

- Agent name, role, input, and output contracts are Provider/model neutral.
- The selected runtime combination is the exact `provider_profile_ref + model`; `model` must equal `ProviderProfile.model`.
- A candidate adapter is not a `ProviderProfile`. The trusted storage registry publishes a profile only after complete PVD evidence and human approval.
- PVD proves technical capability only. It first permits an `EVALUATION` prompt entry.
- `PRODUCTION ACTIVE` requires an exact R8 `ACCEPT_FOR_PRODUCTION` recommendation plus human approval. The existing storage registry owns and validates this closure.
- Registry facades accept exact `StoredDataRef` values. They never resolve by `profile_key`, `prompt_key`, model name, or “latest/current” fallback.
- An explicitly requested stale revision is rejected rather than replaced with a newer revision.
- Provider adapters may translate transport shape only. They cannot change role instructions, context, schema, model, or fallback policy.
- T10+ role wrappers and T16 real-environment capability activation are outside T09.

## 4. Parallel lanes and ownership

### Lane A — Provider adapter and normalization

Owns `src/sastsimi/providers/`, provider contract tests, one API adapter skeleton, safe error normalization, cancellation, and fake adapter compatibility. It must not publish profiles or prompt entries.

### Lane B — Prompt load, build, redact, and validate

Owns `src/sastsimi/prompts/`, `config/prompts/`, prompt templates, immutable payload construction, safe YAML, projection, redaction, schema validation, and injection-negative tests. It must not call Provider SDKs or update registry current pointers.

### Lane C — Trusted registry facades and task plan

Owns this plan, `runtime/provider_profile_registry.py`, `runtime/prompt_registry.py`, and their direct unit tests. The facades delegate publication approval and closure validation to the existing typed configuration registry, then expose exact-current resolution only.

### Integration lane — LLM call service and composition

Starts after Lane A and Lane B interfaces are stable. It owns `runtime/llm_call_service.py`, bootstrap/service composition, action/attempt/budget integration, invocation result/log persistence, and final focused integration tests. No lane may create a competing call service.

Shared `storage/configuration_registry.py`, `storage/action_validator.py`, bootstrap, and `RuntimeServices` are integration-lane files. Parallel lanes do not edit them.

## 5. TDD sequence

### Step 1 — Exact Provider profile facade

1. Write a failing test for publishing PVD/profile through the injected approval-enforcing registry and resolving the same exact current `SUPPORTED` reference.
2. Write a failing test proving approval errors propagate and stale or name-based lookup is rejected.
3. Implement `ProviderProfileRegistry` with no name/current fallback.

Acceptance:

- returned publication reference equals the record's canonical exact reference;
- published record resolves byte-for-byte to the requested record;
- the exact reference is still the current revision of its logical record;
- non-`SUPPORTED`, stale, wrong-kind, artifact-only, and string-key requests fail closed;
- the facade cannot publish around the existing PVD and human-approval validator.

### Step 2 — Exact Prompt Registry facade

1. Write a failing test for exact ACTIVE `EVALUATION` selection by role, task, and purpose.
2. Write a failing test for stale revision, purpose mismatch, and duplicate ACTIVE entries.
3. Write a failing test proving R8 recommendation and human-approval failures from the storage registry propagate.
4. Implement `PromptRegistry` without key-based lookup.

Acceptance:

- an invocation supplies the exact entry reference and expected role/task/purpose;
- `EVALUATION` and `PRODUCTION` cannot be substituted for each other;
- a stale entry is not silently upgraded;
- multiple ACTIVE entries for the same `agent_role + task_kind + purpose` block use;
- production activation stays delegated to the existing exact R8 recommendation and human-approval closure.

### Step 3 — Provider and prompt lanes

Implement Lane A and Lane B with focused tests. The minimum normal path is one provider-neutral structured request producing one validated output. The minimum failure path rejects mismatched hashes/purpose or untrusted instruction promotion before provider invocation. Credential sentinels must be absent from persisted request, response, artifact, and safe log data.

### Step 4 — Integration

After Lane A/B merge into the task branch, implement the LLM call service. It resolves the exact current registries, checks action/attempt/budget, persists the immutable request before I/O, invokes outside a SQLite write transaction, validates output, and commits both success and failure result/log records through the existing runtime authority.

Retry, repair, and failover create explicit new IDs and follow only exact retry policy. No provider/model substitution is implicit.

## 6. Blocker/High completion gates

The following items must be resolved before T09 merges:

1. **Atomic ACTIVE uniqueness (High).** The current storage pointer is keyed by logical record ID, so two different logical IDs can race to publish ACTIVE entries for the same role/task/purpose. The runtime facade detects this and blocks invocation, but the integration lane must add an atomic storage invariant or equivalent serialized activation before declaring T09 complete.
2. **Failure invocation durability (High).** Provider timeout, authentication, rate limit, cancellation, invalid output, and exhausted repair/failover must persist the exact request, terminal `LLMInvocationResult`, and safe `LLMInvocationLog`. They must not disappear after an exception and must never create a domain verdict/output.
3. **Production activation closure (Blocker).** A `PRODUCTION ACTIVE` entry without the exact matching R8 acceptance recommendation and human approval must remain impossible. Existing storage validation is reused, not duplicated with weaker checks.
4. **Secret and instruction boundary (Blocker).** Credential/session secrets cannot enter records, artifacts, or logs, and untrusted repository/provider content cannot change instructions, tools, schema, Provider, model, or purpose.

## 7. Focused verification

During lane work:

```text
pytest tests/unit/runtime/test_provider_profile_registry.py tests/unit/runtime/test_prompt_registry.py -q
ruff check <changed Python files>
ruff format --check <changed Python files>
mypy --strict <changed source files>
```

Lane A/B run only their direct tests. The integration lane runs the T09 contract/integration/security-negative set once. The final PR CI alone runs the complete repository suite.

## 8. Deferred items

- T10: role-specific Agent wrappers and domain orchestration.
- T16: live credentials, real PVD-01 through PVD-16, production capability activation, and quality/cost comparison.
- Additional adapters, prompt tuning, performance refactoring, and Medium/Low cleanup are follow-up work unless needed to correct a Blocker/High failure.
