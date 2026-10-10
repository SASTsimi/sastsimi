# Same-Provider Model Routing Design

## Intent and boundary

An analysis keeps its configured LLM provider. Within that provider, consequential security reasoning uses the configured primary `model`, while bounded, lower-risk work can use an optional `light_model`. For example, a Codex run can use `gpt-6-sol` for verification and `gpt-6-luna` for classification when both models are available to that account. No model ID is hard-coded. Agent prompts, JSON schemas, verdict rules, provider authentication, budgets, and existing opt-in provider fallback remain unchanged. Dashboard pagination is outside this PR.

This is a cost/latency routing feature, not a claim that switching models reduces the number of input tokens. Usage and actual model IDs must be measurable per call before any savings claim.

## Existing behavior and gap

`UserConfig` and `SimpleExecutionProfile` already contain `model` and exact-name `agent_models`. Claude and Cursor honor those overrides, but Codex and OpenAI build fixed-model clients and ignore them. The configured name allowlist also omits real `discovery`, `hypothesis_survey`, `hypothesis_batch`, `hypothesis_surface`, and `hypothesis_page` calls. The call ledger records model and usage, but analysis checkpoints do not pin the routing table.

## Configuration and policy

- Add optional `light_model` to both profile models and setup CLI (`--light-model`). A missing value leaves all existing behavior unchanged.
- Resolve each call as: explicit `agent_models[agent_name]`, otherwise `light_model` for the approved light-role set when configured, otherwise the primary `model`. Unknown roles always use the primary model.
- The initial light-role set is exactly `cwe_label` and `report_draft`. Both remain subject to their current output validation and failure handling. Discovery, hypothesis creation, Pro/Con, PoC creation and interpretation, verification, technical/scope gates, and recovery remain on the primary model by default because errors there can suppress or misclassify vulnerabilities.
- Expand the config allowlist to cover all observed SimpleRuntime `agent_name` values. Keep existing names for backward compatibility. Explicit overrides permit operator experiments without changing the safe default policy.
- Both primary and light IDs are sent through the same selected provider adapter and credential. Routing never picks another provider. A separately configured fallback provider retains its existing error-handling semantics; the light tier does not activate fallback on its own.
- Validate model ID syntax at config load. Preserve Cursor's existing account-catalog validation. Where the provider does not offer a reliable local catalog, surface its unsupported-model response clearly and do not retry it with a different tier or silently substitute a model.

## Runtime and resume

One resolver builds the effective role-to-model map. Claude and Cursor receive that map through their existing `agent_models` route. Codex and OpenAI dispatch to per-model clients wrapped by the existing run-limited adapter. All clients for an analysis share the same semaphore and analysis-level budget accounting; attempts retain the model actually invoked, duration, tokens, status, and cost where supplied.

At analysis creation, persist a versioned effective routing snapshot with the run (model IDs are not secrets). On resume, new-format runs use their saved map even if the local profile was edited, and reject a different configured provider rather than silently mixing providers. Completed checkpoints are reused; no stage is rerun merely because a model route exists. Pre-feature runs without a snapshot retain their prior behavior: the new automatic light-role policy is not retroactively applied, while their existing explicit overrides remain usable. The current provider-fallback behavior remains separate.

## Errors, tests, and evidence

Provider auth/model errors remain terminal under existing retry rules; rate limits and transient failures keep their bounded retries. A light-model failure is a real Agent failure, not a reason to return a fabricated JSON result or automatically reclassify the task as security-negative. Existing cancellation and subprocess cleanup rules apply to either model.

Tests must cover routing precedence and unknown roles; all four provider adapters; actual model in attempt/usage records; shared budgets and concurrency; unsupported models; unchanged legacy config; snapshot-preserving resume and completed-checkpoint reuse; and no tier-induced cross-provider fallback. Run focused tests, then the complete regression suite and lint/type checks. Document PowerShell setup/config examples and explain that measured input/output tokens may be unchanged while per-model cost or latency differs. Create a PR from current `main` only after verification; do not alter the user's existing checkout or analysis data.
