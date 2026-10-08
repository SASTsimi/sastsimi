# Same-Provider Model Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route low-risk Agent calls to an optional lighter model without changing the analysis's configured LLM provider or weakening security decisions.

**Architecture:** Resolve one deterministic role-to-model map from the primary model, optional light model, and explicit Agent overrides. Reuse Claude/Cursor's existing role routing, add a small dispatch wrapper for Codex/OpenAI, and persist the resolved map on new analysis runs so resume uses the same routes.

**Tech Stack:** Python 3.12, Pydantic v2, asyncio, SQLite attempt ledger, pytest, Ruff, mypy.

**Spec:** `docs/superpowers/specs/2026-10-09-same-provider-model-routing-design.md`

## Global Constraints

- No model ID is hard-coded; model IDs come from the selected provider's configuration.
- The analysis provider is fixed. The existing opt-in fallback remains separate and is never triggered merely by tier selection.
- Agent prompts, JSON schemas, verdict rules, authentication, budgets, cancellation, and bounded retries remain unchanged.
- Existing configs without `light_model` and pre-feature analyses remain compatible. Dashboard pagination is outside this PR.
- Only `cwe_label` and `report_draft` default to the light model. Unknown roles default to the primary model; explicit `agent_models` wins.
- Actual model, tokens, duration, success/failure, and known cost remain attributable per attempt. Do not claim fewer input tokens without measurements.
- Use the isolated `codex/same-provider-model-routing` worktree; preserve the user's original checkout and analysis data.

## Review Focus

1. A misspelled/unknown runtime role must use the primary model rather than quietly becoming cheap (Task 1 test).
2. An unsupported light-model response must be a clear terminal Agent failure, never silently retried on the primary model (Task 2 test).
3. Concurrent heavy/light calls must share one analysis budget and configured semaphore (Task 2 test).
4. A new run resumed after local model settings change must use the saved route map and must not replay completed checkpoints (Task 3 test).
5. A pre-feature run must ignore the new automatic light policy while retaining its former explicit override behavior (Task 3 test).

---

### Task 1: Configuration and deterministic role policy

**Files:**
- Create: `src/sastsimi/config/model_roles.py` (role names, light-role set, resolver)
- Modify: `src/sastsimi/config/user_config.py`, `src/sastsimi/setup/service.py`, `src/sastsimi/interfaces/cli/setup.py`, `src/sastsimi/interfaces/cli/main.py`
- Modify: `README.md`, `docs/provider-setup.md`
- Test: `tests/unit/config/test_user_config.py`, `tests/unit/interfaces/test_setup_cli.py`, `tests/unit/config/test_model_roles.py`

**Interfaces:** Produce `effective_agent_models(primary_model: str, light_model: str | None, overrides: Mapping[str, str]) -> dict[str, str]`, `model_for_agent(primary_model: str, agent_models: Mapping[str, str], agent_name: str) -> str`, `ALL_AGENT_NAMES`, and `LIGHT_AGENT_NAMES`. Add `light_model: str | None = None` to both config models and `SetupChoices`, serialized in TOML only when set. Add setup `--light-model` without changing its existing default primary model.

- [ ] **Step 1: Write failing tests** for config TOML round-trip, setup persistence, all observed Agent names (including `discovery`, `hypothesis_survey`, `hypothesis_batch`, `hypothesis_surface`, `hypothesis_page`), explicit override precedence, and unknown-role primary fallback.
- [ ] **Step 2: Run the focused tests** with `python -m pytest tests/unit/config/test_model_roles.py tests/unit/config/test_user_config.py tests/unit/interfaces/test_setup_cli.py -q`; confirm the new assertions fail before implementation.
- [ ] **Step 3: Implement the resolver and config/CLI fields** using the exact two light roles from the spec; preserve existing fallback and credential fields. Add one concise PowerShell setup example and explain cost versus raw token count in the docs.
- [ ] **Step 4: Re-run the focused tests**, `python -m ruff check src/sastsimi/config src/sastsimi/setup src/sastsimi/interfaces/cli`, and `git diff --check`; require green results.
- [ ] **Step 5: Commit only Task 1 files** with `git commit -m "feat: configure same-provider model tiers"`.

### Task 2: Same-provider call dispatch and accounting

**Files:**
- Create: `src/sastsimi/simple_runtime/model_routing.py` (`ModelRoutedClient`)
- Modify: `src/sastsimi/composition/simple_runtime_composition.py`
- Test: `tests/unit/simple_runtime/test_model_routing.py`, `tests/unit/simple_runtime/test_call_queue.py`, `tests/unit/simple_runtime/test_claude_provider.py`, `tests/unit/simple_runtime/test_cursor_provider.py`

**Interfaces:** `ModelRoutedClient(primary_model: str, agent_models: Mapping[str, str], client_factory: Callable[[str], SimpleLLMClient])` implements `SimpleLLMClient.call` without changing its signature or call arguments. `SimpleClientFactory` supplies one provider-specific, run-limited client per selected Codex/OpenAI model; Claude/Cursor receive the same resolved map through their existing API.

- [ ] **Step 1: Write failing tests** proving primary/light/explicit routing for Codex and OpenAI, the effective map passed to Claude/Cursor, prompt/schema/owner forwarding, cancellation propagation, actual-model ledger records, shared budget/semaphore, and terminal unsupported-model errors.
- [ ] **Step 2: Run those tests** with `python -m pytest tests/unit/simple_runtime/test_model_routing.py tests/unit/simple_runtime/test_call_queue.py -q`; confirm the new routing cases fail.
- [ ] **Step 3: Implement lazy per-model dispatch** and compose it without altering the underlying provider retry/fallback policies. Keep the existing fixed-model path when all selected routes use one model.
- [ ] **Step 4: Re-run the focused tests** plus existing Claude/Cursor provider tests, `python -m ruff check src/sastsimi/simple_runtime/model_routing.py src/sastsimi/composition/simple_runtime_composition.py`, `python -m mypy src/sastsimi/simple_runtime/model_routing.py src/sastsimi/composition/simple_runtime_composition.py`, and `git diff --check`; require green results.
- [ ] **Step 5: Commit only Task 2 files** with `git commit -m "feat: route agents within one provider"`.

### Task 3: Durable routes, resume compatibility, and final verification

**Files:**
- Modify: `src/sastsimi/simple_runtime/models.py`, `src/sastsimi/simple_runtime/application.py`, `src/sastsimi/composition/simple_runtime_composition.py`
- Test: `tests/unit/simple_runtime/test_model_routing_resume.py`, `tests/unit/simple_runtime/test_usage_record.py`
- Modify: `docs/architecture/agents-and-providers.md`

**Interfaces:** New `SimpleAnalysisRun` fields `model_route_version: Literal[1] | None = None` and `model_routes: dict[str, str] | None = None` hold the resolved map. The run's existing `model` field is the frozen primary default for unknown roles. `SimpleAnalysisApplication` receives the map for `analyze`; `SimpleClientFactory` uses a new run's stored map and primary default on resume. Runs lacking the snapshot retain their previous non-tiered behavior. New-format runs reject a changed provider before any LLM call.

- [ ] **Step 1: Write failing tests** for snapshot persistence, edited-profile resume using the old route map, provider-mismatch fail-closed status without DB mutation, completed-checkpoint reuse, and legacy-run compatibility with explicit overrides.
- [ ] **Step 2: Run the focused tests** with `python -m pytest tests/unit/simple_runtime/test_model_routing_resume.py tests/unit/simple_runtime/test_usage_record.py -q`; confirm the new cases fail.
- [ ] **Step 3: Persist and resolve the versioned snapshot** at analysis start/resume, and document the behavior. Do not invalidate completed checkpoints because the route map exists.
- [ ] **Step 4: Run all focused provider/config/resume tests, then `python -m pytest -q`, `python -m ruff check .`, `python -m mypy src/sastsimi`, and `git diff --check`**. Set a fresh pytest `--basetemp` inside the workspace if the Windows sandbox temp directory is unavailable. Investigate any failure rather than reporting success.
- [ ] **Step 5: Inspect usage records in a mock heavy/light run**, compare reported models and token counts, and do not claim monetary savings without a real provider price/usage basis.
- [ ] **Step 6: Commit Task 3 files** with `git commit -m "feat: preserve model routes across resume"`; request independent branch review, address findings, push, and open a PR against `main` only after checks pass.
