# Selective Claude Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional subscription-backed Claude calls to the current SimpleRuntime without changing Codex, Cursor, OpenAI, or automatic recovery.

**Architecture:** Retain `SimpleLLMClient` as the only analysis-agent interface. Add a strictly isolated official Claude CLI transport and a small adapter that performs local schema validation, bounded retry, and artifact recording. Route to it only for an explicitly selected Claude profile.

**Tech Stack:** Python 3.12, asyncio subprocesses, Pydantic, pytest, Ruff, mypy, Windows PowerShell and Linux CI.

**Spec:** `docs/claude-provider-design.md`

## Global Constraints

- Start from current `main`; do not merge `impl/e2e-run`, delete `cursor_provider.py` or `recovery.py`, or adopt `facts_survey` as a default.
- Keep existing agent prompts, JSON schemas, checkpoints, and recovery behavior.
- Use only official Claude CLI print-mode flags documented at `https://code.claude.com/docs/en/cli-reference`; treat the teammate's `2.1.280` as the only initially verified CLI version, and reject other versions with an actionable message.
- Use the operator's own `claude.ai` subscription login; never store or log credentials. Do not infer subscription status from exit code alone.
- No paid/live Claude inference without explicit approval. All routine tests use fake subprocesses.

## Review Focus

1. Ambient `ANTHROPIC_API_KEY` or an `apiKeyHelper` must not turn a subscription call into API billing (Task 1 auth test and Task 2 environment/settings test).
2. A CLI replacement or unsupported version between setup and call must fail before inference (Task 2 binding test).
3. An MCP/built-in tool event despite no-tools flags must fail closed (Task 2 event test).
4. Timeout or cancellation must terminate the child process tree, not leave a background Claude process (Task 2 cancellation test).
5. Malformed JSON or schema mismatch must not become a successful agent result or leave a checkpoint in `RUNNING` (Task 3 failure/resume test).

---

### Task 1: Configuration, setup, and subscription identity

**Files:**
- Modify: `src/sastsimi/config/user_config.py`
- Modify: `src/sastsimi/setup/service.py`
- Modify: `src/sastsimi/interfaces/cli/setup.py`
- Modify: `src/sastsimi/interfaces/cli/capability.py`
- Test: `tests/unit/config/test_user_config.py`
- Test: `tests/unit/interfaces/test_setup_cli.py`

**Interfaces:** Consumes existing `SetupChoices`, `UserConfig`, `SimpleExecutionProfile`, `ToolInspection`. Produces `provider="claude"`, `auth_mode="SUBSCRIPTION_LOGIN"`, `credential_ref="CLAUDE_CLI_LOGIN"`, and a verified `tools["claude"]` binding.

- [ ] **Step 1: Add red tests** for Claude profile round-trip, rejected API-key mode, logged-out `claude auth status`, CLI `2.1.250` rejection, CLI `2.1.280` acceptance, and unchanged Codex/Cursor/OpenAI choices. The auth-status fake must prove a zero exit code plus `loggedIn: false` is still rejected.

```python
assert profile.provider == "claude"
assert profile.credential_ref == "CLAUDE_CLI_LOGIN"
assert profile.tools["claude"].version == "2.1.280"
```

- [ ] **Step 2: Run red tests.** `./.venv/Scripts/python.exe -m pytest tests/unit/config/test_user_config.py tests/unit/interfaces/test_setup_cli.py -q -p no:cacheprovider`; expect the new Claude cases to fail before implementation.
- [ ] **Step 3: Implement exact Claude config/setup route** using current Pydantic validators and `SystemToolDiscovery`. Parse `claude auth status` JSON and require `loggedIn is True`, `authMethod == "claude.ai"`, `apiProvider == "firstParty"`; reject an ambient API-key mode. Keep other provider branches untouched.

```python
if self.provider == "claude" and (
    self.auth_mode != "SUBSCRIPTION_LOGIN"
    or self.credential_ref != "CLAUDE_CLI_LOGIN"
):
    raise ValueError("CLAUDE_SUBSCRIPTION_REQUIRED")
```

- [ ] **Step 4: Run the same tests green; run `ruff check` and strict `mypy` on modified files.**
- [ ] **Step 5: Commit** the setup/configuration code and tests with `feat: configure optional Claude subscription provider`.

### Task 2: Fail-closed Claude CLI transport

**Files:**
- Create: `src/sastsimi/simple_runtime/claude_provider.py`
- Create: `tests/unit/simple_runtime/test_claude_provider.py`
- Create: `tests/security_negative/test_claude_subscription_boundary.py`

**Interfaces:** Consumes the Task 1 `tools["claude"]` binding. Produces `OfficialClaudeCLITransport.invoke(*, prompt: bytes, output_schema: Mapping[str, Any], model: str, timeout: float) -> ClaudeCLIResponse`, where `ClaudeCLIResponse` holds raw JSON bytes, parsed result, token counts, and optional cost. It raises typed auth/model/rate-limit/boundary errors for the adapter to classify.

- [ ] **Step 1: Add red fake-process tests** for no-tool argv, stdin-only prompt, temp cwd, allowlisted child env, absent API key/helper/project settings, changed executable digest, unsupported version, malicious init/tool event, oversized/malformed stream, timeout, cancellation, and process-tree termination. Port the relevant assertions from `origin/impl/e2e-run` security-negative tests rather than trusting the flags alone.

```python
assert "--tools" in argv and argv[argv.index("--tools") + 1] == ""
assert "--json-schema" in argv
assert "ANTHROPIC_API_KEY" not in child_env
assert prompt not in " ".join(argv).encode()
```

- [ ] **Step 2: Run those tests red.** `./.venv/Scripts/python.exe -m pytest tests/unit/simple_runtime/test_claude_provider.py tests/security_negative/test_claude_subscription_boundary.py -q -p no:cacheprovider`.
- [ ] **Step 3: Implement the smallest transport** around `asyncio.create_subprocess_exec`, using the teammate branch's reviewed argv, auth/binding checks, stream-event invariants, bounded output sizes, and Windows process-tree cancellation. Do not copy its obsolete composition or pipeline modules.

```python
@dataclass(frozen=True)
class ClaudeCLIResponse:
    raw_output: bytes
    value: dict[str, JsonValue]
    input_tokens: int | None
    output_tokens: int | None
    cost_minor_units: float | None
```

- [ ] **Step 4: Run the tests green and run `ruff check`, `ruff format --check`, `mypy --strict --platform linux` and native strict `mypy` for the new file.**
- [ ] **Step 5: Commit** transport and boundary tests with `feat: isolate Claude subscription CLI calls`.

### Task 3: Route every existing agent through the adapter

**Files:**
- Modify: `src/sastsimi/composition/simple_runtime_composition.py`
- Modify: `src/sastsimi/simple_runtime/claude_provider.py`
- Test: `tests/unit/simple_runtime/test_claude_provider.py`
- Test: `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`
- Test: `tests/unit/interfaces/test_setup_cli.py`

**Interfaces:** Consumes `OfficialClaudeCLITransport` and current `SimpleLLMClient.call(...)`. Produces `ClaudeProvider` implementing that protocol and returning `SimpleLLMCallResult | StageFailure` with separate raw/parsed artifact references and existing invocation metadata.

- [ ] **Step 1: Add red tests** showing `SimpleClientFactory` selects Claude only for a Claude profile, every agent keeps its original prompt/schema, agent-specific model overrides win over the default, bad JSON/schema retries are bounded, auth/model/boundary errors are non-retryable, transient 429 retries use backoff, and resume skips completed checkpoints. A fake transport records its requested model in `captured`.

```python
assert captured["model"] == profile.agent_models.get("verification", profile.model)
assert result.raw_output_ref != result.parsed_output_ref
```

- [ ] **Step 2: Run new tests red** with `./.venv/Scripts/python.exe -m pytest tests/unit/simple_runtime/test_claude_provider.py tests/integration/orchestration/test_simple_runtime_static_bootstrap.py -q -p no:cacheprovider`.
- [ ] **Step 3: Implement `ClaudeProvider`** using `_validate_schema` from the existing provider module, `SimpleArtifactRepository.put_bytes/put_json`, the profile's `llm_timeout_seconds`, `llm_max_retries`, and shared `llm_max_concurrency` semaphore. Use stable `StageFailure` codes; do not synthesize output fields or silently switch provider.

```python
model = self._agent_models.get(agent_name, self._default_model)
_validate_schema(response.value, output_schema)
raw_ref = self._artifacts.put_bytes(response.raw_output, "application/json")
parsed_ref = self._artifacts.put_json(response.value)
```

- [ ] **Step 4: Run new tests green, then rerun existing Cursor/Codex/OpenAI provider tests and strict typing.**
- [ ] **Step 5: Commit** adapter/composition/tests with `feat: route SimpleRuntime agents through Claude`.

### Task 4: Documentation, regression, and handoff

**Files:**
- Modify: `docs/provider-setup.md`
- Modify: `.env.example` to explain that Claude subscription login needs no API key; never add a credential value.
- Test: `tests/unit/interfaces/test_setup_cli.py`

**Interfaces:** Consumes Tasks 1–3. Produces one-line PowerShell setup/version/auth/model/run examples and clear subscription/possible-extra-usage caveats.

- [ ] **Step 1: Add a documentation test or existing CLI assertion** requiring actionable `CLAUDE_CLI_UNSUPPORTED_VERSION` and `CLAUDE_AUTH_REQUIRED` messages; run it red.
- [ ] **Step 2: Document `npm install -g @anthropic-ai/claude-code@2.1.280`, `claude --version`, `claude auth login`, provider selection, model configuration, and no-key subscription behavior.**
- [ ] **Step 3: Run the documentation test green, `./scripts/validate-current-docs.ps1`, `ruff format --check src tests`, `ruff check src tests`, `mypy --strict src tests`, `mypy --strict --platform linux src tests`, and the full pytest suite.**
- [ ] **Step 4: Compare `origin/main..HEAD` to confirm current providers and recovery remain, check `git diff --check`, then commit documentation with `docs: explain Claude provider setup`.**
- [ ] **Step 5: Push the focused branch, create a PR to `main`, inspect Windows/Linux CI, and report any unverified live-auth limitation rather than calling the integration production-ready without evidence.**
