# Selective Claude Provider Integration Design

Status: implemented in feature branch; live subscription and managed-hook boundary unverified (2026-09-25)

## Outcome and scope

Add Claude Code as an **optional** subscription-backed LLM provider in SASTSIMI's current SimpleRuntime. `codex`, `cursor`, and `openai` remain available; existing configurations retain their meaning and default behavior. All analysis agents continue to use their existing prompts, JSON schemas, checkpoints, artifacts, and recovery path. Claude is used only when the operator explicitly selects `provider = "claude"`.

This is the first independent slice of the `impl/e2e-run` handoff. It is based on the latest `main`, not a merge of the handoff branch. The branch is 34 commits behind `main` and lacks the recently merged Cursor provider and automatic recovery. Its fact-survey pipeline, new stage semantics, default-feed changes, and removal of `recovery.py` are outside this slice; they require separate designs and acceptance tests.

## Source and constraints

- Use the official `claude` CLI's non-interactive print mode, structured output, model selection, and no-tools flags, as documented in [Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference).
- Subscription identity comes from the operator's own `claude auth login`. Neither account credentials nor OAuth tokens are copied into SASTSIMI's configuration or logs. A Claude API key must not silently substitute for a subscription; the [Claude environment-variable reference](https://code.claude.com/docs/en/env-vars) says `ANTHROPIC_API_KEY` takes precedence in print mode.
- The teammate's adapter was tested against Claude Code CLI `2.1.280`; the local installed CLI currently reports `2.1.250`. Do not claim compatibility with `2.1.250` without separately validating its event protocol. Setup should report an actionable unsupported-version error rather than attempt an unverified inference. No automatic CLI update or paid inference is in scope.
- Preserve Windows PowerShell support and Linux CI. Model names remain configuration values, not hard-coded IDs.

## Approach

Three approaches were considered:

1. Merge `impl/e2e-run` wholesale: rejected because it would replace current provider and recovery code and bring unrelated analysis-behavior changes.
2. Copy the Claude-specific files verbatim: rejected because their composition and profile contracts target the older branch, which predates Cursor and automatic recovery.
3. **Selected:** port the reviewed Claude CLI boundary and its negative tests into the current provider interfaces, adapting configuration and composition minimally. This keeps one analysis pipeline and makes Claude an optional endpoint.

## Components and data flow

1. `setup` detects the official CLI, records the executable path, digest, and version, and checks `claude auth status` for a first-party `claude.ai` subscription login. The profile stores only a non-secret session marker such as `CLAUDE_CLI_LOGIN` and the existing model/agent-model settings. A missing CLI, unsupported version, API-key authentication, or logged-out account leaves setup blocked with a specific next action. Existing provider setup paths are unchanged.
2. `SimpleClientFactory` routes `provider == "claude"` to a Claude adapter implementing `SimpleLLMClient.call(...)`. Other providers keep their present branches. Agent model selection is `agent_models[agent_name]` when present, otherwise the common `model`; no model ID is forced by code. Claude is not an implicit fallback for another provider, nor does a Claude failure silently switch to another provider.
3. The adapter passes the agent's existing prompt bytes through stdin and its existing JSON schema through the CLI's `--json-schema`. It starts the child in a fresh temporary directory with a minimal environment; it excludes ambient API keys, helpers, hooks, plugins, MCP configuration, and inherited project settings. It uses the teammate branch's reviewed no-tool launch boundary (`--safe-mode`, `--tools ""`, `--strict-mcp-config`, `--disable-slash-commands`, empty setting sources, `--no-session-persistence`, and `dontAsk`), and verifies the CLI's effective init event and absence of tool execution. A tool attempt, ambiguous auth source, or malformed event stream fails closed.
4. The adapter independently parses the returned JSON and validates it against the original agent schema. It never fabricates missing fields. The raw response and parsed JSON are stored as distinct artifacts through the existing artifact repository, while normal logs contain only analysis ID, agent, model, attempt, duration, and outcome. Usage is recorded only when trustworthy token/cost information is present, with unknown cost displayed as unknown rather than zero.
5. Timeouts, cancellation, and process exit terminate the CLI process tree and map to explicit stage failures. Only transient/rate-limit conditions receive bounded retry/backoff. Auth, model, unsupported-version, unsafe-tool, and schema errors fail clearly. The existing checkpoint and automatic-recovery behavior remains responsible for leaving `RUNNING` and supporting resume; already completed agents are not rerun.

## Security and operational boundaries

- The CLI is a local coding agent, not a general completion API. The process wrapper must prove that its tool surface is disabled for each call; a flag alone is not treated as proof.
- Official documentation says managed policy hooks can remain active in `--safe-mode`. The adapter cannot currently prove their absence from the init event; managed environments need operator policy review before this can be claimed as a no-hook boundary.
- A repository under analysis is untrusted input. Its configuration, scripts, and `CLAUDE.md` must not become CLI instructions or executable hooks. A temporary working directory and disabled setting sources prevent project-level configuration from being loaded.
- Setup and runtime recheck the executable binding. A changed path, digest, or version is an error, not an implicit upgrade.
- No live Claude request runs in CI. An optional single low-cost smoke test requires a compatible installed CLI, the operator's own login, and explicit approval because it may consume subscription or extra usage.

## Verification and acceptance

- Unit tests cover config round-trip, unchanged Codex/Cursor/OpenAI selection, Claude selection and agent-model override, CLI discovery/auth/version errors, no-secret child environment, exact no-tool argv, executable swap, init/event rejection, JSON/schema failures, timeout, cancellation, rate-limit retry, and usage/artifact separation.
- Security-negative tests port the teammate branch's cases that exercise credential leakage, project settings, MCP/built-in tools, malicious streams, and process-tree cleanup. Tests use fake processes and no live account.
- Integration tests run the current SimpleRuntime with a fake Claude transport, check checkpoints/resume and dashboard provider/possible-cost labels, and assert the old provider paths still work.
- Before proposing a merge, run formatting, lint, strict typing, the full test suite, Windows/Linux CI, and a diff review proving that `cursor_provider.py` and `recovery.py` remain intact. No passing claim relies only on the teammate's handoff test count.

## Delivery

One focused PR from current `main` adds optional Claude support and setup documentation. Later independent PRs may evaluate the handoff branch's repository-policy Scope Gate fix, container cleanup, rate-limit/resource gates, and fact-survey behavior against current `main`; none is implicitly included in this provider PR.
