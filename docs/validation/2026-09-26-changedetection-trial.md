# changedetection.io pinned analysis trial (2026-09-26 KST)

## Reproduction

- Host: Windows PowerShell, project `.venv`, official Codex CLI subscription login, Docker Desktop Linux.
- Provider/model: `codex` / `gpt-6-sol` in both local configuration files; no Agent override.
- Repository: `https://github.com/dgtlmoon/changedetection.io.git`.
- Pinned `master` commit, checked with `git ls-remote` immediately before the run: `d789fe3ea5809eef0134943917ef50f47259121b`.
- Command: `.\.venv\Scripts\sastsimi.exe analyze https://github.com/dgtlmoon/changedetection.io.git --commit d789fe3ea5809eef0134943917ef50f47259121b --format json`.
- Analysis: display ID `A-002`, exact ID `4126f16d371243358a0b73310be44f8d`.
- Started `2026-09-25 17:24:23 UTC`; completed approximately `18:20:55 UTC` (about 57 minutes).

## Observed outcome

The public `analyze`, `status`, and `result` commands completed normally. The final analysis status was `BLOCKED`, with 33 completed of 86 known work units (58%), seven hypotheses and zero findings. Four hypotheses stopped at `POC_EXECUTION_DONE` with `RECOVERY_EXHAUSTED` after the bounded automatic repair attempts. Two finished final verification with `HOLD`; one finished with `FALSE`. `BLOCKED` was not converted to vulnerability disproof. There was no Docker build failure in this run.

The blocked PoCs failed inside generated reproduction scripts. Safe stderr excerpts included `TypeError: Watch.__init__() takes 1 positional argument but 2 were given`, `StopIteration`, `ApiKeyAuth` validation errors, and `KeyError` from reproduction setup or invocation. These are PoC fixture/invocation failures, not evidence that the hypothesized vulnerability was disproved. Their run artifacts remain in the analysis data directory; this document intentionally omits prompts, generated scripts, and repository source.

The persisted LLM-attempt table recorded 62 calls, all using `gpt-6-sol`. The Codex CLI adapter returned no per-call token or cost measurements, so both totals are unavailable. The configured token and cost caps cannot currently be enforced for this provider: missing usage is counted as zero by `RunUsageBudget`. The elapsed-time cap is checked before LLM calls, but it is not a wall-clock kill switch for an already running request, build, or PoC. Do not describe these three limits as equally effective for Codex.

After the generic progress fix, `resume A-002 --format json` returned the same `BLOCKED` result in about eight seconds. The persisted LLM-attempt count remained 62 before and after resume; previously completed Agent work was not repeated, and recovery-exhausted PoCs were not silently re-run.

## Product diagnosis and next steps

`ProgressProjector._status` currently gives any historical `BLOCKED` checkpoint priority over an actively `RUNNING` checkpoint. During this run, `status A-002` reported `BLOCKED` at an earlier hypothesis while later hypotheses were still executing. This is a reproducible, repository-independent progress-reporting defect. Add a regression test with one blocked and one running hypothesis, then show the active hypothesis until processing stops; when processing has stopped, preserve the terminal `FAILED`/`BLOCKED` precedence.

The current PoC recovery was bounded and recorded, but four generated scripts still failed after repair. No target-specific workaround is justified by this run. Consider a generic prompt/feedback improvement only if a focused test demonstrates the deficiency; otherwise keep the safe `BLOCKED` classification. A second full real run should be a deliberate cost/usage decision because Codex token and cost caps are not measurable here.
