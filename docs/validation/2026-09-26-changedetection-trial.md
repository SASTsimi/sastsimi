# changedetection.io pinned analysis trials (2026-09-26 KST)

## Reproduction

- Host: Windows PowerShell, project `.venv`, official Codex CLI subscription login, Docker Desktop Linux.
- Provider/model: `codex` / `gpt-6-sol` in both local configuration files; no Agent override.
- Repository: `https://github.com/dgtlmoon/changedetection.io.git`.
- Pinned `master` commit, checked with `git ls-remote` immediately before the run: `d789fe3ea5809eef0134943917ef50f47259121b`.
- Command: `.\.venv\Scripts\sastsimi.exe analyze https://github.com/dgtlmoon/changedetection.io.git --commit d789fe3ea5809eef0134943917ef50f47259121b --format json`.
- Analysis: display ID `A-002`, exact ID `4126f16d371243358a0b73310be44f8d`.
- Started `2026-09-25 17:24:23 UTC`; completed approximately `18:20:55 UTC` (about 57 minutes).

## Observed outcome

The public `analyze`, `status`, and `result` commands completed normally. The final analysis status was `BLOCKED`, with 33 completed and 17 legitimately skipped of 86 known work units (58% credited progress), seven hypotheses and zero findings. Four hypotheses stopped at `POC_EXECUTION_DONE` with `RECOVERY_EXHAUSTED` after the bounded automatic repair attempts. Two finished final verification with `HOLD`; one finished with `FALSE`. `BLOCKED` was not converted to vulnerability disproof. There was no Docker build failure in this run.

The blocked PoCs failed inside generated reproduction scripts. Safe stderr excerpts included `TypeError: Watch.__init__() takes 1 positional argument but 2 were given`, `StopIteration`, `ApiKeyAuth` validation errors, and `KeyError` from reproduction setup or invocation. These are PoC fixture/invocation failures, not evidence that the hypothesized vulnerability was disproved. Their run artifacts remain in the analysis data directory; this document intentionally omits prompts, generated scripts, and repository source.

The persisted LLM-attempt table recorded 62 calls, all using `gpt-6-sol`. The Codex CLI adapter returned no per-call token or cost measurements, so both totals are unavailable. The configured token and cost caps cannot currently be enforced for this provider: missing usage is counted as zero by `RunUsageBudget`. The elapsed-time cap is checked before LLM calls, but it is not a wall-clock kill switch for an already running request, build, or PoC. Do not describe these three limits as equally effective for Codex.

After the generic progress fix, `resume A-002 --format json` returned the same `BLOCKED` result in about eight seconds. The persisted LLM-attempt count remained 62 before and after resume; previously completed Agent work was not repeated, and recovery-exhausted PoCs were not silently re-run.

## Product diagnosis and next steps

At the time of the trial, `ProgressProjector._status` gave any historical `BLOCKED` checkpoint priority over an actively `RUNNING` checkpoint. During this run, `status A-002` reported `BLOCKED` at an earlier hypothesis while later hypotheses were still executing. This repository-independent defect was reproduced by tests and fixed by showing the active hypothesis first, then terminal `FAILED`/`BLOCKED` status when no stage is running.

The generic priority fix is now covered by regression tests. Abrupt process death can still leave a persisted `RUNNING` checkpoint: without a cross-process liveness signal, a status reader cannot safely tell it from a legitimately long stage. This is documented as a follow-up rather than applying a time-based failure heuristic.

The current PoC recovery was bounded and recorded, but four generated scripts still failed after repair. No target-specific workaround is justified by this run. Consider a generic prompt/feedback improvement only if a focused test demonstrates the deficiency; otherwise keep the safe `BLOCKED` classification. A second full real run should be a deliberate cost/usage decision because Codex token and cost caps are not measurable here.

## A-003 후속 검증

동일한 고정 commit, Codex `gpt-6-sol`, Docker Linux 환경에서 새 분석 `A-003`
(`e4caf78288d64603baf14045107aa128`)을 실행했습니다. 일곱 가설의
`POC_EXECUTION_DONE`은 모두 `SUCCEEDED`로 끝났습니다. 생성된 재현 스크립트의
실행 오류 두 건은 취약점 반증으로 처리되지 않고 입력 재생성 후 다시 실행됐습니다.
PoC Agent가 Pro·Con에서 요청한 Git 추적 소스를 받는 경로도 실제 artifact에서
제공 파일 3개, 거부 파일 0개로 확인했습니다.

전체 분석은 `BLOCKED`로 끝났습니다. PoC 오류가 아니라 과거 Runtime의
`TECH_GATE_REVISE` 재시도 방식이 같은 Gate를 반복해 한 가설의 복구 횟수를
소진한 것이 원인입니다. 수정 후 `resume A-003`은 재시도 가능한 다른 Gate를
처리했지만, 이미 `RECOVERY_EXHAUSTED`로 확정된 기록을 초기화하지 않았습니다.
최종 상태는 완료 46건과 정당하게 건너뛴 34건을 합쳐 총 86 work units 대비
진행률 93%, 오류 `RECOVERY_EXHAUSTED`이며 LLM 호출 72건이 기록됐습니다.
따라서 이 분석을 성공 또는 제보 가능한 Finding으로
표기하지 않습니다. 수정된 Gate 흐름은 기존 기록 재개만으로 검증할 수 없어
새 분석에서 다시 확인해야 합니다.

## A-004 새 분석으로 기술 검토 재시도 확인

같은 고정 commit에서 새 분석 `A-004` (`560e3973007845a2bcbad9eeafc52090`)을
2026-09-26 05:19:25 UTC에 시작해 06:03:17 UTC에 마쳤습니다. Codex
`gpt-6-sol`로 77회 호출했고 가설 8건을 생성했습니다. 여덟 가설의
`POC_EXECUTION_DONE`은 모두 `SUCCEEDED`였으며, 네 건은 실행 오류 후
입력을 자동 수정한 두 번째 시도에 성공했습니다. Docker build 실패는
관찰되지 않았습니다.

한 가설의 Technical Gate가 `REVISE`를 요구한 뒤 최종 Verification이
실제로 두 번째 시도로 실행됐습니다. Gate가 다시 수정을 요구하자 정해진
상한에서 `RECOVERY_EXHAUSTED`로 중단했습니다. 이는 이전 A-003에서
같은 Gate만 재호출한 결함과 다릅니다. 전체 상태는 `BLOCKED`, 완료 53건과
정당하게 건너뛴 39건을 합쳐 총 98 work units 대비 진행률 93%, Finding
0건입니다. 기술 검토 미통과를 `TRUE`나 제보 가능한 결과로 승격하지 않았습니다.

A-004 프로세스가 시작된 뒤 리뷰에서 찾은 고정 Git blob 조회, source artifact
크기 제한, 핵심 근거 우선순위와 원자적 checkpoint 재시작 변경은 이 실제 실행에
소급 적용되지 않습니다. 각 변경은 별도 회귀 테스트로 검증했습니다. 이 기록은
최종 코드로 전체 분석이 `COMPLETE`가 됐다는 주장이 아닙니다.
