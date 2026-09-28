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

## A-005: 오류 복구와 종결 상태 확인

동일한 고정 commit에서 Codex `gpt-6-sol`로 실행한 A-005의 정확한 ID는
`f72dd832d69d44f4816547a71179e9dd`입니다. 분석 중 기본 누적 LLM 실행시간
1시간 한도에 도달했고, 사용자의 승인을 받아 **이 분석의 재개 실행에만** 한도를
2시간으로 늘렸습니다. 사용자 기본 설정은 1시간 그대로입니다. 재개 시 완료된
Agent 호출을 중복하지 않고 저장된 LLM 실행시간을 합산했습니다.

Docker 내부의 Playwright 브라우저 누락은 관련 실행 artifact와 stderr를 확인한
경우에만 일회용 이미지에 브라우저 및 필수 OS 패키지를 설치해 재실행하도록
수정했습니다. 호스트를 변경하거나 실행 컨테이너의 네트워크 차단을 풀지
않았습니다. 해당 오류로 막혔던 가설 하나가 실제 Docker 재실행 및 최종 검증까지
진행해 `FALSE`로 종결됐습니다. 다른 한 가설은 PoC 스크립트 실행 자체는
종료 코드 0으로 끝났지만 복구 상한에 도달한 마지막 해석에서 근거가 부족해
`INCONCLUSIVE`였습니다. 이 경우에만 근거 artifact를 유지하며 `HOLD`로 종결하고,
Docker 실행 오류나 인증·환경 오류는 계속 `BLOCKED`로 남깁니다. 과거 실행의
동일한 상태도 명시적 `resume`에서 실제 실행/해석 artifact의 연결과 종료 코드를
검증한 뒤에만 이 분류로 옮겼습니다.

최종 공개 `result` 및 대시보드 상태는 **`COMPLETE` 100%**입니다. 가설 10건 중
Finding 2건, 리포트 2건, 근거 부족으로 종결한 `INCONCLUSIVE` 1건입니다.
전체 work unit 122개 중 71개가 실행 완료됐으며, 나머지는 판정에 따라
정당하게 건너뛴 단계입니다. LLM 호출 기록은 109회, 누적 실행시간은
4,385,618ms(약 73분)입니다. Codex CLI가 호출별 토큰·비용을 제공하지 않아
비용 합계는 확인할 수 없습니다. **두 Finding의 Scope Gate 결과는 모두
`UNCERTAIN`입니다.** 분석 `COMPLETE`는 모든 가설이 종결됐다는 의미이며,
이 리포트를 곧바로 외부에 제보해도 된다는 승인이나 취약점 확정을 뜻하지
않습니다.

완료 후 기본 1시간 설정으로 공개 `resume A-005 --format json`을 한 번 더 실행한
결과도 `COMPLETE`였으며 LLM 호출 수 109회와 누적 4,385,618ms는 전후 동일했습니다.
이미 끝난 Agent 작업을 다시 청구하지 않는다는 점을 이 실행에서 확인했습니다.

이 시험은 중간에 수정된 코드를 사용해 동일한 A-005를 재개한 검증입니다.
최종 코드로 처음부터 새 분석을 한 번 더 실행했다는 뜻은 아닙니다. 전 세계의
임의 저장소에서 항상 `COMPLETE`를 보장할 수도 없습니다. 환경·도구 오류는
근거 없이 성공 처리하지 않고 명시적으로 `BLOCKED`로 남겨야 합니다.
