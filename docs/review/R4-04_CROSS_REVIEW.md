# R4-04 교차 검토 기록

이 문서는 무엇을 설명하나요? R4-01~03의 결과가 현재 중앙 문서에 빠짐없이 반영됐는지 역할별로 검토하는 방법과 실제 승인 기록을 설명합니다.

누가 읽어야 하나요? R1~R8 역할 담당자, 통합 구현 담당자와 최종 검토 담당자입니다.

읽은 뒤 무엇을 결정해야 하나요? 자기 담당 영역이 현재 R4 계약과 충돌하지 않는지, R4-04 PR을 병합해도 되는지 결정해야 합니다.

## 현재 상태

- 진행 상태: **교차 검토 중(`IN_REVIEW`)**
- 완료된 범위: R4-01, R4-02, R4-03의 기술 설계와 문서 반영
- 남은 범위: 현재 문서 전체에 대한 역할별 교차 검토, 최종 확인, R4-04 PR 병합
- 교차 검토 PR: [#48](https://github.com/SASTsimi/sastsimi/pull/48)
- 최신 `main` 반영 기준: `eb0076602736ea3821b95c0b81d9a77ba10695d2`
- 최종 검토 기준(`review freeze SHA`): R4-04 PR의 마지막 수정 commit을 PR 본문에 기록합니다.

PR #47은 문서 자동 검사와 기술 검토를 통과했지만 GitHub 교차 리뷰가 없었습니다. 따라서 PR #47과 위 시작 기준 commit은 R4-04의 최종 승인 증거가 아닙니다.

## 이번 검토에서 바꾸지 않는 것

- R4-01의 공통 식별자·상태·오류 계약
- R4-02의 상태 전이·병렬 실행·재시도·복구 계약
- R4-03의 프로그램·LLM·사람 권한 경계
- Verification 중심 제어권, 두 LLM Gate와 Primitive Chaining의 기술 의미

기술 의미를 바꿔야 한다는 의견이 나오면 R4-04에서 조용히 수정하지 않습니다. 별도 수정 commit을 만들고 영향을 받는 역할에게 다시 검토를 요청합니다.

## 승인으로 인정하는 기록

다음 중 하나를 GitHub PR에 남겨야 해당 역할의 검토가 끝난 것으로 봅니다.

1. GitHub 리뷰의 `APPROVED`
2. 리뷰 권한이 없는 경우, PR 댓글에 `검토 완료: 승인`과 확인한 범위를 명시한 기록

단순 확인 댓글, 이모지 반응, 구두 전달은 승인으로 계산하지 않습니다. `CHANGES_REQUESTED` 또는 수정 요청 댓글이 있으면 수정 반영과 해당 역할의 재확인이 필요합니다.

## 역할별 확인 범위와 상태

| 역할 | 담당자 | 이번에 확인할 내용 | 현재 상태 | GitHub 증거 |
|---|---|---|---|---|
| R1 LLM 탐색·체이닝 | `@baeseungwon1010` | 가설 생성, HOLD·TRUE+TRUE 체이닝 입력과 새 가설 재검증 조건 | `RECHECK_REQUIRED` | [이전 승인](https://github.com/SASTsimi/sastsimi/pull/48#issuecomment-5476469510), Research 표현 정리 뒤 최종 SHA 재확인 필요 |
| R2 정적분석·컨텍스트 | `@zv9uvr` | AST/SAST 사실, 코드 위치, 호출 경로, Context 오류·누락 범위와 공통 식별자 연결 | `RECHECK_REQUIRED` | [이전 승인](https://github.com/SASTsimi/sastsimi/pull/48#issuecomment-5477979652), Context 오류의 `AnalysisError`·`DataGap` 연결과 final verdict 조건 추가 뒤 재검토 필요 |
| R3 통합 구현 | `@YHS-Sec` | 상태 전이, 재시도·복구, 계약을 실제 코드로 구현할 수 있는지 | `RECHECK_REQUIRED` | [수정 요청](https://github.com/SASTsimi/sastsimi/pull/48#issuecomment-5486717955) 반영 뒤 최종 SHA 재검토 필요 |
| R4 PM·아키텍처 | `@taehyeon-git` | 다른 역할의 검토 증거, 최신 main과 환경 계약 병합 결과, 최종 commit과 완료 조건 확인 | `RECHECK_REQUIRED` | 최신 main 동기화와 R6–R7 환경 계약 추가 뒤 최종 SHA 재확인 필요 |
| R5 Gate·Finding·보고서 | `@kimhr8463` | 두 Gate 순서, REVISE, Reporter 호출과 사람 전달 조건 | `RECHECK_REQUIRED` | [수정 요청](https://github.com/SASTsimi/sastsimi/pull/48#issuecomment-5476190803) 반영 뒤 최종 SHA 재검토 필요 |
| R6 검증·반박 | `@UltraPeachKeen` | Pro/Con 독립성, Context 오류와 final verdict 구분, TRUE/FALSE/HOLD, `EnvironmentRequirements`·plan revision과 환경 실패 `INCONCLUSIVE` 처리 | `RECHECK_REQUIRED` | Context 오류만으로 HOLD 금지, 정상 근거로 필수 검증 완료 시 판정 허용, 필수 검증 미완료 시 final result 금지 기준 재검토 필요 |
| R7 동적검증·Sandbox | `@Potatonion` | LIMITED/FULL_REPRO, exact 요구사항과 실제 환경 비교, PoC·log·sandbox 권한과 결과 연결 | `RECHECK_REQUIRED` | 최신 main의 실제 환경 비교 계약을 포함한 최종 SHA 재검토 필요 |
| R8 데이터·평가·예산 | `@gitterable` | 운영 `ALWAYS_DEBATE`, 평가 모드 격리, 예산 초과 처리 | `WAITING` | — |

R4 담당자는 이 PR의 작성자이므로 자신의 확인만으로 교차 검토를 대신할 수 없습니다. R4의 최종 확인은 다른 필수 역할의 검토가 끝난 뒤에 수행합니다.

`RECHECK_REQUIRED`는 수정사항을 반영했지만 최종 `review freeze SHA` 기준 재검토가 아직 필요하다는 뜻입니다. 과거 승인·수정 요청 기록은 삭제하지 않습니다.

## 이번 수정 요청의 처리 방향

- 최신 `main`을 병합해 충돌을 해결하고 R4의 exact Sandbox 정책·환경·로그·PoC 전달 계약을 사용합니다.
- R6가 만든 `EnvironmentRequirements`와 plan의 `environment_requirements_ref`, R7의 `EnvironmentCheck`를 exact revision으로 연결합니다.
- 필수 환경 불일치·구성 실패는 공격 전에 멈추고 `INCONCLUSIVE`로 R6에 반환하며 가설 `FALSE`로 바꾸지 않습니다.
- 정책이 없거나 `STALE | UNVERIFIED`이면 Rule Scope Gate를 `UNCERTAIN + DENY`로 고정합니다.
- `POLICY_BLOCKED`는 자동 `REJECT`가 아니며 Technical Gate가 근거 충분성에 따라 `ACCEPT | REVISE | REJECT`를 구분합니다.
- Finding이 없는 packet은 내부 blocked packet으로는 허용하지만 `report_ready=false`와 공개 차단을 강제합니다.
- upstream revision이 바뀐 ReportDraft는 current packet과 공개에 재사용하지 않습니다.
- `handoff_readiness`를 정본과 Wiki에 함께 표시합니다.
- Sandbox authority는 ADR-001에 누적하지 않고 ADR-002에서 별도로 검토합니다.
- active Research 역할처럼 보이는 Issue template과 R3 Issue 표현을 현재 `INITIAL | VERIFICATION | CHAINING` 기준으로 정리합니다.
- Context 조회 실패·timeout·권한 오류는 `AnalysisError`로, 그 때문에 확인하지 못한 범위는 `DataGap`으로 함께 기록하며 오류 자체를 verdict 근거로 쓰지 않습니다.
- 일부 조회가 실패해도 대체 조회·다른 정상 근거와 운영 Pro/Con으로 필수 검증을 완료하면 실제 근거에 따라 `TRUE | FALSE | HOLD`를 허용합니다.
- 필수 Context 또는 운영 Pro/Con을 확보하지 못해 검증 절차를 완료하지 못하면 final `VerificationResult`를 만들지 않고, retry 가능 여부에 따라 work를 `BLOCKED | FAILED`로 남깁니다.

최신 main 병합 commit `cb3aa9944f46f590d631cf3991dcaf44d0f0b00b`에서 위 계약을 보존했고, 문서 자동 검사 61개·Mermaid 정본 13개·Wiki 13개를 실패 0건으로 통과했습니다. 최종 `review freeze SHA`는 이 기록을 포함한 마지막 commit으로 PR 본문에서 다시 고정합니다.

## 리뷰 중 수정이 생겼을 때

1. 수정 요청과 영향을 받는 문서를 PR 대화에 남깁니다.
2. 수정 commit을 별도로 올리고 전체 문서 검사를 다시 실행합니다.
3. PR 본문의 `review freeze SHA`를 새 HEAD commit으로 바꿉니다.
4. 수정 영향을 받는 역할의 기존 승인을 무효로 보고 다시 리뷰를 요청합니다.
5. 수정과 관계없는 역할의 승인을 유지할 때는 영향이 없다는 근거를 PR에 남깁니다.

## 병합 전 필수 조건

- [ ] R1, R2, R3, R5, R6, R7, R8의 승인 증거가 모두 연결되어 있습니다.
- [ ] 해결되지 않은 리뷰 대화와 `CHANGES_REQUESTED`가 없습니다.
- [ ] 마지막 수정 commit이 PR 본문의 `review freeze SHA`와 같습니다.
- [ ] 마지막 수정 이후 영향을 받은 역할의 재검토가 끝났습니다.
- [ ] `scripts/validate-architecture-docs.ps1` 결과가 실패 0건입니다.
- [ ] `git diff --check origin/main...HEAD`가 통과합니다.
- [ ] R4 담당자가 위 증거와 Issue #16 완료 조건을 마지막으로 확인했습니다.

## 완료 처리 순서

1. 필수 교차 검토를 모두 받습니다.
2. 마지막 commit 기준으로 자동 검사와 변경 범위를 다시 확인합니다.
3. R4 담당자가 최종 확인 댓글을 남깁니다.
4. R4-04 PR을 병합합니다.
5. Issue #16을 완료 근거와 함께 닫습니다.
6. R4-01~04가 모두 닫힌 것을 확인하고 상위 Issue #5를 닫습니다.

R4-04와 상위 R4의 종료는 Architecture v5 전체 승인이나 실제 프로그램 구현 완료를 뜻하지 않습니다.
