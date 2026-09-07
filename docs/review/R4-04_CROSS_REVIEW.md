# R4-04 교차 검토 기록

이 문서는 무엇을 설명하나요? R4-01~03의 결과가 현재 중앙 문서에 빠짐없이 반영됐는지 역할별로 검토하는 방법과 실제 승인 기록을 설명합니다.

누가 읽어야 하나요? R1~R8 역할 담당자, 통합 구현 담당자와 최종 검토 담당자입니다.

읽은 뒤 무엇을 결정해야 하나요? 자기 담당 영역이 현재 R4 계약과 충돌하지 않는지, R4-04 PR을 병합해도 되는지 결정해야 합니다.

## 현재 상태

- 진행 상태: **완료(`COMPLETED`)**
- 완료된 범위: R4-01~04 공통 계약·권한·복구·교차 검토
- 교차 검토 PR: [#48](https://github.com/SASTsimi/sastsimi/pull/48), merge commit `7e5450ac552877f54ddfcc613c06c734405e78bb`
- 종료 근거: R4 상위 Issue [#5](https://github.com/SASTsimi/sastsimi/issues/5) 종료
- 현재 전체 설계 기준: Final Issue [#10](https://github.com/SASTsimi/sastsimi/issues/10)과 [최종 승인 기록](./FINAL_ARCHITECTURE_V5_APPROVAL.md)

아래 역할별 표와 수정 요청은 PR #48 당시의 검토 이력입니다. 이후 역할 PR에서 계약이 확장됐으므로 이 기록을 현재 main의 승인으로 재사용하지 않습니다. 현재 정확한 SHA에 대한 최종 확인은 #10의 별도 Final PR에서 다시 받습니다.

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

## PR #48 당시 역할별 확인 범위와 상태

| 역할 | 담당자 | 이번에 확인할 내용 | 현재 상태 | GitHub 증거 |
|---|---|---|---|---|
| R1 LLM 탐색·체이닝 | `@baeseungwon1010` | 가설 생성, HOLD 입력·TRUE 결과의 체이닝과 새 가설 재검증 조건 | `RECHECK_REQUIRED` | [이전 승인](https://github.com/SASTsimi/sastsimi/pull/48#issuecomment-5489231154) 뒤 `validation_checks`의 stable ID 계약이 추가되어 최종 SHA 재검토 필요 |
| R2 정적분석·컨텍스트 | `@zv9uvr` | AST/SAST 사실, 코드 위치, 호출 경로, Context 오류·누락 범위와 공통 식별자 연결 | `RECHECK_REQUIRED` | [b037bd3 승인](https://github.com/SASTsimi/sastsimi/pull/48#issuecomment-5495159036) 뒤 Context 완료 결과와 실패 상태 계약이 추가되어 최종 SHA 재검토 필요 |
| R3 통합 구현 | `@YHS-Sec` | 상태 전이, 재시도·복구, 계약을 실제 코드로 구현할 수 있는지 | `RECHECK_REQUIRED` | [이전 승인](https://github.com/SASTsimi/sastsimi/pull/48#issuecomment-5494246304) 뒤 `ValidationCheckResult`와 가설 `FAILED` atomic transition이 추가되어 최종 SHA 재검토 필요 |
| R4 PM·아키텍처 | `@taehyeon-git` | 다른 역할의 검토 증거, 최신 main과 환경 계약 병합 결과, 최종 commit과 완료 조건 확인 | `RECHECK_REQUIRED` | 최신 main 동기화와 R6–R7 환경 계약 추가 뒤 최종 SHA 재확인 필요 |
| R5 Gate·Finding·보고서 | `@kimhr8463` | 두 Gate 순서, REVISE, Reporter 호출과 사람 전달 조건 | `APPROVED` | [aff3106 승인](https://github.com/SASTsimi/sastsimi/pull/48#issuecomment-5491995886). 이후 변경은 이미 승인한 final TRUE 전용 Gate 범위를 더 명확히 했고 R5의 Gate 결과·순서·Reporter 계약은 바꾸지 않음 |
| R6 검증·반박 | `@UltraPeachKeen` | Pro/Con 독립성, Context 오류와 final verdict 구분, TRUE/FALSE/HOLD, `EnvironmentRequirements`·plan revision과 환경 실패 `INCONCLUSIVE` 처리 | `RECHECK_REQUIRED` | [b037bd3 최종 리뷰](https://github.com/SASTsimi/sastsimi/pull/48#issuecomment-5494941957)의 TRUE 전용 Technical Gate 문구와 검증 완료·실패 계약을 반영한 최종 SHA 재검토 필요 |
| R7 동적검증·Sandbox | `@Potatonion` | 당시 LIMITED/FULL_REPRO, exact 요구사항과 실제 환경 비교, PoC·log·sandbox 권한과 결과 연결 | `SUPERSEDED` | [aff3106 당시 승인](https://github.com/SASTsimi/sastsimi/pull/48#issuecomment-5490971913). 이후 ADR-007 자율 재현 계약이 mode·log·result-owner를 대체했으므로 새 기준 재검토 필요 |
| R8 데이터·평가·예산 | `@gitterable` | 운영 `ALWAYS_DEBATE`, 평가 모드 격리, 예산 초과 처리 | `APPROVED` | [aff3106 승인](https://github.com/SASTsimi/sastsimi/pull/48#issuecomment-5492356188). 이후 변경은 debate·평가·예산 계약을 바꾸지 않음 |

R4 담당자는 이 PR의 작성자이므로 자신의 확인만으로 교차 검토를 대신할 수 없습니다. R4의 최종 확인은 다른 필수 역할의 검토가 끝난 뒤에 수행합니다.

`RECHECK_REQUIRED`는 수정사항을 반영했지만 최종 `review freeze SHA` 기준 재검토가 아직 필요하다는 뜻입니다. 과거 승인·수정 요청 기록은 삭제하지 않습니다.

## 이번 수정 요청의 처리 방향

- 최신 `main`을 병합해 충돌을 해결하고 R4의 exact Sandbox 정책·환경·로그·PoC 전달 계약을 사용합니다.
- R6가 만든 `DynamicReproductionRequest`, R7이 만든 `EnvironmentRequirements`·plan·PoC candidate와 실제 `EnvironmentCheck`를 exact revision으로 연결합니다.
- 모든 final TRUE에는 현재 generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 validated PoC가 필요하고, 실패는 verdict 없이 `BLOCKED | FAILED`로 처리합니다.
- 필수 환경 불일치·구성 실패는 공격 전에 멈추고 `INCONCLUSIVE`로 R6에 반환하며 가설 `FALSE`로 바꾸지 않습니다.
- run 시작 때 `STALE` 정책 cache는 재사용하지 않고 새로 준비합니다. 정책이 없거나 현재 `RunPolicyState=UNVERIFIED`이면 Rule Scope Gate를 `UNCERTAIN + DENY`로 고정합니다.
- `POLICY_BLOCKED`는 Sandbox profile 외부 격리 경계 위반이며 프로그램 정책/testing restriction 판정이 아닙니다. 가설 반증이나 자동 `REJECT`로 바꾸지 않고, validated PoC가 없으므로 final verdict와 Technical Gate 없이 `BLOCKED | FAILED`로 처리합니다.
- Finding이 없으면 Reporter를 호출하지 않고 `AnalysisRunResult.report_draft_refs=[]`와 `REPORT_NOT_READY` 원인을 보존합니다.
- upstream revision이 바뀐 ReportDraft는 current `AnalysisRunResult`에 재사용하지 않습니다.
- ReportDraft 생성 뒤 Agent 자동화는 끝나며 사람의 검토·수정·제출·공개는 자동화 밖에서 수행합니다.
- `handoff_readiness`를 정본과 Wiki에 함께 표시합니다.
- Sandbox authority는 ADR-001에 누적하지 않고 ADR-002에서 별도로 검토합니다.
- active Research 역할처럼 보이는 Issue template과 R3 Issue 표현을 현재 `INITIAL | VERIFICATION | CHAINING` 기준으로 정리합니다.
- Context 조회 실패·timeout·권한 오류는 `AnalysisError`로, 그 때문에 확인하지 못한 범위는 `DataGap`으로 함께 기록하며 오류 자체를 verdict 근거로 쓰지 않습니다.
- 일부 조회가 실패해도 대체 조회·다른 정상 근거와 운영 Pro/Con으로 필수 검증을 완료하면 실제 근거에 따라 `TRUE | FALSE | HOLD`를 허용합니다.
- 필수 Context 또는 운영 Pro/Con을 확보하지 못해 검증 절차를 완료하지 못하면 final `VerificationResult`를 만들지 않고, retry 가능 여부에 따라 work를 `BLOCKED | FAILED`로 남깁니다.
- 가설의 필수 검증 문장을 단순 문자열로 두지 않고 stable `validation_id`가 있는 `ValidationCheck`로 정의하며, final 결과는 같은 ID의 `ValidationCheckResult`가 모두 `COMPLETE`이고 실제 근거를 가리킬 때만 저장합니다.
- retry 가능한 검증 실패는 가설을 `VERIFYING`으로 유지합니다. 재시도를 소진하거나 복구할 수 없으면 failed Verification work와 가설의 `FAILED` 상태를 원자적으로 묶고, final verdict와 Gate 입력을 만들지 않습니다.
- Technical Evidence Gate는 exact final `TRUE`만 의미적으로 검토합니다. `FALSE | HOLD`와 검증 실패 가설은 Gate 입력이 아니며 Runtime Validator의 구조 검사 통과를 Gate 승인으로 해석하지 않습니다.

최신 `main` 기준 계약을 보존했고, 문서 자동 검사 61개·Mermaid 정본 13개·Wiki 13개를 실패 0건으로 통과했습니다. 최종 `review freeze SHA`는 이 기록을 포함한 마지막 commit으로 PR 본문에서 고정합니다.

## 리뷰 중 수정이 생겼을 때

1. 수정 요청과 영향을 받는 문서를 PR 대화에 남깁니다.
2. 수정 commit을 별도로 올리고 전체 문서 검사를 다시 실행합니다.
3. PR 본문의 `review freeze SHA`를 새 HEAD commit으로 바꿉니다.
4. 수정 영향을 받는 역할의 기존 승인을 무효로 보고 다시 리뷰를 요청합니다.
5. 수정과 관계없는 역할의 승인을 유지할 때는 영향이 없다는 근거를 PR에 남깁니다.

## R4-04 완료 근거

- [x] PR #48이 `main`에 병합됐습니다.
- [x] R4-04 Issue #16과 R4 상위 Issue #5가 종료됐습니다.
- [x] 후속 역할 PR의 변경은 각 역할 Issue에서 다시 검토했습니다.
- [x] 현재 main 전체의 정확한 freeze 검토는 과거 승인 재사용 없이 Final Issue #10으로 분리했습니다.

## 완료 처리 기록

1. R4-04 PR #48을 병합했습니다.
2. Issue #16과 상위 Issue #5를 완료 처리했습니다.
3. 이후 변경은 역할별 Issue·PR에서 검토했고, 전체 current main은 #10에서 다시 고정합니다.

R4-04와 상위 R4의 종료는 Architecture v5 전체 승인이나 실제 프로그램 구현 완료를 뜻하지 않습니다.
