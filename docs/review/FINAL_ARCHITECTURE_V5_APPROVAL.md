# Architecture v5 최종 승인 기록

- **이 문서는 무엇을 설명하나요?** 최종 설계의 정확한 기준 commit, 전체 흐름 추적 결과, 승인 범위와 구현 전에 남은 실제 시험을 기록합니다.
- **누가 읽어야 하나요?** R1~R8 역할 담당자, 전체 구현 담당자와 최종 검토자가 읽습니다.
- **읽은 뒤 무엇을 확인하나요?** Final PR의 정확한 head를 검토했는지, 구현이 따라야 할 기준과 아직 증명하지 않은 항목을 구분합니다.

> 상태: **DESIGN_APPROVED / NOT_IMPLEMENTED**
>
> 이 상태는 Final PR #117이 병합된 2026-09-08부터 유효합니다.

## 1. 고정한 검토 대상

- 검토 시작 기준 `main`: `07bd6549a676419c0e720f940ba7abd1b82aea0d`
- 마지막 설계 병합: [PR #116](https://github.com/SASTsimi/sastsimi/pull/116), R3-06 구현 기준선
- 최종 승인 PR: [PR #117](https://github.com/SASTsimi/sastsimi/pull/117)
- 최종 승인 PR head: `0647514f9d3d288fbedfa983c5b828d88c909df8`
- 최종 승인 merge commit: `2de1f6767d8bc25ee7383adacb3082b4ff761f8a`
- 완료 확인: Issue #92와 R3 상위 Issue #4
- 역할별 완료 확인: R1~R8 상위 Issue #2~#9 모두 `CLOSED`
- 최종 관리: [Issue #10](https://github.com/SASTsimi/sastsimi/issues/10)은 PR #117 병합으로 `CLOSED`; [PM Epic #1](https://github.com/SASTsimi/sastsimi/issues/1)은 post-merge `main` 감사 commit `8afd37794ac581039d626f1df52f1be06533b13a` 확인 뒤 `CLOSED`

`07bd654...`은 마지막 선행 설계 PR까지 병합한 **검토 시작 기준 main SHA**입니다. Final PR #117은 새 기능·field·enum·상태 전이·권한·Agent 역할을 추가하지 않았지만, 최종 리뷰에서 발견한 기존 계약의 모호함을 바로잡은 수정과 승인 상태·검토 기록을 함께 포함했습니다. 승인 대상은 위에 기록한 정확한 PR head `0647514...`이고, GitHub가 만든 merge commit은 `2de1f67...`입니다.

승인 뒤 설계 의미가 바뀌면 새 Issue·ADR·PR에서 영향을 받는 역할의 검토를 다시 받아야 합니다. 상태·링크·완료 기록만 고치는 유지보수 변경도 `main`에서 문서 검사와 diff를 다시 확인하고 감사 기록을 남깁니다.

## 2. 승인 범위

이번 승인은 다음 문서 설계를 구현 기준으로 고정합니다.

- root README와 Architecture v5 `01`~`13`
- `08-lightweight-data-contracts.md`의 공통 ID·state·exact reference·권한·저장 계약
- Architecture v5 Wiki와 정본 Mermaid의 동일 흐름
- R3 구현 인계 문서 `implementation/01`~`06`
- 설계 결정 기록 ADR-005~010, ADR-012~015와 이전 결정을 보존한 superseded ADR
- governance, findings, issue tracker와 최종 검토 기록

다음은 승인 범위가 아닙니다.

- 실행 코드 구현 완료
- 특정 Provider·모델·회원 로그인 경로의 실제 지원
- 실제 취약점 탐지 정확도·비용·속도 달성
- Docker 격리와 공식 정책 수집의 실제 운영 시험 통과
- 사람의 외부 제출·공개 자동화

## 3. 시작 조건 확인

| 조건 | 결과 | 근거 |
|---|---|---|
| R1~R8 상위 Issue 완료 | PASS | GitHub Issue #2~#9 `CLOSED` |
| R3-06과 구현 기준선 완료 | PASS | PR #116 병합, Issue #92·#4 `CLOSED` |
| 열린 Blocker 0 | PASS | `FINDINGS.md`의 Blocker 모두 `RESOLVED` |
| 열린 High 0 | PASS | H-003~005를 안전한 기본값·비활성화 조건으로 닫고 실제 시험은 아래 후속 항목으로 분리 |
| Medium/Low의 담당·재검토 시점 | PASS | §6과 `FINDINGS.md`에 owner와 활성화 전 조건 기록 |
| 기준 문서 자동 검사 | PASS | 검토 시작 기준 main, PR #117 head와 merge 뒤 `main`에서 `validate-architecture-docs.ps1` 실패 0 |

## 4. 전체 흐름 문서 추적 결과

아래 `PASS`는 문서와 검증 규칙을 처음부터 끝까지 따라갔을 때 모순이 없다는 뜻입니다. 아직 실행 코드가 없으므로 실제 runtime 시험 성공을 뜻하지 않습니다.

### 4.1 저장소·정적 사실·가설

| ID | 확인한 상황 | 결과 | 기준 문서 |
|---|---|---|---|
| F-01 | clone·checkout 실패가 취약점 `FALSE`가 되지 않음 | PASS | `01`, `02`, `07`, `08`, `10` |
| F-02 | 다른 workspace·commit·record revision 결과가 current 분석에 섞이면 거절 | PASS | `02`, `08`, `10`, 구현 `02`·`03` |
| F-03 | SAST 규칙 실행 후 0건, 미실행, 확인 불가와 부분 성공을 구분 | PASS | `02`, `07`, `08` |
| F-04 | 저장소 지시문은 데이터이며 Provider·권한·정책을 바꾸지 못함 | PASS | `03`, `09`, `10` |
| F-05 | Hypothesis Agent 출력은 `HYPOTHESIS_ONLY / NON_FINAL`이고 trusted validation 뒤에만 등록 | PASS | `03`, `08`, 구현 `01`·`05` |
| F-06 | schema repair 실패·중복 검토 실패는 Finding이나 `FALSE`를 만들지 않음 | PASS | `03`, `08`, `09` |

### 4.2 Verification·찬반·동적 재현

| ID | 확인한 상황 | 결과 | 기준 문서 |
|---|---|---|---|
| F-07 | Context gap·timeout·권한 오류를 기록하고 확인하지 못한 범위를 자동 반증으로 사용하지 않음 | PASS | `02`, `04`, `07`, `08` |
| F-08 | 운영 Pro·Con이 같은 입력 hash와 서로 다른 NEW session으로 병렬 실행되고 한쪽 누락 시 verdict가 없음 | PASS | `04`, `08`, `09` |
| F-09 | R6는 목적·목표·환경 조건을 요청하고 R7이 requirements·plan·PoC·동적 근거를 생산 | PASS | `04`, `08`, ADR-007 |
| F-10 | 한 Verification generation에 동적 work 하나만 만들고 retry는 같은 work의 새 attempt로 추적 | PASS | `04`, `07`, `08` |
| F-11 | PoC candidate와 validated PoC를 구분하고, current generation의 exact `DynamicReproductionRequest`와 같은 `DYNAMIC_REPRO` 실행 attempt의 recipe·환경·AgentLog·candidate·command digest를 요구 | PASS | `04`, `07`, `08`, `10` |
| F-12 | 모든 final TRUE에 `SUCCEEDED + SUPPORTED` 동적 결과와 validated PoC가 필요 | PASS | `04`, `05`, `08` |
| F-13 | 실제 반증은 `FALSE`, 정상 실행했지만 불충분하면 `HOLD`, 환경·정책 경계·Provider 실패면 verdict 없이 `BLOCKED | FAILED` | PASS | `04`, `07`, `08`, `10` |
| F-14 | 늦은 이전 attempt 결과, 바뀐 request·profile과 stale PoC를 current 결과로 저장하지 않음 | PASS | `07`, `08`, 구현 `02`·`03` |

### 4.3 CWE·두 Gate·Finding·Reporter

| ID | 확인한 상황 | 결과 | 기준 문서 |
|---|---|---|---|
| F-15 | CWE Labeling Agent(R5-01)만 current final TRUE에 맞는 CWELabel을 만들고 새 Verification이면 다시 평가 | PASS | `05`, `08`, ADR-009 |
| F-16 | Technical Evidence Gate Agent는 final TRUE·current CWE pair만 검토하고 verdict·label을 직접 바꾸지 않음 | PASS | `05`, `08`, `10` |
| F-17 | Technical `REVISE`가 같은 Verification owner로 돌아가 새 generation·근거·CWE revision을 만들게 함 | PASS | `03`, `04`, `05`, `08` |
| F-18 | 공식 정책 부재는 `UNCERTAIN + DENY`, 수집 실패는 Gate 미호출, 오래되거나 확인 못한 cache는 허용 근거가 아님 | PASS | `05`, `08`, `10`, ADR-013 |
| F-19 | 금지 테스트 위반은 result Primitive를 막고, 다른 scope·impact 실패는 보고 가능성만 막음 | PASS | `05`, `06`, `08`, ADR-011, ADR-014 |
| F-20 | Finding normalization은 Rule Scope review 결과 뒤 항상 수행하고 Reporter는 current TRUE Finding만 처리 | PASS | `05`, `08`, `12`, `13` |
| F-21 | 선행 Verification·CWE·Gate·정책 revision이 바뀌면 기존 ReportDraft를 current 결과에 재사용하지 않음 | PASS | `05`, `08`, `10`, `12` |
| F-21A | ReportDraft 본문의 모든 `path:line`이 exact Verification의 실제 `EvidenceClaim.code_locations`와 같은 workspace·commit·file·line인지 저장 전에 검사 | PASS | `05`, `08`, `10`, `12`, 구현 `02` |

### 4.4 Primitive·Chaining·종료

| ID | 확인한 상황 | 결과 | 기준 문서 |
|---|---|---|---|
| F-22 | `FALSE`와 candidate가 없는 HOLD는 Primitive·Chaining 입력이 아님 | PASS | `06`, `08` |
| F-23 | candidate가 있는 HOLD는 `inputs + result=null`, 승인된 TRUE는 `inputs + result` Primitive로 저장 | PASS | `06`, `08`, ADR-005·014 |
| F-24 | Chaining은 upstream result가 downstream의 특정 input을 충족하는 방향만 검토하고 exact parent·lineage·중복 키를 고정 | PASS | `06`, `08`, ADR-012 |
| F-25 | Chaining 결과는 확정 취약점이 아니라 새 `origin=CHAINING` 가설이며 전체 Verification을 다시 수행 | PASS | `03`, `06`, `08` |
| F-26 | 예산·취소·중단은 stop reason으로 남기고 아직 검증하지 못한 가설을 `FALSE`로 바꾸지 않음 | PASS | `06`, `07`, `08` |
| F-27 | 인증 실패·rate limit·session 오류가 취약점 verdict가 되지 않고 exact profile·model·prompt·schema가 추적됨 | PASS | `07`, `08`, `09` |
| F-28 | `ReportDraft`와 `AnalysisRunResult` 확정 뒤 Agent 자동화가 끝나며 검토·수정·제출·공개는 사람 책임 | PASS | `01`, `05`, `08`, `10`, `12`, `13` |

## 5. 역할별 최종 확인 범위

역할별 상위 Issue 종료는 담당 설계의 완료 근거입니다. 아래 표는 승인 뒤 설계를 변경할 때 다시 확인해야 할 범위를 고정합니다.

| 역할 | 최종 확인 담당 | 확인 범위 |
|---|---|---|
| R1 | `@baeseungwon1010` | Hypothesis·Primitive·Chaining·새 가설 재검증 |
| R2 | `@zv9uvr` | clone·AST/SAST·StaticFactBundle·Context |
| R3 | `@YHS-Sec` | 구현 기준선·Provider·Prompt·복구·통합. PR 작성자의 R4 공동 검토도 수행 |
| R4 | `@YHS-Sec` | 공통 ID·상태·exact reference·권한·리뷰 중 계약 명확화와 승인 기록이 실제 diff와 일치하는지 |
| R5 | `@kimhr8463` | CWE·두 Gate·Finding·Reporter·정책 경계 |
| R6 | `@UltraPeachKeen` | Pro·Con·Verification·동적 요청·final verdict |
| R7 | `@Potatonion` | Dynamic Reproduction Agent·Reproduction Setup Automation·Controller·Session Manager |
| R8 | `@gitterable` | 평가·예산·운영 활성화 기준 |

PR #117의 실제 승인과 대화는 GitHub review·댓글에 보존합니다. 이 표는 사람의 GitHub 승인을 대신하지 않으며, 이후 변경에서 누가 무엇을 다시 확인해야 하는지 정하는 기준입니다.

## 6. 구현·운영 전 후속 조건

| 후속 항목 | 담당 | 다시 볼 시점 | 미완료 시 처리 |
|---|---|---|---|
| exact ProviderProfile의 PVD-01~15, 동적 재현용 PVD-16 실제 결과 | R3·R8 | 해당 Provider/profile 활성화 전 | `UNSUPPORTED | UNVERIFIED`, 호출 차단 |
| versioned corpus·정답·grader·예산으로 실제 품질 평가와 운영 추천 | R8·각 LLM 역할 | Provider·model·Prompt·session 운영 변경 전 | 기존 운영 기본값 유지, 새 설정 활성화 금지 |
| Sandbox 격리·egress·daemon/socket·mount·secret·cleanup 부정 시험 | R7·R3 | untrusted PoC 실행 전 | 동적 실행 차단, TRUE·validated PoC·Gate 없음 |
| 공식 정책 출처·freshness·Parser 실패 시험 | R5·R8·R3 | Rule Scope·Reporter 운영 전 | `UNCERTAIN + DENY` 또는 Gate 미호출 |
| 저장소 라이선스와 외부 기여 범위 | 저장소 관리 담당 | 외부 재사용·기여를 허용하기 전 | 라이선스 권한을 추정하지 않음 |
| Docsify CDN version pin과 offline rendering | 문서 관리 담당 | offline 배포 또는 장기 문서 배포 전 | 번호 문서를 정본으로 사용 |

## 7. Post-merge main 감사

Final PR #117 병합 뒤 merge commit `2de1f6767d8bc25ee7383adacb3082b4ff761f8a`를 새 작업 없이 직접 다시 검토했다. 발견한 문제는 core Agent 흐름을 바꾸는 문제가 아니라 완료 상태·과거 기록·출력 검증 설명의 불일치였으며, 감사 수정 commit `8afd37794ac581039d626f1df52f1be06533b13a`에서 다음과 같이 정리했다.

- PR #97 Prompt 계약을 아직 미병합 제안으로 표시하던 구현 시험 문서를 실제 merge 상태로 수정
- Final PR #117의 exact head·merge commit과 Issue #10 종료 상태를 기준 문서에 동기화
- superseded R6/R7 작업 계획과 과거 ADR이 현재 정본처럼 보이지 않도록 현재 정본 링크와 문서 지위를 명시
- `ReportDraft.content_ref` 본문의 모든 `path:line`을 exact Verification의 `EvidenceClaim.code_locations`와 대조하고, 다른 workspace·commit·file·line이면 `INVALID_OUTPUT`·`REPORT_ERROR`로 저장을 차단하는 규칙과 시험 추가
- `OPEN_QUESTIONS`를 설계 미결정 목록이 아니라 구현·운영 전 설정과 실제 시험 증거 목록으로 정리

감사 commit에서 문서 validator 실패 0, 로컬 Markdown 링크 누락 0, 홀수 code fence 0, Git 충돌 표시 0, 공통 schema 중복 선언 0, 정본/Wiki Mermaid 13/13을 확인했다. 이 수정은 새 Agent·field·enum·상태 전이·권한을 추가하지 않았고, 기존 Reporter의 “검증된 사실만 정확히 표현” 규칙을 실행 가능한 출력 검사로 명확히 했다. 이 증거로 PM Epic #1을 종료했다.

## 8. 최종 판정

- 문서 구조·계약 추적: **PASS**
- 열린 Architecture Blocker/High: **0**
- 설계 상태: **DESIGN_APPROVED**
- 구현 상태: **NOT_IMPLEMENTED**
- 최종 승인 근거: PR #117 exact head `0647514...`에서 문서 검사와 diff 검사를 통과했고 미해결 `CHANGES_REQUESTED` 없이 merge commit `2de1f67...`로 병합됨
- 종료 상태: Issue #10과 PM Epic #1 모두 `CLOSED`; 열린 설계 Issue·PR 없음

이 승인은 “완벽한 제품”이나 “취약점 탐지 성능 검증” 선언이 아닙니다. 구현자가 임의로 다시 해석하지 않아도 되는 설계 기준을 고정하고, 실제 코드와 운영 기능은 위 시험을 통과하기 전까지 안전하게 비활성화하는 결정입니다.
