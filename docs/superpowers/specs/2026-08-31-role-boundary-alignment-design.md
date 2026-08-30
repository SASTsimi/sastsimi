# Architecture v5 역할별 상위 Issue 경계 정합화 설계

## 목적

GitHub 상위 Issue `#1–#10`과 저장소의 역할 안내 문서가 Architecture v5의 현재 제어권을 같은 뜻으로 설명하도록 맞춘다. 특히 동적 재현에서 R6 Verification과 R7 Sandbox의 판단·실행 책임을 분리하고, 서로 연결되는 역할에는 정확한 입력·출력과 교차 검토 지점을 함께 적는다.

## 적용 원칙

각 역할은 다음 다섯 항목으로 설명한다.

1. 무엇을 입력받는가
2. 어떤 판단이나 기준을 소유하는가
3. 무엇을 출력하는가
4. 다음 어느 역할이 소비하는가
5. 무엇을 직접 결정하거나 실행할 수 없는가

역할이 연결되는 지점은 한쪽 문서에만 적지 않는다. 생산자와 소비자 양쪽에 같은 계약 이름과 반대 방향의 책임을 적고, 공통 계약과 실행 허가는 R4의 trusted runtime 경계로 연결한다.

## 역할별 권한 경계

| 역할 | 소유하는 판단·기준 | 주요 출력 | 다음 소비자 | 직접 할 수 없는 일 |
|---|---|---|---|---|
| R1 LLM 탐색·체이닝 | 초기 가설 제안 기준, 활성 Primitive의 `TRUE+HOLD`·방향성 `TRUE+TRUE` 결합 후보 기준 | `HypothesisProposal`, `ChainingResult` | Orchestration 등록 단계, 이후 R6 | verdict·CWE·Gate·보고 확정, 일반 우회 탐색 |
| R2 정적분석·컨텍스트 | AST/SAST 정규화와 동일 workspace/commit 코드 조회 기준 | `StaticFactBundle`, `CodeContextResponse`, `DataGap` | R1, R6 | 취약점 가설·verdict 확정 |
| R3 통합 개발 | 모듈 연결·계약 준수·복구·종단 테스트 설계 | dependency map, contract/E2E test plan | 모든 역할과 최종 검토 | 전문 역할의 enum·판정 의미 변경 |
| R4 PM·아키텍처 | 공통 식별자·상태·오류·권한·실행 순서와 trusted runtime 강제 기준 | 공통 계약, 상태 전이, 권한·승인 규칙 | 모든 역할 | domain verdict·Gate·정책·공개 결정 |
| R5 Gate·보고 | 기술 근거 검토, 공식 정책·영향 검토, 보고서 초안 조건 | 두 Gate 결과, revision request, `ReportDraft` | 같은 R6 owner, 사람 검토 | Verification verdict 변경, 외부 공개 결정 |
| R6 Verification | 가설별 Context·Pro/Con, 동적 재현 필요성, `NOT_REQUIRED/LIMITED_REPRO/FULL_REPRO`, `ReproductionPlan`, 최종 `TRUE/FALSE/HOLD`, Technical `REVISE` 보완 | `ReproductionPlan`, `VerificationResult`, Verification-origin proposal | trusted runtime, R7, R5, R1 | Sandbox 직접 실행·동적 결과 생산, Gate·정책·공개 결정 |
| R7 동적검증·Sandbox | 승인된 계획의 실행 방법, Sandbox 환경·안전 프로파일, 실행·관측·PoC 기록 기준 | `SandboxStepLog`, `DynamicReproductionResult`, redacted PoC | R6, R5, 관측 저장 계층 | 동적 재현 필요성·모드 선택, 계획 수정, 최종 verdict |
| R8 데이터·평가·예산 | 평가 corpus·지표·예산 profile·회귀 합격 기준 | versioned scenario matrix, metric, budget profile | R4 runtime, 각 역할, R3 | 예산을 직접 강제하거나 domain 의미·provider 설정을 조용히 변경 |

## 핵심 연결 흐름

### 동적 재현

```text
R6 Verification
→ 재현 필요성 및 LIMITED/FULL 결정
→ exact ReproductionPlan 후보 생산
→ trusted runtime이 SAVE_RESULT(result_kind=reproduction_plan) 검사·COMMITTED
→ exact RUN_SANDBOX 허가
→ R7이 계획을 변경하지 않고 실행
→ SandboxStepLog·DynamicReproductionResult·PoC 후보 생산
→ trusted runtime이 계획·허가·실행 log·결과를 대조해 COMMITTED
→ R6가 확정 결과를 다른 근거와 종합해 최종 verdict 결정
```

R7은 실행 불가능·정책 차단·환경 실패를 구조화해 반환할 수 있지만, 그 이유로 모드를 바꾸거나 `FALSE`를 판정하지 않는다. 계획 변경이 필요하면 R6가 새 계획 revision과 새 실행 요청을 만든다.

### Gate 보완

Technical Gate의 `REVISE`는 Orchestration이나 R7로 보내지 않는다. 같은 ACTIVE `VerificationAssignment`의 R6 owner가 새 Verification work에서 필요한 Context·Pro/Con·정적·동적 근거 또는 CWE revision을 보완해 다시 제출한다. R7은 새로 승인된 `ReproductionPlan`이 있을 때만 재실행한다.

### Chaining

R1 Chaining은 임의의 `TRUE` 두 개를 입력으로 삼지 않는다. `HOLD`의 REQUIRED Primitive와 두 Gate를 통과한 현재 TRUE revision의 PROVIDED Primitive만 활성 입력이다. 방향성 `TRUE+TRUE`는 앞 PROVIDED가 뒤 TRUE의 exact 선행 조건을 충족할 때만 새 가설 후보를 만들며, 새 가설은 자동 `TRUE`나 `CRITICAL`이 아니다.

### 예산

R8은 측정 가능한 예산 profile과 합격 기준을 설계한다. 각 전문 역할은 최소 실행 요구와 품질 저하 조건을 제공하고, R4 trusted runtime이 승인된 profile을 실제 action에 강제한다. R8의 기준 변경만으로 verdict·Gate·Sandbox 정책이나 provider 설정을 바꿀 수 없다.

## 수정 대상

### GitHub 상위 Issue

- `#1`: 역할 연결 요약과 R6→runtime→R7→R6 흐름 추가
- `#2`: 단순 final TRUE가 아니라 Gate provenance가 있는 PROVIDED Primitive만 TRUE 체이닝 입력이라는 표현으로 통일
- `#6`: Technical `REVISE`의 exact 목적지를 같은 R6 owner로 고정
- `#7`: 동적 재현 모드 선택과 `ReproductionPlan` 생산·결과 소비 책임 명시
- `#8`: 재현 필요성·LIMITED/FULL 선택 책임 제거, 승인된 plan 실행·결과 생산 책임으로 교체하고 `#19–#22` 연결
- `#9`: 예산 기준 설계자와 runtime 강제자, 전문 역할의 품질 요구 제공 책임 분리
- `#10`: 동적 재현 계획 생산·실행·결과 소비와 stale/plan 변경 종단 시나리오 추가

`#3`, `#4`, `#5`는 현재 경계가 명확하므로 의미 변경 없이 상호 참조가 필요한 경우만 최소 수정한다. Issue의 열림·닫힘 상태와 담당자는 이번 작업에서 바꾸지 않는다.

### 저장소 문서

- `README.md`: 역할 표에 R6의 모드·계획 결정과 R7의 exact plan 실행 경계 추가
- `docs/governance/OWNERSHIP.md`: 역할 소유권과 교차 검토 관계 동기화
- `docs/review/ISSUE_TRACKER.md`: R6/R7 역할명을 결정/실행 기준으로 명확화
- `docs/review/ISSUE_CATALOG.md`: 각 역할의 생산자·소비자·금지 권한, R7의 오래된 선택 표현 수정
- `docs/architecture-v5/03-agent-roles-and-orchestration.md`: 정본 경계가 상위 Issue와 일치하는지 확인하고 모호한 표현만 보완
- `docs/architecture-v5/04-verification-and-dynamic-reproduction.md`: R6 계획 생산과 R7 실행 경계를 쉬운 문장으로 보완
- 관련 Wiki·Mermaid: 흐름이나 역할 주체가 다르게 보이는 경우에만 동기화

## 하위 Issue 영향

R7 하위 `#19–#22`는 이미 다음 구조와 대체로 일치한다.

- `#19`: 승인된 `ReproductionPlan` 실행·결과 반환
- `#20`: LIMITED/FULL 공통 환경과 FULL 최소 E2E 구성
- `#21`: Evidence·PoC·실패 상태 기록
- `#22`: Sandbox 격리·네트워크·자원 제한

따라서 하위 Issue의 전문 설계를 다시 쓰지 않는다. 상위 `#8`이 이 네 Issue를 정확히 묶도록 수정하고, 하위 Issue에서 역할 범위를 벗어난 새 문구가 발견되는 경우에만 해당 문장을 최소 수정한다.

## 검증 기준

1. GitHub `#1–#10`과 저장소 역할 문서를 대상으로 `결정`, `선택`, `생산`, `실행`, `판정`, `강제` 표현을 검색한다.
2. R6만 동적 재현 필요성·모드·계획을 결정하고, R7만 승인된 계획의 실행 log·동적 결과를 생산해야 한다.
3. R1은 Gate provenance가 없는 TRUE를 PROVIDED 또는 TRUE+TRUE 입력으로 사용하지 않아야 한다.
4. Technical `REVISE` 목적지는 모든 문서에서 같은 R6 owner여야 한다.
5. R8은 budget profile을 정의하지만 runtime enforcement나 domain 판정을 소유하지 않아야 한다.
6. 기존 Architecture 문서 검증 스크립트가 실패 0건이어야 한다.
7. Git diff 검사와 GitHub 본문 재조회에서 의도한 문구가 정확히 반영되어야 한다.

## 비범위

- Architecture v5의 Agent 구성 자체 변경
- 공통 계약 필드·enum 변경
- R7 하위 전문 설계의 구현
- Issue 상태·담당자·마일스톤 변경
- PR 병합 또는 상위 Issue 종료
