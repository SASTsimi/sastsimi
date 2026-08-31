# 01. 시스템 개요

- **이 문서는 무엇을 설명하나요?** 저장소 입력부터 사람의 최종 공개 판단까지 전체 23단계를 설명합니다.
- **누가 읽어야 하나요?** PM·아키텍처 담당과 모든 역할 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 단계 순서, 각 역할의 책임과 어디에서 작업이 끝나는지 확인합니다.

정확한 데이터 이름은 유지하며, 뜻은 [쉬운 용어집](../GLOSSARY.md)에서 확인할 수 있습니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목표와 경계

SASTSIMI v5는 저장소를 실행별 로컬 폴더에 clone하고 지정한 Git commit을 checkout한 뒤 정적 사실을 수집한다. 이후 LLM Agent가 가설 생성·검증·기술 검토·프로그램 정책 검토·보고서 초안을 단계적으로 수행한다. 정적 분석 도구와 LLM 출력 모두 단독으로 Finding이 되지 않으며, 공개 결정은 사람에게 남는다.

## 정본 23단계

| 단계 | 처리 | 주 산출물 또는 조건 |
|---:|---|---|
| 1 | 저장소 입력 | repository reference |
| 2 | 저장소 clone과 commit checkout | `CodeWorkspace` |
| 3 | AST parse와 SAST 도구 병렬 실행 | raw AST/SAST outputs |
| 4 | 정적 사실 정규화 | `StaticFactBundle` |
| 5 | 초기 가설 생성 실행 | Orchestration이 Hypothesis work 시작 |
| 6 | 저비용 가설 생성 모델 호출 | constrained invocation |
| 7 | 출력 검증과 전역 등록 | schema-valid `HypothesisProposal(origin=INITIAL)` 또는 `INVALID_OUTPUT` |
| 8 | 가설별 Verification owner 할당 | `VulnerabilityHypothesis` + ACTIVE `VerificationAssignment` |
| 9 | Verification이 위치 기반 코드 문맥 조회 | `CodeContextRequest/Response` |
| 10 | 운영 Verification이 Pro/Con을 독립 병렬 실행 | supporting/counter evidence |
| 11 | 초기 판정 | `TRUE | FALSE | HOLD` |
| 12 | Verification이 모드·`ReproductionPlan`을 결정하고 runtime 허가 뒤 R7 Sandbox가 exact plan 실행 | `COMMITTED ReproductionPlan`, `SandboxStepLog`, `DynamicReproductionResult`, PoC evidence |
| 13 | 최종 판정과 material claim 분리 | final `VerificationResult`, optional `origin=VERIFICATION` proposal |
| 14 | 판정별 분기 | FALSE terminal / HOLD REQUIRED 즉시 admission / TRUE CWE 진행 |
| 15 | TRUE 기술 근거 검토 | `TechnicalEvidenceReview` |
| 16 | Technical `REVISE` 보완 loop | same Verification, 새 Verification/CWE revision |
| 17 | Technical `ACCEPT` TRUE의 공식 규칙·범위·영향 검토 | `RuleScopeImpactReview` |
| 18 | Gate-qualified TRUE PROVIDED admission | exact Gate provenance를 가진 `Primitive` |
| 19 | current HOLD 또는 Gate-qualified TRUE 체이닝 | `ChainingResult`; TRUE+TRUE는 앞 능력과 뒤 TRUE의 exact 선행 조건을 방향성 있게 연결 |
| 20 | 체이닝·검증 중 새 주장 전역 등록 | `origin=CHAINING | VERIFICATION` proposal, 새 Verification 배정 |
| 21 | 조건 충족 시 보고서 초안 작성 | `ReportDraft` |
| 22 | 결과·디버깅 저장과 모든 가설 반복 | bounded parallel processing과 run records |
| 23 | 사람의 최종 검토 | disclose, revise, withhold, or more validation |

## 주요 실행 흐름

```text
Repository Loader -> CodeWorkspace
  ├─ AST Parser ─┐
  └─ SAST Tools ─┴─> StaticFactBundle
                           │
                           v
Orchestration -> Hypothesis Agent -> trusted validation and registration
                                                        │ assign only
                                                        v
       on-demand context -> Verification owner -> Pro/Con -> optional dynamic
                                      │
                   ┌──────────────────┼────────────────────┐
                   v                  v                    v
                 FALSE               HOLD                 TRUE
              terminal      REQUIRED -> Chaining     CWE -> Technical Gate
                                                         │ REVISE
                                                         └-> same Verification
                                                         │ ACCEPT
                                                         v
                                                  Rule Scope Impact Gate
                                                         │ normal pass
                                                         v
                                                PROVIDED -> Chaining

Verification material claim -> origin=VERIFICATION proposal ┐
Chaining match -> origin=CHAINING proposal ------------------┴-> trusted registration
                                                               -> Orchestration assigns Verification

Gate-qualified result -> Reporter -> Result Stores -> Human
```

Technical Evidence Gate의 `REVISE`는 같은 가설의 Verification owner에게 직접 돌아간다. Verification은 필요한 Context·Pro/Con·정적·동적 근거를 보완하고 새 `VerificationResult` 및 필요한 `CWELabel` revision으로 Gate를 다시 요청한다. Verification 또는 Chaining이 만든 새 material claim은 기존 결과에 붙여 확정하지 않고 trusted registration 뒤 8단계부터 전체 검증을 새로 거친다.

## 구성 요소와 책임

Orchestration Agent는 전역 분석 계획, 가설 등록과 Verification 배정을 제안·조정하지만 가설 내부 다음 작업이나 enforcement authority를 갖지 않는다. 가설 내부 다음 작업은 Verification owner가 선택한다. 신뢰 경계 안의 비-LLM Runtime Validator가 schema, 호출 권한, 상태 전이, 예산, 병렬성, provider/session 정책, Gate 순서와 Reporter 호출 전제조건을 강제한다. Sandbox의 image·command·file·network·resource·cleanup 세부 정책은 Sandbox Controller가 한곳에서 검사한다. 모든 LLM 출력은 validation 전까지 비신뢰 입력이다.

| 구성 요소 | 책임 | 금지 경계 |
|---|---|---|
| Repository Loader | 실행별 `git clone`, `commit_id` checkout과 HEAD 확인 | 실행 중 작업공간 변경 또는 다른 commit 혼합 |
| AST/SAST runners | 구조·규칙 일치·경로 후보 수집 | 취약점 최종 판정 |
| Static Fact Normalizer | 공통 entity/location/path 표현 생성 | 증거가 없는 의미 확정 |
| Context Retrieval Service | 같은 `workspace_id`와 `commit_id`에서 제한된 추가 문맥 조회 | 작업공간 밖 무제한 repository dump |
| Orchestration Agent | proposal 검증·전역 가설 등록·Verification 배정·가설 간 병렬성 | 가설 내부 Pro/Con·dynamic·Gate·Chaining 결정 또는 Finding 공개 |
| Hypothesis Agent | schema-constrained 가설 후보 생성 | verdict·Finding·exploitability 확정 |
| Verification Agent | 가설 내부 Context·Pro/Con, 동적 모드·`ReproductionPlan`, 판정·REVISE·Gate·Chaining 흐름과 material child proposal | Sandbox 직접 실행·동적 결과 생산, runtime 검사 우회 또는 새 주장의 무검증 승격 |
| Pro/Con Agents | 독립적인 성립·반박 근거 조사 | 동일 session 공유 |
| Sandbox Controller | Verification이 만든 exact `ReproductionPlan`의 image·command·file·network·resource·cleanup 정책 검사와 실행 환경 통제 | 동적 모드·계획·최종 verdict 변경 또는 정책 미검사 실행 |
| Sandbox Runner | Controller가 승인한 exact 계획을 Docker 안에서 실행하고 log·동적 결과·PoC 생산 | 정책 변경, 계획 밖 명령 실행 또는 최종 verdict 판단 |
| Primitive DB | HOLD REQUIRED와 Gate-qualified TRUE PROVIDED의 ACTIVE exact revision 검색 | 작업 queue, Gate 전 TRUE admission 또는 자동 Finding 생성 |
| Chaining Agent | TRUE+HOLD·TRUE+TRUE Primitive matching과 chained proposal | 일반 research, dynamic, Gate, verdict, CWE, report 확정 |
| Technical Evidence Gate | 기술적 연결성과 handoff 품질 검토 | Verification verdict 직접 변경 |
| Rule Scope Impact Gate | 공식 정책·scope·실질 impact·전달 권한 검토 | 공식 자료 없는 추정 승인 |
| Reporter Agent | 통과한 결과의 보고서 초안 작성 | 공개 또는 제출 |
| Runtime Validator | action의 schema·권한·순서·예산·실행 범위 검사 | 취약점·CWE·정책 의미 판단 |
| Result Stores | 결과·로그·PoC·오류·debug 저장 | secret와 불필요한 전체 코드 저장 |
| Human Reviewer | 최종 수정·보류·공개 결정 | — |

## 상태 축은 분리한다

- 분석 판정: `TRUE | FALSE | HOLD`
- Technical Gate: `ACCEPT | REVISE | REJECT`
- Rule/Scope: `PASS | FAIL | UNCERTAIN`
- impact: `SUFFICIENT | INSUFFICIENT | UNCERTAIN`
- report permission: `ALLOW | DENY`
- 보고서 생성: `ReportProcessState.status = NOT_REQUESTED | DRAFTED | FAILED`
- 사람 검토: `HumanReviewDecision.decision = DISCLOSE | REVISE | WITHHOLD | NEED_MORE_VALIDATION`

한 축의 값으로 다른 축을 암묵적으로 추론하지 않는다. 예를 들어 기술적으로 `TRUE`여도 out-of-scope이거나 실질 영향이 부족하면 Reporter를 호출하지 않는다.

Agent와 실행 서비스는 부작용이 있는 일을 `ActionRequest`로 제안한다. 비-LLM Runtime Validator가 역할·schema·exact revision·상태·예산·일반 도구·경로·provider·두 Gate 순서·보고·공개 조건을 검사해 `ActionDecision=ALLOW | DENY`를 저장한다. `RUN_SANDBOX`의 ALLOW는 Sandbox Controller 호출을 허가한다는 뜻이며 Docker 세부 정책 통과나 재현 성공을 뜻하지 않는다. Controller가 Sandbox 정책을 통과시킨 exact 계획만 Runner가 실행한다. 이 검사는 취약점 판정이나 정책 해석을 대신하지 않는다.

## 병렬성과 종료 조건

- AST와 복수 SAST 실행은 tool별 `work_id`와 `attempt_id`로 병렬화할 수 있다. 정규화는 모든 기대 작업의 종료 상태를 확인하고, 일부 실패면 `DataGap`과 오류를 포함한 `PARTIAL` 여부를 명시한다.
- 서로 독립된 가설의 Verification은 가설별 예산 범위에서 병렬화할 수 있다. 한 가설의 실패가 다른 가설을 자동 취소하지 않는다.
- 운영(`PRODUCTION`)에서는 한 가설의 Pro/Con을 서로 다른 work와 NEW session으로 항상 병렬화하고 Verification이 두 결과를 확인해 합류한다. 예산 부족이나 실행 오류로 한쪽이 없으면 final verdict를 만들지 않고 work를 중단한다. `BASIC | CONDITIONAL_DEBATE`와 skip은 격리된 평가(`EVALUATION`)에서만 허용한다.
- 같은 가설의 `workspace_id`와 `commit_id`, final Verification·CWELabel, Technical Gate, Rule Scope Gate와 Reporter 순서는 의존성을 지킨다.
- 실행 상태는 `WorkExecutionState`가 관리하고 가설 판정·Gate 결과·보고서·사람 검토 상태와 분리한다. 같은 `dedupe_key` 요청은 한 `work_id`로만 반영한다.
- `COMMITTED` marker와 종료 상태 pointer가 같은 결과를 가리킨 뒤에만 다음 단계를 호출한다. `PREPARED`, 취소된 attempt, 오래된 revision과 늦은 결과는 다음 단계에서 읽지 않는다.
- 모든 초기·파생 가설이 종료 상태에 도달하고 atomic 저장·복구가 끝나면 Orchestration run을 닫는다.
- chaining은 깊이·개수·토큰·시간·중복 fingerprint 제한을 넘으면 새 가설을 만들지 않고 중단 이유를 기록한다.

최종 분석 상태는 다음 의미를 갖는다.

| 상태 | 의미 |
|---|---|
| `COMPLETE` | 필요한 작업이 모두 확정 종료되고 최종 결과 묶음을 만들 수 있음 |
| `PARTIAL` | 신뢰할 수 있는 결과가 하나 이상 있지만 일부 도구·가설·보완 작업이 실패·제한되어 누락과 오류를 함께 저장함 |
| `FAILED` | clone/checkout 실패, workspace 기준 상실 또는 복구 실패로 신뢰 가능한 분석 결과를 만들 수 없음 |
| `CANCELLED` | 사용자가 전체 분석을 중단했고 새 작업 생성을 멈춤 |

어떤 실행 상태도 취약점 `FALSE`를 직접 만들지 않는다.
