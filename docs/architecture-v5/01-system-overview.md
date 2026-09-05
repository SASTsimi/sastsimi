# 01. 시스템 개요

- **이 문서는 무엇을 설명하나요?** 저장소 입력부터 `ReportDraft`와 최종 결과 저장, Agent 자동화 종료까지 전체 22단계를 설명합니다.
- **누가 읽어야 하나요?** PM·아키텍처 담당과 모든 역할 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 단계 순서, 각 역할의 책임과 어디에서 작업이 끝나는지 확인합니다.

정확한 데이터 이름은 유지하며, 뜻은 [쉬운 용어집](../GLOSSARY.md)에서 확인할 수 있습니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목표와 경계

SASTSIMI v5는 저장소를 실행별 로컬 폴더에 clone하고 지정한 Git commit을 checkout한 뒤 정적 사실을 수집한다. 이후 LLM Agent가 가설 생성·검증·기술 검토·프로그램 정책 검토·보고서 초안을 단계적으로 수행한다. 정적 분석 도구와 LLM 출력 모두 단독으로 Finding이 되지 않는다. Agent 자동화는 `ReportDraft` 생성과 `AnalysisRunResult` 확정 뒤 끝나며, 그 이후 검토·수정·제출·공개는 시스템 밖에서 사람이 수행한다.

## 정본 22단계

| 단계 | 처리 | 주 산출물 또는 조건 |
|---:|---|---|
| 1 | 저장소 입력 | repository reference |
| 2 | 저장소 clone과 commit checkout | `CodeWorkspace` |
| 3 | AST parse와 SAST 도구 병렬 실행 | raw AST/SAST outputs, `ToolRunResult`, 규칙 기반 도구의 `RuleExecutionRecord` |
| 4 | 정적 사실 정규화 | exact 규칙 실행 기록을 연결한 `StaticFactBundle` |
| 5 | 초기 가설 생성 실행 | Orchestration이 Hypothesis work 시작 |
| 6 | 저비용 가설 생성 모델 호출 | constrained invocation |
| 7 | 출력 검증과 전역 등록 | schema-valid `HypothesisProposal(origin=INITIAL)` 또는 `INVALID_OUTPUT` |
| 8 | 가설별 Verification owner 할당 | `VulnerabilityHypothesis` + ACTIVE `VerificationAssignment` |
| 9 | Verification이 위치 기반 코드 문맥 조회 | `CodeContextRequest/Response` |
| 10 | 운영 Verification이 Pro/Con을 독립 병렬 실행 | supporting/counter evidence |
| 11 | 정적·Pro·Con 근거로 초기 판정 | initial `TRUE | FALSE | HOLD`; initial TRUE는 아직 최종 TRUE가 아님 |
| 12 | Verification이 목적을 적은 동적 재현 요청을 만들고, R7 Agent가 환경 요구사항·간단한 plan을 만든다. 외부 경계를 통과하면 Setup Automation이 Sandbox를 준비하고 Agent가 PoC candidate·command·관찰·재시도를 자율 수행하며 Session Manager가 결과를 확정한다. | `DynamicReproductionRequest`, `EnvironmentRequirements`, `ReproductionPlan`, `EnvironmentRecipe`, `AgentLog`, `DynamicReproductionResult` |
| 13 | 동적 결과를 반영해 최종 판정과 material claim 분리 | final TRUE에는 재현 성공을 가리키는 validated `poc_ref` 필수; optional `origin=VERIFICATION` proposal |
| 14 | 판정별 분기와 CWE 분류 | FALSE terminal / HOLD는 `required_primitive_candidates`가 하나 이상일 때만 inputs-only Primitive admission, 후보가 없으면 Primitive·Chaining 없음 / TRUE는 R5-01 `CWE_LABELING`이 exact Verification에 맞는 current `CWELabel` 생성 |
| 15 | TRUE 기술 근거 검토 | `TechnicalEvidenceReview` |
| 16 | Technical `REVISE` 보완 loop | same Verification owner, 새 Verification과 반드시 다시 평가한 새 CWELabel revision |
| 17 | Technical `ACCEPT` TRUE의 정책 수집·Rule Scope 검토와 체이닝 재료 사용 결정 | 독립 `testing_restriction_compliance`, `PrimitiveAdmissionDecision=ALLOW | DENY`; `ALLOW`일 때만 result가 있는 `Primitive` admission |
| 18 | direct·parent chain의 current ALLOW 결정을 고정한 Primitive 체이닝 | upstream result가 downstream input을 근거 있게 충족하고 `source_admission_refs`를 보존한 `ChainingResult` |
| 19 | 공식 규칙·범위·영향의 보고 조건 적용 | 금지 테스트 위반 외의 Rule Scope 판단은 Primitive 자격이 아니라 보고 가능성만 변경 |
| 20 | 체이닝·검증 중 새 주장 전역 등록 | `origin=CHAINING | VERIFICATION` proposal, 새 Verification 배정 |
| 21 | 조건 충족 시 보고서 초안 작성 | `ReportDraft` |
| 22 | 결과·디버깅 저장, 모든 가설 반복과 자동화 종료 | `AnalysisRunResult`, bounded parallel processing과 run records |

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
       on-demand context -> Verification owner -> Pro/Con -> initial verdict
                                                │ initial TRUE or dynamic evidence needed
                                                v
                         DynamicReproductionRequest -> R7 requirements/simple plan
                                                -> external boundary check
                                                -> autonomous PoC execution + AgentLog
                                                -> Session Manager final result
                                      │
                   ┌──────────────────┼────────────────────┐
                   v                  v                    v
                 FALSE               HOLD                 TRUE
              terminal      inputs, result null      R5-01 CWE_LABELING -> current CWELabel -> Technical Gate
                                  -> Chaining                │ REVISE -> same Verification
                                                             │ ACCEPT
                                                             v
                                            policy collection -> Rule Scope Impact Gate
                                                             │
                                           ┌─────────────────┴─────────────────┐
                                           v                                   v
                          PrimitiveAdmissionDecision                 report conditions
                              │ ALLOW       │ DENY                           │ pass
                              v             v                                v
                    result Primitive    no Primitive                      Reporter
                         -> Chaining

Verification material claim -> origin=VERIFICATION proposal ┐
Chaining match -> origin=CHAINING proposal ------------------┴-> trusted registration
                                                               -> Orchestration assigns Verification

Reporter -> ReportDraft -> AnalysisRunResult -> Agent automation end
```

Technical Evidence Gate의 `REVISE`는 같은 가설의 Verification owner에게 직접 돌아간다. Verification은 필요한 Context·Pro/Con·정적·동적 근거를 보완하고 새 `VerificationResult`를 확정한다. R5-01 `CWE_LABELING`은 CWE 값의 변경 여부와 관계없이 그 새 Verification에 맞는 새 `CWELabel` revision을 확정한 뒤 Gate를 다시 요청한다. Verification 또는 Chaining이 만든 새 material claim은 기존 결과에 붙여 확정하지 않고 trusted registration 뒤 8단계부터 전체 검증을 새로 거친다.

모든 final `TRUE`에는 현재 Verification generation에서 성공한 동적 재현과 validated PoC가 필요하다. validated PoC가 없는 `TRUE`는 저장하거나 Technical Gate로 전달하지 않는다. PoC 작성·환경 구성·실행이 실패했다면 취약점 판정을 `FALSE`나 `HOLD`로 바꾸지 않는다. 같은 R7 Agent session에서 해결할 수 있으면 현재 attempt를 계속하고, session 재시작은 같은 work의 새 `attempt_id`·`trigger=RETRY`, 외부 조건 해소 뒤 재개는 새 `attempt_id`·`trigger=RESUME`를 사용하며 복구 불가·한도 소진만 `FAILED`로 끝낸다.

## 구성 요소와 책임

Orchestration Agent는 전역 분석 계획, 가설 등록과 Verification 배정을 제안·조정하지만 가설 내부 다음 작업이나 enforcement authority를 갖지 않는다. 가설 내부 다음 작업은 Verification owner가 선택한다. 신뢰 경계 안의 비-LLM Runtime Validator가 schema, 호출 권한, 상태 전이, 예산, 병렬성, provider/session 정책, Gate 순서와 Reporter 호출 전제조건을 강제한다. Runtime Validator는 R7 `sandbox_profile_ref`와 exact R8 `DynamicReproductionLifecycleProfile` revision을 고정하고, 호출 전 잔여 시간·새 attempt 한도를 검사한다. Sandbox Controller는 R7 profile의 host·Docker·mount/namespace·secret·egress·workspace 격리와 CPU·RAM·disk·PID·요청 가능 최대 시간을 강제하며 내부 command allowlist를 운영하지 않는다. 모든 LLM 출력은 validation 전까지 비신뢰 입력이다.

| 구성 요소 | 책임 | 금지 경계 |
|---|---|---|
| Repository Loader | 실행별 `git clone`, `commit_id` checkout과 HEAD 확인 | 실행 중 작업공간 변경 또는 다른 commit 혼합 |
| AST/SAST runners | 구조·규칙 일치·경로 후보 수집, 규칙별 선택·실행·raw 탐지 수 기록 | 취약점 최종 판정 또는 미실행·확인 불가를 0건으로 변경 |
| Static Fact Normalizer | 공통 entity/location/path 표현 생성 | 증거가 없는 의미 확정 |
| Context Retrieval Service | 같은 `workspace_id`와 `commit_id`에서 제한된 추가 문맥 조회 | 작업공간 밖 무제한 repository dump |
| Orchestration Agent | proposal 검증·전역 가설 등록·Verification 배정·가설 간 병렬성 | 가설 내부 Pro/Con·dynamic·Gate·Chaining 결정 또는 Finding 공개 |
| Hypothesis Agent | schema-constrained 가설 후보 생성 | verdict·Finding·exploitability 확정 |
| Verification Agent | 가설 내부 Context·Pro/Con, 동적 재현 목적·목표·필요 환경을 담은 `DynamicReproductionRequest`, 최종 판정·REVISE·Gate·Chaining 흐름과 material child proposal | `EnvironmentRequirements`·`ReproductionPlan`·PoC·동적 결과 직접 생산, Sandbox 실행 또는 새 주장의 무검증 승격 |
| Pro/Con Agents | 독립적인 성립·반박 근거 조사 | 동일 session 공유 |
| R7 Agent | exact request에서 requirements·간단한 plan·PoC candidate·동적 근거 해석 생산 | R6 목적 변경, 외부 경계 우회 또는 최종 verdict 판단 |
| R7 Setup Automation | recipe·image·container 생성/재사용/재생성·환경 비교·cleanup 실제 수행 | Agent 판단, host/Docker 직접 권한 부여 또는 최종 verdict 판단 |
| Sandbox Controller | R7 `sandbox_profile_ref`의 host·Docker daemon/socket·mount/namespace·secret·egress·workspace 격리와 CPU·RAM·disk·PID·요청 가능 최대 시간 강제 | 내부 command allowlist 운영, R7 profile 값 결정, R8 잔여 예산·새 attempt 결정, 재현 전략·환경 의미·최종 verdict 변경 |
| Reproduction Session Manager | 실제 event를 append-only AgentLog로 저장하고 same-attempt validated PoC·동적 결과 확정 | Agent 호출·command·retry·cleanup 전략 결정 또는 다른 attempt 혼합 |
| Primitive Admission Runtime | exact Technical review·정책 수집·Rule Scope의 전용 테스트 제한 판정을 정해진 표로 변환해 `PrimitiveAdmissionDecision`과 허용된 Primitive 확정 | 정책 원문 해석, Gate 판정 변경 또는 `DENY` 결과의 Primitive 생성 |
| Primitive DB | required candidate가 있는 HOLD의 inputs-only Primitive와 current admission `ALLOW`인 Technical-accepted TRUE의 result Primitive exact revision 검색 | 작업 queue, candidate가 없는 HOLD나 Gate 전·admission `DENY` TRUE 저장 또는 자동 Finding 생성 |
| Chaining Agent | current ALLOW인 direct·parent material만 사용해 upstream Primitive `result`→downstream Primitive `input` matching과 chained proposal 생성 | 일반 research, dynamic, Gate, verdict, CWE, report 확정 |
| R5-01 CWE Labeling | final TRUE의 root cause·Evidence·taxonomy를 평가해 exact Verification에 묶인 current `CWELabel` 생성 | Verification verdict 변경, 과거 label 재사용 또는 Technical Gate 결과 생성 |
| Technical Evidence Gate | 기술적 연결성과 handoff 품질 검토 | Verification verdict 직접 변경 |
| Rule Scope Impact Gate | 공식 정책·scope·실질 impact·전달 권한과 금지 테스트 위반 여부를 독립 필드로 검토 | 공식 자료 없는 추정 승인 또는 Primitive 직접 저장·삭제 |
| Reporter Agent | 통과한 결과의 보고서 초안 작성 | 공개 또는 제출 |
| Runtime Validator | action의 schema·권한·순서·예산·실행 범위 검사 | 취약점·CWE·정책 의미 판단 |
| Result Stores | 결과·로그·PoC·오류·debug 저장 | secret와 불필요한 전체 코드 저장 |

사람의 검토·수정·제출·공개는 이 표의 Agent나 runtime 구성요소가 아니다. 사람은 자동화 종료 뒤 `AnalysisRunResult`와 current `ReportDraft`를 참고하며, 그 후속 과정은 현재 공통 action·상태 계약 밖에 있다.

## 상태 축은 분리한다

- 분석 판정: `TRUE | FALSE | HOLD`
- Technical Gate: `ACCEPT | REVISE | REJECT`
- Rule/Scope: `PASS | FAIL | UNCERTAIN`
- testing restriction: `PASS | FAIL | UNCERTAIN`
- Primitive admission: `ALLOW | DENY`
- impact: `SUFFICIENT | INSUFFICIENT | UNCERTAIN`
- report permission: `ALLOW | DENY`
- 보고서 생성: `ReportProcessState.status = NOT_REQUESTED | DRAFTED | FAILED`

한 축의 값으로 다른 축을 암묵적으로 추론하지 않는다. 예를 들어 기술적으로 `TRUE`여도 out-of-scope이거나 실질 영향이 부족하면 Reporter를 호출하지 않는다.

Agent와 실행 서비스는 부작용이 있는 일을 `ActionRequest`로 제안한다. 비-LLM Runtime Validator가 역할·schema·exact revision·상태·예산·일반 도구·경로·provider·두 Gate 순서와 보고 조건을 검사해 `ActionDecision=ALLOW | DENY`를 저장한다. `REQUEST_DYNAMIC_REPRO`는 Verification의 요청을 R7 work로 등록하는 허가이고, `RUN_SANDBOX`는 exact request·current requirements·current exact plan·`sandbox_profile_ref`·exact `DynamicReproductionLifecycleProfile` revision을 고정해 외부 격리 경계를 만들 허가다. plan이나 profile revision이 바뀌면 기존 `UNUSED` decision을 `EXPIRED`로 만들고 새 action을 요구한다. 어느 허가도 재현 성공을 뜻하지 않는다. Controller가 외부 경계를 통과시키면 Setup Automation과 R7 Agent가 격리 환경에서 재현하고 Session Manager가 실제 event와 결과를 확정한다. 이 검사는 환경 의미·취약점 판정이나 정책 해석을 대신하지 않는다.

## 병렬성과 종료 조건

- AST와 복수 SAST 실행은 tool별 `work_id`와 `attempt_id`로 병렬화할 수 있다. 정규화는 모든 기대 작업의 종료 상태를 확인하고, 일부 실패면 `DataGap`과 오류를 포함한 `PARTIAL` 여부를 명시한다.
- 서로 독립된 가설의 Verification은 가설별 예산 범위에서 병렬화할 수 있다. 한 가설의 실패가 다른 가설을 자동 취소하지 않는다.
- 운영(`PRODUCTION`)에서는 한 가설의 Pro/Con을 서로 다른 work와 NEW session으로 항상 병렬화하고 Verification이 두 결과를 확인해 합류한다. 예산 부족이나 실행 오류로 한쪽이 없으면 final verdict를 만들지 않고 work를 중단한다. `BASIC | CONDITIONAL_DEBATE`와 skip은 격리된 평가(`EVALUATION`)에서만 허용한다.
- 같은 가설의 `workspace_id`와 `commit_id`, final Verification, R5-01의 current CWELabel, Technical Gate, 정책 수집·Rule Scope Gate, Primitive admission과 Reporter 순서는 의존성을 지킨다. 새 Verification에는 값이 같아도 새 label revision과 그 revision을 가리키는 새 admission decision이 필요하다.
- 한 Verification generation에는 동적 재현 work를 하나만 만든다. 같은 R7 Agent session의 command·PoC·환경 조정은 현재 attempt를 유지한다. session 재시작만 같은 work의 새 `attempt_id`·`trigger=RETRY`, 외부 조건 해소 뒤 재개만 새 `attempt_id`·`trigger=RESUME`를 사용하며, Technical Gate의 `REVISE`로 새 generation이 시작된 경우에만 새 동적 재현 한도를 부여한다.
- 실행 상태는 `WorkExecutionState`가 관리하고 가설 판정·Gate 결과·보고서 상태와 분리한다. 같은 `dedupe_key` 요청은 한 `work_id`로만 반영한다.
- `COMMITTED` marker와 종료 상태 pointer가 같은 결과를 가리킨 뒤에만 다음 단계를 호출한다. `PREPARED`, 취소된 attempt, 오래된 revision과 늦은 결과는 다음 단계에서 읽지 않는다.
- 모든 초기·파생 가설이 종료 상태에 도달하고 atomic 저장·복구가 끝나면 Orchestration run을 닫는다.
- chaining 전용 깊이·개수·호출·조합·token 상한은 두지 않는다. R8의 전체 시간·비용·work 예산과 중복 match 조합 규칙으로 중단하며 이유를 기록한다. token 사용량은 관측하되 초과만으로 새 가설을 차단하지 않는다.

최종 분석 상태는 다음 의미를 갖는다.

| 상태 | 의미 |
|---|---|
| `COMPLETE` | 필요한 작업이 모두 확정 종료되고 최종 결과 묶음을 만들 수 있음 |
| `PARTIAL` | 신뢰할 수 있는 결과가 하나 이상 있지만 일부 도구·가설·보완 작업이 실패·제한되어 누락과 오류를 함께 저장함 |
| `FAILED` | clone/checkout 실패, workspace 기준 상실 또는 복구 실패로 신뢰 가능한 분석 결과를 만들 수 없음 |
| `CANCELLED` | 사용자가 전체 분석을 중단했고 새 작업 생성을 멈춤 |

어떤 실행 상태도 취약점 `FALSE`를 직접 만들지 않는다.
