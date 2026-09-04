# 03. Agent 역할과 오케스트레이션

- **이 문서는 무엇을 설명하나요?** 각 LLM Agent의 역할과 여러 Agent의 실행 순서를 조정하는 방법을 설명합니다.
- **누가 읽어야 하나요?** LLM 탐색·체이닝, 검증, PM과 통합 개발 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 각 Agent가 만들 수 있는 결과와 가질 수 없는 권한, 호출·실패 처리 순서를 확인합니다.

`Orchestration`은 여러 Agent의 호출 순서와 상태를 조정하는 기능입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## Orchestration Agent

Orchestration Agent는 분석 전체와 가설 목록을 관리하는 global control-plane이다. 한 가설에 대한 책임은 proposal 검증·전역 등록·Verification 배정에서 끝난다. 배정 뒤 Context, Pro/Con, 동적 재현, 판정, Gate `REVISE`와 Chaining handoff를 선택하는 주체는 그 가설의 Verification owner다.

```text
HypothesisProposal validation
-> runtime narrows duplicate candidates
-> Hypothesis Agent duplicate review when candidates exist
-> VulnerabilityHypothesis registration
-> Verification Agent assignment
-> hypothesis-local control transfers to Verification
```

Orchestration Agent의 주요 책임은 다음과 같다.

- `analysis_id`와 전역 분석 계획 관리
- INITIAL·VERIFICATION·CHAINING proposal의 schema/semantic validation 요청
- 검증된 proposal의 중복 후보 검색과 필요 시 LLM 중복 검토 요청
- 중복이 아닌 proposal의 `hypothesis_id` 등록
- `parent_hypothesis_ids`와 Chaining proposal의 `source_primitive_match_id` 관계 검증 요청
- 독립 가설의 병렬 배정과 hypothesis별 resource budget 배분
- 등록된 각 가설에 정확히 한 Verification owner를 배정하고 trusted runtime이 ACTIVE `VerificationAssignment`로 저장
- 전체 가설의 진행 상태·종료 상태·오류 집계
- R8 전체 시간·비용·work 예산과 체이닝 fingerprint 중복·ancestor 재사용 제외 적용 요청. token 사용량은 관측하지만 상한으로 차단하지 않음
- 실패와 `INVALID_OUTPUT`을 숨기지 않고 분석 결과에 보존

Orchestration Agent는 한 가설 안에서 Pro/Con·동적 재현·두 Gate·Reporter·Chaining의 호출 여부나 Technical `REVISE` 목적지를 결정하지 않는다. 논리 작업의 상태, `work_id`·`dedupe_key`, 활성 attempt, compare-and-set, atomic output binding과 실제 action 허가는 신뢰 경계 안의 비-LLM runtime이 관리한다.

## 저비용 Hypothesis Agent

Hypothesis Agent에는 비용 효율적인 모델을 배치할 수 있지만, 모델 가격과 무관하게 출력 권한은 제한한다. 입력은 `StaticFactBundle`의 요약·reference와 필요한 최소 fragment다. 출력은 자유 형식 분석문이 아니라 `HypothesisProposal[]`이다.

각 proposal은 반드시 다음을 포함한다.

- `proposal_state: HYPOTHESIS_ONLY`
- `assertion_mode: NON_FINAL`
- vulnerability type candidate
- 관련 entity와 실제 location
- suspected source → propagation → sink 또는 권한 흐름
- observed facts, exact 근거가 연결된 restrictions와 assumptions의 분리
- `question_id`가 붙은 구체적인 falsification questions
- `validation_checks`(반드시 확인할 검증 항목과 고유 ID)

세 갈래는 관측 여부와 가설이 그것에 의존하는지로 나눈다. 구분 기준은 `08-lightweight-data-contracts.md`에 있다.

가설 생성 work는 `STATIC_NORMALIZE`가 최종 상태에 도달한 뒤에만 시작한다. 최종 상태가 `PARTIAL`이면 그 bundle로 진행하고 빠진 범위는 `gaps`로 전달된다.

등록된 가설은 전수 검증한다. 점수로 미리 선별하거나 검증 순서를 매기지 않는다. Hypothesis Agent는 `confirmed`, `verified`, `finding`, `exploitable`과 같은 확정 주장을 출력할 권한이 없다.

## 출력 검증과 실패 처리

1. 구조 parser가 JSON/YAML syntax와 schema를 검증한다.
2. enum, 필수 field, `workspace_id`·`commit_id`·`CodeLocation`, restriction 근거 reference, 관측 사실과 restriction 근거의 비중복, 반증 질문, 검증 항목과 금지 assertion을 검사한다. 유효한 proposal의 각 반증 질문에는 전역 `question_id`, 각 검증 항목에는 전역 `validation_id`를 붙인다. 플레이북 질문 ID는 이 단계에서 만들지 않고 Verification work 등록 시 exact `PlaybookApplication`에 별도로 발급한다.
3. 실패하면 원래 의미를 바꾸지 않는 범위에서 제한 횟수의 repair prompt를 새 invocation으로 실행한다.
4. 재시도 후에도 유효하지 않으면 해당 호출을 `INVALID_OUTPUT`으로 저장한다.
5. invalid proposal은 Verification Agent에 전달하지 않는다.

원문·validation error·repair 횟수·최종 parsed output reference는 `LLMInvocationLog`로 추적한다. 코드나 자격 증명의 불필요한 원문 저장은 피한다.

## 가설 lifecycle

```text
ProposalProcessState: PROPOSED -> schema and semantic validation
                      validation failure -> INVALID_OUTPUT
                      validation success -> narrow candidates
                          no candidates -> SCHEMA_VALID -> register new hypothesis_id
                          candidates -> LLM duplicate review
                              UNIQUE | UNCERTAIN -> SCHEMA_VALID -> register new hypothesis_id
                              DUPLICATE with exact target -> DUPLICATE -> stop without a new hypothesis_id
                              call/format/target error -> SCHEMA_VALID -> preserve error and register fail-open
HypothesisProcessState: REGISTERED -> ASSIGNED -> VERIFYING
                                               -> TERMINAL (final verdict)
                                               -> FAILED (no final verdict)
Technical REVISE: TERMINAL -> same assignment + new VERIFICATION work -> VERIFYING
VerificationResult.verdict -> TRUE | FALSE | HOLD
HOLD -> Primitive inputs with result null -> Chaining eligible
TRUE -> Technical ACCEPT -> Primitive with result -> Chaining eligible
Technical ACCEPT -> Rule Scope -> report eligibility only
Verification material claim -> PROPOSED child hypothesis origin VERIFICATION
Chaining match -> PROPOSED child hypothesis origin CHAINING
```

가설 중복 판정은 LLM이 한다. 정적 정규화로 같은 가설인지 결정하지 않으며, trusted runtime은 같은 analysis·workspace·commit의 등록 가설만 비교 후보로 삼고 `symbol_id`, `CodeLocation` 범위와 `relation_id`로 후보를 좁힌다. 후보가 없으면 LLM 호출 없이 등록한다. 후보가 있으면 exact proposal과 후보 가설 revision을 HYPOTHESIS `CALL_LLM` 입력에 고정하고 `HypothesisDuplicateReview`를 저장한다. `DUPLICATE`는 후보 목록의 exact 가설을 지목할 때만 새 등록을 막는다. `UNIQUE | UNCERTAIN`은 등록한다. 호출 실패·형식 오류·후보 밖 대상을 가리킨 판정도 기록을 보존하고 fail-open 등록하여 취약점 탐지를 누락하지 않는다.

`ProposalProcessState.status`는 `hypothesis_id`를 발급하기 전의 출력 검증·중복 판정 상태를 기록한다. `SCHEMA_VALID`에는 `NO_CANDIDATES | UNIQUE | UNCERTAIN | CHECK_FAILED | INVALID_DUPLICATE_TARGET` 중 실제 등록 이유를 남긴다. 등록하면 새 `hypothesis_id`와 별도 `HypothesisProcessState`를 만들고 같은 `proposal_ref`로 연결한다. `DUPLICATE`이면 exact review와 기존 가설 reference를 남기고 새 `HypothesisProcessState`를 만들지 않는다. 등록 뒤에는 `HypothesisProcessState.status`가 처리 진행 상태를 기록하고 `VerificationResult.verdict`가 기술 판정을 기록한다. `TERMINAL`은 final `TRUE | FALSE | HOLD`가 연결된 정상 종료다. 반면 검증을 끝내지 못하고 재시도도 불가능하면 `FAILED`로 끝나며 final verdict를 만들지 않는다. retry 가능한 work가 `BLOCKED`일 때는 가설을 `VERIFYING`으로 유지한다. parent 가설의 결과와 child 가설은 독립된 lifecycle을 갖고 child 결과가 parent verdict를 바꾸지 않는다.

Verification-origin과 Chaining-origin proposal은 직접 부모 ID를 보존하고 trusted validation을 통과할 때만 새 `hypothesis_id`를 받는다. INITIAL·VERIFICATION proposal의 `source_primitive_match_id`는 `null`이고, CHAINING proposal은 자신을 만든 COMMITTED match candidate ID를 가리킨다. 계보 길이는 parent와 match 링크를 따라 계산하며 별도 depth 값을 저장하지 않는다. 새 endpoint·sink·권한 경계·공격 단계·독립 impact는 Verification이 `origin=VERIFICATION` proposal로 분리한다. TRUE+HOLD와 TRUE+TRUE는 upstream result가 downstream input을 코드 근거로 충족할 때만 Chaining Agent가 `origin=CHAINING` proposal로 만든다. 어느 경로도 기존 가설을 수정하거나 child를 자동 TRUE로 만들지 않는다. child가 FALSE여도 부모 판정은 바뀌지 않는다.

## 공통 실행 상태와 전문 결과의 분리

모든 실행 가능한 단계는 `WorkExecutionState`로 관리한다. 이 상태는 작업이 준비·실행·종료되었는지를 나타낼 뿐 전문 판정을 대신하지 않는다.

| 실행 작업 | 실행 종료 뒤 읽어야 하는 전문 결과 |
|---|---|
| Verification `SUCCEEDED` | `VerificationResult.verdict = TRUE | FALSE | HOLD` |
| Technical Gate `SUCCEEDED` | `TechnicalEvidenceReview.status = ACCEPT | REVISE | REJECT` |
| Rule Scope Gate `SUCCEEDED` | `RuleScopeImpactReview.review_status`와 `report_permission` |
| Reporter `SUCCEEDED` | 내부 `ReportDraft`; 마지막 Agent 산출물 |

`PENDING -> READY -> RUNNING` 뒤에는 `SUCCEEDED | PARTIAL | FAILED | CANCELLED`로 끝나거나, 재시도·인증·승인·입력·예산 조건을 기다릴 때 `BLOCKED`로 이동한다. `BLOCKED`는 조건을 충족하면 `READY`가 되지만 종료 상태는 되돌리지 않는다. 일반적인 재시도 가능 attempt 실패는 attempt 자체를 `FAILED`로 보존하고 work를 `BLOCKED`로 둔다. 단, `DYNAMIC_REPRO`가 외부 조건을 기다리지 않고 R7 자율 retry를 즉시 수행할 수 있으면 같은 work를 `RUNNING -> READY -> RUNNING`으로 넘겨 새 attempt를 시작한다. 어느 경우에도 이전 실패를 삭제하지 않는다.

상태 변경을 실제로 승인·저장하는 주체는 Orchestration Agent가 아니라 신뢰 경계 안의 runtime이다. 작업 모듈은 결과와 다음 상태를 요청하고 runtime이 schema, 현재 `state_version`, 활성 attempt, 입력 hash, workspace·commit·가설, 예산과 권한을 검사한 뒤 `StateTransition`을 저장한다.

## 역할별 권한 경계

| 역할 | 제안 | 직접 판단 | 검토 | 프로그램 강제 | 사람만 결정 |
|---|---|---|---|---|---|
| Orchestration Agent | 전역 분석 계획·proposal 등록·가설 배정·가설 간 병렬화 | 없음 | 전체 진행 상태 요약 | 없음 | 없음 |
| Hypothesis Agent | 취약점 가설 | 없음 | static 사실을 입력으로 읽음 | 없음 | 없음 |
| Playbook Registry Runtime | R6가 작성한 플레이북과 사람이 승인한 적용 정책을 versioned record로 등록하고 Verification work별 `PlaybookApplication` 생성 | 없음 | exact proposal의 유형 후보·policy·playbook revision | schema·선택·질문 ID·current pointer 검사 | 운영 지원 유형과 적용 mapping 승인 |
| Pro·Con Agent | 찬성·반대 근거 | 없음 | 자기 역할의 근거 | 없음 | 없음 |
| Verification Agent | Context·Pro/Con, 목적·목표·필요 환경을 담은 `DynamicReproductionRequest`, 두 Gate·Reporter·Chaining 요청, material child proposal | `TRUE | FALSE | HOLD` | static·Pro·Con·COMMITTED dynamic 근거와 Gate 보완 요청 | 없음 | 없음 |
| R7 Agent | `EnvironmentRequirements`·간단한 `ReproductionPlan`·PoC candidate·동적 근거 해석 | 없음 | R6 요청과 Sandbox 안의 실제 관측 | 없음 | 없음 |
| R7 Setup Automation | image build, container 생성·재사용·재생성, 환경 비교와 cleanup 실행 | 없음 | recipe, 실제 환경과 Health Check | host·Docker 권한은 없음 | 없음 |
| Sandbox Controller | 없음 | 없음 | host·Docker daemon/socket·mount/namespace·secret·egress·workspace·R8 resource/lifecycle 외부 경계 | 정책 위반 Sandbox 시작 차단 | 없음 |
| Reproduction Session Manager | 없음 | 없음 | runtime/tool/lifecycle event와 같은 attempt의 plan·recipe·환경·PoC provenance | append-only `AgentLog`, validated PoC와 `DynamicReproductionResult` 확정 | 없음 |
| R5-01 CWE Labeling | CWE 후보와 근거 | current `CWELabel` revision 생성 | exact final TRUE Verification | 없음 | 없음 |
| Chaining Agent | upstream Primitive `result`→downstream Primitive `input` match와 chained proposal | 없음 | exact Primitive, Verification·Technical provenance와 코드 근거 | 없음 | 없음 |
| Technical Evidence Gate Agent | 구체적인 보완 요청 | 없음 | verdict·근거·코드 흐름·CWE | 없음 | 없음 |
| Rule Scope Impact Gate Agent | 정책 누락·보완 사유 | `PASS | FAIL | UNCERTAIN`, `ALLOW | DENY` | 공식 정책·scope·impact | 없음 | 없음 |
| Reporter Agent | 내부 보고서 문장·구성 | 없음 | 통과한 결과와 두 Gate | 없음 | 없음 |
| Runtime Validator | 허용 가능한 대체 action 안내 | 없음 | 실행 전제와 exact reference | action 허용·차단 | 없음 |

Orchestration Agent는 전역 등록과 배정을 제안하지만 hypothesis-local 호출 순서, 기술 verdict, CWE, 두 Gate 결과, 공식 정책 의미, 보고 가능 여부와 공개 여부를 확정하지 않는다. R6 담당은 플레이북 내용과 유형 mapping 후보를 작성할 수 있지만 운영 지원 목록을 활성화하지 않는다. Playbook Registry Runtime은 사람 승인 뒤 policy를 등록하고 exact proposal의 `vulnerability_type_candidates`를 읽어 결정 규칙대로 playbook과 질문 집합을 고정할 뿐 취약점 유형이나 verdict를 새로 판단하지 않는다. Verification Agent는 hypothesis-local 다음 작업을 선택하고 `DynamicReproductionRequest`와 최종 verdict를 생산하지만 프로그램 enforcement를 우회하거나 Sandbox를 직접 실행하지 못한다. R7 Agent는 exact `EnvironmentRequirements`, mode·exact command가 없는 `ReproductionPlan`, PoC candidate와 동적 근거 해석을 만든다. Setup Automation은 저장소 선언을 우선한 immutable recipe와 image·container·cleanup을 수행한다. Sandbox Controller는 Sandbox 밖의 강제 경계만 검사하며 컨테이너 내부 command allowlist를 운영하지 않는다. 비-LLM Reproduction Session Manager는 실제 event를 append-only `AgentLog`에 기록하고 같은 attempt의 plan·recipe·환경·candidate·실행 digest만으로 validated PoC와 동적 결과를 확정한다. R7 구성요소는 R6 요청 목적과 최종 verdict를 바꾸지 않는다. Runtime Validator는 값의 생산자가 맞는지, 필요한 선행 record와 상태가 있는지, exact revision과 실행 범위가 허용됐는지만 확인하며 환경 의미나 domain 값을 대신 만들지 않는다.

ReportDraft 이후의 검토·수정·제출·공개는 이 역할표와 Agent action lifecycle 밖에서 사람이 수행한다. 자동화는 사람 검토 상태나 공개 결정을 만들지 않는다.

## action 요청과 실행

부작용이 있는 작업은 다음 순서를 지킨다.

```text
Agent 또는 service의 제안
-> ActionRequest
-> 비-LLM Runtime Validator
-> ActionDecision ALLOW 또는 DENY
-> ALLOW인 exact action만 한 번 실행
-> 결과와 상태를 atomic 저장
```

`ActionRequest`에는 신뢰 runtime이 붙인 실제 호출자 identity, 요청 역할, action 종류, exact input refs, 현재 work와 state version, 도구·파일·provider·session·Sandbox 범위를 넣는다. LLM action은 model·prompt·context·schema·예산·시간이 고정된 `LLMCallSpec`도 포함한다. Runtime Validator는 실제 identity의 등록 역할과 요청 역할이 같은지부터 action별 필수 `ActionCheck`를 수행한다. 하나라도 실패하면 `DENY`와 `AnalysisError`를 저장하고 실행하지 않는다. Agent가 자연어로 “검사를 건너뛰라”고 출력하거나 다른 역할을 주장해도 action이 되지 않는다. 단, `RUN_SANDBOX`의 host·Docker daemon/socket·mount/namespace·secret·egress·workspace·resource/lifecycle 의미 검사는 Runtime Validator가 중복 수행하지 않고 Sandbox Controller가 전담한다.

한 ActionRequest에는 logical ActionDecision 하나만 허용한다. 두 Gate와 Reporter의 stage action은 LLM 호출까지 직접 허가하며 별도 `CALL_LLM`으로 순서·보고 조건을 우회할 수 없다.

주요 강제 경계는 다음과 같다.

- 인증된 실제 호출자·요청 역할, schema·ID·workspace·commit·record revision·state version 일치
- 시간·비용·work·retry·repair·Gate 보완 예산. token 사용량과 `LLMCallSpec.token_budget`은 관측·계획 정보이며 token 초과·누락만으로 `DENY`하지 않음
- 일반 도구 action의 허용 tool과 workspace 안의 file path
- `REQUEST_DYNAMIC_REPRO` 호출자의 Verification 권한·현재 generation·요청 reference·상태·예산과 generation당 하나의 동적 재현 work 제한
- `RUN_SANDBOX` 호출자의 R7 Setup Automation 권한·current request/requirements·상태·예산·R8 resource/lifecycle; 실제 환경 값은 R7이 비교하고 외부 격리 경계는 Sandbox Controller가 검사
- provider/model/profile, NEW/RESUME/AUTO와 explicit failover
- Verification work 등록 시 exact hypothesis→proposal, `PlaybookPolicy`, 선택된 `VerificationPlaybook`과 `PlaybookApplication`을 함께 고정하고, 직접 검증·Pro·Con·최종 합성이 같은 application 질문 집합을 사용하는지 검사
- final `TRUE` Verification 뒤 R5-01이 만든 current `CWELabel`과의 exact pair로 Technical Gate, 그 뒤 Rule Scope Gate라는 순서. `FALSE | HOLD`와 실패 가설은 CWE work·Gate 입력이 아님
- final `TRUE` 저장과 Technical Gate 요청에는 현재 generation의 `DynamicReproductionRequest`, `SUCCEEDED + SUPPORTED` 결과와 validated `poc_ref`가 모두 필요함
- 모든 report 조건을 통과한 뒤 Reporter 호출
- Reporter 저장 전 redaction 성공과 restriction·limitation 보존
- ReportDraft 저장 뒤 `AnalysisRunResult`를 확정하고 Agent 자동화 종료

Runtime Validator는 취약점 진위, CWE 적절성, 정책 내용과 보고서 품질을 평가하지 않는다. 그것은 Verification, 두 LLM Gate와 Reporter의 역할이다.

`REQUEST_DYNAMIC_REPRO`의 `ActionDecision=ALLOW`는 현재 Verification generation에 하나의 `DYNAMIC_REPRO` work를 등록한다. `RUN_SANDBOX`의 `ActionDecision=ALLOW`는 current request·requirements·profile·resource/lifecycle 범위에서 외부 격리 경계를 만들 권한만 부여한다. Sandbox Controller는 host와 Docker 경계를 검사하고, Setup Automation은 통과한 범위에서 image·container·cleanup을 수행한다. R7 Agent가 Sandbox 안에서 command·PoC·관찰과 재시도를 자율적으로 선택하며, Session Manager가 실제 event를 기록한다. 실행 뒤 `SAVE_RESULT`는 plan·recipe·실제 환경·AgentLog·candidate·validated PoC가 같은 attempt인지 다시 대조한다. 마지막 대조는 환경 의미나 취약점 판단을 반복하는 검사가 아니라 결과 무결성 확인이다.

## 병렬 실행과 결과 합류

| 병렬 구간 | 분리 단위 | 합류 조건 | 일부 실패 처리 |
|---|---|---|---|
| AST와 SAST | tool별 `work_id` | 기대한 tool의 종료 상태와 output/error 확인 | 하나 이상의 신뢰 결과가 있으면 `DataGap`을 포함한 `PARTIAL` 정규화 가능 |
| 가설 검증 | `hypothesis_id`별 work | 각 가설은 자기 final Verification까지 독립 | 한 가설 오류가 다른 가설을 취소하지 않으며 분석은 `PARTIAL` 가능 |
<<<<<<< HEAD
| Pro와 Con | 같은 가설의 역할별 child work·NEW session | 운영은 같은 hypothesis·policy·playbook·application 질문 집합의 exact Pro·Con 결과를 모두 확인; 평가 생략은 명시된 mode와 skip reason 확인 | 필수 결과 누락·application 불일치 시 final 판정을 만들지 않고 부모 Verification을 대기 또는 실패 처리 |
| chaining 후보 | child proposal별 work | exact match lineage, fingerprint 중복·ancestor cycle·R8 전체 예산 검사를 통과한 proposal만 등록 | 거절 사유를 저장하고 부모 verdict 유지 |
=======
| Pro와 Con | 같은 가설의 역할별 child work·NEW session | 운영은 같은 입력의 exact Pro·Con 결과를 모두 확인; 평가 생략은 명시된 mode와 skip reason 확인 | 필수 결과 누락 시 final 판정을 만들지 않고 부모 Verification을 대기 또는 실패 처리 |
| chaining 후보 | child proposal별 work | exact match lineage, fingerprint 중복·ancestor 재사용·R8 전체 예산 검사를 통과한 proposal만 등록 | 거절 사유를 저장하고 부모 verdict 유지 |
>>>>>>> 1fd8dfe (docs: clarify ancestor-reuse exclusion is not cycle prevention)

같은 가설과 같은 `work_type`에는 활성 `attempt_id`를 하나만 허용한다. 중복 요청의 `dedupe_key`가 같으면 기존 `work_id`를 반환한다. 이미 합류가 끝난 뒤 늦게 도착한 tool·Pro·Con 결과는 기존 결과를 덮어쓰지 않는다. 새로운 근거로 사용할 필요가 있으면 입력 revision을 바꾼 새 논리 작업과 새 downstream revision을 만든다.

현재 `VERIFICATION` work는 `PRO_EVIDENCE`와 `CON_EVIDENCE` child work의 부모다. 두 자식은 `parent_work_ref`로 같은 부모와 generation을 가리키고, 각자 exact `EvidenceAgentResult`를 `COMMITTED`한 뒤에만 합류한다. 부모 Verification은 같은 `debate_input_hash`의 Pro·Con result reference를 final 합성 입력에 각각 한 번 넣는다. 한쪽이 재시도 대기이면 해당 자식과 부모를 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지한다. 복구 불가능하면 자식 실패를 먼저 확정해 부모 진행을 막고, 부모 `FAILED`와 가설 `FAILED`를 함께 확정하며 final verdict를 만들지 않는다.

## 바꿀 수 없는 직렬 순서

한 가설의 다음 구간은 병렬화하지 않는다.

```text
final TRUE VerificationResult with current generation SUCCEEDED + SUPPORTED reproduction and validated PoC
-> R5-01 CWE_LABELING work
-> current CWELabel bound to that exact Verification
-> Technical Evidence Gate
-> Technical ACCEPT와 TRUE 확인
-> result Primitive admission + Chaining handoff
and independently
-> Rule Scope Impact Gate -> PASS/PASS/PASS/SUFFICIENT/ALLOW -> Reporter
-> ReportDraft
-> AnalysisRunResult 확정
-> Agent 자동화 종료
```

Technical `REVISE`는 같은 입력으로 다시 투표하는 상태가 아니다. 현재 Technical Gate work는 `TechnicalEvidenceReview.status=REVISE`를 exact output으로 atomic commit하고 `SUCCEEDED`로 끝낸 뒤 같은 hypothesis의 ACTIVE `VerificationAssignment` owner에게 직접 전달한다. runtime은 기존 종료 VERIFICATION work를 되돌리지 않고 증가한 generation의 새 VERIFICATION work를 등록하며, 같은 CAS transition에서 `HypothesisProcessState`를 `TERMINAL -> VERIFYING`으로 바꾸고 새 work를 가리킨다. Verification은 새 근거를 반영하고, final TRUE 후보라면 새 generation의 동적 재현 요청과 validated PoC를 다시 확보한다. 그 뒤 새 `VerificationResult`와 새 work 종료·hypothesis `TERMINAL`·current result pointer를 atomic commit한다. R5-01 `CWE_LABELING`은 새 `CWE_LABEL` work에서 CWE 정렬을 반드시 다시 평가하고 새 Verification을 직접 가리키는 새 `CWELabel` revision을 확정한다. 동일 CWE를 유지해도 이전 label `record_id`는 재사용하지 않는다. 바뀐 Verification과 current label을 가진 새 `input_hash`·`dedupe_key`·`work_id`로 Technical Gate를 다시 요청한다. 새 generation에는 동적 재현 work 하나를 다시 허용한다. 같은 work의 PoC 생성·환경 구성·실행 재시도는 새 동적 work가 아니라 새 `attempt_id`다. 이 새 논리 작업의 첫 attempt는 `attempt_number=1`, `trigger=INITIAL`이다. provider timeout처럼 입력이 그대로인 일반 retry만 같은 `work_id`에서 새 `attempt_id`, `trigger=RETRY`를 사용한다. Rule Scope Gate와 Reporter는 앞 단계의 `COMMITTED` output reference만 읽는다. `PREPARED`, 취소된 attempt, 오래된 input hash와 다른 workspace/commit 결과는 다음 단계로 전달하지 않는다.

Chaining work는 exact Primitive와 source Verification·Technical review를 input으로 고정한다. proposal 저장 전 `source_primitive_match_id`와 parent set을 확인하고, 같은 계보에서 가장 깊은 후보와의 match가 실제로 성립한 뒤에만 그 후보의 양쪽(upstream·downstream) Primitive를 재귀 추적해 얻은 조상을 현재 순회의 후보에서 제외한다. 동일 fingerprint와 조상 재사용 결과는 저장하지 않는다. Primitive index 자체의 동시 갱신은 공통 `RecordMeta.revision_number`와 atomic current pointer 규칙으로 보호한다.

## retry·취소·중단 후 재개

- 일반 retry와 provider/model failover는 새 `attempt_id`를 사용하고, LLM 호출이면 새 `llm_call_id`도 사용한다.
- 일반 재시도에서 외부 조건을 기다리는 오류는 work를 `BLOCKED`로 두고 `waiting_for`에 `RETRY | AUTH | APPROVAL | INPUT | BUDGET | DEPENDENCY` 중 실제 조건을 기록한다. Pro/Con child 오류이면 부모 Verification도 같은 실제 이유로 `BLOCKED`다. `DYNAMIC_REPRO`의 자체 해결 가능한 오류는 예외로 같은 work에서 즉시 새 attempt를 시작하고, 외부 설정·정책·승인·resource 변경을 기다릴 때만 `BLOCKED`를 사용한다.
- Pro/Con 중 성공한 한쪽 결과는 가설·부모 generation·공통 입력·policy·playbook·application과 질문 ID 집합·Debate 설정·예산 profile이 그대로일 때만 보존한다. 이 중 하나가 바뀌면 두 결과를 모두 stale로 격리하고 두 역할을 다시 실행한다.
- 사용자가 개별 가설을 취소하면 그 가설의 새 downstream 작업을 만들지 않고 늦은 결과를 `STALE_RESULT`로 거절한다.
- 전체 분석을 취소하면 새 work 등록을 중단하고 실행 중 attempt에 취소를 전달하되 이미 저장된 결과와 오류는 보존한다.
- 재개 시 마지막 `COMMITTED` marker와 그 marker에서 투영된 상태 pointer만 신뢰한다. 완료 결과는 다시 실행하지 않고, 중단된 attempt만 허용된 새 attempt로 재시도한다.
- `PREPARED` journal과 종료 상태/output pointer 불일치는 runtime 복구가 끝나기 전까지 Gate·Reporter·최종 종료를 막는다.

## Agent 역할과 출력 권한

| 역할 | 주 출력 | 직접 할 수 없는 일 |
|---|---|---|
| Hypothesis Agent | `HypothesisProposal[]` | verdict, Finding, exploitability 확정 |
| Verification Agent | `VerificationResult` | 새 claim의 무검증 승격, 공개 |
| Pro Agent | `EvidenceAgentResult(role=PRO)` | 최종 verdict |
| Con Agent | `EvidenceAgentResult(role=CON)` | 최종 verdict |
| Chaining Agent | `ChainingResult`, `origin=CHAINING` proposal | 일반 research, verdict/CWE/Gate/Finding/report 확정 |
| Technical Evidence Gate | `TechnicalEvidenceReview` | Verification verdict 변경 |
| Rule Scope Impact Gate | `RuleScopeImpactReview` | 공식 정책 없는 허용 추정 |
| Reporter Agent | `ReportDraft` | 보고서 제출·공개 |

## 독립성, provider와 session

역할은 특정 LLM 공급 방식에 묶지 않는다. Agent Runtime은 `LLMProviderAdapter`를 통해 membership session 또는 API provider를 명시적으로 선택한다. 서로 반대되는 판단의 독립성을 위해 Pro와 Con, Verification과 Gate, 두 Gate, Verification과 Chaining, Reporter는 기본적으로 NEW session을 사용한다. 같은 역할·가설에서 추가 문맥을 조회하거나 같은 Verification이 Gate revision을 보완할 때만 `AUTO` 정책이 제한적으로 RESUME을 선택할 수 있다.

세션 재사용은 token 절감 가능성이 있지만 confirmation bias와 prompt contamination 위험이 있다. 실제 정책은 설정 가능해야 하고 선택 결과와 비교 지표를 로그에 남긴다.

Pro와 Con은 session만 분리하지 않는다. trusted prompt builder가 같은 공통 입력에서 역할별 immutable prompt payload를 만들며, 상대 역할의 결과·결론·session·action/decision은 prompt, context, parent/predecessor, 저장소 조회와 tool 입출력 어느 경로에도 넣지 않는다. 위반하면 `CROSS_ROLE_INPUT_DENIED`로 호출 또는 합류를 중단한다.

## prompt-injection 경계

저장소 내용, 도구 message, README와 주석, 모든 LLM output, provider 응답과 Sandbox output은 모두 비신뢰 분석 데이터다. Agent instruction이나 실행 권한으로 승격하지 않는다. Orchestration은 system instruction과 data 구분을 유지하고 Runtime Validator가 structured output과 action policy를 검사한다. Sandbox Controller는 비신뢰 입력이 host·Docker daemon/socket·mount/namespace·secret·egress·workspace·resource/lifecycle 외부 경계를 바꾸지 못하게 한다. 비신뢰 입력은 provider·model·session·Gate 순서·budget·Reporter와 자동화 종료 경계도 변경하지 못한다. 이런 변경 지시는 `UNTRUSTED_INSTRUCTION`으로 기록하고 실행하지 않는다.
