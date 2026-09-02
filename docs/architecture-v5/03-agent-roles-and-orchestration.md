# 03. Agent 역할과 오케스트레이션

- **이 문서는 무엇을 설명하나요?** 각 LLM Agent의 역할과 여러 Agent의 실행 순서를 조정하는 방법을 설명합니다.
- **누가 읽어야 하나요?** LLM 탐색·체이닝, 검증, PM과 통합 개발 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 각 Agent가 만들 수 있는 결과와 가질 수 없는 권한, 호출·실패 처리 순서를 확인합니다.

`Orchestration`은 여러 Agent의 호출 순서와 상태를 조정하는 기능입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## Orchestration Agent

Orchestration Agent는 분석 전체와 가설 목록을 관리하는 global control-plane이다. 한 가설에 대한 책임은 proposal 검증·전역 등록·Verification 배정에서 끝난다. 배정 뒤 Context, Pro/Con, 동적 재현, 판정, Gate `REVISE`와 Primitive 후보 admission 여부를 선택하는 주체는 그 가설의 Verification owner다. admission된 뒤 다른 Primitive와 실제로 비교해 Chaining work를 등록하는 시점은 Primitive DB를 유지하는 trusted runtime이 admission 이벤트마다 자동으로 처리하며, `REGISTER_WORK`를 요청할 수 있는 역할에 이 trusted runtime 전용 identity인 `ADMISSION_RUNTIME`을 포함한다. Chaining Agent 자신은 `REGISTER_WORK`를 요청하지 않는다. Verification owner는 admission 여부만 결정하고 그 뒤의 비교 시점에 매번 다시 관여하지 않는다.

```text
HypothesisProposal validation
-> VulnerabilityHypothesis registration
-> Verification Agent assignment
-> hypothesis-local control transfers to Verification
```

Orchestration Agent의 주요 책임은 다음과 같다.

- `analysis_id`와 전역 분석 계획 관리
- INITIAL·VERIFICATION·CHAINING proposal의 schema/semantic validation 요청
- 검증된 proposal의 `hypothesis_id` 등록
- `parent_hypothesis_ids`·`root_hypothesis_id`·`chain_depth` 관계 검증 요청
- 독립 가설의 병렬 배정과 hypothesis별 resource budget 배분
- 등록된 각 가설에 정확히 한 Verification owner를 배정하고 trusted runtime이 ACTIVE `VerificationAssignment`로 저장
- 전체 가설의 진행 상태·종료 상태·오류 집계
- chain depth/count/token/time/duplicate 전역 제한 적용 요청
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
- observed facts와 assumptions의 분리
- 현재 restriction
- missing information
- `question_id`가 붙은 구체적인 falsification questions
- required validation
- 우선순위용 confidence

confidence는 verdict, exploitability 또는 Finding 확률로 해석하지 않는다. Hypothesis Agent는 `confirmed`, `verified`, `finding`, `exploitable`과 같은 확정 주장을 출력할 권한이 없다.

## 출력 검증과 실패 처리

1. 구조 parser가 JSON/YAML syntax와 schema를 검증한다.
2. enum, 필수 field, `workspace_id`·`commit_id`·`CodeLocation`, 반증 질문과 금지 assertion을 검사한다. 유효한 proposal의 각 반증 질문에는 출력 검증 runtime이 전역 `question_id`를 붙인다.
3. 실패하면 원래 의미를 바꾸지 않는 범위에서 제한 횟수의 repair prompt를 새 invocation으로 실행한다.
4. 재시도 후에도 유효하지 않으면 해당 호출을 `INVALID_OUTPUT`으로 저장한다.
5. invalid proposal은 Verification Agent에 전달하지 않는다.

원문·validation error·repair 횟수·최종 parsed output reference는 `LLMInvocationLog`로 추적한다. 코드나 자격 증명의 불필요한 원문 저장은 피한다.

## 가설 lifecycle

```text
ProposalProcessState: PROPOSED -> SCHEMA_VALID
                      \-> INVALID_OUTPUT

SCHEMA_VALID -> register new hypothesis_id
HypothesisProcessState: REGISTERED -> ASSIGNED -> VERIFYING -> TERMINAL
Technical REVISE: TERMINAL -> same assignment + new VERIFICATION work -> VERIFYING
VerificationResult.verdict -> TRUE | FALSE | HOLD
HOLD -> REQUIRED Primitive -> Chaining eligible
TRUE -> two Gates pass -> PROVIDED Primitive -> Chaining eligible
Verification material claim -> PROPOSED child hypothesis origin VERIFICATION
Chaining match -> PROPOSED child hypothesis origin CHAINING
```

`ProposalProcessState.status`는 `hypothesis_id`를 발급하기 전의 출력 검증 상태를 기록한다. 검증을 통과하면 새 `hypothesis_id`와 별도 `HypothesisProcessState`를 만들고 같은 `proposal_ref`로 연결한다. `HypothesisProcessState.status`가 등록 뒤 처리 진행 상태를 기록하고 `VerificationResult.verdict`가 기술 판정을 기록한다. `TERMINAL`은 검증 처리가 끝났다는 뜻일 뿐 `TRUE`, `FALSE`, `HOLD` 중 어느 판정인지 대신 말하지 않는다. parent 가설의 결과와 child 가설은 독립된 lifecycle을 갖고 child 결과가 parent verdict를 바꾸지 않는다.

초기 가설은 자기 자신을 `root_hypothesis_id`로 사용하고 `chain_depth=0`이다. Verification-origin과 Chaining-origin proposal은 직접 부모 ID를 보존하고 trusted validation을 통과할 때만 새 `hypothesis_id`를 받는다. 새 endpoint·sink·권한 경계·공격 단계·독립 impact는 Verification이 `origin=VERIFICATION` proposal로 분리한다. TRUE+HOLD는 PROVIDED가 HOLD REQUIRED를, TRUE+TRUE는 앞 TRUE의 PROVIDED가 뒤 TRUE의 exact Verification에 기록된 선행 조건을 충족할 때만 Chaining Agent가 `origin=CHAINING` proposal로 만든다. 어느 경로도 기존 가설을 수정하거나 child를 자동 TRUE로 만들지 않는다. child가 FALSE여도 부모 판정은 바뀌지 않는다.

## 공통 실행 상태와 전문 결과의 분리

모든 실행 가능한 단계는 `WorkExecutionState`로 관리한다. 이 상태는 작업이 준비·실행·종료되었는지를 나타낼 뿐 전문 판정을 대신하지 않는다.

| 실행 작업 | 실행 종료 뒤 읽어야 하는 전문 결과 |
|---|---|
| Verification `SUCCEEDED` | `VerificationResult.verdict = TRUE | FALSE | HOLD` |
| Technical Gate `SUCCEEDED` | `TechnicalEvidenceReview.status = ACCEPT | REVISE | REJECT` |
| Rule Scope Gate `SUCCEEDED` | `RuleScopeImpactReview.review_status`와 `report_permission` |
| Reporter `SUCCEEDED` | 내부 `ReportDraft`; 사람 결정은 별도 `HumanReviewDecision` |

`PENDING -> READY -> RUNNING` 뒤에는 `SUCCEEDED | PARTIAL | FAILED | CANCELLED`로 끝나거나, 재시도·인증·승인·입력·예산 조건을 기다릴 때 `BLOCKED`로 이동한다. `BLOCKED`는 조건을 충족하면 `READY`가 되지만 종료 상태는 되돌리지 않는다. 재시도 가능한 attempt 실패는 attempt 자체를 `FAILED`로 보존하고 work를 `BLOCKED`로 두며, 새 attempt를 시작할 때 이전 실패를 삭제하지 않는다.

상태 변경을 실제로 승인·저장하는 주체는 Orchestration Agent가 아니라 신뢰 경계 안의 runtime이다. 작업 모듈은 결과와 다음 상태를 요청하고 runtime이 schema, 현재 `state_version`, 활성 attempt, 입력 hash, workspace·commit·가설, 예산과 권한을 검사한 뒤 `StateTransition`을 저장한다.

## 역할별 권한 경계

| 역할 | 제안 | 직접 판단 | 검토 | 프로그램 강제 | 사람만 결정 |
|---|---|---|---|---|---|
| Orchestration Agent | 전역 분석 계획·proposal 등록·가설 배정·가설 간 병렬화 | 없음 | 전체 진행 상태 요약 | 없음 | 없음 |
| Hypothesis Agent | 취약점 가설 | 없음 | static 사실을 입력으로 읽음 | 없음 | 없음 |
| Pro·Con Agent | 찬성·반대 근거 | 없음 | 자기 역할의 근거 | 없음 | 없음 |
| Verification Agent | Context·Pro/Con, 동적 모드·`EnvironmentRequirements`·`ReproductionPlan`, 두 Gate·Reporter 요청, Primitive 후보 admission 여부 결정, material child proposal | `TRUE | FALSE | HOLD` | static·Pro·Con·COMMITTED dynamic 근거와 환경 차이·Gate 보완 요청 | 없음 | 없음 |
| Sandbox Controller | 없음 | 없음 | exact plan·requirements closure의 image·command·file·network·resource·cleanup 보안 정책 검사와 exact 정책 판정 생산 | 정책 위반 계획 차단과 Runner 호출 통제 | 없음 |
| Sandbox Runner | 없음 | 없음 | Controller가 승인한 exact 계획의 환경 구성·요구사항 비교·Health Check 뒤 일치할 때만 공격 단계 실행, 실제 환경·`SandboxStepLog`와 PoC 실행 사실 생산 | 요구사항 변경·임의 차이 수용·허용되지 않은 fallback·계획 밖 command·입력 실행 차단 | 없음 |
| Sandbox Result Assembler | 없음 | 없음 | exact R6 plan closure와 같은 R7 실행 attempt의 정책·환경 비교·step log·PoC·cleanup reference를 `DynamicReproductionResult`로 조립 | nullable·상태·identity·requirements 조합 위반 결과 저장 차단 | 없음 |
| CWE Labeling | CWE 후보와 근거 | CWE label revision 생성 | final Verification | 없음 | 없음 |
| Chaining Agent | TRUE+HOLD·TRUE+TRUE Primitive match와 chained proposal | 없음 | ACTIVE Primitive와 exact Gate provenance | 없음 | 없음 |
| Technical Evidence Gate Agent | 구체적인 보완 요청 | 없음 | verdict·근거·코드 흐름·CWE | 없음 | 없음 |
| Rule Scope Impact Gate Agent | 정책 누락·보완 사유 | `PASS | FAIL | UNCERTAIN`, `ALLOW | DENY` | 공식 정책·scope·impact | 없음 | 없음 |
| Reporter Agent | 내부 보고서 문장·구성 | 없음 | 통과한 결과와 두 Gate | 없음 | 없음 |
| Runtime Validator | 허용 가능한 대체 action 안내 | 없음 | 실행 전제와 exact reference | action 허용·차단 | 없음 |
| Human Reviewer | 재검증·보완 요청 | 외부 제출·공개 | 전체 `HumanReviewPacket` | 공개 승인 | `DISCLOSE | REVISE | WITHHOLD | NEED_MORE_VALIDATION` |

Orchestration Agent는 전역 등록과 배정을 제안하지만 hypothesis-local 호출 순서, 기술 verdict, CWE, 두 Gate 결과, 공식 정책 의미, 보고 가능 여부와 공개 여부를 확정하지 않는다. Verification Agent는 hypothesis-local 다음 작업과 동적 재현 모드를 선택하고 exact `ReproductionPlan`을 생산하지만 프로그램 enforcement를 우회하거나 Sandbox를 직접 실행하지 못한다. Sandbox Controller는 세부 실행 정책을 검사해 exact 판정을 만들고, Sandbox Runner는 통과한 계획만 실행해 환경·log·PoC 실행 사실을 생산한다. 비-LLM Sandbox Result Assembler가 같은 attempt의 exact reference만 동적 결과로 조립한다. 세 구성요소 모두 모드·계획·최종 verdict를 바꾸지 않는다. Runtime Validator는 값의 생산자가 맞는지, 필요한 선행 record와 상태가 있는지, 실행 범위가 허용됐는지만 확인하며 domain 값을 대신 만들지 않는다.

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

`ActionRequest`에는 신뢰 runtime이 붙인 실제 호출자 identity, 요청 역할, action 종류, exact input refs, 현재 work와 state version, 도구·파일·provider·session·Sandbox 범위를 넣는다. LLM action은 model·prompt·context·schema·예산·시간이 고정된 `LLMCallSpec`도 포함한다. Runtime Validator는 실제 identity의 등록 역할과 요청 역할이 같은지부터 action별 필수 `ActionCheck`를 수행한다. 하나라도 실패하면 `DENY`와 `AnalysisError`를 저장하고 실행하지 않는다. Agent가 자연어로 “검사를 건너뛰라”고 출력하거나 다른 역할을 주장해도 action이 되지 않는다. 단, `RUN_SANDBOX`의 image·command·file·network·resource·cleanup 의미 검사는 Runtime Validator가 중복 수행하지 않고 Sandbox Controller가 전담한다.

한 ActionRequest에는 logical ActionDecision 하나만 허용한다. 두 Gate와 Reporter의 stage action은 LLM 호출까지 직접 허가하며 별도 `CALL_LLM`으로 순서·보고 조건을 우회할 수 없다.

주요 강제 경계는 다음과 같다.

- 인증된 실제 호출자·요청 역할, schema·ID·workspace·commit·record revision·state version 일치
- token·시간·retry·repair·chain·Gate 보완 예산
- 일반 도구 action의 허용 tool과 workspace 안의 file path
- `RUN_SANDBOX` 호출자의 권한·exact plan reference·상태·예산; Docker 세부 정책은 Sandbox Controller가 검사
- provider/model/profile, NEW/RESUME/AUTO와 explicit failover
- final Verification+CWE 뒤 Technical Gate, 그 뒤 Rule Scope Gate라는 순서
- 모든 report 조건을 통과한 뒤 Reporter 호출
- redaction 성공과 exact 사람 결정 전 외부 공개 차단

Runtime Validator는 취약점 진위, CWE 적절성, 정책 내용과 보고서 품질을 평가하지 않는다. 그것은 Verification, 두 LLM Gate, Reporter와 사람의 역할이다.

`RUN_SANDBOX`의 `ActionDecision=ALLOW`는 Controller에 exact `ReproductionPlan`을 전달할 권한만 부여한다. Sandbox Controller가 image digest, command/tool allowlist, mount와 file path, default-deny network, CPU·memory·disk·process·time limit, non-root와 cleanup을 한 번 검사한다. 통과한 계획만 Sandbox Runner가 실행한다. 실행 뒤 `SAVE_RESULT`는 승인 계획과 실제 `SandboxStepLog`의 일치 여부를 다시 대조한다. 마지막 대조는 정책을 재판단하는 중복 검사가 아니라 실행 결과 무결성 확인이다.

## 병렬 실행과 결과 합류

| 병렬 구간 | 분리 단위 | 합류 조건 | 일부 실패 처리 |
|---|---|---|---|
| AST와 SAST | tool별 `work_id` | 기대한 tool의 종료 상태와 output/error 확인 | 하나 이상의 신뢰 결과가 있으면 `DataGap`을 포함한 `PARTIAL` 정규화 가능 |
| 가설 검증 | `hypothesis_id`별 work | 각 가설은 자기 final Verification까지 독립 | 한 가설 오류가 다른 가설을 취소하지 않으며 분석은 `PARTIAL` 가능 |
| Pro와 Con | 같은 가설의 역할별 work·NEW session | 필요한 두 결과 또는 명시된 skip/실패·예산 상태 확인 | 누락을 반증으로 바꾸지 않고 unresolved condition으로 전달 |
| chaining 후보 | child proposal별 work | 중복·cycle·depth·예산 검사를 통과한 proposal만 등록 | 거절 사유를 저장하고 부모 verdict 유지 |

같은 가설과 같은 `work_type`에는 활성 `attempt_id`를 하나만 허용한다. 중복 요청의 `dedupe_key`가 같으면 기존 `work_id`를 반환한다. 이미 합류가 끝난 뒤 늦게 도착한 tool·Pro·Con 결과는 기존 결과를 덮어쓰지 않는다. 새로운 근거로 사용할 필요가 있으면 입력 revision을 바꾼 새 논리 작업과 새 downstream revision을 만든다.

## 바꿀 수 없는 직렬 순서

한 가설의 다음 구간은 병렬화하지 않는다.

```text
final VerificationResult + CWELabel
-> Technical Evidence Gate
-> Technical ACCEPT와 TRUE 확인
-> Rule Scope Impact Gate
-> PASS/PASS/PASS/SUFFICIENT/ALLOW와 exact revision 확인
-> Reporter
-> Human Reviewer
```

Technical `REVISE`는 같은 입력으로 다시 투표하는 상태가 아니다. 현재 Technical Gate work는 `TechnicalEvidenceReview.status=REVISE`를 exact output으로 atomic commit하고 `SUCCEEDED`로 끝낸 뒤 같은 hypothesis의 ACTIVE `VerificationAssignment` owner에게 직접 전달한다. runtime은 기존 종료 VERIFICATION work를 되돌리지 않고 증가한 generation의 새 VERIFICATION work를 등록하며, 같은 CAS transition에서 `HypothesisProcessState`를 `TERMINAL -> VERIFYING`으로 바꾸고 새 work를 가리킨다. Verification은 새 근거를 반영한 `VerificationResult`와 새 work 종료·hypothesis `TERMINAL`·current result pointer를 atomic commit하고, 필요하면 기존 CWE producer가 만든 새 `CWELabel` revision을 조정한다. 그 뒤 바뀐 `input_hash`·`dedupe_key`와 새 `work_id`로 Technical Gate를 다시 요청한다. 이 새 논리 작업의 첫 attempt는 `attempt_number=1`, `trigger=INITIAL`이다. provider timeout처럼 입력이 그대로인 일반 retry만 같은 `work_id`에서 새 `attempt_id`, `trigger=RETRY`를 사용한다. Rule Scope Gate와 Reporter는 앞 단계의 `COMMITTED` output reference만 읽는다. `PREPARED`, 취소된 attempt, 오래된 input hash와 다른 workspace/commit 결과는 다음 단계로 전달하지 않는다.

Chaining work는 각 parent의 current `PrimitiveIndexState` revision을 input으로 고정한다. 결과와 child proposal commit 직전에 index head와 current final Verification을 다시 검사하며, 탐색 중 새 Verification generation이 생겼다면 이전 Primitive record의 표면상 `ACTIVE` 값과 무관하게 `STALE_RESULT`로 거절한다.

## retry·취소·중단 후 재개

- 일반 retry와 provider/model failover는 새 `attempt_id`를 사용하고, LLM 호출이면 새 `llm_call_id`도 사용한다.
- 재시도 가능한 오류는 work를 `BLOCKED`로 두고 `waiting_for`에 `RETRY | AUTH | APPROVAL | INPUT | BUDGET | DEPENDENCY` 중 실제 조건을 기록한다.
- 사용자가 개별 가설을 취소하면 그 가설의 새 downstream 작업을 만들지 않고 늦은 결과를 `STALE_RESULT`로 거절한다.
- 전체 분석을 취소하면 새 work 등록을 중단하고 실행 중 attempt에 취소를 전달하되 이미 저장된 결과와 오류는 보존한다.
- 재개 시 마지막 `COMMITTED` marker와 그 marker에서 투영된 상태 pointer만 신뢰한다. 완료 결과는 다시 실행하지 않고, 중단된 attempt만 허용된 새 attempt로 재시도한다.
- `PREPARED` journal과 종료 상태/output pointer 불일치는 runtime 복구가 끝나기 전까지 Gate·Reporter·최종 종료를 막는다.

## Agent 역할과 출력 권한

| 역할 | 주 출력 | 직접 할 수 없는 일 |
|---|---|---|
| Hypothesis Agent | `HypothesisProposal[]` | verdict, Finding, exploitability 확정 |
| Verification Agent | `VerificationResult` | 새 claim의 무검증 승격, 공개 |
| Pro Agent | supporting evidence candidate | 최종 verdict |
| Con Agent | counterexample·restriction candidate | 최종 verdict |
| Chaining Agent | `ChainingResult`, `origin=CHAINING` proposal | 일반 research, verdict/CWE/Gate/Finding/report 확정 |
| Technical Evidence Gate | `TechnicalEvidenceReview` | Verification verdict 변경 |
| Rule Scope Impact Gate | `RuleScopeImpactReview` | 공식 정책 없는 허용 추정 |
| Reporter Agent | `ReportDraft` | 보고서 제출·공개 |
| Human Reviewer | `HumanReviewDecision` | Agent output을 근거 없이 승인하거나 다른 revision의 결정을 재사용 |

## 독립성, provider와 session

역할은 특정 LLM 공급 방식에 묶지 않는다. Agent Runtime은 `LLMProviderAdapter`를 통해 membership session 또는 API provider를 명시적으로 선택한다. 서로 반대되는 판단의 독립성을 위해 Pro와 Con, Verification과 Gate, 두 Gate, Verification과 Chaining, Reporter는 기본적으로 NEW session을 사용한다. 같은 역할·가설에서 추가 문맥을 조회하거나 같은 Verification이 Gate revision을 보완할 때만 `AUTO` 정책이 제한적으로 RESUME을 선택할 수 있다.

세션 재사용은 token 절감 가능성이 있지만 confirmation bias와 prompt contamination 위험이 있다. 실제 정책은 설정 가능해야 하고 선택 결과와 비교 지표를 로그에 남긴다.

## prompt-injection 경계

저장소 내용, 도구 message, README와 주석, 모든 LLM output, provider 응답과 Sandbox output은 모두 비신뢰 분석 데이터다. Agent instruction이나 실행 권한으로 승격하지 않는다. Orchestration은 system instruction과 data 구분을 유지하고 Runtime Validator가 structured output과 action policy를 검사한다. Sandbox Controller는 비신뢰 입력이 image·command·file·network·resource·cleanup 정책을 바꾸지 못하게 한다. 비신뢰 입력은 provider·model·session·Gate 순서·budget·Reporter·공개 정책도 변경하지 못한다. 이런 변경 지시는 `UNTRUSTED_INSTRUCTION`으로 기록하고 실행하지 않는다.
