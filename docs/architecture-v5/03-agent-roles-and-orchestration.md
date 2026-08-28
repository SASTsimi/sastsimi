# 03. Agent 역할과 오케스트레이션

- **이 문서는 무엇을 설명하나요?** 각 LLM Agent의 역할과 여러 Agent의 실행 순서를 조정하는 방법을 설명합니다.
- **누가 읽어야 하나요?** LLM 탐색·체이닝, 검증, PM과 통합 개발 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 각 Agent가 만들 수 있는 결과와 가질 수 없는 권한, 호출·실패 처리 순서를 확인합니다.

`Orchestration`은 여러 Agent의 호출 순서와 상태를 조정하는 기능입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## Orchestration Agent

Orchestration Agent는 분석 계획과 다음 작업을 제안·조정하는 control-plane 역할이다. 다만 보안 경계를 실제로 강제하는 주체는 Agent가 아니라 신뢰 경계 안의 비-LLM runtime validator다. runtime은 `workspace_id`·`commit_id` 일치, budget, Hypothesis output validation, 가설별 Verification 할당, Research 환류, 두 Gate의 순서, 결과 저장과 종료 조건을 검증·집행한다. Orchestration Agent는 각 단계의 전문 판정이나 runtime enforcement를 대신하지 않는다.

주요 책임은 다음과 같다.

- `analysis_id` 부여와 proposal 검증 뒤 `hypothesis_id` 등록
- `parent_hypothesis_ids`·`root_hypothesis_id`·`chain_depth` 관계 검증
- 가설 schema 검증과 제한된 repair retry
- 독립 가설 병렬 처리와 hypothesis별 resource budget
- 논리 작업별 `work_id`·`dedupe_key` 등록과 활성 `attempt_id` 하나 유지
- `state_version` compare-and-set과 atomic output binding을 runtime에 요청
- session policy와 provider profile을 Agent Runtime에 전달
- 동적 재현·Research·Gate 호출 조건 적용
- chain depth/count/token/time/duplicate 제한 적용
- 실패와 `INVALID_OUTPUT`을 숨기지 않고 종료 상태로 저장
- 모든 LLM 출력을 비신뢰 입력으로 취급하고 schema·semantic·authority validation을 통과한 action만 실행

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
VerificationResult.verdict -> TRUE | FALSE | HOLD
TRUE/HOLD verdict -> Primitive + Research
Research material claim -> PROPOSED child hypothesis
```

`ProposalProcessState.status`는 `hypothesis_id`를 발급하기 전의 출력 검증 상태를 기록한다. 검증을 통과하면 새 `hypothesis_id`와 별도 `HypothesisProcessState`를 만들고 같은 `proposal_ref`로 연결한다. `HypothesisProcessState.status`가 등록 뒤 처리 진행 상태를 기록하고 `VerificationResult.verdict`가 기술 판정을 기록한다. `TERMINAL`은 검증 처리가 끝났다는 뜻일 뿐 `TRUE`, `FALSE`, `HOLD` 중 어느 판정인지 대신 말하지 않는다. parent 가설의 결과와 child 가설은 독립된 lifecycle을 갖는다. Research 후보가 존재한다는 이유만으로 parent verdict나 impact를 강화하지 않는다.
초기 가설은 자기 자신을 `root_hypothesis_id`로 사용하고 `chain_depth=0`이다. Research·체이닝 proposal은 직접 부모 ID를 보존하고 검증을 통과할 때 새 `hypothesis_id`를 받는다. 여러 `TRUE`를 연결하는 경우도 기존 가설을 수정하지 않고 새 child 가설로 등록한다.

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
| Orchestration Agent | 실행 계획·다음 작업·병렬화·retry 후보 | 없음 | 진행 상태 요약 | 없음 | 없음 |
| Hypothesis Agent | 취약점 가설 | 없음 | static 사실을 입력으로 읽음 | 없음 | 없음 |
| Pro·Con Agent | 찬성·반대 근거 | 없음 | 자기 역할의 근거 | 없음 | 없음 |
| Verification Agent | 동적 재현·Research 요청 | `TRUE | FALSE | HOLD` | static·Pro·Con·dynamic 근거 | 없음 | 없음 |
| CWE Labeling | CWE 후보와 근거 | CWE label revision 생성 | final Verification | 없음 | 없음 |
| Research Agent | bypass·alternate path·chain 후보 | 없음 | 기존 verdict와 Primitive | 없음 | 없음 |
| Technical Evidence Gate Agent | 구체적인 보완 요청 | 없음 | verdict·근거·코드 흐름·CWE | 없음 | 없음 |
| Rule Scope Impact Gate Agent | 정책 누락·보완 사유 | `PASS | FAIL | UNCERTAIN`, `ALLOW | DENY` | 공식 정책·scope·impact | 없음 | 없음 |
| Reporter Agent | 내부 보고서 문장·구성 | 없음 | 통과한 결과와 두 Gate | 없음 | 없음 |
| Runtime Validator | 허용 가능한 대체 action 안내 | 없음 | 실행 전제와 exact reference | action 허용·차단 | 없음 |
| Human Reviewer | 재검증·보완 요청 | 외부 제출·공개 | 전체 `HumanReviewPacket` | 공개 승인 | `DISCLOSE | REVISE | WITHHOLD | NEED_MORE_VALIDATION` |

Orchestration Agent는 호출 순서와 작업 분배를 제안하지만 기술 verdict, CWE, 두 Gate 결과, 공식 정책 의미, 보고 가능 여부와 공개 여부를 확정하지 않는다. Runtime Validator도 이 값을 대신 정하지 않는다. 값의 생산자가 맞는지, 필요한 선행 record와 상태가 있는지, 실행 범위가 허용됐는지만 확인한다.

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

`ActionRequest`에는 요청 역할, action 종류, exact input refs, 현재 work와 state version, 도구·파일·provider·session·Sandbox 범위를 넣는다. Runtime Validator는 action별 필수 `ActionCheck`를 모두 수행한다. 하나라도 실패하면 `DENY`와 `AnalysisError`를 저장하고 실행하지 않는다. Agent가 자연어로 “검사를 건너뛰라”고 출력해도 action이 되지 않는다.

주요 강제 경계는 다음과 같다.

- schema·ID·workspace·commit·record revision·state version 일치
- token·시간·retry·repair·chain·Gate 보완 예산
- 허용 tool과 workspace 안의 file path
- Sandbox image digest·default-deny network·resource·cleanup
- provider/model/profile, NEW/RESUME/AUTO와 explicit failover
- final Verification+CWE 뒤 Technical Gate, 그 뒤 Rule Scope Gate라는 순서
- 모든 report 조건을 통과한 뒤 Reporter 호출
- redaction 성공과 exact 사람 결정 전 외부 공개 차단

Runtime Validator는 취약점 진위, CWE 적절성, 정책 내용과 보고서 품질을 평가하지 않는다. 그것은 Verification, 두 LLM Gate, Reporter와 사람의 역할이다.

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

Technical `REVISE`는 같은 입력으로 다시 투표하는 상태가 아니다. Verification 또는 Research에서 새 근거·설명·revision을 만든 뒤 새 Gate attempt를 시작한다. Rule Scope Gate와 Reporter는 앞 단계의 `COMMITTED` output reference만 읽는다. `PREPARED`, 취소된 attempt, 오래된 input hash와 다른 workspace/commit 결과는 다음 단계로 전달하지 않는다.

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
| Research Agent | `ResearchResult` | verdict/CWE/Gate/Finding/report 확정 |
| Technical Evidence Gate | `TechnicalEvidenceReview` | Verification verdict 변경 |
| Rule Scope Impact Gate | `RuleScopeImpactReview` | 공식 정책 없는 허용 추정 |
| Reporter Agent | `ReportDraft` | 보고서 제출·공개 |
| Human Reviewer | `HumanReviewDecision` | Agent output을 근거 없이 승인하거나 다른 revision의 결정을 재사용 |

## 독립성, provider와 session

역할은 특정 LLM 공급 방식에 묶지 않는다. Agent Runtime은 `LLMProviderAdapter`를 통해 membership session 또는 API provider를 명시적으로 선택한다. 서로 반대되는 판단의 독립성을 위해 Pro와 Con, Verification과 Gate, 두 Gate, Verification과 Research, Reporter는 기본적으로 NEW session을 사용한다. 같은 역할·가설에서 추가 문맥을 조회하거나 같은 Verification의 Gate revision을 처리할 때만 `AUTO` 정책이 제한적으로 RESUME을 선택할 수 있다.

세션 재사용은 token 절감 가능성이 있지만 confirmation bias와 prompt contamination 위험이 있다. 실제 정책은 설정 가능해야 하고 선택 결과와 비교 지표를 로그에 남긴다.

## prompt-injection 경계

저장소 내용, 도구 message, README와 주석, 모든 LLM output, provider 응답과 Sandbox output은 모두 비신뢰 분석 데이터다. Agent instruction이나 실행 권한으로 승격하지 않는다. Orchestration은 system instruction과 data 구분을 유지하고 Runtime Validator가 structured output, tool allowlist와 action policy를 검사한다. 비신뢰 입력은 provider·model·session·Gate 순서·Sandbox image/network·budget·Reporter·공개 정책을 변경하지 못한다. 이런 변경 지시는 `UNTRUSTED_INSTRUCTION`으로 기록하고 실행하지 않는다.
