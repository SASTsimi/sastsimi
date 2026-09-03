# 08. 경량 데이터 계약

- **이 문서는 무엇을 설명하나요?** 각 파트가 주고받는 데이터 묶음과 정확한 필드 이름을 정의합니다.
- **누가 읽어야 하나요?** 모든 설계·구현 담당자와 파트 사이의 연결을 검토하는 사람이 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 누가 어떤 데이터를 만들고 받는지, 필수 필드와 상태값이 서로 맞는지 확인합니다.

`contract`는 파트 사이의 입출력 약속이고 `record`는 정해진 형식의 데이터 묶음입니다. 이 문서의 데이터 이름과 필드명은 구현에서 정확히 유지해야 합니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 범위

이 문서는 Agent 경계에서 의미가 달라지지 않도록 최소 record와 enum을 정의한다. 완전한 구현 schema, 모든 내부 event, 서명 체계나 대규모 policy registry를 미리 고정하지 않는다. sandbox 요청, provider 호출, 저장 경계 등 실제 위험·호환성 경계에서만 구현 단계의 강한 validation을 추가한다.

## 공통 식별자와 참조

`CodeWorkspace`는 별도 저장소 복사본이 아니라 `Repository Loader`가 실행별로 clone하고 지정한 commit을 checkout한 로컬 분석 폴더다.

```yaml
CodeWorkspace:
  workspace_id: string
  analysis_id: string
  repository_url: string
  commit_id: string | null
  status: PREPARING | READY | FAILED | REMOVED
  created_at: timestamp
```

실제 로컬 절대 경로는 runtime 내부에서만 관리하며 Agent, Finding과 보고서에 전달하지 않는다.
`workspace_id`는 재사용하지 않는다. clone 또는 checkout이 진행 중이면 `status=PREPARING`, `commit_id=null`이다. 준비 작업이 실패하면 `status=FAILED`이며 `commit_id`는 checkout 확인 여부에 따라 값이 있거나 `null`일 수 있다. `status=READY`이면 `commit_id`가 반드시 있어야 하며, 코드 분석은 이때만 시작한다. 로컬 폴더를 정리하면 `status=REMOVED`로 바꾸되, 성공한 작업공간의 `workspace_id`와 `repository_url`·`commit_id` 연결 정보는 결과 추적을 위해 보존한다.

분석을 시작했지만 아직 코드 작업공간이나 commit이 준비되지 않은 상태는 `RunMeta`를 사용한다.

```yaml
RunMeta:
  record_id: string
  logical_record_id: string
  record_type: string
  schema_version: string
  analysis_id: string
  revision_number: integer
  previous_record_id: string | null
  created_at: timestamp
```

```yaml
RecordMeta:
  record_id: string
  logical_record_id: string
  record_type: string
  schema_version: string
  analysis_id: string
  workspace_id: string
  commit_id: string
  hypothesis_id: string | null
  attempt_id: string | null
  revision_number: integer
  previous_record_id: string | null
  created_at: timestamp
```

코드 근거를 포함하는 모든 핵심 결과는 `meta: RecordMeta`를 갖는다. `analysis_id`, `workspace_id`와 `commit_id`는 필수다. runtime은 `workspace_id`가 가리키는 `CodeWorkspace.status`가 `READY`이고 그 `commit_id`가 `RecordMeta.commit_id`와 같은지 확인한다. 가설별 결과는 `hypothesis_id`, 재시도 가능한 작업은 `attempt_id`가 필수다. 분석 시작·clone 실패처럼 코드에 아직 묶이지 않은 실행 상태와 최종 실행 결과는 `RunMeta`를 사용하고 nullable `workspace_id`, `commit_id`를 record 본문에 둔다. `logical_record_id`는 같은 논리 결과의 모든 수정본에서 유지한다. 첫 결과의 `revision_number`는 `1`, `previous_record_id`는 `null`이다. 결과를 수정할 때 덮어쓰지 않고 새 `record_id`와 증가한 revision을 만든다.

### 식별자 생성·저장·참조 기준

ID 값은 내부 의미를 넣지 않는 불투명 문자열이다. `ana_`, `ws_`, `hyp_` 같은 접두사는 로그 가독성을 위한 예시이며, 프로그램은 접두사에서 상태·소유자·시간을 추론하지 않는다.

| 식별자 | 누가 만드나요? | 어디까지 유일한가요? | 어디에 저장하나요? | 변경·재사용 규칙 |
|---|---|---|---|---|
| `analysis_id` | Orchestration runtime | 전체 시스템 | `runs`, 모든 `RunMeta`와 `RecordMeta` | 변경·재사용 금지 |
| `workspace_id` | Repository Loader | 전체 시스템 | `CodeWorkspace`, `runs`, 코드 근거 record | 변경·재사용 금지 |
| `commit_id` | Git에서 checkout한 commit을 Repository Loader가 확인 | `repository_url`이 가리키는 Git 저장소 | `CodeWorkspace`, `CodeLocation`, `StoredDataRef`, `RecordMeta` | 외부 Git 객체 ID다. 같은 commit은 여러 분석에서 다시 참조할 수 있으나 값은 변경 금지 |
| `stored_data_id` | 결과 저장 계층 | 전체 시스템 | 해당 논리 저장 영역과 `RunStoredDataRef` 또는 `StoredDataRef` | 변경·재사용 금지 |
| `record_id` | record 저장 직전 runtime | 전체 시스템 | 각 `RunMeta`·`RecordMeta`와 정확한 revision을 가리키는 `StoredDataRef` | revision마다 새 값 |
| `logical_record_id` | 논리 결과를 처음 저장하는 runtime | 전체 시스템 | 각 `RunMeta`와 `RecordMeta` | 같은 논리 결과의 모든 revision에서 같은 값 유지 |
| `hypothesis_id` | proposal 검증을 통과시킨 runtime | 전체 시스템 | `hypotheses`와 가설별 `RecordMeta` | 변경·재사용 금지 |
| `work_id` | 논리 작업을 등록하는 Orchestration runtime | 전체 시스템 | `WorkExecutionState`, 모든 `WorkAttempt`와 `StateTransition` | 같은 입력의 retry에서는 유지하고 입력 revision이 달라지면 새 값 |
| `attempt_id` | 재시도 가능한 작업을 시작하는 runtime | 전체 시스템 | 해당 결과와 debug trace | 시도마다 새 값 |
| `transition_id` | 상태 변경을 승인하는 runtime | 전체 시스템 | `StateTransition`과 debug trace | 승인된 상태 변경마다 새 값 |
| `transition_commit_id` | 결과와 상태를 함께 확정하는 저장 runtime | 전체 시스템 | `TransitionCommit` journal | atomic 저장 시도마다 새 값 |
| `action_id` | 실행 요청을 저장하는 runtime | 전체 시스템 | `ActionRequest`, `ActionDecision`과 실행 trace | 요청마다 새 값, retry에서 재사용 금지 |
| `decision_id` | action을 검사한 runtime validator | 전체 시스템 | `ActionDecision`과 실행 trace | 한 `action_ref.record_id`당 하나이며 모든 decision revision에서 유지 |
| `llm_call_id` | LLM 호출 직전 Agent Runtime | 전체 시스템 | `invocations` | retry·failover마다 새 값 |
| `symbol_id` | AST·SAST 정규화 계층 | 같은 `workspace_id + commit_id` | `CodeSymbol`과 코드 근거 record | 같은 코드 버전 안에서 한 symbol만 가리킴 |
| `fact_id` | AST·SAST 정규화 계층 | 같은 `workspace_id + commit_id` | `CodeFact`와 이를 사용하는 결과 | 같은 코드 사실에 재사용하고 다른 사실에 재사용 금지 |
| `relation_id` | AST·SAST 정규화 계층 | 같은 `workspace_id + commit_id` | `CodeRelation`과 이를 사용하는 결과 | 같은 코드 관계에 재사용하고 다른 관계에 재사용 금지 |
| `gap_id` | gap을 처음 발견한 runtime | 전체 시스템 | `DataGap`과 이를 포함한 결과 | gap마다 새 값 |
| `error_id` | 오류를 기록하는 runtime | 전체 시스템 | `AnalysisError`, 실행 결과와 debug trace | 오류 사건마다 새 값 |
| `proposal_id` | Hypothesis Agent 출력 검증 runtime | 전체 시스템 | `HypothesisProposal` | proposal마다 새 값. `hypothesis_id`와 같지 않음 |
| `question_id` | proposal 출력 검증 runtime | 전체 시스템 | `FalsificationQuestion`과 `FalsificationResult` | proposal에서 등록 가설로 그대로 유지하고 다른 질문에 재사용 금지 |
| `code_request_id` | 코드 문맥을 요청하는 Agent Runtime | 전체 시스템 | `CodeContextRequest`와 해당 `CodeContextResponse` | 요청·응답 한 쌍에서 같은 값 유지 |
| `primitive_id` | 검증 결과를 primitive로 저장하는 runtime | 전체 시스템 | `Primitive`와 체이닝 후보 | primitive마다 새 값 |
| `policy_record_id` | 공식 정책 수집 결과를 저장하는 runtime | 전체 시스템 | `ProgramPolicyRecord` | 정책 수집본마다 새 값 |
| `program_id` | 내부 Program Catalog | 전체 시스템 | `ProgramPolicyRecord`와 정책 조회 입력 | 같은 프로그램은 여러 분석에서 같은 값을 재사용 |
| `external_program_id` | 외부 버그바운티 플랫폼 | 같은 `program_namespace` | `ProgramPolicyRecord` | 같은 외부 프로그램을 다시 참조할 수 있으며 namespace 없이 단독 사용 금지 |
| `revision_number` | 새 revision을 저장하는 runtime | 같은 논리 결과 | `RunMeta`와 `RecordMeta` | 1부터 1씩 증가 |

`parent_hypothesis_ids`, `source_hypothesis_id`, `target_hypothesis_id`, `retry_of_llm_call_id`와 `failover_from_llm_call_id`는 새 종류의 ID가 아니라 각각 기존 `hypothesis_id` 또는 `llm_call_id`를 가리키는 참조 필드다. `source_primitive_match_id`는 분석 전체에서 유일한 기존 `primitive_match_id`를 가리킨다. 로컬 폴더를 정리해도 성공한 `workspace_id → repository_url + commit_id` 연결 정보는 삭제하지 않는다. 시스템이 직접 만든 ID는 다른 대상에 재사용하지 않는다. 외부 ID인 `commit_id`와 `external_program_id`는 같은 대상을 다시 가리킬 수 있다. 서로 다른 종류의 ID는 대신 사용할 수 없으며, 소비자는 필요한 ID를 `RecordMeta`와 전문 record 양쪽에서 검사한다.

### 공통 시간 규칙

- 모든 시각은 UTC RFC 3339 형식이다. 예: `2026-08-28T12:34:56.123Z`.
- `created_at`은 해당 record가 처음 저장된 불변 시각이다.
- 실행 작업은 `started_at`과 `finished_at`을 사용한다. 아직 끝나지 않았으면 `finished_at: null`이다.
- `elapsed_ms`는 monotonic clock으로 계산한 0 이상의 밀리초다. 벽시계 시각 차이를 timeout이나 비용 계산의 정본으로 사용하지 않는다.
- 새 revision은 새 `created_at`을 갖고 이전 record의 시각을 덮어쓰지 않는다.

### 상태 계층과 소유 주체

같은 `status`라는 필드명을 쓰더라도 record 종류가 다르면 의미가 다르다. runtime은 아래 계층을 하나의 enum으로 합치거나 한 계층의 실패를 다른 계층의 판정으로 변환하지 않는다.

| 상태 계층 | 소유 record와 field | 허용 값 | 상태를 만드는 주체 | 반드시 분리할 의미 |
|---|---|---|---|---|
| 분석 실행 | `AnalysisRunState.status` | `RUNNING | COMPLETE | PARTIAL | FAILED | CANCELLED` | Orchestration runtime | 가설 verdict가 아님 |
| 공통 실행 작업 | `WorkExecutionState.status` | `PENDING | READY | RUNNING | BLOCKED | SUCCEEDED | PARTIAL | FAILED | CANCELLED` | 신뢰 경계 안의 runtime | 전문 결과·가설 verdict와 분리 |
| proposal 검증 | `ProposalProcessState.status` | `PROPOSED | SCHEMA_VALID | INVALID_OUTPUT | CANCELLED` | 출력 검증 runtime | 아직 `hypothesis_id`가 없는 상태 |
| 등록 가설 처리 | `HypothesisProcessState.status` | `REGISTERED | ASSIGNED | VERIFYING | TERMINAL | FAILED | CANCELLED` | Orchestration runtime | `TRUE | FALSE | HOLD`와 분리 |
| 기술 판정 | `VerificationResult.verdict` | `TRUE | FALSE | HOLD` | Verification Agent | 오류·정보 부족 상태와 분리 |
| 동적 재현 | `DynamicReproductionState.status` | `NOT_REQUESTED | RUNNING | SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED` | Sandbox runtime | `FAILED`만으로 가설 반증 금지 |
| LLM 호출 | `LLMInvocationResult.status` | `SUCCEEDED | FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED | CANCELLED` | Agent Runtime과 provider adapter | 가설 verdict로 변환 금지 |
| 기술 Gate | `TechnicalEvidenceReview.status` | `ACCEPT | REVISE | REJECT` | Technical Evidence Gate Agent | Verification verdict를 변경하지 않음 |
| 정책·영향 Gate | `RuleScopeImpactReview.review_status`, `report_permission` | `PASS | FAIL | UNCERTAIN`, `ALLOW | DENY` | Rule Scope Impact Gate Agent | 기술 판정과 분리 |
| 보고서 초안 | `ReportProcessState.status` | `NOT_REQUESTED | DRAFTED | FAILED` | Reporter runtime | 공개 승인 상태가 아님 |

진행 중인 상태도 저장할 수 있도록 아래 최소 상태 record를 사용한다. 종료 결과 record는 상세 근거를 담고, 상태 record는 현재 진행 위치를 나타낸다.

```yaml
AnalysisRunState:
  meta: RunMeta
  purpose: PRODUCTION | EVALUATION
  workspace_id: string | null
  commit_id: string | null
  status: RUNNING | COMPLETE | PARTIAL | FAILED | CANCELLED
  analysis_result_ref: RunStoredDataRef | null
  started_at: timestamp
  finished_at: timestamp | null
  elapsed_ms: integer

ProposalProcessState:
  meta: RecordMeta without hypothesis/attempt
  proposal_ref: StoredDataRef
  status: PROPOSED | SCHEMA_VALID | INVALID_OUTPUT | CANCELLED
  started_at: timestamp
  finished_at: timestamp | null
  elapsed_ms: integer

VerificationAssignment:
  meta: RecordMeta with attempt_id null
  assignment_id: string
  owner_identity_ref: StoredDataRef
  assignment_generation: integer
  status: ACTIVE | SUPERSEDED
  previous_assignment_ref: StoredDataRef | null
  assigned_at: timestamp

HypothesisProcessState:
  meta: RecordMeta with hypothesis
  proposal_ref: StoredDataRef
  status: REGISTERED | ASSIGNED | VERIFYING | TERMINAL | FAILED | CANCELLED
  verification_assignment_ref: StoredDataRef | null
  verification_generation: integer
  verification_work_ref: StoredDataRef | null
  verification_result_ref: StoredDataRef | null
  started_at: timestamp
  finished_at: timestamp | null
  elapsed_ms: integer

DynamicReproductionState:
  meta: RecordMeta
  status: NOT_REQUESTED | RUNNING | SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED
  request_ref: StoredDataRef | null
  dynamic_result_ref: StoredDataRef | null
  started_at: timestamp | null
  finished_at: timestamp | null
  elapsed_ms: integer

ReportProcessState:
  meta: RecordMeta
  status: NOT_REQUESTED | DRAFTED | FAILED
  report_draft_ref: StoredDataRef | null
  started_at: timestamp | null
  finished_at: timestamp | null
  elapsed_ms: integer
```

`AnalysisRunState`는 처음에는 `workspace_id: null`, `commit_id: null`일 수 있다. Repository Loader가 작업공간을 만들면 `workspace_id`를 기록하고, checkout을 확인하면 `commit_id`를 기록한다. 한 번 기록된 값은 같은 분석에서 바꾸지 않는다. `COMPLETE`와 `PARTIAL`은 두 값이 모두 필요하고, clone·checkout 전 `FAILED | CANCELLED`는 둘 중 하나 또는 모두가 `null`일 수 있다. 코드 근거 record는 두 값이 모두 있고 `CodeWorkspace.status=READY`일 때만 만들 수 있다.

`purpose`는 분석 시작 때 고정하며 같은 `analysis_id`에서 바꾸지 않는다. PRODUCTION에서는 `verification_mode=ALWAYS_DEBATE`만 허용한다. EVALUATION의 `BASIC | CONDITIONAL_DEBATE` 결과는 Gate·Primitive admission·Reporter 입력으로 사용할 수 없다. 예산이 부족하면 `BUDGET_EXCEEDED`로 현재 Verification work를 중단하며 Pro/Con을 생략한 final verdict를 만들지 않는다.

`AnalysisRunState.status=RUNNING`이면 `analysis_result_ref=null`이다. `COMPLETE | PARTIAL | FAILED | CANCELLED`이면 `analysis_result_ref`가 필수이고 같은 `analysis_id`의 정확한 `AnalysisRunResult`를 가리킨다. 최종 상태와 결과는 atomic transition으로 함께 확정한다.

`ProposalProcessState`의 모든 revision은 `meta.hypothesis_id: null`을 유지한다. `SCHEMA_VALID` proposal을 가설로 등록할 때 새 `hypothesis_id`를 발급하고, 별도 `logical_record_id`의 `HypothesisProcessState.status=REGISTERED`를 만든다. 두 상태 record는 같은 `proposal_ref`로 연결하며 서로의 revision으로 취급하지 않는다.

진행 중인 상태는 `finished_at: null`이다. 종료 상태는 `finished_at`이 필수이며 `elapsed_ms`는 시작부터 종료까지 monotonic clock으로 계산한다. `NOT_REQUESTED`는 `started_at: null`, `finished_at: null`, `elapsed_ms: 0`이다. `DynamicReproductionState.status=BLOCKED`는 같은 work가 재시도 또는 외부 설정 수정을 기다리는 비종료 상태이므로 `finished_at: null`을 유지한다. `SUCCEEDED | PARTIAL | FAILED | CANCELLED`로 work를 닫을 때만 `finished_at`을 기록한다. 반면 각 `DynamicReproductionResult`는 한 attempt의 종료 기록이므로 해당 결과의 `finished_at`은 `null`일 수 없다.

`VerificationAssignment`은 Orchestration의 배정 제안을 신뢰 runtime이 검사한 뒤 만드는 저장 record다. `owner_identity_ref`는 한 hypothesis-local workflow의 논리 owner를 가리키며 Agent가 자기 출력으로 만들 수 없다. 최초 배정은 `assignment_generation=1`, `status=ACTIVE`다. 운영상 owner 교체가 필요하면 trusted recovery 또는 사람 승인 절차가 이전 assignment를 `SUPERSEDED`로 만들고 새 generation을 원자적으로 활성화한다. Technical `REVISE` 자체는 owner 교체 사유가 아니며 같은 ACTIVE assignment를 유지한다.

`HypothesisProcessState.status=REGISTERED`에서는 assignment·work·result reference가 `null`이고 `verification_generation=0`이다. `ASSIGNED | VERIFYING | TERMINAL | FAILED`에는 ACTIVE `verification_assignment_ref`가 필수다. `VERIFYING`은 현재 generation의 `verification_work_ref`가 필수이며, 최초 검증 전 `verification_result_ref=null`, Technical `REVISE` 보완 중에는 직전 final result ref를 유지할 수 있다. `TERMINAL`이면 `verification_work_ref=null`이고 `verification_result_ref.record_id`가 현재 가설의 exact final `VerificationResult` revision을 가리켜야 한다. `FAILED`는 검증 절차가 허용된 재시도를 소진했거나 복구 불가능한 오류로 끝나 final verdict를 만들지 못한 종료 상태다. 이때 `verification_work_ref`는 같은 `VERIFICATION` work의 `FAILED` revision을 가리키고 `verification_result_ref=null`이며, 오류와 미확인 범위는 해당 work·transition·최종 분석 결과에 보존한다. 동적 재현을 요청하면 `DynamicReproductionState.request_ref`는 current generation의 exact `DynamicReproductionRequest`를 가리킨다. `SUCCEEDED | PARTIAL`에는 `dynamic_result_ref.record_id`가 필수다. `BLOCKED | FAILED`는 실패 attempt의 `DynamicReproductionResult`를 조립했다면 그 exact reference를 사용하고, PoC candidate 또는 plan 생성 전에 실패해 결과를 조립하지 못했다면 `dynamic_result_ref=null`과 exact work·attempt·error reference를 유지한다. `NOT_REQUESTED`에서는 두 reference가 모두 `null`이고, `RUNNING`에서는 request가 필수이며 final result는 아직 `null`이다. `ReportProcessState.status=DRAFTED`이면 `report_draft_ref.record_id`가 필수이며 정확히 하나인 `ReportDraft` revision을 가리키고, `NOT_REQUESTED | FAILED`이면 `report_draft_ref=null`이다.

### 공통 실행 상태와 상태 변경

`WorkExecutionState`는 프로그램이 실행 순서와 복구를 관리하기 위한 상태다. 전문 결과의 의미를 대신하지 않는다. 예를 들어 `work_type=VERIFICATION` 작업이 `SUCCEEDED`라는 사실만으로 가설을 `TRUE`라고 판단할 수 없고, 반드시 그 작업이 가리키는 `VerificationResult.verdict`를 읽어야 한다.

```yaml
WorkExecutionState:
  meta: RunMeta | RecordMeta
  work_id: string
  parent_work_ref: RunStoredDataRef | StoredDataRef | null
  work_type: WORKSPACE_PREP | STATIC_TOOL | STATIC_NORMALIZE | HYPOTHESIS_PROPOSAL | CONTEXT_RETRIEVAL | PRO_EVIDENCE | CON_EVIDENCE | VERIFICATION | DYNAMIC_REPRO | PRIMITIVE_UPDATE | CHAINING | CWE_LABEL | POLICY_FETCH | TECHNICAL_GATE | RULE_SCOPE_GATE | REPORT_DRAFT
  subject_type: ANALYSIS | PROPOSAL | HYPOTHESIS | REPORT
  subject_id: string
  work_generation: integer
  status: PENDING | READY | RUNNING | BLOCKED | SUCCEEDED | PARTIAL | FAILED | CANCELLED
  state_version: integer
  last_transition_ref: RunStoredDataRef | StoredDataRef | null
  last_transition_commit_ref: RunStoredDataRef | StoredDataRef | null
  active_attempt_id: string | null
  input_hash: string
  dedupe_key: string
  input_refs: [RunStoredDataRef | StoredDataRef]
  output_refs: [RunStoredDataRef | StoredDataRef]
  gap_ids: [string]
  error_ids: [string]
  waiting_for: [RETRY | AUTH | APPROVAL | INPUT | BUDGET | DEPENDENCY]
  stop_reason: string | null
  started_at: timestamp | null
  finished_at: timestamp | null
  elapsed_ms: integer

WorkAttempt:
  meta: RunMeta | RecordMeta
  work_id: string
  attempt_id: string
  attempt_number: integer
  trigger: INITIAL | RETRY | RESUME
  input_hash: string
  status: RUNNING | SUCCEEDED | PARTIAL | FAILED | CANCELLED
  output_refs: [RunStoredDataRef | StoredDataRef]
  gap_ids: [string]
  error_ids: [string]
  started_at: timestamp
  finished_at: timestamp | null
  elapsed_ms: integer

StateTransition:
  meta: RunMeta | RecordMeta
  transition_id: string
  work_id: string
  action_decision_ref: RunStoredDataRef | StoredDataRef
  from_status: PENDING | READY | RUNNING | BLOCKED | SUCCEEDED | PARTIAL | FAILED | CANCELLED
  to_status: READY | RUNNING | BLOCKED | SUCCEEDED | PARTIAL | FAILED | CANCELLED
  expected_state_version: integer
  new_state_version: integer
  attempt_id: string | null
  cause: string
  output_refs: [RunStoredDataRef | StoredDataRef]
  gap_ids: [string]
  error_ids: [string]
  dedupe_key: string
  created_at: timestamp

TransitionCommit:
  meta: RunMeta | RecordMeta
  transition_commit_id: string
  work_id: string
  transition_ref: RunStoredDataRef | StoredDataRef
  expected_state_version: integer
  target_state_version: integer
  attempt_id: string | null
  target_status: BLOCKED | SUCCEEDED | PARTIAL | FAILED | CANCELLED
  output_refs: [RunStoredDataRef | StoredDataRef]
  gap_ids: [string]
  error_ids: [string]
  state: PREPARED | COMMITTED | ABORTED
  prepared_at: timestamp
  committed_at: timestamp | null
  abort_reason: string | null
```

`state_version`은 `1`부터 시작하고 승인된 전이마다 정확히 1 증가한다. runtime은 저장된 현재 version이 `expected_state_version`과 같을 때만 전이를 승인한다. 다르면 `STATE_VERSION_CONFLICT`로 거절하고 최신 상태를 다시 읽는다. `active_attempt_id`는 `RUNNING`일 때만 값이 있고 해당 작업의 현재 `WorkAttempt.attempt_id`와 같아야 한다. 한 `work_id`에는 활성 attempt가 하나만 존재한다.

`last_transition_ref`는 현재 상태를 만든 정확한 `StateTransition` revision을 가리키며 최초 `PENDING` record에서는 `null`이다. 결과를 함께 확정한 상태이면 `last_transition_commit_ref`가 그 atomic 저장의 `COMMITTED` `TransitionCommit` revision을 가리켜야 한다. `READY | RUNNING`처럼 결과를 확정하지 않는 전이는 `last_transition_commit_ref=null`일 수 있다. 두 reference는 저장 record를 가리키므로 `record_id`가 필수다.

`StateTransition.from_status`는 저장된 현재 상태와 같고 `new_state_version=expected_state_version+1`이어야 한다. `action_decision_ref.record_id`는 이 전이를 허용하고 이미 `use_status=USED`로 claim한 exact `ActionDecision` revision을 가리킨다. `TransitionCommit.transition_ref.record_id`는 그 전이의 저장 revision을 가리키고, `work_id`, expected/target version, attempt, target status, output refs, `gap_ids`와 `error_ids`가 `StateTransition`과 같아야 한다. `PREPARED`, `COMMITTED` 또는 `ABORTED`로 바뀔 때마다 같은 `logical_record_id`·`transition_commit_id`를 유지하고 새 `record_id`와 증가한 revision을 만든다. `PREPARED`는 `committed_at=null`, `abort_reason=null`, `COMMITTED`는 `committed_at`이 필수이고 `abort_reason=null`, `ABORTED`는 `abort_reason`이 필수다. `COMMITTED` 또는 `ABORTED` revision이 생기면 다시 다른 상태로 바꾸지 않는다.

허용 전이는 다음 표가 전부다. 표에 없는 전이는 `STATE_TRANSITION_INVALID`다.

| 현재 상태 | 허용되는 다음 상태 | 조건 |
|---|---|---|
| `PENDING` | `READY`, `CANCELLED` | 앞 단계와 입력이 준비되거나 취소됨 |
| `READY` | `RUNNING`, `BLOCKED`, `CANCELLED` | 실행 전 검사를 통과하거나 외부 조건이 부족함 |
| `RUNNING` | `BLOCKED`, `SUCCEEDED`, `PARTIAL`, `FAILED`, `CANCELLED` | attempt 결과와 atomic transition이 있음 |
| `BLOCKED` | `READY`, `FAILED`, `CANCELLED` | 대기 조건을 충족하거나 더 진행할 수 없음 |
| `SUCCEEDED`, `PARTIAL`, `FAILED`, `CANCELLED` | 없음 | 종료 상태를 되돌리지 않음 |

상태별 필드 조건은 다음과 같다.

- `PENDING | READY`는 `active_attempt_id=null`, 빈 `output_refs`와 빈 `waiting_for`를 사용한다.
- `RUNNING`은 `active_attempt_id`, `started_at`이 필수이고 `finished_at=null`이다.
- `BLOCKED`는 `active_attempt_id=null`, 하나 이상의 `waiting_for`와 구체적인 `stop_reason`이 필요하다.
- `SUCCEEDED | PARTIAL | FAILED | CANCELLED`는 `active_attempt_id=null`, `finished_at`과 `stop_reason`이 필요하다. 정상 `SUCCEEDED`의 `stop_reason`은 `COMPLETED`다.
- `PARTIAL`은 `STATIC_TOOL | STATIC_NORMALIZE | CONTEXT_RETRIEVAL | DYNAMIC_REPRO`에서만 허용하고 하나 이상의 신뢰 가능한 `output_refs`가 필요하다. static·context 작업은 누락을 설명하는 `error_ids` 또는 `gap_ids`가 필요하다. `DYNAMIC_REPRO`는 정확히 하나의 `DynamicReproductionResult(status=PARTIAL, failure_reason=NONE)`를 가리키고 그 결과의 `hypothesis_evidence_refs`와 `limitations`가 각각 하나 이상이면 이 구조화된 `limitations`가 부분 실행의 누락 설명을 대신한다. 실제 오류나 `DataGap`이 없는데 동적 재현의 정상적인 환경 한계를 억지로 `error_ids`나 `gap_ids`로 만들지 않는다.
- `FAILED`는 하나 이상의 `error_ids`가 필요하다. 전문 schema가 실패 결과 record를 정의한 `DYNAMIC_REPRO` 같은 작업은 그 실패 record를 `output_refs`에 포함할 수 있지만 성공 결과로 해석하지 않는다.
- `DYNAMIC_REPRO` 취소 전이는 현재 활성 attempt가 만든 `DynamicReproductionResult(status=CANCELLED)`를 같은 atomic transition에서 확정할 수 있다. 이미 `CANCELLED`가 확정된 뒤 늦게 도착한 output은 현재 상태에 연결하지 않는다.
- `WorkExecutionState.elapsed_ms`는 완료된 `WorkAttempt.elapsed_ms`의 합이다. block 대기 시간과 프로세스가 꺼진 시간은 별도 상태 체류 지표로 기록하며 실행 시간에 더하지 않는다.
- `WorkAttempt.attempt_number`는 한 `work_id` 안에서 1부터 1씩 증가하고, `WorkAttempt.input_hash`는 그 attempt를 시작할 때의 `WorkExecutionState.input_hash`와 같다. `RecordMeta`를 쓰면 `meta.attempt_id`도 `WorkAttempt.attempt_id`와 같아야 한다.

`WORKSPACE_PREP`과 commit 준비 전에 만든 실행 상태는 모든 revision에서 `RunMeta`를 유지한다. workspace·commit 준비 뒤 등록한 work는 모든 revision에서 `RecordMeta`를 유지한다. `WorkExecutionState`는 여러 attempt를 묶으므로 `RecordMeta`를 쓸 때도 `meta.attempt_id=null`이다. `WorkAttempt`·`StateTransition`·`TransitionCommit`이 `RecordMeta`를 쓰고 attempt가 원인이면 `meta.attempt_id`와 본문 `attempt_id`가 같아야 한다. `RunMeta`에는 attempt 필드가 없으므로 pre-workspace record는 본문 `attempt_id`로만 연결한다. dependency 준비·사람 취소처럼 attempt 밖에서 일어난 전이는 본문과, 존재하는 경우 `meta.attempt_id`를 모두 `null`로 둔다.

`parent_work_ref`는 작업의 직접 부모를 가리키는 선택 필드다. `PRO_EVIDENCE | CON_EVIDENCE | DYNAMIC_REPRO`에서는 필수이며, 같은 가설과 현재 `verification_generation`의 `VERIFICATION` work exact revision을 가리켜야 한다. `DYNAMIC_REPRO`의 request와 부모 Verification은 같은 `hypothesis_id`와 `verification_generation`이어야 한다. 나머지 work type은 이 문서가 별도 부모 관계를 정하지 않는 한 `null`이다. 자식 work의 `subject_id`와 부모 Verification의 `subject_id`는 같은 `hypothesis_id`여야 하며, 부모가 교체되거나 generation이 바뀌면 기존 자식 결과를 새 부모에 연결하지 않는다.

재시도 가능한 attempt 실패는 `WorkAttempt.status=FAILED`와 오류를 보존하고 작업을 `BLOCKED`로 전환한다. 재인증·backoff·repair·예산 승인처럼 `waiting_for` 조건을 충족하면 `READY`로 이동하고 `attempt_number`가 1 증가한 새 `attempt_id`를 발급한다. 재시도할 수 없거나 한도를 사용한 때만 작업을 최종 `FAILED`로 끝낸다. 종료된 작업을 되돌리지 않는다. 사람이 같은 입력으로 새 논리 실행을 명시적으로 승인하면 이전 값보다 1 큰 `work_generation`과 새 `work_id`를 만들고, 두 작업을 restart 관계로 debug trace에 연결한다.

운영 Pro/Con 자식 중 하나가 재시도 가능한 오류로 `BLOCKED`가 되면 부모 `VERIFICATION` work도 `BLOCKED`가 되고 같은 실제 대기 이유를 `waiting_for`에 기록한다. 가설 상태는 `VERIFYING`을 유지하며 final `VerificationResult`를 만들지 않는다. 자식 `BLOCKED`가 먼저 보인 짧은 구간에도 runtime은 부모의 새 attempt·합성·결과 저장을 거절하고 recovery가 부모 상태를 맞춘다. 입력·부모 generation·Debate 설정이 그대로이면 성공한 다른 자식 결과는 보존할 수 있고 실패한 역할만 새 attempt와 새 `llm_call_id`, 새 `NEW` session으로 재시도한다. 하나라도 달라지면 기존 두 자식 결과를 모두 `STALE_RESULT`로 격리하고 Pro와 Con을 다시 실행한다.

자식이 복구 불가능하거나 허용된 재시도를 모두 소진하면 먼저 그 자식 work의 `FAILED`를 자기 `COMMITTED` `TransitionCommit`으로 확정한다. 이 상태가 보이는 즉시 부모 `VERIFICATION`의 새 실행·합성·결과 저장은 금지한다. 이어서 부모 work의 `FAILED`와 `HypothesisProcessState.status=FAILED`를 기존 Verification 실패 atomic 경계로 함께 확정하고, 가설은 부모의 exact failed work를 가리키며 `verification_result_ref=null`을 유지한다. 두 번째 확정 전에 중단되면 recovery가 `parent_work_ref`와 실패 자식의 commit을 읽어 전파를 끝낼 때까지 부모를 진행시키지 않는다. 취소된 자식은 retry/failover 선행 호출로 사용할 수 없고, 부모가 취소·교체·종료된 뒤 도착한 결과는 `STALE_RESULT`로 격리한다. 어느 오류도 `FALSE | HOLD`로 바꾸지 않는다.

`work_generation`은 같은 분석·작업 종류·대상·입력에서 1부터 시작한다. 일반 retry와 resume에서는 바꾸지 않고, 종료 상태 뒤 사람이 승인한 명시적 restart에서만 1 증가한다. `dedupe_key`는 `analysis_id`, `work_type`, `subject_id`, `work_generation`, 정렬된 입력의 `record_id + content_hash`, 적용한 설정·정책 revision을 canonical JSON으로 만든 SHA-256 값이다. `attempt_id`, 시각과 worker 이름은 넣지 않는다. 같은 generation과 key의 요청이 다시 오면 새 작업을 만들지 않고 기존 `work_id`와 현재 상태를 반환한다. 입력 revision·적용 설정·승인된 generation이 바뀌면 새 `dedupe_key`와 새 `work_id`를 만든다.

`REGISTER_WORK(work_type=VERIFICATION)` 시 trusted runtime은 해당 검증에 적용할 current exact `VerificationPlaybook` revision을 선택하고 그 `StoredDataRef`를 `WorkExecutionState.input_refs`에 포함한다. 해당 reference의 `record_id`와 `content_hash`는 work의 `input_hash`와 `dedupe_key`에도 반영한다.

플레이북의 current revision이 검증 도중 변경되더라도 진행 중인 work의 입력을 새 revision으로 바꾸지 않는다. 기존 revision으로 계속 수행할 수 있으며, 새 revision을 적용하려면 기존 결과와 섞지 않고 새 Verification work 또는 새 verification generation을 만들어야 한다. 단순 retry는 기존 work에 고정된 playbook revision을 유지한다.

`REVISE`는 일반 retry나 resume이 아니다. Technical Gate가 유효한 `TechnicalEvidenceReview.status=REVISE`를 확정하면 기존 Gate work는 `SUCCEEDED`로 종료하고 그 review를 같은 hypothesis의 ACTIVE `VerificationAssignment` owner에게 전달한다. runtime은 `HypothesisProcessState.status=TERMINAL`, 그 상태의 `verification_result_ref`가 Gate가 검토한 exact revision, assignment가 여전히 ACTIVE인지 compare-and-set으로 확인한다. 그 뒤 종료된 기존 VERIFICATION work를 되돌리지 않고 `verification_generation + 1`인 새 `WorkExecutionState(work_type=VERIFICATION)`를 등록하며, 같은 atomic transition에서 hypothesis 상태를 `VERIFYING`, `finished_at=null`, `verification_work_ref=새 work`, `verification_result_ref=직전 final result`로 갱신한다. 새 work의 input에는 exact REVISE review와 직전 Verification/CWE reference가 들어간다.

같은 owner가 새 work에서 보완을 마치면 새 `VerificationResult`와 새 VERIFICATION work의 `SUCCEEDED`, `HypothesisProcessState.status=TERMINAL`, 새 `verification_result_ref`, `verification_work_ref=null`을 한 atomic commit으로 확정한다. CWE 보완이 필요하면 기존 CWE producer가 새 `CWELabel` revision을 만든 뒤에만 새 Technical Gate work를 등록한다. 새 Gate 작업은 달라진 `input_refs`, `input_hash`, `dedupe_key`, `work_id`를 사용하고 첫 `WorkAttempt`는 새 `attempt_id`, `attempt_number=1`, `trigger=INITIAL`을 사용한다. 이전 Gate review와 새 review는 `RecordMeta.previous_record_id`로 이어지는 같은 논리 record의 revision chain에 남긴다. 반대로 provider timeout이나 일시 오류처럼 domain input이 바뀌지 않은 일반 retry는 같은 `work_id`·`dedupe_key`·`input_hash`를 유지하고 새 `attempt_id`와 `trigger=RETRY`를 사용한다. 동일 입력의 새 attempt만 만들어 `REVISE`를 다시 투표하거나 과거 Gate reference를 새 Verification revision에 재사용하는 것은 금지한다.

| `work_type` | 등록 요청 주체 | 실행·출력 생산자 | `SUCCEEDED` 또는 `PARTIAL`이 가리키는 결과 |
|---|---|---|---|
| `WORKSPACE_PREP` | 분석 입력 runtime | Repository Loader | 준비된 `CodeWorkspace` |
| `STATIC_TOOL` | Orchestration runtime | AST/SAST runner | `ToolRunResult`, 규칙 기반 도구이면 exact `RuleExecutionRecord` |
| `STATIC_NORMALIZE` | Orchestration runtime | Static Fact Normalizer | `StaticFactBundle` |
| `HYPOTHESIS_PROPOSAL` | global registration runtime | Hypothesis·Verification·Chaining 출력 검증 runtime | schema-valid `HypothesisProposal[]` |
| `CONTEXT_RETRIEVAL` | 허용된 Agent Runtime | Context Retrieval Service | `CodeContextResponse` |
| `PRO_EVIDENCE` | Verification runtime | Pro Agent | exact `EvidenceAgentResult(role=PRO)` |
| `CON_EVIDENCE` | Verification runtime | Con Agent | exact `EvidenceAgentResult(role=CON)` |
| `VERIFICATION` | Orchestration의 배정 뒤 Verification runtime | Verification runtime | final `VerificationResult` |
| `DYNAMIC_REPRO` | Verification의 `REQUEST_DYNAMIC_REPRO`를 Runtime Validator가 허가 | R7 Dynamic Reproduction·Sandbox runtime | request·requirements·plan·PoC candidate와 실행 결과가 연결된 `DynamicReproductionResult` |
| `PRIMITIVE_UPDATE` | final HOLD의 Verification 또는 Technical-accepted TRUE admission runtime | Primitive 저장 runtime | 새 `Primitive`와 가설별 `PrimitiveIndexState` revision |
| `CHAINING` | Verification handoff 뒤 Chaining runtime | Chaining runtime | `ChainingResult` |
| `CWE_LABEL` | Verification workflow의 요청 뒤 CWE labeling runtime | CWE labeling runtime | `CWELabel` |
| `POLICY_FETCH` | Rule Scope Gate 준비 runtime | 공식 정책 수집 runtime | `ProgramPolicyRecord` |
| `TECHNICAL_GATE` | Verification runtime | Technical Gate runtime | `TechnicalEvidenceReview` |
| `RULE_SCOPE_GATE` | Verification runtime | Rule Scope Gate runtime | `RuleScopeImpactReview` |
| `REPORT_DRAFT` | Reporter 조건 검사 runtime | Reporter runtime | `ReportDraft` |

`DYNAMIC_REPRO`는 공통 작업 상태와 전문 결과 상태를 다음처럼 연결한다. 공통 상태는 “현재 work가 완료·대기·실패 중 어느 상태인가”를 나타내고 전문 상태는 “재현이 얼마나 수행되었는가”를 나타낸다.

| `DynamicReproductionResult.status` | `WorkExecutionState.status` | 저장 조건과 다음 처리 |
|---|---|---|
| `SUCCEEDED` | `SUCCEEDED` | 계획한 실행과 관측을 끝낸 결과를 저장한다. 가설 지지 여부는 `hypothesis_outcome`을 읽는다. |
| `PARTIAL` | `PARTIAL` | 신뢰 관측과 `limitations`가 있는 부분 실행 결과를 저장한다. 오류나 `DataGap`을 억지로 만들지 않는다. |
| `FAILED` | `FAILED` | 복구 불가능하거나 retry 한도를 소진한 실패 결과와 하나 이상의 `error_ids`를 저장한다. final verdict와 Gate는 없다. |
| `BLOCKED` | `BLOCKED` | PoC 생성·외부 설정·환경·정책·실행 문제를 해결한 뒤 같은 work의 새 attempt로 재시도한다. final verdict와 Gate는 없다. |
| `CANCELLED` | `CANCELLED` | 취소 이유와 취소 결과를 같은 transition에서 저장한다. 취소 확정 뒤 늦은 결과는 격리한다. |

공통 `WorkExecutionState.status=BLOCKED`는 retry, 인증, 승인, 외부 설정 또는 입력처럼 다음 조건을 기다리는 비종료 상태다. 실패 attempt의 `DynamicReproductionResult(status=BLOCKED)`를 output history에 보존할 수 있지만 validated PoC나 final verdict로 소비하지 않는다. 조건이 해결되면 같은 `work_id`에서 새 `attempt_id`를 만들며 새 `work_generation`을 만들지 않는다.

작업 모듈과 Agent는 등록 또는 상태 변경을 요청할 뿐 직접 확정하지 않는다. 모든 행의 `StateTransition` 승인과 저장은 신뢰 경계 안의 state transition validator와 state store가 담당한다. Orchestration Agent의 자연어 출력은 상태 변경 명령으로 직접 실행하지 않는다.

결과 record, `StateTransition`과 그 결과를 가리키는 종료 상태는 하나의 논리적 atomic transition으로 확정한다. 저장 제품이 한 transaction을 지원하면 같은 transaction에서 처리한다. 지원하지 않으면 `TransitionCommit` journal을 사용한다. `PREPARED` 출력은 격리 상태이며 다음 단계가 읽을 수 없다. state store는 현재 version·active attempt·입력이 그대로라는 조건을 compare-and-set으로 확인하면서 unique `(work_id, target_state_version)` key의 `COMMITTED` revision을 append한다. 경쟁 중 하나만 성공하며 이 marker가 논리적 확정점이다. runtime은 marker를 `WorkExecutionState`와 전문 상태 pointer에 투영한다. 소비자는 COMMITTED marker와 두 pointer가 모두 같은 output을 가리킬 때만 진행한다. marker 뒤 projection 전에 중단되면 recovery가 marker를 재적용한다. version 충돌, 취소 또는 검증 실패는 `ABORTED`이며 output을 최신 상태에 연결하지 않는다.

state store는 새 전이를 승인하기 전에 `(work_id, current_state_version+1)`의 미완료 journal을 먼저 확인한다. `COMMITTED` marker가 있으면 기존 marker를 상태와 전문 pointer에 재투영하고 경쟁 요청을 `STATE_VERSION_CONFLICT`로 거절한다. `PREPARED`가 있으면 복구 또는 `ABORTED` 처리를 끝내기 전까지 새 전이를 받지 않는다. 따라서 marker와 pointer 사이의 짧은 중단 구간을 이용해 취소·retry·다른 결과가 같은 version을 차지할 수 없다.

다음 output binding은 필수다.

- `STATIC_TOOL` attempt의 `ToolRunResult.tool_kind=RULE_BASED`이고 그 status가 `SUCCEEDED | PARTIAL | SKIPPED`이면 `rule_execution_ref`와 같은 exact `RuleExecutionRecord`를 output으로 함께 확정한다. 두 결과의 attempt·도구·workspace·commit이 다르면 다음 단계에 전달하지 않는다.
- `VERIFICATION`의 `SUCCEEDED`와 `HypothesisProcessState.status=TERMINAL`은 같은 final `VerificationResult.record_id`를 가리킨다.
- retry 가능한 `VERIFICATION` work가 `BLOCKED`이면 가설은 `VERIFYING`을 유지하고 `verification_work_ref`가 그 work revision을 가리킨다. 재시도를 소진했거나 복구 불가능한 경우에는 같은 atomic transition에서 `VERIFICATION`의 `FAILED`와 `HypothesisProcessState.status=FAILED`를 확정한다. 이때 가설의 `verification_work_ref`는 실패한 exact work revision, `verification_result_ref=null`이어야 하며 final verdict나 Gate 입력을 만들지 않는다.
- `DYNAMIC_REPRO`의 종료 transition은 위 매핑을 만족해야 하며 `WorkExecutionState.output_refs`, `TransitionCommit.output_refs`와 `DynamicReproductionState.dynamic_result_ref`가 같은 `DynamicReproductionResult.record_id`를 가리킨다. Verification은 `COMMITTED` marker와 세 reference가 모두 맞을 때만 이 결과를 읽는다.
- `TECHNICAL_GATE`의 `SUCCEEDED`는 정확히 하나의 `TechnicalEvidenceReview.record_id`를 가리킨다.
- `RULE_SCOPE_GATE`의 `SUCCEEDED`는 정확히 하나의 `RuleScopeImpactReview.record_id`를 가리킨다.
- `REPORT_DRAFT`의 `SUCCEEDED`와 `ReportProcessState.status=DRAFTED`는 같은 `ReportDraft.record_id`를 가리킨다.
- 분석 종료 transition과 `AnalysisRunState.analysis_result_ref`는 같은 `AnalysisRunResult`를 가리킨다.
- 각 reference의 workspace, commit, hypothesis, `record_id`와 `content_hash`는 실제 record와 일치한다.

Gate domain input set은 Gate가 판단 대상으로 읽는 저장 record의 정확한 revision 집합이다. `TECHNICAL_GATE`에서는 `VerificationResult`와 `CWELabel` reference가 정확한 domain input set이고, `RULE_SCOPE_GATE`에서는 `VerificationResult`, `TechnicalEvidenceReview`, `CWELabel`과 존재하는 `ProgramPolicyRecord` reference가 정확한 domain input set이다. prompt·provider·실행 설정 reference는 전체 `WorkExecutionState.input_refs`에 추가할 수 있지만 domain input으로 가장하거나 domain input을 대신할 수 없다.

Gate work를 등록할 때 runtime은 전체 `input_refs`를 정렬해 `input_hash`와 `dedupe_key`를 만들고 해당 `work_id`가 끝날 때까지 바꾸지 않는다. Gate 결과를 확정할 때는 다음을 같은 atomic transition에서 확인한다.

- `TechnicalEvidenceReview` 안의 `verification_result_ref`와 `cwe_label_ref`는 Technical Gate work의 domain input 두 개와 각각 exact match여야 한다.
- `RuleScopeImpactReview` 안의 `verification_result_ref`, `technical_review_ref`, `cwe_label_ref`, `policy_record_ref`는 Rule Scope Gate work의 domain input set과 exact match여야 한다.
- `TransitionCommit`이 가리키는 `work_id`, target state version과 output `record_id`가 확정되는 동안 현재 work의 `input_hash`가 등록 시 값과 같아야 한다.
- input revision이 바뀌거나 결과 안의 reference가 다르면 `RECORD_REVISION_MISMATCH` 또는 `STALE_RESULT`로 `ABORTED`하고, 이전 Gate 결과를 교체·재사용하거나 다음 단계에 전달하지 않는다.

분석을 `COMPLETE | PARTIAL | FAILED | CANCELLED`로 닫기 전에 runtime은 해당 `analysis_id`에 `RUNNING` work, 복구되지 않은 `PREPARED` journal과 output pointer가 없는 종료 상태가 없는지 확인한다. `PENDING | READY | BLOCKED` work는 각각 완료, 명시적 실패 또는 취소로 정리하고 그 이유를 `AnalysisRunResult`에 포함한다.

결과를 반영할 때 runtime은 작업이 `RUNNING`이고 결과의 `attempt_id`가 `active_attempt_id`이며, `expected_state_version`, `input_hash`, workspace, commit과 hypothesis가 현재 작업과 같은지 확인한다. 늦은 이전 attempt 결과는 `ATTEMPT_NOT_ACTIVE`, 취소·입력 변경·revision 변경 뒤 도착한 결과는 `STALE_RESULT`로 거절한다. 디버깅용으로 격리할 수는 있지만 Gate, Reporter와 최신 결과 pointer에 연결하지 않는다.

### 실행 요청과 runtime 검사

LLM Agent와 실행 서비스는 상태·도구·Gate와 보고서를 직접 바꾸지 않고 `ActionRequest`를 만든다. 비-LLM runtime validator는 action별 필수 검사를 수행해 `ActionDecision`을 저장한다. 이는 취약점 의미를 판단하는 새 Gate가 아니라 실행 가능 범위만 확인하는 경계다.

```yaml
ActionRequest:
  meta: RunMeta | RecordMeta
  action_id: string
  requested_by: ORCHESTRATION | HYPOTHESIS | PRO | CON | VERIFICATION | CWE_LABELING | CHAINING | TECHNICAL_GATE | RULE_SCOPE_GATE | REPORTER | REPOSITORY_LOADER | STATIC_ANALYSIS | POLICY_COLLECTOR | SANDBOX | RECOVERY
  requester_identity_ref: RunStoredDataRef | StoredDataRef
  action_type: REGISTER_WORK | CHANGE_WORK_STATE | START_ATTEMPT | CANCEL_WORK | READ_CODE | RUN_TOOL | CALL_LLM | FETCH_POLICY | REQUEST_DYNAMIC_REPRO | RUN_SANDBOX | SAVE_RESULT | CALL_TECHNICAL_GATE | CALL_RULE_SCOPE_GATE | CREATE_REPORT_DRAFT
  work_ref: RunStoredDataRef | StoredDataRef | null
  expected_state_version: integer | null
  input_refs: [RunStoredDataRef | StoredDataRef]
  dynamic_request_ref: StoredDataRef | null
  reproduction_plan_ref: StoredDataRef | null
  result_kind: string | null
  candidate_result_ref: RunStoredDataRef | StoredDataRef | null
  llm_call_spec_ref: StoredDataRef | null
  tool_name: string | null
  file_paths: [string]
  provider_profile_ref: RunStoredDataRef | StoredDataRef | null
  session_mode: NEW | RESUME | AUTO | null
  sandbox_profile_ref: RunStoredDataRef | StoredDataRef | null
  image_digest: string | null
  network_targets: [string]
  resource_limits: map | null
  reason: string
  requested_at: timestamp

ActionCheck:
  check_type: SCHEMA | AUTHORITY | IDENTITY | REVISION | STATE | BUDGET | TOOL | FILE_PATH | PROVIDER | SESSION | GATE_ORDER | REPORT_READY | REDACTION
  result: PASS | FAIL
  reason_code: string
  safe_message: string

ActionDecision:
  meta: RunMeta | RecordMeta
  decision_id: string
  action_ref: RunStoredDataRef | StoredDataRef
  decision: ALLOW | DENY
  required_checks: [SCHEMA | AUTHORITY | IDENTITY | REVISION | STATE | BUDGET | TOOL | FILE_PATH | PROVIDER | SESSION | GATE_ORDER | REPORT_READY | REDACTION]
  check_results: [ActionCheck]
  checked_state_version: integer | null
  checked_config_refs: [RunStoredDataRef | StoredDataRef]
  valid_until: timestamp | null
  error_ids: [string]
  use_status: UNUSED | USED | NOT_USED | EXPIRED
  used_at: timestamp | null
  expired_at: timestamp | null
  expire_reason: string | null
  outcome_refs: [RunStoredDataRef | StoredDataRef]
  decided_at: timestamp
```

`requester_identity_ref`는 LLM output에서 복사하지 않고 신뢰 runtime이 현재 인증된 Agent service identity에서 넣는다. 그 identity에 등록된 역할이 `requested_by`와 다르면 `AUTHORITY` check는 `FAIL`이다. `ActionRequest`는 해당 요청을 가리키는 `ActionDecision`이 하나라도 저장된 뒤에는 수정하지 않는다. 입력, 실행 범위 또는 설정을 바꾸려면 새 `action_id`와 새 request record를 만든다. `action_ref.record_id`는 검사한 정확한 `ActionRequest` revision을 가리킨다. `ActionDecision.meta`는 action과 같은 metadata 종류와 analysis·workspace·commit·hypothesis를 유지한다. `work_ref`가 있으면 `expected_state_version`이 필수이고 validator가 읽은 현재 work version과 같아야 한다.

action type별 `required_checks`는 아래 표와 정확히 같아야 한다. `check_results`에는 각 필수 check가 중복 없이 한 번씩 있어야 한다. 하나라도 `FAIL`이면 `decision=DENY`, `valid_until=null`, `use_status=NOT_USED`와 하나 이상의 `error_ids`가 필요하다. 모두 `PASS`일 때만 `ALLOW`이며 최초 revision은 `valid_until>decided_at`, `use_status=UNUSED`, `used_at=null`, `expired_at=null`, `expire_reason=null`, 빈 `outcome_refs`와 빈 `error_ids`를 사용한다. `valid_until`의 최대 길이는 action·provider·Sandbox별 versioned runtime policy에서 제한한다.

한 `action_ref.record_id`에는 정확히 하나의 `decision_id`와 하나의 `ActionDecision.logical_record_id`만 허용한다. validator는 unique constraint와 atomic create-or-read로 이 연결을 저장한다. 같은 request를 동시에 검사하면 새 decision을 만들지 않고 이미 저장된 exact decision을 반환한다. 이후 상태 변화는 그 logical decision의 revision으로만 기록한다. 다시 검사하거나 retry하려면 새 `action_id`의 `ActionRequest`를 만든다.

| `use_status` | 필수 값 | 금지 값 |
|---|---|---|
| `UNUSED` | `decision=ALLOW`, 미래의 `valid_until` | `used_at`, `expired_at`, `expire_reason`, `outcome_refs` |
| `USED` | `decision=ALLOW`, `used_at<=valid_until` | `expired_at`, `expire_reason` |
| `EXPIRED` | `decision=ALLOW`, `expired_at`, 비어 있지 않은 `expire_reason` | `used_at`, `outcome_refs` |
| `NOT_USED` | `decision=DENY`, 하나 이상의 `error_ids` | `valid_until`, `used_at`, `expired_at`, `expire_reason`, `outcome_refs` |

`ActionDecision` revision 사이에서 `decision`, `action_ref`, `required_checks`, `check_results`, `checked_state_version`, `checked_config_refs`, `valid_until`, `decided_at`은 바꾸지 않는다. 이후 revision은 사용 상태·사용/만료 시각·만료 이유와 append-only `outcome_refs`만 갱신할 수 있다.

실행 runtime은 부작용 직전에 현재 시각이 `valid_until`을 넘지 않았는지, requester identity와 권한이 아직 유효한지, 현재 state version·남은 budget·exact input refs·checked config refs가 아직 같은지 다시 확인한다. 하나라도 달라졌으면 compare-and-set으로 `UNUSED -> EXPIRED` revision을 만들고 `expired_at`, `expire_reason`을 기록한 뒤 실행하지 않는다. 모두 같으면 compare-and-set으로 `UNUSED -> USED`로 바꾼다. claim revision에는 새 `record_id`와 `used_at`을 기록하고 `outcome_refs`는 아직 비어 있을 수 있다. 실행 결과가 생기면 `USED`를 유지한 다음 revision에 exact outcome refs를 추가한다. `USED`, `NOT_USED`, `EXPIRED`는 되돌리지 않는다. 따라서 `ALLOW`는 같은 `action_id`, action `record_id`, state version, 입력·설정 revision에서 한 번만 사용할 수 있고 retry·다른 action·새 revision에 재사용하지 않는다. claim 뒤 실행이 시작되지 않았거나 outcome 저장 전에 중단되면 오류를 남기고 새 action을 요청하며 기존 결정을 다시 쓰지 않는다.

action이 만든 output의 `action_decision_ref.record_id`는 `UNUSED -> USED`를 처음 claim했고 아직 `outcome_refs`가 비어 있는 revision을 가리킨다. output이 저장된 뒤 만드는 다음 decision revision만 log와 output refs를 append한다. output은 그 후속 decision revision을 역참조하지 않는다. 이 단방향 순서로 content hash 순환을 막는다.

| `action_type` | `required_checks` | 핵심 조건 |
|---|---|---|
| `REGISTER_WORK` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET | 같은 `dedupe_key`면 기존 work 반환 |
| `CHANGE_WORK_STATE` | SCHEMA, AUTHORITY, IDENTITY, STATE | PENDING·READY·BLOCKED 사이의 허용 전이와 recovery 전이만 수행 |
| `START_ATTEMPT` | SCHEMA, AUTHORITY, STATE, BUDGET | active attempt 하나, 종료 work 재시작 금지 |
| `CANCEL_WORK` | SCHEMA, AUTHORITY, IDENTITY, STATE | 취소 범위·요청 주체 확인, 이미 끝난 work 변경 금지 |
| `READ_CODE` | SCHEMA, AUTHORITY, IDENTITY, REVISION, BUDGET, FILE_PATH | workspace root 밖 경로 금지 |
| `RUN_TOOL` | SCHEMA, AUTHORITY, REVISION, BUDGET, TOOL, FILE_PATH | allowlist tool만 실행 |
| `CALL_LLM` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, REDACTION | 새 `llm_call_id`, explicit retry/failover |
| `FETCH_POLICY` | SCHEMA, AUTHORITY, BUDGET, TOOL, REDACTION | 승인된 공식 source만 정책 후보로 저장 |
| `REQUEST_DYNAMIC_REPRO` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET | R6의 exact `DynamicReproductionRequest`와 generation별 단일 동적 work를 확인해 R7에 전달 |
| `RUN_SANDBOX` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET | R7의 current work, exact request·`ReproductionPlan`·`EnvironmentRequirements`·PoC candidate와 profile을 확인해 Sandbox Controller 호출만 허가 |
| `SAVE_RESULT` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, REDACTION | 역할별 생산 권한, exact input, 환경 요구사항·실제 환경·승인 계획·실행 log 일치, atomic commit |
| `CALL_TECHNICAL_GATE` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, GATE_ORDER, REDACTION | validated PoC가 연결된 final TRUE Verification+CWE의 COMMITTED revision과 exact LLM call spec 필요 |
| `CALL_RULE_SCOPE_GATE` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, GATE_ORDER, REDACTION | `TRUE`+Technical `ACCEPT` exact refs와 exact LLM call spec 필요 |
| `CREATE_REPORT_DRAFT` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, REPORT_READY, REDACTION | current Finding, PASS/PASS/PASS/SUFFICIENT/ALLOW와 exact LLM call spec 필요 |

Gate와 Reporter action의 기존 check는 다음 exact revision을 검사한다. 검사는 `ActionDecision`을 만들 때와 실제 provider 호출 직전에 같은 기준으로 다시 수행한다.

`REQUEST_DYNAMIC_REPRO`의 ALLOW는 R6 요청을 R7의 한 `DYNAMIC_REPRO` work로 등록할 수 있다는 뜻이다. Runtime Validator는 `(analysis_id, hypothesis_id, verification_generation, work_type=DYNAMIC_REPRO)` unique key를 강제하고 같은 generation에서 purpose가 다른 두 번째 request나 work를 거절한다. `RUN_SANDBOX`의 `ActionDecision=ALLOW`는 Docker 실행 성공이나 Sandbox 정책 통과를 뜻하지 않는다. Runtime Validator는 R7 호출자의 권한, 현재 work·attempt와 예산, 변경되지 않은 exact request·`ReproductionPlan`, 그 계획이 가리키는 current `EnvironmentRequirements`, PoC candidate와 request의 exact Sandbox profile까지 검사한다. 이후 Sandbox Controller가 plan closure의 image digest, command/tool allowlist, mount·file path, network target, CPU·memory·disk·process·time limit, non-root와 cleanup 정책을 전담 검사하고 exact 정책 판정을 저장한다. 정책을 통과한 계획만 Sandbox Runner가 실행하며, 정책 거절은 `policy_decision_ref`가 필수인 `DynamicReproductionResult(status=BLOCKED, failure_reason=POLICY_BLOCKED, poc_ref=null)`로 기록한다. R7이 retry에서 새 requirements·plan·candidate revision을 만들더라도 R6의 request 목적·가설·profile을 바꾸거나 이 검사를 생략할 수 없다.

- Technical Gate의 `REVISION`은 action `input_refs`와 call spec context가 final `VerificationResult(verdict=TRUE)`와 `CWELabel`의 정확한 `record_id`·`content_hash`를 가리키는지 검사한다. 이 TRUE의 `dynamic_request_ref`, `dynamic_result_ref`, `poc_ref`는 current Verification generation의 exact request, `SUCCEEDED + SUPPORTED` 결과와 validated PoC를 가리켜야 한다. Gate 출력의 `TechnicalEvidenceReview.verification_result_ref`와 `cwe_label_ref`도 바로 이 두 record를 가리켜야 한다. `GATE_ORDER`는 모든 결과가 현재 work에서 `COMMITTED`됐고 final인지 검사한다. validated PoC가 없는 TRUE, HOLD와 FALSE는 Technical Gate action을 만들 수 없다.
- Rule Scope Gate의 `REVISION`은 같은 Verification·CWE revision과 `RuleScopeImpactReview.technical_review_ref`가 가리킬 exact `TechnicalEvidenceReview` record를 검사한다. `GATE_ORDER`는 Technical review가 그 두 revision을 검토한 `ACCEPT`이고 Verification verdict가 `TRUE`인지 검사한다.
- Reporter의 `REVISION`은 Reporter action, call spec과 context가 current Finding, 두 Gate가 실제로 검토한 같은 Verification·CWE revision, exact Technical·Rule Scope review와 존재하는 정책 revision을 가리키는지 검사한다. `REPORT_READY`는 Finding이 존재하고 그 exact 결과가 보고 조건을 모두 통과했는지 검사한다.

세 hypothesis-local stage action의 `requested_by`는 VERIFICATION이다. runtime은 action의 `meta.hypothesis_id`, 현재 `HypothesisProcessState.verification_assignment_ref`, 그 ACTIVE `VerificationAssignment.owner_identity_ref`와 `ActionRequest.requester_identity_ref`를 exact 비교한다. 배정되지 않은 Verification-role identity나 superseded assignment가 요청하면 `AUTHORITY_DENIED`다. `CALL_TECHNICAL_GATE`의 REVISE output은 같은 assignment owner에게만 전달한다. `CALL_RULE_SCOPE_GATE`와 `CREATE_REPORT_DRAFT`도 그 owner가 제안하되 Runtime Validator가 exact Gate 순서와 보고 조건을 다시 검사한다. CHAINING이나 ORCHESTRATION이 이 stage action을 요청하면 `AUTHORITY_DENIED`다.

provider 호출 직전 exact reference, current state 또는 final pointer가 달라지면 runtime은 해당 `ActionDecision`을 `UNUSED -> EXPIRED`로 바꾸고 호출하지 않는다. 수정된 upstream revision을 입력으로 새 `LLMCallSpec`, `ActionRequest`, `ActionDecision`을 만들어야 한다. 과거 action이나 decision을 새 revision에 재사용할 수 없다.

Technical Gate가 `REVISE`를 확정하면 그 Gate action과 decision은 이미 사용을 마친 것이다. 같은 Verification·CWE revision 또는 같은 domain input hash로 `REVISE`를 다시 투표하려는 action은 `ACTION_NOT_ALLOWED`로 거절한다. Verification 또는 CWE가 보완된 새 revision으로 바뀐 뒤에만 새 Gate work와 새 action을 허가한다. provider 오류나 `INVALID_OUTPUT`의 제한 retry는 같은 domain input을 사용할 수 있지만 새 `llm_call_id`·call spec·action·decision과 `trigger=RETRY`가 필요하며, 이는 `REVISE` 보완 재검토와 구분한다.

`requested_by`와 action의 허용 조합은 다음 표를 따른다.

| `action_type` | 허용 `requested_by` |
|---|---|
| `REGISTER_WORK` | ORCHESTRATION, VERIFICATION, RECOVERY |
| `CHANGE_WORK_STATE` | ORCHESTRATION, VERIFICATION, SANDBOX, RECOVERY |
| `START_ATTEMPT` | ORCHESTRATION, VERIFICATION, SANDBOX, RECOVERY |
| `CANCEL_WORK` | ORCHESTRATION, VERIFICATION, SANDBOX, RECOVERY |
| `READ_CODE` | HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, TECHNICAL_GATE |
| `RUN_TOOL` | REPOSITORY_LOADER, STATIC_ANALYSIS, POLICY_COLLECTOR |
| `CALL_LLM` | HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, CHAINING, SANDBOX |
| `FETCH_POLICY` | POLICY_COLLECTOR |
| `REQUEST_DYNAMIC_REPRO` | VERIFICATION |
| `RUN_SANDBOX` | SANDBOX |
| `SAVE_RESULT` | ORCHESTRATION, HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, CHAINING, TECHNICAL_GATE, RULE_SCOPE_GATE, REPORTER, REPOSITORY_LOADER, STATIC_ANALYSIS, POLICY_COLLECTOR, SANDBOX, RECOVERY |
| `CALL_TECHNICAL_GATE` | VERIFICATION |
| `CALL_RULE_SCOPE_GATE` | VERIFICATION |
| `CREATE_REPORT_DRAFT` | VERIFICATION |

`REQUEST_DYNAMIC_REPRO`는 ACTIVE assignment의 R6 owner만 current Verification generation에서 요청한다. `SANDBOX` identity는 그 요청으로 등록된 exact `DYNAMIC_REPRO` work 안에서만 `CALL_LLM`, 상태 변경·attempt 시작과 `RUN_SANDBOX`를 요청할 수 있다. 이 제한은 R7이 plan·PoC candidate를 만들기 위한 권한이며 가설 verdict·CWE·Gate 결과를 생산할 권한이 아니다. R7이 request의 purpose·goal·가설·Sandbox profile을 바꾸거나 다른 generation의 request를 사용하면 `AUTHORITY_DENIED | STALE_RESULT`로 거절한다.

Orchestration은 전역 proposal 등록과 Verification 배정을 제안할 수 있지만 hypothesis-local 작업, Verification verdict, CWE, 두 Gate 결과, 정책 해석과 ReportDraft 내용을 생산하지 못한다. Verification은 hypothesis-local 작업을 제안하지만 실제 실행·저장 권한은 Runtime Validator를 통과해야 한다. 각 전문 결과는 위 표의 `SAVE_RESULT` 허용 역할 중에서도 해당 result kind를 소유한 역할만 저장한다. 예를 들어 `RuleExecutionRecord`는 STATIC_ANALYSIS, `VerificationResult`는 VERIFICATION, `ChainingResult`는 CHAINING, `TechnicalEvidenceReview`는 TECHNICAL_GATE, `RuleScopeImpactReview`는 RULE_SCOPE_GATE, `ReportDraft`는 REPORTER만 생산한다. runtime validator는 값의 생산자·schema·선행 reference를 확인하지만 취약점 진위·CWE 적절성·정책 의미를 대신 판정하지 않는다.

`ActionCheck.check_type=BUDGET` 실패는 `AnalysisError(stage=ORCHESTRATION, code=BUDGET_EXCEEDED)`로 기록한다. 가설 verdict나 LLM `INVALID_OUTPUT`으로 바꾸지 않으며, 운영 Verification의 Pro/Con 중 하나라도 실행할 예산이 없으면 두 호출과 final result 저장을 시작하지 않는다.

`SAVE_RESULT`는 검사할 결과 후보를 action에 정확히 고정한다.

- `result_kind`와 `candidate_result_ref`는 `SAVE_RESULT`에서 필수이고 다른 action에서는 `null`이다. `candidate_result_ref.data_kind`는 `result_kind`와 같고 `candidate_result_ref.record_id`에는 저장 runtime이 미리 발급한 결과 revision ID가 있어야 한다.
- `candidate_result_ref.content_hash`는 미리 발급한 ID를 포함해 canonical serialization한 결과 후보 전체의 hash다. 후보 record는 read-only staging 영역에 두며 action decision이 생긴 뒤 수정하거나 같은 `stored_data_id`·`record_id`에 다른 bytes를 넣지 않는다. candidate ref도 action `input_refs`에 정확히 한 번 포함한다. staging record는 `TransitionCommit.state=COMMITTED` 전에는 일반 결과 조회나 다음 단계에서 보이지 않는다.
- `SCHEMA`는 result kind에 맞는 schema와 필수 필드를, `AUTHORITY`는 result kind의 등록된 생산 역할과 `requested_by`를 검사한다. `IDENTITY`·`REVISION`·`STATE`는 모든 candidate의 analysis, current `work_ref`·active attempt·input refs와 hash를 검사하고, `RecordMeta` candidate이면 workspace·commit·hypothesis·`meta.attempt_id`까지 정확히 일치하는지 검사한다.
- 핵심 registry 항목은 `rule_execution_record -> RuleExecutionRecord -> STATIC_ANALYSIS`, `pro_evidence_result -> EvidenceAgentResult(role=PRO) -> PRO`, `con_evidence_result -> EvidenceAgentResult(role=CON) -> CON`, `verification_result -> VerificationResult -> VERIFICATION`, `primitive -> Primitive -> VERIFICATION`, `chaining_result -> ChainingResult -> CHAINING`, `dynamic_reproduction_request -> DynamicReproductionRequest -> VERIFICATION`, `environment_requirements -> EnvironmentRequirements -> SANDBOX`, `reproduction_plan -> ReproductionPlan -> SANDBOX`, `dynamic_reproduction_result -> DynamicReproductionResult -> SANDBOX`, `cwe_label -> CWELabel -> CWE_LABELING`, `technical_evidence_review -> TechnicalEvidenceReview -> TECHNICAL_GATE`, `rule_scope_impact_review -> RuleScopeImpactReview -> RULE_SCOPE_GATE`, `report_draft -> ReportDraft -> REPORTER`다. 앞 값은 `result_kind`·`data_kind`, 가운데 값은 검사할 schema, 뒤 값은 유일한 생산 역할이다. 다른 result kind도 versioned result-owner registry에 정확히 한 schema와 생산 역할을 등록해야 하며, broad requester 표만으로 저장 권한을 얻지 않는다.
- `result_kind=rule_execution_record`이면 STATIC_ANALYSIS만 저장할 수 있다. `SCHEMA`는 catalog와 `rules[].rule_id`의 set equality, 중복 rule ID, selection·execution·`hit_count`·`reason`·`detail` 조합을 검사한다. `REVISION | STATE`는 candidate의 `meta.attempt_id`, 도구·버전, workspace·commit, `analysis_config_ref`·`rule_catalog_ref`가 current `STATIC_TOOL` attempt와 exact match하는지 확인한다. 같은 attempt의 `ToolRunResult`를 확정할 때는 `tool_kind=RULE_BASED`이고 `rule_execution_ref`가 이 record를 가리키는지 다시 검사한다. `StaticFactBundle`을 확정할 때 각 `CodeFact.producer.attempt_id`와 규칙 기반 `producer.rule_id`가 연결된 current `ToolRunResult`·`RuleExecutionItem`과 일치하는지도 검사한다. 실패·누락·확인 불가를 `EXECUTED + hit_count=0`으로 바꾼 candidate는 저장하지 않는다.
- `result_kind=pro_evidence_result | con_evidence_result`이면 candidate의 role, `evidence_work_id`, `meta.attempt_id`, `llm_call_id`, `parent_work_id`, `verification_generation`, `debate_input_hash`가 current child work·성공 attempt·호출·부모 Verification과 정확히 일치해야 한다. 다른 역할의 claim이나 상대 역할 record가 입력 경로에 있으면 `AUTHORITY_DENIED` 또는 `CROSS_ROLE_INPUT_DENIED`로 저장하지 않는다.
- `result_kind=verification_result`이면 `SCHEMA | REVISION | STATE`는 가설의 모든 `ValidationCheck.validation_id`와 candidate의 `ValidationCheckResult.validation_id`가 중복 없이 set-equal인지, 모든 `ValidationCheckResult.completion=COMPLETE`인지, 각 결과의 `evidence_refs`가 하나 이상인지 확인한다. `INCOMPLETE` 항목이 하나라도 있으면 final candidate를 `COMMITTED`하지 않는다. 모든 `FalsificationQuestion.question_id`도 정확히 한 번 처리되어야 하며 사용한 근거는 현재 `workspace_id + commit_id`의 저장 record여야 한다. 운영 분석은 독립 Pro/Con work가 모두 정상 종료되어 exact output이 action `input_refs`에 있어야 한다. 일부 Context 조회 오류가 있어도 제한 retry·대체 조회·다른 정상 근거로 이 조건을 완료했다면 final candidate를 검사할 수 있지만, 필수 Context 또는 운영 Pro/Con을 확보하지 못했다면 final candidate를 `COMMITTED`하지 않는다. 이 경우 retry 가능 work는 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지한다. 더 시도할 수 없으면 같은 atomic transition에서 work와 `HypothesisProcessState`를 `FAILED`로 끝내며 runtime이 `HOLD`를 대신 만들지 않는다. Runtime Validator는 구조·reference·완료 상태만 검사한다. final `TRUE` 근거의 의미적 충분성과 코드·실행 근거 연결은 Technical Evidence Gate가 exact final TRUE revision을 대상으로 별도로 검토한다. `FALSE | HOLD`는 Technical Gate 입력이 아니며, 구조 검사를 통과했다는 사실이 Gate 승인을 의미하지 않는다.
- `VerificationResult.verdict=TRUE`이면 현재 가설의 핵심 공격 경로와 필요한 조건을 연결하는 하나 이상의 `supporting_evidence`가 필수다. 각 claim은 실제 저장 근거와 같은 `workspace_id + commit_id`의 코드 위치를 가져야 하며 오류·gap record를 근거로 사용할 수 없다. 또한 current Verification generation의 exact `DynamicReproductionRequest`, `DynamicReproductionResult(status=SUCCEEDED, hypothesis_outcome=SUPPORTED)`와 validated `poc_ref`가 모두 필수이고 candidate와 final result의 세 reference가 exact match여야 한다. 이 조건을 충족하지 않은 TRUE candidate는 저장하지 않는다.
- `VerificationResult.verdict=FALSE`이면 `falsification_results`에 실제 `question_id`, `outcome=DISPROVED`, 하나 이상의 `evidence_refs`가 있는 항목이 필수이고 `verdict_rationale`이 그 질문과 근거를 연결해야 한다. 오류·timeout·빈 출력만 있는 후보는 `SCHEMA` check를 `FAIL`로 만들어 저장하지 않으며 runtime이 다른 verdict를 만들어 주지 않는다.
- `VerificationResult.verdict=HOLD`이면 비어 있지 않은 `unresolved_conditions`와, 정상적으로 확인한 범위 및 결론을 막는 중요한 조건을 설명하는 `supporting_evidence[].evidence_refs | counter_evidence[].evidence_refs | falsification_results[].evidence_refs` 중 하나 이상의 실제 reference가 필요하다. `AnalysisError`, `DataGap`, timeout·권한 오류 또는 빈 Context만으로 만든 HOLD 후보는 `SCHEMA` check를 `FAIL`로 만들며 runtime이 다른 verdict를 만들어 주지 않는다.
- `TRUE | HOLD`에는 `outcome=DISPROVED`인 `FalsificationResult`가 있을 수 없다.
- candidate의 `playbook_ref`는 `SAVE_RESULT.input_refs`에 포함된 exact `VerificationPlaybook` revision과 일치해야 한다. reference가 없거나 `record_id`·`content_hash`가 다르거나, final Verification 합성 호출이 다른 플레이북 revision을 사용했으면 저장을 거절한다.
- `result_kind=dynamic_reproduction_request`이면 VERIFICATION만 저장할 수 있다. `POC_CONFIRMATION`은 `initial_verdict=TRUE`, `VERDICT_EVIDENCE`는 `initial_verdict=HOLD`만 허용한다. production에서는 same-generation ACTIVE assignment, exact hypothesis, 비어 있지 않은 goal·environment needs·code/static refs와 exact Pro·Con refs가 필수다. Runtime Validator는 한 Verification generation에는 `DYNAMIC_REPRO` work를 최대 하나만 허용하고 두 purpose를 동시에 또는 순차 등록하려는 요청을 `ACTION_NOT_ALLOWED`로 거절한다.
- `result_kind=report_draft`이면 REPORTER만 저장할 수 있고 candidate의 `action_decision_ref`는 같은 초안을 허용한 exact `CREATE_REPORT_DRAFT` decision을 가리켜야 한다. `finding_ref`, Verification·CWE·두 Gate·정책, 존재하는 동적 결과·PoC reference는 action `input_refs`와 current upstream record에 정확히 일치해야 한다. `restrictions`와 `unresolved_conditions`는 Verification의 값을 빠짐없이 보존하고 `limitations`는 연결된 동적 결과와 Gate가 남긴 제한을 빠뜨리지 않는다. `redaction_status=PASSED`와 action의 `REDACTION=PASS`가 모두 확인되지 않으면 저장을 거절한다.
- `result_kind=primitive`이면 `SCHEMA`와 `REVISION`은 `result` 유무에 따른 admission을 검사한다. `result=null`은 exact final HOLD만 허용하며 `inputs`는 그 Verification의 `required_primitive_candidates`, `restrictions`는 Verification restrictions와 같고 `technical_review_ref=null`이다. `result`가 있으면 current generation의 validated PoC를 가진 exact final TRUE와 그 TRUE+CWE를 검토한 Technical `ACCEPT`가 필수다. 제공 능력 하나마다 Primitive 하나를 만들고 각 Primitive의 `inputs`는 같은 TRUE의 `required_primitive_candidates`, `result`는 `provided_primitive_candidates` 한 항목, `restrictions`는 Verification 값과 exact match한다. Rule Scope 결과는 primitive action 입력이나 admission 조건이 아니다. FALSE, Gate 전 TRUE와 Technical `REVISE | REJECT` 기반 Primitive는 저장하지 않는다.
- `result_kind=chaining_result`이면 `input_primitive_refs`가 모든 match candidate의 upstream/downstream Primitive exact reference 합집합과 set-equal인지 확인한다. 각 upstream Primitive는 final TRUE + Technical `ACCEPT` 기반의 non-null `result`, downstream은 하나 이상의 `inputs`를 가져야 한다. `matched_input_id`는 downstream `inputs[].draft_id` 하나를 정확히 선택하고 upstream result가 그 input을 충족한다는 entity·privilege·순서·restriction 코드 근거가 `evidence_refs`에 있어야 한다. downstream `result=null`이면 TRUE_HOLD, non-null이면 TRUE_TRUE로 유도한다. 같은 fingerprint 중복, 조상 링크를 따라 이미 사용한 Primitive의 재사용, 일반 research·동적 재현·Gate 보완 출력 또는 CHAINING이 아닌 proposal origin은 저장을 거절한다.
- 저장 runtime은 claim한 action의 candidate bytes와 hash를 다시 확인한다. 확정된 result ref는 candidate와 `stored_data_id`·`data_kind`·`content_hash`·`record_id`가 모두 같아야 한다. 결과 ref, 종료 `StateTransition`과 `TransitionCommit`은 같은 output을 가리켜야 하며 `TransitionCommit.state=COMMITTED`가 된 뒤에만 소비할 수 있다. 후속 `ActionDecision.outcome_refs`에는 그 exact result ref와 COMMITTED commit ref를 각각 한 번 넣는다.
- `result_kind=environment_requirements`이면 SANDBOX만 저장할 수 있다. `request_ref`는 current R7 work의 exact `DynamicReproductionRequest`여야 한다. `SCHEMA`는 R6 request의 모든 `environment_needs`를 빠뜨리거나 약화하지 않은 고유 `requirement_id`, 허용 kind, 필수 여부, 하나 이상의 exact `source_refs`, 값·artifact·검사 조건 연결과 secret 금지를 검사한다. retry에서 요구사항을 바꾸면 같은 record를 덮어쓰지 않고 새 `record_id`를 만든다.
- `result_kind=reproduction_plan`이면 SANDBOX만 저장할 수 있다. plan의 `request_ref`, `purpose`, `hypothesis_ref`, `sandbox_profile_ref`는 R6 request와 exact match하고 `environment_requirements_ref`는 같은 R7 work·attempt가 만든 current requirements를 가리켜야 한다. `poc_candidate_ref`, 순서가 있는 steps와 cleanup policy가 필수이며 R7이 선택한 mode는 `LIMITED_REPRO | FULL_REPRO`다.
- `result_kind=dynamic_reproduction_result`이면 `SAVE_RESULT.input_refs`에 candidate뿐 아니라 exact `DynamicReproductionRequest`, `RUN_SANDBOX` USED decision, `ReproductionPlan`, 그 계획의 exact `EnvironmentRequirements`·PoC candidate와 나머지 closure를 넣는다. `policy_decision_ref`, `environment_ref`, `steps_ref`, validated `poc_ref`가 존재하면 각 exact target도 input에 넣는다. `runner_invoked=true`이면 `SandboxStepLog`가 필수이고 `false`이면 log를 요구하거나 추측해 만들지 않는다. `REVISION` check는 결과의 request·plan·purpose·mode·정책 판정·Runner 호출·공격 입력·PoC candidate·validated PoC·실제 환경·정리 정책과 실제 step log가 승인 당시와 같은지 다시 검사한다. 실제 `sandbox_environment.requirements_ref`가 plan의 `environment_requirements_ref`와 다르거나 current가 아닌 요구사항 revision이면 저장을 거절한다. `SCHEMA` check는 요구사항별 비교 결과, `runner_invoked`, `environment_created`, `cleanup_required`와 nullable reference·`cleanup_status` 조합을 검사한다. `poc_ref`는 `status=SUCCEEDED`, `hypothesis_outcome=SUPPORTED`이고 실행 log가 `poc_candidate_ref`의 같은 revision 또는 digest를 실제 실행한 경우에만 허용한다. 나머지 상태와 `DISPROVED | INCONCLUSIVE`에서는 `poc_ref=null`이다.
- check 뒤 candidate bytes·hash, active attempt, work input 또는 state version이 달라지면 decision을 `EXPIRED`로 만들거나 save를 `DENY`하고 `STALE_RESULT | RECORD_REVISION_MISMATCH | STATE_VERSION_CONFLICT` 중 실제 원인을 기록한다. 변한 후보를 저장하거나 이미 `USED`인 action으로 다시 저장하지 않는다.
Runtime Validator는 구조·reference·완료 상태만 검사한다. final `TRUE` 근거의 의미적 충분성과 코드·실행 근거 연결은 Technical Evidence Gate가 exact final TRUE revision을 대상으로 별도로 검토한다. `FALSE | HOLD`는 Technical Gate 입력이 아니며, 구조 검사를 통과했다는 사실이 Gate 승인을 의미하지 않는다.

action type에서 쓰지 않는 선택 field는 `null` 또는 빈 배열이어야 하고 `reason`은 비어 있지 않아야 한다. `READ_CODE`는 하나 이상의 `file_paths`, `RUN_TOOL`은 `tool_name`과 필요한 file path가 필수다. 실제 LLM을 실행하는 `CALL_LLM | CALL_TECHNICAL_GATE | CALL_RULE_SCOPE_GATE | CREATE_REPORT_DRAFT`는 exact `llm_call_spec_ref`, `provider_profile_ref`, `session_mode`와 work state가 필요하며 action의 provider·session 값은 spec과 같아야 한다. SANDBOX의 `CALL_LLM`은 current `DYNAMIC_REPRO` work에서 requirements·plan·PoC candidate를 만드는 목적만 허용한다. `SAVE_RESULT`만 `result_kind`와 `candidate_result_ref`를 사용한다. Gate와 Reporter는 별도 `CALL_LLM`을 우회 호출하지 않고 각 stage action이 LLM 호출까지 직접 허가한다. `REQUEST_DYNAMIC_REPRO`와 `RUN_SANDBOX`는 같은 exact `dynamic_request_ref`를 사용하고 `RUN_SANDBOX`만 `reproduction_plan_ref`를 추가로 사용한다. Controller가 검사할 `sandbox_profile_ref`·`image_digest`·`resource_limits`도 필수다. action `input_refs`에는 exact request·`ReproductionPlan`, 그 계획의 `hypothesis_ref`·`environment_requirements_ref`·`poc_candidate_ref`·`sandbox_profile_ref`·모든 step `command_ref`·`attack_input_refs`·`cleanup_policy_ref`를 중복 없이 포함한다. request, plan과 action의 profile·purpose·hypothesis가 같고 `environment_requirements_ref` target은 current exact `EnvironmentRequirements` revision이어야 한다. Runtime Validator의 `SCHEMA`·`REVISION`은 이 reference 집합의 존재와 고정 여부만 확인하고 환경 값이나 Sandbox 정책 의미를 판단하지 않는다. Sandbox Controller는 action의 `sandbox_profile_ref`와 계획 값을 exact 비교하고, 빈 `network_targets`를 default-deny로 해석해 세부 정책을 검사한다.

```yaml
CodeLocation:
  workspace_id: string
  commit_id: string
  file_path: string
  start_line: integer
  start_column: integer | null
  end_line: integer
  end_column: integer | null

CodeSymbol:
  symbol_id: string
  symbol_kind: FILE | MODULE | TYPE | CALLABLE | DATA | ROUTE | CONFIG
  native_kind: string | null
  name: string
  location: CodeLocation

StoredDataRef:
  stored_data_id: string
  data_kind: string
  content_hash: string
  workspace_id: string
  commit_id: string
  record_id: string | null

RunStoredDataRef:
  stored_data_id: string
  data_kind: string
  content_hash: string
  analysis_id: string
  record_id: string | null

DataGap:
  gap_id: string
  stage: REPOSITORY | STATIC_ANALYSIS | CONTEXT | DYNAMIC | POLICY
  code: string
  reason: MISSING | FAILED | TRUNCATED | UNSUPPORTED | BLOCKED | TIMEOUT
  description: string
  affected_paths: [string]
  affected_languages: [string]
  affected_locations: [CodeLocation]
  retryable: boolean
  related_record_ids: [string]
  created_at: timestamp

AnalysisError:
  error_id: string
  stage: INPUT | REPOSITORY | STATIC_ANALYSIS | CONTEXT | ORCHESTRATION | AGENT | PROVIDER | SANDBOX | POLICY | GATE | REPORT | STATE | STORAGE | RECOVERY | AUTHORITY
  code: string
  safe_message: string
  retryable: boolean
  work_id: string | null
  attempt_id: string | null
  related_record_ids: [string]
  created_at: timestamp

ToolSource:
  attempt_id: string
  tool_name: string
  tool_version: string
  rule_id: string | null
  raw_result_ref: StoredDataRef

CodeFact:
  fact_id: string
  fact_kind: SOURCE | SINK | SANITIZER | VALIDATOR | AUTH_CHECK | PERMISSION_CHECK | OTHER
  symbol_id: string | null
  location: CodeLocation
  producer: ToolSource

CodeRelation:
  relation_id: string
  relation_kind: CALL | DATA_FLOW | IMPORT | INHERITANCE | ROUTE_BINDING | OTHER
  from_symbol_id: string | null
  from_location: CodeLocation
  to_symbol_id: string | null
  to_location: CodeLocation
  producer: ToolSource

ToolCoverage:
  analyzed_paths: [string]
  skipped_paths: [string]
  analyzed_languages: [string]
  skipped_languages: [string]
  notes: [string]

RuleExecutionItem:
  rule_id: string
  selection_status: SELECTED | NOT_SELECTED
  execution_status: EXECUTED | NOT_EXECUTED | UNKNOWN
  hit_count: integer | null
  reason: NOT_SELECTED | TOOL_FAILURE | UNSUPPORTED | CANCELLED | TELEMETRY_MISSING | OTHER | null
  detail: string | null

RuleExecutionRecord:
  meta: RecordMeta without hypothesis, with attempt
  tool_name: string
  tool_version: string
  analysis_config_ref: StoredDataRef
  rule_catalog_ref: StoredDataRef
  selected_rule_packs: [string]
  rules: [RuleExecutionItem]

ToolRunResult:
  attempt_id: string
  tool_name: string
  tool_version: string
  tool_kind: STRUCTURE | RULE_BASED
  status: SUCCEEDED | PARTIAL | FAILED | SKIPPED
  coverage: ToolCoverage
  rule_execution_ref: StoredDataRef | null
  raw_result_ref: StoredDataRef | null
  gaps: [DataGap]
  errors: [AnalysisError]
  started_at: timestamp
  finished_at: timestamp
  elapsed_ms: integer

ContextRetrievalLimits:
  max_depth: integer
  max_fragments: integer
  max_bytes: integer
  token_budget: integer
  max_requests_per_hypothesis: integer
  timeout_ms: integer
```

`file_path`는 `workspace_root` 기준의 정규화된 Git 상대 경로다. 구분자는 운영체제와 관계없이 `/`를 사용하고 빈 경로, 절대 경로, drive prefix, `.`·`..` segment를 허용하지 않는다. Git에 저장된 경로의 대소문자를 그대로 보존하며 symlink를 해석한 실제 읽기 대상은 `workspace_root` 안에 있어야 한다. 줄은 1부터 시작하고 `start_line`과 `end_line`은 범위에 포함된다. 열 정보가 있는 경우 두 열 모두 1부터 시작하고 Unicode code point 단위이며 `start_column`은 포함, `end_column`은 제외한다. 도구가 줄만 제공하면 두 column을 모두 `null`로 두고 임의의 열 정밀도를 만들지 않는다.

`symbol_kind`는 여러 언어에서 공통으로 쓸 수 있는 큰 범주다. `TYPE`에는 class·interface·enum·struct, `CALLABLE`에는 function·method·constructor·lambda, `DATA`에는 variable·field·property·parameter가 들어간다. 원래 parser나 SAST 도구가 사용한 세부 종류는 `native_kind`에 그대로 남긴다. `symbol_id`, `fact_id`, `relation_id`는 같은 `workspace_id + commit_id` 안에서 유일하다. `CodeFact`와 `CodeRelation`의 `producer.raw_result_ref`는 사실·관계를 만든 도구의 원본 결과를 가리켜야 한다.

`RuleExecutionRecord`는 규칙 기반 SAST가 어떤 규칙을 선택했고 실제로 실행했는지 남기는 별도 record다. `RunMeta`는 분석 실행의 공통 식별 정보만 유지하며 도구별 규칙 목록을 넣지 않는다. `analysis_config_ref`는 실행에 사용한 정확한 설정, `rule_catalog_ref`는 이번 분석에서 선택 여부를 비교할 규칙 전체 목록과 버전을 가리킨다. `selected_rule_packs`는 설정이 선택한 rule pack 이름을 보존하고, 개별 규칙 선택 여부는 `rules[].selection_status`가 최종 기준이다. pack 이름은 사람이 읽기 위한 값이며 exact pack 버전과 digest는 `rule_catalog_ref`에서 확인한다. 개별 규칙만 선택했다면 `selected_rule_packs=[]`일 수 있다. `rules`는 하나 이상이어야 하고 `rule_id` 집합은 `rule_catalog_ref`가 가리키는 목록과 중복 없이 set-equal해야 한다. `rule_id`는 전역 ID가 아니므로 `tool_name + tool_version + rule_catalog_ref.content_hash + rule_id` 문맥에서 해석한다.

규칙별 상태 조합은 다음과 같다.

- `SELECTED + EXECUTED`이면 `hit_count`는 0 이상의 정수이고 `reason=null`이다. `hit_count=0`만이 “규칙을 실행했지만 탐지 결과가 0건”이라는 뜻이다.
- `SELECTED + NOT_EXECUTED`이면 `hit_count=null`이고 `reason=TOOL_FAILURE | UNSUPPORTED | CANCELLED | OTHER` 중 하나가 필수다.
- `SELECTED + UNKNOWN`이면 실행 여부를 증명할 수 없다는 뜻이며 `hit_count=null`, `reason=TELEMETRY_MISSING | TOOL_FAILURE | OTHER` 중 하나가 필수다.
- `NOT_SELECTED + NOT_EXECUTED`이면 `hit_count=null`, `reason=NOT_SELECTED`다. 분석 계획에서 제외한 규칙은 이 조합으로 기록한다.
- `NOT_SELECTED + EXECUTED`와 `NOT_SELECTED + UNKNOWN`은 모순이므로 저장하지 않는다. `NOT_EXECUTED | UNKNOWN`에서 `hit_count=0`을 쓰는 것도 금지한다.

`reason=OTHER`이면 사람이 이해할 수 있는 비어 있지 않은 `detail`이 필수다. 나머지 reason에서도 추가 설명이 필요하면 `detail`을 사용할 수 있고, reason이 `null`이면 `detail`도 `null`이다.

`hit_count`는 정규화 전 raw 도구 결과에서 해당 규칙이 만든 결과 수다. `CodeFact` 수와 같다고 추정하거나 normalizer의 중복 제거 때문에 값을 바꾸지 않는다. `CodeFact.producer.attempt_id`는 이 사실을 만든 exact `ToolRunResult.attempt_id`와 같아야 한다. `CodeFact.producer.rule_id`가 존재하면 같은 attempt의 `RuleExecutionItem`은 반드시 `SELECTED + EXECUTED`, `hit_count>0`이어야 한다. 반대로 `CodeFact`가 없다는 사실만으로 0건을 추정하지 않고 exact `RuleExecutionRecord`를 확인한다.

CodeQL·OpenGrep처럼 규칙을 실행하는 도구는 `tool_kind=RULE_BASED`, AST parser처럼 개별 규칙 개념이 없는 도구는 `tool_kind=STRUCTURE`다. `RULE_BASED`의 `ToolRunResult.rule_execution_ref`는 `SUCCEEDED | PARTIAL | SKIPPED`에서 필수이고, 참조 대상 `RuleExecutionRecord.meta.attempt_id`·도구 이름·버전·workspace·commit이 `ToolRunResult`와 같아야 한다. `FAILED`가 exact 설정이나 catalog를 확정하기 전에 발생한 경우에만 이 참조를 `null`로 둘 수 있으며, 하나 이상의 `AnalysisError`와 영향받은 `DataGap`을 남기고 전체 규칙 실행 여부를 `UNKNOWN`으로 취급한다. `STRUCTURE`는 `rule_execution_ref=null`이며 `ToolSource.rule_id`도 `null`이다.

전체 도구 상태와 규칙별 상태도 모순되면 안 된다. `SUCCEEDED`이면 선택한 규칙이 하나 이상이고 모두 `EXECUTED`여야 한다. 선택한 규칙 중 하나라도 `NOT_EXECUTED | UNKNOWN`이면 `SUCCEEDED`가 될 수 없으며, 사용할 수 있는 일부 결과가 있으면 `PARTIAL`, 사용할 수 있는 결과가 없으면 `FAILED | SKIPPED` 중 실제 원인을 사용한다. `SKIPPED`에는 `EXECUTED` 규칙이 있을 수 없다. 선택한 규칙의 미실행·확인 불가 범위는 `DataGap(stage=STATIC_ANALYSIS)`에 남기고 실제 오류가 원인이면 `AnalysisError(stage=STATIC_ANALYSIS)`도 함께 남긴다. 규칙 0건, 미실행, 확인 불가 어느 것도 취약점이 없거나 가설이 `FALSE`라는 뜻이 아니다.

규칙 실행 record는 attempt마다 새로 만든다. retry는 같은 `work_id`의 새 `attempt_id`와 새 `RuleExecutionRecord`를 사용하며 이전 attempt의 규칙 상태나 탐지 수를 합치지 않는다. 현재 active attempt와 다른 record, 설정·catalog hash가 다른 record와 늦게 도착한 record는 `ATTEMPT_NOT_ACTIVE | STALE_RESULT | RECORD_REVISION_MISMATCH` 중 실제 원인으로 거절한다.

`StoredDataRef`는 준비된 코드와 연결된 결과에만 사용한다. raw 도구 출력·코드 조각처럼 독립 artifact이면 `record_id=null`이다. 저장된 record의 정확한 revision을 가리키는 참조는 해당 revision의 전역 `record_id`를 반드시 넣고, runtime은 참조의 `workspace_id`, `commit_id`, `content_hash`가 그 record와 일치하는지 확인한다. `RunStoredDataRef`는 입력 검증, clone·checkout, 실행 오류와 debug trace처럼 commit 준비 전에도 생기는 실행 자료에만 사용하며 코드 근거·PoC·Finding·보고서 주장의 근거로 사용할 수 없다. raw 실행 artifact이면 `record_id=null`, `RunMeta`를 가진 저장 record의 정확한 revision을 가리키면 그 `record_id`가 필수이며 `analysis_id`와 `content_hash`가 대상과 일치해야 한다. 두 참조 모두 내부 저장 경로 대신 결과 번호와 내용 hash만 전달한다.

`DataGap`은 분석하지 못한 범위이고 `AnalysisError`는 실행 중 발생한 오류다. 둘 다 취약점 `TRUE | FALSE | HOLD`를 뜻하지 않는다. `AnalysisError.safe_message`에는 credential, 개인정보, session secret, authorization header와 절대 로컬 경로를 넣지 않는다. 원본 오류가 필요하면 일반 오류 record에 복사하지 않고 별도 접근 통제·redaction·보존 정책이 적용된 artifact로 저장한다. `DataGap`의 세 affected 목록은 빈 목록일 수 있지만, `REPOSITORY | STATIC_ANALYSIS | CONTEXT` gap은 가능한 범위에서 path·language·location 중 하나 이상을 채운다. 전체 작업공간에 영향을 주거나 정확한 범위를 모르면 그 사실을 `description`에 명시하고 관련 결과를 `related_record_ids`로 연결한다.

Context 조회 실패·timeout·권한 오류가 발생하면 실패 사건은 `AnalysisError(stage=CONTEXT)`로, 그 때문에 확인하지 못한 코드 범위는 `DataGap(stage=CONTEXT)`으로 각각 기록한다. 두 항목의 `related_record_ids`는 가능한 범위에서 같은 `CodeContextRequest`·`CodeContextResponse`·Verification work record를 가리킨다. `error_id`와 `gap_id`는 해당 attempt의 `TransitionCommit`과 최종 `AnalysisRunResult`에 보존한다. 오류가 났다는 사실만으로 verdict를 만들지 않으며, 오류·gap 항목을 supporting/counter/falsification evidence로 사용하지 않는다.

### DataGap 생산자와 소비자

| `stage` | 주 생산자 | 대표 `code` | 주 소비자 |
|---|---|---|---|
| `REPOSITORY` | Repository Loader | `SUBMODULE_UNAVAILABLE`, `LFS_POINTER_ONLY`, `GENERATED_FILE_UNAVAILABLE` | 정적 분석, Hypothesis, Verification |
| `STATIC_ANALYSIS` | AST/SAST runner와 normalizer | `STATIC_COVERAGE_PARTIAL`, `LANGUAGE_UNSUPPORTED` | Hypothesis, Verification, 결과 집계 |
| `CONTEXT` | Context Retrieval Service | `CONTEXT_TRUNCATED`, `SYMBOL_UNRESOLVED` | Verification, Pro/Con, Technical Gate |
| `DYNAMIC` | Sandbox runtime | `DYNAMIC_OBSERVATION_MISSING`, `DEPENDENCY_UNAVAILABLE` | Verification, Technical Gate, Reporter, `AnalysisRunResult` |
| `POLICY` | 정책 수집 계층 | `POLICY_SOURCE_MISSING`, `POLICY_SOURCE_STALE` | Rule Scope Impact Gate, Reporter runtime |

`code`는 정확한 누락 종류, `reason`은 공통 원인 범주다. 빈 결과를 숨기지 않으며 소비자는 gap을 안전함이나 반증으로 해석하지 않는다.

### AnalysisError 생산자와 전달 규칙

| `stage` | 주 생산자 | 반드시 받는 소비자 | 기본 전달·처리 규칙 |
|---|---|---|---|
| `INPUT` | 입력 validator | Orchestration runtime, `AnalysisRunResult` | 분석 시작 전 거절 사유를 저장하고 verdict를 만들지 않음 |
| `REPOSITORY` | Repository Loader | Orchestration runtime, `AnalysisRunResult` | clone·checkout 실패는 실행 상태에 반영하고 가설 verdict를 만들지 않음 |
| `STATIC_ANALYSIS` | AST/SAST runner와 normalizer | Orchestration runtime, 정적 결과, `AnalysisRunResult` | 사용 가능한 결과와 오류를 함께 전달하고 필요하면 실행을 `PARTIAL`로 표시 |
| `CONTEXT` | Context Retrieval Service | 요청 Agent, 관련 Verification work·존재하는 검증 결과, `AnalysisRunResult` | 실패는 `AnalysisError`, 확인하지 못한 범위는 `DataGap`으로 함께 전달한다. 정상 근거로 필수 검증을 완료했을 때만 verdict를 허용하고 오류 자체를 `TRUE | FALSE | HOLD`의 근거로 사용하지 않음 |
| `ORCHESTRATION` | Orchestration runtime | `AnalysisRunResult`, 운영 debug trace | 예산·순서·할당 실패를 기록하고 이미 존재하는 verdict를 바꾸지 않음 |
| `AGENT` | Agent Runtime | Orchestration runtime, 해당 Agent 결과, `AnalysisRunResult` | invalid output과 Agent 실행 실패를 별도 기록하고 자동 FALSE 금지 |
| `PROVIDER` | LLM provider adapter | Agent Runtime, 해당 invocation, `AnalysisRunResult` | 인증·rate limit·timeout을 호출 상태로 전달하고 자동 FALSE 금지 |
| `SANDBOX` | Sandbox runtime | Verification, 동적 결과, Technical Gate, `AnalysisRunResult` | 실행 실패와 실제 반증을 분리해 전달 |
| `POLICY` | 정책 수집 계층 | Rule Scope Impact Gate, `AnalysisRunResult` | 공식 정책 부족 시 `UNCERTAIN + DENY` 판단에 전달 |
| `GATE` | 두 Gate runtime | Orchestration runtime, 해당 Gate 결과, `AnalysisRunResult` | Gate 실패 시 Reporter 호출을 막고 Verification verdict는 유지 |
| `REPORT` | Reporter runtime | Orchestration runtime, `ReportProcessState`, `AnalysisRunResult` | 초안 실패를 저장하고 공개 상태를 만들지 않음 |
| `AUTHORITY` | Runtime Validator·Sandbox Controller | 요청 주체, `AnalysisRunResult`, debug trace | Runtime 권한·provider·Gate·Reporter 차단과 Controller의 Sandbox 정책 차단을 구분해 기록하고 domain 판단은 바꾸지 않음 |

모든 `AnalysisError`는 `AnalysisRunResult.errors`와 운영 debug trace에 전달한다. 특정 가설·호출·동적 실행과 관련된 오류는 해당 전문 결과에도 포함하거나 `related_record_ids`로 연결한다. 오류를 누락하거나 성공 상태로 바꾸어 전달하지 않는다.

### 계약 버전과 revision 규칙

`schema_version`은 `MAJOR.MINOR.PATCH` 형식이다.

- `MAJOR`: 필드 삭제·이름 변경·의미 변경, enum 값의 추가·삭제·이름 변경·의미 변경처럼 호환되지 않는 변경
- `MINOR`: 기존 의미를 바꾸지 않는 선택 필드 추가
- `PATCH`: 데이터 해석이 바뀌지 않는 설명·예시·검증 규칙 명확화

이 문서에 나열한 enum은 모두 닫힌 enum이다. 따라서 소비자는 목록에 없는 값을 추정해서 처리하지 않는다. 소비자는 지원하지 않는 MAJOR를 추정해서 읽지 않고 `SCHEMA_UNSUPPORTED`를 기록한다. 알 수 없는 선택 필드는 보존하거나 무시할 수 있지만 새 의미를 만들지 않는다. schema 변경을 이유로 기존 record를 덮어쓰지 않고 같은 `logical_record_id` 아래 새 `record_id`, `created_at`과 증가한 `revision_number`를 만든다.

`RuleExecutionRecord` 추가, `ToolRunResult.tool_kind`·규칙 기반 `rule_execution_ref`와 `ToolSource.attempt_id` 의무화는 기존 운영 결과의 유효 조건을 바꾸므로 새 MAJOR schema로 적용한다. 이전 MAJOR의 `ToolRunResult`에 규칙 hit이 없다는 이유로 `EXECUTED + hit_count=0`을 추정해 채우지 않는다. 이전 결과는 감사 이력으로 보존할 수 있지만 새 규칙 실행률 계산이나 “검사했지만 탐지 없음”의 근거로 자동 승격하지 않는다.

저장소에서 revision의 유일 키는 `(logical_record_id, revision_number)`다. `previous_record_id`는 같은 `logical_record_id`를 가진 바로 이전 `revision_number`의 `record_id`만 가리킨다. 모든 revision에서 `record_type`과 `analysis_id`가 같아야 한다. `RecordMeta`는 `workspace_id`, `commit_id`, `hypothesis_id`도 이전 revision과 같아야 한다. `RunMeta` 기반 record의 `workspace_id`와 `commit_id`는 준비 과정에서만 `null`에서 실제 값으로 바뀔 수 있고, 실제 값이 기록된 뒤에는 바꿀 수 없다. revision이 연속되지 않거나 이 조건을 어기면 `RECORD_REVISION_MISMATCH`로 거절하고 자동 병합하지 않는다. schema version 변경과 record revision 증가는 서로 다른 개념이다.

## 1. StaticFactBundle

정적분석 계층이 만들고 가설 생성·검증 단계가 사용하는 코드 사실 묶음입니다.

```yaml
StaticFactBundle:
  meta: RecordMeta without hypothesis/attempt
  entities: [CodeSymbol]
  locations: [CodeLocation]
  source_candidates: [CodeFact]
  sink_candidates: [CodeFact]
  call_edges: [CodeRelation]
  data_flow_candidates: [CodeRelation]
  auth_and_permission_checks: [CodeFact]
  route_bindings: [CodeRelation]
  tool_runs: [ToolRunResult]
  gaps: [DataGap]
  errors: [AnalysisError]
```

SAST severity와 tool message는 verdict가 아니다.

## 2. HypothesisProposal과 VulnerabilityHypothesis

가설 생성 Agent가 제안한 후보와, 프로그램이 형식을 확인한 뒤 검증 대상으로 등록한 가설을 구분합니다.

```yaml
FalsificationQuestion:
  question_id: string
  question: string

ValidationCheck:
  validation_id: string
  instruction: string

HypothesisProposal:
  proposal_id: string
  meta: RecordMeta
  proposal_state: HYPOTHESIS_ONLY
  assertion_mode: NON_FINAL
  origin: INITIAL | VERIFICATION | CHAINING
  vulnerability_type_candidates: [string]
  target_entities: [CodeSymbol]
  target_locations: [CodeLocation]
  suspected_path: [CodeRelation | CodeLocation]
  observed_facts: [CodeFact]
  assumptions: [string]
  restrictions: [string]
  falsification_questions: [FalsificationQuestion]
  validation_checks: [ValidationCheck]
  parent_hypothesis_ids: [string]
  source_primitive_match_id: string | null
```

초기 proposal은 `parent_hypothesis_ids: []`, `source_primitive_match_id: null`이다. Verification-origin proposal도 `source_primitive_match_id=null`이다. Chaining-origin proposal은 직접 부모를 `parent_hypothesis_ids`에 넣고 자신을 만든 COMMITTED match candidate의 ID를 `source_primitive_match_id`에 넣는다. schema validation과 semantic validation을 통과한 proposal만 stable `hypothesis_id`가 있는 `VulnerabilityHypothesis`로 등록한다.

`observed_facts`, `restrictions`, `assumptions`는 다음 기준으로 나눈다.

- `observed_facts`: `StaticFactBundle`의 실제 `CodeFact`를 가리키는 관측 결과다.
- `restrictions`: 관측된 것 중 공격을 제한하는 검사·경계다. 근거가 된 `CodeFact`는 `observed_facts`에 함께 넣지 않는다. 하나의 관측 사실은 근거이거나 제약이다.
- `assumptions`: 관측으로 확인하지 못했지만 가설이 성립하려면 참이어야 하는 명제다.

확인하지 못한 것 중 가설이 의존하지 않는 공백은 가설에 넣지 않는다. 가설이 확인해야 할 미확인 조건은 `assumptions`와 `falsification_questions`가 담는다. `StaticFactBundle.gaps`의 `DataGap`은 도구·조회가 실패해 데이터를 얻지 못한 범위이며 가설의 미확인 조건과 다른 것이다. 가설 하나가 결과나 필요 조건을 여러 개 가질 수 있으며 가설의 단위는 규칙으로 강제하지 않는다. 등록된 `VulnerabilityHypothesis`는 이 세 갈래를 자기 필드로 복사하지 않는다. 소비자는 `proposal_ref`가 가리키는 exact `HypothesisProposal` revision에서 읽는다.

```yaml
VulnerabilityHypothesis:
  meta: RecordMeta
  proposal_ref: StoredDataRef
  origin: INITIAL | VERIFICATION | CHAINING
  parent_hypothesis_ids: [string]
  source_primitive_match_id: string | null
  statement: string
  target_entities: [CodeSymbol]
  target_locations: [CodeLocation]
  suspected_path: [CodeRelation | CodeLocation]
  falsification_questions: [FalsificationQuestion]
  validation_checks: [ValidationCheck]
```

`origin=VERIFICATION`은 Verification이 새 endpoint·sink·권한 경계·공격 단계·독립 impact를 분리한 proposal이고, `origin=CHAINING`은 upstream Primitive의 `result`가 downstream Primitive의 특정 `input`을 충족한 match가 만든 proposal이다. INITIAL과 VERIFICATION은 `source_primitive_match_id=null`, CHAINING은 분석 전체에서 유일하고 COMMITTED `ChainingResult.primitive_match_candidates`에 정확히 한 번 존재하는 ID가 필수다. 그 match의 parent hypothesis set은 proposal과 등록 가설의 `parent_hypothesis_ids`와 같아야 한다. 계보 길이가 필요하면 이 직접 링크를 따라 계산하며 별도 depth 값을 저장하지 않는다. 부모와 자식의 lifecycle·verdict는 독립이며 child 결과로 parent verdict를 바꾸지 않는다. proposal 출력 검증 runtime은 각 반증 질문에 전역 `question_id`, 각 필수 검증 항목에 전역 `validation_id`를 부여하고 등록 가설까지 그대로 유지한다. `instruction`은 무엇을 확인해야 완료되는지 짧게 설명한다. 질문은 가설의 필수 조건 하나를 실제 근거로 반증할 수 있게 구체적으로 작성한다. 금지된 확정 assertion, 잘못된 enum, 필수 field/location·반증 질문·검증 항목 누락 또는 중복 ID는 제한된 repair retry 뒤 `INVALID_OUTPUT`이다.

## 3. CodeContextRequest/Response

검증 단계가 필요한 코드 위치를 요청하고 정적분석 계층이 같은 `workspace_id`와 `commit_id`에서 코드를 돌려주는 형식입니다.

```yaml
CodeContextRequest:
  code_request_id: string
  meta: RecordMeta
  action_decision_ref: StoredDataRef
  requested_entities: [CodeSymbol]
  requested_locations: [CodeLocation]
  relation_query: [CALLERS | CALLEES | DATA_FLOW_NEIGHBORS | AUTH_GUARDS | ROUTE_BINDINGS]
  reason: string
  limits: ContextRetrievalLimits
```

`action_decision_ref.record_id`는 `READ_CODE` action을 `ALLOW`하고 `USED`로 claim한 exact decision revision을 가리킨다. 다른 workspace·commit·state version의 decision은 재사용하지 않는다.

```yaml
CodeContextResponse:
  code_request_id: string
  meta: RecordMeta
  entities: [CodeSymbol]
  locations: [CodeLocation]
  code_fragment_refs: [StoredDataRef]
  discovered_relations: [CodeRelation]
  gaps: [DataGap]
  errors: [AnalysisError]
  truncated: boolean
  returned_fragment_count: integer
  returned_bytes: integer
  consumed_token_estimate: integer | null
```

요청과 응답의 `meta.workspace_id` 또는 `meta.commit_id`가 다르거나, 이 값이 `CodeWorkspace`와 일치하지 않으면 `WORKSPACE_MISMATCH`로 기록하고 근거에 사용하지 않는다. 모든 limit은 0보다 커야 한다. `max_requests_per_hypothesis`는 같은 가설의 누적 요청 한도이며 Orchestration runtime이 `code_request_id` 수로 강제한다. empty/truncated/gap/error는 안전함 또는 `TRUE | FALSE | HOLD`를 뜻하지 않는다. `truncated=true`이면 `CONTEXT_TRUNCATED` gap이 반드시 있어야 한다. 조회 실패·timeout·권한 오류가 있으면 응답의 `errors`에 `AnalysisError(stage=CONTEXT)`를 넣고 그 오류 때문에 확인하지 못한 범위를 `gaps`의 `DataGap(stage=CONTEXT)`으로 함께 남긴다.

일부 요청이 실패했어도 제한 retry·대체 조회 또는 다른 정상 근거로 가설의 모든 `validation_checks`, 모든 반증 질문과 운영 Pro/Con을 완료했다면 Verification은 실제 근거에 따라 final `TRUE | FALSE | HOLD`를 만들 수 있다. 필수 Context나 운영 Pro/Con을 확보하지 못해 검증 절차 자체를 완료하지 못했다면 final `VerificationResult`를 만들지 않는다. 재시도할 수 있으면 해당 Verification work를 `BLOCKED`로 두고 `HypothesisProcessState.status=VERIFYING`을 유지한다. 허용된 재시도를 소진했거나 복구할 수 없으면 같은 atomic transition에서 work와 가설 처리 상태를 `FAILED`로 남긴다.

## 4. VerificationResult

검증 Agent가 찬성·반대·동적 근거를 모아 `TRUE / FALSE / HOLD` 판정과 남은 조건을 기록하는 결과입니다.

```yaml
VerificationPlaybook:
  meta: RecordMeta with hypothesis_id null and attempt_id null
  scope: COMMON | TYPE_SPECIFIC
  vulnerability_type: string | null
  prerequisites: [string]
  source_checks: [string]
  sink_checks: [string]
  path_checks: [string]
  defense_checks: [string]
  falsification_question_templates: [string]
  static_evidence_requirements: [string]
  dynamic_evidence_requirements: [string]
  restriction_checks: [string]
  hold_conditions: [string]

EvidenceClaim:
  claim_id: string
  statement: string
  source_role: VERIFICATION | PRO | CON
  evidence_refs: [StoredDataRef]
  code_locations: [CodeLocation]
  limitations: [string]

EvidenceAgentResult:
  meta: RecordMeta
  role: PRO | CON
  parent_work_id: string
  evidence_work_id: string
  verification_generation: integer
  llm_call_id: string
  debate_input_hash: string
  evidence: [EvidenceClaim]
  summary: string
  limitations: [string]

CandidateRef:
  candidate_id: string
  candidate_type: BYPASS | ALTERNATE_PATH | IMPACT_ESCALATION
  statement: string
  source_hypothesis_ids: [string]
  target_entities: [CodeSymbol]
  target_locations: [CodeLocation]
  evidence_refs: [StoredDataRef]
  missing_information: [string]
  candidate_state: UNVALIDATED

PrimitiveDraft:
  draft_id: string
  entity_refs: [CodeSymbol]
  privilege_level: string | null
  evidence_refs: [StoredDataRef]
  description: string

VerificationMetrics:
  pro_tokens: integer | null
  con_tokens: integer | null
  synthesis_tokens: integer | null
  elapsed_ms: integer
  verdict_changed_after_debate: boolean
  hold_resolved: boolean
  false_positive_reduction_candidate: boolean
  new_bypass_count: integer
  new_restriction_count: integer
  new_falsification_count: integer

FalsificationResult:
  question_id: string
  outcome: DISPROVED | NOT_DISPROVED | INCONCLUSIVE
  evidence_refs: [StoredDataRef]
  rationale: string

ValidationCheckResult:
  validation_id: string
  completion: COMPLETE | INCOMPLETE
  evidence_refs: [StoredDataRef]
  summary: string

VerificationResult:
  meta: RecordMeta
  playbook_ref: StoredDataRef
  verification_mode: BASIC | CONDITIONAL_DEBATE | ALWAYS_DEBATE
  debate_triggers: [string]
  debate_skip_reason: string | null
  debate_input_hash: string | null
  pro_evidence_ref: StoredDataRef | null
  con_evidence_ref: StoredDataRef | null
  supporting_evidence: [EvidenceClaim]
  counter_evidence: [EvidenceClaim]
  falsification_results: [FalsificationResult]
  validation_results: [ValidationCheckResult]
  initial_verdict: TRUE | FALSE | HOLD
  dynamic_request_ref: StoredDataRef | null
  dynamic_result_ref: StoredDataRef | null
  poc_ref: StoredDataRef | null
  verdict: TRUE | FALSE | HOLD
  verdict_rationale: string
  restrictions: [string]
  bypass_candidates: [CandidateRef]
  required_primitive_candidates: [PrimitiveDraft]
  provided_primitive_candidates: [PrimitiveDraft]
  impact_escalation_candidates: [CandidateRef]
  material_child_proposals: [HypothesisProposal]
  unresolved_conditions: [string]
  metrics: VerificationMetrics
  errors: [AnalysisError]
```
`VerificationPlaybook.meta.logical_record_id`는 플레이북 식별자이고 `meta.revision_number`는 내용 revision이다. `schema_version`은 플레이북 데이터 구조의 버전이므로 내용 revision과 구분한다. 플레이북 내용이 변경되면 기존 record를 수정하지 않고 새 `record_id`, 증가한 `revision_number`와 새 `content_hash`를 만든다.

`scope=COMMON`이면 `vulnerability_type=null`, `scope=TYPE_SPECIFIC`이면 `vulnerability_type`이 필수다. 지원 유형 목록이 확정되기 전이나 미지원 유형을 검증할 때는 현재 저장된 공통 플레이북의 exact revision을 사용한다.

플레이북 후보는 R6 검증·반박·플레이북 담당이 작성하고, trusted playbook registry runtime이 schema와 revision을 검사해 immutable record로 등록한다. Verification work를 등록하는 trusted runtime은 versioned 적용 규칙에 따라 지원 유형과 일치하는 current `TYPE_SPECIFIC` revision을 선택하고, 적용 가능한 유형별 플레이북이 없으면 current `COMMON` revision을 선택한다. Agent가 실행 도중 임의로 다른 revision을 선택할 수 없다.

`VerificationResult.playbook_ref`는 실제 검증에 사용한 exact `VerificationPlaybook.record_id`와 `content_hash`를 가리킨다. Verification Agent의 직접 검증, `PRO_EVIDENCE`, `CON_EVIDENCE`, final Verification 합성 호출 및 `SAVE_RESULT(result_kind=verification_result)`는 모두 해당 Verification work에 고정된 동일한 `playbook_ref`를 사용해야 한다. Runtime Validator는 각 action의 `input_refs`, 각 LLM 호출의 `LLMCallSpec.context_refs`, 최종 `VerificationResult.playbook_ref` 및 `SAVE_RESULT.input_refs`가 work의 `WorkExecutionState.input_refs`에 고정된 reference와 동일한 `record_id`·`content_hash`를 사용하는지 검사한다. 이후 플레이북에 새 revision이 생겨도 과거 `VerificationResult`는 자신이 실제 사용한 기존 revision을 계속 가리킨다.

`debate_input_hash`는 Pro와 Con이 함께 받은 공통 검증 입력을 canonical JSON으로 만든 SHA-256 값이다. 공통 입력에는 ACTIVE `VerificationAssignment`, exact 가설, 코드·Context·정적 근거 reference, 반증 질문, 검증 항목, exact 플레이북 revision, versioned Debate 설정과 예산 profile을 포함한다. 역할별 system instruction, 시각, worker 이름, `attempt_id`, `llm_call_id`와 session ID는 넣지 않는다. 따라서 두 역할의 prompt는 달라도 같은 사실·설정 묶음을 받았는지 비교할 수 있다.

`EvidenceAgentResult`는 수정할 수 없는 역할별 결과 record다. `role=PRO`이면 `evidence`의 모든 `source_role`은 `PRO`, `role=CON`이면 모두 `CON`이어야 한다. 한 결과 안의 `claim_id`는 중복될 수 없고 `summary`는 비어 있을 수 없다. 찾은 근거가 없다면 빈 `evidence`와 그 사실·확인 범위를 설명하는 `summary`·`limitations`를 저장하며 근거를 만들어 내지 않는다. `parent_work_id`는 현재 generation의 부모 `VERIFICATION.work_id`, `evidence_work_id`는 결과를 확정한 역할별 자식 work ID, `verification_generation`은 부모가 속한 현재 가설 generation, `meta.attempt_id`는 그 자식의 성공 attempt ID와 같아야 한다. `llm_call_id`는 결과를 만든 성공 호출 하나와 같아야 한다. 자식 work의 일반 `input_hash`는 역할별 template까지 포함하므로 Pro와 Con이 다를 수 있지만, 두 결과의 `debate_input_hash`는 반드시 같다. 자식 work의 `output_refs`와 해당 `LLMInvocationResult.parsed_output_ref` 및 `LLMInvocationLog.parsed_output_ref`가 이 exact result revision을 단방향으로 가리킨다. 결과가 invocation record나 종료 work revision을 다시 가리키지 않으므로 content hash 순환을 만들지 않는다.

운영 `purpose=PRODUCTION`은 항상 `verification_mode=ALWAYS_DEBATE`이며 `debate_input_hash`, `pro_evidence_ref`, `con_evidence_ref`가 모두 필수다. 평가 실행에서 실제 Debate를 수행한 `ALWAYS_DEBATE` 또는 trigger가 발생한 `CONDITIONAL_DEBATE`도 세 필드가 모두 필수다. 평가용 `BASIC` 또는 trigger가 발생하지 않은 `CONDITIONAL_DEBATE`는 세 필드를 모두 `null`로 두고, 후자는 비어 있지 않은 `debate_skip_reason`을 남긴다. 필수 reference 하나라도 없으면 final 결과를 저장하지 않는다.

두 evidence reference는 각각 COMMITTED `EvidenceAgentResult(role=PRO)`와 `EvidenceAgentResult(role=CON)` exact revision을 가리켜야 한다. 두 결과는 같은 analysis·workspace·commit·hypothesis, 같은 부모 Verification `work_id`, 같은 `verification_generation`, 같은 `debate_input_hash`를 가져야 하며 서로 다른 `evidence_work_id`, `meta.attempt_id`, `llm_call_id`와 LLM log에 연결되어야 한다. final Verification 합성용 `LLMCallSpec.context_refs`와 `SAVE_RESULT.input_refs`에는 이 두 exact result reference를 각각 한 번 포함한다. final `supporting_evidence`와 `counter_evidence`는 이 두 결과와 Verification의 추가 근거를 출처별로 보존해 합성하며, 다른 generation·입력의 결과를 섞으면 `STALE_RESULT`, Pro/Con 입력에 상대 역할 결과가 섞이면 `CROSS_ROLE_INPUT_DENIED`로 거절한다.

`EvidenceAgentResult`는 새 record schema다. `WorkExecutionState.parent_work_ref`를 Pro/Con에 필수로 만드는 변경과 `VerificationResult`의 세 Debate 연결 필드는 기존 운영 결과의 허용 조건을 바꾸므로 각 record의 새 MAJOR schema로 배포한다. 이전 MAJOR record는 감사 기록으로 보존할 수 있지만 새 운영 Gate·Primitive·Reporter 입력으로 자동 승격하거나 새 필드를 추정해 채우지 않는다.

`EvidenceClaim.claim_id`는 한 `VerificationResult` 안에서 유일하다. 각 claim은 실제 저장 근거를 가리키는 `evidence_refs`를 하나 이상 가져야 하며, 코드 주장이라면 현재 `workspace_id + commit_id`의 `code_locations`도 하나 이상 가져야 한다. `source_role`은 claim을 작성한 역할이며 근거의 출처를 대신하지 않는다. supporting 목록에는 `VERIFICATION | PRO`, counter 목록에는 `VERIFICATION | CON`만 허용한다.

`CandidateRef`는 아직 검증되지 않은 우회·대체 경로·영향 확대 후보다. `candidate_id`는 한 결과 안에서 유일하고 `candidate_state`는 항상 `UNVALIDATED`다. 현재 가설을 `source_hypothesis_ids`에 포함하며, 실제 근거가 있으면 `evidence_refs`, 아직 필요한 사실은 `missing_information`에 넣는다. 후보가 새로운 endpoint·sink·권한 경계·공격 단계 또는 영향을 주장하면 `material_child_proposals`에 `origin=VERIFICATION`인 새 `HypothesisProposal`을 넣는다. trusted validation과 전역 등록 뒤 전체 검증을 거치기 전까지 verdict, CWE, Gate 또는 보고서의 확정 주장으로 사용할 수 없다.

`PrimitiveDraft`는 Verification이 발견한 필요 조건 또는 제공 가능 능력을 같은 모양으로 표현하지만 Primitive DB admission record는 아니다. `draft_id`는 같은 `VerificationResult` 안에서 유일하다. `entity_refs`는 현재 workspace·commit의 코드 요소를 가리키고 `evidence_refs`는 조건·능력의 근거를 하나 이상 가리킨다. `privilege_level`은 저장소 코드에 실제로 나타난 역할명·권한 상수·검사 지점에서만 가져오며 조건에 권한 축이 없으면 `null`이다. 전역 권한 서열표나 이름만 같은 문자열로 충족 관계를 만들지 않는다. final HOLD의 `required_primitive_candidates`는 result가 없는 Primitive의 `inputs`가 된다. final TRUE의 `required_primitive_candidates`는 result가 있는 각 Primitive의 `inputs`, `provided_primitive_candidates`의 각 항목은 서로 다른 Primitive의 `result`가 된다. `FALSE`이면 두 목록이 모두 비어 있어야 한다.

`VerificationMetrics`의 token 값은 provider가 값을 제공하지 않으면 `null`이고, 나머지 정수는 모두 0 이상이어야 한다. debate를 실행하지 않았으면 `pro_tokens`와 `con_tokens`는 `null`, `verdict_changed_after_debate=false`다. `hold_resolved=true`는 `initial_verdict=HOLD`이고 final `verdict`가 `TRUE | FALSE`일 때만 허용한다. initial TRUE는 final 결과가 아니며 `POC_CONFIRMATION` request를 만들기 위한 중간 판단이다. initial TRUE와 PoC가 일치해 `SUCCEEDED + SUPPORTED`가 된 뒤에만 final TRUE를 저장한다.

`VerificationResult.dynamic_request_ref`가 있으면 current Verification generation의 COMMITTED `DynamicReproductionRequest`, `dynamic_result_ref`는 그 request에서 생성된 같은 가설·workspace·commit의 COMMITTED `DynamicReproductionResult` exact revision을 가리킨다. final `TRUE`에는 current Verification generation의 exact `DynamicReproductionRequest`, `SUCCEEDED + SUPPORTED` 동적 결과와 validated `poc_ref`가 모두 필수다. `VerificationResult.poc_ref`는 동적 결과의 `poc_ref`와 같은 `stored_data_id`, `record_id`, `content_hash`를 사용한다. `FALSE | HOLD`는 validated PoC를 가질 수 없으므로 `poc_ref=null`이며, dynamic 결과를 사용했다면 request와 result reference는 유지한다. 오류·정책 차단·환경 설정·PoC 생성·실행 실패 결과는 final VerificationResult의 근거로 소비하지 않는다.

최종 `VerificationResult`는 등록 가설의 모든 `question_id`와 `validation_id`를 각각 중복 없이 정확히 한 번씩 평가한다. 가설의 모든 `ValidationCheck.validation_id`와 candidate의 `ValidationCheckResult.validation_id`가 중복 없이 set-equal해야 한다. 모든 `ValidationCheckResult.completion=COMPLETE`이고 각 결과의 `evidence_refs`가 하나 이상이어야 final 결과를 확정할 수 있다. 확인을 끝내지 못한 항목은 `INCOMPLETE`로 표현하되, `INCOMPLETE` 항목이 하나라도 있으면 final candidate를 `COMMITTED`하지 않는다. `DISPROVED`는 해당 질문이 확인하려는 가설의 필수 조건이 실제 근거로 반증됐다는 뜻이며 `evidence_refs`가 하나 이상이어야 한다. `NOT_DISPROVED`는 반증하지 못했다는 뜻일 뿐 가설을 증명하지 않는다. 확인하지 못한 질문은 `INCONCLUSIVE`로 남긴다. `verdict=TRUE`는 실제 supporting evidence가 핵심 공격 경로와 필요한 조건을 연결할 때만 허용한다. `verdict=FALSE`는 적어도 하나의 `DISPROVED` 결과가 있고 `verdict_rationale`이 그 `question_id`와 근거를 설명할 때만 허용한다. `verdict=HOLD`는 정상 근거로 확인한 범위와 비어 있지 않은 `unresolved_conditions`가 결론을 막는 중요한 조건을 설명할 때만 허용한다. `TRUE | HOLD`에는 `DISPROVED` 결과가 있을 수 없다. `AnalysisError`, `DataGap`, timeout·권한 오류 또는 빈 Context만으로는 어느 verdict도 만들지 않는다.

## 5. Primitive DB records

연계 공격 탐색을 위해 보류된 가설의 필요 조건과 확인된 공격 능력을 저장하는 데이터입니다.

```yaml
Primitive:
  meta: RecordMeta
  primitive_id: string
  workspace_id: string
  commit_id: string
  inputs: [PrimitiveDraft]
  result: PrimitiveDraft | null
  restrictions: [string]
  source_hypothesis_id: string
  source_verification_ref: StoredDataRef
  technical_review_ref: StoredDataRef | null
  evidence_refs: [StoredDataRef]
  description: string
```

```yaml
PrimitiveIndexState:
  meta: RecordMeta with attempt_id null
  current_verification_ref: StoredDataRef
  primitive_refs: [StoredDataRef]
  updated_at: timestamp
```

```yaml
PrimitiveMatchCandidate:
  primitive_match_id: string
  upstream_result_ref: StoredDataRef
  downstream_input_ref: StoredDataRef
  matched_input_id: string
  parent_hypothesis_ids: [string]
  parent_verification_refs: [StoredDataRef]
  workspace_id: string
  commit_id: string
  normalized_fingerprint: string
  evidence_refs: [StoredDataRef]
  candidate_state: UNVALIDATED
```

`Primitive`는 status를 저장하지 않는다. `result=null`이면 final HOLD에서 나온 입력 조건 묶음이고, `result`가 있으면 final TRUE에서 나온 확인된 능력이다. `workspace_id`와 `commit_id`는 `meta`와 exact match한다. `inputs[].draft_id`는 Primitive 안에서 중복될 수 없으며 `result.draft_id`도 같은 Primitive의 input ID와 겹치지 않는다. `evidence_refs`는 inputs, result와 restrictions의 출처를 추적할 수 있어야 한다.

final HOLD는 `required_primitive_candidates`가 하나 이상일 때 Primitive 하나를 만든다. `inputs`는 그 목록과 내용·순서가 같고 `result=null`, `technical_review_ref=null`, `restrictions`는 exact Verification 값과 같다. final FALSE는 Primitive를 만들지 않는다.

final TRUE는 현재 Verification generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 validated PoC가 있고 같은 Verification+CWE를 검토한 Technical `ACCEPT`가 있을 때만 result가 있는 Primitive를 만든다. 제공 능력이 여러 개면 `provided_primitive_candidates` 항목마다 Primitive 하나를 만들고, 각 Primitive의 `inputs`는 같은 TRUE의 `required_primitive_candidates`, `result`는 해당 제공 능력 하나, `restrictions`는 Verification 값과 같아야 한다. Gate 전 TRUE는 result가 있는 Primitive가 될 수 없다. Technical `REVISE | REJECT`도 admission할 수 없다.

Technical `ACCEPT`은 체이닝 재료의 자격을 확정하고 Rule Scope는 보고 가능성만 판단한다. Rule Scope 결과는 이미 admission된 Primitive를 취소하지 않는다. `FAIL | UNCERTAIN | DENY`는 Finding·Reporter 경로를 막지만 실제 코드 능력의 Primitive 저장과 Chaining을 막지 않는다. Technical Gate는 이를 위해 validated PoC 연결, 금지된 재현으로 오염되지 않은 근거, 실제 코드 경로와 restrictions 표현의 정확성을 검토한다.

가설마다 하나인 `PrimitiveIndexState`는 current final Verification과 그 결과에서 admission된 모든 Primitive exact reference를 가리킨다. 전용 `state_version`, status별 목록과 사후 `SUPERSEDED` lifecycle은 사용하지 않는다. 동시 쓰기 손실은 공통 immutable record 규칙으로 막는다. 새 index revision은 직전 `record_id`와 연속된 `meta.revision_number`를 사용하고 current pointer를 atomic하게 바꾼다. 이는 모든 저장 record에 적용되는 revision 검사이며 Chaining 결과 저장 직전의 별도 index CAS가 아니다.

`PrimitiveMatchCandidate.upstream_result_ref`와 `downstream_input_ref`는 nested draft가 아니라 각각 result가 있는 upstream Primitive record와 하나 이상의 input을 가진 downstream Primitive record의 exact reference다. `matched_input_id`는 downstream `inputs[].draft_id` 하나와 같아야 한다. upstream result가 downstream input을 충족한다는 사실은 다음 두 축으로만 판단한다.

- `entity_refs`: 같은 코드 요소이거나 호출·데이터·권한 경계 관계로 연결된다는 코드 근거
- `privilege_level`: 조건에 권한 축이 있으면 저장소의 역할명·권한 상수·검사 위치로 입증한 충족 관계

전역 권한 서열표, 문자열 이름의 단순 일치나 근거 없는 추측은 사용하지 않는다. 양쪽 restrictions를 합친 뒤에도 공격 순서가 성립해야 하며 `evidence_refs`는 entity·privilege·순서·restriction 결론의 실제 근거를 하나 이상 포함한다. 축이 맞지 않거나 근거가 없으면 후보를 만들지 않고 `ChainingResult.no_match_reasons`에 이유를 남긴다. 후보가 존재한다는 것 자체가 비교를 통과했다는 뜻이므로 PASS/UNCERTAIN check와 unresolved 조건을 중복 저장하지 않는다.

downstream Primitive의 `result=null`이면 TRUE_HOLD, non-null이면 TRUE_TRUE로 유도한다. `primitive_match_id`는 분석 전체에서 유일하고 같은 `normalized_fingerprint`도 중복 저장하지 않는다. match는 queue message, verdict, Finding 또는 impact 확정이 아니다.

## 6. ChainingResult

Chaining Agent가 upstream Primitive `result`→downstream Primitive `input` matching 결과와 새로 검증할 가설 후보를 반환하는 결과입니다.

```yaml
ChainingResult:
  meta: RecordMeta
  source_result_refs: [StoredDataRef]
  input_primitive_refs: [StoredDataRef]
  primitive_match_candidates: [PrimitiveMatchCandidate]
  chained_hypothesis_proposals: [HypothesisProposal]
  no_match_reasons: [string]
  errors: [AnalysisError]
```

`source_result_refs`는 입력 Primitive를 만든 exact Verification과 Technical review 결과의 중복 없는 합집합이다. `input_primitive_refs`는 모든 candidate의 upstream/downstream Primitive reference 합집합과 set-equal해야 한다. downstream result 유무로 TRUE_HOLD와 TRUE_TRUE를 유도하며 별도 trigger나 match kind를 저장하지 않는다. `chained_hypothesis_proposals`는 모두 `origin=CHAINING`, 입력 Primitive의 parent hypothesis ID와 exact `source_primitive_match_id`를 보존한다.

순환 검사는 각 parent hypothesis의 `source_primitive_match_id`를 따라 조상 match와 입력 Primitive를 역방향으로 걷는다. 이 과정에서 만난 ancestor Primitive를 현재 순회의 후보에서 제외한다. DB 상태는 바꾸지 않는다. 체이닝 전용 임의 depth·전체/parent별 가설 수·호출 수·Primitive 조합 수 한도는 두지 않는다. 대신 R8의 전체 token·시간·비용·work 예산을 모든 Chaining work에 동일하게 적용한다. 예산 소진은 `FALSE`가 아니며 실행 상태와 `AnalysisRunResult.stop_reasons`에 기록한다.

ChainingResult는 bypass, alternate path, 새 sink, impact escalation, Technical revision, 일반 validation 또는 동적 재현 요청을 포함할 수 없다. 이런 주장은 Verification이 자기 흐름에서 조사하고 material하면 `origin=VERIFICATION` proposal로 분리한다. 이 record는 기존 verdict, CWE, Gate 또는 Finding을 변경하지 않는다.

## 7. CWELabel과 DynamicReproductionResult

취약점 유형 분류와 Docker 재현의 환경·실행 단계·관찰 결과를 각각 기록합니다.

```yaml
CWELabel:
  meta: RecordMeta
  primary: string | null
  alternatives: [string]
  taxonomy_version: string
  rationale: string
  evidence_refs: [StoredDataRef]
  uncertainty: string | null
```

```yaml
EnvironmentNeed:
  need_id: string
  kind: APP_ROLE | AUTH | DATA | DATABASE | SERVICE | FIXTURE | MOCK | VERSION | HEALTH_CHECK
  description: string
  required: boolean
  source_refs: [StoredDataRef]

DynamicReproductionRequest:
  meta: RecordMeta
  verification_assignment_ref: StoredDataRef
  verification_generation: integer
  hypothesis_ref: StoredDataRef
  purpose: POC_CONFIRMATION | VERDICT_EVIDENCE
  initial_verdict: TRUE | HOLD
  goal: string
  environment_needs: [EnvironmentNeed]
  sandbox_profile_ref: StoredDataRef
  code_refs: [StoredDataRef]
  static_evidence_refs: [StoredDataRef]
  pro_evidence_ref: StoredDataRef
  con_evidence_ref: StoredDataRef
  created_at: timestamp

EnvironmentRequirement:
  requirement_id: string
  kind: APP_ROLE | AUTH | DATA | DATABASE | SERVICE | FIXTURE | MOCK | VERSION | HEALTH_CHECK
  name: string
  required: boolean
  expected: string | null
  expected_ref: StoredDataRef | null
  alternatives: [string]
  check_ref: StoredDataRef | null
  secret_ref: StoredDataRef | null
  source_refs: [StoredDataRef]

EnvironmentRequirements:
  meta: RecordMeta
  request_ref: StoredDataRef
  items: [EnvironmentRequirement]

ReproductionStep:
  step_id: string
  command_ref: StoredDataRef
  attack_input_refs: [StoredDataRef]
  required: boolean

ReproductionPlan:
  meta: RecordMeta
  request_ref: StoredDataRef
  purpose: POC_CONFIRMATION | VERDICT_EVIDENCE
  mode: LIMITED_REPRO | FULL_REPRO
  hypothesis_ref: StoredDataRef
  environment_requirements_ref: StoredDataRef
  sandbox_profile_ref: StoredDataRef
  poc_candidate_ref: StoredDataRef
  steps: [ReproductionStep]
  cleanup_policy_ref: StoredDataRef

EnvironmentCheck:
  requirement_id: string
  status: MATCH | MISMATCH | NOT_CHECKED | ERROR
  actual: string | null
  actual_ref: StoredDataRef | null
  difference: string | null
  evidence_refs: [StoredDataRef]
  check_result_ref: StoredDataRef | null

SandboxEnvironment:
  meta: RecordMeta
  reproduction_plan_ref: StoredDataRef
  requirements_ref: StoredDataRef
  status: READY | MISMATCH | ERROR
  checks: [EnvironmentCheck]
  created_at: timestamp

SandboxStepEntry:
  step_id: string
  command_ref: StoredDataRef
  attack_input_refs: [StoredDataRef]
  status: SUCCEEDED | FAILED | SKIPPED | CANCELLED
  observation_refs: [StoredDataRef]

SandboxStepLog:
  meta: RecordMeta
  reproduction_plan_ref: StoredDataRef
  entries: [SandboxStepEntry]

DynamicReproductionResult:
  meta: RecordMeta
  action_decision_ref: StoredDataRef
  request_ref: StoredDataRef
  reproduction_plan_ref: StoredDataRef
  purpose: POC_CONFIRMATION | VERDICT_EVIDENCE
  mode: LIMITED_REPRO | FULL_REPRO
  policy_decision_ref: StoredDataRef | null
  runner_invoked: boolean
  environment_created: boolean
  environment_ref: StoredDataRef | null
  steps_ref: StoredDataRef | null
  poc_candidate_ref: StoredDataRef | null
  poc_ref: StoredDataRef | null
  attack_input_refs: [StoredDataRef]
  cleanup_policy_ref: StoredDataRef
  observation_refs: [StoredDataRef]
  status: SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED
  failure_reason: NONE | EXTERNAL_CONFIGURATION | ENVIRONMENT_SETUP | EXECUTION | OBSERVATION | POLICY_BLOCKED | TIMEOUT | RETRY_LIMIT
  hypothesis_outcome: SUPPORTED | DISPROVED | INCONCLUSIVE
  hypothesis_evidence_refs: [StoredDataRef]
  hypothesis_disproved: boolean
  disproof_evidence_refs: [StoredDataRef]
  hypothesis_linkage: string
  limitations: [string]
  cleanup_required: boolean
  cleanup_status: SUCCEEDED | FAILED | NOT_REQUIRED
  started_at: timestamp
  finished_at: timestamp
  elapsed_ms: integer
```

`status`는 재현 작업을 얼마나 실행했는지, `hypothesis_outcome`은 유효한 관측이 가설과 어떤 관계인지 나타내며 둘 다 Verification verdict가 아니다. 다음 조합만 허용한다.

`DynamicReproductionRequest`는 R6 Verification이 R7에 무엇을 왜 재현할지 전달하는 불변 record다. `verification_assignment_ref`, `verification_generation`과 `hypothesis_ref`는 current Verification work와 exact match한다. `POC_CONFIRMATION`은 `initial_verdict=TRUE`, `VERDICT_EVIDENCE`는 아직 결론에 필요한 동적 근거가 남은 `initial_verdict=HOLD`만 허용한다. `goal`은 어떤 관측이 가설 지지·반증·불충분인지 설명한다. `environment_needs`는 하나 이상이고 각 `need_id`는 request 안에서 유일하며 실제 코드·정적 근거를 가리키는 `source_refs`가 필요하다. production에서는 exact `pro_evidence_ref`와 `con_evidence_ref`가 필수다. R7은 request의 purpose·goal·가설·필수 환경 조건과 `sandbox_profile_ref`를 변경하지 않는다.

`EnvironmentRequirements`는 R7이 exact request의 `environment_needs`를 실제 환경 구성·검사 항목으로 구체화한 불변 요구사항 record다. `request_ref`는 current R7 work의 exact `DynamicReproductionRequest`를 가리킨다. `items`는 하나 이상이고 `requirement_id`는 record 안에서 유일하다. `APP_ROLE`은 대상 애플리케이션 역할·권한, `AUTH`는 인증 방식, `DATA`는 필요한 데이터 상태, `DATABASE | SERVICE`는 DB와 외부 service, `FIXTURE | MOCK`은 준비 자료, `VERSION`은 필수 버전, `HEALTH_CHECK`는 실행 전 확인 조건을 뜻한다. 각 request need는 같은 `need_id` 또는 exact source 연결로 하나 이상의 item에 포함되어야 하고, R7은 `required=true` 조건을 선택 사항으로 낮추거나 내용을 누락할 수 없다. 각 item은 하나 이상의 exact `source_refs`와 `expected`, `expected_ref` 또는 `check_ref` 중 실제 요구를 표현하는 값이 하나 이상 필요하다.

credential·cookie·token·password와 재사용 가능한 인증 값은 `expected`, `alternatives`, source·check artifact와 일반 log에 저장하지 않는다. 비밀이 필요하면 허용된 secret store의 불투명 `secret_ref(data_kind=secret_handle)`만 사용한다. retry에서 환경 구체화가 바뀌면 R7이 새 `EnvironmentRequirements.record_id`를 만들고 이전 revision은 감사 이력으로 남긴다. 새 requirements도 같은 immutable request를 충족해야 하며 다른 목적·가설·profile로 바꿀 수 없다.

`ReproductionPlan`은 R7이 `SAVE_RESULT(result_kind=reproduction_plan)`로 생산하고 신뢰 runtime이 schema와 reference를 확인해 `COMMITTED`하는 실행 계획이다. `request_ref`와 `purpose`는 R6 request, `environment_requirements_ref`는 같은 R7 work·attempt의 current requirements, `hypothesis_ref`와 `sandbox_profile_ref`는 request 값과 exact match한다. request는 재현 목적을 정하고, R7은 그 목표를 안전하게 달성할 `LIMITED_REPRO | FULL_REPRO` mode를 선택한다. `poc_candidate_ref`는 실행 전 PoC 스크립트·요청·입력의 exact `poc_candidate` revision이다. `steps`는 실행 순서대로 나열하며 `step_id`는 계획 안에서 유일하다. `command_ref`와 `attack_input_refs`는 candidate를 실제로 실행하는 명령·입력과 일치해야 한다. `cleanup_policy_ref`는 종료·실패·취소 때 적용할 정리 규칙이다. retry에서 requirements·mode·step·candidate·cleanup이 바뀌면 새 immutable record를 만들고 새 `RUN_SANDBOX` action을 받는다. `DynamicReproductionRequest`, `EnvironmentRequirements`, `ReproductionPlan`과 `DynamicReproductionResult` 변경은 새 MAJOR schema로 배포한다.

PoC candidate 생성 전에 실패하면 아직 실행할 plan과 `RUN_SANDBOX` decision이 없으므로 `ReproductionPlan`이나 `DynamicReproductionResult`를 억지로 만들지 않는다. 해당 attempt에 `AnalysisError(code=POC_GENERATION_FAILED)`를 남기고 `DynamicReproductionState.dynamic_result_ref=null`, `poc_candidate_ref=null`, validated `poc_ref=null`을 유지한다. 재시도 가능하면 같은 `DYNAMIC_REPRO.work_id`를 `BLOCKED`로 두고 새 attempt를 만들며, 복구 불가능하거나 한도를 소진하면 work와 Verification을 verdict 없이 `FAILED`로 끝낸다.

`SandboxEnvironment`는 R7이 해당 attempt에서 실제로 만든 환경과 요구사항 비교를 기록하는 불변 `sandbox_environment` record다. `requirements_ref`는 plan의 `environment_requirements_ref`, `reproduction_plan_ref`는 실행한 exact plan과 같아야 한다. `checks`는 요구사항의 모든 `requirement_id`를 정확히 한 번씩 포함한다. `MATCH | MISMATCH`에는 공개 가능한 `actual` 또는 실제 구성 artifact를 가리키는 exact `actual_ref` 중 하나 이상이 필요하다. `NOT_CHECKED | ERROR`에서는 두 필드가 모두 `null`일 수 있지만 비어 있지 않은 `difference`와 비교 시도 근거가 필요하다. 모든 check는 `evidence_refs` 또는 `check_result_ref` 중 하나 이상을 가져야 하며, `check_result_ref`는 Health Check 결과를 가리킨다. 실제 비밀값은 어느 필드에도 저장하지 않는다.

필수 item은 모두 `MATCH`이고 필수 setup 오류가 없어야 `SandboxEnvironment.status=READY`다. VERSION의 실제 값이 `expected` 또는 plan을 만들 때 R7이 안전하게 명시한 `alternatives` 중 하나면 `MATCH`로 기록할 수 있으며 대체 버전을 썼다면 `difference`에 그 사실을 남긴다. 대체값은 R6 request의 필수 조건을 약화하거나 Sandbox profile을 우회할 수 없다. `MISMATCH | NOT_CHECKED | ERROR`에는 비어 있지 않은 `difference`가 필요하다. 필수 item에 확인된 값 차이 또는 미확인이 있으면 환경 status는 `MISMATCH`, setup·비교 자체의 오류가 있으면 `ERROR`이고 승인된 공격 단계를 시작하지 않는다. 선택 item의 차이·오류만 `limitations`에 남기고 진행할 수 있다.

`action_decision_ref.record_id`는 R7 요청자의 권한·상태·예산과 exact `DynamicReproductionRequest`, `ReproductionPlan`, current `EnvironmentRequirements`, PoC candidate와 Sandbox profile을 확인해 Controller 호출을 허가한 `RUN_SANDBOX` ALLOW decision의 `USED` revision을 가리킨다. 이 decision은 환경 일치, image·tool·file·network·resource·cleanup 정책 통과나 PoC 성공을 뜻하지 않으며 다른 가설·attempt·request·plan에 재사용하지 않는다. Sandbox Controller는 decision이 가리키는 plan closure의 세부 정책을 검사하고 exact `sandbox_policy_decision`을 저장한다. `failure_reason=POLICY_BLOCKED`이면 `policy_decision_ref`가 반드시 존재하고 적용한 정책의 exact revision, `ALLOW | DENY` 결과와 사유 코드를 확인할 수 있어야 한다. 이 정책 판정은 Technical Gate와 다른 결과이며 서로 변환하지 않는다.

Sandbox Controller가 정책을 통과한 계획만 Sandbox Runner에 전달한다. Runner는 환경 준비 단계에서 plan이 가리키는 exact 요구사항과 실제 환경·Health Check를 비교해 `SandboxEnvironment`를 먼저 확정한다. 필수 item이 모두 `MATCH`일 때만 승인된 공격 단계를 계속한다. 필수 `MISMATCH | NOT_CHECKED | ERROR`가 있으면 공격 단계를 시작하지 않고 R7에 exact 차이를 반환한다. `runner_invoked=false`이면 `steps_ref=null`이고 실제 실행 입력을 뜻하는 `attack_input_refs`도 비어 있어야 한다. `runner_invoked=true`이면 성공·실패·취소와 관계없이 exact `SandboxStepLog`를 가리키는 `steps_ref`가 필수다. 환경 차이로 첫 공격 단계 전에 멈춘 log는 `entries=[]`이거나 모든 entry가 `SKIPPED`여야 하며 result의 `attack_input_refs`도 비어 있어야 한다. 그 밖의 log는 실행 중 append-only로 만들고 종료 시 immutable artifact로 확정한다. 각 log entry의 `step_id`, `command_ref`, `attack_input_refs`는 계획의 같은 단계와 field-by-field exact match여야 하고 계획에 없는 entry를 허용하지 않는다. 실행하지 못한 required step은 결과 상태와 `limitations` 또는 실패 이유에 반영한다. 결과의 `attack_input_refs`는 log에서 실제 사용한 입력 reference의 중복 없는 합집합이고 `cleanup_policy_ref`는 계획 값과 같아야 한다.

`environment_created`는 실제 Sandbox 환경이 만들어졌는지를 나타낸다. `false`이면 `environment_ref=null`, `true`이면 `environment_ref`가 필수다. `environment_ref`의 기존 의미는 바꾸지 않으며 해당 attempt에서 실제 생성된 exact `sandbox_environment` record만 가리킨다. 이 record의 `requirements_ref`는 `reproduction_plan_ref -> environment_requirements_ref`와 exact match여야 한다. 계획용 요구사항·Sandbox 보안 profile과 실제 생성 환경 record를 같은 reference로 사용하지 않는다. `DynamicReproductionResult`에는 `environment_requirements_ref`를 중복 저장하지 않고 plan과 environment의 두 경로를 대조한다. `runner_invoked=false`여도 Controller 검사 전에 build·환경 준비가 끝났다면 `environment_created=true`일 수 있다.

`poc_candidate_ref`는 실행 전 작성했거나 실패 attempt에서 사용한 스크립트·요청·입력 묶음을 가리키며 성공을 뜻하지 않는다. `poc_ref`는 실제 취약점 재현에 성공한 validated PoC만 가리킨다. `status=SUCCEEDED`, `hypothesis_outcome=SUPPORTED`, `runner_invoked=true`이고 `SandboxStepLog`가 exact candidate revision 또는 digest를 실제 실행해 지지 관측을 만들었을 때만 `poc_ref`가 필수다. candidate 생성 후 실행 실패, `DISPROVED | INCONCLUSIVE`, `PARTIAL | FAILED | BLOCKED | CANCELLED`에서는 `poc_ref=null`이다. 실패한 candidate와 입력은 `poc_candidate_ref`, plan과 step log에 보존하되 validated PoC로 승격하지 않는다. “가장 최신 PoC”를 다시 조회하거나 candidate와 validated PoC를 한 reference로 덮어쓰지 않는다.

`cleanup_required`는 container·network·volume·image/build 임시 자원·임시 파일 등 정리 대상이 하나라도 생성됐는지를 나타낸다. `false`이면 `cleanup_status=NOT_REQUIRED`, `true`이면 `cleanup_status=SUCCEEDED | FAILED`만 허용한다. 정책 차단이라는 이유만으로 `NOT_REQUIRED`를 선택하지 않는다. Controller 차단 전에 임시 자원이 생겼다면 정리를 수행하고 성공 또는 실패를 기록한다. 실제 자원이 있는데 `cleanup_required=false` 또는 `cleanup_status=NOT_REQUIRED`인 결과는 계약 위반이다. 무엇을 정리 대상으로 판단하고 자원별 결과를 어떻게 적는지는 R7 schema가 정의한다.

다음 reference는 모두 `record_id`가 있는 `StoredDataRef`를 사용한다. target record의 analysis·workspace·commit·hypothesis는 동적 결과와 같아야 한다. request의 `verification_generation`, requirements·plan·candidate·result의 `request_ref`, plan/result의 `purpose`, plan/action의 `sandbox_profile_ref`가 exact match해야 한다. R7이 만드는 requirements·plan·candidate·정책·환경·log·동적 결과는 같은 `DYNAMIC_REPRO` work와 해당 attempt에 묶는다. retry는 같은 `work_id`의 새 `attempt_id`이며 과거 attempt artifact를 current 결과에 섞지 않는다. 별도 `reproduction_id`를 발급하지 않고 exact `DynamicReproductionRequest.record_id + work_id + attempt_id`로 시도를 식별한다.

| reference 위치 | `data_kind` | 만드는 주체 | 읽는 주체 | R4가 보장하는 최소 의미 |
|---|---|---|---|---|
| `DynamicReproductionRequest` | `dynamic_reproduction_request` | R6 Verification | R7 Sandbox, Runtime Validator | 재현 가설·목적·목표·환경 필요·profile과 근거의 current generation 요청 |
| `EnvironmentRequirements.request_ref` | `dynamic_reproduction_request` | R6 Verification | Runtime Validator, R7 Sandbox | R7 requirements가 구체화한 exact 요청 |
| `ReproductionPlan.environment_requirements_ref` | `environment_requirements` | R7 Sandbox | Runtime Validator, Sandbox Controller·Runner | 필요한 애플리케이션 환경의 current exact revision |
| `poc_candidate_ref` | `poc_candidate` | R7 Sandbox | Runtime Validator, Sandbox Runner, Verification | 실행 전 또는 실패 시도의 PoC 스크립트·요청·입력 |
| `poc_ref` | `poc_bundle` | R7 Sandbox | Verification, Gate, Reporter | `SUCCEEDED + SUPPORTED` 실행으로 검증된 exact PoC revision/digest |
| `policy_decision_ref` | `sandbox_policy_decision` | Sandbox Controller | Sandbox runtime, Verification, Gate | exact 정책 revision, 허용·차단 결과와 사유 연결 |
| `environment_ref` | `sandbox_environment` | R7 Sandbox runtime | R6 Verification, Gate, 운영 디버깅 | 실제 생성 환경, 요구사항별 비교와 exact attempt 연결 |
| `steps_ref` | `sandbox_step_log` | Sandbox Runner runtime | Sandbox result assembler, Verification, Gate | Runner가 실제 수행하거나 실패한 단계의 불변 로그 연결 |

R4는 공통 record·필드명·자료형·null·exact reference·상태·생산자와 소비자·오류 규칙을 정한다. R6은 `DynamicReproductionRequest`, 반환 결과 소비와 최종 가설 판정을 맡는다. R7은 `EnvironmentRequirements`, `ReproductionPlan`, PoC candidate, 환경·정책·단계 log와 `DynamicReproductionResult`를 생산한다. Sandbox runtime의 비-LLM result assembler만 exact reference를 동적 결과에 조립한다. Verification은 COMMITTED 결과를 읽어 판정하고, Gate는 final TRUE에 연결된 validated PoC와 동적 근거를 검토하며, Reporter는 두 Gate를 통과한 결과만 사용한다.

Sandbox Controller는 실행 직전 `RUN_SANDBOX` decision의 exact request·plan·requirements·candidate reference와 현재 closure를 비교한 뒤 image·command·file·network·resource·cleanup 정책을 한 번 검사한다. 결과를 저장할 때는 `SAVE_RESULT(requested_by=SANDBOX, result_kind=dynamic_reproduction_result)`가 request·purpose·plan·requirements·candidate·정책·실제 환경·Runner log·validated PoC·cleanup 조합을 다시 확인한다. Verification은 `DynamicReproductionState.dynamic_result_ref`, work output과 commit이 같은 final 결과만 읽으며 `DynamicReproductionResult`를 직접 만들거나 수정하지 않는다.

| `status` | `failure_reason` | 필수 의미 |
|---|---|---|
| `SUCCEEDED` | `NONE` | 계획한 필수 단계와 관측을 끝냄. outcome은 관측에 따라 세 값 모두 가능 |
| `PARTIAL` | `NONE` | 공격 경로를 일부 실행해 신뢰할 수 있는 관측이 하나 이상 있지만 전체 확인은 부족함. `hypothesis_outcome=INCONCLUSIVE`, evidence와 `limitations`가 각각 하나 이상 필요 |
| `FAILED` | `EXTERNAL_CONFIGURATION | ENVIRONMENT_SETUP | EXECUTION | OBSERVATION | POLICY_BLOCKED | TIMEOUT | RETRY_LIMIT` | plan 또는 실행 허가 뒤 복구 불가능하거나 재시도 한도를 소진해 완료하지 못함. final verdict 없음 |
| `BLOCKED` | `EXTERNAL_CONFIGURATION | ENVIRONMENT_SETUP | EXECUTION | OBSERVATION | POLICY_BLOCKED | TIMEOUT` | plan 또는 실행 허가 뒤 재시도·외부 설정 또는 정책 변경을 기다림. 같은 work의 새 attempt 사용 |
| `CANCELLED` | `NONE` | 사용자나 runtime이 중단함. `hypothesis_outcome=INCONCLUSIVE` |

필수 상태 조합은 다음과 같다.

| 상황 | 필수 조합 |
|---|---|
| 정책이 Runner와 어떤 자원도 만들기 전에 차단 | `BLOCKED + POLICY_BLOCKED`, `runner_invoked=false`, `steps_ref=null`, `environment_created=false`, `environment_ref=null`, `cleanup_required=false`, `cleanup_status=NOT_REQUIRED`, `policy_decision_ref`와 `poc_candidate_ref` 필수, `poc_ref=null` |
| Runner 호출 뒤 실행 실패 | `runner_invoked=true`, `steps_ref`와 `poc_candidate_ref` 필수. 실제 환경을 만들었으면 `environment_created=true`와 `environment_ref` 필수. `poc_ref=null` |
| 동적 재현 성공과 가설 지지 | `SUCCEEDED + SUPPORTED`, `runner_invoked=true`, `steps_ref`, `environment_ref`, `poc_candidate_ref`, validated `poc_ref` 필수. PoC·환경·log와 관측은 같은 request·plan·attempt에 속함 |
| 환경 또는 임시 자원을 만든 뒤 오류·정책 차단 | `environment_created=true`이면 `environment_ref` 필수. `cleanup_required=true`, `cleanup_status=SUCCEEDED | FAILED`; `NOT_REQUIRED` 금지. Runner를 부르지 않았으면 `steps_ref=null` 유지 |
| 필수 환경 요구사항 불일치 | 재시도·외부 수정 가능하면 `BLOCKED + ENVIRONMENT_SETUP`, 복구 불가능하거나 한도 소진이면 `FAILED + ENVIRONMENT_SETUP`; `hypothesis_outcome=INCONCLUSIVE`, validated `poc_ref=null`. 환경이 생성됐다면 exact `environment_ref`, Runner가 호출됐다면 `steps_ref`가 필수이고 공격 step은 없거나 모두 `SKIPPED` |

PoC 생성·외부 설정·환경 구성·실행 실패가 재시도 가능하면 실패 attempt와 candidate·log·오류를 보존하고 같은 `DYNAMIC_REPRO.work_id`를 `BLOCKED`로 둔다. 조건이 해결되면 새 `attempt_id`, `trigger=RETRY | RESUME`으로 다시 시작한다. 복구 불가능하거나 한도를 소진하면 work와 현재 Verification을 `FAILED`로 끝내고 final `VerificationResult`를 만들지 않는다. PoC 생성·실행 실패를 `FALSE | HOLD`로 변환하지 않는다. `SUPPORTED | DISPROVED`는 실제 관측 reference가 필수다. `DISPROVED`이면 `hypothesis_disproved=true`와 disproof refs가 필요하고, 정상 실행 또는 신뢰 가능한 부분 실행이 `INCONCLUSIVE`이면 R6가 final HOLD를 만들 수 있다. `POC_CONFIRMATION | VERDICT_EVIDENCE` 모두 실제 반증은 FALSE, 정상 관측의 불충분은 HOLD, `SUCCEEDED + SUPPORTED`와 validated PoC만 TRUE로 이어진다.

다음 조합은 `SAVE_RESULT`의 `SCHEMA | REVISION` 검사에서 거절한다. 거절은 `AnalysisError`와 격리된 candidate로 남기며 가설 `FALSE`를 만들지 않는다.

- `runner_invoked=true`인데 `steps_ref=null`, 또는 `runner_invoked=false`인데 `steps_ref`가 존재함
- `failure_reason=POLICY_BLOCKED`인데 `policy_decision_ref=null`
- `environment_created=true`인데 `environment_ref=null`, 또는 `false`인데 실제 환경 record reference가 존재함
- `ReproductionPlan.environment_requirements_ref`가 없거나 current exact `EnvironmentRequirements` revision이 아님
- R6가 `EnvironmentRequirements` 또는 `ReproductionPlan`을 생산하거나 R7이 request의 목적·필수 조건·profile을 바꿈
- 필수 environment check가 `MISMATCH | NOT_CHECKED | ERROR`인데 공격 step을 실행함
- 실제 VERSION이 `expected | alternatives`에 없는데 자동 fallback을 적용하거나 `MATCH`로 기록함
- EnvironmentRequirements 또는 환경 비교 record에 credential·cookie·token·password 원문을 저장함
- retry에서 새 plan·candidate를 만들고도 새 `RUN_SANDBOX` action이나 Sandbox Controller 검사를 생략함
- `cleanup_required=true`인데 `cleanup_status=NOT_REQUIRED`, 또는 `false`인데 `cleanup_status`가 `SUCCEEDED | FAILED`임
- `DISPROVED | INCONCLUSIVE | PARTIAL | FAILED | BLOCKED | CANCELLED`에 validated `poc_ref`를 붙이거나, `SUCCEEDED + SUPPORTED`인데 exact `poc_ref`가 없음
- 한 Verification generation에 purpose가 다른 두 번째 request 또는 `DYNAMIC_REPRO` work를 등록함
- PoC 생성·실행 실패를 final `FALSE | HOLD`로 저장하거나 Technical Gate를 호출함
- reference target의 analysis·workspace·commit·hypothesis가 동적 결과와 다르거나, 해당 R7 실행에서 만든 정책·환경·log·실행 PoC·cleanup target의 attempt가 동적 결과와 다름
- 고정된 `stored_data_id + record_id + content_hash` 대신 “latest” 조회로 artifact를 다시 선택함

새 request, 생산 권한, purpose·candidate·validated PoC와 TRUE 조건은 관련 record의 새 MAJOR schema로 배포한다. runtime은 이전 MAJOR의 R6-owned requirements/plan이나 candidate와 validated PoC가 섞인 `poc_ref`를 추정 변환하지 않고 명시적으로 거절한다.

## 8. TechnicalEvidenceReview

첫 번째 Gate가 검증 판정과 코드·실행 근거의 연결을 확인하고 승인·보완·거절을 기록하는 결과입니다.

```yaml
TechnicalEvidenceReview:
  meta: RecordMeta
  action_decision_ref: StoredDataRef
  verification_result_ref: StoredDataRef
  cwe_label_ref: StoredDataRef
  status: ACCEPT | REVISE | REJECT
  evidence_verdict_alignment: string
  code_flow_linkage: string
  dynamic_linkage: string
  cwe_assessment: string
  restriction_assessment: string
  handoff_readiness: READY | NOT_READY
  revision_requests: [string]
  verification_requests: [string]
  rationale: string
```

`action_decision_ref.record_id`는 `CALL_TECHNICAL_GATE`를 허가하고 `USED`로 claim한 decision revision을 가리킨다. 실행 결과를 기록한 이후 decision revision의 `outcome_refs`에는 같은 call spec을 실행한 `TECHNICAL_GATE` `LLMInvocationLog`와 현재 review가 각각 한 번 포함되고, log의 `parsed_output_ref.record_id`가 현재 review를 가리켜야 한다. review는 log를 역참조하지 않아 content hash 순환을 만들지 않는다. `verification_result_ref.record_id`와 `cwe_label_ref.record_id`는 필수이며 각각 정확히 한 final `VerificationResult(verdict=TRUE)`와 `CWELabel` revision을 가리킨다. `FALSE | HOLD` 또는 `HypothesisProcessState.status=FAILED`인 가설에는 Technical Gate work와 review를 만들 수 없다. runtime은 두 대상의 `record_id`, `workspace_id`, `commit_id`, `hypothesis_id`와 `content_hash`가 서로와 현재 Technical review에 일치하는지 확인한다. Verification 또는 CWELabel이 새 revision으로 바뀌면 이전 `TechnicalEvidenceReview`를 재사용할 수 없고 Gate를 새로 호출해야 한다. Technical review는 `VerificationResult.verdict`나 `CWELabel`을 덮어쓰지 않는다.

`status=ACCEPT`는 `handoff_readiness=READY`, `status=REVISE | REJECT`는 `handoff_readiness=NOT_READY`만 허용한다. `DynamicReproductionResult(status=BLOCKED, failure_reason=POLICY_BLOCKED)`는 가설 반증이나 Technical `REJECT`가 아니다. 그러나 validated PoC가 없으므로 final `VerificationResult`를 만들거나 Technical Gate를 호출하지 않는다. 재시도 또는 정책·환경 수정이 가능하면 같은 동적 work와 Verification을 `BLOCKED`로 유지하고, 복구 불가능하거나 한도를 소진하면 verdict 없이 `FAILED`로 끝낸다. 어떤 경우에도 정책 차단을 가설 `FALSE | HOLD`로 변환하지 않는다.

## 9. ProgramPolicyRecord과 RuleScopeImpactReview

공식 프로그램 정책을 확인해 저장한 기록과, 두 번째 Gate가 정책 범위·규칙·실제 영향을 검토한 결과입니다.

```yaml
PolicyItem:
  policy_item_id: string
  value: string
  description: string
  conditions: [string]
  source_ref: StoredDataRef
  source_locator: string

ProgramPolicyRecord:
  meta: RecordMeta without hypothesis/attempt
  policy_record_id: string
  program_id: string
  program_namespace: string
  external_program_id: string
  policy_version: string
  fetched_at: timestamp
  freshness_status: CURRENT | STALE | UNVERIFIED
  freshness_checked_at: timestamp | null
  in_scope_assets: [PolicyItem]
  out_of_scope_assets: [PolicyItem]
  accepted_vulnerability_classes: [PolicyItem]
  excluded_vulnerability_classes: [PolicyItem]
  testing_restrictions: [PolicyItem]
  impact_criteria: [PolicyItem]
  disclosure_requirements: [PolicyItem]
  source_refs: [StoredDataRef]
  missing_information: [string]
  freshness_warning: string | null
```

`PolicyItem.policy_item_id`는 한 `ProgramPolicyRecord` 안에서 유일하다. `value`에는 비교할 asset·취약점 분류·제한·기준 값을, `conditions`에는 그 값이 적용되는 조건을 넣는다. `source_ref`는 `ProgramPolicyRecord.source_refs`에도 포함된 공식 자료를 가리키고 `source_locator`는 문서 안에서 해당 항목을 다시 찾을 수 있는 절·anchor·페이지 정보다. 출처와 연결되지 않은 항목은 공식 정책 사실로 사용하지 않고 `missing_information`에 남긴다.

`freshness_status=CURRENT`는 versioned freshness 기준으로 공식 출처를 확인했고 `freshness_checked_at`이 있을 때만 허용한다. 최대 허용 나이와 출처별 확인 방식은 R5가 정한다. 기준을 넘었으면 `STALE`, 확인 자체가 실패했거나 기준을 적용할 수 없으면 `UNVERIFIED`다. 두 상태 모두 `freshness_warning` 또는 `missing_information`에 이유가 있어야 하며 Gate의 `PASS | ALLOW` 근거로 사용할 수 없다. 이 필수 enum 추가는 `ProgramPolicyRecord`의 새 MAJOR schema로 배포한다.

`program_id`는 내부 Program Catalog가 발급한 전역 ID다. `program_namespace`는 외부 플랫폼이나 catalog 출처를 나타내며, `external_program_id`는 그 출처 안의 프로그램 ID다. 외부 프로그램의 유일 키는 `(program_namespace, external_program_id)`이고, 내부 catalog는 이 쌍을 하나의 `program_id`에 매핑한다. namespace가 다른 같은 외부 ID를 자동 병합하지 않는다.

```yaml
RuleScopeImpactReview:
  meta: RecordMeta
  action_decision_ref: StoredDataRef
  verification_result_ref: StoredDataRef
  technical_review_ref: StoredDataRef
  cwe_label_ref: StoredDataRef
  policy_record_ref: StoredDataRef | null
  review_status: PASS | FAIL | UNCERTAIN
  rule_compliance: PASS | FAIL | UNCERTAIN
  scope_compliance: PASS | FAIL | UNCERTAIN
  security_impact: SUFFICIENT | INSUFFICIENT | UNCERTAIN
  report_permission: ALLOW | DENY
  reasons: [string]
  missing_information: [string]
```

`action_decision_ref.record_id`는 `CALL_RULE_SCOPE_GATE`를 허가하고 `USED`로 claim한 decision revision을 가리킨다. 이후 decision revision의 `outcome_refs`에는 같은 call spec을 실행한 `RULE_SCOPE_GATE` log와 현재 review가 각각 한 번 포함되고, log의 `parsed_output_ref.record_id`가 현재 review를 가리켜야 한다. review는 log를 역참조하지 않는다. `verification_result_ref.record_id`, `technical_review_ref.record_id`와 `cwe_label_ref.record_id`는 필수다. `technical_review_ref` 대상은 `status=ACCEPT`이고, 그 대상의 Verification과 CWE reference `record_id`는 Rule Scope review가 직접 가리키는 두 `record_id`와 각각 같아야 한다. runtime은 각 reference의 `workspace_id`, `commit_id`, `content_hash`가 실제 대상 record와 일치하고, Verification·CWELabel·Technical 대상 `RecordMeta.hypothesis_id`가 현재 Rule Scope review의 가설과 같은지 확인한다. `policy_record_ref`가 있으면 그 `record_id`도 필수이며 실제 `ProgramPolicyRecord`와 일치해야 한다. 어느 입력 revision이든 바뀌면 이전 Rule Scope review를 재사용하지 않는다.

공식 `ProgramPolicyRecord`가 없으면 `policy_record_ref=null`이다. 정책 record가 없거나 핵심 출처가 누락되거나 `freshness_status=STALE | UNVERIFIED`이면 `rule_compliance`, `scope_compliance`, `review_status`는 `UNCERTAIN`, permission은 `DENY`다. 불완전하거나 오래된 정책 record 자체가 있으면 exact reference는 감사용으로 보존하고 `missing_information`에 누락·최신성 문제를 기록한다. 이 상태에서 `PASS | ALLOW`를 반환하거나 이 불변조건을 만족하지 않는 출력은 invalid다.

## 10. LLM invocation records

각 LLM 호출의 요청, 응답, 모델·세션 정보, 사용량과 오류를 다시 확인할 수 있게 남기는 기록입니다.

```yaml
LLMCallSpec:
  meta: RecordMeta
  llm_call_id: string
  agent_role: HYPOTHESIS | VERIFICATION | PRO | CON | CWE_LABELING | CHAINING | TECHNICAL_GATE | RULE_SCOPE_GATE | REPORTER
  provider_profile_ref: StoredDataRef
  model: string
  session_policy: NEW | RESUME | AUTO
  parent_session_ref: string | null
  context_refs: [StoredDataRef]
  prompt_template_version: string
  prompt_payload_ref: StoredDataRef
  output_schema: string
  token_budget: integer
  timeout_ms: integer

LLMInvocationRequest:
  meta: RecordMeta
  llm_call_id: string
  action_decision_ref: StoredDataRef
  call_spec_ref: StoredDataRef
  agent_role: HYPOTHESIS | VERIFICATION | PRO | CON | CWE_LABELING | CHAINING | TECHNICAL_GATE | RULE_SCOPE_GATE | REPORTER
  provider_profile_ref: StoredDataRef
  model: string
  session_policy: NEW | RESUME | AUTO
  parent_session_ref: string | null
  context_refs: [StoredDataRef]
  prompt_template_version: string
  prompt_payload_ref: StoredDataRef
  output_schema: string
  token_budget: integer
  timeout_ms: integer
```

`call_spec_ref.record_id`는 수정할 수 없는 exact `LLMCallSpec` revision을 가리킨다. `action_decision_ref.record_id`는 일반 Agent이면 `CALL_LLM`, Gate이면 해당 `CALL_TECHNICAL_GATE | CALL_RULE_SCOPE_GATE`, Reporter이면 `CREATE_REPORT_DRAFT` action을 `ALLOW`하고 `USED`로 claim한 exact decision revision을 가리킨다. 그 action의 `llm_call_spec_ref.record_id`는 `call_spec_ref.record_id`와 같아야 한다. request의 `llm_call_id`, role, provider profile, model, session, parent session, context, prompt template/payload, output schema, token budget와 timeout은 spec과 field-by-field exact equality를 만족해야 하며 runtime은 이 equality를 provider 호출 직전에 다시 확인한다. 다르면 decision을 `EXPIRED`로 바꾸고 호출하지 않는다. `timeout_ms`는 monotonic clock으로 계산하는 0보다 큰 밀리초 실행 예산이다.

`LLMCallSpec`은 이를 입력으로 가진 첫 `ActionDecision`이 저장된 뒤 수정하지 않는다. action `input_refs`에는 spec 자체와 spec의 `prompt_payload_ref`, 모든 `context_refs`를 포함하고 `REVISION`·`REDACTION` check를 적용한다. `CALL_LLM`에서는 spec role이 `requested_by`와 같아야 한다. `CALL_TECHNICAL_GATE | CALL_RULE_SCOPE_GATE | CREATE_REPORT_DRAFT`에서는 각각 `TECHNICAL_GATE | RULE_SCOPE_GATE | REPORTER`여야 한다. retry와 failover는 새 `llm_call_id`, spec, action과 decision을 만든다.

Pro와 Con의 `SESSION` check는 독립성을 선택값이 아닌 필수 불변조건으로 검사한다. `requested_by=PRO | CON`인 `CALL_LLM` action은 `session_mode=NEW`, exact `LLMCallSpec.agent_role`이 같은 역할, `LLMCallSpec.session_policy=NEW`, `parent_session_ref=null`이어야 한다. Pro와 Con은 서로 다른 `llm_call_id`, `LLMCallSpec`, `ActionRequest`, `ActionDecision`과 실제 `session_ref`를 가져야 한다. provider가 session ID를 주지 않아도 adapter가 호출마다 서로 다른 불투명 local `session_ref`를 발급한다. 공통 가설·코드 fact는 각각의 `context_refs`에 넣을 수 있지만 상대 역할의 output·결론·session을 parent 또는 context로 넣을 수 없다.

Pro/Con prompt는 trusted prompt builder가 역할별 template과 허용된 공통 입력 reference만으로 만든 immutable `prompt_payload_ref`를 사용한다. Agent가 prompt payload나 `context_refs`를 직접 늘릴 수 없다. 상대 역할의 output·결론·session·action/decision은 `context_refs`, `prompt_payload_ref`, predecessor/parent, result-store 조회, retrieval/tool 요청 또는 tool output 어느 경로로도 전달하지 않는다. runtime은 provider 호출 직전과 결과 저장 전에 이 경계를 검사하고 위반하면 `CROSS_ROLE_INPUT_DENIED`로 두 호출의 합류를 중단한다.

Pro/Con retry와 failover도 역할 경계를 넘지 않는다. 선행 호출은 같은 역할의 바로 앞 실패 호출일 수 있지만 후속 호출도 `NEW` session과 새 `llm_call_id`·spec·action·decision을 사용하고 `parent_session_ref=null`을 유지한다. 상대 역할의 predecessor, session, parsed output 또는 action decision을 연결하면 `SESSION` check를 `FAIL`로 만들고 `INVOCATION_CHAIN_INVALID` 또는 `ACTION_NOT_ALLOWED`를 기록한다.

```yaml
LLMInvocationResult:
  meta: RecordMeta
  llm_call_id: string
  status: SUCCEEDED | FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED | CANCELLED
  provider: string
  model: string
  actual_session_mode: NEW | RESUMED
  session_ref: string | null
  response_ref: StoredDataRef | null
  parsed_output_ref: StoredDataRef | null
  usage: map | null
  started_at: timestamp
  finished_at: timestamp
  elapsed_ms: integer
  safe_error: string | null
```

Gate LLM 출력이 schema를 통과했더라도 `report_permission=ALLOW`와 필수 `PASS | SUFFICIENT` 조건이 모순되거나 exact input reference가 맞지 않으면 semantic validation 실패다. 이 호출은 `LLMInvocationResult.status=INVALID_OUTPUT`과 하나 이상의 `LLMInvocationLog.validation_errors`를 기록하고, `AnalysisError.stage=GATE`, `AnalysisError.code=INVALID_OUTPUT`으로 같은 `work_id`·`attempt_id`에 연결한다. 해당 `WorkAttempt.status=FAILED`를 보존하고, 제한된 repair가 남아 있으면 Gate work를 `BLOCKED`, 더 시도할 수 없으면 `FAILED`로 전환한다. 이 경우 `RuleScopeImpactReview`를 `COMMITTED`하지 않는다. Reporter 호출과 가설 verdict 변경도 금지한다. 여기서 `INVALID_OUTPUT`은 invocation status이면서 동일 문자열의 `AnalysisError.code`이고, R4-02의 상태 전이 오류 7개를 대체하거나 그 목록에 추가되는 상태값이 아니다.

```yaml
LLMInvocationLog:
  meta: RecordMeta
  llm_call_id: string
  action_decision_ref: StoredDataRef
  call_spec_ref: StoredDataRef
  agent_role: string
  provider_profile_ref: StoredDataRef
  provider: string
  model: string
  session_policy: NEW | RESUME | AUTO
  session_ref: string | null
  parent_session_ref: string | null
  prompt_template_version: string
  context_refs: [StoredDataRef]
  retrieved_code_locations: [CodeLocation]
  exposed_request_ref: StoredDataRef
  exposed_response_ref: StoredDataRef | null
  parsed_output_ref: StoredDataRef | null
  tool_calls: [StoredDataRef]
  usage: map | null
  started_at: timestamp
  finished_at: timestamp
  elapsed_ms: integer
  retry_count: integer
  status: SUCCEEDED | FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED | CANCELLED
  safe_error: string | null
  validation_errors: [string]
  repair_attempts: integer
  retry_of_llm_call_id: string | null
  failover_from_llm_call_id: string | null
  redaction_result: APPLIED | NOT_REQUIRED | FAILED
```

`LLMInvocationLog.action_decision_ref`와 `call_spec_ref`는 request와 같아야 한다. log의 role·profile·model·session·prompt template·context는 request와 spec에서 바뀌지 않으며 실제 adapter가 선택한 값과 차이가 있으면 호출을 실패 처리한다. log의 `parsed_output_ref.record_id`는 역할이 만든 exact structured output revision을 가리킨다. Pro/Con은 각각 exact `EvidenceAgentResult`, Gate는 exact Gate review, Reporter는 exact `ReportDraft`를 가리킨다. output은 log를 역참조하지 않는다. 해당 action decision의 후속 revision `outcome_refs`에 log와 final output을 각각 한 번 포함해 두 record를 같은 실행에 연결한다.

새로운 독립 호출은 `retry_count=0`이고 두 선행 호출 reference가 모두 `null`이다. 같은 provider/model에서 일반 retry를 실행하면 `retry_of_llm_call_id`가 바로 앞의 허용된 실패 호출을 가리키고 `failover_from_llm_call_id=null`이다. provider 또는 model을 바꾸는 failover이면 반대로 `failover_from_llm_call_id`만 바로 앞의 허용된 실패 호출을 가리킨다. 두 필드는 동시에 값을 가질 수 없다.

일반 retry의 선행 status는 `FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED`만 허용한다. `INVALID_OUTPUT`은 제한된 repair가 끝난 뒤, `RATE_LIMITED`는 정한 backoff 뒤, `AUTH_REQUIRED`는 사용자 또는 승인된 운영자가 재인증을 완료한 뒤에만 후속 호출을 시작한다. failover의 선행 status는 `FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED`만 허용하며, 사전에 허용된 fallback profile과 전환 이유를 기록해야 한다. `AUTH_REQUIRED`에서 failover하려면 대상 provider의 유효한 인증이 별도로 준비되어 있어야 한다.

`SUCCEEDED`는 retry나 failover의 선행 호출로 사용할 수 없다. `CANCELLED`도 같은 chain에서 후속 호출을 허용하지 않으며, 사용자가 새 작업을 요청하면 선행 reference가 없는 독립 호출로 시작한다. 선행 호출은 같은 `analysis_id`, `hypothesis_id`, `agent_role`의 바로 앞 호출이어야 하고 현재 호출 자신이나 이후 호출을 가리킬 수 없다. 후속 호출의 `retry_count`는 바로 앞 호출보다 정확히 1 커야 한다. runtime은 허용되지 않은 predecessor status, 존재하지 않는 predecessor, 순환 reference와 순서가 맞지 않는 chain을 `INVOCATION_CHAIN_INVALID`로 거절한다. 이 규칙으로 최초 실패 → 일반 retry → provider/model failover의 순서와 원인을 각 `llm_call_id`를 따라 복원한다.

hidden chain-of-thought와 credential은 이 계약의 대상이 아니며 저장하지 않는다.

## 11. ReportDraft와 AnalysisRunResult

모든 전달 조건을 통과한 내부 보고서 초안과 분석 한 건의 결과·자원·오류·디버깅 정보를 정의합니다. `ReportDraft`는 마지막 Agent 산출물이며, 이후 신뢰 runtime이 `AnalysisRunResult`를 확정하면 Agent 자동화가 끝납니다.

```yaml
ReportDraft:
  meta: RecordMeta
  action_decision_ref: StoredDataRef
  finding_ref: StoredDataRef
  verification_result_ref: StoredDataRef
  technical_review_ref: StoredDataRef
  rule_scope_impact_review_ref: StoredDataRef
  cwe_label_ref: StoredDataRef
  policy_record_ref: StoredDataRef
  dynamic_result_ref: StoredDataRef | null
  poc_ref: StoredDataRef | null
  content_ref: StoredDataRef
  restrictions: [string]
  limitations: [string]
  unresolved_conditions: [string]
  redaction_status: PASSED
  draft_status: DRAFTED
```

`action_decision_ref.record_id`는 `CREATE_REPORT_DRAFT` action의 report 조건, exact LLM call spec과 redaction을 모두 통과한 `USED` decision revision을 가리킨다. 이후 decision revision의 `outcome_refs`에는 같은 call spec을 실행한 `REPORTER` log와 현재 draft가 각각 한 번 포함되고, log의 `parsed_output_ref.record_id`가 현재 draft를 가리켜야 한다. draft는 log를 역참조하지 않는다. `finding_ref`, `verification_result_ref`, `technical_review_ref`, `rule_scope_impact_review_ref`, `cwe_label_ref`와 `policy_record_ref`는 저장된 record를 가리므로 각 `StoredDataRef.record_id`가 필수다. Reporter runtime은 다음 연결을 모두 확인하고 하나라도 다르면 초안을 만들지 않는다.

- Technical review와 Rule Scope review가 모두 ReportDraft의 같은 Verification `record_id`를 가리킨다.
- Rule Scope review의 `technical_review_ref.record_id`가 ReportDraft의 `technical_review_ref.record_id`와 같다.
- Technical review와 Rule Scope review가 모두 ReportDraft의 같은 CWELabel `record_id`를 가리킨다.
- Rule Scope review의 `policy_record_ref.record_id`가 ReportDraft의 `policy_record_ref.record_id`와 같다.
- Finding이 ReportDraft의 같은 Verification, CWE, 두 Gate revision을 근거로 하며 current 결과다.
- 각 reference의 `workspace_id`, `commit_id`, `content_hash`가 실제 대상 record와 일치하고, 가설별 대상 record의 `meta.hypothesis_id`가 ReportDraft와 같다. CWELabel이 새 revision으로 바뀌면 두 Gate와 ReportDraft를 모두 새 revision 기준으로 다시 생성한다.
- `dynamic_result_ref`와 `poc_ref`는 Verification의 같은 이름 필드와 정확히 같아야 한다. 값이 있으면 같은 분석·가설의 COMMITTED 동적 결과와 exact PoC를 가리키고, 값이 없으면 동적 실행이나 PoC 성공을 주장하지 않는다.
- `restrictions`와 `unresolved_conditions`는 Verification의 값을 빠짐없이 보존하고, `limitations`는 정적·동적 검증과 두 Gate에 남은 한계를 빠짐없이 보존한다. 해당 값이 없을 때만 빈 배열을 사용한다.
- `redaction_status=PASSED`는 `CREATE_REPORT_DRAFT`의 `REDACTION=PASS` 결과와 일치해야 하며 credential, session secret, 불필요한 개인정보와 비공개 원문을 `content_ref`에 남기지 않는다.

ReportDraft가 참조한 Finding·Verification·CWELabel·Technical review·Rule Scope review·정책 중 하나라도 새 current revision으로 바뀌면 기존 draft record는 감사 이력으로 보존하되 current report로 사용할 수 없다. runtime은 기존 draft를 덮어쓰지 않고 새 dependency chain의 Gate·Reporter work와 새 `ReportDraft.record_id`를 만든다. 오래된 draft는 `AnalysisRunResult.report_draft_refs`의 current 결과에 넣을 수 없다.

`FindingCandidate` 본문과 품질 기준은 R5가 소유한다. R4는 이미 저장된 Finding revision과 다른 exact 결과를 `AnalysisRunResult`로 전달할 뿐 새 Finding claim을 만들거나 빠진 Finding을 추정하지 않는다. Finding이 없으면 `CREATE_REPORT_DRAFT`를 허용하지 않고 `AnalysisRunResult.report_draft_refs=[]`를 유지한다. 원인은 `REPORT_NOT_READY`와 연결된 오류·상태 기록으로 추적한다.

```yaml
AnalysisRunResult:
  meta: RunMeta
  purpose: PRODUCTION | EVALUATION
  repository_url: string
  workspace_id: string | null
  commit_id: string | null
  status: COMPLETE | PARTIAL | FAILED | CANCELLED
  hypothesis_counts: map
  failed_hypothesis_count: integer
  verdict_counts: map
  gate_counts: map
  finding_refs: [StoredDataRef]
  verification_refs: [StoredDataRef]
  cwe_label_refs: [StoredDataRef]
  technical_review_refs: [StoredDataRef]
  rule_scope_review_refs: [StoredDataRef]
  policy_record_refs: [StoredDataRef]
  dynamic_request_refs: [StoredDataRef]
  dynamic_result_refs: [StoredDataRef]
  primitive_and_chaining_refs: [StoredDataRef]
  poc_candidate_refs: [StoredDataRef]
  poc_refs: [StoredDataRef]
  report_draft_refs: [StoredDataRef]
  llm_invocation_log_refs: [StoredDataRef]
  action_decision_refs: [RunStoredDataRef | StoredDataRef]
  work_state_refs: [RunStoredDataRef | StoredDataRef]
  work_attempt_refs: [RunStoredDataRef | StoredDataRef]
  transition_commit_refs: [RunStoredDataRef | StoredDataRef]
  stop_reasons: [string]
  errors: [AnalysisError]
  gaps: [DataGap]
  resources: map
  started_at: timestamp
  finished_at: timestamp
  elapsed_ms: integer
  debug_trace_ref: RunStoredDataRef
```

Reporter 호출은 `TRUE + Technical ACCEPT + Rule Scope Impact review_status PASS + rule_compliance PASS + scope_compliance PASS + security_impact SUFFICIENT + ALLOW`인 경우만 유효하다.

Reporter가 current `ReportDraft`를 저장하고 해당 `REPORT_DRAFT` work를 종료한 뒤, 신뢰 runtime은 모든 current 결과와 로그를 `AnalysisRunResult`에 묶어 `AnalysisRunState`와 atomic하게 확정한다. `ReportDraft`는 마지막 Agent 산출물이고 `AnalysisRunResult` 확정은 새 판단을 생성하지 않는 저장 작업이다. 그 다음 Agent 자동화는 종료된다. ReportDraft 이후의 검토·수정·제출·공개는 Agent 자동화 밖에서 사람이 수행한다. 이 외부 과정에는 공통 schema, action, 상태 또는 자동 공개 권한을 정의하지 않는다.

`failed_hypothesis_count`는 종료 시점에 `HypothesisProcessState.status=FAILED`인 가설 수와 정확히 같아야 하며 이 가설은 current `verdict_counts`에 포함하지 않는다. 최초 검증에서 실패했다면 current final `VerificationResult` 자체가 없다. Technical `REVISE` 뒤 보완 검증이 실패한 경우에는 이전 Verification·Gate revision을 `verification_refs`와 `technical_review_refs`에 감사 기록으로 보존할 수 있지만 superseded history일 뿐 current verdict·Gate·Primitive·Reporter 입력으로 집계하지 않는다. 연결된 실패 work·attempt·transition, `errors`와 `gaps`로 원인을 추적한다. 실패 가설이 하나라도 있으면 분석 전체를 성공으로 숨기지 않으며 완료된 다른 가설이 있더라도 `AnalysisRunResult.status=PARTIAL`로 기록한다.

## 구현 단계에서 결정할 것

serialization format, schema language/versioning, database/index, Primitive vocabulary, policy source collector, confidence range와 정량 limit은 구현 전 ADR과 평가 corpus로 확정한다. 이 설계의 field 목록을 곧바로 모든 서비스의 영구 API로 간주하지 않는다.
