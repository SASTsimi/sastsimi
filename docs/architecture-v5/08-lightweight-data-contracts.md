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

`root_hypothesis_id`, `parent_hypothesis_ids`, `source_hypothesis_id`, `target_hypothesis_id`, `retry_of_llm_call_id`와 `failover_from_llm_call_id`는 새 종류의 ID가 아니라 각각 기존 `hypothesis_id` 또는 `llm_call_id`를 가리키는 참조 필드다. 로컬 폴더를 정리해도 성공한 `workspace_id → repository_url + commit_id` 연결 정보는 삭제하지 않는다. 시스템이 직접 만든 ID는 다른 대상에 재사용하지 않는다. 외부 ID인 `commit_id`와 `external_program_id`는 같은 대상을 다시 가리킬 수 있다. 서로 다른 종류의 ID는 대신 사용할 수 없으며, 소비자는 필요한 ID를 `RecordMeta`와 전문 record 양쪽에서 검사한다.

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
| 등록 가설 처리 | `HypothesisProcessState.status` | `REGISTERED | ASSIGNED | VERIFYING | TERMINAL | CANCELLED` | Orchestration runtime | `TRUE | FALSE | HOLD`와 분리 |
| 기술 판정 | `VerificationResult.verdict` | `TRUE | FALSE | HOLD` | Verification Agent | 오류·정보 부족 상태와 분리 |
| 동적 재현 | `DynamicReproductionState.status` | `NOT_REQUESTED | RUNNING | SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED` | Sandbox runtime | `FAILED`만으로 가설 반증 금지 |
| LLM 호출 | `LLMInvocationResult.status` | `SUCCEEDED | FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED | CANCELLED` | Agent Runtime과 provider adapter | 가설 verdict로 변환 금지 |
| 기술 Gate | `TechnicalEvidenceReview.status` | `ACCEPT | REVISE | REJECT` | Technical Evidence Gate Agent | Verification verdict를 변경하지 않음 |
| 정책·영향 Gate | `RuleScopeImpactReview.review_status`, `report_permission` | `PASS | FAIL | UNCERTAIN`, `ALLOW | DENY` | Rule Scope Impact Gate Agent | 기술 판정과 분리 |
| 보고서 초안 | `ReportProcessState.status` | `NOT_REQUESTED | DRAFTED | FAILED` | Reporter runtime | 공개 승인 상태가 아님 |
| 사람 검토 | `ReportDraft.human_review_state` | `PENDING | APPROVED | REJECTED` | Human Reviewer | 최종 공개 여부만 사람이 결정 |

진행 중인 상태도 저장할 수 있도록 아래 최소 상태 record를 사용한다. 종료 결과 record는 상세 근거를 담고, 상태 record는 현재 진행 위치를 나타낸다.

```yaml
AnalysisRunState:
  meta: RunMeta
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

HypothesisProcessState:
  meta: RecordMeta with hypothesis
  proposal_ref: StoredDataRef
  status: REGISTERED | ASSIGNED | VERIFYING | TERMINAL | CANCELLED
  verification_result_ref: StoredDataRef | null
  started_at: timestamp
  finished_at: timestamp | null
  elapsed_ms: integer

DynamicReproductionState:
  meta: RecordMeta
  status: NOT_REQUESTED | RUNNING | SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED
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

`AnalysisRunState.status=RUNNING`이면 `analysis_result_ref=null`이다. `COMPLETE | PARTIAL | FAILED | CANCELLED`이면 `analysis_result_ref`가 필수이고 같은 `analysis_id`의 정확한 `AnalysisRunResult`를 가리킨다. 최종 상태와 결과는 atomic transition으로 함께 확정한다.

`ProposalProcessState`의 모든 revision은 `meta.hypothesis_id: null`을 유지한다. `SCHEMA_VALID` proposal을 가설로 등록할 때 새 `hypothesis_id`를 발급하고, 별도 `logical_record_id`의 `HypothesisProcessState.status=REGISTERED`를 만든다. 두 상태 record는 같은 `proposal_ref`로 연결하며 서로의 revision으로 취급하지 않는다.

진행 중인 상태는 `finished_at: null`이다. 종료 상태는 `finished_at`이 필수이며 `elapsed_ms`는 시작부터 종료까지 monotonic clock으로 계산한다. `NOT_REQUESTED`는 `started_at: null`, `finished_at: null`, `elapsed_ms: 0`이다. 상세 결과 record에 나열된 상태는 모두 종료 상태이므로 그 `finished_at`은 `null`일 수 없다.

`HypothesisProcessState.status=TERMINAL`이면 `verification_result_ref.record_id`가 필수이고 현재 가설의 정확히 하나인 final `VerificationResult` revision을 가리켜야 한다. 그 밖의 상태에서는 `verification_result_ref=null`이다. `DynamicReproductionState.status=SUCCEEDED | PARTIAL | FAILED`이면 `dynamic_result_ref.record_id`가 필수이고 해당 attempt의 `DynamicReproductionResult`를 가리킨다. `ReportProcessState.status=DRAFTED`이면 `report_draft_ref.record_id`가 필수이며 정확히 하나인 `ReportDraft` revision을 가리키고, `NOT_REQUESTED | FAILED`이면 `report_draft_ref=null`이다.

### 공통 실행 상태와 상태 변경

`WorkExecutionState`는 프로그램이 실행 순서와 복구를 관리하기 위한 상태다. 전문 결과의 의미를 대신하지 않는다. 예를 들어 `work_type=VERIFICATION` 작업이 `SUCCEEDED`라는 사실만으로 가설을 `TRUE`라고 판단할 수 없고, 반드시 그 작업이 가리키는 `VerificationResult.verdict`를 읽어야 한다.

```yaml
WorkExecutionState:
  meta: RunMeta | RecordMeta
  work_id: string
  work_type: WORKSPACE_PREP | STATIC_TOOL | STATIC_NORMALIZE | HYPOTHESIS_PROPOSAL | CONTEXT_RETRIEVAL | PRO_EVIDENCE | CON_EVIDENCE | VERIFICATION | DYNAMIC_REPRO | PRIMITIVE_UPDATE | RESEARCH | CWE_LABEL | POLICY_FETCH | TECHNICAL_GATE | RULE_SCOPE_GATE | REPORT_DRAFT
  subject_type: ANALYSIS | PROPOSAL | HYPOTHESIS | REPORT
  subject_id: string
  work_generation: integer
  status: PENDING | READY | RUNNING | BLOCKED | SUCCEEDED | PARTIAL | FAILED | CANCELLED
  state_version: integer
  last_transition_id: string | null
  last_transition_commit_id: string | null
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
  state: PREPARED | COMMITTED | ABORTED
  prepared_at: timestamp
  committed_at: timestamp | null
  abort_reason: string | null
```

`state_version`은 `1`부터 시작하고 승인된 전이마다 정확히 1 증가한다. runtime은 저장된 현재 version이 `expected_state_version`과 같을 때만 전이를 승인한다. 다르면 `STATE_VERSION_CONFLICT`로 거절하고 최신 상태를 다시 읽는다. `active_attempt_id`는 `RUNNING`일 때만 값이 있고 해당 작업의 현재 `WorkAttempt.attempt_id`와 같아야 한다. 한 `work_id`에는 활성 attempt가 하나만 존재한다.

`last_transition_id`는 현재 상태를 만든 `StateTransition.transition_id`이고 최초 `PENDING` record에서는 `null`이다. 결과를 함께 확정한 상태이면 `last_transition_commit_id`가 그 atomic 저장의 `TransitionCommit.transition_commit_id`와 같아야 한다. `READY | RUNNING`처럼 결과를 확정하지 않는 전이는 `last_transition_commit_id=null`일 수 있다.

`StateTransition.from_status`는 저장된 현재 상태와 같고 `new_state_version=expected_state_version+1`이어야 한다. `TransitionCommit.transition_ref.record_id`는 그 전이의 저장 revision을 가리키고, `work_id`, expected/target version, attempt, target status와 output refs가 `StateTransition`과 같아야 한다. `PREPARED`는 `committed_at=null`, `abort_reason=null`, `COMMITTED`는 `committed_at`이 필수이고 `abort_reason=null`, `ABORTED`는 `abort_reason`이 필수다. 한 commit이 `COMMITTED`와 `ABORTED` 사이를 오갈 수 없다.

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
- `PARTIAL`은 `STATIC_TOOL | STATIC_NORMALIZE | CONTEXT_RETRIEVAL | DYNAMIC_REPRO`에서만 허용하고, 하나 이상의 신뢰 가능한 `output_refs`와 누락을 설명하는 `error_ids` 또는 `gap_ids`가 필요하다.
- `FAILED`는 하나 이상의 `error_ids`가 필요하다. 전문 schema가 실패 결과 record를 정의한 `DYNAMIC_REPRO` 같은 작업은 그 실패 record를 `output_refs`에 포함할 수 있지만 성공 결과로 해석하지 않는다.
- `CANCELLED` 뒤 도착한 output은 현재 상태에 연결하지 않는다.
- `WorkExecutionState.elapsed_ms`는 완료된 `WorkAttempt.elapsed_ms`의 합이다. block 대기 시간과 프로세스가 꺼진 시간은 별도 상태 체류 지표로 기록하며 실행 시간에 더하지 않는다.
- `WorkAttempt.attempt_number`는 한 `work_id` 안에서 1부터 1씩 증가하고, `WorkAttempt.input_hash`는 그 attempt를 시작할 때의 `WorkExecutionState.input_hash`와 같다. `RecordMeta`를 쓰면 `meta.attempt_id`도 `WorkAttempt.attempt_id`와 같아야 한다.

재시도 가능한 attempt 실패는 `WorkAttempt.status=FAILED`와 오류를 보존하고 작업을 `BLOCKED`로 전환한다. 재인증·backoff·repair·예산 승인처럼 `waiting_for` 조건을 충족하면 `READY`로 이동하고 `attempt_number`가 1 증가한 새 `attempt_id`를 발급한다. 재시도할 수 없거나 한도를 사용한 때만 작업을 최종 `FAILED`로 끝낸다. 종료된 작업을 되돌리지 않는다. 사람이 같은 입력으로 새 논리 실행을 명시적으로 승인하면 이전 값보다 1 큰 `work_generation`과 새 `work_id`를 만들고, 두 작업을 restart 관계로 debug trace에 연결한다.

`work_generation`은 같은 분석·작업 종류·대상·입력에서 1부터 시작한다. 일반 retry와 resume에서는 바꾸지 않고, 종료 상태 뒤 사람이 승인한 명시적 restart에서만 1 증가한다. `dedupe_key`는 `analysis_id`, `work_type`, `subject_id`, `work_generation`, 정렬된 입력의 `record_id + content_hash`, 적용한 설정·정책 revision을 canonical JSON으로 만든 SHA-256 값이다. `attempt_id`, 시각과 worker 이름은 넣지 않는다. 같은 generation과 key의 요청이 다시 오면 새 작업을 만들지 않고 기존 `work_id`와 현재 상태를 반환한다. 입력 revision·적용 설정·승인된 generation이 바뀌면 새 `dedupe_key`와 새 `work_id`를 만든다.

| `work_type` | 등록 요청 주체 | 실행·출력 생산자 | `SUCCEEDED` 또는 `PARTIAL`이 가리키는 결과 |
|---|---|---|---|
| `WORKSPACE_PREP` | 분석 입력 runtime | Repository Loader | 준비된 `CodeWorkspace` |
| `STATIC_TOOL` | Orchestration runtime | AST/SAST runner | `ToolRunResult` |
| `STATIC_NORMALIZE` | Orchestration runtime | Static Fact Normalizer | `StaticFactBundle` |
| `HYPOTHESIS_PROPOSAL` | Orchestration runtime | Hypothesis Agent와 출력 검증 runtime | schema-valid `HypothesisProposal[]` |
| `CONTEXT_RETRIEVAL` | 허용된 Agent Runtime | Context Retrieval Service | `CodeContextResponse` |
| `PRO_EVIDENCE` | Verification runtime | Pro Agent | supporting `EvidenceClaim[]` |
| `CON_EVIDENCE` | Verification runtime | Con Agent | counter `EvidenceClaim[]` |
| `VERIFICATION` | Orchestration runtime | Verification runtime | final `VerificationResult` |
| `DYNAMIC_REPRO` | Verification의 제안 뒤 runtime validator | Sandbox runtime | `DynamicReproductionResult` |
| `PRIMITIVE_UPDATE` | Orchestration runtime | Primitive 저장 runtime | 새 `Primitive` revision |
| `RESEARCH` | Orchestration runtime | Research runtime | `ResearchResult` |
| `CWE_LABEL` | Orchestration runtime | CWE labeling runtime | `CWELabel` |
| `POLICY_FETCH` | Rule Scope Gate 준비 runtime | 공식 정책 수집 runtime | `ProgramPolicyRecord` |
| `TECHNICAL_GATE` | Orchestration runtime | Technical Gate runtime | `TechnicalEvidenceReview` |
| `RULE_SCOPE_GATE` | Orchestration runtime | Rule Scope Gate runtime | `RuleScopeImpactReview` |
| `REPORT_DRAFT` | Reporter 조건 검사 runtime | Reporter runtime | `ReportDraft` |

작업 모듈과 Agent는 등록 또는 상태 변경을 요청할 뿐 직접 확정하지 않는다. 모든 행의 `StateTransition` 승인과 저장은 신뢰 경계 안의 state transition validator와 state store가 담당한다. Orchestration Agent의 자연어 출력은 상태 변경 명령으로 직접 실행하지 않는다.

결과 record, `StateTransition`과 그 결과를 가리키는 종료 상태는 하나의 atomic transition으로 확정한다. 저장 제품이 한 transaction을 지원하면 같은 transaction에서 처리한다. 지원하지 않으면 `TransitionCommit` journal을 사용한다. `PREPARED` 출력은 격리 상태이며 다음 단계가 읽을 수 없다. 상태 pointer와 output reference가 함께 확정된 뒤 `COMMITTED`로 바꾸고 그때만 소비를 허용한다. version 충돌, 취소 또는 검증 실패는 `ABORTED`이며 output을 최신 상태에 연결하지 않는다.

다음 output binding은 필수다.

- `VERIFICATION`의 `SUCCEEDED`와 `HypothesisProcessState.status=TERMINAL`은 같은 final `VerificationResult.record_id`를 가리킨다.
- `TECHNICAL_GATE`의 `SUCCEEDED`는 정확히 하나의 `TechnicalEvidenceReview.record_id`를 가리킨다.
- `RULE_SCOPE_GATE`의 `SUCCEEDED`는 정확히 하나의 `RuleScopeImpactReview.record_id`를 가리킨다.
- `REPORT_DRAFT`의 `SUCCEEDED`와 `ReportProcessState.status=DRAFTED`는 같은 `ReportDraft.record_id`를 가리킨다.
- 분석 종료 transition과 `AnalysisRunState.analysis_result_ref`는 같은 `AnalysisRunResult`를 가리킨다.
- 각 reference의 workspace, commit, hypothesis, `record_id`와 `content_hash`는 실제 record와 일치한다.

분석을 `COMPLETE | PARTIAL | FAILED | CANCELLED`로 닫기 전에 runtime은 해당 `analysis_id`에 `RUNNING` work, 복구되지 않은 `PREPARED` journal과 output pointer가 없는 종료 상태가 없는지 확인한다. `PENDING | READY | BLOCKED` work는 각각 완료, 명시적 실패 또는 취소로 정리하고 그 이유를 `AnalysisRunResult`에 포함한다.

결과를 반영할 때 runtime은 작업이 `RUNNING`이고 결과의 `attempt_id`가 `active_attempt_id`이며, `expected_state_version`, `input_hash`, workspace, commit과 hypothesis가 현재 작업과 같은지 확인한다. 늦은 이전 attempt 결과는 `ATTEMPT_NOT_ACTIVE`, 취소·입력 변경·revision 변경 뒤 도착한 결과는 `STALE_RESULT`로 거절한다. 디버깅용으로 격리할 수는 있지만 Gate, Reporter와 최신 결과 pointer에 연결하지 않는다.

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
  stage: INPUT | REPOSITORY | STATIC_ANALYSIS | CONTEXT | ORCHESTRATION | AGENT | PROVIDER | SANDBOX | POLICY | GATE | REPORT | STATE | STORAGE | RECOVERY
  code: string
  safe_message: string
  retryable: boolean
  work_id: string | null
  attempt_id: string | null
  related_record_ids: [string]
  created_at: timestamp

ToolSource:
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

ToolRunResult:
  attempt_id: string
  tool_name: string
  tool_version: string
  status: SUCCEEDED | PARTIAL | FAILED | SKIPPED
  coverage: ToolCoverage
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

`StoredDataRef`는 준비된 코드와 연결된 결과에만 사용한다. raw 도구 출력·코드 조각처럼 독립 artifact이면 `record_id=null`이다. 저장된 record의 정확한 revision을 가리키는 참조는 해당 revision의 전역 `record_id`를 반드시 넣고, runtime은 참조의 `workspace_id`, `commit_id`, `content_hash`가 그 record와 일치하는지 확인한다. `RunStoredDataRef`는 입력 검증, clone·checkout, 실행 오류와 debug trace처럼 commit 준비 전에도 생기는 실행 자료에만 사용하며 코드 근거·PoC·Finding·보고서 주장의 근거로 사용할 수 없다. raw 실행 artifact이면 `record_id=null`, `RunMeta`를 가진 저장 record의 정확한 revision을 가리키면 그 `record_id`가 필수이며 `analysis_id`와 `content_hash`가 대상과 일치해야 한다. 두 참조 모두 내부 저장 경로 대신 결과 번호와 내용 hash만 전달한다.

`DataGap`은 분석하지 못한 범위이고 `AnalysisError`는 실행 중 발생한 오류다. 둘 다 취약점 `FALSE`를 뜻하지 않는다. `AnalysisError.safe_message`에는 credential, 개인정보, session secret, authorization header와 절대 로컬 경로를 넣지 않는다. 원본 오류가 필요하면 일반 오류 record에 복사하지 않고 별도 접근 통제·redaction·보존 정책이 적용된 artifact로 저장한다. `DataGap`의 세 affected 목록은 빈 목록일 수 있지만, `REPOSITORY | STATIC_ANALYSIS | CONTEXT` gap은 가능한 범위에서 path·language·location 중 하나 이상을 채운다. 전체 작업공간에 영향을 주거나 정확한 범위를 모르면 그 사실을 `description`에 명시하고 관련 결과를 `related_record_ids`로 연결한다.

### DataGap 생산자와 소비자

| `stage` | 주 생산자 | 대표 `code` | 주 소비자 |
|---|---|---|---|
| `REPOSITORY` | Repository Loader | `SUBMODULE_UNAVAILABLE`, `LFS_POINTER_ONLY`, `GENERATED_FILE_UNAVAILABLE` | 정적 분석, Hypothesis, Verification |
| `STATIC_ANALYSIS` | AST/SAST runner와 normalizer | `STATIC_COVERAGE_PARTIAL`, `LANGUAGE_UNSUPPORTED` | Hypothesis, Verification, 결과 집계 |
| `CONTEXT` | Context Retrieval Service | `CONTEXT_TRUNCATED`, `SYMBOL_UNRESOLVED` | Verification, Pro/Con, Research, Technical Gate |
| `DYNAMIC` | Sandbox runtime | `DYNAMIC_OBSERVATION_MISSING`, `DEPENDENCY_UNAVAILABLE` | Verification, Technical Gate, 사람 검토 |
| `POLICY` | 정책 수집 계층 | `POLICY_SOURCE_MISSING`, `POLICY_SOURCE_STALE` | Rule Scope Impact Gate, Reporter runtime |

`code`는 정확한 누락 종류, `reason`은 공통 원인 범주다. 빈 결과를 숨기지 않으며 소비자는 gap을 안전함이나 반증으로 해석하지 않는다.

### AnalysisError 생산자와 전달 규칙

| `stage` | 주 생산자 | 반드시 받는 소비자 | 기본 전달·처리 규칙 |
|---|---|---|---|
| `INPUT` | 입력 validator | Orchestration runtime, `AnalysisRunResult` | 분석 시작 전 거절 사유를 저장하고 verdict를 만들지 않음 |
| `REPOSITORY` | Repository Loader | Orchestration runtime, `AnalysisRunResult` | clone·checkout 실패는 실행 상태에 반영하고 가설 verdict를 만들지 않음 |
| `STATIC_ANALYSIS` | AST/SAST runner와 normalizer | Orchestration runtime, 정적 결과, `AnalysisRunResult` | 사용 가능한 결과와 오류를 함께 전달하고 필요하면 실행을 `PARTIAL`로 표시 |
| `CONTEXT` | Context Retrieval Service | 요청 Agent, 관련 검증 결과, `AnalysisRunResult` | 잘림·조회 실패를 숨기지 않고 HOLD 또는 추가 조회 판단에 전달 |
| `ORCHESTRATION` | Orchestration runtime | `AnalysisRunResult`, 운영 debug trace | 예산·순서·할당 실패를 기록하고 이미 존재하는 verdict를 바꾸지 않음 |
| `AGENT` | Agent Runtime | Orchestration runtime, 해당 Agent 결과, `AnalysisRunResult` | invalid output과 Agent 실행 실패를 별도 기록하고 자동 FALSE 금지 |
| `PROVIDER` | LLM provider adapter | Agent Runtime, 해당 invocation, `AnalysisRunResult` | 인증·rate limit·timeout을 호출 상태로 전달하고 자동 FALSE 금지 |
| `SANDBOX` | Sandbox runtime | Verification, 동적 결과, Technical Gate, `AnalysisRunResult` | 실행 실패와 실제 반증을 분리해 전달 |
| `POLICY` | 정책 수집 계층 | Rule Scope Impact Gate, `AnalysisRunResult` | 공식 정책 부족 시 `UNCERTAIN + DENY` 판단에 전달 |
| `GATE` | 두 Gate runtime | Orchestration runtime, 해당 Gate 결과, `AnalysisRunResult` | Gate 실패 시 Reporter 호출을 막고 Verification verdict는 유지 |
| `REPORT` | Reporter runtime | Orchestration runtime, `ReportProcessState`, `AnalysisRunResult` | 초안 실패를 저장하고 공개 상태를 만들지 않음 |

모든 `AnalysisError`는 `AnalysisRunResult.errors`와 운영 debug trace에 전달한다. 특정 가설·호출·동적 실행과 관련된 오류는 해당 전문 결과에도 포함하거나 `related_record_ids`로 연결한다. 오류를 누락하거나 성공 상태로 바꾸어 전달하지 않는다.

### 계약 버전과 revision 규칙

`schema_version`은 `MAJOR.MINOR.PATCH` 형식이다.

- `MAJOR`: 필드 삭제·이름 변경·의미 변경, enum 값의 추가·삭제·이름 변경·의미 변경처럼 호환되지 않는 변경
- `MINOR`: 기존 의미를 바꾸지 않는 선택 필드 추가
- `PATCH`: 데이터 해석이 바뀌지 않는 설명·예시·검증 규칙 명확화

이 문서에 나열한 enum은 모두 닫힌 enum이다. 따라서 소비자는 목록에 없는 값을 추정해서 처리하지 않는다. 소비자는 지원하지 않는 MAJOR를 추정해서 읽지 않고 `SCHEMA_UNSUPPORTED`를 기록한다. 알 수 없는 선택 필드는 보존하거나 무시할 수 있지만 새 의미를 만들지 않는다. schema 변경을 이유로 기존 record를 덮어쓰지 않고 같은 `logical_record_id` 아래 새 `record_id`, `created_at`과 증가한 `revision_number`를 만든다.

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

HypothesisProposal:
  proposal_id: string
  meta: RecordMeta
  proposal_state: HYPOTHESIS_ONLY
  assertion_mode: NON_FINAL
  origin: INITIAL | RESEARCH | CHAINING
  vulnerability_type_candidates: [string]
  target_entities: [CodeSymbol]
  target_locations: [CodeLocation]
  suspected_path: [CodeRelation | CodeLocation]
  observed_facts: [CodeFact]
  assumptions: [string]
  restrictions: [string]
  missing_information: [string]
  falsification_questions: [FalsificationQuestion]
  required_validation: [string]
  confidence: LOW | MEDIUM | HIGH
  parent_hypothesis_ids: [string]
  root_hypothesis_id: string | null
  chain_depth: integer
```

초기 proposal은 `parent_hypothesis_ids: []`, `root_hypothesis_id: null`, `chain_depth: 0`이다. schema validation과 semantic validation을 통과한 proposal만 stable `hypothesis_id`가 있는 `VulnerabilityHypothesis`로 등록한다.

```yaml
VulnerabilityHypothesis:
  meta: RecordMeta
  proposal_ref: StoredDataRef
  origin: INITIAL | RESEARCH | CHAINING
  parent_hypothesis_ids: [string]
  root_hypothesis_id: string
  chain_depth: integer
  statement: string
  target_entities: [CodeSymbol]
  target_locations: [CodeLocation]
  suspected_path: [CodeRelation | CodeLocation]
  falsification_questions: [FalsificationQuestion]
  required_validation: [string]
```

초기 가설의 `root_hypothesis_id`는 자기 `hypothesis_id`다. 자식 가설은 직접 원인이 된 부모만 `parent_hypothesis_ids`에 넣고, 부모 중 가장 큰 `chain_depth + 1`을 사용한다. 부모와 자식의 lifecycle·verdict는 독립이며 `TRUE + TRUE` 결합도 새 `hypothesis_id`를 만든다. proposal 출력 검증 runtime은 각 반증 질문에 전역 `question_id`를 부여하고 등록 가설까지 그대로 유지한다. 질문은 가설의 필수 조건 하나를 실제 근거로 반증할 수 있게 구체적으로 작성한다. 금지된 확정 assertion, 잘못된 enum, 필수 field/location·반증 질문 누락은 제한된 repair retry 뒤 `INVALID_OUTPUT`이다. confidence는 scheduling hint이지 verdict가 아니다.

## 3. CodeContextRequest/Response

검증 단계가 필요한 코드 위치를 요청하고 정적분석 계층이 같은 `workspace_id`와 `commit_id`에서 코드를 돌려주는 형식입니다.

```yaml
CodeContextRequest:
  code_request_id: string
  meta: RecordMeta
  requested_entities: [CodeSymbol]
  requested_locations: [CodeLocation]
  relation_query: [CALLERS | CALLEES | DATA_FLOW_NEIGHBORS | AUTH_GUARDS | ROUTE_BINDINGS]
  reason: string
  limits: ContextRetrievalLimits
```

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

요청과 응답의 `meta.workspace_id` 또는 `meta.commit_id`가 다르거나, 이 값이 `CodeWorkspace`와 일치하지 않으면 `WORKSPACE_MISMATCH`로 기록하고 근거에 사용하지 않는다. 모든 limit은 0보다 커야 한다. `max_requests_per_hypothesis`는 같은 가설의 누적 요청 한도이며 Orchestration runtime이 `code_request_id` 수로 강제한다. empty/truncated/gap/error는 안전함 또는 `FALSE`를 뜻하지 않는다. `truncated=true`이면 `CONTEXT_TRUNCATED` gap이 반드시 있어야 한다.

## 4. VerificationResult

검증 Agent가 찬성·반대·동적 근거를 모아 `TRUE / FALSE / HOLD` 판정과 남은 조건을 기록하는 결과입니다.

```yaml
EvidenceClaim:
  claim_id: string
  statement: string
  source_role: VERIFICATION | PRO | CON
  evidence_refs: [StoredDataRef]
  code_locations: [CodeLocation]
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

VerificationResult:
  meta: RecordMeta
  verification_mode: BASIC | CONDITIONAL_DEBATE | ALWAYS_DEBATE
  debate_triggers: [string]
  debate_skip_reason: string | null
  supporting_evidence: [EvidenceClaim]
  counter_evidence: [EvidenceClaim]
  falsification_results: [FalsificationResult]
  initial_verdict: TRUE | FALSE | HOLD
  dynamic_decision: NOT_REQUIRED | LIMITED_REPRO | FULL_REPRO
  dynamic_result_ref: StoredDataRef | null
  poc_ref: StoredDataRef | null
  verdict: TRUE | FALSE | HOLD
  verdict_rationale: string
  restrictions: [string]
  bypass_candidates: [CandidateRef]
  required_capabilities: [Primitive]
  provided_capabilities: [Primitive]
  impact_escalation_candidates: [CandidateRef]
  unresolved_conditions: [string]
  metrics: VerificationMetrics
  errors: [AnalysisError]
```

`EvidenceClaim.claim_id`는 한 `VerificationResult` 안에서 유일하다. 각 claim은 실제 저장 근거를 가리키는 `evidence_refs`를 하나 이상 가져야 하며, 코드 주장이라면 현재 `workspace_id + commit_id`의 `code_locations`도 하나 이상 가져야 한다. `source_role`은 claim을 작성한 역할이며 근거의 출처를 대신하지 않는다. supporting 목록에는 `VERIFICATION | PRO`, counter 목록에는 `VERIFICATION | CON`만 허용한다.

`CandidateRef`는 아직 검증되지 않은 우회·대체 경로·영향 확대 후보다. `candidate_id`는 한 결과 안에서 유일하고 `candidate_state`는 항상 `UNVALIDATED`다. 현재 가설을 `source_hypothesis_ids`에 포함하며, 실제 근거가 있으면 `evidence_refs`, 아직 필요한 사실은 `missing_information`에 넣는다. 후보가 새로운 endpoint·sink·권한 경계·공격 단계 또는 영향을 주장하면 새 `HypothesisProposal`로 등록해 전체 검증을 거치기 전까지 verdict, CWE, Gate 또는 보고서의 확정 주장으로 사용할 수 없다.

`VerificationMetrics`의 token 값은 provider가 값을 제공하지 않으면 `null`이고, 나머지 정수는 모두 0 이상이어야 한다. debate를 실행하지 않았으면 `pro_tokens`와 `con_tokens`는 `null`, `verdict_changed_after_debate=false`다. `hold_resolved=true`는 `initial_verdict=HOLD`이고 final `verdict`가 `TRUE | FALSE`일 때만 허용한다.

최종 `VerificationResult`는 등록 가설의 모든 `question_id`를 중복 없이 정확히 한 번씩 평가한다. `DISPROVED`는 해당 질문이 확인하려는 가설의 필수 조건이 실제 근거로 반증됐다는 뜻이며 `evidence_refs`가 하나 이상이어야 한다. `NOT_DISPROVED`는 반증하지 못했다는 뜻일 뿐 가설을 증명하지 않는다. 확인하지 못한 질문은 `INCONCLUSIVE`로 남긴다. `verdict=FALSE`는 적어도 하나의 `DISPROVED` 결과가 있고 `verdict_rationale`이 그 `question_id`와 근거를 설명할 때만 허용한다. `TRUE | HOLD`에는 `DISPROVED` 결과가 있을 수 없다. 오류만으로 `FALSE`를 만들지 않는다.

## 5. Primitive DB records

연계 공격 탐색을 위해 보류된 가설의 필요 조건과 확인된 공격 능력을 저장하는 데이터입니다.

```yaml
Primitive:
  primitive_id: string
  primitive_type: string
  target:
    workspace_id: string
    commit_id: string
    asset: string
    entity_refs: [CodeSymbol]
    privilege_level: string
  status: REQUIRED | PROVIDED
  source_hypothesis_id: string
  evidence_refs: [StoredDataRef]
  confidence: LOW | MEDIUM | HIGH
  description: string
```

```yaml
HeldHypothesis:
  hypothesis_id: string
  verdict: HOLD
  restrictions: [string]
  required_primitives: [Primitive]
  unresolved_conditions: [string]
  related_entities: [CodeSymbol]
  chain_depth: integer
```

```yaml
ConfirmedCapability:
  hypothesis_id: string
  verdict: TRUE
  provided_primitives: [Primitive]
  affected_entities: [CodeSymbol]
  privilege_level: string
  evidence_refs: [StoredDataRef]
```

```yaml
PrimitiveMatchCandidate:
  primitive_match_id: string
  required_primitive_id: string
  provided_primitive_id: string
  workspace_id: string
  commit_id: string
  asset_check: PASS | UNCERTAIN
  entity_check: PASS | UNCERTAIN
  privilege_check: PASS | UNCERTAIN
  attack_order_check: PASS | UNCERTAIN
  restriction_check: PASS | UNCERTAIN
  normalized_fingerprint: string
  evidence_refs: [StoredDataRef]
  unresolved_conditions: [string]
  candidate_state: UNVALIDATED
```

`PrimitiveMatchCandidate`는 같은 `workspace_id + commit_id`의 REQUIRED 하나와 PROVIDED 하나를 연결한다. 두 primitive ID는 서로 달라야 하고 실제 `Primitive`를 가리켜야 한다. 다섯 check 중 하나라도 호환되지 않으면 후보를 만들지 않는다. 모두 `PASS`면 `unresolved_conditions`는 비어 있어야 하고, 하나라도 `UNCERTAIN`이면 확인할 조건을 반드시 기록한다. `evidence_refs`는 하나 이상이며 각 reference도 같은 workspace·commit을 가리킨다. 같은 `normalized_fingerprint`를 같은 분석에서 중복 저장하지 않는다. match는 queue message, verdict, Finding 또는 impact 확정이 아니다.

## 6. ResearchResult

추가 탐색 Agent가 우회·영향 확대·연계 가능성과 새로 검증할 가설 후보를 반환하는 결과입니다.

```yaml
ResearchResult:
  meta: RecordMeta
  target_hypothesis_id: string
  trigger: TRUE_RESULT | HOLD_RESULT | TECHNICAL_REVISION | LOW_IMPACT_EXTENSION | PRIMITIVE_MATCH
  bypass_candidates: [CandidateRef]
  alternate_paths: [CandidateRef]
  impact_escalation_candidates: [CandidateRef]
  primitive_matches: [PrimitiveMatchCandidate]
  chained_hypothesis_proposals: [HypothesisProposal]
  additional_validation_requests: [string]
  no_material_extension_reason: string | null
  errors: [AnalysisError]
```

이 record는 기존 verdict, CWE, Gate 또는 Finding을 변경하지 않는다. material candidate는 새 proposal로 재검증한다.

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
DynamicReproductionResult:
  meta: RecordMeta
  mode: LIMITED_REPRO | FULL_REPRO
  environment_ref: StoredDataRef
  steps_ref: StoredDataRef
  observation_refs: [StoredDataRef]
  status: SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED
  failure_reason: NONE | ENVIRONMENT_SETUP | EXECUTION | OBSERVATION | POLICY_BLOCKED | TIMEOUT
  hypothesis_outcome: SUPPORTED | DISPROVED | INCONCLUSIVE
  hypothesis_evidence_refs: [StoredDataRef]
  hypothesis_disproved: boolean
  disproof_evidence_refs: [StoredDataRef]
  hypothesis_linkage: string
  limitations: [string]
  cleanup_status: SUCCEEDED | FAILED
  started_at: timestamp
  finished_at: timestamp
  elapsed_ms: integer
```

`status`는 재현 작업을 얼마나 실행했는지, `hypothesis_outcome`은 유효한 관측이 가설과 어떤 관계인지 나타내며 둘 다 Verification verdict가 아니다. 다음 조합만 허용한다.

| `status` | `failure_reason` | 필수 의미 |
|---|---|---|
| `SUCCEEDED` | `NONE` | 계획한 필수 단계와 관측을 끝냄. outcome은 관측에 따라 세 값 모두 가능 |
| `PARTIAL` | `NONE` | 공격 경로를 일부 실행해 신뢰할 수 있는 관측이 하나 이상 있지만 전체 확인은 부족함. `hypothesis_outcome=INCONCLUSIVE`, evidence와 `limitations`가 각각 하나 이상 필요 |
| `FAILED` | `ENVIRONMENT_SETUP | EXECUTION | OBSERVATION | TIMEOUT` | 필수 환경·공격 경로·관측을 완료하지 못함. `hypothesis_outcome=INCONCLUSIVE` |
| `BLOCKED` | `POLICY_BLOCKED` | sandbox 정책 때문에 실행하지 못함. `hypothesis_outcome=INCONCLUSIVE` |
| `CANCELLED` | `NONE` | 사용자나 runtime이 중단함. `hypothesis_outcome=INCONCLUSIVE` |

필수 환경을 구성하지 못해 대상 애플리케이션이나 관련 공격 경로를 실행하지 못했다면 `FAILED + ENVIRONMENT_SETUP`이다. 단순 환경 구성 실패를 `PARTIAL`로 기록하지 않는다. `SUPPORTED | DISPROVED`는 `hypothesis_evidence_refs`가 하나 이상 있어야 한다. `DISPROVED`이면 `hypothesis_disproved=true`이고 `disproof_evidence_refs`가 하나 이상이며 모두 `hypothesis_evidence_refs`에도 포함되어야 한다. 나머지 outcome은 `hypothesis_disproved=false`와 빈 `disproof_evidence_refs`를 사용한다. 빈 stdout, exit code, 실행 실패만으로 `DISPROVED`나 `FALSE`를 만들 수 없다. 최종 `TRUE | FALSE | HOLD`는 Verification Agent가 이 결과와 정적·찬반 근거를 함께 보고 결정한다.

## 8. TechnicalEvidenceReview

첫 번째 Gate가 검증 판정과 코드·실행 근거의 연결을 확인하고 승인·보완·거절을 기록하는 결과입니다.

```yaml
TechnicalEvidenceReview:
  meta: RecordMeta
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
  research_requests: [string]
  rationale: string
```

`verification_result_ref.record_id`와 `cwe_label_ref.record_id`는 필수이며 각각 정확히 한 `VerificationResult`와 `CWELabel` revision을 가리킨다. runtime은 두 대상의 `record_id`, `workspace_id`, `commit_id`, `hypothesis_id`와 `content_hash`가 서로와 현재 Technical review에 일치하는지 확인한다. Verification 또는 CWELabel이 새 revision으로 바뀌면 이전 `TechnicalEvidenceReview`를 재사용할 수 없고 Gate를 새로 호출해야 한다. Technical review는 `VerificationResult.verdict`나 `CWELabel`을 덮어쓰지 않는다.

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

`program_id`는 내부 Program Catalog가 발급한 전역 ID다. `program_namespace`는 외부 플랫폼이나 catalog 출처를 나타내며, `external_program_id`는 그 출처 안의 프로그램 ID다. 외부 프로그램의 유일 키는 `(program_namespace, external_program_id)`이고, 내부 catalog는 이 쌍을 하나의 `program_id`에 매핑한다. namespace가 다른 같은 외부 ID를 자동 병합하지 않는다.

```yaml
RuleScopeImpactReview:
  meta: RecordMeta
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

`verification_result_ref.record_id`, `technical_review_ref.record_id`와 `cwe_label_ref.record_id`는 필수다. `technical_review_ref` 대상은 `status=ACCEPT`이고, 그 대상의 Verification과 CWE reference `record_id`는 Rule Scope review가 직접 가리키는 두 `record_id`와 각각 같아야 한다. runtime은 각 reference의 `workspace_id`, `commit_id`, `content_hash`가 실제 대상 record와 일치하고, Verification·CWELabel·Technical 대상 `RecordMeta.hypothesis_id`가 현재 Rule Scope review의 가설과 같은지 확인한다. `policy_record_ref`가 있으면 그 `record_id`도 필수이며 실제 `ProgramPolicyRecord`와 일치해야 한다. 어느 입력 revision이든 바뀌면 이전 Rule Scope review를 재사용하지 않는다.

공식 `ProgramPolicyRecord`가 없으면 `policy_record_ref=null`이다. 정책 record가 없거나 핵심 출처가 누락되면 `rule_compliance`, `scope_compliance`, `review_status`는 `UNCERTAIN`, permission은 `DENY`다. 불완전한 정책 record 자체가 있으면 그 reference는 보존하고 `missing_information`에 누락 내용을 기록한다. 이 불변조건을 만족하지 않는 출력은 invalid다.

## 10. LLM invocation records

각 LLM 호출의 요청, 응답, 모델·세션 정보, 사용량과 오류를 다시 확인할 수 있게 남기는 기록입니다.

```yaml
LLMInvocationRequest:
  meta: RecordMeta
  llm_call_id: string
  agent_role: HYPOTHESIS | VERIFICATION | PRO | CON | RESEARCH | TECHNICAL_GATE | RULE_SCOPE_GATE | REPORTER
  provider_profile: string
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

`timeout_ms`는 monotonic clock으로 계산하는 0보다 큰 밀리초 실행 예산이다.

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

```yaml
LLMInvocationLog:
  meta: RecordMeta
  llm_call_id: string
  agent_role: string
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

새로운 독립 호출은 `retry_count=0`이고 두 선행 호출 reference가 모두 `null`이다. 같은 provider/model에서 일반 retry를 실행하면 `retry_of_llm_call_id`가 바로 앞의 허용된 실패 호출을 가리키고 `failover_from_llm_call_id=null`이다. provider 또는 model을 바꾸는 failover이면 반대로 `failover_from_llm_call_id`만 바로 앞의 허용된 실패 호출을 가리킨다. 두 필드는 동시에 값을 가질 수 없다.

일반 retry의 선행 status는 `FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED`만 허용한다. `INVALID_OUTPUT`은 제한된 repair가 끝난 뒤, `RATE_LIMITED`는 정한 backoff 뒤, `AUTH_REQUIRED`는 사용자 또는 승인된 운영자가 재인증을 완료한 뒤에만 후속 호출을 시작한다. failover의 선행 status는 `FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED`만 허용하며, 사전에 허용된 fallback profile과 전환 이유를 기록해야 한다. `AUTH_REQUIRED`에서 failover하려면 대상 provider의 유효한 인증이 별도로 준비되어 있어야 한다.

`SUCCEEDED`는 retry나 failover의 선행 호출로 사용할 수 없다. `CANCELLED`도 같은 chain에서 후속 호출을 허용하지 않으며, 사용자가 새 작업을 요청하면 선행 reference가 없는 독립 호출로 시작한다. 선행 호출은 같은 `analysis_id`, `hypothesis_id`, `agent_role`의 바로 앞 호출이어야 하고 현재 호출 자신이나 이후 호출을 가리킬 수 없다. 후속 호출의 `retry_count`는 바로 앞 호출보다 정확히 1 커야 한다. runtime은 허용되지 않은 predecessor status, 존재하지 않는 predecessor, 순환 reference와 순서가 맞지 않는 chain을 `INVOCATION_CHAIN_INVALID`로 거절한다. 이 규칙으로 최초 실패 → 일반 retry → provider/model failover의 순서와 원인을 각 `llm_call_id`를 따라 복원한다.

hidden chain-of-thought와 credential은 이 계약의 대상이 아니며 저장하지 않는다.

## 11. ReportDraft와 AnalysisRunResult

모든 전달 조건을 통과한 보고서 초안과, 분석 한 건의 결과·자원·오류·디버깅 정보를 모은 최종 묶음입니다.

```yaml
ReportDraft:
  meta: RecordMeta
  verification_result_ref: StoredDataRef
  technical_review_ref: StoredDataRef
  rule_scope_impact_review_ref: StoredDataRef
  cwe_label_ref: StoredDataRef
  policy_record_ref: StoredDataRef
  content_ref: StoredDataRef
  draft_status: DRAFTED
  human_review_state: PENDING | APPROVED | REJECTED
```

`verification_result_ref`, `technical_review_ref`, `rule_scope_impact_review_ref`, `cwe_label_ref`와 `policy_record_ref`는 저장된 record를 가리키므로 각 `StoredDataRef.record_id`가 필수다. Reporter runtime은 다음 연결을 모두 확인하고 하나라도 다르면 초안을 만들지 않는다.

- Technical review와 Rule Scope review가 모두 ReportDraft의 같은 Verification `record_id`를 가리킨다.
- Rule Scope review의 `technical_review_ref.record_id`가 ReportDraft의 `technical_review_ref.record_id`와 같다.
- Technical review와 Rule Scope review가 모두 ReportDraft의 같은 CWELabel `record_id`를 가리킨다.
- Rule Scope review의 `policy_record_ref.record_id`가 ReportDraft의 `policy_record_ref.record_id`와 같다.
- 각 reference의 `workspace_id`, `commit_id`, `content_hash`가 실제 대상 record와 일치하고, 가설별 대상 record의 `meta.hypothesis_id`가 ReportDraft와 같다. CWELabel이 새 revision으로 바뀌면 두 Gate와 ReportDraft를 모두 새 revision 기준으로 다시 생성한다.

```yaml
AnalysisRunResult:
  meta: RunMeta
  repository_url: string
  workspace_id: string | null
  commit_id: string | null
  status: COMPLETE | PARTIAL | FAILED | CANCELLED
  hypothesis_counts: map
  verdict_counts: map
  gate_counts: map
  verification_refs: [StoredDataRef]
  primitive_and_research_refs: [StoredDataRef]
  poc_refs: [StoredDataRef]
  report_draft_refs: [StoredDataRef]
  llm_invocation_log_refs: [StoredDataRef]
  work_state_refs: [RunStoredDataRef | StoredDataRef]
  work_attempt_refs: [RunStoredDataRef | StoredDataRef]
  transition_commit_refs: [RunStoredDataRef | StoredDataRef]
  stop_reasons: [string]
  errors: [AnalysisError]
  resources: map
  started_at: timestamp
  finished_at: timestamp
  elapsed_ms: integer
  debug_trace_ref: RunStoredDataRef
```

Reporter 호출은 `TRUE + Technical ACCEPT + Rule Scope Impact review_status PASS + rule_compliance PASS + scope_compliance PASS + security_impact SUFFICIENT + ALLOW`인 경우만 유효하다.

## 구현 단계에서 결정할 것

serialization format, schema language/versioning, database/index, Primitive vocabulary, policy source collector, confidence range와 정량 limit은 구현 전 ADR과 평가 corpus로 확정한다. 이 설계의 field 목록을 곧바로 모든 서비스의 영구 API로 간주하지 않는다.
