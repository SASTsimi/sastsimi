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
| `question_id` | proposal 출력 검증 runtime 또는 `PlaybookApplication` 생성 runtime | 전체 시스템 | `FalsificationQuestion`, `AppliedPlaybookQuestion`과 `FalsificationResult` | proposal 질문은 등록 가설까지 유지한다. 플레이북 질문은 적용마다 새 값을 만들며 템플릿 이름이나 다른 가설의 값을 재사용하지 않는다.|
| `code_request_id` | 코드 문맥을 요청하는 Agent Runtime | 전체 시스템 | `CodeContextRequest`와 해당 `CodeContextResponse` | 요청·응답 한 쌍에서 같은 값 유지 |
| `primitive_id` | `PRIMITIVE_ADMISSION_RUNTIME` | 전체 시스템 | `Primitive`와 체이닝 후보 | Primitive마다 새 값 |
| `parser_result_id` | 정책 parser 결과를 저장하는 runtime | 전체 시스템 | `PolicyParserResult` | parser 실행 결과마다 새 값 |
| `collection_result_id` | 정책 수집 결과를 확정하는 runtime | 전체 시스템 | `PolicyCollectionResult` | 정책 수집 시도마다 새 값 |
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
| proposal 검증 | `ProposalProcessState.status` | `PROPOSED | SCHEMA_VALID | DUPLICATE | INVALID_OUTPUT | CANCELLED` | 출력 검증 runtime | 아직 `hypothesis_id`가 없는 상태 |
| 등록 가설 처리 | `HypothesisProcessState.status` | `REGISTERED | ASSIGNED | VERIFYING | TERMINAL | FAILED | CANCELLED` | Orchestration runtime | `TRUE | FALSE | HOLD`와 분리 |
| 기술 판정 | `VerificationResult.verdict` | `TRUE | FALSE | HOLD` | Verification Agent | 오류·정보 부족 상태와 분리 |
| 동적 재현 | `DynamicReproductionState.status` | `NOT_REQUESTED | RUNNING | SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED` | Reproduction Session Manager | `FAILED`만으로 가설 반증 금지 |
| LLM 호출 | `LLMInvocationResult.status` | `SUCCEEDED | FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED | CANCELLED` | Agent Runtime과 provider adapter | 가설 verdict로 변환 금지 |
| 기술 Gate | `TechnicalEvidenceReview.status` | `ACCEPT | REVISE | REJECT` | Technical Evidence Gate Agent | Verification verdict를 변경하지 않음 |
| 정책·영향 Gate | `RuleScopeImpactReview.review_status`, `testing_restriction_compliance`, `report_permission` | `PASS | FAIL | UNCERTAIN`, `ALLOW | DENY` | Rule Scope Impact Gate Agent | 보고 가능성·금지 테스트 판정과 기술 판정 분리 |
| 체이닝 재료 사용 | `PrimitiveAdmissionDecision.decision` | `ALLOW | DENY` | `PRIMITIVE_ADMISSION_RUNTIME` | Gate의 구조화된 값을 재해석하지 않고 기계적으로 매핑 |
| 보고서 초안 | `ReportProcessState.status` | `NOT_REQUESTED | DRAFTED | FAILED` | Reporter runtime | 공개 승인 상태가 아님 |

진행 중인 상태도 저장할 수 있도록 아래 최소 상태 record를 사용한다. 종료 결과 record는 상세 근거를 담고, 상태 record는 현재 진행 위치를 나타낸다.

```yaml
AnalysisRunState:
  meta: RunMeta
  purpose: PRODUCTION | EVALUATION
  eval_config_refs: [RunStoredDataRef | StoredDataRef]
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
  status: PROPOSED | SCHEMA_VALID | DUPLICATE | INVALID_OUTPUT | CANCELLED
  duplicate_review_ref: StoredDataRef | null
  duplicate_of_hypothesis_ref: StoredDataRef | null
  registration_reason: NOT_CHECKED | NO_CANDIDATES | UNIQUE | UNCERTAIN | CHECK_FAILED | INVALID_DUPLICATE_TARGET | DUPLICATE
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

`purpose`와 `eval_config_refs`는 분석 시작 때 고정하며 같은 `analysis_id`에서 바꾸지 않는다. PRODUCTION에서는 `verification_mode=ALWAYS_DEBATE`만 허용한다. 이때 `AnalysisRunState.eval_config_refs=[]`다. EVALUATION은 비어 있지 않은 exact 설정 집합을 사용한다. EVALUATION의 `BASIC | CONDITIONAL_DEBATE` 결과는 Gate·Primitive admission·Reporter 입력으로 사용할 수 없다. 시간·비용·호출·재시도·work 예산이 부족하면 `BUDGET_EXCEEDED`로 현재 Verification work를 중단하며 Pro/Con을 생략한 final verdict를 만들지 않는다. token 예상값·실제 사용량은 관측하되 token 초과·누락만으로 이 오류를 만들지 않는다.

`AnalysisRunState.status=RUNNING`이면 `analysis_result_ref=null`이다. `COMPLETE | PARTIAL | FAILED | CANCELLED`이면 `analysis_result_ref`가 필수이고 같은 `analysis_id`의 정확한 `AnalysisRunResult`를 가리킨다. 최종 상태와 결과는 atomic transition으로 함께 확정한다.

`ProposalProcessState`의 모든 revision은 `meta.hypothesis_id: null`을 유지한다. `PROPOSED`는 schema·semantic·중복 검사가 아직 끝나지 않은 상태이며 `registration_reason=NOT_CHECKED`, 두 duplicate reference는 `null`이다. schema·semantic validation을 통과한 뒤 비교 후보가 없으면 `SCHEMA_VALID + NO_CANDIDATES`이고 두 duplicate reference는 `null`이다. 유효한 LLM 판정이 `UNIQUE | UNCERTAIN`이면 같은 이름의 registration reason, non-null `duplicate_review_ref`, `duplicate_of_hypothesis_ref=null`을 사용한다. LLM 호출 실패·형식 오류는 `SCHEMA_VALID + CHECK_FAILED`, LLM이 후보 목록 밖의 대상을 중복으로 지목하면 `SCHEMA_VALID + INVALID_DUPLICATE_TARGET`이고 두 경우 모두 duplicate reference는 `null`이다. 실패 호출·파싱 결과·오류는 `LLMInvocationLog`와 `AnalysisError`에서 추적한다. 이 `SCHEMA_VALID` 경로들은 새 `hypothesis_id`를 발급하고 별도 `logical_record_id`의 `HypothesisProcessState.status=REGISTERED`를 만든다. `DUPLICATE`이면 새 `hypothesis_id`를 발급하지 않는다. 이때 `duplicate_review_ref`와 후보 목록 안의 exact `duplicate_of_hypothesis_ref`가 필수이고, 두 값은 review record와 정확히 같으며 `registration_reason=DUPLICATE`다. `INVALID_OUTPUT | CANCELLED`에서는 `registration_reason=NOT_CHECKED`, 두 duplicate reference는 `null`이고 새 가설을 만들지 않는다. `PROPOSED`만 `finished_at=null`이고 나머지는 종료 시각이 필수다. 등록 경로에서는 final `ProposalProcessState`, 새 `VulnerabilityHypothesis`와 `HypothesisProcessState.status=REGISTERED`를 같은 atomic transition으로 확정한다. 중복 경로에서는 final state와 exact review를 함께 확정한다. 이 record들은 같은 `proposal_ref`로 연결하지만 서로의 revision으로 취급하지 않는다.

진행 중인 상태는 `finished_at: null`이다. 종료 상태는 `finished_at`이 필수이며 `elapsed_ms`는 시작부터 종료까지 monotonic clock으로 계산한다. `NOT_REQUESTED`는 `started_at: null`, `finished_at: null`, `elapsed_ms: 0`이다. `DynamicReproductionState.status=BLOCKED`는 같은 work가 재시도 또는 외부 설정 수정을 기다리는 비종료 상태이므로 `finished_at: null`을 유지한다. `SUCCEEDED | PARTIAL | FAILED | CANCELLED`로 work를 닫을 때만 `finished_at`을 기록한다. 반면 각 `DynamicReproductionResult`는 한 attempt의 종료 기록이므로 해당 결과의 `finished_at`은 `null`일 수 없다.

`VerificationAssignment`은 Orchestration의 배정 제안을 신뢰 runtime이 검사한 뒤 만드는 저장 record다. `owner_identity_ref`는 한 hypothesis-local workflow의 논리 owner를 가리키며 Agent가 자기 출력으로 만들 수 없다. 최초 배정은 `assignment_generation=1`, `status=ACTIVE`다. 운영상 owner 교체가 필요하면 trusted recovery 또는 사람 승인 절차가 이전 assignment를 `SUPERSEDED`로 만들고 새 generation을 원자적으로 활성화한다. Technical `REVISE` 자체는 owner 교체 사유가 아니며 같은 ACTIVE assignment를 유지한다.

`HypothesisProcessState.status=REGISTERED`에서는 assignment·work·result reference가 `null`이고 `verification_generation=0`이다. `ASSIGNED | VERIFYING | TERMINAL | FAILED`에는 ACTIVE `verification_assignment_ref`가 필수다. `VERIFYING`은 현재 generation의 `verification_work_ref`가 필수이며, 최초 검증 전 `verification_result_ref=null`, Technical `REVISE` 보완 중에는 직전 final result ref를 유지할 수 있다. `TERMINAL`이면 `verification_work_ref=null`이고 `verification_result_ref.record_id`가 현재 가설의 exact final `VerificationResult` revision을 가리켜야 한다. `FAILED`는 검증 절차가 허용된 재시도를 소진했거나 복구 불가능한 오류로 끝나 final verdict를 만들지 못한 종료 상태다. 이때 `verification_work_ref`는 같은 `VERIFICATION` work의 `FAILED` revision을 가리키고 `verification_result_ref=null`이며, 오류와 미확인 범위는 해당 work·transition·최종 분석 결과에 보존한다. 동적 재현을 요청하면 `DynamicReproductionState.request_ref`는 current generation의 exact `DynamicReproductionRequest`를 가리킨다. `SUCCEEDED | PARTIAL | BLOCKED | FAILED | CANCELLED`에는 Reproduction Session Manager가 확정한 exact `DynamicReproductionResult.record_id`가 필수다. Agent 호출 전 정책 차단도 Session Manager가 최소 `AgentLog`와 결과를 만들기 때문에 결과 reference를 생략하지 않는다. 자동 retry 중간 attempt의 실패 결과는 해당 `WorkAttempt.output_refs`와 로그에만 보존하고, R6에 반환하는 `dynamic_result_ref`는 최종 성공·부분 완료·외부 대기·최종 실패·취소 결과만 가리킨다. `NOT_REQUESTED`에서는 두 reference가 모두 `null`이고, `RUNNING`에서는 request가 필수이며 반환할 final result는 아직 `null`이다. `ReportProcessState.status=DRAFTED`이면 `report_draft_ref.record_id`가 필수이며 정확히 하나인 `ReportDraft` revision을 가리키고, `NOT_REQUESTED | FAILED`이면 `report_draft_ref=null`이다.

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
| `RUNNING` | `READY`, `BLOCKED`, `SUCCEEDED`, `PARTIAL`, `FAILED`, `CANCELLED` | attempt 결과와 atomic transition이 있음. `READY`는 DYNAMIC_REPRO의 즉시 자율 retry에만 허용 |
| `BLOCKED` | `READY`, `FAILED`, `CANCELLED` | 대기 조건을 충족하거나 더 진행할 수 없음 |
| `SUCCEEDED`, `PARTIAL`, `FAILED`, `CANCELLED` | 없음 | 종료 상태를 되돌리지 않음 |

상태별 필드 조건은 다음과 같다.

- `PENDING | READY`는 `active_attempt_id=null`, 빈 `output_refs`와 빈 `waiting_for`를 사용한다.
- `RUNNING`은 `active_attempt_id`, `started_at`이 필수이고 `finished_at=null`이다.
- `BLOCKED`는 `active_attempt_id=null`, 하나 이상의 `waiting_for`와 구체적인 `stop_reason`이 필요하다.
- `SUCCEEDED | PARTIAL | FAILED | CANCELLED`는 `active_attempt_id=null`, `finished_at`과 `stop_reason`이 필요하다. 정상 `SUCCEEDED`의 `stop_reason`은 `COMPLETED`다.
- `PARTIAL`은 `STATIC_TOOL | STATIC_NORMALIZE | CONTEXT_RETRIEVAL | DYNAMIC_REPRO`에서만 허용하고 하나 이상의 신뢰 가능한 `output_refs`가 필요하다. static·context 작업은 누락을 설명하는 `error_ids` 또는 `gap_ids`가 필요하다. `DYNAMIC_REPRO`는 정확히 하나의 `DynamicReproductionResult(status=PARTIAL, failure_category=NONE, failure_reason=null)`를 가리키고 그 결과의 `hypothesis_evidence_refs`와 `limitations`가 각각 하나 이상이면 이 구조화된 `limitations`가 부분 실행의 누락 설명을 대신한다. 실제 오류나 `DataGap`이 없는데 동적 재현의 정상적인 환경 한계를 억지로 `error_ids`나 `gap_ids`로 만들지 않는다.
- `FAILED`는 하나 이상의 `error_ids`가 필요하다. 전문 schema가 실패 결과 record를 정의한 `DYNAMIC_REPRO` 같은 작업은 그 실패 record를 `output_refs`에 포함할 수 있지만 성공 결과로 해석하지 않는다.
- `DYNAMIC_REPRO` 취소 전이는 현재 활성 attempt가 만든 `DynamicReproductionResult(status=CANCELLED)`를 같은 atomic transition에서 확정할 수 있다. 이미 `CANCELLED`가 확정된 뒤 늦게 도착한 output은 현재 상태에 연결하지 않는다.
- `CWE_LABEL`의 `SUCCEEDED`, exact `CWELabel` 저장과 그 하나뿐인 `output_refs`는 같은 `COMMITTED` `TransitionCommit`으로 확정한다. label만 저장되거나 work만 종료된 불완전 상태는 current label로 보지 않고 recovery가 journal을 끝낼 때까지 Technical Gate를 차단한다.
- `WorkExecutionState.elapsed_ms`는 완료된 `WorkAttempt.elapsed_ms`의 합이다. block 대기 시간과 프로세스가 꺼진 시간은 별도 상태 체류 지표로 기록하며 실행 시간에 더하지 않는다.
- `WorkAttempt.attempt_number`는 한 `work_id` 안에서 1부터 1씩 증가하고, `WorkAttempt.input_hash`는 그 attempt를 시작할 때의 `WorkExecutionState.input_hash`와 같다. `RecordMeta`를 쓰면 `meta.attempt_id`도 `WorkAttempt.attempt_id`와 같아야 한다.

`WORKSPACE_PREP`과 commit 준비 전에 만든 실행 상태는 모든 revision에서 `RunMeta`를 유지한다. workspace·commit 준비 뒤 등록한 work는 모든 revision에서 `RecordMeta`를 유지한다. `WorkExecutionState`는 여러 attempt를 묶으므로 `RecordMeta`를 쓸 때도 `meta.attempt_id=null`이다. `WorkAttempt`·`StateTransition`·`TransitionCommit`이 `RecordMeta`를 쓰고 attempt가 원인이면 `meta.attempt_id`와 본문 `attempt_id`가 같아야 한다. `RunMeta`에는 attempt 필드가 없으므로 pre-workspace record는 본문 `attempt_id`로만 연결한다. dependency 준비·사람 취소처럼 attempt 밖에서 일어난 전이는 본문과, 존재하는 경우 `meta.attempt_id`를 모두 `null`로 둔다.

`parent_work_ref`는 작업의 직접 부모를 가리키는 선택 필드다. `PRO_EVIDENCE | CON_EVIDENCE | DYNAMIC_REPRO | CWE_LABEL`에서는 필수이며, 같은 가설과 현재 `verification_generation`의 `VERIFICATION` work exact revision을 가리켜야 한다. `DYNAMIC_REPRO`의 request와 부모 Verification은 같은 `hypothesis_id`와 `verification_generation`이어야 한다. `CWE_LABEL`의 입력 `verification_result_ref`는 부모 Verification work가 `SUCCEEDED`로 확정한 유일한 final TRUE output이어야 한다. 나머지 work type은 이 문서가 별도 부모 관계를 정하지 않는 한 `null`이다. 자식 work의 `subject_id`와 부모 Verification의 `subject_id`는 같은 `hypothesis_id`여야 하며, 부모가 교체되거나 generation이 바뀌면 기존 자식 결과를 새 부모에 연결하지 않는다.

일반 작업의 재시도 가능한 attempt 실패는 `WorkAttempt.status=FAILED`와 오류를 보존하고 작업을 `BLOCKED`로 전환한다. 단, `DYNAMIC_REPRO`에서 외부 입력이나 승인을 기다리지 않고 R7이 즉시 자율 재시도할 수 있으면 이전 attempt와 결과·로그를 보존한 채 `RUNNING -> READY`를 atomic하게 확정하고 바로 새 `attempt_id`를 발급한다. 이 전이는 같은 `work_id`·`input_hash`·request를 유지하고 R8 retry·시간·resource 한도가 남아 있을 때만 허용한다. 재인증·정책 변경·외부 설정·resource profile 변경처럼 외부 조건을 기다릴 때만 `BLOCKED`와 `waiting_for`를 사용한다. 재시도할 수 없거나 한도를 소진한 때만 작업을 최종 `FAILED`로 끝낸다. 종료된 작업을 되돌리지 않는다. 사람이 같은 입력으로 새 논리 실행을 명시적으로 승인하면 이전 값보다 1 큰 `work_generation`과 새 `work_id`를 만들고, 두 작업을 restart 관계로 debug trace에 연결한다.

운영 Pro/Con 자식 중 하나가 재시도 가능한 오류로 `BLOCKED`가 되면 부모 `VERIFICATION` work도 `BLOCKED`가 되고 같은 실제 대기 이유를 `waiting_for`에 기록한다. 가설 상태는 `VERIFYING`을 유지하며 final `VerificationResult`를 만들지 않는다. 자식 `BLOCKED`가 먼저 보인 짧은 구간에도 runtime은 부모의 새 attempt·합성·결과 저장을 거절하고 recovery가 부모 상태를 맞춘다. 입력·부모 generation·Debate 설정이 그대로이면 성공한 다른 자식 결과는 보존할 수 있고 실패한 역할만 새 attempt와 새 `llm_call_id`, 새 `NEW` session으로 재시도한다. 하나라도 달라지면 기존 두 자식 결과를 모두 `STALE_RESULT`로 격리하고 Pro와 Con을 다시 실행한다.

자식이 복구 불가능하거나 허용된 재시도를 모두 소진하면 먼저 그 자식 work의 `FAILED`를 자기 `COMMITTED` `TransitionCommit`으로 확정한다. 이 상태가 보이는 즉시 부모 `VERIFICATION`의 새 실행·합성·결과 저장은 금지한다. 이어서 부모 work의 `FAILED`와 `HypothesisProcessState.status=FAILED`를 기존 Verification 실패 atomic 경계로 함께 확정하고, 가설은 부모의 exact failed work를 가리키며 `verification_result_ref=null`을 유지한다. 두 번째 확정 전에 중단되면 recovery가 `parent_work_ref`와 실패 자식의 commit을 읽어 전파를 끝낼 때까지 부모를 진행시키지 않는다. 취소된 자식은 retry/failover 선행 호출로 사용할 수 없고, 부모가 취소·교체·종료된 뒤 도착한 결과는 `STALE_RESULT`로 격리한다. 어느 오류도 `FALSE | HOLD`로 바꾸지 않는다.

`work_generation`은 같은 분석·작업 종류·대상·입력에서 1부터 시작한다. 일반 retry와 resume에서는 바꾸지 않고, 종료 상태 뒤 사람이 승인한 명시적 restart에서만 1 증가한다. `dedupe_key`는 `analysis_id`, `work_type`, `subject_id`, `work_generation`, 작업 등록 전에 이미 존재하는 정렬된 입력의 `record_id + content_hash`, 적용한 설정·정책 revision을 canonical JSON으로 만든 SHA-256 값이다. `attempt_id`, 시각과 worker 이름, 작업 등록 transaction에서 새로 만드는 파생 record는 넣지 않는다. 파생 record가 있으면 그 record의 모든 원본 exact reference를 대신 포함한다. 같은 generation과 key의 요청이 다시 오면 새 작업이나 파생 record를 만들지 않고 기존 `work_id`와 현재 상태를 반환한다. 입력 revision·적용 설정·승인된 generation이 바뀌면 새 `dedupe_key`와 새 `work_id`를 만든다.

`REGISTER_WORK(work_type=VERIFICATION)` 시 trusted runtime은 exact `VulnerabilityHypothesis`와 그 `proposal_ref`, current exact `PlaybookPolicy`를 읽고 아래 §4의 결정 규칙으로 `VerificationPlaybook`을 하나 선택한다. runtime은 hypothesis·proposal·policy·playbook exact reference로 먼저 안정적인 `dedupe_key`를 계산한다. 같은 key의 work가 있으면 새 application을 만들지 않고 기존 work와 그 work에 고정된 application을 반환한다. 새 work이면 `work_id`를 발급하고 새 `PlaybookApplication`을 만든 뒤 hypothesis·proposal·policy·playbook·application exact reference를 `WorkExecutionState.input_refs`에 함께 고정한다. work와 application은 같은 저장 transaction에서 확정하며 둘 중 하나라도 저장되지 않으면 work를 `READY | RUNNING`으로 만들지 않는다. `input_hash`에는 다섯 reference의 `record_id + content_hash`를 모두 반영하되, registration 과정에서 새로 생기는 application reference 자체는 `dedupe_key`에 넣지 않고 application의 원본인 hypothesis·proposal·policy·playbook reference를 넣는다.

플레이북·적용 정책의 current revision이 검증 도중 변경되더라도 진행 중인 work의 입력과 `PlaybookApplication`을 바꾸지 않는다. 같은 work의 retry는 기존 application과 질문 ID를 유지한다. 새 Verification work 또는 새 verification generation은 그때의 current policy와 playbook으로 새 application을 만들고 플레이북 질문에 새 `question_id`를 발급한다. 과거 application·질문 결과를 새 work에 자동 승격하거나 서로 다른 application의 Pro·Con·최종 결과를 섞지 않는다.

`REGISTER_WORK(work_type=CHAINING)` 시 trusted runtime은 같은 analysis·workspace·commit의 current `PrimitiveIndexState` revision을 읽고, 각 index의 `primitive_refs`에서 non-null `result` 또는 하나 이상의 `inputs`를 가진 current exact Primitive만 중복 없이 펼친다. result Primitive는 `admission_decision_ref`가 가리키는 같은 Verification의 current `PrimitiveAdmissionDecision.decision=ALLOW`일 때만 펼친다. 또한 각 Primitive의 source hypothesis가 `origin=CHAINING`이면 `source_primitive_match_id`에서 부모 `ChainingResult.input_primitive_refs`를 재귀 추적하고, 그 계보의 모든 result Primitive가 current ALLOW admission decision을 가리키는지 확인한다. 하나라도 current가 아니거나 `DENY`이면 해당 Primitive를 이번 후보에서 제외한다. runtime은 사용한 index revision, 펼친 Primitive exact reference와 이들에 직접·재귀적으로 연결된 current ALLOW decision exact reference를 함께 고정한다. 이 전체를 `WorkExecutionState.input_refs`, `input_hash`와 `dedupe_key`에 반영하며 Primitive reference 집합이 해당 work의 `considered_primitive_refs`다. 진행 중 새 Primitive나 일반 index revision이 생겨도 기존 work 입력에 섞지 않고 새 Chaining work에서 처리한다. 저장 시에는 실제 match에 사용한 Primitive의 admission 계보만 다시 확인하며, 그중 하나가 더 이상 current가 아니거나 `DENY`로 바뀌면 해당 결과를 `STALE_RESULT`로 거절한다. 사용하지 않은 후보의 decision 변경과 일반 index 갱신만으로는 기존 work를 무효화하지 않는다. 결과에 해당 work가 고정하지 않은 index·Primitive·admission decision reference가 섞여도 `STALE_RESULT`로 거절한다. 이는 별도 Snapshot 모듈이 아니라 실행 입력의 exact reference 고정이다.

`origin=CHAINING` 가설의 새 Verification·Gate·Primitive update·Reporter work를 등록하거나 그 결과를 저장할 때도 trusted runtime은 같은 `source_primitive_match_id` 계보의 result Primitive admission decision을 재귀 확인한다. 확정된 `DENY` 또는 오래된 decision이 있으면 새 작업·결과 사용을 차단하고, 실행 중 work는 `CANCELLED`로 정리하며 가설 verdict를 `FALSE | HOLD`로 바꾸지 않는다. 이미 COMMITTED된 Verification·Gate·Finding·ReportDraft는 감사 이력으로 남기되 current 결과나 외부 전달 가능 결과로 사용하지 않는다. 같은 run 안에서 ALLOW가 DENY로 바뀌면 admission runtime은 이를 참조한 `ChainingResult.source_admission_refs`와 자식 `source_primitive_match_id`를 따라 파생 Primitive를 current index에서 제거한다. 이 전파가 끝나기 전에는 `AnalysisRunResult`를 확정하지 않는다.

`REVISE`는 일반 retry나 resume이 아니다. Technical Gate가 유효한 `TechnicalEvidenceReview.status=REVISE`를 확정하면 기존 Gate work는 `SUCCEEDED`로 종료하고 그 review를 같은 hypothesis의 ACTIVE `VerificationAssignment` owner에게 전달한다. runtime은 `HypothesisProcessState.status=TERMINAL`, 그 상태의 `verification_result_ref`가 Gate가 검토한 exact revision, assignment가 여전히 ACTIVE인지 compare-and-set으로 확인한다. 그 뒤 종료된 기존 VERIFICATION work를 되돌리지 않고 `verification_generation + 1`인 새 `WorkExecutionState(work_type=VERIFICATION)`를 등록하며, 같은 atomic transition에서 hypothesis 상태를 `VERIFYING`, `finished_at=null`, `verification_work_ref=새 work`, `verification_result_ref=직전 final result`로 갱신한다. 새 work의 input에는 exact REVISE review와 직전 Verification·CWELabel reference가 들어간다.

같은 owner가 새 work에서 보완을 마치면 새 `VerificationResult`와 새 VERIFICATION work의 `SUCCEEDED`, `HypothesisProcessState.status=TERMINAL`, 새 `verification_result_ref`, `verification_work_ref=null`을 한 atomic commit으로 확정한다. final TRUE이면 R5-01 `CWE_LABELING`이 새 `CWE_LABEL` work에서 root cause·Evidence·taxonomy 정렬을 반드시 다시 평가하고 새 Verification을 직접 가리키는 새 `CWELabel` revision을 확정한 뒤에만 Technical Gate work를 등록한다. CWE 값이 이전과 같아도 과거 label `record_id`를 재사용하지 않는다. 새 Gate 작업은 달라진 `input_refs`, `input_hash`, `dedupe_key`, `work_id`를 사용하고 첫 `WorkAttempt`는 새 `attempt_id`, `attempt_number=1`, `trigger=INITIAL`을 사용한다. 이전 Gate review와 새 review는 `RecordMeta.previous_record_id`로 이어지는 같은 논리 record의 revision chain에 남긴다. 반대로 provider timeout이나 일시 오류처럼 domain input이 바뀌지 않은 일반 retry는 같은 `work_id`·`dedupe_key`·`input_hash`를 유지하고 새 `attempt_id`와 `trigger=RETRY`를 사용한다. 동일 입력의 새 attempt만 만들어 `REVISE`를 다시 투표하거나 과거 Gate·CWE reference를 새 Verification revision에 재사용하는 것은 금지한다.

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
| `DYNAMIC_REPRO` | Verification의 `REQUEST_DYNAMIC_REPRO`를 Runtime Validator가 허가 | R7 Agent·Setup Automation·Sandbox Controller, 결과는 Reproduction Session Manager | request·plan·recipe·환경·AgentLog·PoC가 같은 attempt로 연결된 `DynamicReproductionResult` |
| `PRIMITIVE_UPDATE` | non-empty `required_primitive_candidates`를 가진 final HOLD의 Verification 또는 Technical `ACCEPT` 뒤 정책 확인을 마친 admission runtime | `PRIMITIVE_ADMISSION_RUNTIME` | `PrimitiveAdmissionDecision`, 허용된 `Primitive`와 가설별 `PrimitiveIndexState` revision |
| `CHAINING` | Verification handoff 뒤 Chaining runtime | Chaining runtime | `ChainingResult` |
| `CWE_LABEL` | final TRUE를 확정한 Verification workflow 뒤 trusted runtime | R5-01 `CWE_LABELING` | current final TRUE를 직접 가리키는 `CWELabel` 한 개 |
| `POLICY_FETCH` | Rule Scope Gate 준비 runtime | 공식 정책 수집 runtime | `PolicyParserResult`, `PolicyCollectionResult`, `FOUND`이면 `ProgramPolicyRecord` |
| `TECHNICAL_GATE` | Verification runtime | Technical Gate runtime | `TechnicalEvidenceReview` |
| `RULE_SCOPE_GATE` | Verification runtime | Rule Scope Gate runtime | `RuleScopeImpactReview` |
| `REPORT_DRAFT` | Reporter 조건 검사 runtime | Reporter runtime | `ReportDraft` |

`DYNAMIC_REPRO`는 공통 작업 상태와 전문 결과 상태를 다음처럼 연결한다. 공통 상태는 “현재 work가 완료·대기·실패 중 어느 상태인가”를 나타내고 전문 상태는 “재현이 얼마나 수행되었는가”를 나타낸다.

| `DynamicReproductionResult.status` | `WorkExecutionState.status` | 저장 조건과 다음 처리 |
|---|---|---|
| `SUCCEEDED` | `SUCCEEDED` | 계획한 실행과 관측을 끝낸 결과를 저장한다. 가설 지지 여부는 `hypothesis_outcome`을 읽는다. |
| `PARTIAL` | `PARTIAL` | 신뢰 관측과 `limitations`가 있는 부분 실행 결과를 저장한다. 오류나 `DataGap`을 억지로 만들지 않는다. |
| `FAILED` | `FAILED` | 복구 불가능하거나 retry 한도를 소진한 실패 결과와 하나 이상의 `error_ids`를 저장한다. final verdict와 Gate는 없다. |
| `BLOCKED` | `BLOCKED` | 외부 설정·승인·정책 또는 resource profile 변경을 기다린다. 조건 해결 뒤 같은 work의 새 attempt로 재개하며 final verdict와 Gate는 없다. |
| `CANCELLED` | `CANCELLED` | 취소 이유와 취소 결과를 같은 transition에서 저장한다. 취소 확정 뒤 늦은 결과는 격리한다. |

공통 `WorkExecutionState.status=BLOCKED`는 인증, 승인, 외부 설정·정책 또는 입력처럼 외부 조건을 기다리는 비종료 상태다. R7이 스스로 해결할 수 있는 command·PoC·환경 조정은 `BLOCKED` 사유가 아니며 현재 attempt 안에서 수행하거나, session 재시작이 필요하면 `RUNNING -> READY -> RUNNING` 자동 retry를 사용한다. 이때 끝난 실패 attempt의 `DynamicReproductionResult(status=FAILED)`와 `AnalysisError.retryable=true`는 해당 attempt의 output history에 보존하지만 validated PoC나 R6 final verdict로 소비하지 않는다. 외부 조건이 해결되면 같은 `work_id`에서 새 `attempt_id`를 만들며 새 `work_generation`을 만들지 않는다.

작업 모듈과 Agent는 등록 또는 상태 변경을 요청할 뿐 직접 확정하지 않는다. 모든 행의 `StateTransition` 승인과 저장은 신뢰 경계 안의 state transition validator와 state store가 담당한다. Orchestration Agent의 자연어 출력은 상태 변경 명령으로 직접 실행하지 않는다.

결과 record, `StateTransition`과 그 결과를 가리키는 종료 상태는 하나의 논리적 atomic transition으로 확정한다. 저장 제품이 한 transaction을 지원하면 같은 transaction에서 처리한다. 지원하지 않으면 `TransitionCommit` journal을 사용한다. `PREPARED` 출력은 격리 상태이며 다음 단계가 읽을 수 없다. state store는 현재 version·active attempt·입력이 그대로라는 조건을 compare-and-set으로 확인하면서 unique `(work_id, target_state_version)` key의 `COMMITTED` revision을 append한다. 경쟁 중 하나만 성공하며 이 marker가 논리적 확정점이다. runtime은 marker를 `WorkExecutionState`와 전문 상태 pointer에 투영한다. 소비자는 COMMITTED marker와 두 pointer가 모두 같은 output을 가리킬 때만 진행한다. marker 뒤 projection 전에 중단되면 recovery가 marker를 재적용한다. version 충돌, 취소 또는 검증 실패는 `ABORTED`이며 output을 최신 상태에 연결하지 않는다.

state store는 새 전이를 승인하기 전에 `(work_id, current_state_version+1)`의 미완료 journal을 먼저 확인한다. `COMMITTED` marker가 있으면 기존 marker를 상태와 전문 pointer에 재투영하고 경쟁 요청을 `STATE_VERSION_CONFLICT`로 거절한다. `PREPARED`가 있으면 복구 또는 `ABORTED` 처리를 끝내기 전까지 새 전이를 받지 않는다. 따라서 marker와 pointer 사이의 짧은 중단 구간을 이용해 취소·retry·다른 결과가 같은 version을 차지할 수 없다.

다음 output binding은 필수다.

- `STATIC_TOOL` attempt의 `ToolRunResult.tool_kind=RULE_BASED`이고 그 status가 `SUCCEEDED | PARTIAL | SKIPPED`이면 `rule_execution_ref`와 같은 exact `RuleExecutionRecord`를 output으로 함께 확정한다. 두 결과의 attempt·도구·workspace·commit이 다르면 다음 단계에 전달하지 않는다.
- `STATIC_NORMALIZE`의 `SUCCEEDED | PARTIAL`과 해당 상태의 `output_refs`는 정확히 하나의 current `StaticFactBundle.record_id`를 같은 atomic transition으로 확정한다. `PARTIAL`이면 누락 범위를 설명하는 `gaps | errors`가 있어야 하며, COMMITTED marker 전에는 Hypothesis·Verification이 이 묶음을 읽지 않는다.
- `VERIFICATION`의 `SUCCEEDED`와 `HypothesisProcessState.status=TERMINAL`은 같은 final `VerificationResult.record_id`를 가리킨다.
- `PRIMITIVE_UPDATE`가 final TRUE를 처리하면 `PrimitiveAdmissionDecision`, 허용된 경우의 모든 `Primitive`, 새 `PrimitiveIndexState`를 같은 `COMMITTED` transition으로 확정한다. `decision=DENY`이면 result Primitive를 만들지 않으며, 이전 ALLOW revision으로 등록된 Primitive가 있으면 새 index revision에서 제거한다. final HOLD는 `required_primitive_candidates`가 하나 이상일 때만 admission decision 없이 HOLD Primitive와 index revision을 함께 확정한다. 후보가 비어 있으면 `PRIMITIVE_UPDATE`나 Chaining work를 만들지 않는다.
- retry 가능한 `VERIFICATION` work가 `BLOCKED`이면 가설은 `VERIFYING`을 유지하고 `verification_work_ref`가 그 work revision을 가리킨다. 재시도를 소진했거나 복구 불가능한 경우에는 같은 atomic transition에서 `VERIFICATION`의 `FAILED`와 `HypothesisProcessState.status=FAILED`를 확정한다. 이때 가설의 `verification_work_ref`는 실패한 exact work revision, `verification_result_ref=null`이어야 하며 final verdict나 Gate 입력을 만들지 않는다.
- `DYNAMIC_REPRO`의 종료 transition은 위 매핑을 만족해야 하며 `WorkExecutionState.output_refs`, `TransitionCommit.output_refs`와 `DynamicReproductionState.dynamic_result_ref`가 같은 `DynamicReproductionResult.record_id`를 가리킨다. Verification은 `COMMITTED` marker와 세 reference가 모두 맞을 때만 이 결과를 읽는다.
- `POLICY_FETCH`의 종료 transition은 parser를 실행했다면 모든 `PolicyParserResult`, 정확히 하나의 `PolicyCollectionResult`, 그리고 그 결과가 `FOUND`일 때만 exact `ProgramPolicyRecord`를 함께 가리킨다. `ABSENT_CONFIRMED | COLLECTION_FAILED`에서는 정책 record를 임의 생성하지 않는다.
- `TECHNICAL_GATE`의 `SUCCEEDED`는 정확히 하나의 `TechnicalEvidenceReview.record_id`를 가리킨다.
- `RULE_SCOPE_GATE`의 `SUCCEEDED`는 정확히 하나의 `RuleScopeImpactReview.record_id`를 가리킨다.
- `REPORT_DRAFT`의 `SUCCEEDED`와 `ReportProcessState.status=DRAFTED`는 같은 `ReportDraft.record_id`를 가리킨다.
- 분석 종료 transition과 `AnalysisRunState.analysis_result_ref`는 같은 `AnalysisRunResult`를 가리킨다.
- 각 reference의 workspace, commit, hypothesis, `record_id`와 `content_hash`는 실제 record와 일치한다.

Gate domain input set은 Gate가 판단 대상으로 읽는 저장 record의 정확한 revision 집합이다. `TECHNICAL_GATE`에서는 `VerificationResult`와 `CWELabel` reference가 정확한 domain input set이다. `RULE_SCOPE_GATE`에서는 `VerificationResult`, `TechnicalEvidenceReview`, `CWELabel`, 정확히 하나의 `PolicyCollectionResult`, 그리고 그 결과가 `FOUND`일 때만 exact `ProgramPolicyRecord` reference가 domain input set이다. prompt·provider·실행 설정 reference는 전체 `WorkExecutionState.input_refs`에 추가할 수 있지만 domain input으로 가장하거나 domain input을 대신할 수 없다.

Gate work를 등록할 때 runtime은 전체 `input_refs`를 정렬해 `input_hash`와 `dedupe_key`를 만들고 해당 `work_id`가 끝날 때까지 바꾸지 않는다. Gate 결과를 확정할 때는 다음을 같은 atomic transition에서 확인한다.

- `TechnicalEvidenceReview` 안의 `verification_result_ref`와 `cwe_label_ref`는 Technical Gate work의 domain input 두 개와 각각 exact match여야 한다.
- `RuleScopeImpactReview` 안의 `verification_result_ref`, `technical_review_ref`, `cwe_label_ref`, `policy_collection_result_ref`, `policy_record_ref`는 Rule Scope Gate work의 domain input set과 exact match여야 한다.
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
  requested_by: ORCHESTRATION | HYPOTHESIS | PRO | CON | VERIFICATION | CWE_LABELING | CHAINING | TECHNICAL_GATE | RULE_SCOPE_GATE | REPORTER | REPOSITORY_LOADER | STATIC_ANALYSIS | POLICY_COLLECTOR | PRIMITIVE_ADMISSION_RUNTIME | R7_AGENT | R7_SETUP_AUTOMATION | SANDBOX_CONTROLLER | REPRODUCTION_SESSION_MANAGER | RECOVERY
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
| `RUN_SANDBOX` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET | R7의 current work, exact `DynamicReproductionRequest`·current `EnvironmentRequirements`·current exact `ReproductionPlan`·`sandbox_profile_ref`·R8 resource/lifecycle profile을 고정해 외부 격리 경계 생성만 허가 |
| `SAVE_RESULT` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, REDACTION | 역할별 생산 권한, exact input과 same-attempt plan·recipe·환경·AgentLog·PoC 일치, atomic commit |
| `CALL_TECHNICAL_GATE` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, GATE_ORDER, REDACTION | validated PoC가 연결된 final TRUE Verification과 이를 직접 가리키는 current CWELabel의 COMMITTED exact pair 및 LLM call spec 필요 |
| `CALL_RULE_SCOPE_GATE` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, GATE_ORDER, REDACTION | `TRUE`+Technical `ACCEPT`, exact 정책 수집 결과와 `FOUND`일 때 current 정책 record, exact LLM call spec 필요 |
| `CREATE_REPORT_DRAFT` | SCHEMA, AUTHORITY, IDENTITY, REVISION, STATE, BUDGET, PROVIDER, SESSION, REPORT_READY, REDACTION | current Finding, PASS/PASS/PASS/SUFFICIENT/ALLOW와 exact LLM call spec 필요 |

Gate와 Reporter action의 기존 check는 다음 exact revision을 검사한다. 검사는 `ActionDecision`을 만들 때와 실제 provider 호출 직전에 같은 기준으로 다시 수행한다.

`REQUEST_DYNAMIC_REPRO`의 ALLOW는 R6 요청을 R7의 한 `DYNAMIC_REPRO` work로 등록할 수 있다는 뜻이다. Runtime Validator는 `(analysis_id, hypothesis_id, verification_generation, work_type=DYNAMIC_REPRO)` unique key를 강제하고 같은 generation에서 purpose가 다른 두 번째 request나 work를 거절한다. `RUN_SANDBOX`의 `ActionDecision=ALLOW`는 Docker 실행 성공이나 Sandbox 정책 통과를 뜻하지 않는다. Runtime Validator는 R7 Setup Automation 호출자의 권한, 현재 work·attempt와 예산, 변경되지 않은 exact `DynamicReproductionRequest`·current `EnvironmentRequirements`·current exact `ReproductionPlan`·`sandbox_profile_ref`·R8 resource/lifecycle profile을 검사하고 그 exact revision을 action input으로 고정한다. 이후 Sandbox Controller는 host·Docker daemon/socket·mount/namespace·secret·egress·다른 workspace 같은 외부 격리 경계만 검사해 exact 정책 판정을 저장한다. Controller는 Agent가 Sandbox 내부에서 고른 command·package·PoC를 allowlist로 검사하지 않는다. 정책 거절은 `policy_decision_ref`와 append-only `agent_log_ref`가 필수인 `DynamicReproductionResult(status=BLOCKED | FAILED, failure_category=POLICY_BLOCKED, agent_invoked=false, poc_ref=null)`로 기록한다. R7이 retry에서 새 requirements·plan·recipe·candidate revision을 만들더라도 R6 request의 목적·가설·profile을 바꾸거나 외부 경계 검사를 생략할 수 없다.

R5-01 `CWE_LABELING`의 `CALL_LLM`은 current `CWE_LABEL` work의 active attempt에서만 허용한다. action·`LLMCallSpec.context_refs`와 immutable prompt payload에는 current final TRUE `VerificationResult`, 그 result의 evidence closure와 사용할 taxonomy revision을 정확히 고정한다. 다른 Verification·generation·가설·commit의 label이나 evidence, 과거 CWE 출력은 current 분류 근거로 넣지 않는다. Runtime Validator는 호출 직전 이 exact 입력과 parent Verification work를 다시 확인하고, 바뀌면 decision을 `EXPIRED`로 만들어 새 work 또는 action을 요구한다.

- Technical Gate의 `REVISION`은 action `input_refs`와 call spec context가 final `VerificationResult(verdict=TRUE)`와 `CWELabel`의 정확한 `record_id`·`content_hash`를 가리키는지 검사한다. 이 TRUE의 `dynamic_request_ref`, `dynamic_result_ref`, `poc_ref`는 current Verification generation의 exact request, `SUCCEEDED + SUPPORTED` 결과와 validated PoC를 가리켜야 한다. Gate 출력의 `TechnicalEvidenceReview.verification_result_ref`와 `cwe_label_ref`도 바로 이 두 record를 가리켜야 한다. `GATE_ORDER`는 모든 결과가 현재 work에서 `COMMITTED`됐고 final인지 검사한다. validated PoC가 없는 TRUE, HOLD와 FALSE는 Technical Gate action을 만들 수 없다.
- Rule Scope Gate의 `REVISION`은 같은 Verification·current CWELabel revision, `RuleScopeImpactReview.technical_review_ref`가 가리킬 exact `TechnicalEvidenceReview`, Gate가 사용할 exact `PolicyCollectionResult`와 `FOUND`일 때 current `ProgramPolicyRecord`를 검사한다. `GATE_ORDER`는 Technical review가 그 두 revision을 검토한 `ACCEPT`이고 Verification verdict가 `TRUE`이며 정책 수집 결과가 `COLLECTION_FAILED`가 아닌지 검사한다.
- Reporter의 `REVISION`은 Reporter action, call spec과 context가 current Finding, 두 Gate가 실제로 검토한 같은 Verification·CWELabel revision, exact Technical·Rule Scope review와 존재하는 정책 revision을 가리키는지 검사한다. `REPORT_READY`는 Finding이 존재하고 그 exact 결과가 보고 조건을 모두 통과했는지 검사한다.

세 hypothesis-local stage action의 `requested_by`는 VERIFICATION이다. runtime은 action의 `meta.hypothesis_id`, 현재 `HypothesisProcessState.verification_assignment_ref`, 그 ACTIVE `VerificationAssignment.owner_identity_ref`와 `ActionRequest.requester_identity_ref`를 exact 비교한다. 배정되지 않은 Verification-role identity나 superseded assignment가 요청하면 `AUTHORITY_DENIED`다. `CALL_TECHNICAL_GATE`의 REVISE output은 같은 assignment owner에게만 전달한다. `CALL_RULE_SCOPE_GATE`와 `CREATE_REPORT_DRAFT`도 그 owner가 제안하되 Runtime Validator가 exact Gate 순서와 보고 조건을 다시 검사한다. CHAINING이나 ORCHESTRATION이 이 stage action을 요청하면 `AUTHORITY_DENIED`다.

provider 호출 직전 exact reference, current state 또는 final pointer가 달라지면 runtime은 해당 `ActionDecision`을 `UNUSED -> EXPIRED`로 바꾸고 호출하지 않는다. 수정된 upstream revision을 입력으로 새 `LLMCallSpec`, `ActionRequest`, `ActionDecision`을 만들어야 한다. 과거 action이나 decision을 새 revision에 재사용할 수 없다.

Technical Gate가 `REVISE`를 확정하면 그 Gate action과 decision은 이미 사용을 마친 것이다. 같은 Verification·CWELabel revision 또는 같은 domain input hash로 `REVISE`를 다시 투표하려는 action은 `ACTION_NOT_ALLOWED`로 거절한다. 새 Verification을 확정하고 R5-01이 그 result를 다시 평가한 새 CWELabel revision이 생긴 뒤에만 새 Gate work와 새 action을 허가한다. provider 오류나 `INVALID_OUTPUT`의 제한 retry는 같은 domain input을 사용할 수 있지만 새 `llm_call_id`·call spec·action·decision과 `trigger=RETRY`가 필요하며, 이는 `REVISE` 보완 재검토와 구분한다.

`requested_by`와 action의 허용 조합은 다음 표를 따른다.

| `action_type` | 허용 `requested_by` |
|---|---|
| `REGISTER_WORK` | ORCHESTRATION, VERIFICATION, PRIMITIVE_ADMISSION_RUNTIME, RECOVERY |
| `CHANGE_WORK_STATE` | ORCHESTRATION, VERIFICATION, PRIMITIVE_ADMISSION_RUNTIME, REPRODUCTION_SESSION_MANAGER, RECOVERY |
| `START_ATTEMPT` | ORCHESTRATION, VERIFICATION, PRIMITIVE_ADMISSION_RUNTIME, REPRODUCTION_SESSION_MANAGER, RECOVERY |
| `CANCEL_WORK` | ORCHESTRATION, VERIFICATION, PRIMITIVE_ADMISSION_RUNTIME, REPRODUCTION_SESSION_MANAGER, RECOVERY |
| `READ_CODE` | HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, TECHNICAL_GATE |
| `RUN_TOOL` | REPOSITORY_LOADER, STATIC_ANALYSIS, POLICY_COLLECTOR |
| `CALL_LLM` | HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, CHAINING, R7_AGENT |
| `FETCH_POLICY` | POLICY_COLLECTOR |
| `REQUEST_DYNAMIC_REPRO` | VERIFICATION |
| `RUN_SANDBOX` | R7_SETUP_AUTOMATION |
| `SAVE_RESULT` | ORCHESTRATION, HYPOTHESIS, PRO, CON, VERIFICATION, CWE_LABELING, CHAINING, TECHNICAL_GATE, RULE_SCOPE_GATE, REPORTER, REPOSITORY_LOADER, STATIC_ANALYSIS, POLICY_COLLECTOR, PRIMITIVE_ADMISSION_RUNTIME, R7_AGENT, R7_SETUP_AUTOMATION, SANDBOX_CONTROLLER, REPRODUCTION_SESSION_MANAGER, RECOVERY |
| `CALL_TECHNICAL_GATE` | VERIFICATION |
| `CALL_RULE_SCOPE_GATE` | VERIFICATION |
| `CREATE_REPORT_DRAFT` | VERIFICATION |

`REQUEST_DYNAMIC_REPRO`는 ACTIVE assignment의 R6 owner만 current Verification generation에서 요청한다. R7 component identity는 그 요청으로 등록된 exact `DYNAMIC_REPRO` work와 current attempt 안에서만 자기 역할의 action을 요청할 수 있다. R7 Agent는 requirements·plan·candidate·동적 해석, Setup Automation은 recipe·image·container·cleanup, Sandbox Controller는 외부 경계 정책 판정, Reproduction Session Manager는 상태·attempt·AgentLog·validated PoC·final dynamic result만 생산한다. 어느 구성요소도 가설 verdict·CWE·Gate 결과를 생산하지 않는다. R7이 request의 purpose·goal·가설·Sandbox profile을 바꾸거나 다른 generation의 request를 사용하면 `AUTHORITY_DENIED | STALE_RESULT`로 거절한다.

Orchestration은 전역 proposal 등록과 Verification 배정을 제안할 수 있지만 hypothesis-local 작업, Verification verdict, CWE, 두 Gate 결과, 정책 해석과 ReportDraft 내용을 생산하지 못한다. Verification은 hypothesis-local 작업을 제안하지만 실제 실행·저장 권한은 Runtime Validator를 통과해야 한다. 각 전문 결과는 위 표의 `SAVE_RESULT` 허용 역할 중에서도 해당 result kind를 소유한 역할만 저장한다. 예를 들어 `RuleExecutionRecord`는 STATIC_ANALYSIS, `VerificationResult`는 VERIFICATION, `CWELabel`은 R5-01 `CWE_LABELING`, `ChainingResult`는 CHAINING, `TechnicalEvidenceReview`는 TECHNICAL_GATE, `RuleScopeImpactReview`는 RULE_SCOPE_GATE, `PrimitiveAdmissionDecision`과 `Primitive`는 `PRIMITIVE_ADMISSION_RUNTIME`, `ReportDraft`는 REPORTER만 생산한다. `PRIMITIVE_ADMISSION_RUNTIME`은 LLM Agent가 아니라 exact Gate·정책 수집 상태를 아래 결정표에 대입하는 신뢰 runtime이며 정책 의미를 새로 해석하지 않는다. runtime validator는 값의 생산자·schema·선행 reference를 확인하지만 취약점 진위·CWE 적절성·정책 의미를 대신 판정하지 않는다.

`ActionCheck.check_type=BUDGET`은 versioned runtime policy의 시간·비용·호출·work·retry·repair·Gate 보완 한도만 검사한다. `LLMCallSpec.token_budget=null`, provider usage 미제공 또는 실제 token 사용량이 계획값을 넘었다는 이유만으로 check를 `FAIL`로 만들거나 `DENY`하지 않는다. 이 check의 실제 실패는 `AnalysisError(stage=ORCHESTRATION, code=BUDGET_EXCEEDED)`로 기록한다. 가설 verdict나 LLM `INVALID_OUTPUT`으로 바꾸지 않으며, 운영 Verification의 Pro/Con 중 하나라도 실행할 비-token 예산이 없으면 두 호출과 final result 저장을 시작하지 않는다.

`SAVE_RESULT`는 검사할 결과 후보를 action에 정확히 고정한다.

- `result_kind`와 `candidate_result_ref`는 `SAVE_RESULT`에서 필수이고 다른 action에서는 `null`이다. `candidate_result_ref.data_kind`는 `result_kind`와 같고 `candidate_result_ref.record_id`에는 저장 runtime이 미리 발급한 결과 revision ID가 있어야 한다.
- `candidate_result_ref.content_hash`는 미리 발급한 ID를 포함해 canonical serialization한 결과 후보 전체의 hash다. 후보 record는 read-only staging 영역에 두며 action decision이 생긴 뒤 수정하거나 같은 `stored_data_id`·`record_id`에 다른 bytes를 넣지 않는다. candidate ref도 action `input_refs`에 정확히 한 번 포함한다. staging record는 `TransitionCommit.state=COMMITTED` 전에는 일반 결과 조회나 다음 단계에서 보이지 않는다.
- `SCHEMA`는 result kind에 맞는 schema와 필수 필드를, `AUTHORITY`는 result kind의 등록된 생산 역할과 `requested_by`를 검사한다. `IDENTITY`·`REVISION`·`STATE`는 모든 candidate의 analysis, current `work_ref`·active attempt·input refs와 hash를 검사하고, `RecordMeta` candidate이면 workspace·commit·hypothesis·`meta.attempt_id`까지 정확히 일치하는지 검사한다.
- 핵심 registry 항목은 `static_fact_bundle -> StaticFactBundle -> STATIC_ANALYSIS`, `rule_execution_record -> RuleExecutionRecord -> STATIC_ANALYSIS`, `hypothesis_duplicate_review -> HypothesisDuplicateReview -> HYPOTHESIS`, `pro_evidence_result -> EvidenceAgentResult(role=PRO) -> PRO`, `con_evidence_result -> EvidenceAgentResult(role=CON) -> CON`, `verification_result -> VerificationResult -> VERIFICATION`, `primitive_admission_decision -> PrimitiveAdmissionDecision -> PRIMITIVE_ADMISSION_RUNTIME`, `primitive -> Primitive -> PRIMITIVE_ADMISSION_RUNTIME`, `chaining_result -> ChainingResult -> CHAINING`, `dynamic_reproduction_request -> DynamicReproductionRequest -> VERIFICATION`, `environment_requirements -> EnvironmentRequirements -> R7_AGENT`, `reproduction_plan -> ReproductionPlan -> R7_AGENT`, `environment_recipe -> EnvironmentRecipe -> R7_SETUP_AUTOMATION`, `sandbox_environment -> SandboxEnvironment -> R7_SETUP_AUTOMATION`, `cleanup_result -> CleanupResult -> R7_SETUP_AUTOMATION`, `sandbox_policy_decision -> SandboxPolicyDecision -> SANDBOX_CONTROLLER`, `poc_candidate -> PoCCandidate -> R7_AGENT`, `agent_log -> AgentLog -> REPRODUCTION_SESSION_MANAGER`, `poc_bundle -> PoCBundle -> REPRODUCTION_SESSION_MANAGER`, `dynamic_reproduction_result -> DynamicReproductionResult -> REPRODUCTION_SESSION_MANAGER`, `cwe_label -> CWELabel -> CWE_LABELING`, `policy_parser_result -> PolicyParserResult -> POLICY_COLLECTOR`, `policy_collection_result -> PolicyCollectionResult -> POLICY_COLLECTOR`, `program_policy_record -> ProgramPolicyRecord -> POLICY_COLLECTOR`, `technical_evidence_review -> TechnicalEvidenceReview -> TECHNICAL_GATE`, `rule_scope_impact_review -> RuleScopeImpactReview -> RULE_SCOPE_GATE`, `report_draft -> ReportDraft -> REPORTER`다. 앞 값은 `result_kind`·`data_kind`, 가운데 값은 검사할 schema, 뒤 값은 유일한 생산 역할이다. 다른 result kind도 versioned result-owner registry에 정확히 한 schema와 생산 역할을 등록해야 하며, broad requester 표만으로 저장 권한을 얻지 않는다.
- `PlaybookPolicy`는 Agent 결과가 아니라 사람이 승인한 운영 설정이며 trusted playbook registry runtime만 새 revision을 current로 만들 수 있다. `PlaybookApplication`도 Agent의 `SAVE_RESULT` 출력이 아니라 `REGISTER_WORK(work_type=VERIFICATION)` runtime이 work와 함께 만드는 고정 입력 record다. R6·Verification·Pro·Con이 두 record를 생성·수정하거나 current pointer를 바꾸려는 요청은 `AUTHORITY_DENIED`다.
- `result_kind=rule_execution_record`이면 STATIC_ANALYSIS만 저장할 수 있다. `SCHEMA`는 catalog와 `rules[].rule_id`의 set equality, 중복 rule ID, selection·execution·`hit_count`·`reason`·`detail` 조합을 검사한다. `REVISION | STATE`는 candidate의 `meta.attempt_id`, 도구·버전, workspace·commit, `analysis_config_ref`·`rule_catalog_ref`가 current `STATIC_TOOL` attempt와 exact match하는지 확인한다. 같은 attempt의 `ToolRunResult`를 확정할 때는 `tool_kind=RULE_BASED`이고 `rule_execution_ref`가 이 record를 가리키는지 다시 검사한다. `StaticFactBundle`을 확정할 때 각 `CodeFact.producer.attempt_id`와 규칙 기반 `producer.rule_id`가 연결된 current `ToolRunResult`·`RuleExecutionItem`과 일치하는지도 검사한다. 실패·누락·확인 불가를 `EXECUTED + hit_count=0`으로 바꾼 candidate는 저장하지 않는다.
- `result_kind=static_fact_bundle`이면 STATIC_ANALYSIS만 저장할 수 있다. `SCHEMA`는 여섯 `CodeFact` 목록의 필수 존재, fact 종류와 목록의 정확한 대응, 전체 합집합에서 `fact_id` 중복이 없는지 검사한다. 빈 후보 목록은 허용하지만 `tool_runs`, `gaps`, `errors`를 보지 않고 안전함이나 검사 완료로 바꾸지 않는다. `IDENTITY | REVISION | STATE`는 bundle과 모든 사실의 analysis·workspace·commit, `producer.attempt_id`, 도구·규칙·원본 결과가 current `STATIC_TOOL` 결과와 exact match하는지 확인한다. 다른 attempt의 사실, 목록과 `fact_kind`가 다른 사실, 같은 ID를 둘 이상의 목록에 넣은 사실은 저장하지 않는다.
- `result_kind=hypothesis_duplicate_review`이면 HYPOTHESIS만 저장할 수 있다. `SCHEMA`는 `UNIQUE | UNCERTAIN`에서 `duplicate_of_hypothesis_ref=null`, `DUPLICATE`에서 non-null인지 검사한다. `REVISION | STATE`는 proposal이 schema·semantic validation을 통과했는지, candidate 목록이 runtime이 같은 analysis·workspace·commit에서 좁힌 current 가설 exact reference 집합과 set-equal한지, `llm_call_id`가 이 입력을 사용한 성공 호출인지 확인한다. `DUPLICATE` 대상이 후보 목록에 없으면 review를 중복 종결 근거로 쓰지 않고 `INVALID_DUPLICATE_TARGET` fail-open 등록으로 전환한다.
- `result_kind=pro_evidence_result | con_evidence_result`이면 candidate의 role, `evidence_work_id`, `meta.attempt_id`, `llm_call_id`, `parent_work_id`, `verification_generation`, `debate_input_hash`가 current child work·성공 attempt·호출·부모 Verification과 정확히 일치해야 한다. 두 child work와 LLM call은 부모 Verification에 고정된 exact `PlaybookPolicy`·`VerificationPlaybook`·`PlaybookApplication` reference를 모두 입력으로 사용해야 한다. 다른 application, 다른 역할의 claim이나 상대 역할 record가 입력 경로에 있으면 `STALE_RESULT`, `AUTHORITY_DENIED` 또는 `CROSS_ROLE_INPUT_DENIED` 중 실제 원인으로 저장하지 않는다.
- `result_kind=verification_result`이면 `SCHEMA | REVISION | STATE`는 가설의 모든 `ValidationCheck.validation_id`와 candidate의 `ValidationCheckResult.validation_id`가 중복 없이 set-equal인지, 모든 `ValidationCheckResult.completion=COMPLETE`인지, 각 결과의 `evidence_refs`가 하나 이상인지 확인한다. `INCOMPLETE` 항목이 하나라도 있으면 final candidate를 `COMMITTED`하지 않는다. `falsification_results[].question_id`는 exact 가설 질문과 current `PlaybookApplication` 질문 ID의 합집합과 중복 없이 set-equal하고 각각 정확히 한 번 처리되어야 하며 사용한 근거는 현재 `workspace_id + commit_id`의 저장 record여야 한다. 운영 분석은 독립 Pro/Con work가 모두 정상 종료되어 exact output이 action `input_refs`에 있어야 한다. 일부 Context 조회 오류가 있어도 제한 retry·대체 조회·다른 정상 근거로 이 조건을 완료했다면 final candidate를 검사할 수 있지만, 필수 Context 또는 운영 Pro/Con을 확보하지 못했다면 final candidate를 `COMMITTED`하지 않는다. 이 경우 retry 가능 work는 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지한다. 더 시도할 수 없으면 같은 atomic transition에서 work와 `HypothesisProcessState`를 `FAILED`로 끝내며 runtime이 `HOLD`를 대신 만들지 않는다. Runtime Validator는 구조·reference·완료 상태만 검사한다. final `TRUE` 근거의 의미적 충분성과 코드·실행 근거 연결은 Technical Evidence Gate가 exact final TRUE revision을 대상으로 별도로 검토한다. `FALSE | HOLD`는 Technical Gate 입력이 아니며, 구조 검사를 통과했다는 사실이 Gate 승인을 의미하지 않는다.
- `VerificationResult.verdict=TRUE`이면 현재 가설의 핵심 공격 경로와 필요한 조건을 연결하는 하나 이상의 `supporting_evidence`가 필수다. 각 claim은 실제 저장 근거와 같은 `workspace_id + commit_id`의 코드 위치를 가져야 하며 오류·gap record를 근거로 사용할 수 없다. 또한 current Verification generation의 exact `DynamicReproductionRequest`, `DynamicReproductionResult(status=SUCCEEDED, hypothesis_outcome=SUPPORTED)`와 validated `poc_ref`가 모두 필수이고 candidate와 final result의 세 reference가 exact match여야 한다. 이 조건을 충족하지 않은 TRUE candidate는 저장하지 않는다.
- `VerificationResult.verdict=FALSE`이면 `falsification_results`에 실제 `question_id`, `outcome=DISPROVED`, 하나 이상의 `evidence_refs`가 있는 항목이 필수이고 `verdict_rationale`이 그 질문과 근거를 연결해야 한다. 오류·timeout·빈 출력만 있는 후보는 `SCHEMA` check를 `FAIL`로 만들어 저장하지 않으며 runtime이 다른 verdict를 만들어 주지 않는다.
- `VerificationResult.verdict=HOLD`이면 비어 있지 않은 `unresolved_conditions`와, 정상적으로 확인한 범위 및 결론을 막는 중요한 조건을 설명하는 `supporting_evidence[].evidence_refs | counter_evidence[].evidence_refs | falsification_results[].evidence_refs` 중 하나 이상의 실제 reference가 필요하다. `AnalysisError`, `DataGap`, timeout·권한 오류 또는 빈 Context만으로 만든 HOLD 후보는 `SCHEMA` check를 `FAIL`로 만들며 runtime이 다른 verdict를 만들어 주지 않는다.
- `TRUE | HOLD`에는 `outcome=DISPROVED`인 `FalsificationResult`가 있을 수 없다.
- candidate의 `playbook_ref`와 `playbook_application_ref`는 `SAVE_RESULT.input_refs`와 부모 `WorkExecutionState.input_refs`에 포함된 exact `VerificationPlaybook`·`PlaybookApplication` revision과 일치해야 한다. application이 같은 hypothesis·proposal·policy·playbook·work·generation을 가리키지 않거나 final Verification 합성 호출이 다른 application을 사용했으면 저장을 거절한다.
- `result_kind=dynamic_reproduction_request`이면 VERIFICATION만 저장할 수 있다. `POC_CONFIRMATION`은 `initial_verdict=TRUE`, `VERDICT_EVIDENCE`는 `initial_verdict=HOLD`만 허용한다. production에서는 same-generation ACTIVE assignment, exact hypothesis, 비어 있지 않은 goal·environment needs·code/static refs와 exact Pro·Con refs가 필수다. Runtime Validator는 한 Verification generation에는 `DYNAMIC_REPRO` work를 최대 하나만 허용하고 두 purpose를 동시에 또는 순차 등록하려는 요청을 `ACTION_NOT_ALLOWED`로 거절한다.
- `result_kind=cwe_label`이면 R5-01 `CWE_LABELING`만 저장할 수 있다. candidate의 `verification_result_ref`는 current `HypothesisProcessState.verification_result_ref`와 같고 `verdict=TRUE`인 final COMMITTED result여야 한다. `verification_generation`은 current process state와 부모 `VERIFICATION` work의 generation, `cwe_labeling_work_id`와 `meta.attempt_id`는 current `CWE_LABEL` work와 성공 attempt, `llm_call_id`는 exact Verification을 context로 사용해 candidate를 만든 성공한 `CWE_LABELING` 호출과 일치해야 한다. `evidence_refs`는 그 Verification의 direct·transitive evidence closure 안의 exact current reference만 허용한다. `(analysis_id, hypothesis_id, verification_generation, verification_result_ref.record_id, work_type=CWE_LABEL)`당 work와 COMMITTED output은 하나뿐이며 work `output_refs`가 이 label 한 개를 가리켜야 한다. `FALSE | HOLD`, 실패한 CWE work, 다른 generation·Verification·가설·commit의 label과 오래된 label 재사용은 거절한다.
- `result_kind=policy_parser_result | policy_collection_result | program_policy_record`이면 POLICY_COLLECTOR만 저장할 수 있다. parser 결과는 실행한 exact parser 이름·버전과 원문 `source_ref`를 보존한다. `FOUND`이면 `policy_record_ref`가 필수이고 `error_ids=[]`다. `ABSENT_CONFIRMED`이면 `policy_record_ref=null`, 하나 이상의 공식 출처와 `gap_ids`가 필요하고 `error_ids=[]`다. `COLLECTION_FAILED`이면 `policy_record_ref=null`과 하나 이상의 `error_ids`가 필요하며 Rule Scope Gate work와 review를 만들지 않는다. `FOUND`의 정책 record는 collection result가 가리키는 parser·공식 출처와 exact match해야 하며, 수집 실패를 공식 정책 부재로 바꾸지 않는다.
- `result_kind=rule_scope_impact_review`이면 RULE_SCOPE_GATE만 저장할 수 있다. `policy_collection_result_ref`는 Gate가 사용한 exact `PolicyCollectionResult`를 가리킨다. `FOUND`이면 `policy_record_ref`가 그 수집 결과의 exact 정책 record여야 하고, `ABSENT_CONFIRMED`이면 `policy_record_ref=null`, Rule·Scope·review·testing restriction은 `UNCERTAIN`, permission은 `DENY`여야 한다. `COLLECTION_FAILED`에는 review candidate 자체를 저장하지 않는다. `rule_compliance`와 `testing_restriction_compliance`는 독립된 판정 축이다. 후자가 `PASS | FAIL`이면 같은 area의 `RuleScopeEvidenceLink`가 하나 이상 필요하고, `UNCERTAIN`이면 `area=TESTING_RESTRICTION`인 `PolicyMissingInfo`가 필요하다. link의 존재만으로 PASS나 FAIL을 추정하지 않는다. 다른 판단 영역도 `PASS | FAIL | SUFFICIENT | INSUFFICIENT`이면 같은 area의 link가 필요하다. link의 policy item은 exact 정책 record 안에 존재하고 evidence reference는 실제 판단 근거여야 한다. `UNCERTAIN` 영역에는 대응하는 `PolicyMissingInfo`가 필요하고, `blocks_allow=true`인 `PolicyMissingInfo`가 하나라도 있으면 `report_permission=ALLOW`를 저장하지 않는다. Runtime Validator는 ID·reference·status 조합을 검사하고 정책 해석의 타당성은 Rule Scope Impact Gate가 판단한다.
- `result_kind=report_draft`이면 REPORTER만 저장할 수 있고 candidate의 `action_decision_ref`는 같은 초안을 허용한 exact `CREATE_REPORT_DRAFT` decision을 가리켜야 한다. `finding_ref`, Verification·CWELabel·두 Gate·정책, 존재하는 동적 결과·PoC reference는 action `input_refs`와 current upstream record에 정확히 일치해야 한다. `restrictions`와 `unresolved_conditions`는 Verification의 값을 빠짐없이 보존하고 `limitations`는 연결된 동적 결과와 Gate가 남긴 제한을 빠뜨리지 않는다. `redaction_status=PASSED`와 action의 `REDACTION=PASS`가 모두 확인되지 않으면 저장을 거절한다.
- `result_kind=primitive_admission_decision`이면 `PRIMITIVE_ADMISSION_RUNTIME`만 저장할 수 있다. exact final TRUE, 이를 검토한 Technical `ACCEPT`, exact `PolicyCollectionResult`와 존재하는 current `RuleScopeImpactReview`를 입력으로 사용한다. `FOUND | ABSENT_CONFIRMED`이면 current Rule Scope review가 필수이고 decision의 testing restriction 값은 review와 같아야 한다. `COLLECTION_FAILED`이면 review가 없어야 하며 아래 결정표의 `NOT_EVALUATED + ALLOW`만 허용한다. Runtime은 이 구조화된 값을 매핑할 뿐 정책 원문을 재해석하지 않는다.
- `result_kind=primitive`이면 `PRIMITIVE_ADMISSION_RUNTIME`만 저장할 수 있고 `SCHEMA`와 `REVISION`은 `result` 유무에 따른 admission을 검사한다. `result=null`은 `required_primitive_candidates`가 하나 이상인 exact final HOLD만 허용하며 `inputs`는 그 Verification의 후보 전체와 같아야 한다. 빈 후보인 HOLD의 Primitive 저장은 거절한다. `restrictions`는 Verification restrictions와 같고 `technical_review_ref=null`, `admission_decision_ref=null`이다. `result`가 있으면 current generation의 validated PoC를 가진 exact final TRUE와 그 Verification을 직접 가리키는 current CWELabel을 검토한 Technical `ACCEPT`가 필수다. `result`가 있는 Primitive의 `admission_decision_ref`는 같은 Verification의 current `PrimitiveAdmissionDecision(decision=ALLOW)`을 exact하게 가리켜야 한다. 제공 능력 하나마다 Primitive 하나를 만들고 각 Primitive의 `inputs`는 같은 TRUE의 `required_primitive_candidates`, `result`는 `provided_primitive_candidates` 한 항목, `restrictions`는 Verification 값과 exact match한다. FALSE, Gate 전 TRUE, Technical `REVISE | REJECT`와 admission `DENY` 기반 Primitive는 저장하지 않는다.
- `result_kind=chaining_result`이면 `considered_primitive_refs`는 Runtime이 `REGISTER_WORK(work_type=CHAINING)`에서 고정한 exact Primitive 입력 집합과 set-equal하다. `SAVE_RESULT.input_refs`에도 current work·candidate와 함께 그 Primitive, work가 고정한 `PrimitiveIndexState`, 실제 match 입력에서 직접·재귀적으로 도달하는 current `PrimitiveAdmissionDecision(decision=ALLOW)` exact reference가 모두 있어야 한다. `source_admission_refs`는 이 실제 사용 decision 집합과 중복 없이 set-equal해야 한다. work 시작 뒤 생긴 새 Primitive나 다른 work가 고정한 reference를 결과에 추가하면 `STALE_RESULT`로 거절한다. 일반 index 갱신이나 실제 match에 사용하지 않은 후보의 decision 변경만으로는 기존 work를 거절하지 않지만, `source_admission_refs` 중 하나가 current가 아니거나 `DENY`로 바뀌면 오염된 재료의 사용을 막기 위해 진행 중인 결과를 거절한다.
- `input_primitive_refs`는 `primitive_match_candidates`의 upstream/downstream exact reference 합집합과 set-equal하다. 이 집합은 `considered_primitive_refs`의 부분집합이어야 한다. 각 upstream Primitive는 final TRUE + Technical `ACCEPT` 기반의 non-null `result`, downstream은 하나 이상의 `inputs`를 가져야 한다. `matched_input_id`는 downstream `inputs[].draft_id` 하나를 정확히 선택하고 upstream result가 그 input을 충족한다는 entity·privilege·순서·restriction 코드 근거가 `evidence_refs`에 있어야 한다. downstream `result=null`이면 TRUE_HOLD, non-null이면 TRUE_TRUE로 유도한다.
- `considered_primitive_refs`, `input_primitive_refs`, `source_result_refs`, `source_admission_refs`와 candidate별 `parent_hypothesis_ids`, `parent_verification_refs`는 각각 중복이 없어야 한다. `source_result_refs`는 `input_primitive_refs`가 가리키는 Primitive들의 `source_verification_ref`와 non-null `technical_review_ref` 합집합과 set-equal하고 모두 같은 `SAVE_RESULT.input_refs`에 포함되어야 한다. `source_admission_refs`는 실제 입력 Primitive와 그 `source_primitive_match_id` 계보에서 재귀적으로 도달한 모든 result Primitive의 current ALLOW admission decision 합집합과 set-equal하고 같은 action input에 포함되어야 한다. 각 candidate의 `parent_hypothesis_ids`는 그 upstream/downstream Primitive의 `source_hypothesis_id` 합집합, `parent_verification_refs`는 두 Primitive의 `source_verification_ref` 합집합과 각각 set-equal해야 한다. 누락·추가·다른 work의 부모 reference는 저장하지 않는다.
- `excluded_primitive_ref`는 `considered_primitive_refs`에 포함되고 `input_primitive_refs`와 모든 match candidate reference에는 포함되지 않아야 한다. `excluded_by_ref`는 `considered_primitive_refs`와 `input_primitive_refs`에 모두 포함되고 같은 결과의 `excluded_primitive_ref` 집합에는 포함되지 않아야 한다. 즉 제외 근거는 실제로 match가 성립한 후보만 될 수 있고, 한 결과 안에서 같은 Primitive가 제외 대상이면서 제외 근거일 수 없다. 두 reference는 같은 analysis·workspace·commit의 exact Primitive여야 하고 `(excluded_primitive_ref, excluded_by_ref, reason_code)` 조합은 중복될 수 없다. `reason_code`는 `ANCESTOR_REUSE`만 허용한다.
- Runtime은 §06의 제외 규칙(성립한 match의 후보에서 양방향 재귀 탐색)으로 기대 제외 쌍을 다시 계산하고 `excluded_lineage_refs`와 set-equal한지 검사한다. match가 성립하지 않은 후보를 근거로 삼았거나, `excluded_by_ref`의 계보가 `excluded_primitive_ref`에 실제로 도달하지 않거나, 실제 제외를 빠뜨리거나 추가한 결과는 저장하지 않는다. 따라서 검토 대상이 아니었던 Primitive, 예산·오류로 확인하지 못한 Primitive와 계보 때문에 제외한 Primitive를 같은 것으로 취급하지 않는다.
- 각 `chained_hypothesis_proposals`는 COMMITTED match의 exact `source_primitive_match_id`와 부모 가설을 보존한다. `origin=CHAINING`이면 `observed_facts=[]`만 허용한다. `target_entities`·`target_locations`·`suspected_path`는 비어 있을 수 있지만, 값을 넣으면 부모 Primitive의 `result.entity_refs`와 `inputs[].entity_refs`에서 exact하게 얻을 수 있는 범위를 벗어날 수 없다. 부모 reference가 무효하거나 Verification이 사용할 entity·location 시작점을 하나도 복원할 수 없으면 가설 등록과 Verification 배정을 거절한다. proposal restrictions는 두 부모 Primitive의 `Restriction` 객체 합집합과 exact match하고, 같은 `restriction_id`의 canonical content가 다르면 저장하지 않는다. 남은 `PrimitiveDraft`마다 `description`과 같은 assumption을 정확히 하나 보존하고, 결합 지점을 겨냥한 반증 질문이 하나 이상 있는지(목록이 비어 있지 않은지만) 확인한다 — 그 질문이 실제로 결합 지점을 겨냥했는지는 Technical Evidence Gate의 의미적 충분성 검토 몫이다.
- 다음 중 하나라도 해당하면 저장을 거절한다: 같은 fingerprint 중복, 조상 링크를 따라 이미 사용한 Primitive의 재사용, 일반 research·동적 재현·Gate 보완 출력, CHAINING이 아닌 proposal origin.
- 저장 runtime은 claim한 action의 candidate bytes와 hash를 다시 확인한다. 확정된 result ref는 candidate와 `stored_data_id`·`data_kind`·`content_hash`·`record_id`가 모두 같아야 한다. 결과 ref, 종료 `StateTransition`과 `TransitionCommit`은 같은 output을 가리켜야 하며 `TransitionCommit.state=COMMITTED`가 된 뒤에만 소비할 수 있다. 후속 `ActionDecision.outcome_refs`에는 그 exact result ref와 COMMITTED commit ref를 각각 한 번 넣는다.
- `result_kind=environment_requirements | reproduction_plan | poc_candidate`이면 R7_AGENT만 저장할 수 있다. requirements는 R6 request의 모든 `environment_needs`를 빠뜨리거나 약화하지 않고, plan의 request·purpose·hypothesis·profile은 request와 exact match하며 current requirements를 가리킨다. plan에는 mode·exact command·step·payload·cleanup allowlist를 넣지 않는다. candidate를 처음 저장할 때는 current request·plan·attempt와 content digest만 검사하며 아직 뒤따를 AgentLog event를 요구하지 않는다. 대신 candidate 존재만으로 실행이나 성공을 인정하지 않고, `DynamicReproductionResult`와 validated PoC를 저장할 때 same-attempt `AgentLog`의 작성·실행 event가 exact candidate revision·digest를 가리키는지 검사한다.
- `result_kind=environment_recipe | sandbox_environment | cleanup_result`이면 R7_SETUP_AUTOMATION만 저장할 수 있다. recipe는 저장소 선언 의존성 source, 서로 구분된 base/built digest, build/reuse 결정을 기록한다. environment는 same-attempt request·plan·recipe·requirements와 container instance·생성/재사용 사유를 가리킨다. cleanup은 실제 생성 자원과 환경을 빠짐없이 가리킨다. 다른 가설의 writable container 공유와 근거 없는 reuse는 거절한다.
- `result_kind=agent_log | poc_bundle | dynamic_reproduction_result`이면 REPRODUCTION_SESSION_MANAGER만 저장할 수 있다. `AgentLog` revision은 event를 삭제·수정·재정렬하지 않고 append만 허용하며 전역 고유 `event_id`, attempt별 증가 `sequence`, start/end의 동일 `action_id`를 검사한다. `DynamicReproductionResult`의 input에는 exact request, RUN_SANDBOX decision, 존재하는 plan·recipe·정책·환경·candidate·PoC·cleanup과 필수 `AgentLog`를 넣는다. `agent_invoked`는 log의 `AGENT_STARTED` 존재와 같아야 한다. plan issue는 결과 안에만 저장하며 `OPEN` issue가 있으면 `SUPPORTED`와 validated PoC를 금지한다. `poc_ref`는 `SUCCEEDED + SUPPORTED`이고 same-attempt log가 exact candidate revision·digest를 실제 실행했으며 `PoCBundle`의 request·plan·recipe·environment·log·candidate·action이 모두 exact match할 때만 허용한다. 나머지 상태와 `DISPROVED | INCONCLUSIVE`에서는 `poc_ref=null`이다.
- check 뒤 candidate bytes·hash, active attempt, work input 또는 state version이 달라지면 decision을 `EXPIRED`로 만들거나 save를 `DENY`하고 `STALE_RESULT | RECORD_REVISION_MISMATCH | STATE_VERSION_CONFLICT` 중 실제 원인을 기록한다. 변한 후보를 저장하거나 이미 `USED`인 action으로 다시 저장하지 않는다.
Runtime Validator는 구조·reference·완료 상태만 검사한다. final `TRUE` 근거의 의미적 충분성과 코드·실행 근거 연결은 Technical Evidence Gate가 exact final TRUE revision을 대상으로 별도로 검토한다. `FALSE | HOLD`는 Technical Gate 입력이 아니며, 구조 검사를 통과했다는 사실이 Gate 승인을 의미하지 않는다.

action type에서 쓰지 않는 선택 field는 `null` 또는 빈 배열이어야 하고 `reason`은 비어 있지 않아야 한다. `READ_CODE`는 하나 이상의 `file_paths`, `RUN_TOOL`은 `tool_name`과 필요한 file path가 필수다. 실제 LLM을 실행하는 `CALL_LLM | CALL_TECHNICAL_GATE | CALL_RULE_SCOPE_GATE | CREATE_REPORT_DRAFT`는 exact `llm_call_spec_ref`, `provider_profile_ref`, `session_mode`와 work state가 필요하며 action의 provider·session 값은 spec과 같아야 한다. R7 Agent의 `CALL_LLM`은 current `DYNAMIC_REPRO` work에서 requirements·plan·PoC candidate와 동적 근거 해석을 만드는 목적만 허용한다. `SAVE_RESULT`만 `result_kind`와 `candidate_result_ref`를 사용한다. Gate와 Reporter는 별도 `CALL_LLM`을 우회 호출하지 않고 각 stage action이 LLM 호출까지 직접 허가한다. `REQUEST_DYNAMIC_REPRO`와 `RUN_SANDBOX`는 같은 exact `dynamic_request_ref`를 사용한다. `ActionRequest.reproduction_plan_ref`는 current `DYNAMIC_REPRO` work·attempt의 current exact `ReproductionPlan`을 가리켜야 한다. `RUN_SANDBOX` action `input_refs`에는 exact `DynamicReproductionRequest`·current `EnvironmentRequirements`·current exact `ReproductionPlan`·`sandbox_profile_ref`·R8 resource/lifecycle profile을 중복 없이 포함한다. Runtime Validator의 `SCHEMA`·`REVISION`은 이 reference와 역할·상태·예산만 확인한다. Sandbox Controller는 host·Docker daemon/socket·mount/namespace·secret·egress·workspace 경계를 검사하고 빈 `network_targets`를 default-deny로 해석한다. `EnvironmentRequirements`와 `ReproductionPlan`은 외부 경계 검사 전에 생성하고, PoC candidate와 command만 경계 승인 후 Sandbox 내부에서 생성한다. 경계 전에 만든 plan은 command allowlist가 아니라 실행 provenance로 사용한다.

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

CodeFactRef:
  bundle_ref: StoredDataRef
  fact_id: string

Restriction:
  restriction_id: string
  statement: string
  fact_refs: [CodeFactRef]
  evidence_refs: [StoredDataRef]

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
  max_requests_per_hypothesis: integer
  timeout_ms: integer
```

`ContextRetrievalLimits`는 depth·fragment·byte·request·timeout만 제한한다. 반환 코드의 token 추정치는 `CodeContextResponse.consumed_token_estimate`로 관측할 수 있지만 조회 허용·차단이나 `BUDGET_EXCEEDED`의 근거로 사용하지 않는다. 기존 `token_budget` 필드를 제거한 `CodeContextRequest`는 새 MAJOR schema로 배포하며 이전 record에 값을 추정해 이식하지 않는다.

`file_path`는 `workspace_root` 기준의 정규화된 Git 상대 경로다. 구분자는 운영체제와 관계없이 `/`를 사용하고 빈 경로, 절대 경로, drive prefix, `.`·`..` segment를 허용하지 않는다. Git에 저장된 경로의 대소문자를 그대로 보존하며 symlink를 해석한 실제 읽기 대상은 `workspace_root` 안에 있어야 한다. 줄은 1부터 시작하고 `start_line`과 `end_line`은 범위에 포함된다. 열 정보가 있는 경우 두 열 모두 1부터 시작하고 Unicode code point 단위이며 `start_column`은 포함, `end_column`은 제외한다. 도구가 줄만 제공하면 두 column을 모두 `null`로 두고 임의의 열 정밀도를 만들지 않는다.

`symbol_kind`는 여러 언어에서 공통으로 쓸 수 있는 큰 범주다. `TYPE`에는 class·interface·enum·struct, `CALLABLE`에는 function·method·constructor·lambda, `DATA`에는 variable·field·property·parameter가 들어간다. 원래 parser나 SAST 도구가 사용한 세부 종류는 `native_kind`에 그대로 남긴다. `symbol_id`, `fact_id`, `relation_id`는 같은 `workspace_id + commit_id` 안에서 유일하다. `CodeFact`와 `CodeRelation`의 `producer.raw_result_ref`는 사실·관계를 만든 도구의 원본 결과를 가리켜야 한다.

`Restriction`은 공격을 제한하는 검사·경계를 자연어만으로 남기지 않고 exact 근거에 연결하는 공통 객체다. `fact_refs`와 `evidence_refs` 중 하나 이상은 비어 있지 않아야 한다. `CodeFactRef.bundle_ref`는 해당 사실을 포함한 final `StaticFactBundle`의 exact revision을 가리키고 `fact_id`는 그 bundle 안에 정확히 한 번 존재해야 한다. 모든 참조는 현재 record와 같은 analysis·workspace·commit이어야 한다. `restriction_id`는 같은 제한을 Verification·Primitive·Chaining·ReportDraft로 전달할 때 그대로 유지한다. statement 또는 근거 집합을 바꾸면 기존 객체를 덮어쓰지 않고 새 `restriction_id`를 만든다.

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

`sanitizer_candidates`, `validator_candidates`, `other_facts`를 필수 목록으로 추가하고 종류별 분할·전체 `fact_id` 유일성을 의무화하는 변경은 StaticFactBundle 새 MAJOR schema로 적용한다. 이전 MAJOR record에 누락 목록을 빈 배열로 추정하거나 `OTHER` 사실의 위치를 임의로 정하지 않는다. 이전 record는 감사 이력으로만 보존하며 새 Hypothesis·Verification 입력으로 자동 승격하지 않는다.

`Restriction` 객체 도입과 문자열 restriction 제거, `ProposalProcessState`의 duplicate lifecycle 확장, `HypothesisDuplicateReview` 추가는 기존 결과의 의미와 허용 조건을 바꾸므로 `HypothesisProposal`, `ProposalProcessState`, `VerificationResult`, `Primitive`, `ReportDraft`와 관련 Chaining 결과를 새 MAJOR schema로 배포한다. 이전 MAJOR의 문자열 restriction에 근거 reference를 추정해 붙이거나 confidence 값을 새 우선순위·판정 입력으로 변환하지 않는다. 이전 결과는 감사 이력으로만 보존한다.

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
  sanitizer_candidates: [CodeFact]
  validator_candidates: [CodeFact]
  auth_and_permission_checks: [CodeFact]
  other_facts: [CodeFact]
  call_edges: [CodeRelation]
  data_flow_candidates: [CodeRelation]
  route_bindings: [CodeRelation]
  tool_runs: [ToolRunResult]
  gaps: [DataGap]
  errors: [AnalysisError]
```

여섯 `CodeFact` 목록은 `fact_kind`별 분할(partition)이다. 대응은 `source_candidates -> SOURCE`, `sink_candidates -> SINK`, `sanitizer_candidates -> SANITIZER`, `validator_candidates -> VALIDATOR`, `auth_and_permission_checks -> AUTH_CHECK | PERMISSION_CHECK`, `other_facts -> OTHER`로 고정한다. 각 사실은 종류에 맞는 목록 하나에만 들어가며 여섯 목록의 합집합에서 `fact_id`는 정확히 한 번만 나타나야 한다. 같은 코드 위치가 둘 이상의 역할을 가지면 역할마다 별도 `CodeFact`와 서로 다른 `fact_id`를 만든다.

모든 목록은 필수이며 후보가 없으면 `[]`를 쓴다. 빈 배열은 후보가 없다는 현재 관찰일 뿐, 안전함이나 검증 완료를 증명하지 않는다. 소비자는 `tool_runs`, `gaps`, `errors`와 실제 규칙 실행 범위를 함께 읽어야 한다. `SANITIZER`와 `VALIDATOR`는 방어 로직 후보이며 안전함, 경로 차단 또는 `FALSE`의 자동 근거가 아니다. R6 Verification이 실제 경로에서의 도달 가능성, 적용 순서·조건과 우회 가능성을 확인한다.

모든 `CodeFact`는 bundle의 `analysis_id` 범위에만 속하고 `location.workspace_id | commit_id`가 bundle과 같아야 한다. `producer.attempt_id`는 current `ToolRunResult`를, 규칙 기반 사실의 `producer.rule_id`는 같은 attempt의 `RuleExecutionRecord.rules[]` 항목을 가리켜야 한다. `data_flow_candidates`는 기존 `CodeRelation`을 사용해 후보 사이의 관찰된 관계만 표현한다. 도구가 관계를 제공하지 않았으면 임의로 연결하지 않고 `DataGap` 또는 검증할 미해결 조건으로 남긴다.

`Static Fact Normalizer`는 result-owner registry의 `STATIC_ANALYSIS` 신뢰 identity로 실행되는 정규화 component이며 별도 권한 역할이 아니다. 따라서 R2 구현은 같은 identity로 `static_fact_bundle` 저장을 요청하고 Runtime Validator가 current `STATIC_NORMALIZE` work와 candidate를 결합해 검사한다.

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
  restrictions: [Restriction]
  falsification_questions: [FalsificationQuestion]
  validation_checks: [ValidationCheck]
  parent_hypothesis_ids: [string]
  source_primitive_match_id: string | null
```

초기 proposal은 `parent_hypothesis_ids: []`, `source_primitive_match_id: null`이다. Verification-origin proposal도 `source_primitive_match_id=null`이다. Chaining-origin proposal은 직접 부모를 `parent_hypothesis_ids`에 넣고 자신을 만든 COMMITTED match candidate의 ID를 `source_primitive_match_id`에 넣는다. schema validation과 semantic validation을 통과한 proposal만 stable `hypothesis_id`가 있는 `VulnerabilityHypothesis`로 등록한다.

`observed_facts`, `restrictions`, `assumptions`는 다음 기준으로 나눈다.

- `observed_facts`: final `StaticFactBundle`의 실제 `CodeFact`를 값 그대로 가져온 관측 결과다.
- `restrictions`: 관측된 것 중 공격을 제한하는 검사·경계와 그 exact 근거다. INITIAL proposal의 각 restriction은 final `StaticFactBundle`을 가리키는 `fact_refs`가 하나 이상 필요하다. VERIFICATION·CHAINING proposal은 부모에서 보존한 restriction 또는 검증 근거가 있는 새 restriction을 사용할 수 있다. 모든 origin에서 `observed_facts[].fact_id` 집합과 `restrictions[].fact_refs[].fact_id` 집합은 서로 겹치면 안 된다. 하나의 관측 사실은 공격을 뒷받침하는 사실이거나 제한 근거 중 한쪽으로만 분류한다.
- `assumptions`: 관측으로 확인하지 못했지만 가설이 성립하려면 참이어야 하는 명제다.

확인하지 못한 것 중 가설이 의존하지 않는 공백은 가설에 넣지 않는다. 가설이 확인해야 할 미확인 조건은 `assumptions`와 `falsification_questions`가 담는다. `StaticFactBundle.gaps`의 `DataGap`은 도구·조회가 실패해 데이터를 얻지 못한 범위이며 가설의 미확인 조건과 다른 것이다. 가설 하나가 결과나 필요 조건을 여러 개 가질 수 있으며 가설의 단위는 규칙으로 강제하지 않는다. 등록된 `VulnerabilityHypothesis`는 이 세 갈래를 자기 필드로 복사하지 않는다. 소비자는 `proposal_ref`가 가리키는 exact `HypothesisProposal` revision에서 읽는다. `origin=CHAINING`의 `observed_facts`·`target_entities`·`target_locations`·`suspected_path`는 모두 비어 있을 수 있다. 이 경계 안에는 `CodeFact`가 없고, entity 정보는 `source_primitive_match_id` 계보(`PrimitiveMatchCandidate` → 부모 `Primitive` → `entity_refs`)를 따라가면 얻을 수 있어 Chaining Agent가 다시 계산해 싣지 않는다. `suspected_path`는 부모 데이터에 관계(순서·연결) 정보 자체가 없어 계산해도 위치 집합일 뿐 실제 경로가 되지 않는다. 자식 Verification이 이 계보를 따라 직접 확보한다.

`vulnerability_type_candidates`는 비어 있을 수 있지만 비어 있지 않은 값과 중복 없는 문자열만 허용한다. 이 목록은 아직 확정 분류가 아니므로 여러 후보가 있으면 trusted runtime이 하나를 임의 선택하지 않는다. Verification playbook 선택은 등록 가설의 exact `proposal_ref`를 따라 이 목록을 읽고 §4의 `PlaybookPolicy` 규칙으로만 수행한다.

`origin=CHAINING` proposal은 Chaining 입력 경계에 `CodeFact`가 없으므로 `observed_facts=[]`만 허용한다. 부모에서 물려받은 restriction과 assumption은 위 필드에 보존하고, 코드 사실은 자식 Verification이 `source_primitive_match_id`를 따라 exact 부모 Primitive의 `result.entity_refs`와 `inputs[].entity_refs`에서 시작해 다시 조회한다. `target_entities`·`target_locations`·`suspected_path`는 비어 있을 수 있으며 채운 값은 이 계보에서 exact하게 복원되는 범위를 벗어나면 안 된다. 계보가 끊겼거나 Verification 시작점을 하나도 얻지 못하면 proposal을 등록하지 않는다.

```yaml
HypothesisDuplicateReview:
  meta: RecordMeta without hypothesis, with attempt
  proposal_ref: StoredDataRef
  candidate_hypothesis_refs: [StoredDataRef]
  decision: UNIQUE | DUPLICATE | UNCERTAIN
  duplicate_of_hypothesis_ref: StoredDataRef | null
  rationale: string
  llm_call_id: string
```

schema·semantic validation 뒤 trusted runtime은 같은 analysis·workspace·commit의 등록 가설만 비교 후보로 좁힌다. proposal의 `symbol_id`, `CodeLocation` 겹침과 `relation_id`는 후보 검색용이며 중복 결론 자체가 아니다. 후보가 없으면 LLM을 부르지 않고 `NO_CANDIDATES`로 등록한다. 후보가 있으면 HYPOTHESIS 역할의 `CALL_LLM` action에 exact `proposal_ref`와 모든 `candidate_hypothesis_refs`를 고정한다. `candidate_hypothesis_refs`는 runtime이 좁힌 후보 집합과 중복 없이 set-equal해야 하고 current exact `VulnerabilityHypothesis` revision만 가리킨다.

중복 검토는 별도 work type을 만들지 않고 현재 `HYPOTHESIS_PROPOSAL` work의 active attempt 안에서 실행한다. `HypothesisDuplicateReview.meta.attempt_id`는 그 attempt와 같고 후보 배열은 하나 이상이어야 한다. proposal·후보·모델·prompt·출력 schema를 고정한 `LLMCallSpec`과 성공한 invocation이 review의 `llm_call_id`에 연결되어야 한다.

LLM의 `DUPLICATE` 판정은 `duplicate_of_hypothesis_ref`가 후보 목록 안의 exact reference일 때만 유효하며 이 경우 새 가설을 등록하지 않는다. `UNIQUE | UNCERTAIN`은 `duplicate_of_hypothesis_ref=null`이어야 하고 새 가설로 등록한다. LLM 호출 실패·형식 오류·유효하지 않은 중복 대상은 가설을 버리는 근거가 아니다. 호출·오류 record는 보존하되 proposal은 각각 `CHECK_FAILED | INVALID_DUPLICATE_TARGET`으로 fail-open 등록한다. 이 정책은 탐지 누락을 막기 위한 것이며 중복이 늘어난 사실은 최종 결과 지표에 남긴다.

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

`origin=VERIFICATION`은 Verification이 새 endpoint·sink·권한 경계·공격 단계·독립 impact를 분리한 proposal이고, `origin=CHAINING`은 upstream Primitive의 `result`가 downstream Primitive의 특정 `input`을 충족한 match가 만든 proposal이다. INITIAL과 VERIFICATION은 `source_primitive_match_id=null`, CHAINING은 분석 전체에서 유일하고 COMMITTED `ChainingResult.primitive_match_candidates`에 정확히 한 번 존재하는 ID가 필수다. 그 match의 parent hypothesis set은 proposal과 등록 가설의 `parent_hypothesis_ids`와 같아야 한다. 계보 길이가 필요하면 이 직접 링크를 따라 계산하며 별도 depth 값을 저장하지 않는다. 부모와 자식의 lifecycle·verdict는 독립이며 child 결과로 parent verdict를 바꾸지 않는다. proposal 출력 검증 runtime은 각 반증 질문에 전역 `question_id`, 각 필수 검증 항목에 전역 `validation_id`를 부여하고 등록 가설까지 그대로 유지한다. `instruction`은 무엇을 확인해야 완료되는지 짧게 설명한다. 질문은 가설의 필수 조건 하나를 실제 근거로 반증할 수 있게 구체적으로 작성한다. 금지된 확정 assertion, 잘못된 enum, 필수 field/location·반증 질문·검증 항목 누락 또는 중복 ID는 제한된 repair retry 뒤 `INVALID_OUTPUT`이다. `origin=CHAINING`의 `observed_facts`·`target_entities`·`target_locations`·`suspected_path`는 이 필수 field 규칙에서 제외한다 — 이 경계에서 채울 수 없는 정보이며 자식 Verification이 `source_primitive_match_id` 계보를 따라 확보한다(§6 `chaining_result` 저장 검사와 동일). 이 계보를 복원할 수 없으면(§6) 등록 자체를 거절한다.

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
PlaybookQuestionTemplate:
  template_key: string
  question: string

VerificationPlaybook:
  meta: RecordMeta with hypothesis_id null and attempt_id null
  scope: COMMON | TYPE_SPECIFIC
  vulnerability_type: string | null
  prerequisites: [string]
  source_checks: [string]
  sink_checks: [string]
  path_checks: [string]
  defense_checks: [string]
  falsification_question_templates: [PlaybookQuestionTemplate]
  static_evidence_requirements: [string]
  dynamic_evidence_requirements: [string]
  restriction_checks: [string]
  hold_conditions: [string]

PlaybookPolicyItem:
  vulnerability_type: string
  playbook_ref: StoredDataRef

PlaybookPolicy:
  meta: RecordMeta with hypothesis_id null and attempt_id null
  common_playbook_ref: StoredDataRef
  type_playbooks: [PlaybookPolicyItem]
  approved_by: string
  approved_at: timestamp

AppliedPlaybookQuestion:
  template_key: string
  question_id: string
  question: string

PlaybookApplication:
  meta: RecordMeta with hypothesis_id set and attempt_id null
  verification_work_id: string
  verification_generation: integer
  hypothesis_ref: StoredDataRef
  proposal_ref: StoredDataRef
  policy_ref: StoredDataRef
  playbook_ref: StoredDataRef
  selection: COMMON | TYPE_SPECIFIC
  selected_type: string | null
  selection_reason: TYPE_MATCH | NO_TYPE | MULTIPLE_TYPES | TYPE_NOT_ALLOWED
  questions: [AppliedPlaybookQuestion]

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
  playbook_application_ref: StoredDataRef
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
  restrictions: [Restriction]
  bypass_candidates: [CandidateRef]
  required_primitive_candidates: [PrimitiveDraft]
  provided_primitive_candidates: [PrimitiveDraft]
  impact_escalation_candidates: [CandidateRef]
  material_child_proposals: [HypothesisProposal]
  unresolved_conditions: [string]
  metrics: VerificationMetrics
  errors: [AnalysisError]
```

`VerificationPlaybook.meta.logical_record_id`는 플레이북 식별자이고 `meta.revision_number`는 내용 revision이다. `schema_version`은 플레이북 데이터 구조의 버전이므로 내용 revision과 구분한다. 플레이북 내용이 변경되면 기존 record를 수정하지 않고 새 `record_id`, 증가한 `revision_number`와 새 `content_hash`를 만든다. `PlaybookQuestionTemplate.template_key`는 같은 플레이북 revision 안에서만 유일한 사람이 읽는 템플릿 이름이고 실제 `question_id`가 아니다. `template_key` 중복과 비어 있는 질문은 플레이북 등록 단계에서 거절한다.

`scope=COMMON`이면 `vulnerability_type=null`, `scope=TYPE_SPECIFIC`이면 `vulnerability_type`이 필수다. R6 검증·반박·플레이북 담당은 플레이북 내용을 제안하지만 등록만으로 운영 지원 유형을 바꾸지 못한다. 운영 지원 목록과 적용 mapping은 사람의 승인을 받은 `PlaybookPolicy` revision으로만 바뀌며 trusted playbook registry runtime이 immutable record로 저장한다. `common_playbook_ref`는 실제 `scope=COMMON` 플레이북을, 각 `type_playbooks[].playbook_ref`는 같은 항목의 `vulnerability_type`을 가진 `scope=TYPE_SPECIFIC` 플레이북을 가리켜야 한다. `type_playbooks`의 유형은 중복될 수 없고 모든 reference는 존재하는 exact `record_id + content_hash`여야 한다. 유효한 COMMON reference가 없거나 TYPE mapping이 중복·불일치하면 policy를 current로 만들지 않는다.

등록된 `VulnerabilityHypothesis`에는 단일 `vulnerability_type` 필드가 없다. 선택 runtime은 `VulnerabilityHypothesis.proposal_ref`가 가리키는 exact `HypothesisProposal.vulnerability_type_candidates`만 읽는다. 이 목록은 중복이 없어야 한다. 후보가 정확히 하나이고 current `PlaybookPolicy.type_playbooks`에 같은 문자열의 유효한 mapping이 하나 있으면 해당 `TYPE_SPECIFIC` revision과 `selection_reason=TYPE_MATCH`를 사용한다. 후보가 없으면 `NO_TYPE`, 둘 이상이면 `MULTIPLE_TYPES`, 하나지만 policy에 없으면 `TYPE_NOT_ALLOWED`로 current COMMON revision을 선택한다. Agent가 statement나 추정으로 유형을 하나 골라내거나 등록된 플레이북의 존재만으로 지원 목록을 넓힐 수 없다.

`PlaybookApplication`은 위 선택을 특정 Verification work에 고정한 runtime record다. `hypothesis_ref`는 current exact `VulnerabilityHypothesis`, `proposal_ref`는 그 가설의 exact `proposal_ref`, `policy_ref`와 `playbook_ref`는 선택에 사용한 exact revision이어야 한다. `selection=TYPE_SPECIFIC`이면 `selected_type`이 proposal의 유일 후보·policy mapping·playbook의 `vulnerability_type`과 모두 같고 이유는 `TYPE_MATCH`다. `selection=COMMON`이면 `selected_type=null`이고 이유와 후보 수·policy 상태가 위 fallback 규칙과 일치해야 한다. `verification_work_id`와 `verification_generation`은 application을 고정한 current `VERIFICATION` work와 같아야 한다.

trusted runtime은 선택된 플레이북의 모든 `falsification_question_templates`를 `PlaybookApplication.questions`에 순서와 내용 변경 없이 한 번씩 복사하고 각 항목에 새 전역 `question_id`를 발급한다. application의 `template_key` 집합은 플레이북 템플릿 집합과 set-equal해야 하며 질문 문장도 같은 key의 원문과 같아야 한다. `question_id`는 application 안에서 중복될 수 없고 기존 가설 질문이나 다른 application에서 재사용할 수 없다. 가설에 이미 등록된 질문은 application에 복사하지 않는다.

`VerificationResult.playbook_ref`는 실제 검증에 사용한 exact `VerificationPlaybook.record_id`와 `content_hash`, `playbook_application_ref`는 같은 work에 고정된 exact `PlaybookApplication`을 가리킨다. application의 `playbook_ref`는 결과의 `playbook_ref`와 같아야 한다. Verification Agent의 직접 검증, `PRO_EVIDENCE`, `CON_EVIDENCE`, final Verification 합성 호출 및 `SAVE_RESULT(result_kind=verification_result)`는 모두 해당 Verification work에 고정된 동일한 policy·playbook·application reference를 사용해야 한다. Runtime Validator는 각 action의 `input_refs`, 각 LLM 호출의 `LLMCallSpec.context_refs`, 최종 결과의 두 reference 및 `SAVE_RESULT.input_refs`가 `WorkExecutionState.input_refs`에 고정된 exact reference와 일치하는지 검사한다. 이후 policy나 플레이북에 새 revision이 생겨도 진행 중인 work와 과거 결과는 자신이 실제 사용한 application을 계속 가리킨다.

final `VerificationResult.falsification_results[].question_id` 집합은 exact `VulnerabilityHypothesis.falsification_questions[].question_id`와 exact `PlaybookApplication.questions[].question_id`의 중복 없는 합집합과 set-equal해야 한다. 각 ID는 정확히 한 번 평가되고 evidence와 rationale을 가져야 한다. application이 없거나 질문 binding이 빠짐·추가·변조됐거나 다른 work·generation의 application이면 결과를 저장하지 않는다.

`debate_input_hash`는 Pro와 Con이 함께 받은 공통 검증 입력을 canonical JSON으로 만든 SHA-256 값이다. 공통 입력에는 ACTIVE `VerificationAssignment`, exact 가설, 코드·Context·정적 근거 reference, 반증 질문, 검증 항목, exact `PlaybookPolicy`·`VerificationPlaybook`·`PlaybookApplication` revision, versioned Debate 설정과 예산 profile을 포함한다. 역할별 system instruction, 시각, worker 이름, `attempt_id`, `llm_call_id`와 session ID는 넣지 않는다. 따라서 두 역할의 prompt는 달라도 같은 사실·설정 묶음을 받았는지 비교할 수 있다.

`PlaybookQuestionTemplate`, `PlaybookPolicy`, `PlaybookApplication`과 `VerificationResult.playbook_application_ref`는 새 필수 계약이므로 새 MAJOR schema에서만 사용한다. 과거 플레이북 문자열이나 Verification 결과에 template key·policy·application·질문 ID를 추정해 채우지 않는다. 과거 record는 감사 이력으로만 보존하고 새 Verification work의 current 입력으로 자동 승격하지 않는다.

`EvidenceAgentResult`는 수정할 수 없는 역할별 결과 record다. `role=PRO`이면 `evidence`의 모든 `source_role`은 `PRO`, `role=CON`이면 모두 `CON`이어야 한다. 한 결과 안의 `claim_id`는 중복될 수 없고 `summary`는 비어 있을 수 없다. 찾은 근거가 없다면 빈 `evidence`와 그 사실·확인 범위를 설명하는 `summary`·`limitations`를 저장하며 근거를 만들어 내지 않는다. `parent_work_id`는 현재 generation의 부모 `VERIFICATION.work_id`, `evidence_work_id`는 결과를 확정한 역할별 자식 work ID, `verification_generation`은 부모가 속한 현재 가설 generation, `meta.attempt_id`는 그 자식의 성공 attempt ID와 같아야 한다. `llm_call_id`는 결과를 만든 성공 호출 하나와 같아야 한다. 자식 work의 일반 `input_hash`는 역할별 template까지 포함하므로 Pro와 Con이 다를 수 있지만, 두 결과의 `debate_input_hash`는 반드시 같다. 자식 work의 `output_refs`와 해당 `LLMInvocationResult.parsed_output_ref` 및 `LLMInvocationLog.parsed_output_ref`가 이 exact result revision을 단방향으로 가리킨다. 결과가 invocation record나 종료 work revision을 다시 가리키지 않으므로 content hash 순환을 만들지 않는다.

운영 `purpose=PRODUCTION`은 항상 `verification_mode=ALWAYS_DEBATE`이며 `debate_input_hash`, `pro_evidence_ref`, `con_evidence_ref`가 모두 필수다. 평가 실행에서 실제 Debate를 수행한 `ALWAYS_DEBATE` 또는 trigger가 발생한 `CONDITIONAL_DEBATE`도 세 필드가 모두 필수다. 평가용 `BASIC` 또는 trigger가 발생하지 않은 `CONDITIONAL_DEBATE`는 세 필드를 모두 `null`로 두고, 후자는 비어 있지 않은 `debate_skip_reason`을 남긴다. 필수 reference 하나라도 없으면 final 결과를 저장하지 않는다.

두 evidence reference는 각각 COMMITTED `EvidenceAgentResult(role=PRO)`와 `EvidenceAgentResult(role=CON)` exact revision을 가리켜야 한다. 두 결과는 같은 analysis·workspace·commit·hypothesis, 같은 부모 Verification `work_id`, 같은 `verification_generation`, 같은 `debate_input_hash`를 가져야 하며 서로 다른 `evidence_work_id`, `meta.attempt_id`, `llm_call_id`와 LLM log에 연결되어야 한다. final Verification 합성용 `LLMCallSpec.context_refs`와 `SAVE_RESULT.input_refs`에는 이 두 exact result reference를 각각 한 번 포함한다. final `supporting_evidence`와 `counter_evidence`는 이 두 결과와 Verification의 추가 근거를 출처별로 보존해 합성하며, 다른 generation·입력의 결과를 섞으면 `STALE_RESULT`, Pro/Con 입력에 상대 역할 결과가 섞이면 `CROSS_ROLE_INPUT_DENIED`로 거절한다.

`EvidenceAgentResult`는 새 record schema다. `WorkExecutionState.parent_work_ref`를 Pro/Con에 필수로 만드는 변경과 `VerificationResult`의 세 Debate 연결 필드는 기존 운영 결과의 허용 조건을 바꾸므로 각 record의 새 MAJOR schema로 배포한다. 이전 MAJOR record는 감사 기록으로 보존할 수 있지만 새 운영 Gate·Primitive·Reporter 입력으로 자동 승격하거나 새 필드를 추정해 채우지 않는다.

`EvidenceClaim.claim_id`는 한 `VerificationResult` 안에서 유일하다. 각 claim은 실제 저장 근거를 가리키는 `evidence_refs`를 하나 이상 가져야 하며, 코드 주장이라면 현재 `workspace_id + commit_id`의 `code_locations`도 하나 이상 가져야 한다. `source_role`은 claim을 작성한 역할이며 근거의 출처를 대신하지 않는다. supporting 목록에는 `VERIFICATION | PRO`, counter 목록에는 `VERIFICATION | CON`만 허용한다.

`VerificationResult.restrictions`는 proposal의 제한과 검증 중 실제 근거로 확인한 제한을 `Restriction` 객체로 저장한다. proposal에서 이어진 항목은 `restriction_id`와 전체 `Restriction` 객체를 그대로 보존한다. 새 제한은 현재 generation의 코드·정적·Pro/Con·동적 근거에 연결된 새 ID를 사용한다. 단순 문장만 있거나 exact 근거가 없는 제한은 final 결과에 넣지 않고 `unresolved_conditions` 또는 `limitations`로 남긴다.

`CandidateRef`는 아직 검증되지 않은 우회·대체 경로·영향 확대 후보다. `candidate_id`는 한 결과 안에서 유일하고 `candidate_state`는 항상 `UNVALIDATED`다. 현재 가설을 `source_hypothesis_ids`에 포함하며, 실제 근거가 있으면 `evidence_refs`, 아직 필요한 사실은 `missing_information`에 넣는다. 후보가 새로운 endpoint·sink·권한 경계·공격 단계 또는 영향을 주장하면 `material_child_proposals`에 `origin=VERIFICATION`인 새 `HypothesisProposal`을 넣는다. trusted validation과 전역 등록 뒤 전체 검증을 거치기 전까지 verdict, CWE, Gate 또는 보고서의 확정 주장으로 사용할 수 없다.

`PrimitiveDraft`는 Verification이 발견한 필요 조건 또는 제공 가능 능력을 같은 모양으로 표현하지만 Primitive DB admission record는 아니다. `draft_id`는 같은 `VerificationResult` 안에서 유일하다. `entity_refs`는 현재 workspace·commit의 코드 요소를 가리키고 `evidence_refs`는 조건·능력의 근거를 하나 이상 가리킨다. `privilege_level`은 저장소 코드에 실제로 나타난 역할명·권한 상수·검사 지점에서만 가져오며 조건에 권한 축이 없으면 `null`이다. 전역 권한 서열표나 이름만 같은 문자열로 충족 관계를 만들지 않는다. `description`은 이 조건 또는 능력을 사람이 읽을 수 있게 요약한 자유 서술이다. final HOLD의 `required_primitive_candidates`가 하나 이상이면 그 전체 목록이 result가 없는 Primitive의 `inputs`가 된다. 목록이 비어 있으면 Primitive와 Chaining work를 만들지 않는다. final TRUE의 `required_primitive_candidates`는 result가 있는 각 Primitive의 `inputs`, `provided_primitive_candidates`의 각 항목은 서로 다른 Primitive의 `result`가 된다. `FALSE`이면 두 목록이 모두 비어 있어야 한다.

`VerificationMetrics`의 token 값은 provider가 값을 제공하지 않으면 `null`이고, 나머지 정수는 모두 0 이상이어야 한다. debate를 실행하지 않았으면 `pro_tokens`와 `con_tokens`는 `null`, `verdict_changed_after_debate=false`다. `hold_resolved=true`는 `initial_verdict=HOLD`이고 final `verdict`가 `TRUE | FALSE`일 때만 허용한다. initial TRUE는 final 결과가 아니며 `POC_CONFIRMATION` request를 만들기 위한 중간 판단이다. initial TRUE와 PoC가 일치해 `SUCCEEDED + SUPPORTED`가 된 뒤에만 final TRUE를 저장한다.

`VerificationResult.dynamic_request_ref`가 있으면 current Verification generation의 COMMITTED `DynamicReproductionRequest`, `dynamic_result_ref`는 그 request에서 생성된 같은 가설·workspace·commit의 COMMITTED `DynamicReproductionResult` exact revision을 가리킨다. final `TRUE`에는 current Verification generation의 exact `DynamicReproductionRequest`, `SUCCEEDED + SUPPORTED` 동적 결과와 validated `poc_ref`가 모두 필수다. `VerificationResult.poc_ref`는 동적 결과의 `poc_ref`와 같은 `stored_data_id`, `record_id`, `content_hash`를 사용한다. `FALSE | HOLD`는 validated PoC를 가질 수 없으므로 `poc_ref=null`이며, dynamic 결과를 사용했다면 request와 result reference는 유지한다. 오류·정책 차단·환경 설정·PoC 생성·실행 실패 결과는 final VerificationResult의 근거로 소비하지 않는다.

최종 `VerificationResult`는 등록 가설의 모든 `question_id`와 `validation_id`를 각각 중복 없이 정확히 한 번씩 평가한다. 가설의 모든 `ValidationCheck.validation_id`와 candidate의 `ValidationCheckResult.validation_id`가 중복 없이 set-equal해야 한다. 모든 `ValidationCheckResult.completion=COMPLETE`이고 각 결과의 `evidence_refs`가 하나 이상이어야 final 결과를 확정할 수 있다. 확인을 끝내지 못한 항목은 `INCOMPLETE`로 표현하되, `INCOMPLETE` 항목이 하나라도 있으면 final candidate를 `COMMITTED`하지 않는다. `DISPROVED`는 해당 질문이 확인하려는 가설의 필수 조건이 실제 근거로 반증됐다는 뜻이며 `evidence_refs`가 하나 이상이어야 한다. `NOT_DISPROVED`는 반증하지 못했다는 뜻일 뿐 가설을 증명하지 않는다. 확인하지 못한 질문은 `INCONCLUSIVE`로 남긴다. `verdict=TRUE`는 실제 supporting evidence가 핵심 공격 경로와 필요한 조건을 연결할 때만 허용한다. `verdict=FALSE`는 적어도 하나의 `DISPROVED` 결과가 있고 `verdict_rationale`이 그 `question_id`와 근거를 설명할 때만 허용한다. `verdict=HOLD`는 정상 근거로 확인한 범위와 비어 있지 않은 `unresolved_conditions`가 결론을 막는 중요한 조건을 설명할 때만 허용한다. `TRUE | HOLD`에는 `DISPROVED` 결과가 있을 수 없다. `AnalysisError`, `DataGap`, timeout·권한 오류 또는 빈 Context만으로는 어느 verdict도 만들지 않는다.

## 5. Primitive DB records

연계 공격 탐색을 위해 보류된 가설의 필요 조건과 확인된 공격 능력을 저장하는 데이터입니다.

```yaml
PrimitiveAdmissionDecision:
  meta: RecordMeta
  verification_result_ref: StoredDataRef
  technical_review_ref: StoredDataRef
  policy_collection_result_ref: StoredDataRef
  rule_scope_review_ref: StoredDataRef | null
  testing_restriction_compliance: PASS | FAIL | UNCERTAIN | NOT_EVALUATED
  decision: ALLOW | DENY
  reason_code: TESTING_RESTRICTION_PASSED | TESTING_RESTRICTION_UNCERTAIN | POLICY_COLLECTION_FAILED | TESTING_RESTRICTION_VIOLATION
  decided_at: timestamp

Primitive:
  meta: RecordMeta
  primitive_id: string
  workspace_id: string
  commit_id: string
  inputs: [PrimitiveDraft]
  result: PrimitiveDraft | null
  restrictions: [Restriction]
  source_hypothesis_id: string
  source_verification_ref: StoredDataRef
  technical_review_ref: StoredDataRef | null
  admission_decision_ref: StoredDataRef | null
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

`Primitive`는 status를 저장하지 않는다. `result=null`이면 final HOLD에서 나온 입력 조건 묶음이고, `result`가 있으면 final TRUE에서 나온 확인된 능력이다. `workspace_id`와 `commit_id`는 `meta`와 exact match한다. `inputs[].draft_id`는 Primitive 안에서 중복될 수 없으며 `result.draft_id`도 같은 Primitive의 input ID와 겹치지 않는다. `restrictions`는 source Verification의 `restriction_id`와 전체 `Restriction` 객체를 그대로 보존하고, `evidence_refs`는 inputs와 result의 출처를 추적할 수 있어야 한다.

final HOLD는 `required_primitive_candidates`가 하나 이상일 때 Primitive 하나를 만든다. `inputs`는 그 목록과 내용·순서가 같고 `result=null`, `technical_review_ref=null`, `admission_decision_ref=null`, `restrictions`는 exact Verification 값과 같다. final FALSE는 Primitive를 만들지 않는다.

final TRUE는 현재 Verification generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 validated PoC가 있고, 같은 Verification과 이를 직접 가리키는 current CWELabel을 검토한 Technical `ACCEPT`가 있을 때 admission 검토를 시작한다. `PRIMITIVE_ADMISSION_RUNTIME`은 exact 정책 수집 결과와 존재하는 Rule Scope review를 아래 결정표에 적용해 `PrimitiveAdmissionDecision`을 만든다. `decision=ALLOW`일 때만 제공 능력마다 result가 있는 Primitive를 만들며, 각 record의 `admission_decision_ref`는 그 current decision을 exact하게 가리킨다. 제공 능력이 여러 개면 `provided_primitive_candidates` 항목마다 Primitive 하나를 만들고, 각 Primitive의 `inputs`는 같은 TRUE의 `required_primitive_candidates`, `result`는 해당 제공 능력 하나, `restrictions`는 Verification 값과 같아야 한다. Gate 전 TRUE는 result가 있는 Primitive가 될 수 없다. Technical `REVISE | REJECT`와 admission `DENY`도 result Primitive가 될 수 없다.

체이닝 재료 자격의 최종 authority는 R4 `PRIMITIVE_ADMISSION_RUNTIME`이 만든 current `PrimitiveAdmissionDecision`이다. Rule Scope의 `review_status`와 `report_permission`의 `FAIL | UNCERTAIN | DENY`는 Finding·Reporter 경로를 막지만 current admission이 `ALLOW`인 실제 코드 능력의 Primitive와 Chaining을 막지 않는다. `testing_restriction_compliance=FAIL`만 이 정책 축에서 `DENY`가 되며, `UNCERTAIN`은 `ALLOW`, `COLLECTION_FAILED`는 review 없는 `NOT_EVALUATED + ALLOW`로 구분한다. Technical Gate는 정책 record를 입력으로 갖지 않으므로 금지 재현을 판정하지 않고, validated PoC 연결(`dynamic_linkage`), 실제 코드 경로 연결(`code_flow_linkage`), restrictions 표현의 정확성(`restriction_assessment`)만 검토한다.

다만 `rule_compliance=FAIL + TESTING_RESTRICTION link`는 다른 규칙 실패와 금지 테스트 위반을 구분하기에 충분하지 않다. `testing_restriction_compliance`는 `rule_compliance`와 독립된 판정 축이다. 다른 `rule_compliance`, `scope_compliance`, impact와 report permission 값은 admission decision에 사용하지 않는다. Rule Scope review의 전용 값과 정책 수집 상태만 다음처럼 기계적으로 매핑한다.

| 정책 확인 상태 | 테스트 제한 판정 | admission 결과 |
|---|---|---|
| `FOUND | ABSENT_CONFIRMED`와 exact Rule Scope review | `PASS` | `ALLOW + TESTING_RESTRICTION_PASSED` |
| `FOUND | ABSENT_CONFIRMED`와 exact Rule Scope review | `UNCERTAIN` | `ALLOW + TESTING_RESTRICTION_UNCERTAIN` |
| `FOUND`와 exact Rule Scope review | `FAIL` | `DENY + TESTING_RESTRICTION_VIOLATION` |
| `COLLECTION_FAILED`, Rule Scope review 없음 | `NOT_EVALUATED` | `ALLOW + POLICY_COLLECTION_FAILED` |

`testing_restriction_compliance=FAIL`이면 `decision=DENY`, `reason_code=TESTING_RESTRICTION_VIOLATION`만 허용하고 result Primitive를 만들지 않는다. `COLLECTION_FAILED`이면 `rule_scope_review_ref=null`, `testing_restriction_compliance=NOT_EVALUATED`, `decision=ALLOW`, `reason_code=POLICY_COLLECTION_FAILED`로만 확정한다. 이는 “확정된 금지 위반만 체이닝을 차단한다”는 정책이며, 수집 실패 사실과 exact error는 숨기지 않는다. 그 밖의 조합, 서로 다른 Verification·Technical·정책 revision 조합, `PASS | FAIL`인데 `TESTING_RESTRICTION` evidence link가 없는 review, `UNCERTAIN`인데 같은 area의 `PolicyMissingInfo`가 없는 review는 저장하지 않는다.

decision의 `meta`는 `PRIMITIVE_UPDATE` current attempt와 같은 `attempt_id`를 사용하고, Verification·Technical review·Rule Scope review가 모두 같은 analysis·workspace·commit·hypothesis와 exact Verification revision을 가리켜야 한다. `policy_collection_result_ref`도 Rule Scope review가 사용한 reference와 같아야 한다. `COLLECTION_FAILED`에서는 Rule Scope review가 없으므로 decision이 가리키는 collection result와 그 오류 reference를 직접 검사한다.

한 Verification generation에는 하나의 `PrimitiveAdmissionDecision.logical_record_id`만 둔다. 정책 수집이나 Rule Scope review가 새 current revision으로 바뀌면 기존 decision을 재사용하지 않고 같은 logical record의 새 revision을 만든다. 새 decision이 `DENY`이면 이전 ALLOW를 근거로 만든 Primitive record는 감사 이력으로 보존하되 current `PrimitiveIndexState.primitive_refs`에서 제거한다. 해당 decision을 고정한 진행 중 Chaining work도 저장 시 `STALE_RESULT`로 거절한다. 따라서 일반 index 갱신은 진행 중 work를 무효화하지 않는다는 규칙과 달리, 오염된 근거의 admission 변경은 명시적 무효화 사유다.

가설마다 하나인 `PrimitiveIndexState`는 current final Verification과 현재 admission이 허용된 모든 Primitive exact reference를 가리킨다. 전용 `state_version`, Primitive 내부 status와 사후 `SUPERSEDED` lifecycle은 사용하지 않는다. 동시 쓰기 손실은 공통 immutable record 규칙으로 막는다. 새 revision은 바로 전 `record_id`와 연속된 `meta.revision_number`를 사용하고 current pointer를 atomic하게 바꾼다. 금지 테스트 위반으로 admission decision이 `DENY`가 된 경우에는 새 index에서 이전 result Primitive reference를 제거하고, 그 밖의 일반 갱신은 기존 work 입력을 바꾸지 않는다.

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
  source_admission_refs: [StoredDataRef]
  considered_primitive_refs: [StoredDataRef]
  input_primitive_refs: [StoredDataRef]
  primitive_match_candidates: [PrimitiveMatchCandidate]
  chained_hypothesis_proposals: [HypothesisProposal]
  excluded_lineage_refs: [LineageExclusion]
  no_match_reasons: [string]
  errors: [AnalysisError]
```

```yaml
LineageExclusion:
  excluded_primitive_ref: StoredDataRef
  excluded_by_ref: StoredDataRef
  reason_code: ANCESTOR_REUSE
```

`considered_primitive_refs`는 work 시작 시(`REGISTER_WORK`) Runtime이 고정한, 조상 제외 전 전체 Primitive 입력이고, `input_primitive_refs`는 실제 match candidate에 사용된 Primitive 합집합이다. 두 목록은 의미가 다르며 서로 대신하지 않는다. `source_result_refs`는 match에 사용된 Primitive들의 `source_verification_ref`와 non-null `technical_review_ref`를 중복 없이 합친 정확한 집합이다. `source_admission_refs`는 실제 match에 사용된 Primitive에서 직접 또는 `source_primitive_match_id` 계보를 따라 재귀적으로 도달하는 모든 result Primitive의 current ALLOW admission decision exact reference를 중복 없이 합친 집합이다. clean initial HOLD처럼 result Primitive 계보가 없을 때만 빈 목록일 수 있다. 각 candidate의 `parent_hypothesis_ids`와 `parent_verification_refs`도 해당 upstream/downstream Primitive가 직접 가리키는 source hypothesis와 Verification의 중복 없는 합집합이다. downstream result 유무로 TRUE_HOLD와 TRUE_TRUE를 유도하며 별도 trigger나 match kind를 저장하지 않는다. `chained_hypothesis_proposals`는 모두 `origin=CHAINING`, 입력 Primitive의 parent hypothesis ID와 exact `source_primitive_match_id`를 보존한다. 각 proposal의 restrictions는 입력 Primitive 양쪽 Restriction 객체의 중복 없는 합집합이며, 같은 `restriction_id`의 canonical content가 다르면 저장하지 않는다.

조상 제외는 §06이 정의한 순서를 따른다(순환 방지가 아니다 — record가 불변·append-only라 계보는 이미 DAG다). 같은 계보에서는 가장 깊은 후보부터 match를 검토하고, 그 match가 실제로 성립한 뒤에만 그 후보의 조상 Primitive를 양방향 재귀 탐색으로 찾아 이번 순회의 후보에서 제외한다. match가 성립하지 않으면 아무것도 제외하지 않고 얕은 후보를 그대로 검토한다. 검토 순서 자체는 Agent 규칙이고 Runtime은 결과 정합성만 검사한다. 순서를 어겨도 제외 대상이 조상뿐이라 더 깊은 후손은 후보로 남고, 같은 결과에서 얕은 후보와 깊은 후보를 모두 match하면 아래 `excluded_primitive_ref` 규칙에 걸려 저장이 거절된다. 조상 쪽은 새 Primitive가 등장하기 전부터 이미 서로 연결이 확정된 상태였으므로, 가장 깊은 match가 성립한 시점에서 그 결론이 얕은 조합들의 결론을 이미 포함한다. 대신 가장 깊은 조합의 자식 가설이 이후 Verification에서 실패해도 제외된 얕은 조합은 다시 제안되지 않으며, 이는 이 중복 제거 정책이 만드는 미탐 위험으로 의도적으로 수용한 결정이다. 실제로 제외한 항목마다 `LineageExclusion`을 남기며 Runtime이 고정 입력에서 기대되는 제외 쌍과 결과를 다시 비교한다. 제외된 Primitive는 match 입력으로 사용할 수 없고, 제외 근거가 된 Primitive는 실제 match에 사용된 같은 work 입력이어야 하며 자신은 제외되지 않아야 한다. DB 상태는 바꾸지 않는다. 체이닝 전용 임의 depth·전체/parent별 가설 수·호출 수·Primitive 조합 수와 token 상한은 두지 않는다. 대신 R8의 전체 시간·비용·work 예산을 모든 Chaining work에 동일하게 적용한다. token 사용량은 관측할 뿐 초과만으로 중단하지 않는다. 다른 예산 소진도 `FALSE`가 아니며 실행 상태와 `AnalysisRunResult.stop_reasons`에 기록한다.

`ChainingResult.considered_primitive_refs`, `source_admission_refs`와 `excluded_lineage_refs` 추가는 기존 결과의 필수 필드를 바꾸므로 새 MAJOR schema로 배포한다. 이전 MAJOR 결과에 세 목록을 빈 배열로 추정하지 않는다. 기존 결과는 감사 이력으로만 보존하고 새 Chaining·가설 등록 입력으로 자동 승격하지 않는다.

ChainingResult는 bypass, alternate path, 새 sink, impact escalation, Technical revision, 일반 validation 또는 동적 재현 요청을 포함할 수 없다. 이런 주장은 Verification이 자기 흐름에서 조사하고 material하면 `origin=VERIFICATION` proposal로 분리한다. 이 record는 기존 verdict, CWE, Gate 또는 Finding을 변경하지 않는다.

## 7. CWELabel과 DynamicReproductionResult

취약점 유형 분류와 Docker 재현의 환경·Agent 활동·PoC·관찰 결과를 각각 기록합니다.

```yaml
CWELabel:
  meta: RecordMeta
  verification_result_ref: StoredDataRef
  verification_generation: integer
  cwe_labeling_work_id: string
  llm_call_id: string
  primary: string | null
  alternatives: [string]
  taxonomy_version: string
  rationale: string
  evidence_refs: [StoredDataRef]
  uncertainty: string | null
```

`CWELabel`의 logical producer/runtime role은 `CWE_LABELING`, R1~R8 실제 업무 owner는 R5-01이다. `CWE_LABEL`은 이 역할을 실행하는 `WorkExecutionState.work_type` 이름이다. label의 `verification_result_ref.record_id`는 자신이 분류한 exact final `VerificationResult(verdict=TRUE)` revision을 가리키고 `verification_generation`은 current `HypothesisProcessState`와 부모 Verification work의 generation에 일치해야 한다. `cwe_labeling_work_id`, `meta.attempt_id`와 `llm_call_id`는 label을 만든 current work, 성공 attempt와 성공한 `CWE_LABELING` invocation을 각각 고정한다. Runtime Validator는 의미상 어떤 CWE가 맞는지 대신 판단하지 않고 이 구조와 exact reference만 검사한다.

한 가설의 최초 label은 새 `logical_record_id`, `revision_number=1`, `previous_record_id=null`이다. 새 Verification revision 또는 generation이 생기면 CWE 정렬을 다시 평가하고 같은 label `logical_record_id`에 새 `record_id`, 증가한 revision과 직전 label의 `previous_record_id`를 가진 새 record를 만든다. primary·alternatives가 그대로여도 새 Verification을 가리키는 새 revision이 필요하다. 과거 label은 overwrite하지 않고 감사 이력으로 보존하지만 새 `CWE_LABEL` work나 Gate의 current input으로 재사용하지 않는다. current label은 current final TRUE를 input으로 가진 유일한 `CWE_LABEL` work가 `SUCCEEDED`이고 그 work의 유일한 `output_refs`가 가리키는 exact revision이다.

Technical Gate를 등록·호출·저장할 때 `verification_result_ref`는 `CWELabel.verification_result_ref`와 exact match해야 한다. label의 generation도 current process state와 같아야 하고, label의 work·attempt·invocation과 evidence closure가 모두 COMMITTED current reference여야 한다. 새 Verification에 과거 label을 붙이거나 값만 복사해 provenance를 생략하면 `STALE_RESULT | RECORD_REVISION_MISMATCH`로 차단한다. CWE labeling 실패·timeout·provider 인증 오류는 Verification을 `FALSE | HOLD`로 바꾸지 않으며, current label이 확정될 때까지 Technical Gate를 호출하지 않는다. Technical Gate는 CWE 정합성을 검토할 뿐 `CWELabel`을 생성·수정·덮어쓰지 않는다.

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

ReproductionPlan:
  meta: RecordMeta
  request_ref: StoredDataRef
  purpose: POC_CONFIRMATION | VERDICT_EVIDENCE
  hypothesis_ref: StoredDataRef
  environment_requirements_ref: StoredDataRef
  sandbox_profile_ref: StoredDataRef
  reproduction_goal: string
  strategy_summary: string
  requested_evidence: [string]

EnvironmentRecipe:
  meta: RecordMeta
  request_ref: StoredDataRef
  environment_requirements_ref: StoredDataRef
  recipe_source_ref: StoredDataRef
  source_refs: [StoredDataRef]
  base_image_digest: string
  built_image_digest: string
  baseline_recipe_ref: StoredDataRef | null
  build_disposition: BUILT | REUSED
  created_at: timestamp

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
  request_ref: StoredDataRef
  reproduction_plan_ref: StoredDataRef
  environment_recipe_ref: StoredDataRef
  requirements_ref: StoredDataRef
  container_instance_id: string
  container_action: CREATED | REUSED
  container_reason: INITIAL_CLEAN | NO_RELEVANT_CHANGE | STATE_CHANGED | CONFIG_CHANGED | STATE_UNCERTAIN
  previous_environment_ref: StoredDataRef | null
  status: READY | MISMATCH | ERROR
  checks: [EnvironmentCheck]
  limitations: [string]
  created_at: timestamp

PlanIssueItem:
  issue_code: MISSING_INPUT | CONTRADICTORY_REQUIREMENT | UNEXECUTABLE_GOAL | STALE_REFERENCE | OTHER
  status: OPEN | RESOLVED
  message: string
  related_refs: [StoredDataRef]

SandboxPolicyDecision:
  meta: RecordMeta
  action_decision_ref: StoredDataRef
  request_ref: StoredDataRef
  sandbox_profile_ref: StoredDataRef
  resource_profile_ref: StoredDataRef
  decision: ALLOW | DENY
  reason_codes: [string]
  checked_boundary_refs: [StoredDataRef]
  decided_at: timestamp

CleanupResult:
  meta: RecordMeta
  request_ref: StoredDataRef
  environment_refs: [StoredDataRef]
  resource_refs: [StoredDataRef]
  status: SUCCEEDED | FAILED
  failure_reason: string | null
  finished_at: timestamp

AgentLogEvent:
  event_id: string
  sequence: integer
  action_id: string
  event_type: SESSION_STARTED | AGENT_STARTED | AGENT_FINISHED | COMMAND_STARTED | COMMAND_FINISHED | POC_CANDIDATE_CREATED | POC_EXECUTION_STARTED | POC_EXECUTION_FINISHED | OBSERVATION_RECORDED | SANDBOX_RECREATE_REQUESTED | SANDBOX_RECREATED | CLEANUP_STARTED | CLEANUP_FINISHED | POLICY_BLOCKED | ERROR | SESSION_FINISHED
  actor: R7_AGENT | R7_SETUP_AUTOMATION | TOOL_RUNTIME | SANDBOX_CONTROLLER | REPRODUCTION_SESSION_MANAGER
  environment_ref: StoredDataRef | null
  environment_recipe_ref: StoredDataRef | null
  poc_candidate_ref: StoredDataRef | null
  input_refs: [StoredDataRef]
  output_refs: [StoredDataRef]
  exit_code: integer | null
  safe_message: string | null
  occurred_at: timestamp

AgentLog:
  meta: RecordMeta
  request_ref: StoredDataRef
  events: [AgentLogEvent]

PoCCandidate:
  meta: RecordMeta
  request_ref: StoredDataRef
  reproduction_plan_ref: StoredDataRef
  content_ref: StoredDataRef
  content_digest: string
  created_by_invocation_ref: StoredDataRef
  created_at: timestamp

PoCBundle:
  meta: RecordMeta
  request_ref: StoredDataRef
  reproduction_plan_ref: StoredDataRef
  environment_recipe_ref: StoredDataRef
  environment_ref: StoredDataRef
  agent_log_ref: StoredDataRef
  candidate_ref: StoredDataRef
  candidate_digest: string
  execution_action_id: string
  evidence_refs: [StoredDataRef]
  validated_at: timestamp

DynamicReproductionResult:
  meta: RecordMeta
  action_decision_ref: StoredDataRef | null
  request_ref: StoredDataRef
  reproduction_plan_ref: StoredDataRef | null
  purpose: POC_CONFIRMATION | VERDICT_EVIDENCE
  policy_decision_ref: StoredDataRef | null
  agent_invoked: boolean
  agent_log_ref: StoredDataRef
  environment_recipe_ref: StoredDataRef | null
  environment_ref: StoredDataRef | null
  poc_candidate_ref: StoredDataRef | null
  poc_ref: StoredDataRef | null
  observation_refs: [StoredDataRef]
  status: SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED
  failure_category: NONE | POLICY_BLOCKED | EXTERNAL_CONFIGURATION | PLAN | ENVIRONMENT_SETUP | DEPENDENCY | AGENT | EXECUTION | OBSERVATION | TIMEOUT | RESOURCE_LIMIT | RETRY_LIMIT | INTERNAL
  failure_reason: string | null
  plan_issues: [PlanIssueItem]
  hypothesis_outcome: SUPPORTED | DISPROVED | INCONCLUSIVE
  hypothesis_evidence_refs: [StoredDataRef]
  hypothesis_disproved: boolean
  disproof_evidence_refs: [StoredDataRef]
  hypothesis_linkage: string
  plan_execution_status: EXECUTABLE | EXECUTABLE_WITH_LIMITATIONS | NEEDS_REVISION
  plan_issue_evidence_refs: [StoredDataRef]
  limitations: [string]
  cleanup_required: boolean
  cleanup_status: SUCCEEDED | FAILED | NOT_REQUIRED
  cleanup_ref: StoredDataRef | null
  started_at: timestamp
  finished_at: timestamp
  elapsed_ms: integer
```

`status`는 재현 작업이 어디까지 진행됐는지, `hypothesis_outcome`은 실제 동적 관측이 가설과 어떤 관계인지 나타낸다. R7의 outcome은 동적 실행 결과에 대한 판단이며 최종 `TRUE | FALSE | HOLD`가 아니다. 최종 취약점 판정은 R6 Verification이 정적·Pro·Con·동적 근거를 함께 읽고 결정한다.

`DynamicReproductionRequest`는 R6 Verification이 R7에 무엇을 왜 재현할지 전달하는 불변 record다. `verification_assignment_ref`, `verification_generation`과 `hypothesis_ref`는 current Verification work와 exact match한다. `POC_CONFIRMATION`은 `initial_verdict=TRUE`, `VERDICT_EVIDENCE`는 동적 근거가 더 필요한 `initial_verdict=HOLD`에 사용한다. R7은 request의 purpose·goal·가설·필수 환경 조건과 `sandbox_profile_ref`를 변경하지 않는다.

R6가 이미 전달한 request 조건을 바꿔야 하면 같은 record나 같은 generation을 수정하지 않고 새 Verification generation의 새 request를 만든다. 새 request는 generation당 단일 work 등록, Runtime Validator와 Sandbox Controller 검사를 모두 다시 거치며 이전 허가·recipe 이외의 attempt artifact를 재사용하지 않는다.

`EnvironmentRequirements`와 `ReproductionPlan`은 R7 Reproduction Agent가 exact request를 실행 가능한 형태로 구체화해 생산한다. 각 request need는 하나 이상의 requirement에 포함되어야 하고 `required=true` 조건을 누락하거나 선택 사항으로 낮출 수 없다. plan의 `request_ref`, `purpose`, `hypothesis_ref`와 `sandbox_profile_ref`는 request와 exact match하며 `environment_requirements_ref`는 같은 R7 work의 current requirements를 가리킨다. R7은 목표·문맥·선택적 관찰 항목을 기록하지만 exact command·payload·실행 순서·cleanup policy를 계약으로 고정하지 않는다. 모든 동적 재현은 같은 Sandbox 실행 경로를 사용하며 별도 LIMITED/FULL 구분을 두지 않는다.

credential·cookie·token·password와 재사용 가능한 인증 값은 requirements의 `expected`, `alternatives`, source·check artifact와 일반 log에 저장하지 않는다. 비밀이 필요하면 허용된 secret store의 불투명 `secret_ref(data_kind=secret_handle)`만 사용한다.

`ReproductionPlan`은 R7 Agent가 exact request를 읽고 만든 불변 재현 전략이다. `request_ref`, `purpose`, `hypothesis_ref`, `sandbox_profile_ref`는 R6 request와 exact match하고 `environment_requirements_ref`는 같은 R7 attempt의 current requirements를 가리킨다. `reproduction_goal`은 request의 목표를 약화하지 않으며 `strategy_summary`는 Agent가 어떤 방식으로 관측할지 설명한다. `requested_evidence`는 비어 있을 수 있는 참고 목표이며, 여기에 없는 추가 관찰·명령·PoC·재시도를 금지하는 allowlist가 아니다. plan에는 실행 mode, exact command·step·payload·PoC·cleanup 지시를 넣지 않는다. Agent는 Sandbox 안에서 이를 자율적으로 결정하고 실제 수행 사실은 `AgentLog`에 남긴다.

plan의 입력 부족이나 모순은 별도 `PlanIssue` record를 만들지 않고 `DynamicReproductionResult.plan_issues`에 `PlanIssueItem`으로 반환한다. Agent가 attempt 안에서 해결하면 `status=RESOLVED`로 이력을 남기고 계속할 수 있다. `OPEN` 항목이 남아 재현을 신뢰할 수 없으면 `hypothesis_outcome=INCONCLUSIVE`, `poc_ref=null`이며, 외부 수정 가능 여부에 따라 결과 status는 `BLOCKED | FAILED`다.

`EnvironmentRecipe`는 current `DYNAMIC_REPRO` attempt의 binding record이자 저장소와 필요한 실행 환경에서 Docker image를 다시 만들 수 있는 불변 build recipe다. `meta.hypothesis_id`와 `meta.attempt_id`는 반드시 현재 work·attempt 값이어야 하며 base·built image digest를 구분해 기록한다. `source_refs`는 Dockerfile·README·package manifest·lockfile처럼 저장소가 이미 선언한 의존성을 우선 가리킨다. 별도 Dependency Scanner나 R2 사전 package prefetch를 전제로 하지 않는다. `base_image_digest`는 시작 image, `built_image_digest`는 실제 build 또는 재사용한 완성 image를 뜻하며 서로 바꾸어 쓰지 않는다. package 누락을 실제로 확인하면 Agent가 recipe source를 갱신하고 Setup Automation이 새 image를 build한 뒤 현재 attempt의 새 binding record를 만든다. 과거 성공 환경은 `baseline_recipe_ref`로만 참조할 수 있다. baseline을 재사용해도 현재 attempt에는 `build_disposition=REUSED`, exact `baseline_recipe_ref`와 같은 `built_image_digest`를 가진 새 `EnvironmentRecipe` binding을 생성해 provenance를 고정한다. `PERSISTENT_BASELINE`을 writable container 재사용 모드로 정의하지 않으며 writable container는 가설 work를 넘겨 재사용하지 않는다.

`SandboxEnvironment`는 R7 Setup Automation이 해당 attempt에서 실제로 만든 또는 재사용한 환경과 요구사항 비교를 기록하는 불변 record다. `request_ref`, `reproduction_plan_ref`, `environment_recipe_ref`와 `requirements_ref`는 같은 attempt의 exact record를 가리킨다. `checks`는 요구사항의 모든 `requirement_id`를 정확히 한 번씩 포함한다. `MATCH | MISMATCH`에는 공개 가능한 `actual` 또는 실제 구성 artifact를 가리키는 exact `actual_ref` 중 하나 이상이 필요하다. `NOT_CHECKED | ERROR`에서는 두 필드가 모두 `null`일 수 있지만 비어 있지 않은 `difference`와 비교 시도 근거가 필요하다. 모든 check는 `evidence_refs` 또는 `check_result_ref` 중 하나 이상을 가져야 하며, `check_result_ref`는 Health Check 결과를 가리킨다. 실제 비밀값은 어느 필드에도 저장하지 않는다.

필수 item은 모두 `MATCH`이고 필수 setup 오류가 없어야 `SandboxEnvironment.status=READY`다. VERSION의 실제 값이 `expected` 또는 R7 requirements에 안전하게 명시한 `alternatives` 중 하나면 `MATCH`로 기록할 수 있으며 대체 버전을 썼다면 `difference`에 그 사실을 남긴다. 대체값은 R6 request의 필수 조건을 약화하거나 Sandbox profile을 우회할 수 없다. `MISMATCH | NOT_CHECKED | ERROR`에는 비어 있지 않은 `difference`가 필요하다. 필수 item에 확인된 값 차이 또는 미확인이 있으면 환경 status는 `MISMATCH`, setup·비교 자체의 오류가 있으면 `ERROR`다. 선택 item의 차이·오류만 `limitations`에 남기고 진행할 수 있다.

가설의 첫 `DYNAMIC_REPRO` attempt는 writable 상태를 공유하지 않는 clean container에서 시작하며 `container_action=CREATED`, `container_reason=INITIAL_CLEAN`, `previous_environment_ref=null`이다. 서로 다른 가설은 같은 `container_instance_id`의 writable container를 공유하지 않는다. 같은 가설·work 안에서는 attempt가 달라도 다음 실행에 영향을 줄 상태·설정 변화가 없을 때만 기존 container를 `REUSED + NO_RELEVANT_CHANGE`로 사용할 수 있다. 재사용하더라도 current attempt의 새 `SandboxEnvironment` binding record를 만들고 `previous_environment_ref`로 직전 환경을 연결한다. Agent가 `STATE_CHANGED | CONFIG_CHANGED | STATE_UNCERTAIN`을 이유로 재생성을 요청할 수 있고, crash·비정상 종료·사후 Health Check 실패면 runtime이 `STATE_UNCERTAIN`으로 강제한다. 각 결정은 새 `SandboxEnvironment` record와 `previous_environment_ref`로 연결하고 `SANDBOX_RECREATE_REQUESTED | SANDBOX_RECREATED` event에 요청 주체·사유·이전/새 환경을 남긴다.

`action_decision_ref`는 plan 입력 부족·모순 때문에 `RUN_SANDBOX` 요청 자체를 만들기 전에 종료된 pre-boundary 결과에서만 `null`일 수 있다. 이때 `failure_category=PLAN`, `agent_invoked=false`, `policy_decision_ref=null`, recipe·환경·candidate·validated PoC reference는 모두 `null`이어야 하며 `AgentLog`가 plan issue와 종료 event를 보존한다. 그 밖에 Sandbox 외부 경계 검사를 시도한 모든 결과의 `action_decision_ref.record_id`는 R7 호출자의 권한·상태·예산, exact `DynamicReproductionRequest`, current `EnvironmentRequirements`, current exact `ReproductionPlan`, `sandbox_profile_ref`와 R8 resource/lifecycle profile을 확인해 외부 격리 경계 생성을 허가한 `RUN_SANDBOX` ALLOW decision의 `USED` revision을 가리킨다. 이 decision은 plan·recipe·PoC·command 성공이나 정책 통과를 뜻하지 않으며 다른 가설·attempt에 재사용하지 않는다. Sandbox Controller는 host, Docker daemon/socket, host mount·namespace, secret, 허용되지 않은 egress, 다른 workspace와 R8 resource profile/lifecycle 같은 Sandbox 바깥 경계만 검사한다. 컨테이너 내부 command를 allowlist로 재판단하지 않는다. `failure_category=POLICY_BLOCKED`이면 `action_decision_ref`와 `policy_decision_ref`가 반드시 존재하고, 정책 판정은 `decision=DENY`이며 적용한 정책의 exact revision과 사유 코드를 확인할 수 있어야 한다. 이 정책 판정은 Technical Gate와 다른 결과이며 서로 변환하지 않는다.

정책을 통과하면 R7 Setup Automation이 image build·container 생성·재생성·정리를 수행한다. R7 Agent는 격리된 container 안에서 환경 설정, 저장소가 필요로 하는 package, 계정, fixture/mock, PoC, command, 관찰과 재시도를 자율적으로 선택할 수 있다. Agent는 Docker daemon이나 host를 직접 제어하지 않고 Setup Automation이 제공한 in-container 실행 통로만 사용한다. 새로운 package registry나 외부 target 접근은 여전히 versioned profile의 egress 경계를 통과해야 한다. Agent가 선택한 command의 내용은 plan allowlist와 비교하지 않지만 모든 실제 event는 `AgentLog`에 기록한다.

비-LLM `Reproduction Session Manager`는 runtime/tool/lifecycle 계층에서 발생한 event를 durable append-only `AgentLog`로 저장하고, 같은 attempt의 exact reference만 사용해 `DynamicReproductionResult`와 validated PoC를 확정하는 result owner다. Agent의 실행 전략이나 해석을 대신 쓰지 않으며 Agent 호출·중단, command 허용, 재시도 또는 cleanup 전략을 결정하지 않는다. `agent_invoked`는 외부 경계 승인 뒤 Sandbox 안에서 실행하는 R7 Agent 단계가 시작됐는지를 뜻하며, 경계 승인 전에 requirements·plan을 작성한 LLM invocation과 구분한다. Sandbox 실행 Agent가 호출되기 전 정책 차단도 `agent_invoked=false`와 `POLICY_BLOCKED` event를 가진 로그·결과로 확정할 수 있다. `event_id`는 시스템 전체에서 고유하고 `sequence`는 attempt별 1부터 엄격히 증가한다. 시작과 종료 event는 동일한 `action_id`로 연결한다. 각 append를 바로 durable revision으로 확정하므로 crash 뒤에도 이전 event가 남고, 종료된 이전 attempt의 늦은 event는 current log나 결과에 붙이지 않는다.

`poc_candidate_ref`는 Agent가 작성했거나 실행을 시도한 exact `PoCCandidate`를 가리킨다. candidate가 있으면 같은 attempt의 `AgentLog`에 `POC_CANDIDATE_CREATED` 또는 `POC_EXECUTION_STARTED` event와 exact candidate revision·digest가 있어야 한다. 생성하지 못했다면 `poc_candidate_ref=null`이다. candidate 생성·실행 실패에서도 candidate와 관련 log는 감사 이력으로 남길 수 있지만 성공을 뜻하지 않는다.

`poc_ref`는 실제 취약점 재현에 성공한 `PoCBundle`만 가리킨다. `status=SUCCEEDED`, `hypothesis_outcome=SUPPORTED`, `agent_invoked=true`이고 같은 attempt의 `AgentLog`가 exact candidate revision과 `content_digest`를 실제 실행해 지지 관측을 만들었음을 보여야 한다. `PoCBundle`의 request·plan·recipe·environment·log·candidate·execution action과 digest는 결과가 가리키는 값과 exact match한다. 환경 실패, 정책 차단, candidate 생성·실행 실패, timeout, `DISPROVED | INCONCLUSIVE`, `PARTIAL | FAILED | BLOCKED | CANCELLED`에서는 `poc_ref=null`이다. “가장 최신 PoC”를 다시 조회하거나 candidate와 validated PoC를 한 reference로 덮어쓰지 않는다.

candidate 생성·환경 구성·실행 실패는 동적 재현 실패 사실일 뿐 `FALSE | HOLD`나 technical impact 사실로 변환하지 않는다.

`cleanup_required`는 container·network·volume·image/build 임시 자원·임시 파일 등 정리 대상이 하나라도 생성됐는지를 나타낸다. `false`이면 `cleanup_status=NOT_REQUIRED`, `true`이면 `cleanup_status=SUCCEEDED | FAILED`만 허용한다. 정책 차단이라는 이유만으로 `NOT_REQUIRED`를 선택하지 않는다. 실제 자원이 있는데 `cleanup_required=false` 또는 `cleanup_status=NOT_REQUIRED`인 결과는 계약 위반이다.

plan 자체가 모순되거나 필수 입력이 없으면 별도 `PlanIssue` 대신 결과의 `plan_execution_status=NEEDS_REVISION`, `plan_issues`와 근거로 반환한다. 해결 가능한 package·setup·PoC·실행 문제는 같은 R7 Agent session이면 현재 attempt에서 조정하고, session 재시작이 필요할 때만 R8 한도 안에서 같은 work의 새 attempt로 재시도한다. 한도를 소진하면 `DynamicReproductionResult(status=FAILED, hypothesis_outcome=INCONCLUSIVE, poc_ref=null)`로 반환하며 R6가 후속 흐름을 결정한다.

다음 reference는 모두 `record_id`가 있는 exact `StoredDataRef`를 사용한다. target record의 analysis·workspace·commit·hypothesis는 동적 결과와 같아야 한다. request의 `verification_generation`, plan·recipe·candidate·result의 `request_ref`, plan/result의 `purpose`가 exact match해야 한다. current `EnvironmentRecipe`, terminal `SandboxEnvironment`, `AgentLog`, `PoCCandidate`, `PoCBundle`, cleanup과 `DynamicReproductionResult`는 모두 결과와 같은 `DYNAMIC_REPRO.work_id + attempt_id`에 속한다. baseline 재사용을 나타내는 `EnvironmentRecipe.baseline_recipe_ref`만 과거 attempt를 가리킬 수 있으며 현재 binding recipe와 `built_image_digest`가 같아야 한다. log event가 가리키는 environment·recipe·candidate도 event가 속한 attempt의 exact record다. 같은 R7 Agent session의 command·PoC·환경 조정은 같은 attempt의 event로 기록한다. session 재시작이 필요하면 같은 work의 새 `attempt_id`와 `trigger=RETRY`를 사용하고, 외부 조건 해소 뒤 재개하면 같은 work의 새 `attempt_id`와 `trigger=RESUME`를 사용한다. 과거 attempt artifact와 늦은 event는 current 결과에 섞지 않는다. 별도 `reproduction_id`를 발급하지 않고 exact `DynamicReproductionRequest.record_id + work_id + attempt_id`로 시도를 식별한다.



| reference 위치 | `data_kind` | 만드는 주체 | 읽는 주체 | 최소 의미 |
|---|---|---|---|---|
| `DynamicReproductionRequest` | `dynamic_reproduction_request` | R6 Verification | R7, Runtime Validator | 재현 가설·목적·목표·환경 필요·profile과 근거의 current generation 요청 |
| `EnvironmentRequirements.request_ref` | `dynamic_reproduction_request` | R6 Verification | Runtime Validator, R7 | R7 requirements가 구체화한 exact 요청 |
| `ReproductionPlan.environment_requirements_ref` | `environment_requirements` | R7 Agent | Runtime Validator, R7 Setup Automation | 필요한 애플리케이션 환경의 current exact revision |
| `environment_recipe_ref` | `environment_recipe` | R7 Setup Automation | Session Manager, Verification, Gate | base·built image digest와 저장소 선언 의존성을 고정한 current attempt recipe |
| `poc_candidate_ref` | `poc_candidate` | R7 Agent | Session Manager, Verification | 작성 또는 실행을 시도한 PoC script·요청·입력 |
| `poc_ref` | `poc_bundle` | Reproduction Session Manager | Verification, Gate, Reporter | 같은 attempt 실행으로 검증된 exact PoC와 provenance 묶음 |
| `policy_decision_ref` | `sandbox_policy_decision` | Sandbox Controller | Session Manager, Verification, Gate | 외부 격리 경계의 exact 정책 revision과 허용·차단 사유 |
| `environment_ref` | `sandbox_environment` | R7 Setup Automation | Session Manager, R6 Verification, Gate | 실제 container instance, 생성·재사용 사유와 요구사항 비교 |
| `agent_log_ref` | `agent_log` | Reproduction Session Manager | Verification, Gate, 운영 디버깅 | Agent·tool·setup의 실제 event를 attempt 순서대로 보존한 로그 |

R4는 공통 record·필드명·자료형·null·exact reference·상태·생산자와 소비자·오류 규칙을 정한다. R6은 `DynamicReproductionRequest`, 반환 결과 소비와 최종 가설 판정을 맡는다. R7 Agent는 requirements·plan·candidate와 동적 근거 해석을 만들고, R7 Setup Automation은 recipe·image·container·cleanup을 실제로 수행한다. Sandbox Controller는 외부 격리 경계만 판정한다. 비-LLM Reproduction Session Manager는 append-only log, validated PoC와 `DynamicReproductionResult`의 유일한 result owner다. Verification은 COMMITTED 결과를 읽어 판정하고, Gate는 final TRUE에 연결된 validated PoC와 동적 근거를 검토하며, Reporter는 두 Gate를 통과한 결과만 사용한다.

Sandbox Controller는 실행 직전 `RUN_SANDBOX` decision의 exact request·current requirements·current exact plan·`sandbox_profile_ref`·R8 resource/lifecycle profile과 현재 외부 경계를 검사한다. 결과를 저장할 때 `SAVE_RESULT(requested_by=REPRODUCTION_SESSION_MANAGER, result_kind=dynamic_reproduction_result)`는 request·purpose·plan·recipe·정책·환경·AgentLog·candidate·validated PoC·cleanup의 same-attempt 조합을 다시 확인한다. Verification은 `DynamicReproductionState.dynamic_result_ref`, work output과 commit이 같은 final 결과만 읽으며 `DynamicReproductionResult`를 직접 만들거나 수정하지 않는다.

| `status` | `failure_category`와 `failure_reason` | 필수 의미 |
|---|---|---|
| `SUCCEEDED` | `NONE`, `null` | 의미 있는 실행과 관측을 정상 종료함. outcome은 관측에 따라 세 값 모두 가능 |
| `PARTIAL` | `NONE`, `null` | 신뢰 가능한 관측이 하나 이상 있지만 전체 확인은 부족함. `INCONCLUSIVE`, evidence와 limitation이 필요 |
| `FAILED` | `NONE` 이외, 비어 있지 않은 자유형 reason | 복구 불가능하거나 R8 자율 retry 한도를 소진함. 반드시 `INCONCLUSIVE`, final verdict 없음 |
| `BLOCKED` | `NONE` 이외, 비어 있지 않은 자유형 reason | 정책·외부 설정·승인·resource profile 변경을 기다림. 반드시 `INCONCLUSIVE`, final verdict 없음 |
| `CANCELLED` | `INTERNAL` 또는 실제 범주, 비어 있지 않은 자유형 reason | 사용자나 runtime이 중단함. `INCONCLUSIVE`, final verdict 없음 |

필수 상태 조합은 다음과 같다.

| 상황 | 필수 조합 |
|---|---|
| plan 입력 부족·모순으로 RUN_SANDBOX 요청 전 종료 | `action_decision_ref=null`, `policy_decision_ref=null`, `agent_invoked=false`, `agent_log_ref` 필수. plan은 만들지 못했으면 `null`, recipe·environment·candidate·validated PoC는 `null`. `BLOCKED | FAILED + PLAN + INCONCLUSIVE` |
| Sandbox 실행 Agent와 어떤 자원도 만들기 전 정책 차단 | `action_decision_ref`와 `agent_log_ref`, `policy_decision_ref(decision=DENY)` 필수. `agent_invoked=false`. 사전에 만든 same-attempt plan은 보존할 수 있지만 recipe·environment·candidate·validated PoC는 `null`. `BLOCKED | FAILED + POLICY_BLOCKED + INCONCLUSIVE` |
| Sandbox 실행 Agent 호출 뒤 생성·실행 실패 | `agent_invoked=true`, `agent_log_ref` 필수. 생성된 plan·recipe·environment·candidate는 same-attempt exact ref로 보존하고 `poc_ref=null` |
| 동적 재현 성공과 가설 지지 | `SUCCEEDED + SUPPORTED`, `action_decision_ref`와 `policy_decision_ref(decision=ALLOW)`, `agent_invoked=true`, plan·recipe·environment·AgentLog·candidate와 validated `poc_ref` 필수. 전부 같은 request·work·attempt·digest에 속함 |
| 환경 또는 임시 자원을 만든 뒤 오류·정책 차단 | `environment_ref`가 있으면 `cleanup_required=true`, `cleanup_status=SUCCEEDED | FAILED`, `cleanup_ref` 필수. 실제 자원이 없을 때만 `NOT_REQUIRED` |
| 필수 환경 요구사항 불일치 | Agent가 같은 attempt에서 recipe를 고쳐 해결하거나 자율 retry한다. 외부 수정이 필요하면 `BLOCKED`, 복구 불가능하거나 한도 소진이면 `FAILED`; 모두 `ENVIRONMENT_SETUP + INCONCLUSIVE`, `poc_ref=null` |

R7 Agent가 command·PoC·환경을 같은 session에서 다시 시도하는 것은 한 attempt의 event로 기록한다. session crash처럼 새 attempt가 필요한 일시 오류라도 외부 입력을 기다리지 않고 R8 한도가 남아 있으면 실패 attempt를 보존하고 같은 work를 `RUNNING -> READY -> RUNNING`으로 넘겨 자동 재시도한다. 외부 설정·정책·승인·resource profile 변경을 기다릴 때만 `BLOCKED`이며, 조건이 해결되면 `trigger=RESUME`인 새 attempt를 시작한다. 복구 불가능하거나 한도를 소진하면 Session Manager가 최종 `FAILED + INCONCLUSIVE`를 확정하고 work와 현재 Verification을 verdict 없이 `FAILED`로 끝낸다. PoC 생성·실행 실패를 `FALSE | HOLD`로 변환하지 않는다. `SUPPORTED | DISPROVED`는 실제 관측 reference가 필수다. `DISPROVED`이면 `hypothesis_disproved=true`와 disproof refs가 필요하고, 정상 종료 또는 신뢰 가능한 부분 완료의 `INCONCLUSIVE`일 때만 R6가 final HOLD를 만들 수 있다. `POC_CONFIRMATION | VERDICT_EVIDENCE` 모두 실제 반증은 FALSE, 정상 관측의 불충분은 HOLD, `SUCCEEDED + SUPPORTED`와 validated PoC만 TRUE로 이어진다.

`SAVE_RESULT`는 Agent/log 불일치, policy reference 누락, recipe와 실제 image digest 불일치, plan/environment requirements 불일치, 빈 plan issue, secret 원문, 잘못된 cleanup 조합, 실패 candidate의 `poc_ref` 승격, 다른 attempt artifact 혼합을 거절한다.

- `agent_invoked=false`인데 `AgentLog`에 `AGENT_STARTED`가 있거나, `true`인데 해당 event가 없음
- pre-boundary `PLAN` 실패가 아닌데 `action_decision_ref=null`, 또는 pre-boundary 실패에 정책·recipe·환경·candidate·validated PoC reference가 붙음
- `failure_category=POLICY_BLOCKED`인데 `action_decision_ref=null`, `policy_decision_ref=null` 또는 정책 decision이 `DENY`가 아님
- `agent_invoked=true`인데 `action_decision_ref=null`, `policy_decision_ref=null` 또는 정책 decision이 `ALLOW`가 아님
- `agent_log_ref=null`이거나 event의 `event_id`·attempt별 `sequence`·start/end `action_id` 규칙을 어김
- `ReproductionPlan.environment_requirements_ref`가 없거나 current exact `EnvironmentRequirements` revision이 아님
- R6가 `EnvironmentRequirements` 또는 `ReproductionPlan`을 생산하거나 R7이 request의 목적·필수 조건·profile을 바꿈
- 실제 VERSION이 `expected | alternatives`에 없는데 자동 fallback을 적용하거나 `MATCH`로 기록함
- EnvironmentRequirements 또는 환경 비교 record에 credential·cookie·token·password 원문을 저장함
- 서로 다른 가설이 같은 writable `container_instance_id`를 공유하거나 상태 변화 뒤 근거 없이 container를 재사용함
- `STATE_CHANGED | CONFIG_CHANGED | STATE_UNCERTAIN` 재생성의 이전·새 environment 연결과 AgentLog event가 없음
- `cleanup_required=true`인데 `cleanup_status=NOT_REQUIRED`, 또는 `false`인데 `cleanup_status`가 `SUCCEEDED | FAILED`임
- `DISPROVED | INCONCLUSIVE | PARTIAL | FAILED | BLOCKED | CANCELLED`에 validated `poc_ref`를 붙이거나, `SUCCEEDED + SUPPORTED`인데 exact `poc_ref`가 없음
- `poc_ref`의 request·plan·recipe·environment·log·candidate·digest·attempt 중 하나라도 결과와 다름
- `plan_issues`에 `OPEN` 항목이 있는데 `SUPPORTED` 또는 validated `poc_ref`를 저장함
- 한 Verification generation에 purpose가 다른 두 번째 request 또는 `DYNAMIC_REPRO` work를 등록함
- PoC 생성·실행 실패를 final `FALSE | HOLD`로 저장하거나 Technical Gate를 호출함
- reference target의 analysis·workspace·commit·hypothesis가 동적 결과와 다르거나, current recipe·환경·log·candidate·PoC·cleanup target의 attempt가 동적 결과와 다름
- 고정된 `stored_data_id + record_id + content_hash` 대신 “latest” 조회로 artifact를 다시 선택함

새 plan·recipe·AgentLog·result-owner·candidate/validated PoC·retry 계약은 관련 record의 새 MAJOR schema로 배포한다. runtime은 이전 MAJOR의 mode·exact step/command·`SandboxStepLog`·Runner/Result Assembler 필드를 추정 변환하지 않고 명시적으로 거절한다.

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

`action_decision_ref.record_id`는 `CALL_TECHNICAL_GATE`를 허가하고 `USED`로 claim한 decision revision을 가리킨다. 실행 결과를 기록한 이후 decision revision의 `outcome_refs`에는 같은 call spec을 실행한 `TECHNICAL_GATE` `LLMInvocationLog`와 현재 review가 각각 한 번 포함되고, log의 `parsed_output_ref.record_id`가 현재 review를 가리켜야 한다. review는 log를 역참조하지 않아 content hash 순환을 만들지 않는다. `verification_result_ref.record_id`와 `cwe_label_ref.record_id`는 필수이며 각각 정확히 한 final `VerificationResult(verdict=TRUE)`와 R5-01이 그 result를 대상으로 만든 current `CWELabel` revision을 가리킨다. `CWELabel.verification_result_ref`는 review의 `verification_result_ref`와 exact match하고 label의 `verification_generation`은 current process state와 같아야 한다. label을 만든 `CWE_LABEL` work는 `SUCCEEDED`이고 유일한 output이 이 `cwe_label_ref`여야 한다. `FALSE | HOLD` 또는 `HypothesisProcessState.status=FAILED`인 가설에는 CWE work, Technical Gate work와 review를 만들 수 없다. runtime은 두 대상의 `record_id`, `workspace_id`, `commit_id`, `hypothesis_id`와 `content_hash`를 확인한다. Verification 또는 CWELabel이 새 revision으로 바뀌면 이전 `TechnicalEvidenceReview`를 재사용할 수 없고 새 CWE 평가와 Gate 호출이 필요하다. Technical review는 `VerificationResult.verdict`나 `CWELabel`을 생성·수정·덮어쓰지 않는다.

`status=ACCEPT`는 `handoff_readiness=READY`, `status=REVISE | REJECT`는 `handoff_readiness=NOT_READY`만 허용한다. `DynamicReproductionResult(status=BLOCKED | FAILED, failure_category=POLICY_BLOCKED)`는 가설 반증이나 Technical `REJECT`가 아니다. 그러나 validated PoC가 없으므로 final `VerificationResult`를 만들거나 Technical Gate를 호출하지 않는다. 정책·외부 설정 수정이 가능하면 같은 동적 work와 Verification을 `BLOCKED`로 유지하고, 복구 불가능하거나 한도를 소진하면 verdict 없이 `FAILED`로 끝낸다. 어떤 경우에도 정책 차단을 가설 `FALSE | HOLD`로 변환하지 않는다.

## 9. PolicyParserResult, PolicyCollectionResult, ProgramPolicyRecord과 RuleScopeImpactReview

공식 프로그램 정책의 파싱·수집 결과, 정규화된 정책 기록과 두 번째 Gate가 정책 범위·규칙·실제 영향을 검토한 결과입니다. Policy Parser만 `PolicyParserResult`를, Policy Collector만 `PolicyCollectionResult`와 수집에 성공한 `ProgramPolicyRecord`를 생산한다. `RULE_SCOPE_GATE`는 이 artifact를 입력으로 읽을 뿐 수집·파싱 결과를 만들거나 수정하지 않는다.

```yaml
PolicyItem:
  policy_item_id: string
  value: string
  description: string
  conditions: [string]
  source_ref: StoredDataRef
  source_locator: string

PolicySourceCheck:
  source_id: string
  source_ref: StoredDataRef
  source_url: string
  publisher: string
  status: VERIFIED | UNVERIFIED
  evidence_refs: [StoredDataRef]
  checked_at: timestamp

PolicyParserResult:
  meta: RecordMeta without hypothesis/attempt
  parser_result_id: string
  parser_name: string
  parser_version: string
  source_ref: StoredDataRef
  parsed_output_ref: StoredDataRef | null
  status: SUCCEEDED | FAILED | INVALID_OUTPUT
  error_ids: [string]
  completed_at: timestamp

PolicyMissingInfo:
  missing_info_id: string
  area: RULE | SCOPE | IMPACT | SOURCE | FRESHNESS | TESTING_RESTRICTION
  blocks_allow: boolean
  description: string
  policy_item_ids: [string]
  evidence_refs: [StoredDataRef]

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
  source_checks: [PolicySourceCheck]
  parser_result_refs: [StoredDataRef]
  freshness_criterion_ref: StoredDataRef | null
  freshness_evidence_refs: [StoredDataRef]
  freshness_valid_until: timestamp | null
  missing_information: [PolicyMissingInfo]
  freshness_warning: string | null

PolicyCollectionResult:
  meta: RecordMeta without hypothesis/attempt
  collection_result_id: string
  program_id: string
  status: FOUND | ABSENT_CONFIRMED | COLLECTION_FAILED
  official_source_refs: [StoredDataRef]
  parser_result_refs: [StoredDataRef]
  policy_record_ref: StoredDataRef | null
  gap_ids: [string]
  error_ids: [string]
  completed_at: timestamp
```

`PolicyItem.policy_item_id`는 한 `ProgramPolicyRecord` 안에서 유일하다. `value`에는 비교할 asset·취약점 분류·제한·기준 값을, `conditions`에는 그 값이 적용되는 조건을 넣는다. `source_ref`는 `ProgramPolicyRecord.source_refs`에도 포함된 공식 자료를 가리키고 `source_locator`는 문서 안에서 해당 항목을 다시 찾을 수 있는 절·anchor·페이지 정보다. 출처와 연결되지 않은 항목은 공식 정책 사실로 사용하지 않고 `PolicyMissingInfo`에 남긴다.

`PolicySourceCheck`는 source URL 문자열만 믿지 않고 공식 게시자와 원문 reference를 확인한 결과다. `source_id`는 한 정책 record 안에서 유일하고 `source_ref`는 `source_refs`에 정확히 한 번 포함된다. `source_checks[].source_ref` 집합과 `source_refs`는 set-equal해야 하며 `freshness_status=CURRENT`인 record는 모든 source check가 `VERIFIED`이고 각 check에 하나 이상의 확인 근거가 있어야 한다. 검색 snippet, 모델 기억과 비공식 요약은 `VERIFIED` 출처가 아니다.

`PolicyParserResult`는 공식 원문을 어떤 parser 버전으로 읽었는지 기록한다. `SUCCEEDED`이면 `parsed_output_ref`가 필수이고 `error_ids=[]`, `FAILED | INVALID_OUTPUT`이면 하나 이상의 `error_ids`가 필요하다. parser 결과를 합쳐 정책 record를 만들 때 `parser_result_refs`는 사용한 성공 결과만 가리키고 각 `source_ref`는 `ProgramPolicyRecord.source_refs`에 포함되어야 한다. 원문·parser 결과·구조화 정책을 “최신값”으로 다시 찾지 않고 exact reference로 연결한다.

`PolicyCollectionResult`는 “정책을 찾음”, “공식 출처를 확인했지만 정책이 없음을 확인함”, “수집 실행이 실패함”을 구분한다. `FOUND`이면 `policy_record_ref`가 필수이고 `error_ids=[]`다. `ABSENT_CONFIRMED`이면 `policy_record_ref=null`, 하나 이상의 공식 출처와 `gap_ids`가 필요하고 `error_ids=[]`다. `COLLECTION_FAILED`이면 `policy_record_ref=null`과 하나 이상의 `error_ids`가 필요하며 Rule Scope Gate work와 review를 만들지 않는다. `FOUND | ABSENT_CONFIRMED`의 `parser_result_refs`는 하나 이상이고 모두 `status=SUCCEEDED`인 exact parser 결과를 가리킨다. `FOUND`에서는 collection의 `official_source_refs`, `parser_result_refs`가 정책 record의 `source_refs`, `parser_result_refs`와 각각 set-equal해야 한다. `COLLECTION_FAILED`의 두 reference 목록은 실패 전 실제로 확인·실행한 범위만 담으며 비어 있을 수 있다. 수집 실패를 `ABSENT_CONFIRMED`로 바꾸지 않는다.

`freshness_status=CURRENT`이면 `freshness_criterion_ref`, 하나 이상의 `freshness_evidence_refs`, `freshness_checked_at`과 미래의 `freshness_valid_until`이 모두 필수다. freshness 기준값과 재수집 주기는 R8이 승인한 versioned 설정만 사용한다. 기준을 넘었으면 `STALE`, 확인 자체가 실패했거나 기준을 적용할 수 없으면 `UNVERIFIED`다. 두 상태 모두 `freshness_warning` 또는 `PolicyMissingInfo(area=FRESHNESS, blocks_allow=true)`에 이유가 있어야 하며 Gate의 `PASS | ALLOW` 근거로 사용할 수 없다. Runtime Validator는 `CALL_RULE_SCOPE_GATE` decision 생성 시점과 provider 호출 직전에 `freshness_valid_until`을 다시 확인한다. Reporter도 action 승인과 호출 직전에 같은 정책 revision이 여전히 CURRENT인지 확인하고 만료되면 과거 Gate·draft를 재사용하지 않는다. 기준 설정의 의미·임곗값·재수집 운영은 R8, 정책 해석은 R5, exact field와 만료 차단은 R4 책임이다.

`COLLECTION_FAILED`에서는 `RULE_SCOPE_GATE` work를 등록·호출하지 않고 `RuleScopeImpactReview`를 생성하지 않으며, 이를 `UNCERTAIN + DENY`로 변환하지 않는다.

`program_id`는 내부 Program Catalog가 발급한 전역 ID다. `program_namespace`는 외부 플랫폼이나 catalog 출처를 나타내며, `external_program_id`는 그 출처 안의 프로그램 ID다. 외부 프로그램의 유일 키는 `(program_namespace, external_program_id)`이고, 내부 catalog는 이 쌍을 하나의 `program_id`에 매핑한다. namespace가 다른 같은 외부 ID를 자동 병합하지 않는다.

`ProgramPolicyRecord`, `PolicyParserResult`, `PolicyCollectionResult`는 각각 `program_policy_record`, `policy_parser_result`, `policy_collection_result` data kind로 저장한다. 새 parser·수집 계약은 schema `1.x`, 기존 `ProgramPolicyRecord`의 source·freshness·missing-information 의미 변경은 새 MAJOR schema에서 시작한다. 이전 MAJOR record에 확인 근거나 만료 시각을 추정해 채우지 않으며 새 Gate 입력으로 자동 승격하지 않는다.

```yaml
RuleScopeImpactReview:
  meta: RecordMeta
  action_decision_ref: StoredDataRef
  verification_result_ref: StoredDataRef
  technical_review_ref: StoredDataRef
  cwe_label_ref: StoredDataRef
  policy_collection_result_ref: StoredDataRef
  policy_record_ref: StoredDataRef | null
  review_status: PASS | FAIL | UNCERTAIN
  rule_compliance: PASS | FAIL | UNCERTAIN
  scope_compliance: PASS | FAIL | UNCERTAIN
  testing_restriction_compliance: PASS | FAIL | UNCERTAIN
  security_impact: SUFFICIENT | INSUFFICIENT | UNCERTAIN
  report_permission: ALLOW | DENY
  evidence_links: [RuleScopeEvidenceLink]
  reasons: [string]
  missing_information: [PolicyMissingInfo]

RuleScopeEvidenceLink:
  link_id: string
  area: RULE | SCOPE | IMPACT | TESTING_RESTRICTION
  policy_item_ids: [string]
  evidence_refs: [StoredDataRef]
```

`action_decision_ref.record_id`는 `CALL_RULE_SCOPE_GATE`를 허가하고 `USED`로 claim한 decision revision을 가리킨다. 이후 decision revision의 `outcome_refs`에는 같은 call spec을 실행한 `RULE_SCOPE_GATE` log와 현재 review가 각각 한 번 포함되고, log의 `parsed_output_ref.record_id`가 현재 review를 가리켜야 한다. review는 log를 역참조하지 않는다. `verification_result_ref.record_id`, `technical_review_ref.record_id`, `cwe_label_ref.record_id`, `policy_collection_result_ref.record_id`는 필수다. collection status는 `FOUND | ABSENT_CONFIRMED`만 허용한다. `FOUND`이면 `policy_record_ref`가 collection result와 같은 exact `ProgramPolicyRecord`를 가리키고, `ABSENT_CONFIRMED`이면 null이다. `COLLECTION_FAILED`인 collection result를 가리키는 review는 존재할 수 없다. `technical_review_ref` 대상은 `status=ACCEPT`이고, 그 대상의 Verification과 CWELabel reference `record_id`는 Rule Scope review가 직접 가리키는 두 `record_id`와 각각 같아야 한다. runtime은 각 reference의 `workspace_id`, `commit_id`, `content_hash`가 실제 대상 record와 일치하는지 확인한다. 어느 입력 revision이든 바뀌면 이전 review를 재사용하지 않는다.

`RuleScopeEvidenceLink`는 Gate의 결론을 실제 정책 항목과 근거에 연결한다. `PASS | FAIL | SUFFICIENT | INSUFFICIENT`인 각 판단 영역은 같은 area의 `RuleScopeEvidenceLink`를 하나 이상 가져야 한다. 각 link의 `link_id`는 review 안에서 유일하고, `policy_item_ids`는 exact `ProgramPolicyRecord`에 존재하며, `evidence_refs`는 실제 판단에 사용한 코드·동적·정책 근거를 하나 이상 가리킨다. `testing_restriction_compliance=PASS | FAIL`이면 `area=TESTING_RESTRICTION` link가 하나 이상 필요하고, `UNCERTAIN`이면 같은 area의 `PolicyMissingInfo`가 하나 이상 필요하다. link에는 판정값이 없으므로 link 존재만으로 위반 여부를 추정하지 않고 반드시 전용 판정을 읽는다. Runtime Validator는 ID와 reference의 존재·중복·exact revision을 검사하고 Gate가 낸 의미 판단을 대신하지 않는다.

`PolicyMissingInfo`는 단순 문자열 대신 어느 판단 영역이 왜 비었는지 기록한다. `UNCERTAIN`인 각 판단 영역은 대응하는 missing item을 하나 이상 가져야 한다. `policy_item_ids`와 `evidence_refs`는 확인 가능한 범위에서 채우고, 정책 부재처럼 항목 ID가 없는 경우에는 빈 목록과 공식 출처 근거를 사용한다. `blocks_allow=true`인 `PolicyMissingInfo`가 하나라도 있으면 `report_permission=ALLOW`를 저장하지 않는다.

`PolicyCollectionResult.status=ABSENT_CONFIRMED`이면 `policy_record_ref=null`이고 `rule_compliance`, `testing_restriction_compliance`, `scope_compliance`, `review_status`는 `UNCERTAIN`, permission은 `DENY`다. `COLLECTION_FAILED`이면 Rule Scope Gate work·호출·`RuleScopeImpactReview` 자체를 만들지 않고 정책 수집 work를 실패 또는 대기 상태로 남긴다. `FOUND`라도 핵심 출처가 누락되거나 정책이 `STALE | UNVERIFIED`이면 Rule·testing restriction·Scope·review는 `UNCERTAIN`, permission은 `DENY`이며 누락·최신성 문제를 구조화해 보존한다. 이 상태에서 `PASS | ALLOW`를 반환하거나 수집 실패를 정책 부재 review로 바꾸는 출력은 invalid다.

`RuleScopeImpactReview.testing_restriction_compliance`, `PrimitiveAdmissionDecision`과 `Primitive.admission_decision_ref`는 새 필수 계약이므로 각각 새 MAJOR schema에서 사용한다. 이전 MAJOR review의 문자열 이유, `rule_compliance` 또는 `TESTING_RESTRICTION` link 존재만으로 전용 판정을 추정하지 않는다. 이전 Primitive에 current decision을 사후 추정해 채우거나 새 Chaining 입력으로 자동 승격하지 않고 감사 이력으로만 보존한다.

Rule·Scope·Impact 판단은 별도 condition/projection 또는 execution-fact schema를 만들지 않고 current final `VerificationResult`의 canonical evidence와 exact transitive reference closure를 직접 소비한다. 동적 사실을 사용할 때에는 `dynamic_result_ref`가 고정한 current generation·same-attempt artifact와 `AgentLogEvent` 연결만 인정하며, 다른 revision·generation·attempt의 artifact나 stale event를 섞지 않는다. 실행되지 않았거나 policy block·environment precheck stop으로 생성되지 않은 artifact는 요구하지 않는다. `PolicyMissingInfo`는 이 closure와 정책 provenance만으로 판단할 수 없는 사항을 구조화하며, Gate가 새로운 Verification 사실이나 child-impact 연결을 만들지 않는다.

`ABSENT_CONFIRMED`이거나 `ProgramPolicyRecord`의 핵심 출처가 누락되면 Gate를 실제 호출할 수 있는 입력 상태에서 `UNCERTAIN + DENY`다. `freshness_status=STALE | UNVERIFIED`이면 `rule_compliance`, `scope_compliance`, `testing_restriction_compliance`, `review_status`는 `UNCERTAIN`, permission은 `DENY`다. 누락은 구조화된 `missing_information`과 관련 provenance로 설명한다. 이 상태에서 Reporter용 `PASS | ALLOW`를 반환하면 invalid지만 R4 admission runtime은 `testing_restriction_compliance=UNCERTAIN`을 확정 위반으로 바꾸지 않고 `ALLOW`로 매핑한다. 반면 `COLLECTION_FAILED`는 이 review 경로에 들어오지 않으며 review 자체가 없다.

## 10. LLM invocation records

각 LLM 호출의 요청, 응답, 모델·세션 정보, 사용량과 오류를 다시 확인할 수 있게 남기는 기록입니다.

```yaml
LLMCallSpec:
  meta: RecordMeta
  llm_call_id: string
  agent_role: HYPOTHESIS | VERIFICATION | PRO | CON | CWE_LABELING | CHAINING | TECHNICAL_GATE | RULE_SCOPE_GATE | REPORTER | R7_AGENT
  provider_profile_ref: StoredDataRef
  model: string
  session_policy: NEW | RESUME | AUTO
  parent_session_ref: string | null
  context_refs: [StoredDataRef]
  prompt_template_version: string
  prompt_payload_ref: StoredDataRef
  output_schema: string
  token_budget: integer | null
  timeout_ms: integer

LLMInvocationRequest:
  meta: RecordMeta
  llm_call_id: string
  action_decision_ref: StoredDataRef
  call_spec_ref: StoredDataRef
  agent_role: HYPOTHESIS | VERIFICATION | PRO | CON | CWE_LABELING | CHAINING | TECHNICAL_GATE | RULE_SCOPE_GATE | REPORTER | R7_AGENT
  provider_profile_ref: StoredDataRef
  model: string
  session_policy: NEW | RESUME | AUTO
  parent_session_ref: string | null
  context_refs: [StoredDataRef]
  prompt_template_version: string
  prompt_payload_ref: StoredDataRef
  output_schema: string
  token_budget: integer | null
  timeout_ms: integer
```

`call_spec_ref.record_id`는 수정할 수 없는 exact `LLMCallSpec` revision을 가리킨다. `action_decision_ref.record_id`는 일반 Agent이면 `CALL_LLM`, Gate이면 해당 `CALL_TECHNICAL_GATE | CALL_RULE_SCOPE_GATE`, Reporter이면 `CREATE_REPORT_DRAFT` action을 `ALLOW`하고 `USED`로 claim한 exact decision revision을 가리킨다. 그 action의 `llm_call_spec_ref.record_id`는 `call_spec_ref.record_id`와 같아야 한다. request의 `llm_call_id`, role, provider profile, model, session, parent session, context, prompt template/payload, output schema, token budget 계획값과 timeout은 spec과 field-by-field exact equality를 만족해야 하며 runtime은 이 equality를 provider 호출 직전에 다시 확인한다. 다르면 decision을 `EXPIRED`로 바꾸고 호출하지 않는다. 이 equality는 승인된 요청의 변조를 막는 `REVISION` 검사이며 token 사용량 상한 검사가 아니다. `timeout_ms`는 monotonic clock으로 계산하는 0보다 큰 밀리초 실행 예산이다.

`LLMCallSpec.token_budget`과 `LLMInvocationRequest.token_budget`은 provider 호출에 예상되는 사용량을 기록하는 0 이상의 선택 계획값이다. 값을 정하지 않았으면 `null`이며, 실제 사용량이 계획값을 넘거나 provider가 usage를 제공하지 않아도 token만을 이유로 `ActionCheck.BUDGET=FAIL`, `DENY` 또는 `BUDGET_EXCEEDED`를 만들지 않는다. 실제 usage는 `LLMInvocationLog`와 `AnalysisRunResult.resources`에 출처와 함께 기록하고 제공되지 않으면 `null`로 둔다. 이 nullable 의미로 바뀐 두 계약은 새 MAJOR schema로 배포하고 이전 값을 강제 상한으로 해석하지 않는다.

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

`LLMInvocationLog.action_decision_ref`와 `call_spec_ref`는 request와 같아야 한다. log의 role·profile·model·session·prompt template·context는 request와 spec에서 바뀌지 않으며 실제 adapter가 선택한 값과 차이가 있으면 호출을 실패 처리한다. log의 `parsed_output_ref.record_id`는 역할이 만든 exact structured output revision을 가리킨다. Pro/Con은 각각 exact `EvidenceAgentResult`, R5-01 `CWE_LABELING`은 exact `CWELabel`, Gate는 exact Gate review, Reporter는 exact `ReportDraft`를 가리킨다. `CWELabel.llm_call_id`는 바로 이 성공한 CWE 호출의 `llm_call_id`와 같아야 한다. output은 log를 역참조하지 않는다. 해당 action decision의 후속 revision `outcome_refs`에 log와 final output을 각각 한 번 포함해 두 record를 같은 실행에 연결한다.

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
  restrictions: [Restriction]
  limitations: [string]
  unresolved_conditions: [string]
  redaction_status: PASSED
  draft_status: DRAFTED
```

`action_decision_ref.record_id`는 `CREATE_REPORT_DRAFT` action의 report 조건, exact LLM call spec과 redaction을 모두 통과한 `USED` decision revision을 가리킨다. 이후 decision revision의 `outcome_refs`에는 같은 call spec을 실행한 `REPORTER` log와 현재 draft가 각각 한 번 포함되고, log의 `parsed_output_ref.record_id`가 현재 draft를 가리켜야 한다. draft는 log를 역참조하지 않는다. `finding_ref`, `verification_result_ref`, `technical_review_ref`, `rule_scope_impact_review_ref`, `cwe_label_ref`와 `policy_record_ref`는 저장된 record를 가리므로 각 `StoredDataRef.record_id`가 필수다. Reporter runtime은 다음 연결을 모두 확인하고 하나라도 다르면 초안을 만들지 않는다.

- Technical review와 Rule Scope review가 모두 ReportDraft의 같은 Verification `record_id`를 가리킨다.
- Rule Scope review의 `technical_review_ref.record_id`가 ReportDraft의 `technical_review_ref.record_id`와 같다.
- Technical review와 Rule Scope review가 모두 ReportDraft의 같은 CWELabel `record_id`를 가리킨다.
- 그 CWELabel의 `verification_result_ref.record_id`가 ReportDraft와 두 Gate가 공통으로 가리킨 Verification `record_id`와 같다.
- Rule Scope review의 `policy_record_ref.record_id`가 ReportDraft의 `policy_record_ref.record_id`와 같다.
- Finding이 ReportDraft의 같은 Verification, CWELabel, 두 Gate revision을 근거로 하며 current 결과다.
- 각 reference의 `workspace_id`, `commit_id`, `content_hash`가 실제 대상 record와 일치하고, 가설별 대상 record의 `meta.hypothesis_id`가 ReportDraft와 같다. CWELabel이 새 revision으로 바뀌면 두 Gate와 ReportDraft를 모두 새 revision 기준으로 다시 생성한다.
- `dynamic_result_ref`와 `poc_ref`는 Verification의 같은 이름 필드와 정확히 같아야 한다. 값이 있으면 같은 분석·가설의 COMMITTED 동적 결과와 exact PoC를 가리키고, 값이 없으면 동적 실행이나 PoC 성공을 주장하지 않는다.
- `restrictions`는 Verification의 `restriction_id`와 전체 `Restriction` 객체를 그대로 보존하고, `unresolved_conditions`도 빠짐없이 보존한다. `limitations`는 정적·동적 검증과 두 Gate에 남은 한계를 빠짐없이 보존한다. 해당 값이 없을 때만 빈 배열을 사용한다.
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
  hypothesis_duplicate_review_refs: [StoredDataRef]
  failed_hypothesis_count: integer
  verdict_counts: map
  gate_counts: map
  finding_refs: [StoredDataRef]
  verification_refs: [StoredDataRef]
  cwe_label_refs: [StoredDataRef]
  technical_review_refs: [StoredDataRef]
  rule_scope_review_refs: [StoredDataRef]
  policy_collection_result_refs: [StoredDataRef]
  policy_parser_result_refs: [StoredDataRef]
  policy_record_refs: [StoredDataRef]
  dynamic_request_refs: [StoredDataRef]
  dynamic_result_refs: [StoredDataRef]
  environment_recipe_refs: [StoredDataRef]
  sandbox_environment_refs: [StoredDataRef]
  agent_log_refs: [StoredDataRef]
  sandbox_policy_decision_refs: [StoredDataRef]
  cleanup_result_refs: [StoredDataRef]
  primitive_and_chaining_refs: [StoredDataRef]
  poc_candidate_refs: [StoredDataRef]
  poc_refs: [StoredDataRef]
  report_draft_refs: [StoredDataRef]
  llm_invocation_log_refs: [StoredDataRef]
  action_decision_refs: [RunStoredDataRef | StoredDataRef]
  work_state_refs: [RunStoredDataRef | StoredDataRef]
  work_attempt_refs: [RunStoredDataRef | StoredDataRef]
  transition_commit_refs: [RunStoredDataRef | StoredDataRef]
  eval_config_refs: [RunStoredDataRef | StoredDataRef]
  stop_reasons: [string]
  errors: [AnalysisError]
  gaps: [DataGap]
  resources: map
  started_at: timestamp
  finished_at: timestamp
  elapsed_ms: integer
  debug_trace_ref: RunStoredDataRef
```

Reporter 호출은 `TRUE + Technical ACCEPT + Rule Scope Impact review_status PASS + rule_compliance PASS + testing_restriction_compliance PASS + scope_compliance PASS + security_impact SUFFICIENT + ALLOW`인 경우만 유효하다.

Reporter가 current `ReportDraft`를 저장하고 해당 `REPORT_DRAFT` work를 종료한 뒤, 신뢰 runtime은 모든 current 결과와 로그를 `AnalysisRunResult`에 묶어 `AnalysisRunState`와 atomic하게 확정한다. `ReportDraft`는 마지막 Agent 산출물이고 `AnalysisRunResult` 확정은 새 판단을 생성하지 않는 저장 작업이다. 그 다음 Agent 자동화는 종료된다. ReportDraft 이후의 검토·수정·제출·공개는 Agent 자동화 밖에서 사람이 수행한다. 이 외부 과정에는 공통 schema, action, 상태 또는 자동 공개 권한을 정의하지 않는다.

`AnalysisRunResult.policy_collection_result_refs`에는 분석에서 확정한 모든 정책 수집 결과를, `policy_parser_result_refs`에는 그 수집 시도에서 실제 사용한 parser 결과를 중복 없이 넣는다. `policy_record_refs`는 `FOUND` collection result가 exact하게 가리킨 정책 record만 포함한다. `ABSENT_CONFIRMED | COLLECTION_FAILED`에 대응하는 가짜 정책 record를 만들거나 누락된 수집 결과를 정책 record 유무만으로 추정하지 않는다. 세 목록의 reference는 해당 `POLICY_FETCH` work output과 COMMITTED transition에서 복원할 수 있어야 한다. 두 목록 추가는 `AnalysisRunResult`의 새 필수 필드이므로 새 MAJOR schema에서만 사용한다. 이전 결과에 current 수집·parser reference를 추정해 넣지 않는다.

`AnalysisRunResult.primitive_and_chaining_refs`에는 current `PrimitiveAdmissionDecision`, current `PrimitiveIndexState`, 그 index가 허용한 Primitive와 current ChainingResult만 넣는다. `ChainingResult.source_admission_refs` 중 하나라도 더 이상 current ALLOW가 아니면 해당 ChainingResult와 그 `source_primitive_match_id`에서 파생된 Primitive·Finding·ReportDraft를 current 목록에 넣지 않는다. 이 검사가 끝나지 않았으면 run을 `COMPLETE`로 확정하지 않는다. 제외된 과거 record와 verdict는 append-only 감사 이력에 보존하며 `FALSE | HOLD`로 바꾸지 않는다.

`AnalysisRunResult.purpose=PRODUCTION`이면 `eval_config_refs=[]`이고 평가 설정을 생산 판정·Gate·Primitive admission·Reporter의 입력으로 사용하지 않는다. `purpose=EVALUATION`이면 runtime은 분석 시작 시 평가 장면 표, 지표·한도 표, 평가 corpus·사람 정답·채점 방식, provider·model·session 설정의 immutable versioned reference를 `AnalysisRunState.eval_config_refs`에 고정한다. 각 평가 action의 `ActionDecision.checked_config_refs`에는 그 action이 실제 사용한 설정만 넣고 모두 이 고정 집합의 원소여야 한다. 분석 종료 시 `AnalysisRunResult.eval_config_refs`는 시작 상태의 전체 집합과 중복 없이 set-equal해야 하며 빠진 값·추가 값·이름만 같은 다른 revision을 허용하지 않는다.

두 `purpose=EVALUATION` 결과는 `eval_config_refs`가 exact reference 기준으로 set-equal할 때만 직접 비교한다. 어느 한쪽이 비어 있거나 `stored_data_id`·`data_kind`·`record_id`·`content_hash`가 다르면 다른 설정의 결과로 취급한다. 이 목록과 오프라인 사람 정답은 평가용 provenance일 뿐 Gate·Primitive·Reporter 입력이나 자동화된 Human Review 결정이 아니다. `eval_config_refs` 추가는 `AnalysisRunResult`의 새 필수 필드이므로 새 MAJOR schema에서만 사용하고 과거 결과에 빈 목록이나 current 설정을 추정해 넣지 않는다.

`AnalysisRunResult.cwe_label_refs`에는 각 current final TRUE Verification에 대응하는 current `CWELabel`만 가설별로 하나씩 넣는다. 각 reference는 성공한 current `CWE_LABEL` work의 유일한 output과 같아야 하며, label의 `verification_result_ref`는 `verification_refs`에 포함된 같은 가설의 current Verification exact revision과 일치해야 한다. 과거 `CWELabel` revision은 append-only 저장소와 work·invocation 이력으로 보존하지만 current 결과 목록에는 섞지 않는다. CWE labeling work가 `BLOCKED | FAILED | CANCELLED`이면 그 가설의 label을 목록에 넣지 않고 Technical Gate·Finding·ReportDraft도 만들지 않으며, Verification verdict를 `FALSE | HOLD`로 바꾸지 않는다.

`hypothesis_counts`는 최소한 proposal 전체, 등록, `DUPLICATE`, `INVALID_OUTPUT`, `CANCELLED`, duplicate `UNIQUE | UNCERTAIN`, `CHECK_FAILED`, `INVALID_DUPLICATE_TARGET` 수를 분리한다. 분석 종료 시 proposal 전체는 등록·DUPLICATE·INVALID_OUTPUT·CANCELLED 수의 합과 같아야 한다. `hypothesis_duplicate_review_refs`는 final `ProposalProcessState.duplicate_review_ref` 중 non-null 값의 중복 없는 집합과 set-equal해야 하며 모두 같은 analysis·workspace·commit의 COMMITTED `HypothesisDuplicateReview` exact revision을 가리킨다. 호출·형식·유효하지 않은 대상 때문에 review가 저장되지 않은 fail-open 경로는 LLM invocation·오류 reference와 registration reason으로 추적한다.

`failed_hypothesis_count`는 종료 시점에 `HypothesisProcessState.status=FAILED`인 가설 수와 정확히 같아야 하며 이 가설은 current `verdict_counts`에 포함하지 않는다. 최초 검증에서 실패했다면 current final `VerificationResult` 자체가 없다. Technical `REVISE` 뒤 보완 검증이 실패한 경우에는 이전 Verification·Gate revision을 `verification_refs`와 `technical_review_refs`에 감사 기록으로 보존할 수 있지만 superseded history일 뿐 current verdict·Gate·Primitive·Reporter 입력으로 집계하지 않는다. 연결된 실패 work·attempt·transition, `errors`와 `gaps`로 원인을 추적한다. 실패 가설이 하나라도 있으면 분석 전체를 성공으로 숨기지 않으며 완료된 다른 가설이 있더라도 `AnalysisRunResult.status=PARTIAL`로 기록한다.

## 구현 단계에서 결정할 것

serialization format, schema language/versioning, database/index, Primitive vocabulary, policy source collector, structured output 합격 기준과 정량 limit은 구현 전 ADR과 평가 corpus로 확정한다. 이 설계의 field 목록을 곧바로 모든 서비스의 영구 API로 간주하지 않는다.
