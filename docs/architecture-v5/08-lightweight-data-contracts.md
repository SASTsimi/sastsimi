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
  commit_id: string
  status: READY | FAILED | REMOVED
  created_at: timestamp
```

실제 로컬 절대 경로는 runtime 내부에서만 관리하며 Agent, Finding과 보고서에 전달하지 않는다.
`workspace_id`는 재사용하지 않는다. 로컬 폴더를 정리하면 `status=REMOVED`로 바꾸되, `workspace_id`와 `repository_url`·`commit_id`의 연결 정보는 결과 추적을 위해 보존한다.

```yaml
RecordMeta:
  record_id: string
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

모든 핵심 결과는 `meta: RecordMeta`를 갖는다. `analysis_id`, `workspace_id`와 `commit_id`는 필수다. runtime은 `workspace_id`가 가리키는 `CodeWorkspace.commit_id`와 `RecordMeta.commit_id`가 같은지 확인한다. 가설별 결과는 `hypothesis_id`, 재시도 가능한 작업은 `attempt_id`가 필수다. 첫 결과의 `revision_number`는 `1`, `previous_record_id`는 `null`이다. 결과를 수정할 때 덮어쓰지 않고 새 `record_id`와 증가한 revision을 만든다.

### 식별자 생성·저장·참조 기준

ID 값은 내부 의미를 넣지 않는 불투명 문자열이다. `ana_`, `ws_`, `hyp_` 같은 접두사는 로그 가독성을 위한 예시이며, 프로그램은 접두사에서 상태·소유자·시간을 추론하지 않는다.

| 식별자 | 누가 만드나요? | 어디까지 유일한가요? | 어디에 저장하나요? | 변경·재사용 규칙 |
|---|---|---|---|---|
| `analysis_id` | Orchestration runtime | 전체 시스템 | `runs`와 모든 `RecordMeta` | 변경·재사용 금지 |
| `workspace_id` | Repository Loader | 전체 시스템 | `CodeWorkspace`, `runs`, 코드 근거 record | 변경·재사용 금지 |
| `stored_data_id` | 결과 저장 계층 | 전체 시스템 | 해당 논리 저장 영역과 `StoredDataRef` | 변경·재사용 금지 |
| `record_id` | record 저장 직전 runtime | 전체 시스템 | 각 `RecordMeta` | revision마다 새 값 |
| `hypothesis_id` | proposal 검증을 통과시킨 runtime | 전체 시스템 | `hypotheses`와 가설별 `RecordMeta` | 변경·재사용 금지 |
| `attempt_id` | 재시도 가능한 작업을 시작하는 runtime | 전체 시스템 | 해당 결과와 debug trace | 시도마다 새 값 |
| `llm_call_id` | LLM 호출 직전 Agent Runtime | 전체 시스템 | `invocations` | retry·failover마다 새 값 |
| `revision_number` | 새 revision을 저장하는 runtime | 같은 논리 결과 | `RecordMeta` | 1부터 1씩 증가 |

로컬 폴더를 정리해도 `workspace_id → repository_url + commit_id` 연결 정보는 삭제하지 않는다. `workspace_id`, `hypothesis_id`, `attempt_id`와 `llm_call_id`는 서로 대신 사용할 수 없으며, 소비자는 필요한 ID를 `RecordMeta`와 전문 record 양쪽에서 검사한다.

### 공통 시간 규칙

- 모든 시각은 UTC RFC 3339 형식이다. 예: `2026-08-28T12:34:56.123Z`.
- `created_at`은 해당 record가 처음 저장된 불변 시각이다.
- 실행 작업은 `started_at`과 `finished_at`을 사용한다. 아직 끝나지 않았으면 `finished_at: null`이다.
- `elapsed_ms`는 monotonic clock으로 계산한 0 이상의 밀리초다. 벽시계 시각 차이를 timeout이나 비용 계산의 정본으로 사용하지 않는다.
- 새 revision은 새 `created_at`을 갖고 이전 record의 시각을 덮어쓰지 않는다.

### 상태 계층과 소유 주체

같은 `status`라는 필드명을 쓰더라도 record 종류가 다르면 의미가 다르다. runtime은 아래 계층을 하나의 enum으로 합치거나 한 계층의 실패를 다른 계층의 판정으로 변환하지 않는다.

| 상태 계층 | 허용 값 | 상태를 만드는 주체 | 반드시 분리할 의미 |
|---|---|---|---|
| 분석 실행 | `RUNNING | COMPLETE | PARTIAL | FAILED | CANCELLED` | Orchestration runtime | 가설 verdict가 아님 |
| 가설 처리 | `PROPOSED | SCHEMA_VALID | ASSIGNED | VERIFYING | TERMINAL | INVALID_OUTPUT | CANCELLED` | Orchestration runtime | `TRUE | FALSE | HOLD`와 분리 |
| 기술 판정 | `TRUE | FALSE | HOLD` | Verification Agent | 오류·정보 부족 상태와 분리 |
| 동적 재현 | `NOT_REQUESTED | RUNNING | SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED` | Sandbox runtime | `FAILED`만으로 가설 반증 금지 |
| LLM 호출 | `SUCCEEDED | FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED | CANCELLED` | Agent Runtime과 provider adapter | 가설 verdict로 변환 금지 |
| 기술 Gate | `ACCEPT | REVISE | REJECT` | Technical Evidence Gate Agent | Verification verdict를 변경하지 않음 |
| 정책·영향 Gate | `PASS | FAIL | UNCERTAIN`과 `ALLOW | DENY` | Rule Scope Impact Gate Agent | 기술 판정과 분리 |
| 보고서 초안 | `NOT_REQUESTED | DRAFTED | FAILED` | Reporter runtime | 공개 승인 상태가 아님 |
| 사람 검토 | `PENDING | APPROVED | REJECTED` | Human Reviewer | 최종 공개 여부만 사람이 결정 |

```yaml
CodeLocation:
  workspace_id: string
  commit_id: string
  file_path: string
  start_line: integer
  start_column: integer
  end_line: integer
  end_column: integer

CodeSymbol:
  symbol_id: string
  symbol_kind: FILE | CLASS | FUNCTION | METHOD | VARIABLE | ROUTE
  name: string
  location: CodeLocation

StoredDataRef:
  stored_data_id: string
  data_kind: string
  content_hash: string
  workspace_id: string
  commit_id: string

DataGap:
  gap_id: string
  stage: CLONE | STATIC_ANALYSIS | CONTEXT | DYNAMIC | POLICY
  reason: MISSING | FAILED | TRUNCATED | UNSUPPORTED | BLOCKED | TIMEOUT
  description: string
  affected_locations: [CodeLocation]
  retryable: boolean

AnalysisError:
  error_id: string
  stage: REPOSITORY | STATIC_ANALYSIS | AGENT | PROVIDER | SANDBOX | POLICY | GATE | REPORT
  code: string
  message: string
  retryable: boolean
  related_record_ids: [string]
  created_at: timestamp
```

`file_path`는 `workspace_root` 기준 상대 경로이고 줄과 열은 1부터 시작한다. `symbol_id`는 같은 `workspace_id` 안에서 유일하다. `StoredDataRef`는 내부 저장 경로 대신 결과 번호와 내용 hash만 전달한다. `DataGap`은 분석하지 못한 범위이고 `AnalysisError`는 실행 중 발생한 오류다. 둘 다 취약점 `FALSE`를 뜻하지 않는다.

## 1. StaticFactBundle

정적분석 계층이 만들고 가설 생성·검증 단계가 사용하는 코드 사실 묶음입니다.

```yaml
StaticFactBundle:
  meta: RecordMeta without hypothesis/attempt
  entities: [CodeSymbol]
  locations: [CodeLocation]
  source_candidates: [FactRef]
  sink_candidates: [FactRef]
  call_edges: [RelationRef]
  data_flow_candidates: [RelationRef]
  auth_and_permission_checks: [FactRef]
  route_bindings: [RelationRef]
  tool_observations: [ToolObservationRef]
  gaps: [DataGap]
```

SAST severity와 tool message는 verdict가 아니다.

## 2. HypothesisProposal과 VulnerabilityHypothesis

가설 생성 Agent가 제안한 후보와, 프로그램이 형식을 확인한 뒤 검증 대상으로 등록한 가설을 구분합니다.

```yaml
HypothesisProposal:
  proposal_id: string
  meta: RecordMeta
  proposal_state: HYPOTHESIS_ONLY
  assertion_mode: NON_FINAL
  origin: INITIAL | RESEARCH | CHAINING
  vulnerability_type_candidates: [string]
  target_entities: [CodeSymbol]
  target_locations: [CodeLocation]
  suspected_path: [RelationOrCodeLocation]
  observed_facts: [FactRef]
  assumptions: [string]
  restrictions: [string]
  missing_information: [string]
  falsification_questions: [string]
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
  lifecycle_state: SCHEMA_VALID | ASSIGNED | VERIFYING | TERMINAL | CANCELLED
  statement: string
  target_entities: [CodeSymbol]
  target_locations: [CodeLocation]
  suspected_path: [RelationOrCodeLocation]
  falsification_questions: [string]
  required_validation: [string]
```

초기 가설의 `root_hypothesis_id`는 자기 `hypothesis_id`다. 자식 가설은 직접 원인이 된 부모만 `parent_hypothesis_ids`에 넣고, 부모 중 가장 큰 `chain_depth + 1`을 사용한다. 부모와 자식의 lifecycle·verdict는 독립이며 `TRUE + TRUE` 결합도 새 `hypothesis_id`를 만든다. 금지된 확정 assertion, 잘못된 enum, 필수 field/location 누락은 제한된 repair retry 뒤 `INVALID_OUTPUT`이다. confidence는 scheduling hint이지 verdict가 아니다.

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
  max_depth: integer
  token_budget: integer
```

```yaml
CodeContextResponse:
  code_request_id: string
  meta: RecordMeta
  entities: [CodeSymbol]
  locations: [CodeLocation]
  code_fragment_refs: [StoredDataRef]
  discovered_relations: [RelationRef]
  gaps: [DataGap]
  truncated: boolean
  consumed_token_estimate: integer | null
```

요청과 응답의 `meta.workspace_id` 또는 `meta.commit_id`가 다르거나, 이 값이 `CodeWorkspace`와 일치하지 않으면 `WORKSPACE_MISMATCH`로 기록하고 근거에 사용하지 않는다. empty/truncated/gap은 안전함 또는 `FALSE`를 뜻하지 않는다.

## 4. VerificationResult

검증 Agent가 찬성·반대·동적 근거를 모아 `TRUE / FALSE / HOLD` 판정과 남은 조건을 기록하는 결과입니다.

```yaml
VerificationResult:
  meta: RecordMeta
  verification_mode: BASIC | CONDITIONAL_DEBATE | ALWAYS_DEBATE
  debate_triggers: [string]
  debate_skip_reason: string | null
  supporting_evidence: [EvidenceClaim]
  counter_evidence: [EvidenceClaim]
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

`FALSE`는 named falsification에 연결한다. `HOLD`는 unresolved condition 또는 누락 환경을 포함한다. 오류만으로 `FALSE`를 만들지 않는다.

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

match는 `workspace_id`·`commit_id`·asset·entity·privilege·attack order compatibility와 evidence를 포함한 `PrimitiveMatchCandidate`다. 저장 항목은 queue message가 아니다.

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
  primitive_matches: [CandidateRef]
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
  hypothesis_disproved: boolean
  disproof_evidence_refs: [StoredDataRef]
  hypothesis_linkage: string
  limitations: [string]
  cleanup_status: SUCCEEDED | FAILED
  started_at: timestamp
  finished_at: timestamp | null
  elapsed_ms: integer
```

재현 환경 구축·실행·관측 실패는 `failure_reason`으로 가설 반증과 구분한다. `status: FAILED | BLOCKED | CANCELLED`, 빈 stdout이나 exit code만으로 `hypothesis_disproved: true`를 만들 수 없다. 반증은 재현 플레이북의 기대 관측과 직접 연결된 `disproof_evidence_refs`를 요구한다. `hypothesis_disproved: false`이면 `disproof_evidence_refs`는 빈 목록이어야 한다.

## 8. TechnicalEvidenceReview

첫 번째 Gate가 검증 판정과 코드·실행 근거의 연결을 확인하고 승인·보완·거절을 기록하는 결과입니다.

```yaml
TechnicalEvidenceReview:
  meta: RecordMeta
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

Technical review는 `VerificationResult.verdict`를 덮어쓰지 않는다.

## 9. ProgramPolicyRecord과 RuleScopeImpactReview

공식 프로그램 정책을 확인해 저장한 기록과, 두 번째 Gate가 정책 범위·규칙·실제 영향을 검토한 결과입니다.

```yaml
ProgramPolicyRecord:
  meta: RecordMeta without hypothesis/attempt
  policy_record_id: string
  program_id: string
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

```yaml
RuleScopeImpactReview:
  meta: RecordMeta
  policy_record_ref: StoredDataRef | null
  review_status: PASS | FAIL | UNCERTAIN
  rule_compliance: PASS | FAIL | UNCERTAIN
  scope_compliance: PASS | FAIL | UNCERTAIN
  security_impact: SUFFICIENT | INSUFFICIENT | UNCERTAIN
  report_permission: ALLOW | DENY
  reasons: [string]
  missing_information: [string]
```

공식 `ProgramPolicyRecord`가 없거나 핵심 출처가 누락되면 `rule_compliance`, `scope_compliance`, `review_status`는 `UNCERTAIN`, permission은 `DENY`다. 이 불변조건을 만족하지 않는 출력은 invalid다.

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
  timeout: duration
```

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
  finished_at: timestamp | null
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
  finished_at: timestamp | null
  elapsed_ms: integer
  retry_count: integer
  status: string
  safe_error: string | null
  validation_errors: [string]
  repair_attempts: integer
  failover_from_llm_call_id: string | null
  redaction_result: APPLIED | NOT_REQUIRED | FAILED
```

hidden chain-of-thought와 credential은 이 계약의 대상이 아니며 저장하지 않는다.

## 11. ReportDraft와 AnalysisRunResult

모든 전달 조건을 통과한 보고서 초안과, 분석 한 건의 결과·자원·오류·디버깅 정보를 모은 최종 묶음입니다.

```yaml
ReportDraft:
  meta: RecordMeta
  verification_result_ref: StoredDataRef
  technical_review_ref: StoredDataRef
  rule_scope_impact_review_ref: StoredDataRef
  policy_record_ref: StoredDataRef
  content_ref: StoredDataRef
  draft_status: DRAFTED
  human_review_state: PENDING | APPROVED | REJECTED
```

```yaml
AnalysisRunResult:
  meta: RecordMeta without hypothesis/attempt
  repository_url: string
  status: COMPLETE | PARTIAL | FAILED | CANCELLED
  hypothesis_counts: map
  verdict_counts: map
  gate_counts: map
  verification_refs: [StoredDataRef]
  primitive_and_research_refs: [StoredDataRef]
  poc_refs: [StoredDataRef]
  report_draft_refs: [StoredDataRef]
  llm_invocation_log_refs: [StoredDataRef]
  errors: [AnalysisError]
  resources: map
  timing: map
  debug_trace_ref: StoredDataRef
```

Reporter 호출은 `TRUE + Technical ACCEPT + Rule Scope Impact review_status PASS + rule_compliance PASS + scope_compliance PASS + security_impact SUFFICIENT + ALLOW`인 경우만 유효하다.

## 구현 단계에서 결정할 것

serialization format, schema language/versioning, database/index, Primitive vocabulary, policy source collector, confidence range와 정량 limit은 구현 전 ADR과 평가 corpus로 확정한다. 이 설계의 field 목록을 곧바로 모든 서비스의 영구 API로 간주하지 않는다.
