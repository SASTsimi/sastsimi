# 08. 경량 데이터 계약

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 범위

이 문서는 Agent 경계에서 의미가 달라지지 않도록 최소 record와 enum을 정의한다. 완전한 구현 schema, 모든 내부 event, 서명 체계나 대규모 policy registry를 미리 고정하지 않는다. sandbox 요청, provider 호출, 저장 경계 등 실제 위험·호환성 경계에서만 구현 단계의 강한 validation을 추가한다.

## 공통 scope

```yaml
Scope:
  run_id: string
  snapshot_id: string
  repository_ref: string
  commit: string
  hypothesis_id: string | null
  attempt_id: string | null
  created_at: timestamp
```

모든 핵심 artifact는 `scope`와 생성 시각을 갖는다. 다른 snapshot의 코드·동적 결과·정책을 조용히 혼합하지 않으며 재시도는 새 `attempt_id`로 보존한다.

## 1. StaticFactBundle

```yaml
StaticFactBundle:
  scope: Scope without hypothesis/attempt
  entities: [EntityRef]
  locations: [LocationRef]
  source_candidates: [FactRef]
  sink_candidates: [FactRef]
  call_edges: [RelationRef]
  data_flow_candidates: [RelationRef]
  auth_and_permission_checks: [FactRef]
  route_bindings: [RelationRef]
  tool_observations: [ToolObservationRef]
  gaps: [AnalysisGap]
```

SAST severity와 tool message는 verdict가 아니다.

## 2. HypothesisProposal과 VulnerabilityHypothesis

```yaml
HypothesisProposal:
  proposal_id: string
  scope: Scope
  proposal_state: HYPOTHESIS_ONLY
  assertion_mode: NON_FINAL
  origin: INITIAL | RESEARCH | CHAINING
  vulnerability_type_candidates: [string]
  target_entities: [EntityRef]
  target_locations: [LocationRef]
  suspected_path: [RelationOrLocationRef]
  observed_facts: [FactRef]
  assumptions: [string]
  restrictions: [string]
  missing_information: [string]
  falsification_questions: [string]
  required_validation: [string]
  confidence: LOW | MEDIUM | HIGH
  parent_hypothesis_ids: [string]
  chain_depth: integer
```

schema validation과 semantic validation을 통과한 proposal만 stable `hypothesis_id`가 있는 `VulnerabilityHypothesis`로 등록한다. 금지된 확정 assertion, 잘못된 enum, 필수 field/location 누락은 제한된 repair retry 뒤 `INVALID_OUTPUT`이다. confidence는 scheduling hint이지 verdict가 아니다.

## 3. CodeContextRequest/Response

```yaml
CodeContextRequest:
  request_id: string
  scope: Scope
  requested_entities: [EntityRef]
  requested_locations: [LocationRef]
  relation_query: [CALLERS | CALLEES | DATA_FLOW_NEIGHBORS | AUTH_GUARDS | ROUTE_BINDINGS]
  reason: string
  max_depth: integer
  token_budget: integer
```

```yaml
CodeContextResponse:
  request_id: string
  snapshot_id: string
  entities: [EntityRef]
  locations: [LocationRef]
  code_fragment_refs: [ArtifactRef]
  discovered_relations: [RelationRef]
  gaps: [AnalysisGap]
  truncated: boolean
  consumed_token_estimate: integer | null
```

snapshot mismatch response는 근거에 사용하지 않는다. empty/truncated/gap은 안전함 또는 `FALSE`를 뜻하지 않는다.

## 4. VerificationResult

```yaml
VerificationResult:
  scope: Scope
  verification_mode: BASIC | CONDITIONAL_DEBATE | ALWAYS_DEBATE
  debate_triggers: [string]
  debate_skip_reason: string | null
  supporting_evidence: [EvidenceClaim]
  counter_evidence: [EvidenceClaim]
  initial_verdict: TRUE | FALSE | HOLD
  dynamic_decision: NOT_REQUIRED | LIMITED_REPRO | FULL_REPRO
  dynamic_result_ref: ArtifactRef | null
  poc_ref: ArtifactRef | null
  verdict: TRUE | FALSE | HOLD
  verdict_rationale: string
  restrictions: [string]
  bypass_candidates: [CandidateRef]
  required_capabilities: [Primitive]
  provided_capabilities: [Primitive]
  impact_escalation_candidates: [CandidateRef]
  unresolved_conditions: [string]
  metrics: VerificationMetrics
  errors: [Error]
```

`FALSE`는 named falsification에 연결한다. `HOLD`는 unresolved condition 또는 누락 환경을 포함한다. 오류만으로 `FALSE`를 만들지 않는다.

## 5. Primitive DB records

```yaml
Primitive:
  primitive_id: string
  primitive_type: string
  scope:
    snapshot_id: string
    asset: string
    entity_refs: [EntityRef]
    privilege_level: string
  status: REQUIRED | PROVIDED
  source_hypothesis_id: string
  evidence_refs: [ArtifactRef]
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
  related_entities: [EntityRef]
  chain_depth: integer
```

```yaml
ConfirmedCapability:
  hypothesis_id: string
  verdict: TRUE
  provided_primitives: [Primitive]
  affected_entities: [EntityRef]
  privilege_level: string
  evidence_refs: [ArtifactRef]
```

match는 snapshot·asset·entity·privilege·attack order compatibility와 evidence를 포함한 `PrimitiveMatchCandidate`다. 저장 항목은 queue message가 아니다.

## 6. ResearchResult

```yaml
ResearchResult:
  scope: Scope
  target_hypothesis_id: string
  trigger: TRUE_RESULT | HOLD_RESULT | TECHNICAL_REVISION | LOW_IMPACT_EXTENSION | PRIMITIVE_MATCH
  bypass_candidates: [CandidateRef]
  alternate_paths: [CandidateRef]
  impact_escalation_candidates: [CandidateRef]
  primitive_matches: [CandidateRef]
  chained_hypothesis_proposals: [HypothesisProposal]
  additional_validation_requests: [string]
  no_material_extension_reason: string | null
  errors: [Error]
```

이 record는 기존 verdict, CWE, Gate 또는 Finding을 변경하지 않는다. material candidate는 새 proposal로 재검증한다.

## 7. CWELabel과 DynamicReproductionResult

```yaml
CWELabel:
  scope: Scope
  primary: string | null
  alternatives: [string]
  taxonomy_version: string
  rationale: string
  evidence_refs: [ArtifactRef]
  uncertainty: string | null
```

```yaml
DynamicReproductionResult:
  scope: Scope
  mode: LIMITED_REPRO | FULL_REPRO
  environment_ref: ArtifactRef
  steps_ref: ArtifactRef
  observation_refs: [ArtifactRef]
  outcome: SUCCEEDED | PARTIAL | FAILED
  failure_class: NONE | ENVIRONMENT_SETUP | EXECUTION | OBSERVATION | POLICY_BLOCKED | TIMEOUT
  falsification_observed: boolean
  hypothesis_linkage: string
  limitations: [string]
  cleanup_status: SUCCEEDED | FAILED
```

재현 환경 구축·실행·관측 실패는 `failure_class`로 가설 반증과 구분한다. `outcome: FAILED`만으로 `falsification_observed: true`를 만들 수 없으며, 반증은 재현 플레이북에 정의된 관측과 evidence reference를 요구한다.

## 8. TechnicalEvidenceReview

```yaml
TechnicalEvidenceReview:
  scope: Scope
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

## 9. ProgramPolicySnapshot과 RuleScopeImpactReview

```yaml
ProgramPolicySnapshot:
  policy_snapshot_id: string
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
  source_refs: [ArtifactRef]
  missing_information: [string]
  freshness_warning: string | null
```

```yaml
RuleScopeImpactReview:
  scope: Scope
  policy_snapshot_ref: ArtifactRef | null
  review_status: PASS | FAIL | UNCERTAIN
  rule_compliance: PASS | FAIL | UNCERTAIN
  scope_compliance: PASS | FAIL | UNCERTAIN
  security_impact: SUFFICIENT | INSUFFICIENT | UNCERTAIN
  report_permission: ALLOW | DENY
  reasons: [string]
  missing_information: [string]
```

공식 정책 snapshot 부재 시 `rule_compliance`, `scope_compliance`, `review_status`는 `UNCERTAIN`, permission은 `DENY`다. 이 불변조건을 만족하지 않는 출력은 invalid다.

## 10. LLM invocation records

```yaml
LLMInvocationRequest:
  invocation_id: string
  run_id: string
  hypothesis_id: string | null
  agent_role: HYPOTHESIS | VERIFICATION | PRO | CON | RESEARCH | TECHNICAL_GATE | RULE_SCOPE_GATE | REPORTER
  provider_profile: string
  model: string
  session_policy: NEW | RESUME | AUTO
  parent_session_ref: string | null
  context_refs: [ArtifactRef]
  prompt_template_version: string
  prompt_payload_ref: ArtifactRef
  output_schema: string
  token_budget: integer
  timeout: duration
```

```yaml
LLMInvocationResult:
  invocation_id: string
  status: SUCCEEDED | FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED | CANCELLED
  provider: string
  model: string
  actual_session_mode: NEW | RESUMED
  session_ref: string | null
  response_ref: ArtifactRef | null
  parsed_output_ref: ArtifactRef | null
  usage: map | null
  elapsed: duration
  safe_error: string | null
```

```yaml
LLMInvocationLog:
  run_id: string
  hypothesis_id: string | null
  attempt_id: string
  agent_role: string
  provider: string
  model: string
  session_policy: NEW | RESUME | AUTO
  session_ref: string | null
  parent_session_ref: string | null
  prompt_template_version: string
  context_refs: [ArtifactRef]
  retrieved_code_locations: [LocationRef]
  exposed_request_ref: ArtifactRef
  exposed_response_ref: ArtifactRef | null
  parsed_output_ref: ArtifactRef | null
  tool_calls: [ArtifactRef]
  usage: map | null
  elapsed: duration
  retry_count: integer
  status: string
  safe_error: string | null
  validation_errors: [string]
  repair_attempts: integer
  failover_from_invocation_id: string | null
  redaction_result: APPLIED | NOT_REQUIRED | FAILED
```

hidden chain-of-thought와 credential은 이 계약의 대상이 아니며 저장하지 않는다.

## 11. ReportDraft와 AnalysisRunResult

```yaml
ReportDraft:
  scope: Scope
  verification_result_ref: ArtifactRef
  technical_review_ref: ArtifactRef
  rule_scope_impact_review_ref: ArtifactRef
  policy_snapshot_ref: ArtifactRef
  content_ref: ArtifactRef
  human_review_state: PENDING | REVIEWED
```

```yaml
AnalysisRunResult:
  scope: Scope without hypothesis/attempt
  status: COMPLETE | PARTIAL | FAILED | CANCELLED
  hypothesis_counts: map
  verdict_counts: map
  gate_counts: map
  verification_refs: [ArtifactRef]
  primitive_and_research_refs: [ArtifactRef]
  poc_refs: [ArtifactRef]
  report_draft_refs: [ArtifactRef]
  llm_invocation_log_refs: [ArtifactRef]
  errors: [Error]
  resources: map
  timing: map
  debug_trace_ref: ArtifactRef
```

Reporter 호출은 `TRUE + Technical ACCEPT + Rule Scope Impact review_status PASS + rule_compliance PASS + scope_compliance PASS + security_impact SUFFICIENT + ALLOW`인 경우만 유효하다.

## 구현 단계에서 결정할 것

serialization format, schema language/versioning, database/index, Primitive vocabulary, policy source collector, confidence range와 정량 limit은 구현 전 ADR과 평가 corpus로 확정한다. 이 설계의 field 목록을 곧바로 모든 서비스의 영구 API로 간주하지 않는다.
