# R3-05. Agent 프롬프트 등록·조립·전달 구조

- **이 문서는 무엇을 설명하나요?** 역할별 프롬프트를 어디에 두고, 어떤 입력을 넣어 LLM에 전달하며, 결과를 어떻게 검사하고 기록할지 설명합니다.
- **누가 읽어야 하나요?** R1·R5·R6·R7의 프롬프트 작성자, R2 입력 자료 담당자, R3 통합 구현자, R4 계약 담당자와 R8 평가 담당자가 읽습니다.
- **읽은 뒤 무엇을 결정해야 하나요?** 각 역할의 첫 prompt revision, 입출력 schema, session 정책, 검증 함수와 평가 fixture를 승인합니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 1. 기준과 핵심 결론

- 작성 기준 `main`: `40c744523c09349c47592b4e3a1ee84a382bb16c`
- 연결 Issue: [R3-05 #91](https://github.com/SASTsimi/sastsimi/issues/91)
- Provider 연결 결정: [R3-04 #90](https://github.com/SASTsimi/sastsimi/issues/90)
- 최종 구현 기준선: [R3-06 #92](https://github.com/SASTsimi/sastsimi/issues/92)

프롬프트는 Markdown 파일 하나만 저장한다고 완성되지 않는다. 다음 네 항목을 함께 versioning해야 실행 가능한 프롬프트가 된다.

1. 역할과 작업을 찾는 `PromptRegistryEntry`
2. 사람이 검토하는 immutable prompt template
3. template에 넣을 허용 입력과 exact reference
4. 출력 JSON Schema와 역할별 semantic validator

Agent는 prompt 문자열을 직접 만들거나 입력을 임의로 추가하지 않는다. 신뢰 경계 안의 `Prompt Registry Runtime`과 `Prompt Builder`가 승인된 등록 정보, template, exact context로 `PromptPayload`를 만들고 `Runtime Validator`가 호출 전 동일성을 검사한다.

OpenAI API, Codex 구독, Anthropic API, Claude 구독은 R3-04의 **연결 후보**다. 그중 실제 시험을 통과해 채택된 `ProviderProfile`은 모두 같은 **논리 PromptPayload와 출력 schema**를 받아야 한다. provider adapter는 이를 각 공식 API·CLI·SDK의 전송 형식으로 바꿀 수 있지만 역할·입력·판정 기준을 바꾸거나 provider별로 별도 결론 규칙을 만들면 안 된다.

## 2. 구현 파일 구조

첫 구현은 하나의 Python 애플리케이션 안에서 다음처럼 나눈다. 경로는 #92에서 저장소 기본 구조로 최종 승인한다.

```text
config/
  models/
    profiles.yaml
  policies/
    llm/
      limits.yaml
      retry.yaml
      tools.yaml
      redaction.yaml
  schemas/
    outputs/
  prompts/
    registry.yaml
    templates/
      hypothesis/
      pro/
      con/
      verification/
      r7_agent/
      chaining/
      cwe_labeling/
      technical_gate/
      rule_scope_gate/
      reporter/
src/sastsimi/
  prompts/
    models.py
    registry.py
    loader.py
    builder.py
    renderer.py
    validation.py
    validators/
  agents/
    hypothesis.py
    pro.py
    con.py
    verification.py
    reproduction.py
    chaining.py
    cwe_labeling.py
    technical_gate.py
    rule_scope_gate.py
    reporter.py
tests/
  contract/prompts/
  integration/prompts/
  security_negative/prompts/
  fixtures/prompts/providers/
```

- `registry.yaml`: 역할과 task를 활성 template·schema·validator에 연결한다.
- `templates/`: 사람이 읽고 review할 역할 지시문만 둔다. 분석 대상 코드·가설·근거를 저장하지 않는다.
- `loader.py`: 등록 정보와 template을 읽고 hash·schema version·상태를 검사한다.
- `builder.py`: 허용된 exact context만 정해진 slot에 결합한다.
- `renderer.py`: provider-neutral payload를 adapter가 받을 공통 message 구조로 만든다.
- `validation.py`: JSON Schema 뒤 역할별 의미 규칙을 검사한다.
- `agents/`: 각 역할의 입력 요청과 출력 소비를 담당하며 prompt 원문을 코드에 중복하지 않는다.

운영 template을 Python 문자열 상수, 환경 변수 또는 provider dashboard prompt와 중복 관리하지 않는다. 외부 prompt 관리 서비스를 나중에 쓰더라도 repository의 registry에는 실제 사용한 immutable revision과 export hash를 고정해야 한다.

## 3. 공통 등록 계약

공통 schema 정본은 [08. Lightweight data contracts](../08-lightweight-data-contracts.md)의 `PromptRegistryEntry`, `PromptPayload`, `LLMCallSpec`, `LLMInvocationRequest`, `LLMInvocationLog`다.

등록 예시는 다음과 같다.

```yaml
PromptRegistryEntry:
  meta: RecordMeta
  prompt_key: verification.final-verdict
  agent_role: VERIFICATION
  task_kind: FINAL_VERDICT
  template_ref: StoredDataRef
  template_version: 1.0.0
  input_slots:
    - slot: assignment
      data_kind: verification_assignment
      field_paths: ["$"]
      cardinality: REQUIRED_ONE
      trust_class: UNTRUSTED_DATA
    - slot: process
      data_kind: hypothesis_process_state
      field_paths: ["/status", "/verification_assignment_ref", "/verification_generation", "/verification_work_ref"]
      cardinality: REQUIRED_ONE
      trust_class: UNTRUSTED_DATA
    - slot: hypothesis
      data_kind: vulnerability_hypothesis
      field_paths: ["$"]
      cardinality: REQUIRED_ONE
      trust_class: UNTRUSTED_DATA
    - slot: proposal
      data_kind: hypothesis_proposal
      field_paths: ["$"]
      cardinality: REQUIRED_ONE
      trust_class: UNTRUSTED_DATA
    - slot: pro
      data_kind: pro_evidence_result
      field_paths: ["$"]
      cardinality: REQUIRED_ONE
      trust_class: UNTRUSTED_DATA
    - slot: con
      data_kind: con_evidence_result
      field_paths: ["$"]
      cardinality: REQUIRED_ONE
      trust_class: UNTRUSTED_DATA
  forbidden_context_kinds:
    - report_draft
    - rule_scope_impact_review
  output_schema_ref: StoredDataRef
  session_policy: NEW
  model_profile_ref: StoredDataRef
  provider_profile_refs: [StoredDataRef]
  execution_limits_ref: StoredDataRef
  retry_policy_ref: StoredDataRef
  semantic_validator_ref: StoredDataRef
  tool_policy_ref: StoredDataRef
  redaction_policy_ref: StoredDataRef
  result_kind: verification_result
  status: DRAFT
  owner_role: R6
  reviewer_roles: [R3, R4, R7, R8]
```

위 YAML은 필드 의미를 보여주는 `DRAFT` 일부 예시다. 운영 `ACTIVE` entry는 아래 task 행에 적힌 모든 필수 slot과 exact data kind를 빠짐없이 등록해야 한다. `prompt_key`는 사람이 설정과 리뷰에서 찾기 쉬운 등록 이름이다. record의 정체성과 정확한 수정본은 `meta.logical_record_id`, `meta.revision_number`와 `StoredDataRef(record_id + content_hash)`가 기준이다. `prompt_key`나 `template_version` 문자열만으로 실행할 수정본을 찾으면 안 된다.

`input_slots`는 slot별 data kind, 노출할 JSON Pointer, 필수 개수와 신뢰 등급을 정한다. `"$"`는 해당 record 전체를 허용할 때만 단독으로 사용한다. Builder는 허용 field만 새 `projected_data_ref`에 canonical serialization하며 원본 exact `source_ref`도 함께 남긴다.

`model_profile_ref`는 역할별 model route, `provider_profile_refs`는 #90에서 검증된 허용 연결 경로, `execution_limits_ref`는 token 계획값·timeout·동시성 한도, `retry_policy_ref`는 repair·retry·explicit failover 조건을 고정한다. `output_schema_ref`, `semantic_validator_ref`, `tool_policy_ref`와 `redaction_policy_ref`도 versioned record다. 실제 호출은 이 목록 중 하나의 exact `provider_profile_ref + model`을 `LLMCallSpec`에 기록한다. Provider가 바뀌어도 template와 판단 기준은 그대로이며, profile 목록 변경은 새 registry revision과 재검토가 필요하다. tool policy의 `allowed_tools=[]`는 tool 사용 금지, `result_kind`는 성공 출력의 유일한 저장 계약을 뜻한다.

`PromptPayload`는 한 번의 호출에 실제로 조립한 불변 입력이다.

```yaml
PromptPayload:
  meta: RecordMeta
  registry_entry_ref: StoredDataRef
  prompt_key: string
  agent_role: HYPOTHESIS | PRO | CON | VERIFICATION | R7_AGENT | CHAINING | CWE_LABELING | TECHNICAL_GATE | RULE_SCOPE_GATE | REPORTER
  task_kind: string
  template_ref: StoredDataRef
  template_version: string
  context_bindings: [PromptContextBinding]
  rendered_prompt_ref: StoredDataRef
  output_schema_ref: StoredDataRef

PromptContextBinding:
  slot: string
  data_kind: string
  source_ref: StoredDataRef
  projected_data_ref: StoredDataRef
  field_paths: [string]
  trust_class: TRUSTED_INSTRUCTION | UNTRUSTED_DATA
```

`rendered_prompt_ref`는 adapter에 넘기기 직전의 redacted prompt artifact를 가리킨다. 비밀값과 hidden chain-of-thought는 저장하지 않는다. `TRUSTED_INSTRUCTION`에는 repository 내용이나 LLM 출력이 들어갈 수 없으며, 분석 대상 코드·README·Issue·정책 원문·도구 출력은 모두 `UNTRUSTED_DATA`다.

## 4. 역할별 첫 Prompt Registry

아래는 구현 시작에 필요한 최소 등록 목록이다. 하나의 역할이 여러 task를 가지면 서로 다른 registry entry와 template을 사용한다.

### 4.0 활성화할 공통 설정

아래 이름은 repository에서 사람이 찾는 logical key다. 운영 시작 때 각 key를 immutable record로 등록하고 registry에는 생성된 exact `StoredDataRef`를 넣는다. key 문자열을 reference 대신 사용하지 않는다.

| 역할 / task | model profile key | provider set | limits | retry | tool | redaction | session |
|---|---|---|---|---|---|---|---|
| HYPOTHESIS / `GENERATE_INITIAL` | `model.hypothesis.generate-initial.quality-v1` | `providers.r3-04-accepted-v1` | `limits.hypothesis.v1` | `retry.standard.v1` | `tools.none.v1` | `redaction.default.v1` | NEW |
| HYPOTHESIS / `DUPLICATE_REVIEW` | `model.hypothesis.duplicate-review.quality-v1` | `providers.r3-04-accepted-v1` | `limits.hypothesis.v1` | `retry.standard.v1` | `tools.none.v1` | `redaction.default.v1` | NEW |
| PRO | `model.pro.quality-v1` | `providers.r3-04-accepted-v1` | `limits.pro.v1` | `retry.debate.v1` | `tools.none.v1` | `redaction.default.v1` | NEW |
| CON | `model.con.quality-v1` | `providers.r3-04-accepted-v1` | `limits.con.v1` | `retry.debate.v1` | `tools.none.v1` | `redaction.default.v1` | NEW |
| VERIFICATION / `CREATE_DYNAMIC_REQUEST` | `model.verification.create-dynamic-request.quality-v1` | `providers.r3-04-accepted-v1` | `limits.verification.v1` | `retry.verification.v1` | `tools.none.v1` | `redaction.default.v1` | NEW |
| VERIFICATION / `FINAL_VERDICT` | `model.verification.final-verdict.quality-v1` | `providers.r3-04-accepted-v1` | `limits.verification.v1` | `retry.verification.v1` | `tools.none.v1` | `redaction.default.v1` | NEW |
| VERIFICATION / `TECHNICAL_REVISE` | `model.verification.technical-revise.quality-v1` | `providers.r3-04-accepted-v1` | `limits.verification.v1` | `retry.verification.v1` | `tools.none.v1` | `redaction.default.v1` | NEW |
| R7_AGENT / `DERIVE_ENVIRONMENT` | `model.r7-agent.derive-environment.quality-v1` | `providers.r3-04-accepted-v1` | `limits.r7-agent.v1` | `retry.r7-agent.v1` | `tools.r7-sandbox-inner.v1` | `redaction.sandbox.v1` | NEW |
| R7_AGENT / `PLAN_REPRODUCTION` | `model.r7-agent.plan-reproduction.quality-v1` | `providers.r3-04-accepted-v1` | `limits.r7-agent.v1` | `retry.r7-agent.v1` | `tools.r7-sandbox-inner.v1` | `redaction.sandbox.v1` | NEW |
| R7_AGENT / `CREATE_POC_CANDIDATE` | `model.r7-agent.create-poc-candidate.quality-v1` | `providers.r3-04-accepted-v1` | `limits.r7-agent.v1` | `retry.r7-agent.v1` | `tools.r7-sandbox-inner.v1` | `redaction.sandbox.v1` | NEW |
| R7_AGENT / `INTERPRET_ATTEMPT` | `model.r7-agent.interpret-attempt.quality-v1` | `providers.r3-04-accepted-v1` | `limits.r7-agent.v1` | `retry.r7-agent.v1` | `tools.r7-sandbox-inner.v1` | `redaction.sandbox.v1` | NEW |
| CHAINING | `model.chaining.quality-v1` | `providers.r3-04-accepted-v1` | `limits.chaining.v1` | `retry.standard.v1` | `tools.none.v1` | `redaction.default.v1` | NEW |
| CWE_LABELING | `model.cwe.quality-v1` | `providers.r3-04-accepted-v1` | `limits.cwe.v1` | `retry.standard.v1` | `tools.none.v1` | `redaction.default.v1` | NEW |
| TECHNICAL_GATE | `model.technical-gate.quality-v1` | `providers.r3-04-accepted-v1` | `limits.technical-gate.v1` | `retry.gate.v1` | `tools.none.v1` | `redaction.default.v1` | NEW |
| RULE_SCOPE_GATE | `model.rule-scope-gate.quality-v1` | `providers.r3-04-accepted-v1` | `limits.rule-scope-gate.v1` | `retry.gate.v1` | `tools.none.v1` | `redaction.policy.v1` | NEW |
| REPORTER | `model.reporter.quality-v1` | `providers.r3-04-accepted-v1` | `limits.reporter.v1` | `retry.standard.v1` | `tools.none.v1` | `redaction.report.v1` | NEW |

`providers.r3-04-accepted-v1`에는 #90의 시험과 검토를 통과한 exact ProviderProfile만 들어간다. #90에서 승인된 profile이 없으면 이 설정도 `DRAFT`이며 어떤 역할도 호출하지 않는다. 따라서 네 후보 adapter를 모두 지원한다고 가정하지 않는다. 표의 각 행은 별도 immutable `ModelProfile` record이고, 그 record의 `agent_role + task_kind`는 아래 task 행과 정확히 하나씩 대응한다. 같은 역할이라도 여러 task가 한 ModelProfile을 공유하지 않는다. 각 `ModelProfile.routes`는 이 provider set의 부분집합이며 primary 하나와 사전에 허용한 fallback만 둔다. 실제 model ID, timeout, token 계획값, 호출·repair 횟수는 R8 평가와 #92 승인 전까지 `DRAFT` 설정에 임의 값으로 채우지 않는다.

첫 기준선은 모두 `NEW`다. 이후 같은 Verification의 Technical `REVISE`에서 `AUTO | RESUME`을 채택하려면 독립성·stale context·비용 비교 시험과 R4/R6 승인을 거친 새 registry·model/session policy revision이 필요하다.

### 4.0.1 task별 구현 행

각 행은 **한 호출당 한 result kind의 structured output artifact 하나**를 만든다. 기존 역할 계약이 목록을 출력하는 경우 artifact 안에 같은 종류의 항목 배열을 둘 수 있지만, 서로 다른 result kind를 한 응답에 섞지 않는다. template 형식은 UTF-8 Markdown이고 version `1.0.0`부터 시작한다. schema·validator 이름도 logical key이며 activation 때 exact record reference로 바뀐다.

| role / task | template | 허용 input slot과 field projection | output schema / validator / result kind | owner / 필수 review / test |
|---|---|---|---|---|
| HYPOTHESIS / `GENERATE_INITIAL` | `config/prompts/templates/hypothesis/generate-initial/1.0.0.md` | `facts: StaticFactBundle(/entities,/locations,/source_candidates,/sink_candidates,/sanitizer_candidates,/validator_candidates,/auth_and_permission_checks,/other_facts,/call_edges,/data_flow_candidates,/route_bindings,/tool_runs,/gaps,/errors)` | `schema.hypothesis-proposal-list.next-major` / `validator.hypothesis-proposal-list.v1` / `hypothesis_proposal` | R1 / R2,R3,R4,R8 / `PMT-HYP-01` |
| HYPOTHESIS / `DUPLICATE_REVIEW` | `config/prompts/templates/hypothesis/duplicate-review/1.0.0.md` | `proposal: HypothesisProposal($)`; `candidates: VulnerabilityHypothesis(/meta,/proposal_ref,/parent_hypothesis_ids,/source_primitive_match_id)` REQUIRED_MANY | `schema.hypothesis-duplicate-review.next-major` / `validator.hypothesis-duplicate-review.v1` / `hypothesis_duplicate_review` | R1 / R3,R4,R8 / `PMT-HYP-02` |
| PRO / `COLLECT_SUPPORT` | `config/prompts/templates/pro/collect-support/1.0.0.md` | `assignment: VerificationAssignment($)`; `process: HypothesisProcessState(/status,/verification_assignment_ref,/verification_generation,/verification_work_ref)`; `hypothesis: VulnerabilityHypothesis($)`; `proposal: HypothesisProposal($)`; `facts: StaticFactBundle(/entities,/locations,/source_candidates,/sink_candidates,/sanitizer_candidates,/validator_candidates,/auth_and_permission_checks,/other_facts,/call_edges,/data_flow_candidates,/route_bindings,/tool_runs,/gaps,/errors)`; `contexts: CodeContextResponse($)` OPTIONAL_MANY; `policy: PlaybookPolicy($)`; `playbook: VerificationPlaybook($)`; `application: PlaybookApplication($)`; `debate_config: debate_config($)`; `budget_profile: verification_budget_profile($)` | `schema.evidence-agent-result.next-major` / `validator.pro-evidence.v1` / `pro_evidence_result` | R6 / R2,R3,R4,R8 / `PMT-PRO-01` |
| CON / `COLLECT_COUNTEREVIDENCE` | `config/prompts/templates/con/collect-counterevidence/1.0.0.md` | `assignment: VerificationAssignment($)`; `process: HypothesisProcessState(/status,/verification_assignment_ref,/verification_generation,/verification_work_ref)`; `hypothesis: VulnerabilityHypothesis($)`; `proposal: HypothesisProposal($)`; `facts: StaticFactBundle(/entities,/locations,/source_candidates,/sink_candidates,/sanitizer_candidates,/validator_candidates,/auth_and_permission_checks,/other_facts,/call_edges,/data_flow_candidates,/route_bindings,/tool_runs,/gaps,/errors)`; `contexts: CodeContextResponse($)` OPTIONAL_MANY; `policy: PlaybookPolicy($)`; `playbook: VerificationPlaybook($)`; `application: PlaybookApplication($)`; `debate_config: debate_config($)`; `budget_profile: verification_budget_profile($)`; 상대 결과는 금지 | `schema.evidence-agent-result.next-major` / `validator.con-evidence.v1` / `con_evidence_result` | R6 / R2,R3,R4,R8 / `PMT-CON-01` |
| VERIFICATION / `CREATE_DYNAMIC_REQUEST` | `config/prompts/templates/verification/create-dynamic-request/1.0.0.md` | `assignment: VerificationAssignment($)`; `process: HypothesisProcessState(/status,/verification_assignment_ref,/verification_generation,/verification_work_ref)`; `hypothesis: VulnerabilityHypothesis($)`; `proposal: HypothesisProposal($)`; `pro: EvidenceAgentResult(role=PRO, data_kind=pro_evidence_result)`; `con: EvidenceAgentResult(role=CON, data_kind=con_evidence_result)`; `facts: StaticFactBundle(/entities,/locations,/auth_and_permission_checks,/call_edges,/data_flow_candidates,/route_bindings,/gaps,/errors)`; `contexts: CodeContextResponse($)` OPTIONAL_MANY; `sandbox_profile: sandbox_profile($)` | `schema.dynamic-reproduction-request.next-major` / `validator.dynamic-request.v1` / `dynamic_reproduction_request` | R6 / R2,R3,R4,R7,R8 / `PMT-VER-01` |
| VERIFICATION / `FINAL_VERDICT` | `config/prompts/templates/verification/final-verdict/1.0.0.md` | `assignment: VerificationAssignment($)`; `process: HypothesisProcessState(/status,/verification_assignment_ref,/verification_generation,/verification_work_ref)`; `hypothesis: VulnerabilityHypothesis($)`; `proposal: HypothesisProposal($)`; `facts: StaticFactBundle($)`; `contexts: CodeContextResponse($)` OPTIONAL_MANY; `policy: PlaybookPolicy($)`; `playbook: VerificationPlaybook($)`; `application: PlaybookApplication($)`; `debate_config: debate_config($)`; `budget_profile: verification_budget_profile($)`; `pro: EvidenceAgentResult(role=PRO, data_kind=pro_evidence_result)`; `con: EvidenceAgentResult(role=CON, data_kind=con_evidence_result)`; `dynamic: DynamicReproductionResult($)` OPTIONAL_ONE; `poc: PoCBundle($)` OPTIONAL_ONE | `schema.verification-result.next-major` / `validator.verification-result.v1` / `verification_result` | R6 / R1,R3,R4,R7,R8 / `PMT-VER-02` |
| VERIFICATION / `TECHNICAL_REVISE` | `config/prompts/templates/verification/technical-revise/1.0.0.md` | `previous: VerificationResult($)`; `review: TechnicalEvidenceReview(/status,/revision_requests,/verification_result_ref,/cwe_label_ref)`; 새 generation의 current exact `assignment`,`process`,`hypothesis`,`proposal`,`facts`,`contexts`,`policy`,`playbook`,`application`,`debate_config`,`budget_profile`,`pro`,`con`,`dynamic`,`poc`를 `FINAL_VERDICT`와 같은 slot·field 규칙으로 입력 | `schema.verification-result.next-major` / `validator.verification-revise.v1` / `verification_result` | R6 / R3,R4,R5,R7,R8 / `PMT-VER-03` |
| R7_AGENT / `DERIVE_ENVIRONMENT` | `config/prompts/templates/r7_agent/derive-environment/1.0.0.md` | `request: DynamicReproductionRequest(/meta,/purpose,/goal,/environment_needs,/sandbox_profile_ref,/code_refs,/static_evidence_refs)` | `schema.environment-requirements.next-major` / `validator.environment-requirements.v1` / `environment_requirements` | R7 / R3,R4,R6,R8 / `PMT-R7-01` |
| R7_AGENT / `PLAN_REPRODUCTION` | `config/prompts/templates/r7_agent/plan-reproduction/1.0.0.md` | `request: DynamicReproductionRequest($)`; `requirements: EnvironmentRequirements($)` | `schema.reproduction-plan.next-major` / `validator.reproduction-plan.v1` / `reproduction_plan` | R7 / R3,R4,R6,R8 / `PMT-R7-02` |
| R7_AGENT / `CREATE_POC_CANDIDATE` | `config/prompts/templates/r7_agent/create-poc-candidate/1.0.0.md` | `request: DynamicReproductionRequest($)`; `plan: ReproductionPlan($)`; `environment: SandboxEnvironment(/meta,/request_ref,/reproduction_plan_ref,/requirements_ref,/status,/checks,/limitations)` | `schema.poc-candidate.next-major` / `validator.poc-candidate.v1` / `poc_candidate` | R7 / R3,R4,R6,R8 / `PMT-R7-03` |
| R7_AGENT / `INTERPRET_ATTEMPT` | `config/prompts/templates/r7_agent/interpret-attempt/1.0.0.md` | `request: DynamicReproductionRequest($)`; `plan: ReproductionPlan($)`; `environment: SandboxEnvironment($)`; `candidate: PoCCandidate($)` OPTIONAL_ONE; `agent_log: AgentLog(/request_ref,/events)`; `observations: dynamic_observation($)` OPTIONAL_MANY | `schema.r7-agent-conclusion.next-major` / `validator.r7-agent-conclusion.v1` / `r7_agent_conclusion` | R7 / R3,R4,R6,R8 / `PMT-R7-04` |
| CHAINING / `MATCH_PRIMITIVES` | `config/prompts/templates/chaining/match-primitives/1.0.0.md` | `index: PrimitiveIndexState($)`; `considered: Primitive($)` REQUIRED_MANY; `admission: PrimitiveAdmissionDecision($)` REQUIRED_MANY | `schema.chaining-result.next-major` / `validator.chaining-result.v1` / `chaining_result` | R1 / R3,R4,R5,R8 / `PMT-CHN-01` |
| CWE_LABELING / `CLASSIFY` | `config/prompts/templates/cwe_labeling/classify/1.0.0.md` | `verification: VerificationResult($)`; `taxonomy: cwe_taxonomy($)` | `schema.cwe-label.next-major` / `validator.cwe-label.v1` / `cwe_label` | R5 / R3,R4,R6,R8 / `PMT-CWE-01` |
| TECHNICAL_GATE / `REVIEW` | `config/prompts/templates/technical_gate/review/1.0.0.md` | `verification: VerificationResult($)`; `cwe: CWELabel($)`; exact transitive evidence refs | `schema.technical-evidence-review.next-major` / `validator.technical-gate.v1` / `technical_evidence_review` | R5 / R1,R3,R4,R6,R7,R8 / `PMT-TG-01` |
| RULE_SCOPE_GATE / `REVIEW` | `config/prompts/templates/rule_scope_gate/review/1.0.0.md` | `verification: VerificationResult($)`; `technical: TechnicalEvidenceReview($)`; `cwe: CWELabel($)`; `collection: PolicyCollectionResult($)`; `policy: ProgramPolicyRecord($)` OPTIONAL_ONE | `schema.rule-scope-impact-review.next-major` / `validator.rule-scope-gate.v1` / `rule_scope_impact_review` | R5 / R3,R4,R6,R8 / `PMT-RSG-01` |
| REPORTER / `CREATE_DRAFT` | `config/prompts/templates/reporter/create-draft/1.0.0.md` | `finding: finding($)`; `verification: VerificationResult($)`; `technical: TechnicalEvidenceReview($)`; `scope: RuleScopeImpactReview($)`; `cwe: CWELabel($)`; `policy: ProgramPolicyRecord($)`; `dynamic: DynamicReproductionResult($)`; `poc: PoCBundle($)` | `schema.report-draft.next-major` / `validator.report-draft.v1` / `report_draft` | R5 / R1,R3,R4,R6,R7,R8 / `PMT-REP-01` |

위 `schema.*`, `validator.*`, `model.*`, `limits.*`, `retry.*`, `tools.*`, `redaction.*`, provider set은 `config/prompts/registry.yaml`에서 각 exact record reference로 resolve된다. 파일이나 logical key가 존재해도 exact reference·상태·검토자가 맞지 않으면 `ACTIVE`로 만들지 않는다. 모든 입력 slot의 기본 trust class는 `UNTRUSTED_DATA`이며 별도 표기가 없는 한 그대로다.

Pro와 Con의 공통 slot은 이름만 같은 것이 아니라 `source_ref + projected_data_ref + field_paths`의 중복 없는 집합이 exact하게 같아야 한다. `debate_config`는 R6가 승인한 versioned Debate 규칙 record, `verification_budget_profile`은 R8이 승인한 이 Verification의 공통 시간·호출·자원 예산 record다. 두 data kind의 실제 schema와 ACTIVE record가 확정되기 전에는 Pro/Con registry entry도 `DRAFT`다. 역할별 `ExecutionLimits`는 개별 LLM 호출 한도이고 이 공통 budget profile을 대신하지 않는다. trusted runtime은 위 공통 slot 전체의 canonical reference 집합으로 `debate_input_hash`를 계산하며 상대 역할의 결과·호출·session은 포함하지 않는다.

### 4.1 Hypothesis Agent — R1

- `hypothesis.generate-initial`: `StaticFactBundle`에서 기존 계약의 `HypothesisProposal[]` 한 묶음을 생성하고, runtime이 각 proposal을 개별 검증·등록
- `hypothesis.duplicate-review`: runtime이 좁힌 후보만 읽고 `HypothesisDuplicateReview` 생성
- 필수 금지: final verdict, CWE, Gate 결과, Sandbox 실행 요청 생성
- 기본 session: 각 독립 proposal batch와 중복 검토마다 `NEW`

### 4.2 Pro Agent — R6

- `pro.collect-support`: 가설·공통 fact·적용 플레이북으로 `EvidenceAgentResult(role=PRO)` 생성
- 필수 금지: Con 결과·session·도구 출력 읽기, final verdict 생성
- 기본 session: 항상 `NEW`

### 4.3 Con Agent — R6

- `con.collect-counterevidence`: named falsification과 대안 경로를 검토해 `EvidenceAgentResult(role=CON)` 생성
- 필수 금지: Pro 결과·session·도구 출력 읽기, final verdict 생성
- 기본 session: 항상 `NEW`

### 4.4 Verification Agent — R6

- `verification.dynamic-request`: 필요 목적·목표·환경 조건을 `DynamicReproductionRequest`로 생성
- `verification.final-verdict`: current generation의 근거와 동적 결과를 종합해 final `VerificationResult` 생성
- `verification.technical-revise`: Technical Gate의 구조화된 보완 요청과 새 generation 근거로 보완된 `VerificationResult` 생성
- 필수 금지: R7의 plan·command 대신 작성, CWE·Gate 결과·보고서 생성
- session: Pro·Con session을 재개하지 않는다. 보완도 새 invocation이며 `NEW`가 기본이다.

### 4.5 R7 Reproduction Agent — R7

- `r7.derive-environment`: exact `DynamicReproductionRequest`에서 `EnvironmentRequirements` 하나를 생성
- `r7.plan-reproduction`: exact request와 requirements에서 `ReproductionPlan` 하나를 생성
- `r7.create-poc-candidate`: current plan과 환경에서 `PoCCandidate` 하나를 생성하거나 새 revision으로 보완
- `r7.interpret-attempt`: 실제 AgentLog·관찰을 읽어 `R7AgentConclusion` 하나를 생성
- 필수 금지: Sandbox 외부 경계 우회, final `TRUE | FALSE | HOLD`, validated PoC 또는 final `DynamicReproductionResult` 직접 확정
- session: 한 dynamic work/attempt의 정책에 따르며 다른 가설 session을 재사용하지 않는다.

한 R7 호출이 requirements와 plan을 동시에 반환하거나 여러 candidate·결론을 한 output에 넣지 않는다. 각 출력은 자기 `LLMInvocationLog.parsed_output_ref` 하나에 연결된다. Session Manager는 `R7AgentConclusion`을 실제 AgentLog·환경·candidate·observation과 대조한 뒤에만 final dynamic result를 확정한다.

이 역할은 기존 `ActionRequest.requested_by=R7_AGENT`와 일치해야 하므로 `LLMCallSpec`, request와 log의 `agent_role`에도 `R7_AGENT`가 반드시 포함된다.

### 4.6 Chaining Agent — R1

- `chaining.match-primitives`: exact eligible Primitive 집합에서 result→input match와 그 match에서 나온 `HypothesisProposal(origin=CHAINING)`을 포함한 `ChainingResult` 생성
- 필수 금지: Primitive admission 변경, 부모 verdict 변경, 직접 자식 등록
- 기본 session: match batch마다 `NEW`

### 4.7 CWE Labeling — R5-01

- `cwe-labeling.classify`: current final TRUE `VerificationResult`, evidence closure와 taxonomy revision으로 current `CWELabel` 생성
- 필수 금지: Verification verdict·근거 수정, 과거 label을 새 Verification의 current label로 재사용
- 기본 session: Verification revision마다 `NEW`

### 4.8 Technical Gate — R5-02

- `technical-gate.review`: exact final TRUE Verification과 current CWELabel의 근거 연결·재현·라벨 정합성을 `TechnicalEvidenceReview`로 검토
- 필수 금지: 새 사실·verdict·CWE 생성, Rule·Scope·Impact 판단
- 기본 session: Gate work마다 `NEW`; `REVISE` 뒤 새 Verification·CWE revision 없이는 재호출 금지

### 4.9 Rule Scope Impact Gate — R5-02

- `rule-scope-gate.review`: Technical `ACCEPT` 결과와 공식 정책 record로 `RuleScopeImpactReview` 생성
- 필수 금지: 정책 수집 실패를 정책 부재로 변환, 기술 verdict 수정, 외부 공개 승인
- 기본 session: Gate work마다 `NEW`

### 4.10 Reporter — R5-03

- `reporter.create-draft`: 두 Gate를 통과한 exact finding·근거·CWE·PoC·제약으로 `ReportDraft` 생성
- 필수 금지: 누락 근거 보충, stale draft 재사용, 사람 검토·제출·공개 수행
- 기본 session: report work마다 `NEW`

Orchestration, Runtime Validator, Prompt Registry Runtime, Playbook Registry Runtime, R7 Setup Automation, Sandbox Controller, Reproduction Session Manager, Primitive Admission Runtime과 저장소 계층은 LLM Agent가 아니다. 따라서 이 역할들을 위한 prompt를 만들지 않는다. 문서에서 쓰는 “Orchestration Agent”는 사용자에게 보이는 전역 분석 조정 기능의 이름이며, 실제 등록·중복 후보 축소·배정·상태 전이·권한 검사는 비-LLM runtime이 수행한다. 즉, Orchestration 자체의 별도 LLM prompt는 만들지 않는다.

## 5. Template 필수 구성

모든 template은 다음 구역을 명시한다.

1. `ROLE_AND_SCOPE`: 이 역할이 할 일과 하지 않을 일
2. `TASK`: 현재 `task_kind`의 단일 목적
3. `TRUSTED_RULES`: 변경할 수 없는 판단·권한·출력 규칙
4. `INPUT_SLOTS`: 허용 data kind와 slot 의미
5. `UNTRUSTED_DATA_BOUNDARY`: 코드·문서 안 지시를 데이터로만 취급한다는 규칙
6. `DECISION_CRITERIA`: 이 역할이 실제로 판단할 수 있는 기준
7. `OUTPUT_SCHEMA`: 반환할 schema 이름과 필수 불변조건
8. `UNCERTAINTY_AND_ERRORS`: 모르면 누락을 기록하며 임의로 사실을 만들지 않는 규칙
9. `FORBIDDEN_BEHAVIOR`: 다른 역할의 결과·권한을 만들지 않는 규칙

template 안에는 model 이름, API Key, 로그인 경로, repository 절대 경로, 특정 `analysis_id`, 실제 취약점 결과를 넣지 않는다. 모델·provider 선택은 `LLMCallSpec`, 실제 분석 자료는 `PromptPayload.context_bindings`가 담당한다.

## 6. 조립과 호출 순서

```text
work의 active attempt
→ 역할·task_kind로 ACTIVE PromptRegistryEntry exact revision 선택
→ template_ref·output_schema_ref·semantic_validator_ref exact revision 로드
→ source record에서 slot별 허용 field만 projected_data_ref로 만든 뒤 binding
→ untrusted data 구획·길이 제한·redaction 적용
→ immutable PromptPayload 저장
→ LLMCallSpec에 registry/template/payload와 model·limits·retry·tool·redaction·schema·validator exact refs 고정
→ ActionRequest와 Runtime Validator 검사
→ 허용된 adapter가 같은 논리 payload와 schema를 전송
→ JSON Schema 검사
→ 역할별 semantic validator 검사
→ 성공 output과 LLMInvocationLog를 같은 action outcome에 연결
```

runtime은 호출 직전에 다음 equality를 검사한다.

- role·task가 registry entry와 같은가
- template exact revision과 version이 같은가
- context binding set이 registry의 허용 목록 안이고 필수 slot이 모두 있는가
- 각 binding의 source·projected reference, field projection, cardinality와 trust class가 slot 계약과 같은가
- model profile·provider profile·execution limits·retry·redaction 정책이 registry의 exact revision과 같은가
- spec·request·payload·log의 registry/template/payload reference가 같은가
- output schema와 semantic validator가 registry entry와 같은가
- session 정책과 provider capability가 해당 역할 요구를 만족하는가

하나라도 다르면 provider를 호출하지 않고 decision을 `EXPIRED` 또는 `DENY`로 처리한다. 호출 뒤 실제 exposed request가 `PromptPayload`와 다르면 성공 output으로 저장하지 않는다.

## 7. Provider 중립성과 변환 경계

Provider adapter가 할 수 있는 일:

- 공통 system/user data 구역을 공식 API·CLI·SDK message 형식으로 직렬화
- 공통 JSON Schema를 provider가 지원하는 structured-output 옵션으로 매핑
- 공식 session·timeout·cancellation·usage를 공통 결과로 정규화

Provider adapter가 하면 안 되는 일:

- 역할 지시문·판정 기준·입력 record를 추가·삭제·요약
- 더 쉽게 통과시키기 위해 output schema를 완화
- provider별 숨은 prompt를 결과 의미에 영향을 주도록 추가
- model이 반환하지 않은 usage·request ID·session ID를 추정

호출 가능한 adapter는 R3-04 #90에서 해당 model·실행 환경 조합의 시험을 통과해 `ProviderProfile`이 생성된 경로뿐이다. 후보로 문서화됐지만 아직 시험하지 않은 API·구독 경로는 fixture 대상이나 fallback으로 간주하지 않는다. 승인 profile이 하나도 없으면 모든 prompt entry는 `DRAFT`로 남고 provider 호출을 시작하지 않는다.

provider 제약 때문에 동일 schema를 직접 지원할 수 없으면 그 profile capability를 `UNSUPPORTED`로 두고 해당 역할 호출을 막는다. 별도 provider template이 꼭 필요하면 공통 template과 의미 동등성 fixture, 변경 이유, owner review를 새 registry revision에 기록해야 하며 조용히 분기하지 않는다.

## 8. 입력 격리와 Prompt Injection 방어

- repository code·README·Issue·commit message·정책 원문·도구 출력과 이전 LLM 결과는 모두 `UNTRUSTED_DATA` 구획에 넣는다.
- untrusted data 안의 “규칙을 무시하라”, “도구를 실행하라”, “secret을 출력하라”는 문장을 instruction으로 승격하지 않는다.
- Agent가 요청한 추가 context는 바로 prompt에 넣지 않고 허용 data kind, workspace·commit·hypothesis, exact revision과 budget을 runtime이 다시 검사한다.
- tool 결과도 같은 경계를 통과하며 tool이 반환한 문자열을 system instruction에 이어 붙이지 않는다.
- credential, cookie, token, browser profile과 host 절대 경로는 builder와 log 양쪽에서 redaction한다.
- prompt 전체가 너무 크면 runtime이 승인된 우선순위와 제한으로 새 payload revision을 만들며 adapter가 임의로 자르지 않는다.

Pro와 Con에는 추가 불변조건이 있다. 두 역할은 같은 `debate_input_hash`의 공통 fact를 받되 서로 다른 template, call ID와 `NEW` session을 사용한다. 상대 역할의 output·session·action·tool 결과를 어느 context slot에도 넣지 않는다.

## 9. 출력 검사·repair·retry

1. provider 응답이 없거나 인증·rate limit·timeout이면 domain output을 만들지 않는다.
2. 응답이 있으면 먼저 JSON Schema를 검사한다.
3. schema-valid이면 역할별 semantic validator가 exact refs, enum 조합, 권한 경계를 검사한다.
4. 실패하면 원래 input set과 role을 유지한 제한 repair를 새 `llm_call_id`·spec·action·attempt로 실행한다.
5. repair가 끝나도 invalid이면 `LLMInvocationResult.status=INVALID_OUTPUT`으로 남기고 해당 domain output을 commit하지 않는다.
6. provider/model failover도 새 호출이며 새 adapter가 같은 논리 PromptPayload와 output schema를 사용한다.

repair prompt는 invalid 응답 전체를 신뢰 지시문으로 넣지 않는다. 오류 위치·검증 메시지와 원래 schema를 trusted 구역에, invalid 출력은 untrusted 구역에 넣는다. repair가 판단 내용을 새로 확장하거나 다른 역할로 넘어가면 안 된다.

## 10. 프롬프트 작성·승인 책임

- R1: Hypothesis·Chaining 내용
- R2: prompt가 읽는 StaticFactBundle·코드 위치·정적 근거 slot의 의미 검토
- R3: registry, loader, builder, provider-neutral 전송, 공통 template 골격과 통합 시험
- R4: 공통 schema, exact reference, session·retry·권한·오류 불변조건
- R5: CWE Labeling·Technical Gate·Rule Scope Gate·Reporter 내용
- R6: Pro·Con·Verification 내용과 플레이북 적용 기준
- R7: R7 Reproduction Agent 내용과 Sandbox 실행 자료 경계
- R8: 평가 fixture, 품질·비용·시간 측정, 호출·repair 제한

각 domain owner가 template 문장을 작성하고 R3가 임의로 보안 판단 기준을 대신 쓰지 않는다. R3는 모든 template이 같은 등록·조립·호출 규칙을 따르게 만든다. ACTIVE 전환에는 domain owner, R3, R4와 직접 입력·출력 파트의 검토가 필요하다.

## 11. 필수 시험

| test ID | 확인할 내용 | 통과 기준 |
|---|---|---|
| `PMT-01` | registry 유일성 | `agent_role + task_kind`의 ACTIVE entry가 정확히 하나 |
| `PMT-02` | exact template | version 문자열이 같아도 hash가 다르면 호출 차단 |
| `PMT-03` | 허용 context | 금지 data kind·다른 workspace/commit/hypothesis ref 차단 |
| `PMT-04` | 필수 slot | 누락 시 provider 호출 전 실패 |
| `PMT-05` | R7 role | `R7_AGENT` spec·request·log가 schema와 authority 검사를 통과 |
| `PMT-06` | Pro/Con 격리 | 같은 debate input, 다른 template·call·NEW session, 교차 output 없음 |
| `PMT-07` | injection | repository 지시문이 role·tool·schema를 바꾸지 못함 |
| `PMT-08` | provider 동등성 | #90에서 채택된 각 adapter profile fixture가 같은 논리 payload·schema·의미 검사를 보존 |
| `PMT-09` | structured output | schema 오류는 output 미저장과 제한 repair로 연결 |
| `PMT-10` | semantic output | schema-valid이지만 권한·reference가 틀린 출력 거절 |
| `PMT-11` | failover | 새 provider도 같은 payload revision을 쓰고 새 call/session으로 기록 |
| `PMT-12` | redaction | prompt·request·response·log에 credential과 host 절대 경로 없음 |
| `PMT-13` | stale registry | template/registry/context 변경 뒤 기존 decision·payload 재사용 차단 |
| `PMT-14` | non-LLM roles | Orchestration runtime·Validator·Controller 등에 prompt entry가 없음 |
| `PMT-15` | role outputs | 10개 역할의 성공 output이 등록된 schema와 result owner에 정확히 연결 |

각 역할 template은 최소 한 개 정상 fixture, schema 실패, semantic 실패, prompt injection, stale reference 사례를 가져야 한다. Pro/Con, Gate, R7은 위 공통 사례에 역할별 금지 행동 사례를 추가한다.

## 12. 완료 조건

이 문서 작성만으로 #91을 닫지 않는다. 다음이 모두 필요하다.

- 10개 역할의 초기 registry entry·template·output schema·semantic validator 확정
- `R7_AGENT`가 spec·request·log와 권한 표에서 일치
- Prompt Registry Runtime·Builder의 unit/contract test
- 각 역할 정상·실패·injection fixture
- R3-04의 각 채택 adapter에서 provider 동등성 통합 시험
- R1·R2·R4·R5·R6·R7·R8의 자기 경계 검토 기록
- #92에 실제 파일 구조, 활성 revision과 구현 시작 기준선 반영

구현 전까지는 이 문서의 상태를 `NOT_IMPLEMENTED`로 유지한다. 특정 template이 검토됐더라도 해당 registry entry와 시험 증거 없이 운영 `ACTIVE`로 표시하지 않는다.
