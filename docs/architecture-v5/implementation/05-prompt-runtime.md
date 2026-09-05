# R3-05. Agent 프롬프트 등록·조립·전달 구조

- **이 문서는 무엇을 설명하나요?** 역할별 프롬프트를 어디에 두고, 어떤 입력을 넣어 LLM에 전달하며, 결과를 어떻게 검사하고 기록할지 설명합니다.
- **누가 읽어야 하나요?** R1·R5·R6·R7의 프롬프트 작성자, R2 입력 자료 담당자, R3 통합 구현자, R4 계약 담당자와 R8 평가 담당자가 읽습니다.
- **읽은 뒤 무엇을 결정해야 하나요?** 각 역할의 첫 prompt revision, 입출력 schema, session 정책, 검증 함수와 평가 fixture를 승인합니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 1. 기준과 핵심 결론

- 작성 기준 `main`: `3d30253acc27d57916611e0ebea2fd46344c5fa8`
- 연결 Issue: [R3-05 #91](https://github.com/SASTsimi/sastsimi/issues/91)
- Provider 연결 결정: [R3-04 #90](https://github.com/SASTsimi/sastsimi/issues/90)
- 최종 구현 기준선: [R3-06 #92](https://github.com/SASTsimi/sastsimi/issues/92)

프롬프트는 Markdown 파일 하나만 저장한다고 완성되지 않는다. 다음 네 항목을 함께 versioning해야 실행 가능한 프롬프트가 된다.

1. 역할과 작업을 찾는 `PromptRegistryEntry`
2. 사람이 검토하는 immutable prompt template
3. template에 넣을 허용 입력과 exact reference
4. 출력 JSON Schema와 역할별 semantic validator

Agent는 prompt 문자열을 직접 만들거나 입력을 임의로 추가하지 않는다. 신뢰 경계 안의 `Prompt Registry Runtime`과 `Prompt Builder`가 승인된 등록 정보, template, exact context로 `PromptPayload`를 만들고 `Runtime Validator`가 호출 전 동일성을 검사한다.

OpenAI API, Codex 구독, Anthropic API, Claude 구독은 같은 **논리 PromptPayload와 출력 schema**를 받는다. provider adapter는 이를 각 공식 API·CLI·SDK의 전송 형식으로 바꿀 수 있지만 역할·입력·판정 기준을 바꾸거나 provider별로 별도 결론 규칙을 만들면 안 된다.

## 2. 구현 파일 구조

첫 구현은 하나의 Python 애플리케이션 안에서 다음처럼 나눈다. 경로는 #92에서 저장소 기본 구조로 최종 승인한다.

```text
config/
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
  allowed_context_kinds:
    - vulnerability_hypothesis
    - playbook_application
    - pro_evidence_result
    - con_evidence_result
    - dynamic_reproduction_result
  forbidden_context_kinds:
    - report_draft
    - rule_scope_impact_review
  output_schema: VerificationResult@MAJOR
  session_policy: NEW
  model_profile_ref: StoredDataRef
  provider_profile_refs: [StoredDataRef]
  execution_limits_ref: StoredDataRef
  retry_policy_ref: StoredDataRef
  semantic_validator: verification_result_v1
  tool_policy_ref: null
  redaction_policy_ref: StoredDataRef
  result_kind: verification_result
  status: ACTIVE
  owner_role: R6
  reviewer_roles: [R3, R4, R7, R8]
```

`prompt_key`는 사람이 설정과 리뷰에서 찾기 쉬운 등록 이름이다. record의 정체성과 정확한 수정본은 `meta.logical_record_id`, `meta.revision_number`와 `StoredDataRef(record_id + content_hash)`가 기준이다. `prompt_key`나 `template_version` 문자열만으로 실행할 수정본을 찾으면 안 된다.

`model_profile_ref`는 역할별 모델 선택 정책, `provider_profile_refs`는 허용 연결 경로 목록, `execution_limits_ref`는 token 계획값·timeout·동시성 한도, `retry_policy_ref`는 repair·retry·explicit failover 조건을 고정한다. 실제 호출은 이 목록 중 하나의 exact `provider_profile_ref + model`을 `LLMCallSpec`에 기록한다. Provider가 바뀌어도 template와 판단 기준은 그대로이며, profile 목록 변경은 새 registry revision과 재검토가 필요하다. `tool_policy_ref=null`은 tool 사용 금지, `result_kind`는 성공 출력의 유일한 저장 계약을 뜻한다.

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
  output_schema: string

PromptContextBinding:
  slot: string
  data_kind: string
  data_ref: StoredDataRef
  trust_class: TRUSTED_INSTRUCTION | UNTRUSTED_DATA
```

`rendered_prompt_ref`는 adapter에 넘기기 직전의 redacted prompt artifact를 가리킨다. 비밀값과 hidden chain-of-thought는 저장하지 않는다. `TRUSTED_INSTRUCTION`에는 repository 내용이나 LLM 출력이 들어갈 수 없으며, 분석 대상 코드·README·Issue·정책 원문·도구 출력은 모두 `UNTRUSTED_DATA`다.

## 4. 역할별 첫 Prompt Registry

아래는 구현 시작에 필요한 최소 등록 목록이다. 하나의 역할이 여러 task를 가지면 서로 다른 registry entry와 template을 사용한다.

### 4.1 Hypothesis Agent — R1

- `hypothesis.generate-initial`: `StaticFactBundle`에서 `HypothesisProposal(origin=INITIAL)` 생성
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

- `verification.initial-synthesis`: Pro·Con과 정적 근거를 종합해 동적 재현 필요 여부와 초기 판단 초안 생성
- `verification.dynamic-request`: 필요 목적·목표·환경 조건을 `DynamicReproductionRequest`로 생성
- `verification.final-verdict`: current generation의 근거와 동적 결과를 종합해 final `VerificationResult` 생성
- `verification.technical-revise`: Technical Gate의 구조화된 보완 요청을 읽고 같은 가설의 새 generation 작업 결정
- 필수 금지: R7의 plan·command 대신 작성, CWE·Gate 결과·보고서 생성
- session: Pro·Con session을 재개하지 않는다. 보완도 새 invocation이며 `NEW`가 기본이다.

### 4.5 R7 Reproduction Agent — R7

- `r7.prepare-reproduction`: exact `DynamicReproductionRequest`에서 `EnvironmentRequirements`와 `ReproductionPlan` 생성
- `r7.run-and-observe`: 승인된 Sandbox 안에서 PoC candidate·command·관찰·자율 retry를 수행하고 해석 event 생성
- 필수 금지: Sandbox 외부 경계 우회, final `TRUE | FALSE | HOLD`, validated PoC 또는 final `DynamicReproductionResult` 직접 확정
- session: 한 dynamic work/attempt의 정책에 따르며 다른 가설 session을 재사용하지 않는다.

이 역할은 기존 `ActionRequest.requested_by=R7_AGENT`와 일치해야 하므로 `LLMCallSpec`, request와 log의 `agent_role`에도 `R7_AGENT`가 반드시 포함된다.

### 4.6 Chaining Agent — R1

- `chaining.match-primitives`: exact eligible Primitive 집합에서 result→input match와 `ChainingResult` 생성
- `chaining.propose-child`: committed material match에서 `HypothesisProposal(origin=CHAINING)` 생성
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
→ template_ref·output_schema·semantic_validator 로드
→ 허용된 exact context만 slot에 binding
→ untrusted data 구획·길이 제한·redaction 적용
→ immutable PromptPayload 저장
→ LLMCallSpec에 registry/template/payload exact refs 고정
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
| `PMT-08` | provider 동등성 | 네 adapter fixture가 같은 논리 payload·schema·의미 검사를 보존 |
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
