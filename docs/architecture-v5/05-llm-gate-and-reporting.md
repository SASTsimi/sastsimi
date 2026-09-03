# 05. 이중 LLM Gate와 보고

- **이 문서는 무엇을 설명하나요?** 기술 근거와 공식 정책을 차례로 검토하고 보고서 초안을 만들 수 있는 조건을 설명합니다.
- **누가 읽어야 하나요?** Gate·Finding·보고서, 검증과 PM 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 각 Gate의 입력·출력, 보완 요청과 Reporter 호출 조건을 확인합니다.

`Gate`는 다음 단계로 보내도 되는지 확인하는 검토 단계입니다. Gate는 검증 판정을 바꾸지 않고 Reporter는 외부 공개를 결정하지 않습니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목적과 순서

v5에는 책임이 다른 두 LLM 검토 Agent가 있다.

1. final `VerificationResult.verdict=TRUE`, 현재 generation의 `DynamicReproductionRequest`·성공한 `DynamicReproductionResult`·validated PoC와 별도 `CWELabel`의 정확한 `record_id` revision을 Technical Evidence Gate Agent가 함께 검토한다. FALSE와 HOLD는 이 Gate를 호출하지 않는다.
2. Technical 결과가 `ACCEPT`이면 result가 있는 Primitive admission과 Chaining을 허용한다. 이 기술 재료 경로는 Rule Scope 결과를 기다리지 않는다.
3. 같은 Technical `ACCEPT`에서 Rule Scope Impact Gate Agent를 호출하고, 두 Gate와 impact·permission 조건을 모두 통과했을 때만 같은 Verification owner가 Reporter Agent 호출을 요청한다.

가설 내부의 Gate 제출 시점은 같은 가설의 Verification owner가 정한다. Verification은 `CALL_TECHNICAL_GATE`와, Technical `ACCEPT` 뒤의 `CALL_RULE_SCOPE_GATE`, 모든 보고 조건을 통과한 뒤의 `CREATE_REPORT_DRAFT`를 제안한다. 실제 호출 가능 여부와 순서는 비-LLM Runtime Validator가 강제한다. Orchestration Agent가 `REVISE` 목적지를 선택하거나 Verification 대신 Gate 보완 내용을 조정하지 않는다.

두 Gate는 점수 합산식이나 취약점 진위를 새로 판정하는 규칙 엔진이 아니다. 각자의 자료를 읽고 근거가 있는 검토 결과를 생성하는 LLM Agent이며 Verification verdict를 직접 변경할 수 없다.

비-LLM Runtime Validator는 Gate의 결론을 대신 만들지 않는다. `ActionRequest`의 역할·schema·exact input revision·상태·예산과 Gate 순서만 검사한다. Technical Gate 호출에는 final TRUE Verification, CWELabel, 현재 generation의 동적 요청, `SUCCEEDED + SUPPORTED` 동적 결과와 validated `poc_ref`의 `COMMITTED` revision이 필요하다. Rule Scope Gate 호출에는 같은 Verification이 `TRUE`이며 Technical review가 `ACCEPT`라는 exact reference가 필요하다. 조건이 맞지 않으면 `GATE_ORDER_INVALID`로 호출 자체를 막는다. 이 exact reference 검사는 action 허가 시점과 실제 LLM 호출 직전에 다시 수행한다.

## CWE 라벨링

CWE 후보는 final TRUE 뒤에 Gate 입력으로 작성한다. primary·alternative CWE, taxonomy version, 선택 이유와 evidence reference를 포함한다. `HOLD`나 `FALSE`에 분석용 분류 메모를 남길 수는 있지만 Gate 입력 `CWELabel`이나 보고 가능한 취약점 라벨로 승격하지 않는다. 구분 근거가 부족하면 억지로 단일 CWE를 확정하지 않는다.

## Gate 1: Technical Evidence Gate Agent

### 입력

- `VulnerabilityHypothesis`
- final `VerificationResult`의 정확한 `record_id`가 있는 `StoredDataRef`와 revision history
- Pro/Con evidence와 debate mode/trigger
- 실제 code/entity/location/path reference
- 현재 generation의 `DynamicReproductionRequest`, `DynamicReproductionResult`와 exact validated `poc_ref`·`policy_decision_ref`·`environment_ref`·`agent_log_ref`
- `CWELabel`의 정확한 `record_id`가 있는 `StoredDataRef`와 근거
- restriction, bypass candidate, unresolved condition
- 같은 Verification에서 분리한 material child proposal 중 재검증 완료 여부

### 검토 항목

- final `TRUE`와 찬성·반대 근거의 일치
- 핵심 주장이 현재 `workspace_id`와 `commit_id`의 코드 위치·호출·데이터 흐름에 연결되는지
- 동적 관측이 현재 가설·`workspace_id`·실행 조건에 연결되는지
- `agent_invoked`와 같은 attempt의 `agent_log_ref`, 실제 환경 생성 여부와 `environment_ref`, 정책 차단과 Controller의 `policy_decision_ref`, cleanup 필요 여부·상태가 공통 계약에 맞는지
- `poc_ref`가 실제 실행된 `poc_candidate_ref`, 성공 log와 `SUCCEEDED + SUPPORTED` 관측의 같은 revision에 연결되는지
- 동적 근거가 승인된 Sandbox 정책 안에서 생성되었고 금지된 재현으로 오염되지 않았는지
- CWE 선택이 취약점 유형과 근거에 적절한지
- 실제 코드 경로, restriction·반박·HOLD 조건이 빠짐없이 정확하게 표현되었는지
- 기술 검토 결과를 다음 단계 또는 내부 종결 기록으로 전달할 수 있는지

### 출력과 의미

```yaml
technical_evidence_review:
  action_decision_ref: StoredDataRef
  verification_result_ref:
    stored_data_id: data-verification-001
    data_kind: verification_result
    content_hash: sha256:example
    workspace_id: ws-001
    commit_id: 7f3a2c1
    record_id: rec-verification-003
  cwe_label_ref: StoredDataRef
  status: ACCEPT | REVISE | REJECT
  evidence_verdict_alignment: explanation
  code_flow_linkage: explanation
  dynamic_linkage: explanation
  cwe_assessment: explanation
  restriction_assessment: explanation
  handoff_readiness: READY | NOT_READY
  revision_requests: []
  verification_requests: []
  rationale: explanation
```

- `ACCEPT`: 현재 TRUE 판정과 기술 설명이 검토 가능한 근거에 연결되어 있다. 정책상 보고 가능하다는 뜻은 아니다.
- `REVISE`: 같은 hypothesis의 Verification owner가 구체적인 누락·restriction·재현·CWE 설명을 보완해야 한다.
- `REJECT`: 현재 자료를 신뢰 가능한 기술 기록이나 다음 단계 입력으로 사용할 수 없다.

`ACCEPT`는 `handoff_readiness=READY`, `REVISE | REJECT`는 `handoff_readiness=NOT_READY`와 함께 사용한다. 이 조합이 맞지 않으면 Gate output을 저장하지 않는다.

`DynamicReproductionResult(status=BLOCKED, failure_category=POLICY)`는 정책 때문에 현재 attempt를 진행하지 못했다는 뜻이지 가설 반증이 아니다. 그러나 validated PoC가 없으므로 final TRUE를 저장하거나 Technical Gate를 호출할 수 없다. 이 경우 Verification과 동적 work를 `BLOCKED`로 유지하거나 복구 불가능하면 verdict 없이 `FAILED`로 끝낸다. 정책 차단 자체를 `FALSE | HOLD` 또는 Gate의 `REJECT` 근거로 바꾸지 않는다.

`verification_result_ref.record_id`와 `cwe_label_ref.record_id`는 Gate가 실제로 읽은 `VerificationResult`와 `CWELabel` revision을 각각 고정한다. runtime은 Gate와 두 대상의 `workspace_id`, `commit_id`, `hypothesis_id`, `record_id`, `content_hash`를 확인한다. Verification 또는 CWELabel이 수정되면 이전 `ACCEPT`를 새 revision에 재사용하지 않고 Gate를 새로 호출한다.

`REVISE`는 동일 입력 재투표나 provider retry가 아니다. 현재 Gate work는 `REVISE` review를 exact output으로 확정하고 종료한다. 그 review는 Orchestration을 경유해 목적지를 다시 선택하지 않고 같은 hypothesis의 ACTIVE `VerificationAssignment` owner에게 전달한다. runtime은 이전 종료 work를 되돌리지 않고 새 generation의 VERIFICATION work를 등록하며 hypothesis 상태를 `TERMINAL -> VERIFYING`으로 CAS 전환한다. Verification은 필요한 Context·Pro/Con·정적 근거·restriction을 보완하고, final TRUE 후보라면 새 generation의 동적 재현 요청과 validated PoC도 다시 확보한다. 새 result·work 종료·hypothesis current pointer를 atomic commit하고, 필요하면 CWE producer와 새 label revision을 조정한다. 그 뒤 새 `VerificationResult` 및 필요한 `CWELabel` revision을 가리키는 새 Gate work를 요청한다. 새 Gate work는 새 `input_hash`·`dedupe_key`·`work_id`와 `attempt_number=1`, `trigger=INITIAL`을 사용한다. 입력이 바뀌지 않은 호출 실패만 같은 work 안에서 `trigger=RETRY`인 새 attempt를 사용할 수 있다. 공통 token·시간·비용·work 예산을 소진하면 보고와 result Primitive admission을 차단하고 미해결 사유를 저장한다.

Runtime Validator는 `REVISE`를 만든 기존 action·decision을 다시 사용하지 못하게 하고, 같은 Verification·CWE revision 또는 같은 domain input hash로 새 Gate 투표를 요청하면 `ACTION_NOT_ALLOWED`로 차단한다. 보완된 upstream revision을 가리키는 새 work·call spec·action·decision이 모두 있어야 한다. 반대로 provider 실패나 `INVALID_OUTPUT` repair는 Gate 판단을 다시 요구한 것이 아니므로, 허용된 횟수 안에서 같은 domain input과 새 invocation 식별자·action을 사용하는 `RETRY`로만 처리한다.

## Gate 2: Rule Scope Impact Gate Agent

이 Gate는 Technical `ACCEPT`인 `TRUE`만 받는다. 취약점 기술 성립과 bug-bounty 프로그램의 보고 가능성을 분리한다.

### ProgramPolicyRecord

입력 정책은 Gate가 확인할 수 있는 공식 자료를 수집한 기록이어야 한다.

- program identifier, policy version과 fetch timestamp
- 공식 rule, eligibility와 severity/impact 기준
- in-scope/out-of-scope asset와 vulnerability class
- 금지된 테스트·재현 행위
- known limitation, duplicate 또는 disclosure 조건
- 각 항목의 official source reference
- 수집하지 못한 자료와 freshness warning

저장소 문서나 모델 기억을 공식 정책으로 자동 승격하지 않는다. 공식 `ProgramPolicyRecord`가 없거나 핵심 자료가 누락되면 추측하지 않는다. 정책 record가 있어도 `freshness_status=STALE | UNVERIFIED`이면 최신 정책으로 취급하지 않는다. `CURRENT` 판정의 최대 허용 나이와 출처별 확인 방법은 R5 정책 수집 설계에서 정하지만, stale·미검증 상태의 Gate 결과는 항상 `UNCERTAIN + DENY`다.

### 검토 항목

- 프로그램 rule과 eligibility 충족 여부
- 대상 asset과 vulnerability class의 scope
- 수행한 재현이 금지 조건과 충돌하는지
- 검증된 실제 impact가 프로그램 기준에 충분한지
- restriction, alternate path와 미검증 Verification-origin 또는 Chaining-origin child의 표현이 정확한지
- 보고서 초안을 작성할 수 있는지

### 출력

```yaml
rule_scope_impact_review:
  action_decision_ref: StoredDataRef
  verification_result_ref: StoredDataRef
  technical_review_ref: StoredDataRef
  cwe_label_ref: StoredDataRef
  review_status: PASS | FAIL | UNCERTAIN
  rule_compliance: PASS | FAIL | UNCERTAIN
  scope_compliance: PASS | FAIL | UNCERTAIN
  security_impact: SUFFICIENT | INSUFFICIENT | UNCERTAIN
  report_permission: ALLOW | DENY
  policy_record_ref: StoredDataRef | null
  reasons: []
  missing_information: []
```

공식 정책 자료가 없거나 `freshness_status=STALE | UNVERIFIED`이면 Rule Scope Gate Agent가 정책을 추정하지 않고 최소한 `rule_compliance=UNCERTAIN`, `scope_compliance=UNCERTAIN`, `review_status=UNCERTAIN`, `report_permission=DENY`와 `missing_information`을 판단해 반환한다. impact도 검토할 근거가 부족하면 `security_impact=UNCERTAIN`이다. stale record의 exact reference와 경고는 감사 기록으로 보존하지만 `PASS | ALLOW` 근거로 사용하지 않는다.

Runtime Validator는 공식 정책 문장이나 정책의 의미를 대신 해석하지 않는다. Rule Scope Gate가 판단한 `UNCERTAIN + DENY`의 필수 필드, exact 정책 reference와 구조적 불변조건만 검사한다. `policy_record_ref=null`이거나 핵심 공식 source가 누락된 출력에서 `ALLOW`·`PASS`가 함께 나타나면 semantic `INVALID_OUTPUT`으로 거절하고, 정상적인 `UNCERTAIN + DENY`이면 `REPORT_READY` check로 Reporter만 프로그램적으로 차단한다. 제한된 repair 뒤에도 불변조건이 맞지 않으면 Rule Scope Gate work를 실패 처리한다. 두 경우 모두 Verification verdict를 바꾸지 않는다.

`verification_result_ref`, `technical_review_ref`, `cwe_label_ref`와 존재하는 `policy_record_ref`에는 정확한 저장 revision의 `record_id`가 필요하다. runtime은 Technical review가 `ACCEPT`이고, Technical review와 Rule Scope review가 같은 Verification과 CWELabel `record_id`를 각각 가리키는지 확인한다. 각 reference의 `workspace_id`, `commit_id`, `content_hash`는 대상 record와 일치해야 하며, Verification·CWELabel·Technical 대상의 `meta.hypothesis_id`는 Rule Scope review의 가설과 같아야 한다. 정책이 있으면 Rule Scope review가 가리킨 정책 record와 Reporter가 사용할 정책 record도 같아야 한다. 입력 revision이 하나라도 달라지면 기존 Rule Scope 결과를 재사용하지 않는다.

## Technical-accepted TRUE와 Primitive admission

final TRUE가 Chaining에 쓰이려면 current generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 validated PoC가 있고 exact 같은 Verification+CWE revision을 Technical Gate가 `ACCEPT`해야 한다. 이때 runtime은 `provided_primitive_candidates`의 각 능력을 result로, `required_primitive_candidates`를 inputs로, Verification restrictions를 restrictions로 가진 Primitive admission을 허가한다.

Rule Scope Gate는 제출·보고 가능성을 판단하며 Primitive admission의 입력이 아니다. Rule Scope `FAIL | UNCERTAIN | DENY`는 Reporter를 차단하지만 Technical-accepted TRUE에서 이미 확인된 Primitive와 Chaining을 취소하지 않는다. Gate 전 TRUE와 Technical `REVISE | REJECT`는 result Primitive나 Chaining 입력이 아니다. HOLD는 Technical Gate를 사용하지 않고 final HOLD의 required candidates를 inputs로 가진 result 없는 Primitive로 즉시 들어간다.

## Reporter 호출 조건

다음 조건을 모두 만족해야 한다.

```text
final verdict == TRUE
AND current dynamic reproduction == SUCCEEDED + SUPPORTED
AND validated poc_ref exists
AND Technical Evidence Gate == ACCEPT
AND Rule Scope Impact Gate review_status == PASS
AND rule_compliance == PASS
AND scope_compliance == PASS
AND security_impact == SUFFICIENT
AND report_permission == ALLOW
```

조건이 하나라도 충족되지 않거나 Gate reference 연결이 맞지 않으면 결과와 검토 사유는 저장하지만 Reporter를 호출하지 않는다. LLM이 `review_status`, rule, scope 또는 impact 조건과 모순되는 `ALLOW`를 출력하면 semantic validation 실패다. 이 호출은 `LLMInvocationResult.status=INVALID_OUTPUT`, `AnalysisError.stage=GATE`, `AnalysisError.code=INVALID_OUTPUT`으로 기록하며 invalid output을 `RuleScopeImpactReview`로 commit하지 않는다. 제한된 repair가 남아 있을 때만 같은 입력의 새 invocation attempt를 허용하고, 한도를 소진하면 Gate work를 `FAILED`로 끝낸다. 어느 경우에도 Reporter를 호출하거나 Verification verdict를 변경하지 않는다. 이는 취약점 판정 규칙이 아니라 권한 없는 보고 생성을 막는 호출 전제다.

Gate와 Reporter의 stage action은 exact `LLMCallSpec`까지 포함해 실제 LLM 호출을 직접 허가한다. 이 세 역할이 별도 `CALL_LLM` action으로 stage 검사를 우회하는 것은 허용하지 않는다. Technical action의 `REVISION`은 exact Verification+CWE를, `GATE_ORDER`는 두 revision의 final `COMMITTED` 상태를 검사한다. Rule Scope action의 `REVISION`은 같은 Verification+CWE와 exact Technical review를, `GATE_ORDER`는 `TRUE`+Technical `ACCEPT`를 검사한다. Reporter action의 `REVISION`은 current Finding과 두 Gate가 검토한 같은 Verification+CWE·Technical·Rule Scope·정책 revision을 검사하고 `REPORT_READY`는 Finding 존재와 위 모든 조건을 검사한다. 하나라도 맞지 않으면 `REPORT_NOT_READY`로 차단한다. Runtime은 이 검사를 action 허가 때와 실제 provider 호출 직전에 반복하며, 달라졌으면 decision을 `EXPIRED`로 바꾸고 호출하지 않는다. 실제 invocation request의 model·prompt·context·schema·budget·timeout은 검사한 call spec과 모두 같아야 한다.

## Reporter Agent

Reporter는 통과한 근거를 읽기 쉬운 내부 초안으로 구성한다.

- 취약점 요약, 공격 전제와 실제 영향
- current Finding과 final Verification의 exact reference
- entity·코드 위치와 source → propagation/call → sink
- restriction, bypass 검토와 반박 처리
- 성공한 동적 재현과 redacted validated PoC. 실패한 PoC candidate는 실행 이력으로만 구분해 표시
- 두 Gate가 검토한 같은 `CWELabel` revision과 선택 이유
- 두 Gate 결과와 `ProgramPolicyRecord` reference
- Verification-origin 및 Chaining-origin child proposal의 재검증 여부
- 완화와 회귀 테스트 제안
- invocation trace와 남은 불확실성

Reporter는 새로운 공격 경로를 확정하거나 미검증 material child 또는 Chaining 후보를 실제 영향으로 쓰지 않는다. 초안의 핵심 주장은 current Finding, Verification, validated PoC와 두 Gate의 exact revision에 연결한다. 실패한 시도의 `poc_candidate_ref`는 validated `poc_ref`나 재현 성공으로 서술하지 않는다. `ReportDraft.cwe_label_ref.record_id`는 Technical review와 Rule Scope review가 공통으로 가리킨 CWELabel `record_id`와 같아야 하며, CWELabel이 수정되면 두 Gate를 다시 통과하기 전에는 초안을 만들지 않는다.

Reporter는 Verification의 restriction과 unresolved condition, 정적·동적 검증 및 두 Gate의 limitation을 빠뜨리거나 완화하지 않는다. 저장 전 `REDACTION=PASS`를 요구하며 credential, session secret, 불필요한 개인정보와 비공개 원문을 제거한다. 이 값은 `ReportDraft.restrictions`, `limitations`, `unresolved_conditions`, `redaction_status=PASSED`로 확인할 수 있어야 한다.

ReportDraft가 참조한 `FindingCandidate`, `VerificationResult`, `CWELabel`, `TechnicalEvidenceReview`, `RuleScopeImpactReview` 또는 `ProgramPolicyRecord` 중 하나라도 새 current revision으로 바뀌면 기존 초안은 감사 기록으로만 남고 `AnalysisRunResult.report_draft_refs`의 current 결과로 사용할 수 없다. 새 exact dependency chain으로 Gate와 Reporter를 다시 실행해 새 ReportDraft를 만든다.

## Agent 자동화 종료와 사람 주도 후속 과정

`ReportDraft`는 R5-03 Reporter와 전체 Agent 파이프라인의 마지막 Agent 산출물이다. Reporter work가 atomic하게 종료되면 신뢰 runtime은 다음 항목을 `AnalysisRunResult`에 묶는다.

- Finding 후보와 final Verification
- Technical·Rule Scope Gate와 CWE·공식 정책 reference
- dynamic reproduction과 redacted PoC
- current ReportDraft 또는 초안이 만들어지지 않은 구체적인 이유
- token·시간·Sandbox 등 자원 사용량
- 모든 실행 오류·DataGap·남은 HOLD 조건
- LLM 호출·action decision·work state·work attempt·transition commit와 debug trace reference

`AnalysisRunResult`와 `AnalysisRunState`를 함께 확정하면 Agent 자동화가 끝난다. Finding이 없으면 Reporter를 호출하지 않고 `report_draft_refs=[]`로 종료 원인을 보존한다. 이후 사람이 결과를 검토하거나 문서를 수정하고 외부에 제출·공개하는 과정은 Agent 자동화 밖이다. 현재 아키텍처는 이 사람 주도 과정의 schema, 상태, 결정 enum 또는 자동 action을 정의하지 않는다.
