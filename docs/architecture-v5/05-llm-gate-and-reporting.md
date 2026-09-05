# 05. 이중 LLM Gate와 보고

- **이 문서는 무엇을 설명하나요?** 기술 근거와 공식 정책을 차례로 검토하고 보고서 초안을 만들 수 있는 조건을 설명합니다.
- **누가 읽어야 하나요?** Gate·Finding·보고서, 검증과 PM 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 각 Gate의 입력·출력, 보완 요청과 Reporter 호출 조건을 확인합니다.

`Gate`는 다음 단계로 보내도 되는지 확인하는 검토 단계입니다. Gate는 검증 판정을 바꾸지 않고 Reporter는 외부 공개를 결정하지 않습니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목적과 순서

v5에는 책임이 다른 두 LLM 검토 Agent가 있다.

1. final `VerificationResult.verdict=TRUE`와 현재 generation의 validated PoC가 확정되면 R5-01 `CWE_LABELING`이 별도 `CWE_LABEL` work에서 그 exact Verification을 가리키는 current `CWELabel` revision을 만든다. Technical Evidence Gate Agent는 이 정확한 Verification·CWELabel 쌍과 연결된 동적 결과를 함께 검토한다. FALSE와 HOLD는 CWE work와 이 Gate를 호출하지 않는다.
2. Technical 결과가 `ACCEPT`이면 같은 exact Verification에 대해 Rule Scope Impact Gate Agent를 호출한다. Gate 2가 실제 수행 행위와 공식 정책을 비교해 `testing_restriction_compliance`을 명시적으로 판정한다.
3. R5는 `testing_restriction_compliance`와 정책 provenance를 생산하고, R4 `PRIMITIVE_ADMISSION_RUNTIME`이 이를 current `PrimitiveAdmissionDecision`으로 기계적으로 매핑한다. result Primitive 저장과 Chaining은 `decision=ALLOW`만 허용하며 Reporter는 별도로 Rule·Scope·Impact·permission 조건까지 모두 통과해야 한다.

가설 내부의 Gate 제출 시점은 같은 가설의 Verification owner가 정한다. Verification은 `CALL_TECHNICAL_GATE`와, Technical `ACCEPT` 뒤의 `CALL_RULE_SCOPE_GATE`, 모든 보고 조건을 통과한 뒤의 `CREATE_REPORT_DRAFT`를 제안한다. 실제 호출 가능 여부와 순서는 비-LLM Runtime Validator가 강제한다. Orchestration Agent가 `REVISE` 목적지를 선택하거나 Verification 대신 Gate 보완 내용을 조정하지 않는다.

두 Gate는 점수 합산식이나 취약점 진위를 새로 판정하는 규칙 엔진이 아니다. 각자의 자료를 읽고 근거가 있는 검토 결과를 생성하는 LLM Agent이며 Verification verdict를 직접 변경할 수 없다.

비-LLM Runtime Validator는 Gate나 CWE의 의미 결론을 대신 만들지 않는다. `ActionRequest`의 역할·schema·exact input revision·상태·예산과 Gate 순서만 검사한다. Technical Gate 호출에는 final TRUE Verification, 그 exact Verification을 직접 가리키며 성공한 R5-01 `CWE_LABEL` work의 유일한 output인 current CWELabel, 현재 generation의 동적 요청, `SUCCEEDED + SUPPORTED` 동적 결과와 validated `poc_ref`의 `COMMITTED` revision이 필요하다. Rule Scope Gate 호출에는 같은 Verification이 `TRUE`이며 Technical review가 `ACCEPT`라는 exact reference가 필요하다. 조건이 맞지 않으면 `GATE_ORDER_INVALID`로 호출 자체를 막는다. 이 exact reference 검사는 action 허가 시점과 실제 LLM 호출 직전에 다시 수행한다.

## CWE 라벨링

`CWELabel`의 logical producer/runtime role은 `CWE_LABELING`, R1~R8 실제 owner는 R5-01이다. final TRUE 뒤 별도 `CWE_LABEL` work에서 primary·alternative CWE, taxonomy version, 선택 이유와 evidence reference를 작성한다. label은 자신이 분류한 exact `VerificationResult` revision·generation과 생산 work·호출을 직접 가리킨다. `HOLD`나 `FALSE`에 분석용 분류 메모를 남길 수는 있지만 Gate 입력 `CWELabel`이나 보고 가능한 취약점 라벨로 승격하지 않는다. 구분 근거가 부족하면 억지로 단일 CWE를 확정하지 않는다.

새 Verification revision 또는 generation이 생기면 R5-01은 root cause·Evidence·taxonomy 정렬을 다시 평가한다. 동일 CWE가 계속 적절하더라도 새 Verification을 가리키는 새 `CWELabel` revision을 확정하며 과거 label은 history로만 보존한다. Technical Gate는 current label의 정합성만 검토하고 이를 생성·수정·덮어쓰지 않는다.

## Gate 1: Technical Evidence Gate Agent

### 입력

- `VulnerabilityHypothesis`
- final `VerificationResult`의 정확한 `record_id`가 있는 `StoredDataRef`와 revision history
- Pro/Con evidence와 debate mode/trigger
- 실제 code/entity/location/path reference
- 현재 generation의 `DynamicReproductionRequest`, `DynamicReproductionResult`와 exact validated `poc_ref`·`policy_decision_ref`·`environment_recipe_ref`·`environment_ref`·`agent_log_ref`
- `CWELabel`의 정확한 `record_id`가 있는 `StoredDataRef`와 근거
- restriction, bypass candidate, unresolved condition
- 같은 Verification에서 분리한 material child proposal 중 재검증 완료 여부

### 검토 항목

- final `TRUE`와 찬성·반대 근거의 일치
- 핵심 주장이 현재 `workspace_id`와 `commit_id`의 코드 위치·호출·데이터 흐름에 연결되는지
- 동적 관측이 현재 가설·`workspace_id`·실행 조건에 연결되는지
- Agent 호출 여부와 append-only AgentLog, recipe·실제 환경·container lifecycle, 정책 차단과 Controller 판정, 정리 필요 여부와 상태가 공통 계약에 맞는지
- `poc_ref`가 실제 실행된 `poc_candidate_ref`, 성공 log와 `SUCCEEDED + SUPPORTED` 관측의 같은 revision에 연결되는지
- 동적 근거가 승인된 Sandbox 경계 안에서 생성되었고 exact 실행 provenance가 손상·혼합되지 않았는지
- CWE 선택이 취약점 유형과 근거에 적절한지
- 실제 코드 경로와 각 restriction의 `restriction_id`·exact 근거 reference, 반박·HOLD 조건이 빠짐없이 정확하게 표현되었는지
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

`ACCEPT`는 `handoff_readiness=READY`, `REVISE | REJECT`는 `handoff_readiness=NOT_READY`와 함께 사용한다. 여기서 `READY`는 동일 exact Verification revision을 Gate 2 입력으로 전달할 수 있다는 뜻이며 Reporter나 그 이후 단계를 허가하지 않는다. 이 조합이 맞지 않으면 Gate output을 저장하지 않는다.

`DynamicReproductionResult(status=BLOCKED | FAILED, failure_category=POLICY_BLOCKED)`는 정책 때문에 실행하지 못했다는 뜻이지 가설 반증이 아니다. 그러나 validated PoC가 없으므로 final TRUE를 저장하거나 Technical Gate를 호출할 수 없다. 외부 정책·설정을 바꿀 수 있으면 Verification과 동적 work를 `BLOCKED`로 유지하고, 복구 불가능하면 verdict 없이 `FAILED + INCONCLUSIVE`로 끝낸다. 정책 차단 자체를 `FALSE | HOLD` 또는 Gate의 `REJECT` 근거로 바꾸지 않는다.

`verification_result_ref.record_id`와 `cwe_label_ref.record_id`는 Gate가 실제로 읽은 `VerificationResult`와 `CWELabel` revision을 각각 고정한다. runtime은 Gate와 두 대상의 `workspace_id`, `commit_id`, `hypothesis_id`, `record_id`, `content_hash`를 확인하고 `CWELabel.verification_result_ref`가 Gate의 `verification_result_ref`와 정확히 같은지 검사한다. label의 generation·work·attempt·invocation이 current CWE work와 다르거나 과거 Verification의 label이면 호출·저장을 차단한다. Verification 또는 CWELabel이 수정되면 이전 `ACCEPT`를 새 revision에 재사용하지 않고 R5-01 CWE 평가와 Gate를 새로 실행한다.

`REVISE`는 동일 입력 재투표나 provider retry가 아니다. 현재 Gate work는 `REVISE` review를 exact output으로 확정하고 종료한다. 그 review는 Orchestration을 경유해 목적지를 다시 선택하지 않고 같은 hypothesis의 ACTIVE `VerificationAssignment` owner에게 전달한다. runtime은 이전 종료 work를 되돌리지 않고 새 generation의 VERIFICATION work를 등록하며 hypothesis 상태를 `TERMINAL -> VERIFYING`으로 CAS 전환한다. Verification은 필요한 Context·Pro/Con·정적 근거·restriction을 보완하고, final TRUE 후보라면 새 generation의 동적 재현 요청과 validated PoC도 다시 확보한다. 새 result·work 종료·hypothesis current pointer를 atomic commit한다. 이후 R5-01이 새 CWE work에서 정렬을 다시 평가해 새 Verification을 직접 가리키는 current `CWELabel` revision을 확정한다. 같은 CWE 값이어도 이전 label reference를 재사용하지 않는다. 그 뒤 새 `VerificationResult`와 current `CWELabel` revision을 가리키는 새 Gate work를 요청한다. 새 Gate work는 새 `input_hash`·`dedupe_key`·`work_id`와 `attempt_number=1`, `trigger=INITIAL`을 사용한다. 입력이 바뀌지 않은 호출 실패만 같은 work 안에서 `trigger=RETRY`인 새 attempt를 사용할 수 있다. 공통 시간·비용·work 예산을 소진하면 보고와 result Primitive admission을 차단하고 미해결 사유를 저장한다. token 사용량은 기록하지만 초과만으로 이 경로를 차단하지 않는다.

Runtime Validator는 `REVISE`를 만든 기존 action·decision을 다시 사용하지 못하게 하고, 같은 Verification·CWELabel revision 또는 같은 domain input hash로 새 Gate 투표를 요청하면 `ACTION_NOT_ALLOWED`로 차단한다. 보완된 Verification과 이를 다시 평가한 새 current CWELabel을 가리키는 새 work·call spec·action·decision이 모두 있어야 한다. 반대로 provider 실패나 `INVALID_OUTPUT` repair는 Gate 판단을 다시 요구한 것이 아니므로, 허용된 횟수 안에서 같은 domain input과 새 invocation 식별자·action을 사용하는 `RETRY`로만 처리한다.

## Gate 2: Rule Scope Impact Gate Agent

이 Gate는 final `VerificationResult.verdict=TRUE`이고 그 exact revision을 검토한
`TechnicalEvidenceReview.status=ACCEPT`일 때만 호출한다. 취약점의 기술적 성립을 다시 판정하지
않고, 고정된 검증 결과를 공식 프로그램 정책의 rule·scope·impact 기준과 비교한다. 다른
Verification revision의 Technical `ACCEPT`는 Gate 2 입력이 아니다.

### ProgramPolicyRecord

입력 정책은 Gate가 확인할 수 있는 공식 자료를 수집한 기록이어야 한다. 공식 source는 프로그램
운영 주체 또는 그 주체가 정책 정본으로 명시적으로 위임한 플랫폼이 게시한 원문이다. 검색 결과,
제3자 요약, 저장소 문서, 모델 기억은 발견 단서일 수 있지만 공식 source가 아니다.

- program identifier, source URL/reference, policy version과 fetch timestamp
- 게시 주체·도메인·플랫폼 연결을 확인한 source authenticity와 그 확인 근거
- 수집한 원문의 exact content reference/hash와 source provenance
- parser 이름·version·실행 시각·입력 원문 reference와 parser output provenance
- 공식 rule, eligibility와 severity/impact 기준
- in-scope/out-of-scope asset와 vulnerability class
- 금지된 테스트·재현 행위
- known limitation, duplicate 또는 disclosure 조건
- 각 항목의 official source reference
- 수집하지 못한 자료와 freshness warning

각 `PolicyItem`은 원문 source reference와 절·anchor·페이지 같은 locator로 다시 찾을 수 있어야
한다. parser가 원문에 없는 rule, scope, impact 기준을 채우거나 정규화 과정에서 의미를 넓힐 수
없다. 출처와 연결되지 않은 parser 항목은 정책 사실로 사용하지 않는다.

freshness는 정책 최신성을 마지막으로 검증한 `freshness_checked_at`, source가 제공한 version/effective date·last-modified 정보, 수집 시각과
R8이 승인한 적용 기준을 함께 기록한 판정이다. source-native current-version·유효 기간 확인 결과는 freshness의 provenance와 evidence로 보존하지만 `freshness_valid_until`을 대신하지 않는다. `CURRENT`는 이 근거에 R8이 정한 프로그램별 freshness 기준을 적용해 미래의 `freshness_valid_until`을 확정한 경우에만 부여한다. threshold가 필요한데
아직 정해지지 않았거나 적용할 승인 기준이 없으면 `UNVERIFIED`이며, 단지 최근 수집했다는 이유로
`CURRENT`를 만들지 않는다. threshold와 재수집 주기 자체는 R8이 확정한다. `STALE | UNVERIFIED` 정책으로
`ALLOW`하지 않는다.

freshness 판정은 `freshness_checked_at`, 승인된 criterion reference, 하나 이상의 source-native 또는 수집 시각 evidence reference와 해당 판정을 유효하게 사용할 수 있는 미래의 `freshness_valid_until`을 함께 가진 assertion이어야
한다. R5는 모든 정책에 임의의 TTL을 만들지 않는다. criterion을 정할 수 없거나 currentness 확인이
끝나지 않으면 `UNVERIFIED + DENY`다. runtime은 정책 의미를 판단하지 않고 Gate 2 action 허가·실제 호출
직전과 Reporter action 허가·실제 호출 직전에 같은 exact policy
revision이 아직 `CURRENT`인지 검사한다. stale이 되거나 currentness가 깨지면 기존 Gate 2 결과를
새 downstream action에 재사용하지 않는다.

저장소 문서나 모델 기억을 공식 정책으로 자동 승격하지 않는다. 정책 수집은 `FOUND | ABSENT_CONFIRMED | COLLECTION_FAILED`를 구분한다. 공식 부재를 확인한 `ABSENT_CONFIRMED`만 `UNCERTAIN + DENY` review를 만들 수 있고, 수집·parser 실패인 `COLLECTION_FAILED`는 Rule Scope Gate를 호출하지 않는다. `FOUND`라도 핵심 자료가 누락되거나 `freshness_status=STALE | UNVERIFIED`이면 최신 정책으로 취급하지 않는다. 최신성 기준값과 재수집 주기는 R8이 승인한 versioned 설정을 사용하고 R5는 그 결과를 정책 의미로 해석한다. stale·미검증 상태의 Gate 결과는 항상 `UNCERTAIN + DENY`다.

`FOUND`는 exact `PolicyParserResult`, `PolicyCollectionResult`, `ProgramPolicyRecord`와 official source provenance가 필요하다. `ABSENT_CONFIRMED`는 확인한 official source와 부재 근거가 필요하다. `COLLECTION_FAILED`는 하나 이상의 `AnalysisError`를 기록하고 Gate work·review·Reporter를 만들지 않으며 `UNCERTAIN + DENY`로 변환하지 않는다. 원문, parser 결과 또는 정책 내용이 변경되면 새 exact revision으로 취급하고 이전 Gate 결과를 재사용하지 않는다.

Policy Parser만 `PolicyParserResult`를, Policy Collector만 `PolicyCollectionResult`와 `ProgramPolicyRecord`를 생산한다. R5는 이 exact artifact를 입력으로 받아 Rule·Scope·Impact 의미만 판정한다.

### 검토 항목

- 프로그램 rule과 eligibility 충족 여부
- 대상 asset과 vulnerability class의 scope
- 수행한 재현이 금지 조건과 충돌하는지
- 검증된 실제 impact가 프로그램 기준에 충분한지
- Technical Gate가 정확성을 확인한 restriction과 실제 수행 행위를 공식 프로그램 정책 조건과 비교할 수 있는지
- 보고서 초안을 작성할 수 있는지

### 판단 경계

Rule 검토는 report eligibility, 허용·제외 vulnerability class와 기타 일반적인 program rule을 비교한다.

- `PASS`: 적용 가능한 모든 필수 rule에 공식 근거가 있고 허용 class/eligibility를 충족한다.
- `FAIL`: 신뢰 가능한 공식 정책이 현재 후보를 일반 report/eligibility 기준에서 명시적으로 부적격·제외한다.
- `UNCERTAIN`: 적용 rule, 예외·조건 또는 eligibility가 없거나 모호하여
  충족/위반 중 어느 쪽도 공식 근거로 확정할 수 없다. 명시가 없다는 이유로 허용을 추정하지 않는다.

Scope 검토는 repository, application, asset, endpoint, package, version과 vulnerability class를
정책의 포함·제외 항목 및 조건과 비교한다.

- `PASS`: 현재 검증 대상의 식별자와 version을 공식 in-scope 항목에 명시적으로 매칭할 수 있고
  적용되는 out-of-scope 조건이 없다.
- `FAIL`: 공식 out-of-scope 항목에 명시적으로 매칭되거나, 명시된 in-scope 조건을 충족하지 않는다.
- `UNCERTAIN`: 대상 식별자/version/class 또는 정책의 포함·제외 기준이 없거나 모호해서 어느 쪽도
  확정할 수 없다. in-scope라는 명시적 근거가 없으면 자동 `PASS`가 아니다.

Security Impact 검토에는 final Verification과 Technical `ACCEPT`의 동일 exact revision chain에서
실제 근거로 검증된 impact만 사용한다. 미검증 child proposal, alternate path, 추가 exploitation
가능성, `CandidateRef`와 현재 revision에서 확정되지 않은 조건은 impact를 높이는 근거가 아니다.

Gate 2가 사용하는 R6-owned 검증 완료 impact는 exact final `VerificationResult`의 `supporting_evidence`, `verdict_rationale`, `required_primitive_candidates`·`provided_primitive_candidates`와 이들이 가리키는 evidence 중 현재 가설의 실제 impact를 뒷받침하는 내용이다. `impact_escalation_candidates`, `bypass_candidates`, `material_child_proposals`는 모두 미검증 후보이므로 impact를 높이는 입력이 아니다. Gate 2는 `verification_result_ref`에서 이 기존 필드와 transitive evidence closure를 읽으며, 별도 impact ID·evidence 목록을 복사하거나 새 impact record를 만들지 않는다.

`unresolved_conditions`도 같은 exact `VerificationResult`에서 읽는다. final TRUE에 남아 있는 condition이나 `supporting_evidence`·`counter_evidence`의 limitation이 impact 범위 또는 policy/testing restriction 매핑을 불확실하게 하면 해당 component를 `UNCERTAIN`으로 하고 그 누락을 `missing_information`에 보존한다. 문자열 condition에 문서에 없는 ID·domain·blocking field를 덧붙여 projection하지 않는다. 근거 provenance는 `verification_result_ref`와 그 result가 실제로 가진 evidence/dynamic reference closure로 고정하며, 다른 Verification revision이나 generation의 condition·evidence로 보완하지 않는다.

- `SUFFICIENT`: verified impact가 공식 정책의 최소 impact/eligibility 기준에 명시적으로 도달한다.
- `INSUFFICIENT`: verified impact와 공식 기준을 모두 확정할 수 있고, 검증된 범위가 그 기준에
  미달하거나 명시적 비적격 impact에 해당한다.
- `UNCERTAIN`: verified impact의 범위 또는 공식 impact 기준·매핑 조건이 부족하거나 모호하다.
  possible impact만 존재하면 `SUFFICIENT`가 아니다.

R7 Dynamic Reproduction/PoC의 testing restriction 검토는 R7이 실제 수행했다고 기록한 target, environment, command/method, network target, automation, account/privilege, production 여부, state change와 destructive action만 정책과 비교한다. current provenance는 `DynamicReproductionRequest -> EnvironmentRequirements -> ReproductionPlan -> Reproduction Agent -> AgentLog -> Reproduction Session Manager -> DynamicReproductionResult`다. Gate 2는 `VerificationResult.dynamic_request_ref`와 `dynamic_result_ref`에서 current-generation exact request와 result를 고정하고, result의 exact `reproduction_plan_ref`와 같은 attempt의 `agent_log_ref`, 실제 `environment_ref`·`environment_recipe_ref`, observation, candidate/validated PoC와 cleanup reference를 따라 execution facts를 읽는다. `AgentLogEvent.event_type`, `input_refs`, output/observation reference, status·exit code와 연결 artifact가 실제 명령·네트워크 대상·계정/권한·환경·상태 변경을 입증하며, 실행 여부는 canonical `agent_invoked`로 확인한다. Gate 2는 이 closure를 환경 적합성이나 R7 정책 판정을 다시 심사하기 위해 읽지 않고 testing restriction과 비교할 실제 수행 사실의 identity만 확인한다.

`agent_invoked=false`인 사전 정책 차단에서도 같은 attempt의 exact `AgentLog`와 `POLICY_BLOCKED` event가 필요하지만, 계획이나 request의 목표를 수행 사실로 보지 않는다. Agent가 시작됐다면 성공·실패·취소와 관계없이 같은 attempt의 exact `AgentLog`가 필요하며, 실제 완료되거나 실패한 event와 생성된 artifact만 사용한다. `poc_ref` 존재만으로 실행을 주장할 수 없고, current dynamic attempt의 exact PoC bundle이 AgentLog의 `POC_EXECUTION_STARTED | POC_EXECUTION_FINISHED`, observation과 `DynamicReproductionResult`에 같은 revision 또는 digest로 연결된 경우만 실제 PoC 행위다. request·requirements·plan·policy decision·recipe·environment·AgentLog·PoC·cleanup·dynamic result 중 다른 revision, generation 또는 attempt를 섞거나 latest lookup으로 보정하면 기존 공통 revision/error 계약으로 거절한다.

Gate 2는 별도 실행 사실 목록을 만들지 않고 exact `verification_result_ref -> dynamic_result_ref`의 canonical transitive reference closure를 소비한다. 정책 판단에 중요한 실제 행위를 선택적으로 빼 결과를 바꿀 수 없고, current generation과 same-attempt의 실제 수행 artifact만 인정한다. 반대로 실행되지 않은 attack/PoC step, `agent_invoked=false`인 실행 fact, observation 연결 없는 PoC는 사용하지 않는다. policy block 또는 environment precheck로 artifact가 생성되지 않았다면 존재하지 않는 artifact reference를 요구하지 않는다. Runtime Validator는 reference closure, artifact 존재와 lifecycle을 검사하고 정책 의미는 재판정하지 않는다.

`testing_restriction_compliance`은 위 actual execution closure와 공식 `ProgramPolicyRecord`의 testing restriction을 비교한 독립 판정축이다.

- `PASS`: 현재 공식 정책과 exact 실행 근거에서 금지 테스트 위반이 없음을 확인했다. R4 admission runtime은 `ALLOW`로 매핑할 수 있다.
- `FAIL`: 실제 수행 행위가 공식 정책의 금지 조건을 위반했다. R4 admission runtime은 `DENY`로 매핑하며 Primitive·Chaining·Reporter를 차단한다.
- `UNCERTAIN`: 정책 부재·freshness 문제·핵심 실행 정보 부족 등으로 금지 여부를 확정할 수 없다. R4 admission runtime은 확정 위반이 아니므로 `ALLOW`로 매핑하지만 Reporter는 차단한다.

`RuleScopeEvidenceLink.area=TESTING_RESTRICTION`은 이 판정에 사용한 공식 정책 항목과 exact 실행 artifact를 연결하는 provenance일 뿐 판정값이 아니다. 위반 여부는 반드시 `testing_restriction_compliance`에서 읽는다.

공통 계약, R4와 R8에는 혼합 component의 `review_status` 우선순위가 정의되어 있지 않다. 따라서
아래 규칙은 R5-02가 Rule·Scope·Impact 결과를 하나의 Gate 2 `review_status`로 합성하기 위해
명확화한 semantic composition rule이다. 새로운 score·정량 평가 체계나 별도 runtime 책임이
아니다. 이미 공식 근거로 확정된 거부 사유를 전체 상태에서 숨기지 않되, 개별 `UNCERTAIN`
component와 `missing_information`은 그대로 보존한다.

1. Rule/Scope/testing restriction 중 하나가 `FAIL`이거나 impact가 `INSUFFICIENT`이면, 다른 component가
   `UNCERTAIN`이어도 `review_status=FAIL`이다.
2. 확정적 거부 component가 없고 하나 이상이 `UNCERTAIN`이면 `review_status=UNCERTAIN`이다.
3. `rule_compliance=PASS`, `scope_compliance=PASS`, `testing_restriction_compliance=PASS`, `security_impact=SUFFICIENT`일 때만
   `review_status=PASS`다.

따라서 `FAIL + UNCERTAIN + SUFFICIENT`는 명시적 정책 위반을 약화시키지 않고 전체 `FAIL + DENY`다.
`PASS + UNCERTAIN + SUFFICIENT`는 확정적 거부는 없지만 scope 근거가 부족하므로 전체
`UNCERTAIN + DENY`다. 이 합성은 정책 근거 부족을 fail-closed로 처리하는 원칙과 일치한다.

### 출력

```yaml
rule_scope_impact_review:
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
  reasons: []
  missing_information: [PolicyMissingInfo]
```

`evidence_links`는 domain별 `PolicyItem`과 exact evidence를 묶어 정책 원문/항목에서 parser·collection result와 `ProgramPolicyRecord`를 거쳐 Gate 판정까지 이어지는 reference chain을 보존한다. Rule의 확정 상태에는 공식 rule item과 관련 verified evidence, Scope에는 공식 scope item과 실제
target/asset/version/endpoint, Impact에는 공식 criterion과 verified impact evidence의 exact reference가
각각 필요하다. testing restriction의 확정 판단에는 restriction item과 R7이 보존한 실제 execution
fact reference가 모두 필요하다. 필요한 근거가 없으면 `UNCERTAIN`이며 explanation 문자열은 exact
provenance를 대신하지 않는다.

공식 정책 부재를 확인한 `ABSENT_CONFIRMED`이거나 `freshness_status=STALE | UNVERIFIED`이면 Rule Scope Gate Agent가 정책을 추정하지 않고 최소한 `rule_compliance=UNCERTAIN`, `scope_compliance=UNCERTAIN`, `testing_restriction_compliance=UNCERTAIN`, `review_status=UNCERTAIN`, `report_permission=DENY`와 구조화된 `missing_information`을 판단해 반환한다. impact도 검토할 근거가 부족하면 `security_impact=UNCERTAIN`이다. stale record의 exact reference와 경고는 감사 기록으로 보존하지만 Reporter의 `PASS | ALLOW` 근거로 사용하지 않는다. 수집 자체가 실패한 `COLLECTION_FAILED`는 review를 만들지 않으며 R4 admission runtime이 `NOT_EVALUATED + ALLOW`로 기록한다.

각 확정 판정은 `RuleScopeEvidenceLink`를 통해 exact `PolicyItem`과 evidence reference에 연결한다. 핵심 정책·근거 누락은 구조화된 `PolicyMissingInfo`에 보존하고 `ALLOW`를 금지한다. Runtime Validator는 설명 문자열에서 정책 의미나 중요도를 새로 추론하지 않는다.

Gate의 `evidence_links`와 `missing_information`은 current final `VerificationResult`의 canonical evidence 및 exact reference closure와 직접 연결한다. 별도 condition/projection 계층을 만들지 않으며, 확인되지 않은 사실이나 child impact를 Gate가 새 Verification 사실로 승격하지 않는다.

Runtime Validator는 공식 정책 문장이나 정책의 의미를 대신 해석하지 않는다. Rule Scope Gate가 판단한 `UNCERTAIN + DENY`의 필수 필드, exact 정책 수집·정책 reference, 판단별 `RuleScopeEvidenceLink`, 구조화된 `PolicyMissingInfo`와 상태 불변조건만 검사한다. `ABSENT_CONFIRMED`인데 `policy_record_ref`가 있거나 핵심 공식 source가 누락된 출력에서 `ALLOW`·`PASS`가 함께 나타나면 semantic `INVALID_OUTPUT`으로 거절하고, 정상적인 `UNCERTAIN + DENY`이면 `REPORT_READY` check로 Reporter만 프로그램적으로 차단한다. 제한된 repair 뒤에도 불변조건이 맞지 않으면 Rule Scope Gate work를 실패 처리한다. 두 경우 모두 Verification verdict를 바꾸지 않는다.

`report_permission=ALLOW`는 동일 exact Verification revision이 R5-03 Reporter로 진행하기 위한
Gate 2 정책 전제조건을 만족했다는 뜻으로만 사용한다. 외부 제출·공개, 사람의 disclosure 승인,
Reporter 호출 또는 `ReportDraft`·result Primitive 생성을 뜻하지 않으며, 다음 조건을 모두
만족할 때만 유효하다.

```text
review_status == PASS
AND rule_compliance == PASS
AND scope_compliance == PASS
AND testing_restriction_compliance == PASS
AND security_impact == SUFFICIENT
AND policy_record_ref != null
AND policy authenticity/provenance/freshness is valid for this review
AND missing critical information is empty
```

그 밖의 유효한 정책 판단 결과는 `DENY`다. 예를 들어 `FAIL`, `UNCERTAIN`, `INSUFFICIENT`, stale
또는 `UNVERIFIED` 정책과 `ALLOW`의 조합은 semantic contradiction이다. trusted runtime은
기존 공통 semantic validation 계약으로 이를 `INVALID_OUTPUT` 처리하고 해당 Gate 출력을
Reporter 입력으로 사용하지 않는다. 다만 일반 Rule·Scope·Impact/report eligibility 실패와 `testing_restriction_compliance=UNCERTAIN`은 R4가 current `PrimitiveAdmissionDecision=ALLOW`로 확정한 기술 재료의 admission을 막지 않는다. Gate 2 전용 오류 enum이나 validator를 새로 만들지 않는다.

정책 source 부재가 확인되었거나 유효한 record의 핵심 정보가 부족한 것은 정책 근거 부족이므로
`UNCERTAIN + DENY`다. 반면 source fetch unavailable, parser failure, invalid parser output,
schema/reference 오류, LLM/runtime 실패는 정책상 `FAIL`이 아니다. 공통 `AnalysisError`와
`INVALID_OUTPUT` 계약으로 실패를 기록하고 성공한 Gate review를 만들거나 사용하지 않은 채
Reporter handoff를 차단한다. 오류를 `UNCERTAIN + DENY`라는 정상 Gate 결과로 변환하지 않는다.

`verification_result_ref`, `technical_review_ref`, `cwe_label_ref`와 존재하는 `policy_record_ref`에는 정확한 저장 revision의 `record_id`가 필요하다. runtime은 Technical review가 `ACCEPT`이고, Technical review와 Rule Scope review가 같은 Verification과 CWELabel `record_id`를 각각 가리키는지 확인한다. 즉 R5-01이 ACCEPT할 때 검토한 Verification/CWE revision과 R5-02가 사용하는 Verification/CWE revision은 각각 동일해야 하며 임의의 다른 revision을 조합할 수 없다. 각 reference의 `workspace_id`, `commit_id`, `content_hash`는 대상 record와 일치해야 하며, Verification·CWELabel·Technical 대상의 `meta.hypothesis_id`는 Rule Scope review의 가설과 같아야 한다. 정책이 있으면 Gate가 실제 읽은 exact `ProgramPolicyRecord` revision을 가리키고 Reporter가 사용할 정책 record도 같아야 한다. Verification, Technical review, CWELabel, 정책 원문/parser 결과를 포함한 ProgramPolicyRecord 중 어느 input revision이든 바뀌면 기존 Rule Scope 결과를 재사용하지 않는다. 구체적인 reference/revision 검사는 기존 공통 `StoredDataRef`·revision validator 책임이며 Gate 2가 별도 validator를 정의하지 않는다.

Gate 판단 시점에 policy가 이미 `STALE | UNVERIFIED`인데 `ALLOW`를 출력한 경우는 생성 당시의 semantic
contradiction이므로 `INVALID_OUTPUT`이다. 반면 유효한 policy와 input으로 정상 생성된 review 뒤에
Verification, policy 또는 관련 upstream의 새 revision이 생긴 경우, 과거 review 자체를 사후
`INVALID_OUTPUT`으로 바꾸지 않는다. 그 review는 자신이 검토한 과거 exact revision의 기록으로
남지만 새 revision의 Reporter 요청에는 사용할 수
없으며 공통 revision/runtime validation이 재사용을 차단한다.

### 권한 경계와 추가 결정 필요

Gate 2는 Verification verdict나 부모 가설 판정을 변경하지 않고 새 취약점·공격 경로·child
proposal·공식 정책·impact를 만들지 않는다. 미검증 child proposal을 verified impact로 승격하거나
Pro/Con·추가 Evidence·동적 재현을 소유하지 않으며, result Primitive를 직접 생성하거나 Reporter를
직접 호출하거나 ReportDraft를 만들지 않는다. runtime validation을 우회하거나 외부 제출·공개와
사람의 disclosure 결정을 정하지 않는다.

`material_child_proposals` 자체는 verified impact가 아니다. child는 전역 등록과 독립 Verification lifecycle을 거쳐야 하며, child가 final `TRUE`가 되어도 부모 결과는 자동 변경되지 않는다. child 결과가 부모 impact에 필요하면 부모 Verification owner가 exact child `VerificationResult` revision을 명시적으로 채택해 새 부모 `VerificationResult` revision N+1을 만든다. 이후 N+1에 대해 Technical Gate와 Gate 2를 모두 다시 수행하며 N의 두 Gate 결과는 재사용하지 않는다. 부모가 명시적으로 흡수하지 않은 child impact는 child 자신의 Gate 2에서만 평가한다.

- R4: final `TRUE + same-revision Technical ACCEPT` 호출 순서, exact revision·`REPORT_READY`
  validation, stale/invalid Reporter·Primitive 차단과 공통 semantic validation의 상태 전이
- R6: verified security impact의 정본 표현과 unresolved verification condition, Verification 범위
  밖 impact를 사용하지 못하게 하는 연결
- R7: 실제 PoC/재현 행위와 testing restriction 비교에 필요한 execution metadata, 미확정 PoC 정책
- R8: 공식 source authenticity/provenance 수집, freshness threshold·재수집 정책과 Rule/Scope/Impact
  평가 추적 지표, 공통 DataGap·freshness assertion·schema MAJOR/migration 계약
- 공통 계약: exact direct/transitive input과 `StoredDataRef` 검증. parser 실행 실패를 기존 어느
  `AnalysisError.code`로 정규화할지와 policy collection result 저장 record는 R4/R8 절차에서 결정

ProgramPolicyRecord/RuleScopeImpactReview의 호환되지 않는 이전 schema MAJOR는 current Gate input으로
자동 사용하지 않고 `SCHEMA_UNSUPPORTED`로 거절한다. 기존 record를 덮어쓰지 않고 current schema의
새 revision을 만들며 실제 schema version을 input identity/hash에 포함한다. migration만으로
authenticity `VERIFIED` 또는 freshness `CURRENT`를 부여하지 않는다. 구체 MAJOR 번호는 R4/R8이 정한다.

### 정책·Gate 오류 매핑

| 상황 | 처리 |
|---|---|
| official source fetch 실패 | `POLICY_FETCH_ERROR`; 성공한 Gate review 없음 |
| parser 실행 실패 | 공통 parser error code는 R4/R8 결정 전까지 POLICY-stage `AnalysisError`; `UNCERTAIN`으로 변환 금지 |
| malformed parser output 또는 존재하지 않는 record/hash를 Gate 출력이 참조 | `INVALID_OUTPUT` |
| 지원하지 않는 parser/policy schema MAJOR | `SCHEMA_UNSUPPORTED`; malformed output과 구분 |
| Gate 시작 전 요구 exact revision과 전달 revision 불일치 | `RECORD_REVISION_MISMATCH`; 선행 Gate/status 자체가 없거나 순서가 틀리면 `GATE_ORDER_INVALID` |
| ALLOW 후 실제 invocation 직전 current input/revision 변경 | decision `EXPIRED`와 `STALE_RESULT` 또는 원인에 맞는 revision 오류 |
| Reporter readiness 부족 또는 stale/mismatched/invalid Gate 결과 사용 | `REPORT_NOT_READY` |
| official source 확인 완료 후 정책 실제 부재 | 오류가 아니라 `ABSENT_CONFIRMED` provenance에 근거한 `UNCERTAIN + DENY` |

`STALE_RESULT`는 이미 생산된 결과가 current input/state/revision보다 오래되어 재사용 불가한 경우,
`RECORD_REVISION_MISMATCH`는 action/input 검사 시 요구 exact revision과 전달 revision이 다른 경우,
`GATE_ORDER_INVALID`는 선행 Gate/status가 성립하지 않은 호출, `INVALID_OUTPUT`은 Gate/LLM 출력 자체의
schema·semantic 위반이다. `REPORT_NOT_READY`는 Reporter 전제조건 실패이며 앞 오류의 의미를
대체하지 않는다.
`verification_result_ref`, `technical_review_ref`, `cwe_label_ref`, `policy_collection_result_ref`와 존재하는 `policy_record_ref`에는 정확한 저장 revision의 `record_id`가 필요하다. runtime은 Technical review가 `ACCEPT`이고, Technical review와 Rule Scope review가 같은 Verification과 CWELabel `record_id`를 각각 가리키는지 확인한다. 각 reference의 `workspace_id`, `commit_id`, `content_hash`는 대상 record와 일치해야 하며, Verification·CWELabel·Technical 대상의 `meta.hypothesis_id`는 Rule Scope review의 가설과 같아야 한다. 정책 수집 결과가 `FOUND`이면 review의 정책 record가 그 결과의 exact `policy_record_ref`와 같아야 한다. 입력 revision이 하나라도 달라지면 기존 Rule Scope 결과를 재사용하지 않는다.

## Technical-accepted TRUE, testing restriction과 Primitive admission

final TRUE가 Chaining에 쓰이려면 current generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 validated PoC가 있고 exact Verification과 current CWELabel을 Technical Gate가 `ACCEPT`해야 한다. R5는 같은 exact chain의 Rule Scope review와 `testing_restriction_compliance`를 생산하고, R4 `PRIMITIVE_ADMISSION_RUNTIME`이 정책 수집 결과까지 입력으로 current `PrimitiveAdmissionDecision`을 확정한다. runtime은 `decision=ALLOW`일 때만 제공 능력별 result Primitive와 index를 저장하며 각 Primitive의 `admission_decision_ref`는 같은 Verification의 current decision을 exact하게 가리킨다.

`testing_restriction_compliance=FAIL`만 이 정책 축에서 `DENY`가 되어 Primitive와 Chaining을 차단한다. `PASS | UNCERTAIN`은 `ALLOW`로 매핑하며, `COLLECTION_FAILED`는 review 없이 `testing_restriction_compliance=NOT_EVALUATED`, `decision=ALLOW`, `reason_code=POLICY_COLLECTION_FAILED`로 구분한다. `UNCERTAIN`과 수집 실패, scope `FAIL`, 일반 eligibility 실패, impact `INSUFFICIENT` 또는 `report_permission=DENY`는 Reporter를 차단하지만 current `ALLOW` Primitive를 제거하지 않는다. R5는 admission을 직접 결정하지 않으며 자식 가설은 새로운 대상·경로와 자신의 Verification·두 Gate로 다시 판정한다. Gate 전 TRUE와 Technical `REVISE | REJECT`는 result Primitive나 Chaining 입력이 아니다. HOLD는 Technical Gate를 사용하지 않으며, final HOLD의 `required_primitive_candidates`가 하나 이상일 때만 전체 후보를 inputs로 가진 result 없는 Primitive로 들어간다. 후보가 비어 있으면 Primitive와 Chaining work를 만들지 않는다.

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
AND testing_restriction_compliance == PASS
AND security_impact == SUFFICIENT
AND report_permission == ALLOW
```

조건이 하나라도 충족되지 않거나 Gate reference 연결이 맞지 않으면 결과와 검토 사유는 저장하지만 Reporter를 호출하지 않는다. LLM이 `review_status`, rule, scope 또는 impact 조건과 모순되는 `ALLOW`를 출력하면 semantic validation 실패다. 이 호출은 `LLMInvocationResult.status=INVALID_OUTPUT`, `AnalysisError.stage=GATE`, `AnalysisError.code=INVALID_OUTPUT`으로 기록하며 invalid output을 `RuleScopeImpactReview`로 commit하지 않는다. 제한된 repair가 남아 있을 때만 같은 입력의 새 invocation attempt를 허용하고, 한도를 소진하면 Gate work를 `FAILED`로 끝낸다. 어느 경우에도 Reporter를 호출하거나 Verification verdict를 변경하지 않는다. 이는 취약점 판정 규칙이 아니라 권한 없는 보고 생성을 막는 호출 전제다.

Gate와 Reporter의 stage action은 exact `LLMCallSpec`까지 포함해 실제 LLM 호출을 직접 허가한다. 이 세 역할이 별도 `CALL_LLM` action으로 stage 검사를 우회하는 것은 허용하지 않는다. Technical action의 `REVISION`은 exact Verification·current CWELabel pair를, `GATE_ORDER`는 두 revision의 final `COMMITTED` 상태를 검사한다. Rule Scope action의 `REVISION`은 같은 Verification·CWELabel, exact Technical review와 정책 수집 결과, `FOUND`일 때 정책 record를 검사하고, `GATE_ORDER`는 `TRUE`+Technical `ACCEPT`이며 수집 결과가 `COLLECTION_FAILED`가 아닌지 검사한다. Reporter action의 `REVISION`은 current Finding과 두 Gate가 검토한 같은 Verification·CWELabel·Technical·Rule Scope·정책 revision을 검사하고 `REPORT_READY`는 Finding 존재와 위 모든 조건을 검사한다. 하나라도 맞지 않으면 `REPORT_NOT_READY`로 차단한다. Runtime은 이 검사를 action 허가 때와 실제 provider 호출 직전에 반복하며, 달라졌으면 decision을 `EXPIRED`로 바꾸고 호출하지 않는다. 실제 invocation request의 model·prompt·context·schema·budget·timeout은 검사한 call spec과 모두 같아야 한다.

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

Reporter는 새로운 공격 경로를 확정하거나 미검증 material child 또는 Chaining 후보를 실제 영향으로 쓰지 않는다. 초안의 핵심 주장은 current Finding, Verification, validated PoC와 두 Gate의 exact revision에 연결한다. 실패한 시도의 `poc_candidate_ref`는 validated `poc_ref`나 재현 성공으로 서술하지 않는다. `poc_ref`가 있어도 `agent_invoked=false`, `status=BLOCKED` 또는 current generation의 `SUCCEEDED + SUPPORTED` 결과 및 same-attempt `AgentLog`의 `POC_EXECUTION_STARTED | POC_EXECUTION_FINISHED`와 연결되지 않으면 validated PoC나 실행·재현 성공으로 서술하지 않는다. `ReportDraft.cwe_label_ref.record_id`는 Technical review와 Rule Scope review가 공통으로 가리킨 CWELabel `record_id`와 같아야 하며, CWELabel이 수정되면 두 Gate를 다시 통과하기 전에는 초안을 만들지 않는다.

Reporter는 presentation/synthesis 역할이다. 새 vulnerability fact, attack path, exploitation step,
policy·scope 판단, reproduction·PoC 성공이나 upstream보다 강한 exploitability·security impact를
만들지 않는다. severity, exploitability, capability, scope, exposure, required privilege,
reproduction certainty와 security impact를 포함한 모든 주장의 강도는 verified upstream evidence보다
강할 수 없다. 조건부·부분·제한된 관측을 무조건적이거나 완전히 재현된 결과로 바꾸면 안 된다.
완화·회귀 테스트 제안도 검증된 root cause와 근거 범위 안에서 recommendation으로 구분하며 새
취약점 사실을 만들지 않는다. 이 규칙은 새 score·enum·claim-mapping schema가 아닌 Reporter output의
semantic invariant다.

각 주요 claim은 `finding_ref`의 current Finding, `verification_result_ref`의 exact Verification,
그 Verification을 검토한 `technical_review_ref`, exact `rule_scope_impact_review_ref`, 두 Gate가 사용한
동일 `cwe_label_ref`, Rule Scope Gate가 사용한 `policy_record_ref`로 추적할 수 있어야 한다.
Dynamic/PoC 주장은 Verification이 실제 참조한 exact `dynamic_result_ref`와 `poc_ref`만 사용한다.
runtime은 같은 workspace·commit·hypothesis, `record_id`, `content_hash`와 revision chain을 검사하며,
Reporter가 저장소에서 가장 최신처럼 보이는 별도 결과를 다시 검색해 연결하거나 서로 다른 revision의
유리한 근거를 조합해서는 안 된다.

Reporter는 R7이 이미 확정한 `DynamicReproductionResult`의 request·plan·requirements 연결과 존재하는
policy·environment·`AgentLog`·PoC candidate·validated PoC·cleanup provenance만 그대로 소비한다.
request, plan, `environment_ref`, `agent_log_ref`, PoC candidate, validated PoC, `cleanup_ref`는 모두 동일한 reproduction attempt에 속해야 한다. 서로 다른 attempt의 artifact를 섞거나 누락된 reference를 다른 실행에서 보충하지 않으며, 특히 `agent_log_ref`·`environment_ref`·PoC·cleanup reference의 attempt가 하나라도 다르면 fail-closed 처리한다. 이 무결성을
새로 판정하거나 `poc_candidate_ref`를 validated PoC로 승격하지 않는다. validated `poc_ref`는 R7에서
exact `poc_candidate_ref`와 같은 bundle revision/digest, `AgentLog`의 실제 `POC_EXECUTION_STARTED`와 `POC_EXECUTION_FINISHED`, 지지
observation 및 `SUCCEEDED + SUPPORTED`가 연결되어 확정된 reference라는 의미로만 표시한다.

환경의 존재와 식별은 `environment_ref`로, 생성 또는 재사용 여부는 `SandboxEnvironment.container_action=CREATED | REUSED`로 표시한다.
`agent_log_ref`는 정책 단계에서 차단되어 `agent_invoked=false`인 경우에도 Session Manager가 남기는 필수 reference이며 `null`을 허용하지 않는다. `agent_invoked=false`이거나, `agent_invoked=true`인데 같은 attempt의 exact `agent_log_ref`와 `AgentLog`
event가 실제 PoC 실행·관측을 뒷받침하지 않거나, Dynamic/PoC가 `BLOCKED`이거나 환경 restriction 때문에
실행하지 못했거나 실제 observation이 부족하면 재현 성공으로 서술하지 않는다. 실행 사실과 관측은
`agent_log_ref`, `observation_refs` 및 결과에 연결된 exact environment·policy·PoC·cleanup provenance를
함께 따라 표현한다.
동적 검증 실패·환경 실패는 취약점이 존재하지 않는다는 뜻으로 바꾸지 않는다. ReportDraft는 실제
실행 여부, 관측 범위와 환경·실행 limitation을 원래 상태 그대로 표시한다.

Reporter는 Verification의 restriction과 unresolved condition, 정적·동적 검증 및 두 Gate의 limitation을
빠뜨리거나 완화하지 않는다. `ReportDraft.restrictions`는 Verification restriction을,
`unresolved_conditions`는 Verification unresolved condition을 빠짐없이 보존하고, `limitations`는
정적·동적 검증과 Gate limitation을 보존한다. 문장을 자연스럽게 만들기 위해 조건을 삭제하거나
해결된 것처럼 표현해서는 안 된다.

저장 전 `REDACTION=PASS`를 요구하며 API/access/session token, password, private key, credential,
cookie·authorization secret, 불필요한 PII, 내부 secret과 private/raw reasoning 또는 hidden
chain-of-thought 성격의 비공개 원문을 `content_ref`에 넣지 않는다. 민감정보를 먼저 저장하고 나중에
제거하는 흐름은 허용하지 않는다. 이 검사는 `ReportDraft.redaction_status=PASSED`와 일치해야 한다.

ReportDraft가 참조한 `Finding`, `VerificationResult`, `CWELabel`, `TechnicalEvidenceReview`,
`RuleScopeImpactReview` 또는 `ProgramPolicyRecord` 중 하나라도 새 current revision으로 바뀌면 기존 초안은
감사 기록으로만 남고 `AnalysisRunResult.report_draft_refs`의 current 결과로 사용할 수 없다. 새 exact
dependency chain에서 필요한 Gate와 Reporter 흐름을 다시 수행해 새 ReportDraft를 만든다. Reporter는
공통 `Finding`/`FindingCandidate` schema나 lifecycle을 재설계하지 않으며 current Finding이 없으면
`CREATE_REPORT_DRAFT`를 허용하지 않고 `report_draft_refs=[]`와 기존 `REPORT_NOT_READY` 오류·상태 원인을
유지한다.

## Agent 자동화 종료와 사람 주도 후속 과정

`ReportDraft`는 R5-03 Reporter와 전체 Agent 파이프라인의 마지막 Agent 산출물이다. Reporter work가 atomic하게 종료되면 신뢰 runtime은 다음 항목을 `AnalysisRunResult`에 묶는다.

- current Finding 후보와 final Verification
- Technical·Rule Scope Gate와 CWE·공식 정책 reference
- current generation의 dynamic reproduction과 redacted validated PoC
- current ReportDraft 또는 초안이 만들어지지 않은 구체적인 이유
- token·시간·Sandbox 등 자원 사용량
- 모든 실행 오류·DataGap·남은 HOLD 조건
- LLM 호출·action decision·work state·work attempt·transition commit와 debug trace reference

신뢰 runtime이 `AnalysisRunResult`와 `AnalysisRunState`를 원자적으로 함께 확정하면 Agent 자동화가
끝난다. 이 finalization은 이미 생성된 결과의 저장·상태 확정이며 새로운 Agent 판단이 아니다. Finding이
없으면 Reporter를 호출하지 않고 `report_draft_refs=[]`로 종료 원인을 보존한다. 이후 사람이 결과를
검토하거나 문서를 수정하고 외부에 제출·공개하는 과정은 Agent 자동화 밖이다. 현재 아키텍처는 이 사람
주도 과정의 schema, 상태, 결정 enum 또는 자동 action을 정의하지 않으며 Reporter에는 사람 승인,
submission decision, 외부 전송·공개 또는 CVE/GHSA 발급·요청 권한이 없다.
