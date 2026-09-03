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
- 현재 generation의 `DynamicReproductionRequest`, `DynamicReproductionResult`와 exact validated `poc_ref`·`policy_decision_ref`·`environment_ref`·`steps_ref`
- `CWELabel`의 정확한 `record_id`가 있는 `StoredDataRef`와 근거
- restriction, bypass candidate, unresolved condition
- 같은 Verification에서 분리한 material child proposal 중 재검증 완료 여부

### 검토 항목

- final `TRUE`와 찬성·반대 근거의 일치
- 핵심 주장이 현재 `workspace_id`와 `commit_id`의 코드 위치·호출·데이터 흐름에 연결되는지
- 동적 관측이 현재 가설·`workspace_id`·실행 조건에 연결되는지
- Runner 호출 여부와 step log, 실제 환경 생성 여부와 환경 reference, 정책 차단과 Controller 판정 reference, 정리 필요 여부와 상태가 공통 계약에 맞는지
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

`ACCEPT`는 `handoff_readiness=READY`, `REVISE | REJECT`는 `handoff_readiness=NOT_READY`와 함께 사용한다. 여기서 `READY`는 동일 exact Verification revision을 Gate 2 입력으로 전달할 수 있다는 뜻이며 Reporter나 그 이후 단계를 허가하지 않는다. 이 조합이 맞지 않으면 Gate output을 저장하지 않는다.

`DynamicReproductionResult(status=BLOCKED, failure_reason=POLICY_BLOCKED)`는 정책 때문에 실행하지 못했다는 뜻이지 가설 반증이 아니다. 그러나 validated PoC가 없으므로 final TRUE를 저장하거나 Technical Gate를 호출할 수 없다. 이 경우 Verification과 동적 work를 `BLOCKED`로 유지하거나 복구 불가능하면 verdict 없이 `FAILED`로 끝낸다. 정책 차단 자체를 `FALSE | HOLD` 또는 Gate의 `REJECT` 근거로 바꾸지 않는다.

`verification_result_ref.record_id`와 `cwe_label_ref.record_id`는 Gate가 실제로 읽은 `VerificationResult`와 `CWELabel` revision을 각각 고정한다. runtime은 Gate와 두 대상의 `workspace_id`, `commit_id`, `hypothesis_id`, `record_id`, `content_hash`를 확인한다. Verification 또는 CWELabel이 수정되면 이전 `ACCEPT`를 새 revision에 재사용하지 않고 Gate를 새로 호출한다.

`REVISE`는 동일 입력 재투표나 provider retry가 아니다. 현재 Gate work는 `REVISE` review를 exact output으로 확정하고 종료한다. 그 review는 Orchestration을 경유해 목적지를 다시 선택하지 않고 같은 hypothesis의 ACTIVE `VerificationAssignment` owner에게 전달한다. runtime은 이전 종료 work를 되돌리지 않고 새 generation의 VERIFICATION work를 등록하며 hypothesis 상태를 `TERMINAL -> VERIFYING`으로 CAS 전환한다. Verification은 필요한 Context·Pro/Con·정적 근거·restriction을 보완하고, final TRUE 후보라면 새 generation의 동적 재현 요청과 validated PoC도 다시 확보한다. 새 result·work 종료·hypothesis current pointer를 atomic commit하고, 필요하면 CWE producer와 새 label revision을 조정한다. 그 뒤 새 `VerificationResult` 및 필요한 `CWELabel` revision을 가리키는 새 Gate work를 요청한다. 새 Gate work는 새 `input_hash`·`dedupe_key`·`work_id`와 `attempt_number=1`, `trigger=INITIAL`을 사용한다. 입력이 바뀌지 않은 호출 실패만 같은 work 안에서 `trigger=RETRY`인 새 attempt를 사용할 수 있다. 공통 token·시간·비용·work 예산을 소진하면 보고와 result Primitive admission을 차단하고 미해결 사유를 저장한다.

Runtime Validator는 `REVISE`를 만든 기존 action·decision을 다시 사용하지 못하게 하고, 같은 Verification·CWE revision 또는 같은 domain input hash로 새 Gate 투표를 요청하면 `ACTION_NOT_ALLOWED`로 차단한다. 보완된 upstream revision을 가리키는 새 work·call spec·action·decision이 모두 있어야 한다. 반대로 provider 실패나 `INVALID_OUTPUT` repair는 Gate 판단을 다시 요구한 것이 아니므로, 허용된 횟수 안에서 같은 domain input과 새 invocation 식별자·action을 사용하는 `RETRY`로만 처리한다.

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

freshness는 `evaluated_at`, source가 제공한 version/effective date·last-modified 정보, 수집 시각과
R8이 승인한 적용 기준을 함께 기록한 판정이다. `CURRENT`는 source가 명시한 현재 유효 기간·현재
version 같은 R8 승인 source-native 기준으로 평가 시점의 유효성을 입증하거나, age 검사가 필요한
source라면 R8이 정한 프로그램별 freshness threshold를 만족할 때만 부여한다. threshold가 필요한데
아직 정해지지 않았거나 적용할 승인 기준이 없으면 `UNVERIFIED`이며, 단지 최근 수집했다는 이유로
`CURRENT`를 만들지 않는다. threshold와 재수집 주기 자체는 R8이 확정한다. `STALE | UNVERIFIED` 정책으로
`ALLOW`하지 않는다.

freshness 판정은 `freshness_checked_at`, 승인된 criterion reference, 시간 기반 criterion의
`valid_until` 또는 source-native current-version 검사 결과/reference를 함께 가진 assertion이어야
한다. R5는 모든 정책에 임의의 TTL을 만들지 않는다. criterion을 정할 수 없거나 currentness 확인이
끝나지 않으면 `UNVERIFIED + DENY`다. runtime은 정책 의미를 판단하지 않고 Gate 2 action 허가·실제 호출
직전과 Reporter action 허가·실제 호출 직전에 같은 exact policy
revision이 아직 `CURRENT`인지 검사한다. stale이 되거나 currentness가 깨지면 기존 Gate 2 결과를
새 downstream action에 재사용하지 않는다.

정책 수집은 `FOUND | ABSENT_CONFIRMED | COLLECTION_FAILED`를 구분해야 한다. `FOUND`는 exact
ProgramPolicyRecord가 필요하고, `ABSENT_CONFIRMED`는 확인한 official source와 부재를 입증하는
provenance/누락 reference가 필요하다. `COLLECTION_FAILED`는 하나 이상의 AnalysisError가 필요하며
정상 `UNCERTAIN + DENY` review로 변환하지 않는다. collection record 이름과 공통 schema는 R4/R8이
정하며, 정책 reference 없이 정상 `UNCERTAIN + DENY`가 가능한 경우는 실제 부재가 확인된 때뿐이다.

저장소 문서나 모델 기억을 공식 정책으로 자동 승격하지 않는다. 공식 `ProgramPolicyRecord`가
없거나 핵심 자료가 누락되면 추측하지 않는다. 원문, parser 결과 또는 정책 내용이 변경되면 새
`ProgramPolicyRecord` revision으로 취급하고 이전 Gate 2 결과를 재사용하지 않는다.
저장소 문서나 모델 기억을 공식 정책으로 자동 승격하지 않는다. 공식 `ProgramPolicyRecord`가 없거나 핵심 자료가 누락되면 추측하지 않는다. 정책 record가 있어도 `freshness_status=STALE | UNVERIFIED`이면 최신 정책으로 취급하지 않는다. `CURRENT` 판정의 최대 허용 나이와 출처별 확인 방법은 R5 정책 수집 설계에서 정하지만, stale·미검증 상태의 Gate 결과는 항상 `UNCERTAIN + DENY`다.

### 검토 항목

- 프로그램 rule과 eligibility 충족 여부
- 대상 asset과 vulnerability class의 scope
- 수행한 재현이 금지 조건과 충돌하는지
- 검증된 실제 impact가 프로그램 기준에 충분한지
- restriction, alternate path와 미검증 Verification-origin 또는 Chaining-origin child의 표현이 정확한지
- 보고서 초안을 작성할 수 있는지

### 판단 경계

Rule 검토는 report eligibility, 허용·제외 vulnerability class, 실제 수행한 검증 행위에 적용되는
testing restriction과 기타 명시적 program rule을 함께 비교한다.

- `PASS`: 적용 가능한 모든 필수 rule에 공식 근거가 있고, 허용 class/eligibility를 충족하며,
  제외 class나 금지 testing method 등 명시적 금지와 충돌하지 않는다.
- `FAIL`: 신뢰 가능한 공식 정책이 현재 후보 또는 기록된 검증 행위를 명시적으로 부적격·제외·금지한다.
- `UNCERTAIN`: 적용 rule, 예외·조건, eligibility 또는 실제 수행 행위 metadata가 없거나 모호하여
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

정본은 R6 final `VerificationResult.verified_impacts`이며 Gate 2는 `verification_result_ref + verified_impact_ids`로 그 revision의 채택값을 고정한다. `impact_evidence_refs`는 선택된 impact의 exact evidence/dynamic/PoC closure와 set-equal해야 하므로 supporting claim이라는 이유만으로 임의 record를 추가할 수 없다. R6의 범용 unresolved condition 가운데 `gate_projections`가 선언된 Gate-relevant domain만 `(source_verification_ref, source_condition_id, domain)` projection을 정확히 하나씩 `missing_information`에 남긴다. 빈 projection을 가진 일반 HOLD/Chaining condition은 Gate 2에 넣지 않는다. multi-domain condition의 domain별 항목은 정상이며 같은 tuple 중복이나 선언 domain 누락만 invalid다. projection은 source condition의 evidence와 blocking 의미를 그대로 보존한다. IMPACT `blocking_for_sufficiency=true` projection은 `blocking=true`이고 관련 impact의 `SUFFICIENT`와 전체 `ALLOW`를 금지한다.

- `SUFFICIENT`: verified impact가 공식 정책의 최소 impact/eligibility 기준에 명시적으로 도달한다.
- `INSUFFICIENT`: verified impact와 공식 기준을 모두 확정할 수 있고, 검증된 범위가 그 기준에
  미달하거나 명시적 비적격 impact에 해당한다.
- `UNCERTAIN`: verified impact의 범위 또는 공식 impact 기준·매핑 조건이 부족하거나 모호하다.
  possible impact만 존재하면 `SUFFICIENT`가 아니다.

R7 Dynamic Reproduction/PoC의 testing restriction 검토는 R7이 실제 수행했다고 기록한 target, environment, method, automation, account/privilege, production 여부와 destructive action만 정책과 비교한다. provenance closure는 `EnvironmentRequirements -> ReproductionPlan.environment_requirements_ref -> RUN_SANDBOX action_decision_ref -> Sandbox Controller policy_decision_ref -> actual SandboxEnvironment(requirements_ref) -> requirement별 EnvironmentCheck -> runner_invoked -> steps_ref/SandboxStepLog -> observation/실제 실행된 PoC -> DynamicReproductionResult`다. Gate 2는 이 closure를 환경 적합성이나 Sandbox 정책 판정을 다시 심사하기 위해 읽지 않고 testing restriction과 비교할 execution fact의 identity만 확인한다.

`runner_invoked=false, steps_ref=null`인 정책 차단에서는 계획의 공격 단계를 수행 사실로 보지 않는다. 필수 requirement가 `MISMATCH | NOT_CHECKED | ERROR`여서 공격 전 중단된 경우에도 환경 setup/check와 실제 생성된 log만 사용하며 계획된 공격, 빈 stdout, 환경 차이를 공격 실패·`FALSE` 근거로 바꾸지 않는다. `poc_ref` 존재만으로 실행을 주장할 수 없고, current dynamic attempt의 exact PoC revision이 실행 step/log/observation 및 `DynamicReproductionResult` closure에 연결된 경우만 실제 PoC 행위다. plan·requirements·action/policy decision·environment·PoC·step log·dynamic result 중 다른 revision이나 attempt를 섞거나 latest lookup으로 보정하면 기존 공통 revision/error 계약으로 거절한다.

`execution_fact_refs`는 전체 R7 graph의 복사본이 아니라 current `DynamicReproductionResult`와 같은 attempt에서 testing restriction 판단에 필요한 실제 수행 fact closure다. 정책 판단에 중요한 실제 행위를 선택적으로 빼 결과를 바꿀 수 없고, lifecycle상 존재하며 실제 수행된 fact는 complete해야 한다. 반대로 실행되지 않은 attack step, Runner 미호출 시 attack fact, observation 연결 없는 PoC는 넣지 않는다. policy block이나 environment precheck stop으로 생성되지 않은 artifact의 reference는 요구하지 않는다. Runtime Validator는 current result closure와 artifact 존재/lifecycle을 기준으로 completeness를 검사하고 정책 의미는 재판정하지 않는다.

공통 계약, R4와 R8에는 혼합 component의 `review_status` 우선순위가 정의되어 있지 않다. 따라서
아래 규칙은 R5-02가 Rule·Scope·Impact 결과를 하나의 Gate 2 `review_status`로 합성하기 위해
명확화한 semantic composition rule이다. 새로운 score·정량 평가 체계나 별도 runtime 책임이
아니다. 이미 공식 근거로 확정된 거부 사유를 전체 상태에서 숨기지 않되, 개별 `UNCERTAIN`
component와 `missing_information`은 그대로 보존한다.

1. Rule/Scope 중 하나가 `FAIL`이거나 impact가 `INSUFFICIENT`이면, 다른 component가
   `UNCERTAIN`이어도 `review_status=FAIL`이다.
2. 확정적 거부 component가 없고 하나 이상이 `UNCERTAIN`이면 `review_status=UNCERTAIN`이다.
3. `rule_compliance=PASS`, `scope_compliance=PASS`, `security_impact=SUFFICIENT`일 때만
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
  policy_record_ref: StoredDataRef | null
  review_status: PASS | FAIL | UNCERTAIN
  rule_compliance: PASS | FAIL | UNCERTAIN
  scope_compliance: PASS | FAIL | UNCERTAIN
  security_impact: SUFFICIENT | INSUFFICIENT | UNCERTAIN
  report_permission: ALLOW | DENY
  reasons: []
  missing_information: []
```

Rule의 확정 상태에는 공식 rule item과 관련 verified evidence, Scope에는 공식 scope item과 실제
target/asset/version/endpoint, Impact에는 공식 criterion과 verified impact evidence의 exact reference가
각각 필요하다. testing restriction의 확정 판단에는 restriction item과 R7이 보존한 실제 execution
fact reference가 모두 필요하다. 필요한 근거가 없으면 `UNCERTAIN`이며 explanation 문자열은 exact
provenance를 대신하지 않는다.

핵심 정책·근거 누락은 기존 `missing_information`에 보존하고 `ALLOW`를 금지한다. Runtime Validator는 설명 문자열에서 정책 의미나 중요도를 새로 추론하지 않는다.

공식 정책 자료가 없거나 `freshness_status=STALE | UNVERIFIED`이면 Rule Scope Gate Agent가 정책을 추정하지 않고 최소한 `rule_compliance=UNCERTAIN`, `scope_compliance=UNCERTAIN`, `review_status=UNCERTAIN`, `report_permission=DENY`와 `missing_information`을 판단해 반환한다. impact도 검토할 근거가 부족하면 `security_impact=UNCERTAIN`이다. stale record의 exact reference와 경고는 감사 기록으로 보존하지만 `PASS | ALLOW` 근거로 사용하지 않는다.

Runtime Validator는 공식 정책 문장이나 정책의 의미를 대신 해석하지 않는다. Rule Scope Gate가 판단한 `UNCERTAIN + DENY`의 필수 필드, exact 정책 reference와 구조적 불변조건만 검사한다. `policy_record_ref=null`이거나 핵심 공식 source가 누락된 출력에서 `ALLOW`·`PASS`가 함께 나타나면 semantic `INVALID_OUTPUT`으로 거절하고, 정상적인 `UNCERTAIN + DENY`이면 `REPORT_READY` check로 Reporter만 프로그램적으로 차단한다. 제한된 repair 뒤에도 불변조건이 맞지 않으면 Rule Scope Gate work를 실패 처리한다. 두 경우 모두 Verification verdict를 바꾸지 않는다.

`report_permission=ALLOW`는 동일 exact Verification revision이 R5-03 Reporter로 진행하기 위한
Gate 2 정책 전제조건을 만족했다는 뜻으로만 사용한다. 외부 제출·공개, 사람의 disclosure 승인,
Reporter 호출 또는 `ReportDraft`·result Primitive 생성을 뜻하지 않으며, 다음 조건을 모두
만족할 때만 유효하다.

```text
review_status == PASS
AND rule_compliance == PASS
AND scope_compliance == PASS
AND security_impact == SUFFICIENT
AND policy_record_ref != null
AND policy authenticity/provenance/freshness is valid for this review
AND missing critical information is empty
```

그 밖의 유효한 정책 판단 결과는 `DENY`다. 예를 들어 `FAIL`, `UNCERTAIN`, `INSUFFICIENT`, stale
또는 `UNVERIFIED` 정책과 `ALLOW`의 조합은 semantic contradiction이다. trusted runtime은
기존 공통 semantic validation 계약으로 이를 `INVALID_OUTPUT` 처리하고 해당 Gate 출력을
Reporter 입력으로 사용하지 않는다. 이미 Technical `ACCEPT`으로 admission된 Primitive의 자격에는 영향을 주지 않는다. Gate 2 전용 오류 enum이나
validator를 새로 만들지 않는다.

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

Gate와 Reporter의 stage action은 exact `LLMCallSpec`까지 포함해 실제 LLM 호출을 직접 허가한다. 이 세 역할이 별도 `CALL_LLM` action으로 stage 검사를 우회하는 것은 허용하지 않는다. Technical action의 `REVISION`은 exact Verification+CWE를, `GATE_ORDER`는 두 revision의 final `COMMITTED` 상태와 current generation의 동적 재현 요청·`SUCCEEDED + SUPPORTED` 결과·validated `poc_ref`를 검사한다. Rule Scope action의 `REVISION`은 같은 Verification+CWE와 exact Technical review를, `GATE_ORDER`는 `TRUE`+Technical `ACCEPT`를 검사한다. Reporter action의 `REVISION`은 current Finding과 두 Gate가 검토한 같은 Verification+CWE·Technical·Rule Scope·정책 revision을 검사하고 `REPORT_READY`는 Finding 존재와 위 모든 조건을 검사한다. 하나라도 맞지 않으면 stage에 맞는 `GATE_ORDER_INVALID` 등 공통 오류 또는 `REPORT_NOT_READY`로 차단한다. Runtime은 이 검사를 action 허가 때와 실제 provider 호출 직전에 반복하며, 달라졌으면 decision을 `EXPIRED`로 바꾸고 호출하지 않는다. 실제 invocation request의 model·prompt·context·schema·budget·timeout은 검사한 call spec과 모두 같아야 한다.

정상 통과 뒤에도 Gate 2가 Reporter를 실행하지 않는다. 같은 Verification owner가 exact revision을
지정해 Reporter 호출을 요청하고, runtime이 same-revision Technical `ACCEPT`, Gate 2 정상 통과,
정책·CWE와 모든 reference 일치, current Finding 존재 및 `REPORT_READY`를 확인한 뒤에만 Reporter를 실행한다. Reporter의
구체적인 입력·출력은 Reporter 설계를 따른다.

### Gate 2 시나리오

| 시나리오 | 처리 |
|---|---|
| 정상 | final `TRUE rev1` + rev1 Technical `ACCEPT`를 Gate 2가 같은 rev1·exact 정책으로 검토해 정상 통과하면 `ALLOW`가 가능하다. rev1의 result Primitive admission은 Technical `ACCEPT`으로 독립 확정되고, 같은 owner의 요청과 runtime `REPORT_READY` 검증 뒤 Reporter로 간다. |
| 정책 불확실 | 공식 scope 또는 impact 기준이 부족하면 해당 component와 `review_status=UNCERTAIN`, `report_permission=DENY`이며 Reporter를 차단한다. Technical `ACCEPT`으로 admission된 result Primitive와 Chaining 자격은 유지한다. |
| stale Technical Gate | rev1 Technical `ACCEPT`로 rev2 Gate 2를 호출하면 exact Verification reference가 달라 `GATE_ORDER_INVALID` 또는 공통 stale/revision 오류로 호출을 차단한다. |
| stale Gate 2 | rev1 Gate 2 통과 뒤 rev2가 생기면 rev1 review는 rev2의 Reporter 입력이 될 수 없다. rev2의 result Primitive 자격은 rev2 Technical review로 별도 판정한다. |
| 모순된 ALLOW | `FAIL | UNCERTAIN | INSUFFICIENT`이거나 policy freshness가 `STALE | UNVERIFIED`인 상태와 `ALLOW`의 조합은 `INVALID_OUTPUT`이며 review를 commit하거나 Reporter 입력으로 사용하지 않는다. |

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

Reporter는 새로운 공격 경로를 확정하거나 미검증 material child 또는 Chaining 후보를 실제 영향으로 쓰지 않는다. 초안의 핵심 주장은 current Finding, Verification, validated PoC와 두 Gate의 exact revision에 연결한다. 실패한 시도의 `poc_candidate_ref`는 validated `poc_ref`나 재현 성공으로 서술하지 않는다. `poc_ref`가 있어도 `runner_invoked=false`, `steps_ref=null`, `status=BLOCKED` 또는 current generation의 `SUCCEEDED + SUPPORTED` 결과와 연결되지 않으면 validated PoC나 실행·재현 성공으로 서술하지 않는다. `ReportDraft.cwe_label_ref.record_id`는 Technical review와 Rule Scope review가 공통으로 가리킨 CWELabel `record_id`와 같아야 하며, CWELabel이 수정되면 두 Gate를 다시 통과하기 전에는 초안을 만들지 않는다.

Reporter는 Verification의 restriction과 unresolved condition, 정적·동적 검증 및 두 Gate의 limitation을 빠뜨리거나 완화하지 않는다. 저장 전 `REDACTION=PASS`를 요구하며 credential, session secret, 불필요한 개인정보와 비공개 원문을 제거한다. 이 값은 `ReportDraft.restrictions`, `limitations`, `unresolved_conditions`, `redaction_status=PASSED`로 확인할 수 있어야 한다.

ReportDraft가 참조한 current Finding, `VerificationResult`, `CWELabel`, `TechnicalEvidenceReview`, `RuleScopeImpactReview` 또는 `ProgramPolicyRecord` 중 하나라도 새 current revision으로 바뀌면 기존 초안은 감사 기록으로만 남고 `AnalysisRunResult.report_draft_refs`의 current 결과로 사용할 수 없다. 새 exact dependency chain으로 Gate와 Reporter를 다시 실행해 새 ReportDraft를 만든다.

## Agent 자동화 종료와 사람 주도 후속 과정

`ReportDraft`는 R5-03 Reporter와 전체 Agent 파이프라인의 마지막 Agent 산출물이다. Reporter work가 atomic하게 종료되면 신뢰 runtime은 다음 항목을 `AnalysisRunResult`에 묶는다.

- current Finding 후보와 final Verification
- Technical·Rule Scope Gate와 CWE·공식 정책 reference
- current generation의 dynamic reproduction과 redacted validated PoC
- current ReportDraft 또는 초안이 만들어지지 않은 구체적인 이유
- token·시간·Sandbox 등 자원 사용량
- 모든 실행 오류·DataGap·남은 HOLD 조건
- LLM 호출·action decision·work state·work attempt·transition commit와 debug trace reference

`AnalysisRunResult`와 `AnalysisRunState`를 함께 확정하면 Agent 자동화가 끝난다. Finding이 없으면 Reporter를 호출하지 않고 `report_draft_refs=[]`로 종료 원인을 보존한다. 이후 사람이 결과를 검토하거나 문서를 수정하고 외부에 제출·공개하는 과정은 Agent 자동화 밖이다. 현재 아키텍처는 이 사람 주도 과정의 schema, 상태, 결정 enum 또는 자동 action을 정의하지 않는다. `report_permission=ALLOW`는 이 경계 뒤의 어떤 행위도 허용하지 않는다.
