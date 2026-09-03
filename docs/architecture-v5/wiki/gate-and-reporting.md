# 이중 LLM Gate와 보고

## 쉽게 말하면

첫 번째 검토는 취약점 판정과 코드·실행 근거가 맞는지 확인합니다. 두 번째 검토는 공식 정책 범위와 실제 영향을 확인합니다. 두 검토를 모두 통과한 결과만 보고서 초안으로 만듭니다.

**상세 기준:** [05. 이중 LLM Gate와 보고](../05-llm-gate-and-reporting.md)

Gate는 검증 판정을 직접 바꾸지 않고 Reporter는 외부 공개를 결정하지 않습니다. 모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

## 1. 기술 근거 검토(`Technical Evidence Gate`)

final TRUE `VerificationResult`의 찬반 근거, 실제 코드·호출·데이터 흐름, 현재 generation의 `DynamicReproductionRequest`·성공한 동적 결과·validated PoC, CWE와 restriction을 검토한다. FALSE와 HOLD는 이 Gate를 호출하지 않는다. 각 exact revision을 고정하며 하나라도 수정되면 기존 Gate 결과를 재사용하지 않는다. 출력은 `ACCEPT | REVISE | REJECT`와 별도 `handoff_readiness: READY | NOT_READY`다. `ACCEPT`는 `READY`, 나머지는 `NOT_READY`만 허용하며 verdict를 직접 바꾸지 않는다. `REVISE`는 같은 Verification owner에게 직접 돌아가며, 새 generation에서 TRUE를 다시 만들려면 새 동적 결과와 validated PoC도 필요하다.

동적 재현이 Sandbox 정책에 막힌 것은 `FALSE`나 Gate의 `REJECT` 근거가 아니다. 하지만 validated PoC가 없으므로 final TRUE와 Technical Gate 입력을 만들 수 없다. retry 가능하면 동적 work를 `BLOCKED`, 복구 불가능하면 verdict 없이 `FAILED`로 끝낸다.

## 2. 공식 정책·범위·영향 검토(`Rule Scope Impact Gate`)

final `TRUE`이고 Technical `ACCEPT`인 exact revision만 공식 `ProgramPolicyRecord`과 함께 검토한다. Rule Scope 결과에는 자신이 읽은 Verification, Technical review, CWELabel과 정책의 정확한 `record_id`를 남긴다. Technical Gate가 ACCEPT할 때 검토한 Verification/CWELabel과 Gate 2의 두 입력은 각각 같아야 한다. 이 중 하나나 정책 원문/parser 결과가 수정되면 이전 Rule Scope 결과를 재사용하지 않는다.

- rule_compliance: `PASS | FAIL | UNCERTAIN`
- scope_compliance: `PASS | FAIL | UNCERTAIN`
- security_impact: `SUFFICIENT | INSUFFICIENT | UNCERTAIN`
- report permission: `ALLOW | DENY`

Rule은 eligibility·허용/제외 class·금지 testing method·명시 rule을, Scope는 repository·application·asset·endpoint·package·version·class를 검토한다. 명시적으로 충족하면 `PASS`, 명시적 위반/제외면 `FAIL`, 근거가 없거나 모호하면 `UNCERTAIN`이다. Impact는 같은 final Verification exact revision의 R6-owned `verified_impacts`만 사용한다. Gate의 impact ID와 evidence refs는 그 closure와 set-equal해야 하며 CandidateRef·possible impact·다른 revision은 사용할 수 없다. R6 범용 condition 중 `gate_projections`에 선언된 Gate-relevant domain만 `(source verification, condition ID, domain)` 항목으로 정확히 한 번 projection한다. Gate와 무관한 condition은 projection하지 않는다. multi-domain projection은 정상이고 선언 domain 누락·같은 tuple 중복·source evidence 또는 IMPACT blocking 약화는 invalid다.

공통 계약, R4와 R8에는 혼합 component의 전체 상태 우선순위가 없으므로 `FAIL > UNCERTAIN > PASS`는 R5-02가 Gate 2 결과를 합성하기 위해 명확화한 semantic rule이다. score나 새 runtime 책임이 아니다. `FAIL + UNCERTAIN + SUFFICIENT`는 명시적 거부를 보존해 `FAIL + DENY`, `PASS + UNCERTAIN + SUFFICIENT`는 `UNCERTAIN + DENY`이며 개별 불확실성과 누락은 그대로 남긴다.

공식 정책 자료의 실제 부재가 확인되거나 authenticity·핵심 정보가 부족하면 관련 항목은 `UNCERTAIN`이고 permission은 `DENY`다. freshness는 R8이 승인한 source-native 유효성 기준 또는 필요한 프로그램별 threshold를 만족할 때만 `CURRENT`다. threshold가 필요한데 미확정이거나 적용 기준이 없으면 `UNVERIFIED + DENY`이며 최근 fetch만으로 `CURRENT`를 만들지 않는다. 저장소 문서나 모델 기억으로 공식 정책을 추정하지 않는다. source URL, 수집 원문, parser version/output과 각 PolicyItem의 원문 locator를 보존한다.

기존 `ProgramPolicyRecord`의 freshness 상태와 확인 시각을 사용한다. Gate 2·PROVIDED·Reporter의 action 허가와 실제 호출 직전에 exact policy revision이 여전히 `CURRENT`인지 다시 검사하며 stale Gate 2 결과는 downstream에 재사용하지 않는다. R5-02가 독립 freshness schema나 공통 TTL을 만들지 않고 기준이 없으면 `UNVERIFIED + DENY`다.

정책 수집은 `FOUND | ABSENT_CONFIRMED | COLLECTION_FAILED`를 구분한다. 실제 부재 확인만 provenance/DataGap에 근거한 정상 `UNCERTAIN + DENY`가 될 수 있고, fetch/parser/schema/runtime 실패는 AnalysisError로 남겨 성공한 Gate review를 만들지 않는다.

fetch/parser/schema/runtime 실패나 invalid output은 정책 `FAIL` 또는 정상 `UNCERTAIN + DENY` Gate 결과가 아니다. 공통 오류로 기록하고 성공한 Gate review 없이 Reporter를 차단한다.

`ALLOW`는 `review_status PASS + rule PASS + scope PASS + impact SUFFICIENT + authentic fresh exact policy revision + 핵심 누락 없음`에서만 유효하며, 동일 exact Verification revision이 R5-03 Reporter로 진행하기 위한 Gate 2 정책 전제조건을 충족했다는 뜻으로 한정한다. 다른 조합의 `ALLOW`는 공통 semantic validation의 `INVALID_OUTPUT`이며 Reporter나 PROVIDED admission에 사용할 수 없다. `ALLOW`는 Reporter 실행, ReportDraft·Primitive 생성 또는 Human Review·외부 제출·공개 승인이 아니다.

Gate 결과는 authoritative policy/source/parser/authenticity/freshness와 upstream evidence/execution reference graph, 그리고 그중 LLM이 실제 읽은 bounded context를 구분해 기록한다. Rule은 공식 rule item+verified evidence, Scope는 공식 scope item+실제 target/version, Impact는 공식 criterion+verified impact evidence에 exact linkage가 있어야 확정 상태가 된다. 누락은 stable ID, domain, blocking 여부, 설명과 policy/evidence refs로 구조화하며 blocking 누락과 `ALLOW`가 함께 있으면 `INVALID_OUTPUT`이다. 공통 DataGap 통합은 R8, hash/dedupe 구현은 R4 책임이다.

testing restriction은 R7의 `EnvironmentRequirements -> ReproductionPlan -> action_decision_ref -> policy_decision_ref -> SandboxEnvironment/EnvironmentCheck -> runner_invoked -> steps_ref/log -> observation/실행 PoC -> DynamicReproductionResult` closure 중 실제 행위만 사용한다. `execution_fact_refs`는 전체 graph와 set-equal하지 않지만 current attempt에서 정책 판단에 중요한 실제 수행 fact는 빠짐없이 포함해야 한다. 다른 closure 혼합과 결과를 바꾸는 누락을 금지한다. 정책 차단·환경 precheck stop에서는 실제 setup/check/log만 포함하고 실행되지 않았거나 생성되지 않은 artifact를 요구하지 않는다. `poc_ref`만으로 PoC execution fact를 만들지 않으며 same-attempt log/observation 연결이 필요하다. Gate 2는 R7 환경·정책 판정을 재심사하지 않는다.

child proposal은 독립 Verification을 거치며 child TRUE가 부모 impact를 자동 높이지 않는다. 부모가 exact child final revision을 새 parent Verification N+1에 명시적으로 채택한 뒤 Technical Gate와 Gate 2를 다시 수행한 경우만 부모 impact에 사용할 수 있다.

Gate 판단 시점부터 policy가 `STALE | UNVERIFIED`인데 `ALLOW`이면 생성 당시 모순이므로 `INVALID_OUTPUT`이다. 정상 policy와 revision으로 생성된 review가 이후 upstream 변경 때문에 오래된 경우에는 기존 review 자체를 invalid로 바꾸지 않고, 새 revision의 Reporter·PROVIDED admission·Chaining provenance에 재사용하지 못하게 runtime이 차단한다.
공식 정책 자료가 없거나 정책의 `freshness_status`가 `STALE | UNVERIFIED`이면 rule/scope/review는 `UNCERTAIN`이고 permission은 `DENY`다. 오래된 정책 reference는 감사용으로 남길 수 있지만 `PASS | ALLOW` 근거로 쓰지 않는다. 저장소 문서나 모델 기억으로 공식 정책을 추정하지 않는다.

두 Gate가 validated PoC를 가진 같은 TRUE revision에 대해 `Technical ACCEPT`와 `review/rule/scope PASS`, `impact SUFFICIENT`, `permission ALLOW`를 모두 만들었을 때만 PROVIDED Primitive를 저장해 Chaining에 사용할 수 있다. 같은 Verification owner가 Reporter 호출도 요청하며 프로그램 검사를 통과해야 실제 초안 작성을 시작한다. Technical만 통과했거나 Gate2가 `FAIL | UNCERTAIN | DENY`이면 보고서와 Chaining을 모두 막는다. 새 Verification revision에는 과거 Gate·동적 결과·PoC를 재사용하지 않는다. HOLD는 Gate를 거치지 않고 REQUIRED Primitive로 Chaining에 들어간다.

이 판단은 Rule Scope Gate가 내립니다. 프로그램 검사기는 정책 문장의 뜻을 다시 판단하지 않고 결과 형식과 공식 출처 연결을 확인합니다. 정상적인 `UNCERTAIN + DENY`는 그대로 저장하고 Reporter만 부르지 않습니다.

## Reporter 조건

```text
TRUE
+ Technical ACCEPT
+ Rule Scope Impact review_status PASS
+ rule_compliance PASS
+ scope_compliance PASS
+ security_impact SUFFICIENT
+ permission ALLOW
```

Reporter는 위 조건을 모두 만족하고 current Finding이 있으며 exact revision closure와 `REPORT_READY`, 동일 ACTIVE Verification owner를 runtime이 확인한 때만 내부 ReportDraft를 만든다. 두 Gate가 검토한 CWELabel과 보고서 초안의 `cwe_label_ref.record_id`가 다르면 초안을 만들지 않는다. 이 upstream 중 하나가 새 revision으로 바뀌면 기존 초안은 감사 기록으로만 남고 새 Gate·Reporter 결과가 나오기 전까지 current 결과로 쓸 수 없다. 두 Gate와 Reporter 모두 외부 제출·공개 권한이 없다.

`ReportDraft`가 마지막 Agent 산출물이며 `AnalysisRunResult` 확정 뒤 자동화가 끝납니다. trusted runtime은 `AnalysisRunResult + AnalysisRunState`를 원자적으로 확정한다. 이후 Human Review·초안 수정·외부 제출/공개는 사람 주도 과정이며 active architecture는 이를 위한 schema, state, decision enum이나 자동 action을 정의하지 않는다.

프로그램 검사기는 Gate 결론을 대신 내리지 않습니다. Verification이 Gate 호출을 제안하더라도 Technical 다음 Rule Scope라는 순서, 정확한 입력·LLM call spec, PROVIDED admission과 Reporter 조건을 검사합니다. Finding이 없으면 Reporter를 호출하지 않고 `report_draft_refs=[]`와 오류·상태 이유를 남긴 뒤 runtime finalization으로 간다.

`ALLOW`가 PASS·scope·impact 조건과 모순되거나 Gate가 현재 작업과 다른 input revision을 가리키면 유효한 Gate 결과가 아니다. LLM 호출을 `INVALID_OUTPUT`, 오류를 `GATE/INVALID_OUTPUT`으로 기록하고 Reporter를 호출하지 않는다.

각 Gate와 Reporter는 action 허가 시점과 실제 LLM 호출 직전에 같은 입력 수정본을 다시 확인합니다. `REVISE` 뒤에는 같은 입력으로 재투표할 수 없고, 보완된 Verification 또는 CWE 수정본으로 새 Gate 작업과 새 action을 만들어야 합니다.

상세 내용은 [이중 LLM Gate와 보고](../05-llm-gate-and-reporting.md)을 따른다.
