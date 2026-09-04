# 이중 LLM Gate와 보고

## 쉽게 말하면

첫 번째 검토는 취약점 판정과 코드·실행 근거가 맞는지 확인합니다. 두 번째 검토는 공식 정책 범위와 실제 영향을 확인합니다. 두 검토를 모두 통과한 결과만 보고서 초안으로 만듭니다.

**상세 기준:** [05. 이중 LLM Gate와 보고](../05-llm-gate-and-reporting.md)

Gate는 검증 판정을 직접 바꾸지 않고 Reporter는 외부 공개를 결정하지 않습니다. 모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

## 0. R5-01 CWE labeling

final TRUE와 현재 generation의 validated PoC가 확정되면 R5-01 `CWE_LABELING`이 별도 `CWE_LABEL` work에서 current `CWELabel`을 만듭니다. label은 자신이 분류한 exact Verification revision·generation과 생산 work·LLM 호출을 직접 가리킵니다. 새 Verification에는 같은 CWE를 유지하더라도 새 label revision이 필요하며 과거 label은 history로만 남습니다.

Technical Gate는 이 label이 Verification 근거와 맞는지 검토하지만 label을 만들거나 수정하지 않습니다. current label이 없거나 label이 다른 Verification을 가리키면 Gate를 호출하지 않습니다.

## 1. 기술 근거 검토(`Technical Evidence Gate`)

final TRUE `VerificationResult`의 찬반 근거, 실제 코드·호출·데이터 흐름, 현재 generation의 `DynamicReproductionRequest`·성공한 동적 결과·validated PoC, CWE와 restriction을 검토한다. FALSE와 HOLD는 이 Gate를 호출하지 않는다. 각 exact revision을 고정하며 하나라도 수정되면 기존 Gate 결과를 재사용하지 않는다. 출력은 `ACCEPT | REVISE | REJECT`와 별도 `handoff_readiness: READY | NOT_READY`다. `ACCEPT`는 `READY`, 나머지는 `NOT_READY`만 허용하며 verdict를 직접 바꾸지 않는다. `REVISE`는 같은 Verification owner에게 직접 돌아가며, 새 generation에서 TRUE를 다시 만들려면 새 동적 결과와 validated PoC도 필요하다.

동적 재현이 Sandbox 정책에 막힌 것은 `FALSE`나 Gate의 `REJECT` 근거가 아니다. 하지만 validated PoC가 없으므로 final TRUE와 Technical Gate 입력을 만들 수 없다. retry 가능하면 동적 work를 `BLOCKED`, 복구 불가능하면 verdict 없이 `FAILED`로 끝낸다.

## 2. 공식 정책·범위·영향 검토(`Rule Scope Impact Gate`)

정책 경로는 `Policy collection/parser -> PolicyParserResult -> PolicyCollectionResult 확인 -> ProgramPolicyRecord -> Rule Scope Impact Gate -> Reporter`입니다. Parser와 Collector가 공통 artifact를 만들고 R5는 Rule·Scope·Impact 의미만 판단합니다.

Technical `ACCEPT`인 `TRUE`만 정책 수집 결과와 함께 검토합니다. 정책 수집은 `FOUND`, `ABSENT_CONFIRMED`, `COLLECTION_FAILED`를 구분합니다. `FOUND`이면 exact `ProgramPolicyRecord`도 함께 읽고, `ABSENT_CONFIRMED`이면 정책을 추정하지 않고 `UNCERTAIN + DENY`로 검토할 수 있습니다. `COLLECTION_FAILED`는 Rule Scope review를 만들지 않습니다.

Rule Scope 결과에는 `policy_collection_result_ref`로 정책 수집 결과를 고정하고, 자신이 읽은 Verification, Technical review, CWELabel과 존재하는 정책 record의 정확한 `record_id`를 남깁니다. Rule·Scope·Impact와 독립된 `testing_restriction_compliance: PASS | FAIL | UNCERTAIN` 판정은 실제 정책 항목과 코드·실행 근거에 연결하고, 부족한 정보는 어느 판단을 막는지 구조화해 남깁니다. 입력 중 하나라도 수정되거나 정책 최신성이 만료되면 이전 Rule Scope 결과를 재사용하지 않습니다.

Technical Gate가 `ACCEPT`할 때 검토한 Verification/CWELabel과 Gate 2의 두 exact input revision은 각각 같아야 하며, Gate는 Verification verdict나 hypothesis를 수정하지 않습니다.

- rule_compliance: `PASS | FAIL | UNCERTAIN`
- testing_restriction_compliance: `PASS | FAIL | UNCERTAIN`
- scope_compliance: `PASS | FAIL | UNCERTAIN`
- security_impact: `SUFFICIENT | INSUFFICIENT | UNCERTAIN`
- report permission: `ALLOW | DENY`

Rule은 eligibility·허용/제외 class·금지 testing method·명시 rule을, Scope는 repository·application·asset·endpoint·package·version·class를 검토한다. 명시적으로 충족하면 `PASS`, 명시적 위반/제외면 `FAIL`, 근거가 없거나 모호하면 `UNCERTAIN`이다. Impact는 같은 final Verification exact revision의 `supporting_evidence`, `verdict_rationale`, required/provided primitive candidate와 실제 evidence reference 중 현재 가설에서 검증된 내용만 사용한다. `impact_escalation_candidates`, CandidateRef, possible impact와 child proposal은 사용할 수 없다. 관련 `unresolved_conditions`와 evidence limitation도 같은 result revision에서 읽으며 impact 또는 policy 매핑을 막으면 해당 component를 `UNCERTAIN`으로 하고 `missing_information`에 보존한다. Gate 전용 impact·condition schema를 만들거나 다른 revision의 값으로 보완하지 않는다.

공통 계약, R4와 R8에는 혼합 component의 전체 상태 우선순위가 없으므로 `FAIL > UNCERTAIN > PASS`는 R5-02가 Gate 2 결과를 합성하기 위해 명확화한 semantic rule이다. score나 새 runtime 책임이 아니다. `FAIL + UNCERTAIN + SUFFICIENT`는 명시적 거부를 보존해 `FAIL + DENY`, `PASS + UNCERTAIN + SUFFICIENT`는 `UNCERTAIN + DENY`이며 개별 불확실성과 누락은 그대로 남긴다.

공식 정책 자료의 실제 부재가 확인되거나 authenticity·핵심 정보가 부족하면 관련 항목은 `UNCERTAIN`이고 permission은 `DENY`다. freshness는 R8이 승인한 source-native 유효성 기준 또는 필요한 프로그램별 threshold를 만족할 때만 `CURRENT`다. threshold가 필요한데 미확정이거나 적용 기준이 없으면 `UNVERIFIED + DENY`이며 최근 fetch만으로 `CURRENT`를 만들지 않는다. 저장소 문서나 모델 기억으로 공식 정책을 추정하지 않는다. source URL, 수집 원문, parser version/output과 각 PolicyItem의 원문 locator를 보존한다.

기존 `ProgramPolicyRecord`의 freshness 상태와 확인 시각을 사용한다. Gate 2와 Reporter의 action 허가·실제 호출 직전에 exact policy revision이 여전히 `CURRENT`인지 다시 검사하며 stale Gate 2 결과는 Reporter에 재사용하지 않는다. R5-02가 독립 freshness schema나 공통 TTL을 만들지 않고 기준이 없으면 `UNVERIFIED + DENY`다.

정책 수집은 `FOUND | ABSENT_CONFIRMED | COLLECTION_FAILED`를 구분한다. `FOUND`는 exact parser result·공식 source와 `ProgramPolicyRecord`를 연결한다. 실제 부재를 확인한 `ABSENT_CONFIRMED`만 provenance/DataGap에 근거한 정상 `UNCERTAIN + DENY`가 될 수 있다. `COLLECTION_FAILED`는 AnalysisError와 함께 `AnalysisRunResult`에 남기지만 Gate work를 호출하지 않고 `RuleScopeImpactReview`를 생성하지 않는다. 따라서 downstream Reporter도 진행할 수 없다.

fetch/parser/schema/runtime 실패나 invalid output은 정책 `FAIL` 또는 정상 `UNCERTAIN + DENY` Gate 결과가 아니다. 공통 오류로 기록하고 성공한 Gate review 없이 Reporter를 차단한다.

`ALLOW`는 `review_status PASS + rule PASS + scope PASS + impact SUFFICIENT + authentic fresh exact policy revision + 핵심 누락 없음`에서만 유효하며, 동일 exact Verification revision이 R5-03 Reporter로 진행하기 위한 Gate 2 정책 전제조건을 충족했다는 뜻으로 한정한다. 다른 조합의 `ALLOW`는 공통 semantic validation의 `INVALID_OUTPUT`이며 Reporter에 사용할 수 없다. `ALLOW`는 Reporter 실행, ReportDraft·Primitive 생성 또는 Human Review·외부 제출·공개 승인이 아니다.

Gate 결과는 authoritative policy/source/parser/authenticity/freshness와 current final `VerificationResult`의 exact evidence/reference closure, 그리고 그중 LLM이 실제 읽은 bounded context를 구분해 기록한다. `evidence_links`로 Rule은 공식 rule item+verified evidence, Scope는 공식 scope item+실제 target/version, Impact는 공식 criterion+verified impact evidence에 연결되어야 확정 상태가 된다. 누락은 `missing_information`에 stable ID, domain, blocking 여부, 설명과 policy/evidence refs로 구조화한다. 별도 condition/projection schema는 만들지 않으며 blocking 누락과 `ALLOW`의 조합은 `INVALID_OUTPUT`이다.

testing restriction은 `verification_result_ref -> dynamic_result_ref`의 canonical transitive reference closure를 통해 current-generation exact attempt에서 실제 수행한 사실만 사용한다. `AgentLogEvent.event_type`, `input_refs`, output/observation과 연결 artifact 및 canonical `agent_invoked`가 실행 사실의 provenance를 제공한다. 계획했지만 실행하지 않은 attack/PoC, `agent_invoked=false`인 실행 fact, observation 없는 PoC는 사용하지 않고 policy block이나 environment precheck로 만들지 않은 artifact는 요구하지 않는다. 다른 generation/revision/attempt 혼합과 결과를 바꾸는 실제 수행 사실 누락을 금지한다. R7은 사실과 provenance를 제공하고 Gate 2가 공식 testing restriction과 비교하며, Gate 2는 R7 환경·정책 판정을 재심사하지 않는다.

R5는 `testing_restriction_compliance`와 provenance를 만들고 R4 `PRIMITIVE_ADMISSION_RUNTIME`이 current `PrimitiveAdmissionDecision`을 확정한다. `FAIL`만 `DENY`로 Primitive·Chaining·Reporter를 차단한다. `PASS | UNCERTAIN`은 admission `ALLOW`이며, `COLLECTION_FAILED`는 review 없이 `NOT_EVALUATED + ALLOW`로 구분한다. `UNCERTAIN`과 수집 실패는 Primitive·Chaining을 허용하지만 Reporter는 차단한다. `RuleScopeEvidenceLink.area=TESTING_RESTRICTION`은 공식 정책과 exact 실행 근거를 연결하는 provenance이며 판정값이나 저장 authority가 아니다.

child proposal은 독립 Verification을 거치며 child TRUE가 부모 impact를 자동 높이지 않는다. 부모 impact 판단은 current parent `VerificationResult`의 exact evidence/reference closure에 이미 검증되어 포함된 사실만 소비하며, Gate 2가 별도 child-adoption schema를 만들거나 child 결과를 부모 사실로 승격하지 않는다.

Gate 판단 시점부터 policy가 `STALE | UNVERIFIED`인데 `ALLOW`이면 생성 당시 모순이므로 `INVALID_OUTPUT`이다. 정상 policy와 revision으로 생성된 review가 이후 upstream 변경 때문에 오래된 경우에는 기존 review 자체를 invalid로 바꾸지 않고, 새 revision의 Reporter에 재사용하지 못하게 runtime이 차단한다.
공식 정책 부재가 확인된 `ABSENT_CONFIRMED`이거나 정책의 `freshness_status`가 `STALE | UNVERIFIED`이면 rule/scope/review는 `UNCERTAIN`이고 permission은 `DENY`입니다. 오래된 정책 reference는 감사용으로 남길 수 있지만 `PASS | ALLOW` 근거로 쓰지 않습니다. 수집 실패 `COLLECTION_FAILED`는 review를 만들지 않으며, 저장소 문서나 모델 기억으로 공식 정책을 추정하지 않습니다.

validated PoC를 가진 TRUE의 exact revision을 Technical Gate가 `ACCEPT`하면 정책 수집과 Rule Scope 검토를 진행한다. Rule Scope는 금지 테스트 위반 여부를 `testing_restriction_compliance`로 다른 판단과 분리한다. 이 값이 `FAIL`이면 result Primitive를 만들지 않고, `PASS | UNCERTAIN`이면 admission `ALLOW` 뒤 제공 능력별 Primitive를 저장한다. 정책 수집 실패는 `NOT_EVALUATED + ALLOW`로 구분하되 Reporter는 막는다. 나머지 `review/rule/scope PASS`, `impact SUFFICIENT`, `permission ALLOW`를 모두 만족해야 Reporter를 호출할 수 있다. 다른 Rule Scope 항목의 `FAIL | UNCERTAIN | DENY`는 보고서만 막고 current `ALLOW` Primitive와 Chaining 자격은 유지한다. 새 Verification revision에는 과거 Gate·동적 결과·PoC·admission decision을 재사용하지 않는다. HOLD는 Gate 없이 `inputs`와 `result=null`인 Primitive로 Chaining에 들어간다.

이 판단은 Rule Scope Gate가 내립니다. 프로그램 검사기는 정책 문장의 뜻을 다시 판단하지 않고 결과 형식과 공식 출처 연결을 확인합니다. 정상적인 `UNCERTAIN + DENY`는 그대로 저장하고 Reporter만 부르지 않습니다.

## Reporter 조건

```text
TRUE
+ Technical ACCEPT
+ Rule Scope Impact review_status PASS
+ rule_compliance PASS
+ scope_compliance PASS
+ testing_restriction_compliance PASS
+ security_impact SUFFICIENT
+ permission ALLOW
```

Reporter는 위 조건을 모두 만족하고 current Finding이 있으며 exact revision closure와 `REPORT_READY`, 동일 ACTIVE Verification owner를 runtime이 확인한 때만 내부 ReportDraft를 만든다. 두 Gate가 검토한 CWELabel과 보고서 초안의 `cwe_label_ref.record_id`가 다르면 초안을 만들지 않는다. 이 upstream 중 하나가 새 revision으로 바뀌면 기존 초안은 감사 기록으로만 남고 새 Gate·Reporter 결과가 나오기 전까지 current 결과로 쓸 수 없다. 두 Gate와 Reporter 모두 외부 제출·공개 권한이 없다.

Reporter는 검증된 사실을 합성·표현할 뿐 새 vulnerability fact, attack path, reproduction/PoC 성공,
policy·scope 판단이나 upstream보다 강한 severity·exploitability·security impact를 만들지 않습니다.
주요 claim은 current Finding과 두 Gate가 실제 검토한 exact Verification·CWE·정책·Dynamic/PoC revision으로
추적해야 하며, 별도로 최신 결과를 검색해 연결하지 않습니다. Dynamic/PoC 표시는 Verification의 exact
`dynamic_result_ref`와 R7에서 이미 validated된 `poc_ref`만 소비하고, request·plan·requirements와 존재하는
policy·environment·AgentLog·PoC·cleanup을 다른 attempt와 섞지 않습니다. Reporter는 이 무결성이나 실행
성공을 새로 판정하지 않습니다. Verification restriction과 unresolved condition, 정적·동적·Gate
limitation을 빠짐없이 보존하고 실행·환경 실패를 취약점 부재로 바꾸지 않습니다. 저장 전
secret·불필요한 PII·private/raw reasoning을 제거한 `REDACTION=PASS`가 필요합니다.

프로그램 검사기는 Gate 결론을 대신 내리지 않습니다. Verification이 Gate 호출을 제안하더라도 정확한
입력·LLM call spec, Technical-accepted TRUE의 current admission decision과 Reporter 조건을 검사합니다.
금지 테스트 위반이 확정되면 result Primitive admission을 거절하고, 그 밖의 Rule Scope 판단은 보고
경로에만 적용합니다. Finding이 없으면 Reporter를 호출하지 않고 `report_draft_refs=[]`와
오류·상태 이유를 남깁니다. `ReportDraft`가 마지막 Agent 산출물이며 `AnalysisRunResult` 확정 뒤 자동화가 끝납니다.
Reporter work 종료 뒤 신뢰 runtime은 `AnalysisRunResult`와 `AnalysisRunState`를 새 Agent 판단 없이
원자적으로 확정합니다. 이후 사람의 검토·수정·제출·공개는 Agent 계약 밖이며 Reporter에는 외부 제출·공개나
CVE/GHSA 요청 권한이 없습니다.

`ALLOW`가 PASS·scope·impact 조건과 모순되거나 Gate가 현재 작업과 다른 input revision을 가리키면 유효한 Gate 결과가 아니다. LLM 호출을 `INVALID_OUTPUT`, 오류를 `GATE/INVALID_OUTPUT`으로 기록하고 Reporter를 호출하지 않는다.

각 Gate와 Reporter는 action 허가 시점과 실제 LLM 호출 직전에 같은 입력 수정본을 다시 확인합니다. `REVISE` 뒤에는 같은 입력으로 재투표할 수 없고, 보완된 Verification을 만든 뒤 R5-01이 CWE 정렬을 다시 평가해 새 label revision을 확정한 다음 새 Gate 작업과 새 action을 만들어야 합니다.

상세 내용은 [이중 LLM Gate와 보고](../05-llm-gate-and-reporting.md)을 따른다.
