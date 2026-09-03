# 이중 LLM Gate와 보고

## 쉽게 말하면

첫 번째 검토는 취약점 판정과 코드·실행 근거가 맞는지 확인합니다. 두 번째 검토는 공식 정책 범위와 실제 영향을 확인합니다. 두 검토를 모두 통과한 결과만 보고서 초안으로 만듭니다.

**상세 기준:** [05. 이중 LLM Gate와 보고](../05-llm-gate-and-reporting.md)

Gate는 검증 판정을 직접 바꾸지 않고 Reporter는 외부 공개를 결정하지 않습니다. 모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

## 1. 기술 근거 검토(`Technical Evidence Gate`)

final TRUE `VerificationResult`의 찬반 근거, 실제 코드·호출·데이터 흐름, 현재 generation의 `DynamicReproductionRequest`·성공한 동적 결과·validated PoC, CWE와 restriction을 검토한다. FALSE와 HOLD는 이 Gate를 호출하지 않는다. 각 exact revision을 고정하며 하나라도 수정되면 기존 Gate 결과를 재사용하지 않는다. 출력은 `ACCEPT | REVISE | REJECT`와 별도 `handoff_readiness: READY | NOT_READY`다. `ACCEPT`는 `READY`, 나머지는 `NOT_READY`만 허용하며 verdict를 직접 바꾸지 않는다. `REVISE`는 같은 Verification owner에게 직접 돌아가며, 새 generation에서 TRUE를 다시 만들려면 새 동적 결과와 validated PoC도 필요하다.

동적 재현이 Sandbox 정책에 막힌 것은 `FALSE`나 Gate의 `REJECT` 근거가 아니다. 하지만 validated PoC가 없으므로 final TRUE와 Technical Gate 입력을 만들 수 없다. retry 가능하면 동적 work를 `BLOCKED`, 복구 불가능하면 verdict 없이 `FAILED`로 끝낸다.

## 2. 공식 정책·범위·영향 검토(`Rule Scope Impact Gate`)

Technical `ACCEPT`인 `TRUE`만 공식 `ProgramPolicyRecord`과 함께 검토한다. Rule Scope 결과에는 자신이 읽은 Verification, Technical review, CWELabel과 정책의 정확한 `record_id`를 남긴다. Technical review가 가리킨 CWELabel과 Rule Scope가 직접 가리킨 CWELabel은 같아야 한다. 이 중 하나라도 수정되면 이전 Rule Scope 결과를 재사용하지 않는다.

- rule_compliance: `PASS | FAIL | UNCERTAIN`
- scope_compliance: `PASS | FAIL | UNCERTAIN`
- security_impact: `SUFFICIENT | INSUFFICIENT | UNCERTAIN`
- report permission: `ALLOW | DENY`

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

Reporter는 위 조건을 모두 만족하고 ReportDraft가 가리킨 current Finding·Verification·Technical review·Rule Scope review·CWELabel·정책 revision이 서로 맞을 때만 내부 보고서 초안을 만든다. 두 Gate가 검토한 CWELabel과 보고서 초안의 `cwe_label_ref.record_id`가 다르면 초안을 만들지 않는다. restriction·limitation·남은 불확실성과 redaction 통과 상태도 초안에 보존한다. 이 upstream 중 하나가 새 revision으로 바뀌면 기존 초안은 감사 기록으로만 남고 새 Gate·Reporter 결과가 나오기 전까지 current `AnalysisRunResult`에 쓸 수 없다.

프로그램 검사기는 Gate 결론을 대신 내리지 않습니다. Verification이 Gate 호출을 제안하더라도 Technical 다음 Rule Scope라는 순서, 정확한 입력·LLM call spec, PROVIDED admission과 Reporter 조건을 검사합니다. Finding이 없으면 Reporter를 호출하지 않고 `report_draft_refs=[]`와 오류·상태 이유를 남깁니다. `ReportDraft`가 마지막 Agent 산출물이며 `AnalysisRunResult` 확정 뒤 자동화가 끝납니다. 이후 사람의 검토·수정·제출·공개는 Agent 계약 밖입니다.

`ALLOW`가 PASS·scope·impact 조건과 모순되거나 Gate가 현재 작업과 다른 input revision을 가리키면 유효한 Gate 결과가 아니다. LLM 호출을 `INVALID_OUTPUT`, 오류를 `GATE/INVALID_OUTPUT`으로 기록하고 Reporter를 호출하지 않는다.

각 Gate와 Reporter는 action 허가 시점과 실제 LLM 호출 직전에 같은 입력 수정본을 다시 확인합니다. `REVISE` 뒤에는 같은 입력으로 재투표할 수 없고, 보완된 Verification 또는 CWE 수정본으로 새 Gate 작업과 새 action을 만들어야 합니다.

상세 내용은 [이중 LLM Gate와 보고](../05-llm-gate-and-reporting.md)을 따른다.
