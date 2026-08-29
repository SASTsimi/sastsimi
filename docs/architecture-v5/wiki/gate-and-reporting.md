# 이중 LLM Gate와 보고

## 쉽게 말하면

첫 번째 검토는 취약점 판정과 코드·실행 근거가 맞는지 확인합니다. 두 번째 검토는 공식 정책 범위와 실제 영향을 확인합니다. 두 검토를 모두 통과한 결과만 보고서 초안으로 만듭니다.

**상세 기준:** [05. 이중 LLM Gate와 보고](../05-llm-gate-and-reporting.md)

Gate는 검증 판정을 직접 바꾸지 않고 Reporter는 외부 공개를 결정하지 않습니다. 모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

## 1. 기술 근거 검토(`Technical Evidence Gate`)

final `VerificationResult`의 verdict와 찬반 근거, 실제 코드·호출·데이터 흐름, 동적 결과, CWE, restriction와 HOLD 표현을 검토한다. 이때 `verification_result_ref.record_id`와 `cwe_label_ref.record_id`로 정확히 어느 검증 결과와 CWE 수정본을 검토했는지 고정한다. 둘 중 하나가 수정되면 기존 Gate 결과를 재사용하지 않고 다시 검토한다. 출력은 `ACCEPT | REVISE | REJECT`이며 verdict를 직접 바꾸지 않는다. `REVISE`는 현재 Gate 작업을 종료한 뒤 Verification이 실제 보완 내용을 새 Verification 또는 CWE 수정본으로 확정하고, 새 `work_id`와 첫 attempt로 다시 검토한다. Research 근거도 이 새 Verification 수정본에 연결해야 한다. 같은 입력의 retry attempt만 늘려 재투표하지 않는다.

## 2. 공식 정책·범위·영향 검토(`Rule Scope Impact Gate`)

Technical `ACCEPT`인 `TRUE`만 공식 `ProgramPolicyRecord`과 함께 검토한다. Rule Scope 결과에는 자신이 읽은 Verification, Technical review, CWELabel과 정책의 정확한 `record_id`를 남긴다. Technical review가 가리킨 CWELabel과 Rule Scope가 직접 가리킨 CWELabel은 같아야 한다. 이 중 하나라도 수정되면 이전 Rule Scope 결과를 재사용하지 않는다.

- rule_compliance: `PASS | FAIL | UNCERTAIN`
- scope_compliance: `PASS | FAIL | UNCERTAIN`
- security_impact: `SUFFICIENT | INSUFFICIENT | UNCERTAIN`
- report permission: `ALLOW | DENY`

공식 정책 자료가 없으면 rule/scope는 `UNCERTAIN`이고 permission은 `DENY`다. 저장소 문서나 모델 기억으로 공식 정책을 추정하지 않는다.

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

Reporter는 위 조건을 모두 만족하고 ReportDraft가 가리킨 Verification·Technical review·Rule Scope review·CWELabel·정책 revision이 서로 맞을 때만 내부 보고서 초안을 만든다. 두 Gate가 검토한 CWELabel과 보고서 초안의 `cwe_label_ref.record_id`가 다르면 초안을 만들지 않는다. 두 Gate와 Reporter 모두 외부 제출 권한이 없고 사람만 최종 공개를 결정한다.

프로그램 검사기는 Gate 결론을 대신 내리지 않습니다. Technical 다음 Rule Scope라는 순서, 정확한 입력·LLM call spec과 Reporter 조건만 검사합니다. 사람에게는 보고서뿐 아니라 근거·PoC·비용·오류·HOLD 조건을 담은 `HumanReviewPacket`을 전달합니다. `HumanReviewState`가 최신 packet과 결정을 가리키므로 새 packet이 생기면 이전 결정은 공개에 쓸 수 없습니다.

`ALLOW`가 PASS·scope·impact 조건과 모순되거나 Gate가 현재 작업과 다른 input revision을 가리키면 유효한 Gate 결과가 아니다. LLM 호출을 `INVALID_OUTPUT`, 오류를 `GATE/INVALID_OUTPUT`으로 기록하고 Reporter를 호출하지 않는다.

각 Gate와 Reporter는 action 허가 시점과 실제 LLM 호출 직전에 같은 입력 수정본을 다시 확인합니다. `REVISE` 뒤에는 같은 입력으로 재투표할 수 없고, 보완된 Verification 또는 CWE 수정본으로 새 Gate 작업과 새 action을 만들어야 합니다.

상세 내용은 [이중 LLM Gate와 보고](../05-llm-gate-and-reporting.md)을 따른다.
