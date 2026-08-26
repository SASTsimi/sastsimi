# 05. 이중 LLM Gate와 보고

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목적과 순서

v5에는 책임이 다른 두 LLM 검토 Agent가 있다.

1. `CWELabel`을 포함한 final `VerificationResult`를 Technical Evidence Gate Agent가 검토한다.
2. Technical 결과가 `ACCEPT`이고 Verification verdict가 `TRUE`일 때만 Rule Scope Impact Gate Agent를 호출한다.
3. 두 Gate와 impact·permission 조건을 모두 통과했을 때만 Reporter Agent를 호출한다.

두 Gate는 점수 합산식이나 취약점 진위를 새로 판정하는 규칙 엔진이 아니다. 각자의 자료를 읽고 근거가 있는 검토 결과를 생성하는 LLM Agent이며 Verification verdict를 직접 변경할 수 없다.

## CWE 라벨링

CWE 후보는 final verdict 뒤에 작성한다. primary·alternative CWE, taxonomy version, 선택 이유와 evidence reference를 포함한다. `HOLD`나 `FALSE`에도 분석 기록용 후보를 남길 수 있지만 보고 가능한 취약점 라벨이라는 뜻은 아니다. 구분 근거가 부족하면 억지로 단일 CWE를 확정하지 않는다.

## Gate 1: Technical Evidence Gate Agent

### 입력

- `VulnerabilityHypothesis`
- final `VerificationResult`와 revision history
- Pro/Con evidence와 debate mode/trigger
- 실제 code/entity/location/path reference
- `DynamicReproductionResult`와 PoC reference
- CWE 후보와 근거
- restriction, bypass candidate, unresolved condition
- 관련 Research proposal 중 재검증 완료 여부

### 검토 항목

- `TRUE | FALSE | HOLD`와 찬성·반대 근거의 일치
- 핵심 주장이 실제 snapshot의 코드 위치와 호출·데이터 흐름에 연결되는지
- 동적 관측이 현재 가설·snapshot·실행 조건에 연결되는지
- CWE 선택이 취약점 유형과 근거에 적절한지
- restriction·반박·HOLD 조건이 정확히 표현되었는지
- 기술 검토 결과를 다음 단계 또는 내부 종결 기록으로 전달할 수 있는지

### 출력과 의미

```yaml
technical_evidence_review:
  status: ACCEPT | REVISE | REJECT
  evidence_verdict_alignment: explanation
  code_flow_linkage: explanation
  dynamic_linkage: explanation
  cwe_assessment: explanation
  restriction_assessment: explanation
  handoff_readiness: READY | NOT_READY
  revision_requests: []
  research_requests: []
  rationale: explanation
```

- `ACCEPT`: 현재 verdict와 기술 설명이 검토 가능한 근거에 연결되어 있다. `TRUE` 또는 정책상 보고 가능하다는 뜻은 아니다.
- `REVISE`: Verification 또는 Research가 구체적인 누락·restriction·재현·CWE 설명을 보완해야 한다.
- `REJECT`: 현재 자료를 신뢰 가능한 기술 기록이나 다음 단계 입력으로 사용할 수 없다.

`REVISE`는 동일 입력 재투표가 아니다. Orchestration Agent가 요청을 Verification 또는 Research에 보내고 새 근거·설명·revision이 생긴 뒤 다시 호출한다. 횟수·token·시간 한도 도달 시 보고를 차단하고 미해결 사유를 저장한다.

## Gate 2: Rule Scope Impact Gate Agent

이 Gate는 Technical `ACCEPT`인 `TRUE`만 받는다. 취약점 기술 성립과 bug-bounty 프로그램의 보고 가능성을 분리한다.

### ProgramPolicySnapshot

입력 정책은 분석 시점에 고정된 공식 자료여야 한다.

- program identifier, policy version과 fetch timestamp
- 공식 rule, eligibility와 severity/impact 기준
- in-scope/out-of-scope asset와 vulnerability class
- 금지된 테스트·재현 행위
- known limitation, duplicate 또는 disclosure 조건
- 각 항목의 official source reference
- 수집하지 못한 자료와 freshness warning

저장소 문서나 모델 기억을 공식 정책으로 자동 승격하지 않는다. 공식 `ProgramPolicySnapshot`이 없거나 핵심 자료가 누락되면 추측하지 않는다.

### 검토 항목

- 프로그램 rule과 eligibility 충족 여부
- 대상 asset과 vulnerability class의 scope
- 수행한 재현이 금지 조건과 충돌하는지
- 검증된 실제 impact가 프로그램 기준에 충분한지
- restriction, alternate path와 미검증 Research 후보의 표현이 정확한지
- 보고서 초안을 작성할 수 있는지

### 출력

```yaml
rule_scope_impact_review:
  review_status: PASS | FAIL | UNCERTAIN
  rule_compliance: PASS | FAIL | UNCERTAIN
  scope_compliance: PASS | FAIL | UNCERTAIN
  security_impact: SUFFICIENT | INSUFFICIENT | UNCERTAIN
  report_permission: ALLOW | DENY
  policy_snapshot_ref: string | null
  reasons: []
  missing_information: []
```

공식 정책 자료가 없으면 최소한 `rule_compliance=UNCERTAIN`, `scope_compliance=UNCERTAIN`, `review_status=UNCERTAIN`, `report_permission=DENY`와 `missing_information`을 반환한다. impact도 검토할 근거가 부족하면 `security_impact=UNCERTAIN`이다.

## Reporter 호출 조건

다음 조건을 모두 만족해야 한다.

```text
final verdict == TRUE
AND Technical Evidence Gate == ACCEPT
AND Rule Scope Impact Gate review_status == PASS
AND rule_compliance == PASS
AND scope_compliance == PASS
AND security_impact == SUFFICIENT
AND report_permission == ALLOW
```

조건이 하나라도 충족되지 않으면 결과와 검토 사유는 저장하지만 Reporter를 호출하지 않는다. LLM이 모순되는 `ALLOW`를 출력하면 schema/semantic validation 오류로 처리한다. 이는 취약점 판정 규칙이 아니라 권한 없는 보고 생성을 막는 호출 전제다.

## Reporter Agent

Reporter는 통과한 근거를 읽기 쉬운 내부 초안으로 구성한다.

- 취약점 요약, 공격 전제와 실제 영향
- entity·코드 위치와 source → propagation/call → sink
- restriction, bypass 검토와 반박 처리
- 동적 재현과 redacted PoC
- CWE와 선택 이유
- 두 Gate 결과와 `ProgramPolicySnapshot` reference
- Research 후보의 재검증 여부
- 완화와 회귀 테스트 제안
- invocation trace와 남은 불확실성

Reporter는 새로운 공격 경로를 확정하거나 미검증 Research 후보를 실제 영향으로 쓰지 않는다. 초안의 핵심 주장은 Verification/PoC/Gate artifact에 연결한다.

## 사람의 최종 결정

자동 산출물은 내부 `FindingCandidate`와 `ReportDraft`다. 사람은 원문 근거, 두 Gate, 공식 정책 snapshot, PoC, 오류와 자원 제한을 함께 검토해 `DISCLOSE | REVISE | WITHHOLD | NEED_MORE_VALIDATION`을 결정한다. 어떤 Agent도 외부 제출·공개 권한을 갖지 않는다.
