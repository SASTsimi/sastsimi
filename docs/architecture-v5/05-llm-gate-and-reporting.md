# 05. 이중 LLM Gate와 보고

- **이 문서는 무엇을 설명하나요?** 기술 근거와 공식 정책을 차례로 검토하고 보고서 초안을 만들 수 있는 조건을 설명합니다.
- **누가 읽어야 하나요?** Gate·Finding·보고서, 검증과 PM 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 각 Gate의 입력·출력, 보완 요청과 Reporter 호출 조건을 확인합니다.

`Gate`는 다음 단계로 보내도 되는지 확인하는 검토 단계입니다. Gate는 검증 판정을 바꾸지 않고 Reporter는 외부 공개를 결정하지 않습니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목적과 순서

v5에는 책임이 다른 두 LLM 검토 Agent가 있다.

1. final `VerificationResult`와 별도 `CWELabel`의 정확한 `record_id` revision을 Technical Evidence Gate Agent가 함께 검토한다.
2. Technical 결과가 `ACCEPT`이고 Verification verdict가 `TRUE`일 때만 Rule Scope Impact Gate Agent를 호출한다.
3. 두 Gate와 impact·permission 조건을 모두 통과했을 때만 Reporter Agent를 호출한다.

두 Gate는 점수 합산식이나 취약점 진위를 새로 판정하는 규칙 엔진이 아니다. 각자의 자료를 읽고 근거가 있는 검토 결과를 생성하는 LLM Agent이며 Verification verdict를 직접 변경할 수 없다.

비-LLM Runtime Validator는 Gate의 결론을 대신 만들지 않는다. `ActionRequest`의 역할·schema·exact input revision·상태·예산과 Gate 순서만 검사한다. Technical Gate 호출에는 final Verification과 CWELabel의 `COMMITTED` revision이 필요하고, Rule Scope Gate 호출에는 같은 Verification이 `TRUE`이며 Technical review가 `ACCEPT`라는 exact reference가 필요하다. 조건이 맞지 않으면 `GATE_ORDER_INVALID`로 호출 자체를 막는다.

## CWE 라벨링

CWE 후보는 final verdict 뒤에 작성한다. primary·alternative CWE, taxonomy version, 선택 이유와 evidence reference를 포함한다. `HOLD`나 `FALSE`에도 분석 기록용 후보를 남길 수 있지만 보고 가능한 취약점 라벨이라는 뜻은 아니다. 구분 근거가 부족하면 억지로 단일 CWE를 확정하지 않는다.

## Gate 1: Technical Evidence Gate Agent

### 입력

- `VulnerabilityHypothesis`
- final `VerificationResult`의 정확한 `record_id`가 있는 `StoredDataRef`와 revision history
- Pro/Con evidence와 debate mode/trigger
- 실제 code/entity/location/path reference
- `DynamicReproductionResult`와 PoC reference
- `CWELabel`의 정확한 `record_id`가 있는 `StoredDataRef`와 근거
- restriction, bypass candidate, unresolved condition
- 관련 Research proposal 중 재검증 완료 여부

### 검토 항목

- `TRUE | FALSE | HOLD`와 찬성·반대 근거의 일치
- 핵심 주장이 현재 `workspace_id`와 `commit_id`의 코드 위치·호출·데이터 흐름에 연결되는지
- 동적 관측이 현재 가설·`workspace_id`·실행 조건에 연결되는지
- CWE 선택이 취약점 유형과 근거에 적절한지
- restriction·반박·HOLD 조건이 정확히 표현되었는지
- 기술 검토 결과를 다음 단계 또는 내부 종결 기록으로 전달할 수 있는지

### 출력과 의미

```yaml
technical_evidence_review:
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
  research_requests: []
  rationale: explanation
```

- `ACCEPT`: 현재 verdict와 기술 설명이 검토 가능한 근거에 연결되어 있다. `TRUE` 또는 정책상 보고 가능하다는 뜻은 아니다.
- `REVISE`: Verification 또는 Research가 구체적인 누락·restriction·재현·CWE 설명을 보완해야 한다.
- `REJECT`: 현재 자료를 신뢰 가능한 기술 기록이나 다음 단계 입력으로 사용할 수 없다.

`verification_result_ref.record_id`와 `cwe_label_ref.record_id`는 Gate가 실제로 읽은 `VerificationResult`와 `CWELabel` revision을 각각 고정한다. runtime은 Gate와 두 대상의 `workspace_id`, `commit_id`, `hypothesis_id`, `record_id`, `content_hash`를 확인한다. Verification 또는 CWELabel이 수정되면 이전 `ACCEPT`를 새 revision에 재사용하지 않고 Gate를 새로 호출한다.

`REVISE`는 동일 입력 재투표가 아니다. Orchestration Agent가 요청을 Verification 또는 Research에 보내고 새 근거·설명·revision이 생긴 뒤 다시 호출한다. 횟수·token·시간 한도 도달 시 보고를 차단하고 미해결 사유를 저장한다.

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

저장소 문서나 모델 기억을 공식 정책으로 자동 승격하지 않는다. 공식 `ProgramPolicyRecord`가 없거나 핵심 자료가 누락되면 추측하지 않는다.

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

공식 정책 자료가 없으면 최소한 `rule_compliance=UNCERTAIN`, `scope_compliance=UNCERTAIN`, `review_status=UNCERTAIN`, `report_permission=DENY`와 `missing_information`을 반환한다. impact도 검토할 근거가 부족하면 `security_impact=UNCERTAIN`이다.

Runtime Validator는 공식 정책 문장을 대신 해석하지 않는다. 다만 `policy_record_ref=null`이거나 핵심 공식 source가 누락된 출력에서 `ALLOW`·`PASS`가 함께 나타나는 구조적 모순은 invalid output으로 거절한다. 제한된 repair 뒤에도 불변조건이 맞지 않으면 Rule Scope Gate work를 실패 처리하고 Reporter를 차단한다. 이 오류는 Verification verdict를 바꾸지 않는다.

`verification_result_ref`, `technical_review_ref`, `cwe_label_ref`와 존재하는 `policy_record_ref`에는 정확한 저장 revision의 `record_id`가 필요하다. runtime은 Technical review가 `ACCEPT`이고, Technical review와 Rule Scope review가 같은 Verification과 CWELabel `record_id`를 각각 가리키는지 확인한다. 각 reference의 `workspace_id`, `commit_id`, `content_hash`는 대상 record와 일치해야 하며, Verification·CWELabel·Technical 대상의 `meta.hypothesis_id`는 Rule Scope review의 가설과 같아야 한다. 정책이 있으면 Rule Scope review가 가리킨 정책 record와 Reporter가 사용할 정책 record도 같아야 한다. 입력 revision이 하나라도 달라지면 기존 Rule Scope 결과를 재사용하지 않는다.

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

조건이 하나라도 충족되지 않거나 Gate reference 연결이 맞지 않으면 결과와 검토 사유는 저장하지만 Reporter를 호출하지 않는다. LLM이 모순되는 `ALLOW`를 출력하면 schema/semantic validation 오류로 처리한다. 이는 취약점 판정 규칙이 아니라 권한 없는 보고 생성을 막는 호출 전제다.

Reporter 호출도 `CREATE_REPORT_DRAFT` `ActionRequest`로 요청한다. Runtime Validator는 위 일곱 조건, exact `record_id`·hash·workspace·commit·hypothesis, current state version과 redaction 전제를 `REPORT_READY` check로 확인한다. 하나라도 맞지 않으면 `REPORT_NOT_READY`로 차단한다. Reporter Agent의 자연어 요청이나 Orchestration Agent의 일정 판단만으로 이 check를 건너뛸 수 없다.

## Reporter Agent

Reporter는 통과한 근거를 읽기 쉬운 내부 초안으로 구성한다.

- 취약점 요약, 공격 전제와 실제 영향
- entity·코드 위치와 source → propagation/call → sink
- restriction, bypass 검토와 반박 처리
- 동적 재현과 redacted PoC
- 두 Gate가 검토한 같은 `CWELabel` revision과 선택 이유
- 두 Gate 결과와 `ProgramPolicyRecord` reference
- Research 후보의 재검증 여부
- 완화와 회귀 테스트 제안
- invocation trace와 남은 불확실성

Reporter는 새로운 공격 경로를 확정하거나 미검증 Research 후보를 실제 영향으로 쓰지 않는다. 초안의 핵심 주장은 Verification/PoC/Gate artifact에 연결한다. `ReportDraft.cwe_label_ref.record_id`는 Technical review와 Rule Scope review가 공통으로 가리킨 CWELabel `record_id`와 같아야 하며, CWELabel이 수정되면 두 Gate를 다시 통과하기 전에는 초안을 만들지 않는다.

## 사람의 최종 결정

자동 산출물은 내부 `FindingCandidate`와 `ReportDraft`다. 사람에게는 별도 `HumanReviewPacket`을 전달한다.

packet에는 다음을 빠뜨리지 않는다.

- exact `AnalysisRunResult`, Finding 후보와 final Verification
- Technical·Rule Scope Gate와 CWE·공식 정책 reference
- dynamic reproduction과 redacted PoC
- ReportDraft 또는 보고서가 차단된 구체적인 이유
- token·시간·Sandbox 등 자원 사용량
- 모든 실행 오류·DataGap·남은 HOLD 조건
- LLM 호출·action decision·work state·transition commit와 debug trace reference

사람은 이 packet의 정확한 revision을 읽고 별도 `HumanReviewDecision`에 `DISCLOSE | REVISE | WITHHOLD | NEED_MORE_VALIDATION`을 기록한다. 결정 저장은 인증된 사람 identity와 exact packet을 확인하는 `SAVE_HUMAN_DECISION` action을 거친다. `ReportDraft` 안의 field를 바꾸거나 LLM output을 사람 결정으로 저장하지 않는다.

시스템의 외부 disclosure action은 Human Reviewer가 만든 exact `HumanReviewDecision=DISCLOSE`, `report_ready=true`인 packet, packet 안의 `approved_report_refs`와 명시된 `disclosure_targets`가 있을 때만 허용한다. Agent·Gate·Reporter가 만든 결정, 승인 목록 밖 report, 다른 packet이나 수정 전 revision의 결정은 `DISCLOSURE_DENIED`다. 어떤 Agent도 외부 제출·공개 권한을 갖지 않으며 실제 자동 제출 integration은 이 설계 범위 밖이다.
