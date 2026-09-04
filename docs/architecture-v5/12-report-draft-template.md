# 12. 보고서 초안 템플릿

- **이 문서는 무엇을 설명하나요?** 모든 검토 조건을 통과한 결과를 사람이 읽을 보고서 초안으로 정리하는 양식입니다.
- **누가 읽어야 하나요?** Gate·Finding·보고서 담당과 최종 사람 검토자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 어떤 근거·정책·영향·재현 정보가 있어야 초안을 만들 수 있는지 확인합니다.

`Finding`은 검증된 취약점 결과이고 `ReportDraft`는 Reporter가 만드는 내부 초안입니다. 이 초안이 마지막 Agent 산출물이며 자동 외부 제출을 허용하지 않습니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

Reporter Agent는 다음 조건이 모두 참일 때만 이 내부 초안을 작성한다.

```text
current final Verification TRUE
+ current Finding
+ current dynamic reproduction SUCCEEDED + SUPPORTED
+ current validated poc_ref
+ Technical Evidence Gate ACCEPT
+ Rule Scope Impact Gate review_status PASS
+ rule_compliance PASS
+ scope_compliance PASS
+ security_impact SUFFICIENT
+ report_permission ALLOW
```

Reporter 호출은 `CREATE_REPORT_DRAFT` `ActionRequest`로만 요청한다. 비-LLM Runtime Validator가 위 조건, exact input revision, 현재 state version과 redaction을 확인해 `ALLOW`한 요청만 실행한다. Reporter나 Orchestration의 자연어 출력은 이 조건을 바꾸지 못한다.

중괄호 값은 검증된 artifact에서 채우며 미검증 Verification-origin 또는 Chaining-origin 후보를 확정 사실로 표현하지 않는다.

---

# {취약점 제목}

## 1. 요약

- 대상 코드: `{repository}@{commit_id} / {workspace_id}`
- 취약점 유형: `{vulnerability type}`
- CWE: `{primary CWE}`
- 영향 entity/endpoint: `{entity or endpoint}`
- Verification: `TRUE`
- Technical Evidence Gate: `ACCEPT`
- Rule/Scope/Impact: `rule_compliance PASS / scope_compliance PASS / security_impact SUFFICIENT`
- Reporter 초안 생성 권한: `ALLOW`
- Finding ref: `{finding_ref.record_id}`
- ReportDraft redaction: `PASSED`

`{공격 전제, 검증된 동작과 실제 보안 영향을 한 문단으로 설명}`

## 2. 공식 프로그램 정책과 범위

- ProgramPolicyRecord: `{policy_record_ref}`
- 공식 source: `{official source refs}`
- capture 시각/freshness: `{timestamp and warning}`
- 적용 rule: `{rule and eligibility}`
- 대상 asset/class scope: `{scope evidence}`
- 금지 테스트 준수: `{assessment}`
- disclosure 조건: `{requirements}`

## 3. 실제 영향과 제한

- 공격자에게 필요한 권한·상태: `{required capabilities}`
- 제공되는 능력: `{provided capabilities}`
- 영향받는 자산: `{data, account, service or boundary}`
- 검증된 실제 결과: `{confidentiality, integrity, availability or privilege impact}`
- restriction: `{restrictions}`
- 검토한 bypass/alternate path: `{validated outcomes}`
- 남은 불확실성: `{unresolved conditions or none}`

과장된 최악 시나리오 대신 재검증된 경로와 재현 범위만 실제 영향으로 쓴다.
severity, exploitability, capability, scope, exposure, required privilege, reproduction certainty와
security impact는 exact upstream evidence보다 강하게 표현하지 않는다.

## 4. 취약 위치

| 역할 | Entity | 위치 | 설명 |
|---|---|---|---|
| Source | `{entity}` | `{path:line}` | `{attacker-controlled input}` |
| Propagation | `{entity}` | `{path:line}` | `{call or data transformation}` |
| Guard | `{entity}` | `{path:line}` | `{missing, insufficient or bypassed guard}` |
| Sink | `{entity}` | `{path:line}` | `{security-sensitive operation}` |

## 5. 코드 및 호출 흐름

```text
{source}
→ {propagation/call step 1}
→ {guard/bypass step}
→ {sink}
```

`{각 단계가 동일 workspace_id와 commit_id에서 연결되는 근거와 CodeLocation}`

## 6. 검증 근거

### 찬성 근거

- `{claim}` — `{fact/code/dynamic ref}`

### 반대 근거와 처리

- `{counterclaim}` — `{accepted, refuted or bounded explanation}`

### Debate

- 모드와 trigger: `{BASIC | CONDITIONAL_DEBATE | ALWAYS_DEBATE / reasons}`
- 독립 Pro/Con 결과: `{summary or documented skip reason}`
- 전후 verdict/HOLD/bypass 변화: `{comparison}`

### Verification 판정

`{TRUE 이유, 충족된 전제와 남은 restriction}`

### 반증 질문 결과

| question_id | 질문 | 결과 | 근거 |
|---|---|---|---|
| `{question id}` | `{필수 조건을 반증하기 위한 질문}` | `{DISPROVED | NOT_DISPROVED | INCONCLUSIVE}` | `{evidence refs or unresolved reason}` |

`FALSE` 초안은 적어도 하나의 근거 있는 `DISPROVED` 결과와 판정의 연결을 표시한다. `NOT_DISPROVED`를 취약점 성립 증거로 표현하지 않는다.

## 7. 동적 재현과 PoC

- Verification이 참조한 동적 결과: `{dynamic_result_ref.record_id and content_hash}`
- 요청 목적: `{POC_CONFIRMATION | VERDICT_EVIDENCE}`
- R7 재현 전략: `{strategy_summary}`
- Docker 환경: `{image digest and relevant configuration}`
- 전제: `{account, data, route or build condition}`
- 실행 상태: `{SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED}`
- 실패 분류: `{NONE | POLICY_BLOCKED | EXTERNAL_CONFIGURATION | PLAN | ENVIRONMENT_SETUP | DEPENDENCY | AGENT | EXECUTION | OBSERVATION | TIMEOUT | RESOURCE_LIMIT | RETRY_LIMIT | INTERNAL}`
- 실패 상세 사유: `{failure_reason string or null}`
- Reproduction Agent 호출 여부: `{agent_invoked}`
- AgentLog reference: `{agent_log_ref.record_id; 정책 단계에서 차단된 경우에도 Session Manager가 남기는 필수 reference이며 null 불가}`
- 환경 생성 또는 재사용 여부: `{SandboxEnvironment.container_action: CREATED | REUSED; environment_ref가 있을 때}`
- 실제 환경 reference: `{environment_ref.record_id or null}`
- 환경 recipe reference: `{environment_recipe_ref.record_id or null}`
- 관측 references: `{observation_refs}`
- cleanup 필요 여부와 상태: `{cleanup_required / cleanup_status}`
- cleanup reference: `{cleanup_ref.record_id or null}`
- 동일 결과 provenance: `{request_ref, reproduction_plan_ref와 그 plan의 environment_requirements_ref, policy_decision_ref, environment_ref, agent_log_ref, poc_candidate_ref, poc_ref, cleanup_ref의 exact revision/hash; request, plan, environment, AgentLog, PoC candidate, validated PoC, cleanup은 모두 동일 reproduction attempt에 속해야 함}`
- 관측 결과: `{SUPPORTED | DISPROVED | INCONCLUSIVE}`
- PoC candidate reference: `{poc_candidate_ref.record_id}`
- validated PoC reference: `{poc_ref.record_id; R7이 exact candidate revision/digest의 POC_EXECUTION_STARTED와 POC_EXECUTION_FINISHED, 지지 observation 및 SUCCEEDED + SUPPORTED를 연결해 확정한 값만 사용}`
- 가설 연결: `{hypothesis evidence refs와 관측이 지지·반증하는 정확한 claim}`
- 환경 차이/제한: `{limitations}`

### AgentLog 기반 재현 과정 요약

- `{exact AgentLog event의 event_type/action_id/sequence와 실제 수행 결과}`
- `{POC_EXECUTION_STARTED와 POC_EXECUTION_FINISHED event가 있으면 exact candidate 실행과 연결된 observation}`
- `{실패·timeout·cancel·cleanup event와 그 limitation}`

이 목록은 exact `AgentLog`의 실제 event를 사람이 읽을 수 있게 요약한 것이며 새 실행 순서나 action을
추론하지 않는다. 실행되지 않은 action을 단계처럼 만들지 않고, `POC_EXECUTION_STARTED`와 `POC_EXECUTION_FINISHED` 및 observation은 log와
`observation_refs`에 존재하는 범위만 표시한다.

### 검증된 PoC 입력

```text
{redacted input from the exact validated PoC}
```

실제 credential, session cookie, API key와 개인정보를 포함하지 않는다.
환경의 존재와 식별은 `environment_ref`로, 생성 또는 재사용 여부는 `SandboxEnvironment.container_action=CREATED | REUSED`로 기록한다.
`agent_log_ref`는 정책 단계에서 차단되어 `agent_invoked=false`인 경우에도 Session Manager가 남기는 필수 reference이며 `null`을 허용하지 않는다. `agent_invoked=false`이거나, `agent_invoked=true`인데 동일 attempt의 exact `agent_log_ref`와 `AgentLog`
event가 실제 PoC 실행·관측을 뒷받침하지 않거나, 상태가 `BLOCKED`이면 성공 단계처럼 채우지 않는다.
Reporter는 R7이 확정하고 Verification의 exact `dynamic_result_ref`에 연결한 request·plan·requirements와
environment·policy·AgentLog·PoC·cleanup provenance를 그대로 따라 실제 미실행·차단·제한 상태와
관측 범위를 기록한다. request, plan, `environment_ref`, `agent_log_ref`, PoC candidate, validated PoC, `cleanup_ref`는 모두 동일한 reproduction attempt에 속해야 한다. 서로 다른 attempt의 artifact를 섞거나 이 무결성을 새로 판정하지 않으며, 특히 `agent_log_ref`·`environment_ref`·PoC·cleanup reference의 attempt가 하나라도 다르면 fail-closed 처리한다.
환경·실행 실패를 취약점 부재로 해석하지 않는다.

## 8. CWE

- 검토한 CWELabel revision: `{cwe_label_ref.record_id}`
- CWELabel이 직접 가리킨 Verification revision: `{CWELabel.verification_result_ref.record_id}`
- primary: `{CWE-ID and name}`
- taxonomy version: `{version}`
- 선택 이유와 evidence: `{rationale and refs}`
- alternatives/uncertainty: `{alternatives or none}`

## 9. Verification 확장 조사와 Chaining

- Verification이 조사한 bypass/alternate/impact: `{validated outcomes or none}`
- Verification-origin 새 가설: `{proposal and validated child refs or none}`
- Chaining에 사용한 Primitive: `{primitive refs and exact Verification/Technical review provenance}`
- Chaining 조합: `{upstream result Primitive, downstream input Primitive, matched_input_id, match refs or skipped}`
- Chaining-origin 새 가설: `{proposal and validated child refs or none}`
- 아직 미검증: `{candidate refs; report claim으로 사용하지 않음}`
- match 없음 또는 전역 예산 중단: `{no-match/global-budget reason if applicable}`

## 10. 두 Gate 검토

### Technical Evidence Gate

- 상태: `ACCEPT`
- 검토한 Verification revision: `{verification_result_ref.record_id}`
- 검토한 CWELabel revision: `{cwe_label_ref.record_id}`
- verdict-evidence/코드 흐름/동적 연결: `{assessment}`
- CWE/restriction/handoff: `{assessment}`
- revision 이력: `{history or none}`

### Rule Scope Impact Gate

- 검토한 Verification revision: `{verification_result_ref.record_id}`
- 검토한 Technical review revision: `{technical_review_ref.record_id}`
- 검토한 CWELabel revision: `{cwe_label_ref.record_id}`
- 검토한 정책 revision: `{policy_record_ref.record_id}`
- overall/rule/scope: `PASS / PASS / PASS`
- impact: `SUFFICIENT`
- 정책 근거와 판단 이유: `{policy refs and rationale}`
- report permission: `ALLOW`

위 세 위치의 `cwe_label_ref.record_id`는 같아야 한다. 또한 `CWELabel.verification_result_ref.record_id`는 두 Gate와 초안이 검토한 `verification_result_ref.record_id`와 같아야 한다. CWELabel이나 Verification이 수정되면 기존 Gate 결과와 보고서 초안을 재사용하지 않는다.

## 11. LLM invocation trace와 오류

- 역할별 invocation refs: `{Hypothesis, Verification, Pro/Con, Chaining, Gates, Reporter}`
- provider/model/session mode: `{safe metadata}`
- retrieved code locations: `{location refs}`
- schema repair/failover: `{attempt refs or none}`
- 관련 error/resource limit: `{safe summary or none}`

hidden chain-of-thought와 secret은 포함하지 않는다.
access/session token, password, private key, credential, cookie·authorization secret, 불필요한 PII,
내부 secret과 private/raw reasoning도 저장하지 않는다.

## 12. 완화와 회귀 테스트

- `{root-cause-linked remediation}`
- `{authorization/validation/control remediation}`
- `{regression test recommendation}`

## 13. 자동화 종료 연결 정보

- ReportDraft record: `{report_draft_ref.record_id}`
- 함께 검토할 AnalysisRunResult: `{analysis_result_ref.record_id}`
- 남은 오류·DataGap·HOLD 조건: `{refs or none}`

---

Reporter Agent는 이 초안을 만든 뒤 추가 검토·수정·제출·공개를 수행하지 않는다. 신뢰 runtime이
current 결과와 이 초안을 `AnalysisRunResult`에 묶고 `AnalysisRunState`와 원자적으로 확정한 뒤 Agent
자동화가 끝난다. 이 finalization은 새 Agent 판단이 아니라 저장·상태 확정이다. 이후 과정은 사람이
시스템 밖에서 주도하며, 이 템플릿은 사람의 결정 상태나 자동 공개 action을 정의하지 않는다.
