# R5 handoff — prompt and synthetic I/O drafts

Owner: R5

## 1. 담당 기능

- CWE Labeling: final TRUE의 exact revision에 대한 CWELabel
- Technical Evidence Gate: 기술적 evidence/provenance 정합성 검토
- Rule Scope Impact Gate: 공식 정책 기준 reportability 검토
- Reporter: current Finding 기반 내부 ReportDraft 합성

## 2. 기준 architecture 문서

- `docs/architecture-v5/05-llm-gate-and-reporting.md`
- `docs/architecture-v5/07-results-and-observability.md`
- `docs/architecture-v5/08-lightweight-data-contracts.md`
- `docs/architecture-v5/10-security-boundaries.md`
- `docs/architecture-v5/12-report-draft-template.md`
- `docs/architecture-v5/13-architecture-diagrams.md`
- `docs/architecture-v5/implementation/01-module-map.md`
- `docs/architecture-v5/wiki/gate-and-reporting.md`
- `docs/architecture-v5/wiki/common-contracts.md`

## 3. 생성 파일

- Prompts: `prompts_cwe_labeling.md`, `prompts_technical_gate.md`, `prompts_rule_scope_gate.md`, `prompts_reporter.md`, `prompts_policy_parser.md`
- CWE fixtures: `samples_cwe_labeling/{normal,failure}.{input,expected}.json`
- Technical fixtures: `samples_technical_gate/{normal,failure}.{input,expected}.json`
- Rule Scope fixtures: `samples_rule_scope_gate/{normal,failure}.{input,expected}.json`
- Reporter fixtures: `samples_reporter/{normal,failure,chaining_normal}.{input,expected}.json`
- Policy Parser fixtures: `samples_policy_parser/{normal,failure}.{input,expected}.json`

모두 이 `docs/handoff/R5/` 디렉터리 아래에 있다.

## 4. fixture 성격과 expected 이유

모든 JSON은 `fixture_notice`로 **SYNTHETIC FIXTURE**임을 표시했다. Envelope와 `content_assertions`/`expected_behavior`은 테스트 설명용이며 canonical persisted record의 신규 필드가 아니다. `canonical_input_projection`과 `expected_canonical_projection`은 전체 persisted record가 아닌 fixture assertion projection이며, `record_id`만 보이는 reference assertion은 `StoredDataRef`가 아니다.

- CWE normal은 exact TRUE root cause로 CWE-22를 선택한다. failure는 root cause 부족이므로 `primary=null`로 둔다.
- Technical normal은 exact TRUE/CWE, `agent_invoked=true`, same-attempt dynamic/AgentLog/validated PoC closure와 candidate revision/content-or-command digest 실행 증명이 있어 ACCEPT다. cross-attempt AgentLog failure는 호출 전 stale/reference validation failure로 domain output·새 generation 없이 차단한다. 별도 REVISE fixture는 reference가 모두 정상이지만 기술 근거가 의미적으로 부족한 경우다.
- Rule Scope normal은 CURRENT official policy와 각 area의 evidence link가 있어 PASS 및 ALLOW다. failure는 `ABSENT_CONFIRMED + UNVERIFIED`로서 policy를 추측하지 않고 UNCERTAIN 및 DENY다. `COLLECTION_FAILED`라면 이 failure fixture처럼 review를 만들지 않는다는 점을 분리했다.
- Reporter normal은 REPORT_READY와 `FindingIndexState(status=CURRENT, finding_ref=exact input Finding)`, validated PoC, same-attempt execution proof 및 redaction PASS를 충족한다. chaining normal은 같은 조건에서 `ChainingResult`의 정확한 `source_result_refs`와 match/proposal provenance로 §9를 작성하되, 그 결과에 CWE/Rule Scope/admission ref를 추가하지 않는다. 이 current chain은 authorization, provider invocation, draft save에서 모두 재검증한다. failure는 token이 남아 REDACTION=PASS 전에는 draft 생성/저장이 차단된다.
- Policy Parser normal은 Collector가 고정한 exact 공식 원문 하나를 구조화하고, failure는 원문의 비신뢰 지시문이 pre-invocation에서 차단되는 경우다. 두 fixture 모두 schema/semantic/stale/prompt-injection 공통 Runtime Validator 규칙을 따른다.

## 5. 반드시 지켜야 하는 처리 규칙

- 이번 PR에서 Reporter의 `chaining_results(OPTIONAL_MANY)` 정식 slot과 POLICY_PARSER / `PARSE_OFFICIAL_POLICY` Prompt·fixture 계약을 완료했다. Chaining provenance는 `ChainingResult.source_result_refs`의 canonical set-equality만 사용하며 CWE/Rule Scope/admission ref를 결과에 넣지 않는다.
- CWE Labeling은 Verification을 재판정하지 않으며 final TRUE/current exact revision만 Gate용 label로 만든다.
- Technical Gate는 정책상 보고 가능성을 판정하지 않는다. `ACCEPT=READY`, `REVISE|REJECT=NOT_READY`다.
- Rule Scope Gate는 technical fact/impact를 새로 만들지 않는다. policy absence와 collection/parser failure를 혼동하지 않는다. `COLLECTION_FAILED`에는 Gate review가 없다.
- `report_permission=ALLOW`은 PASS/PASS/PASS/SUFFICIENT, CURRENT fixed policy state, authenticated exact policy provenance 및 critical missing info 없음에서만 가능하며 external authorization이 아니다.
- Rule Scope는 `verified_execution_facts` 같은 자유문자열을 실행 근거로 사용하지 않는다. current same-attempt Dynamic/AgentLog와 request·policy·recipe·environment·PoC exact closure만 사용한다.
- exact `PolicyCollectionResult.status=COLLECTION_FAILED`이면 Rule Scope review와 Reporter는 만들지 않고 `PRIMITIVE_ADMISSION_RUNTIME`으로 넘길 수 있다. 그 runtime은 `testing_restriction_compliance=NOT_EVALUATED`, `decision=ALLOW`, `reason=POLICY_COLLECTION_FAILED`인 `PrimitiveAdmissionDecision`을 만들 수 있다. `collection_result_ref=null`인 PREPARING/BLOCKED/FAILED 계열은 Rule Scope, Primitive Admission, Reporter 모두 진행하지 않는다. R5는 admission을 직접 생성하지 않는다.
- Reporter는 verified upstream보다 강한 claim을 만들지 않고 restriction/limitation/unresolved condition을 보존한다. validated PoC와 candidate PoC, 그리고 dynamic attempts를 섞지 않는다.
- stale/exact revision mismatch는 무시하지 않는다. Runtime Validator의 call-order, status, reference, readiness, redaction 선차단을 Agent가 대신하거나 우회하지 않는다.

## 6. cross-role review — 확인 필요

### R6

- final TRUE `VerificationResult` 최소 구조와 generation/current pointer 표현
- `supporting_evidence` 및 evidence reference의 Gate 소비 방식
- Technical REVISE 뒤 새 Verification generation 및 새 CWE/Gate work 연결
- verified impact와 unresolved condition 전달 범위

### R7

- `DynamicReproductionResult` 최소 구조
- validated `poc_ref`와 `poc_candidate_ref` 구분 및 COMMITTED 조건
- AgentLog/environment/cleanup same-attempt provenance
- FAILED/BLOCKED일 때 존재하지 않는 artifact reference를 요구하지 않는 방식

### R8

- Rule Scope Gate가 실제 소비 가능한 `RunPolicyState`/`PolicyCollectionResult` 상태
- policy freshness criterion 및 exact reference
- `ABSENT_CONFIRMED`와 `COLLECTION_FAILED`/parser failure 구분

### R4

- Runtime Validator의 CWE/Gate/Reporter 선차단 조건
- Rule Scope 결과 뒤 `PrimitiveAdmissionDecision` 기계적 연결
- current `Finding` 최소 구조와 normalization authority
- Reporter readiness 및 stale 차단

### R3

- prompt/fixture 공통 형식과 fixture envelope의 비-canonical 위치
- schema version, exact reference 표현, handoff 구조

## 7. 미결정 사항

architecture v5가 fixture 전용 envelope schema나 실제 test runner의 assertion schema를 정의하지 않는다. 따라서 `fixture_notice`, `canonical_input_projection`, `expected_canonical_projection`, `content_assertions`, `expected_behavior`은 handoff/test-document 표현이며 persisted canonical record로 확정하지 않았다. R3/R4와 공통 fixture runner가 필요하면 이 표현의 수용 여부를 확인해야 한다.
