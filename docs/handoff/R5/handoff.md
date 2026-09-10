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

- Prompts: `prompts_cwe_labeling.md`, `prompts_technical_gate.md`, `prompts_rule_scope_gate.md`, `prompts_reporter.md`
- CWE fixtures: `samples_cwe_labeling/{normal,failure}.{input,expected}.json`
- Technical fixtures: `samples_technical_gate/{normal,failure}.{input,expected}.json`
- Rule Scope fixtures: `samples_rule_scope_gate/{normal,failure}.{input,expected}.json`
- Reporter fixtures: `samples_reporter/{normal,failure}.{input,expected}.json`

모두 이 `docs/handoff/R5/` 디렉터리 아래에 있다.

## 4. fixture 성격과 expected 이유

모든 JSON은 `fixture_notice`로 **SYNTHETIC FIXTURE**임을 표시했다. Envelope와 `content_assertions`/`expected_behavior`은 테스트 설명용이며 canonical persisted record의 신규 필드가 아니다. `canonical_input_projection`과 `expected_canonical_projection`은 전체 persisted record가 아닌 fixture assertion projection이며, `record_id`만 보이는 reference assertion은 `StoredDataRef`가 아니다.

- CWE normal은 exact TRUE root cause로 CWE-22를 선택한다. failure는 root cause 부족이므로 `primary=null`로 둔다.
- Technical normal은 exact TRUE/CWE, same-attempt dynamic/AgentLog/validated PoC closure가 있어 ACCEPT다. failure는 다른 attempt AgentLog를 섞어 REVISE이며 새 Verification generation으로 보완해야 한다.
- Rule Scope normal은 CURRENT official policy와 각 area의 evidence link가 있어 PASS 및 ALLOW다. failure는 `ABSENT_CONFIRMED + UNVERIFIED`로서 policy를 추측하지 않고 UNCERTAIN 및 DENY다. `COLLECTION_FAILED`라면 이 failure fixture처럼 review를 만들지 않는다는 점을 분리했다.
- Reporter normal은 REPORT_READY와 current non-stale Finding, validated PoC 및 redaction PASS를 충족한다. failure는 token이 남아 REDACTION=PASS 전에는 draft 생성/저장이 차단된다.

## 5. 반드시 지켜야 하는 처리 규칙

- CWE Labeling은 Verification을 재판정하지 않으며 final TRUE/current exact revision만 Gate용 label로 만든다.
- Technical Gate는 정책상 보고 가능성을 판정하지 않는다. `ACCEPT=READY`, `REVISE|REJECT=NOT_READY`다.
- Rule Scope Gate는 technical fact/impact를 새로 만들지 않는다. policy absence와 collection/parser failure를 혼동하지 않는다. `COLLECTION_FAILED`에는 Gate review가 없다.
- `report_permission=ALLOW`은 PASS/PASS/PASS/SUFFICIENT, CURRENT fixed policy state, authenticated exact policy provenance 및 critical missing info 없음에서만 가능하며 external authorization이 아니다.
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

### R1

- admitted Primitive를 Chaining으로 넘길 때 필요한 R5 provenance (Verification/CWE/Technical/Rule Scope/admission refs)

### R3

- prompt/fixture 공통 형식과 fixture envelope의 비-canonical 위치
- schema version, exact reference 표현, handoff 구조

## 7. 미결정 사항

architecture v5가 fixture 전용 envelope schema나 실제 test runner의 assertion schema를 정의하지 않는다. 따라서 `fixture_notice`, `canonical_input_projection`, `expected_canonical_projection`, `content_assertions`, `expected_behavior`은 handoff/test-document 표현이며 persisted canonical record로 확정하지 않았다. R3/R4와 공통 fixture runner가 필요하면 이 표현의 수용 여부를 확인해야 한다.
