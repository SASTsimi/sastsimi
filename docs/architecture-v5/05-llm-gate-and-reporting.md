# 05. 이중 LLM Gate와 보고

- **이 문서는 무엇을 설명하나요?** 기술 근거와 공식 정책을 차례로 검토하고 보고서 초안을 만들 수 있는 조건을 설명합니다.
- **누가 읽어야 하나요?** Gate·Finding·보고서, 검증과 PM 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 각 Gate의 입력·출력, 보완 요청과 Reporter 호출 조건을 확인합니다.

`Gate`는 다음 단계로 보내도 되는지 확인하는 검토 단계입니다. Gate는 검증 판정을 바꾸지 않고 Reporter는 외부 공개를 결정하지 않습니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목적과 순서

v5에는 책임이 다른 두 LLM 검토 Agent가 있다.

1. final `VerificationResult.verdict=TRUE`와 별도 `CWELabel`의 정확한 `record_id` revision을 Technical Evidence Gate Agent가 함께 검토한다. FALSE와 HOLD는 이 Gate를 호출하지 않는다.
2. Technical 결과가 `ACCEPT`일 때만 Rule Scope Impact Gate Agent를 호출한다.
3. 두 Gate와 impact·permission 조건을 모두 통과했을 때만 같은 Verification owner가 Reporter Agent 호출을 요청한다.

가설 내부의 Gate 제출 시점은 같은 가설의 Verification owner가 정한다. Verification은 `CALL_TECHNICAL_GATE`와, Technical `ACCEPT` 뒤의 `CALL_RULE_SCOPE_GATE`, 모든 보고 조건을 통과한 뒤의 `CREATE_REPORT_DRAFT`를 제안한다. 실제 호출 가능 여부와 순서는 비-LLM Runtime Validator가 강제한다. Orchestration Agent가 `REVISE` 목적지를 선택하거나 Verification 대신 Gate 보완 내용을 조정하지 않는다.

두 Gate는 점수 합산식이나 취약점 진위를 새로 판정하는 규칙 엔진이 아니다. 각자의 자료를 읽고 근거가 있는 검토 결과를 생성하는 LLM Agent이며 Verification verdict를 직접 변경할 수 없다.

비-LLM Runtime Validator는 Gate의 결론을 대신 만들지 않는다. `ActionRequest`의 역할·schema·exact input revision·상태·예산과 Gate 순서만 검사한다. Technical Gate 호출에는 final TRUE Verification과 CWELabel의 `COMMITTED` revision이 필요하고, Rule Scope Gate 호출에는 같은 Verification이 `TRUE`이며 Technical review가 `ACCEPT`라는 exact reference가 필요하다. 조건이 맞지 않으면 `GATE_ORDER_INVALID`로 호출 자체를 막는다. 이 exact reference 검사는 action 허가 시점과 실제 LLM 호출 직전에 다시 수행한다.

## CWE 라벨링

CWE 후보는 final TRUE 뒤에 Gate 입력으로 작성한다. primary·alternative CWE, taxonomy version, 선택 이유와 evidence reference를 포함한다. `HOLD`나 `FALSE`에 분석용 분류 메모를 남길 수는 있지만 Gate 입력 `CWELabel`이나 보고 가능한 취약점 라벨로 승격하지 않는다. 구분 근거가 부족하면 억지로 단일 CWE를 확정하지 않는다.

## Gate 1: Technical Evidence Gate Agent

### 입력

Top-level direct input은 다음 두 reference뿐이다.

- final `VerificationResult`의 정확한 `record_id`가 있는 `verification_result_ref`
- `CWELabel`의 정확한 `record_id`가 있는 `cwe_label_ref`

등록 가설, Pro/Con Evidence, 실제 code/entity/location/path, `DynamicReproductionResult`, PoC, restriction·unresolved condition과 `CWELabel.evidence_refs`는 두 direct input에서 도달하는 transitive dependency다. 이를 `CALL_TECHNICAL_GATE`의 별도 top-level domain input으로 다시 전달하지 않는다.

Gate의 기준 입력은 `verification_result_ref`가 고정한 final `VerificationResult` revision과
`cwe_label_ref`가 고정한 `CWELabel` revision이다. 정확한 가설 revision은 Verification의
필수 `hypothesis_ref`로 고정한다. 등록 완료된 `VulnerabilityHypothesis`의 material content는 수정하지 않으며 statement·target·attack path 등 의미가 달라지면 새 proposal을 등록해 새 `hypothesis_id`로 처음부터 Verification lifecycle을 수행한다. supporting/counter Evidence,
`DynamicReproductionResult`, PoC는 별도의 최상위 Gate reference를 새로 만들지 않고,
그 `VerificationResult` revision 안의 `hypothesis_ref`, `supporting_evidence[].evidence_refs`,
`counter_evidence[].evidence_refs`, `dynamic_result_ref`, `poc_ref`를 따라 검토한다.
`CWELabel.evidence_refs`도 `cwe_label_ref`에서 따라가는 전이적 입력이다.
따라서 Gate가 검토한 입력 집합은 두 직접 reference와 그 revision이 실제로 가리키는
전이적 reference 집합이다. revision history는 변경 이유를 이해하기 위한 문맥이지, 서로 다른 revision의
근거를 골라 합치는 권한을 주지 않는다.

검사는 record 종류별로 분리한다.

- shared static evidence인 `CodeLocation`, `CodeSymbol`, `CodeFact`, `CodeRelation`, `StaticFactBundle`은 현재 분석의 `workspace_id + commit_id`, Verification/Evidence가 사용한 exact reference·revision과 hash를 확인한다. 직접적인 `hypothesis_id`는 요구하지 않으며 같은 commit의 여러 가설이 재사용할 수 있다.
- hypothesis-scoped record인 `VulnerabilityHypothesis`, `VerificationResult`, `DynamicReproductionResult`, `CWELabel`, `TechnicalEvidenceReview`와 기타 가설별 artifact는 `hypothesis_id`, workspace·commit, exact `record_id`와 `content_hash`를 확인한다. 내장 `EvidenceClaim`은 이를 소유한 Verification의 가설 범위로 검사한다. revision chain은 별도의 공통 revision 계약으로 검증하며, 다른 가설의 Verification·Dynamic 결과 혼입은 invalid input이다.

`StoredDataRef.record_id`가 있는 Evidence·Dynamic 결과는 정확한 저장 record revision을,
`record_id=null`인 raw observation·code fragment·PoC artifact는 `stored_data_id`,
`content_hash`, `workspace_id`, `commit_id`로 불변 내용을 가리킨다. PoC도 현재 검증 결과의 `poc_ref`로
도달할 수 있어야 하며, reference 없이 별도로 전달된 자료는 Gate 근거로 승격하지 않는다.

특히 `DynamicReproductionResult`에서는 exact `poc_ref`·`policy_decision_ref`·`environment_ref`·
`steps_ref`, `runner_invoked`, `environment_created`, `cleanup_required`·`cleanup_status`를 위
transitive closure로 읽는다. restriction, bypass candidate, unresolved condition과 같은 Verification에서
분리한 material child proposal의 재검증 여부도 해당 exact revision chain에서만 확인한다.

### 검토 항목

- final `TRUE`와 찬성·반대 근거의 일치
- 핵심 주장이 현재 `workspace_id`와 `commit_id`의 코드 위치·호출·데이터 흐름에 연결되는지
- 동적 관측이 현재 가설·`workspace_id`·실행 조건에 연결되는지
- Runner 호출 여부와 step log, 실제 환경 생성 여부와 환경 reference, 정책 차단과 Controller 판정 reference, 정리 필요 여부와 상태가 공통 계약에 맞는지
- PoC reference가 있다는 사실을 실행 또는 성공으로 오해하지 않고 실제 log·관측과 같은 revision인지
- CWE 선택이 취약점 유형과 근거에 적절한지
- restriction·unresolved condition·반박과 limitation이 정확히 표현되었는지
- 기술 검토 결과를 다음 단계 또는 내부 종결 기록으로 전달할 수 있는지

#### Evidence와 verdict 정렬

Gate는 final `TRUE` verdict를 다시 판정하지 않고, Verification Agent가 남긴 판정과 설명이
그 exact revision의 근거로 실제 뒷받침되는지만 검토한다. `FALSE | HOLD`는 이 검토의 입력이 아니다.

- `TRUE`는 핵심 exploit path와 필수 조건을 설명하는 supporting claim이 실제 evidence와
  code location에 연결되어야 한다. 단순한 source·sink 존재나 `NOT_DISPROVED`만을 지지
  근거로 표현하면 정렬되지 않은 것이다.
- final `TRUE`에서도 관련 counter evidence, falsification 결과와 limitation을 설명이 누락·축소하지
  않아야 하며, supporting/counter claim의 statement, evidence, limitation이 서로 모순되면
  그 위치를 특정한다.
- hypothesis-scoped evidence가 다른 `hypothesis_id`를 가리키거나, 어떤 evidence든 다른 workspace·commit 또는 현재 reference와 다른 content/revision이면 현재 verdict의 근거로 사용할 수 없다.

#### 코드 연결

- `CodeLocation`의 Git 상대 경로와 line/column 범위가 현재 commit에서 검토한 코드 조각을
  실제로 가리키고, `CodeSymbol`의 entity·symbol·route/endpoint 종류와 이름이 그 위치와
  일치하는지 확인한다.
- source → propagation/call → sink 또는 source → security check 관계가 기존 `CodeFact`,
  `CodeRelation`, context/Evidence reference로 이어지는지, 설명된 방향·순서·guard 적용 여부가
  그 연결과 같은지 확인한다.
- 모든 location, symbol, fact, relation과 이를 담은 Evidence가 같은 `workspace_id + commit_id`에 속하고 exact reference로 연결되는지 확인한다. shared static record 자체에는 현재 `hypothesis_id`를 요구하지 않고, 이를 현재 주장에 연결하는 hypothesis-scoped Evidence에 가설 일치를 요구한다.
- 누락된 edge를 추론해 채우거나 새 data-flow·endpoint·공격 경로를 만들지 않는다. 새 material
  claim이 필요하면 Gate 판정 근거로 쓰지 않고 기존 proposal/재검증 경계를 따른다.

#### 불완전한 코드 문맥과 DataGap

Gate가 `CodeContextResponse`를 근거로 사용할 때에는 R2가 정의한 `DataGap.affected_locations`,
`affected_paths` 등 기존 영향 범위를 현재 Verification claim이 의존하는 code path,
auth/permission check와 data-flow 영역에 대조한다. claim과 겹치는 gap은 evidence-verdict alignment와
code-flow linkage 판단에서 무시할 수 없으며, 해결되지 않았다면 기존 restriction·unresolved condition의
표현이 충분한지 검토하고 필요한 경우 `revision_requests`에 구체적인 보완 범위를 기록한다. 다만
`DataGap`의 존재 자체는 자동 `REVISE | REJECT` 조건이 아니다.

`CodeContextResponse.truncated=true`이거나 claim 관련 `DataGap`이 있으면 조회되지 않은 영역을
확인된 것으로 가정하거나 반환되지 않은 코드까지 검증된 것으로 해석하지 않으며, 그 불완전한 문맥으로
claim strength를 높이거나 그것만을 근거로 `ACCEPT`하지 않는다. 확인되지 않은 코드 영역은 verified
evidence로 승격할 수 없고, Gate는 upstream Verification과 Evidence가 실제로 검증한 수준보다 강한
claim을 승인할 수 없다. 이는 Gate가 새 claim을 만들거나 Verification verdict를 변경한다는 뜻이 아니다.

반대로 이미 확보된 독립적인 Evidence/Verification만으로 현재 claim이 충분히 입증되었다면
`truncated=true` 또는 관련 gap의 존재만으로 `ACCEPT`를 금지하지 않는다. 따라서 Gate는 gap이나
truncation의 존재 여부만으로 status를 정하지 않고, 누락 범위가 현재 claim의 근거 충분성에 실제로
영향을 주는지를 기존 evidence-verdict alignment, code-flow linkage, restriction과
`ACCEPT | REVISE | REJECT` 기준 안에서 판단한다. 누락된 영역을 안전하거나 문제가 없는 영역으로
간주해서는 안 된다.

#### 동적 재현과 PoC 연결

- `dynamic_decision`과 `dynamic_result_ref`의 존재가 일치하고, Dynamic 결과의
  `meta.hypothesis_id`, workspace·commit, `hypothesis_linkage`가 현재 가설과 일치하는지 확인한다.
- `policy_decision_ref`, `environment_ref`, `steps_ref`, observation과 실행 전제(권한·설정·입력·버전)가 기술 설명의
  공격 조건과 같은지 확인한다. 다른 환경에서의 결과를 현재 대상으로 일반화하지 않는다.
- `status`, `failure_reason`, `hypothesis_outcome`, `runner_invoked`, `environment_created`,
  `cleanup_required`, `cleanup_status`, evidence와 `limitations`의 허용 조합을 공통
  계약대로 확인한다. `FAILED | BLOCKED | CANCELLED`, `PARTIAL`, 미수행 결과를 성공·반증으로
  표현하거나 그 제한을 누락하면 정렬되지 않은 것이다.
- `poc_ref`의 존재만으로 PoC 실행, 재현 성공 또는 impact 입증을 주장하지 않는다. 생성되었지만
  실행되지 않은 PoC가 있을 수 있으며, 실행 PoC 주장은 Runner가 실제 사용한 command/input,
  관련 step log와 observation에 같은 revision 또는 digest로 연결되어야 한다.
- Dynamic 결과와 정책 판정·환경·step log·실행 PoC·cleanup 기록은 같은 hypothesis·workspace·commit 및
  같은 R7 Dynamic execution attempt에 속해야 한다. 서로 다른 attempt의 artifact를 섞거나 “latest”로
  다시 선택하지 않는다.
- PoC는 `poc_ref`가 가리키는 실행·관측과 재현된 impact 범위까지만 설명해야 한다. PoC가
  더 큰 권한·asset·endpoint·영향을 주장하거나 현재 환경/commit과 연결되지 않으면 보완 또는
  거절 대상이다.
- 필수 `EnvironmentRequirement`가 일치하지 않으면 R7이 조건을 완화하거나 공격 단계를 실행할 수 없다.
  환경 차이·구축 실패는 자동 `FALSE`나 `DISPROVED`가 아니며, 필요하면 같은 Verification owner가
  새 requirements와 이를 가리키는 plan revision을 만든 뒤 새 동적 실행·Verification revision 흐름을 밟는다.
- redaction에 실패한 raw observation·PoC는 일반 Verification → Gate → Reporter evidence closure에
  들어올 수 없다. Gate가 이를 정제하거나 대체 evidence로 만들지 않는다.
- Gate는 동적 결과나 PoC를 새로 해석해 새 취약점·공격 경로를 만들지 않는다.

decision/result/status/PoC의 정본 compatibility matrix는 [경량 데이터 계약](08-lightweight-data-contracts.md#dynamic-decisionresultpoc-compatibility)을 따른다. 구조 불변조건 위반은 Runtime Validator·schema·semantic validation에서 Gate 전에 invalid output으로 차단하며 Gate의 `REVISE | REJECT`로 처리하지 않는다. Dynamic/PoC의 생성·실행·상태·reference·redaction·attempt 정합성은 R7-04에서 확정된 공통 계약을 따른다. Technical Evidence Gate는 해당 계약을 새로 정의하지 않고, 현재 Verification revision이 참조하는 exact Dynamic/PoC artifact가 그 계약에 맞게 연결되었고 기술 claim이 실제 관측 범위를 넘어가지 않는지만 검토한다. mode별 PoC 필수 여부처럼 정본 계약이 명시하지 않은 사항은 Gate가 추정하지 않는다.

#### CWE와 제한 조건 정렬

- `CWELabel.primary`, alternatives, taxonomy version, rationale, evidence와 uncertainty가 현재
  Verification에서 실제 검증된 동작과 구분 수준에 맞는지 확인한다. 미검증 impact나 후보
  경로를 CWE 선택 근거로 사용해서는 안 된다.
- Gate가 새 CWE를 자유롭게 선택하거나 기존 label을 덮어쓰지 않는다. 불일치하면 어느
  검증 동작·근거와 맞지 않는지와 새 `CWELabel` revision 필요 여부를 요청한다.
- Verification/Evidence/Dynamic/PoC의 권한·설정·환경·미검증 flow·제한된 impact,
  `restrictions`, `unresolved_conditions`, claim/dynamic limitations와 관련 gap/error가 기술
  설명에서 보존되어야 한다. 이를 확정적·일반적 취약점으로 과장하면 통과시키지 않는다.

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

`handoff_readiness`는 현재 Technical review가 고정한 revision chain을 downstream에 전달할 수 있는지를
뜻한다. 현재 R5 pipeline의 immediate next stage는 R5-02 Rule Scope Impact Gate다. 허용 조합은
`ACCEPT + READY`, `REVISE + NOT_READY`, `REJECT + NOT_READY`뿐이다. 이 문맥에서 `READY`는 동일 exact Verification revision의 R5-02 진입 근거일 뿐
R5-02의 정책·scope·impact 판정, `report_permission`, `REPORT_READY`, Reporter 호출,
ReportDraft 생성 또는 외부 제출·공개 허용을 뜻하지 않는다.

`ACCEPT`는 final TRUE의 모든 핵심 claim과 반대 근거, 코드·동적·PoC·CWE·제한 reference가 현재 revision chain에 정렬되고 다음 소비자가 누락된 기술 근거를 새로 구성할 필요가 없을 때만 사용한다. 이는 정책상 보고 가능성, Reporter 실행 권한 또는 PROVIDED Primitive 자격을 단독으로 부여하지 않는다.

`REJECT`는 direct/transitive reference와 exact provenance chain이 모두 정상인데도 핵심 주장과 Evidence·code-flow·동적 설명의 의미 linkage가 근본적으로 맞지 않아 현재 전달 묶음을 단순 보완의 기반으로도 신뢰할 수 없을 때 사용한다. 이는 Verification verdict를 `FALSE`로 바꾸지 않는다. 다른 workspace·commit·hypothesis, 존재하지 않거나 잘못된 record/revision, content hash mismatch, stale reference, schema·semantic validation 실패, LLM/provider/runtime 오류와 `INVALID_OUTPUT`은 Gate 호출 또는 review 저장·사용 전에 기존 공통 오류 계약으로 차단하며 `REJECT`를 생성하지 않는다.

`revision_requests`와 `verification_requests`는 부족하거나 모순된 claim/location/condition, 현재 artifact reference/hash, 필요한 Evidence 또는 새 revision, 완료 확인 기준을 구체적으로 기록한다. 이 요청은 목적지 routing 권한이 아니며 같은 Verification owner가 보완 범위를 정한다. 새 material claim이나 미검증 child proposal은 현재 Gate 근거로 승격하지 않고 trusted registration 뒤 별도 hypothesis의 전체 Verification lifecycle을 거친다.
`ACCEPT`는 `handoff_readiness=READY`, `REVISE | REJECT`는 `handoff_readiness=NOT_READY`와 함께 사용한다. 이 조합이 맞지 않으면 Gate output을 저장하지 않는다.

`DynamicReproductionResult(status=BLOCKED, failure_reason=POLICY_BLOCKED)`는 정책 때문에 실행하지 못했다는 뜻이지 가설 반증이 아니므로 그 사실만으로 `REJECT`하지 않는다.

- 정적·찬반 근거만으로 final TRUE의 핵심 주장을 충분히 검토할 수 있고, 차단된 재현의 제한·미실행 사실·exact `policy_decision_ref`가 정확히 연결되면 `ACCEPT + READY`가 가능하다.
- 보고서 핵심 주장에 동적 재현이 꼭 필요한데 정책 차단으로 근거가 부족하고, 범위 축소·안전한 대체 검증·추가 설명으로 보완할 수 있으면 `REVISE + NOT_READY`다.
- reference 조합이 계약을 위반하거나 근거가 서로 모순되어 현재 기술 기록을 신뢰할 수 없을 때만 `REJECT + NOT_READY`다. 정책 차단 자체를 `FALSE` 또는 `REJECT` 근거로 바꾸지 않는다.

`verification_result_ref.record_id`와 `cwe_label_ref.record_id`는 Gate가 실제로 읽은 `VerificationResult`와 `CWELabel` revision을 각각 고정한다. runtime은 Gate와 두 대상의 `workspace_id`, `commit_id`, `hypothesis_id`, `record_id`, `content_hash`를 확인한다. Verification 또는 CWELabel이 수정되면 이전 `ACCEPT`를 새 revision에 재사용하지 않고 Gate를 새로 호출한다.

`REVISE`는 동일 입력 재투표나 provider retry가 아니다. 현재 Gate work는 `REVISE` review를 exact output으로 확정하고 종료한다. 그 review는 Orchestration을 경유해 목적지를 다시 선택하지 않고 같은 hypothesis의 ACTIVE `VerificationAssignment` owner에게 전달한다. runtime은 이전 종료 work를 되돌리지 않고 새 generation의 VERIFICATION work를 등록하며 hypothesis 상태를 `TERMINAL -> VERIFYING`으로 CAS 전환한다. Verification은 필요한 Context·Pro/Con·정적 근거·동적 재현·PoC 연결·restriction을 보완하고, 새 result·work 종료·hypothesis current pointer를 atomic commit하며, 필요하면 CWE producer와 새 label revision을 조정한다. 그 뒤 새 `VerificationResult` 및 필요한 `CWELabel` revision을 가리키는 새 Gate work를 요청한다. 새 Gate work는 새 `input_hash`·`dedupe_key`·`work_id`와 `attempt_number=1`, `trigger=INITIAL`을 사용한다. 입력이 바뀌지 않은 호출 실패만 같은 work 안에서 `trigger=RETRY`인 새 attempt를 사용할 수 있다. 횟수·token·시간 한도 도달 시 보고와 TRUE 체이닝을 차단하고 미해결 사유를 저장한다.

Runtime Validator는 `REVISE`를 만든 기존 action·decision을 다시 사용하지 못하게 하고, 같은 Verification·CWE revision 또는 같은 domain input hash로 새 Gate 투표를 요청하면 `ACTION_NOT_ALLOWED`로 차단한다. 보완된 upstream revision을 가리키는 새 work·call spec·action·decision이 모두 있어야 한다. 반대로 provider 실패나 `INVALID_OUTPUT` repair는 Gate 판단을 다시 요구한 것이 아니므로, 허용된 횟수 안에서 같은 domain input과 새 invocation 식별자·action을 사용하는 `RETRY`로만 처리한다.

`verification_result_ref.record_id`와 `cwe_label_ref.record_id`는 Gate가 실제로 읽은 exact revision을 고정한다. runtime은 두 direct reference에서 supporting/counter Evidence, Dynamic result, PoC, restriction·unresolved condition과 `CWELabel.evidence_refs`를 따라 transitive closure를 만들고 공통 validator로 대상 존재, exact revision, workspace·commit, hypothesis-scoped artifact의 `hypothesis_id`, `content_hash`를 확인한다. 정책 판정·실제 환경·step log·실행 PoC·cleanup처럼 같은 R7 실행에서 만들어진 dependency는 `DynamicReproductionResult.meta.attempt_id`와 같은 execution attempt인지도 확인한다. 이 검사는 `CALL_TECHNICAL_GATE` 실행 직전, `TechnicalEvidenceReview` 저장 직전과 R5-02 진입 직전에 반복한다. 어느 direct/transitive dependency가 바뀌어도 기존 review는 `RECORD_REVISION_MISMATCH` 또는 `STALE_RESULT` 등 기존 공통 오류로 차단하며 변경된 revision의 R5-02 진입 근거로 재사용할 수 없다. Reporter·ReportDraft·PROVIDED의 별도 stale 검사는 각 downstream 공통 계약이 소유한다.

### 권한 경계

Technical Evidence Gate는 Dynamic reproduction mode를 선택하거나 Sandbox를 실행하지 않고, `EnvironmentRequirements`·`ReproductionPlan`·PoC·Dynamic observation·Dynamic 결과를 생성·수정하지 않는다. 환경 mismatch의 허용 여부를 정하거나 R7 결과에서 새 vulnerability evidence를 만들지도 않는다. 또한 Verification verdict, CWELabel, Evidence, data-flow, 공격 경로를 생성·수정하지 않고 공식 프로그램 정책을 추정하거나 Rule·Scope·Impact 결과, `report_permission`, `REPORT_READY`, Primitive admission, Reporter 실행, ReportDraft, Human Review, disclosure 또는 외부 제출·공개를 결정하지 않는다. 고정된 final TRUE 묶음의 기술적 정렬과 동일 exact revision의 R5-02 진입 가능성만 검토한다.

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

저장소 문서나 모델 기억을 공식 정책으로 자동 승격하지 않는다. 공식 `ProgramPolicyRecord`가 없거나 핵심 자료가 누락되면 추측하지 않는다. 정책 record가 있어도 `freshness_status=STALE | UNVERIFIED`이면 최신 정책으로 취급하지 않는다. `CURRENT` 판정의 최대 허용 나이와 출처별 확인 방법은 R5 정책 수집 설계에서 정하지만, stale·미검증 상태의 Gate 결과는 항상 `UNCERTAIN + DENY`다.

### 검토 항목

- 프로그램 rule과 eligibility 충족 여부
- 대상 asset과 vulnerability class의 scope
- 수행한 재현이 금지 조건과 충돌하는지
- 검증된 실제 impact가 프로그램 기준에 충분한지
- restriction, alternate path와 미검증 Verification-origin 또는 Chaining-origin child의 표현이 정확한지
- 보고서 초안을 작성할 수 있는지

### 출력

```yaml
rule_scope_impact_review:
  action_decision_ref: StoredDataRef
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

공식 정책 자료가 없거나 `freshness_status=STALE | UNVERIFIED`이면 Rule Scope Gate Agent가 정책을 추정하지 않고 최소한 `rule_compliance=UNCERTAIN`, `scope_compliance=UNCERTAIN`, `review_status=UNCERTAIN`, `report_permission=DENY`와 `missing_information`을 판단해 반환한다. impact도 검토할 근거가 부족하면 `security_impact=UNCERTAIN`이다. stale record의 exact reference와 경고는 감사 기록으로 보존하지만 `PASS | ALLOW` 근거로 사용하지 않는다.

Runtime Validator는 공식 정책 문장이나 정책의 의미를 대신 해석하지 않는다. Rule Scope Gate가 판단한 `UNCERTAIN + DENY`의 필수 필드, exact 정책 reference와 구조적 불변조건만 검사한다. `policy_record_ref=null`이거나 핵심 공식 source가 누락된 출력에서 `ALLOW`·`PASS`가 함께 나타나면 semantic `INVALID_OUTPUT`으로 거절하고, 정상적인 `UNCERTAIN + DENY`이면 `REPORT_READY` check로 Reporter만 프로그램적으로 차단한다. 제한된 repair 뒤에도 불변조건이 맞지 않으면 Rule Scope Gate work를 실패 처리한다. 두 경우 모두 Verification verdict를 바꾸지 않는다.

`verification_result_ref`, `technical_review_ref`, `cwe_label_ref`와 존재하는 `policy_record_ref`에는 정확한 저장 revision의 `record_id`가 필요하다. runtime은 Technical review가 `ACCEPT`이고, Technical review와 Rule Scope review가 같은 Verification과 CWELabel `record_id`를 각각 가리키는지 확인한다. 각 reference의 `workspace_id`, `commit_id`, `content_hash`는 대상 record와 일치해야 하며, Verification·CWELabel·Technical 대상의 `meta.hypothesis_id`는 Rule Scope review의 가설과 같아야 한다. 정책이 있으면 Rule Scope review가 가리킨 정책 record와 Reporter가 사용할 정책 record도 같아야 한다. 입력 revision이 하나라도 달라지면 기존 Rule Scope 결과를 재사용하지 않는다.

## Gate-qualified TRUE와 PROVIDED admission

TRUE가 Chaining에 쓰이려면 Reporter 호출 조건과 같은 Rule Scope 정상 통과 의미를 재사용한다. 즉 final TRUE, Technical `ACCEPT`, `review_status/rule/scope=PASS`, `security_impact=SUFFICIENT`, `report_permission=ALLOW`가 exact 같은 Verification·CWE revision에 연결되어야 한다. 이 조건을 모두 통과한 뒤에만 runtime이 `PROVIDED` Primitive admission을 허가한다.

Technical `ACCEPT`만 받은 결과, `FAIL | UNCERTAIN | DENY` 결과와 Gate 전 TRUE는 내부 기록으로 보존하지만 PROVIDED나 Chaining input이 아니다. 새 Verification generation 또는 revision이 생기면 과거 두 Gate reference는 새 revision의 자격을 증명하지 못하며 이전 Primitive는 current `PrimitiveIndexState`에서 제외된다. 진행 중 Chaining result도 commit 직전 index head와 current final Verification을 다시 검사하므로 오래된 ACTIVE record로 proposal을 등록할 수 없다. HOLD는 이 절차를 사용하지 않고 final HOLD에서 REQUIRED Primitive로 즉시 Chaining에 들어간다.

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

조건이 하나라도 충족되지 않거나 Gate reference 연결이 맞지 않으면 결과와 검토 사유는 저장하지만 Reporter를 호출하지 않는다. LLM이 `review_status`, rule, scope 또는 impact 조건과 모순되는 `ALLOW`를 출력하면 semantic validation 실패다. 이 호출은 `LLMInvocationResult.status=INVALID_OUTPUT`, `AnalysisError.stage=GATE`, `AnalysisError.code=INVALID_OUTPUT`으로 기록하며 invalid output을 `RuleScopeImpactReview`로 commit하지 않는다. 제한된 repair가 남아 있을 때만 같은 입력의 새 invocation attempt를 허용하고, 한도를 소진하면 Gate work를 `FAILED`로 끝낸다. 어느 경우에도 Reporter를 호출하거나 Verification verdict를 변경하지 않는다. 이는 취약점 판정 규칙이 아니라 권한 없는 보고 생성을 막는 호출 전제다.

Gate와 Reporter의 stage action은 exact `LLMCallSpec`까지 포함해 실제 LLM 호출을 직접 허가한다. 이 세 역할이 별도 `CALL_LLM` action으로 stage 검사를 우회하는 것은 허용하지 않는다. Technical action의 `REVISION`은 exact Verification+CWE를, `GATE_ORDER`는 두 revision의 final `COMMITTED` 상태를 검사한다. Rule Scope action의 `REVISION`은 같은 Verification+CWE와 exact Technical review를, `GATE_ORDER`는 `TRUE`+Technical `ACCEPT`를 검사한다. Reporter action의 `REVISION`은 current Finding과 두 Gate가 검토한 같은 Verification+CWE·Technical·Rule Scope·정책 revision을 검사하고 `REPORT_READY`는 Finding 존재와 위 일곱 조건을 검사한다. 하나라도 맞지 않으면 `REPORT_NOT_READY`로 차단한다. Runtime은 이 검사를 action 허가 때와 실제 provider 호출 직전에 반복하며, 달라졌으면 decision을 `EXPIRED`로 바꾸고 호출하지 않는다. 실제 invocation request의 model·prompt·context·schema·budget·timeout은 검사한 call spec과 모두 같아야 한다.

## Reporter Agent

Reporter는 통과한 근거를 읽기 쉬운 내부 초안으로 구성한다.

- 취약점 요약, 공격 전제와 실제 영향
- current Finding과 final Verification의 exact reference
- entity·코드 위치와 source → propagation/call → sink
- restriction, bypass 검토와 반박 처리
- 동적 재현과 redacted PoC. 실행하지 않은 PoC나 정책 차단 자료는 그 상태를 숨기지 않음
- 두 Gate가 검토한 같은 `CWELabel` revision과 선택 이유
- 두 Gate 결과와 `ProgramPolicyRecord` reference
- Verification-origin 및 Chaining-origin child proposal의 재검증 여부
- 완화와 회귀 테스트 제안
- invocation trace와 남은 불확실성

Reporter는 새로운 공격 경로를 확정하거나 미검증 material child 또는 Chaining 후보를 실제 영향으로 쓰지 않는다. 초안의 핵심 주장은 current Finding, Verification, PoC와 두 Gate의 exact revision에 연결한다. `poc_ref`가 있어도 `runner_invoked=false`, `steps_ref=null` 또는 `status=BLOCKED`이면 실행·재현 성공으로 서술하지 않는다. `ReportDraft.cwe_label_ref.record_id`는 Technical review와 Rule Scope review가 공통으로 가리킨 CWELabel `record_id`와 같아야 하며, CWELabel이 수정되면 두 Gate를 다시 통과하기 전에는 초안을 만들지 않는다.

Reporter는 Verification의 restriction과 unresolved condition, 정적·동적 검증 및 두 Gate의 limitation을 빠뜨리거나 완화하지 않는다. 저장 전 `REDACTION=PASS`를 요구하며 credential, session secret, 불필요한 개인정보와 비공개 원문을 제거한다. 이 값은 `ReportDraft.restrictions`, `limitations`, `unresolved_conditions`, `redaction_status=PASSED`로 확인할 수 있어야 한다.

ReportDraft가 참조한 `FindingCandidate`, `VerificationResult`, `CWELabel`, `TechnicalEvidenceReview`, `RuleScopeImpactReview` 또는 `ProgramPolicyRecord` 중 하나라도 새 current revision으로 바뀌면 기존 초안은 감사 기록으로만 남고 `AnalysisRunResult.report_draft_refs`의 current 결과로 사용할 수 없다. 새 exact dependency chain으로 Gate와 Reporter를 다시 실행해 새 ReportDraft를 만든다.

## Agent 자동화 종료와 사람 주도 후속 과정

`ReportDraft`는 R5-03 Reporter와 전체 Agent 파이프라인의 마지막 Agent 산출물이다. Reporter work가 atomic하게 종료되면 신뢰 runtime은 다음 항목을 `AnalysisRunResult`에 묶는다.

- Finding 후보와 final Verification
- Technical·Rule Scope Gate와 CWE·공식 정책 reference
- dynamic reproduction과 redacted PoC
- current ReportDraft 또는 초안이 만들어지지 않은 구체적인 이유
- token·시간·Sandbox 등 자원 사용량
- 모든 실행 오류·DataGap·남은 HOLD 조건
- LLM 호출·action decision·work state·work attempt·transition commit와 debug trace reference

`AnalysisRunResult`와 `AnalysisRunState`를 함께 확정하면 Agent 자동화가 끝난다. Finding이 없으면 Reporter를 호출하지 않고 `report_draft_refs=[]`로 종료 원인을 보존한다. 이후 사람이 결과를 검토하거나 문서를 수정하고 외부에 제출·공개하는 과정은 Agent 자동화 밖이다. 현재 아키텍처는 이 사람 주도 과정의 schema, 상태, 결정 enum 또는 자동 action을 정의하지 않는다.
