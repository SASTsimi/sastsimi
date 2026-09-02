# 06. Primitive DB와 Chaining

- **이 문서는 무엇을 설명하나요?** 보류된 가설의 부족 조건과 Gate를 통과한 공격 능력을 연결해 새 가설을 만드는 방법을 설명합니다.
- **누가 읽어야 하나요?** LLM 탐색·체이닝, 검증과 데이터·평가 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 어떤 결과가 언제 체이닝 입력이 되는지와 깊이·횟수·token·시간 중단 기준을 확인합니다.

`Primitive`는 연계 공격의 필요 조건 또는 확인된 능력입니다. `Chaining`은 호환되는 Primitive 두 개를 연결해 새 가설을 제안하는 제한된 작업입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목적과 범위

Chaining Agent는 다음 두 조합만 확인한다.

```text
Gate-qualified TRUE + HOLD
Gate-qualified TRUE + Gate-qualified TRUE
```

Chaining Agent는 Primitive 조회·호환성 검사·중복 및 순환 검사·새 가설 제안만 담당한다. 일반 취약점 탐색, 우회·대체 경로 탐색, 영향 확대 조사, 추가 정적·동적 검증과 Technical Gate `REVISE` 처리는 Verification Agent의 책임이다. Primitive DB와 Chaining Agent는 Finding을 만들거나 부모 가설의 판정을 바꾸지 않는다.

## Primitive 모델과 등록 시점

Primitive는 공격 경로에서 필요하거나 제공되는 최소 능력을 표현한다.

```yaml
Primitive:
  meta: RecordMeta
  primitive_id: string
  primitive_type: string
  target:
    workspace_id: string
    commit_id: string
    asset: string
    entity_refs: [CodeSymbol]
    endpoint: string | null
    privilege_level: string
    data_type: string | null
  status: REQUIRED | PROVIDED
  source_hypothesis_id: string
  source_verification_ref: StoredDataRef
  technical_review_ref: StoredDataRef | null
  rule_scope_review_ref: StoredDataRef | null
  required_preconditions: [PrimitiveDraft]
  eligibility: ACTIVE | SUPERSEDED
  superseded_by_verification_ref: StoredDataRef | null
  evidence_refs: [StoredDataRef]
  confidence: LOW | MEDIUM | HIGH
  description: string
```

등록 규칙은 판정별로 다르다.

- final `HOLD`: exact final `VerificationResult`에서 `REQUIRED` Primitive를 즉시 저장한다. 두 Gate를 기다리지 않으며 `technical_review_ref`와 `rule_scope_review_ref`는 `null`이다.
- final `FALSE`: Primitive를 만들지 않고 체이닝을 호출하지 않는다.
- final `TRUE`: Verification 결과만으로 `PROVIDED`를 만들지 않는다. 같은 Verification revision과 CWE revision을 Technical Gate가 `ACCEPT`하고, Rule Scope Gate가 기존 정상 통과 조건을 모두 만족한 뒤에만 `PROVIDED`를 저장한다. 이 PROVIDED의 `required_preconditions`에는 exact Verification이 기록한 악용 전제조건을 복사한다.

Rule Scope Gate의 정상 통과는 다음 기존 조건을 그대로 사용한다.

```text
review_status == PASS
AND rule_compliance == PASS
AND scope_compliance == PASS
AND security_impact == SUFFICIENT
AND report_permission == ALLOW
```

따라서 `Technical ACCEPT`만 받은 TRUE, `FAIL | UNCERTAIN | DENY`인 TRUE와 Gate 전 TRUE는 체이닝 자격이 없다. PROVIDED의 세 provenance reference는 동일한 `workspace_id`, `commit_id`, `hypothesis_id`와 exact Verification revision을 가리켜야 한다.

## exact revision과 오래된 승인 차단

Primitive DB는 가설별 `PrimitiveIndexState`가 가리키는 exact final Verification revision과 `ACTIVE` 항목만 조회한다. 새 Verification generation 또는 새 `VerificationResult` revision이 생기면 index version을 증가시키고 이전 revision에서 나온 Primitive는 기록으로 보존하되 새 Primitive revision에서 `SUPERSEDED`로 표시하고 현재 체이닝 조회에서 제외한다. REVISE 재진입에서는 새 Verification work와 hypothesis `VERIFYING` 전이와 같은 atomic transaction으로 active 목록을 먼저 비운다.

과거 Technical `ACCEPT` 또는 Rule Scope `PASS`가 Verification N을 가리키는데 Verification N+1이 만들어졌다면 N+1은 아직 Gate-qualified TRUE가 아니다. N의 Gate reference를 N+1의 PROVIDED admission에 재사용할 수 없다. 이 규칙은 Gate에서 나중에 탈락할 TRUE가 먼저 chain ancestor가 되는 문제를 구조적으로 막는다.

Chaining work는 각 parent의 current `PrimitiveIndexState` exact revision을 input에 고정한다. 결과와 child proposal을 저장하기 직전에 runtime이 index head와 현재 final Verification을 compare-and-set으로 다시 검사한다. 탐색 중 새 Verification/index revision이 생기면 과거 Primitive record에 `ACTIVE`가 남아 있어도 해당 결과는 `STALE_RESULT`이며 proposal을 등록하지 않는다.

## HeldHypothesis와 ConfirmedCapability

- `HeldHypothesis`는 final HOLD, restriction, unresolved condition과 `REQUIRED` Primitive를 묶는다. 이는 확인된 취약점이 아니다.
- `ConfirmedCapability`는 두 Gate를 정상 통과한 exact TRUE revision과 `PROVIDED` Primitive를 묶는다. `TRUE` 자체가 외부 공개되었다는 뜻은 아니다.
- HOLD를 `PROVIDED`로 바꾸거나 체이닝 성공을 근거로 부모 HOLD를 TRUE로 바꾸지 않는다.

Primitive DB는 worker가 항목을 꺼내 실행하는 queue가 아니다. 가설 등록과 Verification 배정은 global trusted runtime과 Orchestration Agent가 담당하고, DB는 체이닝 후보를 찾는 분석 인덱스다.

## Chaining Agent

### 입력과 허용 책임

Chaining Agent는 final HOLD의 ACTIVE REQUIRED와 Gate-qualified TRUE의 ACTIVE PROVIDED만 입력으로 받는다. 다음 항목을 확인한다.

- 같은 `workspace_id`와 `commit_id`
- 같은 asset 또는 근거가 있는 asset 간 이동
- entity와 endpoint 호환성
- privilege 수준의 충족 관계
- data 형식과 식별자 호환성
- 공격 순서상 능력이 필요한 시점보다 먼저 생기는지
- 결합 뒤에도 남는 restriction
- normalized fingerprint 중복, ancestor cycle과 chain budget

두 종류의 matching을 지원한다.

- `TRUE_HOLD`: 한 PROVIDED가 한 REQUIRED를 충족하는지 확인한다.
- `TRUE_TRUE`: 앞 TRUE의 PROVIDED가 뒤 TRUE의 PROVIDED에 포함된 `required_preconditions` 중 하나를 충족하는지 순서 있게 확인한다. 양쪽 부모 TRUE 모두 exact Gate-qualified revision이어야 하며, 뒤 TRUE의 exact Verification에 기록되지 않은 전제조건을 새로 만들어 연결하지 않는다.

문자열 `primitive_type`이 같다는 이유만으로 match를 만들지 않는다. 호환성 근거와 미확인 조건을 `PrimitiveMatchCandidate`에 남긴다.

Chaining이 비교하는 REQUIRED/PROVIDED의 `target.primitive_type`·`target.privilege_level`·`target.data_type`은 admission 시점에 Verification이 생산한 `PrimitiveDraft`(`08-lightweight-data-contracts.md`)의 같은 이름 필드에서 그대로 복사된 값이다. `PrimitiveDraft.target_asset`은 `Primitive.target.asset`, `PrimitiveDraft.entity_refs`/`endpoint`/`data_type`도 `Primitive.target`의 같은 이름 필드에 각각 대응한다. Chaining Agent는 이 값을 다시 계산하거나 재해석하지 않고 admission된 그대로 읽는다.

### 7개 check 판정 절차

구조적으로 동일 여부는 결정론적으로 먼저 비교하고, `evidence_refs` 근거가 필요한 나머지 판정만 Chaining Agent(LLM)가 수행한다. 명백히 양립 불가하면 후보 자체를 만들지 않는다(기존 규칙). `entity_check`/`endpoint_check`는 `CodeRelation`(`CALLERS`/`CALLEES`/`DATA_FLOW_NEIGHBORS`)·`ROUTE_BINDING` 등 R2가 만드는 구조화된 사실로 뒷받침할 수 있다. 반면 `asset_check`/`data_check`는 R2 스키마에 "asset"·"data type" 개념이 없어 R2의 구조화된 사실로 뒷받침할 수 없다. 그래도 판정에 쓰는 `evidence_refs`는 여전히 Chaining Agent가 실제로 읽은 코드 조각·설정을 가리키는 저장 참조여야 하며, R2가 만드는 구조화된 사실이 아닐 뿐이다.

모든 check의 `evidence_refs`는 Chaining Agent가 실제로 읽은 코드 조각·설정·관계를 가리키는 저장 참조여야 한다. LLM이 그 근거가 무엇을 뜻하는지 설명한 서술 자체는 근거가 아니며 `evidence_refs`를 대신하지 않는다. 가리킬 실제 저장 근거가 없으면 판정은 `PASS`가 아니라 `UNCERTAIN`이다.

`endpoint`/`data_type`의 `null`은 그 개념이 대상에 애초에 적용되지 않는다는 뜻으로만 쓴다. 이 보장은 생산 단계, 즉 `PrimitiveDraft`를 채우는 Verification 쪽 책임이다(`08-lightweight-data-contracts.md`). Verification이 아직 확인하지 못했거나 도구가 값을 제공하지 못한 경우는 `null`로 남기지 않고 알아낸 값 또는 그 불확실성을 `description`에 남긴다. `endpoint_check`/`data_check`가 `null`을 근거 없이 `PASS`로 처리하는 것은 이 생산 단계 보장을 전제로 한다.

| check | `PASS` 조건 | `UNCERTAIN` 조건 | 서열표 기준 명백한 실패 |
|---|---|---|---|
| `asset_check` | `target.asset` 문자열이 같거나, 다르면 이동을 뒷받침하는 실제 근거(`evidence_refs`)가 있음 | 다른데 근거 없음 | 해당 없음 |
| `entity_check` | `entity_refs`가 겹치거나 관련성을 뒷받침하는 근거가 있음 | 무관한데 근거 없음 | 해당 없음 |
| `endpoint_check` | `endpoint`가 같거나, 한쪽이 `null`(개념 자체가 적용되지 않음, 생산 단계에서 보장)이거나, 연결을 뒷받침하는 실제 근거가 있음 | 다른데 근거 없음 | 해당 없음 |
| `privilege_check` | upstream이 제공하는 privilege 등급이 downstream이 요구하는 등급 이상(아래 서열표 기준) | 서열표에 없는 값이고 근거 없음 | 둘 다 서열표에 있고 upstream 등급이 낮음 → 후보 자체를 만들지 않음 |
| `data_check` | `data_type`이 같거나, 한쪽이 `null`(개념 자체가 적용되지 않음, 생산 단계에서 보장)이거나, 변환을 뒷받침하는 실제 근거가 있음 | 다른데 근거 없음 | 해당 없음 |
| `attack_order_check` | downstream의 요구 조건이 upstream이 제공하는 능력을 논리적으로 전제한다는 근거가 있음 | 순서 근거가 불명확함 | 순서가 반대라는 근거가 명확함 → 후보 자체를 만들지 않음 |
| `restriction_check` | 결합 뒤에도 남는 restriction이 새 `HypothesisProposal`의 `restrictions`/`assumptions`로 정확히 승계됨 | 승계 여부가 불명확하거나 결합 논리와 충돌 가능성이 있음 | 해당 없음 |

### primitive_type vocabulary

Chaining Agent가 1차 분류에 쓰는 `primitive_type` vocabulary다. `primitive_type`은 이 목록 중 하나이거나 목록에 없는 자유 문자열(`OTHER`로 강제 치환하지 않고 원래 값 유지)이다. 매칭의 유일한 기준이 아니라 후보를 걸러내는 1차 분류로만 쓴다.

`ARBITRARY_FILE_READ | ARBITRARY_FILE_WRITE | CODE_EXECUTION | COMMAND_EXECUTION | SSRF_CAPABILITY | AUTH_BYPASS | PRIVILEGE_ESCALATION | CREDENTIAL_ACCESS | SENSITIVE_DATA_DISCLOSURE | DESERIALIZATION_TRIGGER | INJECTION_CAPABILITY | OPEN_REDIRECT | OTHER`

하나의 능력이 여러 카테고리에 해당할 수 있으면, 가장 직접적으로 입증된 하나를 고르고 나머지는 강제하지 않는다(복수 `PrimitiveDraft` 작성 여부는 Verification의 재량이며 이 문서가 강제하지 않음).

### privilege 서열표

`privilege_level`은 다음 서열을 기준으로 비교한다.

```text
UNAUTHENTICATED < AUTHENTICATED < ELEVATED < ADMIN < SYSTEM
```

앱 고유 role 이름(예: "repo-admin")도 `privilege_level`에 그대로 쓸 수 있지만, 이 서열표에 없으면 `privilege_check`는 명시적 근거(`evidence_refs`) 없이 `PASS`로 판정하지 않는다. 앱 고유 role을 서열표 항목과 비교 가능하다고 인정하려면, 그 role이 서열표의 특정 등급과 동등하거나 그 이상이라는 근거(예: 코드·설정에서 그 role에 부여된 실제 권한 범위가 특정 서열표 등급의 권한을 포함한다는 확인)가 `evidence_refs`에 있어야 한다. 이름의 유사성만으로 비교하지 않는다.

`REQUIRED` Primitive의 `privilege_level`은 그 취약점을 악용하기 전에 공격자가 이미 갖추고 있어야 하는 최소 권한이고, `PROVIDED` Primitive의 `privilege_level`은 그 취약점 성립 뒤 공격자가 실제로 얻게 되는 권한이다. `privilege_check`는 upstream(PROVIDED)의 이 값이 downstream(REQUIRED)의 이 값 이상인지를 비교하며, 두 값이 같은 asset·tenant·권한 체계에서 비교 가능한 값이라는 근거 없이는 이름이 더 높아 보인다는 이유만으로 비교하지 않는다.

vocabulary(위 `primitive_type` 목록·이 서열표)가 이후 개정되어도 이미 admission된 Primitive의 기록된 값은 그대로 보존하고 재해석하지 않는다. 새 vocabulary는 그 시점 이후 새로 admission되는 Primitive에만 적용한다.

`04-verification-and-dynamic-reproduction.md`에서 Verification이 `PrimitiveDraft.primitive_type`/`privilege_level`을 채울 때는 이 절의 vocabulary와 위 비교 기준을 따른다.

### vocabulary 확장 규칙

`primitive_type`과 privilege 서열 모두, 목록에 없는 새 값을 강제로 매핑하거나 거부하지 않고 원본 값 그대로 둔다(미분류로 취급). `primitive_type`은 매칭의 판정 기준이 아니라 1차 분류일 뿐이라 목록에 없어도 나머지 check는 정상 진행된다. 목록에 없는 `privilege_level`은 `privilege_check`가 명시적 근거 없이 PASS로 보지 않아 UNCERTAIN이 되지만, 그래도 후보 자체는 만들어지고 `unresolved_conditions`에 남는다. 이 vocabulary를 최신 상태로 유지하는 별도 절차는 두지 않는다.

### restriction_check 승계 규칙

`restriction_check`는 두 parent의 exact `VerificationResult.restrictions`와 `unresolved_conditions`(문자열 목록)를 수집 대상으로 한다. 각 항목마다 다음 중 하나로 처리하고, 그 판단을 `PrimitiveMatchCandidate.evidence_refs`에 근거와 함께 남긴다.

- **승계**: 결합 뒤에도 적용되는 restriction은 새 `HypothesisProposal.restrictions`로, 적용되는 assumption은 `assumptions`로, 아직 확인 못 한 조건은 `missing_information` 또는 `required_validation`으로 그대로 옮긴다.
- **제외**: 결합으로 그 조건이 해소됐다고 판단하면(예: 한 parent의 restriction이 다른 parent가 이미 충족한 조건이라 더 이상 제약이 아님) child proposal에 옮기지 않되, 제외 근거(exact evidence)와 이유를 `PrimitiveMatchCandidate.evidence_refs`에 남긴다.

승계 대상인지 제외 대상인지 판단할 근거가 없는 항목은 `UNCERTAIN`으로 남기고 `missing_information` 또는 `required_validation`에 옮긴다. `restriction_check=PASS`는 두 parent의 모든 restriction·unresolved_condition이 위 세 목록(`restrictions`/`assumptions`/`missing_information`+`required_validation`) 중 하나로 승계됐거나, 명시적 근거와 함께 제외됐을 때만 허용한다. 하나라도 승계·제외 판단 없이 누락되면 `restriction_check=UNCERTAIN`이다. `SAVE_RESULT(result_kind=chaining_result)`는 저장 전 두 parent의 restrictions·unresolved_conditions 목록이 child proposal의 네 목록 합집합이나 제외 근거 목록에 모두 포함되는지 검사하고, 누락이 있으면 저장을 거절한다.

### 출력

```yaml
ChainingResult:
  meta: RecordMeta
  trigger: HOLD_MATCH | TRUE_HOLD_MATCH | TRUE_TRUE_MATCH
  source_result_refs: [StoredDataRef]
  input_primitive_refs: [StoredDataRef]
  input_primitive_index_refs: [StoredDataRef]
  primitive_match_candidates: [PrimitiveMatchCandidate]
  chained_hypothesis_proposals: [HypothesisProposal]
  no_match_reasons: [string]
  bounded_stop_reason: DUPLICATE_FINGERPRINT | CYCLE_DETECTED | MAX_COMBINATIONS_PER_CALL | null
  errors: [AnalysisError]
```

새 가설은 `HypothesisProposal(origin=CHAINING)`으로 만든다. trusted runtime이 schema·semantic·workspace·commit·exact Primitive eligibility·중복·깊이·예산을 검사한 뒤 새 `hypothesis_id`로 등록한다. Orchestration Agent는 등록된 가설에 새 Verification Agent를 배정한다. child는 전체 Verification 파이프라인을 처음부터 거친다.

각 child proposal의 `source_primitive_match_id`는 자신을 만든 `PrimitiveMatchCandidate`를 가리키지만 `primitive_match_id`는 같은 `ChainingResult` 안에서만 유일하다. 그래서 `ChainingResult` 저장 뒤 등록되는 `VulnerabilityHypothesis`는 이 값에 더해 그 exact `ChainingResult`를 가리키는 `source_chaining_result_ref`도 함께 보존하며, 두 값이 있어야 컨테이너 밖에서도 exact `PrimitiveMatchCandidate`를 가리킬 수 있다(`08-lightweight-data-contracts.md`의 등록 검사 참고). `parent_hypothesis_ids`/`root_hypothesis_id`/`chain_depth`가 가설 사이의 계보를 보여준다면, `source_chaining_result_ref`와 `source_primitive_match_id`는 그 계보의 각 단계가 어느 Primitive 쌍과 7개 check 근거로 연결됐는지 보여준다.

`TRUE_HOLD`/`TRUE_TRUE`는 부모가 둘이고 두 부모의 `root_hypothesis_id`가 서로 다를 수 있다(`TRUE_TRUE`는 두 부모 모두 독립적으로 Gate-qualified TRUE까지 간 별개 계보라 항상 다를 수 있다). child의 `root_hypothesis_id`는 `chain_depth`가 더 큰 부모, 같으면 `upstream_provided_ref` 쪽 부모의 값을 물려받는다 — 이건 단순 tie-break이며 물려받지 못한 부모 계보가 사라진다는 뜻이 아니다.

따라서 한 가설에서 `source_chaining_result_ref`로 exact `ChainingResult`를 찾고 그 안에서 `source_primitive_match_id`로 candidate를 찾은 뒤, 그 candidate의 `parent_hypothesis_ids` → 그 부모의 `source_chaining_result_ref`/`source_primitive_match_id`를 반복해서 거슬러 올라가는 것이 다단계 공격 순서를 재구성하는 방법이다. `root_hypothesis_id` 하나만 따라가면 매 merge 지점에서 물려받은 쪽 부모의 계보만 보이므로, 두 부모 계보를 모두 보려면 각 merge 지점마다 남은 부모에서 같은 walk를 별도로 반복해야 한다. `origin=VERIFICATION` 중간 세대는 `source_primitive_match_id=null`, `source_chaining_result_ref=null`이라 그 세대는 Primitive match 근거 없이 `parent_hypothesis_ids`만으로 잇는다. 이 문서는 진행 상태나 순서 번호를 담는 별도 필드를 두지 않고, 이미 있는 계보 필드와 이 참조를 반복 조회하는 walk를 다단계 공격 순서의 기록 형식으로 정한다.

### 호출 시점과 trigger 의미

`03-agent-roles-and-orchestration.md`는 Verification owner가 Primitive 후보 admission 여부를 결정하고, admission된 뒤 다른 hypothesis의 Primitive와 실제로 비교해 Chaining work를 등록하는 시점은 Primitive DB를 유지하는 trusted runtime이 admission 이벤트마다 자동으로 처리한다고 정한다. `08-lightweight-data-contracts.md`의 `REGISTER_WORK` 허용 `requested_by` 표에 이 trusted runtime 전용 identity인 `ADMISSION_RUNTIME`을 포함해 이 자동 등록만 허용하며, Chaining Agent는 `agent_role`에 없는 이 identity로 인증될 수 없어 스스로 `REGISTER_WORK`를 요청하지 못한다.

Primitive가 새로 `ACTIVE`로 admission될 때마다(REQUIRED는 final HOLD commit, PROVIDED는 두 Gate 통과 admission) 즉시 Chaining work 등록을 시도한다(batch로 모아 두지 않는다). 이 절은 호출 *시점*(이벤트 기반 vs batch)만 정하며, 실제 호출 총량·조합 수 상한과 상한 도달 시 처리 방식은 "확장 제한과 순환 방지" 절의 한도를 따른다. 이벤트 기반 즉시 등록도 이 한도 검사를 우회하지 않는다 — 매 시도마다 그 절의 검사를 거치며, 한도 도달은 부모 가설의 `FALSE`나 매칭 실패로 기록하지 않는다.

admission 이벤트는 Primitive DB를 유지하는 같은 trusted runtime이 받는다. Chaining Agent나 Orchestration이 받는 게 아니다 — Primitive DB는 "출력과 의미" 절에서 이미 명시했듯 queue가 아니라 분석 인덱스이며, 이 인덱스를 갱신하는 runtime이 admission과 후속 work 등록을 함께 처리한다. 이 runtime은 admission된 Primitive와 비교 대상 후보 Primitive(`HOLD_MATCH`/`TRUE_HOLD_MATCH`는 반대편, `TRUE_TRUE_MATCH`는 같은 PROVIDED 쪽) 각각의 exact `record_id` 조합으로 `work_type=CHAINING` work의 `dedupe_key`를 만든다. 같은 admission 이벤트가 재전달되거나 같은 조합이 중복 시도되면 기존 `08-lightweight-data-contracts.md`의 dedupe 규칙(같은 `dedupe_key`는 기존 `work_id`를 반환)에 따라 새 work를 만들지 않는다. 각 work는 그 admission 시점의 `PrimitiveIndexState` snapshot을 input으로 고정하며(위 "exact revision과 오래된 승인 차단" 절), 저장 직전 index head가 바뀌었으면 `STALE_RESULT`로 거절한다. 등록 자체가 "확장 제한과 순환 방지" 절의 run 전체 한도에 걸리면 work를 만들지 않고 `AnalysisError(stage=ORCHESTRATION, code=BUDGET_EXCEEDED)`로 기록한다. `bounded_stop_reason`은 work가 만들어지고 호출이 실제로 일어난 뒤에만 쓰는 값이다(아래 "확장 제한과 순환 방지" 절 참고).

`trigger`는 방금 admission된 쪽을 가리킨다.

- `HOLD_MATCH`: 새 `REQUIRED`(HOLD)가 admission되어 기존 `ACTIVE` `PROVIDED`와 비교
- `TRUE_HOLD_MATCH`: 새 `PROVIDED`(TRUE)가 admission되어 기존 `ACTIVE` `REQUIRED`와 비교
- `TRUE_TRUE_MATCH`: 새 `PROVIDED`(TRUE)가 admission되어 기존 `ACTIVE` `PROVIDED` 전체와 비교. HOLD_MATCH/TRUE_HOLD_MATCH가 REQUIRED-PROVIDED 반대편끼리 비교하는 것과 달리 같은 PROVIDED끼리 비교한다

새 `PROVIDED`가 admission되면 한 admission 이벤트에서 `TRUE_HOLD_MATCH`(기존 ACTIVE REQUIRED 대상)와 `TRUE_TRUE_MATCH`(기존 ACTIVE PROVIDED 대상)를 모두 시도한다. `TRUE_TRUE_MATCH`의 비교는 방향이 있어 두 경우를 모두 확인한다.

- 새 PROVIDED가 upstream: 기존 ACTIVE PROVIDED 각각의 `required_preconditions` 중 새 PROVIDED가 충족하는 항목이 있는지
- 새 PROVIDED가 downstream: 새 PROVIDED 자신의 `required_preconditions` 중 기존 ACTIVE PROVIDED가 충족하는 항목이 있는지

두 경우 모두 앞 PROVIDED가 뒤 PROVIDED의 exact `required_preconditions` 한 항목을 충족해야 후보가 되며(기존 규칙), 같은 Primitive 쌍을 upstream/downstream 양쪽에서 중복 평가해 같은 `normalized_fingerprint`의 candidate를 두 번 만들지 않는다. REQUIRED admission은 `TRUE_TRUE_MATCH`를 만들지 않는다 — REQUIRED는 TRUE_TRUE 어느 쪽에도 참여하지 않는다.

### 금지 권한

Chaining Agent는 다음을 할 수 없다.

- 기존 verdict, CWE, Gate 결과, severity 또는 Finding 변경
- 일반 취약점·bypass·alternate endpoint·새 sink·impact escalation 독립 탐색
- 추가 CodeContext·정적 검증·동적 재현 요청
- Technical `REVISE` 해결 또는 Gate 호출
- ReportDraft 생성 또는 외부 공개
- Primitive match가 없는 관련 없는 material claim 제안
- `REGISTER_WORK` 요청. 이 요청은 Primitive DB를 유지하는 trusted runtime만 `requested_by=ADMISSION_RUNTIME`으로 할 수 있다

이 금지 출력은 schema 또는 result-owner authority validation에서 `INVALID_OUTPUT` 또는 `AUTHORITY_DENIED`로 거절한다.

## Verification에서 발견한 새 주장

Verification이 새 endpoint, sink, authorization boundary, 별도 auth bypass, privilege escalation 단계, 다른 asset 또는 독립 impact path를 발견하면 Chaining Agent로 보내지 않는다.

```text
Verification
-> HypothesisProposal(origin=VERIFICATION)
-> trusted validation and global registration
-> Orchestration assigns Verification
-> full Verification pipeline
```

Verification은 proposal을 만들 수 있지만 `hypothesis_id`를 직접 발급하거나 child를 자동 TRUE로 만들 수 없다. duplicate·depth·token·time 제한을 우회할 수도 없다. 부모와 child의 lifecycle과 verdict는 독립이며 child가 FALSE여도 부모 판정은 바뀌지 않는다.

## 확장 제한과 순환 방지

제한은 두 층이다. Chaining Agent 호출 하나 안의 자원 상한(token·time·호출당 비교 조합 수)은 `07-results-and-observability.md`의 역할별 자원 한도(R8-03, Chaining 행)가 정하며 이 절은 그 숫자를 다시 정의하지 않는다. 이 절은 admission 이벤트가 Chaining work를 등록하기 *전*에 거치는 분석 run 전체 단위의 한도를 정한다.

### run 전체 한도 (제안, 교차 전)

| 한도 | 제안값 | 검사 시점 |
|---|---|---|
| maximum chain depth | 4 | `REGISTER_WORK` |
| 전체 파생 가설 수 (분석 run당 `origin=CHAINING`) | 200 | `REGISTER_WORK` |
| parent당 파생 가설 수 | 10 | `REGISTER_WORK` |
| Chaining Agent 호출 수 (분석 run 전체, `work_type=CHAINING` `WorkAttempt` 전체, 재시도 포함) | 500 | `REGISTER_WORK` |
| primitive 조합 수 (분석 run 전체, 실제 candidate로 저장된 것만) | 1,000 | `REGISTER_WORK` |
| 누적 Chaining LLM token (분석 run 전체, 이전 Chaining 호출들의 실제 usage 합) | 2,000,000 (R8 draft 초안, 미확정) | `REGISTER_WORK` |
| 누적 Chaining elapsed time (분석 run 전체, 이전 Chaining 호출들의 실제 `elapsed_ms` 합) | 10,800,000ms(약 3시간, R8 draft 초안, 미확정) | `REGISTER_WORK` |

숫자는 corpus 실측 전 제안이며 R8과 조율해 확정한다(아래 "R8과의 관계" 참고). 이 일곱 한도는 Chaining Agent를 부르기 전 `REGISTER_WORK` 시점에 걸리므로 work도 `ChainingResult`도 만들어지지 않는다 — `08-lightweight-data-contracts.md`가 이미 정한 `ActionCheck.BUDGET` 실패 처리를 그대로 따라 `AnalysisError(stage=ORCHESTRATION, code=BUDGET_EXCEEDED)`로 기록한다. 걸린 구체적 한도는 사람이 읽는 `safe_message`뿐 아니라 이미 있는 `ActionCheck.reason_code`에도 한도별 값(`CHAINING_DEPTH_LIMIT | CHAINING_TOTAL_HYPOTHESIS_LIMIT | CHAINING_PER_PARENT_HYPOTHESIS_LIMIT | CHAINING_CALL_COUNT_LIMIT | CHAINING_COMBINATION_COUNT_LIMIT | CHAINING_TOKEN_BUDGET | CHAINING_TIME_BUDGET`)으로 남겨, R8 텔레메트리가 일곱 한도 중 어떤 것이 걸렸는지 `safe_message` 문장을 파싱하지 않고 이 필드만으로 구분할 수 있게 한다. 한도 도달은 `FALSE`도 `INVALID_OUTPUT`도 아닌 별도 범주다.

이 일곱 한도 검사와 `REGISTER_WORK` 커밋은 같은 `analysis_id` 안에서 직렬화한다 — 여러 admission 이벤트가 동시에 도착해도 한 번에 하나씩만 이 검사·등록을 통과시킨다. 값들이 여러 record를 실시간 집계해 얻는 파생값이라 단일 `state_version` 같은 CAS 대상이 없으므로, 이 문서의 다른 CAS 검사(index head, `ActionDecision` claim 등)와 달리 직렬화로 경쟁을 막는다. 직렬화하지 않으면 한도 근처에서 동시에 여러 admission이 통과해 실제 상한을 넘길 수 있다.

누적 token·elapsed time 두 항목은 R8-03의 호출당 상한(현재 제안 16,000 token/60초, #60 미병합)과 다른 층이다. 호출당 상한은 한 번의 호출을 얼마나 크게 허용할지를 정하고, 이 두 항목은 그 호출을 몇 번이나 계속 허용할지를 이전 호출들의 실제 사용량 누계로 정한다. 호출 수 상한(500)만으로는 누적 token·elapsed time을 대신하지 못한다 — 호출마다 실제 사용량이 상한보다 훨씬 작을 수도, 재시도로 상한에 가깝게 반복될 수도 있어 호출 횟수와 실제 누적 사용량은 별도로 추적해야 한다. 시각 차이가 아니라 `08-lightweight-data-contracts.md`가 이미 정한 monotonic `elapsed_ms`의 합이므로 "wall-clock time"이라 부르지 않는다.

이 두 누적값은 새 카운터 필드가 아니라 같은 `analysis_id`와 `agent_role=CHAINING`의 기존 `LLMInvocationLog`(`08-lightweight-data-contracts.md` "10. LLM invocation records") 전체(재시도 포함, 실제로 provider를 호출한 모든 기록)의 `usage`와 `elapsed_ms`를 합산한 값이다. `REGISTER_WORK`는 이 합을 실시간으로 계산해 검사하며, 합산 결과를 저장하는 별도 record는 두지 않는다. `usage=null`인 호출은 token 합계에서 제외한다 — 이 경우 token 누적 한도는 그 몫만큼 실제보다 낮게 계산되며, 이는 R8-02 지표("usage: token 숫자를 서비스가 안 줌")가 이미 다루는 한계다.

### bounded_stop_reason

`ChainingResult.bounded_stop_reason`은 호출이 실제로 일어난 뒤에만 알 수 있는 세 값만 쓴다: `DUPLICATE_FINGERPRINT | CYCLE_DETECTED | MAX_COMBINATIONS_PER_CALL`. `MAX_COMBINATIONS_PER_CALL`은 R8-03의 호출당 비교 상한(현재 제안 20)에 도달했을 때 쓰며 위 run 전체 한도와는 다른 값이다. 셋 다 candidate를 `SAVE_RESULT`로 저장하는 시점에 검사한다. 한도 도달은 `FALSE`가 아니다. 만들지 못한 후보와 적용한 제한을 저장한다.

### normalized_fingerprint 정규화 규칙

`PrimitiveMatchCandidate.normalized_fingerprint`는 `workspace_id`, `commit_id`, `trigger`, `upstream_provided_ref.record_id`, `downstream_input_ref.record_id`, `matched_requirement_id`를 이 여섯 필드를 key로 하는 JSON 객체(key 정렬, 값 순서는 그대로)로 만든 뒤 SHA-256 한 값이다. `trigger`는 `PrimitiveMatchCandidate` 자신의 필드가 아니라 그 candidate를 담는 `ChainingResult.trigger`이며, 이 hash를 계산할 때는 candidate가 속한 컨테이너의 이 값을 그대로 가져와 쓴다 — work `dedupe_key`가 여러 개의 동종 입력 목록을 정렬해 순서 무관하게 만드는 것과 달리, 여기서는 여섯 필드 각각의 값 자체는 순서를 바꾸지 않는다. 같은 분석에서 같은 값을 다시 저장하지 않는다. 양방향 `TRUE_TRUE_MATCH`에서 같은 Primitive 쌍을 upstream/downstream을 바꿔 같은 `matched_requirement_id`를 다시 평가하면 `trigger`가 같아도 참조 순서가 달라 fingerprint가 달라지므로, 저장 전 두 record_id를 오름차순으로 정렬한 값과 `matched_requirement_id`가 모두 같은 기존 candidate가 있는지 함께 비교해 있으면 새로 만들지 않는다. `matched_requirement_id`가 다르면 두 record_id가 같은 쌍이라도 서로 다른 전제조건을 충족하는 별개의 match이므로 이 규칙으로 걸러내지 않는다 — 같은 Primitive 쌍 사이에서도 upstream이 downstream의 조건 하나를 충족하는 match와 downstream이 upstream의 다른 조건을 충족하는 match는 각각 저장한다.

### cycle 판정 규칙

candidate를 만들기 전 `upstream_provided_ref`, `downstream_input_ref` 두 Primitive 각각의 `source_hypothesis_id`에서 시작해 그 가설의 `source_chaining_result_ref`/`source_primitive_match_id` → 그 candidate의 `parent_hypothesis_ids` → 각 부모 가설의 `source_chaining_result_ref`/`source_primitive_match_id`로 이어지는 walk(R1-03의 다단계 lineage 재구성 규칙)로 ancestor `hypothesis_id` 집합을 구한다. Primitive는 재검증될 때마다(`SUPERSEDED` 뒤 새 revision admission) 새 `record_id`를 받으므로, ancestor 식별은 Primitive `record_id`가 아니라 같은 revision 사이에서도 바뀌지 않는 `hypothesis_id` 기준으로 한다. 두 Primitive 모두에서 이 walk를 각각 실행해 두 ancestor `hypothesis_id` 집합을 만들고, 양쪽 방향을 모두 확인한다: upstream Primitive의 `source_hypothesis_id`가 downstream 쪽 ancestor 집합에 있는지, downstream Primitive의 `source_hypothesis_id`가 upstream 쪽 ancestor 집합에 있는지. 둘 중 하나라도 있으면(자기 자신을 가리키는 경우 포함) cycle로 판정하고 candidate를 만들지 않는다. 같은 가설의 Primitive가 재검증으로 새 `record_id`를 받아도 `hypothesis_id`는 그대로이므로 이 판정은 revision이 바뀐 뒤에도 그대로 적용된다. 새 사실이나 capability 없이 `A -> B -> A`로 돌아오는 조합과 이미 같은 조건으로 반증된 조합은 다시 생성하지 않는다.

### R8과의 관계

`OWNERSHIP.md`에 따라 예산 profile 숫자는 R8이 설계하고 각 전문 역할은 최소 요구를 제공한다. 이 절의 depth·전체/parent당 파생 가설 수·호출 수·조합 수(위 표의 다섯 행)와 dedup·cycle 규칙은 체이닝 확장 자체의 구조적 한도라 R1이 chaining 의미론의 일부로 제안하지만, 이 다섯 행과 두 예산 행 사이의 경계 자체도 R8 확인 전 R1의 제안이다 — 특히 호출 수·조합 수는 자원 소비량이라는 점에서 R8이 관할하는 예산 범주로 볼 수도 있어, 이 층 분리가 맞는지 자체를 아래 검토 요청에서 R8에게 확인받는다. 반면 누적 token·elapsed time(위 표의 두 행)은 R8-03의 호출당 상한과 같은 종류의 예산 수치이므로 R1은 여기서 초안만 제시하고, 최종 확정과 `07-results-and-observability.md`(R8-03, #60)의 역할별 자원 한도 표 반영은 R8이 한다. R8이 이 두 값을 다른 숫자로 확정하면 이 절의 표는 그 값을 따라 갱신한다.

제안값을 그대로 대입하면 누적 token 2,000,000 ÷ 호출당 상한 16,000 = 약 125회, 누적 time 10,800,000ms ÷ 호출당 60초 = 180회로, 호출 수 상한 500회보다 훨씬 작다. 호출마다 실제 사용량이 매번 최대치에 가까우면 누적 예산이 500회 훨씬 전에 소진돼 호출 수 상한이 사실상 무의미해질 수 있다. 이 간극이 의도한 것인지(호출당 평균 사용량이 최대치보다 충분히 낮을 것으로 보는지), 아니면 누적 예산을 올리거나 호출 수 상한을 낮춰야 하는지도 R8 확인이 필요하다.

## 사람에게 보이는 결과

사람은 HOLD requirement, Gate-qualified capability, exact Gate provenance, match 이유, 생성된 child hypothesis와 검증 여부를 구분해서 본다. match 후보와 미검증 child는 Finding, PoC 또는 실제 impact 주장에 섞이지 않는다.
