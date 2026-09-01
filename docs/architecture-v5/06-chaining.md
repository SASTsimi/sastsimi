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

### 7개 check 판정 절차

구조적으로 동일 여부는 결정론적으로 먼저 비교하고, `evidence_refs` 근거가 필요한 나머지 판정만 Chaining Agent(LLM)가 수행한다. 명백히 양립 불가하면 후보 자체를 만들지 않는다(기존 규칙). `entity_check`/`endpoint_check`는 `CodeRelation`(`CALLERS`/`CALLEES`/`DATA_FLOW_NEIGHBORS`)·`ROUTE_BINDING` 등 R2가 만드는 구조화된 사실로 뒷받침할 수 있다. 반면 `asset_check`/`data_check`는 R2 스키마에 "asset"·"data type" 개념이 없어 구조화된 사실로 뒷받침할 수 없고, `evidence_refs`가 코드 조각을 읽은 LLM의 서술적 판단(narrative)일 수밖에 없다 — 이 두 check는 R2 확인 전까지 잠정(provisional) 절차다.

| check | `PASS` 조건 | `UNCERTAIN` 조건 | 서열표 기준 명백한 실패 |
|---|---|---|---|
| `asset_check`(잠정) | `target.asset` 문자열이 같거나, 다르면 이동을 뒷받침하는 `evidence_refs`(서술적 근거 허용)가 있음 | 다른데 근거 없음 | 해당 없음 |
| `entity_check` | `entity_refs`가 겹치거나 관련성을 뒷받침하는 근거가 있음 | 무관한데 근거 없음 | 해당 없음 |
| `endpoint_check` | `endpoint`가 같거나, 한쪽이 `null`(해당 없음)이거나, 연결 근거가 있음 | 다른데 근거 없음 | 해당 없음 |
| `privilege_check` | upstream이 제공하는 privilege 등급이 downstream이 요구하는 등급 이상(아래 서열표 기준) | 서열표에 없는 값이고 근거 없음 | 둘 다 서열표에 있고 upstream 등급이 낮음 → 후보 자체를 만들지 않음 |
| `data_check`(잠정) | `data_type`이 같거나, 한쪽이 `null`이거나, 변환 근거(서술적 근거 허용)가 있음 | 다른데 근거 없음 | 해당 없음 |
| `attack_order_check` | downstream의 요구 조건이 upstream이 제공하는 능력을 논리적으로 전제한다는 근거가 있음 | 순서 근거가 불명확함 | 순서가 반대라는 근거가 명확함 → 후보 자체를 만들지 않음 |
| `restriction_check` | 결합 뒤에도 남는 restriction이 새 `HypothesisProposal`의 `restrictions`/`assumptions`로 정확히 승계됨 | 승계 여부가 불명확하거나 결합 논리와 충돌 가능성이 있음 | 해당 없음 |

### primitive_type vocabulary(작업용 제안값)

`08-lightweight-data-contracts.md`는 Primitive vocabulary를 "구현 전 ADR과 평가 corpus로 확정"하도록 이미 정해뒀다. 아래 목록은 그 ADR이 나오기 전까지 Chaining Agent가 1차 분류에 쓰는 **작업용 제안값**이며, 이 문서가 최종 확정하지 않는다. `primitive_type`은 이 목록 중 하나이거나 목록에 없는 자유 문자열(`OTHER`로 강제 치환하지 않고 원래 값 유지)이다. 매칭의 유일한 기준이 아니라 후보를 걸러내는 1차 분류로만 쓴다.

`ARBITRARY_FILE_READ | ARBITRARY_FILE_WRITE | CODE_EXECUTION | COMMAND_EXECUTION | SSRF_CAPABILITY | AUTH_BYPASS | PRIVILEGE_ESCALATION | CREDENTIAL_ACCESS | SENSITIVE_DATA_DISCLOSURE | DESERIALIZATION_TRIGGER | INJECTION_CAPABILITY | OPEN_REDIRECT | OTHER`

하나의 능력이 여러 카테고리에 해당할 수 있으면, 가장 직접적으로 입증된 하나를 고르고 나머지는 강제하지 않는다(복수 `PrimitiveDraft` 작성 여부는 Verification의 재량이며 이 문서가 강제하지 않음).

### privilege 서열표(작업용 제안값)

같은 이유로 아래 서열표도 ADR 전까지의 작업용 제안값이다. `privilege_level`은 다음 서열을 기준으로 비교한다.

```text
UNAUTHENTICATED < AUTHENTICATED < ELEVATED < ADMIN < SYSTEM
```

앱 고유 role 이름(예: "repo-admin")도 `privilege_level`에 그대로 쓸 수 있지만, 이 서열표에 없으면 `privilege_check`는 명시적 근거(`evidence_refs`) 없이 `PASS`로 판정하지 않는다.

### vocabulary 확장 규칙

`primitive_type`과 privilege 서열 모두, 목록에 없는 새 값을 강제로 매핑하거나 거부하지 않고 원본 값 그대로 둔다(미분류로 취급). `primitive_type`은 매칭의 판정 기준이 아니라 1차 분류일 뿐이라 목록에 없어도 나머지 check는 정상 진행된다. 목록에 없는 `privilege_level`은 `privilege_check`가 명시적 근거 없이 PASS로 보지 않아 UNCERTAIN이 되지만, 그래도 후보 자체는 만들어지고 `unresolved_conditions`에 남는다. 이 vocabulary를 최신 상태로 유지하는 별도 절차는 두지 않는다.

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
  bounded_stop_reason: string | null
  errors: [AnalysisError]
```

새 가설은 `HypothesisProposal(origin=CHAINING)`으로 만든다. trusted runtime이 schema·semantic·workspace·commit·exact Primitive eligibility·중복·깊이·예산을 검사한 뒤 새 `hypothesis_id`로 등록한다. Orchestration Agent는 등록된 가설에 새 Verification Agent를 배정한다. child는 전체 Verification 파이프라인을 처음부터 거친다.

### 호출 시점과 trigger 의미

`03-agent-roles-and-orchestration.md`의 "Chaining handoff를 선택하는 주체는 Verification owner"는, Verification이 자기 결과에 `required_primitive_candidates`/`provided_primitive_candidates`를 채워 Primitive 후보로 만들지를 결정한다는 뜻이다. admission된 뒤 다른 hypothesis의 Primitive와 실제로 비교하는 시점은 Primitive DB가 admission 이벤트마다 자동으로 처리하는 후속 절차이며 Verification Agent가 매번 다시 관여하지 않는다.

Primitive가 새로 `ACTIVE`로 admission될 때마다(REQUIRED는 final HOLD commit, PROVIDED는 두 Gate 통과 admission) 즉시 반대편 `ACTIVE` Primitive 전체를 대상으로 Chaining work 등록을 시도한다(batch로 모아 두지 않는다). 이 절은 호출 *시점*(이벤트 기반 vs batch)만 정하며, 실제 호출 총량·조합 수 상한과 상한 도달 시 처리 방식은 "확장 제한과 순환 방지" 절의 한도를 따른다.

`trigger`는 방금 admission된 쪽을 가리킨다.

- `HOLD_MATCH`: 새 `REQUIRED`(HOLD)가 admission되어 기존 `ACTIVE` `PROVIDED`와 비교
- `TRUE_HOLD_MATCH`: 새 `PROVIDED`(TRUE)가 admission되어 기존 `ACTIVE` `REQUIRED`와 비교

`TRUE_TRUE_MATCH`의 트리거(호출 이벤트·비교 대상)는 이 문서가 정의하지 않는다. `PrimitiveMatchCandidate`의 `match_kind=TRUE_TRUE` 판정 절차(위 7개 check)만 공유한다.

### 금지 권한

Chaining Agent는 다음을 할 수 없다.

- 기존 verdict, CWE, Gate 결과, severity 또는 Finding 변경
- 일반 취약점·bypass·alternate endpoint·새 sink·impact escalation 독립 탐색
- 추가 CodeContext·정적 검증·동적 재현 요청
- Technical `REVISE` 해결 또는 Gate 호출
- ReportDraft 생성 또는 외부 공개
- Primitive match가 없는 관련 없는 material claim 제안

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

모든 run은 다음 제한을 설정한다.

- maximum chain depth
- 전체 및 parent당 파생 가설 수
- Chaining Agent 호출 수와 primitive 조합 수
- 누적 LLM token과 wall-clock time
- normalized hypothesis/primitive-match fingerprint 중복 횟수
- 동일 ancestor/capability cycle

한도 도달은 `FALSE`가 아니다. 만들지 못한 후보, 적용한 제한과 `bounded_stop_reason`을 저장한다. 새 사실이나 capability 없이 `A -> B -> A`로 순환하는 후보와 이미 같은 조건으로 반증된 후보는 다시 생성하지 않는다.

## 사람에게 보이는 결과

사람은 HOLD requirement, Gate-qualified capability, exact Gate provenance, match 이유, 생성된 child hypothesis와 검증 여부를 구분해서 본다. match 후보와 미검증 child는 Finding, PoC 또는 실제 impact 주장에 섞이지 않는다.
