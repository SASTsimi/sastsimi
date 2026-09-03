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
- final `TRUE`: Verification 결과만으로 `PROVIDED`를 만들지 않는다. 현재 generation의 성공한 동적 재현과 validated PoC가 연결되고, 같은 Verification revision과 CWE revision을 Technical Gate가 `ACCEPT`하고, Rule Scope Gate가 기존 정상 통과 조건을 모두 만족한 뒤에만 `PROVIDED`를 저장한다. 이 PROVIDED의 `required_preconditions`에는 exact Verification이 기록한 악용 전제조건을 복사한다.

Rule Scope Gate의 정상 통과는 다음 기존 조건을 그대로 사용한다.

```text
review_status == PASS
AND rule_compliance == PASS
AND scope_compliance == PASS
AND security_impact == SUFFICIENT
AND report_permission == ALLOW
```

따라서 validated PoC가 없는 TRUE 후보, `Technical ACCEPT`만 받은 TRUE, `FAIL | UNCERTAIN | DENY`인 TRUE와 Gate 전 TRUE는 체이닝 자격이 없다. PROVIDED의 provenance reference는 동일한 `workspace_id`, `commit_id`, `hypothesis_id`와 exact Verification·동적 결과·PoC revision을 가리켜야 한다.

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
