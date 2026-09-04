# 06. Primitive DB와 Chaining

- **이 문서는 무엇을 설명하나요?** 보류된 가설의 부족 조건과 검증된 공격 능력을 같은 형식으로 저장하고 새 연계 가설을 만드는 방법을 설명합니다.
- **누가 읽어야 하나요?** LLM 탐색·체이닝, 검증, Gate와 데이터·평가 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 어떤 결과가 체이닝 재료가 되는지, 어떤 근거로 결합하며 조상 재사용과 비용을 어떻게 막는지 확인합니다.

`Primitive`는 공격 경로의 입력 조건과 결과 능력을 담는 재료입니다. `Chaining`은 확인된 결과가 다른 Primitive의 입력을 채울 수 있을 때 새 가설을 제안하는 작업입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목적과 범위

Chaining Agent는 다음 두 조합만 확인한다.

```text
result가 있는 TRUE Primitive + result가 없는 HOLD Primitive
result가 있는 TRUE Primitive + result가 있는 다른 TRUE Primitive
```

Chaining Agent는 Primitive 조회·근거 기반 호환성 검사·중복 및 조상 재사용 검사·새 가설 제안만 담당한다. 일반 취약점 탐색, 우회·대체 경로 탐색, 영향 확대 조사, 추가 정적·동적 검증과 Technical Gate `REVISE` 처리는 Verification Agent의 책임이다. Primitive DB와 Chaining Agent는 Finding을 만들거나 부모 가설의 판정을 바꾸지 않는다.

## Primitive 모델

```yaml
Primitive:
  meta: RecordMeta
  primitive_id: string
  workspace_id: string
  commit_id: string
  inputs: [PrimitiveDraft]
  result: PrimitiveDraft | null
  restrictions: [Restriction]
  source_hypothesis_id: string
  source_verification_ref: StoredDataRef
  technical_review_ref: StoredDataRef | null
  admission_decision_ref: StoredDataRef | null
  evidence_refs: [StoredDataRef]
  description: string
```

- `inputs`: 이 능력을 사용하거나 HOLD를 해소하기 위해 필요한 조건
- `result`: 이 Primitive가 제공하는 확인된 능력. HOLD는 `null`
- `restrictions`: exact 코드·검증 근거와 연결되고 결합 뒤 새 가설에도 그대로 남겨야 하는 제약

status는 따로 저장하지 않는다. `result=null`이면 HOLD에서 나온 조건 묶음이고, result가 있으면 TRUE에서 나온 능력이다.

## 등록 시점

- final `HOLD`: `required_primitive_candidates`가 있을 때 Primitive 하나를 즉시 저장한다. 해당 목록은 `inputs`, `result=null`, `technical_review_ref=null`이며 restrictions를 그대로 보존한다.
- final `FALSE`: Primitive와 Chaining work를 만들지 않는다.
- final `TRUE`: 현재 generation의 성공한 동적 재현과 validated PoC가 있고, exact TRUE Verification과 이를 직접 가리키는 current `CWELabel`을 Technical Gate가 `ACCEPT`한 뒤에만 result가 있는 Primitive를 저장한다. 제공 능력이 여러 개면 능력마다 Primitive 하나를 만들고 각 record의 inputs에는 그 TRUE의 악용 전제조건을 복사한다.
- Gate 전 TRUE와 Technical `REVISE | REJECT`: Primitive를 만들지 않는다.

체이닝 재료 자격은 세 가지를 확인해 정한다 — `result`가 있는 Primitive일 것, 그 Primitive의 current `PrimitiveAdmissionDecision.decision=ALLOW`일 것, 그리고 직접 부모와 `source_primitive_match_id` 계보를 따라 도달하는 모든 result Primitive도 current `ALLOW`일 것. Chaining Agent는 `rule_compliance`나 `evidence_links`를 읽어 금지 테스트 위반을 추정하지 않는다. 위반 판정과 그 결론은 admission decision이 이미 담고 있다.

Rule Scope의 나머지 판정은 보고 가능성만 가른다. 범위 밖 자산, 영향 부족, 중복, 프로그램 정책 부족, 보상 대상 클래스 아님은 체이닝을 막지 않는다. 확정된 금지 테스트 위반으로 `DENY`가 된 경우만 재료에서 제외된다. 정책상 보고할 수 없는 능력이라도 그것을 발판으로 삼는 다른 취약점은 보고 대상일 수 있기 때문이다.

Chaining work를 시작할 때 Runtime은 사용 가능한 Primitive뿐 아니라 그 Primitive와 부모 체인의 current `ALLOW` decision reference도 `WorkExecutionState.input_refs`에 함께 고정한다. `source_admission_refs`에는 실제 match에 사용한 Primitive와 그 계보에서 재귀적으로 도달한 모든 admission decision을 중복 없이 기록하며, 이 목록은 실제 사용한 decision 집합과 정확히 같아야 한다.

결과를 저장하기 직전에 실제로 사용한 decision을 다시 확인한다. 하나라도 current가 아니거나 `DENY`로 바뀌었으면 `STALE_RESULT`로 저장을 거절하고 새 자식 가설을 만들지 않는다. 이때 기존 가설의 verdict를 `FALSE`나 `HOLD`로 바꾸지 않는다. 실제 match에 사용하지 않은 후보의 decision 변경만으로는 진행 중인 결과를 무효화하지 않는다.

이미 만들어진 자식과 그 아래 세대도 같은 계보 확인을 받는다. 부모의 admission이 나중에 `DENY`로 바뀌면 파생 결과는 감사 기록으로만 보존하고 새 Verification·Gate·Primitive·Reporter 입력으로 사용하지 않는다.

Technical Gate는 자기 입력으로 확인할 수 있는 근거 품질을 판단한다 — validated PoC가 실제로 연결되는지(`dynamic_linkage`), 실제 경로가 근거와 이어지는지(`code_flow_linkage`), restrictions가 정확히 표현됐는지(`restriction_assessment`). 하나라도 통과하지 못한 TRUE는 체이닝에 들어가지 않는다. 부모의 제약 서술이 부정확하면 그 오류가 자식 가설의 `Restriction` 합집합으로 그대로 승계되기 때문이다.

## PrimitiveIndexState

```yaml
PrimitiveIndexState:
  meta: RecordMeta with attempt_id null
  current_verification_ref: StoredDataRef
  primitive_refs: [StoredDataRef]
  updated_at: timestamp
```

가설마다 하나의 index가 current final Verification과 그 결과에서 만든 Primitive exact reference를 가리킨다. REQUIRED/PROVIDED 목록, 별도 `state_version`, 사후 ACTIVE/SUPERSEDED 상태는 사용하지 않는다.

동시에 index를 쓰면서 결과가 사라지지 않도록 공통 immutable record 규칙은 유지한다. 새 revision은 바로 전 `record_id`와 연속된 `revision_number`를 사용하고 current pointer를 원자적으로 바꾼다. 이는 모든 record에 적용되는 저장 안전 규칙이며 체이닝 전용 CAS나 사후 자격 변경 절차가 아니다.

## Chaining Agent

### 입력과 비교 기준

Chaining Agent는 result가 있는 Primitive를 upstream으로 사용한다. downstream은 하나 이상의 input을 가져야 한다. 다음 조건을 모두 확인한다.

- 같은 `workspace_id`와 `commit_id`
- upstream result와 downstream input의 `entity_refs`가 같거나 코드 흐름으로 연결됨
- 권한 조건이 있으면 저장소의 역할명·권한 상수·검사 위치로 충족 관계가 확인됨
- upstream 능력이 downstream보다 먼저 성립함
- 양쪽 restrictions를 합쳐도 공격 경로가 성립함
- 비교 결론을 뒷받침하는 실제 코드·검증 근거가 있음
- 동일 fingerprint 중복이 아니고, 같은 계보의 조상 Primitive 재사용도 아님

전역 권한 서열표나 문자열 이름의 단순 일치는 사용하지 않는다. 축이 맞지 않거나 근거가 없으면 candidate를 만들지 않고 `no_match_reasons`에 이유를 남긴다. 별도 PASS/UNCERTAIN 필드는 두지 않는다.

### PrimitiveMatchCandidate

```yaml
PrimitiveMatchCandidate:
  primitive_match_id: string
  upstream_result_ref: StoredDataRef
  downstream_input_ref: StoredDataRef
  matched_input_id: string
  parent_hypothesis_ids: [string]
  parent_verification_refs: [StoredDataRef]
  workspace_id: string
  commit_id: string
  normalized_fingerprint: string
  evidence_refs: [StoredDataRef]
  candidate_state: UNVALIDATED
```

`upstream_result_ref`와 `downstream_input_ref`는 nested draft가 아니라 두 Primitive record의 exact reference다. upstream은 non-null result를 가져야 하고 `matched_input_id`는 downstream `inputs[].draft_id` 하나를 선택한다. downstream result가 `null`이면 TRUE_HOLD, result가 있으면 TRUE_TRUE로 유도하므로 match 종류를 따로 저장하지 않는다.

### 출력

```yaml
ChainingResult:
  meta: RecordMeta
  source_result_refs: [StoredDataRef]
  source_admission_refs: [StoredDataRef]
  considered_primitive_refs: [StoredDataRef]
  input_primitive_refs: [StoredDataRef]
  primitive_match_candidates: [PrimitiveMatchCandidate]
  chained_hypothesis_proposals: [HypothesisProposal]
  excluded_lineage_refs: [LineageExclusion]
  no_match_reasons: [string]
  errors: [AnalysisError]
```

```yaml
LineageExclusion:
  excluded_primitive_ref: StoredDataRef
  excluded_by_ref: StoredDataRef
  reason_code: ANCESTOR_REUSE
```

`considered_primitive_refs`는 Chaining work를 시작할 때(`REGISTER_WORK`) Runtime이 고정한, 조상 제외 전 전체 Primitive 입력이다. `input_primitive_refs`는 실제 match candidate에 사용된 upstream/downstream Primitive의 중복 없는 합집합이다. `excluded_lineage_refs`는 계보 때문에 match에서 제외한 Primitive와 그 제외를 일으킨 같은 work의 Primitive를 기록한다. `source_result_refs`는 실제 match Primitive들이 직접 가리키는 source Verification과 non-null Technical review의 중복 없는 합집합이다. `source_admission_refs`는 실제 입력 Primitive와 그 계보에서 재귀적으로 도달한 모든 result Primitive의 current `ALLOW` admission decision을 중복 없이 모은 집합이다. 각 candidate의 `parent_hypothesis_ids`와 `parent_verification_refs`도 해당 upstream/downstream Primitive가 직접 가리키는 source hypothesis와 Verification의 정확한 합집합이어야 한다. 세 Primitive 목록과 source·parent 목록은 중복을 허용하지 않으며 자세한 저장 검사는 [경량 데이터 계약](08-lightweight-data-contracts.md)의 `SAVE_RESULT` 규칙을 따른다.

새 가설은 `HypothesisProposal(origin=CHAINING)`으로 만든다. proposal의 `source_primitive_match_id`는 자신을 만든 candidate ID와 같고, `parent_hypothesis_ids`는 그 candidate의 부모 set과 같아야 한다. Chaining Agent는 새 코드 사실을 만들지 않으므로 `observed_facts=[]`만 허용한다. `target_entities`·`target_locations`·`suspected_path`는 비어 있을 수 있지만, 값을 넣으면 부모 Primitive의 exact entity·location 계보에서 얻을 수 있어야 한다. Verification이 시작할 entity나 location을 부모 계보에서 하나도 복원할 수 없으면 proposal 등록과 배정을 거절한다.

proposal의 `restrictions`는 입력 Primitive 양쪽에 있는 Restriction 객체의 중복 없는 합집합이다. 같은 `restriction_id`는 canonical content가 완전히 같을 때 한 번만 유지하고, ID는 같은데 statement나 근거 reference가 다르면 계약 충돌로 거절한다. trusted runtime이 schema·semantic·workspace·commit·exact Primitive·중복·조상 재사용·예산을 검사한 뒤 새 `hypothesis_id`로 등록한다. Orchestration Agent는 등록된 가설에 새 Verification Agent를 배정하고 child는 전체 Verification 파이프라인을 처음부터 거친다.

### 자식 가설의 내용

Chaining input은 exact Primitive와 그 Primitive를 만든 source Verification·Technical review로 고정된다. 부모 가설의 proposal은 이 경계 밖이므로 참조하지 않는다. Chaining Agent는 추가 코드 조회·정적 검증·독립 탐색을 할 수 없으므로 자식 가설의 재료는 이 경계 안에서만 나온다. 다음 규칙으로 채운다.

- 결과 서술은 저장하지 않고 `source_primitive_match_id` 링크로 읽는다. 자식 proposal에는 `result`·`statement` 필드가 없으므로 값을 복사할 자리도 없다.
- `observed_facts`·`target_entities`·`target_locations`·`suspected_path`는 모두 비어 있을 수 있다. entity 정보는 `source_primitive_match_id` 계보(`PrimitiveMatchCandidate` → `upstream_result_ref`/`downstream_input_ref` → `Primitive.result`/`inputs` → `entity_refs`)를 따라가면 얻을 수 있어 Chaining Agent가 다시 계산해 싣지 않아도 된다. `suspected_path`는 부모 데이터에 관계(순서·연결) 정보 자체가 없어 흉내 내도 위치 집합일 뿐 실제 경로가 되지 않는다. 값을 채우는 경우에도 이 계보 밖의 entity·location·path를 임의로 추가하지 않는다. 계보를 복원할 수 없으면(부모 참조가 무효하거나 시작점을 하나도 못 얻으면) 자식 가설 등록과 Verification 배정을 거절한다.
- `vulnerability_type_candidates`는 Chaining Agent가 이번 match가 정의한 노리는 능력에서 판단한다.
- `restrictions`는 위에서 정한 대로 두 부모의 `Restriction` 합집합과 정확히 같다.
- 이번 매칭으로 채워진 downstream input은 자식의 전제에서 빠지고, upstream의 남은 `inputs`와 downstream의 나머지 `inputs`가 자식이 아직 필요로 하는 조건으로 `assumptions`에 남는다. 남은 `PrimitiveDraft` 하나마다 그 `description`을 문자열 그대로 사용해 `assumptions`에 하나씩 담는다.

승계는 다시 확인하지 않는다는 뜻이 아니다. 물려받은 사실이 결합 상황에서도 참인지는 자식 검증이 전부 다시 본다.

자식 가설은 두 능력이 이어지는 지점을 겨냥한 반증 질문을 최소 하나 포함한다. 결합 지점은 어느 쪽 부모의 조건도 아니고 자식이 새로 만든 것이라 `assumptions`로는 드러나지 않으므로 별도로 요구한다. 이 질문이 실제로 결합 지점을 겨냥했는지는 Technical Evidence Gate가 다른 의미적 충분성 검토와 함께 판단하며, Runtime Validator는 반증 질문 목록이 비어 있지 않은지만 구조적으로 확인한다.

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

Verification은 proposal을 만들 수 있지만 `hypothesis_id`를 직접 발급하거나 child를 자동 TRUE로 만들 수 없다. 부모와 child의 lifecycle과 verdict는 독립이며 child가 FALSE여도 부모 판정은 바뀌지 않는다.

## 조상 재사용과 비용 제어

이 규칙은 순환을 막기 위한 것이 아니다. `Primitive`와 `VulnerabilityHypothesis`는 모두 불변·append-only record이고 match는 이미 존재하는(시간상 앞선) record만 참조할 수 있으므로, 계보 그래프는 구성 자체로 DAG다 — 순환은 애초에 만들어질 수 없다.

이 규칙이 실제로 막는 것은 중복이다. 제외는 후보를 미리 걸러내는 단계가 아니라, 실제 match가 성립한 뒤 그 결론에 이미 포함되는 얕은 조합만 걷어내는 단계다. 순서를 다음과 같이 고정한다.

1. 같은 계보 안에서는 가장 깊은 후보부터 match를 검토한다. 후보의 깊이는 그 후보의 `source_hypothesis_id`가 가리키는 등록 가설의 `source_primitive_match_id`를 따라가 얻은 match의 `upstream_result_ref`와 `downstream_input_ref` 양쪽을 재귀적으로 거슬러 올라가 얻은 조상 수다. `source_primitive_match_id`가 `null`이면(=체이닝 산물이 아니면) 깊이는 0이고 조상도 없다.
2. 가장 깊은 후보와의 match가 실제로 성립하면, 그 후보의 조상 Primitive 전체를 이번 순회의 후보에서 제외한다. 이때 `excluded_by_ref`는 match가 성립한 그 후보 하나뿐이고, 제외된 Primitive는 다시 다른 항목의 제외 근거가 되지 않는다. 따라서 한 결과 안에서 같은 Primitive가 제외 대상이면서 제외 근거인 상태는 생기지 않는다.
3. 가장 깊은 후보와의 match가 성립하지 않으면 아무것도 제외하지 않는다. 같은 계보의 얕은 후보들은 후보로 남아 그대로 match를 검토한다.

1번의 검토 순서는 Chaining Agent가 지키는 규칙이고, Runtime은 저장할 결과의 정합성만 검사한다. 순서를 지키지 않아 얕은 후보부터 match해도 최상위 조합을 잃지는 않는다 — 제외 대상은 조상뿐이라 더 깊은 후손은 후보로 남기 때문이다. 실제 손실은 경로가 겹치는 중복 제안이 늘어나는 것뿐이고, 같은 결과에서 얕은 후보와 깊은 후보를 모두 match하면 얕은 후보가 match 입력이면서 제외 대상이 되므로 아래 저장 검사에서 거절된다. 따라서 검토 순서를 강제하는 별도 필드나 검사는 두지 않는다.

이 제외가 안전한 이유는 다음과 같다. 조상 쪽(예: B, B→C, B→C→D)은 새 Primitive가 등장하기 전부터 이미 서로 연결이 확정된 상태로 candidate pool에 존재한다 — 그 계보 자체는 새 Primitive와 무관하게 독립적으로 이미 성립해 있었다는 뜻이다. 그러므로 새 Primitive가 가장 깊은 후손(B→C→D→E)과 맺는 match가 성립한 시점에서 그 결합 지점(새 Primitive가 조상 쪽 빈 자리를 실제로 채우는지)은 이미 확인된 것이고, 가장 깊은 조합이 얕은 조합들의 결론을 그대로 포함하므로 얕은 조합을 따로 제안해도 새 정보가 없다. match가 성립하지 않았다면 3번에 따라 얕은 후보가 그대로 남으므로 잃는 조합도 없다.

남는 위험은 하나다. 가장 깊은 조합의 match는 성립했지만 그 자식 가설이 이후 Verification에서 실패하는 경우, 이미 제외된 얕은 조합은 이 분석에서 다시 제안되지 않는다. 이는 검증 과정 일반의 오판이 아니라 이 중복 제거 정책 자체가 만드는 미탐 위험이며, 중복 제안을 줄이는 대가로 팀이 의도적으로 수용한 설계 결정이다.

계보가 겹치지 않는 다른 Primitive의 정당한 재사용(같은 조상이 전혀 다른 능력으로 다른 곳에 쓰이는 것)은 이 규칙과 무관하며 막지 않는다.

제외한 항목마다 `LineageExclusion`을 만들고, `excluded_by_ref`에는 실제로 match가 성립해 그 조상들을 제외시킨 정확한 record를 넣는다. 제외된 Primitive와 제외 근거 Primitive는 모두 고정된 `considered_primitive_refs`에 있어야 하고, 제외 근거 Primitive 자신은 제외 목록에 있으면 안 되며 실제 match candidate에 사용된 상태여야 한다. Runtime은 같은 규칙(성립한 match의 후보에서 양방향 재귀 탐색)으로 기대 제외 쌍을 다시 계산하여 `excluded_lineage_refs`와 정확히 같은지 확인한다. DB record는 바꾸지 않는다.

체이닝 전용 임의 depth, 전체·parent별 가설 수, Chaining 호출 수, Primitive 조합 수와 token 상한은 두지 않는다. 대신 R8의 전체 시간·비용·work 예산이 모든 체이닝에도 적용된다. token 사용량은 관측하되 초과만으로 중단하지 않는다. 다른 예산 소진도 `FALSE`가 아니며 work 상태와 `AnalysisRunResult.stop_reasons`에 기록한다. 같은 `normalized_fingerprint`도 한 분석에서 중복 저장하지 않는다.

`considered_primitive_refs`, `source_admission_refs`와 `excluded_lineage_refs`는 기존 `ChainingResult`에 없던 필수 필드이므로 새 MAJOR schema에서만 사용한다. 이전 MAJOR 결과에 빈 목록을 추정해 넣지 않고 감사 이력으로만 보존한다.

## 사람에게 보이는 결과

사람은 result 없는 HOLD 조건, Technical-accepted TRUE 능력, 두 Primitive를 연결한 근거, 생성된 child hypothesis와 검증 여부를 구분해서 본다. match candidate와 미검증 child는 Finding, PoC 또는 실제 impact 주장에 섞이지 않는다.

사슬에서 나온 Finding은 재료가 된 Finding 밑에 중첩해 저장하지 않는다. 한 부모가 여러 자식의 재료가 되고 부모 자신도 독립 Finding이라 중첩이 성립하지 않으며, HOLD 부모는 Finding이 없어 자리가 빈다. Finding은 평평하게 둔다.

재료 계보는 별도 저장 필드가 아니라 기존 참조를 따라 복원한다. 자식의 `VulnerabilityHypothesis.parent_hypothesis_ids`와 `source_primitive_match_id`가 `PrimitiveMatchCandidate`를 거쳐 재료가 된 upstream Primitive와 그 `source_hypothesis_id`에 닿는다. TRUE 부모는 그 `hypothesis_id`로 자기 Finding에 이르고, HOLD 부모는 Finding이 없으므로 `hypothesis_id`와 exact `VerificationResult` reference에서 멈춘다. `FindingCandidate`에 이 계보를 직접 저장하는 새 reference field는 두지 않는다. 이 경로는 결과를 열람하거나 재분석할 때 쓰는 정보이며 `ReportDraft`에는 싣지 않는다.
