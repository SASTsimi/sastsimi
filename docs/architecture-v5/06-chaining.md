# 06. Primitive DB와 Chaining

- **이 문서는 무엇을 설명하나요?** 보류된 가설의 부족 조건과 검증된 공격 능력을 같은 형식으로 저장하고 새 연계 가설을 만드는 방법을 설명합니다.
- **누가 읽어야 하나요?** LLM 탐색·체이닝, 검증, Gate와 데이터·평가 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 어떤 결과가 체이닝 재료가 되는지, 어떤 근거로 결합하며 순환과 비용을 어떻게 막는지 확인합니다.

`Primitive`는 공격 경로의 입력 조건과 결과 능력을 담는 재료입니다. `Chaining`은 확인된 결과가 다른 Primitive의 입력을 채울 수 있을 때 새 가설을 제안하는 작업입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 목적과 범위

Chaining Agent는 다음 두 조합만 확인한다.

```text
result가 있는 TRUE Primitive + result가 없는 HOLD Primitive
result가 있는 TRUE Primitive + result가 있는 다른 TRUE Primitive
```

Chaining Agent는 Primitive 조회·근거 기반 호환성 검사·중복 및 순환 검사·새 가설 제안만 담당한다. 일반 취약점 탐색, 우회·대체 경로 탐색, 영향 확대 조사, 추가 정적·동적 검증과 Technical Gate `REVISE` 처리는 Verification Agent의 책임이다. Primitive DB와 Chaining Agent는 Finding을 만들거나 부모 가설의 판정을 바꾸지 않는다.

## Primitive 모델

```yaml
Primitive:
  meta: RecordMeta
  primitive_id: string
  workspace_id: string
  commit_id: string
  inputs: [PrimitiveDraft]
  result: PrimitiveDraft | null
  restrictions: [string]
  source_hypothesis_id: string
  source_verification_ref: StoredDataRef
  technical_review_ref: StoredDataRef | null
  evidence_refs: [StoredDataRef]
  description: string
```

- `inputs`: 이 능력을 사용하거나 HOLD를 해소하기 위해 필요한 조건
- `result`: 이 Primitive가 제공하는 확인된 능력. HOLD는 `null`
- `restrictions`: 결합 뒤 새 가설에도 남겨야 하는 제약

status는 따로 저장하지 않는다. `result=null`이면 HOLD에서 나온 조건 묶음이고, result가 있으면 TRUE에서 나온 능력이다.

## 등록 시점

- final `HOLD`: `required_primitive_candidates`가 있을 때 Primitive 하나를 즉시 저장한다. 해당 목록은 `inputs`, `result=null`, `technical_review_ref=null`이며 restrictions를 그대로 보존한다.
- final `FALSE`: Primitive와 Chaining work를 만들지 않는다.
- final `TRUE`: 현재 generation의 성공한 동적 재현과 validated PoC가 있고, exact TRUE+CWE를 Technical Gate가 `ACCEPT`한 뒤에만 result가 있는 Primitive를 저장한다. 제공 능력이 여러 개면 능력마다 Primitive 하나를 만들고 각 record의 inputs에는 그 TRUE의 악용 전제조건을 복사한다.
- Gate 전 TRUE와 Technical `REVISE | REJECT`: Primitive를 만들지 않는다.

Technical `ACCEPT`은 체이닝 재료의 자격을 확정하고 Rule Scope는 보고 가능성만 판단한다. Rule Scope 결과는 이미 admission된 Primitive를 취소하지 않는다. 따라서 프로그램 정책 부족, 범위 밖, 중복 또는 보고 불가 판정은 Reporter를 막지만 코드에 실제로 존재하는 능력을 체이닝 재료에서 제거하지 않는다.

Technical Gate는 validated PoC 연결뿐 아니라 금지된 재현으로 근거가 오염되지 않았는지, 실제 경로와 restrictions가 정확히 표현됐는지를 확인한다. 이 검사를 통과하지 못한 TRUE는 체이닝에 들어가지 않는다.

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
- 동일 fingerprint 중복이나 ancestor Primitive 재사용 순환이 아님

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
  input_primitive_refs: [StoredDataRef]
  primitive_match_candidates: [PrimitiveMatchCandidate]
  chained_hypothesis_proposals: [HypothesisProposal]
  no_match_reasons: [string]
  errors: [AnalysisError]
```

새 가설은 `HypothesisProposal(origin=CHAINING)`으로 만든다. proposal의 `source_primitive_match_id`는 자신을 만든 candidate ID와 같고, `parent_hypothesis_ids`는 그 candidate의 부모 set과 같아야 한다. trusted runtime이 schema·semantic·workspace·commit·exact Primitive·중복·순환·예산을 검사한 뒤 새 `hypothesis_id`로 등록한다. Orchestration Agent는 등록된 가설에 새 Verification Agent를 배정하고 child는 전체 Verification 파이프라인을 처음부터 거친다.

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

## 순환과 비용 제어

각 parent hypothesis에서 `source_primitive_match_id`를 따라 조상 match와 입력 Primitive를 역방향으로 걷는다. 이 과정에서 만난 ancestor Primitive를 현재 순회의 후보에서 제외한다. DB record는 바꾸지 않는다.

체이닝 전용 임의 depth, 전체·parent별 가설 수, Chaining 호출 수와 Primitive 조합 수 한도는 두지 않는다. 대신 R8의 전체 token·시간·비용·work 예산이 모든 체이닝에도 적용된다. 예산 소진은 `FALSE`가 아니며 work 상태와 `AnalysisRunResult.stop_reasons`에 기록한다. 같은 `normalized_fingerprint`도 한 분석에서 중복 저장하지 않는다.

## 사람에게 보이는 결과

사람은 result 없는 HOLD 조건, Technical-accepted TRUE 능력, 두 Primitive를 연결한 근거, 생성된 child hypothesis와 검증 여부를 구분해서 본다. match candidate와 미검증 child는 Finding, PoC 또는 실제 impact 주장에 섞이지 않는다.
