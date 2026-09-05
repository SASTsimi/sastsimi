# ADR-012. Primitive match 중복 판정을 exact reference 조합으로 정한다

- 상태: `PROPOSED`
- 결정일: 2026-09-06
- 기준 main: `ef8e1ad`
- 결정 담당: LLM 탐색·체이닝(R1)
- 함께 검토할 역할: PM·아키텍처·워크플로(R4), 데이터·평가·예산(R8)
- 연결 Issue/PR: #104, PR #105, ADR-005
- 반영 commit: `docs: replace chaining fingerprint with match reference key`

## Context

`PrimitiveMatchCandidate`에는 `normalized_fingerprint` 필드가 있고, 같은 지문을 한 분석에서 중복 저장하지 않는다는 규칙이 여러 문서에 걸려 있습니다.

그런데 이 값을 무엇으로 어떻게 계산하는지가 어느 문서에도 없습니다. 정규화 대상, 입력 필드, 해시 방식 중 어느 것도 정해져 있지 않아 지금 상태로는 구현할 수 없습니다. Runtime이 중복을 검사하려면 두 후보의 지문이 같은지 비교해야 하는데, 같은 입력에서 같은 값이 나온다는 보장을 만들 규칙이 없습니다.

반면 `PrimitiveMatchCandidate`는 이미 match를 유일하게 식별하는 값을 갖고 있습니다. `upstream_result_ref`와 `downstream_input_ref`는 두 Primitive record의 exact reference이고, `matched_input_id`는 그중 어느 input이 채워졌는지를 가리킵니다. 세 값이 같으면 같은 match이고 다르면 다른 match입니다.

## Options

### 1. `normalized_fingerprint` 계산 규칙을 새로 정의

정규화 대상과 해시 입력을 정하고 Runtime이 재계산해 비교하게 만듭니다. 그러나 그 계산은 결국 두 Primitive reference와 선택된 input을 재료로 삼게 되므로, 이미 record에 있는 값을 한 번 더 가공해 저장하는 것이 됩니다. 값이 어긋날 여지만 새로 만들어 선택하지 않습니다.

### 2. 중복 판정을 없앤다

같은 조합에서 나온 자식 가설이 여러 번 등록되어 중복 제안과 검증 비용이 늘어납니다. 선택하지 않습니다.

### 3. exact reference 조합을 중복 키로 사용

새 값을 만들지 않고 이미 저장된 세 필드를 그대로 키로 씁니다. Runtime이 별도 계산 없이 비교할 수 있고, 파생값이 원본과 어긋날 여지가 없습니다. 이 방식을 선택합니다.

## Decision

`PrimitiveMatchCandidate.normalized_fingerprint`를 제거합니다.

중복 판정 기준은 `(upstream_result_ref, downstream_input_ref, matched_input_id)` 조합입니다. 한 분석 안에서 같은 조합을 두 번 저장하지 않습니다. 매칭 조건, `SAVE_RESULT` 저장 검사와 비용 제어 서술은 모두 이 조합을 기준으로 씁니다.

같은 조합을 두 번 검토하지 않도록 순회 단위도 함께 정합니다. Chaining Agent는 새로 저장된 Primitive 하나를 계기로 그 Primitive와 자기 자신을 제외한 기존 Primitive 전체를 비교합니다. 각 조합은 나중에 저장된 쪽이 계기가 될 때 한 번만 검토합니다.

필드 제거는 기존 `PrimitiveMatchCandidate`의 필드를 없애므로 새 MAJOR schema에서만 사용합니다. 이전 MAJOR 결과의 지문을 다시 계산해 채우지 않고 감사 이력으로만 보존합니다.

ADR-005는 `PrimitiveMatchCandidate`가 fingerprint를 고정한다고 적었습니다. 그 문장은 이 ADR로 대체하며 ADR-005 본문은 결정 당시 기록으로 그대로 둡니다.

## Consequences

Runtime의 중복 검사가 저장된 reference 비교로 끝나므로 별도 계산 계층이 없어집니다.

`CHAINING` work의 등록 계기는 `WorkExecutionState.trigger_primitive_ref`로 고정합니다. `subject_type`은 `ANALYSIS`를 유지하고, 이 필드는 `work_type=CHAINING`에서만 값을 가집니다. 한 조합의 담당 work는 두 Primitive 중 나중에 저장된 쪽을 계기로 가진 work이므로 서로 다른 두 work가 같은 조합을 검토하지 않습니다. 저장 시점 uniqueness는 안전장치로 남기며, 위반이 실제로 나오면 해당 조합만 결과에서 빼고 오류로 기록합니다.

## Responsibility

- R1: `06-chaining.md`의 매칭 조건, `PrimitiveMatchCandidate` schema, 비용 제어 서술을 조합 키로 맞춥니다.
- R4: `08-lightweight-data-contracts.md`의 `chaining_result` 저장 검사와 MAJOR schema 처리, `CHAINING` work 등록 계약을 확정합니다.
- R8: 중복 차단 건수를 세는 지표가 있으면 조합 키 기준으로 맞춥니다.
