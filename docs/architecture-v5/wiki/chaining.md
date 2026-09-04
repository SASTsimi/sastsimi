# Primitive DB와 Chaining

## 쉽게 말하면

한 취약점에서 얻은 결과가 다른 취약점을 실행하는 데 필요한 입력을 채울 수 있는지 찾습니다. 연결되더라도 바로 취약점으로 확정하지 않고 새 가설로 등록해 처음부터 검증합니다.

**상세 기준:** [06. Primitive DB와 Chaining](../06-chaining.md)

`Primitive`는 한 가설의 입력 조건들과 실행 뒤 결과를 함께 담는 연계 재료입니다. `Chaining`은 한 Primitive의 결과가 다른 Primitive의 입력을 충족하는지 비교하는 작업입니다. 자세한 용어는 [쉬운 용어집](../../GLOSSARY.md)을 따릅니다.

## 통합 Primitive

- HOLD는 부족한 조건들을 `inputs`에 넣고 `result=null`로 저장합니다.
- TRUE는 validated PoC가 있고 Technical Gate가 exact revision을 `ACCEPT`한 뒤, 같은 exact chain의 Rule Scope Gate가 `testing_restriction=PASS`로 판정해야 `result`가 있는 Primitive가 됩니다.
- TRUE의 제공 능력이 여러 개면 능력마다 Primitive 하나를 만들며, 같은 TRUE의 입력 조건과 제한을 각각 함께 보존합니다.
- `REQUIRED`, `PROVIDED`, `TRUE_HOLD`, `TRUE_TRUE` 같은 별도 종류는 저장하지 않습니다. 필요하면 `result` 유무와 부모 verdict에서 계산합니다.
- `testing_restriction=FAIL`은 Primitive·Chaining을 금지하고 `UNCERTAIN`은 재판정까지 admission을 보류합니다. 명시적 `PASS`일 때만 admission할 수 있습니다.
- `testing_restriction=PASS`라면 scope·일반 eligibility·impact·report permission 실패는 현재 Reporter만 차단하고 Primitive·Chaining은 허용합니다.
- FALSE, Rule Scope 전 TRUE, Technical `REVISE | REJECT`는 result Primitive가 되지 않습니다.

## Matching과 새 가설

Chaining Agent는 `upstream_result_ref`가 `downstream_input_ref`의 `matched_input_id`를 충족하는지 코드 근거로 비교합니다. 저장소 전체에 공통인 임의의 권한 서열은 두지 않고, 분석 중인 저장소의 역할·권한 상수와 실제 검사 위치를 근거로 사용합니다.

match 후보는 부모 가설·Verification, workspace·commit, 정확한 Primitive record와 근거를 고정한 `PrimitiveMatchCandidate`입니다. 이 후보는 `UNVALIDATED`이며, 의미 있는 연결이면 `HypothesisProposal(origin=CHAINING)`을 만들고 trusted validation·전역 등록 뒤 새 Verification을 배정합니다. 새 가설은 `source_primitive_match_id`로 자신을 만든 정확한 match를 가리키고, 양쪽 Primitive의 `Restriction` 객체를 중복 없이 합쳐 그대로 보존합니다. 같은 restriction ID의 내용이나 근거가 다르면 등록하지 않습니다.

Runtime은 work를 시작할 때 조상 제외 전 전체 Primitive를 `considered_primitive_refs`로 고정합니다. 실제 match에 사용된 Primitive만 `input_primitive_refs`에 남기므로 두 목록을 같은 의미로 사용하지 않습니다. 두 목록에는 같은 exact reference를 중복해서 넣지 않습니다. 진행 중인 Chaining work의 입력은 바뀌지 않습니다. 새 Primitive가 생기면 별도 Chaining work에서 처리합니다.

`source_result_refs`와 각 match의 부모 가설·Verification 목록은 실제 match에 사용한 Primitive가 직접 가리키는 값만 중복 없이 모읍니다. 빠진 값, 관계없는 값, 다른 work의 값을 넣으면 결과를 저장하지 않습니다.

`origin=CHAINING` 자식의 `observed_facts`는 빈 목록으로 고정합니다. Chaining Agent가 코드 사실을 새로 만들지 않고, 자식 Verification이 `source_primitive_match_id`를 따라 부모 Primitive의 entity와 location에서 다시 확인합니다. 부모 계보가 끊겨 검증 시작점을 찾을 수 없으면 자식 가설을 등록하지 않습니다.

일반 우회·대체 경로·영향 탐색, 동적 재현과 Technical `REVISE` 보완은 Verification이 담당합니다. 어느 child도 부모 판정을 바꾸지 않습니다.

## 자식 가설의 내용

결과 서술은 저장하지 않고 `source_primitive_match_id` 링크로 읽습니다. `restrictions`는 두 부모 `Restriction`의 합집합과 정확히 같고, 이번 매칭으로 채워진 입력은 자식의 전제에서 빠지며 나머지 남은 입력은 문자열 그대로 `assumptions`에 담깁니다. 물려받은 사실이라고 다시 확인을 건너뛰지 않습니다 — 결합 상황에서도 참인지는 자식 검증이 전부 다시 봅니다.

자식 가설은 두 능력이 이어지는 지점을 겨냥한 반증 질문을 최소 하나 포함해야 합니다. 이 지점은 어느 쪽 부모의 조건도 아니라 자식이 새로 만든 것이라 별도로 요구합니다. 질문이 실제로 그 지점을 겨냥했는지는 Technical Evidence Gate가 판단하고, Runtime은 목록이 비어 있지 않은지만 확인합니다.

## Finding은 평평하게

체이닝으로 나온 Finding은 재료가 된 Finding 아래에 중첩해 저장하지 않습니다. 한 부모가 여러 자식의 재료가 될 수 있고 HOLD 부모는 Finding이 아예 없어서 중첩할 자리가 없기 때문입니다. 어떤 Primitive가 재료가 됐는지는 새 저장 필드 없이 `parent_hypothesis_ids`·`source_primitive_match_id`를 따라가 복원하며, 이 경로는 결과를 열람하거나 재분석할 때만 쓰고 `ReportDraft`에는 싣지 않습니다.

## 조상 재사용과 비용 제한

이 규칙은 순환 방지가 아닙니다 — record가 불변·append-only라 계보는 이미 DAG입니다. 상세 문서 §06대로, 같은 계보에서는 가장 깊은 후보부터 match를 검토하고 그 match가 실제로 성립한 뒤에만 그 후보의 양쪽(upstream·downstream) Primitive를 재귀 추적해 얻은 조상을 현재 순회의 후보에서 제외합니다. match가 성립하지 않으면 아무것도 제외하지 않고 얕은 후보를 그대로 검토합니다. 조상 쪽은 새 Primitive가 등장하기 전부터 이미 서로 연결이 확정돼 있었으므로, 가장 깊은 match가 성립한 시점에서 그 결론이 얕은 조합들의 결론을 이미 포함합니다. 대신 가장 깊은 조합의 자식 가설이 이후 검증에서 실패해도 제외된 얕은 조합은 다시 제안되지 않으며, 이는 중복 제안을 줄이는 대가로 의도적으로 수용한 미탐 위험입니다. 계보가 겹치지 않는 다른 Primitive의 재사용은 막지 않습니다. 실제 제외한 항목은 `excluded_lineage_refs`에 제외된 Primitive, 제외 근거가 된 같은 work의 Primitive와 `ANCESTOR_REUSE` 이유를 함께 남깁니다. Runtime은 이 기록을 고정된 `considered_primitive_refs`와 다시 비교해 누락·추가·잘못된 계보를 거절합니다. 별도 루트 ID나 깊이 숫자, 체이닝 전용 임의 깊이·호출·조합 한도는 저장하지 않습니다.

체이닝 전용 depth·count·call·조합·token 상한은 두지 않습니다. R8의 전체 시간·비용·작업 예산, 중복 fingerprint와 조상 재사용은 Runtime Validator가 검사하며, 중단은 `FALSE`가 아닙니다. token은 사용량만 관측합니다.

상세 내용은 [Primitive DB와 Chaining](../06-chaining.md)을 따릅니다.
