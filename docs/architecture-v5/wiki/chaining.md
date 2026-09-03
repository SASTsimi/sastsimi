# Primitive DB와 Chaining

## 쉽게 말하면

한 취약점에서 얻은 결과가 다른 취약점을 실행하는 데 필요한 입력을 채울 수 있는지 찾습니다. 연결되더라도 바로 취약점으로 확정하지 않고 새 가설로 등록해 처음부터 검증합니다.

**상세 기준:** [06. Primitive DB와 Chaining](../06-chaining.md)

`Primitive`는 한 가설의 입력 조건들과 실행 뒤 결과를 함께 담는 연계 재료입니다. `Chaining`은 한 Primitive의 결과가 다른 Primitive의 입력을 충족하는지 비교하는 작업입니다. 자세한 용어는 [쉬운 용어집](../../GLOSSARY.md)을 따릅니다.

## 통합 Primitive

- HOLD는 부족한 조건들을 `inputs`에 넣고 `result=null`로 저장합니다.
- TRUE는 validated PoC가 있고 Technical Gate가 exact revision을 `ACCEPT`한 뒤에만 `result`가 있는 Primitive가 됩니다.
- TRUE의 제공 능력이 여러 개면 능력마다 Primitive 하나를 만들며, 같은 TRUE의 입력 조건과 제한을 각각 함께 보존합니다.
- `REQUIRED`, `PROVIDED`, `TRUE_HOLD`, `TRUE_TRUE` 같은 별도 종류는 저장하지 않습니다. 필요하면 `result` 유무와 부모 verdict에서 계산합니다.
- Rule Scope Gate는 보고 가능성만 판단합니다. `FAIL | UNCERTAIN | DENY`여도 이미 admission된 Primitive와 Chaining 자격은 유지됩니다.
- FALSE, Gate 전 TRUE, Technical `REVISE | REJECT`는 result Primitive가 되지 않습니다.

## Matching과 새 가설

Chaining Agent는 `upstream_result_ref`가 `downstream_input_ref`의 `matched_input_id`를 충족하는지 코드 근거로 비교합니다. 저장소 전체에 공통인 임의의 권한 서열은 두지 않고, 분석 중인 저장소의 역할·권한 상수와 실제 검사 위치를 근거로 사용합니다.

match 후보는 부모 가설·Verification, workspace·commit, 정확한 Primitive record와 근거를 고정한 `PrimitiveMatchCandidate`입니다. 이 후보는 `UNVALIDATED`이며, 의미 있는 연결이면 `HypothesisProposal(origin=CHAINING)`을 만들고 trusted validation·전역 등록 뒤 새 Verification을 배정합니다. 새 가설은 `source_primitive_match_id`로 자신을 만든 정확한 match를 가리킵니다.

일반 우회·대체 경로·영향 탐색, 동적 재현과 Technical `REVISE` 보완은 Verification이 담당합니다. 어느 child도 부모 판정을 바꾸지 않습니다.

## 순환과 비용 제한

현재 가설의 `parent_hypothesis_ids`와 `source_primitive_match_id`를 따라 조상 계보를 계산하고, 조상 Primitive는 현재 matching 후보에서 제외합니다. 별도 루트 ID나 깊이 숫자, 체이닝 전용 임의 깊이·호출·조합 한도는 저장하지 않습니다.

전체 token·시간·작업 수는 R8의 전역 예산 정책으로 제한합니다. 중복 fingerprint와 ancestor cycle은 Runtime Validator가 차단하며, 예산 중단은 `FALSE`가 아닙니다.

상세 내용은 [Primitive DB와 Chaining](../06-chaining.md)을 따릅니다.
