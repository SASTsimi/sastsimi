# Primitive DB와 Chaining

## 쉽게 말하면

보류된 가설에 부족한 조건과 이미 확인된 공격 능력을 비교해 서로 연결될 가능성을 찾습니다. 연결되더라도 바로 확정하지 않고 새로운 가설로 처음부터 검증합니다.

**상세 기준:** [06. Primitive DB와 Chaining](../06-chaining.md)

`Primitive`는 연계 공격의 필요 조건 또는 확인된 능력이고 `Chaining`은 호환되는 조건·능력을 연결하는 제한된 matching입니다. 자세한 용어는 [쉬운 용어집](../../GLOSSARY.md)을 따릅니다.

## 조건·능력 저장소(`Primitive DB`)

- `HOLD`의 미충족 조건은 REQUIRED Primitive로 저장한다.
- `TRUE`가 제공할 능력은 두 Gate를 정상 통과한 exact revision만 PROVIDED Primitive로 저장하고, 그 TRUE의 악용 선행 조건을 `required_preconditions`로 함께 고정한다.
- `FALSE`와 Gate 전·stale TRUE는 Primitive matching에 쓰지 않는다.
- match는 `workspace_id`, `commit_id`, asset, entity, endpoint, privilege, data와 공격 순서가 맞을 때만 후보가 된다.
- DB는 queue가 아니며 match는 Finding이 아니라 새 가설 후보다.

## Chaining Agent

Chaining Agent는 Gate-qualified TRUE+HOLD와 양쪽이 Gate-qualified인 TRUE+TRUE matching만 수행한다. TRUE+TRUE는 앞 PROVIDED가 뒤 TRUE의 exact `required_preconditions` 한 항목을 충족할 때만 후보가 된다. 각 parent의 current `PrimitiveIndexState`를 함께 고정하고 저장 직전에 다시 검사하므로 탐색 중 새 Verification이 생긴 오래된 결과는 `STALE_RESULT`로 버린다. match가 material하면 `HypothesisProposal(origin=CHAINING)`을 만들고 trusted validation·전역 등록 뒤 새 Verification을 배정한다.

일반 bypass·alternate path·impact 탐색, 동적 재현과 Technical `REVISE` 보완은 Verification이 담당한다. Verification에서 생긴 별도 material claim은 `origin=VERIFICATION` proposal로 등록한다. 어느 child도 부모 판정을 바꾸지 않는다.

## 끝없이 확장되지 않게 하는 제한

chain depth, 전체/parent별 가설 수, Chaining 호출·Primitive 조합, token, wall-clock, duplicate fingerprint와 cycle을 제한한다. 한도 도달은 `FALSE`가 아니며 미생성 후보와 이유를 기록한다.

상세 내용은 [Primitive DB와 Chaining](../06-chaining.md)을 따른다.
