# Primitive DB, Research와 chaining

## 쉽게 말하면

보류된 가설에 부족한 조건과 이미 확인된 공격 능력을 비교해 서로 연결될 가능성을 찾습니다. 연결되더라도 바로 확정하지 않고 새로운 가설로 처음부터 검증합니다.

**상세 기준:** [06. Primitive DB, Research와 chaining](../06-chaining.md)

`Primitive`는 연계 공격의 필요 조건 또는 확인된 능력이고 `Research`는 추가 탐색입니다. 자세한 용어는 [쉬운 용어집](../../GLOSSARY.md)을 따릅니다.

## 조건·능력 저장소(`Primitive DB`)

- `HOLD`의 미충족 조건은 REQUIRED Primitive로 저장한다.
- `TRUE`가 제공하는 검증된 능력은 PROVIDED Primitive로 저장한다.
- match는 `workspace_id`, `commit_id`, asset, entity, privilege와 공격 순서가 맞을 때만 후보가 된다.
- DB는 queue가 아니며 match는 Finding이 아니라 새 가설 후보다.

## 추가 탐색(`Research`) Agent

Research는 TRUE, HOLD, Technical Gate 보완 요청, 낮은 impact 확장 후보와 Primitive match에서 우회·alternate path·impact·chain을 조사한다. material claim은 Orchestration으로 돌아가 전체 검증을 새로 거친다.

Research는 기존 verdict, CWE, Gate 결과, Finding과 보고서를 확정하지 못한다. 의미 있는 확장이 없으면 그 이유를 남긴다.

## 끝없이 확장되지 않게 하는 제한

chain depth, 전체/parent별 가설 수, Research 호출, token, sandbox와 wall-clock, duplicate fingerprint와 cycle을 제한한다. 한도 도달은 `FALSE`가 아니며 미생성 후보와 이유를 기록한다.

상세 내용은 [Primitive DB, Research와 chaining](../06-chaining.md)을 따른다.
