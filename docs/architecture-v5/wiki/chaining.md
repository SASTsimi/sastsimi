# Primitive DB, Research와 chaining

## Primitive DB

- `HOLD`의 미충족 조건은 REQUIRED Primitive로 저장한다.
- `TRUE`가 제공하는 검증된 능력은 PROVIDED Primitive로 저장한다.
- match는 snapshot, asset, entity, privilege와 공격 순서가 호환될 때만 후보가 된다.
- DB는 queue가 아니며 match는 Finding이 아니라 새 가설 후보다.

## Research Agent

Research는 TRUE, HOLD, Technical Gate 보완 요청, 낮은 impact 확장 후보와 Primitive match에서 우회·alternate path·impact·chain을 조사한다. material claim은 Orchestration으로 돌아가 전체 검증을 새로 거친다.

Research는 기존 verdict, CWE, Gate 결과, Finding과 보고서를 확정하지 못한다. 의미 있는 확장이 없으면 그 이유를 남긴다.

## 제한

chain depth, 전체/parent별 가설 수, Research 호출, token, sandbox와 wall-clock, duplicate fingerprint와 cycle을 제한한다. 한도 도달은 `FALSE`가 아니며 미생성 후보와 이유를 기록한다.

상세 내용은 [Primitive DB, Research와 chaining](../06-chaining.md)을 따른다.
