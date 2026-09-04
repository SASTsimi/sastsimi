# ADR-010. StaticFactBundle 사실 종류별 분할과 방어 후보 의미

- 상태: `ACCEPTED`
- 결정일: 2026-09-04
- 관련 역할: R2 정적분석·컨텍스트, R4 공통 계약, R6 검증, R8 데이터·평가

## 상황

`CodeFact.fact_kind`에는 `SANITIZER`, `VALIDATOR`, `OTHER`가 있었지만 `StaticFactBundle`에는 이 사실을 담을 명시적 목록이 없었다. 도구가 찾은 사실을 버리거나 임의 목록에 섞을 수 있고, 방어 로직 후보를 안전함의 확정 근거로 오해할 위험이 있었다.

## 결정

`StaticFactBundle`에 필수 `sanitizer_candidates`, `validator_candidates`, `other_facts` 목록을 추가한다. 기존 source, sink, 인증·권한 목록과 함께 모든 `CodeFact.fact_kind`를 정확히 한 목록에만 넣고, 전체 합집합에서 `fact_id`를 유일하게 유지한다. 후보가 없으면 필드를 생략하지 않고 빈 배열을 사용한다.

sanitizer·validator는 방어 로직 후보일 뿐이다. 실제 경로 적용, 순서·조건과 우회 가능성을 R6 Verification이 확인하기 전에는 안전함, 경로 차단 또는 `FALSE`의 근거로 승격하지 않는다. 같은 위치가 여러 역할이면 역할마다 별도 사실과 ID를 만든다.

이 필드와 불변 조건은 과거 record의 허용 의미를 바꾸므로 StaticFactBundle **새 MAJOR schema**로 배포한다. 이전 record에 누락 필드를 추정해 채우지 않고 감사 이력으로만 보존한다.

## 역할별 책임

- R2: `STATIC_ANALYSIS` 신뢰 identity로 Static Fact Normalizer를 실행하고 종류에 맞는 목록, current tool attempt와 원본 결과 provenance를 가진 `StaticFactBundle`을 생산한다.
- R4: Runtime Validator에서 목록과 종류 대응, `fact_id` 유일성, exact identity·revision·producer 연결을 검사한다.
- R6: sanitizer·validator 후보가 실제 공격 경로를 막는지 검증하고 후보 존재나 부재만으로 verdict를 만들지 않는다.
- R8: `fact_kind`별 후보 수, 잘못된 목록·중복 ID·stale provenance 거절 수를 별도 지표로 집계한다.

## 결과

정적분석 결과가 정의된 모든 사실 종류를 잃지 않고 전달하며, 각 모듈이 같은 후보 의미를 사용한다. Mermaid의 단계나 Agent 연결은 바뀌지 않으므로 흐름 다이어그램 수정은 필요하지 않다.
