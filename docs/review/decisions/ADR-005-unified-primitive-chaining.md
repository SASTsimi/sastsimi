# ADR-005. 통합 Primitive와 결과→입력 Chaining

- 상태: `ACCEPTED`
- 결정일: 2026-09-03
- 기준 main: `48fc302550eeb97e77ce6b5358323ae948f22247`
- 결정 담당: PM·아키텍처·워크플로, LLM 탐색·체이닝
- 영향 역할: 검증·반박, Gate·보고서, 데이터·평가, 통합 개발
- 연결 Issue: #2, #5, #78, #79, #80
- 대체 결정: ADR-001의 Primitive 형식, Chaining admission과 체이닝 전용 제한

## Context

기존 계약은 HOLD의 필요 조건과 TRUE의 제공 능력을 서로 다른 record처럼 다루고, `TRUE_HOLD | TRUE_TRUE` 분기와 전용 index version·depth·여러 compatibility flag를 저장했습니다. Rule Scope까지 통과해야 TRUE를 체이닝에 사용할 수 있어 코드에서 확인된 기술 능력과 버그바운티 보고 가능성이 섞였습니다.

이 구조는 같은 정보를 여러 이름으로 반복하고, 저장소마다 다른 권한 체계를 하나의 전역 서열로 비교하며, 연계 공격의 계보보다 임의 깊이 숫자에 의존하는 문제가 있었습니다.

## Decision

### 1. 하나의 Primitive 형식

`Primitive`는 필요한 `inputs`, nullable `result`, 공통 `restrictions`, source Verification과 근거를 함께 저장합니다.

- final HOLD: 부족 조건을 `inputs`에 넣고 `result=null`
- final TRUE: validated PoC와 exact Technical `ACCEPT`, 같은 chain의 Rule Scope `testing_restriction=PASS` 뒤 제공 능력 하나마다 `result`가 있는 Primitive 하나 생성
- TRUE Primitive의 각 record는 같은 TRUE의 `inputs`와 `restrictions`를 함께 보존
- `REQUIRED | PROVIDED`, `status`, `match_kind`는 저장하지 않고 `result` 유무와 부모 verdict에서 계산

`PrimitiveDraft`는 `draft_id`, `entity_refs`, nullable `privilege_level`, `evidence_refs`, `description`만 가집니다. `privilege_level`은 전역 서열이 아니라 분석 중인 저장소의 역할·권한 상수와 실제 검사 위치를 근거로 해석합니다.

### 2. 결과→입력 matching

`PrimitiveMatchCandidate`는 upstream Primitive의 하나뿐인 `result`가 downstream Primitive의 `inputs` 중 `matched_input_id`를 충족하는지 나타냅니다. 양쪽 Primitive record, 부모 가설·Verification, workspace·commit, fingerprint와 실제 근거를 고정하며 상태는 항상 `UNVALIDATED`입니다.

의미 있는 후보는 `HypothesisProposal(origin=CHAINING)`을 만들고 trusted validation·전역 등록 뒤 전체 Verification을 다시 거칩니다. 새 가설은 `source_primitive_match_id`로 자신을 만든 COMMITTED match를 정확히 가리킵니다.

### 3. Technical integrity와 Rule Scope testing restriction 분리

validated PoC가 있는 final TRUE가 exact Technical `ACCEPT`을 받은 뒤 Rule Scope Impact Gate가 실제 수행 행위와 공식 정책을 비교해 `testing_restriction=PASS`로 판정해야 result Primitive와 Chaining 자격을 얻습니다. `FAIL`은 admission을 차단하고 `UNCERTAIN`은 재판정까지 보류합니다. 다른 Rule·Scope·Impact/report eligibility 실패는 현재 Reporter만 막습니다.

Technical Gate는 verdict·근거 연결과 실제 코드 경로·restrictions의 기술적 정확성 및 evidence integrity를 검토합니다. 공식 정책상 금지 테스트 여부는 Rule Scope Gate가 판정합니다.

### 4. 계보 기반 순환 방지와 전역 예산

별도 `root_hypothesis_id`, `chain_depth`와 체이닝 전용 임의 depth·hypothesis·call·combination 한도를 제거합니다. 현재 가설의 `parent_hypothesis_ids`와 `source_primitive_match_id`를 따라 조상 Primitive를 계산하고, 이들을 현재 순회의 후보에서 제외해 순환을 막습니다.

시간·비용·작업 수 제한은 R8의 전역 예산 정책과 Runtime Validator가 강제합니다. token은 사용량만 관측하며 계획값 초과·누락만으로 체이닝을 중단하지 않습니다. 중복 fingerprint, ancestor 재사용 제외 또는 전역 예산 중단은 취약점 `FALSE`가 아닙니다.

### 5. revision 안전성

Primitive 전용 `state_version`과 전용 commit-time CAS 필드는 제거합니다. 다만 모든 결과에 적용되는 불변 `RecordMeta.revision_number`, `previous_record_id`, exact `StoredDataRef`와 원자적 current pointer 갱신은 유지합니다. 이는 체이닝 정책이 아니라 병렬 저장에서 오래된 결과나 lost update를 막는 공통 안전 규칙입니다.

## Compatibility

기존 Primitive와 가설·Chaining schema의 의미가 바뀌므로 새 MAJOR schema입니다. `HeldHypothesis`, `ConfirmedCapability`, `required_preconditions`, `root_hypothesis_id`, `chain_depth`, 전용 match flag와 bounded stop 필드는 새 운영 record에서 읽거나 자동 변환하지 않습니다. 과거 record는 감사 이력으로만 보존합니다.

## Verification

- 정본과 Wiki의 Mermaid block은 같은 수와 같은 내용이어야 합니다.
- schema block에는 새 필수 필드가 모두 있고 제거 필드가 없어야 합니다.
- final HOLD, Technical-accepted + testing-restriction-PASS TRUE, testing restriction FAIL/UNCERTAIN, report-only eligibility 실패, stale revision, ancestor 재사용 제외와 전역 예산 중단 시나리오를 문서 검사로 확인합니다.
