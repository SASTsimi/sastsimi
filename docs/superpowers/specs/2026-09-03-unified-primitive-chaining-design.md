# Unified Primitive Chaining Design

## Goal

HOLD의 부족 조건과 TRUE의 확인된 능력을 서로 다른 상태·보조 객체로 관리하지 않고, `inputs + result + restrictions`라는 하나의 `Primitive` 구조로 표현한다. 체이닝은 확인된 result가 다른 Primitive의 input을 실제 코드 근거로 충족할 때만 새 가설을 만든다.

## Scope

- `Primitive`, `PrimitiveDraft`, `PrimitiveIndexState`, `PrimitiveMatchCandidate`, `ChainingResult` 재구성
- `HeldHypothesis`, `ConfirmedCapability` 제거
- `HypothesisProposal`, `VulnerabilityHypothesis` 계보 필드 단순화
- TRUE 재료 자격을 final TRUE + Technical `ACCEPT`로 변경
- Rule Scope Gate를 보고서 제출 가능성 판단으로 한정
- 체이닝 전용 depth/count/call/combination 한도 제거, R8 공통 예산과 순환 제외 유지
- 정본·Wiki·Mermaid·governance·review·validator 동기화

## Unified Primitive

`Primitive.inputs`는 능력을 사용하거나 HOLD를 해소하기 위해 필요한 조건이다. `Primitive.result`는 이 Primitive가 제공하는 확인된 능력이며, HOLD에서 `null`, TRUE에서 필수다. `Primitive.restrictions`는 새 가설에도 승계해야 할 제약이다.

- final HOLD: `inputs`에 `required_primitive_candidates`, `result=null`, `technical_review_ref=null`
- final TRUE + Technical `ACCEPT`: `inputs`에 `required_primitive_candidates`, `result`에 제공 능력 하나, exact Technical review 필수
- final FALSE, Gate 전 TRUE, Technical `REVISE | REJECT`: Primitive 없음
- final TRUE는 기존 계약대로 current generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 validated PoC를 가져야 한다.

한 TRUE가 제공 능력을 여러 개 만들면 제공 능력마다 Primitive 하나를 만든다. 각 Primitive는 같은 TRUE의 inputs와 restrictions를 복사하고 서로 다른 result를 갖는다. HOLD는 required candidate가 하나 이상일 때 하나의 Primitive로 저장한다.

## Matching

`PrimitiveMatchCandidate.upstream_result_ref`와 `downstream_input_ref`는 각각 result가 있는 upstream Primitive record와 input을 가진 downstream Primitive record를 가리킨다. `matched_input_id`는 downstream `inputs[].draft_id` 하나를 정확히 선택한다.

후보는 다음 조건을 모두 만족할 때만 존재한다.

- 두 Primitive의 `workspace_id`와 `commit_id`가 같다.
- upstream `result.entity_refs`와 downstream input `entity_refs`의 동일성 또는 연결 관계가 코드 근거로 확인된다.
- 권한 조건이 있으면 저장소의 역할명·권한 상수·검사 위치로 충족 관계가 입증된다. 전역 권한 서열표는 사용하지 않는다.
- 결합 순서와 양쪽 restrictions를 함께 적용해도 경로가 성립한다.
- 비교 근거가 하나 이상 존재한다.
- 같은 fingerprint 중복이나 ancestor Primitive 재사용 순환이 아니다.

축이 맞지 않거나 근거가 없으면 `UNCERTAIN` 후보를 저장하지 않고 `no_match_reasons`에 이유를 남긴다. downstream `result=null`이면 TRUE+HOLD, result가 있으면 TRUE+TRUE로 유도하므로 `match_kind`는 저장하지 않는다.

## Lineage and cycle prevention

`root_hypothesis_id`와 `chain_depth`를 제거하고 직접 부모인 `parent_hypothesis_ids`만 유지한다. Chaining-origin proposal과 hypothesis는 `source_primitive_match_id`로 자신을 만든 match candidate를 가리킨다. 이 ID는 분석 전체에서 유일하며 COMMITTED `ChainingResult` 안의 후보 하나로 해석되어야 한다.

순환 검사는 현재 parent hypothesis에서 `source_primitive_match_id`를 따라 조상 match와 입력 Primitive를 역방향으로 걷는다. 이 과정에서 만난 Primitive는 현재 순회의 후보에서 제외한다. DB record를 수정하지 않는다. 체이닝 전용 임의 depth·가설 수·호출 수·조합 수 한도는 두지 않지만, R8의 전체 token·시간·비용·work 예산은 모든 체이닝에도 적용한다.

## Primitive index and concurrency

`PrimitiveIndexState`는 가설별 current Verification과 그 결과에서 admission된 Primitive reference 목록만 가진다. 별도 `state_version`, REQUIRED/PROVIDED 분리 목록과 Primitive eligibility는 제거한다.

동시 갱신 손실을 막기 위해 공통 immutable record 규칙은 유지한다. 새 index revision은 직전 `record_id`와 연속된 `revision_number`를 사용하고, current pointer 갱신은 atomic하게 수행한다. 이는 제거된 Primitive 전용 commit-time Chaining CAS나 사후 supersede lifecycle이 아니라 저장소 전체에 적용되는 공통 revision 안전 규칙이다.

## Gate boundary

Primitive의 기술적 자격은 final TRUE + exact Technical `ACCEPT`로 결정한다. Technical Gate는 validated PoC 연결, 금지된 재현으로 오염되지 않은 근거, 실제 경로·제약 표현의 정확성을 검토한다. Rule Scope Gate는 프로그램 정책, 제출 범위, 중복과 보고 가능성만 검토하며 Primitive admission이나 Chaining 입력 자격을 취소하지 않는다.

따라서 Technical `ACCEPT` 뒤 Primitive admission/Chaining과 Rule Scope/Reporter 경로는 독립적으로 진행할 수 있다. Rule Scope가 `FAIL | UNCERTAIN | DENY`여도 보고서는 차단하지만 이미 확인된 코드 능력은 체이닝 재료로 남는다.

## Compatibility

변경된 record는 새 MAJOR schema다. 기존 REQUIRED/PROVIDED Primitive, HeldHypothesis, ConfirmedCapability, match check/status와 index CAS 필드를 새 구조로 자동 승격하지 않는다. 기존 ADR-001은 기록으로 보존하고 새 ADR이 대체한다.

## Validation

- 활성 계약에서 제거된 객체·필드 0건
- HOLD와 Technical-accepted TRUE admission 시나리오 통과
- Rule Scope 실패가 보고만 차단하고 체이닝은 유지
- entity·privilege 근거 없는 match 저장 차단
- ancestor Primitive 재사용 순환 차단
- Chaining-origin proposal의 match lineage 검증
- 정본과 Wiki Mermaid 블록 일치
- 전체 architecture validator 실패 0건
