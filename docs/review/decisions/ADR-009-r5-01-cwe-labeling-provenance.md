# ADR-009. R5-01 CWE labeling 소유권과 Verification provenance

- 상태: `ACCEPTED`
- 결정일: 2026-09-04
- 결정 담당: R4 PM·아키텍처·공통 계약, R5 Gate·Finding·보고서
- 필수 확인 역할: R3 통합 개발, R5-01, R6 검증·반박

## 쉽게 설명하면

CWE 번호가 같더라도 검증 결과가 새로 바뀌면 예전 CWELabel을 그대로 붙이지 않습니다. R5-01이 새 검증 결과를 다시 읽고, 그 결과를 직접 가리키는 새 label 수정본을 만든 뒤 Technical Gate가 검토합니다.

## 결정

1. `CWELabel`의 logical producer/runtime role은 `CWE_LABELING`, 실제 R1~R8 owner는 R5-01이다.
2. `CWE_LABEL`은 이 역할을 실행하는 `WorkExecutionState.work_type`이다.
3. 흐름은 `final TRUE Verification -> R5-01 CWE_LABELING -> current CWELabel -> Technical Gate`다.
4. `CWELabel`은 exact `verification_result_ref`, `verification_generation`, `cwe_labeling_work_id`, `llm_call_id`를 필수로 가진다.
5. current label은 current final TRUE를 입력으로 가진 유일한 `CWE_LABEL` work가 성공하고 그 work의 유일한 output이 가리키는 revision이다.
6. 새 Verification revision 또는 generation마다 CWE 정렬을 다시 평가한다. 값이 같아도 새 label revision을 만든다.
7. 같은 가설의 과거 label은 같은 `logical_record_id`의 immutable history로 보존하고 새 Verification의 current input으로 재사용하지 않는다.
8. Technical Gate는 Verification과 label의 exact pair와 의미 정렬을 검토할 뿐 label을 생성·수정·덮어쓰지 않는다.
9. CWE labeling 실패·timeout·인증 오류는 Verification을 `FALSE | HOLD`로 바꾸지 않으며 current label이 없으면 Technical Gate를 호출하지 않는다.

## Runtime Validator 조건

- `result_kind=cwe_label`은 R5-01 `CWE_LABELING`만 저장한다.
- candidate가 가리키는 Verification은 current final TRUE이며 process state·부모 Verification work와 generation이 같아야 한다.
- label의 work, attempt, 성공 invocation과 evidence closure가 current exact input에 연결되어야 한다.
- `(analysis_id, hypothesis_id, verification_generation, verification_result_ref.record_id, work_type=CWE_LABEL)`당 work와 COMMITTED output은 하나다.
- Technical Gate의 `verification_result_ref`와 `CWELabel.verification_result_ref`가 다르면 `STALE_RESULT | RECORD_REVISION_MISMATCH`로 차단한다.

## 상태 객체 선택

별도 `CWELabelingState`와 `HypothesisProcessState.cwe_label_ref`는 만들지 않는다. 기존 `CWE_LABEL` work의 unique key, 성공 상태와 유일한 output reference가 current label을 결정하므로 중복 상태와 불일치 가능성을 늘리지 않는다.

## 검증 조건

- 정본, Wiki, Mermaid와 governance가 같은 생산자·소유자·순서를 설명함
- 새 Verification 뒤 동일 CWE 값의 새 label revision도 허용·요구함
- 과거 label, 다른 generation·가설·commit label과 실패한 work output을 Gate가 거절함
- Technical Gate가 CWE 생산 권한을 갖지 않음
