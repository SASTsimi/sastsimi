# R5-01 CWE labeling 소유권과 provenance 설계

## 목표

final `VerificationResult.verdict=TRUE`가 만들어진 뒤 R5-01 `CWE_LABELING`이 별도 `CWE_LABEL` work에서 현재 `CWELabel`을 만들고, Technical Gate가 정확히 같은 Verification과 label 한 쌍만 읽도록 공통 계약을 고정한다.

## 역할 경계

- R6 Verification은 final `VerificationResult`를 생산한다.
- R5-01 `CWE_LABELING`은 final TRUE를 입력으로 CWE 정렬을 평가하고 `CWELabel`을 생산한다.
- Technical Evidence Gate는 label과 Verification의 근거 정렬을 검토하지만 label을 만들거나 수정하지 않는다.
- 비-LLM Runtime Validator는 생산 역할, 정확한 revision 연결, work 상태와 stale 여부만 검사하고 CWE 의미를 대신 판단하지 않는다.

`CWE_LABELING`은 logical producer와 Agent/runtime role 이름이다. `CWE_LABEL`은 `WorkExecutionState.work_type` 값이다. R1~R8 업무 소유권은 R5-01이다.

## 데이터 계약

`CWELabel`은 다음 provenance를 필수로 가진다.

- `verification_result_ref`: 이 label이 분류한 exact final TRUE `VerificationResult` revision
- `verification_generation`: 해당 가설의 Verification generation
- `cwe_labeling_work_id`: label을 생산한 `CWE_LABEL` work
- `llm_call_id`: label을 만든 성공한 `CWE_LABELING` 호출

`RecordMeta.attempt_id`는 해당 work의 성공 attempt와 같아야 한다. label의 `evidence_refs`는 `verification_result_ref`가 가리키는 Verification과 그 transitive evidence closure 안에서만 선택한다.

## lifecycle과 current 판정

1. final TRUE Verification을 atomic commit한다.
2. `(analysis_id, hypothesis_id, verification_generation, verification_result_ref.record_id, work_type=CWE_LABEL)`을 기준으로 CWE work를 하나 등록한다.
3. R5-01 `CWE_LABELING`이 분류하고 Runtime Validator가 저장 후보를 검사한다.
4. CWE work가 `SUCCEEDED`이고 `output_refs`가 exact `CWELabel` 한 개를 가리킬 때 그 label을 현재 label로 인정한다.
5. Technical Gate는 현재 final TRUE와 그 Verification을 직접 가리키는 현재 label만 입력으로 받는다.

별도 `CWELabelingState`나 `HypothesisProcessState.cwe_label_ref`는 추가하지 않는다. 기존 `WorkExecutionState`의 unique work와 exact output이 current pointer 역할을 충분히 수행하므로 중복 상태를 만들지 않는다.

## 새 Verification 처리

Technical `REVISE`나 다른 허용 흐름으로 새 Verification revision 또는 generation이 생기면 새 `CWE_LABEL` work를 실행한다. CWE 번호와 설명이 이전과 같아도 이전 `CWELabel.record_id`를 그대로 쓰지 않고, 새 Verification을 가리키는 새 label revision을 만든다.

같은 가설의 label revision은 같은 `logical_record_id`를 유지하고 새 `record_id`, 증가한 `revision_number`, 직전 label을 가리키는 `previous_record_id`로 연결한다. 과거 label과 Gate 결과는 감사 이력으로 보존하지만 current 입력으로 사용하지 않는다.

## 실패와 차단

- final verdict가 `FALSE | HOLD`이면 Gate용 `CWE_LABEL` work와 `CWELabel`을 만들지 않는다.
- CWE labeling 실패·timeout·provider 인증 오류를 Verification `FALSE | HOLD`로 바꾸지 않는다.
- CWE work가 성공하지 않았거나 current label이 없으면 Technical Gate 호출을 차단한다.
- label의 Verification reference, generation, work, attempt, invocation 또는 evidence closure가 맞지 않으면 저장하지 않고 기존 공통 오류 계약에 따라 격리한다.
- 새 Verification에 이전 label을 붙이면 `STALE_RESULT | RECORD_REVISION_MISMATCH`로 거절한다.

## 문서와 검증 범위

Architecture 정본, Wiki, Mermaid, 결과·보안 경계, governance, 역할별 Issue 안내와 자동 검증 스크립트가 같은 역할·순서·필드·stale 규칙을 설명해야 한다. R5-01 브랜치를 병합할 때 현재 main의 R7/R1 계약과 이름을 되돌리지 않는다.
