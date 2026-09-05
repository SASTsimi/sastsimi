# ADR-011. 금지 테스트 위반과 Primitive 체이닝 자격 분리

- 상태: `ACCEPTED`
- 결정일: 2026-09-05
- 기준 main: `f0aa79c485a17d9e7ee2f54002ad33fcf537dbe9`
- 결정 담당: PM·아키텍처·워크플로(R4)
- 함께 검토할 역할: LLM 탐색·체이닝(R1), Gate·Finding·보고서(R5-02)
- 연결 Issue/PR: #2, #5, PR #52, PR #88
- 반영 commit: `docs: define prohibited-testing primitive admission contract`

## Context

Technical Gate는 Verification과 CWELabel만 읽으므로 공식 프로그램 정책의 금지 테스트 방법을 판단할 수 없습니다. Rule Scope Gate는 공식 정책을 읽지만 기존 `rule_compliance` 하나로는 일반 규칙 실패와 금지 테스트 위반을 안전하게 구분할 수 없습니다.

또한 Technical `ACCEPT` 직후 Primitive를 체이닝에 넣으면 Rule Scope 결과가 늦게 도착했을 때 금지 테스트로 얻은 근거가 이미 새 가설에 사용될 수 있습니다. 정확한 판정과 사용 근거를 별도 record로 연결해야 합니다.

## Options

### 1. `rule_compliance=FAIL`과 `TESTING_RESTRICTION` link 존재만 검사

link는 테스트 제한을 단순 비교한 경우에도 존재할 수 있고 자체 판정값이 없습니다. 다른 규칙 실패를 금지 테스트 위반으로 잘못 해석할 수 있어 선택하지 않습니다.

### 2. 모든 Rule Scope 실패를 체이닝에서 제외

범위 밖이나 보상 대상이 아닌 현재 능력이 다른 in-scope 연계 취약점의 발판이 될 수 있습니다. 미탐 가능성이 커져 선택하지 않습니다.

### 3. 테스트 제한 전용 판정과 별도 admission decision 사용

Rule Scope Gate는 정책 의미를 판단하고, 신뢰 Runtime은 그 구조화된 결과만 정해진 표에 대입합니다. 일반 정책 판단과 체이닝 자격을 분리하면서 exact provenance와 늦은 변경 차단을 함께 구현할 수 있어 이 방식을 선택합니다.

## Decision

`RuleScopeImpactReview`에 전용 `testing_restriction_compliance` 필드를 추가하며 허용 값은 `PASS | FAIL | UNCERTAIN`입니다. 이 값은 `rule_compliance`와 독립적입니다.

`PrimitiveAdmissionDecision`은 다음 exact reference를 묶습니다.

- final TRUE `VerificationResult`
- 이를 검토한 Technical `ACCEPT`
- `PolicyCollectionResult`
- 존재하는 current `RuleScopeImpactReview`
- 테스트 제한 판정과 최종 `ALLOW | DENY`

`PRIMITIVE_ADMISSION_RUNTIME`은 LLM Agent가 아닙니다. 정책을 해석하지 않고 다음 규칙만 적용합니다.

- 테스트 제한 `PASS`: `ALLOW`
- 테스트 제한 `UNCERTAIN`: `ALLOW`
- 테스트 제한 `FAIL`: `DENY`
- `COLLECTION_FAILED`: Rule Scope review 없이 `NOT_EVALUATED + ALLOW`

마지막 규칙은 확정된 위반만 체이닝을 차단한다는 현재 정책을 따릅니다. 수집 실패와 오류는 그대로 보존하며 Reporter는 계속 차단됩니다.

result Primitive는 current `PrimitiveAdmissionDecision(decision=ALLOW)`을 exact하게 참조해야 합니다. `DENY`이면 새 result Primitive를 만들지 않습니다. `ChainingResult.source_admission_refs`는 실제 match Primitive에서 직접 또는 부모 match를 따라 재귀적으로 도달하는 모든 result Primitive의 current ALLOW decision을 고정합니다.

이후 decision이 `DENY`로 바뀌면 과거 Primitive는 감사 이력으로 남기되 current index에서 제거하고, 실제 match가 과거 decision을 사용한 진행 중 Chaining 결과도 `STALE_RESULT`로 거절합니다. 이미 자식·손자 결과가 만들어졌다면 `source_admission_refs`와 `source_primitive_match_id` 계보를 따라 파생 Primitive를 current index에서 제거하고 새 Verification·Gate·Primitive·Reporter 입력으로 쓰지 않습니다. 과거 verdict와 결과 자체는 감사 이력으로 보존하며 `FALSE | HOLD`로 바꾸지 않습니다.

## Responsibility

- R1: PR #88에서 Chaining 후보 조회와 저장이 current ALLOW decision과 실제 match의 direct·ancestor `source_admission_refs`만 사용하도록 반영합니다.
- R4: schema, result owner, exact reference, atomic 저장, stale 차단과 실패 시나리오를 유지합니다.
- R5-02: Rule Scope Gate 출력에 독립 테스트 제한 판정과 근거·누락 조건을 반영합니다.

## Compatibility

`RuleScopeImpactReview.testing_restriction_compliance`, `PrimitiveAdmissionDecision`, `Primitive.admission_decision_ref`, `ChainingResult.source_admission_refs`는 기존 필수 형식을 바꾸므로 새 MAJOR schema입니다. 이전 review의 문자열, `rule_compliance` 또는 link 존재만 보고 새 판정을 추정하지 않습니다. 이전 Primitive와 ChainingResult도 새 decision·계보 reference를 사후 추정해 체이닝 입력으로 자동 승격하지 않습니다.

## Verification

- 다른 규칙만 실패하고 테스트 제한이 PASS이면 admission을 허용합니다.
- 테스트 제한이 FAIL이면 admission을 거절합니다.
- 전용 판정과 `TESTING_RESTRICTION` 근거 또는 누락 구조가 모순되면 저장을 거절합니다.
- 정책 수집 실패는 `NOT_EVALUATED`로 구분하며 금지 위반이나 정책 부재로 바꾸지 않습니다.
- 다른 Verification·정책 revision의 decision을 Primitive에 연결하면 저장을 거절합니다.
- current decision이 바뀐 뒤 이전 decision을 사용하는 Chaining 결과를 거절합니다.
- 이미 생성된 child·descendant도 direct·ancestor admission 계보가 current ALLOW인지 새 downstream 작업 전에 다시 확인합니다.
