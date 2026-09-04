# R6–R7 PoC 필수화와 생산 권한 변경 설계

## 상태

- 승인일: 2026-09-03
- 승인 근거: 사용자가 R6 요청사항을 제시하고 이 설계 방향의 직접 반영을 승인함
- 대상: Architecture v5 공통 계약, R6 Verification, R7 동적 재현, Technical Gate

## 목표

모든 최종 `TRUE`가 실제 Sandbox 실행으로 검증된 PoC를 갖도록 강제한다. R6는 재현 목적과 필요한 사실을 요청하고, R7은 환경 요구사항·실행 계획·PoC 후보·동적 결과를 생산한다. PoC 생성이나 실행 자체의 실패는 취약점 `FALSE | HOLD`로 바꾸지 않는다.

## 유지하는 범위

- 정적 사실 계층, 운영 Pro/Con 독립 실행과 합류 규칙
- Verification이 최종 `TRUE | FALSE | HOLD`를 판정하는 권한
- R7 Sandbox Controller의 세부 정책 검사와 Runner의 격리 실행
- exact revision, Runtime Validator, atomic commit, retry·복구 규칙
- HOLD REQUIRED와 Gate-qualified TRUE PROVIDED Chaining 규칙
- Technical Gate `REVISE`가 같은 Verification owner의 새 generation으로 돌아가는 규칙

## 핵심 흐름

1. R6가 정적·Pro·Con 근거를 종합한다.
2. 근거만으로 가설이 반증되거나 HOLD가 충분히 설명되면 PoC 없이 final `FALSE | HOLD`를 만들 수 있다.
3. initial TRUE이면 R6가 `purpose=POC_CONFIRMATION`인 `DynamicReproductionRequest`를 만든다.
4. 최종 판정에 동적 근거가 필요하면 R6가 `purpose=VERDICT_EVIDENCE`인 요청을 만든다.
5. 한 Verification generation에는 두 purpose 중 정확히 하나를 가진 동적 work를 최대 하나만 등록한다.
6. R7은 요청을 바꾸지 않고 `EnvironmentRequirements`, `ReproductionPlan`, PoC candidate를 만든 뒤 Sandbox에서 실행한다.
7. 실행 결과를 R6가 소비한다.
   - `SUCCEEDED + SUPPORTED + validated poc_ref`: final `TRUE`
   - 정상 관측의 `DISPROVED`: final `FALSE`
   - 정상 실행 또는 신뢰 가능한 부분 실행의 `INCONCLUSIVE`: final `HOLD`
   - 생성·설정·실행 자체의 실패: final verdict 없음, work `BLOCKED | FAILED`
8. final `TRUE`와 validated `poc_ref`가 같은 exact 동적 결과를 가리킬 때만 CWE와 Technical Gate로 보낸다.

`POC_CONFIRMATION`에서 initial TRUE와 다른 관측이 나와도 initial 판단을 유지하지 않는다. 실제 반증은 `FALSE`, 정상 관측이 있으나 결론이 부족하면 `HOLD`, 실행 자체가 실패했다면 verdict 없이 대기 또는 실패한다.

## R6 → R7 요청 계약

새 공통 record `DynamicReproductionRequest`를 사용한다.

```yaml
DynamicReproductionRequest:
  meta: RecordMeta
  verification_assignment_ref: StoredDataRef
  verification_generation: integer
  hypothesis_ref: StoredDataRef
  purpose: POC_CONFIRMATION | VERDICT_EVIDENCE
  initial_verdict: TRUE | HOLD
  goal: string
  environment_needs: [EnvironmentNeed]
  sandbox_profile_ref: StoredDataRef
  code_refs: [StoredDataRef]
  static_evidence_refs: [StoredDataRef]
  pro_evidence_ref: StoredDataRef
  con_evidence_ref: StoredDataRef
  created_at: timestamp
```

- `POC_CONFIRMATION`은 `initial_verdict=TRUE`만 허용한다.
- `VERDICT_EVIDENCE`는 아직 결론이 부족한 `initial_verdict=HOLD`를 사용한다.
- `goal`은 무엇이 관측되면 지지·반증·불충분인지 설명한다.
- `environment_needs`는 R6가 알고 있는 애플리케이션 조건이다. R7은 이를 빠뜨리거나 약화하지 않고 실행 가능한 `EnvironmentRequirements`로 구체화한다.
- production에서는 exact Pro·Con reference가 필수다.
- `sandbox_profile_ref`는 R6가 전달한 exact 안전 profile이며 R7이 다른 profile로 바꾸지 않는다.

R6는 `EnvironmentRequirements`, `ReproductionPlan`, PoC candidate 또는 `DynamicReproductionResult`를 저장하지 않는다.

## R7 생산 계약

- `EnvironmentRequirements.request_ref`는 exact `DynamicReproductionRequest`를 가리킨다.
- `ReproductionPlan.request_ref`와 `purpose`는 같은 요청과 일치한다.
- `ReproductionPlan.mode=LIMITED_REPRO | FULL_REPRO`는 R7이 목표에 맞춰 선택한다.
- `ReproductionPlan.sandbox_profile_ref`는 요청 값을 그대로 사용한다.
- `ReproductionPlan.poc_candidate_ref`는 실행 전 PoC 스크립트·요청·입력 묶음의 exact reference다.
- `DynamicReproductionResult.request_ref`, `reproduction_plan_ref`, `purpose`, `poc_candidate_ref`는 같은 실행 closure를 가리킨다.

R7은 환경·계획·PoC를 만들 수 있지만 가설 verdict, CWE, Gate 결과는 만들지 않는다.

## PoC 후보와 validated PoC

- `poc_candidate_ref`: 실행 전 작성했거나 실패한 시도에서 사용한 스크립트·요청·입력. 성공을 뜻하지 않는다.
- `poc_ref`: 실제 Sandbox 실행이 취약점을 재현해 `status=SUCCEEDED`와 `hypothesis_outcome=SUPPORTED`를 만든 경우에만 존재하는 validated PoC.

다음 규칙을 강제한다.

- 생성 실패: candidate와 validated `poc_ref` 모두 `null`일 수 있다.
- candidate 생성 후 실행 실패: `poc_candidate_ref`는 보존하고 `poc_ref=null`이다.
- `DISPROVED | INCONCLUSIVE`: `poc_ref=null`이다.
- `SUCCEEDED + SUPPORTED`: `poc_candidate_ref`와 validated `poc_ref`가 모두 필수이며 실행 log가 같은 candidate revision 또는 digest를 가리킨다.
- 실패한 candidate와 입력은 결과·attempt log에 보존하지만 Finding, Gate, Reporter에서 validated PoC로 사용하지 않는다.

## 한 generation의 동적 work 제한

- unique key는 `analysis_id + hypothesis_id + verification_generation + work_type=DYNAMIC_REPRO`다.
- 한 generation에는 `POC_CONFIRMATION | VERDICT_EVIDENCE` 중 하나의 request와 동적 work만 등록한다.
- retry, 외부 설정 대기와 복구는 같은 `work_id`에서 새 `attempt_id`로 처리한다.
- 요청의 purpose·goal·가설·profile을 바꾸어 같은 work를 재사용하지 않는다.
- Technical `REVISE`는 새 Verification generation이므로 새 한도를 적용한다. 새 final TRUE는 그 generation의 동적 결과와 validated PoC를 다시 가져야 한다.

## 실패와 복구

- PoC 생성·환경 설정·실행 실패가 재시도 가능하면 attempt 실패를 보존하고 동적 work를 `BLOCKED`로 둔다.
- 외부 설정이나 환경 수정이 필요해도 `BLOCKED`이며, 설정이 바뀐 뒤 같은 work의 새 attempt를 시작한다.
- 복구 불가능하거나 retry 한도를 소진하면 동적 work와 현재 Verification을 `FAILED`로 끝낸다.
- 이 경우 final `VerificationResult`와 validated `poc_ref`를 만들지 않고 Gate를 호출하지 않는다.
- 오류를 `FALSE | HOLD`로 변환하지 않는다.

실패 attempt의 `DynamicReproductionResult`는 디버깅 기록으로 저장할 수 있다. 다만 R6가 verdict를 만드는 final 동적 결과로 사용할 수 없으며, pre-run 생성 실패로 결과를 조립할 수 없는 경우에는 `dynamic_result_ref=null`과 exact error·attempt reference를 유지한다.

## Action과 생산 권한

- `REQUEST_DYNAMIC_REPRO`: R6 Verification만 요청한다. exact request와 generation별 단일 work 제한을 검사한다.
- `RUN_SANDBOX`: R7 `SANDBOX`만 요청한다. exact request·requirements·plan·candidate·profile을 검사한다.
- R7의 계획·PoC candidate 생성에 LLM이 필요하면 `SANDBOX`의 `CALL_LLM`을 DYNAMIC_REPRO work 안에서만 허용한다.
- registry owner:
  - `dynamic_reproduction_request -> DynamicReproductionRequest -> VERIFICATION`
  - `environment_requirements -> EnvironmentRequirements -> SANDBOX`
  - `reproduction_plan -> ReproductionPlan -> SANDBOX`
  - `dynamic_reproduction_result -> DynamicReproductionResult -> SANDBOX`

## VerificationResult와 Gate 조건

`VerificationResult.dynamic_decision`은 제거한다. 대신 다음 exact reference를 사용한다.

- `dynamic_request_ref: StoredDataRef | null`
- `dynamic_result_ref: StoredDataRef | null`
- `poc_ref: StoredDataRef | null`

final `TRUE`는 세 reference가 모두 필수다. request와 result는 current Verification generation에 속해야 하며, result는 `SUCCEEDED + SUPPORTED`, `poc_ref`는 result의 validated PoC와 exact match여야 한다.

`CALL_TECHNICAL_GATE`도 같은 조건을 호출 직전에 다시 검사한다. PoC 없는 TRUE, candidate만 있는 TRUE, 다른 generation의 PoC, 실패·차단·불충분 결과를 붙인 TRUE는 `SCHEMA | REVISION | GATE_ORDER` 실패로 저장·호출하지 않는다.

## 문서와 결정 기록

- Architecture v5 정본, root/v5 README, Wiki와 13개 Mermaid를 같은 흐름으로 맞춘다.
- R4/R6/R7 ownership, review checklist와 Issue catalog를 새 생산자 기준으로 바꾼다.
- 기존 ADR-003은 역사 보존을 위해 `SUPERSEDED`로 표시한다.
- 새 ADR은 R6 request/R7 production, PoC 후보·검증 구분과 TRUE Gate 조건을 정본 결정으로 기록한다.
- 검증 스크립트가 새 schema·소유권·상태 조합·negative scenario와 제거된 표현을 검사하게 한다.

## 검증 시나리오

1. initial TRUE → `POC_CONFIRMATION` → 성공·SUPPORTED·validated PoC → final TRUE → Technical Gate
2. initial TRUE → candidate 생성 실패 → BLOCKED retry → 성공
3. initial TRUE → 외부 설정 필요 → BLOCKED → 같은 work 새 attempt
4. initial TRUE → retry 소진 → FAILED, final verdict/Gate 없음
5. `VERDICT_EVIDENCE` → DISPROVED → final FALSE, validated PoC 없음
6. `VERDICT_EVIDENCE` → 정상 관측 INCONCLUSIVE → final HOLD, validated PoC 없음
7. 실행 실패·정책 차단·timeout → final verdict 없음
8. PoC 없는 TRUE 저장 또는 Technical Gate 호출 → 거절
9. 한 generation에 purpose가 다른 두 번째 dynamic work 등록 → 거절
10. Technical REVISE 새 generation → 별도 한도와 새 validated PoC 확인
