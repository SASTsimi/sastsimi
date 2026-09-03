# ADR-004. R6 동적 재현 요청과 R7 PoC 생산

- 상태: `ACCEPTED`
- 결정일: 2026-09-03
- 결정 담당: R4 PM·아키텍처·공통 계약
- 요청 역할: R6 검증·반박
- 영향 역할: R5 Gate·Finding·보고서, R7 동적검증·Sandbox, R3 통합 개발
- 대체 대상: [ADR-003](./ADR-003-r6-r7-environment-requirements-handoff.md)

## 쉽게 설명하면

R6는 “무엇을 왜 재현할지” 요청합니다. R7은 그 요청을 바탕으로 환경·실행 계획·PoC 초안을 만들고 Docker에서 실행합니다. 실제로 취약점 재현에 성공한 PoC가 있어야 최종 `TRUE`와 Technical Gate 진행을 허용합니다.

## 결정

1. R6는 `DynamicReproductionRequest`와 최종 `VerificationResult`만 생산합니다.
2. R7 Agent는 `EnvironmentRequirements`, `ReproductionPlan`, `EnvironmentRecipe`와 `poc_candidate`를 생산하고, R7 Session Manager는 `AgentLog`·cleanup·`DynamicReproductionResult`와 validated `poc_bundle`을 확정합니다.
3. request purpose는 다음 둘뿐입니다.
   - `POC_CONFIRMATION`: 정적·Pro·Con 결과가 initial TRUE일 때 PoC로 확인
   - `VERDICT_EVIDENCE`: 최종 판정에 필요한 동적 근거 확보
4. 한 Verification generation에는 두 purpose 중 하나를 가진 `DYNAMIC_REPRO` work를 최대 하나만 등록합니다.
5. retry와 외부 설정 대기는 같은 work의 새 attempt입니다.
6. `poc_candidate_ref`는 실행 전 또는 실패한 스크립트·입력이고, `poc_ref`는 `SUCCEEDED + SUPPORTED` 실행으로 검증된 PoC만 뜻합니다.
7. final TRUE는 current generation의 exact request·동적 결과·validated PoC가 모두 필요합니다.
8. PoC 생성·환경 구성·실행 자체의 실패는 verdict 없이 `BLOCKED | FAILED`이며 `FALSE | HOLD`로 변환하지 않습니다.

## 결과 해석

- `SUCCEEDED + SUPPORTED + poc_ref`: final TRUE 가능
- 실제 관측 `DISPROVED`: final FALSE 가능, `poc_ref=null`
- 정상 실행 또는 신뢰 가능한 부분 실행의 `INCONCLUSIVE`: final HOLD 가능, `poc_ref=null`
- `FAILED | BLOCKED | CANCELLED`: final VerificationResult 없음, Gate 호출 없음

initial TRUE를 확인하는 `POC_CONFIRMATION`도 같은 결과 규칙을 사용합니다. PoC가 initial 판단과 다르면 initial TRUE를 그대로 유지하지 않습니다.

## 권한 경계

- R6는 request의 가설·목적·목표·환경 필요·Sandbox profile과 근거를 정합니다.
- R7은 request를 약화하거나 다른 profile로 바꾸지 않고 실행 가능한 requirements·plan·candidate를 만듭니다.
- R7은 plan mode를 `LIMITED_REPRO | FULL_REPRO` 중 선택할 수 있지만 verdict·CWE·Gate 결과를 만들 수 없습니다.
- Runtime Validator는 생산자, exact revision, generation별 work 하나와 TRUE의 validated PoC 전제를 검사합니다.
- Sandbox Controller는 host·Docker daemon·secret·egress·다른 workspace·resource·lifecycle의 외부 경계를 검사하고 Agent 내부 command·package·payload·실행 순서는 정하지 않습니다.
- Setup Automation이 clean Sandbox를 만들고 Reproduction Agent가 내부 환경·PoC·실행·관찰·retry를 자율 수행합니다. Session Manager는 actual event와 결과 무결성만 확정합니다.

## 실패와 복구

- 재시도 가능: 실패 attempt를 보존하고 work `BLOCKED`, 새 attempt로 재시도
- 외부 설정 필요: work `BLOCKED`, 설정 변경 대기 후 새 attempt
- 복구 불가능 또는 한도 소진: work와 Verification `FAILED`, final verdict 없음
- 실패한 candidate·입력·log는 디버깅 이력으로 보존하지만 validated PoC로 사용하지 않음

## 호환성

`DynamicReproductionRequest`, `VerificationResult`, `EnvironmentRequirements`, `ReproductionPlan`, `EnvironmentRecipe`, `AgentLog`, `PoCBundle`, `DynamicReproductionResult`와 action/owner registry는 새 MAJOR schema로 배포합니다. ADR-003 기반 R6-owned requirements/plan이나 이전 step log를 자동 승격하지 않습니다.

## 검증 조건

- PoC 없는 TRUE 저장 차단
- PoC 없는 TRUE의 Technical Gate 호출 차단
- candidate만 있는 TRUE 차단
- 다른 generation 또는 다른 attempt의 PoC 결합 차단
- 한 generation의 두 번째 dynamic work 차단
- PoC 생성·실행 실패를 FALSE/HOLD로 변환하는 흐름 차단
- 정본·Wiki·Mermaid·validator 동기화
