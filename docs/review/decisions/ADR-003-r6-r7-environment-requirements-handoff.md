# ADR-003. R6 환경 요구사항과 R7 실제 환경 handoff

> ADR-004가 exact step 실행과 mismatch 즉시 중단 구조를 대체한다. R6가 `EnvironmentRequirements`를 생산하고 R7 실행 환경이 exact revision을 참조한다는 결정은 유지한다.

- 상태: `PROPOSED`
- 결정 담당: R4 PM·아키텍처·공통 계약
- 필수 검토: R6 검증·반박, R7 동적검증·Sandbox
- 추가 검토: R3 통합 개발, R8 데이터·평가

## Context

R6가 요구한 애플리케이션 역할·인증·데이터·DB/service·fixture/mock·version·Health Check와 R7이 실제로 만든 환경을 exact reference로 연결해야 한다. Sandbox 외부 정책을 나타내는 `sandbox_profile_ref`와 애플리케이션 재현 요구사항은 서로 다른 의미이므로 합치지 않는다.

## Decision

- R6 Verification은 불변 `EnvironmentRequirements`를 생산한다.
- `ReproductionPlan.environment_requirements_ref`는 current exact 요구사항 revision을 가리킨다.
- R7 `SandboxEnvironment.requirements_ref`는 같은 revision을 가리키고 requirement별 `PASSED | FAILED | NOT_CHECKED`, 실제 값·근거·Health Check를 기록한다.
- Environment failure와 requirement 차이는 그 자체로 가설 반증이나 최종 `FALSE`가 아니다.
- Reproduction Agent는 Sandbox 내부에서 해결 가능한 package·계정·fixture·mock·service 차이를 자율적으로 해결하고 모든 실제 action은 runtime/tool event로 남긴다.
- Sandbox Controller는 외부 경계 정책만 결정·강제하며 Sandbox를 생성하거나 Agent command를 검사하지 않는다.
- R7 Sandbox Setup Automation이 승인된 외부 정책과 immutable `EnvironmentRecipe`로 clean Sandbox를 생성한다.
- Reproduction Session Manager는 실제 환경·event·Agent 의미 초안을 최종 결과 문서로 기록할 뿐 Agent의 실행·retry에 개입하지 않는다.

## Recipe and image identity

- `EnvironmentRecipe`는 특정 가설·attempt에 종속하지 않는 저장소·환경 범위의 immutable revision이다.
- `base_image_digest`와 실제 build 결과인 `built_image_digest`를 구분한다.
- `SandboxEnvironment.image_digest`와 실행된 PoC가 참조한 환경은 exact `built_image_digest`와 같아야 한다.
- 같은 recipe/image는 여러 가설에서 참조할 수 있지만 각 가설·attempt는 별도의 clean Sandbox와 writable state를 사용한다.
- package나 setup을 변경하면 기존 recipe를 덮어쓰지 않고 새 revision과 새 `built_image_digest`를 만든다.

## Responsibility boundary

- R4: 공통 record·field·reference·state·producer/consumer 규칙
- R6: EnvironmentRequirements, 최소 ReproductionPlan과 최종 판정
- R7 Reproduction Agent: Sandbox 내부 환경 구성·PoC·관찰·retry 및 동적 의미 초안
- Sandbox Controller: 외부 경계 정책 결정·강제와 정책 판정
- R7 Sandbox Setup Automation: image build, clean Sandbox 생성과 lifecycle cleanup
- Reproduction Session Manager: 수동 event 기록과 최종 DynamicReproductionResult 문서화

## Validation before acceptance

- R6 외 생산자가 EnvironmentRequirements를 저장하지 못함
- plan과 actual environment가 다른 requirements revision을 가리키면 저장 거절
- base image와 실제 built image digest가 구분됨
- 다른 가설의 writable Sandbox state가 재사용되지 않음
- 환경 실패·차이를 `DISPROVED | FALSE`로 변환하지 않음
- Controller와 Session Manager가 Agent command·실행 순서·retry에 개입하지 않음
