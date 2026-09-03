# ADR-003. R6 환경 요구사항과 R7 실제 환경 비교 handoff

- 상태: `SUPERSEDED`
- 대체 결정: [ADR-004. R6 동적 재현 요청과 R7 PoC 생산](./ADR-004-r6-request-r7-poc-production.md)
- 결정 담당: R4 PM·아키텍처·공통 계약
- 필수 검토: R6 검증·반박, R7 동적검증·Sandbox
- 추가 검토: R3 통합 개발, R8 데이터·평가

## Context

> 이 문서는 당시 R6가 `EnvironmentRequirements`와 `ReproductionPlan`을 생산하던 결정을 보존하는 역사 기록입니다. 현재 계약으로 사용하지 않습니다. 현재 생산 권한과 PoC 규칙은 ADR-004를 따릅니다.

기존 `environment_ref`는 R7이 실제로 만든 `sandbox_environment`를 정확히 가리키지만, R6이 재현 전에 요구한 애플리케이션 역할·인증·데이터·DB/service·fixture/mock·버전·Health Check를 별도 record로 남기지 않았습니다. 따라서 실제 환경이 R6의 전제와 같은지 기계적으로 비교할 exact reference가 없었습니다.

`sandbox_profile_ref`는 image·명령·네트워크·자원 등 Sandbox 보안 정책을 가리킵니다. 애플리케이션 환경 요구사항을 이 필드에 섞으면 보안 허용과 재현 전제가 같은 의미처럼 보이고 R4·R6·R7 책임이 겹칩니다.

## Options

### A. sandbox_profile에 애플리케이션 요구사항도 넣는다

- 장점: 새 record가 필요 없습니다.
- 단점: Sandbox 보안 정책과 취약점 재현 전제가 섞이고, R6가 필요한 환경을 정한다는 역할 경계가 깨집니다.

### B. DynamicReproductionResult에 요구사항과 실제 값을 모두 복사한다

- 장점: 결과 하나만 읽으면 됩니다.
- 단점: plan과 결과에 같은 정보가 중복되고 어느 요구사항 revision을 실행했는지 쉽게 어긋납니다.

### C. R6 요구사항 record와 R7 실제 환경 비교 record를 exact reference로 연결한다

- 장점: 필요한 환경과 실제 환경의 생산자가 분리되고, revision 불일치와 오래된 요구사항을 프로그램으로 차단할 수 있습니다.
- 단점: `ReproductionPlan`의 새 MAJOR schema와 항목별 비교 검사가 필요합니다.

## Outcome

후보 결정은 C입니다. R6·R7이 최종 review freeze SHA를 검토하기 전까지 이 ADR은 `PROPOSED`입니다.

- R6 Verification은 불변 `EnvironmentRequirements`를 생산합니다.
- `ReproductionPlan.environment_requirements_ref`는 current exact 요구사항 revision을 가리킵니다.
- R7의 `sandbox_environment.requirements_ref`는 같은 revision을 가리키고 각 `requirement_id`의 `MATCH | MISMATCH | NOT_CHECKED | ERROR`, 실제 값 또는 artifact, 차이·근거·Health Check 결과를 기록합니다.
- `DynamicReproductionResult`에는 요구사항 reference를 중복 저장하지 않습니다. plan과 actual environment를 따라가 같은 revision인지 확인합니다.
- 필수 항목이 모두 `MATCH`일 때만 공격 단계를 실행합니다. 차이가 있으면 `FAILED + ENVIRONMENT_SETUP`과 actual comparison을 R6에 반환합니다.
- R6이 환경 조건이나 허용 대체값을 바꾸면 새 요구사항과 이를 가리키는 새 계획을 함께 만들고, 단계만 바꾸면 새 계획만 만듭니다. 두 경우 모두 새 `RUN_SANDBOX` action을 만들고 Runtime Validator와 Sandbox Controller 검사를 다시 거칩니다.

## Responsibility boundary

- R4: 공통 record·필드·exact reference·상태·생산자/소비자·오류 규칙
- R6: 필요한 환경, 미리 허용한 대체 버전·차이, 요구사항 변경 시 새 requirements+plan 또는 단계 변경 시 새 plan revision과 최종 판정
- R7: 환경 구성, 실제 값·차이·Health Check·실행 결과 기록
- Runtime Validator: schema·권한·identity·revision·state·예산 검사
- Sandbox Controller: image·command·file·network·resource·cleanup 보안 정책 검사
- Sandbox Runner: Controller가 승인한 exact 계획의 환경 비교와 필수 일치 뒤 공격 단계 실행

R6의 차이 수용은 Sandbox 보안 정책을 우회하는 권한이 아닙니다. R7은 요구사항을 수정하거나 허용 목록 밖 fallback을 선택하거나 차이를 임의 승인하거나 최종 `TRUE | FALSE | HOLD`를 만들 수 없습니다.

## Security and compatibility

- credential·cookie·token·password는 두 환경 record, artifact와 일반 log에 저장하지 않습니다. 필요한 비밀은 secret store의 불투명 handle만 연결합니다.
- plan과 actual environment가 다른 requirements revision을 가리키면 결과 저장을 거절합니다.
- 오래된 requirements revision과 변경 전 `RUN_SANDBOX` decision은 `STALE_RESULT` 또는 `EXPIRED`입니다.
- 환경 실패와 차이는 가설 반증이 아니며 `INCONCLUSIVE`로 R6에 전달합니다.
- 필수 `environment_requirements_ref` 추가로 `ReproductionPlan`은 새 MAJOR schema가 필요합니다.

## Validation before acceptance

- R6 외 생산자가 EnvironmentRequirements를 저장하지 못함
- plan에 current exact requirements가 없으면 RUN_SANDBOX 차단
- plan과 actual environment requirements revision 불일치 차단
- 필수 mismatch에서 공격 step 실행 차단
- 허용되지 않은 version fallback 차단
- environment secret 원문 저장 차단
- R6 차이 수용 뒤 Sandbox 정책 재검사 강제
- 환경 실패·차이를 `FALSE`로 변환하지 않음
- 정본/Wiki Mermaid와 architecture validator 통과

## Tracking

- 관련 역할 Issue: #5, #7, #8
- 반영 방식: PR 없이 최신 `origin/main`에 직접 커밋
- 반영 commit: `docs: define R6-R7 environment requirement handoff`
- 승인 전제: R6·R7의 실제 교차 검토 기록
