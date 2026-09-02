# ADR-004. 자율 Reproduction Agent와 Sandbox 외부 안전 경계

- 상태: `PROPOSED`
- 결정 담당: R7 동적검증·Sandbox
- 필수 검토: R4 PM·아키텍처·공통 계약, R6 검증·반박, R8 데이터·평가·예산
- 추가 검토: R3 통합 개발, R5 Gate·보고
- 일부 대체: ADR-002의 command/step 사전 정책 검사, ADR-003의 exact step 실행·mismatch 즉시 중단 부분

## Context

이전 R7 설계는 R6가 환경 요구사항뿐 아니라 exact step·command·공격 입력·cleanup policy까지 `ReproductionPlan`에 고정하고, R7 code가 정책을 한 번 더 검사한 뒤 그대로 대리 실행하는 구조였다. 이 방식은 동적 재현 중 발견되는 package 누락, 계정·fixture 구성 차이, PoC 수정과 관찰 방식 변경마다 R6의 새 plan을 요구해 Agent의 강점을 사용하지 못한다.

R7의 목적은 가설의 최종 취약점 판정이 아니라, 격리 환경에서 실제로 재현해 얻은 동적 근거를 R6에 반환하는 것이다. 따라서 Sandbox 안의 재현 전략은 상위 모델 Agent에 맡기고 보안 강제는 Sandbox 밖에 두는 편이 책임과 구현을 단순하게 한다.

## Options

### A. exact step 대리 실행 유지

- 장점: 실행 전 모든 command를 예측하고 비교하기 쉽다.
- 단점: 환경·PoC·retry마다 새 plan이 필요하고 Agent가 단순 스크립트 생성기로 축소된다.

### B. command마다 정책 검사

- 장점: 실행 세부 제어가 가능하다.
- 단점: 범용 shell·package·PoC 활동을 code가 다시 의미 판단해야 하며 중복 정책 모듈이 커진다.

### C. Sandbox 내부 자율성 + 외부 강제 경계

- 장점: Agent가 환경·PoC·관찰·retry를 자율적으로 해결하고, host·Docker daemon·secret·network·resource 영향만 결정론적으로 차단할 수 있다.
- 단점: 실제 행동을 재현 가능한 log와 immutable artifact로 남기는 계약이 필요하다.

## Outcome

후보 결정은 C다.

- R6는 `EnvironmentRequirements`, 가설, 재현 목표, Sandbox profile과 관련 context만 `ReproductionPlan`으로 전달한다.
- R6는 exact step·command·payload·cleanup policy를 전달하지 않는다.
- R7 `REPRODUCTION_AGENT`는 환경 recipe, package·계정·fixture·mock, PoC, command, 관찰과 retry를 자율적으로 결정한다.
- R7은 동적 근거를 `SUPPORTED | DISPROVED | INCONCLUSIVE`로 판단한다. 최종 `TRUE | FALSE | HOLD`는 R6가 맡는다.
- Runtime Validator는 schema·authority·identity·revision·state·budget과 exact input refs만 검사한다.
- Sandbox Controller는 Docker socket/daemon, host mount/namespace, secret, network egress와 R8 resource profile을 강제한다. Agent command·payload 의미를 사전 allowlist로 검사하지 않는다.
- 실제 행동은 `AgentLog`, 환경 build는 `EnvironmentRecipe`, 실행된 최종 PoC는 `PoCBundle`, 정리는 `CleanupLog`로 저장한다.
- Agent가 result 의미 필드를 초안 작성하고 trusted code가 runtime 사실을 채운 뒤 작은 deterministic finalizer가 불변조건만 검사한다.

## Environment and package lifecycle

- 풍부한 공통 Toolbox Image와 저장소/환경별 versioned `EnvironmentRecipe`를 사용한다.
- package 누락을 발견하면 실패를 Agent Log에 남기고 Dockerfile·manifest·setup을 수정해 새 recipe revision과 image digest를 만든다.
- package download는 baseline image build 단계에서 수행한다.
- 성공한 recipe/image는 `PERSISTENT_BASELINE`, 개별 실행의 container·network·volume·tmp·임시 build는 `SESSION_EPHEMERAL`로 구분한다.
- ephemeral 자원은 성공·실패·차단·취소와 관계없이 R7이 cleanup한다.

## Result boundary

- `poc_ref`는 실제 실행을 시작한 final PoC Bundle만 가리킨다. draft-only PoC는 Agent Log에 남길 수 있으나 결과 PoC가 아니다.
- plan이 모순되거나 필수 문맥이 없으면 `plan_execution_status=NEEDS_REVISION`과 string `plan_issues`를 결과에 포함한다. 별도 `PlanIssue` record와 고정 issue code enum은 만들지 않는다.
- 넓은 `failure_category`와 자유 형식 `failure_reason`을 사용한다.
- 환경·실행·정책·timeout 실패와 빈 출력만으로 `DISPROVED` 또는 최종 `FALSE`를 만들지 않는다.

## Pending review decisions

- `LIMITED_REPRO | FULL_REPRO` mode를 공통 계약에 유지할지
- 가설마다 반드시 새 Docker container를 만들지, 다른 격리 lifecycle을 허용할지
- `requested_evidence` 선택 필드를 유지할지

정적 dependency scanner와 사전 package prefetch 연동은 R2와 별도 협의하며 이 ADR 승인 전제나 이번 PR reviewer 요청에 포함하지 않는다.

## Validation before acceptance

- Agent command가 plan에 없다는 이유로 차단하지 않음
- Docker socket·host path·secret·profile 밖 egress 차단
- R8 profile 적용과 실제 사용량·timeout 기록
- recipe·image·environment·Agent Log·PoC·cleanup의 같은 attempt/digest 연결
- 실행하지 않은 PoC draft를 결과에 연결하지 않음
- persistent baseline과 ephemeral cleanup lifecycle 혼합 차단
- Agent Log에 hidden chain-of-thought를 요구·저장하지 않음
- 환경·실행 실패를 반증이나 `FALSE`로 변환하지 않음
- 정본·Wiki·Mermaid와 architecture validator 통과

## Tracking

- 상위 Issue: #8
- 하위 Issue: #73, #74, #75

