# ADR-007. R7 자율 동적 재현과 Session Manager 결과 확정

- 상태: `ACCEPTED`
- 결정일: 2026-09-03
- 결정 담당: R4 PM·아키텍처·공통 계약, R7 동적검증·Sandbox
- 필수 확인 역할: R3 통합 개발, R6 검증·반박, R8 데이터·평가·예산
- 대체 대상: [ADR-002](./ADR-002-sandbox-policy-enforcement.md), [ADR-004](./ADR-004-r6-request-r7-poc-production.md)의 mode·exact plan·Runner·result-owner·retry 세부 계약

## 쉽게 설명하면

R6는 “무엇을 왜 재현할지”만 요청합니다. R7 Agent는 격리된 Docker 안에서 명령·PoC·관찰·재시도를 스스로 정합니다. Sandbox Controller는 Docker 밖으로 위험한 접근이 나가지 못하게 막고, 비-LLM Reproduction Session Manager는 실제로 일어난 기록만 모아 결과를 확정합니다.

## 결정

1. `ReproductionPlan`에는 목적·가설·환경 요구사항·재현 목표·전략 요약과 선택적 `requested_evidence`만 둡니다. `LIMITED_REPRO | FULL_REPRO`, exact step·command·payload·cleanup allowlist는 제거합니다.
2. R7 Agent는 Sandbox 안에서 환경 설정, 저장소에 필요한 package, 계정, fixture/mock, PoC, command·관찰·재시도를 자율적으로 정합니다.
3. Sandbox Controller는 host, Docker daemon/socket, mount/namespace, secret, 허용되지 않은 egress, 다른 workspace와 R8 resource/lifecycle 같은 외부 경계만 강제합니다. 내부 command allowlist는 운영하지 않습니다.
4. R7 Setup Automation이 실제 image build, container 생성·재사용·재생성과 cleanup을 맡습니다.
5. 비-LLM Reproduction Session Manager가 runtime/tool/lifecycle event를 durable append-only `AgentLog`에 기록하고 validated PoC와 `DynamicReproductionResult`를 확정합니다.
6. R6의 최종 `TRUE | FALSE | HOLD` 권한과 모든 TRUE의 validated PoC 의무는 유지합니다. R7은 `SUPPORTED | DISPROVED | INCONCLUSIVE`만 반환합니다.

## 환경과 container

- `EnvironmentRecipe`는 저장소/환경 단위의 불변 build recipe입니다. `base_image_digest`와 실제 `built_image_digest`를 구분하고 Dockerfile·README·package manifest·lockfile 같은 저장소 선언을 우선합니다.
- 별도 Dependency Scanner와 R2 package prefetch를 전제로 하지 않습니다.
- package 누락을 실제로 확인하면 Agent가 recipe source를 고치고 Setup Automation이 새 baseline image와 recipe revision을 만듭니다.
- 성공한 baseline image는 재사용할 수 있지만 current attempt에는 baseline ref와 built digest를 고정한 binding record를 남깁니다.
- 각 가설의 최초 attempt는 clean container에서 시작하고 서로 다른 가설은 writable container를 공유하지 않습니다.
- 같은 가설 work에서는 영향 있는 상태·설정 변화가 없을 때만 재사용합니다. `STATE_CHANGED | CONFIG_CHANGED | STATE_UNCERTAIN`이면 재생성하고 crash·비정상 종료·사후 Health Check 실패는 runtime이 `STATE_UNCERTAIN`으로 강제합니다.

## AgentLog와 result owner

- `event_id`는 전역 고유하고 `sequence`는 attempt별 1부터 증가합니다.
- 시작과 종료 event는 같은 `action_id`로 연결합니다.
- 각 append를 durable revision으로 확정해 crash 뒤에도 기존 event를 보존합니다.
- 이전 attempt의 늦은 event는 current attempt와 결과에 섞지 않습니다.
- `agent_invoked`는 외부 경계 승인 뒤 Sandbox 안의 R7 Agent 실행 단계만 뜻합니다. 사전 requirements·plan 작성 호출과 구분하며, 실행 Agent 호출 전 정책 차단도 `agent_invoked=false`, exact 정책 결정과 `POLICY_BLOCKED` event를 가진 결과로 기록할 수 있습니다.
- Session Manager는 Agent 호출·중단, command 허용, retry와 cleanup 전략을 결정하지 않습니다.

## retry와 실패

- 같은 session 안의 command·PoC·환경 조정은 한 attempt의 event입니다.
- session 재시작이 필요한 일시 오류는 R8 한도 안에서 같은 work의 새 attempt로 자동 retry하며 외부 대기가 없으면 `BLOCKED`를 사용하지 않습니다.
- `BLOCKED`는 외부 설정·정책·승인 또는 resource profile 변경을 기다릴 때만 사용합니다.
- 복구 불가능하거나 retry 한도를 소진하면 `FAILED + INCONCLUSIVE`로 끝냅니다.
- 실패는 R6의 `FALSE | HOLD`로 자동 변환하지 않고 final VerificationResult와 Technical Gate를 만들지 않습니다.

## PoC와 provenance

- `poc_candidate_ref`는 Agent가 작성했거나 실행을 시도한 candidate입니다. 실패해도 같은 attempt의 AgentLog와 함께 남길 수 있습니다.
- validated `poc_ref`는 `SUCCEEDED + SUPPORTED`, `agent_invoked=true`, exact candidate revision·digest의 실제 실행 event가 모두 있을 때만 생성합니다.
- request·plan·recipe·environment·AgentLog·candidate·validated PoC와 dynamic result는 같은 work·attempt에 연결합니다. 과거 baseline recipe ref만 명시된 예외입니다.
- 환경 실패, 정책 차단, candidate 생성/실행 실패, timeout, `DISPROVED | INCONCLUSIVE`이면 `poc_ref=null`입니다.
- current generation의 exact request, `SUCCEEDED + SUPPORTED` 결과와 validated PoC 중 하나라도 없으면 R6 final TRUE 저장과 Technical Gate 호출을 막습니다.

## 호환성

관련 schema와 result-owner registry는 새 MAJOR로 배포합니다. 이전 mode·exact step/command·`SandboxStepLog`·`runner_invoked`·`steps_ref`·Runner·Result Assembler 필드를 자동 변환하지 않습니다.

## 검증 조건

- 정본, Wiki, Mermaid, governance와 validator가 같은 역할·필드·상태를 설명함
- 외부 경계와 Sandbox 내부 자율성의 충돌이 없음
- 자동 retry와 외부 대기 `BLOCKED`가 구분됨
- AgentLog event 순서·action pair·attempt 격리가 검증됨
- same-attempt recipe/environment/log/candidate/PoC provenance가 검증됨
- validated PoC 없는 TRUE와 Technical Gate 호출이 차단됨
