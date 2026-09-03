# R7 자율 동적 재현 공통 계약 반영 계획

> 상태: 실행 계획. 기준 commit은 작업 시작 시 `312fcb2`이다.

## 목표

R6는 재현 목적과 필요한 조건만 요청하고, R7 Agent가 격리된 Sandbox 안에서 실행 전략·명령·PoC·관찰·재시도를 자율적으로 정하도록 공통 계약을 바꾼다. 비-LLM `Reproduction Session Manager`가 실제 event를 append-only `AgentLog`에 기록하고 같은 attempt의 환경·recipe·PoC·결과를 확정한다.

## 작업 순서

1. Architecture v5 정본의 역할, 동적 재현, 상태·복구, 데이터 schema, 보안 경계와 다이어그램을 새 책임 경계로 수정한다.
2. `ReproductionPlan`에서 mode와 exact step·command·payload·cleanup 지시를 제거하고, `requested_evidence`를 선택적 목표로만 둔다.
3. `EnvironmentRecipe`, `SandboxEnvironment`, `AgentLog`, `DynamicReproductionResult`의 같은-attempt provenance와 result-owner 규칙을 확정한다.
4. 내부 자율 retry, 외부 조건 대기 `BLOCKED`, 복구 불가·한도 소진 `FAILED`를 구분하고 이전 attempt의 늦은 event를 격리한다.
5. candidate PoC와 validated PoC 조건, final TRUE 및 Technical Gate 전제조건을 강화한다.
6. README, Wiki, 용어집, 문서 안내, governance, Issue catalog와 ADR을 같은 표현으로 동기화한다.
7. 문서 validator를 새 schema와 금지된 옛 표현에 맞춰 수정하고 전체 검증·잔존 검색을 실행한다.
8. 검증이 통과한 변경만 commit하고 최신 `main`에 push한다.

## 완료 조건

- 현재 정본 어디에도 `LIMITED_REPRO | FULL_REPRO`, exact step/command 중심 plan, `SandboxStepLog`, `runner_invoked`, `steps_ref`, `Sandbox Runner`, `Sandbox Result Assembler`가 현재 계약으로 남지 않는다.
- R6/R7/Controller/Setup Automation/Session Manager의 책임과 Sandbox 내부·외부 경계가 서로 모순되지 않는다.
- 실패 결과는 R6의 `FALSE | HOLD`로 자동 변환되지 않는다.
- validated `poc_ref`는 같은 generation·attempt·환경·recipe·digest의 실제 candidate 실행을 `AgentLog`로 입증할 때만 생성된다.
- `scripts/validate-architecture-docs.ps1`와 잔존 표현 검색이 통과한다.
