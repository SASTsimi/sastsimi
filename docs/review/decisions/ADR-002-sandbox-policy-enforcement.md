# ADR-002. Sandbox 외부 정책·실행 기록·결과 저장 권한 분리

> ADR-007이 command/step 사전 검사와 exact 대리 실행 구조를 대체한다. 이 ADR은 외부 경계 정책, 자율 실행, 수동 기록과 최종 문서화의 권한을 분리하는 결정만 유지한다.

- 상태: `SUPERSEDED`
- 대체 결정: [ADR-007. R7 자율 동적 재현과 Session Manager 결과 확정](./ADR-007-r7-autonomous-reproduction-session.md)
- 결정 담당: PM·아키텍처·워크플로, 동적검증·Sandbox
- 필수 검토: 검증·반박, 통합 개발, Gate·보고서, 데이터·평가
- 검토 PR: [#76](https://github.com/SASTsimi/sastsimi/pull/76)

## Context

> 이 문서는 exact plan·Runner·Result Assembler를 사용하던 당시 제안을 보존한 역사 기록입니다. 현재 계약으로 사용하지 않습니다. 외부 격리 경계와 현재 result owner는 ADR-007을 따릅니다.

Runtime Validator의 `RUN_SANDBOX ALLOW`는 호출 권한·상태·예산과 exact `ReproductionPlan`만 확인합니다. 이를 Sandbox 세부 정책 통과나 Docker 실행 성공으로 해석하면 Controller를 우회한 실행과 정책 차단 근거 누락을 구분할 수 없습니다.

## Decision

- Runtime Validator는 R7 호출 전제와 current reference만 검사한다.
- Sandbox Controller는 host·Docker daemon·mount/namespace·secret·network egress·R8 resource·lifecycle의 외부 경계 정책만 결정·강제하고 exact `sandbox_policy_decision`을 저장한다.
- Sandbox Controller는 Sandbox 생성·폐기, Agent 호출, command 허용·거절, 실행 순서, retry와 cleanup을 수행하지 않는다.
- R7 Sandbox Setup Automation이 승인된 정책을 사용해 image build, clean Sandbox 생성과 lifecycle cleanup을 수행한다.
- Reproduction Agent는 Sandbox 내부 환경·package·PoC·command·관찰·retry를 자율적으로 결정한다.
- 기존 Agent tool runtime과 Sandbox lifecycle automation은 실제 action event를 방출한다.
- Reproduction Session Manager는 이 event를 append-only로 수동 기록하고, Agent 의미 초안과 runtime 사실을 최종 `DynamicReproductionResult` 문서로 확정한다.
- Session Manager는 Agent 실행을 허용·차단·변경하지 않으며 동적 의미를 다시 판단하지 않는다.
- Verification은 COMMITTED 결과를 읽어 최종 `TRUE | FALSE | HOLD`를 결정한다.

## Required invariants

- `agent_invoked=false`인 정책 차단·실행 전 취소도 Session Manager가 Agent 출력 없이 결과로 문서화할 수 있다.
- `agent_invoked=true`이면 Session Manager가 runtime/tool event에서 확정한 exact `AgentLog`가 필요하다.
- event는 실행 전 `STARTED`와 종료 상태를 같은 `action_id`로 연결하고 attempt 안에서 sequence가 단조 증가한다.
- Agent crash 뒤에도 이미 기록된 event를 보존하며 retry는 새 attempt를 사용한다.
- 정책 차단·환경 실패·실행 실패를 취약점 `FALSE`로 바꾸지 않는다.
- 서로 다른 analysis·workspace·commit·hypothesis·attempt의 실행 artifact를 섞지 않는다.

## Responsibility boundary

R4는 공통 필드·자료형·null·상태·identity·생산자/소비자 규칙을 관리한다. R7은 외부 경계 정책, 환경 자동화, Agent 실행 artifact, event 기록과 최종 결과 문서 형식을 관리한다.
