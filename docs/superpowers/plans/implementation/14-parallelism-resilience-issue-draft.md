# T14 구현 Issue 초안 — 병렬 실행·취소·복구·Production CLI

## Issue 제목

`[T14] 전체 파이프라인 병렬 실행, 정확한 취소·재개, 중단 복구와 Production CLI 구현`

## 상위 작업과 순서

- Parent: 구현 총괄 Issue #121
- 선행: T09 Provider/Prompt Runtime → T10 Verification → T11 Dynamic
  Reproduction → T12 Gate/Reporter → T13 Primitive/Chaining
- 후속: T15 Security Hardening
- 상세 계획:
  `docs/superpowers/plans/implementation/14-parallelism-resilience.md`

## 쉽게 설명하면

지금까지 만든 각 단계는 결과를 정확하게 만들고 저장하는 역할입니다. T14는 그
단계들을 실제 실행 순서로 연결하고, 서로 독립적인 작업은 정해진 수만큼 동시에
돌리며, 사용자가 중단하거나 프로그램이 꺼져도 같은 외부 요청을 두 번 보내지 않고
안전하게 이어서 실행하게 만듭니다.

이 작업은 취약점 판정 규칙을 바꾸지 않습니다. 작업 실행 순서, 동시 실행 수,
취소, 재개, 복구, 최종 결과 조회만 구현합니다.

## 계획 기준

- 계획 작성 기준 main:
  `342fcfa2b8cc06900897a0afb06c71ec32af4f6e` (T08 병합 상태)
- T13 계획 기준:
  `28e446146ec7ddd72e42903efb4d0e7013e3219d`
- 위 T13 SHA는 구현 코드가 아니라 계획입니다. T14 구현 branch는 T09~T13의 최종
  reviewed 구현이 모두 main에 병합된 뒤 새로 만듭니다.

## 구현 시작을 막는 선행 Gate

다음 항목 중 하나라도 없으면 T14 병렬 lane을 시작하지 않습니다.

- [ ] T09~T13 최종 구현 SHA가 모두 최신 main의 조상입니다.
- [ ] 모든 `WorkType`에 production `WorkHandler.execute(WorkContext)`가 정확히
  하나씩 있습니다.
- [ ] 각 handler는 이미 claim된 work/attempt만 받고, 다음 work는 실제 merged
  READY-only API로 등록합니다.
- [ ] production handler가 `WorkflowRunner.start`, `activate`,
  `AttemptService.start`, 다른 handler나 worker loop를 직접 호출하지 않습니다.
- [ ] T09의 Provider 동시성·정확한 호출 취소·미확정 dispatch 차단이 있습니다.
- [ ] T10의 Pro/Con 독립 세션과 evidence 동시성 제한이 있습니다.
- [ ] T11의 exact Sandbox attempt/action/resource/cleanup 참조가 저장됩니다.
- [ ] T12의 Gate/Reporter handler와 T13의 Primitive/Chaining handler·복구 경계가
  있습니다.
- [ ] Alembic head가 하나입니다.

최종 API 이름은 계획 branch에서 가져오지 않습니다. 최신 main의 실제 공개 API를
읽고 Issue/PR 본문에 기록한 뒤 사용합니다.

## 반드시 해결할 Blocker/High

1. **중복 실행 방지**
   - READY work 하나를 두 worker가 동시에 보더라도 attempt는 하나만 시작합니다.
   - cancellation latch, 최신 work version, budget, 동시 실행 수, reservation,
     attempt, lease, READY → RUNNING 전이를 SQLite 한 transaction에서 확인합니다.

2. **전체 동시 실행 한도**
   - exact ACTIVE `ExecutionBudgetProfile.max_parallel_work`만 분석 전체 한도로
     사용합니다.
   - `DYNAMIC_REPRO`도 같은 한도를 사용합니다.
   - 별도 `max_parallel_sandboxes` 설정을 만들지 않습니다.
   - 값이 0이면 attempt·외부 호출·남은 reservation이 모두 0건이어야 합니다.

3. **정확한 취소**
   - `cancel`은 먼저 DB에 취소 요청을 남겨 새 work/attempt/result를 막습니다.
   - Provider, 정적 도구, Sandbox는 저장된 같은 analysis/work/attempt/action의
     정확한 대상만 취소합니다.
   - host process나 Docker resource를 전체 검색하거나 삭제하지 않습니다.

4. **안전한 재개**
   - 같은 입력을 가진 nonterminal BLOCKED work만 새 `RESUME` attempt로 재개합니다.
   - terminal, stale input, 한도 소진, 결과가 불확실한 외부 dispatch는 재개하지
     않습니다.

5. **결정적 복구**
   - startup에서 migration/integrity → PREPARED transition → lease/dispatch → exact
     output/pointer → cancellation 순으로 정리한 뒤에만 worker를 시작합니다.
   - 이미 COMMITTED인 결과는 다시 실행하지 않습니다.
   - dispatched but unreturned 외부 호출은 자동 재전송하지 않고 BLOCKED로 둡니다.

6. **늦은 결과 차단과 독립 실패**
   - 이전 attempt의 늦은 결과나 heartbeat는 current pointer를 움직이지 못합니다.
   - 가설 하나의 실패는 다른 가설을 중단시키지 않고, 실패한 가설의 verdict도
     만들어내지 않습니다.

7. **정확한 종료**
   - 모든 work가 terminal이고 PREPARED·미확정 dispatch가 없을 때만
     `AnalysisRunResult`를 한 번 확정합니다.
   - BLOCKED work만 남은 상태는 진행 가능한 중간 상태이며 최종 결과를 만들지
     않습니다.
   - 취소가 먼저 확정됐으면 run은 `CANCELLED`로만 종료합니다.

8. **Production CLI**
   - `run`, `status`, `cancel`, `resume`, `result`를 제공합니다.
   - public production 명령은 `FakePipeline`을 사용하지 않습니다.
   - Windows `KeyboardInterrupt`에서도 먼저 취소 요청을 저장하고, 강제 종료 뒤
     다음 실행의 startup recovery가 중복 전송 없이 수렴합니다.

## 직렬 선행 작업 S1

한 명이 다음 원자 경계를 먼저 구현하고 reviewed commit을 만듭니다. 이 단계가
끝나기 전에는 아래 병렬 lane을 시작하지 않습니다.

- scheduler/run-control port와 transport DTO
- cancellation latch 저장소와 다음 단일 Alembic migration
- READY 조회와 atomic claim
- `WorkflowRunner.enqueue`와 worker-only claim 경계
- work 등록·READY 전환·attempt 시작·work 결과 저장·run finalization의 latch 재검사
- exact Provider/static/Sandbox cancellation target 조회
- cap 거절 시 남는 reservation이 없는 transaction

정확한 파일과 method는 상세 계획의 S1 목록을 사용하되, migration 이름과 T09~T13
호출부는 최종 main을 읽은 뒤 확정합니다.

## 병렬 작업 배정

S1 reviewed SHA에서 네 worktree를 만들어 동시에 진행합니다.

### Lane A — Worker pool과 heartbeat

- complete handler registry
- bounded `asyncio` worker pool
- 전체 `max_parallel_work` 적용
- exact attempt lease heartbeat
- worker별 오류 격리

소유 중심 파일: `runtime/handler_registry.py`, `runtime/worker_pool.py`,
`runtime/lease_heartbeat.py`, `runtime/work_service.py`, worker focused test

### Lane B — 취소·재개와 CLI leaf service

- durable cancel service
- exact external cancellation routing
- same-input BLOCKED resume
- `run/status/cancel/resume/result`의 leaf command
- Windows interrupt의 latch-first 처리

이 lane은 shared `interfaces/cli/main.py`, `output.py`, `exit_codes.py`를 수정하지
않습니다.

### Lane C — Startup recovery

- 기존 `RecoveryService`의 순서 확장
- PREPARED, expired lease, unresolved dispatch 수렴
- exact persisted target만 복원
- 두 번 실행해도 같은 상태가 되는 idempotent recovery

소유 중심 파일: runtime/storage `recovery_service.py`,
`storage/lease_recovery.py`, recovery focused test

### Lane D — Production orchestration

- run initialization과 exact budget pin
- T08~T13 production handler composition
- downstream READY enqueue와 worker-pool drive
- current 상태 기반 result aggregation
- BLOCKED/terminal 구분

이 lane은 T09~T13 내부 구현이나 SQLite concrete adapter를 직접 import하지 않습니다.

## 직렬 통합

Lane A~D를 검토한 뒤 한 명만 다음 shared 파일을 수정합니다.

- `src/sastsimi/bootstrap.py`
- `src/sastsimi/runtime/services.py`
- `src/sastsimi/interfaces/cli/main.py`
- `src/sastsimi/interfaces/cli/output.py`
- `src/sastsimi/interfaces/cli/exit_codes.py`
- 필요한 package export
- `tests/e2e/test_production_cli.py`
- `tests/contract/test_architecture_imports.py`

현재 `.github/workflows/ci.yml`은 이미 Ubuntu/Windows에서 Ruff, strict mypy, 전체
pytest와 문서 검증을 실행합니다. T14는 테스트를 반복하려고 CI workflow를 바꾸지
않습니다. CI action 고정 등 보안 hardening은 T15 책임입니다.

## 최소 테스트 원칙

각 작업은 다음 두 모양만 먼저 만듭니다.

- 정상 1개: 독립 work가 정해진 cap 안에서 실행되고 exact 결과까지 이어짐
- 중요 실패 1개: parameterized test로 duplicate claim, cancel race, stale attempt,
  unresolved dispatch, wrong target처럼 안전성을 깨는 경우를 묶음

Task 중에는 해당 focused test, Ruff, strict mypy, `git diff --check`만 실행합니다.
전체 test suite는 최종 candidate SHA의 PR CI에서 한 번만 실행합니다. CI가
Blocker/High를 찾으면 최소 수정 후 새 SHA에서 한 번 다시 실행합니다.

## 완료 조건

- [ ] S0에 최종 base SHA, T09~T13 ancestry, 실제 public API 이름과 단일 migration
  head를 기록했습니다.
- [ ] 모든 `WorkType`이 production handler 하나에만 연결됩니다.
- [ ] READY claim과 cancel/cap/reservation/attempt/lease/RUNNING 전이가 원자입니다.
- [ ] `max_parallel_work`가 모든 work type에 분석 전체 한도로 적용됩니다.
- [ ] 취소 후 새 dispatch와 stale result가 저장되지 않습니다.
- [ ] exact persisted Provider/static/Sandbox target만 취소·복구합니다.
- [ ] 같은 입력의 eligible BLOCKED work만 `RESUME` attempt로 재개합니다.
- [ ] startup recovery가 scheduling보다 먼저 실행되고 두 번 실행해도 중복 호출이
  없습니다.
- [ ] 한 가설 실패가 다른 가설과 그 판정을 오염시키지 않습니다.
- [ ] BLOCKED-only run은 최종 결과가 없고, terminal run만 exact result를 한 번
  확정합니다.
- [ ] production `run/status/cancel/resume/result`가 fake pipeline 없이 동작합니다.
- [ ] 정상 focused test 1개와 parameterized 중요 실패 test 1개가 각 lane에서
  통과합니다.
- [ ] Ruff와 strict mypy가 통과합니다.
- [ ] immutable candidate SHA에서 전체 PR CI가 한 번 통과합니다.
- [ ] R3·R4·R8과 변경 영향을 받은 T08~T13 owner가 최종 SHA를 검토합니다.

## 범위 밖

- 분산 queue, daemon, multi-host scheduler, autoscaling
- 별도 Sandbox 동시성 한도
- 새로운 verdict, Gate, Agent 또는 취약점 탐지 규칙
- T09~T13 내부 리팩터링
- dashboard, 우선순위 scheduler, 성능 cache
- Medium/Low 테스트 확대와 문서 미세 보정

위 항목은 실제 Blocker/High 근거가 생기지 않는 한 T14에서 구현하지 않습니다.
