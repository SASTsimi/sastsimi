# ADR-002. Sandbox 정책 판정·실행·결과 조립 권한 분리

- 상태: `PROPOSED`
- 결정 담당: PM·아키텍처·워크플로, 동적검증·Sandbox
- 필수 검토: 검증·반박, 통합 개발, Gate·보고서, 데이터·평가
- 검토 PR: [#48](https://github.com/SASTsimi/sastsimi/pull/48)

## Context

Runtime Validator의 `RUN_SANDBOX ALLOW`는 호출 권한·상태·예산과 exact `ReproductionPlan`만 확인합니다. 이를 Sandbox 세부 정책 통과나 Docker 실행 성공으로 해석하면 Controller를 우회한 실행과 정책 차단 근거 누락을 구분할 수 없습니다.

또한 Controller가 Runner를 호출하지 않은 정책 차단 결과에 필수 step log를 요구하면 존재하지 않는 실행 기록을 만들게 됩니다. 정책 판정, 실제 실행, 결과 reference 조립의 책임을 분리해야 합니다.

## Options

### A. Runtime Validator가 Sandbox 세부 정책까지 모두 검사

- 장점: 검사 주체가 하나입니다.
- 단점: 공통 권한 검사와 Docker 전문 정책이 섞이고 R4와 R7 책임이 겹칩니다.

### B. Controller가 판단과 실행 결과를 모두 생산

- 장점: Sandbox 내부 구성요소가 적습니다.
- 단점: 정책 판정과 실제 실행 사실, 최종 결과 조립 책임이 한곳에 집중됩니다.

### C. Controller·Runner·Result Assembler를 분리

- 장점: 정책 판정, 실행 로그, exact reference 조립을 각각 검증할 수 있습니다.
- 단점: 공통 상태와 nullable reference 규칙이 추가로 필요합니다.

## Outcome

후보 결정은 C입니다. Architecture v5 정본에는 검토 후보로 반영되어 있으며 PR #48의 필수 교차 검토가 끝나기 전까지 이 ADR은 `PROPOSED`입니다.

- Runtime Validator는 Sandbox 호출 전제만 검사합니다.
- Sandbox Controller는 exact plan closure와 정책 revision을 검사해 `ALLOW | DENY`와 사유를 `sandbox_policy_decision`으로 저장합니다.
- Sandbox Runner는 Controller가 허용한 exact 계획만 실행하고 실제 환경·단계 로그·PoC 실행 사실을 저장합니다.
- 비-LLM Sandbox Result Assembler는 같은 attempt의 정책·환경·로그·PoC·정리 reference만 `DynamicReproductionResult`에 조립합니다.
- Verification은 COMMITTED 결과를 읽어 최종 `TRUE | FALSE | HOLD`를 결정하며 Sandbox 구성요소는 verdict를 만들지 않습니다.

## Required invariants

- `POLICY_BLOCKED`이면 exact `policy_decision_ref`가 필수입니다.
- `runner_invoked=false`이면 `steps_ref=null`, `true`이면 실패해도 exact step log가 필수입니다.
- 실제 환경 생성 여부와 `environment_ref`, 정리 대상 여부와 `cleanup_status`가 일치해야 합니다.
- PoC reference 존재는 실행이나 성공을 뜻하지 않습니다.
- 정책 차단·환경 실패·실행 실패를 취약점 `FALSE`로 바꾸지 않습니다.
- 서로 다른 analysis·workspace·commit·hypothesis·attempt의 artifact를 섞지 않습니다.

## Responsibility boundary

R4는 공통 필드·자료형·null·상태·identity·생산자/소비자 규칙을 관리합니다. R7은 정책 판정, 환경, 단계 로그와 PoC artifact의 상세 구조와 실행·정리 절차를 관리합니다.

## Acceptance

- Architecture 정본·Wiki·Mermaid가 같은 흐름을 설명합니다.
- 잘못된 nullable reference와 cleanup 조합을 자동 문서 검사가 탐지합니다.
- R3·R5·R6·R7이 최종 review freeze SHA를 기준으로 역할 경계를 재검토합니다.
- PR #48 병합 뒤 상태를 `ACCEPTED`로 바꾸고 병합 commit을 기록합니다.
