# ADR-001. Verification 중심 제어권과 Gate-qualified Chaining

- 상태: `PROPOSED`
- 회의 결정일: 2026-08-30
- 문서 반영 브랜치: `review/verification-owned-chaining-flow`
- 결정 담당: PM·아키텍처·워크플로
- 필수 검토: 검증·반박, LLM 탐색·체이닝, Gate·보고서, 통합 개발, 데이터·평가

## Context

기존 Architecture v5는 Orchestration이 한 가설의 Pro/Con, 동적 재현, Research와 Gate 호출까지 조정하는 것으로 읽혔다. Research Agent는 Primitive matching 외에 bypass·alternate path·impact 확대와 Technical revision 보완까지 맡았고, final TRUE가 두 Gate 전에 PROVIDED Primitive가 될 수 있었다.

이 구조에는 세 문제가 있었다.

1. 가설 내부의 근거를 가장 잘 아는 Verification과 다음 작업 선택 주체가 달랐다.
2. Research와 Verification의 우회·영향·보완 책임이 겹쳤다.
3. Gate에서 나중에 탈락할 TRUE가 먼저 Chaining parent가 될 수 있었다.

## Options

### A. 기존 Orchestration·Research 구조 유지

- 장점: 현재 문서와 이름 변경이 적다.
- 단점: 책임 중복과 Gate 전 TRUE 오염 문제가 남는다.

### B. Verification이 가설 내부 흐름을 소유하고 Research를 matching 전용 Chaining으로 축소

- 장점: 한 가설의 근거 수집·판정·보완 주체가 일치한다. Chaining 입력 자격이 명확해진다.
- 단점: 공통 역할 enum, 결과 계약, action requester와 다이어그램을 함께 바꿔야 한다.

### C. Chaining을 제거하고 사람이 연계를 선택

- 장점: 자동 확장 위험이 작다.
- 단점: 프로젝트 목표인 연계 취약점 탐색을 충족하지 못한다.

## Outcome

2026-08-30 회의에서는 B를 선택했다. 이 파일의 저장소 상태는 관련 문서 변경이 병합되기 전까지 `PROPOSED`이며, 병합과 필수 교차 검토가 끝난 뒤 `ACCEPTED`로 바꾼다.

### 1. 역할 경계

- Orchestration Agent는 proposal 검증·전역 가설 등록·Verification 배정까지만 담당한다.
- trusted runtime은 배정 결과를 ACTIVE `VerificationAssignment`로 저장하며, 같은 역할의 다른 identity가 아니라 그 논리 owner만 가설 내부 action을 요청할 수 있다.
- Verification Agent는 배정된 가설의 Context·Pro/Con·동적 재현·근거 종합·판정·material child·Technical Gate 제출·REVISE·Chaining handoff를 소유한다. REVISE는 같은 assignment의 새 VERIFICATION work와 `TERMINAL -> VERIFYING` 전이로 처리한다.
- Runtime Validator는 action 권한, exact revision, 상태, 예산, Sandbox, provider/session, Gate/Reporter 전제를 계속 강제한다.

### 2. Research 제거와 Chaining 한정

- active `Research Agent`, `ResearchResult`, `origin=RESEARCH`를 제거한다.
- `Chaining Agent`와 `ChainingResult`는 TRUE+HOLD와 TRUE+TRUE Primitive matching만 수행한다.
- bypass·alternate path·impact escalation·추가 정적/동적 검증·Technical revision 보완은 Verification 책임이다.
- Verification material claim은 `origin=VERIFICATION`, Primitive match claim은 `origin=CHAINING`인 새 proposal이 된다.

### 3. 판정별 Chaining admission

- FALSE: terminal, Primitive와 Chaining 없음.
- HOLD: exact final Verification에서 REQUIRED Primitive를 즉시 저장하며 Gate를 거치지 않는다.
- TRUE: exact 같은 revision이 Technical `ACCEPT`와 Rule Scope `PASS/PASS/PASS/SUFFICIENT/ALLOW`를 모두 받은 뒤에만 PROVIDED Primitive가 된다.
- 새 Verification revision이 생기면 과거 Gate 자격은 새 revision에 적용되지 않고 이전 Primitive는 current matching에서 `SUPERSEDED`된다.
- TRUE+TRUE는 앞 PROVIDED가 뒤 TRUE의 exact Verification에 기록된 `required_preconditions`를 충족할 때만 허용한다.
- 각 parent의 `PrimitiveIndexState`를 Chaining input에 고정하고 commit 직전에 current head를 재검사해 in-flight stale 결과를 차단한다.

## Security and operational consequences

- Verification ownership은 실행 허가 권한이 아니므로 기존 `ActionRequest`·`ActionDecision`, state/revision/budget/Sandbox 검사를 유지한다.
- Chaining child와 parent의 lifecycle·verdict는 독립이다.
- Gate 전·비정상 Gate·오래된 revision TRUE가 chain ancestor가 되는 경로를 차단한다.
- HOLD는 확인된 취약점이나 PROVIDED 능력으로 해석하지 않는다.
- Chaining 폭증은 depth, count, token, time, duplicate, cycle과 primitive 조합 예산으로 제한한다.

## Compatibility impact

| 이전 | 새 계약 | 영향 |
|---|---|---|
| Research Agent | Chaining Agent | 단순 rename이 아니라 일반 research 기능 제거 |
| ResearchResult | ChainingResult | trigger와 출력 schema 호환 불가 |
| `origin=RESEARCH` | `origin=VERIFICATION` | 기존 active enum 사용자는 migration 필요 |
| Orchestration의 hypothesis-local 호출 | Verification-owned workflow | action requester와 work 등록 흐름 변경 |
| final TRUE → PROVIDED | Gate-qualified exact TRUE → PROVIDED | admission 순서와 조회 index 변경 |
| 역할 이름만 확인 | ACTIVE `VerificationAssignment` exact owner 확인 | requester identity와 assignment 저장 필요 |
| TRUE PROVIDED 두 개 비교 | 앞 PROVIDED → 뒤 TRUE exact precondition 비교 | PROVIDED와 match schema 보강 |
| lookup 시 ACTIVE 확인 | `PrimitiveIndexState` commit-time CAS | 진행 중 stale Chaining 결과 비호환 |

## Affected documents and contracts

- `README.md`, `CONTRIBUTING.md`
- Architecture v5 `01`–`13`
- Architecture v5 Wiki와 Mermaid
- `docs/GLOSSARY.md`, `docs/DOCUMENT_GUIDE.md`
- governance/review 문서와 관련 상위 GitHub Issue

## Validation before acceptance

- active Research Agent/ResearchResult/RESEARCH origin reference 0
- HOLD without Gate, FALSE terminal, ungated TRUE blocked
- Technical-only TRUE blocked, Gate-qualified TRUE admitted
- TRUE+HOLD, both-qualified TRUE+TRUE, one-ungated-parent rejection
- stale Gate revision invalidation
- Verification-origin material child와 parent immutability
- Verification runtime bypass 및 Chaining generic research rejection
- canonical/Wiki Mermaid와 기존 architecture validator 통과

## Tracking

- GitHub Issue: 상위 #1, #2, #4, #5, #6, #7, #9, #10과 의미 동기화
- Pull Request: 이번 작업에서는 생성·수정하지 않음
- 반영 commit: 이 ADR을 포함한 branch commit은 Git history로 추적하고, 병합 commit SHA는 `ACCEPTED` 전환 때 기록
