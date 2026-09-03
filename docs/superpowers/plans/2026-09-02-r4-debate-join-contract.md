# R4 Pro·Con Join Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pro·Con 병렬 결과를 exact final Verification에 안전하게 연결하는 R4 공통 계약을 정본·Wiki·검증 스크립트에 반영한다.

**Architecture:** `EvidenceAgentResult`가 한 역할의 근거와 부모·자식 work ID, 공통 입력 hash를 기록하고, child work와 호출 log가 그 exact 결과를 단방향으로 가리킨다. `VerificationResult`는 같은 공통 입력을 사용한 Pro·Con 결과를 하나씩 참조한다. 기존 `WorkExecutionState`, `TransitionCommit`, `LLMCallSpec`과 Runtime Validator가 부모·자식 상태, stale 결과, 교차 역할 입력을 강제한다.

**Tech Stack:** Markdown architecture contracts, PowerShell contract validation, Git

**Spec:** `docs/superpowers/specs/2026-09-02-r4-debate-join-contract-design.md`

## Global Constraints

- 실제 필드명은 짧은 영문을 사용하고 처음 등장할 때 쉬운 한국어 설명을 붙인다.
- 운영 final verdict는 exact Pro·Con 결과가 모두 없으면 저장하지 않는다.
- 실행 오류·예산 부족·취소를 `FALSE | HOLD`로 변환하지 않는다.
- 평가 결과는 Gate·Primitive·Reporter로 승격하지 않는다.
- Pro와 Con은 모든 입력 경로에서 서로의 결과를 읽지 않는다.
- Gate 순서와 사람 최종 공개 경계는 바꾸지 않는다.

---

### Task 1: 정본 결과·work 계약 추가

**Files:**
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`

**Interfaces:**
- Consumes: 기존 `RecordMeta`, `StoredDataRef`, `WorkExecutionState`, `EvidenceClaim`, `LLMInvocationLog`
- Produces: `EvidenceAgentResult`, `parent_work_ref`, `debate_input_hash`, `pro_evidence_ref`, `con_evidence_ref`

- [ ] `EvidenceAgentResult` schema와 역할별 evidence 규칙을 추가한다.
- [ ] Pro·Con child work의 `parent_work_ref` 규칙을 추가한다.
- [ ] 운영·평가 모드별 `VerificationResult` reference 필수/null 조합을 추가한다.
- [ ] final 합성과 `SAVE_RESULT`가 exact 두 결과를 검사하는 규칙을 추가한다.

### Task 2: 상태·관찰성·세션 경계 동기화

**Files:**
- Modify: `docs/architecture-v5/03-agent-roles-and-orchestration.md`
- Modify: `docs/architecture-v5/07-results-and-observability.md`
- Modify: `docs/architecture-v5/09-llm-provider-session-and-logging.md`
- Modify: `docs/architecture-v5/10-security-boundaries.md`

**Interfaces:**
- Consumes: Task 1의 exact 결과·부모 작업 필드
- Produces: 한쪽 실패 상태 전파, 로그 연결, trusted prompt builder와 `CROSS_ROLE_INPUT_DENIED`

- [ ] 하위 work 대기·복구 불가·취소가 상위 Verification과 가설에 전달되는 규칙을 추가한다.
- [ ] Pro·Con parsed output이 `EvidenceAgentResult`를 가리키도록 로그 의미를 명확히 한다.
- [ ] prompt payload·조회·tool을 포함한 모든 교차 역할 입력을 금지한다.
- [ ] stale·부분 join·교차 오염 부정 시나리오를 추가한다.

### Task 3: 쉬운 Wiki 설명 동기화

**Files:**
- Modify: `docs/architecture-v5/wiki/common-contracts.md`
- Modify: `docs/architecture-v5/wiki/state-and-recovery.md`
- Modify: `docs/architecture-v5/wiki/providers-and-logging.md`

**Interfaces:**
- Consumes: Task 1과 Task 2의 정본 규칙
- Produces: 담당자가 구현 전에 읽을 수 있는 쉬운 한국어 요약

- [ ] exact Pro·Con 결과 연결을 설명한다.
- [ ] 한쪽 실패 때 부모·자식 상태를 설명한다.
- [ ] prompt와 결과 조회를 포함한 독립성 경계를 설명한다.

### Task 4: 자동 계약 회귀 검증

**Files:**
- Modify: `scripts/validate-architecture-docs.ps1`

**Interfaces:**
- Consumes: Task 1~3의 필수 contract marker
- Produces: 필드·상태·독립성 규칙이 빠지면 실패하는 문서 검증

- [ ] 새 schema와 reference 필드를 검사한다.
- [ ] 부모·자식 상태 전파 문장을 검사한다.
- [ ] trusted prompt builder와 `CROSS_ROLE_INPUT_DENIED`를 검사한다.
- [ ] 전체 문서 검증과 `git diff --check`를 실행한다.

### Task 5: 검토·커밋·main 반영

**Files:**
- Review: Task 1~4의 모든 변경 파일

**Interfaces:**
- Consumes: 검증을 통과한 문서 변경
- Produces: 최신 `main` 위의 단일 R4 계약 커밋

- [ ] PR #69의 R6 흐름과 필드 의미를 다시 대조한다.
- [ ] 전문용어 설명, null 조합, producer·consumer, Gate 경계를 재검토한다.
- [ ] 최신 `origin/main`과 fast-forward 가능 여부를 확인한다.
- [ ] R4 계약 커밋을 만들고 `main`에 push한다.
