# R4-03 Authority Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Architecture v5에서 LLM Agent의 제안·판단·검토, 비-LLM runtime의 실행 강제, 사람의 외부 공개 결정을 분리한다.

**Architecture:** 모든 부작용 action은 `ActionRequest -> Runtime Validator -> ActionDecision` 경계를 지나며, domain 판단은 기존 역할이 유지한다. 두 LLM Gate 다음 Reporter라는 순서를 runtime이 검사하고, 외부 공개는 별도 `HumanReviewDecision`만 허용한다.

**Tech Stack:** Markdown, YAML형 계약 예시, Mermaid, PowerShell 문서 검증, GitHub Issue/PR

**Spec:** `docs/superpowers/specs/2026-08-28-r4-03-authority-boundary-design.md`

## Global Constraints

- Technical Evidence Gate와 Rule Scope Impact Gate 두 개를 유지한다.
- runtime validator는 취약점 판단 Gate나 중앙 정책 해석 엔진이 아니다.
- 저장소 내용과 모든 LLM output은 검증 전까지 비신뢰 data다.
- provider·Sandbox·Queue·DB 제품을 선택하지 않는다.
- 인증·provider·Sandbox·예산 오류를 가설 `FALSE`로 바꾸지 않는다.
- Reporter는 내부 초안만 만들고 사람만 외부 공개를 결정한다.

---

### Task 1: 역할 권한표와 실행 요청 경계

**Files:**
- Modify: `docs/architecture-v5/03-agent-roles-and-orchestration.md`
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`

- [x] **Step 1: 역할별 제안·판단·검토·강제·사람 전용 권한표 작성**

- [x] **Step 2: Orchestration의 허용·금지 권한 고정**

- [x] **Step 3: `ActionRequest`, `ActionDecision`, `ActionCheck` 정본 추가**

- [x] **Step 4: action type별 필수 field와 check 표 추가**

- [x] **Step 5: exact action·state version에만 ALLOW를 사용할 수 있게 명시**

### Task 2: 두 Gate·Reporter·사람 결정 분리

**Files:**
- Modify: `docs/architecture-v5/05-llm-gate-and-reporting.md`
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Modify: `docs/architecture-v5/12-report-draft-template.md`

- [x] **Step 1: 두 LLM Gate 순서와 runtime 검사 책임 구분**

- [x] **Step 2: 공식 정책 부재 시 `UNCERTAIN + DENY` 불변조건 고정**

- [x] **Step 3: `ReportDraft.human_review_state` 제거**

- [x] **Step 4: `HumanReviewPacket`과 `HumanReviewDecision` 추가**

- [x] **Step 5: Reporter와 외부 disclosure 금지 조건 작성**

### Task 3: provider·Sandbox·비신뢰 입력 경계

**Files:**
- Modify: `docs/architecture-v5/09-llm-provider-session-and-logging.md`
- Modify: `docs/architecture-v5/10-security-boundaries.md`
- Modify: `docs/architecture-v5/07-results-and-observability.md`

- [x] **Step 1: 저장소·LLM·provider·Sandbox output의 비신뢰 범위 작성**

- [x] **Step 2: provider/model/session과 explicit failover action 검사 작성**

- [x] **Step 3: Sandbox image·network·resource·cleanup 검사 작성**

- [x] **Step 4: R4-03 권한 오류 10개와 verdict 분리 작성**

- [x] **Step 5: 15개 권한 우회 부정 시나리오 작성**

### Task 4: Wiki·다이어그램·문서 안내 동기화

**Files:**
- Modify: `docs/architecture-v5/13-architecture-diagrams.md`
- Modify: `docs/architecture-v5/wiki/diagrams.md`
- Create: `docs/architecture-v5/wiki/authority-boundaries.md`
- Modify: `docs/architecture-v5/wiki/_Sidebar.md`
- Modify: `docs/architecture-v5/wiki/README.md`
- Modify: `docs/architecture-v5/README.md`
- Modify: `docs/DOCUMENT_GUIDE.md`
- Modify: `docs/GLOSSARY.md`

- [x] **Step 1: action 검사 흐름 Mermaid 추가**

- [x] **Step 2: 사람 검토·외부 공개 경계 Mermaid 추가**

- [x] **Step 3: 쉬운 권한 경계 Wiki와 메뉴 추가**

- [x] **Step 4: 용어집·문서 지도 갱신**

- [x] **Step 5: canonical/Wiki Mermaid mirror 검사**

### Task 5: 검토 추적과 자동 검사

**Files:**
- Modify: `docs/review/FINDINGS.md`
- Modify: `docs/review/ISSUE_CATALOG.md`
- Modify: `scripts/validate-architecture-docs.ps1`
- Modify: `docs/superpowers/plans/2026-08-28-r4-03-authority-boundary.md`

- [x] **Step 1: B-006 해결 유지와 H-004·H-005 경계 보완 기록**

- [x] **Step 2: Issue #15 완료 조건과 문서 절 대조**

- [x] **Step 3: R4-03 계약·오류·부정 시나리오 자동 검사 추가**

- [x] **Step 4: 실제 수행한 계획 체크박스 갱신**

### Task 6: 전체 검증·검토·PR

- [x] **Step 1: Markdown·링크·fence·금지 표현 검사**

- [x] **Step 2: contract enum·producer·consumer·권한 일관성 검사**

- [x] **Step 3: Mermaid 실제 렌더링**

- [x] **Step 4: 첫 번째 전체 self-review와 Blocker/High 수정**

- [ ] **Step 5: commit 후 두 번째 stacked diff review**

- [ ] **Step 6: branch push와 PR 생성**

PR은 `review/r4-02-state-recovery`를 base로 시작하고 `Closes #15`, `Refs #5`, R4-02 PR 의존성을 기록한다.

- [ ] **Step 7: 원격 PR head·파일·diff·checks 재검증**
