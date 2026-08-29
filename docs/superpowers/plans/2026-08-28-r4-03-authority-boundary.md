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

- [x] **Step 5: commit 후 두 번째 stacked diff review**

검증 기록:

- Markdown 55개 검사 통과
- Mermaid 정본 13개와 Wiki 사본 13개 일치, 실제 SVG 렌더링 13개 통과
- R4-02 선행 계약 이름 11개, 원자적 전이 field 3개, output binding 5개 유지
- R4-03 계약 이름 16개, action type 16개, action별 exact check 16개, requester binding 16개 검사 통과
- `ActionCheck` type 15개, 사람 검토 공통 field 15개, 실제 LLM 호출 경계 2개 검사 통과
- 권한 오류 10개, 부정 시나리오 25개, 권한 규칙 26개 검사 통과
- 전체 자동 검사 `Failures: 0`, `git diff --check` 통과
- 독립 1차 검토의 Critical 2개·Important 3개와 2차 검토의 Critical 1개를 모두 수정
- 최종 독립 재검토 결과 Critical 0, Important 0, Minor 0

- [x] **Step 6: branch push와 PR 생성**

PR은 `review/r4-02-state-recovery`를 base로 시작하고 `Closes #15`, `Refs #5`, R4-02 PR 의존성을 기록한다.

- PR: [#27](https://github.com/SASTsimi/sastsimi/pull/27)
- Base: `review/r4-02-state-recovery`
- Head: `review/r4-03-authority-boundary`
- 실제 GitHub 교차 검토 요청: `kimhr8463`, `Potatonion`, `gitterable`, `UltraPeachKeen`
- `v1sion`은 저장소 collaborator가 아니어서 GitHub review request API가 HTTP 422로 거부했다. 권한이 추가되면 다시 요청한다.

- [x] **Step 7: 원격 PR head·파일·diff·checks 재검증**

원격 확인 기록:

- 상태 `OPEN`, merge 상태 `CLEAN`, `MERGEABLE`
- 원격 head SHA가 로컬 commit과 일치
- stacked diff는 R4-03 관련 26개 파일
- GitHub에 등록된 자동 check는 없음

### PR #27 외부 리뷰 반영

- [x] R5 리뷰 1: Technical·Rule Scope·Reporter 호출의 exact revision을 `REVISION`·`GATE_ORDER`·`REPORT_READY`에 연결하고 호출 직전 재검사
- [x] R5 리뷰 2: Technical `REVISE` 뒤 같은 input revision·domain input hash 재투표를 action 권한 단계에서 차단
- [x] R5 리뷰 3: semantic `INVALID_OUTPUT`, action 권한 오류, stale state/revision 오류의 기록 층 분리
- [x] R5 리뷰 4: 공식 정책 의미는 Rule Scope Gate가 판단하고 Runtime Validator는 구조·reference 확인과 Reporter 차단만 집행
- [x] R6 리뷰 1: Pro/Con의 명시적 독립 `NEW` session과 retry·failover의 역할·session 분리 강제
- [x] R6 리뷰 2: `SAVE_RESULT.result_kind`·`candidate_result_ref`, 생산 역할, exact candidate, named falsification, 오류 분리와 `COMMITTED` 연결 강제

리뷰 반영 커밋:

- `740ac6a` `docs: enforce gate action review boundaries`
- `55d8351` `docs: bind debate sessions and result saves`

재검증 결과:

- Markdown 55개, 정본/Wiki Mermaid 13쌍 검사 통과
- R4-02 review rule 4개와 부정 시나리오 14개 유지
- R4-03 action type/check/requester binding 각 16개, ActionCheck 15개 유지
- R4-03 권한 오류 10개, 부정 시나리오 25개, 권한 규칙 26개 검사 통과
- `Failures: 0`, `git diff --check` 통과
