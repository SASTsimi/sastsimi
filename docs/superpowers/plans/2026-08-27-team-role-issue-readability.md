# Team Role Issue Readability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Architecture v5의 GitHub Issue #1–#10을 실제 팀원에게 연결하고, 처음 읽는 사람도 담당 작업과 완료 결과를 이해할 수 있게 고친다.

**Architecture:** 기존 23단계 정본과 역할 권한 경계는 유지한다. GitHub Issue에는 쉬운 요약과 단계 이름 중심 흐름을 먼저 배치하고, 기존 상세 계약·금지 권한·완료 조건은 그 아래 검토 기준으로 보존한다. 로컬 governance 문서와 GitHub assignee/body를 같은 매핑으로 동기화한다.

**Tech Stack:** GitHub Issues, Markdown, Git

**Spec:** `docs/review/ISSUE_CATALOG.md`, 사용자 제공 팀 역할 표

## Global Constraints

- 현재 상태는 `DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED`다.
- Gate 담당은 Verification verdict나 사람의 공개 결정을 대신하지 않는다.
- R3은 현재 설계 검토 단계에서는 구현 가능성과 통합 계획을 검토하고, runtime 구현은 승인 후 후속 Issue로 분리한다.
- #10의 independent final reviewer는 사용자가 지정하지 않았으므로 임의로 배정하지 않는다.
- 숫자만 나열한 단계 범위 대신 단계 이름과 `6–7단계` 표기를 사용한다.

---

### Task 1: 팀 매핑과 governance 문서 정리

**Files:**
- Modify: `README.md`
- Modify: `docs/governance/OWNERSHIP.md`
- Modify: `docs/governance/OPEN_QUESTIONS.md`
- Modify: `docs/review/FINDINGS.md`
- Modify: `docs/review/ISSUE_TRACKER.md`
- Modify: `docs/review/ISSUE_CATALOG.md`

**Interfaces:**
- Consumes: 김태현 `@taehyeon-git`, 윤희섭 `@v1sion`, 김나연 `@meow`, 배승원 `@baeseungwon1010`, 임채민 `@UltraPaechKeen`, 조근석 `@Potatonion`, 성병찬 `@gitterable`, 김혜령 `@kimhr8465`
- Produces: 이름·GitHub 계정·역할·Issue가 일치하는 표와 역할별 쉬운 설명

- [x] README 담당 영역 표에 이름과 GitHub 계정을 추가한다.
- [x] OWNERSHIP과 ISSUE_TRACKER에 실제 계정과 GitHub 배정 가능 여부를 기록한다.
- [x] 역할 매핑 Blocker를 실제 assignee·대체 reviewer 상태에 맞게 IN_PROGRESS로 구체화하고 independent reviewer는 OPEN으로 유지한다.
- [x] ISSUE_CATALOG의 각 역할에 쉬운 설명과 실제 담당자를 추가한다.

### Task 2: GitHub Issue #1–#10 재작성과 배정

**Files:**
- Update: GitHub Issue #1–#10

**Interfaces:**
- Consumes: Task 1의 동일 팀 매핑과 기존 Issue 상세 계약
- Produces: 쉬운 요약, 담당자, 작업 흐름, 해야 할 일, 산출물, 상세 검토 기준이 있는 Issue

- [x] #1은 PM 공동 담당을 본문에 연결하고, 선택 가능한 `@taehyeon-git`을 배정한 뒤 전체 작업 순서를 쉽게 설명한다.
- [x] #2–#9를 역할별 계정과 연결하고, GitHub 선택기에 나타나는 계정은 실제 assignee로 배정한다.
- [x] 모든 Issue의 bare pipeline 범위를 단계 이름 중심 문장으로 교체한다.
- [x] 각 Issue 상단에 `한 줄 설명`, `담당자`, `이번에 할 일`, `완료 시 남는 결과`를 추가한다.
- [x] #10은 전 팀 필수 검토자를 계정과 함께 적되 independent final reviewer assignee는 비워 둔다.
- [x] 기존 금지 권한과 완료 조건이 쉬운 설명 과정에서 약화되지 않았는지 재검토한다.

실제 assignee 배정 완료: `@taehyeon-git`, `@baeseungwon1010`, `@Potatonion`, `@gitterable`. GitHub 선택기에 나타나지 않아 본문 연결만 완료: `@v1sion`, `@meow`, `@kimhr8465`, `@UltraPaechKeen`.

### Task 3: 검증·커밋·Draft PR 갱신

**Files:**
- Verify: 모든 Markdown, GitHub Issue #1–#10, Draft PR #11

**Interfaces:**
- Consumes: Task 1–2 변경
- Produces: 검증된 `docs/role-review-governance` 원격 브랜치와 갱신된 Draft PR #11

- [x] local Markdown link, fence, trailing whitespace와 Mermaid 8개 일치를 검사한다.
- [x] GitHub Issue #1–#10의 assignee와 쉬운 설명을 다시 읽어 대조한다.
- [x] `git diff --check` 후 커밋하고 `docs/role-review-governance`에 push한다.
- [x] Draft PR #11이 두 팀 매핑 문서와 Issue #1–#10을 계속 연결하는지 확인한다.
