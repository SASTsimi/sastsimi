# Architecture v5 Role Review Governance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** GitHub에 Architecture v5 Parent Epic, 역할별 8개 Issue, 최종 교차 검토 Issue를 만들고 실제 Issue 번호를 governance 문서에 연결한 Draft PR을 생성한다.

**Architecture:** Architecture v5 candidate baseline은 `main`에 유지한다. 역할별 작업은 각각 독립 Issue와 `main` 대상 PR로 수행하며, 이번 `docs/role-review-governance` 브랜치는 실제 Issue 링크와 검토 운영 문서만 동기화한다.

**Tech Stack:** Git, GitHub Issues/PR, Markdown, GitHub 브라우저 UI

**Spec:** `docs/review/ISSUE_CATALOG.md`

## Global Constraints

- 현재 상태는 `DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED`다.
- 실제 GitHub username이 확인된 계정만 assignee로 지정한다.
- R1~R3와 R5~R8 및 최종 독립 reviewer는 username 확인 전 미할당으로 둔다.
- Repository steward와 초기 R4 coordination만 `@taehyeon-git`에 할당한다.
- 모든 역할 PR은 최신 `main`에서 분기하여 `main`을 대상으로 한다.
- Blocker/High가 0이 되기 전에는 최종 승인 상태로 변경하지 않는다.
- Draft PR은 Issue·governance 연결 검토용이며 Architecture 승인 PR이 아니다.

---

### Task 1: GitHub Issue 생성

**Files:**
- Read: `docs/review/ISSUE_CATALOG.md`
- Read: `docs/governance/OWNERSHIP.md`

**Interfaces:**
- Consumes: 역할별 목적, 문서 범위, 입력·출력, 금지 권한, reviewer, 완료 조건
- Produces: Parent Epic 1개, R1~R8 Issue 8개, Final Issue 1개의 GitHub URL과 번호

- [x] **Step 1: 기존 중복 Issue 확인**

GitHub Issues 화면에서 `[EPIC]`, `[R1]`~`[R8]`, `[FINAL]` 제목을 검색한다. 동일 목적의 열린 Issue가 있으면 새로 만들지 않고 해당 번호를 사용한다.

- [x] **Step 2: Parent Epic 생성**

제목은 `[EPIC] Architecture v5 candidate baseline 검토와 승인`으로 하고 목적·범위·비범위·완료 조건을 기재한다. Repository steward인 `taehyeon-git`을 assignee로 지정한다.

- [x] **Step 3: R1~R8 생성**

`ISSUE_CATALOG.md`의 각 역할별 역할 소유권, pipeline 단계, 검토 문서, 입력·출력, 금지 권한, 필수 교차 reviewer와 완료 조건을 Issue 본문에 포함한다. R4만 `taehyeon-git`에 할당하고 나머지는 역할 owner가 계정을 확인한 뒤 claim하도록 미할당 상태로 둔다.

- [x] **Step 4: Final Issue 생성**

제목은 `[FINAL] Architecture v5 전체 교차 시나리오와 최종 승인 검토`로 하고 18개 시나리오, freeze SHA, 독립 reviewer와 최종 상태 변경 조건을 포함한다.

- [x] **Step 5: Parent Epic에 Child 링크 연결**

생성된 R1~R8과 Final Issue의 실제 번호를 Parent Epic 체크리스트에 링크한다.

### Task 2: Governance 문서 동기화

**Files:**
- Modify: `README.md`
- Modify: `docs/governance/OWNERSHIP.md`
- Modify: `docs/governance/OPEN_QUESTIONS.md`
- Modify: `docs/governance/REVIEW_CHECKLIST.md`
- Modify: `docs/review/FINDINGS.md`
- Modify: `docs/review/ISSUE_CATALOG.md`
- Create: `docs/review/ISSUE_TRACKER.md`

**Interfaces:**
- Consumes: Task 1에서 생성된 실제 Issue 번호와 URL
- Produces: 역할·Issue·브랜치·필수 reviewer·상태를 한눈에 확인하는 저장소 문서

- [x] **Step 1: Issue tracker 작성**

Parent Epic, R1~R8, Final의 실제 번호, 역할, assignee 상태, branch 이름, primary 문서, 필수 reviewer와 현재 상태를 표로 작성한다.

- [x] **Step 2: README 연결**

root README의 역할별 검토 안내에서 Parent Epic과 Issue tracker를 직접 연결한다.

- [x] **Step 3: Ownership와 open questions 갱신**

확인된 assignee만 기록하고, 미확인 역할 username과 independent final reviewer는 계속 Blocker로 유지한다.

- [x] **Step 4: Findings와 checklist 갱신**

각 Blocker/High에 owner 역할과 처리할 Issue를 연결하고, 모든 역할 Issue가 `main` 대상 PR과 연결되는지 확인하는 항목을 유지한다.

- [x] **Step 5: Catalog에 live Issue 링크 추가**

각 역할 절 제목 바로 아래에 실제 GitHub Issue 링크를 추가하되, 상세 기준 본문은 그대로 유지한다.

### Task 3: 문서 검증과 Draft PR

**Files:**
- Verify: 모든 Markdown과 `docs/architecture-v5/13-architecture-diagrams.md`
- Commit: Task 1~2 문서 변경

**Interfaces:**
- Consumes: 실제 Issue 링크가 반영된 governance/review 문서
- Produces: 검증된 `docs/role-review-governance` 원격 브랜치와 `main` 대상 Draft PR

- [x] **Step 1: Markdown 검증**

모든 local Markdown link, fence 짝, trailing whitespace를 검사하고 오류가 0인지 확인한다.

- [x] **Step 2: Mermaid와 상태 검증**

정본/Wiki 다이어그램이 동일하고 Mermaid 블록이 8개인지 확인한다. 상태 표현은 계속 `REVIEW_REQUIRED / NOT_IMPLEMENTED`여야 한다.

- [ ] **Step 3: Commit과 push**

`docs: link Architecture v5 role review issues` 메시지로 commit하고 `docs/role-review-governance` 브랜치를 push한다.

- [ ] **Step 4: Draft PR 생성**

`main` 대상으로 `[Draft] Architecture v5 역할별 Issue와 governance 연결` PR을 만들고, 생성된 Parent Epic과 R1~R8, Final Issue를 본문에 링크한다. 이 PR은 governance 연결 검토용이며 Architecture 승인이나 구현 완료를 뜻하지 않는다고 명시한다.

- [ ] **Step 5: 원격 검증**

Issue 10개, Draft PR 1개, 브랜치 HEAD, PR base/head와 문서 링크가 실제 GitHub에서 일치하는지 확인한다.
