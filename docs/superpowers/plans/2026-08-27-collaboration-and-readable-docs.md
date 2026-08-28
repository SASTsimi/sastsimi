# Collaboration and Readable Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** PM 상위 Issue와 담당자 생성 하위 Issue 운영 방식을 저장소 전체에 반영하고, 모든 문서의 목적과 필수 전문용어를 처음 참여한 팀원도 이해할 수 있게 설명한다.

**Architecture:** 기존 #1–#10과 Architecture v5의 정확한 데이터 이름·상태값·권한 경계는 유지한다. 첫 화면·협업·governance·review 문서는 쉬운 한국어 중심으로 재구성하고, 기술 기준 문서는 상단 독자 안내와 첫 사용 용어 설명을 추가한다. 공통 용어집과 전체 문서 지도를 새 진입점으로 둔다.

**Tech Stack:** Markdown, GitHub Issues, Mermaid, Git

**Spec:** `docs/superpowers/specs/2026-08-27-collaboration-and-readable-docs-design.md`

## Global Constraints

- 현재 상태 `DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED`를 유지한다.
- #1은 PM 전체 관리 Issue, #2–#9는 역할별 상위 Issue, #10은 전체 최종 검토 Issue로 유지한다.
- 기존 Issue 제목·번호·논의 기록을 삭제하거나 다시 만들지 않는다.
- 역할 담당자는 자신의 역할별 상위 Issue 아래에 세부 하위 Issue를 직접 만든다.
- 데이터 형식, 필드명, 상태값과 Mermaid 식별자는 정확한 표기를 유지한다.
- Gate는 Verification 판정을 변경하지 않고 Reporter는 초안만 작성하며 사람만 공개를 결정한다.
- 정본과 Wiki Mermaid 8개는 내용이 같아야 한다.

---

### Task 1: 공통 용어집과 전체 문서 지도 작성

**Files:**
- Create: `docs/GLOSSARY.md`
- Create: `docs/DOCUMENT_GUIDE.md`
- Modify: `docs/README.md`

**Interfaces:**
- Consumes: 설계 문서 5절의 공통 용어, 현재 `rg --files` 목록
- Produces: 모든 문서가 링크할 공통 용어 설명과 저장소 전체 파일별 목적 지도

- [x] **Step 1: 공통 용어집 작성**

`docs/GLOSSARY.md`에 용어, 쉬운 설명, 정확한 사용 기준을 표로 작성한다. 최소 항목은 `candidate baseline`, `contract`, `CodeWorkspace`, `StoredDataRef`, `record`, `runtime validator`, `upstream/downstream`, `owner/reviewer`, `Finding`, `Gate`, `human handoff`, `provenance`, `corpus`, `observability`, `TRUE/FALSE/HOLD`, `PoC`, `CWE`, `Primitive`, `Research`, `sandbox`, `provider/session`이다.

- [x] **Step 2: 저장소 전체 문서 지도 작성**

`docs/DOCUMENT_GUIDE.md`에 root 문서, governance, review, Architecture 01–13, Wiki, Wiki 보조 파일, superpowers 설계·계획 기록을 한 파일씩 적는다. 각 행은 `파일`, `쉽게 말하면`, `주로 읽는 사람`, `기준 문서 여부` 열을 사용한다.

- [x] **Step 3: docs 진입점 단순화**

`docs/README.md`를 쉬운 문장으로 바꾸고 첫 링크를 `DOCUMENT_GUIDE.md`, 두 번째 링크를 `GLOSSARY.md`로 둔다. 번호 문서가 기술 기준이고 Wiki와 superpowers 기록은 참고 자료라는 차이를 설명한다.

- [x] **Step 4: Task 1 검증**

Run: `rg -n "DOCUMENT_GUIDE|GLOSSARY" docs/README.md docs/DOCUMENT_GUIDE.md docs/GLOSSARY.md`

Expected: 세 파일의 상호 링크와 제목이 출력된다.

---

### Task 2: README와 협업 안내에 Issue 계층 반영

**Files:**
- Modify: `README.md`
- Modify: `CONTRIBUTING.md`

**Interfaces:**
- Consumes: #1–#10 구조, 역할 담당자 표, Task 1 용어집과 문서 지도
- Produces: 처음 참여한 팀원이 읽는 프로젝트 설명과 실제 업무 시작 순서

- [x] **Step 1: README 첫 화면 재구성**

README 상단에 `30초 요약`, `지금 무엇을 하는 저장소인가`, `팀원이 일을 시작하는 순서`를 둔다. 전문용어는 쉬운 설명 뒤 괄호에 정확한 이름을 적고, 전체 23단계는 쉬운 단계 묶음과 상세 링크로 안내한다.

- [x] **Step 2: README에 Issue 계층과 담당자 책임 추가**

#1 → #2–#9 → 담당자 생성 하위 Issue → PR → #10의 순서를 표시한다. PM은 전체 목표·역할 충돌·진행 상태를 관리하고, 역할 담당자는 세부 하위 Issue를 직접 작성한다는 차이를 명시한다.

- [x] **Step 3: CONTRIBUTING에 하위 Issue 작성 절차 추가**

브랜치보다 먼저 하위 Issue를 만들도록 순서를 바꾼다. 하위 Issue의 필수 항목은 담당자, 한 줄 설명, 필요한 이유, 할 일, 수정 문서, 완료 조건, 상위 Issue 번호다. PR은 `Closes #하위-Issue`와 `Refs #역할별-상위-Issue`를 함께 사용한다.

- [x] **Step 4: 협업 문서의 영어 중심 표현 정리**

`upstream/downstream`, `owner`, `reviewer`, `runtime`, `record/state`, `focused PR`의 첫 사용에 쉬운 한국어 설명을 붙이고 이후에는 한국어를 우선한다.

- [x] **Step 5: Task 2 검증**

Run: `rg -n "하위 Issue|Closes #하위|Refs #역할별|PM은|담당자는" README.md CONTRIBUTING.md`

Expected: Issue 계층, PM 책임과 담당자 책임이 두 문서에서 확인된다.

---

### Task 3: Governance 문서를 실제 역할과 쉬운 표현으로 정리

**Files:**
- Modify: `docs/governance/OWNERSHIP.md`
- Modify: `docs/governance/OPEN_QUESTIONS.md`
- Modify: `docs/governance/REVIEW_CHECKLIST.md`

**Interfaces:**
- Consumes: 사용자 제공 8개 역할·담당자·GitHub 계정, Issue 계층
- Produces: 역할 책임, GitHub 배정 상태, 미결정 사항과 검토 기준의 쉬운 정본

- [x] **Step 1: OWNERSHIP의 영문 역할 표현 교체**

`Repository steward`, `Design review coordinators`, `Independent final reviewer`, `Domain owner`, `Primary`, `upstream/downstream`을 각각 `저장소 관리 담당`, `설계 검토 진행 담당`, `독립 최종 검토자`, `역할 담당자`, `주요 담당 영역`, `앞 단계/뒤 단계 검토자`로 바꾼다. 정확한 영문 용어가 필요한 곳에는 괄호로 한 번만 남긴다.

- [x] **Step 2: 역할 담당자의 하위 Issue 책임 추가**

각 역할별 상위 Issue와 담당자를 유지하고, 역할 담당자가 세부 하위 Issue를 작성·연결·완료 확인한다는 절을 추가한다. PM이 대신 세부 작업을 작성하지 않는다는 경계를 포함한다.

- [x] **Step 3: 역할 배정과 GitHub 권한 상태 분리**

역할 담당은 8개 모두 확정됐다고 적는다. `@v1sion`, `@meow`, `@kimhr8465`, `@UltraPaechKeen`은 역할 미배정이 아니라 GitHub assignee 선택 문제라고 별도 표시한다.

- [x] **Step 4: OPEN_QUESTIONS를 쉬운 질문 형식으로 변경**

각 항목에 `무엇을 정해야 하나`, `정하지 않으면 생기는 문제`, `담당 역할과 연결 Issue`를 표시한다. 구현 전 필수 결정의 데이터 이름은 유지하되 첫 사용에 쉬운 설명을 붙인다.

- [x] **Step 5: REVIEW_CHECKLIST에 하위 Issue 검사 추가**

역할별 상위 Issue의 하위 Issue 연결, 하위 Issue 완료 조건, PR 연결, 모든 하위 Issue 완료 후 상위 Issue 종료를 확인하는 항목을 추가한다. 전문 상태값은 쉬운 뜻을 함께 적는다.

- [x] **Step 6: Task 3 검증**

Run: `rg -n "하위 Issue|역할 담당은|GitHub assignee|저장소 관리 담당|독립 최종 검토자" docs/governance`

Expected: 세 governance 문서에서 새 역할·Issue 규칙과 상태 분리가 확인된다.

---

### Task 4: Review 업무 문서의 구조와 설명 정리

**Files:**
- Modify: `docs/review/ISSUE_TRACKER.md`
- Modify: `docs/review/ISSUE_CATALOG.md`
- Modify: `docs/review/FINDINGS.md`
- Modify: `docs/review/PROVENANCE.md`
- Modify: `docs/review/decisions/README.md`

**Interfaces:**
- Consumes: Task 2–3의 Issue 계층과 쉬운 용어 기준
- Produces: 역할별 작업 분해, 발견사항, 출처와 설계 결정 기록을 안내하는 업무 문서

- [x] **Step 1: ISSUE_TRACKER에 네 단계 계층 추가**

#1, #2–#9, 담당자 생성 하위 Issue, #10의 목적과 종료 조건을 표로 설명한다. 현재 실제 assignee 상태는 유지한다.

- [x] **Step 2: ISSUE_CATALOG에 공통 하위 Issue 지침 추가**

각 역할별 상위 Issue가 담당자의 작업 분해 출발점임을 명시한다. 모든 R1–R8 절에 역할에 맞는 하위 Issue 예시 2–4개를 추가하되 실제 Issue를 PM이 미리 생성하지는 않는다.

- [x] **Step 3: FINDINGS에 쉬운 설명 추가**

Blocker와 High 표에 `쉽게 말하면` 열을 추가한다. 정확한 ID, 상태, 완료 조건과 연결 Issue는 유지한다.

- [x] **Step 4: PROVENANCE와 결정 기록 안내 단순화**

`PROVENANCE.md` 상단에 이 파일이 ‘설계 파일을 어디에서 가져왔는지 증명하는 기록’임을 적는다. `decisions/README.md`는 설계 결정을 남겨야 하는 상황과 기록 순서를 한국어로 설명한다.

- [x] **Step 5: Task 4 검증**

Run: `rg -n "하위 Issue|쉽게 말하면|가져온 출처|설계 결정" docs/review`

Expected: tracker, catalog, findings, provenance, decisions 문서의 새 안내가 출력된다.

---

### Task 5: Architecture v5 번호 문서의 독자 안내와 용어 설명 추가

**Files:**
- Modify: `docs/architecture-v5/README.md`
- Modify: `docs/architecture-v5/01-system-overview.md`
- Modify: `docs/architecture-v5/02-static-fact-layer.md`
- Modify: `docs/architecture-v5/03-agent-roles-and-orchestration.md`
- Modify: `docs/architecture-v5/04-verification-and-dynamic-reproduction.md`
- Modify: `docs/architecture-v5/05-llm-gate-and-reporting.md`
- Modify: `docs/architecture-v5/06-chaining.md`
- Modify: `docs/architecture-v5/07-results-and-observability.md`
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Modify: `docs/architecture-v5/09-llm-provider-session-and-logging.md`
- Modify: `docs/architecture-v5/10-security-boundaries.md`
- Modify: `docs/architecture-v5/11-migration-from-v4.md`
- Modify: `docs/architecture-v5/12-report-draft-template.md`
- Modify: `docs/architecture-v5/13-architecture-diagrams.md`

**Interfaces:**
- Consumes: Task 1 용어집, 기존 Architecture v5 의미
- Produces: 기술 정확성을 유지하면서 목적·독자·확인 결과가 분명한 기준 문서

- [x] **Step 1: v5 README를 쉬운 진입점으로 변경**

`candidate baseline`, `canonical`, `runtime`의 쉬운 뜻을 붙이고, 23단계를 `입력과 사실 수집`, `가설과 검증`, `동적 재현과 연계 탐색`, `최종 검토와 보고`, `사람의 결정`으로 먼저 묶어 설명한다. 정확한 23단계 목록은 유지한다.

- [x] **Step 2: 01–13 상단에 독자 안내 추가**

각 문서 제목 아래에 `이 문서는 무엇을 설명하나요?`, `누가 읽어야 하나요?`, `읽은 뒤 무엇을 확인하거나 결정하나요?` 세 문장을 파일 내용에 맞게 작성한다.

- [x] **Step 3: 주요 전문용어 첫 사용 설명 보강**

각 문서에서 반복되는 `record`, `artifact`, `retrieval`, `verdict`, `restriction`, `capability`, `debate`, `Primitive`, `provider`, `session`, `observability`, `redaction`, `migration`, `Gate`의 첫 사용에 쉬운 설명 또는 용어집 링크를 추가한다. 코드 블록과 정확한 식별자는 변경하지 않는다.

- [x] **Step 4: 데이터 계약 문서에 한 줄 설명 추가**

`08-lightweight-data-contracts.md`의 각 데이터 형식 1–11 앞에 ‘어느 단계가 만들고 다음 단계가 무엇에 쓰는 데이터인지’를 한 문장으로 적는다.

- [x] **Step 5: 다이어그램 읽는 법 추가**

`13-architecture-diagrams.md`에 도형과 화살표를 읽는 법, 상세 용어는 용어집에서 확인하는 방법을 추가한다. Mermaid 코드 본문은 변경하지 않는다.

- [x] **Step 6: Task 5 검증**

Run: `rg -l "이 문서는 무엇을 설명하나요\?" docs/architecture-v5/README.md docs/architecture-v5/[0-1][0-9]-*.md`

Expected: README와 번호 문서 13개가 모두 출력된다.

---

### Task 6: Wiki를 쉬운 요약 계층으로 정리

**Files:**
- Modify: `docs/architecture-v5/wiki/README.md`
- Modify: `docs/architecture-v5/wiki/_Sidebar.md`
- Modify: `docs/architecture-v5/wiki/quick-guide.md`
- Modify: `docs/architecture-v5/wiki/pipeline.md`
- Modify: `docs/architecture-v5/wiki/agents.md`
- Modify: `docs/architecture-v5/wiki/verification-and-dynamic.md`
- Modify: `docs/architecture-v5/wiki/gate-and-reporting.md`
- Modify: `docs/architecture-v5/wiki/chaining.md`
- Modify: `docs/architecture-v5/wiki/providers-and-logging.md`
- Modify: `docs/architecture-v5/wiki/results.md`
- Verify unchanged: `docs/architecture-v5/wiki/index.html`
- Verify unchanged: `docs/architecture-v5/wiki/theme.css`
- Verify unchanged: `docs/architecture-v5/wiki/serve.ps1`
- Verify semantic mirror: `docs/architecture-v5/wiki/diagrams.md`

**Interfaces:**
- Consumes: Task 5 번호 문서와 Task 1 용어집
- Produces: 번호 문서를 바꾸지 않는 쉬운 탐색·요약 Wiki

- [x] **Step 1: Wiki README와 Sidebar 단순화**

Wiki가 쉬운 요약이며 기준 문서가 아니라는 점을 첫 문단에 적는다. 메뉴 이름은 한국어를 먼저 사용한다.

- [x] **Step 2: 주요 Wiki 문서 상단 안내 추가**

각 Markdown 문서에 `쉽게 말하면`과 `상세 기준 문서`를 추가한다. 상태값과 데이터 이름은 그대로 두고 첫 사용에 쉬운 뜻을 붙인다.

- [x] **Step 3: Wiki 다이어그램 동기화 보존**

정본 다이어그램의 Mermaid 블록과 Wiki 다이어그램 블록이 정확히 같은지 검사하고, 설명을 추가해야 하면 Mermaid 블록 밖에만 추가한다.

- [x] **Step 4: Task 6 검증**

Run: `rg -n "쉽게 말하면|상세 기준" docs/architecture-v5/wiki -g '*.md'`

Expected: Wiki 요약 문서마다 쉬운 설명과 기준 문서 링크가 확인된다.

---

### Task 7: GitHub Issue와 Draft PR 갱신

**Files:**
- Update: GitHub Issue #1
- Update: GitHub Issue #2–#9
- Update: GitHub Issue #10
- Update: Draft PR #11

**Interfaces:**
- Consumes: Task 2–6의 확정 문구와 역할 구조
- Produces: 저장소 문서와 일치하는 실제 GitHub 업무 지시

- [x] **Step 1: #1에 전체 운영 규칙 추가**

PM의 책임, 역할 담당자의 하위 Issue 생성 책임, 상위 Issue 종료 조건과 #10 시작 조건을 쉬운 번호 목록으로 추가한다.

- [x] **Step 2: #2–#9에 담당자의 첫 작업 추가**

각 역할별 상위 Issue에 ‘먼저 이 Issue를 2–4개의 세부 하위 Issue로 나누어 직접 생성하고 연결한다’는 안내와 공통 하위 Issue 필수 항목을 추가한다.

- [x] **Step 3: #10에 하위 Issue 완료 검증 추가**

각 역할별 상위 Issue의 모든 하위 Issue와 연결 PR이 완료됐는지 확인하는 체크 항목을 추가한다.

- [x] **Step 4: Draft PR #11 본문 갱신**

새 Issue 계층, 쉬운 문서 원칙, `GLOSSARY.md`, `DOCUMENT_GUIDE.md`, 실제 assignee 제한과 검증 결과를 반영한다. PR은 Draft로 유지한다.

- [x] **Step 5: Task 7 검증**

GitHub Issue #1–#10과 PR #11을 다시 읽어 `하위 Issue`, 역할 담당자, 쉬운 설명, 기존 권한 경계와 Draft 상태를 확인한다.

---

### Task 8: 전체 검증·커밋·푸시

**Files:**
- Verify: 저장소 전체 변경 파일
- Update: 이 계획의 체크박스

**Interfaces:**
- Consumes: Task 1–7 전체 변경
- Produces: 검증된 원격 `docs/role-review-governance` 브랜치와 최신 Draft PR #11

- [x] **Step 1: 문서 무결성 검사**

모든 Markdown 로컬 링크, 코드 블록 쌍, 뒤쪽 공백과 물결표 범위를 검사한다. 실패하면 해당 파일을 수정하고 전체 검사를 다시 실행한다.

- [x] **Step 2: Mermaid 동기화 검사**

`13-architecture-diagrams.md`와 `wiki/diagrams.md`에서 Mermaid 블록이 각각 8개이며 내용이 같은지 확인한다.

- [x] **Step 3: 요구사항 대조**

설계 문서 3–8절의 각 요구사항을 실제 파일과 GitHub Issue에서 하나씩 대조한다. 전문용어 설명, 전체 문서 지도 누락, 역할·권한 경계 변경이 없는지 확인한다.

- [x] **Step 4: Git 검사**

Run: `git diff --check`

Expected: 오류 출력 없이 종료 코드 0.

- [x] **Step 5: 커밋과 푸시**

문서 기반 변경과 검증 기록을 의미 단위로 커밋하고 `docs/role-review-governance` 원격 브랜치에 푸시한다.

- [x] **Step 6: 원격 최종 확인**

로컬 HEAD와 원격 브랜치 SHA가 같고 작업 트리가 깨끗한지 확인한다. Draft PR #11이 `main ← docs/role-review-governance`이며 GitHub 화면에서 충돌이 없는지 확인한다.
