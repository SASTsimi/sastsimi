# Architecture v5 Role Boundary Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** GitHub 상위 Issue `#1–#10`과 Architecture v5 역할 문서가 R1–R8의 판단·생산·실행·강제 책임을 같은 의미로 설명하게 한다.

**Architecture:** 역할별 생산자·소비자 계약을 중심으로 문서를 정리한다. R6가 동적 재현 모드와 `ReproductionPlan`을 결정·생산하고, trusted runtime이 허가하며, R7이 exact plan을 실행해 동적 결과를 반환하는 흐름을 기준선으로 사용한다.

**Tech Stack:** Markdown, Mermaid, PowerShell architecture validator, GitHub Issues/CLI

**Spec:** `docs/superpowers/specs/2026-08-31-role-boundary-alignment-design.md`

## Global Constraints

- 공통 계약 필드와 enum은 변경하지 않는다.
- Issue 상태·담당자·마일스톤은 변경하지 않는다.
- `#19–#22`의 전문 설계는 현재 역할 경계와 충돌하는 문장이 발견될 때만 최소 수정한다.
- GitHub 본문은 기존 내용을 유지하고 충돌하는 문장만 교체하거나 경계 설명을 추가한다.
- PR은 만들 수 있지만 병합하지 않는다.

---

### Task 1: 저장소 역할 문서 정합화

**Files:**
- Modify: `README.md`
- Modify: `docs/governance/OWNERSHIP.md`
- Modify: `docs/review/ISSUE_TRACKER.md`
- Modify: `docs/review/ISSUE_CATALOG.md`
- Modify if needed: `docs/architecture-v5/03-agent-roles-and-orchestration.md`
- Modify if needed: `docs/architecture-v5/04-verification-and-dynamic-reproduction.md`
- Modify if needed: `docs/architecture-v5/wiki/agents.md`
- Modify if needed: `docs/architecture-v5/wiki/verification-and-dynamic.md`

**Interfaces:**
- Consumes: 승인된 역할 경계 명세와 현재 Architecture v5 정본
- Produces: R1–R8 역할명, 소유 판단, 입력·출력, 금지 권한과 교차 전달이 일치하는 문서

- [ ] **Step 1: 모호한 기존 표현을 검색한다**

Run:

```powershell
rg -n "재현 필요성 결정|선택 기준|dynamic decision|최종 TRUE.*체이닝|REVISE.*Orchestration|예산.*강제" README.md docs
```

Expected: R6/R7, R1, R5, R8 경계 검토 대상이 출력된다.

- [ ] **Step 2: 역할 표와 검토 카탈로그를 수정한다**

Required content:

```text
R6: 동적 재현 필요성·EnvironmentRequirements·최소 ReproductionPlan 결정/생산
Runtime: schema/reference/권한/예산 검사와 COMMITTED/ALLOW
R7: Controller 외부 경계 정책·clean Sandbox 자동화·자율 Agent 실행·AgentLog/PoC/DynamicReproductionResult 생산
R6: COMMITTED 결과 소비와 최종 TRUE/FALSE/HOLD
```

- [ ] **Step 3: 연결 역할 경계를 동기화한다**

Required content:

```text
R1: Gate provenance가 있는 PROVIDED Primitive만 TRUE chaining 입력
R5: Technical REVISE는 같은 ACTIVE Verification owner에게 반환
R8: budget profile/metric을 정의하고 trusted runtime이 실제 강제
R3/R4: domain 의미를 바꾸지 않고 통합/공통 강제 경계 유지
```

- [ ] **Step 4: 저장소 문서 검증을 실행한다**

Run:

```powershell
& .\scripts\validate-architecture-docs.ps1
git diff --check
```

Expected: `Failures: 0`, `Architecture document validation passed.`, diff 오류 없음.

- [ ] **Step 5: 문서 변경을 커밋한다**

```powershell
git add README.md docs
git commit -m "docs: clarify cross-role authority boundaries"
```

---

### Task 2: GitHub 상위 Issue 본문 정합화

**Files:**
- Modify externally: GitHub Issues `#1`, `#2`, `#6`, `#7`, `#8`, `#9`, `#10`
- Inspect only unless conflict exists: GitHub Issues `#3`, `#4`, `#5`, `#19–#22`

**Interfaces:**
- Consumes: Task 1의 역할 경계 문서와 각 Issue의 현재 본문
- Produces: 기존 작업 내용은 유지하면서 결정자·생산자·실행자·소비자·금지 권한이 명확한 상위 Issue

- [ ] **Step 1: 수정 직전 현재 본문과 상태를 재조회한다**

Run:

```powershell
1..10 | ForEach-Object { gh issue view $_ --repo SASTsimi/sastsimi --json number,title,state,body,assignees }
19..22 | ForEach-Object { gh issue view $_ --repo SASTsimi/sastsimi --json number,title,state,body }
```

Expected: Issue 상태와 기존 본문을 확보하고, 상태·담당자는 변경 대상에서 제외한다.

- [ ] **Step 2: 각 상위 Issue의 충돌 문장을 교체한다**

Required mutations:

```text
#1: R6→runtime→R7→R6 연결 요약
#2: final TRUE 일반 입력 표현을 current gated PROVIDED Primitive로 제한
#6: Technical REVISE의 exact 목적지를 같은 R6 owner로 고정
#7: LIMITED/FULL 결정, ReproductionPlan 생산, COMMITTED 결과 소비를 R6 출력/책임에 추가
#8: 재현 필요성·모드 선택 제거, COMMITTED plan 실행·결과 생산으로 교체, #19–#22 연결
#9: budget profile 설계와 runtime enforcement 분리
#10: plan 생산·허가·실행·결과 commit·최종 판정 종단 시나리오 추가
```

- [ ] **Step 3: 변경하지 않은 내용과 상태가 보존됐는지 확인한다**

Run:

```powershell
1..10 | ForEach-Object { gh issue view $_ --repo SASTsimi/sastsimi --json number,title,state,body,assignees }
```

Expected: 제목·상태·담당자 보존, 필요한 경계 문구 존재, 기존 범위와 체크리스트 유지.

---

### Task 3: 교차 경계 검증과 PR 생성

**Files:**
- Verify: all modified Markdown
- Create externally: branch push and GitHub PR

**Interfaces:**
- Consumes: Task 1 문서와 Task 2 Issue 본문
- Produces: 재현 가능한 검증 결과와 병합 전 검토용 PR

- [ ] **Step 1: 금지·필수 표현을 교차 검색한다**

Run:

```powershell
rg -n "재현 필요성 결정|R7.*모드.*선택|R7.*ReproductionPlan.*생산|REVISE.*Orchestration|최종 TRUE.*두 개" README.md docs
rg -n "ReproductionPlan|AgentLog|DynamicReproductionResult|PROVIDED Primitive|ACTIVE.*VerificationAssignment|budget profile" README.md docs
```

Expected: 금지 표현 0건 또는 역사 문맥만 존재하고, 필수 표현은 생산자·소비자 양쪽에 존재한다.

- [ ] **Step 2: 전체 검증을 다시 실행한다**

Run:

```powershell
& .\scripts\validate-architecture-docs.ps1
git diff --check
git status --short
```

Expected: 검증 실패 0건, diff 오류 없음, 계획된 파일만 변경됨.

- [ ] **Step 3: 브랜치를 push하고 PR을 만든다**

Run:

```powershell
git push -u origin docs/role-boundary-alignment
gh pr create --repo SASTsimi/sastsimi --base main --head docs/role-boundary-alignment --title "docs: clarify Architecture v5 role boundaries" --body "R1–R8 상위 Issue와 역할 문서의 판단·생산·실행·강제 경계를 맞춥니다. 특히 R6가 LIMITED/FULL과 ReproductionPlan을 결정·생산하고, trusted runtime이 승인하며, R7이 exact plan을 실행해 결과를 반환하는 흐름으로 통일합니다. Closes 없이 #1–#10의 설계 검토를 지원합니다."
```

Expected: `main` 대상 OPEN PR URL 생성. 병합은 수행하지 않는다.

- [ ] **Step 4: PR diff와 GitHub Issue 본문을 최종 재조회한다**

Run:

```powershell
gh pr view --repo SASTsimi/sastsimi --json number,state,url,baseRefName,headRefName,files,commits
gh pr diff --repo SASTsimi/sastsimi --check
```

Expected: 의도한 문서만 포함하고 PR은 OPEN, Issue의 역할 경계와 PR 문서가 일치한다.
