# R6–R7 PoC Required Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 모든 final TRUE에 validated PoC를 강제하고 R6 request/R7 production 경계를 Architecture v5 전체에 일관되게 반영한다.

**Architecture:** R6는 immutable `DynamicReproductionRequest`만 생산하고 R7은 같은 요청에서 환경 요구사항·계획·PoC candidate·동적 결과를 생산한다. Runtime Validator는 generation별 동적 work 하나, candidate/validated PoC 구분, 실패 시 no-verdict와 TRUE→Technical Gate의 validated PoC 전제를 구조적으로 강제한다.

**Tech Stack:** Markdown, Mermaid, PowerShell architecture validator, Git

**Spec:** `docs/superpowers/specs/2026-09-03-r6-r7-poc-required-design.md`

## Global Constraints

- 모든 schema field 이름은 영문이며 설명은 쉬운 한국어를 함께 쓴다.
- final TRUE는 current generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 validated `poc_ref`가 필수다.
- 오류·정책 차단·PoC 생성/실행 실패를 `FALSE | HOLD`로 바꾸지 않는다.
- 한 Verification generation에는 동적 work를 최대 하나만 만들고 retry는 같은 work의 새 attempt다.
- R6는 request와 final verdict, R7은 requirements·plan·candidate·dynamic result를 생산한다.
- PROVIDED Primitive/Chaining, exact revision, Runtime Validator와 R5-03 자동화 종료 계약은 유지한다.

---

### Task 1: 새 계약을 검증 스크립트에 먼저 고정

**Files:**
- Modify: `scripts/validate-architecture-docs.ps1`
- Test: `scripts/validate-architecture-docs.ps1`

**Interfaces:**
- Consumes: 현재 Architecture v5 Markdown과 Mermaid
- Produces: 새 schema·소유권·Gate 조건·실패 시나리오가 없으면 실패하는 validator

- [ ] **Step 1: 다음 실패 조건을 validator에 추가**

```text
DynamicReproductionRequest 필수 field
EnvironmentRequirements/ReproductionPlan의 request_ref와 SANDBOX 생산 권한
poc_candidate_ref와 validated poc_ref 상태 조합
generation별 단일 DYNAMIC_REPRO work
TRUE 저장 및 CALL_TECHNICAL_GATE의 validated PoC 전제
POC 생성·실행 실패의 BLOCKED/FAILED와 no-verdict
기존 R6 requirements/plan/mode 생산 표현 금지
```

- [ ] **Step 2: 기존 문서에서 validator가 예상 이유로 실패하는지 확인**

Run: `powershell -ExecutionPolicy Bypass -File scripts/validate-architecture-docs.ps1`

Expected: 새 contract 또는 marker 누락으로 `Failures`가 1 이상이다.

### Task 2: 공통 schema·authority·상태 계약 수정

**Files:**
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Create: `docs/review/decisions/ADR-004-r6-request-r7-poc-production.md`
- Modify: `docs/review/decisions/ADR-003-r6-r7-environment-requirements-handoff.md`

**Interfaces:**
- Consumes: 승인된 설계 문서
- Produces: `DynamicReproductionRequest`, R7-owned requirements/plan, PoC candidate/validated PoC, TRUE Gate invariants

- [ ] **Step 1: 공통 schema를 새 MAJOR 계약으로 변경**

```text
VerificationResult.dynamic_decision 제거
dynamic_request_ref 추가
DynamicReproductionRequest 추가
EnvironmentRequirements.request_ref 추가
ReproductionPlan.request_ref/purpose/poc_candidate_ref 추가
DynamicReproductionResult.request_ref/purpose/poc_candidate_ref와 validated poc_ref 의미 확정
```

- [ ] **Step 2: action과 result-owner registry 변경**

```text
REQUEST_DYNAMIC_REPRO: VERIFICATION
RUN_SANDBOX: SANDBOX
CALL_LLM in DYNAMIC_REPRO: SANDBOX 제한 허용
dynamic_reproduction_request: VERIFICATION
environment_requirements/reproduction_plan/dynamic_reproduction_result: SANDBOX
```

- [ ] **Step 3: 상태·retry·Gate 조건 변경**

```text
generation별 DYNAMIC_REPRO unique key
retry/external configuration: same work new attempt
unrecoverable/retry exhausted: FAILED, no VerificationResult
TRUE save and Technical Gate: current SUCCEEDED+SUPPORTED result and validated poc_ref required
```

- [ ] **Step 4: ADR-003을 SUPERSEDED로 표시하고 ADR-004에 새 결정을 기록**

### Task 3: 정본 역할·흐름·결과 문서 동기화

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture-v5/README.md`
- Modify: `docs/architecture-v5/01-system-overview.md`
- Modify: `docs/architecture-v5/03-agent-roles-and-orchestration.md`
- Modify: `docs/architecture-v5/04-verification-and-dynamic-reproduction.md`
- Modify: `docs/architecture-v5/05-llm-gate-and-reporting.md`
- Modify: `docs/architecture-v5/06-chaining.md`
- Modify: `docs/architecture-v5/07-results-and-observability.md`
- Modify: `docs/architecture-v5/10-security-boundaries.md`
- Modify: `docs/architecture-v5/11-migration-from-v4.md`
- Modify: `docs/architecture-v5/12-report-draft-template.md`

**Interfaces:**
- Consumes: Task 2의 공통 schema와 authority
- Produces: 같은 R6→R7→Verification→Gate 의미를 가진 정본 설명

- [ ] **Step 1: R6 설명을 request·result consumption·final verdict로 제한**
- [ ] **Step 2: R7 설명에 requirements·plan·PoC candidate·실행 결과 생산을 배정**
- [ ] **Step 3: initial TRUE와 VERDICT_EVIDENCE 두 경로 및 오류 no-verdict를 반영**
- [ ] **Step 4: Chaining·Reporter가 validated PoC를 가진 Gate-qualified TRUE만 소비하도록 정리**

### Task 4: Mermaid와 Wiki 동기화

**Files:**
- Modify: `docs/architecture-v5/13-architecture-diagrams.md`
- Modify: `docs/architecture-v5/wiki/diagrams.md`
- Modify: `docs/architecture-v5/wiki/README.md`
- Modify: `docs/architecture-v5/wiki/agents.md`
- Modify: `docs/architecture-v5/wiki/authority-boundaries.md`
- Modify: `docs/architecture-v5/wiki/common-contracts.md`
- Modify: `docs/architecture-v5/wiki/gate-and-reporting.md`
- Modify: `docs/architecture-v5/wiki/pipeline.md`
- Modify: `docs/architecture-v5/wiki/quick-guide.md`
- Modify: `docs/architecture-v5/wiki/results.md`
- Modify: `docs/architecture-v5/wiki/state-and-recovery.md`
- Modify: `docs/architecture-v5/wiki/verification-and-dynamic.md`

**Interfaces:**
- Consumes: 정본 22단계와 Task 2 계약
- Produces: canonical과 Wiki에서 동일한 Mermaid 13개 및 쉬운 설명

- [ ] **Step 1: 동적 흐름 Mermaid를 R6 request → R7 requirements/plan/candidate/run으로 변경**
- [ ] **Step 2: TRUE → validated PoC 검사 → Technical Gate 경로를 모든 관련 도식에 표시**
- [ ] **Step 3: Wiki 역할·계약·상태·오류 설명을 정본과 맞춤**

### Task 5: 거버넌스와 역할별 작업 기준 수정

**Files:**
- Modify: `docs/governance/OWNERSHIP.md`
- Modify: `docs/governance/REVIEW_CHECKLIST.md`
- Modify: `docs/review/ISSUE_CATALOG.md`
- Modify: `docs/review/R4-04_CROSS_REVIEW.md`
- Modify if impacted: `docs/review/FINDINGS.md`

**Interfaces:**
- Consumes: 새 R4/R6/R7 소유권
- Produces: 팀원이 자기 파트에서 확인할 완료 조건과 교차 검토 항목

- [ ] **Step 1: R6/R7 생산자·소비자와 Gate 전제 변경**
- [ ] **Step 2: PoC candidate/validated PoC, 한 work/generation, 실패 no-verdict 완료 조건 추가**
- [ ] **Step 3: 기존 R6 ownership 문구와 충돌하는 항목 제거**

### Task 6: 전체 재검증과 main 반영

**Files:**
- Test: all modified files

**Interfaces:**
- Consumes: Tasks 1–5 결과
- Produces: 검증된 fast-forward main commit

- [ ] **Step 1: validator 재실행**

Run: `powershell -ExecutionPolicy Bypass -File scripts/validate-architecture-docs.ps1`

Expected: `Failures: 0`, canonical/Wiki Mermaid counts equal.

- [ ] **Step 2: 제거 대상 표현과 소유권 충돌 검색**

```powershell
rg -n "R6.*EnvironmentRequirements.*생산|R6.*ReproductionPlan.*생산|Verification.*동적.*mode.*결정|PoC reference 존재.*성공" README.md docs/architecture-v5 docs/governance docs/review
```

Expected: superseded ADR의 역사 설명 외 활성 계약에서 결과 없음.

- [ ] **Step 3: diff와 원격 기준 확인**

Run: `git diff --check` and `git fetch origin main` and `git merge-base --is-ancestor origin/main HEAD`

Expected: whitespace error 없음, origin/main이 HEAD의 ancestor.

- [ ] **Step 4: 구현 커밋 후 main 직접 push**

```text
git commit -m "docs: require validated PoC for every TRUE"
git push origin HEAD:main
```
