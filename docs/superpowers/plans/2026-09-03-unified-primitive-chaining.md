# Unified Primitive Chaining Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Primitive와 Chaining 공통 계약을 단일 `inputs/result/restrictions` 모델과 Technical Gate 기반 admission으로 전환한다.

**Architecture:** HOLD는 result가 없는 Primitive, Technical-accepted TRUE는 result가 있는 Primitive로 표현한다. Chaining은 upstream result가 downstream input을 근거 있게 충족할 때 새 가설을 만들고, Rule Scope는 보고 경로에만 영향을 준다.

**Tech Stack:** Markdown, YAML schema examples, Mermaid, PowerShell architecture validator

**Spec:** `docs/superpowers/specs/2026-09-03-unified-primitive-chaining-design.md`

## Global Constraints

- 모든 final TRUE의 validated PoC 필수 계약은 유지한다.
- exact `workspace_id`, `commit_id`, `record_id`, `content_hash` 추적을 유지한다.
- 별도 Snapshot과 Queue를 추가하지 않는다.
- 체이닝 산출물은 언제나 새 가설로 전체 Verification을 다시 거친다.
- Rule Scope Gate는 보고 가능성만 판단한다.

---

### Task 1: Contract regression checks

**Files:**
- Modify: `scripts/validate-architecture-docs.ps1`

**Interfaces:**
- Consumes: 현재 Architecture v5 정본과 보안 시나리오
- Produces: 새 Primitive/Chaining 필수 marker와 제거 계약 탐지

- [ ] 새 schema와 admission·lineage·cycle 시나리오 marker를 validator에 추가한다.
- [ ] 제거 대상 객체·필드가 활성 계약에 남으면 실패하도록 검사한다.
- [ ] `./scripts/validate-architecture-docs.ps1`을 실행해 기존 문서에서 새 검사 실패를 확인한다.

### Task 2: Canonical contract and decision records

**Files:**
- Modify: `docs/architecture-v5/03-agent-roles-and-orchestration.md`
- Modify: `docs/architecture-v5/04-verification-and-dynamic-reproduction.md`
- Modify: `docs/architecture-v5/05-llm-gate-and-reporting.md`
- Modify: `docs/architecture-v5/06-chaining.md`
- Modify: `docs/architecture-v5/07-results-and-observability.md`
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Modify: `docs/architecture-v5/10-security-boundaries.md`
- Modify: `docs/architecture-v5/11-migration-from-v4.md`
- Modify: `docs/architecture-v5/12-report-draft-template.md`
- Create: `docs/review/decisions/ADR-005-unified-primitive-chaining.md`
- Modify: `docs/review/decisions/ADR-001-verification-owned-chaining-admission.md`
- Modify: `docs/review/decisions/README.md`

**Interfaces:**
- Consumes: approved design spec와 기존 validated PoC 계약
- Produces: 새 MAJOR Primitive/Chaining 계약과 Gate 책임 경계

- [ ] 공통 YAML schema와 저장·권한·오류 규칙을 교체한다.
- [ ] admission, exact reference, lineage, 조상 재사용 제외와 공통 예산 규칙을 정본에 반영한다.
- [ ] ADR-005를 ACCEPTED로 추가하고 ADR-001을 SUPERSEDED로 표시한다.
- [ ] validator를 실행해 Task 1 검사가 통과하도록 수정한다.

### Task 3: Pipeline, Wiki, diagrams, collaboration docs

**Files:**
- Modify: `README.md`
- Modify: `docs/DOCUMENT_GUIDE.md`
- Modify: `docs/GLOSSARY.md`
- Modify: `docs/architecture-v5/01-system-overview.md`
- Modify: `docs/architecture-v5/13-architecture-diagrams.md`
- Modify: `docs/architecture-v5/README.md`
- Modify: `docs/architecture-v5/wiki/*.md`
- Modify: `docs/governance/OWNERSHIP.md`
- Modify: `docs/governance/REVIEW_CHECKLIST.md`
- Modify: `docs/review/FINDINGS.md`
- Modify: `docs/review/ISSUE_CATALOG.md`
- Modify: `docs/review/ISSUE_TRACKER.md`
- Modify: `docs/review/R4-04_CROSS_REVIEW.md`

**Interfaces:**
- Consumes: Task 2의 정본 계약
- Produces: 사람이 읽는 흐름과 정본이 같은 README·Wiki·Mermaid·협업 지침

- [ ] Technical ACCEPT 뒤 admission/Chaining과 Rule Scope/Reporter가 갈라지는 흐름을 반영한다.
- [ ] 두 Mermaid 파일의 같은 블록을 함께 수정한다.
- [ ] 역할·용어·검토 체크리스트와 R1/R4/R5/R8 업무 경계를 동기화한다.
- [ ] validator를 실행해 정본/Wiki Mermaid 일치와 문서 marker 통과를 확인한다.

### Task 4: Final consistency and integration

**Files:**
- Verify: all files under `README.md`, `docs/`, `scripts/validate-architecture-docs.ps1`

**Interfaces:**
- Consumes: Tasks 1–3의 전체 diff
- Produces: 충돌과 활성 구계약이 없는 main 반영 커밋

- [ ] 활성 문서에서 제거된 객체·필드와 이전 admission 표현을 전수 검색한다.
- [ ] `./scripts/validate-architecture-docs.ps1`과 `git diff --check`를 실행한다.
- [ ] 원격 main을 fetch하고 fast-forward 가능 여부를 확인한다.
- [ ] 검증된 커밋만 `origin/main`에 직접 푸시한다.
