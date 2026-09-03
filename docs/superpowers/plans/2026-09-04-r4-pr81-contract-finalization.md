# R4 PR #81 Contract Finalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** PR #81의 가설 생성 변경과 R4의 제약 근거·중복 lifecycle·confidence 제거를 하나의 충돌 없는 공통 계약으로 `main`에 반영한다.

**Architecture:** 승인된 PR #81 변경을 현재 `main` 위에 먼저 통합한다. `Restriction`은 exact CodeFact/evidence provenance를 가진 구조로 바꾸고, 중복 판정은 별도 LLM review와 fail-open 등록 이유를 저장한다.

**Tech Stack:** Markdown, YAML schema examples, Mermaid, PowerShell architecture validator, Git

**Spec:** `docs/superpowers/specs/2026-09-04-r4-pr81-contract-finalization-design.md`

## Global Constraints

- 별도 Snapshot과 Queue를 추가하지 않는다.
- Runtime Validator는 취약점 의미나 중복 의미를 대신 판단하지 않는다.
- 중복 판정 실패·불확실성 때문에 proposal을 폐기하지 않는다.
- exact `record_id`, `content_hash`, `workspace_id`, `commit_id` 추적을 유지한다.
- 이전 MAJOR schema를 추정 변환하지 않는다.

---

### Task 1: Regression checks

**Files:**
- Modify: `scripts/validate-architecture-docs.ps1`

**Interfaces:**
- Consumes: 기존 Architecture v5 정본
- Produces: 새 restriction·duplicate·confidence 제거 계약 검사

- [x] `Restriction`, `CodeFactRef`, `HypothesisDuplicateReview`, `DUPLICATE` 상태 필수 marker를 검사한다.
- [x] 활성 Architecture v5 문서의 문자열 restriction과 hypothesis confidence 잔존을 금지한다.
- [x] `& .\scripts\validate-architecture-docs.ps1`로 기존 문서가 새 검사에 실패하는지 확인한다.

### Task 2: Canonical data and lifecycle contracts

**Files:**
- Modify: `docs/architecture-v5/03-agent-roles-and-orchestration.md`
- Modify: `docs/architecture-v5/04-verification-and-dynamic-reproduction.md`
- Modify: `docs/architecture-v5/05-llm-gate-and-reporting.md`
- Modify: `docs/architecture-v5/06-chaining.md`
- Modify: `docs/architecture-v5/07-results-and-observability.md`
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Modify: `docs/architecture-v5/10-security-boundaries.md`
- Create: `docs/review/decisions/ADR-008-hypothesis-restriction-duplicate-contract.md`
- Modify: `docs/review/decisions/README.md`

**Interfaces:**
- Consumes: exact StaticFactBundle·CodeFact와 기존 LLM call/action contracts
- Produces: structured Restriction, auditable duplicate review, fail-open registration lifecycle

- [x] PR #81의 가설 필드·생성 순서·지표 변경을 현재 `main`에 통합한다.
- [x] 공통 schema와 저장 검사를 새 구조로 변경한다.
- [x] duplicate 후보 선정부터 등록·종료까지 상태 전이를 정의한다.
- [x] Verification·Primitive·Chaining·Gate·ReportDraft의 restriction 승계를 동기화한다.

### Task 3: Human-readable docs and diagrams

**Files:**
- Modify: `docs/architecture-v5/13-architecture-diagrams.md`
- Modify: `docs/architecture-v5/wiki/diagrams.md`
- Modify: `docs/architecture-v5/wiki/common-contracts.md`
- Modify: `docs/architecture-v5/wiki/state-and-recovery.md`
- Modify: `docs/architecture-v5/wiki/agents.md`
- Modify: `docs/architecture-v5/wiki/chaining.md`
- Modify: `docs/architecture-v5/wiki/results.md`
- Modify: `docs/GLOSSARY.md`
- Modify: `docs/governance/OPEN_QUESTIONS.md`
- Modify: `docs/review/ISSUE_CATALOG.md`
- Modify: `docs/DOCUMENT_GUIDE.md`

**Interfaces:**
- Consumes: Task 2 정본 계약
- Produces: 정본과 같은 쉬운 설명·Mermaid·역할 안내

- [x] duplicate 검사와 fail-open 등록 흐름을 두 Mermaid 사본에 동일하게 반영한다.
- [x] restriction provenance와 상태 의미를 Wiki·용어집·검토 문서에 반영한다.
- [x] 가설 confidence를 활성 운영 질문과 역할 설명에서 제거한다.

### Task 4: Verification and direct main integration

**Files:**
- Verify: `README.md`, `docs/`, `scripts/validate-architecture-docs.ps1`

**Interfaces:**
- Consumes: Tasks 1–3 전체 변경
- Produces: 검증된 `main` 반영 커밋

- [x] `rg`로 제거 대상과 새 필수 계약을 전수 확인한다.
- [x] `& .\scripts\validate-architecture-docs.ps1`과 `git diff --check`를 실행한다.
- [ ] 원격 `main`을 다시 fetch해 현재 HEAD가 fast-forward 가능한지 확인한다.
- [ ] 검증된 커밋만 `origin/main`에 직접 push한다.
