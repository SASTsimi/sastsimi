# PR #18 Review Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** PR #18의 R2 대행 검토와 R6·R7 실제 리뷰에서 확인된 계약 결함을 수정하고 정본 문서·Wiki·검토 상태를 다시 일치시킨다.

**Architecture:** `08-lightweight-data-contracts.md`를 정확한 필드와 불변조건의 정본으로 유지한다. R2 변경은 정적 사실·위치·누락·조회 계약, R7 변경은 동적 실행 상태와 관측 의미, R6 변경은 반증·Gate revision·안전한 오류 메시지에 한정하고 각 묶음을 독립 커밋으로 검증한다.

**Tech Stack:** Markdown, YAML 계약 예시, Mermaid, Git

**Spec:** `docs/superpowers/specs/2026-08-28-r4-01-common-contracts-design.md`

## Global Constraints

- 실제 필드명은 짧은 영문 `snake_case`, 설명은 쉬운 한국어를 사용한다.
- 정적 도구·코드 조회·provider·sandbox 실패를 취약점 `FALSE`로 자동 변환하지 않는다.
- 모든 코드 근거는 같은 `workspace_id`와 `commit_id`에 연결한다.
- `08-lightweight-data-contracts.md`가 정본이며 전문 문서와 Wiki는 새 규칙을 만들지 않는다.
- 리뷰 수정 뒤에도 R2·R6·R7·R3 재확인 전에는 PR #18과 H-002를 완료 처리하지 않는다.

---

### Task 1: R2 정적 사실·위치·조회 계약 보완

**Files:**
- Modify: `docs/architecture-v5/02-static-fact-layer.md`
- Modify: `docs/architecture-v5/07-results-and-observability.md`
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Modify: `docs/architecture-v5/10-security-boundaries.md`
- Modify: `docs/architecture-v5/wiki/common-contracts.md`
- Modify: `docs/superpowers/specs/2026-08-28-r4-01-common-contracts-design.md`

**Interfaces:**
- Consumes: `CodeWorkspace`, AST/SAST 원본 결과, `CodeContextRequest`
- Produces: 정규화된 `CodeLocation`, `CodeFact`, `CodeRelation`, `ToolRunResult`, 범위를 포함한 `DataGap`, 오류가 포함된 `StaticFactBundle`과 `CodeContextResponse`

- [ ] **Step 1: 위치와 symbol 정본 규칙 작성**

`file_path`의 `/` 구분자·상대 경로·금지 경로, 1-based line, nullable column, end-exclusive column 규칙을 작성한다. `CodeSymbol.symbol_kind`는 언어 공통 범주와 원래 도구 종류를 함께 보존한다.

- [ ] **Step 2: 정적 사실·관계·도구 실행 구조 작성**

`FactRef`, `RelationRef`, `ToolObservationRef` 같은 미정의 이름을 `CodeFact`, `CodeRelation`, `ToolRunResult`로 바꾸고 producer·원본 결과·coverage·부분 실패를 추적할 필드를 정의한다.

- [ ] **Step 3: gap과 오류 전달 구조 작성**

`DataGap`에 path·language 범위를 추가하고 `StaticFactBundle`과 `CodeContextResponse`에 `errors: [AnalysisError]`를 추가한다.

- [ ] **Step 4: 조회 한도 정렬**

`ContextRetrievalLimits`에 depth, fragment, byte, token, hypothesis별 요청 수와 timeout을 정의하고 요청·응답 예시를 맞춘다.

- [ ] **Step 5: R2 계약 검사**

Run:

```powershell
rg -n "FactRef|RelationRef|ToolObservationRef|RelationOrCodeLocation|location_ref" docs/architecture-v5
rg -n "CodeFact|CodeRelation|ToolRunResult|affected_paths|affected_languages|errors: \[AnalysisError\]|ContextRetrievalLimits" docs/architecture-v5
```

Expected: 첫 명령은 활성 계약에서 0건이고 두 번째 명령은 정본과 전문 설명에서 확인된다.

- [ ] **Step 6: Commit**

```powershell
git add docs/architecture-v5 docs/superpowers/specs/2026-08-28-r4-01-common-contracts-design.md
git commit -m "docs: fix R2 static context contracts"
```

---

### Task 2: R7 동적 실행 상태와 관측 의미 보완

**Files:**
- Modify: `docs/architecture-v5/04-verification-and-dynamic-reproduction.md`
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Modify: `docs/architecture-v5/wiki/common-contracts.md`
- Modify: `docs/architecture-v5/wiki/verification-and-dynamic.md`
- Modify: `docs/superpowers/specs/2026-08-28-r4-01-common-contracts-design.md`

**Interfaces:**
- Consumes: sandbox 실행 단계와 관측 결과
- Produces: 명확한 `FAILED | PARTIAL` 경계, `hypothesis_outcome`, 일반 관측 근거와 반증 근거

- [ ] **Step 1: 상태 경계 작성**

필수 환경이나 공격 경로를 실행하지 못하면 `FAILED + ENVIRONMENT_SETUP`, 유효한 관측이 하나 이상 있으나 환경 차이로 전체 판단이 부족하면 `PARTIAL + NONE + limitations`로 기록한다.

- [ ] **Step 2: 동적 관측 의미 작성**

`hypothesis_outcome: SUPPORTED | DISPROVED | INCONCLUSIVE`와 `hypothesis_evidence_refs`를 추가하고 `hypothesis_disproved`·`disproof_evidence_refs`와의 일치 조건을 정한다.

- [ ] **Step 3: R7 계약 검사**

Run:

```powershell
rg -n "hypothesis_outcome|hypothesis_evidence_refs|PARTIAL.*failure_reason|ENVIRONMENT_SETUP" docs/architecture-v5/04-verification-and-dynamic-reproduction.md docs/architecture-v5/08-lightweight-data-contracts.md docs/architecture-v5/wiki
```

Expected: 정본·전문 문서·Wiki가 같은 상태 경계를 설명한다.

- [ ] **Step 4: Commit**

```powershell
git add docs/architecture-v5 docs/superpowers/specs/2026-08-28-r4-01-common-contracts-design.md
git commit -m "docs: clarify dynamic reproduction outcomes"
```

---

### Task 3: R6 반증·Gate revision·오류 메시지 보완

**Files:**
- Modify: `docs/architecture-v5/03-agent-roles-and-orchestration.md`
- Modify: `docs/architecture-v5/04-verification-and-dynamic-reproduction.md`
- Modify: `docs/architecture-v5/05-llm-gate-and-reporting.md`
- Modify: `docs/architecture-v5/07-results-and-observability.md`
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Modify: `docs/architecture-v5/10-security-boundaries.md`
- Modify: `docs/architecture-v5/12-report-draft-template.md`
- Modify: `docs/architecture-v5/wiki/common-contracts.md`
- Modify: `docs/architecture-v5/wiki/verification-and-dynamic.md`
- Modify: `docs/superpowers/specs/2026-08-28-r4-01-common-contracts-design.md`

**Interfaces:**
- Consumes: named falsification, `VerificationResult` revision, `AnalysisError`
- Produces: 구조화된 `FalsificationQuestion/Result`, 정확한 Verification revision을 가리키는 Gate reference, `safe_message`

- [ ] **Step 1: named falsification 연결 작성**

가설의 `FalsificationQuestion.question_id`를 `VerificationResult.falsification_results`와 연결하고, 실제 근거가 있는 `DISPROVED` 결과가 있을 때만 `FALSE`를 허용한다.

- [ ] **Step 2: Gate 검토 대상 revision 고정**

`StoredDataRef.record_id`로 정확한 저장 record revision을 가리키게 하고 `TechnicalEvidenceReview.verification_result_ref`를 추가한다. runtime은 다른 revision의 Gate 결과 재사용을 거절한다.

- [ ] **Step 3: 안전한 오류 메시지 통일**

`AnalysisError.message`를 `safe_message`로 바꾸고 원본 오류는 접근 통제·redaction이 적용된 별도 결과로만 보관하도록 정본·전문·Wiki를 맞춘다.

- [ ] **Step 4: R6 계약 검사**

Run:

```powershell
rg -n "AnalysisError[\s\S]*message:|safe_message|FalsificationQuestion|falsification_results|verification_result_ref|record_id" docs/architecture-v5 docs/superpowers/specs/2026-08-28-r4-01-common-contracts-design.md
```

Expected: 일반 `AnalysisError.message` 계약은 없고 세 리뷰 요구가 정본과 전문 문서에서 확인된다.

- [ ] **Step 5: Commit**

```powershell
git add docs/architecture-v5 docs/superpowers/specs/2026-08-28-r4-01-common-contracts-design.md
git commit -m "docs: bind verification review evidence"
```

---

### Task 4: 검토 상태와 전체 문서 동기화

**Files:**
- Modify: `docs/review/FINDINGS.md`
- Modify: `docs/superpowers/plans/2026-08-28-r4-01-common-contracts.md`
- Modify: `docs/superpowers/plans/2026-08-28-pr18-review-remediation.md`

**Interfaces:**
- Consumes: Task 1–3의 계약 변경
- Produces: 리뷰 반영 완료·재검토 대기 상태와 검증 기록

- [ ] **Step 1: H-002와 계획 상태 갱신**

R2 대행 검토와 R6·R7 리뷰 요구를 반영했지만 담당자 재검토와 R3 검토가 남았음을 기록한다.

- [ ] **Step 2: 전체 검증**

Run:

```powershell
git diff --check origin/main...HEAD
rg -n "FactRef|RelationRef|ToolObservationRef|RelationOrCodeLocation|AnalysisError\.message|snapshot_id|RepositorySnapshot" docs/architecture-v5 docs/review
```

Markdown 상대 링크와 code fence, 본문/Wiki Mermaid 동일성, Mermaid parser를 기존 검증 방식으로 다시 확인한다.

- [ ] **Step 3: Commit**

```powershell
git add docs/review/FINDINGS.md docs/superpowers/plans
git commit -m "docs: record PR 18 review remediation"
```

- [ ] **Step 4: Push**

```powershell
git push origin review/r4-01-common-contracts
```

Expected: PR #18 head가 마지막 로컬 커밋과 같고 PR은 재검토를 위해 Draft 상태를 유지한다.
