# R4-01 Common Contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Issue #13의 공통 식별자·상태·오류·시간·버전 계약을 Architecture v5 정본 문서와 검토 절차에 일관되게 반영한다.

**Architecture:** `08-lightweight-data-contracts.md`를 정본 계약으로 유지하고, `07`은 저장·오류 운영 의미, `04`와 `09`는 전문 상태 의미를 구체화한다. Wiki는 쉬운 요약, Mermaid는 식별자 참조 흐름만 보여 주며 새로운 규칙을 만들지 않는다.

**Tech Stack:** Markdown, YAML 예시, Mermaid, GitHub Issues/PR

**Spec:** `docs/superpowers/specs/2026-08-28-r4-01-common-contracts-design.md`

## Global Constraints

- 실제 필드명은 간단한 영문 `snake_case`, 문서 설명은 쉬운 한국어를 사용한다.
- 오류·정보 부족·timeout·인증·sandbox 실패를 취약점 `FALSE`로 변환하지 않는다.
- 모든 코드 근거는 같은 `workspace_id`와 `commit_id`에 연결한다.
- 상태 계층을 하나의 거대한 enum으로 합치지 않는다.
- runtime 구현 완료나 Architecture v5 최종 승인을 주장하지 않는다.
- R2·R6·R7·R3 실제 교차 검토 기록 전에는 Issue #13과 H-002를 완료 처리하지 않는다.

---

### Task 1: 식별자·시간·가설 관계 정본화

**Files:**
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Modify: `docs/architecture-v5/03-agent-roles-and-orchestration.md`

**Interfaces:**
- Consumes: 기존 `CodeWorkspace`, `RunMeta`, `RecordMeta`, `HypothesisProposal`
- Produces: 식별자 책임표, 코드 binding 전후 `RunMeta`·`RecordMeta` 및 저장 참조 분리, UTC 시간 규칙, `VulnerabilityHypothesis`, 부모·root·depth 관계

- [x] **Step 1: 현재 식별자와 관계 필드 목록 확인**

Run:

```powershell
rg -n "analysis_id|workspace_id|stored_data_id|record_id|logical_record_id|hypothesis_id|attempt_id|llm_call_id|external_program_id|revision_number|parent_hypothesis_ids" docs/architecture-v5
```

Expected: 모든 기존 사용 위치가 출력되고 서로 다른 대체 이름이 있으면 수정 목록에 포함된다.

- [x] **Step 2: 생성 주체·유일 범위·재사용·저장 위치 표 추가**

`08`에 spec 3장의 식별자 표를 추가하고 ID 값은 불투명 문자열임을 명시한다.

- [x] **Step 3: 시간 규칙 추가**

`created_at`, `started_at`, `finished_at`, `elapsed_ms`를 spec 5장과 동일하게 정의한다.

- [x] **Step 4: 가설 관계 계약 추가**

`VulnerabilityHypothesis` schema에 `origin`, `parent_hypothesis_ids`, `root_hypothesis_id`, `chain_depth`를 추가하고 부모 결과 불변 규칙을 `03`과 맞춘다.

- [x] **Step 5: 계약 이름 검사**

Run:

```powershell
rg -n "root_hypothesis_id|parent_hypothesis_ids|created_at|started_at|finished_at|elapsed_ms" docs/architecture-v5/03-agent-roles-and-orchestration.md docs/architecture-v5/08-lightweight-data-contracts.md
```

Expected: 정본 schema와 lifecycle 설명에 같은 이름이 존재한다.

- [x] **Step 6: Commit**

```powershell
git add docs/architecture-v5/03-agent-roles-and-orchestration.md docs/architecture-v5/08-lightweight-data-contracts.md
git commit -m "docs: define common identity and time contracts"
```

---

### Task 2: 상태 계층과 동적 반증 의미 확정

**Files:**
- Modify: `docs/architecture-v5/04-verification-and-dynamic-reproduction.md`
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Modify: `docs/architecture-v5/09-llm-provider-session-and-logging.md`

**Interfaces:**
- Consumes: Verification, sandbox, provider와 Gate의 기존 상태
- Produces: 계층별 enum·소유 주체 표, 동적 실패와 반증 분리 규칙

- [x] **Step 1: 상태 계층 표 추가**

spec 6장의 분리된 상태 계층을 `08`에 추가한다. proposal 검증과 등록된 hypothesis 처리를 나누고, 각 상태가 어느 record에 속하는지와 다른 계층을 덮어쓰지 않는다는 규칙을 명시한다.

- [x] **Step 2: 동적 결과 계약 보강**

`DynamicReproductionResult`에 `disproof_evidence_refs`를 추가하고 `status=FAILED`만으로 `hypothesis_disproved=true`가 될 수 없음을 `04`와 `08`에 같은 표현으로 적는다.

- [x] **Step 3: LLM 오류 lifecycle 정렬**

`09`에서 `AUTH_REQUIRED`, `RATE_LIMITED`, `TIMED_OUT`, `INVALID_OUTPUT`, `CANCELLED`가 기술 판정과 별개임을 상태표로 요약한다.

- [x] **Step 4: 상태 enum 검사**

Run:

```powershell
rg -n "RUNNING \| COMPLETE \| PARTIAL|PROPOSED \| SCHEMA_VALID|hypothesis_disproved|disproof_evidence_refs|AUTH_REQUIRED" docs/architecture-v5/04-verification-and-dynamic-reproduction.md docs/architecture-v5/08-lightweight-data-contracts.md docs/architecture-v5/09-llm-provider-session-and-logging.md
```

Expected: 각 상태가 자기 계층 문서에 있고 자동 `FALSE` 금지 문장이 존재한다.

- [x] **Step 5: Commit**

```powershell
git add docs/architecture-v5/04-verification-and-dynamic-reproduction.md docs/architecture-v5/08-lightweight-data-contracts.md docs/architecture-v5/09-llm-provider-session-and-logging.md
git commit -m "docs: separate workflow states from verdicts"
```

---

### Task 3: DataGap·AnalysisError·버전 규칙 확정

**Files:**
- Modify: `docs/architecture-v5/07-results-and-observability.md`
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Modify: `docs/architecture-v5/10-security-boundaries.md`

**Interfaces:**
- Consumes: 기존 error code와 `DataGap`, `AnalysisError`, `RecordMeta`
- Produces: 생산자·소비자 표, 실패 시나리오 표, schema version/revision 규칙

- [x] **Step 1: DataGap 구조 보강**

`DataGap.stage`를 공통 단계명으로 정렬하고 `code`를 추가한다. submodule·LFS·생성 파일·부분 정적분석·잘린 문맥·정책 누락 대표 code를 문서화한다.

- [x] **Step 2: 오류 분류표 작성**

`07`의 단순 목록을 `code / 생산자 / 영향을 받는 상태 / 기본 retry / 자동 FALSE 금지` 표로 바꾼다.

- [x] **Step 3: 계약 버전 규칙 추가**

`08`에 `MAJOR.MINOR.PATCH`, `SCHEMA_UNSUPPORTED`, revision 연결 불변조건과 `RECORD_REVISION_MISMATCH`를 추가한다.

- [x] **Step 4: 보안 검사 규칙 연결**

`10` runtime validator 항목에 schema major, record revision, workspace·commit 검사를 함께 적는다.

- [x] **Step 5: 시나리오 검사**

Run:

```powershell
rg -n "SUBMODULE_UNAVAILABLE|LFS_POINTER_ONLY|CONTEXT_TRUNCATED|SCHEMA_UNSUPPORTED|RECORD_REVISION_MISMATCH|자동.*FALSE|`FALSE`" docs/architecture-v5/07-results-and-observability.md docs/architecture-v5/08-lightweight-data-contracts.md docs/architecture-v5/10-security-boundaries.md
```

Expected: 각 code의 의미와 취약점 판정 비연결 규칙이 확인된다.

- [x] **Step 6: Commit**

```powershell
git add docs/architecture-v5/07-results-and-observability.md docs/architecture-v5/08-lightweight-data-contracts.md docs/architecture-v5/10-security-boundaries.md
git commit -m "docs: define gap error and schema version rules"
```

---

### Task 4: H-002·Wiki·Mermaid 동기화

**Files:**
- Modify: `docs/review/FINDINGS.md`
- Modify: `docs/architecture-v5/13-architecture-diagrams.md`
- Create: `docs/architecture-v5/wiki/common-contracts.md`
- Modify: `docs/architecture-v5/wiki/_Sidebar.md`
- Modify: `docs/architecture-v5/wiki/README.md`
- Modify: `docs/architecture-v5/wiki/diagrams.md`

**Interfaces:**
- Consumes: Task 1–3의 정본 계약
- Produces: 쉬운 Wiki 요약, 식별자 추적 Mermaid, H-002 교차 검토 대기 상태

- [x] **Step 1: H-002 상태 설명 갱신**

계약 작성은 완료됐지만 실제 역할별 검토가 남았다고 기록하고 상태는 `IN_PROGRESS`로 유지한다.

- [x] **Step 2: Wiki 요약 추가**

ID, 상태, gap/error, 실패와 반증, 버전 규칙을 쉬운 한국어로 한 페이지에 정리하고 sidebar/README에서 연결한다.

- [x] **Step 3: Mermaid 식별자 흐름 추가**

Repository Loader부터 최종 결과까지 `RunMeta`, `analysis_id`, `workspace_id + commit_id`, `hypothesis_id`, `attempt_id`, `logical_record_id`, `record_id + revision`의 관계를 한 diagram으로 추가하고 main/wiki diagram을 동일하게 유지한다.

- [x] **Step 4: Markdown과 Mermaid 동기화 검사**

Run:

```powershell
rg -n "common-contracts|H-002|analysis_id|workspace_id|revision_number" docs/architecture-v5/wiki docs/review/FINDINGS.md
```

Expected: Wiki 탐색 경로와 H-002 남은 조건이 확인된다.

- [x] **Step 5: Commit**

```powershell
git add docs/review/FINDINGS.md docs/architecture-v5/13-architecture-diagrams.md docs/architecture-v5/wiki
git commit -m "docs: publish R4-01 contract review guide"
```

---

### Task 5: 전체 검증과 GitHub 교차 검토 요청

**Files:**
- Modify only if verification finds a contract defect

**Interfaces:**
- Consumes: 전체 R4-01 문서 변경
- Produces: 검증 증거, PR, Issue #13 진행 기록, 실제 담당자 검토 요청

- [x] **Step 1: 금지·필수 이름 검사**

```powershell
rg -n "failure_class|falsification_observed|snapshot_id|RepositorySnapshot" docs/architecture-v5 docs/review
rg -n "failure_reason|hypothesis_disproved|disproof_evidence_refs|DataGap|AnalysisError|schema_version|revision_number" docs/architecture-v5 docs/review
```

Expected: 첫 명령은 0건, 두 번째는 정본·전문·Wiki 문서에서 확인된다.

- [x] **Step 2: Markdown link·fence와 Mermaid 검사**

모든 Markdown 상대 링크와 code fence를 검사하고, main/wiki Mermaid block이 같으며 각 block이 Mermaid parser를 통과하는지 확인한다.

- [x] **Step 3: 독립 문서 리뷰**

Issue #13 완료 조건을 기준으로 Critical/Important/Minor를 분류한다. Critical/Important는 PR 전에 수정하고 재검토한다.

- [x] **Step 4: Push와 Draft PR 생성**

브랜치 `review/r4-01-common-contracts`를 push하고 `Refs #13`, `Refs #5`를 포함한 Draft PR을 만든다. 실제 교차 검토 전에는 `Closes #13`을 쓰지 않는다.

- [x] **Step 5: GitHub Issue 진행 기록**

Issue #13에 변경 문서, 검증 결과와 남은 R2·R6·R7·R3 교차 검토를 쉬운 한국어로 남긴다. 담당 검토자에게 PR review를 요청한다.

- [x] **Step 6: 완료 조건 판정**

실제 교차 검토가 모두 기록되면 H-002와 Issue #13을 완료 후보로 바꾼다. 검토가 남아 있으면 PR과 Issue를 열린 상태로 유지하고 부족한 승인만 명시한다.

판정 결과: Draft PR #18과 Issue #13을 열어 두고 H-002를 `IN_PROGRESS`로 유지한다. R2·R6·R7에는 GitHub review를 요청했다. R3 `@v1sion`은 repository collaborator가 아니라 정식 review request가 거절되어 Issue 멘션 검토와 권한 추가가 남아 있다.
