# R4-02 State and Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Architecture v5에 상태 전이, 병렬 합류, 중복 방지, atomic 저장과 crash-resume 규칙을 구현 가능한 문서 계약으로 확정한다.

**Architecture:** 전문 판정 record와 실행 상태를 분리하고 모든 실행 작업을 `WorkExecutionState`로 추적한다. compare-and-set, `dedupe_key`, exact output reference와 `TransitionCommit` journal로 중복·늦은 결과·부분 저장을 차단한다.

**Tech Stack:** Markdown, YAML형 계약 예시, Mermaid, PowerShell 기반 문서 검증, GitHub Issue/PR

**Spec:** `docs/superpowers/specs/2026-08-28-r4-02-state-recovery-design.md`

## Global Constraints

- 두 LLM Gate의 순서는 Technical Evidence Gate 다음 Rule Scope Impact Gate다.
- repository snapshot 모듈을 다시 도입하지 않고 `workspace_id + commit_id`를 사용한다.
- Queue·DB·workflow engine 제품을 선택하지 않는다.
- 오류·인증 실패·취소·정보 부족을 취약점 `FALSE`로 바꾸지 않는다.
- 기존 record와 실패 기록을 덮어쓰지 않는다.
- 실제 필드명은 간단한 영문을 사용하고 문서에는 쉬운 한국어 설명을 붙인다.

---

### Task 1: 실행 상태와 전이 정본 추가

**Files:**
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Modify: `docs/architecture-v5/03-agent-roles-and-orchestration.md`

**Interfaces:**
- Consumes: R4-01 `RunMeta`, `RecordMeta`, `StoredDataRef`, `attempt_id`, revision 계약
- Produces: `WorkExecutionState`, `StateTransition`, `TransitionCommit`, 허용 전이표

- [x] **Step 1: 공통 실행 상태를 정본 계약에 추가**

`PENDING | READY | RUNNING | BLOCKED | SUCCEEDED | PARTIAL | FAILED | CANCELLED`의 의미, 허용 다음 상태와 종료 상태 불변성을 표로 작성한다.

- [x] **Step 2: 실행 상태 구조를 추가**

`work_id`, `work_type`, `subject_id`, `state_version`, `active_attempt_id`, `input_hash`, `dedupe_key`, input/output/error refs와 시각을 포함한다.

- [x] **Step 3: 상태 전이와 저장 commit 구조를 추가**

compare-and-set용 `expected_state_version`, 정확한 result refs와 `PREPARED | COMMITTED | ABORTED` journal 의미를 작성한다.

- [x] **Step 4: orchestration 흐름과 전문 상태 분리를 동기화**

실행 `SUCCEEDED`와 취약점 `TRUE`, Gate 결과, 보고서 상태가 서로 다른 축임을 `03`에 반영한다.

- [x] **Step 5: diff와 이름 검사**

Run: `rg -n "WorkExecutionState|StateTransition|TransitionCommit|state_version|dedupe_key|active_attempt_id" docs/architecture-v5/03-agent-roles-and-orchestration.md docs/architecture-v5/08-lightweight-data-contracts.md`

Expected: 모든 새 이름이 정본 정의와 소비 설명에 나타난다.

### Task 2: 병렬·직렬·retry·늦은 결과 규칙 추가

**Files:**
- Modify: `docs/architecture-v5/01-system-overview.md`
- Modify: `docs/architecture-v5/03-agent-roles-and-orchestration.md`
- Modify: `docs/architecture-v5/09-llm-provider-session-and-logging.md`

**Interfaces:**
- Consumes: Task 1 실행 상태와 R4-01 invocation chain
- Produces: fan-out/join, 직렬 Gate/Reporter, retry/failover, stale result 검사

- [x] **Step 1: AST/SAST와 가설별 fan-out/join 규칙 작성**

부분 성공, `DataGap`, 같은 가설의 활성 attempt 하나, Pro/Con 독립 합류 조건을 명시한다.

- [x] **Step 2: 두 Gate와 Reporter 직렬 순서 고정**

정확한 Verification·CWE·정책 revision과 Technical `ACCEPT` 없이는 뒤 단계를 시작하지 못하게 한다.

- [x] **Step 3: retry와 failover 작업 상태 연결**

새 attempt, 허용된 바로 앞 실패 호출, 재인증·backoff·repair와 취소 뒤 retry 금지를 명시한다.

- [x] **Step 4: 늦은 결과 수락 조건 작성**

active attempt, state version, input hash, workspace/commit/hypothesis 일치 조건과 거절 오류를 정한다.

- [x] **Step 5: 순서 검사**

Run: `rg -n "fan-out|합류|STALE_RESULT|ATTEMPT_NOT_ACTIVE|STATE_VERSION_CONFLICT|Technical.*Rule Scope.*Reporter" docs/architecture-v5`

Expected: 병렬 합류와 직렬 순서, 늦은 결과 차단 근거를 찾을 수 있다.

### Task 3: atomic 저장·복구·오류 전파 정리

**Files:**
- Modify: `docs/architecture-v5/07-results-and-observability.md`
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Modify: `docs/architecture-v5/10-security-boundaries.md`

**Interfaces:**
- Consumes: `TransitionCommit`, `AnalysisError`, `AnalysisRunResult`
- Produces: atomic transition, crash-resume, failure propagation와 negative cases

- [x] **Step 1: 결과와 종료 상태의 atomic binding 작성**

Verification `TERMINAL`, Gate 완료와 Report `DRAFTED`가 정확한 output `record_id`를 가리키게 한다.

- [x] **Step 2: crash-resume 표 작성**

마지막 `COMMITTED`, 남은 `PREPARED`, 중단된 `RUNNING`, pointer 누락과 안전하지 않은 복구를 구분한다.

- [x] **Step 3: 오류·취소·부분 성공 전파표 작성**

clone, static, Agent, auth, Sandbox, policy, Gate, report, budget와 사용자 취소가 가설·분석에 미치는 영향을 정한다.

- [x] **Step 4: 보안 차단 조건 작성**

오래된·취소된·다른 workspace/commit 결과와 uncommitted output을 다음 단계에서 읽지 못하게 한다.

- [x] **Step 5: 오류 이름 검사**

Run: `rg -n "STATE_TRANSITION_INVALID|STATE_VERSION_CONFLICT|ATTEMPT_NOT_ACTIVE|STALE_RESULT|TRANSITION_INCOMPLETE|RECOVERY_FAILED" docs/architecture-v5`

Expected: 각 오류의 생성 주체, 영향과 복구가 정본과 관측 문서에서 일치한다.

### Task 4: Mermaid와 쉬운 Wiki 동기화

**Files:**
- Modify: `docs/architecture-v5/13-architecture-diagrams.md`
- Modify: `docs/architecture-v5/wiki/diagrams.md`
- Create: `docs/architecture-v5/wiki/state-and-recovery.md`
- Modify: `docs/architecture-v5/wiki/_Sidebar.md`
- Modify: `docs/architecture-v5/wiki/README.md`
- Modify: `docs/architecture-v5/README.md`
- Modify: `docs/DOCUMENT_GUIDE.md`
- Modify: `docs/GLOSSARY.md`

**Interfaces:**
- Consumes: Tasks 1–3의 정본
- Produces: 상태도, 저장·복구 흐름, 비전문가용 요약

- [x] **Step 1: 실행 상태 Mermaid 추가**

허용 전이와 retry가 기존 종료 상태를 되돌리지 않는다는 흐름을 그린다.

- [x] **Step 2: atomic 저장·stale result Mermaid 추가**

결과 검증, atomic commit, 다음 단계 전달과 거절·격리 경로를 그린다.

- [x] **Step 3: Wiki 요약과 메뉴 추가**

중복 방지, 재시도, 중단 후 재개를 쉬운 한국어로 설명하고 정본 링크를 제공한다.

- [x] **Step 4: 용어집과 문서 안내 갱신**

`work_id`, `dedupe_key`, `state_version`, atomic transition, stale result와 crash-resume을 설명한다.

- [x] **Step 5: Mermaid mirror 검사**

Run: PowerShell로 `13-architecture-diagrams.md`와 `wiki/diagrams.md`의 Mermaid block 개수와 내용을 비교한다.

Expected: 두 파일의 모든 Mermaid block이 같은 순서와 내용이다.

### Task 5: 발견사항과 완료 조건 검토

**Files:**
- Modify: `docs/review/FINDINGS.md`
- Modify: `docs/review/ISSUE_CATALOG.md`
- Modify: `docs/superpowers/plans/2026-08-28-r4-02-state-recovery.md`

**Interfaces:**
- Consumes: Issue #14, H-002, H-006과 Tasks 1–4
- Produces: 추적 가능한 해결 근거와 남은 구현 결정

- [x] **Step 1: H-006 해결 근거 갱신**

중복·누락·late result·부분 저장·복구 설계가 어느 문서에 있는지 기록한다.

- [x] **Step 2: H-002 상태 전파 부분 갱신**

오류 상태가 verdict와 분리되며 retry/terminal 의미가 일치하는지 기록한다.

- [x] **Step 3: Issue #14 완료 조건 대조**

각 체크 항목을 문서 절과 연결하고 누락이 있으면 정본에 보완한다.

- [x] **Step 4: 계획 체크리스트 갱신**

실제 수행한 항목만 `[x]`로 바꾸고 미완료는 이유를 적는다.

### Task 6: 전체 검증·커밋·PR

**Files:**
- Modify only if verification finds a defect

**Interfaces:**
- Consumes: 전체 R4-02 변경
- Produces: 검증 증거, 분리된 commit과 GitHub PR

- [x] **Step 1: Markdown·링크·fence 검사**

모든 Markdown 상대 링크가 존재하고 code fence 수가 짝수인지 확인한다.

- [x] **Step 2: 계약 일관성 검사**

정의되지 않은 구조 이름, 서로 다른 enum, output pointer 누락과 금지된 repository snapshot 표현을 검사한다.

- [x] **Step 3: 부정 시나리오 재검토**

Issue #14의 12개 작업 항목과 negative scenario를 독립 체크리스트로 다시 대조한다.

- [x] **Step 4: 첫 번째 self-review와 수정**

Blocker/High/Medium/Low로 분류하고 Blocker/High를 모두 수정한다.

- [x] **Step 5: commit 후 두 번째 diff review**

`git diff origin/main...HEAD`를 새로 읽어 범위 이탈·중복·모순을 확인하고 필요한 수정은 별도 commit으로 남긴다.

- [x] **Step 6: push와 PR 생성**

브랜치 `review/r4-02-state-recovery`를 push하고 `Closes #14`, `Refs #5`와 검증 결과를 포함한 PR을 `main` 대상으로 만든다.

- [x] **Step 7: 원격 PR diff 재검증**

GitHub의 PR head SHA, 변경 파일, checks와 실제 diff를 다시 확인한다.

## 검증 기록

- 문서 검사: Markdown 52개, canonical/Wiki Mermaid 각각 11개, 상대 링크·fence·mirror·금지 표현·R4-02 필수 계약 검사 실패 0건
- 실제 Mermaid 렌더링: Chrome 기반 `mmdc`로 11/11 SVG 생성, parse error 0건
- 첫 검토 보완: `work_generation`, exact transition reference, metadata의 attempt 의미와 non-transaction 저장 순서를 명확화
- 두 번째 검토 보완: `TransitionCommit`에 gap·오류를 원자적으로 포함하고, COMMITTED marker 투영 전 경쟁 전이를 차단
- 원격 확인: [PR #26](https://github.com/SASTsimi/sastsimi/pull/26), base `main`, 변경 파일 22개, `Closes #14`, mergeable `MERGEABLE`, merge state `CLEAN`
- GitHub checks: 저장소에 보고된 자동 check 없음. 로컬 검증 결과를 PR 본문에 기록함
- PR #26 R5 리뷰 보완: Gate 결과와 frozen domain input revision의 atomic exact binding, Technical `REVISE`와 일반 retry의 `work_id`·`attempt_id` 분리, 모순된 `ALLOW`의 `INVALID_OUTPUT`·Reporter 차단 계약을 정본·Wiki·보안 시나리오에 반영
- 회귀 검사 보완: 단순 문자열 존재 검사를 4개 순서 기반 regex 계약 검사로 강화하고, 핵심 절을 약화한 4개 mutation이 모두 탐지되는지 확인
- 보완 후 검사: R4-02 review remediation rule 4개, negative scenario 14개, 전체 `Failures: 0`, `git diff --check` 통과
- 독립 최종 재검토: Critical 0, Important 0, Minor 0, 외부 리뷰 요청 3개 모두 해결 판정
- PR #26 R7 추가 리뷰 보완: 동적 `PARTIAL`은 신뢰 관측과 구조화된 `limitations`로 누락 범위를 설명해 가짜 오류·`DataGap`을 만들지 않으며, 동적 `BLOCKED + POLICY_BLOCKED`는 공통 작업 `SUCCEEDED`, 동적 `CANCELLED`는 공통 작업 `CANCELLED`로 매핑함
- 동적 결과 연결 보완: `SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED` 전체에 `dynamic_result_ref`를 요구하고 `TransitionCommit`, work output, 전문 상태 pointer가 같은 결과 revision을 가리킬 때만 Verification 전달
- R7 보완 후 검사: exact output binding 6개, review remediation rule 8개, negative scenario 16개, 전체 `Failures: 0`, `git diff --check` 통과
