# R3-06 Implementation Baseline Documentation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Architecture v5와 R3-01~R3-05를 한 명의 구현 담당자가 그대로 코드로 옮길 수 있는 기술·파일 구조·저장·설정·실행 기준선으로 확정한다.

**Architecture:** 새 `implementation/06-implementation-baseline.md`가 물리 기술과 repository 구조의 정본이 되고, 기존 `01`~`05`는 단계·계약 시험·복구·Provider·Prompt 세부 설계를 계속 소유한다. 중요한 기술 선택은 ADR에 근거와 상태를 남기고, 문서 인덱스와 validator가 누락·폐기 용어·미확정 구현 차단 항목을 검출한다.

**Tech Stack:** Markdown, PowerShell architecture validator, Git, GitHub Issue/PR

**Spec:** GitHub Issue #92 및 `docs/architecture-v5/implementation/01-module-map.md`, `02-contract-test-plan.md`, PR #107의 `03-recovery-test-plan.md`, `04-provider-decision.md`, `05-prompt-runtime.md`

## Global Constraints

- 기준 branch는 최신 `origin/main`에서 만든 `docs/r3-06-implementation-baseline`이다.
- PR은 PR #107과 Issue #89가 끝나기 전까지 Draft로 유지한다.
- Agent 역할은 Provider·모델과 분리하고 별도 모델 전용 profile 객체를 만들지 않는다.
- 모델은 exact `provider_profile_ref`와 `LLMCallSpec.model`로 선택한다.
- 공식 역할명과 실행 식별값은 `docs/GLOSSARY.md`를 따른다.
- 별도 Repository Snapshot 모듈과 첫 구현용 외부 message queue 제품을 추가하지 않는다.
- 구현하지 않은 코드·실제 성능·운영 Provider 지원을 완료했다고 표현하지 않는다.
- 구현 차단 결정을 미확정 상태로 남긴 채 Issue #92를 닫지 않는다.

---

### Task 1: 기존 validator의 Windows 줄바꿈 오류 수정

**Files:**
- Modify: `scripts/validate-architecture-docs.ps1`

**Interfaces:**
- Consumes: `implementation/05-prompt-runtime.md`의 `EXECUTE_REPRODUCTION` registry 행
- Produces: LF와 CRLF에서 같은 결과를 내는 session policy 검사

- [x] **Step 1:** 현재 `main`에서 validator를 실행해 `AUTO enum` 실패를 재현한다.
- [x] **Step 2:** 정규식이 CRLF 행 끝을 허용하지 않아 행을 찾지 못한다는 진단 값을 기록한다.
- [x] **Step 3:** 행 정규식의 끝을 `\r?$`로 바꿔 문서 의미는 건드리지 않고 플랫폼 의존성만 제거한다.
- [x] **Step 4:** validator를 다시 실행해 기존 검사 전체가 통과하는지 확인한다.

### Task 2: R3-06 산출물 검사를 먼저 추가

**Files:**
- Modify: `scripts/validate-architecture-docs.ps1`

**Interfaces:**
- Consumes: Issue #92 완료 조건
- Produces: baseline·인덱스·ADR·최신 명칭·모델 비고정·Reporter 종료 경계를 검사하는 규칙

- [x] **Step 1:** `06-implementation-baseline.md`, implementation README와 ADR 파일 존재 검사를 추가한다.
- [x] **Step 2:** `provider_profile_ref + model`, 11개 LLM 역할, 비-LLM 구성요소, `ReportDraft` 자동화 종료와 #107 dependency marker 검사를 추가한다.
- [x] **Step 3:** 폐기된 모델 전용 profile 명칭, `R7 Setup Automation`, 특정 모델 기본값과 구현 차단 미확정 표현을 R3-06 문서에서 거절하는 검사를 추가한다.
- [x] **Step 4:** validator를 실행해 새 산출물이 없어서 실패하는 것을 확인한다.

### Task 3: 구현 기준선과 기술 결정 ADR 작성

**Files:**
- Create: `docs/architecture-v5/implementation/06-implementation-baseline.md`
- Create: `docs/review/decisions/ADR-015-r3-implementation-baseline.md`
- Modify: `docs/review/decisions/README.md`

**Interfaces:**
- Consumes: Architecture v5 정본과 R3-01~R3-05
- Produces: 기술 결정표, 실제 repository tree, 모듈 dependency, 저장 layout, CLI, CI와 구현 순서

- [x] **Step 1:** 문서 권한·상태·선행 문서·충돌 시 우선순위를 적는다.
- [x] **Step 2:** Python, uv, Pydantic, SQLite·SQLAlchemy·Alembic, content-addressed artifact, argparse와 subprocess adapter 선택을 근거·대안·상태와 함께 확정한다.
- [x] **Step 3:** `src/sastsimi`, tests, config, evals, migrations, docker와 runtime data tree의 책임·금지 권한·public interface를 확정한다.
- [x] **Step 4:** 허용 import DAG와 Agent·runtime·adapter·storage 권한을 확정한다.
- [x] **Step 5:** Provider·모델·Prompt·session·secret·설정 precedence와 활성화 전 capability gate를 확정한다.
- [x] **Step 6:** SQLite transaction·migration·artifact staging·crash recovery와 cleanup을 구체적인 순서로 확정한다.
- [x] **Step 7:** CLI command·exit code, 외부 dependency preflight와 CI job을 확정한다.
- [x] **Step 8:** 한 명 구현 순서와 fake 기반 vertical slice 완료 조건을 확정한다.
- [x] **Step 9:** ADR-015에 고려한 선택지, 결정, 영향, 검토자와 PR #107 이후 기준 SHA 갱신 조건을 기록한다.

### Task 4: 구현 문서 인덱스와 상위 안내 동기화

**Files:**
- Create: `docs/architecture-v5/implementation/README.md`
- Modify: `docs/architecture-v5/README.md`
- Modify: `docs/DOCUMENT_GUIDE.md`

**Interfaces:**
- Consumes: implementation 문서 `01`~`06`
- Produces: 구현 담당자와 역할 검토자가 읽을 순서·권한·상태를 찾는 단일 인덱스

- [x] **Step 1:** `01`~`06`의 목적, 독자, 결정 범위와 읽는 순서를 implementation README에 기록한다.
- [x] **Step 2:** `03-recovery-test-plan.md`는 PR #107 병합 전 dependency 상태임을 표시한다.
- [x] **Step 3:** Architecture README에 구현 인계 묶음과 `06` 정본 역할을 연결한다.
- [x] **Step 4:** DOCUMENT_GUIDE에 implementation README, `06`과 ADR-015를 추가한다.

### Task 5: 요구사항 대조, 검증, commit과 Draft PR

**Files:**
- Verify: 이번 branch의 모든 변경 파일

**Interfaces:**
- Consumes: Issue #92 완료 조건과 Tasks 1~4 산출물
- Produces: 검증된 commit, 원격 branch와 Draft PR

- [x] **Step 1:** Issue #92 항목별로 산출물 위치를 대조하고 누락을 수정한다.
- [x] **Step 2:** 폐기 용어, 고정 모델, 잘못된 Agent 이름, 미확정 구현 차단 표현과 끊어진 상대 링크를 검색한다.
- [x] **Step 3:** `scripts/validate-architecture-docs.ps1`과 `git diff --check`를 실행한다.
- [x] **Step 4:** 변경 통계와 diff를 다시 읽어 기존 역할·데이터·상태 의미 변경이 없는지 확인한다.
- [ ] **Step 5:** 검증 결과와 PR #107 dependency를 포함해 commit하고 branch를 push한다.
- [ ] **Step 6:** `Closes #92`, `Refs #4, #24, #25, #89, #90, #91`, `Depends on #107`을 포함한 Draft PR을 생성한다.
