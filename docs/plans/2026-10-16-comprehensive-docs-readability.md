# 전체 현행 문서 가독성 정리 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 현행 사용자·운영·구현 문서를 찾고 읽기 쉽게 정리하면서 원본 기록, 실행 프롬프트, 명령과 링크 호환성을 보존한다.

**Architecture:** 현행 설명은 작업별 진입점과 작은 주제 문서로 조직하고, 기존 긴 문서는 호환 길잡이로 남긴다. 날짜 유무와 관계없이 과거 기록은 원본을 유지하고 색인에서 현행 설명과 구분한다. 링크·앵커·명령 계약을 자동 및 수동으로 검증한다.

**Tech Stack:** Markdown, PowerShell 7 문서 검증기, Python 3.12 표준 라이브러리와 `pytest` 계약 테스트, GitHub Actions 문서 CI.

**Spec:** `docs/plans/2026-10-16-comprehensive-docs-readability-design.md`

## Global Constraints

- 기존 분석 파이프라인·보안 판정·스키마·실행 프롬프트 25개는 변경하지 않는다.
- 과거 설계·계획·검증 기록의 본문과 수치를 보존한다. 현행/기록 분류는 파일 내용으로 결정한다.
- 기존 경로와 공개 앵커를 유지하며 이동한 설명에는 원위치 길잡이를 둔다.
- `COMPLETE`/`PARTIAL`/`BLOCKED`와 진행률, Python 제품 코드 범위, 미검증 항목, PoC·Scope Gate의 독립 판정 의미를 바꾸지 않는다.
- 인증·새 분석 명령은 검증 과정에서 실행하지 않는다. 명령 구문은 CLI 도움말·구현·계약 테스트로 확인한다.
- `scripts/validate-current-docs.ps1`가 금지한 폐기 문서 폴더는 만들지 않는다. 이 계획도 저장소가 허용하는 `docs/plans/`에 둔다.
- 검증기 코드 변경은 RED→GREEN 테스트로 보호한다. 사람이 읽는 설명 문장은 새 문자열 고정 테스트를 늘리지 않고 기존 계약·링크 검사와 직접 대조한다.

## Review Focus

1. 옮겨진 문제 해결 절에 대한 기존 외부 앵커가 여전히 증상 요약과 새 본문으로 연결되는가? Task 1의 프래그먼트 검사와 Task 2의 원위치 점검.
2. 자동 제목 앵커의 한글·중복 제목과 명시적 `<a id>`가 링크 검사에서 잘못 깨지지 않는가? Task 1의 프래그먼트 테스트.
3. 과거 계획의 미완료 체크박스가 현재 미완료 작업으로 보이지 않는가? Task 4의 색인 직접 검토.
4. Provider·PoC 문서를 정리하며 토큰·비밀정보 안내나 `READY`의 제한 의미를 지우지 않았는가? Task 2의 기존 계약 테스트.
5. 오래된 실측값과 검증 근거를 최신 성능·제보 성과처럼 표현하지 않는가? Task 4의 원본 대조와 독립 리뷰.

---

### Task 1: 문서 링크·앵커 보호

**Files:**
- Modify: `scripts/validate-current-docs.ps1`
- Create: `scripts/validate_doc_fragments.py`
- Modify: `.github/workflows/docs.yml`
- Modify: `tests/contract/test_current_documentation.py`

**Interfaces:**
- Consumes: 추적 Markdown 목록과 기존 `validate-current-docs.ps1`의 로컬 파일 링크 검사.
- Produces: `validate_local_fragments(root: Path, files: list[Path]) -> list[str]`가 각 내부 프래그먼트의 누락을 반환한다. 현행 PowerShell 검증기와 문서 CI가 이 검사도 실행한다.

- [ ] **Step 1: 실패 계약 테스트 추가.** `test_current_documentation.py::test_local_fragments_accept_unicode_duplicate_and_explicit_id`는 한글 제목·중복 제목·`<a id>`가 유효함을, `::test_local_fragments_reject_missing_target`은 대상에 없는 `#fragment`를 오류로 반환함을 검사한다. 코드 펜스 내부의 가짜 링크는 무시한다.
- [ ] **Step 2: 테스트를 실행해 새 검사가 없는 상태의 실패를 확인한다.** 실행: `$env:PYTHONPATH='src'; & ..\..\.venv\Scripts\python.exe -m pytest tests/contract/test_current_documentation.py -q`. 예상: 새 검사 함수가 없어 실패.
- [ ] **Step 3: `validate_local_fragments(root: Path, files: list[Path]) -> list[str]`를 구현한다.** 로컬 Markdown 링크의 프래그먼트만 검사한다. fenced code·원격 URL을 제외하고 URL 디코딩, 명시적 HTML `id`, GitHub 제목 slug(한글·중복 번호)를 처리한다. PowerShell 검증기는 `python` 실행 실패도 오류로 보고하고, 문서 CI에는 저장소의 기존 SHA로 고정된 Python 3.12 설치 단계를 추가한다. 기존 파일 링크·stage·ADR 검사는 유지한다.
- [ ] **Step 4: 집중 검증한다.** 위 pytest와 `pwsh -NoProfile -File scripts/validate-current-docs.ps1`가 통과해야 한다.
- [ ] **Step 5: 이 단계만 커밋한다.** `git add scripts/validate-current-docs.ps1 scripts/validate_doc_fragments.py .github/workflows/docs.yml tests/contract/test_current_documentation.py` 후 `git commit -m "test: protect documentation anchors"`.

### Task 2: 설치·운영·복구 안내

**Files:**
- Modify: `docs/installation.md`, `docs/provider-setup.md`, `docs/usage.md`, `docs/troubleshooting.md`, `docs/onboarding-evidence.md`, `docs/dashboard-demo.md`, `docs/dashboard-read-model.md`, `docs/release-follow-ups.md`, `docs/GLOSSARY.md`
- Create: `docs/troubleshooting/poc-environment.md`, `docs/troubleshooting/poc-recovery.md`, `docs/usage/dashboard-and-results.md`

**Interfaces:**
- Consumes: Task 1의 앵커 검사와 기존 CLI·온보딩 문서 계약.
- Produces: 설치→인증→분석/재개→대시보드/보고서→오류 복구의 읽기 경로. 원래 문서와 앵커는 남고 이동한 심화 설명으로 연결된다.

- [ ] **Step 1: 원위치·정보 보존 목록 작성.** Docker·PoC, `analyze`/`resume`/`dashboard`/`results`/`runtime` 앵커와 고유 명령·제한·두 manifest 제목을 문서에서 읽고 작업 기록에 적는다.
- [ ] **Step 2: 기존 계약의 기준 결과 확인.** 실행: `$env:PYTHONPATH='src'; & ..\..\.venv\Scripts\python.exe -m pytest tests/contract/test_operator_docs.py -q`. 예상: 변경 전 통과.
- [ ] **Step 3: 현행 안내를 정리한다.** 첫 화면에는 대상 사용자·증상/작업별 선택·주의 상태를, 심화 페이지에는 상세 환경·재개 절차를 둔다. 원위치 제목과 명령·오류 코드는 남긴다. 같은 설명만 중복 삭제하고 고유 제한은 유지한다.
- [ ] **Step 4: 문서 검증과 계약 테스트를 통과시킨다.** `pwsh -NoProfile -File scripts/validate-current-docs.ps1` 및 Task 2의 pytest. CLI 구문은 `python -m sastsimi --help`/서브명령 `--help`와 코드로 대조하며 로그인·분석은 실행하지 않는다.
- [ ] **Step 5: 해당 파일만 커밋한다.** `git commit -m "docs: clarify operator and recovery guides"`.

### Task 3: 현재 구현 구조 문서

**Files:**
- Modify: `docs/architecture/README.md`, `pipeline.md`, `runtime-and-recovery.md`, `agents-and-providers.md`, `contracts-and-storage.md`, `static-and-dynamic-analysis.md`, `gates-chaining-reporting.md`, `security-boundaries.md`, `implementation-map.md` (모두 `docs/architecture/` 아래)
- Create: `docs/architecture/surface-evidence-versions.md`

**Interfaces:**
- Consumes: 기존 14개 pipeline stage 순서, 코드 경로, `REVIEWED`와 `COVERED` 구분, 과거 기록.
- Produces: 현재 파이프라인/재개의 짧은 개요와 세부 근거로 가는 링크; 기술적 의미가 바뀌지 않은 구조 문서.

- [ ] **Step 1: 기술 의미 보존 목록 작성.** 기존 14개 stage 순서, v4–v11의 불변성·해시·범위·`REVIEWED`/`COVERED`·`HOLD`/`PARTIAL` 문구와 코드 참조를 읽고 작업 기록에 적는다.
- [ ] **Step 2: 기준 결과 확인.** Task 1의 pytest와 문서 validator가 변경 전 통과해야 한다.
- [ ] **Step 3: 구현 문서를 주제별로 정리한다.** 특히 Runtime의 v4–v11 설명을 원위치 요약표와 `surface-evidence-versions.md` 세부 페이지로 분리하며 해시/불변성/`REVIEWED`·`COVERED`/`HOLD`·`PARTIAL` 경계를 유지한다. 과거 보고서 그룹 수치는 현재 동작 설명에서 분리해 원본 검증 기록을 링크한다.
- [ ] **Step 4: 문서·계약 검증.** validator와 `test_current_documentation.py`가 통과하고 `rg`로 모든 `src/sastsimi/...py` 참조를 확인한다.
- [ ] **Step 5: 이 문서군을 커밋한다.** `git commit -m "docs: organize current architecture guides"`.

### Task 4: 결정·과거 계획·검증 기록의 색인

**Files:**
- Modify: `docs/decisions/README.md`
- Create: `docs/plans/README.md`, `docs/validation/README.md`

**Interfaces:**
- Consumes: 13개 `ACCEPTED` ADR, 결정 폴더의 날짜 기반 과거 설계 3개, 계획·검증 기록과 원본 수치.
- Produces: 현재 결정과 과거 기록을 구분한 목록. 원본 문서 본문은 변경하지 않는다.

- [ ] **Step 1: 기록 경계 목록 작성.** ADR 13개와 과거 설계 3개, 날짜 없는 옛 설계, 계획·검증 문서의 출처·수치·현재 상태를 분류한다.
- [ ] **Step 2: 기준 결과 확인.** Task 1의 pytest와 문서 validator가 변경 전 통과해야 한다.
- [ ] **Step 3: 색인 작성.** 파일명에 날짜가 없는 기록도 내용에 따라 분류한다. `docs/validation/2026-10-08-python-recall-methodology.md`의 원본 수치·해시는 그대로 두고 현행 평가 안내와 링크한다. 과거 설계가 최신 파이프라인을 설명하는 것처럼 보이지 않게 한다.
- [ ] **Step 4: 원본 보존·링크 검사.** 변경 파일 목록에 과거 원본·프롬프트가 없는지 `git diff --name-only origin/main`으로 확인하고 validator 및 집중 pytest를 통과시킨다.
- [ ] **Step 5: 이 문서군을 커밋한다.** `git commit -m "docs: index decisions and historical records"`.

### Task 5: 최상단 읽기 순서와 통합 검증

**Files:**
- Modify: `README.md`, `CONTRIBUTING.md`, `docs/README.md`, `docs/DOCUMENT_GUIDE.md`

**Interfaces:**
- Consumes: Tasks 2–4가 확정한 현행 문서와 과거 색인 경로.
- Produces: 목적별 첫 진입점, 간결한 README, 현재/기록 구분, 깨지지 않는 공개 링크.

- [ ] **Step 1: 최상단 진입점 점검.** README의 네 공개 앵커와 Windows 단계별 시작 명령, 문서 지도의 현재 안내·기록 링크, 빠진 대시보드 읽기 모델을 확인한다.
- [ ] **Step 2: 기준 결과 확인.** `test_distribution.py`, `test_operator_docs.py`, `test_current_documentation.py`와 문서 validator가 변경 전 통과해야 한다.
- [ ] **Step 3: 첫 화면과 문서 지도를 정리한다.** 독자별 시작 경로만 상위에 배치하고 중복 목록을 줄인다. ADR 수를 13개로 고치고, 과거 기록의 현재 상태를 오해하지 않게 한다. Markdown 표는 좁은 화면에서도 읽히는 단순한 구조로 유지한다.
- [ ] **Step 4: 통합 검증.** `pwsh -NoProfile -File scripts/validate-current-docs.ps1`, 위 계약 테스트, `git diff --check`, 모든 변경 파일의 링크·프래그먼트·평문 경로 검사. Windows `.venv` 명령과 Linux/WSL 구분을 읽고 확인한다.
- [ ] **Step 5: 통합 문서 변경을 커밋한다.** `git commit -m "docs: simplify project navigation"`.

### Task 6: 독립 리뷰·PR·병합

**Files:** 새 파일 없음. 필요 시 앞선 문서 또는 검증기만 수정.

**Interfaces:**
- Consumes: Task 1–5의 커밋과 통과한 검증 결과.
- Produces: 사용자가 검토할 수 있는 PR, CI 통과 증거, main 병합 결과.

- [ ] **Step 1: 독립 리뷰로 누락·의미 변화·깨진 앵커를 확인한다.** 삭제된 고유 명령·안전 제한, 과거 기록 변경, 프롬프트 변경을 우선 점검한다.
- [ ] **Step 2: 지적 사항을 최소 수정하고 전체 문서/계약 검증을 재실행한다.** `pwsh -NoProfile -File scripts/validate-current-docs.ps1` 및 `PYTHONPATH=src`의 관련 `pytest`가 통과해야 한다.
- [ ] **Step 3: 브랜치를 푸시하고 PR을 만든다.** 변경·이동·삭제의 이유와 보존 원본, 검증 결과를 PR 본문에 적는다.
- [ ] **Step 4: Documentation 및 관련 CI 통과와 PR diff를 확인한다.** 실패하면 원인을 수정하고 같은 PR을 갱신한다.
- [ ] **Step 5: CI와 리뷰 조건이 충족된 경우에만 main에 병합한다.** 병합 SHA와 남은 제한사항을 보고한다.
