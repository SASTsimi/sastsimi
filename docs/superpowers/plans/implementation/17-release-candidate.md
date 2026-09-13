# T17 Release Candidate Documentation and Wheel Smoke Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` or `superpowers:executing-plans`.

**Goal:** 현재 구현에서 실제로 동작하는 설치·설정·조회 경계를 쉬운 한국어로
설명하고, 배포 wheel만 설치한 Ubuntu 24.04·Windows Server 2022 환경에서 CLI,
DB migration, 결정론적 분석, 결과 조회와 Markdown 보고서 export가 이어지는지
자동으로 확인한다.

**Architecture:** README는 짧은 입구로 두고 상세 운영 절차는 `docs/`로
분리한다. wheel에는 실행에 필요한 migration·prompt뿐 아니라 예제 TOML과
사용자 문서를 포함한다. `scripts/wheel-smoke.ps1`은 source import를 차단한 새
venv에 wheel을 설치해 공개 CLI만 호출하며, CI의 두 운영체제 job이 같은
스크립트를 사용한다. 현재 public `analyze`는 실제 저장소 분석이 아니라
결정론적 fake scenario임을 모든 문서와 시험에서 명시한다.

**Spec:** [전체 구현 계획의 Task 17](../2026-09-08-sastsimi-complete-implementation.md),
[Architecture v5](../../../architecture-v5/README.md),
[코드 연결 지도](../../../architecture-to-code.md)

## 선행 상태와 범위

- 이 계획은 `origin/main`의 `1390ec3b`에서 시작한다. 이 기준에는 PR #183
  T15가 이미 들어와 있으므로 “T17을 T15보다 먼저 완료”하는 병합 순서는 더
  이상 만족시킬 수 없다. 이 구현은 T15 파일의 의미를 다시 고치지 않는다.
- PR #182 T14는 이 기준에 없다. T14가 만질 가능성이 큰 production composition,
  provider, sandbox 파일은 피하고 문서·배포 metadata·독립 smoke 경계만 바꾼다.
- 실제 repository 입력을 받는 production 분석 CLI, 외부 제출·공개, 자동 API
  key 탐색, Codex 세션 재사용은 지원한다고 쓰지 않는다.
- Medium/Low 문장 미세 보정과 공개 release/tag/push는 범위 밖이다.

## Task 1: 보고서 목록의 public 식별자 경계 복구

**Files:**

- Modify: `tests/e2e/test_fake_true_pipeline.py`
- Modify: `src/sastsimi/storage/report_export.py`

1. 기존 `test_true_pipeline_closes_exact_report_without_submission`에
   `source.list_current("fake-analysis")`가 정확히 한 건을 반환한다는 assertion을
   추가한다.
2. 해당 test만 실행해 typed `AnalysisId`와 CLI 문자열 비교 때문에 실패하는지
   확인한다.
3. `SQLiteCurrentReportSource.list_current()`가 비교할 때 저장된 ID를 `str()`로
   public 문자열 경계에 맞춘다. 다른 closure·redaction 검사는 바꾸지 않는다.
4. 같은 test와 `tests/unit/interfaces/test_report_cli.py`,
   `tests/unit/reporting/test_markdown_export.py`를 실행한다.

## Task 2: 실제 구현 상태를 반영한 한국어 운영 문서

**Files:**

- Modify: `README.md`
- Create: `docs/installation.md`
- Create: `docs/configuration.md`
- Create: `docs/usage.md`
- Create: `docs/external-tools.md`
- Create: `docs/troubleshooting.md`
- Create: `docs/architecture-to-code.md`
- Create: `config/sastsimi.example.toml`
- Modify: `docs/README.md`
- Modify: `docs/DOCUMENT_GUIDE.md`

1. README 첫 화면을 목적, 구현됨/미지원, Python·uv 필수 조건, Git·Docker·CodeQL·
   OpenGrep·OpenAI 선택 조건, 빠른 설치, 설정, `doctor`, DB, `analyze`, `results`,
   `reports`, `report export`, 문제 해결 링크 순으로 다시 구성한다.
2. `docs/installation.md`에 Python 3.12 64-bit, Ubuntu 24.04 x86_64, Windows
   11/Server 2022 x64라는 현재 host 계약과 source/wheel 설치 절차를 적는다.
3. `docs/configuration.md`와 예제 TOML에 허용 field, CLI > environment > TOML
   우선순위, 허용 환경변수, secret 금지, data layout을 적는다. OpenAI API key와
   Codex ChatGPT 구독 로그인의 공식 경로를 서로 다른 인증 방식으로 설명하고,
   현재 fake `analyze`가 둘을 소비하지 않는다고 적는다.
4. `docs/external-tools.md`에 `capability probe/list/approve`의 의미와 Git,
   CodeQL, OpenGrep, Docker 설치·검증 링크를 적는다. 특히 Docker Desktop은
   Windows Server 2022에서 지원되지 않는다는 공식 제한을 적는다.
5. `docs/usage.md`에 migration부터 fake TRUE 실행, `status` JSON field 확인,
   결과/보고서 목록/show/export까지 실제 명령과 안전 경계를 적는다.
6. `docs/troubleshooting.md`에 host 불일치, migration 미실행, probe 실패,
   report 없음, unsafe path, Windows Docker 문제를 오류 코드 중심으로 적는다.
7. `docs/architecture-to-code.md`에 loader/static/provider/verification/sandbox/
   gates/reporting/storage/CLI 단계별 정본 모듈, 시험 위치와 production 연결 상태를
   표로 연결한다.
8. 문서 index 두 곳에 새 문서의 지위와 읽는 순서를 추가한다.

## Task 3: wheel metadata와 사용자 자료 포함 계약

**Files:**

- Create: `tests/contract/test_distribution.py`
- Modify: `pyproject.toml`

1. 임시 폴더에 wheel을 빌드하고 archive를 읽는 contract test를 작성한다.
   test는 `METADATA`의 Markdown README와 다음 파일을 요구한다:
   `sastsimi/resources/sastsimi.example.toml`, 설치·설정·사용·외부 도구·문제 해결·
   코드 연결 문서, prompt registry/template, Alembic migration.
2. test가 예제 설정과 새 문서 누락으로 실패하는지 확인한다.
3. `[project].readme`와 Hatch wheel `force-include` allowlist를 추가한다.
4. contract test를 다시 실행하고 빌드 결과에 source 경로가 새지 않는지 확인한다.

## Task 4: 설치된 wheel 전용 cross-platform smoke

**Files:**

- Create: `scripts/wheel-smoke.ps1`
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/contract/test_ci_workflow.py`

1. workflow contract test에 `installed-wheel-smoke` job, Ubuntu 24.04/Windows 2022
   matrix, build/script step, `core.needs`와 결과 강제를 요구하는 assertion을
   추가하고 먼저 실패를 확인한다.
2. smoke script는 존재하지 않는 전용 work root만 받아 wheel build, 새 venv,
   wheel install을 수행한다. 설치 뒤 repository 밖에서 `sastsimi --help`,
   `doctor --format json`, `db upgrade/current`, `analyze --scenario TRUE`,
   `results`, `reports`, `report show`, `report export --format markdown`을 실행하고
   JSON status/count와 export file을 검사한다.
3. CI job이 matrix 두 OS에서 동일 script를 실행하도록 하고 `core`가 그 결과를
   필수로 요구하게 한다. action은 기존 workflow의 pin과 권한 경계를 재사용한다.
4. workflow contract test를 통과시킨다.
5. Windows 로컬에서 고유 work root로 script를 실제 실행한다. source tree가
   `PYTHONPATH`에 없어도 설치된 wheel 명령만으로 완료되는지 확인한다.

## Task 5: 완료 전 focused 검증과 독립 검토

1. `uv run ruff format --check`와 `uv run ruff check`를 변경 Python 파일에
   실행한다.
2. `uv run mypy --strict`를 변경 Python test와 production 파일에 실행한다.
3. report CLI/report export/distribution/workflow contract focused tests를 새
   출력으로 다시 실행한다.
4. `scripts/validate-architecture-docs.ps1`와
   `scripts/audit-doc-inventory.ps1 -RepositoryRoot . -CheckLinks`를 실행한다.
5. `git diff --check`와 `git status --short`로 범위 밖 변경과 임시 산출물이 없는지
   확인한다.
6. Blocker/High만 독립 code review로 확인하고 발견 사항을 수정하거나 남은
   blocker로 명시한다.

## 커밋 단위

1. 계획과 현재 범위 기록.
2. 보고서 목록 public 경계 회귀 수정.
3. README·운영 문서·예제 설정·wheel 자료 계약.
4. wheel smoke script와 CI gate.

## 완료 검사

- [ ] CLI 문자열 analysis ID로 current 보고서가 조회된다.
- [ ] README 첫 화면과 상세 문서가 실제 지원/미지원 경계를 일치시킨다.
- [ ] wheel metadata와 archive에 README, 예제 설정, 운영 문서가 들어 있다.
- [ ] clean wheel smoke가 Windows 로컬에서 통과한다.
- [ ] CI가 Ubuntu 24.04와 Windows Server 2022 wheel smoke를 필수로 실행한다.
- [ ] focused tests, Ruff, strict mypy, 문서 validator, link audit, diff check가
      통과한다.
- [ ] 공개 release/tag/push가 없다.
- [ ] 독립 Blocker/High 검토 결과가 처리되거나 명시된다.
