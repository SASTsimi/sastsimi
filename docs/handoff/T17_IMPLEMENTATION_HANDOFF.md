# T17 구현 인계서

이 문서는 T17까지 병합된 `main`의 실제 구현 상태와 다음 작업 시작 기준을 설명합니다.
기능이 존재하는 것과 실제 외부 환경에서 운영 승인이 끝난 것을 구분하며, 확인하지
못한 기능을 완료로 표시하지 않습니다.

## 1. 인계 기준

- 작성 시점: 2026-09-14 04:23 KST
- T17 병합 PR: [#184](https://github.com/SASTsimi/sastsimi/pull/184)
- T17 최종 branch head: `f1a5163e452d9bdfb19109c838da1d0dbc0f41d8`
- T17 시작 기준 main: `53fee232a1810e9432c070a5f4e2c37651274c86`
- T17 병합 기준 main: `d0acc729447eaf87368a421a65a9cc2bfe6eb5f0`
- PR candidate CI:
  - [Application foundation 34774586896](https://github.com/SASTsimi/sastsimi/actions/runs/34774586896): SUCCESS
  - [Documentation 34774586879](https://github.com/SASTsimi/sastsimi/actions/runs/34774586879): SUCCESS
  - [Ubuntu wheel smoke](https://github.com/SASTsimi/sastsimi/actions/runs/34774586896/job/103770242780): SUCCESS
  - [Windows wheel smoke](https://github.com/SASTsimi/sastsimi/actions/runs/34774586896/job/103770242715): SUCCESS
- T17 병합 main CI:
  - [Application foundation 34775892491](https://github.com/SASTsimi/sastsimi/actions/runs/34775892491): SUCCESS
  - [Documentation 34775892527](https://github.com/SASTsimi/sastsimi/actions/runs/34775892527): SUCCESS
  - [Ubuntu wheel smoke](https://github.com/SASTsimi/sastsimi/actions/runs/34775892491/job/103773808141): SUCCESS
  - [Windows wheel smoke](https://github.com/SASTsimi/sastsimi/actions/runs/34775892491/job/103773808286): SUCCESS
- 로컬 smoke 환경:
  - Microsoft Windows `10.0.26200`, x64
  - CPython `3.12.10`
  - `uv sync --frozen` 소스 설치와 clean virtual environment wheel 설치
- CI 환경:
  - Ubuntu 24.04 x86-64, Python 3.12
  - Windows Server 2022 x64, Python 3.12
  - Ubuntu에서 실제 Docker 동적 재현 E2E 별도 실행
- 공개 release, tag, package registry publish는 수행하지 않았습니다.

이 문서의 구현 기준은 PR #184를 병합한 위 main SHA입니다. SHA나 CI가 다르면 현재
코드를 다시 확인해야 하며, 이 문서만으로 완료를 추정하면 안 됩니다.
인계서 자체를 병합하는 문서 전용 commit은 위 구현 기준 SHA 다음에 생성됩니다.

## 2. 현재 구현 상태

### T08~T17 범위

- **T08 정적 사실 계층 — 구현됨**
  - exact Git commit clone·checkout, `RepositoryProfile`, Python AST·CodeQL·OpenGrep
    adapter, 결과 정규화, 규칙 실행 상태, `StaticFactBundle`, 제한된 코드 context 조회가
    연결돼 있습니다.
  - 실제 도구 실행은 현재 host의 승인된 capability가 필요합니다. CodeQL adapter의
    존재는 production 활성화를 의미하지 않습니다.
- **T09 Provider·Prompt runtime — 구현됨**
  - Provider에 종속되지 않는 Prompt registry, exact Provider·model·Prompt 선택,
    입력 projection·민감정보 제거, 구조화 출력 검사와 호출 provenance가 있습니다.
  - 실제 credential, 약관, 평가와 사람 승인은 별도로 준비해야 합니다.
- **T10 Hypothesis·Verification — 구현됨**
  - Hypothesis 제안·등록, 독립 Pro·Con, initial assessment, FALSE·HOLD, Technical
    `REVISE`의 새 Verification generation 흐름이 연결돼 있습니다.
  - final TRUE는 T11의 같은 generation validated PoC 없이는 허용되지 않습니다.
- **T11 동적 재현 — 구현됨**
  - `EnvironmentRequirements`, `ReproductionPlan`, Docker Sandbox, `AgentLog`, PoC
    candidate, 같은 attempt의 validated PoC, 동적 결과와 cleanup 경계가 있습니다.
  - 실행 실패는 취약점 FALSE가 아닙니다. 실제 사용에는 승인된 Docker capability와
    profile이 필요합니다.
- **T12 Gate·Finding·Reporter — 구현됨**
  - final TRUE 이후 CWE Labeling, Technical Gate, Rule Scope Gate, Finding,
    `ReportDraft`, current closure를 검사하는 Markdown show·export가 연결돼 있습니다.
  - HTML·PDF 및 자동 외부 제출·공개는 지원하지 않습니다.
- **T13 Primitive·Chaining — 구현됨**
  - TRUE·조건 있는 HOLD Primitive, admission, exact lineage, child hypothesis,
    중복·순환·예산·restart 경계가 있습니다.
  - 새로운 공격 주장은 반드시 새 가설로 전체 검증을 다시 거칩니다.
- **T14 production 조립 — 구현됨**
  - production `analyze`, T08~T13 graph, Provider·Prompt·정책·provisioning 연결,
    지연 Docker 준비 검사, status·results·reports·cancel과 read-only resume 검사가
    연결돼 있습니다.
  - Fake 없는 clone→Markdown production 전체 E2E와 실제 resume dispatch는 아직
    확인 또는 구현되지 않았습니다. CodeQL은 fail-closed입니다.
- **T15 보안 조치 — 일부 병합됨, 최종 감사 미완료**
  - SQLite workspace lease, 중앙 `SensitivePathPolicy`, CI Action full SHA pin,
    checkout credential 비보존 조치는 이미 병합됐습니다.
  - 최종 통합 보안 감사, 공통 failure oracle, `docs/security.md`, 독립 보안 승인은
    완료되지 않았고 이번 T17 작업에서 실행하지 않았습니다.
- **T16 capability·onboarding — 구성요소 구현, 외부 조합 검증 미완료**
  - capability registry·probe·approval, Docker build 경계 검증, OpenAI API adapter,
    공식 Codex CLI adapter, production onboarding·provisioning과 Python·JavaScript
    저장소 matrix가 있습니다.
  - 실제 Provider·model·Prompt 조합의 전체 PVD·R8 평가·사람 승인, CodeQL production
    promotion과 추가 Provider는 완료되지 않았습니다.
- **T17 운영 문서·배포 smoke — 완료**
  - README, 설치·Provider·사용·문제 해결·코드 지도, public analysis ID 보고서 조회,
    wheel metadata·resource 검사, Ubuntu·Windows clean-wheel smoke를 추가했습니다.
  - T17 완료는 Fake 없는 production 출시 성공이나 정식 배포를 뜻하지 않습니다.

### 외부 준비가 필요한 기능

- Git·Python AST·OpenGrep·Docker는 사용할 host에서 probe를 통과하고 exact
  `approval_target_hash`를 사람이 승인해야 합니다.
- OpenAI API는 실행 환경 또는 secret store가 `OPENAI_API_KEY`를 주입해야 합니다.
- Codex 회원제는 공식 `codex login`만 사용합니다. cookie나 browser profile을
  복사하지 않습니다.
- Provider·model·Prompt별 PVD, 약관 확인, R8 평가, 사람 승인과 current onboarding
  manifest가 모두 필요합니다.
- 공식 프로그램 정책과 production provisioning도 exact hash와 유효 기간을 가진
  승인 근거가 필요합니다.
- Docker는 daemon identity, 실제 build·run·health·cleanup, resource limit와 외부
  Sandbox 경계를 probe로 확인해야 합니다.
- CodeQL은 안전한 hard-quota backend와 exact prebuilt DB 공급 경로가 없어
  production에서 의도적으로 활성화할 수 없습니다.

### Fake·demo와 production 구분

- Production은 `sastsimi analyze --repo ... --commit ... --profile ...` 경로이며 실제
  capability·Provider·onboarding·정책·provisioning을 요구합니다.
- Fake는 `sastsimi demo analyze --scenario ...`에서만 실행하며 설치와 결정론적 회귀
  확인용입니다.
- production 준비 실패를 Fake로 자동 대체하지 않습니다.
- Fake TRUE와 Fake 보고서는 실제 저장소·LLM·Docker의 production 성공 증거가 아닙니다.

## 3. 실제 사용자 실행 흐름

아래 명령은 소스 저장소 설치 기준입니다. 검증된 wheel 사용자는 가상환경을 활성화한
뒤 `uv run sastsimi` 대신 `sastsimi`를 사용합니다.

### 3.1 clone과 설치

```text
git clone https://github.com/SASTsimi/sastsimi.git
cd sastsimi
git rev-parse HEAD
uv sync --frozen
uv run sastsimi --help
uv run sastsimi analyze --help
uv run sastsimi doctor --format json
```

개발·검증 도구가 필요하면 `uv sync --frozen --all-groups`를 사용합니다. wheel은
Python 3.12의 새 가상환경에 다음처럼 설치합니다.

```text
python -m pip install <검증된-sastsimi-wheel-경로>
sastsimi --help
sastsimi doctor --format json
```

### 3.2 데이터베이스 초기화

```text
uv run sastsimi --data-dir <data-dir> db upgrade head --format json
uv run sastsimi --data-dir <data-dir> db current --format json
```

current revision은 이 기준 SHA에서 `0008_cancellation_observations`입니다.

### 3.3 Provider 인증

API key를 저장소나 TOML에 쓰지 않습니다. 실행 환경이 주입한 이름만 참조합니다.

```text
uv run sastsimi --data-dir <data-dir> capability probe OPENAI_API --model <model-id> --credential-ref env:OPENAI_API_KEY --format json
```

이 probe는 작은 인증·구조화 출력 시험이며 full PVD, R8 평가와 사람 승인을 대신하지
않습니다. Codex 회원 로그인은 공식 client에서만 수행합니다.

```text
codex login
codex login status
```

### 3.4 CodeQL·OpenGrep·Docker 준비

```text
git --version
codeql version --format=terse
codeql resolve languages
codeql resolve packs
docker version
docker info
```

OpenGrep 실행 파일의 설치·`PATH` 확인과 profile 설정은
[`docs/installation.md`](../installation.md)의 현재 운영 절차를 따릅니다.

사용할 환경의 capability를 같은 data directory에서 probe합니다.

```text
uv run sastsimi --data-dir <data-dir> capability probe GIT --format json
uv run sastsimi --data-dir <data-dir> capability probe PYTHON_AST --format json
uv run sastsimi --data-dir <data-dir> capability probe OPENGREP --format json
uv run sastsimi --data-dir <data-dir> capability probe DOCKER --docker-host <승인된-daemon-주소> --format json
uv run sastsimi --data-dir <data-dir> capability list --format json
```

`status=PASSED`, `activation_supported=true`, `approval_target_hash`를 확인한 receipt만
사람이 승인합니다.

```text
uv run sastsimi --data-dir <data-dir> capability approve <probe-id> --target-hash <approval-target-hash> --format json
uv run sastsimi --data-dir <data-dir> capability approve <docker-probe-id> --target-hash <docker-approval-target-hash> --docker-host <승인된-daemon-주소> --format json
```

CodeQL은 강제로 approve하지 않습니다. production profile이 CodeQL을 요구하면 현재는
exit 4로 안전하게 차단됩니다.

### 3.5 production profile과 onboarding

`config/profiles/production.example.toml`을 저장소 밖의
`<production-profile.toml>`로 복사해 승인값을 채웁니다. 실제 secret은 쓰지 않고
`credential_ref = "env:NAME"` 형식만 사용합니다.

```text
uv run sastsimi --data-dir <data-dir> onboarding init --profile <production-profile.toml> --output-dir <new-onboarding-work-dir> --format json
uv run sastsimi --data-dir <data-dir> onboarding requirements --profile <production-profile.toml> --format json
uv run sastsimi --data-dir <data-dir> onboarding prepare --profile <production-profile.toml> --manifest <approval-manifest.json> --evidence <evidence-1.json> --evidence <evidence-2.json> --format json
uv run sastsimi --data-dir <data-dir> onboarding status --profile <production-profile.toml> --format json
```

`requirements`는 누락 항목을 보여 줄 뿐 READY를 만들지 않습니다. `prepare`에는 실제
PVD·정책·R8 평가·Prompt 승인·provisioning 근거를 모두 전달하고, 마지막에
`status=READY`인지 확인합니다.

### 3.6 저장소 분석

commit은 branch·tag·짧은 SHA가 아닌 소문자 40자리 또는 64자리 exact SHA입니다.

```text
uv run sastsimi --data-dir <data-dir> analyze --repo <URL-or-local-Git-path> --commit <exact-SHA> --profile <production-profile.toml> --format json
```

### 3.7 상태·결과·Markdown 보고서

```text
uv run sastsimi --data-dir <data-dir> status <analysis_id> --format json
uv run sastsimi --data-dir <data-dir> results <analysis_id> --format json
uv run sastsimi --data-dir <data-dir> reports <analysis_id> --format json
uv run sastsimi --data-dir <data-dir> report show <finding_id>
uv run sastsimi --data-dir <data-dir> report export <finding_id> --format markdown
```

기본 export 경로는 `<data-dir>/reports/<analysis_id>/<finding_id>.md`입니다. 실패하면
[`docs/troubleshooting.md`](../troubleshooting.md)를 확인하고 오래된 Markdown이나
다른 분석의 결과를 복사해 우회하지 않습니다.

## 4. 현재 아키텍처 연결 상태

- **Repository Loader**: `src/sastsimi/static_analysis/repository_loader.py`가 분석별
  workspace에 exact commit을 준비하고 URL credential·경로 이탈·민감 파일을
  fail-closed 처리합니다.
- **Static Analysis**: `src/sastsimi/static_analysis/`의 AST·CodeQL·OpenGrep adapter와
  coordinator가 실제 실행 상태와 raw artifact를 같은 attempt의 `StaticFactBundle`로
  정규화합니다.
- **Hypothesis Agent**: `src/sastsimi/agents/hypothesis.py`가 proposal을 만들고,
  `src/sastsimi/orchestration/hypothesis_workflow.py`와 trusted Runtime이 형식·중복·
  권한을 확인한 뒤 ID와 등록 상태를 확정합니다.
- **Verification**: `src/sastsimi/verification/`이 독립 Pro·Con, initial assessment,
  동적 요청과 final verdict를 관리합니다. Provider·context·형식 실패는 verdict 없는
  BLOCKED 또는 FAILED입니다.
- **Dynamic Reproduction**: `src/sastsimi/reproduction/`과 `src/sastsimi/sandbox/`가
  환경·recipe·PoC candidate를 만들고 승인된 Docker 경계 안에서 실행합니다. 비-LLM
  Session Manager가 같은 attempt의 log·환경·digest를 검사해 validated PoC와 결과를
  확정합니다.
- **CWE Labeling**: `src/sastsimi/reporting/cwe_workflow.py`가 current final TRUE와 exact
  Verification에 맞는 current `CWELabel`을 만듭니다.
- **Technical Gate**: `src/sastsimi/reporting/technical_gate_*`가 current TRUE,
  validated PoC, CWE와 기술 근거를 검토합니다. REVISE는 같은 owner의 새 Verification
  generation으로 돌아갑니다.
- **Rule Scope Gate**: `src/sastsimi/reporting/rule_scope_gate_*`가 실행 시작 때 고정한
  공식 정책으로 testing restriction·scope·reportability를 검토하며 기술 verdict를
  바꾸지 않습니다.
- **Chaining**: `src/sastsimi/chaining/`과
  `src/sastsimi/orchestration/primitive_handoff.py`가 허용된 TRUE 또는 조건 있는 HOLD
  Primitive를 exact lineage로 연결하고 새 주장을 child hypothesis로 등록합니다.
- **Finding**: `src/sastsimi/reporting/finding_normalization.py`가 Verification·CWE·두
  Gate·PoC closure가 current일 때만 내부 Finding을 확정합니다.
- **Reporter**: `src/sastsimi/reporting/`과
  `src/sastsimi/storage/report_export.py`가 `ReportDraft`의 exact closure를 검사해
  Markdown으로 보여 주고 내보냅니다. 새 사실을 만들거나 외부 공개하지 않습니다.

상세 지도는 [`docs/architecture-to-code.md`](../architecture-to-code.md)를 따릅니다.
schema나 모듈 존재만으로 production 완료를 판단하지 않습니다.

## 5. 중요한 공통 규칙

1. 오류·timeout·인증 실패·도구 미실행·Docker 실패를 취약점 FALSE로 바꾸지 않습니다.
   재시도 가능하면 BLOCKED, 복구 불가이면 verdict 없는 FAILED로 남깁니다.
2. final TRUE에는 current Verification generation과 같은 attempt의
   `SUCCEEDED + SUPPORTED` 동적 결과와 validated PoC가 필요합니다.
3. 모든 소비자는 같은 `analysis_id`, `workspace_id`, `commit_id`, `hypothesis_id`,
   generation·attempt와 immutable exact record reference를 확인합니다.
4. LLM Agent는 proposal·분석 결과를 만들고, trusted Runtime이 권한·입력 closure·예산·
   호출 순서·상태 전이와 저장 여부를 결정합니다.
5. Dynamic Reproduction Agent는 Sandbox 안의 재현 방법을 제안할 수 있지만 host,
   Docker daemon/socket, mount, namespace, secret, egress와 resource 경계를 완화할
   권한이 없습니다.
6. API key, token, cookie, session, 개인정보, repository secret과 host 절대 경로를
   stdout·stderr·log·artifact·Markdown·Issue·PR에 기록하지 않습니다.
7. Prompt·Provider·model·policy·workspace·commit·generation·attempt가 바뀌면 이전
   승인과 결과를 current로 재사용하지 않습니다.
8. stale `ReportDraft`, Finding, Gate, PoC 또는 과거 Markdown을 최신 결과로
   재사용하지 않습니다.
9. Rule Scope 판단은 technical verdict를 바꾸거나 가설을 사전 삭제하지 않습니다.
10. Agent 자동화는 `ReportDraft`에서 끝납니다. 검토·수정·제출·공개는 사람 책임입니다.

## 6. 다음 담당자가 다시 하면 안 되는 작업

- T08 Repository Loader·Profile·정적 adapter·normalization·context retrieval을 별도
  계층으로 중복 구현하지 않습니다.
- T09 Prompt registry·projection·redaction·Provider provenance를 우회하는 직접 SDK
  호출 경로를 만들지 않습니다.
- T10 Verification이나 T11 reproduction·Sandbox 결과 owner를 다른 모듈에서 다시
  구현하지 않습니다.
- T12 CWE·두 Gate·Finding·Reporter·Markdown export를 별도 pipeline으로 복제하지
  않습니다.
- T13 Primitive admission·lineage·Chaining 저장소를 별도 DB나 index로 중복 구현하지
  않습니다.
- T14 production composition을 다른 bootstrap 또는 CLI entrypoint로 복제하지
  않습니다.
- 이미 병합된 workspace lease, `SensitivePathPolicy`, CI Action SHA pin과 checkout
  credential 비보존을 되돌리지 않습니다.
- capability와 onboarding을 수동 `ACTIVE` 값이나 가짜 근거로 우회하지 않습니다.
- T17의 public analysis ID 조회, UTF-8 Windows 출력과 installed-wheel smoke를
  되돌리지 않습니다.
- 제거된 `RepositorySnapshot`·Snapshot Manager를 다시 만들지 않습니다. 현재 기준은
  `git clone → exact commit → CodeWorkspace`입니다.
- 일반 Research Agent를 다시 추가하지 않습니다. 연계 탐색은 Primitive·Chaining입니다.
- 과거 LIMITED/FULL mode와 exact command 사전 계획 중심 Sandbox 계약을 되살리지
  않습니다.
- final TRUE의 validated PoC 의무와 Primitive 등록 시점의 단일 admission 결정을
  약화하지 않습니다.
- CodeQL autobuild나 저장소 코드를 host에서 직접 실행하는 우회 경로를 만들지 않습니다.

공통 계약·migration·production composition·CLI·Prompt registry·운영 문서는 충돌이
쉬운 공용 파일입니다. 항상 최신 main의 새 worktree에서 한 PR씩 수정합니다.

## 7. 남은 작업

이 절의 T15 내용은 읽기 전용 기존 계획과 현재 구현을 대조한 후속 안내입니다. 이번
T17 작업에서는 T15 감사를 실행하거나 수정하지 않았습니다.

### 7.1 T15 최종 보안 감사 — 다음 순차 Gate

- 주 담당: 보안 경계·Runtime 담당
- 공동 검토: 정적분석·컨텍스트, 동적검증·Sandbox, Gate·Reporter 담당
- 최종 검토: PM·Architecture와 독립 보안 검토자
- 확인 범위:
  - Prompt injection이 설정·권한·Provider·Gate 순서를 바꾸지 못하는지
  - 위조 hash·reference, cross-run cache, stale `ActionDecision` 차단
  - key·cookie·token·session·host path의 출력·log·artifact 전 범위 비노출
  - Docker daemon/socket·mount·namespace·network·resource 경계
  - 실패별 same-attempt `AnalysisError`, unauthorized output와 current pointer 불변
  - `docs/security.md`, 독립 검토와 Blocker·High 0
- 먼저 공통 failure oracle과 immutable candidate를 순차 확정합니다. 이후 서로 다른
  파일의 위협군 조사는 병렬 가능하지만, 최종 통합·전체 CI·승인은 한 SHA에서
  순차 수행합니다.

### 7.2 실제 외부 조합 검증

- OpenAI API 및 공식 Codex CLI의 exact client·model·Prompt PVD, 약관, R8 평가,
  사람 승인과 onboarding READY
- Ubuntu·Windows OpenGrep 실제 probe와 승인
- Docker daemon별 build·run·health·cleanup·resource·Sandbox probe
- Python·JavaScript, Dockerfile 유·무 저장소 조합
- CodeQL hard-quota backend와 immutable prebuilt DB 경로
- Fake 없는 clone→Static→LLM→Docker→Gates→Markdown production E2E

Provider·OS·도구 조합은 서로 다른 worktree와 data directory에서 병렬 검증할 수
있습니다. 각 조합 내부의 `PVD → R8 평가 → 사람 승인 → onboarding READY → E2E`와
CodeQL의 `quota 구현 → probe → 승인 → production 선택 → E2E`는 순차입니다.

### 7.3 미지원·후속 개선

- 실제 resume dispatcher와 새 RESUME attempt
- owner process 종료 뒤 public cancel의 외부 process·container cleanup
- 추가 Provider, Python·JavaScript 외 언어와 framework
- HTML·PDF 보고서, UI·dashboard
- 원격 Sandbox·분산 worker
- 자동 외부 제출·공개
- GitHub Actions Node 20 deprecation 경고 해소

resume·cancellation·storage migration은 공용 Runtime·storage 파일을 바꾸므로 한 PR씩
순차 통합합니다. 독립 Provider 조사나 추가 출력 형식처럼 공통 계약을 바꾸지 않는
작업은 병렬 진행할 수 있습니다.

## 8. 다음 작업 시작 절차

```text
git fetch origin
git switch main
git pull --ff-only
git rev-parse HEAD
git status --short
```

1. 이 문서의 기준 SHA 이상이며 작업트리가 깨끗한지 확인합니다.
2. 연결 Issue의 범위·선행 조건·담당자·교차 검토 역할을 확인합니다.
3. 최신 main에서 새 branch 또는 독립 worktree를 만듭니다. T17이나 과거 Task branch를
   새 작업의 base로 재사용하지 않습니다.
4. 설치와 최소 smoke를 먼저 실행합니다.

```text
uv sync --frozen
uv run sastsimi --help
uv run sastsimi doctor --format json
uv run sastsimi --data-dir <fresh-data-dir> db upgrade head --format json
uv run sastsimi --data-dir <fresh-data-dir> db current --format json
```

5. 변경 단계의 Architecture v5, 승인 ADR, contract·integration test와 production
   composition을 읽습니다.
6. 공통 계약·보안 경계 변경은 먼저 실패하는 회귀 test로 문제를 고정합니다.
7. PR에 Issue, 기준 main SHA, 역할 경계, 실행한 명령, 실행하지 못한 외부 시험과
   Blocker·High 검토자를 기록합니다.
8. 공용 계약·migration·composition PR은 병합 순서를 정하고 앞 PR 병합 후 다음 PR을
   최신 main으로 갱신합니다.

## 9. 알려진 제한과 위험

### Blocker·High — production 완료 주장 전에 해결

- T15 최종 통합 보안 감사와 독립 승인이 완료되지 않았습니다.
  - 우회: 연구·검증 환경으로 제한하고 production security sign-off를 주장하지 않습니다.
- Fake 없는 실제 Provider·정적 도구·Docker clone→Markdown 전체 E2E가 없습니다.
  - 우회: Fake demo와 component CI를 production 출시 증거로 사용하지 않습니다.
- exact Provider·model·Prompt의 PVD·R8·사람 승인·onboarding 조합이 외부 환경에서
  완성됐다는 저장소 근거가 없습니다.
  - 우회: 누락 상태를 READY 또는 SUPPORTED로 수동 변경하지 않습니다.
- CodeQL production은 hard-quota와 prebuilt DB 경로 부재로 fail-closed입니다.
  - 우회: CodeQL이 필수이면 BLOCKED로 남깁니다. 강제 승인하지 않습니다.
- production `resume`은 입력 검사만 하고 새 attempt를 dispatch하지 않습니다.
  - 우회: exit 4를 정상 제한으로 처리하고 다른 입력이면 새 `analysis_id`를 사용합니다.
- owner process 종료 뒤 public `cancel`은 외부 자원을 직접 중단·정리하지 않습니다.
  - 우회: CANCELLING을 정리 완료로 해석하지 않고 resource journal을 확인합니다.

### Medium·Low — 후속 목록

- HTML·PDF, UI·dashboard, 자동 외부 제출·공개 미지원
- 추가 Provider·model 및 Python·JavaScript 외 언어 조합 미검증
- 원격 Sandbox·분산 worker 미지원
- GitHub Actions에서 Node 20 기반 Action을 Node 24로 강제 실행한다는 deprecation 경고

## 10. 검증 증거

### PR #184 candidate

- candidate head: `f1a5163e452d9bdfb19109c838da1d0dbc0f41d8`
- `uv run pytest -p no:cacheprovider tests/unit/interfaces/test_report_cli.py tests/contract/test_operator_docs.py -q`
  - 결과: 8 passed
- `uv run ruff check src/sastsimi/interfaces/cli/main.py tests/unit/interfaces/test_report_cli.py`
  - 결과: PASS
- `uv run mypy --strict src/sastsimi/interfaces/cli/main.py`
  - 결과: PASS
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate-architecture-docs.ps1`
  - 결과: `Failures: 0`
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/audit-doc-inventory.ps1 -RepositoryRoot . -CheckLinks`
  - 결과: `Missing local Markdown links: 0`
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/wheel-smoke.ps1 -WorkRoot <새-검증-경로>`
  - 결과: `Installed wheel smoke passed: sastsimi-0.1.0-py3-none-any.whl`
- PR CI는 Ubuntu·Windows quality, 모든 test shard, 실제 Docker E2E, 양쪽 wheel smoke와
  문서 CI가 모두 성공했습니다.

### 병합 main `d0acc729447eaf87368a421a65a9cc2bfe6eb5f0`

- `uv sync --frozen`: 새 `.venv` 생성과 설치 PASS
- `uv run sastsimi --help`: public command 목록 PASS
- `uv run sastsimi analyze --help`: `--repo`, `--commit`, `--profile` PASS
- `uv run sastsimi doctor --format json`: exit 0, `OK`
- 새 data directory의 `db upgrade head`와 `db current`: PASS,
  `0008_cancellation_observations`
- `demo analyze --scenario TRUE`: exit 0, `COMPLETE`, TRUE 1
- `demo results`: exit 0
- `reports fake-analysis --format json`: public 문자열 ID 조회 PASS, report 1
- `report show fake-recordid-3127`: 한국어 Markdown UTF-8 출력 PASS
- `report export fake-recordid-3127 --format markdown`: PASS,
  `reports/fake-analysis/fake-recordid-3127.md`
- 임시 DB·보고서는 검증 뒤 삭제했으며 Git에 포함하지 않았습니다.

### 실행하지 않은 시험

- Fake 없는 실제 Provider·OpenGrep·Docker clone→Markdown 전체 production E2E:
  exact 승인 Provider·profile·onboarding 근거가 없어 미실행
- OpenAI·Codex live PVD와 R8 전체 평가: 외부 인증·사람 승인 근거가 없어 미실행
- production CodeQL: hard-quota backend와 prebuilt DB 경로가 없어 fail-closed
- production resume dispatch: 기능 미지원
- T15 최종 보안 감사: 이번 요청 범위 밖이므로 실행·수정하지 않음
- HTML·PDF 및 외부 제출·공개: 미지원이며 이번 범위가 아님

위 미실행 항목을 PASS나 완료로 바꾸면 안 됩니다.

## 후속 구현 요청: 실제 분석 준비 자동화 및 사용자 화면 추가

현재 T17까지 기본 설치·CLI·보고서 출력 구조는 구현되었습니다. 다만 실제 저장소를
실제 LLM·OpenGrep·Docker와 연결해 분석하려면 T16의 운영 설정과 전체 실행 검증이
아직 필요합니다.

다음 순서로 진행해주세요.

### 1. 실제 분석 설정 자동화

- `sastsimi setup` 형태의 대화형 설정 기능을 구현합니다.
- Git, Python, OpenGrep, CodeQL, Docker, Codex CLI 설치 여부와 버전을 자동 탐지합니다.
- 사용자는 다음과 같은 중요한 선택만 직접 결정합니다.
  - API Key 방식 또는 공식 회원제 로그인 방식
  - 사용할 Provider와 모델
  - 비용·토큰·시간 제한
  - Docker 네트워크 허용 범위
  - 분석할 저장소와 적용 정책
- 선택 결과를 바탕으로 실행 가능한 TOML 프로필을 자동 생성합니다.
- API Key, 로그인 세션, 토큰 등의 비밀정보는 프로필 파일에 직접 저장하지 않습니다.
- 지원하지 않거나 검증되지 않은 Provider·모델·도구 조합은 자동 활성화하지 않습니다.

### 2. T16 실제 연동 및 전체 실행 검증

- 실제 LLM Provider, OpenGrep, Docker를 연결합니다.
- CodeQL은 안전한 실행량 제한이 준비된 경우에만 활성화합니다.
- 실제 Git 저장소 입력부터 Markdown 보고서 생성까지 Fake Adapter 없이 검증합니다.
- 인증 실패, 도구 미설치, Docker 빌드 실패를 취약점 FALSE로 처리하지 않습니다.
- 실제로 검증한 Provider·모델·도구 조합만 운영 가능 상태로 표시합니다.

### 3. CLI 진행 화면

- 분석 중 현재 단계를 사람이 알 수 있도록 진행 표시를 추가합니다.
- 저장소 준비, 정적 분석, 가설 생성, 검증, 동적 재현, Gate, 보고서 생성 단계를 표시합니다.
- 실제 완료된 작업과 Runtime 상태를 기준으로 표시하며 가짜 진행률은 사용하지 않습니다.
- 정확한 비율을 계산할 수 없다면 퍼센트 대신 현재 단계와 완료 작업 수를 표시합니다.
- `--format json` 사용 시 애니메이션을 끄고 기존 구조화 출력만 유지합니다.
- 비밀정보, 전체 프롬프트, 민감한 코드, 로컬 절대 경로는 출력하지 않습니다.

### 4. 웹 대시보드

- 초기 버전은 로컬 전용 읽기 화면으로 구현합니다.
- 분석 목록, 현재 단계, 성공·실패·차단 상태, 가설 수, Finding, 오류 요약, Markdown
  보고서 링크를 제공합니다.
- 대시보드는 기존 Runtime과 저장 데이터를 조회만 하며 자체적으로 판정하거나 상태를
  변경하지 않습니다.
- 외부 네트워크에는 기본 공개하지 않습니다.
- 취소·재시도·공개 승인 같은 쓰기 기능은 별도 권한 설계 전까지 추가하지 않습니다.

### 5. 구현 경계

- Agent 이름과 역할은 특정 Provider나 모델에 종속하지 않습니다.
- Provider와 모델은 기존 `provider_profile_ref + model` 계약으로 선택합니다.
- 회원제 연동은 브라우저 쿠키 복사 방식이 아니라 공식 CLI·SDK 로그인만 허용합니다.
- CLI와 웹 화면은 기존 공통 계약과 판정 규칙을 변경하지 않는 표현 계층으로 둡니다.
- TRUE·validated PoC·정확한 reference·Sandbox 경계 규칙은 그대로 유지합니다.

### 6. 권장 진행 순서

- T16 설정 자동화 및 실제 연동
- Fake 없는 실제 저장소 전체 E2E
- CLI 진행 표시
- 로컬 읽기 전용 웹 대시보드
- T15 최종 보안 감사
- 최종 E2E 재검증

각 단계는 별도 Issue와 PR로 진행하고, Blocker/High 문제만 즉시 수정합니다. 완료되지
않은 기능이나 검증하지 않은 Provider 조합을 사용할 수 있다고 문서화하지 마세요.
