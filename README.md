# SASTSIMI

SASTSIMI는 저장소의 AST·OpenGrep·CodeQL 결과를 LLM Agent가 검토하고, Docker에서 PoC를 재현한 뒤 사람이 읽을 수 있는 한국어 Markdown 보고서를 만드는 로컬 보안 분석 도구입니다.

정적 분석 결과만으로 취약점을 확정하지 않습니다. Hypothesis Agent가 가설을 만들고, Pro·Con Agent와 Verification Agent가 근거를 검토합니다. `TRUE`는 Docker에서 성공한 validated PoC가 있을 때만 Gate·Finding·Reporter 단계로 이동합니다. 여러 취약 조건을 연결하는 Chaining 결과는 새 가설로 등록해 같은 검증을 다시 거칩니다.

## 현재 구현 상태

- 구현됨: exact commit clone, Python AST, OpenGrep, CodeQL, LLM Agent 파이프라인, Docker PoC, 두 Gate, Chaining, `F-001.md` 보고서, 실패 단계 재개, CLI 진행 표시, 로컬 읽기 전용 대시보드
- LLM 연결: OpenAI API 또는 공식 Codex CLI 회원 로그인
- 기본 실행 방식: 작은 단일 프로세스 `SimpleRuntime`
- 지원 기준: Python 3.12, Git, OpenGrep, Docker. `full` 프로필은 CodeQL도 필수
- 제한: Python 저장소가 첫 통합 검증 대상입니다. 자동 외부 제출·공개, HTML/PDF 보고서, 대시보드 쓰기 기능은 지원하지 않습니다.
- 주의: 실제 Provider·도구·Docker 조합은 설치한 컴퓨터에서 `sastsimi setup`으로 다시 확인해야 합니다. 인증·도구·환경 오류는 취약점 `FALSE`로 바꾸지 않습니다.

현재 통합 상태: `LIVE_E2E_VERIFICATION_PENDING`. 구현 경로는 연결됐지만 깨끗한
설치 환경에서 실제 Provider·OpenGrep·CodeQL·Docker로 두 대상 저장소를 완주한
최종 증거는 이 변경의 마지막 검증에서 확정합니다.

## 가장 빠른 설치

Python 3.12 가상환경에서 설치합니다.

```powershell
git clone https://github.com/SASTsimi/sastsimi.git
cd sastsimi
python -m pip install .
sastsimi --help
```

소스 개발자는 `uv sync --frozen` 후 `uv run sastsimi ...`를 사용할 수 있지만, 일반 사용자는 설치 후 `sastsimi`만 입력하면 됩니다.

외부 프로그램을 준비한 다음 한 번만 설정합니다.

```text
git --version
opengrep --version
codeql version --format=terse
docker version
codex --version
sastsimi setup
```

`setup`은 운영체제의 사용자 설정·데이터 폴더를 사용합니다. 실행 파일의 위치와 버전을 현재 컴퓨터에서 탐지하므로 저장소를 만든 사람의 절대 경로를 재사용하지 않습니다. API key와 로그인 token은 설정 파일에 저장하지 않습니다.

## LLM 인증

OpenAI API를 선택하면 key는 환경변수로만 전달합니다.

```powershell
$env:OPENAI_API_KEY = "<현재 터미널에만 설정>"
sastsimi setup --auth api-key --provider openai --model <사용할-model>
```

ChatGPT 회원 로그인을 선택하면 공식 Codex CLI만 사용합니다.

```text
codex login
codex login status
sastsimi setup --auth subscription --provider codex --model <사용할-model>
```

브라우저 cookie나 session 파일을 복사하는 방식은 사용하지 않습니다. 모델은 Agent 역할에 고정되지 않으며 설정의 Provider와 `model` 값으로 선택합니다.

## 사용법

정확한 40자리 또는 64자리 commit SHA를 사용합니다.

```text
sastsimi analyze https://github.com/adeyosemanputra/pygoat.git --commit <exact-SHA>
sastsimi status A-001
sastsimi resume A-001
sastsimi result A-001
sastsimi dashboard
```

분석 중에는 저장된 체크포인트를 기준으로 진행 바가 표시됩니다. 터미널이 애니메이션을 지원하지 않으면 단계가 바뀔 때만 한 줄을 출력합니다. `--format json`은 애니메이션 없이 구조화된 결과만 출력합니다.

대시보드는 기본적으로 `http://127.0.0.1:8765`에서 열립니다. 분석별 주소는 `http://127.0.0.1:8765/analyses/A-001` 형식입니다. 대시보드는 진행률, 가설, Agent 활동 요약, Primitive·Chaining 관계, Finding과 보고서 링크를 읽기만 하며 판정을 변경하지 않습니다.

Finding이 생성되면 다음 명령을 사용합니다.

```text
sastsimi poc F-001
sastsimi report F-001
sastsimi report F-001 --export markdown
```

보고서는 기본 데이터 폴더의 `reports/<exact-analysis-id>/F-001.md`에 저장됩니다. 내용은 한국어 `Summary`, `Details`, `PoC`, `Impact` 구역으로 구성되며 검증된 PoC 코드·명령·결과를 포함합니다.

## 실제 분석 흐름

```text
저장소 URL/로컬 경로 + exact commit
→ clone과 tracked file 확인
→ RepositoryProfile
→ Python AST + OpenGrep + CodeQL
→ Hypothesis Agent
→ Pro Agent + Con Agent
→ Verification Agent
→ Docker 환경 + PoC candidate 실행
→ validated PoC + 최종 TRUE/FALSE/HOLD
→ CWE Labeling
→ Technical Gate
→ Rule Scope Gate
→ Primitive Admission + Chaining
→ Finding
→ Reporter
→ F-001.md
```

공식 Rule Scope 정책이 없거나 대상 범위 밖이어도 기술 검증 결과는 내부 보고서로 남길 수 있습니다. 이 경우 보고서에는 외부 제출·공개 제한이 명시됩니다.

## 실패 후 재개

성공한 clone·정적 분석·가설·Pro·Con·Docker image는 exact 입력이 같으면 재사용합니다. 실패한 분석은 앞 단계를 다시 실행하지 않고 재개합니다.

```text
sastsimi status A-001
sastsimi resume A-001
```

인증 실패, 도구 미설치, timeout, Docker build 실패와 LLM 형식 오류는 `FALSE`가 아닙니다. `BLOCKED` 또는 verdict 없는 `FAILED`로 저장됩니다.

## 문서

- [설치와 외부 프로그램](docs/installation.md)
- [실행과 결과 확인](docs/usage.md)
- [Provider 인증](docs/provider-setup.md)
- [실패 해결](docs/troubleshooting.md)
- [구현 인계서](docs/handoff/T17_IMPLEMENTATION_HANDOFF.md)
- [Architecture v5 설계](docs/architecture-v5/README.md)

SASTSIMI는 허가받은 저장소와 환경에서만 사용하세요. 보고서는 자동 공개하지 않으며 사람이 근거와 PoC를 검토한 뒤 외부 제출 여부를 결정합니다.
