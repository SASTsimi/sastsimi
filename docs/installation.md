# 설치와 실행 환경 준비

이 문서는 새로운 Windows 또는 Linux/WSL 컴퓨터에서 SASTSIMI를 설치하는 순서를 설명합니다. 다른 컴퓨터의 절대 경로나 설정 파일을 복사하지 않습니다.

## 1. 필수 프로그램

- 64-bit CPython `>=3.12,<3.13`
- Git
- OpenGrep CLI
- Docker Desktop 또는 Docker Engine
- Full profile: 호환 query pack이 포함된 공식 CodeQL platform bundle
- 회원 로그인 사용 시: 공식 Codex CLI

각 프로그램은 현재 컴퓨터의 `PATH`에서 실행 가능해야 합니다.

Windows용 OpenGrep 공식 release 파일 이름이 `opengrep_windows_x86.exe`인
경우에는 이름을 바꾸지 않아도 됩니다. 해당 파일이 있는 폴더를 `PATH`에 추가하면
`sastsimi setup`이 `opengrep`과 이 공식 파일 이름을 모두 확인합니다.

```text
python --version
git --version
opengrep --version
codeql version --format=terse
codeql resolve packs --format=json
docker version
codex --version
```

Lightweight profile은 CodeQL을 제외하고 Python AST와 OpenGrep을 사용합니다. Full profile은 Python AST·OpenGrep·CodeQL을 모두 사용하며, 하나라도 없으면 분석을 시작하지 않습니다.

CodeQL은 GitHub CodeQL Action release의 현재 운영체제용 bundle을 설치합니다.
standalone CLI만 설치하면 `codeql version`은 성공해도 분석 query가 없으므로 사용할
수 없습니다. `codeql resolve packs --format=json` 결과에 `codeql/*-queries` query
pack이 있어야 `sastsimi setup`의 Full profile 검사를 통과합니다.

## 2. 설치

가상환경 사용을 권장합니다.

### Windows PowerShell

```powershell
git clone https://github.com/SASTsimi/sastsimi.git
cd sastsimi
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
sastsimi --help
```

### Linux 또는 WSL

```bash
git clone https://github.com/SASTsimi/sastsimi.git
cd sastsimi
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
sastsimi --help
```

개발자는 `uv sync --frozen --all-groups`를 사용할 수 있습니다. 설치된 일반 사용자는 `uv run`, `UV_PROJECT_ENVIRONMENT`, `--data-dir`, `--profile`을 반복 입력하지 않습니다.

## 3. LLM 인증

API key 또는 공식 회원 로그인 중 하나를 선택합니다.

### OpenAI API

환경변수에만 key를 둡니다.

```powershell
$env:OPENAI_API_KEY = "<key>"
```

```bash
export OPENAI_API_KEY='<key>'
```

### Codex 회원 로그인

```text
codex login
codex login status
```

브라우저 cookie나 다른 사용자의 인증 파일을 복사하지 않습니다.

## 4. 한 번만 설정

대화형 설정을 실행합니다.

```text
sastsimi setup
```

설정 중 다음을 선택합니다.

- 기본 데이터 폴더
- API key 또는 공식 회원 로그인
- Provider와 model
- Full 또는 Lightweight profile
- 비용·token·시간 제한
- Docker build network 사용 여부

자동화 환경에서는 값을 명시합니다.

```powershell
sastsimi setup --non-interactive --auth subscription --provider codex --model gpt-6-sol --profile full --docker-network none
```

새 Codex `setup`은 모델을 생략해도 `gpt-6-sol`을 기본으로 제안하지만, 기존 설정을 자동 변경하지는 않습니다. 실행 전 본인 계정에서 모델 사용 가능 여부를 확인하세요. Codex CLI의 호출별 토큰·비용은 현재 측정되지 않아 설정한 토큰·비용 상한이 실제 사용량을 제한하지 못합니다. [Provider 설정](provider-setup.md#codex-회원-로그인)에 제한을 설명했습니다.

API 방식은 다음과 같습니다.

```text
sastsimi setup --non-interactive --auth api-key --provider openai --model <model> --profile full --docker-network none
```

설정 파일은 운영체제의 사용자 설정 폴더에, 실행 데이터는 사용자 데이터 폴더에 생성됩니다. 파일에는 환경변수 이름이나 공식 로그인 사용 여부만 저장하며 key·token·cookie를 저장하지 않습니다.

`READY`는 현재 컴퓨터에서 필요한 실행 파일과 인증 상태를 확인했다는 뜻입니다. 실제 model 접근, 저장소 의존성 설치와 Docker build는 첫 분석에서 추가로 확인될 수 있습니다.

## 5. 새 환경 확인

```text
sastsimi --help
sastsimi setup --help
sastsimi analyze --help
sastsimi dashboard --help
```

Full profile에서 CodeQL bundle·query pack이 없거나, 선택한 인증을 확인하지 못하면 setup은 누락 항목을 표시하고 `BLOCKED`로 끝납니다. 설정 파일을 손으로 고쳐 우회하지 말고 프로그램이나 인증을 준비한 뒤 setup을 다시 실행합니다.

설치 뒤의 실제 사용은 [실행 안내](usage.md), 인증 문제는 [Provider 설정](provider-setup.md), 실패 원인은 [문제 해결](troubleshooting.md)을 확인하세요.
