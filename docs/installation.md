# 설치와 실행 환경 준비

이 문서는 새로운 Windows 또는 Linux/WSL 컴퓨터에서 SASTSIMI를 설치하는 순서를 설명합니다. 다른 컴퓨터의 절대 경로나 설정 파일을 복사하지 않습니다.

## 1. 필수 프로그램

- 64-bit CPython `>=3.12,<3.13`
- Git
- OpenGrep CLI
- Docker Desktop 또는 Docker Engine
- Full profile: 호환 query pack이 포함된 공식 CodeQL platform bundle
- 선택형 파일·규칙 재검사를 켠 경우에만: Semgrep CE (`python -m pip install semgrep`)
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

개발자는 `uv sync --frozen --all-groups`로 의존성을 준비한 뒤 `uv run sastsimi ...`로 소스 CLI를 실행할 수 있습니다. 설치된 일반 사용자는 `uv run`, `UV_PROJECT_ENVIRONMENT`, `--data-dir`, `--profile`을 반복 입력하지 않습니다.

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

새 Codex `setup`은 모델을 생략해도 `gpt-6-sol`을 기본으로 제안하지만, 기존 설정을 자동 변경하지는 않습니다. 실행 전 본인 계정에서 모델 사용 가능 여부를 확인하세요. Codex CLI 완료 이벤트의 입력·출력 토큰은 기록하며, `--max-tokens`에 양의 정수를 지정하면 누적 사용량이 한도에 도달하거나 이전 시도의 사용량을 확인할 수 없을 때 후속 요청을 차단합니다. 요청 하나가 한도를 넘을 수 있고, CLI 금액은 제공되지 않아 비용 상한으로 실제 청구액을 강제할 수 없습니다. [Provider 설정](provider-setup.md#codex-회원-로그인)에 제한을 설명했습니다.

API 방식은 다음과 같습니다.

```text
sastsimi setup --non-interactive --auth api-key --provider openai --model <model> --profile full --docker-network none
```

설정 파일은 운영체제의 사용자 설정 폴더에, 실행 데이터는 사용자 데이터 폴더에 생성됩니다. 파일에는 환경변수 이름이나 공식 로그인 사용 여부만 저장하며 key·token·cookie를 저장하지 않습니다.

기본 `AUTO` 모드는 `python:3.12-slim` 태그를 확인하고 로컬에 없을 때만 받은 뒤 그 실행의 local digest와 안전한 Python binary wheel을 자동으로 준비합니다. 고정 commit의 제품 manifest와 PEP 621 build-system 요구사항은 권위 있는 입력이며 제거·대체하지 않습니다. manifest와 정규화한 이름이 겹치지 않는 Agent 추가 `pip:` 항목만 정확한 `No matching distribution` 진단과 다른 요구사항이 남는 경우에 receipt와 함께 제외할 수 있고, 해당 제외 판단과 receipt 참조는 recipe의 `dependency_resolution_omitted_agent_requirements`와 `dependency_resolution_omission_attempt_refs`에 남습니다. 반대로 고정 manifest·build 요구사항의 no-match는 제외하거나 같은 입력으로 자동 재시도하지 않으며, 연결된 receipt가 검증되면 PoC·Finding 없는 `INCONCLUSIVE`로 종료합니다. timeout·지원하지 않는 manifest는 `BLOCKED`로 남습니다. resolver에는 대상 저장소를 마운트하지 않고, 최종 PoC 빌드·실행은 `docker_network = "NONE"`으로 유지합니다. 외부 통신을 전혀 허용하지 않으려면 `setup` 출력의 실행 프로필 `profile.toml`에서 `OFFLINE_ONLY`를 선택하고 승인한 wheel TAR의 `poc_wheel_archive_path`와 소문자 SHA-256인 `poc_wheel_archive_sha256`을 함께 지정하세요. 이 세 필드는 `setup` 옵션이 아니며 `setup`을 다시 실행하면 다시 지정해야 합니다. 평탄한 TAR 생성과 Docker 환경 확인 방법은 [Docker 또는 PoC 실패](troubleshooting.md#docker-또는-poc-실패)에 있습니다.

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
