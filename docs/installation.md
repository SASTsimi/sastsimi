# SASTSIMI 설치와 실행 환경 준비

이 문서는 SASTSIMI를 실행할 컴퓨터에 필요한 프로그램을 설치하고, 운영 분석을 시작해도 되는 상태인지 확인하는 방법을 설명합니다.

## 1. 먼저 알아둘 점

- 이 저장소의 Python 요구 버전은 CPython `3.12`입니다. `3.11`이나 `3.13`은 현재 지원 범위가 아닙니다.
- `sastsimi doctor`는 운영체제·CPU·Python 같은 기본 조건만 확인합니다. Git, CodeQL, OpenGrep, Docker 또는 LLM 연결을 `ACTIVE`로 승인하지 않습니다.
- 프로그램이 설치되어 있고 `--version` 명령이 성공해도 운영 capability가 자동으로 승인되지는 않습니다. 실제 probe 결과와 사람 승인이 연결된 정확한 profile만 운영 실행에 사용할 수 있습니다.
- 검증되지 않은 capability는 사용할 수 없는 상태로 취급합니다. 사용자가 설정 파일에서 임의로 `ACTIVE`라고 적어 우회할 수 없습니다.

## 2. 지원하는 기본 실행 환경

현재 `doctor`가 확인하는 환경은 다음과 같습니다.

- Windows 11 또는 Windows Server 2022, x86-64, 64-bit CPython 3.12
- Ubuntu 24.04, x86-64, 64-bit CPython 3.12

Docker를 이용한 실제 동적 재현은 Linux container 경계와 해당 host의 승인된 Docker capability가 추가로 필요합니다. 위 운영체제 조건을 통과했다는 이유만으로 Docker 실행이 허용되지는 않습니다.

## 3. 기본 프로그램 설치

### Python과 uv

1. [Python 공식 다운로드](https://www.python.org/downloads/)에서 Python 3.12를 설치합니다.
2. [uv 공식 설치 안내](https://docs.astral.sh/uv/getting-started/installation/)에 따라 uv를 설치합니다.
3. 저장소 루트에서 고정된 dependency를 설치합니다.

```text
uv sync --frozen
```

개발·검증 도구까지 필요하면 다음을 사용합니다.

```text
uv sync --frozen --all-groups
```

출시 wheel을 받은 운영 사용자는 별도의 새 가상 환경에 해당 wheel을 설치합니다. 저장소 checkout이나 `PYTHONPATH`에 의존하는 설치 결과는 출시 근거로 사용하지 않습니다.

```text
python -m pip install <검증된-sastsimi-wheel-경로>
```

### Git

[Git 공식 다운로드](https://git-scm.com/downloads/)에서 설치한 뒤 확인합니다.

```text
git --version
```

SASTSIMI는 사용자가 지정한 정확한 commit을 실행별 로컬 workspace로 준비합니다. 분석 대상 저장소의 hook이나 임의 지시문을 실행 설정으로 신뢰하지 않습니다.

### CodeQL

[GitHub의 CodeQL CLI 설치 안내](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli)에 따라 플랫폼별 CodeQL bundle을 내려받아 압축을 풀고 `codeql` 실행 파일을 `PATH`에 둡니다. CodeQL 사용 조건도 함께 확인해야 합니다.

```text
codeql version
codeql resolve languages
codeql resolve packs
```

위 명령은 설치 사전 확인일 뿐입니다. SASTSIMI 운영 분석은 실제 parse/analyze probe와 실행 파일 version·digest가 승인 profile에 연결된 경우에만 CodeQL을 선택합니다.

### OpenGrep

[OpenGrep 공식 저장소의 설치 안내](https://github.com/OpenGrep/OpenGrep/blob/main/INSTALL.md)에 따라 설치합니다. 원격 설치 스크립트를 바로 실행하기보다 내용을 확인하거나 공식 release artifact를 검증해 설치하는 방식을 권장합니다.

```text
<profile의 OpenGrep 실행 파일> --version
```

설치 확인만으로 `ACTIVE`가 되지는 않습니다. 선택한 규칙과 실제 실행 기록을 구분해 저장할 수 있는 승인 profile이 필요합니다.

### Docker

[Docker Engine 공식 설치 안내](https://docs.docker.com/engine/install/)에 따라 설치합니다.

```text
docker version
docker info
```

SASTSIMI의 Docker capability 검사는 단순 접속 성공보다 엄격합니다. host mount·Docker socket·host namespace·secret·다른 workspace·허용되지 않은 network 접근 차단과 resource 경계를 실제로 증명하지 못하면 동적 재현은 `BLOCKED`입니다. 이를 취약점 `FALSE`로 바꾸지 않습니다.

## 4. SASTSIMI 기본 확인

저장소 설치 환경에서는 다음과 같이 실행합니다.

```text
uv run python -m sastsimi doctor
uv run python -m sastsimi db upgrade head
uv run python -m sastsimi db current
```

wheel 설치 환경에서는 `uv run` 없이 실행합니다.

```text
sastsimi doctor
sastsimi db upgrade head
sastsimi db current
```

`doctor` 성공은 전체 운영 준비 완료가 아닙니다. 다음 문서를 이어서 확인합니다.

1. [Provider 인증과 활성화](./provider-setup.md)
2. [저장소 분석 실행](./usage.md)
3. [오류와 안전한 대응](./troubleshooting.md)
