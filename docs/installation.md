# SASTSIMI 설치와 실행 환경 준비

이 문서는 SASTSIMI를 실행할 컴퓨터에 필요한 프로그램을 준비하고, 실제 분석에 사용할 수 있는지 확인하는 순서를 설명합니다.

## 1. 먼저 구분할 세 가지

- **설치됨**: 실행 파일이 컴퓨터에 있습니다.
- **probe 통과**: SASTSIMI가 제한된 시험을 실제로 실행했습니다.
- **ACTIVE**: probe 결과를 사람이 정확한 hash와 함께 승인했습니다.

설치나 `--version` 성공만으로 운영 `ACTIVE`가 되지는 않습니다. 확인하지 못한 도구는 사용하지 않으며, 설정 파일에 `ACTIVE`를 직접 적어 우회하지 않습니다.

현재 release가 어떤 명령을 제공하는지는 도움말로 확인합니다.

```text
uv run sastsimi --help
uv run sastsimi analyze --help
```

- `analyze`에 `--repo`, `--commit`, `--profile`이 없으면 그 설치본은 Fake 전용입니다.
- `capability` 또는 `onboarding`이 도움말에 없으면 해당 준비 기능이 아직 포함되지 않은 설치본입니다.
- 이 문서의 production 명령은 관련 T14·T16 구현이 병합되고 출시 검증을 마친 설치본에서만 사용합니다.

## 2. 기본 실행 환경

필수 Python 범위는 `>=3.12,<3.13`입니다. 운영체제와 CPU 조합은 이름만으로 지원을 가정하지 않고, 실제 실행 host에서 capability probe와 onboarding을 통과한 조합만 사용합니다.

Docker 동적 재현은 Linux container와 승인된 Docker 경계가 추가로 필요합니다. 운영체제와 Python 검사가 성공해도 Docker가 자동 허용되지는 않습니다.

## 3. Python과 SASTSIMI

1. [Python 공식 다운로드](https://www.python.org/downloads/)에서 Python 3.12를 설치합니다.
2. [uv 공식 설치 안내](https://docs.astral.sh/uv/getting-started/installation/)에 따라 uv를 설치합니다.
3. 저장소 루트에서 lock에 고정된 dependency를 설치합니다.

```text
uv sync --frozen
```

개발·검증 도구까지 설치하려면 다음을 사용합니다.

```text
uv sync --frozen --all-groups
```

이후 이 문서와 운영 안내의 SASTSIMI 명령은 모두 저장소 루트에서 `uv run sastsimi`로 실행합니다. `uv run`은 방금 lock으로 설치한 실행 환경을 선택하므로 별도 가상 환경 활성화에 의존하지 않습니다.

출시 wheel을 받은 사용자는 깨끗한 가상 환경에 그 wheel을 설치합니다.

```text
python -m pip install <검증된-sastsimi-wheel-경로>
```

기본 상태 저장소를 준비합니다.

```text
uv run sastsimi doctor --format json
uv run sastsimi --data-dir <data-dir> db upgrade head
uv run sastsimi --data-dir <data-dir> db current --format json
```

`doctor`는 OS·CPU·Python만 읽어서 확인합니다. Git, 정적 분석 도구, Docker 또는 LLM을 승인하지 않습니다.

## 4. 외부 프로그램

### Git

[Git 공식 설치 안내](https://git-scm.com/downloads)를 따라 설치한 뒤 확인합니다.

```text
git --version
```

SASTSIMI는 분석마다 별도 로컬 폴더에 clone하고 사용자가 입력한 정확한 commit을 checkout합니다. branch, tag, 짧은 SHA나 현재 작업 폴더 상태를 분석 기준으로 추정하지 않습니다.

### Python AST

Python AST parser는 CPython 3.12 안에 포함되어 있습니다. 별도 parser를 설치하지 않으며, 현재 실행 중인 Python과 실제 parse가 모두 확인되어야 합니다.

### OpenGrep

[OpenGrep 공식 설치 안내](https://github.com/OpenGrep/OpenGrep/blob/main/README.md)를 따라 설치하고, 안내에 나온 OpenGrep CLI 실행 파일이 `PATH`에서 동작하는지 `--version` 옵션으로 확인합니다.

운영 활성화에는 version 확인뿐 아니라 Python·JavaScript 시험 파일에 승인된 규칙을 실제 실행한 probe가 필요합니다.

### CodeQL

[GitHub CodeQL CLI 설치 안내](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli)를 따라 CodeQL bundle을 설치하고 `PATH`에서 확인합니다.

```text
codeql version --format=terse
codeql resolve languages
codeql resolve packs
```

현재 capability 구현은 CodeQL version을 읽어도 실행량 제한을 강제하는 근거가 없어 `activation_supported=false`로 남깁니다. CodeQL을 production에서 사용하려면 quota control을 포함한 별도 probe와 사람 승인이 먼저 구현·검증되어야 합니다. 그 전에는 다른 활성 정적 도구만 선택하거나 분석을 `BLOCKED`로 남깁니다.

### Docker

[Docker Engine 공식 설치 안내](https://docs.docker.com/engine/install/) 또는 승인된 Windows Docker 환경 설치 안내를 따릅니다.

```text
docker version
docker info
```

Docker probe는 CLI와 daemon 연결뿐 아니라 실제 image build, container 실행, health check, cleanup, CPU·memory·PID·disk 제한과 Sandbox 외부 경계를 확인합니다. host mount, Docker socket 노출, host namespace, secret, 다른 workspace와 허용되지 않은 network 접근을 완화해 probe를 통과시키면 안 됩니다.

## 5. capability 확인과 승인

다음 명령은 설치본의 도움말에 `capability`가 있을 때만 사용할 수 있습니다. `--data-dir`과 선택적인 `--host-id`는 `capability` 앞에 둡니다.

```text
uv run sastsimi --data-dir <data-dir> capability probe GIT --format json
uv run sastsimi --data-dir <data-dir> capability probe PYTHON_AST --format json
uv run sastsimi --data-dir <data-dir> capability probe OPENGREP --format json
uv run sastsimi --data-dir <data-dir> capability probe DOCKER --docker-host <승인된-daemon-주소> --format json
uv run sastsimi --data-dir <data-dir> capability list --format json
```

probe 출력이 `status=PASSED`, `activation_supported=true`이고 `approval_target_hash`가 있을 때만 사람이 같은 값을 확인해 승인합니다.

```text
uv run sastsimi --data-dir <data-dir> capability approve <probe_id> --target-hash <approval_target_hash> --format json
```

Docker 승인에는 probe와 같은 `--docker-host`를 다시 지정합니다. probe 실패, hash 불일치 또는 `activation_supported=false`를 수동 파일 편집으로 바꾸지 않습니다.

OpenAI API의 `capability probe OPENAI_API`는 인증과 구조화 출력의 작은 연결 시험입니다. 현재 구현에서는 성공해도 Provider 전체 검증을 대신하지 않으며 `activation_supported=false`입니다. Provider는 [Provider 인증과 운영 활성화](./provider-setup.md)의 별도 onboarding을 완료해야 합니다.

## 6. 다음 순서

1. [`config/profiles/production.example.toml`](../config/profiles/production.example.toml)을 복사해 실행 환경에 맞는 profile을 작성합니다.
2. [Provider 인증과 운영 활성화](./provider-setup.md)에 따라 Provider·Prompt·정책 근거를 준비합니다.
3. [저장소 분석 실행](./usage.md)에 따라 정확한 저장소와 commit으로 시작합니다.
4. 막히면 [오류와 안전한 대응](./troubleshooting.md)을 확인합니다.
