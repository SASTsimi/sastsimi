# 외부 도구 준비

SASTSIMI 기본 CLI는 외부 도구 없이 설치할 수 있습니다. 실제 저장소 분석에서
필요한 기능만 설치하고, 실행 전에 `capability probe`와 사람의 승인을 거칩니다.
probe 성공은 설치 상태를 확인했다는 뜻이며 분석에 자동 연결됐다는 뜻은 아닙니다.

## 공통 확인 순서

```powershell
sastsimi --data-dir .sastsimi-local capability probe GIT --format json
sastsimi --data-dir .sastsimi-local capability list --format json
sastsimi --data-dir .sastsimi-local capability approve <probe_id> --target-hash <approval_target_hash> --format json
```

`probe_id`와 `approval_target_hash`는 probe JSON 응답에서 복사합니다. 실행 파일,
버전 또는 안전 경계가 달라지면 이전 승인을 재사용하지 않습니다.

## Git

[Git 공식 설치 안내](https://git-scm.com/downloads)로 설치한 뒤 다음을 확인합니다.

```powershell
git --version
sastsimi --data-dir .sastsimi-local capability probe GIT --format json
```

Git은 원격 저장소 clone과 정확한 commit checkout에 필요합니다. 인증정보가 포함된
URL을 명령·설정·로그에 넣지 않습니다.

## OpenGrep

[OpenGrep 공식 저장소](https://github.com/OpenGrep/OpenGrep)의 설치 안내를 따릅니다.
설치 안내에 나온 실행 파일이 `PATH`에서 동작해야 합니다.

```powershell
sastsimi --data-dir .sastsimi-local capability probe OPENGREP --format json
```

현재 probe는 실행 파일과 버전을 확인합니다. 실제 분석 활성화에는 언어에 맞는
exact tool profile과 별도 승인이 필요합니다.

## CodeQL CLI

[GitHub CodeQL CLI 안내](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli)를
따라 CLI와 query pack을 준비합니다.

```powershell
codeql version --format=json
sastsimi --data-dir .sastsimi-local capability probe CODEQL --format json
```

CodeQL은 query pack과 database의 exact digest, 출력 용량 강제 경계까지 검증된
profile만 production에서 활성화합니다. 단순히 `codeql` 명령이 실행된다는 이유로
production 준비 완료로 보지 않습니다.

## Docker

[Docker Engine 설치](https://docs.docker.com/engine/install/) 또는 지원되는 환경의
[Docker Desktop 설치](https://docs.docker.com/desktop/) 안내를 따릅니다.

```powershell
docker version
sastsimi --data-dir .sastsimi-local capability probe DOCKER --format json
```

Docker socket은 사실상 host 관리자 권한으로 이어질 수 있습니다. SASTSIMI는
승인한 endpoint, 전용 daemon 경계, image digest와 workspace만 사용해야 합니다.
임의의 `DOCKER_HOST`, host mount, Docker socket mount, secret 전달과 허용되지 않은
network egress는 지원하지 않습니다.

Docker Desktop은 Windows Server에서 지원되지 않습니다. Windows Server 2022의
기본 CLI 지원과 Docker 동적 재현 지원은 별개입니다. production Docker 경계를
증명하지 못한 host에서는 Docker capability를 활성화하지 않습니다.

## OpenAI API

API 인증과 구독 로그인 차이는 [설정과 인증](./configuration.md#openai와-codex-인증)을
먼저 확인합니다. API probe는 secret 값이 아니라 외부 secret reference와 모델을
받습니다.

```powershell
sastsimi --data-dir .sastsimi-local capability probe OPENAI_API --model <model> --credential-ref env:OPENAI_API_KEY --format json
```

현재 public fake 분석은 이 capability를 소비하지 않습니다. API key를 command
line이나 TOML에 직접 적지 않습니다.
