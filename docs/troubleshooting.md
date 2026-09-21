# 실행 실패 해결

## 먼저 확인할 원칙

인증 실패, 도구 미설치, timeout, LLM 형식 오류, Docker build·실행 실패는 취약점이 없다는 뜻이 아닙니다. SASTSIMI는 이런 오류를 `FALSE`로 바꾸지 않고 `BLOCKED` 또는 verdict 없는 `FAILED`로 저장합니다.

```text
sastsimi status A-001
sastsimi resume A-001
```

`resume`은 성공한 앞 단계를 재사용하고 실패한 단계부터 이어갑니다.

## `sastsimi` 명령이 없음

가상환경을 활성화하고 설치를 확인합니다.

```text
python --version
python -m pip show sastsimi
python -m pip install .
sastsimi --help
```

Python은 64-bit 3.12가 필요합니다.

## setup이 BLOCKED

setup 출력의 누락 목록을 확인합니다.

```text
git --version
opengrep --version
codeql version --format=terse
docker version
codex --version
codex login status
```

Lightweight profile은 CodeQL을 사용하지 않습니다. OpenGrep이나 Docker를 생략하는 profile은 현재 제공하지 않습니다. Full profile은 CodeQL까지 모두 필요합니다.

## LLM 인증 실패

API 방식은 분석을 실행하는 현재 shell에 `OPENAI_API_KEY`가 있는지 확인합니다. 값을 출력하거나 GitHub Issue에 붙이지 않습니다.

회원 로그인은 공식 CLI에서 다시 확인합니다.

```text
codex login status
codex login
```

장치 코드가 만료되면 이전 브라우저 callback을 재사용하지 말고 CLI에서 새 로그인을 시작합니다.

## clone 또는 commit 실패

- URL에 credential을 넣지 않습니다.
- branch·tag·짧은 SHA가 아니라 정확한 40자리 또는 64자리 commit을 사용합니다.
- 로컬 경로는 실제 Git 저장소여야 합니다.
- 이전 workspace와 다른 저장소·commit이 섞였다는 오류가 나면 새 분석을 시작합니다.

## OpenGrep 또는 CodeQL 실패

`sastsimi setup`을 다시 실행해 현재 실행 파일을 확인합니다. Full profile의 CodeQL은 Python database를 만들고 제한된 query suite를 실행하므로 첫 분석에 시간이 걸릴 수 있습니다. 같은 저장소와 commit의 성공 결과는 재개 시 재사용합니다.

CodeQL package가 없으면 다음으로 설치 상태를 확인합니다.

```text
codeql resolve languages
codeql resolve packs
```

정적 도구 실행 실패는 `FALSE`가 아닙니다.

## Docker 또는 PoC 실패

```text
docker version
docker info
```

Docker Desktop은 Linux container 모드여야 합니다. Repository Dockerfile이 있으면 우선 사용하고, 없으면 Python package 파일을 바탕으로 기본 Dockerfile을 만듭니다. package 설치나 image build가 실패하면 환경을 고친 뒤 `sastsimi resume A-001`을 실행합니다.

PoC 초안은 validated PoC가 아닙니다. 같은 attempt에서 실제 실행이 성공하고 가설을 지지해야만 validated PoC가 됩니다.

## 대시보드에 분석이 없음

- 분석과 대시보드가 같은 사용자 설정의 data directory를 사용하는지 확인합니다.
- 먼저 `sastsimi analyze ...`를 시작한 뒤 `sastsimi dashboard`를 실행합니다.
- 주소는 `http://127.0.0.1:8765`입니다.
- 브라우저에서 이전 WSL 주소가 아니라 현재 명령이 출력한 주소를 엽니다.

대시보드는 읽기 전용입니다. 종료해도 분석 상태는 삭제되지 않습니다.

## 보고서 또는 PoC가 없음

보고서가 생성되려면 다음이 모두 필요합니다.

- final `TRUE`
- 같은 실행의 validated PoC
- current CWE label
- Technical Gate 결과
- Rule Scope Gate 결과
- Finding과 Reporter 완료

확인합니다.

```text
sastsimi status A-001
sastsimi result A-001
sastsimi resume A-001
```

오래된 Markdown을 최신 결과처럼 복사하지 않습니다.

## INTERNAL_ERROR

출력된 `trace_id`, 안전한 오류 코드, 사용한 명령과 운영체제만 전달합니다. API key, token, session 파일, 전체 prompt, 민감한 코드나 로컬 절대 경로는 공개 이슈에 첨부하지 않습니다.
