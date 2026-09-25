<div align="center">

# SASTSIMI

**코드의 의심 지점을, 검토 가능한 보안 보고서로.**

정적 분석, AI 근거 검토, Docker 재현 검증을 결합해<br>
보안 분석 결과를 한국어 Markdown 보고서로 정리하는 로컬 도구입니다.

[![CI](https://github.com/SASTsimi/sastsimi/actions/workflows/ci.yml/badge.svg)](https://github.com/SASTsimi/sastsimi/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Docs](https://img.shields.io/badge/Docs-문서_보기-4A5568)](docs/README.md)

[빠른 시작](#빠른-시작) · [사용법](docs/usage.md) · [아키텍처](docs/architecture/README.md) · [기여하기](CONTRIBUTING.md)

</div>


## 핵심 특징

- **근거 중심 검토**: AST·OpenGrep·CodeQL이 수집한 코드 위치와 흐름을 바탕으로 AI가 취약점 가설과 찬성·반대 근거를 검토합니다.
- **실행으로 확인하는 PoC**: 최종 `TRUE` 판정에는 Docker에서 실제 재현에 성공한 validated PoC가 필요합니다.
- **연계형 취약점 탐색**: 이미 확인한 취약 조건을 연결해 더 큰 영향으로 이어지는 새 가설을 검증합니다.
- **중단 지점부터 재개**: 성공한 저장소 준비·정적 분석·Agent 결과·Docker 이미지는 재사용하고 실패한 단계부터 이어서 실행합니다.
- **진행 상황 확인**: CLI 진행 표시와 로컬 읽기 전용 대시보드에서 단계, 가설, 오류, Finding과 보고서를 확인할 수 있습니다.
- **검토 가능한 결과물**: 확인된 근거만 사용해 한국어 Markdown 보고서를 만들며 외부 공개 여부는 사람이 결정합니다.

## 빠른 시작

### 1. 필수 프로그램 준비

- Python 3.12
- Git
- OpenGrep
- Docker
- OpenAI API 또는 공식 Codex CLI 회원 로그인
- Cursor 사용 시 공식 CLI의 본인 계정 로그인 (선택적으로 개인 API 키 또는 Team 서비스 계정 API 키)
- CodeQL 공식 platform bundle과 query pack (`full` 프로필 사용 시 필수)

자세한 운영체제별 설치 방법은 [설치 문서](docs/installation.md)를 확인하세요.

### 2. SASTSIMI 설치

```powershell
git clone https://github.com/SASTsimi/sastsimi.git
cd sastsimi
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
sastsimi --help
```

위 명령은 각각 PowerShell 한 줄입니다. 가상환경이 활성화된 터미널에서는 `sastsimi`를 바로 실행할 수 있습니다. 새 터미널에서는 `.\.venv\Scripts\Activate.ps1`을 다시 실행하세요.
개발 환경에서 uv를 사용한다면 `uv sync --frozen`으로 잠긴 의존성을 설치할 수도 있습니다.

### 3. 최초 설정

```powershell
codex login
codex login status
sastsimi setup --non-interactive --auth subscription --provider codex --model gpt-6-sol --profile full --docker-network none
```

`setup`은 기본 저장 위치, Provider·모델, 분석 도구, 사용 제한과 Docker 네트워크를 구성합니다. Codex에서 모델을 생략하면 새 설정의 기본 제안은 `gpt-6-sol`이며, 기존 설치 설정은 자동으로 바뀌지 않습니다. 다른 모델은 `--model`로 지정하세요. API key와 로그인 token은 설정 파일에 직접 저장하지 않습니다. `full`에는 CodeQL query pack이 필요합니다.

API를 사용한다면 key는 환경변수로 전달합니다.

```powershell
$env:OPENAI_API_KEY = "<현재 터미널에만 설정>"
sastsimi setup --auth api-key --provider openai --model <사용할-model>
```

ChatGPT 회원 로그인은 공식 Codex CLI의 본인 계정으로 처리하며 브라우저 cookie를 복사하지 않습니다.

Cursor와 Claude도 선택할 수 있습니다. 계정별 인증, 모델 목록 확인, Agent별 모델, fallback, on-demand 사용량 설정은 [Provider 설정](docs/provider-setup.md)을 참고하세요. 기존 분석 방식의 선택형 `facts_survey`와 Docker 복구 동작은 [운영 설정](docs/provider-setup.md#선택형-분석-설정) 및 [오류 해결](docs/troubleshooting.md#docker-또는-poc-실패)에 정리했습니다.

### 4. 저장소 분석

정확한 40자리 또는 64자리 commit SHA를 사용합니다.

```powershell
sastsimi analyze https://github.com/owner/repository.git --commit <정확한-40자리-SHA>
```

분석 중단 후에는 완료된 앞 단계를 다시 실행하지 않고 이어서 진행할 수 있습니다.

```powershell
sastsimi status A-001
sastsimi resume A-001
sastsimi result A-001
```

### 5. 결과 확인

```powershell
sastsimi dashboard
sastsimi poc F-001
sastsimi report F-001
sastsimi report F-001 --export markdown
```

대시보드는 기본적으로 `http://127.0.0.1:8765`에서 열립니다. 조회 전용이며 판정, 재시도 또는 공개 승인 상태를 직접 변경하지 않습니다.

## 동작 방식

```text
저장소 입력
→ AST·OpenGrep·CodeQL로 코드 사실 수집
→ AI가 가설과 찬성·반대 근거 검토
→ 필요한 경우 Docker에서 PoC 재현
→ 기술 근거와 분석 범위 검토
→ Finding과 한국어 Markdown 보고서 생성
```

정적 분석 도구는 취약점을 단독으로 확정하지 않습니다. 실행 관리 프로그램이 작업 순서, 저장, 재시도와 권한을 관리하고, LLM Agent는 주어진 코드와 근거를 분석합니다. Agent의 이름과 역할은 특정 Provider나 모델에 고정되지 않습니다.

내부 Agent, Gate, Chaining과 데이터 계약은 [현재 구현 아키텍처](docs/architecture/README.md)에서 확인할 수 있습니다.

## 결과 예시

Finding 보고서는 기본 데이터 폴더 아래에 분석별로 저장됩니다.

```text
reports/<analysis_id>/F-001.md
```

보고서는 다음 네 구역을 중심으로 구성됩니다.

- `Summary`: 취약점과 영향 요약
- `Details`: 코드 위치, 입력부터 위험 함수까지의 흐름, 찬성·반대 근거와 판정 이유
- `PoC`: 검증된 재현 코드, 실행 방법과 실행 결과
- `Impact`: 영향받는 사용자·기능, 위험도와 제한사항

Reporter는 검증 결과, CWE, validated PoC와 Gate 결과에 없는 새로운 사실을 만들지 않습니다. 오래된 근거 또는 민감정보 검사를 통과하지 못한 내용은 최신 보고서로 내보내지 않습니다.

## 지원 범위와 한계

- 현재 첫 통합 검증 대상은 Python 저장소이며 Python 3.12가 필요합니다.
- Windows clean wheel 환경과 WSL/Linux Docker 흐름을 확인했지만, 설치한 컴퓨터에서 `sastsimi setup`으로 외부 도구와 인증 상태를 다시 확인해야 합니다.
- CodeQL은 query pack이 포함된 공식 platform bundle이 필요합니다. 준비되지 않으면 `full` 프로필을 활성화하지 않습니다.
- 인증 실패, 도구 미설치, timeout, Docker build 실패와 LLM 출력 오류는 취약점 `FALSE`로 바꾸지 않고 `BLOCKED` 또는 판정 없는 `FAILED`로 기록합니다.
- Codex CLI 경로의 요청별 토큰·비용은 현재 미제공입니다. 설정된 토큰·비용 상한으로 실제 사용량을 강제할 수 없으므로 계정 사용량을 별도로 확인하세요. 자세한 내용은 [Provider 설정](docs/provider-setup.md#codex-회원-로그인)을 참고하세요.
- 공식 분석 정책이 없거나 대상 범위 밖이어도 기술 검증 결과를 내부 보고서로 남길 수 있습니다. 외부 제출·공개 제한은 보고서에 함께 표시합니다.
- 자동 외부 제출·공개, HTML/PDF 보고서와 대시보드 쓰기 기능은 지원하지 않습니다.

## 문서

- [문서 안내](docs/README.md)
- [설치와 외부 프로그램](docs/installation.md)
- [실행과 결과 확인](docs/usage.md)
- [Provider 인증](docs/provider-setup.md)
- [실패 해결](docs/troubleshooting.md)
- [현재 구현 아키텍처](docs/architecture/README.md)
- [현재 설계 결정](docs/decisions/README.md)
- [현재 제한과 후속 작업](docs/release-follow-ups.md)

## 기여와 사용 원칙

개발 환경 구성, 테스트와 PR 절차는 [기여 안내](CONTRIBUTING.md)를 확인하세요. SASTSIMI는 반드시 허가받은 저장소와 환경에서만 사용해야 하며, 생성된 보고서는 사람이 근거와 PoC를 검토한 뒤 외부 제출 여부를 결정해야 합니다.

현재 저장소에는 별도 라이선스 파일이 없습니다. 재사용·수정·배포 조건은 라이선스가 명시되기 전까지 별도로 확인해야 합니다.
