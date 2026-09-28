<div align="center">

# SASTSIMI

**코드의 의심 지점을, 검토 가능한 보안 보고서로.**

정적 분석, AI 근거 검토, Docker 재현 검증을 결합해<br>
보안 분석 결과를 영문 제보 초안·국문 검토 보고서와 PoC·근거 파일로 정리하는 로컬 도구입니다.

[![CI](https://github.com/SASTsimi/sastsimi/actions/workflows/ci.yml/badge.svg)](https://github.com/SASTsimi/sastsimi/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Docs](https://img.shields.io/badge/Docs-문서_보기-4A5568)](docs/README.md)

[빠른 시작](#빠른-시작) · [사용법](docs/usage.md) · [아키텍처](docs/architecture/README.md) · [기여하기](CONTRIBUTING.md)

</div>


## 핵심 특징

- **근거 중심 검토**: AST·OpenGrep·CodeQL이 수집한 코드 위치와 흐름을 바탕으로 AI가 취약점 가설과 찬성·반대 근거를 검토합니다.
- **정적 검사 누락 표시**: 파일·규칙별 검사 상태를 확인하고, 미검증 조합만 선택형 Semgrep CE로 재검사합니다. 검증된 부분이 신뢰 가능하면 후속 Agent를 진행하고 남은 누락은 `PARTIAL`로 표시합니다.
- **실행으로 확인하는 PoC**: Agent가 요청한 고정 commit의 Git 추적 소스만 제한적으로 확인하고 Docker에서 재현합니다. 최종 `TRUE` 판정에는 실행에 성공한 validated PoC가 필요합니다.
- **연계형 취약점 탐색**: 이미 확인한 취약 조건을 연결해 더 큰 영향으로 이어지는 새 가설을 검증합니다.
- **중단 지점부터 재개**: 성공한 저장소 준비·정적 분석 근거·같은 입력의 Agent 결과·Docker 이미지는 재사용하고 미검증 조합과 끝나지 않은 단계부터 이어서 실행합니다. Technical Gate의 근거 보완 요청은 새 PoC 후보부터 다시 검증합니다.
- **진행 상황 확인**: CLI 진행 표시와 로컬 읽기 전용 대시보드에서 단계, 가설, 오류, Finding과 보고서를 확인할 수 있습니다.
- **검토 가능한 결과물**: 기존 한국어 Markdown과 함께, 새 Finding에는 영문·국문 보고서 및 검증된 PoC·근거 파일을 묶어 제공합니다. 외부 제보·공개 여부는 사람이 결정합니다.
- **정책 근거별 Scope Gate**: 공개 GitHub 저장소의 공식 `SECURITY.md`를 확인하고 정책 출처·개정과 인용 근거를 보고서와 대시보드에 표시합니다. 정책이 없거나 근거가 부족하면 외부 제보 가능 여부는 `UNCERTAIN`입니다.

## 빠른 시작

### 1. 필수 프로그램 준비

- Python 3.12
- Git
- OpenGrep
- Docker
- OpenAI API 또는 공식 Codex CLI 회원 로그인
- Cursor 사용 시 공식 CLI의 본인 계정 로그인 (선택적으로 개인 API 키 또는 Team 서비스 계정 API 키)
- CodeQL 공식 platform bundle과 query pack (`full` 프로필 사용 시 필수)
- Semgrep CE (`--semgrep-fallback`을 선택한 경우에만 필요)

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

OpenGrep에서 파싱 경고·미검사·건너뜀 등으로 검증되지 않은 파일·규칙 조합만 로컬 Semgrep CE로 재검사하려면, 분석 시작 전 또는 기존 분석이 `PARTIAL`/`BLOCKED`로 멈춘 뒤 다음 PowerShell 명령들을 순서대로 실행합니다. 설정 후 `sastsimi resume A-001`로 이어갑니다. Semgrep은 기본값에서는 사용하지 않으며, `setup`을 다시 실행하면 기존 사용자 설정이 갱신되므로 다른 제한·모델 옵션도 필요에 맞게 함께 지정하세요. 로컬 규칙만 사용하며 분석 중 자동 설치나 계정 로그인은 하지 않습니다.

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install semgrep
semgrep --version
sastsimi setup --non-interactive --auth subscription --provider codex --model gpt-6-sol --profile full --docker-network none --semgrep-fallback
```

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

분석 중단 후에는 완료된 앞 단계를 다시 실행하지 않고 이어서 진행할 수 있습니다. 최초 분석에서 수집한 정책도 같은 분석에 고정되므로 `resume`은 인터넷의 최신 정책을 다시 조회하지 않습니다.

큰 저장소는 정적 도구가 실행되는 동안 `STATIC_DONE` 단계에 진행률 `0%`가 표시될 수 있습니다. `RUNNING`이면 상태를 확인하며 기다리고, 기존 실행이 종료된 뒤에만 `resume`하세요. 정적 분석 시간 초과와 복구 방법은 [오류 해결](docs/troubleshooting.md#opengrep-또는-codeql-실패)을 참고하세요.

정적 검사의 범위는 배포되는 제품 코드입니다. `tests`, `specs`, `e2e`, `testdata`, `unit_tests` 등 이름이 정확히 일치하는 테스트 전용 디렉터리와 언어별 확실한 테스트 파일명은 AST·OpenGrep·Semgrep·CodeQL 입력과 파일×규칙 커버리지에서 제외합니다. 제외 파일의 목록·개수·사유는 저장하거나 보고하지 않으며, 테스트 파일을 다시 포함하는 설정도 없습니다. 디렉터리 이름 일부가 우연히 일치하는 파일이나 제품 실행 진입점은 안전하게 제품 범위에 남깁니다. OpenGrep은 대상 파일을 최대 64개·소스 합계 512 KiB의 명시적 묶음으로 검사하고 시간 초과 묶음은 단일 파일까지 나눕니다. 각 호출은 Windows 명령줄 길이와 유한한 시간을 지키며, `resume`에서는 동일한 범위·규칙·도구·원문 요청을 검증한 완료 증거만 재사용합니다. 기존 전체 파일 범위의 완료 근거를 새 제품 범위에 옮길 수 없으므로 범위가 바뀐 분석은 새 분석 ID로 시작해야 합니다. 파싱 경고·미검사·시간 초과로 남은 제품 코드 조합만 선택형 Semgrep에 전달합니다.

OpenGrep이 실패해도 AST와 설정된 CodeQL 결과는 보존합니다. 제품 범위의 미지원 파일은 확장자가 없어도 경로와 이유를 기록합니다. 일부 파일·규칙 조합이 검증되고 정적 bundle·coverage artifact가 온전하면 `STATIC_DONE`은 검증된 근거를 게시하고 후속 Agent로 진행할 수 있습니다. 미검증 조합의 raw hit는 Agent 후보나 Finding 근거에 넣지 않습니다. 검증 근거가 전혀 없거나 무결성이 깨지면 `BLOCKED`입니다. 대시보드는 검증/예상 수, 누락·미지원 이유와 전체 목록의 페이지 조회를 제공합니다.

같은 commit·제품 범위·규칙·도구 지문에서 해시를 재검증한 파일·규칙 증거만 재개에 재사용합니다. `PARTIAL` 분석은 남은 정적 조합을 다시 시도하며, 완료된 Agent는 원래 입력 참조에 묶어 유지하고 새 근거에서 나온 가설만 추가합니다. 미지원 제품 언어를 완료로 간주하지 않습니다.

Python AST는 사실(facts) 저장 상한에 도달해도 선택된 제품 Python 파일을 계속 파싱합니다. 파싱 실패·용량 초과 파일은 불완전한 범위로 기록하며 사용 가능한 검증 부분이 있으면 `PARTIAL`로 진행할 수 있습니다. 패키지 설정을 읽지 못해 실제 배포 진입점을 확인할 수 없는 경우는 `STATIC_SCOPE_MANIFEST_UNVERIFIED`로 차단합니다.

새 분석의 누적 LLM 호출시간 기본값은 `unlimited`이며 공유 정적 검사 1시간 제한도 적용하지 않습니다. 개별 외부 호출의 시간 제한과 유한한 재시도는 유지됩니다. 선택형 Semgrep fallback을 켜면 OpenGrep 묶음·분할 호출당 최대 120초, Semgrep 호출당 최대 120초입니다. OpenGrep 분할은 최대 64파일·소스 합계 512 KiB(초과 단일 파일은 단독 호출), Semgrep 분할은 최대 128파일이며 둘 다 Windows 명령줄 24,000 UTF-16 단위 이내로 실행합니다. OpenGrep·Semgrep·CodeQL 결과 파일과 재개용 정적 검사 원문은 각각 최대 64 MiB까지만 읽습니다. 한 정적 coverage 실행에서 정규화한 후보 결과는 최대 500,000건, 평가에 채택된 스캔 원문 누적량은 최대 4 GiB이며 같은 원문을 다시 평가해도 합산합니다. 초과 시 `STATIC_CANDIDATES_TOO_LARGE`로 `BLOCKED`됩니다. 로컬 도구 호출의 기본 메모리 제한은 4 GiB입니다. Windows에서는 하위 프로세스를 포함한 Job 전체의 커밋 메모리, POSIX에서는 각 프로세스의 가상 주소 공간에 적용되며 POSIX 하위 프로세스 전체의 메모리 합계 제한은 아닙니다. Semgrep은 실패한 묶음을 파일 단위까지 분할합니다.

완료된 검사 원문은 같은 commit·규칙·도구 지문에서 다시 검증해 재사용합니다. 재개 때 묶음 경계가 달라져도 이미 증명된 파일·규칙은 다시 세지 않습니다. 손상된 원문이나 파싱 오류는 완료로 취급하지 않습니다. 파일 하나의 시간 초과는 `--timeout 30`으로 한 번 더 시험하고, 끝내 확인할 수 없는 조합은 경로·규칙·이유를 coverage artifact에 남깁니다.

scanner 실행 요청은 시작 전 `STARTED`와 종료 결과를 실행 ledger에 남깁니다. 완료 증거는 같은 commit·규칙·도구·요청 설명자와 원문 해시를 재검증한 파일·규칙 조합에만 부여합니다. coverage artifact의 각 미검증 조합에서 `known_attempt_count`는 완료 기록이 남은 scanner 실행 요청 수, `known_attempts_by_engine`는 그 OpenGrep·Semgrep별 수입니다. `history_complete`는 전체 실행 요청 이력을 정확히 셀 수 있는지 나타내며, 이전 summary나 미완료 `STARTED` 기록이 남아 있다면 `attempt_count`는 `null`입니다(완전하면 정확한 총 요청 수). `latest_error_code`·`latest_error_ref`는 가장 최근 기록된 실패 코드와 비공개 오류 근거 참조입니다. 캐시 재사용과 실행 전 검사는 호출로 세지 않습니다.

정적 검사 한 회 예산 `static_scan_pass_seconds`의 기본값은 180초이며 `setup --static-scan-pass-seconds <초>`로 바꿀 수 있습니다. 예산이 끝난 조합은 `not_attempted_budget`로 남고 같은 범위의 `resume`에서 다시 시도합니다. 이는 분석 전체의 누적 시간 제한과 별개입니다.

[기존 Dify 정적 검사 검증](docs/validation/2026-09-27-dify-static-coverage.md)은 변경 전 관찰 기록입니다. [새 정적 재시험](docs/validation/2026-09-28-dify-static-retest.md)과 [전체 파이프라인 판정](docs/validation/2026-09-28-dify-end-to-end.md)은 실제 진행 상태와 확인된 한계를 구분해 기록합니다.

```powershell
sastsimi status A-001
sastsimi resume A-001
sastsimi result A-001
```

### 5. 결과 확인

```powershell
sastsimi dashboard
sastsimi poc F-001
sastsimi report show F-001
sastsimi report export F-001 --format markdown
```

대시보드는 기본적으로 `http://127.0.0.1:8765`에서 열립니다. 조회 전용이며 판정, 재시도 또는 공개 승인 상태를 직접 변경하지 않습니다.
보고서 미리보기·다운로드·결과 ZIP은 같은 검증된 보고서 내용을 사용합니다. 영문 보고서와 PoC·증거는 현재 Finding의 검증된 첨부 manifest가 있을 때만 결과 ZIP에 포함됩니다. 아티팩트가 표시 한도(최대 512개, 파일당 1 MiB, 전체 64 MiB)를 넘거나 읽을 수 없으면 누락 최소 개수를 표시하고 불완전한 전체 ZIP은 제공하지 않습니다. 표시된 자료의 선택 다운로드는 계속 사용할 수 있습니다.

## 동작 방식

```text
저장소 입력
→ AST·OpenGrep·CodeQL로 코드 사실 수집
→ AI가 가설과 찬성·반대 근거 검토
→ 필요한 경우 Docker에서 PoC 재현
→ 기술 근거와 공식 정책의 범위·시험·제보 조건 검토
→ Finding, 기존 한국어 Markdown 및 영문·국문 보고서 번들 생성
```

정적 분석 도구는 취약점을 단독으로 확정하지 않습니다. 실행 관리 프로그램이 작업 순서, 저장, 재시도와 권한을 관리하고, LLM Agent는 주어진 코드와 근거를 분석합니다. Agent의 이름과 역할은 특정 Provider나 모델에 고정되지 않습니다.

내부 Agent, Gate, Chaining과 데이터 계약은 [현재 구현 아키텍처](docs/architecture/README.md)에서 확인할 수 있습니다.

## 결과 예시

Finding 보고서는 기본 데이터 폴더 아래에 분석별로 저장됩니다. 기존 단일 Markdown은 유지하고, 새 보고서에는 개별 첨부파일과 ZIP이 추가됩니다.

```text
reports/<analysis_id>/
  F-001.md
  F-001/
    report_en.md
    report_kr.md
    poc.sh
    evidence/provenance.json
    evidence/stdout.txt     (안전하게 내보낼 수 있을 때만)
    evidence/stderr.txt     (안전하게 내보낼 수 있을 때만)
    manifest.json
    bundle.zip
```

두 새 보고서는 같은 검증 근거와 아홉 개 섹션을 공유합니다: 요약, 영향 대상·테스트 버전, 심각도·CWE, 기술 설명, 재현 방법·PoC, 근거, 영향, Scope Gate·한계, 수정 제안. `report_en.md`는 GitHub 비공개 보안 제보에 옮기기 쉽게, `report_kr.md`는 사용자가 검토하기 쉽게 작성됩니다. 현재 분석 경로의 검증된 셸 PoC는 `poc.sh`로 저장됩니다. 번들 형식은 `poc.py`도 허용하지만 현재 분석 경로에서 Python PoC를 자동 선택하지는 않습니다.

두 언어의 보고서는 같은 정적 coverage의 검증/예상 수, 누락·미지원 수와 주요 이유, artifact 해시를 보여 줍니다. `PARTIAL`이면 미완료 경고가 표시됩니다. 확인된 Finding도 저장소 전체 검사 완료를 뜻하지 않습니다. 큰 경로별 목록은 별도 coverage artifact에 두며, 과거 coverage 정보가 없는 보고서는 전체 검사를 주장하지 않습니다.

`report export`의 기존 `path` 값은 그대로 유지되며, 검증된 새 번들이 있으면 `bundle_path`가 추가됩니다.

테스트한 commit만으로 전체 영향 버전, 패치 버전, 심각도·CVSS를 확정하지 않습니다. 미확인 필드는 `Needs review`/`검토 필요`로 남겨 사람이 확인해야 하며, 영문 파일을 그대로 공개하라는 뜻이 아닙니다. 민감정보 가림으로 첨부 PoC가 실제 실행된 원본과 달라지면 그 사실과 두 해시를 보고서에 표시합니다. 각 파일은 검증된 참조와 해시가 맞는 경우에만 내려받을 수 있습니다.

Reporter는 검증 결과, CWE, validated PoC와 Gate 결과에 없는 새로운 사실을 만들지 않습니다. 보고서에는 Scope Gate의 정책 수집 상태·출처·개정과 항목별 인용 근거가 표시됩니다. 오래된 근거 또는 민감정보 검사를 통과하지 못한 내용은 최신 보고서로 내보내지 않습니다.

## 지원 범위와 한계

- 현재 첫 통합 검증 대상은 Python 저장소이며 Python 3.12가 필요합니다.
- 현재 CodeQL은 Python query suite만 실행합니다. JavaScript/TypeScript는 OpenGrep 규칙의 적용 범위이며, AST·CodeQL 결과를 해당 규칙의 대체 검사 증거로 간주하지 않습니다.
- Windows clean wheel 환경과 WSL/Linux Docker 흐름을 확인했지만, 설치한 컴퓨터에서 `sastsimi setup`으로 외부 도구와 인증 상태를 다시 확인해야 합니다.
- CodeQL은 query pack이 포함된 공식 platform bundle이 필요합니다. 준비되지 않으면 `full` 프로필을 활성화하지 않습니다.
- 인증 실패, 도구 미설치, timeout, Docker build 실패와 LLM 출력 오류는 취약점 `FALSE`로 바꾸지 않고 `BLOCKED` 또는 판정 없는 `FAILED`로 기록합니다.
- Technical Gate가 근거 보완을 요구하면 PoC 후보·Docker 실행·최종 검증부터 다시 수행합니다. 최대 세 번의 Gate 결정 후에도 승인되지 않으면 해당 가설은 `INCONCLUSIVE`, 명시적으로 거절되면 `REJECT`로 끝나며 Finding·보고서를 만들지 않습니다. 필수 Agent가 모두 끝나고 실행 오류가 없으면 정적 범위가 완전할 때 `COMPLETE`, 누락이 남으면 `PARTIAL`입니다. 어느 상태도 취약점 발견이나 제보 가능을 뜻하지 않습니다.
- PoC 복구 시도 상한에 도달한 마지막 실행이 정상 종료(종료 코드 0)됐지만 해석 근거가 부족하면 가설을 `INCONCLUSIVE`로 종료합니다. 검증된 PoC·Finding·보고서는 만들지 않으며, Docker 실행 자체가 실패한 경우는 이 판정에 포함하지 않습니다.
- Docker·인증·Provider·DB 등 실행 오류는 위의 미확정 판정으로 바꾸지 않으며 `BLOCKED` 또는 `FAILED`로 남습니다.
- 새 `setup`은 누적 시간(`max_elapsed_seconds`)과 누적 LLM 토큰(`max_tokens`)을 모두 `unlimited`로 설정합니다. 기존 설정의 숫자 한도는 그대로 적용되며 `--max-tokens <양의 정수>` 또는 `--max-elapsed-seconds <양의 정수>`로 다시 지정할 수 있습니다. 기존 설치에서 무제한으로 바꾸려면 `config.toml`과 `profile.toml` 양쪽의 `max_tokens`를 `"unlimited"`로 설정해야 합니다.
- 입력·출력 토큰은 가능한 범위에서 계속 기록합니다. 숫자 한도를 지정하면 누적 사용량이 도달하거나 이전 시도의 토큰을 확인할 수 없을 때 다음 요청을 차단합니다. `unlimited`이면 이 두 토큰 차단만 해제되고, 개별 OpenGrep·Semgrep·CodeQL·Docker·LLM 호출의 타임아웃·취소·재시도 제한은 유지됩니다. Provider 계정 자체의 사용량·결제 한도는 별도입니다. Codex CLI의 금액 정보는 제공되지 않아 `max_cost_minor_units`로 실제 청구액을 강제할 수 없습니다. OpenAI API 경로는 신뢰할 수 있는 요청별 금액이 없으면 후속 API 요청을 `LLM_COST_USAGE_UNAVAILABLE`로 차단합니다. 자세한 내용은 [Provider 설정](docs/provider-setup.md#codex-회원-로그인)을 참고하세요.
- 동일한 분석 ID를 두 프로세스에서 동시에 실행·재개하지 않습니다. 이미 실행 중이면 두 번째 `resume`은 작업과 LLM 호출을 중복하지 않고 현재 상태와 `ANALYSIS_ALREADY_RUNNING` 이유를 돌려줍니다.
- 공개 GitHub 저장소는 분석 시작 시 기본 브랜치의 `.github/SECURITY.md`, 루트 `SECURITY.md`, `docs/SECURITY.md` 순서로 조회하고, 없으면 같은 소유자의 공개 `.github` 저장소를 확인합니다. 분석한 코드 commit과 정책 개정은 다를 수 있으며 각각 기록합니다. 임의의 버그바운티 사이트나 저장소 내 링크는 자동으로 따라가지 않습니다.
- GitHub 외 저장소·로컬 경로, 정책 부재, 조회 실패 또는 불완전한 정책 근거는 Scope Gate에서 `UNCERTAIN`으로 남깁니다. 명시적 정책 제외는 `DENY`입니다. 검증된 정책의 모든 필수 항목이 근거와 함께 충족되고 명시적 제한 문구가 없을 때만 예비 판정 `ALLOW`입니다. 제한이 있으면 사람 검토 전까지 `UNCERTAIN`이며, `ALLOW`도 자동 제보·공개 승인이 아닙니다. 어느 경우든 기술 검증 결과를 내부 보고서로 남길 수 있습니다. 기존 기록의 근거 없는 `ALLOW`도 조회·내보내기·대시보드에서 제보 가능으로 표시하지 않습니다.
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
