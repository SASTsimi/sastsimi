<div align="center">

# SASTSIMI

**코드의 의심 지점을 검토 가능한 보안 보고서로.**

SASTSIMI는 Python 저장소의 제품 코드를 정적 검사하고, AI Agent의 근거 검토와
Docker PoC 검증을 거쳐 결과를 로컬에 보관하는 보안 분석 도구입니다.
최종 제보 여부는 사람이 판단합니다.

[![CI](https://github.com/SASTsimi/sastsimi/actions/workflows/ci.yml/badge.svg)](https://github.com/SASTsimi/sastsimi/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)

[빠른 시작](#빠른-시작) · [사용법](docs/usage.md) · [설치 안내](docs/installation.md) · [기여하기](CONTRIBUTING.md)

</div>

## 무엇을 하나요?

- **Python 코드 검사**: Git에 추적된 제품용 `.py` 파일에서 AST와 OpenGrep으로 코드 사실을 수집합니다. `full` 프로필에는 CodeQL Python 검사가 추가됩니다. 선택형 Semgrep CE는 OpenGrep이 검증하지 못한 파일·규칙 조합을 재검사합니다.
- **후보 수집·선별**: 검증된 정적 결과에서 명시적으로 표시된 입력 지점·확인된 흐름·단순 힌트를 구분해 후보로 저장합니다. CodeQL 결과 한 건의 여러 흐름도 각각 후보로 다루며, Discovery가 후보별 판정과 이유를 기록합니다. 선별 자체는 취약점 확정이 아닙니다.
- **근거 기반 판단**: 선별된 후보와 보조 자유 탐색에서 나온 가설을 기존 Agent가 찬성·반대 근거로 검토합니다. 정적 도구의 경고나 AI의 주장만으로 취약점을 확정하지 않습니다.
- **격리된 재현**: 필요한 경우 Docker에서 PoC를 실행합니다. 최종 `TRUE` 판정에는 실행으로 검증된 PoC가 필요합니다.
- **누락을 드러내는 결과**: 미검증 정적 범위가 남아도 검증된 근거로 후속 분석을 진행할 수 있지만, 전체 분석은 `PARTIAL`로 표시합니다. 스캔할 수 없었던 Python 제품 파일, 제외한 테스트 파일, Python 검사 대상 밖의 JS/TS 제품 코드를 구분해 보여 주며 실패한 검사를 탐지 없음으로 간주하지 않습니다.
- **재개와 검토**: 완료 증거를 재사용해 중단 지점부터 이어서 실행하고, CLI와 읽기 전용 대시보드에서 진행 상황·Finding·보고서를 확인합니다.

## 빠른 시작

아래 명령은 **Windows PowerShell에서 한 줄씩** 실행합니다. Python 3.12, Git,
OpenGrep, Docker와 LLM 인증 수단 하나가 필요합니다. 아래는 본인 계정의
**Codex CLI 회원 로그인**을 사용하는 예시입니다. OpenAI API, Cursor,
Claude 설정은 [Provider 안내](docs/provider-setup.md)를 참고하세요.
`full` 프로필에는 query pack이 포함된 공식 CodeQL platform bundle도 필요합니다.

### 1. 설치

```powershell
git clone https://github.com/SASTsimi/sastsimi.git
cd sastsimi
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
codex login
codex login status
```

새 PowerShell 창에서는 `.\.venv\Scripts\Activate.ps1`을 다시 실행합니다.
외부 프로그램 준비 방법은 [설치 안내](docs/installation.md)에 있습니다.
개발 의존성이 필요하다면 `uv sync --frozen --all-groups`를 사용할 수 있습니다.
Windows에서 사용하는 저장소 로더의 clone·checkout·검증 명령에는 호출별로
`core.longpaths=true`를 적용합니다. 사용자의 전역 Git 설정은 변경하지 않습니다.

### 2. 설정과 분석

처음 시험할 때는 CodeQL이 필요 없는 `lightweight` 프로필을 선택할 수
있습니다. 다음 명령은 인증 방식·Provider·모델 등을 묻습니다. Codex 예시에서는
`subscription`, `codex`, `gpt-6-sol`을 선택합니다. CodeQL까지 사용하려면
공식 bundle을 준비한 뒤 `full` 프로필로 설정하세요.

OpenAI API를 선택한다면 키는 `OPENAI_API_KEY` 환경변수로 전달합니다.
OpenGrep의 미검증 조합을 Semgrep CE로 재검사하려면 먼저 Semgrep을 설치하고
설정에 `--semgrep-fallback`을 추가하세요. `setup`을 다시 실행할 때는 기존
인증·Provider·모델·프로필·사용 제한 옵션도 유지해야 합니다.

```powershell
sastsimi setup --profile lightweight
$repo = Read-Host '분석할 Git 저장소 URL 또는 로컬 경로'
$commit = Read-Host '소문자 40자리 또는 64자리 commit SHA'
sastsimi analyze $repo --commit $commit
```

분석 대상은 정확한 commit으로 고정합니다. URL을 넣어도 되고 로컬 Git
저장소를 넣어도 됩니다. 긴 분석은 사용시간과 Provider 사용량이 늘 수
있습니다. 새 설정의 누적 LLM 시간·토큰 한도는 기본적으로 무제한이지만,
개별 호출의 시간 제한·재시도 상한과 계정 자체의 사용 한도는 유지됩니다.

### 3. 상태와 결과 확인

```powershell
sastsimi status A-001
sastsimi resume A-001
sastsimi result A-001
```

`A-001`은 예시입니다. 실제 분석 ID는 `analyze` 출력에서 확인하세요.
`resume`은 실행이 종료되거나 중단된 뒤 사용하며, 같은 범위의 완료 검사·Discovery 판정·Agent 작업을 재사용합니다. 누적 LLM 사용량 한도에 도달한 새 분석은 `PAUSED`로 멈추고 남은 후보를 `PENDING`으로 보존합니다. 한도를 올린 뒤 `resume`하세요.
Codex CLI의 토큰 사용량은 호출이 끝난 뒤 확정되므로 `max_tokens`는 호출 전 기록된 누적 사용량을 기준으로 한 **소프트 한도**입니다. 마지막 요청에서 상한을 넘길 수 있고 공급자가 사용량을 제공하지 않은 실패 호출은 정확히 계측할 수 없으므로, 과금을 막는 하드 쿼터로 사용해서는 안 됩니다. 정확한 비용이 제공되지 않는 공급자에 유한 비용 한도를 설정하면 비용을 추정해 통과시키지 않고 일시 중단합니다.
Finding이 생성된 경우에는 해당 ID로 PoC와 보고서를 확인할 수 있습니다.

```powershell
sastsimi poc F-001
sastsimi report show F-001
sastsimi report export F-001 --format markdown
```

`F-001`도 예시이며, Finding이 없으면 이 명령의 대상이 없습니다. 명령별
옵션과 재개·오류 처리 방법은 [사용법](docs/usage.md)과
[문제 해결](docs/troubleshooting.md)을 참고하세요.

```powershell
sastsimi dashboard
```

읽기 전용 대시보드는 기본적으로
[http://127.0.0.1:8765](http://127.0.0.1:8765)에서 열립니다. 실행 중에는
터미널을 차지하므로 다른 명령은 새 PowerShell 창에서 실행하고, 종료할 때는
대시보드 터미널에서 `Ctrl+C`를 누르세요.

## 분석 흐름과 결과물

```text
저장소와 commit 고정
→ Python 제품 코드 정적 검사
→ 후보 수집·Discovery 선별 + 보조 자유 탐색
→ 가설 및 찬성·반대 근거 검토
→ 필요 시 Docker PoC 재현
→ 기술 근거와 공식 보안 정책 검토
→ Finding 및 보고서 작성
```

새 Finding에는 기존 한국어 Markdown 보고서와 함께 검증된 자료에 근거한
영문 제보 **초안**, 국문 검토 보고서, PoC·근거 파일이 생성될 수 있습니다.
아래는 설정된 데이터 폴더 아래의 첫 생성 예시입니다. 실제 첨부 구성은
검증 결과에 따라 달라지며, 개정 번들은 디렉터리 이름에 해시가 붙을 수 있습니다.

```text
reports/<analysis-id>/
  F-001.md
  F-001/
    report_en.md
    report_kr.md
    poc.sh
    evidence/
    manifest.json
    bundle.zip
```

`report_en.md`는 비공개 보안 제보 양식에 옮기기 쉽게,
`report_kr.md`는 내부 검토에 읽기 쉽게 구성합니다. 검증되지 않은 영향
버전·심각도 등은 임의로 채우지 않으므로 제출 전에 사람이 확인해야 합니다.
두 보고서는 스캔할 수 없었던 Python 파일의 수·이유·경로 예시를 다른
미검증 파일×규칙 조합과 구분해 표시합니다. 전체 목록은 coverage artifact에서
확인합니다.
첨부파일·ZIP의 생성 조건은 [결과 안내](docs/usage.md)에
정리했습니다.

## 범위와 판정의 의미

- 정적 검사 대상은 Git에 추적된 **제품용 Python `.py` 파일**입니다. 테스트 전용 파일은 경로·이유를 별도 기록하고 검사 성공으로 세지 않습니다. 단, 배포 manifest가 제품 진입점으로 선언한 파일은 `tests/` 경로라도 제품 코드로 취급합니다. manifest를 읽을 수 없어 제품 여부가 불확실한 파일은 제외 성공으로 처리하지 않고 미지원 범위에 남깁니다. `.pyi`, JS/TS와 기타 비Python 파일에는 Python 규칙을 적용하지 않습니다. JS/TS 제품 코드가 있는 혼합 저장소는 Python 검사만으로 전체 완료를 주장하지 않아 `PARTIAL`로 남습니다. Dockerfile·의존성 파일은 PoC 환경 준비에 사용할 수 있지만 정적 커버리지로 계산하지 않습니다.
- `COMPLETE`는 계획된 정적 범위와 필수 분석 단계가 끝나고 후보에 `PENDING`·`ERROR`가 없다는 뜻입니다. 미검증 제품 코드나 파일×규칙 조합이 남으면 `PARTIAL`이며, 확인된 Finding이 있어도 전체 검사가 완료됐다는 의미는 아닙니다. 후보 수, 가설 수, Finding 수는 서로 다른 집계입니다.
- 체크아웃 실패, 증거 손상, Agent 실행 실패처럼 부분 결과 자체를 신뢰할 수 없는 오류는 `PARTIAL`로 덮지 않고 `BLOCKED` 또는 `FAILED`로 남깁니다. 누락된 조합은 `resume`에서 다시 시도할 수 있습니다.
- 공식 보안 정책이 없거나 근거가 부족하면 Scope Gate는 `UNCERTAIN`입니다. `ALLOW`도 자동 제보·공개 승인은 아닙니다. 허가된 대상에서만 분석하고, 기술 근거·정책·PoC를 사람이 검토한 뒤 외부 제출 여부를 결정하세요.
- 자동 외부 제출·공개, HTML/PDF 보고서, 대시보드에서의 판정 변경은 지원하지 않습니다. 환경·Provider·저장소에 따라 실행 결과가 달라질 수 있으며, 모든 저장소의 완전한 검사나 취약점 발견을 보장하지 않습니다.

## 문서

- [설치와 외부 프로그램](docs/installation.md)
- [Provider·모델·인증 설정](docs/provider-setup.md)
- [분석·재개·대시보드·보고서](docs/usage.md)
- [오류 해결](docs/troubleshooting.md)
- [구현 아키텍처](docs/architecture/README.md)
- [검증 기록과 남은 제한](docs/release-follow-ups.md)
- [기여 안내](CONTRIBUTING.md)

현재 저장소에는 별도 라이선스 파일이 없습니다. 재사용·수정·배포 조건은
라이선스가 명시되기 전까지 별도로 확인해야 합니다.
