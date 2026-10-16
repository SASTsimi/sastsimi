<div align="center">

# SASTSIMI

**Python 코드의 보안 신호를, 검토 가능한 근거로.**

Evidence-first security analysis for Python repositories.

[![CI](https://github.com/SASTsimi/sastsimi/actions/workflows/ci.yml/badge.svg)](https://github.com/SASTsimi/sastsimi/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Scope: Python product code](https://img.shields.io/badge/Scope-Python%20product%20code-155e75)](#검사-범위)

[빠른 시작](#빠른-시작) · [분석 흐름](#분석-흐름) · [결과 해석](#결과-해석) · [전체 문서](docs/README.md)

</div>

SASTSIMI는 **고정된 Git 커밋의 제품용 Python 코드**에서 보안 후보를 수집하고,
AI Agent의 찬성·반대 근거 검토와 필요한 경우 격리된 Docker PoC를 거쳐 결과를
로컬에 남기는 도구입니다. 스캐너 경고, 가설, Finding은 서로 다른 단계이며
**취약점 확정과 외부 제보 여부는 검증 근거와 사람의 판단에 달려 있습니다.**

## 분석 흐름

```mermaid
flowchart LR
    A["고정된 Git 커밋"] --> B["Python 정적 검사"]
    B --> C["후보 수집 · Discovery"]
    C --> D["가설 · 찬반 근거 검토"]
    D --> E["필요 시 Docker PoC"]
    E --> F["최종 검증 · Scope Gate"]
    F --> G["Finding · 영문/국문 보고서"]
```

| 수집 | 검토 | 확인 |
| :--- | :--- | :--- |
| AST·OpenGrep으로 Python 코드의 사실과 후보를 보존합니다. | Agent가 후보를 선별하고 가설의 Pro/Con 근거를 대조합니다. | 필요한 PoC를 격리 실행하고 판정·정책 범위·보고서를 확인합니다. |

`full` 프로필에는 CodeQL Python 검사가 추가됩니다. 선택형 Semgrep CE는
OpenGrep이 검증하지 못한 파일·규칙 조합만 재검사합니다. 한 도구의 실패를
다른 도구의 “탐지 없음”으로 바꾸지 않습니다.
Semgrep 재검사를 사용하려면 `python -m pip install semgrep` 후 `sastsimi setup`에
`--semgrep-fallback`을 추가하고 기존 인증·모델·프로필 옵션도 함께 지정하세요.

## 빠른 시작

Windows PowerShell에서 **각 줄을 한 명령씩** 실행합니다. Python 3.12, Git,
OpenGrep, Docker 및 LLM 인증 수단을 먼저 준비하세요. 아래는 본인 계정의
**Codex CLI 로그인**과 CodeQL 없이 시작하는 `lightweight` 예시입니다.
외부 도구 설치는 [설치 안내](docs/installation.md), Cursor·Claude·OpenAI API 및
모델 선택은 [Provider 안내](docs/provider-setup.md)에 있습니다.

### 1. 저장소 복제·가상환경 준비

```powershell
git clone https://github.com/SASTsimi/sastsimi.git
cd sastsimi
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
```

### 2. Codex 로그인 확인

```powershell
codex login
codex login status
```

### 3. SASTSIMI 설정

```powershell
sastsimi setup --non-interactive --auth subscription --provider codex --model gpt-6-sol --profile lightweight
```

### 4. 대상 저장소·커밋 지정 후 분석

```powershell
$repo = Read-Host 'Git 저장소 URL 또는 로컬 경로'
$commit = Read-Host '분석할 정확한 commit SHA'
sastsimi analyze $repo --commit $commit
```

대상은 **허가받은 저장소의 정확한 커밋**으로 지정합니다. 새 PowerShell 창에서는
`.\.venv\Scripts\Activate.ps1`을 다시 실행하세요. `full` 프로필은 공식
CodeQL bundle과 Python query pack이 필요합니다. 긴 분석은 LLM 사용량과
실행시간이 커질 수 있습니다.
개발용 잠금 의존성까지 설치할 때는 `uv sync --frozen --all-groups`를 사용할 수
있습니다. OpenAI API 인증은 `OPENAI_API_KEY` 환경변수로 전달합니다.

### 진행 상황 보기

`A-001`은 예시 ID입니다. 실제 ID는 `analyze` 출력에서 확인합니다.
분석 실행 중 상태를 보려면 새 PowerShell 창에서 `.venv`를 활성화하고 아래 명령을 실행하세요.

```powershell
sastsimi status A-001
sastsimi result A-001
sastsimi dashboard
```

읽기 전용 대시보드는 기본적으로 [127.0.0.1:8765](http://127.0.0.1:8765)에서
열립니다. 대시보드가 터미널을 차지하므로 다른 명령은 새 PowerShell 창에서
실행하세요. **실행 중인 분석에 `resume`을 동시에 호출하지 마세요.**
중단·일시정지된 경우 원인을 확인한 뒤 `sastsimi resume A-001`로 이어갑니다.
완료 근거가 일치하는 작업만 재사용됩니다.

저장된 보안 표면을 다시 검토하는
`sastsimi resume A-001 --enrich-saved-surface-evidence`는 **별도 명시 옵션**입니다.
일반 `resume`이 자동으로 시작하지 않으며, 근거가 부족하면 보강 후에도
`PARTIAL`일 수 있습니다. 상세 재개 조건은
[문제 해결](docs/troubleshooting.md)과
[런타임·재개 구조](docs/architecture/runtime-and-recovery.md)를 참고하세요.

## 결과 해석

| 상태 | 읽는 방법 |
| :--- | :--- |
| `COMPLETE` | 계획된 검사와 필수 후속 작업이 끝났습니다. 취약점이 없거나 모든 언어를 검사했다는 뜻은 아닙니다. |
| `PARTIAL` | 검증된 결과는 남겼지만 제품 코드·파일×규칙·호출 경로 등 미검증 범위가 있습니다. **진행률 100%와 함께 표시될 수도 있습니다.** |
| `PAUSED` | 사용 한도 등으로 다음 작업을 일시 중단했습니다. 남은 작업과 사용량을 확인한 뒤 재개합니다. |
| `BLOCKED` / `FAILED` | 환경·Agent·실행 또는 증거 무결성 문제입니다. 취약점 부재로 해석하지 않습니다. |
| 가설 `INCONCLUSIVE` | 근거만으로 취약점 여부를 확정하지 못했습니다. 이 가설을 Finding으로 세지 않습니다. |

후보 수, 가설 수, Finding 수는 다른 지표입니다. Finding의 기술적 판정과
**Scope Gate의 정책 판단도 별개**입니다. `UNCERTAIN`은 제보 가능 승인이
아니며, `ALLOW`도 자동 제출 허가는 아닙니다.

## 검사 범위

- 정적 검사는 Git에 추적된 **제품용 Python `.py` 파일**을 대상으로 합니다.
  식별된 테스트 전용 파일은 이유를 기록해 제외합니다. `.pyi`, JS/TS 및
  기타 비Python 제품 코드에는 Python 규칙을 적용하지 않습니다.
- 실패하거나 시간 초과된 파일·규칙은 “탐지 없음”이 아니라 **미검증**으로
  남습니다. 혼합 언어 저장소의 검사 범위 밖 제품 코드도 전체 완료로 세지
  않습니다.
- 정적 경고나 LLM 답변만으로 `TRUE`를 만들지 않습니다. 최종 확인에는
  검증된 PoC와 기술 근거가 필요하고, 외부 제출 전에는 영향 버전·정책·공개
  조건을 사람이 검토해야 합니다.

## 보고서와 첨부파일

Finding이 생성된 경우에만 해당 ID(`F-001`은 예시)로 PoC와 보고서를 조회합니다.

```powershell
sastsimi poc F-001
sastsimi report show F-001
sastsimi report export F-001 --format markdown
```

검증 결과에 따라 `report_en.md`(비공개 제보용 **초안**),
`report_kr.md`(내부 검토용), `poc.sh`, `evidence/`, `manifest.json`,
`bundle.zip`이 생성될 수 있습니다. 영향 버전·심각도처럼 확인되지 않은 값은
임의로 채우지 않습니다. [보고서 사용법](docs/usage.md)에서 생성 조건과
첨부파일 확인 방법을 확인하세요.

## 더 알아보기

### 시작과 운영

- [설치](docs/installation.md): 환경과 외부 도구 준비
- [Provider·모델](docs/provider-setup.md): 인증과 모델 선택
- [CLI·대시보드](docs/usage.md): 분석, 재개, 결과 확인
- [문제 해결](docs/troubleshooting.md): 오류별 확인과 복구

### 동작 원리와 검증

- [아키텍처](docs/architecture/README.md): 파이프라인과 구현 구조
- [재개·근거 버전](docs/architecture/runtime-and-recovery.md): 체크포인트와 재개 조건
- [탐지율 평가 방법](docs/validation/2026-10-08-python-recall-methodology.md): 정답표와 측정 범위
- [현재 제한과 후속 작업](docs/release-follow-ups.md): 아직 지원하거나 검증하지 않은 범위

### 프로젝트 안내

- [전체 문서 지도](docs/DOCUMENT_GUIDE.md): 필요한 문서 찾기
- [용어집](docs/GLOSSARY.md): 공통 용어와 상태값
- [기여 안내](CONTRIBUTING.md): 코드·문서 변경과 PR 절차

> SASTSIMI는 모든 저장소의 완전한 검사나 취약점 발견·제보 가능한 보고서를
> 보장하지 않습니다. 현재 별도 라이선스 파일이 없으므로 재사용·수정·배포
> 조건은 라이선스가 명시되기 전까지 별도로 확인해야 합니다.
