<div align="center">

# SASTSIMI

**Python 제품 코드의 보안 후보를 수집하고, 재현 근거까지 검토하는 로컬 분석 도구**

[![CI](https://github.com/SASTsimi/sastsimi/actions/workflows/ci.yml/badge.svg)](https://github.com/SASTsimi/sastsimi/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)

[빠른 시작](#빠른-시작) · [결과 해석](#결과-해석) · [사용법](docs/usage.md) · [문제 해결](docs/troubleshooting.md)

</div>

SASTSIMI는 고정된 Git 커밋의 제품용 Python `.py` 파일을 정적 검사하고, 후보를 AI Agent가 검토한 뒤 필요한 경우 격리된 Docker 환경에서 PoC를 실행합니다. 확인된 근거는 로컬 대시보드와 영문·국문 보고서로 볼 수 있습니다. **경고, 가설, Finding은 서로 다르며 최종 제보 여부는 사람이 결정합니다.**

## 분석 흐름

```text
저장소·커밋 고정 → Python AST·OpenGrep 검사 (full: CodeQL 추가)
→ 후보 수집·Discovery 선별 → 가설·찬반 근거 검토
→ 필요한 경우 Docker PoC·최종 검증·Gate → Finding·보고서
```

- Git에 추적된 **제품용 Python `.py` 코드**만 정적 검사합니다. 식별된 테스트 전용 파일은 제외 사유를 기록하며, `.pyi`, JS/TS 등에는 Python 규칙을 적용하지 않습니다. 혼합 언어 저장소의 비Python 제품 코드는 검사 완료로 계산하지 않습니다.
- OpenGrep이 일부 파일·규칙을 검증하지 못하면 선택형 Semgrep CE로 해당 조합만 재검사할 수 있습니다. 검증에 성공한 AST·CodeQL 결과는 유지하고, 끝내 확인하지 못한 조합은 누락으로 남깁니다.
- Discovery의 `INCLUDE`·`UNDECIDED`는 심층 검토 대상이지 취약점 확정이 아닙니다. 정적 경고나 LLM 답변만으로 `TRUE` 또는 제보 가능 상태를 만들지 않습니다.
- 개별 도구·LLM 호출에는 시간·재시도 제한이 있습니다. 새 설정에서 누적 LLM 시간·토큰 한도는 기본 무제한이지만, 별도의 누적 비용 한도는 유지되며 계정·공급자 사용량도 확인해야 합니다. 완료 근거가 일치하는 작업만 재개 시 재사용합니다.

## 빠른 시작

아래 명령은 **Windows PowerShell에서 각각 한 줄씩** 실행합니다. Python 3.12, Git, OpenGrep, Docker와 LLM 인증 수단이 필요합니다. 이 예시는 본인 계정의 Codex CLI 회원 로그인과 CodeQL을 요구하지 않는 `lightweight` 프로필을 사용합니다. `full` 프로필은 공식 CodeQL bundle의 Python query pack도 필요합니다. 설치 방법은 [외부 프로그램 안내](docs/installation.md)를 참고하세요.

```powershell
git clone https://github.com/SASTsimi/sastsimi.git
cd sastsimi
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
codex login
codex login status
sastsimi setup --non-interactive --auth subscription --provider codex --model gpt-6-sol --profile lightweight
$repo = Read-Host 'Git 저장소 URL 또는 로컬 경로'
$commit = Read-Host '분석할 정확한 commit SHA'
sastsimi analyze $repo --commit $commit
```

새 PowerShell 창에서는 `.venv`를 다시 활성화하세요. 개발용 잠금 의존성까지 설치할 때는 `uv sync --frozen --all-groups`를 사용할 수 있습니다. OpenAI API 방식은 `OPENAI_API_KEY`를 환경변수로 전달하며, Cursor·Claude 인증과 모델별 설정은 [Provider 안내](docs/provider-setup.md)에 있습니다. 대상은 허가받은 저장소와 정확한 커밋으로 지정하세요.

같은 Provider 안에서 가벼운 분류·보고서 초안만 다른 모델로 실행하려면, 두 모델의 계정 사용 가능 여부를 확인한 뒤 setup에 `--light-model <모델-ID>`를 추가할 수 있습니다. 취약점 선별·PoC·검증은 기본 모델을 유지합니다. 모델 배치는 비용·대기시간 선택이며 입력 토큰 수가 자동으로 줄어든다는 뜻은 아닙니다.

OpenGrep이 확인하지 못한 파일·규칙 조합을 선택형 Semgrep CE로 재검사하려면 `python -m pip install semgrep`으로 설치한 뒤 `sastsimi setup`에 `--semgrep-fallback`을 추가하세요. 기존 인증·모델·프로필 옵션도 함께 유지해야 합니다.

### 진행 상황과 결과

`A-001`과 `F-001`은 예시 ID입니다. 실제 ID는 분석 출력에서 확인합니다.

```powershell
sastsimi status A-001
sastsimi result A-001
sastsimi dashboard
```

대시보드는 기본적으로 [http://127.0.0.1:8765](http://127.0.0.1:8765)에서 열리며, 조회 전용입니다. 장시간 실행 중인 분석을 끝까지 기다리지 않아도 상태를 확인할 수 있습니다. **실행 중인 분석에 `resume`을 동시에 호출하지 마세요.** 중단 또는 일시정지된 분석은 오류 원인을 확인한 뒤 `sastsimi resume A-001`로 재개합니다. 완료된 작업은 저장 근거가 맞을 때만 재사용됩니다. 단, 신규 후보 파이프라인에서 정적 단계 `STATIC_DONE`이 성공한 `PARTIAL` 분석은 같은 ID로 미검증 정적 조합을 다시 스캔하지 않습니다. 원인을 고친 뒤 새 분석 ID로 시작해야 합니다. 자세한 복구 조건은 [문제 해결](docs/troubleshooting.md)에 있습니다.

## 결과 해석

| 표시 | 의미 |
| --- | --- |
| `COMPLETE` | **계획된 검사와 후속 작업**이 끝났습니다. 취약점이 없거나 저장소의 모든 언어를 검사했다는 뜻은 아닙니다. |
| `PARTIAL` | 확인된 부분은 분석했지만 Python 파일·규칙, 보안 표면 또는 범위 밖 제품 코드 등 미검증 항목이 남았습니다. Finding이 있어도 전체 완료는 아닙니다. |
| `PAUSED` | 설정된 사용 한도 등으로 다음 작업이 일시 중단되었습니다. 남은 작업과 사용량을 확인한 뒤 재개할 수 있습니다. |
| `BLOCKED` / `FAILED` | 환경, Agent, 실행 또는 증거 무결성 문제로 결과를 신뢰할 수 없습니다. 이를 취약점 부재로 해석하지 마세요. |
| 가설 `INCONCLUSIVE` | 실행·근거만으로 취약점 여부를 확정하지 못했습니다. 이 가설의 Finding이나 제보 보고서를 만들지 않습니다. |

후보 수·가설 수·Finding 수는 서로 다른 지표입니다. `TRUE`로 판정된 Finding이 있더라도 **기술적 재현과 외부 제보 허가는 별개**입니다. Scope Gate가 `UNCERTAIN`이면 정책상 제보 가능하다고 가정하지 마세요. 제출 전에는 대상 버전, 실제 PoC, 영향, 보안 정책과 공개 조건을 직접 확인해야 합니다.

## Finding과 보고서

Finding이 생성된 경우에만 해당 ID로 검증된 PoC와 보고서를 조회할 수 있습니다.

```powershell
sastsimi poc F-001
sastsimi report show F-001
sastsimi report export F-001 --format markdown
```

검증된 Finding에는 기존 Markdown 보고서와 함께 `report_en.md`(비공개 제보용 **초안**), `report_kr.md`(내부 검토용), PoC 스크립트(`poc.sh`), `evidence/` 및 `bundle.zip`이 생성될 수 있습니다. 실제 파일과 경로는 결과마다 다르며, 영문 초안도 검증되지 않은 영향 버전·심각도를 임의로 채우지 않습니다. 대시보드 또는 [결과 안내](docs/usage.md)에서 첨부를 확인하세요. 동일 취약점 흐름으로 **입증된** 여러 Finding은 표시용 그룹으로 묶을 수 있지만 원본 Finding과 근거는 보존합니다.

### 고정 커밋 탐지율 평가

알려진 취약점의 탐지율은 분석 전에 고정한 정답표와 분석 후 독립적으로 작성한 검토 기록이 있을 때만 계산합니다. 평가기는 실행 데이터를 바꾸지 않고 읽기만 하며, 환경 미검증은 미탐으로 세지 않습니다. [평가 방법과 정답표 범위](docs/validation/2026-10-08-python-recall-methodology.md)를 먼저 확인하세요.

```powershell
$dataDir = Read-Host '분석 데이터 폴더'
$analysisId = Read-Host '정확한 분석 ID'
$oracle = Read-Host '실행 전에 고정한 정답표 JSON 경로'
$review = Read-Host '분석 후 독립 검토 JSON 경로'
python tools/recall_audit.py --data-dir $dataDir --analysis-id $analysisId --oracle $oracle --score --review $review
```

## 문서와 한계

- [설치·외부 프로그램](docs/installation.md) · [Provider·인증](docs/provider-setup.md) · [분석·재개·보고서](docs/usage.md)
- [오류·복구](docs/troubleshooting.md) · [아키텍처](docs/architecture/README.md) · [검증 기록](docs/release-follow-ups.md)
- [기여 안내](CONTRIBUTING.md)

Python 정적 검사 범위의 완료는 알려지지 않은 모든 취약점을 찾았다는 증명이 아닙니다. 미검증 코드·환경 보류·정책 불확실성을 숨기지 않으며, 탐지율이나 오탐률은 **고정 커밋의 독립적으로 검토된 정답표와 실행 근거**가 있을 때만 산출해야 합니다. 모든 저장소에서 `COMPLETE`, `TRUE`, 제보 가능한 보고서를 보장하지 않습니다.

현재 저장소에는 별도 라이선스 파일이 없습니다. 재사용·수정·배포 조건은 라이선스가 명시되기 전까지 별도로 확인해야 합니다.
