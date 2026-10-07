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

- **Python 코드 검사**: Git에 추적된 제품용 `.py` 파일에서 AST와 OpenGrep으로 코드 사실을 수집합니다. 파싱에 성공한 파일의 AST 사실은 파일별 아티팩트에 모두 보존하고, Agent에는 필요한 위치 주변의 작은 문맥만 전달합니다. `full` 프로필에는 CodeQL Python 검사가 추가됩니다. 선택형 Semgrep CE는 OpenGrep이 검증하지 못한 파일·규칙 조합을 재검사합니다.
- **후보 수집·선별**: 검증된 정적 결과에서 명시적으로 표시된 입력 지점·확인된 흐름·단순 힌트를 구분해 후보로 저장합니다. CodeQL 결과 한 건의 여러 흐름도 각각 후보로 다루며, Discovery가 후보별 판정과 이유를 기록합니다. 선별 자체는 취약점 확정이 아닙니다.
- **중복 근거 보존**: 새 분석은 입력→위험 동작의 전체 흐름과 정확한 위치·유형이 일치함을 증명한 정적 후보만 합칩니다. 위치만 같은 힌트나 컬럼·중간 경로가 부족한 경고는 서로 다른 취약점일 수 있어 각각 검토하며, 합쳐진 후보에도 모든 원본 도구·규칙·결과 행의 출처를 남깁니다. 진행 중이던 분석은 후보 ID와 판정을 그대로 재사용합니다.
- **근거 기반 판단**: 새 분석은 같은 파일의 선별 후보에 공유 문맥을 한 번 붙여 가설을 만들고, 등록된 가설부터 찬성·반대 근거와 PoC를 검증합니다. 신규 정적 번들의 `candidate_context_version=5`는 입력 후보의 제한된 후속 호출·callee 본문과 요청 처리 중 정상/오류 응답의 구문 경로를 보여 줍니다. 기존 분석의 v1–v4 문맥·배치 식별값은 재개 시 그대로 보존합니다. 이 문맥은 taint나 실행 증명·실측 개선 결과가 아니며, Agent가 응답 차이와 실제 영향을 별도로 검증해야 합니다. 지원하는 Python route에서는 handler 정의·제한된 request 접근·직접 호출·sink의 구문 경로도 함께 보존합니다. import는 실제로 선언된 모듈·심볼만 해석하고, 추적 파일에 있다는 이유만으로 형제 모듈을 연결하지 않습니다. 해석하지 못한 import·동적 호출은 명시적 gap으로 남깁니다. 후보와 연결된 위치라도 입력·민감 동작·경계의 검토 근거가 부족하면 보조 탐색에 남깁니다. 정적 도구의 경고나 AI의 주장만으로 취약점을 확정하지 않습니다.
- **격리된 재현**: 필요한 경우 Docker에서 PoC를 실행합니다. 종료 코드 0만으로 재현을 주장하지 않으며, 근거가 부족한 완료 관찰은 `INCONCLUSIVE`로 구분합니다. 최종 `TRUE` 판정에는 실행으로 검증된 PoC가 필요합니다.
- **PoC 근거 전달**: PoC Agent에는 고정 commit에서 확인한 Pro/Con의 핵심 소스와 요청한 추적 파일을 전달합니다. 재시도에서는 최근 후보·실행 기록과 검증 피드백을 우선하고, 이전의 큰 스크립트·로그는 문맥 한도 안에서만 추가합니다. 필수 근거가 한도를 넘으면 생략한 채 성공 처리하지 않고 오류로 남깁니다.
- **안전한 PoC 의존성 준비**: 기본 `AUTO` 모드는 `python:3.12-slim` 태그를 확인하고 로컬에 없을 때만 별도 일회용 resolver에서 받은 뒤, 그 실행의 local digest로 고정합니다. wheel은 고정 commit의 `requirements.txt`, 기본 PEP 621 `pyproject.toml` 및 build-system 요구사항, 또는 PoC Agent가 명시한 `pip:<PEP 508 requirement>`에서만 받으며 대상 저장소를 마운트·실행하지 않습니다. 고정 manifest는 권위 있는 입력이라 제거·대체하지 않습니다. 정확한 `No matching distribution` 진단이 있고 manifest와 정규화한 패키지명이 겹치지 않으며 다른 요구사항이 남는 경우에만 Agent 추가 `pip:` 항목을 receipt와 함께 제외할 수 있습니다. 고정 manifest·build 요구사항의 no-match는 제외하거나 같은 입력으로 자동 재시도하지 않으며, 해당 시도에 연결된 receipt가 검증될 때만 PoC·Finding 없이 `INCONCLUSIVE`로 종료합니다. 지원하지 않는 설치 방식은 `BLOCKED`로 남습니다. 최종 이미지 빌드와 PoC 실행은 계속 네트워크 없이 수행합니다. 운영자가 승인한 wheel TAR를 지정하거나 `OFFLINE_ONLY`로 강제할 수도 있습니다. URL·VCS·sdist·OS 패키지와 외부 DB·캐시 서비스는 자동 실행하지 않으며, 지원하지 않는 설치 방식은 검증을 가장하지 않고 차단합니다.
- **누락을 드러내는 결과**: 미검증 정적 범위나 미검토 보안 표면이 남아도 검증된 근거로 후속 분석을 진행할 수 있지만, 전체 분석은 `PARTIAL`로 표시합니다. 스캔할 수 없었던 Python 제품 파일, 제외한 테스트 파일, Python 검사 대상 밖의 JS/TS 제품 코드를 구분해 보여 주며 실패한 검사를 탐지 없음으로 간주하지 않습니다.
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
인증·Provider·모델·프로필·사용 제한 옵션도 유지해야 합니다. 실행 프로필
`profile.toml`의 기본값 `poc_dependency_bundle_mode = "AUTO"`는 필요할 때 기본
Python 태그를 local digest로 고정하고 제한된 Python binary wheel만 준비합니다. 외부 통신을 전혀
허용하지 않으려면
`"OFFLINE_ONLY"`로 바꾸고 운영자가 검토한
`poc_wheel_archive_path`와 `poc_wheel_archive_sha256`을 함께 지정하세요.
두 모드 모두 `docker_network = "NONE"`인 최종 PoC 빌드·실행을 유지합니다.
고정 소스 근거가 Python 3.12 이외의 인터프리터를 요구하면 초기 검증은
`python:X.Y[.Z]`로 명시할 수 있습니다. 이 경우 운영자가 이미 로컬에 준비한
Linux 이미지의 digest를 `poc_offline_base_image_digest`에 지정해야 하며,
도구가 네트워크 없는 컨테이너에서 실제 Python 버전을 검사합니다. 이미지를
자동으로 찾거나 임의로 내려받지 않고, 해당 버전의 제품 의존성에 호환되는
binary wheel이 없으면 PoC를 성공으로 간주하지 않습니다.
이 필드는 `setup` 옵션이 아니며, `setup`을 다시 실행하면 프로필을 새로 쓰므로
수동 설정도 다시 지정해야 합니다. 지원 범위와 오류 해석은
[Docker 또는 PoC 실패](docs/troubleshooting.md#docker-또는-poc-실패)를 참고하세요.

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
오프라인 PoC가 확인된 base-image 환경 결함으로 복구 한도에 이른 경우에는 검증된 로컬 Python 3.12 브라우저 이미지의 digest를 실행 프로필에 지정한 뒤, 실패한 가설 하나에 한해 `sastsimi resume A-001 --repair-exhausted-hypothesis hypothesis-...`를 명시적으로 사용할 수 있습니다. 일반 `resume`은 소진 기록을 초기화하지 않습니다. 안전 조건과 제한은 [문제 해결](docs/troubleshooting.md)을 참고하세요.
과거 복구 Agent의 정책 위반 출력 때문에 `FALLBACK STOP`으로 저장된 한 PoC는 정확한 실행·정리·체크포인트 결합이 검증될 때만 `sastsimi resume A-001 --repair-fallback-poc-stop hypothesis-...`로 명시적 재시도를 요청할 수 있습니다. 별도의 이전 Python import STOP 또는 정제된 traceback 형식을 잘못 읽어 저장된 import STOP에는 `--repair-legacy-import-stop hypothesis-...`를 사용합니다. 실제 실행 증거·정리 상태·고정 소스가 일치하는 정확한 가설만 다시 열며, 이전 실패 기록이나 시도 한도를 지우지 않고 실행 오류를 취약점 반증으로 바꾸지 않습니다.
PoC 후보 검증 오류 `POC_PLACEHOLDER_FORBIDDEN`이 세 번 반복된 과거 가설은 검증기 규칙이 실제로 수정된 뒤에만 `sastsimi resume A-001 --repair-poc-placeholder-exhaustion hypothesis-...`로 해당 가설을 한 번 더 재평가할 수 있습니다. 같은 검증기 버전의 반복 재개는 거부하며 완료된 다른 작업은 보존합니다.
세 번째 시도가 PoC 컨테이너 생성 **전** `DOCKER_OWNED_LIST_FAILED`로 끝난 특정 분석은 소유 라벨 조회에서 해당 시도의 컨테이너가 없고 기존 증거가 모두 일치할 때에만 `sastsimi resume A-001 --repair-docker-owned-list-exhaustion hypothesis-...`로 한 번 재개할 수 있습니다. 이때 해당 가설의 PoC 후보를 새 시도에서 다시 만들며 이전 시도 증거는 보존합니다. 일반적인 Docker 실패나 실제 PoC 실행 실패에는 적용되지 않습니다.
과거 보고서 검증기가 서버 IPv4 주소를 제품 버전으로 잘못 해석해 중단한 경우에만 `sastsimi resume A-001 --repair-report-validator hypothesis-...`로 정확한 보고서 단계를 다시 평가할 수 있습니다. 저장된 초안·근거·이전 검증 오류가 일치하지 않으면 거부합니다.
과거 PoC 후보가 민감 내용 검사에서 두 번 거부되어 `POC_SENSITIVE_CONTENT`로 멈춘 경우에는 검증 오류와 가설·시도·루트 차단 기록이 정확히 일치할 때만 `sastsimi resume A-001 --repair-poc-sensitive-content hypothesis-...`로 한 번 재평가할 수 있습니다. 수리 기록은 보존되며 같은 옵션의 반복 실행은 거부합니다.
`resume`은 실행이 종료되거나 중단된 뒤 사용하며, 같은 범위의 완료 검사·Discovery 판정·Agent 작업을 재사용합니다. 신규 후보 파이프라인(v2)은 완료된 파일별 묶음·후보별 결과·가설 단계·보안 표면 탐색을 정확한 입력 해시로 확인해 재사용하고, 누락되거나 실패한 항목만 다시 시도합니다. 기존 후보 파이프라인(v1)의 완료 표시와 소스 페이지는 기존 뜻대로 재개하며 v2 표시로 재해석하지 않습니다. 기존 인라인 AST 근거를 가진 분석도 기존 형식으로 재개하며, 새 파일별 AST 형식과 섞어 완료로 계산하지 않습니다. 기존 형식의 후보 선별까지 끝난 `PARTIAL` 분석은 정적 재검사로 형식이 바뀔 때 `AST_FORMAT_UPGRADE_NEW_ANALYSIS_REQUIRED`를 표시하고 기존 결과를 보존합니다. 새 형식으로 전체 범위를 다시 검사하려면 새 분석을 시작하세요. 누적 LLM 사용량 한도에 도달한 새 분석은 `PAUSED`로 멈추고 남은 작업을 보존합니다. 한도를 올린 뒤 `resume`하세요.
최종 Verification의 근거 전달 형식은 v3입니다. v2에서 끝난 TRUE·FALSE·HOLD를 재개하면 가설·고정 소스 근거를 포함해 최종 판정과 그 이후 단계를 다시 확인합니다. 기존 정적 검사·Pro/Con·검증된 PoC는 재사용하며, 이 버전 전환에서 최종 Agent 호출 비용이 추가될 수 있습니다. 이전 판정을 새 버전의 확인 결과로 자동 승격하지 않습니다. 고정 소스 근거가 손상되거나 크기 제한을 넘으면 명시적 오류로 멈춥니다.
후보 묶음의 누락·형식 오류는 제한된 횟수에 한해 해당 후보 ID만 다시 요청합니다. 요청하지 않은 ID나 중복 ID는 즉시, 누락·오류가 반복되면 시도 소진 뒤 `HYPOTHESIS_BATCH_OUTPUT_INVALID`로 차단합니다.
재개할 때 저장된 Pro/Con 근거와 인용도 다시 확인합니다. 이전 형식의 근거가 존재하지만 인용한 해시만 실제 입력에 없으면 해당 가설과 안전하게 되돌릴 수 있는 후속 단계만 다시 실행합니다. 원본·해시·실행 계보가 손상됐거나 파생 작업을 안전하게 되돌릴 수 없으면 `HYPOTHESIS_EVIDENCE_INVALID`로 차단하고 오래된 Finding·보고서를 현재 결과처럼 보여주지 않습니다. 이 상태를 취약점 부재나 완료로 해석하지 마세요.
이미 `STATIC_DONE`이 성공한 v2 `PARTIAL` 분석은 같은 ID의 `resume`에서 정적 누락을 다시 검사하지 않습니다. 저장된 정적 근거로 미완료 후보·표면·가설 작업을 이어가며, 누락 원인을 해결해 정적 범위를 다시 확인하려면 기존 분석은 보존하고 새 분석 ID로 시작하세요. 기존 v1 `PARTIAL` 분석은 같은 범위의 정적 누락을 재시도할 수 있습니다.
이미 의존성 환경 검증에 실패해 재시도 불가로 기록된 PoC는 wheel 묶음을 추가해도 같은 분석 ID의 `resume`으로 다시 열리지 않습니다. 새 묶음을 사용하려면 새 분석을 시작하세요. 신규 표면 탐색은 첫 문맥에서 관련 소스나 AST 사실이 생략되고 근거가 부족하다고 판정된 경우에만 확장 문맥을 한 차례 만들고, 필요하면 크기를 제한한 여러 부분으로 나누어 검토합니다. 확장 후에도 근거가 부족하면 미검토 표면으로 남으며 `PARTIAL`이 될 수 있습니다.
Codex CLI의 토큰 사용량은 호출이 끝난 뒤 확정되므로 `max_tokens`는 호출 전 기록된 누적 사용량을 기준으로 한 **소프트 한도**입니다. 마지막 요청에서 상한을 넘길 수 있고 공급자가 사용량을 제공하지 않은 실패 호출은 정확히 계측할 수 없으므로, 과금을 막는 하드 쿼터로 사용해서는 안 됩니다. 현재 OpenAI API는 요청별 신뢰 가능한 비용을 기록하지 못해 첫 비용 미확인 호출 뒤의 후속 API 요청을 차단합니다. Codex CLI도 실제 금액을 제공하지 않으므로 `max_cost_minor_units`로 청구액을 강제할 수 없습니다. 공급자 계정의 사용량·지출 한도를 별도로 확인하세요.
파일 문맥 공유와 표면별 탐색은 반복 프롬프트를 줄이려는 설계이지만, 실제 토큰·비용 절감률을 보장하지 않습니다. 기록된 프롬프트 바이트 수는 공급자가 보고한 토큰·청구액이 아닙니다. Codex는 한 분석에서 안전상 실제 호출을 하나씩 실행하고, 현재 OpenAI API 호출도 분석별 예산 잠금 아래 직렬화됩니다. 가설 동시성 설정만 올려도 유료 호출이 병렬화되지는 않습니다.
Finding이 생성된 경우에는 해당 ID로 PoC와 보고서를 확인할 수 있습니다.
`status`와 `result`의 `finding_count`는 현재 근거 기준으로 유효한 Finding 수입니다.
이전 판정까지 포함한 감사용 원본 기록 수는 JSON의 `raw_finding_count`로 별도
표시합니다. 자동 묶음은 단일 정적
Flask route에서 고정된 Python 소스와 입력→위험 호출의 직접 def-use를 검증한
경우에만 적용합니다. 명령 실행(CWE-78)에 더해 보수적으로 입증 가능한
SQLite SQL 주입(CWE-89), 반사형 XSS(CWE-79), SSRF(CWE-918), `eval`
(CWE-95), 파일 경로 사용(CWE-22)의 일부 패턴을 지원합니다. 저장형 XSS처럼
요청·저장소를 가로지르는 흐름, 복잡한 프레임워크·호출·동적 바인딩은
근거가 부족하면 절대 합치지 않습니다.
`finding_group_count`는 입증된 그룹과 미확정 단독 항목을 합친 **표시 묶음 수**이며,
`--format json`의
`finding_groups`에는 대표 `F-NNN`, 모든 원본 ID·가설·후보 출처·PoC 해시와
각 항목의 Scope 상태가 남습니다. 근거가 부족한 항목은
`GROUPING_UNDETERMINED` 단독 항목이며 `finding_group_undetermined_count`에
포함됩니다. CodeQL 경로 추적이 있는 결과와 추적이 없는 결과는 서로 다른
근거로 취급해 자동으로 합치지 않습니다. 미지원 CWE·프레임워크·표현도 이
상태로 남습니다. 대시보드의
표시 묶음은 현재 보고서를 열 수 있는 Finding만 대상으로 하므로 보고서 생성
전에는 현재 Finding 수보다 작을 수 있습니다. 묶음 근거 자체를 읽을 수 없는
과거·손상 기록은 묶음 수를
`null`로 표시하고 감사용 원본 기록은 보존합니다. 묶음은 표시 방식일 뿐
취약점 판정·정적 검사 완료·제보 허가를 바꾸지 않습니다.
자동·수동 의존성 준비로도 제품 의존성을 재현하지 못해 소스 전용 Docker 이미지만 만들 수 있으면 PoC 실행 전에 `POC_ENVIRONMENT_UNVERIFIED`로 차단하고 근거를 남깁니다. 자세한 내용은 [문제 해결](docs/troubleshooting.md)을 참고하세요.

```powershell
sastsimi poc F-001
sastsimi report show F-001
sastsimi report export F-001 --format markdown
sastsimi report export-group A-001 <group-id> --format json
```

`F-001`도 예시이며, Finding이 없으면 이 명령의 대상이 없습니다. 명령별
옵션과 재개·오류 처리 방법은 [사용법](docs/usage.md)과
[문제 해결](docs/troubleshooting.md)을 참고하세요.
`export-group`은 같은 입력→위험 동작 흐름이 **입증된** 둘 이상의 현재 Finding에
한해 영문·국문 검토 초안과 각 원본 보고서·PoC·증거를 담은 ZIP의 경로를
반환합니다. 알 수 없거나 근거가 손상된 그룹은 내보내지 않습니다. 원본 `F-NNN`
링크와 개별 ZIP은 계속 유지되며, 묶음이나 ZIP 생성은 취약점 확정 또는
제보 허가를 뜻하지 않습니다.

```powershell
sastsimi dashboard
```

읽기 전용 대시보드는 기본적으로
[http://127.0.0.1:8765](http://127.0.0.1:8765)에서 열립니다. 실행 중에는
터미널을 차지하므로 다른 명령은 새 PowerShell 창에서 실행하고, 종료할 때는
대시보드 터미널에서 `Ctrl+C`를 누르세요.
대시보드는 입증된 묶음만 하나의 카드 아래 표시합니다. 기본 전체 ZIP에는
입증된 묶음당 대표 보고서 하나와 대표·원본 ID의 매핑을 넣습니다. 명시적으로
원본 `F-NNN`을 선택하면 해당 보고서를 그대로 내보낼 수 있으며, 모든 원본
보고서·PoC·첨부 링크와 저장된 근거는 삭제하거나 덮어쓰지 않습니다.
과거 형식처럼 묶음 근거가 없는 보고서가 섞여 있으면, 입증된 그룹만 대표로
묶고 나머지는 원본 보고서로 유지합니다. 발표 ZIP 요약에 그룹 적용 범위와
원본 유지 ID를 표시합니다.
`PoC∙증거∙보고서` 탭에는 근거가 유효한 그룹의 별도 검토 ZIP 링크가 표시되고,
같은 화면에서 원본 Finding별 보고서와 첨부도 내려받을 수 있습니다.

## 분석 흐름과 결과물

```text
저장소와 commit 고정
→ Python 제품 코드 정적 검사
→ 후보 수집·Discovery 선별 + 보안 표면 인덱스
→ 파일별 후보 묶음에서 가설 등록·즉시 검증(필요 시 Docker PoC·Gate 포함)
→ 아직 미검토인 보안 표면만 보조 탐색·즉시 검증
→ 검증된 Primitive의 최종 Chaining 검토·새 자식 검증
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
- AST 사실은 파싱에 성공한 Python 제품 파일마다 별도 저장합니다. 새 AST 형식(v3)은 직접 호출과 호출 결과의 메서드를 구분해 `eval(...)`을 `super(...).eval(...)`과 같은 호출로 취급하지 않습니다. 보안 표면 인덱스(v2)는 속성 인자가 문자열 리터럴이 아닌 직접 `getattr(...)` 호출을 reflection 검토 힌트로 포함하며, 그 자체로 취약점이라고 판정하지 않습니다. 정적 번들의 소형 요약은 파일별 manifest 참조와 총건수를 포함하되 전체 사실을 복제하지 않습니다. v1 후보 가설은 해당 파일·줄 주변에서 고른 AST 사실을 최대 8 KiB로 전달하고, 신규 후보 파이프라인(v2)은 크기를 제한하고 민감정보를 제거한 파일별 공유 문맥을 사용합니다. 프롬프트에서 생략된 사실은 저장 누락이 아닙니다. 반대로 파싱 오류나 파일당 2 MiB 초과는 성공으로 세지 않고 미검증 범위로 남깁니다.
- 신규 v2의 `COMPLETE`는 계획된 정적 범위, 후보·가설 공급과 자식 검증, 최종 Chaining이 끝나고 후보의 `PENDING`·`ERROR` 및 미검토 보안 표면이 없다는 뜻입니다. 정적 미검증 제품 코드·파일×규칙 조합이나 미검토 보안 표면이 남으면 `PARTIAL`이며, 확인된 Finding이 있어도 저장소 전체를 완전히 검사했다는 의미는 아닙니다. 기존 v1은 저장 당시의 완료 조건으로 재개합니다. 후보 수, 가설 수, Finding 수는 서로 다른 집계입니다.
- 체크아웃 실패, 증거 손상, Agent 실행 실패처럼 부분 결과 자체를 신뢰할 수 없는 오류는 `PARTIAL`로 덮지 않고 `BLOCKED` 또는 `FAILED`로 남깁니다. 정적 단계가 완료되기 전의 재시도와 기존 v1의 같은 범위 정적 누락 재시도에는 `resume`을 사용할 수 있습니다. 성공한 v2 정적 단계의 누락은 새 분석 ID에서 다시 검사해야 합니다.
- 초기 검증에서 공격자 권한·외부 서비스 같은 전제가 입증되지 않거나, 고정 Python 배포본을 현재 환경에서 해결할 수 없다는 같은 시도의 receipt가 검증되면 해당 가설은 `INCONCLUSIVE`로 기록하고 PoC·Finding·제보 보고서를 만들지 않습니다. timeout·지원하지 않는 설치 방식·종료 근거 아티팩트 손상은 완료로 계산하지 않고 `BLOCKED`로 표시합니다.
- portable 환경 점검의 fixture 범위는 고정 snapshot `vfapi@f36f177e1a32`, `insecure-web@5d1b791bb6c2`, `dvpwa@a1d8f89fac2e` 세 곳으로 한정됩니다. 이는 Python 정적 범위와 PoC 환경 준비의 호환성 점검 범위일 뿐, 세 저장소의 최종 검증 완료·전체 취약점 발견·완전한 커버리지를 뜻하지 않습니다.
- 신규 v2의 보안 표면 분류가 놓친 경로는 표적 탐색 대상에도 잡히지 않을 수 있습니다. `COMPLETE`도 취약점 부재의 증명이 아니며, 중요한 코드 경계는 사람이 검토해야 합니다.
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
