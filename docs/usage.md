# 저장소 분석과 결과 확인

먼저 [설치 안내](installation.md)에 따라 `sastsimi setup`을 완료합니다.

## 빠른 길잡이

- [처음 분석할 때](#analyze): 저장소와 commit을 지정하고 진행률을 확인합니다.
- [중단되었거나 미완료 범위를 확인할 때](#resume): 상태를 조회하고 저장된 분석을 재개합니다.
- [진행과 근거를 웹에서 볼 때](#dashboard): 읽기 전용 대시보드를 엽니다.
- [Finding·PoC·보고서를 확인할 때](#results): 결과를 조회하고 검증된 자료를 내보냅니다.
- [일반 사용 명령의 범위를 확인할 때](#runtime): 실행 경로와 고급 옵션의 용도를 확인합니다.

<a id="analyze"></a>

## 1. 분석 시작

저장소 URL 또는 로컬 Git 경로와 정확한 commit SHA를 전달합니다.

```text
sastsimi analyze <URL-or-local-path> --commit <exact-SHA>
```

예시:

```text
sastsimi analyze https://github.com/adeyosemanputra/pygoat.git --commit 19d17cc8874861142b330636d068bbde54e86b85
```

Windows PowerShell에서 Dify의 고정된 공개 소스 commit을 분석하려면, 각 줄을 별도 한 줄 명령으로 실행합니다. 먼저 기존 설정의 Provider가 Codex `gpt-6-sol`인지 확인하세요. 이 명령은 저장소 코드를 로컬에서 분석하며 Dify 서비스에 요청하거나 제보를 전송하지 않습니다.

```powershell
.\.venv\Scripts\Activate.ps1
sastsimi analyze https://github.com/langgenius/dify.git --commit 8387590ace4a094de812b7847fc6a4c3a27cd52b
```

사람이 보는 기본 출력은 다음처럼 간단합니다.

```text
[██████------------------] 25% 4/16 PRO_CON_DONE
분석 ID: A-001
현재 단계: PRO_CON_DONE
대시보드: http://127.0.0.1:8765/analyses/A-001
```

v2의 `기본 분석 작업 진행률`은 현재 알려진 기본 작업 가운데 종료 결과가 검증된 작업의 비율입니다.

- 보안 표면의 `COVERED`와 검토는 끝났으나 근거가 부족한 `INSUFFICIENT`는 **작업 완료**로 셉니다. 미검토 `UNCOVERED`는 세지 않습니다. `INSUFFICIENT`가 검사 성공이나 취약점 반증이 되는 것은 아닙니다.
- 과거 `HOLD`를 다시 검토하는 새 PoC·후속 Gate·보고서 체인은 기본 비율에서 제외하고 별도 현황으로 표시합니다.
- `100% / PARTIAL`은 기본 작업만 끝났다는 뜻입니다. 전체 범위 검증, 확정 Finding, 제보 가능을 뜻하지 않습니다.
- 비-v2 분석의 기존 계산은 유지합니다. 어느 비율도 시간·비용 또는 저장소 전체 커버리지가 아닙니다. Chaining으로 새 기본 가설이 생기면 분모가 늘어 비율이 일시적으로 낮아질 수 있습니다.

한 가설이 `BLOCKED`여도 다른 가설의 단계가 실행 중이면 전체 상태는 `RUNNING`과 현재 가설을 표시합니다. 실행이 끝나면 남은 `FAILED` 또는 `BLOCKED`를 표시합니다.

자동화에서 구조화된 값만 필요하면 다음을 사용합니다.

```text
sastsimi analyze <repo> --commit <exact-SHA> --format json
```

이때 진행 애니메이션은 출력하지 않습니다. 사람용 출력에서도 진행 표시를 끄려면 `--no-progress`를 사용합니다.

<a id="resume"></a>

## 2. 상태와 미완료 범위 재개

```text
sastsimi status A-001
sastsimi resume A-001
```

### 재개할 때 재사용하는 기록

`resume`은 저장된 정확한 근거와 같은 commit의 Docker image를 재사용하고 끝나지 않은 단계부터 이어갑니다. 신규 v2 분석은 파일별 후보 묶음, 후보 ID별 결과, 가설 단계, 표면별 탐색의 저장된 입력 해시를 검증해 완료 항목을 재사용합니다. 묶음 응답에서 일부 ID가 빠졌다면 이미 확정한 ID를 다시 생성하지 않고 누락 ID만 제한적으로 시도합니다.

기존 v1 분석의 자유 탐색 페이지·완료 표시는 그대로 유지해 재개하며 v2의 표면별 표시와 섞지 않습니다.

이미 `STATIC_DONE`이 성공했고 정적 coverage가 `PARTIAL`인 v2 분석은 같은 분석 ID의 `resume`에서 그 정적 근거를 고정해 재사용합니다. 후보·표면·가설의 미완료 작업은 이어가지만 미검증 정적 파일×규칙 조합을 재검사하거나 정적 상태를 `FULL`로 바꾸지는 않습니다. 정적 누락의 원인을 해결한 뒤 전체 범위를 다시 검사하려면 기존 분석 데이터는 보존하고 새 분석 ID로 `analyze`를 시작하세요.

기존 v1의 같은 범위 `PARTIAL` 재개는 미검증 정적 조합을 다시 시도할 수 있습니다.

새 AST 사실 형식(v3)과 보안 표면 인덱스(v2)는 이전 기록과 구분됩니다. 기존 기록은 저장된 뜻대로 재개하며 새 호출·표면 분류를 소급 적용하지 않습니다. 새 분류로 전체 범위를 검사하려면 새 분석을 시작하세요.

신규 표면 탐색에서 첫 문맥이 관련 소스나 AST 사실을 생략했고 Agent가 근거 부족을 반환하면, 한 차례 확장 문맥을 만들어 크기를 제한한 부분별로 검토합니다. 각 결과는 표면·문맥·정적 근거의 정확한 해시와 버전으로 저장·재사용하며, 확장 후에도 부족한 근거는 미검토 표면과 `PARTIAL` 제한으로 남습니다.

### 사용량 한도 확인

`max_tokens`는 호출 **전에 기록된 누적 사용량**을 확인하는 소프트 한도입니다. Codex CLI는 최종 토큰 수를 호출 후에 알려 주므로 마지막 요청에서 한도를 초과할 수 있습니다. 실패 호출의 사용량이 제공되지 않으면 실제 과금을 정확히 계측할 수도 없습니다.

현재 OpenAI API는 요청별 청구액을 신뢰 가능하게 기록하지 못해 첫 비용 미확인 API 호출 뒤의 후속 API 요청을 `LLM_COST_USAGE_UNAVAILABLE`로 차단할 수 있습니다. Codex CLI도 금액을 제공하지 않으므로 `max_cost_minor_units`가 실제 지출 상한은 아닙니다. 정확한 과금 제한이 필요하면 공급자 측 사용량·지출 한도를 별도로 설정하세요.

### 정적 검사 대상과 Coverage

coverage artifact가 확인된 경우 `sastsimi status A-001`과 `sastsimi status A-001 --format json`은 검증된 파일×규칙 수와 별도로 미검증 조합, 스캔할 수 없었던 Python 제품 파일, 지원되지 않는 제품 파일, 제외 테스트, 대상 밖 제품 코드의 개수와 경로·이유 미리보기를 보여 줍니다. 미리보기는 전체 목록이 아니며 coverage artifact에 원장이 남습니다.

OpenGrep은 테스트 전용 파일을 제외한 Python `.py` 제품 코드만 명시적 묶음으로 검사합니다. 배포 manifest가 제품 진입점으로 선언한 `tests/` 경로는 실제 제품 코드로 취급합니다. manifest가 손상되어 테스트 전용인지 확인할 수 없는 파일은 제외 성공이 아니라 미지원 제품 코드로 남깁니다.

`.pyi`, JS/TS와 기타 비Python 파일은 Python AST·OpenGrep·Semgrep·CodeQL의 파일×규칙 검사 분모에서 빠집니다. JS/TS 제품 코드는 대상 밖 코드로 경로·이유를 별도 표시하며 분석 전체는 `PARTIAL`로 남습니다. 제외한 테스트 파일도 경로·이유를 기록하고 검사 성공으로 세지 않습니다. Dockerfile과 의존성 파일은 PoC 환경 설정을 위한 별도 검증 메타데이터입니다.

같은 분석 ID·저장소·commit·Python 범위·규칙·도구 지문과 CAS 해시가 일치하는 파일·규칙 증거만 재사용합니다. 범위가 바뀌면 새 분석 ID가 필요합니다. 검증된 부분과 정확한 coverage artifact가 있으면 `STATIC_DONE`은 성공한 근거 게시로 기록되고 후속 Agent가 진행될 수 있습니다. 미검증 Python 조합·설정된 보조 엔진 오류는 별도 누락으로 남아 최종 상태를 `PARTIAL`로 제한합니다. Python 제품 소스나 검증 근거가 없거나 증거 무결성이 깨지면 `BLOCKED`입니다.

파싱 경고 파일이 `paths.scanned`에 있어도 해당 파일·규칙은 완료로 세지 않습니다. 선택형 Semgrep fallback은 OpenGrep이 검증하지 못한 조합만 재검사합니다. OpenGrep이 실패해도 Python AST와 설정된 CodeQL 결과는 보존합니다.

AST 파싱 실패·용량 초과와 Semgrep 실패도 이유로 남기며, 사용 가능한 검증 부분이 있으면 `PARTIAL`로 진행할 수 있습니다. 어떤 엔진의 불완전한 raw hit도 다른 엔진의 완료 사실만으로 Agent 후보가 되지 않습니다.

### 실행 중 작업 공간과 완료 상태

분석 중에는 데이터 디렉터리의 전용 `workspaces/<workspace-id>` checkout을 다른 프로세스나 편집기로 수정하지 마세요. 실행 전 commit과 작업 트리 상태를 확인하지만, 검사 도중 변경된 파일을 분석하는 작업은 지원하지 않습니다. 동시 수정이 의심되면 그 결과를 제보 근거로 쓰지 말고 새 분석 ID에서 다시 시작하세요.

정적 검사 전체의 180초 종료 시각은 적용하지 않습니다. 기존 설정의 `static_scan_pass_seconds`는 읽어도 일정에 영향을 주지 않습니다. 각 도구 호출은 유한하게 제한하며 시간 초과 묶음은 분할합니다. 검증되지 않은 단일 파일·규칙은 명시적 누락으로 남습니다.

신규 v2에서 `COMPLETE`는 후보와 표면의 가설 공급, 등록된 모든 자식의 검증, 최종 Chaining이 끝나고 후보의 `PENDING`·`ERROR`, 미검토 보안 표면, 정적 미검증 범위 및 대상 밖 제품 코드가 없을 때만 가능합니다. 검증 가능한 정적 누락·JS/TS 제품 코드나 미검토 보안 표면이 남으면 `PARTIAL`입니다. Agent 오류·손상된 근거는 `BLOCKED` 또는 `FAILED`가 우선하며 비용 한도 소진은 `PAUSED`로 구분합니다.

### Semgrep fallback 설정과 실행

Semgrep fallback을 켜면 OpenGrep 제품 파일 묶음의 각 실행을 최대 120초로 제한합니다. OpenGrep은 최대 64파일·소스 합계 512 KiB의 묶음에서 시작하고, 시간 초과가 나면 단일 파일까지 나눕니다. 이어지는 Semgrep 재검사 묶음은 최대 128파일·소스 합계 512 KiB와 Windows 명령줄 24,000 UTF-16 단위로 제한합니다. 길이 제한을 넘는 단일 경로는 별도 미검증으로 남기고 다른 경로는 계속 검사합니다.

결과 JSON을 크기 제한이 있는 분석별 임시 파일에 받으며, 이전 성공 기록과 새 묶음의 부분 성공은 원본을 다시 검증한 뒤에만 인정합니다. 새 성공 기록은 재개 때 묶음 경계가 바뀌어도 같은 commit·Python 범위·규칙·도구 지문에서 파일·규칙별로 다시 검증해 재사용합니다. Semgrep 한 묶음이 120초 안에 끝나지 않으면 더 작게 나누고, 단일 파일의 프로세스 시간 초과 또는 JSON `Timeout`은 `--timeout 30`으로 한 번만 재시도합니다. 기본 누적 실행시간은 `unlimited`지만 개별 호출과 재시도는 계속 제한됩니다. 같은 파일의 결정적 파싱 오류나 길이 제한은 억지로 성공 처리하지 않습니다.

`sastsimi dashboard`의 정적 검사 항목에서 미검증 Python 코드의 상대 경로·규칙·이유를 최대 100개 확인할 수 있고 전체 목록은 해당 분석의 coverage artifact에 보존됩니다.

Windows PowerShell의 선택형 설정 명령은 각각 한 줄입니다. `.venv`를 활성화한 터미널에서 실행하고 기존 `setup`의 사용 제한·모델 옵션이 있다면 다시 지정하세요. [Semgrep CE](https://semgrep.dev/products/community-edition/)는 Windows에서 Python으로 설치할 수 있고 로컬 규칙 실행에 로그인이 필요하지 않습니다.

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install semgrep
semgrep --version
sastsimi setup --non-interactive --auth subscription --provider codex --model gpt-6-sol --profile full --docker-network none --semgrep-fallback
sastsimi resume A-001
```

설정 변경 전 이미 진행 중인 분석은 먼저 종료될 때까지 기다리세요. `--semgrep-fallback`을 사용하지 않으면 Semgrep은 필수가 아닙니다. 누락이 있으면 coverage에 이유가 남고, 신뢰할 수 있는 검증 부분이 있으면 `PARTIAL`로 진행할 수 있습니다.

### 정책과 동시 실행

최초 분석에서 수집해 저장한 공식 정책도 분석마다 하나의 고정된 snapshot으로 재사용합니다. `resume`은 정책을 다시 조회하지 않으며, 인터넷의 정책이 바뀌었더라도 이전 Scope Gate와 PoC 기록을 조용히 바꾸지 않습니다. 새 정책으로 판단하려면 새 분석을 시작합니다.

같은 분석을 다른 PowerShell에서 이미 실행 중이면 두 번째 `resume`은 중복 분석을 시작하지 않고 현재 상태와 `ANALYSIS_ALREADY_RUNNING` 이유를 반환합니다. 첫 번째 프로세스가 끝난 뒤 다시 재개할 수 있습니다. 잠금은 프로세스가 비정상 종료돼도 운영체제가 해제합니다.

### PoC와 중단된 프로세스 재개

자동 복구 횟수를 이미 소진한 PoC는 `resume`만으로 새 시도를 만들지 않습니다. 실행 오류는 계속 `BLOCKED`로 남고 취약점 `FALSE` 판정이 아닙니다. 다만 과거 기록의 마지막 PoC가 정상 실행됐고 근거 부족 해석이 정확한 artifact로 검증되면, 명시적 `resume`에서 그 가설만 `INCONCLUSIVE`로 종결할 수 있습니다.

PoC 후보 작성 단계는 인용된 Python 클래스의 실제 요청 경로가 다른 Python 파일에서 읽는 Git 추적 XML에 등록된 경우, 고정 커밋의 파일에서 범위가 제한된 클래스·경로·해시 힌트를 추가할 수 있습니다. 이 값은 신뢰되지 않는 선택형 문맥이며 정적 검사 성공이나 취약점 증거로 계산하지 않습니다. 조회가 불완전하거나 힌트가 없다고 경로가 없다고 판단하지 않으며, 최종 판정에는 실제 실행된 PoC가 필요합니다.

의존성 검증에 실패해 재시도 불가로 저장된 PoC도 wheel 묶음을 추가한 뒤 같은 분석 ID에서 다시 실행되지 않습니다. 새 오프라인 묶음은 새 분석에 적용하세요. 준비와 제한은 [Docker 또는 PoC 실패](troubleshooting.md#docker-또는-poc-실패)를 참고하세요.

분석 프로세스가 강제로 종료되면 마지막 `RUNNING` 체크포인트가 남을 수 있습니다. 프로세스가 실제로 끝났는지 확인한 뒤 `resume`으로 중단 단계를 조정하세요. 새 Agent 호출이 발생할 수 있으므로 사용량도 확인해야 합니다. 시간만 보고 정상적인 장시간 PoC를 실패로 간주하지는 않습니다.

### 후보 파이프라인의 재개

선택형 `facts_survey`와 병렬 처리 설정도 성공한 가설·Agent 단계를 중복 실행하지 않도록 체크포인트를 사용합니다. 신규 후보 파이프라인(v2)은 파일별 후보 묶음의 유효한 가설을 저장한 직후 검증을 시작하고, 그 뒤에도 검토 근거가 부족한 보안 표면만 제한된 문맥으로 탐색합니다. 이전 분석(v1)은 저장된 소스 페이지와 옛 경로로 재개합니다.

현재 v2 자식 실행과 OpenAI API 유료 호출은 직렬화되므로 가설 동시성 설정만 올려도 호출이 병렬화되지 않습니다. 설정과 주의사항은 [Provider 설정](provider-setup.md#선택형-분석-설정)을 참조하세요.

### 새 분석이 필요할 수 있는 변경

다음 변경은 이전 실행을 억지로 재사용하지 않고 새 분석이 필요할 수 있습니다.

- 저장소 또는 commit 변경
- Provider·model 변경
- 정적 분석 규칙 변경
- 이전 데이터의 exact reference 불일치

### 후보·가설·Finding은 다른 집계입니다

정적 도구가 실제 검증한 원본 결과는 아티팩트로 보존하고 안정적인 ID의 후보로 등록합니다. 후보 근거는 다음처럼 구분합니다.

- `ENTRY_POINT`: Python 요청 입력 규칙에서 `candidate_kind`로 명시한 입력 지점. 다른 경고를 입력 지점으로 추정하지 않습니다.
- `FLOW`: 실제 확인된 source→sink 경로. CodeQL SARIF의 한 결과에 여러 `codeFlows`·`threadFlows`가 있다면 trace마다 별도 후보입니다.
- `HINT`: 개별 도구가 제시한 위치 힌트. 따로 나온 source와 sink를 임의로 연결하지 않습니다.

동일 위치·trace의 중복만 합치고, 원본 아티팩트 참조와 행 인덱스를 보존합니다. 파일×규칙 검사 횟수는 후보 수와 별개입니다.

Discovery는 작은 배치로 후보를 검토하고 이유와 함께 상태를 기록합니다.

- `INCLUDE`: 심층 검토 대상
- `EXCLUDE`: 제외
- `UNDECIDED`: 불확실하지만 심층 검토 대상
- `PENDING`: 아직 처리하지 않음
- `ERROR`: Agent 실행 또는 출력 형식 실패. 불확실 판정과 다릅니다.

신규 v2는 같은 파일의 선별 후보를 크기 제한이 있는 공유 문맥으로 묶습니다. 공격자 통제 입력·민감 동작·도달 가능성·경계 등의 코드 근거가 있는 가설만 등록하고, 구체적 근거가 있지만 불확실한 가설은 후속 Pro·Con·PoC 검증으로 보냅니다. 해당 묶음의 가설은 다음 묶음이나 전체 자유 탐색이 끝나기를 기다리지 않고 검증합니다. Discovery는 취약점 확정 판정이 아닙니다. 후속 가설의 `INCONCLUSIVE`는 근거 부족으로 끝났다는 뜻입니다.

프롬프트는 개별 호출 크기에 맞춰 묶거나 나눕니다. 후보·가설 전체를 고정 총수 상한으로 잘라 버리지 않지만, 개별 호출 시간·크기·재시도와 Chaining 깊이·중복 방지는 유한합니다. 신규 v2의 파일별 공유 문맥과 미검토 표면 문맥에도 민감정보 제거와 크기 제한을 적용합니다. 위치·줄 수를 유지한 안전한 문맥을 만들 수 없으면 모델에 보내지 않고 오류 또는 미검토 범위로 남깁니다. 원본 정적 근거는 별도 artifact에 보존합니다. 한 후보가 호출 크기를 넘거나 응답 형식 검증에 반복 실패하면 `ERROR`로 남고 다른 후보의 성공은 유지됩니다. 한도 소진으로 `PAUSED`가 되면 남은 작업은 재개 가능하게 보존됩니다. 프롬프트 바이트 감소는 토큰·비용 절감을 보장하지 않으며 공급자가 보고하지 않은 비용을 추정해 0으로 기록하지 않습니다.

<a id="dashboard"></a>

## 3. 읽기 전용 대시보드

분석과 같은 사용자 데이터 폴더를 사용하는 터미널에서 실행하고 `http://127.0.0.1:8765`를 엽니다. 분석별 주소는 `/analyses/A-001`입니다.

```text
sastsimi dashboard
```

상단의 진행률과 `COMPLETE`/`PARTIAL`/`BLOCKED`를 함께 읽고, Coverage 탭에서 미검증 Python 파일·규칙과 대상 밖 제품 코드를 확인하세요. `100%`만으로 전체 범위 검증이나 취약점 확정을 주장할 수 없습니다. 화면은 저장된 자료를 읽기만 하며 취소·재시도·판정 변경·공개 승인을 수행하지 않습니다. 탭별 조회, 표시 한도, Scope Gate가 적용되는 다운로드는 [대시보드와 결과 상세](usage/dashboard-and-results.md#dashboard)에 있습니다. 짧은 발표 순서는 [대시보드 발표 시나리오](dashboard-demo.md)를 따르세요.

<a id="results"></a>

## 4. 결과·PoC·보고서

```text
sastsimi result A-001
sastsimi poc F-001
sastsimi report show F-001
sastsimi report export F-001 --format markdown
sastsimi report export-group A-001 <group-id> --format json
```

`result`는 분석 상태와 Finding을, `poc`는 실행으로 검증된 PoC만 보여 줍니다. 새 보고서의 영문·국문 첨부, 그룹 ZIP, 정확한 manifest·해시와 Scope Gate 조건은 [결과·PoC·보고서 상세](usage/dashboard-and-results.md#results)를 확인하세요. `PARTIAL`에 남은 미검증 범위, `UNCERTAIN` 정책 판정이나 `Needs review` 필드를 전체 검증·외부 제보 승인으로 바꾸어 해석하지 마세요. SASTSIMI는 자동으로 외부에 제출하지 않습니다.

<a id="runtime"></a>

## 5. 실행 경로

저장소 분석은 `SimpleRuntime` 한 경로만 사용합니다. `setup`이 저장한 기본 설정을
읽어 실제 저장소 분석을 시작하며, 준비 실패를 다른 시험용 분석 경로로 대체하지
않습니다.

`--data-dir`, `--profile`, `evaluate`, `capability`, `onboarding` 같은 세부 명령과
옵션은 문제 진단 또는 고급 운영을 위해 유지합니다. 일반 사용자는 위의 공개 명령만
사용하면 됩니다.
