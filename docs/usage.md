# 저장소 분석과 결과 확인

먼저 [설치 안내](installation.md)에 따라 `sastsimi setup`을 완료합니다.

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

진행률은 시간·비용이나 저장소 전체 검토율이 아니라 저장에 성공한 checkpoint와 현재 알려진 작업 수의 비율입니다. 후보 수집·선별·심층 분석은 각각 별도 집계하며, Chaining이 새 가설을 만들면 전체 작업 수가 늘어 비율이 일시적으로 낮아질 수 있습니다.
한 가설이 `BLOCKED`여도 다른 가설의 단계가 실제로 실행 중이면 전체 상태는 `RUNNING`과 현재 가설을 표시합니다. 실행이 끝나면 남은 `FAILED` 또는 `BLOCKED`를 표시합니다.

자동화에서 구조화된 값만 필요하면 다음을 사용합니다.

```text
sastsimi analyze <repo> --commit <exact-SHA> --format json
```

이때 진행 애니메이션은 출력하지 않습니다. 사람용 출력에서도 진행 표시를 끄려면 `--no-progress`를 사용합니다.

## 2. 상태와 미완료 범위 재개

```text
sastsimi status A-001
sastsimi resume A-001
```

`resume`은 저장된 정확한 근거와 같은 commit의 Docker image를 재사용하고 끝나지 않은 단계부터 이어갑니다. 신규 v2 분석은 파일별 후보 묶음, 후보 ID별 결과, 가설 단계, 표면별 탐색의 저장된 입력 해시를 검증해 완료 항목을 재사용합니다. 묶음 응답에서 일부 ID가 빠졌다면 이미 확정한 ID를 다시 생성하지 않고 누락 ID만 제한적으로 시도합니다. 기존 v1 분석의 자유 탐색 페이지·완료 표시는 그대로 유지해 재개하며 v2의 표면별 표시와 섞지 않습니다.
이미 `STATIC_DONE`이 성공했고 정적 coverage가 `PARTIAL`인 v2 분석은 같은 분석 ID의 `resume`에서 그 정적 근거를 고정해 재사용합니다. 후보·표면·가설의 미완료 작업은 이어가지만 미검증 정적 파일×규칙 조합을 재검사하거나 정적 상태를 `FULL`로 바꾸지는 않습니다. 정적 누락의 원인을 해결한 뒤 전체 범위를 다시 검사하려면 기존 분석 데이터는 보존하고 새 분석 ID로 `analyze`를 시작하세요. 기존 v1의 같은 범위 `PARTIAL` 재개는 미검증 정적 조합을 다시 시도할 수 있습니다.
새 AST 사실 형식(v3)과 보안 표면 인덱스(v2)는 이전 기록과 구분됩니다. 기존 기록은 저장된 뜻대로 재개하며 새 호출·표면 분류를 소급 적용하지 않습니다. 새 분류로 전체 범위를 검사하려면 새 분석을 시작하세요. 신규 표면 탐색에서 첫 문맥이 관련 소스나 AST 사실을 생략했고 Agent가 근거 부족을 반환하면, 한 차례 확장 문맥을 만들어 크기를 제한한 부분별로 검토합니다. 각 결과는 표면·문맥·정적 근거의 정확한 해시와 버전으로 저장·재사용하며, 확장 후에도 부족한 근거는 미검토 표면과 `PARTIAL` 제한으로 남습니다.
`max_tokens`는 호출 **전에 기록된 누적 사용량**을 확인하는 소프트 한도입니다. Codex CLI는 최종 토큰 수를 호출 후에 알려 주므로 마지막 요청에서 한도를 초과할 수 있습니다. 실패 호출의 사용량이 제공되지 않으면 실제 과금을 정확히 계측할 수도 없습니다. 현재 OpenAI API는 요청별 청구액을 신뢰 가능하게 기록하지 못해 첫 비용 미확인 API 호출 뒤의 후속 API 요청을 `LLM_COST_USAGE_UNAVAILABLE`로 차단할 수 있습니다. Codex CLI도 금액을 제공하지 않으므로 `max_cost_minor_units`가 실제 지출 상한은 아닙니다. 정확한 과금 제한이 필요하면 공급자 측 사용량·지출 한도를 별도로 설정하세요.
coverage artifact가 확인된 경우 `sastsimi status A-001`과 `sastsimi status A-001 --format json`은 검증된 파일×규칙 수와 별도로 미검증 조합, 스캔할 수 없었던 Python 제품 파일, 지원되지 않는 제품 파일, 제외 테스트, 대상 밖 제품 코드의 개수와 경로·이유 미리보기를 보여 줍니다. 미리보기는 전체 목록이 아니며 coverage artifact에 원장이 남습니다.
OpenGrep은 테스트 전용 파일을 제외한 Python `.py` 제품 코드만 명시적 묶음으로 검사합니다. 배포 manifest가 제품 진입점으로 선언한 `tests/` 경로는 실제 제품 코드로 취급합니다. manifest가 손상되어 테스트 전용인지 확인할 수 없는 파일은 제외 성공이 아니라 미지원 제품 코드로 남깁니다. `.pyi`, JS/TS와 기타 비Python 파일은 Python AST·OpenGrep·Semgrep·CodeQL의 파일×규칙 검사 분모에서 빠집니다. JS/TS 제품 코드는 대상 밖 코드로 경로·이유를 별도 표시하며 분석 전체는 `PARTIAL`로 남습니다. 제외한 테스트 파일도 경로·이유를 기록하고 검사 성공으로 세지 않습니다. Dockerfile과 의존성 파일은 PoC 환경 설정을 위한 별도 검증 메타데이터입니다. 같은 분석 ID·저장소·commit·Python 범위·규칙·도구 지문과 CAS 해시가 일치하는 파일·규칙 증거만 재사용합니다. 범위가 바뀌면 새 분석 ID가 필요합니다. 검증된 부분과 정확한 coverage artifact가 있으면 `STATIC_DONE`은 성공한 근거 게시로 기록되고 후속 Agent가 진행될 수 있습니다. 미검증 Python 조합·설정된 보조 엔진 오류는 별도 누락으로 남아 최종 상태를 `PARTIAL`로 제한합니다. Python 제품 소스나 검증 근거가 없거나 증거 무결성이 깨지면 `BLOCKED`입니다.
파싱 경고 파일이 `paths.scanned`에 있어도 해당 파일·규칙은 완료로 세지 않습니다. 선택형 Semgrep fallback은 OpenGrep이 검증하지 못한 조합만 재검사합니다. OpenGrep이 실패해도 Python AST와 설정된 CodeQL 결과는 보존합니다. AST 파싱 실패·용량 초과와 Semgrep 실패도 이유로 남기며, 사용 가능한 검증 부분이 있으면 `PARTIAL`로 진행할 수 있습니다. 어떤 엔진의 불완전한 raw hit도 다른 엔진의 완료 사실만으로 Agent 후보가 되지 않습니다.

분석 중에는 데이터 디렉터리의 전용 `workspaces/<workspace-id>` checkout을 다른 프로세스나 편집기로 수정하지 마세요. 실행 전 commit과 작업 트리 상태를 확인하지만, 검사 도중 변경된 파일을 분석하는 작업은 지원하지 않습니다. 동시 수정이 의심되면 그 결과를 제보 근거로 쓰지 말고 새 분석 ID에서 다시 시작하세요.

정적 검사 전체의 180초 종료 시각은 적용하지 않습니다. 기존 설정의 `static_scan_pass_seconds`는 읽어도 일정에 영향을 주지 않습니다. 각 도구 호출은 유한하게 제한하며 시간 초과 묶음은 분할합니다. 검증되지 않은 단일 파일·규칙은 명시적 누락으로 남습니다. 신규 v2에서 `COMPLETE`는 후보와 표면의 가설 공급, 등록된 모든 자식의 검증, 최종 Chaining이 끝나고 후보의 `PENDING`·`ERROR`, 미검토 보안 표면, 정적 미검증 범위 및 대상 밖 제품 코드가 없을 때만 가능합니다. 검증 가능한 정적 누락·JS/TS 제품 코드나 미검토 보안 표면이 남으면 `PARTIAL`입니다. Agent 오류·손상된 근거는 `BLOCKED` 또는 `FAILED`가 우선하며 비용 한도 소진은 `PAUSED`로 구분합니다.

Semgrep fallback을 켜면 OpenGrep 제품 파일 묶음의 각 실행을 최대 120초로 제한합니다. OpenGrep은 최대 64파일·소스 합계 512 KiB의 묶음에서 시작하고, 시간 초과가 나면 단일 파일까지 나눕니다. 이어지는 Semgrep 재검사 묶음은 최대 128파일·소스 합계 512 KiB와 Windows 명령줄 24,000 UTF-16 단위로 제한합니다. 길이 제한을 넘는 단일 경로는 별도 미검증으로 남기고 다른 경로는 계속 검사합니다. 결과 JSON을 크기 제한이 있는 분석별 임시 파일에 받으며, 이전 성공 기록과 새 묶음의 부분 성공은 원본을 다시 검증한 뒤에만 인정합니다. 새 성공 기록은 재개 때 묶음 경계가 바뀌어도 같은 commit·Python 범위·규칙·도구 지문에서 파일·규칙별로 다시 검증해 재사용합니다. Semgrep 한 묶음이 120초 안에 끝나지 않으면 더 작게 나누고, 단일 파일의 프로세스 시간 초과 또는 JSON `Timeout`은 `--timeout 30`으로 한 번만 재시도합니다. 기본 누적 실행시간은 `unlimited`지만 개별 호출과 재시도는 계속 제한됩니다. 같은 파일의 결정적 파싱 오류나 길이 제한은 억지로 성공 처리하지 않습니다. `sastsimi dashboard`의 정적 검사 항목에서 미검증 Python 코드의 상대 경로·규칙·이유를 최대 100개 확인할 수 있고 전체 목록은 해당 분석의 coverage artifact에 보존됩니다.

Windows PowerShell의 선택형 설정 명령은 각각 한 줄입니다. `.venv`를 활성화한 터미널에서 실행하고 기존 `setup`의 사용 제한·모델 옵션이 있다면 다시 지정하세요. [Semgrep CE](https://semgrep.dev/products/community-edition/)는 Windows에서 Python으로 설치할 수 있고 로컬 규칙 실행에 로그인이 필요하지 않습니다.

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install semgrep
semgrep --version
sastsimi setup --non-interactive --auth subscription --provider codex --model gpt-6-sol --profile full --docker-network none --semgrep-fallback
sastsimi resume A-001
```

설정 변경 전 이미 진행 중인 분석은 먼저 종료될 때까지 기다리세요. `--semgrep-fallback`을 사용하지 않으면 Semgrep은 필수가 아닙니다. 누락이 있으면 coverage에 이유가 남고, 신뢰할 수 있는 검증 부분이 있으면 `PARTIAL`로 진행할 수 있습니다.
최초 분석에서 수집해 저장한 공식 정책도 분석마다 하나의 고정된 snapshot으로 재사용합니다. `resume`은 정책을 다시 조회하지 않으며, 인터넷의 정책이 바뀌었더라도 이전 Scope Gate와 PoC 기록을 조용히 바꾸지 않습니다. 새 정책으로 판단하려면 새 분석을 시작합니다.
같은 분석을 다른 PowerShell에서 이미 실행 중이면 두 번째 `resume`은 중복 분석을 시작하지 않고 현재 상태와 `ANALYSIS_ALREADY_RUNNING` 이유를 반환합니다. 첫 번째 프로세스가 끝난 뒤 다시 재개할 수 있습니다. 잠금은 프로세스가 비정상 종료돼도 운영체제가 해제합니다.
자동 복구 횟수를 이미 소진한 PoC는 `resume`만으로 새 시도를 만들지 않습니다. 실행 오류는 계속 `BLOCKED`로 남고 취약점 `FALSE` 판정이 아닙니다. 다만 과거 기록의 마지막 PoC가 정상 실행됐고 근거 부족 해석이 정확한 artifact로 검증되면, 명시적 `resume`에서 그 가설만 `INCONCLUSIVE`로 종결할 수 있습니다.
PoC 후보 작성 단계는 인용된 Python 클래스의 실제 요청 경로가 다른 Python 파일에서 읽는 Git 추적 XML에 등록된 경우, 고정 커밋의 파일에서 범위가 제한된 클래스·경로·해시 힌트를 추가할 수 있습니다. 이 값은 신뢰되지 않는 선택형 문맥이며 정적 검사 성공이나 취약점 증거로 계산하지 않습니다. 조회가 불완전하거나 힌트가 없다고 경로가 없다고 판단하지 않으며, 최종 판정에는 실제 실행된 PoC가 필요합니다.
의존성 검증에 실패해 재시도 불가로 저장된 PoC도 wheel 묶음을 추가한 뒤 같은 분석 ID에서 다시 실행되지 않습니다. 새 오프라인 묶음은 새 분석에 적용하세요. 준비와 제한은 [Docker 또는 PoC 실패](troubleshooting.md#docker-또는-poc-실패)를 참고하세요.
분석 프로세스가 강제로 종료되면 마지막 `RUNNING` 체크포인트가 남을 수 있습니다. 프로세스가 실제로 끝났는지 확인한 뒤 `resume`으로 중단 단계를 조정하세요. 새 Agent 호출이 발생할 수 있으므로 사용량도 확인해야 합니다. 시간만 보고 정상적인 장시간 PoC를 실패로 간주하지는 않습니다.

선택형 `facts_survey`와 병렬 처리 설정도 성공한 가설·Agent 단계를 중복 실행하지 않도록 체크포인트를 사용합니다. 신규 후보 파이프라인(v2)은 파일별 후보 묶음의 유효한 가설을 저장한 직후 검증을 시작하고, 그 뒤에도 검토 근거가 부족한 보안 표면만 제한된 문맥으로 탐색합니다. 이전 분석(v1)은 저장된 소스 페이지와 옛 경로로 재개합니다. 현재 v2 자식 실행과 OpenAI API 유료 호출은 직렬화되므로 가설 동시성 설정만 올려도 호출이 병렬화되지 않습니다. 설정과 주의사항은 [Provider 설정](provider-setup.md#선택형-분석-설정)을 참조하세요.

다음 변경은 이전 실행을 억지로 재사용하지 않고 새 분석이 필요할 수 있습니다.

- 저장소 또는 commit 변경
- Provider·model 변경
- 정적 분석 규칙 변경
- 이전 데이터의 exact reference 불일치

### 후보·가설·Finding은 다른 집계입니다

정적 도구가 실제 검증한 원본 결과는 아티팩트로 보존하고 안정적인 ID의 후보로 등록합니다. 후보의 근거 수준은 입력 지점(`ENTRY_POINT`), 실제 확인된 source→sink 경로(`FLOW`), 개별 도구 힌트(`HINT`)로 구분합니다. 따로 나온 source와 sink를 임의의 흐름으로 합치지 않습니다. 파일×규칙 검사 횟수도 후보 수가 아닙니다.
현재 Python 요청 입력 규칙의 명시적 `candidate_kind`만 `ENTRY_POINT`로 분류하며 다른 경고를 입력 지점으로 추정하지 않습니다. CodeQL SARIF의 한 결과에 여러 `codeFlows`·`threadFlows`가 있으면 개별 trace마다 후보를 만들고, 동일 위치·trace의 중복만 합칩니다. 각 후보에는 원본 결과의 아티팩트 참조와 행 인덱스를 유지합니다.

Discovery는 후보를 작은 배치로 검토해 `INCLUDE`(심층 검토), `EXCLUDE`(제외), `UNDECIDED`(불확실하지만 심층 검토)를 이유와 함께 기록합니다. 아직 처리하지 않은 후보는 `PENDING`, Agent·출력 형식 실패는 `ERROR`입니다. 신규 v2는 같은 파일의 선별 후보를 크기 제한이 있는 공유 문맥으로 묶고, 공격자 통제 입력·민감 동작·도달 가능성·경계 등의 코드 근거가 있는 가설만 등록합니다. 구체적 근거가 있으나 불확실한 가설은 후속 Pro·Con·PoC 검증으로 보냅니다. 해당 묶음의 가설은 다음 묶음이나 전체 자유 탐색 종료를 기다리지 않고 검증합니다. Discovery 판정은 취약점 판정이 아닙니다. 후속 가설의 `INCONCLUSIVE`는 근거 부족으로 끝났다는 뜻입니다.

프롬프트는 개별 호출 크기에 맞춰 묶거나 나눕니다. 후보·가설 전체를 고정 총수 상한으로 잘라 버리지 않지만, 개별 호출 시간·크기·재시도와 Chaining 깊이·중복 방지는 유한합니다. 신규 v2의 파일별 공유 문맥과 미검토 표면 문맥에도 민감정보 제거와 크기 제한을 적용합니다. 위치·줄 수를 유지한 안전한 문맥을 만들 수 없으면 모델에 보내지 않고 오류 또는 미검토 범위로 남깁니다. 원본 정적 근거는 별도 artifact에 보존합니다. 한 후보가 호출 크기를 넘거나 응답 형식 검증에 반복 실패하면 `ERROR`로 남고 다른 후보의 성공은 유지됩니다. 한도 소진으로 `PAUSED`가 되면 남은 작업은 재개 가능하게 보존됩니다. 프롬프트 바이트 감소는 토큰·비용 절감을 보장하지 않으며 공급자가 보고하지 않은 비용을 추정해 0으로 기록하지 않습니다.

## 3. 읽기 전용 대시보드

다른 터미널에서 실행합니다.

```text
sastsimi dashboard
```

브라우저에서 `http://127.0.0.1:8765`를 엽니다. 분석별 주소는 `/analyses/A-001`입니다.

화면에서 다음을 확인할 수 있습니다.

- `개요 / 진행 / Finding∙검증 / Coverage / 아티팩트 / LLM / PoC∙증거∙보고서 / 로그`로 구분된 상세 화면. 공통 요약에는 TRUE Finding, 검증된 PoC, 최종 판정이 저장된 가설, LLM 호출·토큰·비용을 표시합니다.
- 왼쪽 분석 목록의 저장소명, 글자와 색상을 함께 사용한 상태, 실행 시각, 상태별 핵심 수치. 좁은 화면에서는 분석 목록이 서랍으로 전환됩니다.
- 현재 단계·상태·현재 알려진 checkpoint 기준 진행률과 AST·OpenGrep·CodeQL 상태
- 정적 파일×규칙 검증 수, 후보 총수와 `INCLUDE`·`EXCLUDE`·`UNDECIDED`·`PENDING`·`ERROR`별 수, 심층 분석 진행·완료 수, 가설·Finding 수
- Agent가 확인한 근거·행동·판정 이유 요약 및 검색 가능한 실행 로그
- 단계별 JSON·텍스트 아티팩트와 비밀값을 제거한 LLM 요청·응답
- LLM 호출 상세의 Agent·모델·시각·상태·재시도·토큰·연결 가설/Finding과 응답 결과, 시스템/사용자 프롬프트, 저장 원문 요청/응답 JSON
- 저장된 reference를 기반으로 한 아티팩트 입력→출력 관계 추적과 발표 패키지 ZIP
- 검증된 PoC와 정적·동적 증거의 분리된 목록 및 개별 다운로드
- 허용·제외된 Primitive와 Chaining 부모·자식 관계
- 렌더링/원문 전환이 가능한 Markdown 보고서
- 항목을 선택한 ZIP 또는 `전체 결과 ZIP 다운로드`를 통한 로그·아티팩트·보고서 일괄 저장
- Finding과 기존 Markdown 보고서 링크; 검증된 새 보고서라면 영문·국문·PoC·근거 파일 및 ZIP 다운로드 링크
- Scope Gate의 정책 수집 상태, 출처 URL·개정, 다섯 검토 항목의 판정·인용·이유와 비공개 제보 조건 표시
- Provider별 호출 수·확인된 토큰/비용·비용 미제공 호출 수와 추가 사용량 가능성
- 정적 검사 검증/예상 파일·규칙 수, 엔진별 검증 수, 미검증 파일×규칙 조합과 스캔 불가 Python 제품 파일의 별도 개수·경로·이유, 제외 테스트·대상 밖 JS/TS 제품 코드 및 coverage artifact 참조. 화면의 원장 버튼으로 각 목록을 페이지 단위로 조회

대시보드는 저장 데이터를 읽기만 합니다. 취소·재시도·판정 변경·공개 승인을 수행하지 않으며 기본적으로 외부 네트워크에 공개하지 않습니다.

CLI 진행 로그는 분석별로 data directory의 `logs/<analysis-id>.log`에도
저장됩니다. 새 분석에서 발생한 LLM 요청·응답은 credential, token, host 절대
경로와 숨겨진 추론을 제거한 뒤 아티팩트로 저장합니다. 이전 분석에는 이 항목이
없을 수 있습니다.
CLI와 웹의 정적 검사 세부 단계·수량은 확인된 스캐너 결과와 저장 이벤트만 사용합니다. 일부 과거 분석이나 누락된 계측은 `—` 또는 미기록으로 표시하며 추정값을 만들지 않습니다. 후보는 후보로 표시하고, 확정 Finding 수에는 포함하지 않습니다.

대시보드는 처음에 선택한 탭만 조회합니다. 가설·아티팩트·LLM 호출·로그 목록은 페이지 단위로 불러오고, 긴 아티팩트·프롬프트·저장 JSON은 사용자가 선택했을 때만 조회합니다. 탭 메뉴만 스크롤 고정하며 핵심 결과와 LLM 사용량은 페이지 최상단에서 작은 아이콘과 숫자로 표시합니다. 아이콘에 마우스를 올리거나 키보드 초점을 두면 수치의 의미가 나타납니다.

영문 Markdown은 현재 Finding의 검증된 첨부 manifest에 있을 때만 전체·선택 결과 ZIP의
`reports/en/`에 포함됩니다. 디스크에 남은 단독 `F-NNN.en.md`는 검증 없이 포함하지
않습니다. 보고서 미리보기·다운로드·ZIP은 동일한 Scope Gate 보호를 적용합니다.
아티팩트가 표시 한도를 넘어 일부만 보이면 대시보드가 최소 누락 개수를 알리고
불완전한 전체 ZIP을 차단합니다. 표시된 자료는 선택 ZIP으로 받을 수 있습니다.

짧은 발표용 실행 순서와 고정된 취약 저장소 예시는
[대시보드 발표 시나리오](dashboard-demo.md)를 참고합니다.

## 4. 결과·PoC·보고서

```text
sastsimi result A-001
sastsimi poc F-001
sastsimi report show F-001
sastsimi report export F-001 --format markdown
sastsimi report export-group A-001 <group-id> --format json
```

`result`는 분석 상태와 Finding 목록을, `poc`는 실제 실행에 성공한 validated PoC만 보여 줍니다. `report show`는 current Finding의 기존 한국어 Markdown을 보여 주고 `report export`는 파일 위치를 반환합니다. 검증된 새 번들이 있으면 export 출력에 `bundle_path`가 추가됩니다. 첨부파일은 대시보드에서 개별 다운로드하거나 `bundle.zip`으로 받을 수도 있습니다. 기존 `F-NNN.md` 경로와 저장된 과거 보고서는 그대로 유지합니다.

`report export-group`은 `result A-001 --format json`의 `finding_groups`에서 확인한
64자리 `group_id`를 사용합니다. 현재 분석에 속한 둘 이상의 Finding이 같은
입력→위험 동작 경로임이 입증되고, 각 Finding의 보고서·PoC·증거와
대상 commit·CWE·영향 버전·심각도·Scope 판정이 모두 다시 검증될 때만
`reports/<analysis_id>/groups/<group_id>/<archive-sha256>/bundle.zip`을 만듭니다.
JSON 출력의 `bundle_path`는 이 상대 경로입니다. ZIP에는 영문·국문 검토 초안,
`evidence/group-manifest.json`, `members/F-NNN/` 아래의 원본별 첨부가
들어갑니다. 내용이 충돌하거나 오래되었으면 명시적 오류를 반환하고,
일부만 담은 ZIP을 만들지 않습니다. 같은 내용은 같은 경로를 재사용합니다.
대시보드의 `PoC∙증거∙보고서` 탭에서도 유효한 그룹 ZIP과 각 원본 Finding의
보고서·첨부 링크를 함께 볼 수 있습니다. 그룹 초안은 첫 번째 Finding의
검증된 주장만 사용하므로, 제출 전 모든 원본과 영향 범위를 사람이 확인해야
합니다. 그룹화는 취약점 확정이나 정책상 제보 허가를 부여하지 않습니다.
기본 전체 결과 ZIP은 입증된 그룹의 대표 보고서만 최상위 보고서로 선택하고
나머지 그룹 멤버를 `reports/originals/`에 보존합니다. 그룹 근거가 없는 과거
보고서가 함께 있으면 그 보고서는 원래 경로를 유지합니다.
`reports/export-selection.json`과 발표 ZIP의 `presentation/summary.json`에
그룹 적용 범위(`FULL`/`PARTIAL`/`UNVERIFIED`) 및 원본 유지 ID를 기록합니다. 개별 보고서
ID를 명시해 ZIP을 받으면 그룹 요약 대신 요청한 원본만 내보냅니다.

새 Finding의 보고서 번들은 다음과 같이 저장됩니다.

```text
reports/<analysis_id>/F-001.md
reports/<analysis_id>/F-001/report_en.md
reports/<analysis_id>/F-001/report_kr.md
reports/<analysis_id>/F-001/poc.sh
reports/<analysis_id>/F-001/evidence/provenance.json
reports/<analysis_id>/F-001/evidence/stdout.txt  (안전할 때만)
reports/<analysis_id>/F-001/evidence/stderr.txt  (안전할 때만)
reports/<analysis_id>/F-001/manifest.json
reports/<analysis_id>/F-001/bundle.zip
```

`report_en.md`는 GitHub 비공개 security advisory에 옮기기 쉽고 `report_kr.md`는 사람이 읽기 쉬운 표현을 사용합니다. 두 파일 모두 같은 순서로 요약, 영향 대상·테스트 버전, 심각도·CWE, 기술 설명, 재현·PoC, 근거, 영향, Scope Gate·한계, 수정 제안을 담습니다. 현재 분석 경로의 실제 검증된 셸 후보는 `poc.sh`입니다. 번들 형식은 `poc.py`도 허용하지만 현재 분석 경로에서 Python PoC를 자동 선택하지는 않습니다. `evidence/provenance.json`과 `manifest.json`에는 출처 참조·해시를 기록합니다.

두 언어는 같은 검증/예상 수, 미검증 파일×규칙 조합과 스캔 불가 Python 제품 파일의 별도 수·이유·경로 예시, 제외 테스트·대상 밖 제품 코드, coverage artifact 해시를 사용합니다. `PARTIAL` 경고는 정적 검사가 불완전함을 뜻하며, confirmed Finding도 저장소 전체 검사가 끝났다는 뜻이 아닙니다. 전체 경로별 목록은 크기가 제한된 보고서 번들에 넣지 않고 별도 coverage artifact에 둡니다. 과거 coverage 정보가 없는 보고서는 전체 검사 완료를 주장하지 않습니다.

분석한 commit만으로 영향받는 전체 버전 범위, 수정 버전, 심각도나 CVSS를 확정하지 않습니다. 근거가 없는 필드는 `Needs review`/`검토 필요`로 남기며 GitHub 제보 양식에 제출하기 전에 사람이 채워야 합니다. 첨부 PoC에서 민감정보가 가려져 실제 실행된 바이트와 달라졌다면 두 보고서가 이를 알리고 원본·첨부 해시를 구분합니다. 임의의 저장소 파일이나 raw 출력은 첨부하지 않습니다.

외부 정책이 없거나 범위 밖인 결과는 내부 기술 보고서로 생성할 수 있지만 외부 제출·공개가 제한됐다고 표시합니다. 대시보드는 current Finding, Gate와 정책, manifest·첨부 참조·해시를 확인한 후에만 다운로드를 제공하며, 기존 공개 보고서가 제한되는 경우 첨부파일로 이를 우회할 수 없습니다. 과거 단일 보고서에는 새 번들이 자동 생성되지 않습니다. SASTSIMI가 자동으로 외부에 제출하지 않습니다.

이전 버전에서 만든 첨부 묶음에 로컬 `file:` URL이 남아 있으면 묶음과 개별 첨부의 공개 다운로드를 차단합니다. 원본 분석 기록은 삭제하지 않으며, 화면의 저장소·정책·이벤트·로그 URL은 가려서 표시합니다. 해당 묶음이 필요하면 현재 버전으로 안전하게 다시 생성·검증해야 합니다. 컨테이너 내부 `/tmp`만 사용하는 검증된 셸 PoC는 이 차단 대상이 아닙니다.

공개 GitHub 저장소는 분석 시작 시 기본 브랜치의 `.github/SECURITY.md`, 루트 `SECURITY.md`, `docs/SECURITY.md` 순서로 확인하고, 셋 다 없으면 같은 소유자의 공개 `.github` 저장소를 확인합니다. 정책은 분석한 코드 commit과 다른 개정일 수 있어 출처 URL과 Git blob SHA를 따로 기록합니다. 저장소 내 임의의 링크나 GitHub의 비공개 취약점 제보 버튼을 시험·공개 허가로 간주하지 않습니다. GitHub 외 URL과 로컬 Git 경로에서는 이 자동 수집을 지원하지 않아 정책 상태가 `UNVERIFIED`로 남습니다.

Scope Gate는 정책의 자격·규칙(`rules`), 자산 범위(`asset_scope`), 영향 조건(`impact`), 시험 제한(`testing`), 비공개 제보 조건(`reporting`)을 각각 확인합니다. `PASS` 또는 `FAIL`에는 저장된 정책의 정확한 행과 인용이 필요합니다. 검증된 공식 정책에서 다섯 항목이 모두 `PASS`이고 명시적 제한 문구가 없을 때만 예비 판정 `ALLOW`, 명시적으로 근거가 확인된 제외 항목이 있으면 `DENY`, 정책 부재·조회 실패·근거 부족은 `UNCERTAIN`입니다. 명시적 제한이 있으면 Agent가 준수했다고 판단해도 모든 PoC 동작을 자동 증명할 수 없으므로 사람 검토 전에는 `UNCERTAIN`입니다. `ABSENT`나 `UNVERIFIED`는 명시적 금지인 `DENY`와 다릅니다. `ALLOW`도 자동 제보 허가가 아니며 외부 공개 허용이나 자동 제출을 뜻하지 않습니다. 기술적 `TRUE`나 분석 `COMPLETE`/`PARTIAL`만으로도 제보 가능하다는 뜻이 아닙니다.

새 보고서와 대시보드는 정책 수집 상태, 출처, 개정, 항목별 인용과 판단 이유를 보여 줍니다. 예전 기록의 근거 없는 `ALLOW`는 공개 조회에서 제보 불가로 제한됩니다. `report F-001 --export markdown`은 이 경우 기존 원본을 덮어쓰지 않고 `F-001.restricted.md`를 만듭니다. 정책 근거를 못 찾았던 A-005의 두 보고서는 역사적으로 `UNCERTAIN`이며, 새 정책 검토를 적용하려면 별도의 새 분석이 필요합니다. 최종 외부 제출 여부는 사람이 정책과 기술 근거를 직접 검토해 결정합니다.

## 5. 실행 경로

저장소 분석은 `SimpleRuntime` 한 경로만 사용합니다. `setup`이 저장한 기본 설정을
읽어 실제 저장소 분석을 시작하며, 준비 실패를 다른 시험용 분석 경로로 대체하지
않습니다.

`--data-dir`, `--profile`, `evaluate`, `capability`, `onboarding` 같은 세부 명령과
옵션은 문제 진단 또는 고급 운영을 위해 유지합니다. 일반 사용자는 위의 공개 명령만
사용하면 됩니다.
