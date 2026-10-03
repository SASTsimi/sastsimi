# 실행 실패 해결

## 먼저 확인할 원칙

인증 실패, 도구 미설치, timeout, LLM 형식 오류, Docker build·실행 실패는 취약점이 없다는 뜻이 아닙니다. SASTSIMI는 이런 오류를 `FALSE`로 바꾸지 않고 `BLOCKED` 또는 verdict 없는 `FAILED`로 저장합니다.

```text
sastsimi status A-001
sastsimi resume A-001
```

`resume`은 같은 범위의 검증된 정적 검사, 완료된 후보 선별과 Agent 단계를 재사용하고 미완료 단계부터 이어갑니다. 후보 파이프라인 도입 전 분석은 저장된 이전 재개 경로를 유지합니다.
정책 snapshot은 최초 분석 시 고정되므로 `resume`으로 최신 GitHub 정책을 다시
받지는 않습니다. 정책이 새로 게시되거나 바뀌었다면 새 분석을 시작하세요.

`LLM_ELAPSED_BUDGET_EXHAUSTED`는 양의 정수로 설정한 누적 LLM 시도 시간의
상한에 도달했다는 뜻입니다. 새 설치의 기본값은 `unlimited`이며, 기존 설정의
숫자 한도는 자동 변경하지 않습니다. 계정 사용량을 확인한 뒤 한도를 높이거나
`--max-elapsed-seconds unlimited`로 다시 설정하고 `resume`하세요. 중단 중 경과한
시간은 한도에 더해지지 않습니다. 예전 elapsed-budget `FAILED` 체크포인트만
명시적 재개에서 다시 열며, 성공한 Agent 결과와 다른 실패는 건드리지 않습니다.

`status`가 `INTERNAL_ERROR`를 내면 함께 기록된 `trace_id`와 안전한
`error_type`을 보관하고 한 번 다시 조회하세요. CLI가 오류를 `doctor`처럼 다른
명령으로 표시하지 않도록 요청한 명령 이름을 함께 출력합니다. 반복되면 두 값과
실행 시각을 전달해 원인을 조사하고, DB나 분석 기록을 삭제하지 마세요.
특히 서로 다른 checkout의 코드를 같은 `.venv`와 데이터 디렉터리에서 번갈아
실행하면, 구버전 코드가 새 체크포인트 필드를 읽지 못해 `ValidationError`가
날 수 있습니다. 설치된 실행 파일이 어느 checkout을 import하는지 확인하고
분석·조회·재개에 같은 버전의 코드를 사용하세요. DB를 초기화하는 해결책은 아닙니다.
후보 파이프라인 v1에서 마지막 기록이 `RUNNING`이지만 활성 실행 잠금(lease)이 없으면 `status`는 DB 체크포인트를 변경하지 않고 `PAUSED`·`INTERRUPTED_RESUME_REQUIRED`로 표시합니다. 이전 프로세스가 종료된 것을 확인한 뒤 `sastsimi resume A-001`로 저장된 단계부터 재개하세요.

`HYPOTHESIS_EVIDENCE_INVALID`는 저장된 가설 또는 Pro/Con 근거를 신뢰할 수 없어 재개를 차단한 상태입니다. 구형 Pro/Con의 인용 해시만 현재 저장된 입력과 다르고 원본·실행 계보가 온전하면, `resume`은 해당 가설과 후속 결과가 없는 연쇄 단계만 되돌려 다시 검증합니다. 이때 이전 Finding·보고서는 새 검증이 끝날 때까지 현재 결과로 표시하지 않습니다. 원본 손상, 다른 가설의 파생 작업 또는 불명확한 연쇄 의존성이 있으면 자동 복구하지 않습니다. `resume`만 반복하거나 DB에서 체크포인트를 삭제하지 말고, 상태와 보관된 근거를 확인하세요.

`HYPOTHESIS_BATCH_OUTPUT_INVALID`는 요청하지 않은·중복된 후보 ID가 응답에 있거나, 후보별 누락·형식 오류가 두 번의 검증 시도 뒤에도 남은 경우입니다. 해당 가설 단계는 `BLOCKED`로 남고 실패 후보는 `ERROR`로 기록됩니다. `PRO_CON_RESPONSE_INVALID`(개별 역할)와 `PRO_CON_BATCH_RESPONSE_INVALID`(묶음 역할)는 필수 필드·상대 경로·허용된 근거 해시의 검증이 두 번 모두 실패한 `BLOCKED` 상태입니다. 저장된 시도 근거와 실제 입력 해시를 확인하세요. 이 오류들은 취약점 부재를 뜻하지 않습니다.

`LLM_TOKEN_BUDGET_EXHAUSTED`는 숫자로 설정한 누적 토큰 한도에 도달해 다음 요청을 차단한 상태입니다. 새 후보 분석에서 토큰·비용·누적 시간 한도 소진은 `PAUSED`로 표시하고 남은 후보를 `PENDING`으로 보존합니다. 한도를 바꾸지 않은 `resume`은 같은 유료 요청을 무한히 제출하지 않습니다. Provider 계정 사용량을 확인하고 필요한 설정 한도를 높인 뒤 재개하세요. 요청 전 검사이므로 한 번의 호출이 한도를 넘어설 수 있습니다. `LLM_TOKEN_USAGE_UNAVAILABLE`은 숫자 한도가 설정됐지만 이전 시도의 토큰 수치를 확인할 수 없어 후속 요청을 차단한 상태입니다. 새 `setup`의 기본값 `max_tokens = "unlimited"`에서는 이 두 차단을 적용하지 않습니다. 기존 설치의 `config.toml`과 `profile.toml` 모두 `max_tokens`를 `"unlimited"`로 바꾼 뒤 `resume`하면 해당 실패 단계를 다시 시도할 수 있습니다. 사용량 미확인 기록은 지우지 않으며 Codex CLI의 누락·잘못된 정상 완료 이벤트도 성공으로 인정하지 않습니다. Cursor CLI에서 토큰 수치가 없는 정상 응답은 무제한 설정에서 다음 요청을 차단하지 않지만 사용량은 미확인으로 남습니다.

Codex 호출이 `CODEX_CALL_IN_FLIGHT_UNRESOLVED`로 남았다면, 재개 시 해당 호출의 자식 프로세스가 **생성되지 않았음**을 버전·시도·프로세스 원장과 배타적 실행 잠금으로 입증할 수 있는 경우에만 같은 작업을 다시 시도합니다. 자식 프로세스 생성 기록이 있거나 종료 여부를 입증할 수 없으면 중복 유료 호출을 피하기 위해 차단을 유지합니다. 임의로 DB의 호출 상태나 PID를 고쳐 해제하지 마세요.

`LLM_COST_USAGE_UNAVAILABLE`은 이전 OpenAI API 시도의 신뢰할 수 있는 금액이 없어 후속 API 요청을 차단한 상태입니다. API adapter는 실제 청구 금액을 산출하지 않습니다. Codex·Cursor CLI는 비용을 제공하지 않고 Cursor SDK의 비용 확정도 늦을 수 있습니다. `max_cost_minor_units`는 기록된 신뢰 가능한 비용에만 다음 요청 전에 적용되므로 실제 청구액의 정확한 상한은 아닙니다. Provider 계정의 사용량과 지출 설정을 확인하세요. 미확인 시도가 남아 있으면 `resume`만 반복해도 차단이 해소되지 않습니다.

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
codeql resolve packs --format=json
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
- Windows에서 사용하는 저장소 로더는 clone·checkout·검증 Git 명령에 `core.longpaths=true`를 호출별로 적용합니다. 전역 Git 설정을 바꾸지 않으므로 긴 경로 오류가 계속 나면 `sastsimi status A-001`의 오류 코드와 실제 Git 실패 기록을 확인하세요. 기존 분석 폴더를 지우지 마세요.

## OpenGrep 또는 CodeQL 실패

같은 저장소와 commit을 서로 다른 분석 ID에서 동시에 시작하면 현재 공유 CodeQL 데이터베이스 생성이 충돌할 수 있습니다. 해당 조합의 분석은 하나씩 실행하고, `CODEQL_DATABASE_CREATE_FAILED`나 `CODEQL_ANALYZE_FAILED`가 발생하면 다른 실행이 종료된 뒤 실패한 분석을 재개하세요. 이 제한은 정적 검사 누락을 성공으로 바꾸지 않습니다.

OpenGrep의 `PartialParsing`·구문 오류는 `paths.scanned`에 파일이 보여도 파일·규칙별 검사 완료가 아닙니다. AST와 설정된 CodeQL 결과는 계속 저장합니다. 정적 범위는 테스트 파일을 제외한 Python `.py` 제품 코드뿐입니다. 제외 테스트는 경로·이유를 별도 기록하며 검사 성공으로 세지 않습니다. JS/TS·`.pyi`에는 Python 규칙을 적용하지 않고, JS/TS 제품 코드가 있는 혼합 저장소는 대상 밖 코드로 표시하며 전체 결과를 `PARTIAL`로 제한합니다. 대시보드에서 Python 검증/예상 수와 누락 경로·규칙·이유를 확인하세요. CodeQL을 OpenGrep 규칙의 대체 증거로 세지 않습니다. 검증된 부분이 유효하면 후속 Agent는 진행할 수 있으나 남은 누락은 최종 `PARTIAL`로 표시합니다.
`status`와 대시보드는 미검증 파일×규칙 조합, 스캔 불가 Python 제품 파일, 지원되지 않는 파일을 서로 다른 항목으로 보여 줍니다. 스캔 불가 경로의 이유가 `NO_PYTHON_RULES`나 OpenGrep 실행 오류이면 해당 파일에 완료 증거가 없다는 뜻입니다. 화면의 경로 미리보기만으로 전체 범위를 판단하지 말고 대시보드 원장 또는 coverage artifact를 확인하세요. 영·한 보고서에도 스캔 불가 파일의 수·이유·경로 예시가 별도로 표시됩니다.

선택형 Semgrep CE를 쓰려면 Windows PowerShell의 `.venv`에서 각 줄을 한 줄 명령으로 실행합니다. `setup`을 다시 실행할 때 기존 제한·모델 옵션도 필요하면 함께 지정하세요. 분석 중에는 Semgrep을 자동 설치하거나 원격 규칙을 받지 않습니다.

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install semgrep
semgrep --version
sastsimi setup --non-interactive --auth subscription --provider codex --model gpt-6-sol --profile full --docker-network none --semgrep-fallback
sastsimi status A-001
```

Semgrep 미설정은 `SEMGREP_TOOL_UNAVAILABLE`, 실행 실패는 `SEMGREP_EXECUTION_FAILED`, 잘못되거나 잘린 JSON은 `SEMGREP_RESULT_INVALID`로 남습니다. 실행 오류는 취약점 반증이 아닙니다. Semgrep fallback을 켠 경우 OpenGrep의 검증된 부분 결과만 재사용하고 파싱 경고·미검사·시간 초과 등 미검증 파일·규칙 조합만 Semgrep에 넘깁니다. Semgrep도 확인하지 못한 조합은 누락 이유와 함께 남습니다. 기존 v1의 `PARTIAL` 분석은 같은 범위의 미검증 조합을 `resume`에서 재시도하되 완료된 Agent의 원래 입력 참조는 바꾸지 않습니다. 이미 `STATIC_DONE`이 성공한 v2 `PARTIAL` 분석은 같은 ID에서 정적 누락을 재검사하지 않으므로, 원인을 해결한 뒤 새 분석 ID로 시작하세요.

결정적 파싱 오류 외에 Semgrep 실행 오류나 설정된 CodeQL 오류가 남아 있으면 coverage에 제한 사항을 유지합니다. 기존 v1 분석을 같은 commit·제품 범위·규칙·도구 지문에서 `resume`하면 완료된 증거는 재사용하고 미검증 조합을 다시 시도합니다. 성공한 정적 근거가 `PARTIAL`로 저장된 v2 분석은 같은 ID로 후보·표면·가설 작업만 이어가며 정적 누락은 다시 검사하지 않습니다. 지문이 바뀌는 수정과 v2 정적 누락의 재검사는 새 분석 ID가 필요합니다. 해결되지 않은 범위를 `COMPLETE`로 표시하지 않습니다.

OpenGrep은 Python 제품 코드만 최대 64파일·소스 합계 512 KiB의 명시적 묶음으로 검사하며, 각 호출은 최대 120초입니다. 시간 초과된 다중 파일 묶음은 단일 파일까지 나눕니다. 선택형 Semgrep에는 미검증 Python 파일·규칙만 넘깁니다. Semgrep은 최대 128파일·512 KiB, Windows 명령줄 24,000 UTF-16 단위를 지키고 호출당 최대 120초입니다. 파일 하나의 시간 초과나 JSON `Timeout`은 `--timeout 30`으로 한 번 더 시험합니다. 명령 길이·재시도·출력 크기 제한에 걸린 조합은 완료가 아니라 명시적인 누락입니다. 전체 미검증 경로·규칙·이유는 coverage artifact에 남고 대시보드에서 페이지 단위로 조회할 수 있습니다. 검증된 부분이 있으면 `STATIC_DONE`은 후속 Agent에 안전한 근거를 게시하며, 정적 범위가 불완전한 분석은 모든 Agent가 끝나도 `PARTIAL`입니다.

OpenGrep·Semgrep·CodeQL 결과 파일과 재개용 스캔 원문은 건별 최대 64 MiB까지만 읽습니다. 새 후보 경로는 결과 건수에 고정된 전체 상한을 적용해 나머지를 버리지 않고, 원본을 보존한 채 페이지로 처리합니다. 스캔 원문 누적 4 GiB, 개별 출력 크기·메모리 등 자원 경계는 유지하며 이를 넘기면 완료로 속이지 않고 명시적인 오류나 미검증 상태로 남깁니다. 로컬 도구 호출에는 기본 4 GiB 메모리 제한이 있습니다. Windows는 하위 프로세스를 포함한 Job 전체 커밋 메모리, POSIX는 각 프로세스의 가상 주소 공간 제한이므로 POSIX 프로세스 트리의 메모리 총합을 제한하지는 않습니다. 이 자원 한도에 걸린 결과는 검사 완료 증거가 아닙니다.

coverage artifact의 각 미검증 조합에서 `known_attempt_count`는 완료 기록이 남은 scanner 실행 요청 수이고, `known_attempts_by_engine`는 이를 OpenGrep·Semgrep별로 나눕니다. 실행 요청 직전 `STARTED`를, 종료 후 결과를 ledger에 영속 기록하므로 비정상 종료 흔적을 발견할 수 있습니다. 저장된 원문·요청 설명자·해시와 commit·규칙·도구 지문을 재검증한 파일·규칙 조합만 완료 증거로 인정합니다. `history_complete=false`이면 이전 summary 또는 미완료 요청의 정확한 이력을 확정할 수 없어 `attempt_count=null`이며, 참일 때만 정확한 총 요청 수를 표시합니다. `latest_error_code`와 `latest_error_ref`는 가장 최근 기록된 실패 코드와 비공개 오류 근거 참조입니다. 캐시 재사용·실행 전 검사는 호출 수에서 제외합니다.

`sastsimi setup`을 다시 실행해 현재 실행 파일을 확인합니다. Full profile의 CodeQL은 Python database를 만들고 제한된 query suite를 실행하므로 첫 분석에 시간이 걸릴 수 있습니다. 같은 저장소·commit·제품 범위에서 성공한 결과라도 query suite·로컬 qlpack·실제로 해석된 쿼리 팩 내용과 실행 파일·SARIF 해시를 검증할 수 있을 때만 재개에 재사용합니다. 쿼리 팩 식별이 불가능하면 캐시를 쓰지 않고 CodeQL을 다시 실행합니다.

큰 저장소에서는 `sastsimi status A-001 --format json`의 `current_stage`가
`STATIC_DONE`, 진행률이 `0%`여도 정적 단계의 체크포인트가 아직 실행 중일 수
있습니다. `RUNNING`이고 오류 코드가 없다면 그 숫자만으로 중단을 판단하지
마세요. 같은 분석의 `resume`을 동시에 실행하지 말고, 원래 실행 프로세스가
종료됐거나 상태가 `BLOCKED`/`FAILED`로 바뀐 뒤 오류 코드를 확인해 재개하세요.
분석용 `workspaces/<workspace-id>` checkout도 실행 중에는 직접 수정하지 마세요. 도구는 실행 전 상태를 검사하지만 중간 수정은 지원하지 않으므로, 의심되면 해당 결과를 근거로 쓰지 말고 새 분석 ID로 다시 시작해야 합니다.

정적 분석 전체에는 180초나 공유 1시간 종료 시각을 적용하지 않습니다. 이전
프로필의 `static_scan_pass_seconds`는 읽어도 전체 검사 시간 제한으로 사용하지
않습니다. OpenGrep·Semgrep 하위 호출은 각각 최대 120초이고, 실패 묶음은
유한 횟수로 분할·재시도합니다. CodeQL은 독립적으로 create/analyze 호출마다
최대 1800초입니다. 사용자는 실행을 취소할 수 있습니다. 정적 도구 실행시간은
DB의 누적 LLM 호출시간에 더해지지 않습니다. Python 소스가 없으면
`NO_PYTHON_SOURCE`, Python 소스는 있지만 적용 가능한 규칙이 없으면
`NO_PYTHON_RULES`로 중단하며 검사 완료로 표시하지 않습니다.
제품 코드만 정적 검사하며 명확한 테스트 파일은 입력과 커버리지에서 빠집니다. 제외된 테스트 파일은 경로·이유를 별도 기록하지만 검사 성공으로 세지 않으며, 테스트 포함 옵션은 제공하지 않습니다. 원본 규칙은 그대로이며 저장소별 별도 설정은 필요 없습니다.

`STATIC_SCOPE_CHANGED_NEW_ANALYSIS_REQUIRED`는 이전 전체 파일 범위의 완료된 정적 근거를 새 제품 코드 범위로 `resume`하려 할 때의 안전 중단입니다. 기존 분석 데이터는 그대로 두고 같은 저장소·commit으로 새 `analyze`를 시작하세요. `resume`을 반복해도 두 범위의 근거를 섞지 않습니다.

정적 분석은 Python `.py` 제품 파일만 지원합니다. `.css`, `.html`, Go·PHP·shell·SQL·JS/TS 소스 등은 Python 파일×규칙 커버리지에 포함하지 않습니다. JS/TS 제품 코드가 있으면 대상 밖 경로로 별도 표시되고 전체 결과는 `PARTIAL`입니다. Python 범위 안에서 미검증 파일·규칙이 남으면 대시보드에서 이유를 확인하세요. 그 누락을 숨겨 `COMPLETE`로 바꾸면 안 됩니다.

`NO_PYTHON_SOURCE`는 선택된 비테스트 `.py` 제품 소스가 없는 경우의 명시적 중단입니다. `NO_PYTHON_RULES`는 `.py` 소스는 있지만 적용 가능한 Python 규칙이 없는 설정 오류입니다. 둘 다 `COMPLETE`가 아니며, 저장소·commit·규칙 설정을 확인해야 합니다. 테스트 파일을 정적 검사에 다시 넣는 옵션은 없습니다.

정적 Python 범위 선정에 JS `package.json` 파싱은 필요하지 않습니다. Python AST 파싱 오류나 입력 크기 초과는 coverage artifact의 제한 사항으로 남습니다. 다른 검증 부분이 사용 가능하면 `PARTIAL`로 진행할 수 있습니다. 파싱에 성공한 파일의 AST 사실은 파일별로 모두 보존하며, 프롬프트에서 일부만 선택해 전달한 것을 저장 누락으로 간주하지 않습니다.

시간 초과나 취소 시 하위 프로세스 트리 정리를 시도하고 `EXTERNAL_TOOL_TIMEOUT`을
취약점 반증으로 취급하지 않습니다. 정확한 분석·저장소·commit·도구 지문과 CAS를
다시 확인해 완료된 파일·규칙 증거는 재사용하고 실패한 조합만 재시도합니다.
증거가 손상됐거나 검증된 조합이 전혀 없으면 `BLOCKED`입니다. 검증된 부분만
Agent 후보 근거가 될 수 있으며 불완전한 raw hit는 Finding 근거가 아닙니다.
기존 프로세스가 끝났고 도구 상태를 확인했다면 PowerShell에서 다음
한 줄로 이어갑니다.

```powershell
sastsimi resume A-001
```

데이터 폴더 전체나 다른 분석의 파일은 임의로 삭제하지 마세요. 재개 후에도 모든
저장소가 `COMPLETE`가 된다고 보장하지는 않습니다.

CodeQL package가 없으면 다음으로 설치 상태를 확인합니다.

```text
codeql resolve languages
codeql resolve packs --format=json
```

`codeql version`만 성공하고 `resolve packs`에 `codeql/*-queries`가 없다면 실행 파일만
있는 standalone CLI입니다. 현재 운영체제용 공식 CodeQL bundle로 교체한 뒤
`sastsimi setup`을 다시 실행합니다. SASTSIMI는 query pack이 없는 CodeQL을 Full
profile의 정상 capability로 저장하지 않습니다.

정적 도구 실행 실패는 `FALSE`가 아닙니다.

## Docker 또는 PoC 실패

```text
docker version
docker info
```

Docker Desktop은 Linux container 모드여야 합니다. 승인된 Python wheel을 미리 준비했다면 선택형 오프라인 PoC 환경을 사용할 수 있습니다. 다음 PowerShell 명령은 지정한 폴더의 `.whl` 파일만 평탄한 TAR로 묶고 SHA-256을 출력합니다. `C:\approved-wheels`는 실제 wheel 폴더로 바꾸고, 그 폴더에는 필요한 직접·전이·빌드 의존성 wheel을 모두 준비하세요. 빈 폴더나 하위 폴더를 포함한 TAR는 사용할 수 없습니다.

```powershell
$wheelDir = (Resolve-Path 'C:\approved-wheels').Path
$wheelNames = @(Get-ChildItem -LiteralPath $wheelDir -File -Filter '*.whl' | Sort-Object Name | Select-Object -ExpandProperty Name)
tar -cf (Join-Path $wheelDir 'poc-wheels.tar') --format ustar -C $wheelDir @wheelNames
$archive = (Resolve-Path (Join-Path $wheelDir 'poc-wheels.tar')).Path
(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
docker image inspect python:3.12-slim --format '{{.Id}}'
```

`sastsimi setup` 출력의 실행 프로필 `profile.toml`에서 기존 `docker_network`을 `NONE`으로 확인하고, 아래 wheel 관련 최상위 필드 두 개를 추가합니다. `docker_network`을 중복해서 추가하지 마세요. Windows 경로는 TOML에서 `/`로 적고, 출력된 SHA-256을 소문자 64자리로 붙여 넣으세요. 두 wheel 필드는 반드시 함께 있어야 하고 `setup` 옵션으로는 입력할 수 없습니다. `setup`을 다시 실행하면 `profile.toml`이 새로 쓰이므로 두 필드를 다시 지정해야 합니다.

```toml
docker_network = "NONE"
poc_wheel_archive_path = "C:/approved-wheels/poc-wheels.tar"
poc_wheel_archive_sha256 = "<소문자 SHA-256 64자리>"
```

이 모드는 로컬에 이미 있는 Linux `python:3.12-slim` 이미지와 검증된 wheel만 사용합니다. TAR 크기와 TAR 안의 wheel 데이터는 각각 최대 64 MiB이고, wheel은 최대 20,000개입니다. 대상 Linux 이미지와 호환되는 wheel이어야 하며 대상 태그를 확인할 수 없으면 범용 `py3-none-any` wheel만 허용합니다. 저장소 Dockerfile 대신 생성된 Dockerfile과 고정 commit의 파일로 분리된 빌드 문맥을 만들고, `pip --no-index --find-links`로 설치합니다. Docker build와 PoC 컨테이너는 모두 `--network none`입니다. 제품 패키지를 wheel로 만들 때 ZIP 형식의 최소 시각보다 오래된 파일 때문에 실패하지 않도록, 이미지 안에 복사된 소스 파일의 수정 시각만 고정된 1980년 값으로 맞춥니다. 파일 내용과 대상 commit은 변경하지 않습니다. 현재 선택된 Buildx 빌더가 로컬 Docker 엔진 드라이버인지 `docker buildx inspect`로 확인하며, 지원되지 않는 빌더면 `POC_OFFLINE_BUILDER_UNSUPPORTED`로 중단합니다. 고정 저장소에 추적된 비밀파일은 Docker 문맥에 넣지 않습니다. 공통 테스트 파일 판정과 지원하는 Flit 패키지 경계를 통해 제품 데이터가 아니라고 확인된 테스트용 비밀파일만 제외합니다. 패키지 데이터 여부가 불명확하거나 그 밖의 비밀파일이면 `PINNED_CONTEXT_SECRET_FILE_DENIED`로 차단합니다. 필요한 wheel·전이 의존성·빌드 의존성 또는 로컬 base image가 없으면 명시적으로 `BLOCKED`로 남습니다. sdist, VCS·apt 설치, uv/Poetry lock 및 지원되지 않는 manifest는 이 모드에서 설치하지 않습니다. 실패를 PoC 반증이나 `confirmed` Finding으로 바꾸지 않습니다.

두 PoC 빌드 경로는 고정된 저장소의 `.dockerignore`를 문맥에서 제외할 파일을 고르는 데 사용합니다. 단일 `*`와 영숫자 문자 클래스(예: `*.py[cod]`, `cache[12]/`)를 지원하지만 `!` 재포함, `**`, `?`, 범위·부정 문자 클래스는 지원하지 않습니다. 지원하지 않는 패턴은 임의로 해석하거나 무시하지 않고 `DOCKERIGNORE_UNSUPPORTED`로 중단합니다. 필요한 파일이 제외됐다면 해당 commit의 패턴을 확인하고 새 분석에서 수정된 commit을 사용하세요.

wheel 묶음을 지정하지 않은 기존 경로에서는 저장소 Dockerfile이 있으면 우선 사용하고, 없으면 Python package 파일을 바탕으로 기본 Dockerfile을 만듭니다. 가설의 제품 파일이 하위 Python 프로젝트에 있으면 가장 가까운 `requirements.txt` 또는 `pyproject.toml`을 찾아 일회용 이미지 안에 의존성을 설치하며, 로컬 패키지 소스를 지정한 uv 프로젝트는 lock 파일과 소스 경로를 사용합니다. 하위 프로젝트 설치가 실패하면 의존성 없는 이미지로 성공을 가장하지 않고 빌드 오류와 시도 기록을 남깁니다. 그 외 의존성 설치 단계의 빌드 실패가 확인된 경우에만 설치를 생략한 Python 소스 전용 image를 한 번 더 시도합니다. 이 경우 recipe의 `dockerfile_source`가 `GENERATED_NO_INSTALL`, `degraded`가 `true`가 되고 두 빌드 시도와 원본 진단이 artifact에 남습니다. 소스 전용 image가 만들어졌다는 사실만으로 PoC 검증이나 취약점 판정이 성공한 것은 아닙니다. 두 빌드가 모두 실패하거나 실패 원인이 의존성 설치가 아니면 `DOCKER_BUILD_FAILED`로 중단하고 환경을 확인한 뒤 `sastsimi resume A-001`을 실행합니다.

소스 전용 image만 만들 수 있고 제품 의존성이 재현되지 않았다면 PoC 실행 전에 `POC_ENVIRONMENT_UNVERIFIED`로 차단합니다. 이 환경의 결과를 검증된 PoC나 취약점 부재의 근거로 승격하지 않습니다. wheel 묶음을 지정하지 않은 경로는 임의 저장소의 빌드 의존성을 네트워크 없이 자동 공급하지 못하며, 선택형 묶음도 승인된 wheel로 해결 가능한 설치에만 적용됩니다. 네트워크 정책을 자동으로 완화하지 않습니다. 이미 재시도 불가로 저장된 이 PoC는 profile에 wheel 묶음을 추가해도 같은 ID의 `resume`으로 다시 실행되지 않습니다. 기존 분석을 보존하고 검증 가능한 의존성 환경을 준비한 뒤 새 분석을 시작해야 합니다.

`POC_RUNTIME_IMPORT_FAILED`는 컨테이너에서 PoC 또는 대상 앱을 불러오는 중 Python import가 실패했다는 뜻입니다. 실행·stderr·컨테이너 정리 근거를 보존한 `BLOCKED` 상태이며, 실제 공격 요청이 실행됐거나 취약점이 반증됐다는 뜻은 아닙니다. 누락된 모듈이 제품 의존성인지 PoC 코드 의존성인지는 고정 소스와 이미지 입력을 함께 확인해야 합니다. 패키지를 임의로 설치하거나 네트워크 격리를 풀지 않으며, 승인된 의존성·wheel로 환경을 다시 만들 수 있는 경우에만 재검증하세요. 단순 `resume`이 기존 이미지 digest를 재사용한다면 환경 변경이 반영되지 않으므로 같은 오류를 반복할 수 있습니다.

이 안전 검사보다 앞서 완료된 PoC는 DB와 아티팩트를 보존하되 현재 검증으로 표시하지 않습니다. 상태가 `POC_REVALIDATION_REQUIRED`라면 같은 분석 ID를 `sastsimi resume A-001`로 재개하세요. 완료된 정적 검사·후보 선별·Pro/Con·초기 검증·PoC 후보는 재사용하고 PoC 실행과 후속 판정만 새 기준으로 확인합니다. 필요한 의존성을 오프라인에서 구할 수 없으면 재검증도 `BLOCKED`로 남으며, 이전 보고서를 제보 근거로 다시 사용해서는 안 됩니다.

PoC 종료 후에는 현재 가설·시도에 정확히 속한 컨테이너만 확인하고 정리합니다. `OWNED_CONTAINER_CLEANUP_FAILED`나 `DOCKER_CONTAINER_LIMIT_REACHED`가 나오면 소유 라벨이 확인되지 않은 컨테이너를 임의로 지우지 말고 상태를 확인하세요. Windows에서 종료된 프로세스의 PID 소유 여부를 확실히 증명할 수 없는 오래된 컨테이너는 자동 정리하지 않습니다. Docker 실행 오류는 가설 반증(`FALSE`)으로 처리하지 않습니다.

Windows에서 Docker 소유 리소스 journal 파일의 원자적 교체가 일시적인 공유 거부로 실패하면 최대 5회 재시도합니다. 계속 `Access denied`가 나면 권한이나 보안 프로그램 점유를 확인하세요. 이때 다른 분석의 컨테이너를 임의로 정리하지 않습니다.

wheel 묶음을 지정하지 않은 기존 경로에서 Python Playwright가 PoC 실행 중
`BrowserType.launch: Executable doesn't exist` 오류를 내고 실제 실행 stderr가
누락된 Chromium·Firefox·WebKit 바이너리를 가리키면, 해당 가설의 일회용 Docker
이미지에만 공식 브라우저와 시스템 의존성을 설치해 재시도합니다. 오프라인 wheel
모드는 브라우저 다운로드 복구를 지원하지 않으므로 이 오류를 `BLOCKED`로 남깁니다.
지원되는 환경을 준비한 뒤 새 분석을 시작해야 하며, 네트워크 차단을 자동으로 풀지
않습니다. 기존 경로의 설치 위치는 비루트 PoC 사용자도 읽을 수 있는 이미지 내부의 공유
경로로 고정합니다. [Playwright 공식 문서](https://playwright.dev/python/docs/browsers)의
설치·공유 경로 방식을 따르며, Docker 빌드에서 다운로드가 불가능하거나 이미지가
지원되지 않으면 실행 오류로 `BLOCKED`에 남깁니다. 대상 저장소나 호스트 파일은
수정하지 않고 PoC 런타임 네트워크 차단도 해제하지 않습니다.

`POC_INCONCLUSIVE`는 스크립트 실행이 완료됐지만 출력만으로 가설을 지지하거나
반증할 수 없다는 뜻입니다. 제한된 횟수 안에서 PoC 입력을 보강하고,
복구 상한에 이른 마지막 실행이 종료 코드 0이면서 여전히 근거 부족이면
가설을 `INCONCLUSIVE`·제보 불가로 종료합니다.
상한 전이라도 복구 Agent가 `STOP`을 결정했다면, 같은 시도의 실행 성공·해석
`INCONCLUSIVE`·결정 기록이 정확히 연결된 경우에만 미확정으로 종료합니다.
근거 연결이 없거나 실행 자체가 실패했다면 `BLOCKED`를 유지합니다.
전체 가설이 분석상 종료되고 다른 실행 오류가 없으면 정적 범위에 따라
`COMPLETE` 또는 `PARTIAL`입니다.
반면 `POC_EXECUTION_FAILED`와 Docker/Provider 오류는 완료된 관찰이 아니므로
계속 `BLOCKED` 또는 판정 없는 `FAILED`로 남습니다.

PoC 초안은 validated PoC가 아닙니다. 같은 attempt에서 실제 실행이 성공하고 가설을 지지해야만 validated PoC가 됩니다.

초기 Verification의 `environment_requirements`에는 설치 가능한 Python 실행환경과 패키지만 넣습니다. 공격자가 대상 프로세스 설정을 바꿀 권한, 외부 서비스·자격 증명·네트워크 호출처럼 별도로 입증해야 하는 조건은 `unmet_external_prerequisites`로 기록합니다. 이 조건이 남으면 해당 가설은 환경 준비·PoC·Finding·보고서를 실행하지 않고 `INCONCLUSIVE`(제보 불가)로 끝납니다. 검증하지 못한 공격 표면은 여전히 미검증이며 전체 분석이 `PARTIAL`일 수 있습니다. 반대로 설치 요구 자체가 지원되지 않아 `POC_OFFLINE_REQUIREMENT_UNSUPPORTED`가 발생했다면 이를 미확정으로 위장하지 않고 `BLOCKED`로 남깁니다. 과거 형식 때문에 이 오류로 멈춘 같은 분석은 완료된 앞 단계를 보존하고 초기 Verification만 최대 3회까지 재평가할 수 있습니다.

`INITIAL_VERIFICATION_EVIDENCE_INVALID`는 이 조기 종료의 Agent 근거 아티팩트가 없거나 내용·해시·시도 ID가 일치하지 않는다는 뜻입니다. CLI와 대시보드는 이를 완료로 계산하지 않고 `BLOCKED`로 표시하며, `resume`도 손상된 근거를 미확정 판정으로 재사용하지 않습니다. 원본 분석 데이터를 지우거나 임의로 복구했다고 표시하지 마세요.

`POC_STOP_EVIDENCE_INVALID`는 상한 전에 복구 Agent가 중단하기로 한 결정이나 같은 시도의 PoC 실행·해석 근거가 삭제·손상됐다는 뜻입니다. CLI·대시보드와 `resume`은 이 가설을 완료로 계산하지 않고 `BLOCKED`로 표시합니다. 기록된 STOP 결정을 무시하고 같은 PoC를 다시 실행하지 마세요.

`POC_TERMINAL_EVIDENCE_INVALID`는 복구 상한에 이른 PoC의 실행·해석 근거가 삭제·손상됐다는 뜻입니다. 이 경우에도 완료된 미확정 판정으로 세지 않고 `BLOCKED`로 표시합니다.

PoC Agent에는 Pro·Con Agent가 요청한 저장소 상대 경로 중 고정 commit의 Git 추적 파일만 전달합니다. 본문은 현재 작업 폴더가 아니라 고정 commit의 Git blob에서 읽어 재개 중 파일 변경의 영향을 받지 않습니다. 경로 이탈, 심볼릭 링크, 비추적 파일과 크기 한도 초과 파일은 거부하고 `simple_requested_sources` artifact에 제공·거부 내역을 남깁니다. PoC 단계는 원본 소스 총량 128,000바이트, 요청 경로 32개, JSON 변환 후 프롬프트 source artifact 96,000바이트로 제한합니다. 큰 파일은 내용을 읽기 전에 거부하고, 포장 후 한도를 넘는 파일은 `PROMPT_BUDGET_EXHAUSTED`로 남깁니다. 이 근거 제공은 재현 코드의 성공을 보장하지 않습니다.

동적 실행 오류의 복구 계보가 최대 3회 시도를 소진하면 `RECOVERY_EXHAUSTED`로 남습니다. `resume`은 이미 소진된 시도를 자동으로 초기화하지 않으므로 같은 오류를 반복 호출해도 해결되지 않습니다. 도구 수정 후 새 분석을 시작하고 이전 분석·artifact는 보존하세요.

Technical Gate의 `REVISE`는 Docker 오류가 아니라 검증 근거 보완 요청입니다. Runtime은 요청을 저장하고 해당 가설의 PoC 후보부터 Docker 실행·최종 Verification·Gate를 새 시도로 진행합니다. Gate 결정은 최대 세 번이며, 마지막에도 `REVISE`이면 `INCONCLUSIVE`, 명시적으로 `REJECT`이면 제보 불가로 끝납니다. 이 두 결과는 Finding 없이 분석을 끝낼 수 있지만 정적 누락이 남으면 최종 상태는 `PARTIAL`입니다. 취약점 반증이나 제보 승인을 뜻하지 않습니다. Docker·인증·Provider·DB 실행 오류는 `BLOCKED` 또는 `FAILED`가 우선합니다.

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

## Scope Gate가 `UNCERTAIN`이거나 보고서가 제한됨

보고서와 대시보드에서 정책 수집 상태·출처·개정, 다섯 항목의 인용과 이유를 확인하세요.
`ABSENT`는 공식 위치에 정책이 확인되지 않았다는 뜻이고, `FETCH_FAILED`는 조회에
실패했다는 뜻입니다. `UNVERIFIED`는 대상 또는 정책 출처를 검증하지 못했다는 뜻입니다.
이 상태나 인용 근거 부족은 명시적 정책 금지인 `DENY`가 아니며 외부 제보 가능 여부를
`UNCERTAIN`으로 남깁니다. GitHub 외 저장소와 로컬 Git 경로에는 공식 GitHub 정책
자동 조회가 적용되지 않습니다. 저장소의 임의 `SECURITY.md`나 비공개 제보 버튼만으로
허가를 확정하지 않습니다.

이전 분석의 근거 없는 `ALLOW`가 있으면 CLI의 `report`와 대시보드는 제한된 내용을
보여 주고, `report F-001 --export markdown`은 기존 원본을 보존한 채
`F-001.restricted.md`를 만듭니다. 원본을 외부에 전달하지 마세요. 정책이나 도구가
갱신됐더라도 기존 분석의 snapshot은 자동 변경되지 않으므로 새 분석으로 다시
판정해야 합니다. `ALLOW`도 정책상 비공개 제보 조건만 나타내며 외부 공개 승인이
아닙니다. `COMPLETE`나 기술적 `TRUE` 역시 외부 제보 승인이 아닙니다.

## 영문·국문 보고서 또는 첨부파일 링크가 보이지 않음

`PARTIAL` 분석에서도 실제 검증과 Gate를 통과한 Finding은 보고서가 생성될 수 있습니다.
두 언어의 보고서는 같은 검증/예상 수, 미검증 파일×규칙 조합·스캔 불가 Python 파일·미지원 파일의 별도 수와 이유·경로 예시, coverage artifact
해시를 표시합니다. 확인된 Finding은 전체 저장소 검사가 끝났다는 뜻이 아닙니다.
전체 누락 목록은 보고서 ZIP이 아니라 별도 coverage artifact에 남습니다.

새 번들은 검증된 Finding의 Reporter가 성공하고 manifest·정확한 아티팩트
참조·파일 해시가 모두 일치할 때만 대시보드에서 제공합니다. 이전 버전의 단일
`F-NNN.md`에는 새 번들이 자동 생성되지 않습니다. Scope Gate 근거가 부족해
기존 공개 보고서가 제한되면 `poc.sh`와 ZIP을 포함한 첨부 링크도 이를
우회해 공개하지 않습니다. `sastsimi status A-001`로 분석·Reporter 상태를
확인하고, 정책 출처와 검토 항목을 대시보드에서 확인하세요.

대시보드 결과 ZIP이 `incomplete_export`를 반환하거나 전체 다운로드 링크가
보이지 않으면 아티팩트 표시 한도를 넘었거나 일부 저장 참조를 안전하게 읽지
못한 것입니다. 화면의 최소 누락 개수를 확인하고 표시된 자료는 선택 ZIP으로
받으세요. 이를 전체 분석 증거로 간주하지 말고 원본 분석 데이터와 오류를
확인해야 합니다. 과거 단독 영문 Markdown은 검증된 번들 없이 ZIP에 포함되지
않습니다.

manifest가 없거나 참조·해시가 맞지 않으면 파일이 디스크에 보여도 안전한
다운로드로 취급하지 않습니다. DB와 보고서 폴더를 삭제하거나 파일을 직접
외부로 보내지 말고 오류 코드와 분석 ID를 보존해 원인을 조사하세요. 영향
버전·패치 버전·심각도/CVSS가 `Needs review`로 남은 것은 생성 오류가 아니라
해당 근거를 분석 결과만으로 확정할 수 없다는 뜻입니다.

## INTERNAL_ERROR

OpenGrep 규칙 묶음의 완료 증거는 같은 제품 범위에서만 재개에 재사용합니다. 미검증 제품 코드가 남아도 신뢰할 수 있는 검증 부분은 `PARTIAL`로 진행할 수 있습니다. 무결성 실패는 계속 `BLOCKED`입니다.

출력된 `trace_id`, 안전한 오류 코드, 사용한 명령과 운영체제만 전달합니다. API key, token, session 파일, 전체 prompt, 민감한 코드나 로컬 절대 경로는 공개 이슈에 첨부하지 않습니다.
