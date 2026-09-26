# 실행 실패 해결

## 먼저 확인할 원칙

인증 실패, 도구 미설치, timeout, LLM 형식 오류, Docker build·실행 실패는 취약점이 없다는 뜻이 아닙니다. SASTSIMI는 이런 오류를 `FALSE`로 바꾸지 않고 `BLOCKED` 또는 verdict 없는 `FAILED`로 저장합니다.

```text
sastsimi status A-001
sastsimi resume A-001
```

`resume`은 성공한 앞 단계를 재사용하고 실패한 단계부터 이어갑니다.
정책 snapshot은 최초 분석 시 고정되므로 `resume`으로 최신 GitHub 정책을 다시
받지는 않습니다. 정책이 새로 게시되거나 바뀌었다면 새 분석을 시작하세요.

`LLM_ELAPSED_BUDGET_EXHAUSTED`는 DB에 기록된 LLM 시도 시간의 누적 상한에
도달했다는 뜻입니다. 중단 중 경과한 시간은 새 버전에서 이 한도를 소모하지
않습니다. 추가 사용을 허용하려면 계정 사용량과 설정의 `max_elapsed_seconds`를
확인한 뒤 한도를 명시적으로 높이고 `resume`하세요. 시간이 남아 있는 예전
`FAILED` 체크포인트만 명시적 재개 때 다시 실행하며, 이미 성공한 Agent 결과와
다른 비재시도 오류는 건드리지 않습니다.

`status`가 `INTERNAL_ERROR`를 내면 함께 기록된 `trace_id`와 안전한
`error_type`을 보관하고 한 번 다시 조회하세요. CLI가 오류를 `doctor`처럼 다른
명령으로 표시하지 않도록 요청한 명령 이름을 함께 출력합니다. 반복되면 두 값과
실행 시각을 전달해 원인을 조사하고, DB나 분석 기록을 삭제하지 마세요.
실행 프로세스가 종료됐는데 checkpoint가 `RUNNING`으로 남은 경우에는
`resume A-001`로 중단 지점의 복구를 시도할 수 있습니다.

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

## OpenGrep 또는 CodeQL 실패

`sastsimi setup`을 다시 실행해 현재 실행 파일을 확인합니다. Full profile의 CodeQL은 Python database를 만들고 제한된 query suite를 실행하므로 첫 분석에 시간이 걸릴 수 있습니다. 같은 저장소와 commit의 성공 결과는 재개 시 재사용합니다.

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

Docker Desktop은 Linux container 모드여야 합니다. 저장소 Dockerfile이 있으면 우선 사용하고, 없으면 Python package 파일을 바탕으로 기본 Dockerfile을 만듭니다. 의존성 설치 단계의 빌드 실패가 확인된 경우에만 설치를 생략한 Python 소스 전용 image를 한 번 더 시도합니다. 이 경우 recipe의 `dockerfile_source`가 `GENERATED_NO_INSTALL`, `degraded`가 `true`가 되고 두 빌드 시도와 원본 진단이 artifact에 남습니다. 소스 전용 image가 만들어졌다는 사실만으로 PoC 검증이나 취약점 판정이 성공한 것은 아닙니다. 두 빌드가 모두 실패하거나 실패 원인이 의존성 설치가 아니면 `DOCKER_BUILD_FAILED`로 중단하고 환경을 확인한 뒤 `sastsimi resume A-001`을 실행합니다.

PoC 종료 후에는 현재 가설·시도에 정확히 속한 컨테이너만 확인하고 정리합니다. `OWNED_CONTAINER_CLEANUP_FAILED`나 `DOCKER_CONTAINER_LIMIT_REACHED`가 나오면 소유 라벨이 확인되지 않은 컨테이너를 임의로 지우지 말고 상태를 확인하세요. Windows에서 종료된 프로세스의 PID 소유 여부를 확실히 증명할 수 없는 오래된 컨테이너는 자동 정리하지 않습니다. Docker 실행 오류는 가설 반증(`FALSE`)으로 처리하지 않습니다.

Windows에서 Docker 소유 리소스 journal 파일의 원자적 교체가 일시적인 공유 거부로 실패하면 최대 5회 재시도합니다. 계속 `Access denied`가 나면 권한이나 보안 프로그램 점유를 확인하세요. 이때 다른 분석의 컨테이너를 임의로 정리하지 않습니다.

Python Playwright가 PoC 실행 중 `BrowserType.launch: Executable doesn't exist`
오류를 내고 실제 실행 stderr가 누락된 Chromium·Firefox·WebKit 바이너리를 가리키면,
해당 가설의 일회용 Docker 이미지에만 공식 브라우저와 시스템 의존성을 설치해
재시도합니다. 설치 경로는 비루트 PoC 사용자도 읽을 수 있는 이미지 내부의 공유
경로로 고정합니다. [Playwright 공식 문서](https://playwright.dev/python/docs/browsers)의
설치·공유 경로 방식을 따르며, Docker 빌드에서 다운로드가 불가능하거나 이미지가
지원되지 않으면 실행 오류로 `BLOCKED`에 남깁니다. 대상 저장소나 호스트 파일은
수정하지 않고 PoC 런타임 네트워크 차단도 해제하지 않습니다.

`POC_INCONCLUSIVE`는 스크립트 실행이 완료됐지만 출력만으로 가설을 지지하거나
반증할 수 없다는 뜻입니다. 제한된 횟수 안에서 PoC 입력을 보강하고,
복구 상한에 이른 마지막 실행이 종료 코드 0이면서 여전히 근거 부족이면
가설을 `INCONCLUSIVE`·제보 불가로 종료합니다.
전체 가설이 분석상 종료되고 다른 실행 오류가 없으면 분석 상태는 `COMPLETE`입니다.
반면 `POC_EXECUTION_FAILED`와 Docker/Provider 오류는 완료된 관찰이 아니므로
계속 `BLOCKED` 또는 판정 없는 `FAILED`로 남습니다.

PoC 초안은 validated PoC가 아닙니다. 같은 attempt에서 실제 실행이 성공하고 가설을 지지해야만 validated PoC가 됩니다.

PoC Agent에는 Pro·Con Agent가 요청한 저장소 상대 경로 중 고정 commit의 Git 추적 파일만 전달합니다. 본문은 현재 작업 폴더가 아니라 고정 commit의 Git blob에서 읽어 재개 중 파일 변경의 영향을 받지 않습니다. 경로 이탈, 심볼릭 링크, 비추적 파일과 크기 한도 초과 파일은 거부하고 `simple_requested_sources` artifact에 제공·거부 내역을 남깁니다. PoC 단계는 원본 소스 총량 128,000바이트, 요청 경로 32개, JSON 변환 후 프롬프트 source artifact 96,000바이트로 제한합니다. 큰 파일은 내용을 읽기 전에 거부하고, 포장 후 한도를 넘는 파일은 `PROMPT_BUDGET_EXHAUSTED`로 남깁니다. 이 근거 제공은 재현 코드의 성공을 보장하지 않습니다.

동적 실행 오류의 복구 계보가 최대 3회 시도를 소진하면 `RECOVERY_EXHAUSTED`로 남습니다. `resume`은 이미 소진된 시도를 자동으로 초기화하지 않으므로 같은 오류를 반복 호출해도 해결되지 않습니다. 도구 수정 후 새 분석을 시작하고 이전 분석·artifact는 보존하세요.

Technical Gate의 `REVISE`는 Docker 오류가 아니라 검증 근거 보완 요청입니다. Runtime은 요청을 저장하고 해당 가설의 PoC 후보부터 Docker 실행·최종 Verification·Gate를 새 시도로 진행합니다. Gate 결정은 최대 세 번이며, 마지막에도 `REVISE`이면 `INCONCLUSIVE`, 명시적으로 `REJECT`이면 제보 불가로 끝납니다. 이 두 결과는 Finding 없이 분석을 `COMPLETE`로 끝낼 수 있지만 취약점 반증이나 제보 승인을 뜻하지 않습니다. `resume`으로 같은 Gate를 무한 재시도하지 않습니다. Docker·인증·Provider·DB 실행 오류는 여전히 `BLOCKED` 또는 `FAILED`이며 미확정 판정으로 바꾸지 않습니다.

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

## INTERNAL_ERROR

출력된 `trace_id`, 안전한 오류 코드, 사용한 명령과 운영체제만 전달합니다. API key, token, session 파일, 전체 prompt, 민감한 코드나 로컬 절대 경로는 공개 이슈에 첨부하지 않습니다.
