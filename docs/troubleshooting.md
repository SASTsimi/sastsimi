# 오류와 안전한 대응

이 문서는 분석이 시작되지 않거나 중간에 멈췄을 때 결과 의미를 바꾸지 않고 확인하는 방법을 설명합니다.

## 1. CLI 종료 코드

현재 CLI가 사용하는 종료 코드는 다음과 같습니다.

- `0`: 명령 성공
- `2`: 입력 오류
- `3`: 설정 또는 database migration 오류
- `4`: 필요한 production composition이나 capability를 사용할 수 없음
- `5`: current 보고서를 찾거나 안전하게 내보낼 수 없음
- `10`: 예상하지 못한 내부 오류

종료 코드와 취약점 verdict는 다른 값입니다. `3`, `4`, `5`, `10`을 `FALSE`나 `HOLD`로 해석하지 않습니다.

## 2. 자주 발생하는 문제

### `analyze --help`에 `--repo`가 없음

현재 설치본은 Fake 분석 전용 개발 상태입니다. 실제 저장소 분석을 시작하지 말고 production CLI가 포함된 release를 설치합니다. `analyze --scenario` 결과를 운영 결과로 사용하지 않습니다.

### `CAPABILITY_UNSUPPORTED`

다음 중 하나가 빠졌을 수 있습니다.

- production composition
- 현재 host에서 승인된 Git·AST·CodeQL·OpenGrep·Docker profile
- 지원 상태가 `SUPPORTED`인 exact ProviderProfile
- 운영 평가와 사람 승인을 받은 production Prompt
- 선택한 언어·작업을 지원하는 capability

설정 파일에서 상태를 임의로 바꾸지 않습니다. 실제 probe와 승인 기록을 준비한 뒤 새 실행 또는 허용된 resume 절차를 사용합니다.

### LLM 인증 실패

API key 환경변수 또는 공식 client login 상태를 실행 환경에서 확인합니다. secret 값을 로그나 Issue에 붙이지 않습니다. 인증 실패는 가설 반증이 아니므로 `FALSE` 결과가 생기면 안 됩니다.

### CodeQL 또는 OpenGrep 실패

먼저 `codeql version`, `codeql resolve languages`와 profile에 지정한 OpenGrep 실행 파일의 `--version`으로 설치 상태를 확인합니다. 그다음 `status`의 work 상태와 안전한 오류 범주를 확인합니다. 실행되지 않은 규칙과 실행 결과 0건을 같은 의미로 취급하지 않습니다.

### Docker build 또는 container 실패

`docker version`과 `docker info`는 접속 사전 확인일 뿐입니다. Sandbox 외부 경계나 resource 조건을 증명하지 못하면 정상적인 차단입니다. Docker socket, host mount, secret 또는 network 제한을 완화해 우회하지 않습니다.

환경 구성·package 설치·image build·health check 실패는 취약점 `FALSE`가 아닙니다. 재시도 가능한 같은 입력이면 `BLOCKED` 후 새 attempt를 사용할 수 있고, 입력 profile이나 request를 바꿔야 하면 새 generation 또는 새 analysis가 필요합니다.

### 보고서가 없거나 `REPORT_UNAVAILABLE`

다음을 확인합니다.

- Finding과 ReportDraft가 실제로 생성됐는지
- 두 Gate와 validated PoC 조건을 충족했는지
- 선행 근거가 바뀌어 보고서가 stale 상태가 아닌지
- 민감정보 제거와 exact reference 연결이 증명됐는지
- 올바른 `data-dir`과 `finding_id`를 사용했는지

오래된 Markdown 파일을 최신 보고서처럼 복사해 사용하지 않습니다. current 근거로 Gate와 Reporter를 다시 완료한 뒤 새 파일을 내보냅니다.

### 내부 오류와 `trace_id`

CLI가 제공한 `trace_id`와 민감정보가 제거된 event 이름만 운영 담당자에게 전달합니다. raw stack trace, API key, session, 저장소의 비밀값 또는 host 절대 경로를 공개 Issue에 올리지 않습니다.

## 3. 다시 실행할지 판단

- 같은 입력과 같은 승인 profile을 유지하면서 일시 조건만 해결됨: 저장된 상태가 허용하는 resume 또는 retry
- commit, Provider/model, Prompt, policy, Sandbox profile, 동적 재현 request가 바뀜: 기존 결과를 재사용하지 말고 새 generation 또는 새 `analysis_id`
- exact reference가 맞지 않거나 이전 attempt 결과가 늦게 도착함: 최신 결과에 연결하지 않고 stale 결과로 격리
- 원인을 알 수 없음: 새 verdict를 만들지 않고 `BLOCKED` 또는 `FAILED` 상태와 안전한 진단을 보존

외부 공개 여부는 자동 오류 복구의 대상이 아닙니다. 사람이 보고서와 근거를 검토한 뒤 별도로 결정합니다.
