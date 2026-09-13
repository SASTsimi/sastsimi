# 오류와 안전한 대응

이 문서는 분석이 시작되지 않거나 중간에 멈췄을 때 결과 의미를 바꾸지 않고 원인을 확인하는 방법을 설명합니다.

## 1. 종료 코드와 취약점 판정은 다릅니다

현재 CLI가 사용하는 종료 코드는 다음과 같습니다.

- `0`: 명령 성공
- `2`: 입력 오류
- `3`: 설정 또는 database migration 오류
- `4`: production 구성, capability 또는 인증 준비 부족
- `5`: current 보고서를 찾거나 안전하게 내보낼 수 없음
- `10`: 예상하지 못한 내부 오류

종료 코드 `3`, `4`, `5`, `10`은 취약점 `FALSE` 또는 `HOLD`가 아닙니다. 정적 도구, LLM, package 설치, Docker build, container, health check 또는 cleanup 실패도 가설을 반증하지 않습니다.

## 2. 명령 자체가 보이지 않습니다

### `analyze --help`에 `--repo`가 없음

현재 설치본은 production 분석 CLI가 포함되지 않은 이전 개발본입니다. Fake는 `demo analyze` 아래의 시연 결과일 뿐 운영 결과가 아니므로, production CLI가 포함된 release를 설치합니다.

### `capability` 또는 `onboarding` 명령이 없음

해당 T16 구현이 포함되지 않은 설치본입니다. 설정 파일을 손으로 고쳐 승인된 것처럼 만들지 않습니다.

## 3. `CAPABILITY_UNSUPPORTED` 또는 `BLOCKED`

다음 중 무엇이 빠졌는지 안전한 `reason_code`, `safe_summary`, `waiting_for`를 확인합니다.

- production orchestration 또는 handler
- 현재 host의 ACTIVE Git·AST·OpenGrep·Docker profile
- 분석 언어를 지원하는 정적 도구
- exact Provider/model의 완전한 PVD와 onboarding
- R8 평가와 승인된 production Prompt
- 최신 공식 정책과 예산

다른 host·version·digest·daemon·model의 승인 기록을 재사용하지 않습니다.

## 4. capability probe가 통과하지 않습니다

### Git 또는 Python AST

- Git은 `git --version`, clone, detached checkout과 안전한 저장 경계를 모두 확인합니다.
- Python AST는 현재 실행 중인 CPython 3.12 executable과 실제 parse를 확인합니다.
- 사용자가 바꿀 수 있는 위치의 실행 파일이나 probe 도중 변경된 실행 파일은 거부될 수 있습니다.

### OpenGrep

OpenGrep CLI의 version 확인만 성공해서는 부족합니다. Python·JavaScript 시험 파일에 probe 규칙을 실제 실행할 수 있어야 합니다. 설치 위치와 권한을 고친 뒤 새 probe를 만듭니다.

### CodeQL

현재 probe는 quota control을 증명하지 못해 `activation_supported=false`입니다. version 출력이 보여도 강제로 approve하지 않습니다. CodeQL production 활성화는 후속 안전성 구현이 필요합니다.

### Docker

`docker version`과 `docker info`는 사전 확인일 뿐입니다. CLI·daemon identity, 실제 build/run/health/cleanup, resource limit와 외부 경계를 모두 증명해야 합니다.

Docker socket이나 host mount를 Agent/container에 노출하거나 network·secret 제한을 풀어 우회하지 않습니다. 실패는 `FALSE`가 아니라 동적 work의 `BLOCKED` 또는 verdict 없는 `FAILED`입니다.

### OpenAI API

`OPENAI_API_KEY` 환경변수, 승인된 model 접근과 네트워크를 실행 환경에서 확인합니다. secret 값을 출력하거나 Issue에 붙이지 않습니다.

OpenAI probe가 `PASSED`여도 현재 `activation_supported=false`인 것은 정상입니다. 이 probe는 full PVD·R8 평가·사람 승인·onboarding을 대신하지 않습니다.

### Codex 회원 로그인

`codex login status`로 공식 client 상태를 확인할 수 있습니다. 그러나 로그인은 인증 확인일 뿐 Provider 검증·격리 시험·R8 평가·사람 승인을 대신하지 않습니다. 브라우저 cookie 복사나 `support_status` 수동 변경으로 우회하지 않습니다.

## 5. onboarding이 READY가 아닙니다

- `PRODUCTION_ONBOARDING_REQUIRED`: 현재 profile hash의 manifest가 없습니다.
- `PRODUCTION_ONBOARDING_EVIDENCE_MISSING`: manifest가 참조한 근거 파일을 모두 가져오지 않았습니다.
- `PRODUCTION_ONBOARDING_STALE`: profile 또는 승인 유효 기한이 바뀌었습니다.
- `PROVIDER_TERMS_APPROVAL_STALE`: 약관 확인 기한이 끝났습니다.
- `PRODUCTION_PROVIDER_APPROVAL_INCOMPLETE`: Provider/model 조합의 승인이 빠졌습니다.
- `PRODUCTION_PROMPT_APPROVAL_INCOMPLETE`: 역할별 Prompt route 승인이 빠졌습니다.
- `PRODUCTION_PROMPT_APPROVAL_STALE`: Prompt 파일·hash·model·승인 연결이 현재 값과 다릅니다.

누락 값을 `PASS`로 채워 넣지 않습니다. 실제 시험·평가·사람 승인을 다시 수행하고 새 exact manifest와 근거를 가져옵니다.

## 6. 저장소 준비 또는 정적 분석이 실패합니다

- URL에 credential이 없는지, 로컬 경로가 Git 저장소인지 확인합니다.
- `--commit`이 소문자 40자리 또는 64자리 exact SHA인지 확인합니다.
- commit이 clone한 저장소에 실제 존재하는지 확인합니다.
- RepositoryProfile이 감지한 언어·package 파일과 선택한 ACTIVE 도구를 확인합니다.
- “규칙 실행 결과 0건”과 “도구 또는 규칙 미실행”을 구분합니다.

언어·framework·build 방법을 확실히 알 수 없으면 임의 추정하지 않습니다. 확인 필요 gap을 해결한 새 분석을 시작합니다.

## 7. package, image build 또는 PoC가 실패합니다

Reproduction Setup Automation은 저장소의 Dockerfile과 package 선언을 먼저 사용하고, 필요한 경우에만 recipe와 Dockerfile을 만듭니다. 설치·build·health check·PoC 실행 실패는 취약점 `FALSE`가 아닙니다.

- 같은 입력의 일시 실패: 같은 work의 새 attempt로 제한 재시도
- 외부 설정·승인·resource 필요: `BLOCKED`로 대기
- 재시도 한도 소진 또는 복구 불가: verdict 없이 `FAILED`
- request, profile, commit 또는 환경 요구사항 변경: 이전 결과를 재사용하지 않고 새 generation 또는 새 analysis

실패한 PoC candidate와 log는 조사 기록일 뿐 validated `poc_ref`가 아닙니다. `SUCCEEDED + SUPPORTED` 실행과 같은 attempt·환경·recipe·digest 연결이 있어야 validated PoC가 됩니다.

## 8. 보고서가 없거나 `REPORT_UNAVAILABLE`입니다

다음을 확인합니다.

- final `TRUE`와 같은 generation의 validated PoC가 있는지
- current CWELabel, Technical Gate, Rule Scope Gate와 Finding이 있는지
- ReportDraft가 current이고 선행 근거가 바뀌지 않았는지
- 민감정보 제거와 exact reference 연결을 확인했는지
- 같은 `data-dir`과 올바른 `analysis_id`·`finding_id`를 사용했는지

오래된 Markdown을 최신 보고서처럼 복사하지 않습니다. current 근거로 Gate와 Reporter가 다시 끝난 뒤 새 파일을 내보냅니다.

## 9. 내부 오류와 다시 실행 판단

CLI가 제공한 `trace_id`, 안전한 오류 코드와 민감정보가 제거된 event 이름만 운영 담당자에게 전달합니다. raw stack trace, API key, session, 저장소 비밀값 또는 host 절대 경로를 공개 Issue에 올리지 않습니다.

- 같은 입력·승인 profile에서 일시 조건만 해결됨: 저장된 상태가 허용하는 retry 또는 resume
- commit, Provider/model, Prompt, policy, Sandbox profile 또는 동적 request 변경: 새 generation 또는 새 `analysis_id`
- 이전 attempt의 늦은 결과나 exact reference 불일치: current 결과에 연결하지 않고 stale로 격리
- 원인을 알 수 없음: 새 verdict 없이 `BLOCKED` 또는 `FAILED`와 안전한 진단을 보존

외부 제출·공개 여부는 자동 복구 대상이 아닙니다. 사람이 ReportDraft와 Markdown을 검토해 별도로 결정합니다.
