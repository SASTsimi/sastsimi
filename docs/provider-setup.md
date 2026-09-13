# Provider 인증과 운영 활성화

이 문서는 LLM 연결 정보, 검증 근거와 Prompt 승인을 준비하는 방법을 설명합니다. API key나 회원 로그인 정보 자체를 저장하는 문서가 아닙니다.

## 1. 공통 원칙

- Agent의 이름·역할·입출력은 Provider나 모델에 고정되지 않습니다.
- 실제 호출은 승인된 `provider_profile_ref + model`로 정합니다.
- model을 바꾸면 같은 Agent라도 새 Provider 검증·평가·승인이 필요할 수 있습니다.
- API key, access token, cookie, browser profile, 로그인 session과 실제 secret을 TOML·Markdown·Issue·PR·로그에 적지 않습니다.
- 인증 실패는 가설 반증이 아닙니다. `FALSE`를 만들지 않고 LLM work를 `AUTH_REQUIRED`, `BLOCKED` 또는 verdict 없는 `FAILED`로 남깁니다.

계약에는 여러 Provider 이름이 있어도 실제 adapter와 완전한 검증 근거가 있는 경로만 production에서 사용할 수 있습니다.

## 2. OpenAI Responses API

OpenAI API key는 코드나 profile에 넣지 않고 실행 환경의 secret으로 주입합니다. 공식 OpenAI 문서도 SDK가 환경변수에서 key를 읽는 방법을 안내합니다. [OpenAI API quickstart](https://platform.openai.com/docs/quickstart/make-your-first-api-request)를 참고하세요.

profile에는 실제 값이 아니라 변수 이름만 적습니다.

```text
credential_ref = { reference = "env:OPENAI_API_KEY" }
```

운영 shell 또는 secret store가 `OPENAI_API_KEY` 값을 안전하게 주입해야 합니다. 출력, shell history, 화면 공유와 저장소에 실제 값을 남기지 않습니다.

capability 명령이 포함된 설치본에서는 작은 연결 시험을 실행할 수 있습니다.

```text
uv run sastsimi --data-dir <data-dir> capability probe OPENAI_API --model <model-id> --credential-ref env:OPENAI_API_KEY --format json
```

이 probe는 인증과 구조화 출력만 확인합니다. 현재 구현은 성공해도 `activation_supported=false`이며, 이 결과만으로 `ProviderProfile.support_status=SUPPORTED`를 만들 수 없습니다. production 활성화에는 아래 onboarding의 PVD-01~PVD-15, 현재 약관 확인, R8 평가, 사람 승인과 Prompt 승인이 모두 필요합니다.

## 3. Codex 회원 로그인 — EXPERIMENTAL

Codex 회원 로그인은 공식 Codex CLI 경로만 허용합니다. 브라우저 cookie를 읽거나 browser profile을 복사해 연결하지 않습니다. 공식 인증 안내는 [Codex 인증 문서](https://developers.openai.com/codex/auth/)를 참고하세요.

```text
codex login
codex login status
```

현재 저장소에는 공식 Codex CLI를 감싸는 adapter와 격리 경계 시험이 있습니다. 그러나 이 경로의 `support_status`는 `EXPERIMENTAL`이며 production 자동 활성화가 금지되어 있습니다. 로그인 성공이나 adapter 존재만으로 실제 분석 route에 선택할 수 없습니다.

다음 증거를 별도 승인 환경에서 모두 확보하기 전에는 Codex 회원제를 production profile 예시에 넣지 않습니다.

- 승인된 Codex 실행 파일의 절대 경로·version·SHA-256
- 격리된 `CODEX_HOME`과 `OFFICIAL_CLIENT_SESSION`
- repository, shell, web, MCP, hook, plugin과 ambient secret을 사용하지 않는 no-tools 경계
- PVD-01~PVD-15와 필요한 경우 PVD-16
- 정확한 model identity, 구조화 출력, 새 독립 session, timeout·취소·사용량 기록
- R8 평가와 사람의 production 승인

## 4. onboarding 명령의 역할

onboarding 명령은 “시험을 대신 수행해 PASS를 만들어 주는 명령”이 아닙니다. 외부에서 실제로 수집하고 사람이 승인한 근거를 가져와, 현재 profile·Provider·model·Prompt와 정확히 같은지 다시 확인합니다.

먼저 필요한 항목을 조회합니다.

```text
uv run sastsimi --data-dir <data-dir> onboarding requirements --profile <production-profile.toml> --format json
```

이 명령은 필요한 PVD 번호, Prompt route와 template hash를 보여 주고 `BLOCKED`로 끝납니다. 준비 완료를 뜻하지 않습니다.

운영 담당자는 다음을 별도 승인 절차에서 준비합니다.

- PVD-01~PVD-15의 실제 관측 파일과 SHA-256
- 현재 Provider 약관 확인자·확인 시각·유효 기한
- R8 평가 결과와 `ACCEPT_FOR_PRODUCTION` 추천
- 각 route의 정확한 Prompt template hash와 사람 승인
- 공식 정책 원문의 안전한 artifact와 SHA-256
- 위 값을 묶은 secret 없는 `ProductionOnboardingManifest` JSON

현재 CLI에는 이 근거를 자동으로 만들어 승인하는 명령이 없습니다. 값을 추측해 manifest를 작성하거나 다른 실행의 근거를 재사용하면 안 됩니다. 필드 의미와 안전한 작성 순서는 [운영 onboarding manifest와 근거 작성 안내](./onboarding-evidence.md)를 따릅니다.

준비한 manifest와 그 안에서 참조하는 모든 근거 파일을 가져옵니다. `--evidence`는 필요한 파일 수만큼 반복합니다.

```text
uv run sastsimi --data-dir <data-dir> onboarding prepare --profile <production-profile.toml> --manifest <approval-manifest.json> --evidence <evidence-1.json> --evidence <evidence-2.json> --format json
```

마지막으로 현재 시각에도 모든 승인이 유효한지 다시 확인합니다.

```text
uv run sastsimi --data-dir <data-dir> onboarding status --profile <production-profile.toml> --format json
```

`status=READY`일 때만 해당 profile로 분석을 요청할 수 있습니다. 파일 수정, Prompt 변경, model 변경, 유효 기한 만료 또는 근거 hash 변경이 있으면 다시 `BLOCKED`가 됩니다.

## 5. production profile

예시는 [`config/profiles/production.example.toml`](../config/profiles/production.example.toml)에 있습니다. 이 파일은 구조를 설명하는 template이며 승인 자료가 아닙니다.

반드시 다음 값을 실제 승인 내용으로 바꿉니다.

- 절대 `workspace_root`
- 프로그램과 공식 정책 정보
- 실행 파일 이름 또는 승인 경로
- 정확한 Provider client version과 model
- 역할별 승인 Prompt key
- 사람이 승인한 budget과 유효한 onboarding manifest

실제 secret은 바꾸어 넣지 않습니다. `credential_ref`에는 `env:NAME`처럼 secret의 위치만 둡니다.

## 6. 현재 지원 상태 확인

- OpenAI API adapter: 구현되어 있으나 exact full PVD·평가·사람 승인·onboarding을 통과한 profile만 production 후보입니다.
- Codex 회원 로그인 adapter: `EXPERIMENTAL`, production 자동 활성화 불가입니다.
- Anthropic API·Claude Code 회원 로그인: 계약 이름만으로 지원을 주장하지 않습니다. 현재 production adapter와 검증 증거가 없으면 사용할 수 없습니다.
- Fake Provider: 테스트·시연 전용이며 production fallback이 아닙니다.

전체 Fake 없는 production 실행은 아직 출시 증거가 완성되지 않았습니다. `READY`나 `ACTIVE`를 설정 파일에서 임의로 만들지 말고 실제 capability와 onboarding 결과를 기다립니다.
