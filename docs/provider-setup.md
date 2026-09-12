# Provider 인증과 운영 활성화

이 문서는 API key 또는 공식 회원 로그인을 SASTSIMI에 연결할 때 지켜야 할 조건을 설명합니다.

## 1. 공통 원칙

- Agent의 이름·역할·입출력은 특정 Provider나 모델에 고정되지 않습니다.
- 실제 호출 경로는 승인된 `provider_profile_ref`와 호출의 `model`로 정합니다.
- 설정에 Provider 이름이나 model을 적었다는 이유만으로 사용할 수 없습니다. 정확한 client·version·인증 방식·model·실행 환경 조합이 capability 시험을 통과하고 사람 승인을 받아야 합니다.
- API key, access token, cookie, browser profile, 회원 로그인 session 또는 실제 secret을 TOML·Markdown·Issue·PR·로그에 적지 않습니다.
- 인증 실패는 취약점 `FALSE`가 아닙니다. 해당 LLM work는 verdict 없이 `AUTH_REQUIRED`, `BLOCKED` 또는 `FAILED`로 남습니다.

현재 계약에는 `OPENAI_API`, `CODEX`, `ANTHROPIC_API`, `CLAUDE_CODE` 이름이 있지만, 계약에 이름이 있다는 것은 adapter가 현재 설치본에서 지원된다는 뜻이 아닙니다. 아래 조건을 모두 만족하는 경로만 사용합니다.

1. 설치본에 해당 production adapter가 존재합니다.
2. exact Provider 검증 항목이 통과했습니다.
3. `ProviderProfile.support_status=SUPPORTED`입니다.
4. 현재 실행 환경과 승인된 환경이 같습니다.
5. 운영 Prompt와 평가 승인이 같은 profile·model을 허용합니다.

## 2. OpenAI Responses API key

SASTSIMI 설정에는 key 값 대신 환경변수 이름만 적습니다.

```text
credential_ref = { reference = "env:OPENAI_API_KEY" }
```

실제 값은 실행 환경의 secret store나 shell 밖의 안전한 주입 경로로 제공합니다. OpenAI도 API key를 코드에 넣지 않고 환경변수나 key management service에서 불러오도록 안내합니다. 자세한 내용은 [OpenAI API quickstart](https://platform.openai.com/docs/quickstart/make-your-first-api-request)를 확인합니다.

아래는 변수 이름만 보여 주는 예시입니다. 실제 key를 명령 기록, 설정 파일 또는 화면 공유에 남기지 마세요.

```text
OPENAI_API_KEY=<실행 환경에서 안전하게 주입>
```

현재 `OpenAIResponsesApiAdapter`는 tools, provider-side persistence, background 실행과 자동 fallback을 사용하지 않는 Responses API 경계입니다. 다만 adapter 코드가 존재한다는 사실만으로 운영 지원을 선언할 수 없습니다. 해당 exact profile이 실제 probe와 승인을 통과해야 합니다.

## 3. Codex 회원 로그인

Codex 회원 로그인은 공식 Codex CLI 경로만 허용합니다. 브라우저 cookie를 읽거나 browser profile을 복사해 연결하지 않습니다.

공식 로그인과 상태 확인 명령은 다음과 같습니다.

```text
codex login
codex login status
```

공식 Codex 문서는 `codex login`이 ChatGPT 브라우저 로그인 흐름을 시작하고, `codex login status`가 현재 인증 방식을 확인한다고 설명합니다. 자세한 내용은 [Codex 인증 안내](https://developers.openai.com/codex/auth/)를 확인합니다.

SASTSIMI에서 이 경로를 운영에 사용하려면 설치본에 공식 Codex CLI adapter가 포함되어야 하며, 실행 파일 경로·SHA-256, client version, 격리된 `CODEX_HOME`, ChatGPT 로그인 상태와 no-tools 실행 경계가 승인된 exact profile과 일치해야 합니다. 특히 실제 저장소 접근, shell·web tool, MCP, hook, plugin, 추가 instruction과 ambient secret을 차단하는 검증을 통과하지 못하면 사용할 수 없습니다.

Codex CLI가 로그인되어 있다는 사실만으로 SASTSIMI용 `SUPPORTED` profile이 생기지 않습니다. profile 승인 기록이 없으면 운영 호출은 차단되어야 합니다.

## 4. 현재 지원을 확인하는 방법

운영 담당자는 다음을 모두 확인합니다.

- Provider adapter가 설치 artifact에 포함되어 있는지
- API key는 `env:NAME` 또는 승인된 opaque `handle:UUID`로만 참조하는지
- 회원 로그인은 `OFFICIAL_CLIENT_SESSION` 경로인지
- Provider/model별 검증 결과가 `PASS`인지
- 일반 역할은 PVD-01~PVD-15, 동적 재현 역할은 PVD-16까지 통과했는지
- `support_status=SUPPORTED`인 current exact profile인지
- 운영 Prompt activation과 평가 승인이 같은 profile/model을 가리키는지

현재 공개 CLI에 profile probe·승인 명령이 없다면 설정 파일을 손으로 바꿔 대신 승인하지 않습니다. 해당 release는 production 분석 준비가 끝나지 않은 것으로 보고 `CAPABILITY_UNSUPPORTED`를 유지합니다.

## 5. Provider 설정의 최소 모양

생산 profile의 Provider 항목에는 secret 값이 아니라 연결 식별 정보와 secret 참조만 둡니다.

```text
[[providers]]
provider_profile_key = "approved-openai-profile"
product = "OPENAI_API"
environment = "PERSONAL_LOCAL"
client_name = "openai-python"
client_version = "<승인한-version>"
credential_ref = { reference = "env:OPENAI_API_KEY" }
```

Agent별 route는 model을 고정 상수로 만드는 곳이 아니라, 이번 profile에서 사용할 승인된 model을 선택하는 곳입니다.

```text
[[llm_routes]]
role = "HYPOTHESIS"
task_kind = "GENERATE_INITIAL"
provider_profile_key = "approved-openai-profile"
model = "<승인한-model-id>"
prompt_key = "<승인된-production-prompt-key>"
```

이 TOML만으로 profile이나 Prompt가 승인되지는 않습니다. current exact `ProviderProfile`, 평가 recommendation, 사람 승인과 production Prompt activation이 별도로 저장되어 있어야 합니다.

