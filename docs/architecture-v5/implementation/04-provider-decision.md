# R3-04. LLM Provider·인증 경로 결정

- **이 문서는 무엇을 설명하나요?** OpenAI와 Anthropic 모델을 API Key 또는 공식 구독 로그인으로 연결할 때 사용할 어댑터, 모델 선택, 지원 판정과 시험 기준을 설명합니다.
- **누가 읽어야 하나요?** R3 통합 구현자, R4 공통 계약 담당자, R8 평가 담당자와 각 LLM Agent 담당자가 읽습니다.
- **읽은 뒤 무엇을 결정해야 하나요?** 네 연결 경로의 실제 시험 결과를 확인하고 환경별 `SUPPORTED | EXPERIMENTAL | REJECTED` 상태와 첫 기본 Provider를 승인합니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 1. 기준과 결론

- 작성 기준 `main`: `3d30253acc27d57916611e0ebea2fd46344c5fa8`
- 연결 Issue: [R3-04 #90](https://github.com/SASTsimi/sastsimi/issues/90)
- 후속 결정: [R3-06 #92](https://github.com/SASTsimi/sastsimi/issues/92)
- 공식 문서 확인일: 2026-09-05

SASTSIMI는 Agent를 특정 회사·상품·인증 방식에 묶지 않는다. 모든 LLM 호출은 하나의 `LLMProviderAdapter` port를 사용하고, 실제 경로는 수정할 수 없는 `ProviderProfile` revision으로 고른다.

첫 구현 후보는 다음 네 경로다.

1. OpenAI Responses API + API Key
2. Codex CLI/SDK + ChatGPT 구독 로그인
3. Anthropic Messages API + API Key
4. Claude Code CLI + Claude 구독 로그인

네 경로는 같은 자격 증명을 공유하지 않는다. ChatGPT 구독으로 Claude를 호출하거나 Claude 구독으로 OpenAI 모델을 호출할 수 있다고 가정하지 않는다. Codex에서 Claude로 바꾼다는 말은 **SASTSIMI가 다른 ProviderProfile과 어댑터를 선택한다**는 뜻이지, Codex 로그인 안에서 Claude 모델로 바꾼다는 뜻이 아니다.

공식 경로가 존재한다는 사실과 SASTSIMI 구현이 검증됐다는 사실도 구분한다. 이 문서 작성 시점에는 실제 adapter 코드와 네 경로의 공통 E2E 시험이 없으므로 어느 경로도 SASTSIMI의 운영 `SUPPORTED`로 선언하지 않는다.

## 2. 공통 선택 단위

`ProviderProfile`은 다음 값을 한 revision으로 묶는 versioned configuration이다. 식별자와 revision은 새 방식을 만들지 않고 공통 `RecordMeta`를 사용한다. `provider_profile_ref`는 이 record의 exact `StoredDataRef(record_id + content_hash)`다.

```yaml
ProviderProfile:
  meta: RecordMeta
  profile_key: string
  provider: OPENAI | ANTHROPIC
  product: OPENAI_API | CODEX | ANTHROPIC_API | CLAUDE_CODE
  transport: RESPONSES_API | CODEX_CLIENT | MESSAGES_API | CLAUDE_CODE_CLIENT
  model: string
  environment: PERSONAL_LOCAL | TEAM_LOCAL | PRIVATE_CI | SHARED_SERVER
  auth_mode: API_KEY | SUBSCRIPTION_LOGIN
  credential_source: ENVIRONMENT | SECRET_STORE | OFFICIAL_CLIENT_SESSION
  client_name: string
  client_version: string
  capabilities: ProviderCapabilities
  support_status: SUPPORTED | EXPERIMENTAL | REJECTED
  validation_evidence_ref: StoredDataRef
  client_execution_profile_ref: StoredDataRef | null
  limitations: [string]
  checked_at: RFC3339 UTC timestamp
  evidence_urls: [string]
```

`profile_key`는 사람이 설정에서 읽기 쉬운 등록 이름이다. record 정체성과 수정본은 각각 `meta.logical_record_id`와 `meta.revision_number`가 기준이며, `profile_key`를 exact reference 대신 사용하면 안 된다.

`ProviderProfile` 한 revision은 **정확히 한 provider·product·transport·인증·client version·model·실행 환경 조합**만 나타낸다. 따라서 `LLMCallSpec.provider_profile_ref` 하나로 허가한 실행 환경까지 복원할 수 있고, spec의 `model`은 profile의 `model`과 같아야 한다. 한 모델의 개인 로컬 성공을 다른 모델·CI·공용 server에 복사하지 않는다.

시험 전 후보에는 `ProviderProfile`을 발급하지 않는다. `EXPERIMENTAL`도 제한된 환경에서 실제 필수 시험을 통과했다는 증거가 있을 때만 사용한다. `SUPPORTED | EXPERIMENTAL`은 non-null `validation_evidence_ref`가 필수다. `REJECTED`도 시험 실패 또는 운영 정책상 금지한 근거를 연결한다.

`ProviderCapabilities`에는 최소한 다음 값이 있어야 한다.

```yaml
ProviderCapabilities:
  non_interactive: SUPPORTED | UNSUPPORTED | UNVERIFIED
  structured_output: SUPPORTED | UNSUPPORTED | UNVERIFIED
  new_session: SUPPORTED | UNSUPPORTED | UNVERIFIED
  resume_session: SUPPORTED | UNSUPPORTED | UNVERIFIED
  parallel_calls: SUPPORTED | UNSUPPORTED | UNVERIFIED
  cancellation: SUPPORTED | UNSUPPORTED | UNVERIFIED
  timeout_detection: SUPPORTED | UNSUPPORTED | UNVERIFIED
  auth_expiry_detection: SUPPORTED | UNSUPPORTED | UNVERIFIED
  rate_limit_detection: SUPPORTED | UNSUPPORTED | UNVERIFIED
  request_id: SUPPORTED | UNSUPPORTED | UNVERIFIED
  token_usage: SUPPORTED | UNSUPPORTED | UNVERIFIED
  session_metadata: SUPPORTED | UNSUPPORTED | UNVERIFIED
```

비밀값, cookie, OAuth token, browser profile 경로와 실제 session credential은 `ProviderProfile`에 저장하지 않는다. `credential_source`는 비밀값의 종류와 주입 경계만 설명한다.

구독 client를 LLM 전송 경계로 사용할 때에는 다음 record도 필수다.

```yaml
ClientExecutionProfile:
  meta: RecordMeta
  execution_key: string
  working_directory_mode: ISOLATED_EMPTY
  filesystem_mode: NO_REPOSITORY_ACCESS
  tool_mode: DISABLED
  mcp_mode: DISABLED
  hooks_mode: DISABLED
  plugin_mode: DISABLED
  instruction_sources: EXPLICIT_SASTSIMI_PAYLOAD_ONLY
  environment_variable_allowlist: [string]
  network_policy_ref: StoredDataRef
  provider_fallback: DISABLED
  verification_evidence_ref: StoredDataRef
```

Codex·Claude Code는 단순 채팅 client가 아니라 파일·명령·tool을 사용할 수 있는 coding agent다. 구독 adapter는 실제 분석 저장소를 client working directory로 열지 않고 격리된 빈 directory에서 실행하며, 코드와 근거는 redacted `PromptPayload`로만 전달한다. tool·MCP·hook·plugin·project/user instruction 자동 발견·provider 자체 fallback과 불필요한 환경 변수는 모두 꺼야 한다. 사용 중인 정확한 client version에서 이 경계를 공식 옵션과 부정 시험으로 강제할 수 없으면 그 구독 조합은 `REJECTED`다. API adapter의 `client_execution_profile_ref`는 `null`, 구독 adapter는 검증된 exact profile이 필수다.

## 3. 어댑터 구조

```text
Agent Runtime
→ trusted Prompt Builder
→ Runtime Validator
→ LLM Logging Proxy
→ LLMProviderAdapter
   ├─ APIProviderAdapter
   │  ├─ OpenAIResponsesApiAdapter
   │  └─ AnthropicMessagesApiAdapter
   └─ MembershipSessionAdapter
      ├─ CodexSubscriptionAdapter
      └─ ClaudeSubscriptionAdapter
```

공통 port는 provider SDK 객체나 CLI 출력 원문을 상위 Agent에 노출하지 않는다.

```python
class LLMProviderAdapter(Protocol):
    async def probe(self, profile: ProviderProfile) -> CapabilityProbeResult: ...
    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult: ...
    async def cancel(self, llm_call_id: str) -> CancellationResult: ...
```

- `probe`: 인증 비밀을 출력하지 않고 client version, 모델 접근 가능성, 구조화 출력과 session 기능을 확인한다.
- `invoke`: 공통 요청을 공식 API·SDK·CLI 호출로 변환하고 공통 결과로 되돌린다.
- `cancel`: provider가 취소를 지원하면 실제 취소 결과를, 지원하지 않으면 `UNSUPPORTED`를 명시한다.

기능이 없는 adapter가 성공한 것처럼 빈 값을 채우면 안 된다. 공개되지 않은 usage, request ID 또는 session ID는 추정하지 않고 `null`과 capability 상태로 남긴다.

## 4. 네 연결 경로

### 4.1 OpenAI Responses API + API Key

- profile 후보: `openai.responses.api-key.v1`
- 공식 경계: OpenAI Responses API와 공식 SDK
- credential: 승인된 환경 변수 또는 secret store가 adapter process에만 주입
- 모델: API 조직·project가 실제 허용한 OpenAI model ID와 현재 환경을 별도 ProviderProfile로 등록
- 구조화 출력: Responses API JSON Schema 기능을 사용
- session: 기본 `NEW`; 이어가기가 필요하면 공식 conversation/previous response 기능을 adapter 내부에서 매핑
- 제안 환경: 개인·팀 로컬, private CI와 shared server 후보

API Key가 존재한다는 사실만으로 특정 모델 접근 권한이나 한도를 보장하지 않는다. `probe`에서 실제 조직·project의 접근 결과를 확인한다.

### 4.2 Codex + ChatGPT 구독 로그인

- profile 후보: `openai.codex.subscription.v1`
- 공식 경계: 공식 Codex CLI의 `codex exec` 또는 공식 Codex SDK
- credential: 사용자가 공식 client에서 로그인해 관리되는 session
- 모델: 그 ChatGPT 계정·workspace·client에서 실제 표시되고 호출되는 모델만 등록
- 구조화 출력: 비대화형 호출의 `--output-schema` 또는 SDK 대응 기능
- session: 새 thread를 `NEW`, 명시한 thread 재개를 `RESUME`으로 매핑
- 제안 환경: 개인·팀 로컬 우선, private CI는 신뢰 runner와 공식 인증 수단을 별도 검토

SASTSIMI는 Codex 인증 파일을 읽어 token을 추출하거나 다른 HTTP client에 재사용하지 않는다. 공식 client/SDK를 검증된 `ClientExecutionProfile`의 자식 process 또는 library 경계로 호출하고, 인증 만료는 `AUTH_REQUIRED`로 변환한다. client의 command·file·web·MCP·project instruction 기능이 남아 있으면 이 경로를 사용하지 않는다.

### 4.3 Anthropic Messages API + API Key

- profile 후보: `anthropic.messages.api-key.v1`
- 공식 경계: Anthropic Messages API와 공식 SDK
- credential: `ANTHROPIC_API_KEY` 또는 승인된 secret store
- 모델: Anthropic workspace가 실제 허용한 Claude model ID만 등록
- 구조화 출력: Messages API의 `output_config.format(type=json_schema)` 사용
- session: Messages API 입력 이력을 SASTSIMI가 exact reference로 관리하며 기본 `NEW`
- 제안 환경: 개인·팀 로컬, private CI와 shared server 후보

공유·무인 실행에서는 개인 key를 공유하지 않고 service account 또는 제공되는 workload identity 방식을 사용한다.

### 4.4 Claude Code + Claude 구독 로그인

- profile 후보: `anthropic.claude-code.subscription.v1`
- 공식 경계: 첫 구현은 공식 Claude Code CLI의 `claude -p`
- credential: Claude Pro·Max·Team·Enterprise의 공식 로그인 또는 공식 `setup-token` 경계
- 모델: 해당 구독과 client가 실제 허용한 Claude model ID만 등록
- 구조화 출력: `--output-format json --json-schema` 또는 Agent SDK 대응 기능
- session: 새 호출을 `NEW`, 공식 session ID 재개를 `RESUME`으로 매핑
- 제안 환경: 개인·팀 로컬 우선, private CI는 공식 token과 신뢰 runner에서 별도 검토

SASTSIMI는 Claude credential 파일, browser cookie 또는 token을 직접 파싱하지 않는다. 구독 사용량과 API 사용량이 같은 한도라고 가정하지 않고 provider가 공개한 값만 기록한다. `claude -p`가 built-in tool·MCP·hook·plugin·project/user instruction을 불러오지 않도록 검증된 `ClientExecutionProfile`을 강제할 수 없으면 이 경로를 사용하지 않는다.

구독 경로의 첫 허용 범위는 **구독 사용자가 자기 개발 환경에서 시작하는 내부 분석**이다. 제3자 사용자에게 Claude 로그인을 제공하거나 그 사용자를 대신해 구독 credential로 요청을 중계하는 제품 경로로 확장하지 않는다.

Claude Agent SDK는 이번 네 adapter 범위에서 제외한다. Agent SDK는 Messages API client SDK와 달리 agent loop와 tool 실행 기능을 가진 별도 제품이므로 `AnthropicMessagesApiAdapter`로 분류할 수 없고, `ClaudeSubscriptionAdapter`의 CLI 경계와도 섞지 않는다. 나중에 도입하려면 별도 `product + transport + adapter`를 정의하고 인증 방식과 무관하게 `ClientExecutionProfile`·`PVD-13` 전체를 적용하며, 사용 시점의 공식 인증·약관 범위를 검토한 새 설계와 profile revision이 필요하다.

## 5. 환경별 기본 판정

아래 표는 **실제 SASTSIMI smoke test 전의 후보 상태**다. `NOT_EVALUATED`는 ProviderProfile의 지원 상태가 아니라 profile을 아직 발급하지 않았다는 뜻이다.

| 연결 후보 | 개인 로컬 | 팀 로컬 | private CI | shared server |
|---|---|---|---|---|
| `openai.responses.api-key.v1` | `NOT_EVALUATED` | `NOT_EVALUATED` | `NOT_EVALUATED` | `NOT_EVALUATED` |
| `openai.codex.subscription.v1` | `NOT_EVALUATED` | `NOT_EVALUATED` | `NOT_EVALUATED` | `REJECTED` |
| `anthropic.messages.api-key.v1` | `NOT_EVALUATED` | `NOT_EVALUATED` | `NOT_EVALUATED` | `NOT_EVALUATED` |
| `anthropic.claude-code.subscription.v1` | `NOT_EVALUATED` | `NOT_EVALUATED` | `NOT_EVALUATED` | `REJECTED` |

구독 경로의 `shared server=REJECTED`는 개인 또는 대화형 계정 credential을 공용 서비스 credential로 쓰지 않는 현재 안전 기본값이다. 조직용 공식 비대화형 인증과 격리된 사용자별 실행 경계가 별도 ADR로 승인되면 새 profile revision에서 다시 판단할 수 있다.

### 현재 개발 PC 사전 확인

2026-09-05에 Windows 개발 PC에서 secret 값을 출력하지 않고 다음만 확인했다.

- Codex CLI `0.152.1`: 설치됨, 공식 상태 명령에서 ChatGPT 로그인 확인
- Claude Code CLI `2.1.250`: 설치됨, 로그인되지 않은 상태 확인
- OpenAI·Anthropic API adapter와 고정 SDK version: 아직 구현·선정되지 않음

이는 client 설치·인증 사전 확인일 뿐 `PVD-01`–`PVD-15` adapter 시험이 아니다. 따라서 ProviderProfile을 발급하거나 지원 상태를 정하는 증거로 사용하지 않는다.

Issue에서 요구한 `gpt-5.6-sol`, `gpt-5.6-terra`, `gpt-5.6-luna`는 OpenAI 경로의 접근 확인 후보로 사용한다. 이름이 문서나 설정에 있다는 사실만으로 접근 가능하다고 표시하지 않고, 실제 계정·client·환경별 probe에 성공한 model ID만 route로 등록한다. Claude 모델도 같은 방식으로 실제 접근 결과 뒤에 exact model ID를 등록한다.

첫 구현의 **제안 기본값**은 `openai.responses.api-key.v1`이다. 이는 최종 승인이나 성능 우위를 뜻하지 않는다. 네 경로의 smoke test와 R4 계약 검토, R8 품질·비용 평가가 끝난 뒤 #92에서 실제 기본 profile revision과 지원 상태를 확정한다.

## 6. 모델 변경과 Provider 전환

Agent 코드와 prompt template에 모델명을 넣지 않는다. Runtime은 model·environment까지 포함한 exact `provider_profile_ref`와 같은 `model`을 `LLMCallSpec`에 고정한다.

호출 전 다음을 모두 검사한다.

1. exact profile revision의 model·현재 environment가 실제 요청과 같고 상태가 `SUPPORTED` 또는 사용자가 명시적으로 허용한 `EXPERIMENTAL`인지
2. profile capability가 해당 Agent가 요구하는 structured output·session·취소·기록 조건을 충족하는지
3. 해당 Agent 역할에 필요한 structured output과 session 기능이 있는지
4. credential source가 profile의 인증 방식과 일치하는지
5. prompt·schema·timeout·budget과 실제 adapter 요청이 call spec과 같은지

다른 model·환경·인증·provider로 전환하려면 항상 다른 exact ProviderProfile을 사용하는 명시적 failover다. 새 `llm_call_id`, `LLMCallSpec`, `ActionRequest`, `ActionDecision`, session과 attempt를 만들고 `failover_from_llm_call_id`로 바로 앞의 허용된 실패 호출을 연결한다. 성공 호출 뒤 자동 전환하거나 provider가 자체 fallback을 조용히 적용하는 것은 금지한다.

## 7. 공통 오류 변환

| provider 현상 | 공통 결과 |
|---|---|
| key·구독 session 없음, 만료 또는 재로그인 필요 | `AUTH_REQUIRED` |
| 호출량 또는 구독 사용량 제한 | `RATE_LIMITED` |
| 제한 시간 안에 완료되지 않음 | `TIMED_OUT` |
| 사용자가 취소했고 adapter가 종료를 확인함 | `CANCELLED` |
| 응답은 왔지만 JSON Schema 또는 의미 검사 실패 | `INVALID_OUTPUT` |
| client 시작 실패, 지원하지 않는 model·기능, provider 오류 | `FAILED`와 구조화된 원인 |

어떤 연결 오류도 취약점 `FALSE | HOLD`로 바꾸지 않는다. 재시도와 failover는 [09. LLM provider, session과 logging](../09-llm-provider-session-and-logging.md)의 허용 상태와 새 호출 규칙을 그대로 따른다.

## 8. 지원 상태를 올리는 시험

각 `profile + client_version + model + environment` 조합을 따로 시험한다. 한 조합의 성공을 다른 인증 방식이나 환경에 복사하지 않는다.

| test ID | 확인할 내용 | 통과 기준 |
|---|---|---|
| `PVD-01` | 인증 preflight | 비밀 출력 없이 로그인/키 상태와 만료를 구분 |
| `PVD-02` | 모델 선택 | 요청 model과 실제 결과 model이 같고 미허용 model은 실행 전 차단 |
| `PVD-03` | 구조화 출력 | 같은 JSON Schema fixture가 parse되고 필수 의미 검사 통과 |
| `PVD-04` | NEW session | 이전 역할·가설 문맥이 새 호출에 포함되지 않음 |
| `PVD-05` | RESUME | 지원 경로만 exact parent session을 재개하고 미지원이면 명시 오류 |
| `PVD-06` | Pro/Con 병렬성 | 같은 입력 hash, 서로 다른 NEW session으로 동시 실행 |
| `PVD-07` | timeout·취소 | runtime 제한 시간과 사용자 취소가 공통 상태로 귀결 |
| `PVD-08` | 인증 만료·rate limit | `AUTH_REQUIRED | RATE_LIMITED`를 구분하고 verdict를 만들지 않음 |
| `PVD-09` | invalid output | 제한 repair가 새 call/action/attempt를 사용 |
| `PVD-10` | explicit failover | 원래 실패와 새 provider/model 호출이 모두 보존됨 |
| `PVD-11` | redaction | key·cookie·token·credential path·절대 경로가 prompt/result/log에 없음 |
| `PVD-12` | 관측값 | 공개된 request ID·usage·session metadata만 기록하고 미제공 값은 null |
| `PVD-13` | 구독 client 격리 | 실제 저장소 접근, command·file·web tool, MCP·hook·plugin·추가 instruction·ambient secret 사용이 모두 차단 |
| `PVD-14` | 환경 binding | local용 profile을 CI·shared server에서 사용하면 호출 전 거절하고 exact profile로 환경을 복원 가능 |
| `PVD-15` | 이용 범위·약관 | 인증 종류·계정 유형·실행 환경·내부/서비스 사용 목적이 provider의 현재 공식 허용 범위와 일치하고 검토 근거를 보존 |

`SUPPORTED`로 올리려면 `PVD-01`–`PVD-15`가 그 조합에서 통과하고 증거에 다음이 포함되어야 한다. API 경로의 `PVD-13`은 client tool이 없음을 확인해 `NOT_APPLICABLE`로 기록할 수 있지만 생략하지 않는다.

- exact client/SDK version과 model ID
- 실행 환경과 인증 종류
- redaction된 명령·입력 fixture·output schema
- 종료 코드 또는 API status와 normalized result
- 공개 가능한 invocation log reference
- 확인자와 확인 시각, 기준 commit SHA

credential·cookie·token·원문 인증 파일은 증거로 첨부하지 않는다.

## 9. 공식 근거

다음 공식 문서를 기준으로 경로 존재 여부만 확인했다. 실제 SASTSIMI adapter 통과 증거는 별도로 필요하다.

- OpenAI Codex 인증: <https://learn.chatgpt.com/docs/auth>
- OpenAI Codex 비대화형 실행과 JSON Schema: <https://learn.chatgpt.com/docs/non-interactive-mode>
- OpenAI Codex 모델 선택: <https://learn.chatgpt.com/docs/models>
- OpenAI Responses API: <https://developers.openai.com/api/reference/cli/resources/responses/methods/create>
- OpenAI 개인용 이용약관: <https://openai.com/policies/terms-of-use/>
- OpenAI API·비즈니스 서비스 계약: <https://openai.com/policies/services-agreement/>
- Claude Code 인증: <https://code.claude.com/docs/en/authentication>
- Claude Code 비대화형 실행과 JSON Schema: <https://code.claude.com/docs/en/headless>
- Claude Code CLI 모델 선택: <https://code.claude.com/docs/en/cli-reference>
- Anthropic API 인증: <https://platform.claude.com/docs/en/manage-claude/authentication>
- Anthropic Messages API 구조화 출력: <https://platform.claude.com/docs/en/build-with-claude/structured-outputs>
- Anthropic Consumer Terms: <https://www.anthropic.com/legal/consumer-terms>
- Anthropic Commercial Terms: <https://www.anthropic.com/legal/commercial-terms>
- Claude Code 인증·credential 사용 범위: <https://code.claude.com/docs/en/legal-and-compliance>

## 10. 미완료 증거와 종료 조건

이 문서만으로 #90을 닫지 않는다. 다음 증거가 없기 때문이다.

- 네 경로별 실제 `PVD-01`–`PVD-15` 결과
- 역할별 필요한 model의 실제 계정 접근 범위
- private CI의 credential 격리·취소·동시성 검증
- R8의 동일 fixture 품질·시간·사용량 비교
- R4의 profile·session·retry·failover·secret·log 계약 승인

위 증거가 준비되면 model·환경 조합마다 별도 ProviderProfile을 발급한다. `EXPERIMENTAL`을 `SUPPORTED`로 바꾸는 새 revision에는 시험 증거와 검토 기준 SHA가 반드시 있어야 한다.
