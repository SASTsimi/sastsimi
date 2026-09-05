# Provider, session과 logging

## 쉽게 말하면

LLM을 회원 로그인이나 API로 연결하는 공통 방법, 새 대화·이어가기 규칙과 호출·오류 기록 방법을 설명합니다.

**상세 기준:** [09. LLM provider, session과 logging](../09-llm-provider-session-and-logging.md)

`provider`는 LLM 연결 방식, `session`은 로그인·대화 상태, `logging`은 실행 기록입니다. 자세한 용어는 [쉬운 용어집](../../GLOSSARY.md)을 따릅니다.

## LLM 연결 공통 구조

```text
Agent Runtime
→ LLM Logging Proxy
→ LLMProviderAdapter
   ├─ APIProviderAdapter
   │  ├─ OpenAI Responses API
   │  └─ Anthropic Messages API
   └─ MembershipSessionAdapter
      ├─ Codex + ChatGPT 구독 로그인
      └─ Claude Code + Claude 구독 로그인
```

API provider는 공식 API/SDK 경계다. Membership session은 공식 지원·약관·동시성·session/log 가용성 검토를 통과해야 채택할 수 있는 `EXPERIMENTAL / FEASIBILITY_REQUIRED` adapter다. 어느 하나도 아직 기본·검증 완료 방식으로 확정하지 않는다. API key와 membership credential은 각 adapter의 secret boundary 안에 두며 Agent와 일반 log에 노출하지 않는다. 구독 경로는 구독 사용자가 자기 개발 환경에서 시작하는 내부 분석 후보이며, 제3자 사용자를 대신해 구독 credential로 요청을 중계하는 서비스 경로로 확장하지 않는다. Claude Agent SDK는 이번 네 경로에서 제외하며, 나중에 도입하려면 Messages API나 Claude CLI와 합치지 않고 별도 adapter·격리·약관 검토를 거친다.

네 연결 경로의 구체적인 차이와 시험 기준은 [R3-04 Provider 결정](../implementation/04-provider-decision.md)에 정리한다. ChatGPT 구독은 OpenAI/Codex 경로에만, Claude 구독은 Anthropic/Claude Code 경로에만 사용한다. Provider를 바꿀 때는 model 이름만 교체하지 않고 새 profile·adapter·call ID·session으로 실행한다.

ProviderProfile 하나는 provider·인증·client version뿐 아니라 model과 실행 환경 하나까지 고정합니다. 시험하지 않은 후보는 실행 가능한 `EXPERIMENTAL`로 표시하지 않습니다. 구독형 Codex·Claude Code는 원래 파일과 명령을 다룰 수 있으므로, 실제 저장소가 없는 격리 directory에서 tool·MCP·hook·plugin·추가 instruction을 모두 끌 수 있을 때만 LLM 전송 경로로 사용합니다. 이 격리를 증명하지 못하면 해당 구독 경로를 거절합니다.

R7이 Sandbox 안에서 명령을 반복 실행할 때도 provider 내장 tool은 켜지 않습니다. 모델은 다음 작업을 구조화된 형식으로 제안하고, SASTSIMI Runtime이 허용 여부를 검사해 격리 container 안에서만 실행한 뒤 결과를 다시 전달합니다. 이 기능을 실제 시험해 `runtime_tool_loop=SUPPORTED`가 된 ProviderProfile만 R7 실행에 사용할 수 있습니다. 다른 Agent에서 사용할 수 있는 Provider라도 이 기능이 없으면 R7에는 배정하지 않습니다.

provider/model failover는 조용히 수행하지 않는다. 모든 retry와 fallback 호출은 새 `llm_call_id`를 사용한다. 일반 retry는 `retry_of_llm_call_id`, provider/model 전환은 `failover_from_llm_call_id`로 바로 앞의 허용된 실패 호출을 가리킨다. 두 필드를 동시에 사용하지 않으며 이 연결을 따라 최초 실패부터 마지막 결과까지 순서와 원인을 확인할 수 있어야 한다.

선행 상태는 `FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED`만 허용한다. `INVALID_OUTPUT`은 제한된 repair 뒤, `RATE_LIMITED`는 backoff 뒤, `AUTH_REQUIRED`는 재인증 뒤에만 retry한다. failover는 미리 허용한 profile과 전환 이유가 필요하다. `SUCCEEDED`나 `CANCELLED` 뒤에는 같은 retry/failover chain을 잇지 않으며, 새 작업이면 선행 reference가 없는 독립 호출로 시작한다.

LLM 호출 상태는 `SUCCEEDED | FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED | CANCELLED`다. 호출 실패·인증 필요·rate limit·timeout은 취약점 `FALSE`가 아니다.

Pro와 Con은 항상 서로 다른 새 대화에서 시작합니다. 두 호출 모두 `NEW`, `parent_session_ref=null`이고 서로 다른 call ID·session·action·decision을 사용합니다. 재시도나 provider 변경 때도 상대 역할의 대화나 결론을 이어받지 않습니다. 두 역할이 공통으로 읽어도 되는 것은 같은 가설과 검증된 코드 사실뿐입니다.

독립성은 대화 분리만 뜻하지 않습니다. trusted prompt builder(허용된 입력만 조립하는 프로그램)가 역할별 prompt를 만들고, Pro는 Con 결과를, Con은 Pro 결과를 prompt·context·저장소 조회·도구 결과로 받을 수 없습니다. 위반하면 `CROSS_ROLE_INPUT_DENIED`로 호출과 합류를 중단합니다.

성공한 호출의 log는 Pro 또는 Con의 exact `EvidenceAgentResult`를 가리킵니다. 부모 Verification은 같은 부모·generation·공통 입력 hash의 두 결과만 최종 합성에 사용합니다.

일반 Agent의 provider 호출은 `CALL_LLM` action을 사용합니다. 두 Gate와 Reporter는 각각 자기 stage action이 LLM 호출까지 직접 허가하므로 별도 `CALL_LLM`으로 우회하지 않습니다. 모든 호출은 model·prompt·context·출력 형식·예산·시간을 적은 immutable `LLMCallSpec`과 실제 요청이 정확히 같을 때만 실행합니다. retry와 failover도 새 spec·action·decision이 필요합니다.

LLM 호출은 상위 `work_id`의 한 attempt로 실행한다. 재시도 가능한 호출 실패는 실패 attempt를 보존하고 작업을 `BLOCKED`로 둔다. 재인증·backoff·repair 같은 조건이 해결되면 새 `attempt_id`와 `llm_call_id`로 시작한다. 취소되었거나 이전 attempt에서 늦게 도착한 응답은 최신 결과에 연결하지 않는다.

## SessionPolicy

- `NEW`: 독립 새 session
- `RESUME`: 명시한 parent session 재사용
- `AUTO`: 역할·가설 관계로 결정

같은 역할·가설의 추가 retrieval과 같은 Verification owner의 Gate revision 보완은 RESUME 가능하다. 다른 가설, Pro/Con 상호 간, Verification/Chaining/Gates/Reporter 사이에는 NEW가 기본이다. 실제 결정과 token 절감·confirmation bias·prompt contamination 비교 지표를 남긴다.

## Logging

가능하면 Logging Proxy가 exposed request/response, tool trace, provider/model/session, retrieved code location, schema repair, usage와 오류를 `LLMInvocationLog`로 정규화한다. Membership client에 proxy 적용이 어려우면 raw session log를 provider parser와 redaction을 거쳐 정규화한다.

hidden chain-of-thought, cookie, token, API key와 불필요한 전체 코드는 저장하지 않는다.

상세 내용은 [LLM provider, session과 logging](../09-llm-provider-session-and-logging.md)을 따른다.
