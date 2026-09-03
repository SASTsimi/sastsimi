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
   ├─ MembershipSessionAdapter
   └─ APIProviderAdapter
```

API provider는 공식 API/SDK 경계다. Membership session은 공식 지원·약관·동시성·session/log 가용성 검토를 통과해야 채택할 수 있는 `EXPERIMENTAL / FEASIBILITY_REQUIRED` adapter다. 어느 하나도 아직 기본·검증 완료 방식으로 확정하지 않는다. API key와 membership credential은 각 adapter의 secret boundary 안에 두며 Agent와 일반 log에 노출하지 않는다.

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
