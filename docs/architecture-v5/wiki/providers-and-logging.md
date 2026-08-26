# Provider, session과 logging

## Provider abstraction

```text
Agent Runtime
→ LLM Logging Proxy
→ LLMProviderAdapter
   ├─ MembershipSessionAdapter
   └─ APIProviderAdapter
```

API provider는 공식 API/SDK 경계다. Membership session은 공식 지원·약관·동시성·session/log 가용성 검토를 통과해야 채택할 수 있는 `EXPERIMENTAL / FEASIBILITY_REQUIRED` adapter다. 어느 하나도 아직 기본·검증 완료 방식으로 확정하지 않는다. API key와 membership credential은 각 adapter의 secret boundary 안에 두며 Agent와 일반 log에 노출하지 않는다.

provider/model failover는 조용히 수행하지 않는다. 실패한 호출과 fallback 호출을 서로 연결된 별도 invocation으로 기록한다.

## SessionPolicy

- `NEW`: 독립 새 session
- `RESUME`: 명시한 parent session 재사용
- `AUTO`: 역할·가설 관계로 결정

같은 역할·가설의 추가 retrieval과 같은 Verification의 Gate revision은 RESUME 가능하다. 다른 가설, Pro/Con 상호 간, Verification/Research/Gates/Reporter 사이에는 NEW가 기본이다. 실제 결정과 token 절감·confirmation bias·prompt contamination 비교 지표를 남긴다.

## Logging

가능하면 Logging Proxy가 exposed request/response, tool trace, provider/model/session, retrieved code location, schema repair, usage와 오류를 `LLMInvocationLog`로 정규화한다. Membership client에 proxy 적용이 어려우면 raw session log를 provider parser와 redaction을 거쳐 정규화한다.

hidden chain-of-thought, cookie, token, API key와 불필요한 전체 코드는 저장하지 않는다.

상세 내용은 [LLM provider, session과 logging](../09-llm-provider-session-and-logging.md)을 따른다.
