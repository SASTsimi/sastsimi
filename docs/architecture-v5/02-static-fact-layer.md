# 02. 정적 사실 계층과 코드 문맥 조회

- **이 문서는 무엇을 설명하나요?** AST와 SAST 결과를 LLM이 사용할 코드 사실로 정리하고 필요한 코드만 다시 가져오는 방법을 설명합니다.
- **누가 읽어야 하나요?** 정적분석·컨텍스트, LLM 탐색과 검증 담당자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 어떤 사실과 코드 위치를 제공할지, 조회 범위와 한도를 확인합니다.

`retrieval`은 필요한 코드를 위치 기준으로 다시 가져오는 작업입니다. 다른 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 정적 분석의 역할

AST parser와 SAST 도구는 취약점 판정기가 아니라 LLM Agent가 확인할 사실 후보의 공급자다. 같은 `CodeWorkspace`에서 병렬 실행하고 다음 정보를 공통 형식으로 정규화한다.

- source, sink, sanitizer와 validator 후보
- 함수·메서드·클래스·route·configuration 등 entity
- file, symbol, start/end line과 안정적인 location reference
- caller/callee, import, inheritance, route binding과 data-flow edge
- 인증·인가·역할·소유권 확인 로직 후보
- 도구 rule id, message, severity와 원본 결과 reference
- 분석하지 못한 언어·파일·generated code·resolution gap

SAST rule hit와 불완전한 경로는 관찰된 사실 후보이지 취약점 확정이 아니다. 도구 결과가 없거나 문맥 조회가 비어 있는 것도 안전함이나 `FALSE`의 증거로 자동 해석하지 않는다.

## StaticFactBundle

`StaticFactBundle`은 raw output 전체를 프롬프트에 밀어 넣지 않고 위치와 관계 중심으로 필요한 사실을 찾게 하는 시작점이다.

```yaml
static_fact_bundle:
  workspace_id: ws-001
  entities: []
  locations: []
  source_candidates: []
  sink_candidates: []
  call_edges: []
  data_flow_candidates: []
  auth_and_permission_checks: []
  route_bindings: []
  tool_observations: []
  gaps: []
```

각 항목은 가능한 경우 `workspace_id`, `entity_ref`, `location_ref`, producer와 원본 artifact reference를 갖는다. 정규화 계층은 서로 다른 도구 결과를 병합하되 충돌이나 불확실성을 지우지 않는다.

## 위치 기반 on-demand retrieval

Hypothesis Agent는 전체 코드가 아니라 entity, location과 suspected path를 제안한다. Verification·Pro·Con·Research·Technical Gate는 필요한 추가 문맥을 `CodeContextRequest`로 요청한다.

1. 가설의 `entity_ref`, `location_ref`, `suspected_path`에서 시작한다.
2. 분석 목적에 맞는 관계를 명시한다.
3. Context Retrieval Service가 동일한 `workspace_id`와 연결된 `commit_id`인지, 요청이 budget 안인지 검증한다.
4. 허용된 깊이까지 필요한 fragment와 관계만 조회한다.
5. `CodeContextResponse`에 반환 위치·관계·gap을 기록한다.
6. 실제 LLM 호출이 열람한 location reference를 `LLMInvocationLog`에 남긴다.

지원 관계의 초기 집합은 다음과 같다.

- `CALLERS`: 현재 entity를 호출하는 위치
- `CALLEES`: 현재 entity가 호출하는 위치
- `DATA_FLOW_NEIGHBORS`: 인접 source, transform, sanitizer, sink 후보
- `AUTH_GUARDS`: 인증·인가·역할·소유권 검사의 적용 위치
- `ROUTE_BINDINGS`: 외부 endpoint와 handler 연결

## 요청과 응답 예시

```yaml
code_context_request:
  code_request_id: ctxreq-001
  hypothesis_id: hyp-001
  workspace_id: ws-001
  requested_entities: [entity:OrderController.update]
  requested_locations: [loc:src/order.ts:41]
  relation_query: [CALLERS, AUTH_GUARDS]
  reason: verify whether ownership checks cover the update path
  max_depth: 3
  token_budget: 6000
```

```yaml
code_context_response:
  code_request_id: ctxreq-001
  workspace_id: ws-001
  entities: []
  locations: []
  code_fragment_refs: []
  discovered_relations: []
  gaps: []
  truncated: false
  consumed_token_estimate: 2400
```

## 일관성·예산·보안 규칙

- 응답의 `workspace_id`가 가설과 다르거나 작업공간의 `commit_id`가 분석 대상과 다르면 사용하지 않고 `WORKSPACE_MISMATCH`로 기록한다.
- `max_depth`, fragment 수, byte/token budget, 요청 횟수와 wall-clock limit을 적용한다.
- 반복 요청은 normalized request fingerprint로 탐지한다.
- symlink escape, submodule drift와 path traversal을 차단하고 `workspace_root` 안의 파일만 읽는다.
- `file_path`는 `workspace_root` 기준 상대 경로이고 줄과 열 번호는 1부터 시작한다.
- 분석 중 HEAD 또는 추적 파일이 바뀌면 `WORKSPACE_CHANGED`로 기록하고 해당 작업공간의 새 결과를 사용하지 않는다.
- 민감 파일과 생성물 제외 정책을 적용하되 제외 사실은 gap으로 남긴다.
- LLM log에는 전달된 위치와 artifact reference를 우선 저장하고 전체 코드 원문 복제를 기본값으로 삼지 않는다.
- truncation이나 unresolved symbol은 숨기지 않고 `gaps`와 `truncated`에 표시한다.

## 품질 기준

정적 사실은 원본 위치로 추적할 수 있어야 한다. Verification verdict, CWE와 Technical Gate 검토가 사용하는 핵심 주장은 적어도 하나의 실제 location 또는 동적 evidence에 연결되어야 하며, 연결되지 않는 추론은 assumption이나 unresolved condition으로 남긴다.
