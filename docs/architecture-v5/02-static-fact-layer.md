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
- file, symbol, start/end line·column과 정규화된 `CodeLocation`
- caller/callee, import, inheritance, route binding과 data-flow edge
- 인증·인가·역할·소유권 확인 로직 후보
- 도구 이름·버전·rule id·message·severity, 실행 설정·규칙 catalog와 원본 결과 reference
- 도구별 성공·부분 성공·실패, 실제 분석·제외 경로와 언어 범위
- 규칙별 선택·실행 여부와 raw 탐지 건수
- 분석하지 못한 언어·파일·generated code·resolution gap

SAST rule hit와 불완전한 경로는 관찰된 사실 후보이지 취약점 확정이 아니다. 도구 결과가 없거나 문맥 조회가 비어 있는 것도 안전함이나 `FALSE`의 증거로 자동 해석하지 않는다.

## StaticFactBundle

`StaticFactBundle`은 raw output 전체를 프롬프트에 밀어 넣지 않고 위치와 관계 중심으로 필요한 사실을 찾게 하는 시작점이다.

```yaml
static_fact_bundle:
  meta:
    analysis_id: analysis-001
    workspace_id: ws-001
    commit_id: 7f3a2c1
    hypothesis_id: null
  entities: []
  locations: []
  source_candidates: []
  sink_candidates: []
  call_edges: []
  data_flow_candidates: []
  auth_and_permission_checks: []
  route_bindings: []
  tool_runs: []
  gaps: []
  errors: []
```

`CodeFact`와 `CodeRelation`은 같은 `workspace_id + commit_id`의 `CodeLocation`, producer와 원본 `StoredDataRef`를 갖는다. `ToolRunResult`는 도구별 상태·coverage·gap·error를 함께 기록한다. 정규화 계층은 서로 다른 도구 결과를 병합하되 충돌이나 불확실성을 지우지 않는다. `StaticFactBundle.errors`가 비었다는 사실만으로 도구가 성공했다고 추정하지 않고 각 `tool_runs.status`를 확인한다.

CodeQL·OpenGrep처럼 규칙을 실행하는 도구는 `ToolRunResult.tool_kind=RULE_BASED`와 별도 `RuleExecutionRecord`를 만들고 `rule_execution_ref`로 exact record를 연결한다. AST parser처럼 개별 규칙이 없는 도구는 `tool_kind=STRUCTURE`, `rule_execution_ref=null`이다. 규칙 실행 record에는 도구·버전, 실행 설정, 비교 기준이 되는 규칙 catalog, 선택한 rule pack과 규칙별 `selection_status`, `execution_status`, `hit_count`가 들어간다. `RunMeta`에는 이런 도구별 내용을 넣지 않는다.

- `SELECTED + EXECUTED + hit_count=0`: 규칙을 실행했지만 탐지 결과가 0건이다.
- `SELECTED + NOT_EXECUTED`: 선택했지만 실행하지 못했다. 이유를 함께 기록한다.
- `NOT_SELECTED + NOT_EXECUTED`: 분석 계획에서 제외해 실행하지 않았다.
- `SELECTED + UNKNOWN`: 오류나 실행 기록 부족으로 실제 실행 여부를 확인할 수 없다.

도구 실패·timeout·실행 기록 누락을 `EXECUTED + hit_count=0`으로 바꾸지 않는다. `CodeFact.producer.attempt_id`는 자신을 만든 exact `ToolRunResult.attempt_id`와 같아야 한다. `producer.rule_id`는 hit이 생겼을 때만 존재하므로 `CodeFact`가 없다는 사실만으로 규칙을 실행했거나 결과가 0건이었다고 추정하지 않는다. 정확한 필드·상태 조합과 retry 규칙은 [경량 데이터 계약](./08-lightweight-data-contracts.md)의 `RuleExecutionRecord`를 따른다.

`ToolRunResult.status`는 다음 의미를 갖는다.

- `SUCCEEDED`: 요청한 지원 범위를 끝까지 분석했고 알려진 누락이 없다.
- `PARTIAL`: 사용할 수 있는 결과가 있지만 일부 path·language·rule 실행이 빠졌다. 빠진 범위는 `coverage`와 `gaps`에 남긴다.
- `FAILED`: 사용할 수 있는 정규 결과를 만들지 못했다. 실패 사건은 `errors`에 남긴다.
- `SKIPPED`: 정책·설정·지원 여부 때문에 실행하지 않았다. 이유와 영향 범위는 `gaps`에 남긴다.

한 도구가 `FAILED | SKIPPED`여도 다른 도구의 사용 가능한 사실을 버리지 않는다. 이때 전체 묶음에는 해당 `ToolRunResult`, 존재하는 `RuleExecutionRecord`, `DataGap`, 필요한 `AnalysisError`가 함께 있어야 한다. retry는 같은 `work_id`의 새 `attempt_id`와 새 규칙 실행 record를 사용하며 이전 시도의 규칙 상태나 탐지 수를 합치지 않는다.

## submodule, Git LFS와 생성 파일

- 분석 범위에 submodule이 필요하면 `Repository Loader`가 명시적으로 초기화한다. 실패한 submodule과 영향 범위는 `DataGap`으로 남긴다.
- Git LFS 파일이 실제 내용이 아닌 pointer로 남아 있으면 코드로 해석하지 않고 `DataGap`으로 남긴다.
- build·설치 과정에서 생긴 생성 파일은 원본 저장소 코드와 구분한다. 생성 도구, 입력과 생성 시각을 별도 결과에 기록한다.
- submodule, LFS 또는 생성 파일이 부족하다는 이유만으로 가설을 `FALSE`로 바꾸지 않는다.

## 위치 기반 on-demand retrieval

Hypothesis Agent는 전체 코드가 아니라 entity, location과 suspected path를 제안한다. Verification·Pro·Con은 필요한 추가 문맥을 `CodeContextRequest`로 요청한다. Technical Gate는 별도 Context 조회를 시작하지 않고 exact final TRUE Verification이 가리키는 저장 근거와 CWE를 검토한다. Chaining Agent는 코드 문맥을 새로 탐색하지 않고 저장된 ACTIVE Primitive와 provenance만 읽는다.

1. 가설의 `CodeSymbol`, `CodeLocation`, `suspected_path`에서 시작한다.
2. 분석 목적에 맞는 관계를 명시한다.
3. Context Retrieval Service가 동일한 `workspace_id`와 연결된 `commit_id`인지, 요청이 budget 안인지 검증한다.
4. 허용된 깊이까지 필요한 fragment와 관계만 조회한다.
5. `CodeContextResponse`에 반환 위치·관계·gap·error와 실제 반환량을 기록한다.
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
  meta:
    analysis_id: analysis-001
    workspace_id: ws-001
    commit_id: 7f3a2c1
    hypothesis_id: hyp-001
  requested_entities:
    - symbol_id: sym-order-update
      symbol_kind: CALLABLE
      native_kind: method
      name: OrderController.update
      location:
        workspace_id: ws-001
        commit_id: 7f3a2c1
        file_path: src/order.ts
        start_line: 41
        start_column: 3
        end_line: 68
        end_column: 4
  requested_locations:
    - workspace_id: ws-001
      commit_id: 7f3a2c1
      file_path: src/order.ts
      start_line: 41
      start_column: null
      end_line: 68
      end_column: null
  relation_query: [CALLERS, AUTH_GUARDS]
  reason: verify whether ownership checks cover the update path
  limits:
    max_depth: 3
    max_fragments: 20
    max_bytes: 80000
    token_budget: 6000
    max_requests_per_hypothesis: 6
    timeout_ms: 15000
```

```yaml
code_context_response:
  code_request_id: ctxreq-001
  meta:
    analysis_id: analysis-001
    workspace_id: ws-001
    commit_id: 7f3a2c1
    hypothesis_id: hyp-001
  entities: []
  locations:
    - workspace_id: ws-001
      commit_id: 7f3a2c1
      file_path: src/order.ts
      start_line: 41
      start_column: null
      end_line: 68
      end_column: null
  code_fragment_refs:
    - stored_data_id: data-code-001
      data_kind: code_fragment
      content_hash: sha256:example
      workspace_id: ws-001
      commit_id: 7f3a2c1
      record_id: null
  discovered_relations: []
  gaps: []
  errors: []
  truncated: false
  returned_fragment_count: 1
  returned_bytes: 1800
  consumed_token_estimate: 520
```

위 예시는 읽기 쉽도록 `RecordMeta`의 일부 공통 metadata 필드를 생략했다. 실제 저장 record는 [경량 데이터 계약](./08-lightweight-data-contracts.md)의 전체 `RecordMeta`를 사용한다.

## 일관성·예산·보안 규칙

- 응답의 `meta.workspace_id` 또는 `meta.commit_id`가 요청·가설·`CodeWorkspace`와 다르면 사용하지 않고 `WORKSPACE_MISMATCH`로 기록한다.
- `ContextRetrievalLimits`의 depth, fragment 수, byte/token budget, 가설별 요청 횟수와 `timeout_ms`를 적용한다.
- 반복 요청은 normalized request fingerprint로 탐지한다.
- symlink escape, submodule drift와 path traversal을 차단하고 `workspace_root` 안의 파일만 읽는다.
- `file_path`는 `/` 구분자를 쓰는 정규화된 Git 상대 경로다. 절대 경로, drive prefix, `.`·`..` segment를 거절한다.
- 줄은 1부터 시작하며 시작·끝 줄을 포함한다. 열이 있으면 1-based Unicode code point 단위로 시작 열은 포함하고 끝 열은 제외한다. 줄만 아는 도구는 두 column을 모두 `null`로 둔다.
- 분석 중 HEAD 또는 추적 파일이 바뀌면 `WORKSPACE_CHANGED`로 기록하고 해당 작업공간의 새 결과를 사용하지 않는다.
- 민감 파일과 생성물 제외 정책을 적용하되 제외 사실은 gap으로 남긴다.
- LLM log에는 전달된 위치와 artifact reference를 우선 저장하고 전체 코드 원문 복제를 기본값으로 삼지 않는다.
- truncation이나 unresolved symbol은 숨기지 않고 `gaps`와 `truncated`에 표시한다. 조회 실행 실패는 `errors`에도 기록한다.

## 품질 기준

정적 사실은 원본 위치로 추적할 수 있어야 한다. Verification verdict, CWE와 Technical Gate 검토가 사용하는 핵심 주장은 적어도 하나의 실제 location 또는 동적 evidence에 연결되어야 하며, 연결되지 않는 추론은 assumption이나 unresolved condition으로 남긴다.
