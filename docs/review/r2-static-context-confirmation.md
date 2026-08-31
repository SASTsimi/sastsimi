# R2(정적분석·컨텍스트) 완료 조건 근거 정리

Issue #3의 완료 조건 7개와 관련된 기존 설계 문서상의 근거를 정리한 기록입니다.

> **2026-08-31 갱신**: 이 문서를 처음 작성한 시점 이후 `main`에 병합된 여러 PR로
> `docs/architecture-v5/08-lightweight-data-contracts.md` 등 일부 문서가 재구성되며
> 아래 line 번호가 실제 위치와 어긋나 있었습니다. `main` `8190b5f` 기준으로 각 인용을
> 다시 열어 확인하고 갱신했습니다. 내용상 결론은 바뀌지 않았습니다.

## 1. `CodeWorkspace`, `StoredDataRef`, `CodeLocation`, `CodeSymbol`의 식별자와 생성 주체

- `CodeWorkspace`의 identity(`workspace_id`, `analysis_id`, `repository_url`, `commit_id`, `status`) — `08-lightweight-data-contracts.md` L19-27
- 각 식별자의 생성 주체 표: `workspace_id`는 `Repository Loader`가 만들고 전체 시스템에서 유일하며 변경·재사용 금지 — `08-lightweight-data-contracts.md` L68-72(표 헤더 포함)
- `CodeLocation`(`workspace_id`, `commit_id`, `file_path`, `start_line`/`end_line`/`start_column`/`end_column`), `CodeSymbol`(`symbol_id`, `symbol_kind`, `native_kind`, `name`, `location`)의 불변 식별자 형식 — `08-lightweight-data-contracts.md` L539-552

## 2. clone/checkout, submodule, LFS와 generated dependency의 `DataGap` 처리 규칙

- submodule, LFS, generated dependency를 분석 범위에 포함할지/어떻게 고정할지 규칙 — `02-static-fact-layer.md` L61-66
- `DataGap` 스키마(`gap_id`, `stage`, `code`, `reason`, `description`, `affected_*`, `retryable`, `related_record_ids`, `created_at`) — `08-lightweight-data-contracts.md` L570-581

## 3. 모든 사실을 producer, `StoredDataRef`, `CodeLocation`, `workspace_id`로 역추적

- `entities`, `locations`, `source_candidates`, `sink_candidates`, `call_edges`, `data_flow_candidates`, `auth_and_permission_checks`, `route_bindings`, `tool_runs` 스키마 — `08-lightweight-data-contracts.md` L701-713 (`StaticFactBundle`)
- `ToolSource`(`tool_name`, `tool_version`, `rule_id`, `raw_result_ref`) — `08-lightweight-data-contracts.md` L594-598
- `CodeFact.producer`/`CodeRelation.producer`로 각 fact/relation이 어떤 도구 결과에서 왔는지 역추적 가능 — `08-lightweight-data-contracts.md` L605(`CodeFact.producer`), L614(`CodeRelation.producer`)

## 4. AST/SAST 부분 실패·충돌·불확실성이 `DataGap`/`AnalysisError`로 보존

- `STATIC_TOOL_ERROR` 등 실패 분류 체계(코드별 주 생산자·실행 영향·복구 방향 표) — `07-results-and-observability.md` L213-224
- `tool_runs`의 `SUCCEEDED`/`PARTIAL`/`FAILED`/`SKIPPED` 상태 표기 규칙 — `02-static-fact-layer.md` L52-59
- "empty/truncated/unresolved 결과 → 안전 또는 FALSE 해석 금지" 규칙이 소비자 쪽 계약에도 명시 — `02-static-fact-layer.md` L24, `08-lightweight-data-contracts.md` L651·L663, `07-results-and-observability.md` L213

## 5. relation query와 depth/fragment/byte/token/request/time 제한

- `CodeContextRequest`(`requested_entities`/`requested_locations`, `relation_query`, `limits: ContextRetrievalLimits`) — `08-lightweight-data-contracts.md` L774-782
- `CodeContextResponse`(`truncated`, `returned_fragment_count`, `returned_bytes`, `consumed_token_estimate` 등) — `08-lightweight-data-contracts.md` L788-800
- `ContextRetrievalLimits`(`max_depth`, `max_fragments`, `max_bytes`, `token_budget`, `max_requests_per_hypothesis`, `timeout_ms`) — `08-lightweight-data-contracts.md` L636-642
- 요청 가능한 relation 종류(`CALLERS`, `CALLEES`, `DATA_FLOW_NEIGHBORS`, `AUTH_GUARDS`, `ROUTE_BINDINGS`)와 depth/byte/token/request/time 한도 예시 — `02-static-fact-layer.md` L81-127

## 6. `WORKSPACE_MISMATCH`, `WORKSPACE_CHANGED`와 path/symlink negative scenario

- 서로 다른 workspace/commit이 섞였을 때의 처리 규칙 — `02-static-fact-layer.md` L164-175(요청·응답 mismatch는 L166, 분석 중 변경은 L172), `07-results-and-observability.md` L220-221(오류 코드 표), `10-security-boundaries.md` L23(`WORKSPACE_CHANGED`), L157(다른 `workspace_id`/`commit_id` 결과 합류 negative scenario 표)
- path traversal·symlink escape 차단 규칙 — `10-security-boundaries.md` L24-25
- 누락·truncation을 안전함 또는 `FALSE`로 해석하지 않는다는 규칙 — `10-security-boundaries.md` L28
- 전체 저장소 대신 필요한 location/context만 전달한다는 규칙 — `10-security-boundaries.md` L63

## 7. `gaps: [DataGap]` 필드와 소비자 의미의 문서 전체 일관성

- `02-static-fact-layer.md` L24, `08-lightweight-data-contracts.md` L651·L663, `07-results-and-observability.md` L213
