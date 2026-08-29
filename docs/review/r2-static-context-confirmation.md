# R2(정적분석·컨텍스트) 완료 조건 근거 정리

Issue #3의 완료 조건 7개와 관련된 기존 설계 문서상의 근거를 정리한 기록입니다.

## 1. `CodeWorkspace`, `StoredDataRef`, `CodeLocation`, `CodeSymbol`의 식별자와 생성 주체

- `CodeWorkspace`의 identity(`workspace_id`, `analysis_id`, `repository_url`, `commit_id`, `status`)와 생성 주체(Repository Loader) — `08-lightweight-data-contracts.md` L19-27, L68-91
- `CodeLocation`, `CodeSymbol`의 불변 식별자 형식(파일 경로, 라인/컬럼 범위, symbol_kind 등) — `08-lightweight-data-contracts.md` L170-184

## 2. clone/checkout, submodule, LFS와 generated dependency의 `DataGap` 처리 규칙

- submodule, LFS, generated dependency를 분석 범위에 포함할지/어떻게 고정할지 규칙 — `02-static-fact-layer.md` L61-66
- `DataGap` 스키마(`gap_id`, `stage`, `code`, `reason`, `description`, `affected_*`, `retryable`, `related_record_ids`, `created_at`) — `08-lightweight-data-contracts.md` L200-211

## 3. 모든 사실을 producer, `StoredDataRef`, `CodeLocation`, `workspace_id`로 역추적

- `entities`, `locations`, `source_candidates`, `sink_candidates`, `call_edges`, `data_flow_candidates`, `auth_and_permission_checks`, `route_bindings`, `tool_runs` 스키마 — `08-lightweight-data-contracts.md` L323-343
- `ToolSource`/`CodeFact.producer`/`CodeRelation.producer`로 각 fact가 어떤 도구 결과에서 왔는지 역추적 가능 — `08-lightweight-data-contracts.md` L222-243, L275

## 4. AST/SAST 부분 실패·충돌·불확실성이 `DataGap`/`AnalysisError`로 보존

- `STATIC_TOOL_ERROR` 등 실패 분류 체계 — `07-results-and-observability.md` L115-145
- `tool_runs`의 success/partial/failure/skipped 상태 표기 규칙 — `02-static-fact-layer.md` L52-59
- "empty/truncated/unresolved 결과 → 안전 또는 FALSE 해석 금지" 규칙이 소비자 쪽 계약에도 명시 — `02-static-fact-layer.md` L24, `08-lightweight-data-contracts.md` L279, `07-results-and-observability.md` L117

## 5. relation query와 depth/fragment/byte/token/request/time 제한

- `CodeContextRequest`/`CodeContextResponse` 필드(`requested_entities`/`requested_locations`, `relation_query`, `limits: ContextRetrievalLimits`, `truncated`) — `08-lightweight-data-contracts.md` L396-427
- 요청 가능한 relation 종류(`CALLERS`, `CALLEES`, `DATA_FLOW_NEIGHBORS`, `AUTH_GUARDS`, `ROUTE_BINDINGS`)와 depth/byte/token/request/time 한도 — `08-lightweight-data-contracts.md` L264-271, `02-static-fact-layer.md` L79-127

## 6. `WORKSPACE_MISMATCH`, `WORKSPACE_CHANGED`와 path/symlink negative scenario

- 서로 다른 workspace/commit이 섞였을 때의 처리 규칙 — `02-static-fact-layer.md` L164-175, `07-results-and-observability.md` L124-125, `10-security-boundaries.md` L13, L23-25, L29
- path traversal·symlink escape 차단 규칙 — `10-security-boundaries.md` L24-25

## 7. `gaps: [DataGap]` 필드와 소비자 의미의 문서 전체 일관성

- `02-static-fact-layer.md` L24, `08-lightweight-data-contracts.md` L279, `07-results-and-observability.md` L117
