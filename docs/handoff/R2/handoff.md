# R2 검증 자료 — 정적분석 도구 원본 결과 → StaticFactBundle 정규화

## 기능 및 기준 문서

- 기능: AST/SAST 도구의 원본 결과를 공통 형식(`StaticFactBundle`, `ToolRunResult`, `RuleExecutionRecord`)으로 정리하는 `Static Fact Normalizer` — R2 담당 파트의 대표 기능.
- 기준 문서: `docs/architecture-v5/02-static-fact-layer.md`, `docs/architecture-v5/08-lightweight-data-contracts.md`, `docs/review/decisions/ADR-006-static-rule-execution-record.md`.
- 이 파트는 LLM Agent가 아니라 규칙 기반 정규화 단계이므로 별도 `prompt.md`는 없습니다.

## 파일 위치

- `normal.input.json` / `normal.expected.json` — 정상 사례 (CodeQL이 SQL Injection을 실제로 탐지)
- `failure.input.json` / `failure.expected.json` — 실패 사례 (CodeQL 실행 자체가 실제로 실패)
- `sample-app/src/orders.py` — 두 사례가 함께 쓰는 취약 코드 샘플 (Flask, `get_order` 핸들러)
- `codeql-실행-방법.md` — 위 결과를 실제로 재현한 CodeQL 명령어 기록

## 출처

- 정상·실패 사례 모두 CodeQL CLI 2.26.4(github/codeql-action 최신 release bundle, 2026-09-05 다운로드) + `codeql/python-queries` 1.8.9의 `Security/CWE-089/SqlInjection.ql`을 **실제로 실행**해서 얻은 결과입니다. 합성(synthetic) 데이터가 아닙니다.
- 대상 코드(`src/orders.py`)는 이 검증 자료를 위해 새로 작성한 최소 Flask 샘플이며, SASTsimi 본 프로젝트의 실제 코드가 아닙니다.
- `commit_id`(`99c66f2`)는 이 sample-app만 담은 별도 git 저장소의 실제 커밋 해시이며, SASTsimi repo의 커밋이 아닙니다.
- `route_bindings`를 만든 도구(`py_ast_route_scan`)는 정식 도구가 아니라 Python 표준 `ast` 모듈로 직접 짠 최소 추출 스크립트입니다. "codeql이 실패해도 다른 도구 결과는 버리지 않는다"는 02번 규칙을 실제로 보여주기 위한 용도로만 넣었고, 실제 R2 구현에서는 별도 route 추출 도구로 대체될 예정입니다.
- 모든 `content_hash`는 실제 파일의 sha256이며 직접 계산한 값입니다(임의로 만든 값 아님). 다만 `rule_execution_ref.content_hash`는 자기 자신(RuleExecutionRecord)을 가리키는 순환 참조라 이 자료에서는 `<computed_at_write_time:...>`로 표시했습니다 — 실제 저장 시점에 그 레코드 JSON 자체의 해시로 채워야 합니다.
- `tool_runs[].meta`는 PR #116([R3-06] 구현 기준선·파일 구조·실행 순서 최종 확정) 병합 이후 스키마를 기준으로 작성했습니다. `ToolRunResult`가 flat `attempt_id: string`에서 `meta: RecordMeta without hypothesis, with attempt`로 바뀐 것을 `docs/architecture-v5/08-lightweight-data-contracts.md`(현재 main 기준 L803-804)로 직접 확인하고 `normal.expected.json`/`failure.expected.json`의 `tool_runs[]`에 반영했습니다. `record_id`/`logical_record_id`는 `trr-r2verify-<normal|failure>-00N` 형식으로 새로 부여했습니다.

## 근거

- 정상 사례: `SELECTED + EXECUTED + hit_count=1` — 실제 SQL Injection이 탐지됨. `source_candidates`/`sink_candidates`/`data_flow_candidates`가 모두 채워지고 진입점(`/orders/<id>`)에서 sink까지 이어지는 reachability edge(`DATA_FLOW`)도 확인됩니다.
- 실패 사례: `SELECTED + NOT_EXECUTED + hit_count=null + reason=TOOL_FAILURE` — 실행 환경(데이터베이스 root 누락) 문제로 쿼리 평가 자체가 시작되지 못한 경우. 여섯 `CodeFact` 목록은 모두 명시적 빈 배열(`[]`)이고, 실패 사실은 `gaps`/`errors`에 남습니다.
- 두 사례를 나란히 두면 "정상 실행 후 0건"(가상 사례: `SELECTED+EXECUTED+hit_count=0`)과 "실행 실패"(`SELECTED+NOT_EXECUTED`)가 `hit_count`/`reason` 필드로 명확히 구분된다는 것을 보여줍니다 — 어느 쪽도 안전함이나 `FALSE`의 근거가 아닙니다(자세한 대조는 `failure.expected.json`의 `_contrast_note_ko` 참고).
- 실패 사례에서도 별도 도구(`py_ast_route_scan`)의 `SUCCEEDED` 결과(`route_bindings`)는 지우지 않습니다 — 02번 "한 도구가 FAILED\|SKIPPED여도 다른 도구의 사용 가능한 사실을 버리지 않는다" 규칙의 실제 예시입니다.
- `normal.expected.json` 끝에 `code_context_response_example`을 덧붙였습니다 — "코드 문맥 전달 예시"에 해당하며, 실제 소스 파일(571 byte)의 sha256을 `code_fragment_refs`로 남기고 원문을 복제하지 않는 방식(02번 L248 요구사항)을 보여줍니다.

## 처리 규칙 · 통과 조건

1. 여섯 `CodeFact` 목록(`source_candidates` 등)은 후보가 없어도 반드시 `[]`로 존재해야 하며, 생략되면 실패로 판정합니다.
2. `RuleExecutionRecord.rules[]`의 상태 조합은 08번의 5가지 조합만 허용합니다 — 특히 `NOT_EXECUTED`/`UNKNOWN`에서 `hit_count=0`을 쓰면 실패입니다.
3. 한 도구의 `ToolRunResult.status=FAILED`가 있어도 `SUCCEEDED`인 다른 도구의 사실을 정규화 결과에서 지우면 실패입니다.
4. `CodeFact.producer.raw_result_ref.content_hash`는 실제 원본 결과 파일의 해시와 일치해야 합니다 — 이 자료의 해시값과 직접 비교할 수 있습니다.
5. `FAILED` 상태인 `tool_run`에는 `gaps` 또는 `errors` 중 최소 하나가 있어야 하며, 둘 다 비어 있으면 실패입니다.
6. LLM에 전달되는 것은 원문 코드가 아니라 위치·해시 참조(`code_fragment_refs`)여야 합니다 — `code_context_response_example`로 확인할 수 있습니다.

이 정규화 단계는 규칙 기반이라 위 항목 모두 exact-match로 검증 가능합니다. LLM 판단이 들어가는 자유서술 파트(Hypothesis 등 이후 단계)는 이 자료의 범위 밖입니다.

## 미결정사항 (검토 담당자 지정 필요)

1. `route_bindings`를 만드는 실제 도구가 아직 없습니다 — 이 자료의 `py_ast_route_scan`은 임시 스텁입니다. 실제 어떤 도구·방식으로 route binding을 추출할지는 별도 논의가 필요합니다. → 검토: R3(구현), R2
2. `StaticFactBundle.meta`가 08번 스키마상 "RecordMeta without hypothesis/attempt"인데, 02번 문서 자체 예시는 `hypothesis_id: null`을 포함하고 있어 두 문서 사이에 사소한 불일치가 있습니다. 이 자료는 08번(canonical 스키마)을 따랐습니다. 02번 예시를 08과 맞출지는 별도 확인이 필요합니다. → 검토: R2, R4
3. AST/SAST 실행 예산(900초/재시도 1회, `07`, PR #99)은 아직 "제안(교차 전) 초안" 상태입니다. 이 자료의 `elapsed_ms`(정상 4500ms, 실패 200ms)는 그 예산 안에 있다는 것만 보여줄 뿐, 예산 자체의 확정 여부와는 무관합니다.
4. `ToolRunResult`가 `SUCCEEDED`인데도 커버리지가 완전하지 않은 경우(예: `normal.expected.json`의 `py_ast_route_scan`—`coverage.notes`에 "route decorator만 구조적으로 추출하는 최소 스텁"이라고 명시된 상태)에도 `gaps: []`를 그대로 둔 게 맞는지 확실하지 않습니다. 실행 실패(`FAILED`)가 아니라 도구 자체의 알려진 한계로 생기는 분석 공백을 `coverage.notes`(자유 서술)로만 남길지, 아니면 `DataGap`으로도 명시적으로 남겨야 하는지—남긴다면 `DataGap.code`를 어떤 값으로 정할지—기준이 필요합니다. → 검토: R2, R3
5. **[R3-06/PR #116 반영 완료]** PR #116 병합으로 바뀐 `ToolRunResult.meta`(flat `attempt_id: string` → `RecordMeta without hypothesis, with attempt`)는 `docs/architecture-v5/08-lightweight-data-contracts.md` 최신 main과 대조해 `normal.expected.json`/`failure.expected.json`에 반영했습니다(출처 섹션 참고). 더 이상 미결정 사항이 아닙니다.

## 재현 방법

```
codeql database create orders-db --language=python --source-root=sample-app --overwrite
codeql database analyze orders-db <bundle>/qlpacks/codeql/python-queries/1.8.9/Security/CWE-089/SqlInjection.ql \
  --format=sarif-latest --output=sqli-result.sarif

# 실패 사례 (존재하지 않는 database root)
codeql database analyze orders-db-corrupted <같은 쿼리> \
  --format=sarif-latest --output=sqli-fail.sarif
```

CodeQL CLI 2.26.4, `codeql/python-queries` 1.8.9 (github/codeql-action 최신 release bundle 기준, 2026-09-05 다운로드). 위 명령을 그대로 실행하면 이 자료와 동일한 결과가 나옵니다.
