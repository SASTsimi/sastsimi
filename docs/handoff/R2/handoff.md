# R2 검증 자료 — 정적분석 도구 원본 결과 → StaticFactBundle 정규화

## 기능 및 기준 문서

- 기능: AST/SAST 도구의 원본 결과를 공통 형식(`StaticFactBundle`, `ToolRunResult`, `RuleExecutionRecord`)으로 정리하는 `Static Fact Normalizer` — R2 담당 파트의 대표 기능.
- 기준 문서: `docs/architecture-v5/02-static-fact-layer.md`, `docs/architecture-v5/08-lightweight-data-contracts.md`, `docs/review/decisions/ADR-006-static-rule-execution-record.md`.
- 이 파트는 LLM Agent가 아니라 규칙 기반 정규화 단계이므로 별도 `prompt.md`는 없습니다.

## 파일 위치

파일 하나 = record 하나입니다(PR #138 리뷰 R3 `YHS-Sec` 반영 — 이전에는 여러 record와 설명 문자열을 하나의 임의 wrapper에 섞어서 "파일 전체가 어떤 record인지" 불명확했습니다).

- `normal.input.json` — 정상 사례 원본 (실제 SARIF)
- `normal.expected.json` — 정상 사례 `StaticFactBundle` 단독
- `normal.rule_execution_record.expected.json` — 정상 사례 `RuleExecutionRecord` 단독
- `normal.code_context_response.expected.json` — 코드 문맥 전달 예시 `CodeContextResponse` 단독
- `failure.input.json` — 실패 사례 원본 (실제 CLI 에러)
- `failure.expected.json` — 실패 사례 `StaticFactBundle` 단독
- `failure.rule_execution_record.expected.json` — 실패 사례 `RuleExecutionRecord` 단독
- `sample-app/src/orders.py` — 두 사례가 함께 쓰는 취약 코드 샘플 (Flask, `get_order` 핸들러)
- `codeql-실행-방법.md` — 위 결과를 실제로 재현한 CodeQL 명령어 기록
- `tests/contract/domain/test_r2_handoff_fixtures.py` — 위 `*.expected.json` 5개가 각각 대응하는 Pydantic model(`StaticFactBundle`/`RuleExecutionRecord`/`CodeContextResponse`, `src/sastsimi/contracts/static.py`)로 `model_validate_json` 검증을 통과하는지 자동으로 확인하는 pytest (`ToolRunResult`도 `tool_runs[]` 각 항목을 개별로 재검증합니다). PR #138 리뷰(R3)의 BLOCKING 요청으로 추가.

## 출처

- 정상·실패 사례 모두 CodeQL CLI 2.26.4(github/codeql-action 최신 release bundle, 2026-09-05 다운로드) + `codeql/python-queries` 1.8.9의 `Security/CWE-089/SqlInjection.ql`을 **실제로 실행**해서 얻은 결과입니다. 합성(synthetic) 데이터가 아닙니다.
- 대상 코드(`src/orders.py`)는 이 검증 자료를 위해 새로 작성한 최소 Flask 샘플이며, SASTsimi 본 프로젝트의 실제 코드가 아닙니다.
- `commit_id`(`99c66f2`)는 이 sample-app만 담은 별도 git 저장소의 실제 커밋 해시이며, SASTsimi repo의 커밋이 아닙니다.
- `route_bindings`를 만든 도구(`py_ast_route_scan`)는 정식 도구가 아니라 Python 표준 `ast` 모듈로 직접 짠 최소 추출 스크립트입니다. "codeql이 실패해도 다른 도구 결과는 버리지 않는다"는 02번 규칙을 실제로 보여주기 위한 용도로만 넣었고, 실제 R2 구현에서는 별도 route 추출 도구로 대체될 예정입니다.
- 모든 `content_hash`는 실제 파일의 sha256이며 직접 계산한 값입니다(임의로 만든 값 아님). `src/sastsimi/contracts/base.py`의 `Sha256 = Field(pattern=r"^[0-9a-f]{64}$")` 규격에 맞춰 접두사 없이 소문자 64자리 hex만 씁니다. `rule_execution_ref.content_hash`는 자기 자신(RuleExecutionRecord)을 가리키는 순환 참조라 이전에는 `<computed_at_write_time:...>` 플레이스홀더였는데, 지금은 `src/sastsimi/contracts/canonical_json.py`의 `content_hash()`로 (수정된) `RuleExecutionRecord`를 실제로 직렬화·해시한 값을 그대로 채웠습니다. 같은 참조의 `record_id`도 `null`이 아니라 해당 `RuleExecutionRecord.meta.record_id`를 가리켜야 해서(`refs.py`의 `require_record_ref`) 채워 넣었습니다.
- `tool_runs[].meta`는 PR #116([R3-06] 구현 기준선·파일 구조·실행 순서 최종 확정) 병합 이후 스키마를 기준으로 작성했습니다. `ToolRunResult`가 flat `attempt_id: string`에서 `meta: RecordMeta without hypothesis, with attempt`로 바뀐 것을 `docs/architecture-v5/08-lightweight-data-contracts.md`(현재 main 기준 L803-804)로 직접 확인하고 `normal.expected.json`/`failure.expected.json`의 `tool_runs[]`에 반영했습니다. `record_id`/`logical_record_id`는 `trr-r2verify-<normal|failure>-00N` 형식으로 새로 부여했습니다.
- `RecordMeta`(`src/sastsimi/contracts/records.py`)의 `hypothesis_id`/`attempt_id`는 기본값이 없는 **필수-이지만-nullable** 필드라 값이 없어도 키 자체는 항상 있어야 합니다. `_domain.py`의 `DomainRecord.domain_scope`가 각 record의 `HYPOTHESIS`/`ATTEMPT` 클래스 플래그와 실제 값의 유무를 대조해 어긋나면 `METADATA_SCOPE_MISMATCH`를 냅니다. 이 자료의 각 record는 다음을 따릅니다: `StaticFactBundle`(`HYPOTHESIS=False, ATTEMPT=False`) → `hypothesis_id: null, attempt_id: null`; `ToolRunResult`·`RuleExecutionRecord`(`HYPOTHESIS=False, ATTEMPT=True`) → `hypothesis_id: null`, `attempt_id`는 실값; `CodeContextResponse`(`HYPOTHESIS=True, ATTEMPT=True`) → `hypothesis_id`·`attempt_id` 둘 다 실값. `normal.code_context_response.expected.json`(`CodeContextResponse`)의 `meta`도 원래 일부 필드만 있는 예시였는데 전체 `RecordMeta`(+ 실값 `hypothesis_id`/`attempt_id`)를 채웠습니다.
- `CodeLocation`(`src/sastsimi/contracts/static.py`)은 `start_column`과 `end_column`이 둘 다 있거나 둘 다 `null`이어야 합니다(`INVALID_CODE_RANGE`). `route_bindings[0].from_location`(데코레이터 줄 전체를 가리킴)과 `normal.code_context_response.expected.json`의 `locations[0]`은 원래 `start_column`만 채워져 있었는데 둘 다 `null`로 바꿔서 "줄 전체"를 나타내도록 정리했습니다.
- `route_bindings[0]._note_ko`(정상/실패 공통)와 `failure.expected.json`의 `_contrast_note_ko`는 `ContractModel(extra="forbid")`에 걸려 실제 record 안에는 둘 수 없습니다. 두 설명은 이 문서의 근거 섹션으로 옮겼습니다.

## 근거

- 정상 사례: `SELECTED + EXECUTED + hit_count=1` — 실제 SQL Injection이 탐지됨. `source_candidates`/`sink_candidates`/`data_flow_candidates`가 모두 채워지고 진입점(`/orders/<id>`)에서 sink까지 이어지는 reachability edge(`DATA_FLOW`)도 확인됩니다.
- 실패 사례: `SELECTED + NOT_EXECUTED + hit_count=null + reason=TOOL_FAILURE` — 실행 환경(데이터베이스 root 누락) 문제로 쿼리 평가 자체가 시작되지 못한 경우. 여섯 `CodeFact` 목록은 모두 명시적 빈 배열(`[]`)이고, 실패 사실은 `gaps`/`errors`에 남습니다.
- 두 사례를 나란히 두면 "정상 실행 후 0건"(가상 사례: `SELECTED+EXECUTED+hit_count=0`)과 "실행 실패"(`SELECTED+NOT_EXECUTED`)가 `hit_count`/`reason` 필드로 명확히 구분된다는 것을 보여줍니다 — 어느 쪽도 안전함이나 `FALSE`의 근거가 아닙니다. 이 SELECTED+NOT_EXECUTED, hit_count=null, reason=TOOL_FAILURE 조합은 "정상 실행했지만 0건"인 SELECTED+EXECUTED, hit_count=0 조합과 다릅니다. 후자는 `normal.expected.json`처럼 hit_count가 정수(0 이상)이고 reason=null입니다. 이 둘을 안전함/FALSE의 근거로 같게 취급하면 안 됩니다(02 "정적 분석의 역할", ADR-006).
- 실패 사례에서도 별도 도구(`py_ast_route_scan`)의 `SUCCEEDED` 결과(`route_bindings`)는 지우지 않습니다 — 02번 "한 도구가 FAILED\|SKIPPED여도 다른 도구의 사용 가능한 사실을 버리지 않는다" 규칙의 실제 예시입니다. `route`는 `'/orders/<id>'`(실제 `@app.route` 데코레이터 인자, python `ast` 모듈로 직접 파싱해 추출)이며, codeql은 실패했지만 별도 도구의 `SUCCEEDED` 결과는 버리지 않고 그대로 유지합니다.
- `normal.code_context_response.expected.json`은 "코드 문맥 전달 예시"에 해당하는 `CodeContextResponse` 단독 파일입니다 — 실제 소스 파일(571 byte)의 sha256을 `code_fragment_refs`로 남기고 원문을 복제하지 않는 방식(02번 L248 요구사항)을 보여줍니다.

## 처리 규칙 · 통과 조건

1. 여섯 `CodeFact` 목록(`source_candidates` 등)은 후보가 없어도 반드시 `[]`로 존재해야 하며, 생략되면 실패로 판정합니다.
2. `RuleExecutionRecord.rules[]`의 상태 조합은 08번의 5가지 조합만 허용합니다 — 특히 `NOT_EXECUTED`/`UNKNOWN`에서 `hit_count=0`을 쓰면 실패입니다.
3. 한 도구의 `ToolRunResult.status=FAILED`가 있어도 `SUCCEEDED`인 다른 도구의 사실을 정규화 결과에서 지우면 실패입니다.
4. `CodeFact.producer.raw_result_ref.content_hash`는 실제 원본 결과 파일의 해시와 일치해야 합니다 — 이 자료의 해시값과 직접 비교할 수 있습니다.
5. `FAILED` 상태인 `tool_run`에는 `gaps` 또는 `errors` 중 최소 하나가 있어야 하며, 둘 다 비어 있으면 실패입니다.
6. LLM에 전달되는 것은 원문 코드가 아니라 위치·해시 참조(`code_fragment_refs`)여야 합니다 — `normal.code_context_response.expected.json`으로 확인할 수 있습니다.
7. **[스키마 검증 완료, 자동 test 있음]** 이 디렉터리의 `*.expected.json` 5개는 각각 대응하는 `src/sastsimi/contracts/static.py`의 실제 `StaticFactBundle`/`RuleExecutionRecord`/`CodeContextResponse` Pydantic model로 `model_validate_json` 검증을 통과합니다(0 errors) — `tests/contract/domain/test_r2_handoff_fixtures.py`가 매 CI마다 이를 자동으로 확인합니다. 문서 기준 통과 조건뿐 아니라 실제 구현 계약과도 exact-match임을 리포지토리를 직접 clone해서 확인했습니다.

이 정규화 단계는 규칙 기반이라 위 항목 모두 exact-match로 검증 가능합니다. LLM 판단이 들어가는 자유서술 파트(Hypothesis 등 이후 단계)는 이 자료의 범위 밖입니다.

## 미결정사항 (검토 담당자 지정 필요)

1. `route_bindings`를 만드는 실제 도구가 아직 없습니다 — 이 자료의 `py_ast_route_scan`은 임시 스텁입니다. 실제 어떤 도구·방식으로 route binding을 추출할지는 별도 논의가 필요합니다. → 검토: R3(구현), R2
2. **[해결]** `StaticFactBundle.meta`의 `hypothesis_id`/`attempt_id` 표기 문제 — `src/sastsimi/contracts/records.py`가 두 필드 모두 기본값 없는 필수-nullable 필드로 이미 정해 두었습니다(값이 `null`이어도 키는 있어야 함). 02번 예시가 맞았고, 08번 canonical 스키마도 같은 결론입니다. 이 자료에도 반영했습니다(출처 섹션 참고). PR #138 리뷰(R1, `baeseungwon1010`)에서 확인. 더 이상 미결정 사항이 아닙니다.
3. AST/SAST 실행 예산(900초/재시도 1회, `07`, PR #99)은 아직 "제안(교차 전) 초안" 상태입니다. 이 자료의 `elapsed_ms`(정상 4500ms, 실패 200ms)는 그 예산 안에 있다는 것만 보여줄 뿐, 예산 자체의 확정 여부와는 무관합니다.
4. `ToolRunResult`가 `SUCCEEDED`인데도 커버리지가 완전하지 않은 경우(예: `normal.expected.json`의 `py_ast_route_scan`—`coverage.notes`에 "route decorator만 구조적으로 추출하는 최소 스텁"이라고 명시된 상태)에도 `gaps: []`를 그대로 둔 게 맞는지 확실하지 않습니다. 실행 실패(`FAILED`)가 아니라 도구 자체의 알려진 한계로 생기는 분석 공백을 `coverage.notes`(자유 서술)로만 남길지, 아니면 `DataGap`으로도 명시적으로 남겨야 하는지—남긴다면 `DataGap.code`를 어떤 값으로 정할지—기준이 필요합니다. 참고로 `docs/architecture-v5/wiki/common-contracts.md`는 `DataGap`을 "분석하지 못했거나 **일부만 확인한** 범위"로 정의하고 있어(완전 실패로 한정하지 않음), `SUCCEEDED`이면서도 부분 커버리지인 이 경우도 `DataGap` 대상에 가깝다는 근거는 있습니다 — 다만 08번에 정확히 맞는 `DataGap.code` 값이 아직 없어 최종 판단은 열어둡니다. PR #138 리뷰(R3, `YHS-Sec`)에서도 [HIGH]로 같은 문제를 제기했습니다: "승인된 analysis config가 요구한 범위를 전부 수행했다면 SUCCEEDED, 일부를 확인 못했다면 PARTIAL+DataGap"이 기준이라면, 이 자료는 py_ast_route_scan 자신이 선언한 범위(route decorator 추출)를 전부 수행했으므로 SUCCEEDED가 맞다고 봅니다 — 다만 최종 확정은 아직 열어둡니다. → 검토: R2, R3
5. **[R3-06/PR #116 반영 완료]** PR #116 병합으로 바뀐 `ToolRunResult.meta`(flat `attempt_id: string` → `RecordMeta without hypothesis, with attempt`)는 `docs/architecture-v5/08-lightweight-data-contracts.md` 최신 main과 대조해 `normal.expected.json`/`failure.expected.json`에 반영했습니다(출처 섹션 참고). 더 이상 미결정 사항이 아닙니다.
6. **[PR #138 리뷰, R3 `YHS-Sec`, BLOCKING — 반영 완료]** fixture envelope 구조 문제 — 이전에는 `normal.expected.json` 하나에 `StaticFactBundle`, `RuleExecutionRecord`, 설명 문자열, `CodeContextResponse` 예시가 임의 wrapper 객체로 섞여 있어 파일 전체가 어떤 단일 record인지 불명확했습니다. record별 파일 분리로 정리했습니다(파일 위치 섹션 참고) — 파일 하나 = record 하나이며, 각각 실제 model로 개별 검증됩니다. 더 이상 미결정 사항이 아닙니다.

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
