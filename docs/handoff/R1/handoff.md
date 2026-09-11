# R1 인계 자료 — Hypothesis·Chaining 프롬프트와 검증 샘플

- 담당: R1 (LLM 탐색·체이닝)
- 기준 main: `342fcfa`
- 작성일: 2026-09-09 (main 기준 재작성 3판)

> **임시본입니다.** 이 자료는 현재 main 계약만으로 작성했으며 계약 수정을 전제하지 않습니다.
> 그 대가로 두 곳에서 우회했습니다 — Hypothesis는 `restrictions`를 비우고, Chaining은 담당 계산을
> Agent가 하지 않습니다. 근거와 비용은 아래 「이 경계에서 치른 대가」에 적었습니다.
> 해당 항목이 정리되면 프롬프트와 샘플을 다시 맞춰야 합니다.

## 담당 기능

| 역할 / task | prompt id | 출력 result kind | 출력 schema / validator |
|---|---|---|---|
| HYPOTHESIS / `GENERATE_INITIAL` | `PMT-HYP-01` | `hypothesis_proposal` | `schema.hypothesis-proposal-list.next-major` / `validator.hypothesis-proposal-list.v1` |
| CHAINING / `MATCH_PRIMITIVES` | `PMT-CHN-01` | `chaining_result` | `schema.chaining-result.next-major` / `validator.chaining-result.v1` |

이번 자료는 두 기능에 정상 1건, 실패 1건씩입니다. Chaining은 06이 정한 두 조합이 구조적으로 다르게 다뤄지지 않는지 확인해야 해서 정상 사례를 TRUE + HOLD와 TRUE + TRUE로 나눴고, 조합 열거가 Primitive 둘로는 드러나지 않아 셋짜리 사례를 하나 더 두었습니다.

| 기능 | 샘플 | 무엇을 확인하나 |
|---|---|---|
| `GENERATE_INITIAL` | `normal` | 세 갈래 구분, 확정 어휘, 근거 인용 |
| | `failure` | 도구 실패를 탐지 0건으로 바꾸지 않기, 없는 사실 만들지 않기 |
| `MATCH_PRIMITIVES` | `normal` (TRUE + HOLD) | 매칭 성립, `assumptions` 계산, 조합 분류 |
| | `normal-true-true` (TRUE + TRUE) | 양방향 조합 열거, 권한 축을 코드 근거로 성립시키기 |
| | `normal-three` (Primitive 셋) | 모든 조합을 빠짐없이 검토하기, 담당을 임의로 판단하지 않기 |
| | `failure` | 권한 서열표 금지, 어긋난 축 정확히 지목하기 |

같은 R1 소관인 HYPOTHESIS / `DUPLICATE_REVIEW`(`PMT-HYP-02`)는 위 두 기능을 확정한 뒤 같은 형식으로 준비합니다.

## 기준 설계 문서

| 문서 | 무엇을 정하나 |
|---|---|
| [`03-agent-roles-and-orchestration.md`](../../architecture-v5/03-agent-roles-and-orchestration.md) | proposal 필수 항목, 출력 권한 제한, 출력 검증 5단계, 중복 판정 fail-open |
| [`02-static-fact-layer.md`](../../architecture-v5/02-static-fact-layer.md) | `StaticFactBundle` 의미, 도구 상태 해석, 빈 목록의 뜻 |
| [`06-chaining.md`](../../architecture-v5/06-chaining.md) | 매칭 조건, 조상 제외, 자식 가설 구성, 금지 권한 |
| [`08-lightweight-data-contracts.md`](../../architecture-v5/08-lightweight-data-contracts.md) §1·§2·§5·§6 | 스키마와 `SAVE_RESULT` 저장 검사 |
| [`verification-playbooks.md`](../../architecture-v5/verification-playbooks.md) | `vulnerability_type` 어휘 |
| [`07-results-and-observability.md`](../../architecture-v5/07-results-and-observability.md) | `no_match_reasons` 관측 항목 |
| [`implementation/06-implementation-baseline.md`](../../architecture-v5/implementation/06-implementation-baseline.md) / ADR-015 | 파일 경로, ID 생성 규칙 |
| [`implementation/05-prompt-runtime.md`](../../architecture-v5/implementation/05-prompt-runtime.md) §4.1·§4.7 | 입력 slot, session 정책, 신뢰 등급 |

## 파일 위치

```
docs/handoff/R1/
  handoff.md
  prompts_hypothesis_generate_initial.md
  prompts_chaining_match_primitives.md
  samples_hypothesis_generate_initial/
    normal.input.json   normal.expected.json
    failure.input.json  failure.expected.json
  samples_chaining_match_primitives/
    normal.input.json             normal.expected.json
    normal-true-true.input.json   normal-true-true.expected.json
    normal-three.input.json       normal-three.expected.json
    failure.input.json            failure.expected.json
```

두 프롬프트는 운영에서 각각 `hypothesis/generate-initial`과 `chaining/match-primitives` 경로의 template revision으로 등록됩니다. 저장소 안 위치는 `implementation/06-implementation-baseline.md:731`이 `src/sastsimi/prompts/templates/<role>/<task>/<semver>.md`로 정합니다.

프롬프트는 분석 대상과 무관한 공통 템플릿입니다. 저장소 코드와 정적분석 결과는 실행 시 입력 slot으로 주입합니다. 입력 조립과 LLM 전달은 R3 구현 범위입니다.

## 입력 slot

확정된 registry 목록(`05-prompt-runtime.md:231`, `:245`)을 그대로 따랐습니다.

| task | slot | 개수 |
|---|---|---|
| `GENERATE_INITIAL` | `facts: StaticFactBundle` | `REQUIRED_ONE` |
| `MATCH_PRIMITIVES` | `indexes: PrimitiveIndexState` | `REQUIRED_MANY` |
| | `considered: Primitive` | `REQUIRED_MANY` |
| | `lineage_hypotheses: VulnerabilityHypothesis` | `REQUIRED_MANY` |
| | `lineage_results: ChainingResult` | `OPTIONAL_MANY` |

`admission` slot은 목록에 없습니다. admission이 Primitive 등록 시점의 1회 판정으로 확정되므로 체이닝은 다시 확인하지 않습니다(`06-chaining.md:54`, `08:401`).

`lineage_results`가 `OPTIONAL_MANY`인 것은 최초 체이닝에서 빈 목록이 정상이기 때문입니다. 정상 샘플 둘 다 이 경우입니다.

**입력 샘플은 projection 후 payload입니다.** 즉 Prompt Builder가 `field_paths`로 잘라 실제로 프롬프트에 넣는 값만 담았습니다. `facts`는 `05:231`의 열네 pointer(`/meta` 없음), `lineage_hypotheses`는 네 pointer, `indexes`와 `considered`는 `$`로 전체 record입니다.

**계기 Primitive는 이 목록에 없습니다.** 그래서 Agent가 담당을 계산하지 않습니다. 아래 「이 경계에서 치른 대가」 2번을 보세요.

## 입력 샘플 출처

**전부 직접 만든 테스트 데이터입니다.** 실제 도구 출력이나 실행 결과가 아닙니다. 각 파일 최상단 `_note.source`에 표시했습니다.

`08`의 필드명과 값 형식을 그대로 따랐고, 가정한 코드는 Flask + sqlite3(가설 생성)과 Flask 링크 미리보기 기능(체이닝)입니다.

실제 CodeQL·OpenGrep 출력이 확보되면 교체가 필요합니다. 특히 `producer.raw_result_ref`와 `symbol_id` 형식은 R2의 정규화 결과에 맞춰야 합니다.

도구 구성도 가정입니다. 하나의 `ast_dataflow` 실행이 `call_edges`·`data_flow_candidates`·`route_bindings`를 모두 만드는 것으로 두었습니다. `02:88`이 `AST의 call/data-flow 분석도 결국 하나의 도구 실행`이라고 보장하는 범위는 call·data-flow까지이고 route binding은 별도 언급이 없습니다. 금지되지도 않고 흔한 구현이지만 정본 근거가 아니라 합리적 가정이므로, 실제 도구 배치를 확정할 때 R2·R3가 확인해 주셔야 합니다.

## 기대 결과를 읽는 법

LLM 출력은 실행마다 문장이 달라집니다. 그래서 문장 전체를 정답으로 두지 않고 셋으로 나눴습니다.

| 키 | 뜻 |
|---|---|
| `must` | 반드시 성립해야 하는 것. 항목마다 `why`에 근거 문서를 적었습니다 |
| `must_not` | 하나라도 걸리면 실패인 것 |
| `example_valid_output` | 통과하는 출력 하나. 정답이 아니라 형태 확인용입니다 |

각 항목에는 `grading`이 붙어 있습니다. **`auto`**는 출력 JSON만 보고 코드로 판정할 수 있는 구조·값·개수이고, **`judgement`**는 자연어의 의미를 봐야 해서 LLM-judge나 사람 검토가 필요한 항목입니다. 자동 시험에 연결할 때 `auto`만 하네스가 강제하고 `judgement`는 별도 경로로 채점해야 합니다.

| 샘플 | auto | judgement |
|---|---|---|
| hypothesis `normal` | 23 | 4 |
| hypothesis `failure` | 5 | 4 |
| chaining `normal` | 25 | 5 |
| chaining `normal-true-true` | 22 | 5 |
| chaining `normal-three` | 12 | 1 |
| chaining `failure` | 15 | 4 |

`failure` 샘플에 `judgement` 비중이 높은 것은 의도한 것입니다. 결론(빈 배열, candidate 0건)은 쉽게 맞고 실제 판정은 근거 서술에서 갈리기 때문입니다.

`downstream_expectation`은 그 결과를 받는 runtime이 어떻게 처리해야 하는지입니다. LLM 출력 판정 기준이 아니라 R3 구현 확인용입니다.

**통과 조건은 `must`를 전부 만족하고 `must_not`에 하나도 걸리지 않는 것입니다.** `example_valid_output`과 문장이 달라도 `must`를 만족하면 통과이고, 문장이 비슷해도 `must_not`에 걸리면 실패입니다.

두 실패 샘플은 **결론이 맞아도 근거가 틀리면 실패**하도록 잡았습니다. 체이닝 실패 샘플에서 권한 서열표로 판단하면 결론이 같아도 `must_not`에 걸립니다.

## 반드시 지켜야 하는 처리 규칙

### 공통

**입력은 전부 `UNTRUSTED_DATA`입니다.** `05-prompt-runtime.md` §3이 분석 대상 코드·README·도구 출력을 모두 신뢰할 수 없는 데이터로 규정합니다. 두 프롬프트에 입력 안의 지시문을 따르지 말라는 절을 넣었습니다.

**내부 ID를 지어내지 않습니다.** `06-implementation-baseline.md:558`이 `LLM output과 tool output을 내부 ID로 채택하지 않는다`고 정합니다. `record_id`·`content_hash` 같은 저장 식별자는 출력에 넣지 않고, `question_id`·`validation_id`는 출력 안에서만 유일한 지역 값으로 두어 runtime이 전역 ID로 바꾸게 합니다.

**`vulnerability_type_candidates`는 확정 어휘만 씁니다.** `SQL_INJECTION` / `XSS` / `OS_COMMAND_INJECTION` / `PATH_TRAVERSAL` / `SSRF` / `IDOR_BOLA`. `verification-playbooks.md`의 mapping 표와 문자열이 정확히 일치해야 `TYPE_SPECIFIC` 플레이북이 선택됩니다(`08:1231`). 자유 서술을 넣으면 `TYPE_NOT_ALLOWED`로 떨어져 항상 COMMON이 붙습니다.

**세션은 둘 다 `NEW`입니다.** proposal batch마다, match batch마다 새로 시작합니다.

### Hypothesis

**세 갈래 구분이 이 기능의 핵심입니다.**

| | 판단 기준 | 어기면 |
|---|---|---|
| `observed_facts` | 입력 bundle의 `fact_id`를 그대로 인용할 수 있는가 | 없는 사실을 만든 것 |
| `restrictions` | **INITIAL proposal에서는 항상 빈 배열** | 아래 설명 참조 |
| `assumptions` | 근거가 없고 가설이 그것에 의존하는가 | — |

**`restrictions`를 비웁니다.** `Restriction.fact_refs`의 각 항목은 `CodeFactRef`이고 `bundle_ref`가 필수인데, `05:231`의 `facts` projection에 bundle의 `meta`가 없어 `StoredDataRef`를 만들 재료가 없습니다. `evidence_refs`도 `StoredDataRef`라 같습니다. `08:983`이 INITIAL proposal의 각 restriction에 `fact_refs`를 하나 이상 요구하므로, 이 단계에서 낼 수 있는 값은 빈 배열뿐입니다.

제한에 해당하는 관측 사실은 `observed_facts`에 `CodeFact` 그대로 보존합니다. `CodeFact`는 `bundle_ref`를 요구하지 않습니다. 제한으로 표시하는 일은 `StaticFactBundle($)` 전체를 받는 Verification(`05:235`, `05:237`)이 맡으며 `08:1260`이 이미 이를 허용합니다.

**빈 후보 목록을 안전함으로 읽지 않습니다.** `tool_runs.status`가 `FAILED`·`SKIPPED`·`PARTIAL`이면 도구가 못 본 것이지 없는 것이 아닙니다. `failure` 샘플이 이 규칙을 확인합니다.

**확정 주장 금지.** `confirmed`, `verified`, `exploitable`, `finding`과 `TRUE`/`FALSE`/`HOLD`는 출력할 수 없습니다. 심각도·점수·우선순위도 없습니다. 등록된 가설은 전수 검증합니다.

**모든 `CodeLocation`의 `workspace_id`·`commit_id`가 입력 bundle과 같아야 합니다.** 다르면 저장이 거절됩니다.

### Chaining

**권한 축이 있는지는 downstream input이 정합니다.** `08:1355`가 `조건에 권한 축이 있으면`으로 쓰는데 여기서 조건은 downstream input입니다. downstream input의 `privilege_level`이 `null`이면 조건 3은 해당 없음이고 upstream의 값은 기준이 아닙니다. `normal` 샘플이 이 경우(upstream `authenticated_user`, downstream `null`)입니다.

**권한 조건은 코드 근거로만 판단합니다.** 전역 권한 서열표나 문자열 이름의 단순 일치를 쓰지 않습니다(`06:96`, `08:1357`). `failure` 샘플이 이 규칙을 확인하고 `normal-true-true` 샘플이 무엇이 있어야 성립하는지를 보여줍니다.

**`entity_refs`는 같은 코드 요소이거나 호출·데이터·권한 경계 관계로 이어진다는 코드 근거로 판단합니다.** `symbol_id` 문자열 일치는 근거의 하나일 뿐 그 자체가 조건이 아닙니다.

**`assumptions` 계산이 정해져 있습니다.**

```
upstream의 inputs 전부       → 남음
downstream의 나머지 inputs   → 남음
downstream의 매칭된 input    → 빠짐
```

남은 `PrimitiveDraft`마다 `description`을 **문자열 그대로** 하나씩 담습니다. 요약·합침 금지입니다. 개수와 내용을 runtime이 대조합니다.

**조상 깊이는 양방향 재귀로 셉니다.** `06:210`이 `match의 upstream_result_ref와 downstream_input_ref 양쪽을 재귀적으로 거슬러 올라가 얻은 조상 수`로 정합니다. 자식 Primitive는 부모가 둘이라 계보가 갈라지는 DAG이므로 한쪽만 따라가면 조상을 절반 놓칩니다. 이번 샘플 셋은 `lineage_results`가 모두 비어 있어 이 경로를 시험하지 못합니다.

**계보 복구는 Context Retrieval Service가 합니다.** `08:986`이 `Context Retrieval Service가 CONTEXT_RETRIEVAL work에 고정된 exact proposal의 source_primitive_match_id를 읽어 계보를 검사하고 검증 시작점을 복구한다. 자식 Verification은 검증된 CodeContextResponse를 소비한다`로 정합니다. 자식 Verification이 직접 계보를 조회하지 않습니다.

**한 조합은 세 목록 중 정확히 하나에만 들어갑니다.** `primitive_match_candidates` / `excluded_lineage_refs` / `no_match_reasons`. 쓰면서 동시에 제외할 수 없습니다.

**`reason_code`는 실제로 어긋난 축을 지목합니다.** entity가 맞고 권한이 어긋났으면 `PRIVILEGE_UNSATISFIED`이지 `ENTITY_UNRELATED`가 아닙니다.

**TRUE + HOLD와 TRUE + TRUE를 다르게 다루지 않습니다.** downstream의 `result` 유무로 두 경우가 유도될 뿐 저장 구조는 같고 `match_kind` 같은 종류 필드는 두지 않습니다. result를 가진 Primitive도 `inputs`가 있으면 downstream이 되며, 양쪽이 모두 result와 inputs를 가지면 두 방향을 모두 검토해야 합니다. `normal-true-true` 샘플이 이 경우입니다.

**결합 지점 반증 질문이 필수입니다.** 두 능력이 이어지는 지점은 어느 부모의 조건도 아니라 `assumptions`에 드러나지 않습니다. 그래서 따로 요구합니다.

**admission을 다시 판단하지 않습니다.** 입력으로 들어온 Primitive는 이미 자격이 확정된 것입니다. HOLD Primitive의 `admission_decision_ref`가 `null`인 것은 정상입니다.

### 잘못된 입력과 중복 처리

| 상황 | 처리 |
|---|---|
| Hypothesis 출력이 schema·semantic 검증 실패 | 의미를 바꾸지 않는 범위에서 제한 횟수 repair 후 `INVALID_OUTPUT`. invalid proposal은 다음 단계로 넘기지 않음 |
| 중복 후보 있음 | runtime이 `symbol_id`·`CodeLocation` 겹침·`relation_id`로 후보를 좁힌 뒤 `DUPLICATE_REVIEW` 호출. `DUPLICATE`가 후보 목록 안의 가설을 지목할 때만 등록 차단 |
| 중복 판정 호출 실패·형식 오류·후보 밖 지목 | 기록만 남기고 **fail-open 등록**(`CHECK_FAILED` / `INVALID_DUPLICATE_TARGET`). 탐지 누락보다 중복을 택함 |
| Chaining 결과에 `considered`에 없는 Primitive | `STALE_RESULT`로 저장 거절 |
| 같은 match 조합이 중복 저장됨 | 정상 중복이 아니라 담당 규칙 위반이므로 결과 전체를 저장하지 않고 `AnalysisError`로 기록. `FALSE`·`HOLD`로 바꾸지 않음 |
| Chaining이 담당 아닌 조합을 검토 | 결과에 넣지 않음. `no_match_reasons`에도 안 들어감 |
| 두 부모의 `restriction_id`가 같은데 내용이 다름 | 임의로 하나를 고르거나 합치지 않고 `errors`에 남김. `08:679`가 그 상태의 저장을 거절함. `no_match_reasons`의 `reason_code`에는 이 경우가 배정돼 있지 않음(확인 요청 3번) |

## 미결정 사항

설계 문서만으로 결정할 수 없어 임의로 채우지 않은 항목입니다.

**`PrimitiveDraft.entity_refs`에 공유 저장 위치를 넣어도 되는가 — R6**

`normal-true-true` 샘플이 `session['role']`(`symbol_kind=DATA`)을 upstream result와 downstream input 양쪽 `entity_refs`에 넣어, 한쪽이 쓰고 한쪽이 읽는다는 사실을 매칭 조건 2와 3의 코드 근거로 씁니다. `08:1357`이 금지하는 것은 전역 권한 서열표와 문자열 이름의 단순 일치이므로 위반은 아니지만, `entity_refs`에 무엇을 넣어야 하는지는 정해져 있지 않습니다.

이 선택이 체이닝의 실질 범위를 정합니다. 익스플로잇 지점만 가리키면 상태 결합이 성립하지 않고, 권한 상승 체인 대부분이 그 형태입니다. `PrimitiveDraft`를 작성하는 것은 R6이므로 R6가 정해 주셔야 합니다. 아니라면 `evidence_refs` 쪽으로 옮깁니다.

## 이 경계에서 치른 대가

두 프롬프트 모두 현재 main 계약만으로 작성했습니다. 계약 수정을 전제하지 않습니다. 대신 두 곳에서 대가를 치렀습니다.

### 1. Hypothesis의 `restrictions`를 비웁니다

`Restriction.fact_refs`의 각 항목은 `CodeFactRef`이고 `bundle_ref`가 필수인데, `05:231`의 `facts` projection에 bundle의 `meta`가 없어 `StoredDataRef`를 만들 재료가 없습니다. `evidence_refs`도 `StoredDataRef`라 같습니다. `08:983`이 INITIAL proposal의 각 restriction에 `fact_refs`를 하나 이상 요구하므로 이 단계에서 낼 수 있는 값은 빈 배열뿐입니다.

제한에 해당하는 관측 사실은 `observed_facts`에 `CodeFact` 그대로 보존합니다. `CodeFact`는 `bundle_ref`를 요구하지 않습니다. 제한으로 표시하는 일은 `StaticFactBundle($)` 전체를 받는 Verification(`05:235`, `05:237`)이 맡으며 `08:1260`이 이미 이를 허용합니다. 잃는 사실은 없고 제한 식별 책임이 Verification으로 옮겨갑니다.

### 2. Chaining Agent가 담당을 계산하지 않습니다

`08:407`이 한 조합을 어느 work가 검토할지를 이렇게 정합니다.

```text
한 조합의 담당은 두 Primitive 중 자기 후보 pool에 상대가 들어 있는 work다. pool은 `REGISTER_WORK`가
COMMITTED된 index에서 고정하므로 실제 저장 순서를 그대로 따른다. 양쪽 pool에 서로가 모두 있으면
`record_id`가 사전순으로 큰 Primitive를 계기로 가진 work가 담당이다.
```

담당을 계산하려면 이 work의 계기를 알아야 하는데, `05:245`의 slot 목록에 계기가 없습니다. `08:295`가 `WorkExecutionState.trigger_primitive_ref`로 그 값을 이미 정의하고 `08:405`가 CHAINING 필수로 정하지만 Agent에게 전달되지 않습니다.

`considered`의 `meta.created_at` 최대값으로 유도하는 방법을 검토했으나 성립하지 않습니다. `08:403`이 Primitive COMMIT 뒤에 work를 등록하게 하고 `08:401`이 등록 시점의 current index를 읽으므로, 그 사이에 다른 가설의 Primitive가 저장되면 계기가 아닌 것이 가장 최근 값이 됩니다. `record_id` 최대값도 같은 이유로 틀립니다.

그래서 **Agent는 `considered`의 모든 조합을 검토하고 담당은 따지지 않습니다.** 어느 조합을 저장할지는 trusted runtime이 계기를 기준으로 정합니다.

이 방식의 비용은 셋입니다. R3·R4 확인을 요청합니다.

| | 무엇 |
|---|---|
| 1 | `08:407`이 "담당이 아닌 조합은 `no_match_reasons`에도 넣지 않는다"고 정하는데 Agent 출력에는 들어갑니다. runtime이 지워야 하므로 검증이 아니라 편집이 됩니다 |
| 2 | Primitive가 n개면 매 work가 조합 수만큼 봅니다. work는 Primitive마다 생기므로 누적 비용이 빠르게 늘어납니다 |
| 3 | Agent가 조합을 빠뜨려도 runtime이 어차피 잘라내므로 누락이 드러나지 않습니다 |

`05:245`에 `trigger_primitive_ref`를 노출하면 셋 다 사라집니다. 계약 변경이 아니라 이미 필수인 값을 프롬프트 입력에 더하는 일입니다.

fixture 형태가 역할마다 다른 것도 함께 봐 주셨으면 합니다. R2는 입력이 원본 도구 출력이고 기대 결과가 저장 record 형태, R5는 assertion projection, 이 자료는 projection 후 프롬프트 payload와 `must`/`must_not`입니다. 하나의 harness로 묶을지 R3 판단이 필요합니다.

## 결과를 받는 다음 파트와 검토 요청

- `hypothesis_proposal` → ORCHESTRATION 등록 runtime → **R6 Verification**
- `chaining_result`의 `chained_hypothesis_proposals` → 같은 등록 경로 → `CONTEXT_RETRIEVAL` → **R6 Verification**

`docs/governance/OWNERSHIP.md:21`이 R1의 반드시 함께 검토할 역할을 정적분석·검증·데이터·평가로 정합니다.

| 역할 | 무엇을 봐 주셨으면 하는지 |
|---|---|
| R3 구현·통합 | runtime이 담당 아닌 조합을 잘라내는 방식이 수용 가능한지, `trigger_primitive_ref`를 slot으로 노출할 수 있는지, template 경로와 자동 테스트 연결 |
| R4 PM·아키텍처 | `08` 식별자 표와 registry 변경, 담당 동점 tie-break의 실행 주체, 공통 계약 정합성 |
| R2 정적분석·컨텍스트 | `StaticFactBundle` 샘플이 실제 정규화 출력과 맞는지, ID 형식, 도달 근거 관계의 형태 |
| R6 검증·반박·플레이북 | INITIAL proposal의 `restrictions`가 항상 비어 restriction 식별 전량이 Verification으로 옮겨오는데 기존 설계가 이를 전제하는지, 아래 미결정 사항, 자식 proposal로 Verification을 시작할 수 있는지, 반증 질문 기준이 플레이북과 충돌하지 않는지 |
| R8 데이터·평가·예산 | `must`/`must_not`의 `grading` 구분이 품질 지표로 쓸 만한지, repair 재시도 한도와 맞물리는지 |

체이닝 자식 가설은 `observed_facts=[]`로 등록되어 Context Retrieval Service가 계보에서 시작점을 복구한 뒤 Verification이 시작하므로, 그 복구 절차와 이 자료의 기대가 맞는지 R6 확인을 함께 요청합니다.
