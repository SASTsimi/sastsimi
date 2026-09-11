# R7 Dynamic Reproduction Agent handoff

이 문서는 R7 프롬프트와 검증 자료를 실제 Prompt Runtime 및 동적 재현 구현에
연결할 다음 담당자를 위한 인계 문서다. 상세한 설계 배경과 검증 기록은
[`implementation-notes.md`](./implementation-notes.md)를 참고한다.

## 1. 담당 기능과 기준 설계 문서

R7은 R6가 생성한 exact `DynamicReproductionRequest`를 받아 승인된
`LOCAL_ONLY` Sandbox 안에서 취약점 가설을 동적으로 재현하고, 실제 실행 기록과
관찰을 `SUPPORTED | DISPROVED | INCONCLUSIVE` 중 하나로 해석한다. 최종
`TRUE | FALSE | HOLD` 판정은 R6의 책임이다.

기준 설계 문서는 다음과 같다.

- [`검증과 동적 재현`](../../architecture-v5/04-verification-and-dynamic-reproduction.md)
- [`경량 데이터 계약`](../../architecture-v5/08-lightweight-data-contracts.md)
- [`Prompt Runtime`](../../architecture-v5/implementation/05-prompt-runtime.md)
- [`ADR-007 R7 자율 재현 session`](../../review/decisions/ADR-007-r7-autonomous-reproduction-session.md)

## 2. 담당 프롬프트와 입력·기대 결과 파일의 위치

R7은 task별로 독립된 Prompt Registry entry와 완결된 template을 사용한다.
각 호출에는 현재 task의 template, 입력 slot, 출력 schema만 전달하며 다른 R7
task의 지시문이나 출력 schema를 함께 전달하지 않는다.

- 환경 요구사항:
  [`prompts/derive-environment/1.0.0.md`](./prompts/derive-environment/1.0.0.md)
- 재현 계획:
  [`prompts/plan-reproduction/1.0.0.md`](./prompts/plan-reproduction/1.0.0.md)
- PoC 후보:
  [`prompts/create-poc-candidate/1.0.0.md`](./prompts/create-poc-candidate/1.0.0.md)
- 실행 loop:
  [`prompts/execute-reproduction/1.0.0.md`](./prompts/execute-reproduction/1.0.0.md)
- 시도 해석:
  [`prompts/interpret-attempt/1.0.0.md`](./prompts/interpret-attempt/1.0.0.md)
- 검증 자료 설명: [`validation/README.md`](./validation/README.md)
- 입력 envelope schema:
  [`validation/validation-case.schema.json`](./validation/validation-case.schema.json)
- 기대 결과 envelope schema:
  [`validation/validation-expectation.schema.json`](./validation/validation-expectation.schema.json)
- task 검증 입력 schema:
  [`validation/prompt-task-case.schema.json`](./validation/prompt-task-case.schema.json)
- task 검증 기대 결과 schema:
  [`validation/prompt-task-expectation.schema.json`](./validation/prompt-task-expectation.schema.json)
- task별 정상·schema 오류·semantic 오류·prompt injection·stale reference 사례:
  [`validation/prompt-tasks/README.md`](./validation/prompt-tasks/README.md)
- 환경 준비 성공:
  [`environment-ready.input.json`](./validation/environment-ready.input.json),
  [`environment-ready.expected.json`](./validation/environment-ready.expected.json)
- 환경 준비 실패:
  [`environment-setup-failure.input.json`](./validation/environment-setup-failure.input.json),
  [`environment-setup-failure.expected.json`](./validation/environment-setup-failure.expected.json)
- 실행 중단:
  [`execution-cancelled.input.json`](./validation/execution-cancelled.input.json),
  [`execution-cancelled.expected.json`](./validation/execution-cancelled.expected.json)
- 종료 후 cleanup 실패:
  [`cleanup-failure.input.json`](./validation/cleanup-failure.input.json),
  [`cleanup-failure.expected.json`](./validation/cleanup-failure.expected.json)

### 2.1 Prompt Registry 등록 정보

모든 entry의 `agent_role`은 `DYNAMIC_REPRODUCTION`, `template_version`은
`1.0.0`이다. 아래 key는 DRAFT logical key이며 실제 등록과 호출은 immutable
record의 exact `StoredDataRef`를 사용한다.

| task_kind | prompt_key | output_schema | semantic_validator | result_kind | session_policy | tool_policy |
|---|---|---|---|---|---|---|
| `DERIVE_ENVIRONMENT` | `r7.derive-environment` | `schema.environment-requirements.next-major` | `validator.environment-requirements.v1` | `environment_requirements` | `NEW` | `tools.none.v1` |
| `PLAN_REPRODUCTION` | `r7.plan-reproduction` | `schema.reproduction-plan.next-major` | `validator.reproduction-plan.v1` | `reproduction_plan` | `NEW` | `tools.none.v1` |
| `CREATE_POC_CANDIDATE` | `r7.create-poc-candidate` | `schema.poc-candidate.next-major` | `validator.poc-candidate.v1` | `poc_candidate` | `NEW` | `tools.none.v1` |
| `EXECUTE_REPRODUCTION` | `dynamic-reproduction.execute-reproduction` | `schema.dynamic-reproduction-tool-request.next-major` | `validator.dynamic-reproduction-tool-request.v1` | `dynamic_reproduction_tool_request` | `AUTO` | `tools.dynamic-reproduction-inner.v1` |
| `INTERPRET_ATTEMPT` | `dynamic-reproduction.interpret-attempt` | `schema.dynamic-reproduction-conclusion.next-major` | `validator.dynamic-reproduction-conclusion.v1` | `dynamic_reproduction_conclusion` | `NEW` | `tools.none.v1` |

정확한 input slot과 cardinality는 다음과 같다. 별도 표기가 없는 필수 slot은
정확히 하나, 선택 하나는 0~1개, 선택 다수는 0개 이상이다.

| task_kind | input slot과 cardinality |
|---|---|
| `DERIVE_ENVIRONMENT` | `request` 필수 하나, `dependency_context` 필수 하나, `dependency_files` 선택 다수 |
| `PLAN_REPRODUCTION` | `request` 필수 하나, `requirements` 필수 하나, `dependency_context` 필수 하나, `dependency_files` 선택 다수 |
| `CREATE_POC_CANDIDATE` | `request` 필수 하나, `plan` 필수 하나, `environment` 필수 하나 |
| `EXECUTE_REPRODUCTION` | `request`, `requirements`, `plan`, `environment`, `agent_log` 각각 필수 하나, `candidate` 선택 하나, `prior_turns`와 `observations` 선택 다수 |
| `INTERPRET_ATTEMPT` | `request`, `plan`, `environment`, `agent_log` 각각 필수 하나, `candidate` 선택 하나, `observations` 선택 다수 |

task별 입력의 data kind와 field projection은 기준 문서
[`Prompt Runtime`](../../architecture-v5/implementation/05-prompt-runtime.md)의
R7 구현 행을 그대로 따른다.

## 3. 입력 샘플의 출처

환경 준비 성공 사례와 경로 탐색 관찰은
[`validation/fixture/README.md`](./validation/fixture/README.md)의 Python 3.12,
Flask 3.1.2 합성 프로젝트에서 가져왔다. `allowed-files/allowed.txt`는 정상 조회 대상이고,
`../outside-allowed-directory/path-traversal-target.txt`는 허용된 `allowed-files/` 경계 밖의 접근을 확인하는 local-only
probe다. 두 실행은 2026-09-09에 직접 확인했으며 fixture 파일 내용 hash를 입력에
기록했다.

환경 준비 실패와 실행 취소는 해당 lifecycle 분기를 검증하기 위해 의도적으로
주입한 Runtime 사건이다. cleanup 실패 사례는 위 합성 fixture에서 확인한 exact
candidate 실행·관찰에 의도적인 cleanup 실패 상태를 결합했다. 모든 샘플은 외부
계정, 실제 secret, live service 및 network egress를 사용하지 않는다.

## 4. 기대 결과가 그렇게 나와야 하는 이유

| 사례 | 기대 결과와 근거 |
|---|---|
| 환경 준비 성공 | 모든 필수 요구사항 check가 `MATCH`여야 환경이 `READY`가 된다. 환경 준비만으로 취약점 재현이나 validated PoC를 주장할 수는 없다. |
| 환경 준비 실패 | 필수 Python 버전이 `MISMATCH`이고 Agent와 Health Check가 실행되지 않았으므로 준비 실패로 남겨야 한다. 실행하지 못한 가설을 `DISPROVED`로 판단할 수 없다. |
| 실행 중단 | 취소 전에 생성된 candidate와 tool request는 provenance로 보존하지만 지지 observation이 없으므로 validated PoC나 동적 결과를 만들 수 없다. 취소 뒤 도착한 output은 현재 결과에 포함하지 않는다. |
| cleanup 실패 | exact candidate가 실행되고 경로 탐색을 지지하는 관찰이 기록된 시점에 기술적 `SUPPORTED` 근거가 성립한다. 이후 cleanup 실패는 별도 lifecycle 상태이며 이미 얻은 기술적 관찰을 뒤집지 않는다. |

자연어 문장 전체를 고정된 정답으로 비교하지 않는다. `*.expected.json`에 정의된
필수 근거, exact reference, 상태, ownership, assertion과 `must_not_claim` 조건을
검사한다.

## 5. 반드시 지켜야 하는 처리 규칙과 통과 조건

- R6 request의 가설, 목적, 목표, generation과 `sandbox_profile_ref`를 변경하거나
  약화하지 않는다.
- 실제 실행은 Sandbox 승인 후 `LOCAL_ONLY` 경계 안에서 Runtime을 통해서만
  수행한다.
- 실행하지 않은 명령, 관찰되지 않은 출력·영향, 검증되지 않은 PoC를 사실이나
  증거로 주장하지 않는다.
- setup·provider·runtime·timeout·취소·cleanup 실패를 `DISPROVED`로 변환하지
  않는다.
- 각 호출은 현재 task에 허용된 입력 slot만 받고 정확히 하나의 schema-valid
  artifact를 반환한다.
- `ReproductionPlan`을 command·payload·step·PoC·cleanup allowlist로 사용하지
  않는다.
- `AgentLog`는 append-only로 유지하며 current request·workspace·commit·work·
  attempt의 exact reference만 결합한다.
- validated `PoCBundle`은 exact candidate revision과 digest의 실행 및 지지 관찰을
  Runtime이 확인한 경우에만 Session Manager가 생성한다.
- 다섯 task 각각의 정상 출력, schema 오류, semantic 오류, prompt injection,
  stale reference 사례가 기대한 허용 또는 차단 결과와 일치해야 한다.
- 네 lifecycle 사례의 schema, source hash, reference, 상태, ownership와 금지
  주장 assertion이 모두 통과해야 한다.
- `scripts/validate-r7-handoff.py`가 schema, case pair, source hash, 허용 input
  slot과 cardinality, 출력 schema, semantic 차단, scope 혼합 차단과 assertion
  연산자를 자동 검사하고 CI에서 통과해야 한다.

## 6. 미결정 사항

1. [`#162 R7 PoC 생성 입력·Runtime 메타데이터 계약 확정`](https://github.com/SASTsimi/sastsimi/issues/162)에서
   `CREATE_POC_CANDIDATE`의 실제 코드 fragment 입력과
   `PoCCandidate.content_ref`, `content_digest`, `llm_call_id` 등 Runtime 소유
   metadata의 저장·주입 방식을 확정해야 한다. 해결 전에는 R7 Prompt Registry
   entry를 `ACTIVE`로 전환하지 않는다.
2. request와 requirements의 exact reference가 모순되어 `ReproductionPlan`을 만들
   수 없을 때 사용할 Runtime 소유 실패 channel을 확정해야 한다.
3. 각 task template을 Prompt Registry에 등록할 최종 provider profile과 exact
   policy reference를 최신 `main` 기준으로 검증해야 한다.

## 7. 함께 검토할 담당자

| 담당 | 검토 내용 |
|---|---|
| R3 Prompt Runtime·통합 | 주 인계 대상. task별 Registry entry와 template 선택, input projection, Runtime metadata 주입, Sandbox tool loop와 session 유지를 구현·검토한다. |
| R6 Verification | request의 필수 조건이 약화되지 않는지, R7 outcome을 최종 verdict와 분리해 소비할 수 있는지 검토한다. |

다음 담당자는 이 문서와 다섯 task template, task별 25개 검증 사례와 네
lifecycle 입력·기대 결과 쌍을 같은 commit SHA로 검토한다. 미결정 사항을 관련
담당자와 확정한 뒤 Prompt Registry와 input assembler에 연결한다.
