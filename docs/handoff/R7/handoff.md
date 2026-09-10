# R7 Dynamic Reproduction Agent 구현 인계

## 1. 목적과 현재 상태

이 디렉터리는 R7 Dynamic Reproduction Agent를 실제 LLM과 Docker 기반 동적
재현 흐름에 연결하기 위한 프롬프트 초안과 검증 자료를 제공한다.

현재 프롬프트는 검토 초안이며 아직 ACTIVE Prompt Registry template이 아니다.
프로젝트별 코드, 분석 결과와 실행 관찰은 프롬프트 본문에 포함하지 않고 각
호출의 입력 slot으로 전달한다.

현재 `main`의 fake 기반 전체 실행 흐름에서 R7 구간을 실제 기능으로 교체할 때
이 자료를 사용한다. 이 문서는 production 구현이나 Sandbox 격리 검증이 이미
완료됐다는 의미가 아니다.

## 2. 산출물 위치

| 구분 | 파일 | 용도 |
|---|---|---|
| 공통 프롬프트 | [`common-agent-prompt.md`](./common-agent-prompt.md) | 모든 R7 task에 공통으로 적용할 역할, 권한, 증거 및 실패 처리 경계 |
| 환경 요구사항 | [`derive-environment.md`](./derive-environment.md) | 저장소 선언과 R6 요청으로 `EnvironmentRequirements` 생성 |
| 재현 계획 | [`plan-reproduction.md`](./plan-reproduction.md) | 실행 목표와 관찰 전략을 담은 `ReproductionPlan` 생성 |
| PoC 후보 | [`create-poc-candidate.md`](./create-poc-candidate.md) | 실행 전 `PoCCandidate` 생성 |
| 재현 실행 | [`execute-reproduction.md`](./execute-reproduction.md) | Sandbox 안에서 다음 행동을 `DynamicReproductionToolRequest`로 한 번에 하나씩 요청 |
| 실행 해석 | [`interpret-attempt.md`](./interpret-attempt.md) | 실제 로그와 관찰을 `DynamicReproductionConclusion`으로 해석 |
| 검증 자료 안내 | [`validation/README.md`](./validation/README.md) | fixture, 사례 형식, assertion 연산자와 소유권 설명 |
| 입력 형식 | [`validation/validation-case.schema.json`](./validation/validation-case.schema.json) | 검증용 입력 envelope schema |
| 기대 결과 형식 | [`validation/validation-expectation.schema.json`](./validation/validation-expectation.schema.json) | 검증용 기대 결과 envelope schema |

## 3. 실행 순서

1. `DERIVE_ENVIRONMENT`
2. `PLAN_REPRODUCTION`
3. Runtime Validator의 `RUN_SANDBOX` 허가
4. Sandbox Controller의 `LOCAL_ONLY` 경계 판정
5. Reproduction Setup Automation의 recipe·image·container·환경 준비
6. `CREATE_POC_CANDIDATE`
7. `EXECUTE_REPRODUCTION` 반복
8. Agent가 `FINISH`를 반환한 뒤 `INTERPRET_ATTEMPT`
9. Reproduction Session Manager가 실제 기록을 검사해 validated PoC와 최종
   `DynamicReproductionResult` 확정

`EXECUTE_REPRODUCTION`은 같은 work·attempt의 논리 session을 이어간다. Agent는
한 turn에 하나의 구조화된 tool request를 반환하고, Runtime이 실행한 결과를
Session Manager가 append-only `AgentLog`에 기록한 뒤 다음 turn에 다시 전달한다.

## 4. 프롬프트 조립과 입출력

Prompt Runtime은 매 호출에서 공통 프롬프트와 해당 task 프롬프트를 조합하고,
정확한 `task_kind`, 허용된 입력 slot, 출력 schema, tool policy, 실행 제한, retry
정책과 redaction 정책을 함께 제공한다. 한 LLM 호출은 등록된 result kind 하나만
반환한다.

| Task | 입력 slot | 출력 | Tool/session |
|---|---|---|---|
| `DERIVE_ENVIRONMENT` | `request`, `dependency_context`, `dependency_files`(0개 이상) | `EnvironmentRequirements` | tools 없음 / `NEW` |
| `PLAN_REPRODUCTION` | `request`, `requirements`, `dependency_context`, `dependency_files`(0개 이상) | `ReproductionPlan` | tools 없음 / `NEW` |
| `CREATE_POC_CANDIDATE` | `request`, `plan`, `environment` | `PoCCandidate` | tools 없음 / `NEW` |
| `EXECUTE_REPRODUCTION` | `request`, `requirements`, `plan`, `environment`, `candidate`(선택), `agent_log`, `prior_turns`(0개 이상), `observations`(0개 이상) | `DynamicReproductionToolRequest` | Sandbox 내부 tool policy / `AUTO` |
| `INTERPRET_ATTEMPT` | `request`, `plan`, `environment`, `candidate`(선택), `agent_log`, `observations`(0개 이상) | `DynamicReproductionConclusion` | tools 없음 / `NEW` |

Prompt Registry 구현 대상 경로는 다음과 같다.

```text
config/prompts/templates/dynamic_reproduction/derive-environment/1.0.0.md
config/prompts/templates/dynamic_reproduction/plan-reproduction/1.0.0.md
config/prompts/templates/dynamic_reproduction/create-poc-candidate/1.0.0.md
config/prompts/templates/dynamic_reproduction/execute-reproduction/1.0.0.md
config/prompts/templates/dynamic_reproduction/interpret-attempt/1.0.0.md
```

초안 파일을 그대로 복사해 ACTIVE로 지정하지 않는다. Prompt Registry 등록 전에
현재 schema ID, validator ID, provider profile, tool policy와 input projection을
최신 `main`의 Prompt Runtime 계약으로 검증한다.

## 5. 역할과 실행 경계

R7 LLM이 생성할 수 있는 artifact는 다음 다섯 가지다.

- `EnvironmentRequirements`
- `ReproductionPlan`
- `PoCCandidate`
- `DynamicReproductionToolRequest`
- `DynamicReproductionConclusion`

다음 artifact와 실제 상태는 trusted component가 생성하거나 확정한다.

- Reproduction Setup Automation: `EnvironmentRecipe`, `SandboxEnvironment`,
  `CleanupResult`
- Sandbox Controller: `SandboxPolicyDecision`
- Reproduction Session Manager: append-only `AgentLog`, `SandboxCommandRecord`,
  validated `PoCBundle`, final `DynamicReproductionResult`

R7은 R6의 exact `DynamicReproductionRequest`, 가설, 목적, generation,
`sandbox_profile_ref`를 바꾸지 않는다. 실제 실행은 승인된 `LOCAL_ONLY` Sandbox
안에서만 수행한다. R7은 최종 `TRUE | FALSE | HOLD`, CWE, Technical Gate,
Rule Scope Gate, reportability 또는 보고서를 판단하지 않는다.

`ReproductionPlan`은 목표와 관찰 전략의 provenance다. 명령·payload·step·PoC·
cleanup allowlist로 사용하지 않는다. 승인된 Sandbox 안에서 Agent는 명령, PoC,
fixture와 mock, 환경 조정, 관찰 방법과 재시도를 기술적으로 선택할 수 있다.

실제로 실행되지 않은 명령, 관찰되지 않은 출력이나 영향, 검증되지 않은 PoC를
실행 사실이나 증거로 주장하지 않는다. 실행 오류·취소·timeout·환경 준비 실패는
`DISPROVED`가 아니다.

## 6. 검증 fixture와 출처

[`validation/fixture`](./validation/fixture)는 Python 3.12와 Flask 3.1.2를 사용하는
합성 local-only 프로젝트다. `app.py`는 요청받은 report 이름이 `reports/` 아래에
남는지 검사하지 않는 의도적인 경로 탐색 결함을 포함한다.

검증한 명령과 관찰은 다음과 같다.

```text
cd docs/handoff/R7/validation/fixture

uv run --project . python reproduce.py public.txt
=> {"status_code": 200, "content": "PUBLIC_REPORT"}

uv run --project . python reproduce.py ../fixtures/probe.txt
=> {"status_code": 200, "content": "R7_LOCAL_PROBE"}
```

위 결과는 2026-09-09에 Python 3.12.13과 Flask 3.1.2로 직접 확인했다. probe는
합성 프로젝트 내부에만 존재하며 외부 계정, secret, host target, live service와
network egress를 사용하지 않는다.

각 입력 파일의 `source.type`이 실제 실행을 확인한 합성 fixture인지, 의도적으로
주입한 Runtime 실패·취소인지 구분한다. `dependency_files`와 fixture source의
내용 hash는 현재 fixture 파일과 일치해야 한다.

## 7. 검증 사례와 기대 결과

| 사례 | 입력과 기대 결과 | 반드시 확인할 조건 |
|---|---|---|
| 환경 준비 성공 | [`environment-ready.input.json`](./validation/environment-ready.input.json), [`environment-ready.expected.json`](./validation/environment-ready.expected.json) | requirements·plan 생성 후 `RUN_SANDBOX`가 허가되고 모든 필수 환경 check가 `MATCH`, 환경은 `READY`. 이 상태만으로 취약점이나 validated PoC를 주장하지 않음 |
| 환경 준비 실패 | [`environment-setup-failure.input.json`](./validation/environment-setup-failure.input.json), [`environment-setup-failure.expected.json`](./validation/environment-setup-failure.expected.json) | Python 버전 `MISMATCH`, Agent 미시작, 실패 원인과 미실행 Health Check 기록. 환경 실패를 `DISPROVED`로 바꾸지 않음 |
| 실행 중단 | [`execution-cancelled.input.json`](./validation/execution-cancelled.input.json), [`execution-cancelled.expected.json`](./validation/execution-cancelled.expected.json) | candidate와 tool request는 보존하되 observation과 validated PoC는 없음. 취소 뒤 도착한 output은 final result에서 제외 |
| 종료 후 cleanup 실패 | [`cleanup-failure.input.json`](./validation/cleanup-failure.input.json), [`cleanup-failure.expected.json`](./validation/cleanup-failure.expected.json) | exact candidate 실행과 지지 관찰로 `SUPPORTED`와 validated PoC가 성립. cleanup 실패와 남은 resource는 별도로 보존하며 기술적 재현 결과를 뒤집지 않음 |

`*.input.json`은 future input assembler를 위한 scenario specification이며 production
record 전체가 아니다. `*.expected.json`은 안정적인 record projection, assertion과
`must_not_claim`을 담는다. 자연어 설명 전체를 byte-for-byte로 비교하지 않고,
반드시 포함할 근거와 충족할 판단 조건을 검사한다.

## 8. 구현 시 통과 조건

- 각 task가 표에 정의된 input slot만 받고 정확히 하나의 output artifact를 만든다.
- 모든 output이 current request·workspace·commit·hypothesis·generation·work·
  attempt의 exact reference를 유지한다.
- `RUN_SANDBOX` 전에는 PoC나 command를 실행하지 않는다.
- 실제 실행과 환경 변경은 Runtime을 통해 수행하고 Agent의 서술만으로 성공을
  인정하지 않는다.
- `AgentLog`는 append-only이고 tool request, command record, candidate revision,
  digest와 observation을 같은 attempt에서 연결한다.
- validated `PoCBundle`은 exact candidate revision과 digest가 실제 실행되고 이를
  지지하는 관찰이 기록된 경우에만 Session Manager가 생성한다.
- setup·provider·runtime·timeout·취소·cleanup 실패를 가설 반증으로 변환하지 않는다.
- 네 검증 사례의 schema, source hash, ownership, reference, 상태와 금지 주장
  assertion이 모두 통과한다.

## 9. 구현 전에 확인할 연결 사항

아래 항목은 프롬프트 문장으로 임의 확정하지 않고 담당 계약과 함께 정한다.

1. `CREATE_POC_CANDIDATE`의 현재 Prompt Runtime slot에는 dereference된 실제 코드
   fragment나 이전 candidate 본문이 없다. 코드별 PoC를 만들기 위해 어떤 기존
   record projection을 추가할지 R3 Prompt Runtime, R4 공통 계약, R6 요청 담당이
   함께 확인한다.
2. `PoCCandidate.content_ref`, `content_digest`, `llm_call_id`와 기타 저장 metadata를
   Agent가 생성하지 않고 Runtime persistence가 채우는 방식을 R3·R4가 확정한다.
3. request와 requirements가 모순되어 `ReproductionPlan`을 만들 수 없을 때 사용할
   Runtime 소유 실패 channel을 R3·R4·R6가 확인한다. Agent가 한쪽 입력을 임의로
   약화하거나 지원되지 않는 값을 채우지 않는다.
4. R8은 네 사례를 평가 자료에 연결할 때 자유형 문장 대신 assertion에 명시된
   근거, ownership, 상태, 비용과 실행 시간을 채점 기준으로 사용한다.

## 10. 교차 리뷰 요청

| 담당 파트 | 확인 요청 사항 |
|---|---|
| R2 정적 분석·Context | `dependency_context.code_fragment_refs`와 실제 `dependency_files`가 current workspace·commit에서 set-equal하게 전달되는지, 경로·내용·hash·redaction 정보만으로 환경 선언을 확인할 수 있는지 검토 |
| R3 Prompt Runtime·통합 | 공통·단계 프롬프트 조립, task별 input projection, 한 호출당 한 artifact, `EXECUTE_REPRODUCTION`의 Sandbox 내부 tool loop와 session 유지, Runtime 소유 metadata 주입 방식을 검토 |
| R4 공통 계약 | artifact 생산자, exact reference, `ActionRequest → ActionDecision → SandboxPolicyDecision` 연결, AgentLog append-only와 오류·취소·cleanup 상태 조합이 정본 계약과 일치하는지 검토 |
| R5 Gate·정책 | 최종 `AgentLog`·validated `PoCBundle`·`DynamicReproductionResult`가 Technical Gate와 Rule Scope Gate에서 실제 수행 사실과 testing restriction을 검토하기에 충분한 provenance를 제공하는지 검토 |
| R6 Verification | `DynamicReproductionRequest`의 목적·필수 조건이 requirements·plan에서 약화되지 않는지, R7의 `SUPPORTED | DISPROVED | INCONCLUSIVE`를 최종 `TRUE | FALSE | HOLD`와 분리해 소비할 수 있는지 검토 |
| R8 평가·예산 | 네 검증 사례의 assertion을 평가 case와 채점 기준으로 연결할 수 있는지, 실행 시간·비용·실패·cleanup 지표가 R8 소유 기준과 충돌하지 않는지 검토 |

각 검토자는 확인한 commit SHA와 담당 항목, 수정 요구 또는 승인 의견을 PR에
남긴다. R3 통합 담당은 교차 리뷰 결과와 이 디렉터리의 자료를 실제 Prompt
Registry·input assembler·동적 재현 구현으로 연결한다.

## 11. 정본 참고 문서

- [`검증과 동적 재현`](../../architecture-v5/04-verification-and-dynamic-reproduction.md)
- [`경량 데이터 계약`](../../architecture-v5/08-lightweight-data-contracts.md)
- [`Prompt Runtime`](../../architecture-v5/implementation/05-prompt-runtime.md)
- [`ADR-007 R7 자율 재현 session`](../../review/decisions/ADR-007-r7-autonomous-reproduction-session.md)
