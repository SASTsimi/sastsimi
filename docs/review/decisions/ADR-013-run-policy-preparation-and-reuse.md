# ADR-013. 실행 단위 정책 준비·재사용과 Sandbox 사전 확인

- 상태: `PROPOSED`
- 제안일: 2026-09-06
- 기준 main: `0cae9bdc5161efb68a3fdc15cb72ec12e3a3440e`
- 결정 담당: PM·아키텍처·공통 계약(R4, `@taehyeon-git`)
- 반드시 확인할 역할: Gate·정책(R5-02, `@kimhr8463`), 동적 재현·Sandbox(R7, `@Potatonion`), 데이터·평가·최신성(R8, `@gitterable`)
- 후속 반영 역할: 구현·LLM 연결(R3, `@YHS-Sec`), Verification 요청(R6, `@UltraPeachKeen`), 탐색·체이닝(R1, `@baeseungwon1010`), 정적 분석(R2, `@zv9uvr`)
- 연결 Issue/PR: #1, #4, #10, 이 ADR을 추가하는 PR

## Context

변경 전 설계는 final TRUE가 Technical Gate를 통과한 뒤에 공식 정책을 수집했습니다. 이 순서에서는 가설마다 정책 수집을 다시 시작할 수 있고, Sandbox 실행 전에 정책 준비 상태와 출처를 확인하기 어려웠습니다. 반대로 정책을 `StaticFactBundle`에 섞으면 코드 사실과 프로그램 운영 정책이 같은 의미로 취급되고, Hypothesis Agent가 scope 밖이라는 이유로 기술적 가설을 너무 일찍 버릴 수 있습니다.

R4는 세 가지를 먼저 공통 계약으로 정합니다.

1. 어떤 정책 정보를 만들고 어디에 저장하는가
2. Sandbox가 실행 전에 무엇을 확인하고 무엇은 판단하지 않는가
3. 정책이 언제 만료되고 어느 단계에서 다시 확인하는가

## Decision

### 1. 정책은 실행당 한 번 준비하고 가설들이 공유합니다

Repository Loader가 `CodeWorkspace.status=READY`를 확정하면 AST·SAST work와 별도로 `POLICY_FETCH` work를 시작합니다. 두 흐름은 서로 기다리지 않고 병렬 실행합니다. 정책 준비 실패는 정적 분석 결과를 바꾸지 않고, 정적 분석 실패도 정책 결과를 바꾸지 않습니다.

최초 정책 준비는 `policy_generation=1`입니다. 같은 `analysis_id + program_id + policy_generation`에는 active policy work를 하나만 허용합니다. 동시에 여러 가설이 정책을 요구해도 새 수집을 만들지 않고 같은 `RunPolicyState`의 COMMITTED exact revision을 기다립니다. 정책은 가설마다 다시 수집·파싱하지 않습니다.

### 2. 원문 수집과 의미 구조화를 분리합니다

- 비-LLM Policy Collector: 승인된 공식 URL에서 원문을 가져오고 원문 bytes/hash, 게시 주체, 확인 근거와 수집 시각을 저장합니다.
- LLM Policy Parser: Collector가 고정한 exact 원문만 읽어 scope, 취약점 분류, testing restriction, impact와 disclosure 항목을 구조화합니다.
- 비-LLM Runtime Validator: Parser 출력 schema, exact source reference, 생산 역할과 저장 revision을 확인합니다. 정책 문장의 뜻을 대신 판단하지 않습니다.

`PolicyParserResult.llm_invocation_ref`는 실제 Parser 호출을 가리킵니다. 모델 기억, 검색 snippet, 저장소 README와 코드 주석은 공식 정책 근거로 승격하지 않습니다.

### 3. 현재 실행의 정책 pointer를 따로 둡니다

`RunPolicyState`는 실행의 모든 가설이 공유하는 current 정책 pointer입니다.

- `PREPARING`: 수집·파싱 중
- `CURRENT`: 검증된 공식 출처, exact collection/policy record와 유효한 만료 시각이 있음
- `ABSENT`: 공식 출처에서 정책 부재를 확인했고 그 확인의 유효기간이 남아 있음
- `BLOCKED`: 인증·외부 입력처럼 해결을 기다림
- `FAILED`: 복구 불가능하거나 retry 소진
- `STALE`: `freshness_valid_until`이 지남
- `UNVERIFIED`: 최신성 기준을 적용하거나 확인하지 못함

과거 revision은 덮어쓰지 않고 감사 이력으로 보존합니다. 만료되면 `policy_generation`을 1 증가시켜 새 work를 만듭니다. `PREPARING` 중이거나 새 결과를 확정하기 전에도 프로그램 정책과 무관한 외부 격리 경계를 통과한 `LOCAL_ONLY` Sandbox는 허용할 수 있습니다. Rule Scope는 `PREPARING` 동안 기다리고, `STALE | UNVERIFIED`에서는 `UNCERTAIN + DENY`만 허용합니다. Reporter와 `PASS | ALLOW`에는 최신성이 유효한 current 정책만 사용할 수 있습니다.

### 4. 정책은 정적 사실이나 가설 사전 필터가 아닙니다

정책 record는 `StaticFactBundle`에 넣지 않습니다. 정적 분석은 코드의 source, sink, 호출 관계, guard와 위치를 제공하고 정책 준비는 프로그램의 운영 규칙을 제공합니다.

Hypothesis Agent는 scope 안의 가능성만 생성하도록 제한하지 않습니다. 기술적으로 의미 있는 가설은 먼저 검증하고, 공식 rule·scope·impact·보고 가능성은 Technical `ACCEPT` 뒤 Rule Scope Gate가 판정합니다.

### 5. Sandbox는 강제할 수 있는 안전 경계만 확인합니다

모든 `RUN_SANDBOX` 요청은 요청 당시 관측한 `RunPolicyState` exact revision을 감사 reference로 고정합니다. 이 reference는 프로그램 정책의 최신성으로 Sandbox 권한을 넓히기 위한 입력이 아닙니다. Sandbox Controller는 다음을 확인합니다.

- 실행 범위가 `LOCAL_ONLY`인지
- clone한 코드는 current `CodeWorkspace.workspace_id + commit_id`에서 만든 Sandbox 내부 복사본인지
- mock과 fixture는 같은 R7 work·attempt에서 생성되어 exact environment·AgentLog·artifact reference로 추적되는지
- 공격 대상 endpoint가 loopback 또는 현재 격리 network 안의 container인지, 출처 불명 endpoint·외부 계정·live program asset을 사용하지 않는지
- Docker daemon/socket, host mount·namespace, secret, 다른 workspace와 허용되지 않은 egress가 차단됐는지
- exact request, plan, Sandbox profile과 R8 lifecycle profile이 같은 action에 연결되고, policy state·collection·policy record는 실행 당시 exact provenance로 서로 일치하는지

현재 아키텍처에서 live target testing은 허용하지 않습니다. 경로·endpoint·계정·fixture의 출처를 위 exact reference로 증명하지 못하면 live로 간주해 거절합니다. network는 default-deny이고, 승인된 package registry egress는 dependency 준비에만 쓰며 공격 대상 통신과 분리해 기록합니다. 정책이 `PREPARING | ABSENT | BLOCKED | FAILED | STALE | UNVERIFIED`여도 이 기술 경계를 통과한 순수 로컬 재현은 기다리지 않고 진행할 수 있지만, 외부 target 작업은 허용하지 않습니다.

Sandbox Controller는 공식 정책의 의미, 가설의 scope 또는 보고 가능성을 판정하지 않습니다. 실제 수행한 `AgentLog`와 정책의 testing restriction이 일치하는지는 Technical `ACCEPT` 뒤 Rule Scope Gate가 LLM으로 검토합니다.

### 6. 만료는 action 직전에 다시 확인합니다

R8이 승인한 versioned freshness 기준으로 `freshness_valid_until`을 계산합니다. 정책을 찾은 `CURRENT`뿐 아니라 공식 정책 부재를 확인한 `ABSENT`에도 기준·확인 시각·확인 근거·만료 시각이 필요합니다. Runtime Validator는 프로그램 정책 판단을 실제로 소비하는 다음 시점에 exact policy state를 다시 확인합니다.

- `CALL_RULE_SCOPE_GATE` 승인과 실제 호출 직전
- `CREATE_REPORT_DRAFT` 승인과 실제 호출 직전

만료된 state는 `STALE`로 전환하고 새 policy generation 준비를 시작합니다. 아직 사용하지 않은 Rule Scope·Reporter action은 `EXPIRED`로 끝내고, 새 current 정책이 준비될 때까지 Reporter와 `PASS | ALLOW`를 거절합니다. `RUN_SANDBOX`는 항상 `LOCAL_ONLY` 경계로 허가되므로 정책 pointer·freshness 변경만으로 기존 decision을 만료시키지 않습니다. 실행 당시 exact policy state는 `SandboxPolicyDecision`에 감사 이력으로 보존합니다. 이후 새 정책 revision이 생기면 Rule Scope Gate는 새 current 정책과 실제 실행 기록을 비교하고, 과거 Gate·Finding·ReportDraft는 새 입력에 재사용하지 않습니다.

### 7. 오류를 취약점 판정으로 바꾸지 않습니다

정책 수집·Parser 실패, 만료와 사전 검사 차단은 `FALSE | HOLD`가 아닙니다. 정적 분석과 기술 검증 결과는 그대로 보존합니다. `COLLECTION_FAILED`에서는 Rule Scope review와 Reporter를 만들지 않습니다. 정책 부재를 공식 확인한 `ABSENT_CONFIRMED`만 기존 계약대로 `UNCERTAIN + DENY` review를 만들 수 있습니다.

## 팀 확인 요청

### R5-02 확인

- Policy Parser가 만드는 구조화 항목이 Rule Scope Gate에 필요한 rule·scope·impact·testing restriction을 빠짐없이 표현하는지
- Parser와 Rule Scope Gate의 프롬프트·출력 책임이 중복되지 않는지
- 정책 revision이 바뀌었을 때 실제 실행 기록과 새 정책을 비교하는 방법이 맞는지

### R7 확인

- `LOCAL_ONLY` 정의와 live asset·외부 계정·egress 차단이 실제 Sandbox 구현으로 강제 가능한지
- `SandboxPolicyDecision`에 추가한 policy reference와 freshness 값이 실행 로그에 충분히 남는지
- 순수 로컬 재현과 정책 의존 외부 작업의 경계가 모호하지 않은지

### R8 확인

- 정책 종류·플랫폼별 freshness 기준과 `freshness_valid_until` 계산 방식. `ABSENT_CONFIRMED` 부재 확인도 언제 만료시킬지 포함
- 만료 검사 주기, 재수집 retry·timeout·비용 한도와 평가 지표
- 실행 중 정책 generation이 바뀌었을 때 stale 결과를 측정하는 기준

## Compatibility

`RunPolicyState`, `PolicyParserResult.llm_invocation_ref`, `SandboxPolicyDecision`의 정책 provenance, `POLICY_PARSER` 역할, `ReportDraft.run_policy_state_ref`와 `AnalysisRunResult.run_policy_state_ref`는 새 필수 계약입니다. 새 MAJOR schema에서 시작하며 과거 record에 현재 정책 pointer나 LLM 호출 reference를 추정해 채우지 않습니다.

## Merge order

1. 이 R4 공통 계약 PR을 R5-02·R7·R8이 확인합니다.
2. R5-02와 R8이 정책 의미·최신성 세부 기준을 반영합니다.
3. R3가 Policy Parser prompt/provider 실행을 구현 설계에 연결합니다.
4. R7이 Sandbox 입력·로그·강제 경계를 반영합니다.
5. R6가 동적 요청과 policy state 연결을 확인하고 R1·R2가 정책을 가설 사전 필터나 StaticFactBundle로 사용하지 않는지 확인합니다.
6. R4가 정본·Wiki·검증 시나리오를 최종 교차 검토합니다.
