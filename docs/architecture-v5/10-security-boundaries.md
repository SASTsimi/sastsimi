# 10. 보안 경계

- **이 문서는 무엇을 설명하나요?** 저장소, LLM, 비밀정보, Docker와 공식 정책을 안전하게 다루는 규칙을 설명합니다.
- **누가 읽어야 하나요?** 모든 역할 담당자와 보안 검토자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 무엇을 믿지 않아야 하는지, 프로그램이 강제할 제한과 남는 위험을 확인합니다.

`sandbox`는 다른 시스템과 격리된 실행 환경이고 `redaction`은 로그·보고서의 비밀정보를 가리는 처리입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 신뢰 실행 경계

LLM Agent는 분석·검토 결과와 다음 action을 제안하지만 enforcement authority를 갖지 않는다. 신뢰 경계 안의 비-LLM Runtime Validator가 identity·schema·reference·state·budget·provider/session·Gate/Reporter 전제를 강제한다. R7 Sandbox Controller는 host·Docker daemon·mount·namespace·secret·network egress·R8 resource profile·lifecycle의 외부 경계를 전담한다. Reproduction Agent는 이 경계 안에서 command·파일·환경·PoC와 재시도를 자율적으로 선택한다. 저장소 내용과 모든 LLM 출력은 외부 경계를 바꾸는 policy 명령으로 해석하지 않는다.

## 방향

v5는 계약·정책·무결성 artifact를 아키텍처의 중심으로 확대하지 않는다. 그러나 비신뢰 저장소, LLM provider, 공식 프로그램 정책과 동적 실행을 다루므로 아래 실행 경계는 필수다.

## 1. 로컬 작업공간과 코드 조회

- 모든 사실·가설·문맥·PoC는 동일한 `workspace_id`와 연결된 `commit_id`에 연결한다.
- `Repository Loader`는 실행별 폴더에 clone하고 지정한 commit을 checkout한 뒤 HEAD를 확인한다.
- 분석 중 HEAD나 추적 파일이 바뀌면 `WORKSPACE_CHANGED`로 중단하고 기존 결과에 섞지 않는다.
- retrieval은 `workspace_root` 안의 허용 파일만 읽고 path traversal·symlink escape를 차단한다.
- `CodeLocation.file_path`는 `/` 구분자의 Git 상대 경로로 정규화하며 절대 경로, drive prefix와 `.`·`..` segment를 거절한다. symlink를 해석한 실제 대상도 `workspace_root` 안이어야 한다.
- 도구별 line·column 표현은 정본 `CodeLocation` 규칙으로 변환하고 원래 위치와 tool message는 원본 결과 reference에 보존한다.
- depth/token/request budget과 반환 location을 기록한다.
- 누락·truncation은 안전함 또는 `FALSE`로 해석하지 않는다.
- 지원하지 않는 schema MAJOR는 `SCHEMA_UNSUPPORTED`로 거절한다. 같은 `logical_record_id`가 아니거나 바로 이전 revision과 이어지지 않는 수정본은 `RECORD_REVISION_MISMATCH`로 거절하고 자동 변환·병합하지 않는다. `RunMeta`의 workspace·commit은 `null`에서 실제 값으로만 바인딩할 수 있고, 코드 근거 `RecordMeta`에서는 두 값이 필수·불변이다.
- 저장된 record를 가리키는 `StoredDataRef.record_id`는 참조 대상 revision의 workspace·commit·내용 hash와 일치해야 하고, 가설별 대상 record의 `RecordMeta.hypothesis_id`도 현재 가설과 같아야 한다. Technical Gate가 검토한 Verification revision이나 Rule Scope Gate가 검토한 Verification·Technical·정책 revision이 바뀌면 이전 Gate 결과를 재사용하지 않는다.

## 1.1 상태·동시성·복구 경계

- runtime은 `dedupe_key`가 같은 요청을 새 작업으로 중복 등록하지 않고 기존 `work_id`를 반환한다.
- 한 `work_id`에는 활성 `attempt_id`를 하나만 허용하고 상태 변경은 `state_version` compare-and-set을 통과해야 한다.
- worker가 제출한 결과는 `attempt_id`, 예상 state version, `input_hash`, workspace·commit·hypothesis와 record hash가 모두 현재 작업과 같을 때만 반영한다.
- `TransitionCommit.state=COMMITTED`가 아닌 output은 Agent, Gate, Reporter와 최종 결과 조립기가 읽지 못한다.
- `PREPARED` journal, output pointer가 없는 종료 상태와 존재하지 않는 output을 가리키는 상태는 `TRANSITION_INCOMPLETE`로 차단한다.
- 같은 work의 다음 version에 `PREPARED` 또는 pointer에 아직 투영하지 못한 `COMMITTED` marker가 있으면 이를 복구·중단 처리하기 전까지 취소·retry를 포함한 새 전이를 차단한다.
- 이전 attempt, 이미 취소된 작업, 변경된 입력과 오래된 revision의 결과는 `ATTEMPT_NOT_ACTIVE` 또는 `STALE_RESULT`로 격리한다.
- 전체 또는 개별 가설 취소 뒤에는 새 downstream work를 만들지 않는다. 늦은 성공 결과도 취소를 되돌리지 않는다.
- 복구 runtime은 마지막 `COMMITTED` marker와 거기서 투영된 pointer만 신뢰하고 자동 복구의 안전성을 증명할 수 없으면 `RECOVERY_FAILED`로 중단한다.
- retry 성공은 이전 실패·중단·failover 기록을 삭제하지 않는다. 최종 상태와 전문 결과를 한 값으로 합치지 않는다.

## 1.2 action 권한과 일회성 실행

- Agent·service의 자연어 출력이나 tool call 제안은 실행 권한이 아니다. 부작용 action은 `ActionRequest`로 정규화한다.
- 비-LLM Runtime Validator는 action type별 필수 check를 수행한다. `RUN_SANDBOX`에서는 exact plan·requirements·profile reference와 실행 전제만 확인하며 Agent command·payload·package 의미를 검사하지 않는다. Sandbox Controller는 외부 안전 경계를 한 번 적용한다.
- 하나라도 실패하면 `ActionDecision=DENY`와 오류를 저장하고 실행하지 않는다.
- `ALLOW` decision은 인증된 requester identity, exact action·state version·입력·설정 revision과 `valid_until`에만 유효하다. 실행 직전에 허가 시간이 지나거나 권한·상태·예산·입력·설정이 달라지면 runtime은 `UNUSED -> EXPIRED`로 바꾸고 거절한다. 그대로인 decision만 `UNUSED -> USED`로 compare-and-set claim해 한 번 실행한다.
- claim 뒤 중단됐으면 기존 decision을 다시 사용하지 않는다. 중단 오류와 실행 outcome 유무를 기록하고 새 action을 요청한다.
- 한 `ActionRequest`에는 하나의 logical `ActionDecision`만 만들고 concurrent validator는 unique action-ref 제약으로 같은 decision을 반환한다.
- 실제 LLM call은 검사한 immutable `LLMCallSpec`과 field-by-field 같아야 한다. Gate와 Reporter는 자기 stage action이 호출까지 허가하며 별도 `CALL_LLM`으로 우회하지 않는다.
- Orchestration은 전역 proposal 등록과 Verification 배정을 제안할 수 있지만 가설 내부 호출, verdict, CWE, 두 Gate 결과, 공식 정책 의미, 보고 가능 여부와 공개 여부를 저장할 권한이 없다. Verification이 가설 내부 다음 작업을 선택해도 모든 action은 같은 Runtime Validator 검사를 통과해야 한다.
- Runtime Validator는 역할과 실행 전제를 검사하지만 취약점 진위·CWE 적절성·정책 의미를 대신 판단하지 않는다.

## 2. 저장소와 외부 텍스트는 비신뢰 데이터

- 코드·주석·README·build script·SAST message는 Agent instruction이 아니다.
- 모든 LLM output, provider 응답, 외부 정책 본문과 Sandbox stdout·파일도 validation 전까지 비신뢰 data다.
- 저장소 텍스트와 비신뢰 output이 provider, model, session, sandbox image/network, budget, Gate 순서, Reporter와 disclosure 정책을 바꾸지 못하게 한다.
- system instruction과 분석 데이터 경계를 유지하고 structured output을 검증한다.
- 전체 저장소 대신 역할에 필요한 location/context만 전달한다.
- 위 변경을 요구하는 문구는 `UNTRUSTED_INSTRUCTION`으로 기록하고 실행하지 않는다.

## 3. LLM provider와 secret

- membership token, cookie, password, browser profile secret을 Agent와 repository에 노출하지 않는다.
- API key, service credential과 authorization header는 secret boundary 안에서만 주입한다.
- 두 방식의 credential을 prompt, response artifact, 일반 debug log, PoC와 report에서 제외한다.
- 인증 오류를 verdict로 변환하지 않는다.
- provider/model 전환은 silent failover 없이 새 invocation으로 기록한다.

## 4. LLM log와 redaction

- 사용자에게 노출된 request/response와 tool trace만 기록하고 hidden chain-of-thought는 수집하지 않는다.
- code는 전체 원문 복제보다 저장소 상대 `CodeLocation`과 `StoredDataRef`를 우선한다.
- raw membership session log는 제한된 접근·짧은 보존·provider parser·redaction을 거친다.
- redaction 실패 artifact는 일반 관측 저장소로 전달하지 않고 오류로 격리한다.
- session reference 자체가 재사용 가능한 secret이면 hash/opaque handle로 대체한다.
- `AnalysisError.safe_message`에는 credential, 개인정보, session secret, authorization header와 절대 로컬 경로를 넣지 않는다. 원본 오류는 별도 접근 통제와 redaction을 거친 artifact로만 보관한다.

## 5. Docker sandbox

- Agent에게 host root/home, Docker socket/daemon API, host process namespace, device, production secret와 다른 workspace를 제공하지 않는다.
- trusted R7 Controller가 exact plan·requirements·profile로 Docker image와 격리 lifecycle을 만들고 R8의 CPU·memory·disk·PID·wall-clock 값을 적용한다.
- Sandbox 내부 filesystem·process·service에는 재현을 위한 shell·파일·package·계정·fixture·mock·PoC 활동을 넓게 허용한다. 개별 command allowlist나 실행 직전 payload 검사를 두지 않는다.
- 외부 network egress는 profile 경계 밖으로 나갈 수 없다. package download는 versioned baseline image build 단계에서 수행하고 runtime Agent의 임의 설치 상태를 최종 baseline으로 숨기지 않는다.
- 실제 외부 통신이 취약점 재현에 본질적이면 versioned target/port/protocol 범위와 mock 대체 가능성을 별도로 검토한다. host gateway·cloud metadata·사설망·범위 밖 실제 target은 차단한다.
- Toolbox Image와 저장소별 `EnvironmentRecipe`를 사용한다. package가 없으면 Agent Log에 실패를 기록하고 Dockerfile·manifest·setup을 수정해 새 recipe revision과 image digest를 만든 뒤 격리 실행을 다시 시작한다.
- 성공한 baseline image/recipe는 `PERSISTENT_BASELINE`으로 보존한다. 개별 session의 container·network·volume·tmp·임시 build는 `SESSION_EPHEMERAL`이며 성공·실패·차단·취소와 관계없이 cleanup한다.
- 가설마다 반드시 새 container를 만들지는 PL 결정 후 확정한다. 어떤 lifecycle이든 서로 다른 가설·attempt의 writable state와 secret이 섞이면 안 된다.
- Agent 행동은 command·file/environment change·image build·PoC create/update/execute·observation·retry·cleanup event를 `AgentLog`에 append-only로 남기고 종료 시 immutable artifact로 확정한다. 숨은 사고 과정은 저장하지 않는다.
- `poc_ref`는 실제 실행을 시작한 final PoC Bundle만 가리킨다. 실행하지 않은 draft는 Agent Log에 남길 수 있지만 결과의 PoC로 전달하지 않는다.
- credential·cookie·token·password 원문은 requirements, recipe, environment, Agent Log와 PoC에 저장하지 않고 허용된 secret handle만 연결한다.

## 6. 프로그램 정책 신뢰 경계

- Rule Scope Impact Gate는 확인 가능한 공식 source만 `ProgramPolicyRecord`로 사용한다.
- 저장소 문서, 검색 snippet, 오래된 모델 지식과 비공식 요약을 공식 rule로 승격하지 않는다.
- source URL/reference, 수집 시각, 누락과 freshness warning을 보존한다.
- 공식 자료가 없거나 `ProgramPolicyRecord.freshness_status=STALE | UNVERIFIED`이면 `UNCERTAIN + DENY`다. 오래된 record는 감사용으로 보존할 수 있지만 `PASS | ALLOW` 근거로 사용하지 않는다.
- 정책 수집기가 향후 추가되면 외부 fetch, parser, provenance와 변경 탐지에 별도 보안 검토가 필요하다.

## 7. 근거·권한 연결

다음 연결을 보존한다.

- tool observation → 현재 `workspace_id`의 `CodeLocation`
- hypothesis claim → observed fact/assumption과 `question_id`가 있는 falsification
- retrieved context → request와 실제 location
- `FALSE` verdict → `DISPROVED` falsification question과 실제 evidence
- verdict → Pro/Con/dynamic evidence와 restriction
- HOLD REQUIRED Primitive → exact final HOLD Verification revision
- TRUE PROVIDED Primitive → exact final TRUE + Technical ACCEPT + Rule Scope 정상 통과 revision
- Chaining candidate → ACTIVE Primitive refs, match kind와 아직 검증되지 않은 상태
- CWE → 정확한 `CWELabel` revision, evidence와 uncertainty
- Technical review → 정확한 Verification·CWELabel revision
- Rule/Scope review → 정확한 Verification·Technical review·CWELabel과 `ProgramPolicyRecord` revision
- report claim → current Finding, 통과한 result, 두 Gate와 두 Gate가 공통으로 검토한 CWELabel revision

Verification, Chaining, Gate와 Reporter는 제출·공개 권한이 없다. `ReportDraft`는 마지막 Agent 산출물이다.

Reporter는 current Finding·Verification·CWE·두 Gate·정책의 exact revision을 사용하고 restriction, limitation, unresolved condition을 보존해야 한다. `CREATE_REPORT_DRAFT`의 redaction 검사가 실패하면 초안을 저장하지 않는다. 선행 revision이 바뀌면 기존 draft는 감사 이력으로만 남고 current `AnalysisRunResult.report_draft_refs`에 넣지 않는다.

Reporter work와 `ReportDraft`가 확정되면 신뢰 runtime이 `AnalysisRunResult`와 최종 실행 상태를 저장하고 Agent 자동화를 종료한다. Finding이 없으면 `REPORT_NOT_READY`로 Reporter를 호출하지 않는다. 이후 사람의 검토·수정·제출·공개에는 Agent action, 자동 상태 전이 또는 자동 권한을 제공하지 않는다.

## 위협과 최소 대응

| 위협 | 대응 |
|---|---|
| repository prompt injection | instruction/data 분리, 최소 context, output validation |
| SAST hit 자동 승격 | fact-only 정규화, Verification |
| 저비용 모델의 과도한 확정 | fixed hypothesis schema, 금지 assertion, `INVALID_OUTPUT` |
| LLM 확증 편향 | 운영상 항상 실행하는 독립 Pro/Con, 역할 간 NEW session, 두 Gate |
| session contamination | `NEW/RESUME/AUTO` policy와 결정 logging |
| 잘못된 path 연결 | location retrieval와 Technical Gate linkage 검토 |
| Verification/Chaining 후보의 오승격 | origin을 구분한 새 hypothesis로 전체 재검증 |
| Gate 전 TRUE의 체이닝 오염 | 두 Gate 정상 통과 전 PROVIDED admission 금지 |
| 오래된 Gate 승인 재사용 | exact Verification revision binding과 이전 Primitive `SUPERSEDED` |
| Chaining Agent의 일반 research 확장 | ChainingResult schema와 result-owner validation으로 matching 외 출력 거절 |
| chain 폭증 | depth/count/token/time/duplicate/cycle 제한 |
| 같은 작업의 중복 반영 | canonical `dedupe_key`, 한 active attempt, state version compare-and-set |
| 취소·retry 뒤 늦은 결과 오염 | active attempt/input hash 검사와 `STALE_RESULT` 격리 |
| 결과와 상태 일부 저장 | atomic transaction 또는 `TransitionCommit` journal, uncommitted output 차단 |
| crash 뒤 이중 실행 | 마지막 committed transition 재사용과 attempt 이력 보존 |
| 위험한 PoC | sandbox default-deny와 resource limit |
| credential·코드 유출 | adapter secret boundary, 최소 context, redaction |
| 정책 환각 | 공식 `ProgramPolicyRecord`가 없으면 `UNCERTAIN + DENY` |
| 오래되거나 최신성을 확인하지 못한 정책으로 보고 허용 | `freshness_status=STALE | UNVERIFIED`이면 `UNCERTAIN + DENY`, `PASS | ALLOW` 거절 |
| Finding이 없거나 오래된 ReportDraft가 current 결과에 포함됨 | Reporter 입력의 exact current dependency 재검사, `REPORT_NOT_READY` 또는 `STALE_RESULT` |
| Agent가 검토·제출·공개를 계속 자동화 | ReportDraft와 AnalysisRunResult 확정 뒤 Agent action이 없는 종료 경계 |
| 역할 위조, ALLOW replay 또는 stale 허가 사용 | trusted requester identity와 exact action·state·input·config·`valid_until` binding, stale이면 `UNUSED -> EXPIRED`, 유효하면 `UNUSED -> USED` 일회성 claim |
| 권한 없는 domain 결과 저장 | 역할별 `SAVE_RESULT` authority와 선행 exact ref 검사 |

## 상태·복구 부정 시나리오

| 입력·사건 | runtime이 반드시 확인할 것 | 기대 차단·복구 결과 |
|---|---|---|
| 같은 가설 검증 요청이 동시에 두 번 도착 | `dedupe_key`, 기존 `work_id` | 기존 작업 반환, 결과 한 번만 반영 |
| retry 전 attempt 결과가 새 attempt보다 늦게 도착 | `active_attempt_id`, `state_version` | `ATTEMPT_NOT_ACTIVE`, 최신 pointer 연결 금지 |
| 다른 `workspace_id` 또는 `commit_id` 결과가 합류 | work input과 result meta | `WORKSPACE_MISMATCH`, 결과 사용 금지 |
| 가설·분석 취소 뒤 결과가 도착 | work와 analysis 취소 상태 | `STALE_RESULT`, downstream 미호출 |
| Technical 보완 전 revision이 Rule Scope Gate나 Reporter로 전달 | exact Verification·CWE·Gate `record_id` | `RECORD_REVISION_MISMATCH`, 뒤 단계 차단 |
| 결과 record만 저장되고 종료 상태가 갱신되지 않음 | `TransitionCommit`, state pointer | journal 복구 또는 `TRANSITION_INCOMPLETE` |
| 종료 상태만 있고 output record가 없음 | pointer 대상 존재·hash | `TRANSITION_INCOMPLETE`, 다음 단계 차단 |
| 허용되지 않은 provider/model failover | 바로 앞 호출 status와 fallback profile | `INVOCATION_CHAIN_INVALID`, 결과 사용 금지 |
| crash 뒤 같은 요청이 다시 들어옴 | 마지막 `COMMITTED`, `dedupe_key` | 완료 결과 재사용 또는 허용된 새 attempt, 중복 반영 금지 |
| retry·Gate `REVISE`·chaining이 한도를 넘음 | 횟수·token·시간·cycle·duplicate budget | 중단 이유 저장, Reporter 차단, verdict 자동 변경 금지 |
| `PARTIAL` 결과에 누락 설명이 없음 | static/context의 `gap_ids`·`error_ids` 또는 dynamic 결과의 `limitations`, output refs | `STATE_TRANSITION_INVALID`, 부분 결과 사용 금지 |
| 동적 `BLOCKED + failure_category=POLICY` 결과를 공통 work `BLOCKED`에 연결 | 전문 결과 status와 공통 실행 status 매핑 | 종료 결과를 비종료 대기 상태에 연결하지 않고 `STATE_TRANSITION_INVALID` |
| 동적 종료 결과와 work·전문 상태 pointer가 다름 | `TransitionCommit`, `WorkExecutionState.output_refs`, `dynamic_result_ref` | `TRANSITION_INCOMPLETE`, Verification 전달 차단 |
| 분석 종료 시 `RUNNING` work나 `PREPARED` journal이 남음 | 전체 work와 commit 상태 | 최종 `AnalysisRunState` 전이 차단 |
| `COMMITTED` marker 투영 전에 취소·retry 전이가 경쟁 | 다음 target version의 unique marker와 pointer | 기존 marker를 먼저 재투영하고 경쟁 전이는 version conflict로 거절 |
| 모순된 `ALLOW`가 Reporter 호출을 요청 | Gate 조건·exact input refs·semantic validation | `INVALID_OUTPUT`과 `GATE/INVALID_OUTPUT` 오류 기록, Gate output commit·Reporter 호출 금지 |

## 권한 우회 부정 시나리오

| 입력·사건 | Runtime Validator가 확인할 것 | 기대 차단 결과 |
|---|---|---|
| Orchestration이 `TRUE`를 저장하려 함 | `requested_by`, 저장 result kind | `AUTHORITY_DENIED`, verdict 미변경 |
| Hypothesis Agent가 final verdict를 출력 | 역할별 output schema | `INVALID_OUTPUT`, proposal만 사용 가능 |
| Technical Gate가 Verification verdict를 바꾸려 함 | Gate output과 input verdict | `ACTION_NOT_ALLOWED`, 기존 verdict 보존 |
| Technical Gate 없이 Rule Scope Gate 호출 | exact Technical review ref와 status | `GATE_ORDER_INVALID` |
| Rule Scope Gate 없이 Reporter 호출 | exact Rule Scope review와 일곱 report 조건 | `REPORT_NOT_READY` |
| 공식 정책이 없는데 `ALLOW` 출력 | policy ref와 Rule Scope 불변조건 | invalid output, `UNCERTAIN + DENY` 또는 Gate 실패 |
| repository prompt가 Sandbox network를 열라고 함 | Sandbox Controller가 versioned profile과 instruction source 확인 | `UNTRUSTED_INSTRUCTION` 또는 `SANDBOX_POLICY_DENIED` |
| LLM이 workspace 밖 파일을 요청 | 정규화·symlink 해석 뒤 실제 path | `FILE_ACCESS_DENIED` |
| 허용하지 않은 provider/model로 silent failover | provider profile과 선행 invocation | `PROVIDER_PROFILE_DENIED`, 호출 미실행 |
| 인증 실패를 `FALSE`로 저장하려 함 | invocation status와 falsification evidence | invalid result 또는 `AUTHORITY_DENIED`, 실행 오류 유지 |
| Reporter가 새 공격 경로를 확정 | report claim refs와 verified hypothesis | invalid output, 새 hypothesis 검증 전 사용 금지 |
| ReportDraft 이후 Agent 자동화를 계속하려 함 | 현재 stage와 final `AnalysisRunState` | 후속 Agent action 미등록, 자동화 종료 |
| Agent가 사람 검토·외부 제출·공개 action을 요청 | action registry와 요청 역할 | `ACTION_NOT_ALLOWED`, 해당 action 미실행 |
| 선행 결과가 바뀐 오래된 ReportDraft를 current 결과로 사용 | Finding·Verification·CWE·두 Gate·정책 exact revision | `STALE_RESULT`, 새 Gate·Reporter work 요구 |
| restriction·limitation 또는 redaction 상태가 빠진 초안을 저장 | ReportDraft 필수 필드와 `CREATE_REPORT_DRAFT` 검사 결과 | `SAVE_RESULT` 거절, 누락을 보존한 새 초안 요구 |
| 같은 ActionRequest를 동시에 두 번 검사 | unique `action_ref.record_id -> decision_id` | 기존 decision 반환, action 한 번만 claim |
| Gate 또는 Reporter가 별도 CALL_LLM으로 우회 | requester 역할과 stage action·call spec | `ACTION_NOT_ALLOWED`, stage action부터 새로 요청 |
| Technical Gate `REVISE` 뒤 같은 입력으로 재투표 | Verification·CWE `record_id`와 domain input hash, 이전 decision 사용 상태 | `ACTION_NOT_ALLOWED`, 보완된 upstream revision으로 새 work·action 요구 |
| action 허가 뒤 Gate 입력 revision이 바뀜 | provider 호출 직전 exact refs·current state 재검사 | `UNUSED -> EXPIRED`, 호출 금지와 새 action 요구 |
| Runtime Validator가 공식 정책 의미를 다시 판단 | Rule Scope output의 생산 역할과 validator 검사 범위 | 정책 해석 금지, Gate의 `UNCERTAIN + DENY` 구조만 확인하고 Reporter 차단 |
| Pro와 Con이 같은 session 또는 parent를 공유 | 역할별 `SESSION`, `NEW`, `parent_session_ref=null`, 서로 다른 call/session ID | `ACTION_NOT_ALLOWED` 또는 `INVOCATION_CHAIN_INVALID`, 두 호출 모두 독립 action으로 다시 요청 |
| Pro 또는 Con prompt·context·조회·tool 결과에 상대 역할 output을 넣음 | trusted prompt payload, context refs, predecessor/parent, result-store query와 tool trace | `CROSS_ROLE_INPUT_DENIED`, 호출·결과 저장·합류 금지 |
| final Verification에 Pro 또는 Con exact result reference가 빠짐 | mode별 `debate_input_hash`, `pro_evidence_ref`, `con_evidence_ref` 조합 | `SAVE_RESULT` 거절, 부모 Verification 대기 또는 실패 처리 |
| Pro·Con 결과의 부모·generation·공통 입력 hash가 서로 다름 | 두 `EvidenceAgentResult`와 current parent Verification exact 비교 | `STALE_RESULT`, 두 결과를 섞지 않고 current 입력으로 다시 실행 |
| 입력이 바뀌었는데 이전에 성공한 Pro 또는 Con 결과를 재사용 | 가설·Context·코드·playbook·Debate·budget revision과 `debate_input_hash` | `STALE_RESULT`, 두 역할 모두 새 child work 또는 current generation 실행 요구 |
| Pro/Con child가 `BLOCKED`인데 부모 Verification은 `RUNNING`으로 계속됨 | `parent_work_ref`, child와 parent state, `waiting_for` | 상태 변경 거절, 부모도 같은 실제 이유로 `BLOCKED`와 가설 `VERIFYING` 강제 |
| Pro/Con child가 최종 실패했는데 부모나 가설을 계속 진행 | child·parent의 committed transition과 `HypothesisProcessState` | 자식 실패를 먼저 확정해 부모 진행 차단, 이어 부모와 가설 `FAILED`를 함께 확정; final result·Gate 금지 |
| `SAVE_RESULT` 검사 뒤 candidate bytes를 바꿈 | `candidate_result_ref.stored_data_id`와 `content_hash`, current attempt·state | decision `EXPIRED` 또는 save `DENY`, 변조 후보 미저장 |
| 실행 오류만 든 `FALSE` 후보를 저장 | `result_kind`, VERIFICATION 생산자, named `DISPROVED`의 `question_id`·`evidence_refs` | `SAVE_RESULT` 거절, 오류 상태 유지와 verdict 자동 생성 금지 |
| 다른 역할이 만든 결과 후보를 저장 | result-owner registry와 `requested_by`, candidate meta | `AUTHORITY_DENIED`, candidate 격리와 최신 pointer 미연결 |
| `RUN_SANDBOX` 허가 뒤 plan·requirements·profile revision이 바뀜 | 실행 직전 action refs와 current state | 기존 decision `UNUSED -> EXPIRED`, 새 action 요구 |
| Agent가 Sandbox 내부에서 plan에 없는 command·payload를 실행 | 외부 경계와 Agent Log | 허용; 실제 event와 artifact를 기록하고 host·network·resource 경계만 강제 |
| Agent가 Docker socket·host path·profile 밖 egress를 요청 | Controller boundary와 실제 option | `SANDBOX_POLICY_DENIED`, Agent 미호출 또는 해당 외부 action 차단 |
| 동적 결과의 recipe·environment·Agent Log·PoC digest가 서로 다름 | 같은 plan·attempt의 exact refs와 hashes | `SAVE_RESULT` 거절, Verification 전달 금지 |
| Verification이 `DynamicReproductionResult`를 직접 저장 | result-owner와 `requested_by` | `AUTHORITY_DENIED`, REPRODUCTION_AGENT 후보만 허용 |
| Agent를 호출했는데 Agent Log가 없거나 반대 조합 | `agent_invoked`와 `agent_log_ref` | `SAVE_RESULT`의 `SCHEMA` 검사 거절, 가설 판정 변경 금지 |
| 정책 차단 결과에 Controller 판정 reference가 없음 | `failure_category=POLICY`와 `policy_decision_ref` | `SAVE_RESULT` 거절, Technical Gate 결과로 대신 채우기 금지 |
| 실제 환경 생성 여부와 `environment_ref`가 다름 | `environment_created`와 exact `sandbox_environment` record | `SAVE_RESULT` 거절, 계획용 환경 설정으로 대체 금지 |
| ReproductionPlan에 `environment_requirements_ref`가 없음 | 새 MAJOR schema와 plan closure | `SAVE_RESULT` 또는 `RUN_SANDBOX` 거절, R6가 current 요구사항을 연결한 새 plan 생성 |
| R7이 EnvironmentRequirements를 만들거나 수정함 | result-owner registry와 candidate producer | `AUTHORITY_DENIED`, 변경 후보 격리 |
| plan과 실제 환경이 다른 requirements revision을 가리킴 | `plan.environment_requirements_ref`와 `sandbox_environment.requirements_ref` exact 비교 | `RECORD_REVISION_MISMATCH`, 동적 결과 저장·Verification 전달 금지 |
| 환경 문제를 고치며 recipe revision을 바꿨지만 결과가 이전 image를 가리킴 | recipe parent·digest, environment와 Agent Log | `RECORD_REVISION_MISMATCH`, 실행 artifact 격리 |
| 오래된 EnvironmentRequirements revision을 재사용함 | logical record current head와 RUN_SANDBOX input ref | `STALE_RESULT`, current requirements와 이를 가리키는 새 plan·action 요구 |
| 환경 구성 실패나 차이를 `DISPROVED | FALSE`로 변환함 | `failure_category=ENVIRONMENT`, outcome과 Verification falsification evidence | 결과 또는 Verification 저장 거절, `INCONCLUSIVE` 유지 |
| 환경 요구사항·실제 값에 credential·token 원문을 저장함 | schema secret scan과 `secret_ref` data kind | `REDACTION` 실패, candidate 미저장 |
| 정리 대상이 생겼는데 `NOT_REQUIRED`로 기록 | `cleanup_required`, Agent/Cleanup Log와 status | `SAVE_RESULT` 거절, 남은 자원 격리와 운영 오류 기록 |
| baseline image를 session ephemeral로 삭제하거나 임시 자원을 baseline으로 보존 | CleanupEntry lifecycle과 recipe provenance | 결과 저장 거절 또는 운영 오류, 잘못 보존한 image 격리 |
| 실행하지 않은 PoC draft를 최종 `poc_ref`로 연결 | PoCBundle digest와 `POC_EXECUTE` Agent event | `SAVE_RESULT` 또는 Gate 검토 거절 |

## Verification ownership과 Chaining admission 시나리오

| ID | 입력·사건 | 기대 결과 |
|---|---|---|
| N1 | final HOLD | 두 Gate 없이 REQUIRED Primitive 저장과 Chaining 조회 허용 |
| N2 | final FALSE | terminal internal result; Primitive와 Chaining work 생성 금지 |
| N3 | final TRUE, Gate 미실행 | PROVIDED admission과 Chaining 금지 |
| N4 | TRUE + Technical `ACCEPT`, Rule Scope 미실행 | PROVIDED admission과 Chaining 금지 |
| N5 | TRUE + Technical `ACCEPT` + Rule Scope `FAIL | UNCERTAIN | DENY` | PROVIDED admission과 Chaining 금지 |
| N6 | TRUE + Technical `ACCEPT` + Rule Scope `PASS/PASS/PASS/SUFFICIENT/ALLOW` | exact revision PROVIDED admission과 Chaining 허용 |
| N7 | Gate-qualified TRUE PROVIDED + HOLD REQUIRED | TRUE_HOLD match가 있으면 `origin=CHAINING` proposal을 새로 등록·검증 |
| N8 | 서로 다른 Gate-qualified TRUE PROVIDED 둘 | 앞 PROVIDED가 뒤 PROVIDED의 exact Verification에서 복사한 `required_preconditions` 한 항목을 충족하고 양쪽 parent revision이 유효할 때만 TRUE_TRUE proposal 허용 |
| N9 | TRUE_TRUE 입력 중 한 부모가 Gate 전 또는 비정상 Gate 결과 | match 저장과 proposal 등록 거절 |
| N10 | Verification N은 Gate-qualified지만 N+1이 새로 생성됨 | N 기록은 보존하되 current Primitive는 `SUPERSEDED`; N+1은 두 Gate 전까지 자격 없음 |
| N10-A | Chaining이 N의 ACTIVE Primitive를 읽은 뒤 commit 전에 새 Verification generation/index revision 생성 | commit-time index CAS에서 `STALE_RESULT`; ChainingResult와 child proposal 등록 금지 |
| N11 | Verification이 새 endpoint·sink·권한 경계를 발견 | Chaining을 거치지 않고 `HypothesisProposal(origin=VERIFICATION)`로 전역 등록 후 새 Verification |
| N12 | chained child가 FALSE | 두 parent의 기존 verdict와 Gate record 불변 |
| N13 | Verification이 budget·Sandbox·Gate 순서를 우회하려 함 | Runtime Validator가 budget·Gate·호출 권한을, Sandbox Controller가 세부 Sandbox 정책을 `DENY`; hypothesis-local ownership은 enforcement 권한이 아님 |
| N13-A | 같은 역할이지만 배정되지 않은 Verification identity가 Gate·Reporter·새 verification work를 요청 | ACTIVE `VerificationAssignment.owner_identity_ref` 불일치로 `AUTHORITY_DENIED` |
| N14 | Chaining Agent가 Primitive match 없는 bypass·impact·dynamic 요청을 출력 | schema/result-owner validation에서 invalid로 거절 |
| N15 | `purpose=PRODUCTION`인데 `verification_mode=BASIC | CONDITIONAL_DEBATE`를 요청 | Runtime Validator가 `ACTION_NOT_ALLOWED`; 운영 결과·Gate·Primitive·Reporter 생성 금지 |
| N16 | 운영 Pro/Con 중 하나를 실행할 예산이 부족 | `BUDGET_EXCEEDED`로 Verification work 중단; skip·BASIC fallback·final verdict 생성 금지 |
| N17 | Context 조회 실패·timeout·권한 오류만으로 `HOLD`를 저장하려 함 | 오류는 `AnalysisError`, 확인하지 못한 범위는 `DataGap`으로 기록; verdict evidence가 없으므로 `SAVE_RESULT` 거절 |
| N18 | 일부 Context 조회는 실패했지만 대체 조회·다른 정상 근거와 운영 Pro/Con으로 필수 검증을 완료 | 오류·gap을 보존하고 실제 근거에 따라 `TRUE | FALSE | HOLD` 저장 허용 |
| N19 | 필수 Context 또는 운영 Pro/Con을 확보하지 못했는데 final `VerificationResult`를 저장하려 함 | final 저장 거절; retry 가능이면 work `BLOCKED`, 허용된 재시도 소진·복구 불가이면 `FAILED` |
| N20 | 가설의 검증 항목이 결과에서 빠지거나 중복되거나 `INCOMPLETE`인데 final `VerificationResult`를 저장하려 함 | `validation_id` 집합과 완료·근거 조건 불일치로 저장 거절; retry 가능이면 work `BLOCKED`, 아니면 가설까지 `FAILED` |
| N21 | Verification work만 `FAILED`로 끝내고 가설을 계속 `VERIFYING`으로 두거나, 실패 가설에 과거 final result를 연결하려 함 | 같은 atomic transition에서 `HypothesisProcessState.status=FAILED`, exact failed work ref, `verification_result_ref=null` 강제; 불일치 상태는 분석 종료 차단 |
| N22 | 운영 final Verification에 Pro 또는 Con result reference가 하나만 있거나 둘 다 없음 | `SAVE_RESULT` 거절; exact 두 결과를 모으기 전 verdict·Gate 생성 금지 |
| N23 | 서로 다른 부모·generation·`debate_input_hash`의 Pro·Con 결과를 합침 | `STALE_RESULT`; current 입력으로 두 역할을 다시 실행 |
| N24 | Pro가 Con output을, Con이 Pro output을 prompt·context·조회·tool 경로로 읽음 | `CROSS_ROLE_INPUT_DENIED`; 해당 호출과 결과를 합류에 사용하지 않음 |
| N25 | 한 child가 retry 가능한 `BLOCKED`인데 부모 Verification이 계속 실행됨 | 부모도 같은 `waiting_for`로 `BLOCKED`, 가설은 `VERIFYING`; final 결과 없음 |
| N26 | 한 child가 복구 불가능하게 실패했는데 부모·가설이 종료되지 않음 | 자식 `FAILED` commit이 부모 진행을 막고 recovery가 부모·가설 `FAILED` 확정을 완료; `verification_result_ref=null` |

## 남는 위험

LLM 오판, static coverage gap, 실제 환경과 sandbox의 차이, provider 기능·약관 변경, policy freshness와 redaction 누락 가능성은 남는다. 따라서 두 Gate를 안전 보증으로 설명하지 않고 원문 근거·오류·제한·미확인 후보를 사람에게 함께 제공한다.
