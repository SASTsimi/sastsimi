# 04. 검증과 동적 재현

- **이 문서는 무엇을 설명하나요?** 취약점 가설의 찬성·반대 근거를 확인하고 필요하면 Docker에서 재현하는 절차를 설명합니다.
- **누가 읽어야 하나요?** 검증·반박·플레이북과 동적검증·Sandbox 담당자가 우선 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** `TRUE / FALSE / HOLD` 판정 기준, 추가 근거 요청과 재현 범위를 확인합니다.

`Verification`은 가설을 근거로 확인하는 과정이고 `verdict`는 그 기술 판정입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## Verification의 목적과 제어권

Verification Agent는 배정받은 한 가설 안에서 검증 흐름 전체를 소유한다. 가설이 실제 코드 흐름과 실행 조건에서 성립하는지 검토하고 `TRUE | FALSE | HOLD`를 판정하며, 필요한 Context·Pro/Con·동적 재현·보완 작업과 Gate 제출 시점을 선택한다. 제한 조건·우회 후보·필요 능력·제공 가능 능력·실질 영향의 상승 가능성도 함께 기록한다.

이 제어권은 실행 허가 권한이 아니다. Verification이 다음 작업을 제안하면 비-LLM Runtime Validator가 `ActionRequest`, exact revision, 역할, 상태, 예산과 provider/session을 확인한다. `RUN_SANDBOX`가 허가된 뒤에는 Sandbox Controller가 Docker 세부 정책을 검사하며, Controller가 승인한 exact 계획만 Sandbox Runner가 실행한다.

## 기본 검증 순서

1. 배정된 가설의 `workspace_id`, `commit_id`, entity, location과 suspected path를 확인한다.
2. `CodeContextRequest`로 caller/callee, data flow, auth guard와 route 문맥을 필요한 만큼 조회한다.
3. observed fact와 assumption을 분리하고 각 `FalsificationQuestion.question_id`를 확인한다.
4. 운영 분석이면 Pro/Con Agent를 서로 독립된 NEW session으로 병렬 호출해 supporting/counter evidence를 모두 수집한다. BASIC 또는 조건부 debate는 격리된 평가 실행에서만 선택한다.
5. initial verdict와 unresolved condition을 만든다.
6. 정적 근거만으로 부족하고 안전하게 재현할 가치가 있으면 `LIMITED_REPRO | FULL_REPRO`를 요청한다.
7. 정적·찬반·동적 결과를 종합해 final verdict를 만든다.
8. HOLD면 REQUIRED Primitive 후보를, TRUE면 Gate 통과 뒤 등록할 PROVIDED Primitive 후보를 기록한다. FALSE는 Primitive 후보를 만들지 않는다.
9. 새 endpoint·sink·권한 경계·공격 단계·독립 impact를 발견하면 `HypothesisProposal(origin=VERIFICATION)`으로 분리한다.
10. TRUE의 CWE labeling을 조정하고 Technical Evidence Gate를 요청한다. `REVISE`면 같은 Verification owner가 보완한 새 revision으로 다시 제출한다.
11. HOLD는 즉시 Chaining으로 넘길 수 있고, TRUE는 두 Gate를 정상 통과한 exact revision만 Chaining으로 넘길 수 있다.

## 우회 인지 검증

각 가설은 다음 항목을 명시적으로 검토한다.

- validator, sanitizer와 canonicalization의 적용 순서 및 누락 경로
- authentication, authorization, role, tenancy와 ownership check
- alternate endpoint, serializer, background job, internal call과 configuration path
- 공격자가 먼저 가져야 하는 권한·상태·자산 접근: required capability
- 가설 성공으로 새로 얻게 되는 권한·동작·정보: provided capability
- 현재 impact를 더 큰 asset·privilege·scope로 확장할 후보
- 성립을 막는 restriction과 아직 확인하지 못한 조건

검증 중 발견한 별도 endpoint 우회, 새로운 sink, 새로운 권한 상승과 독립 impact path는 material claim이다. 작은 supporting subtask로 같은 주장만 확인하는 경우를 제외하고 `HypothesisProposal(origin=VERIFICATION)`으로 만든다. trusted runtime이 schema·semantic·중복·깊이·예산을 확인해 전역 등록하고, Orchestration Agent가 새 Verification을 배정한다. Verification은 `hypothesis_id`를 직접 발급하거나 child를 자동 TRUE로 만들지 않는다.

## Debate 정책

`verification_mode`는 구성 가능한 세 가지 값이다.

| 모드 | 동작 | 용도 |
|---|---|---|
| `BASIC` | Verification Agent가 직접 찬반 근거를 수집 | 격리된 비교 평가 전용 |
| `CONDITIONAL_DEBATE` | trigger 충족 시 Pro/Con을 독립 병렬 호출 | 격리된 비교 평가 전용 |
| `ALWAYS_DEBATE` | 모든 유효 가설에 Pro/Con 호출 | 운영(`PRODUCTION`)의 유일한 허용값 |

`AnalysisRunState.purpose=PRODUCTION`에서는 `verification_mode=ALWAYS_DEBATE`만 허용한다. `purpose=EVALUATION`에서만 `BASIC | CONDITIONAL_DEBATE`를 사용할 수 있으며, 그 결과는 품질·비용 비교 자료일 뿐 Gate·Primitive admission·Reporter 입력으로 사용할 수 없다.

조건부 debate trigger 예시는 다음과 같다.

- 상충하는 정적 근거 또는 도구 결과
- 높은 impact나 높은 비용의 후속 조치
- initial `HOLD` 가능성
- 인증·인가·sanitizer 우회 확인 필요
- evidence가 한쪽 주장에만 치우침
- Technical Gate가 반박 또는 restriction 보강을 요구
- 같은 Verification의 이전 검토나 Technical `REVISE`가 의미 있는 alternate path 확인을 요구

운영 분석에서는 named falsification으로 빠르게 반증될 가능성이 있거나 duplicate/unsupported 후보여도 Pro/Con을 생략하지 않는다. 예산이 부족하면 `BUDGET_EXCEEDED`로 현재 Verification work를 중단하며 Pro/Con을 생략한 final verdict를 만들지 않는다. 새 예산이 승인된 새 work에서만 이어서 검증한다.

Pro와 Con은 context contamination을 막기 위해 항상 서로 다른 `NEW` session에서 시작한다. 각 호출은 `requested_by=PRO | CON`, 같은 역할의 `LLMCallSpec.agent_role`, `session_mode=NEW`, `session_policy=NEW`, `parent_session_ref=null`과 서로 다른 `llm_call_id`·action·decision·실제 session을 사용한다. retry와 failover도 상대 역할의 session·output·decision을 이어받지 않고 같은 역할의 새 `NEW` session으로 실행한다. 동일한 `workspace_id`·`commit_id`와 가설·공통 코드 fact는 받지만 상대 Agent의 결론은 입력받지 않는다. Verification Agent만 두 결과와 직접 확인한 사실을 종합한다.

## Debate 효과 측정

각 가설에 다음을 저장해 조건부 정책을 향후 평가할 수 있게 한다.

- 모드와 trigger/skip reason
- Pro/Con 및 종합에 사용한 token과 wall-clock time
- debate 전후 verdict와 confidence 변화
- `HOLD` 해소 여부
- false-positive 감소 후보
- 새 bypass·restriction·falsification 발견 여부

`BASIC | CONDITIONAL_DEBATE`가 더 정확하거나 저렴한지는 동일 corpus의 격리된 평가에서만 측정한다. 평가 결과가 운영 기본 변경의 합격선을 통과하고 별도 설계 결정을 남기기 전까지 운영은 `ALWAYS_DEBATE`를 유지한다.

## 판정 의미

- `TRUE`: 현재 가설의 핵심 exploit path와 필요한 조건이 evidence로 지지된다. restriction이 있으면 그대로 보존한다.
- `FALSE`: 가설의 필수 조건을 묻는 named falsification 하나 이상이 실제 근거로 `DISPROVED`되었다. 다른 path 가능성까지 부정하지 않는다.
- `HOLD`: 핵심 정보·환경·재현 조건이 부족하거나 상충해 현재 증거로 결론을 낼 수 없다.

`HOLD`는 실패가 아니다. 누락 정보와 필요한 capability를 구조화해 exact final Verification revision에 연결된 REQUIRED Primitive로 즉시 저장하고 Chaining Agent의 matching 입력으로 사용할 수 있다. HOLD는 두 Gate를 거치지 않으며 PROVIDED 능력이나 확인된 취약점으로 승격되지 않는다.

`TRUE`도 판정 직후에는 Chaining 입력이 아니다. 현재 revision이 Technical `ACCEPT`와 Rule Scope의 정상 통과 조건을 모두 만족한 뒤에만 PROVIDED Primitive가 된다. `FALSE`는 terminal internal result이며 REQUIRED/PROVIDED Primitive와 Chaining work를 만들지 않는다.

최종 결과는 등록 가설의 모든 반증 질문에 `DISPROVED | NOT_DISPROVED | INCONCLUSIVE` 중 하나를 기록한다. `DISPROVED`에는 실제 `evidence_refs`가 필요하고, `NOT_DISPROVED`는 가설이 참이라는 증거로 승격하지 않는다. `FALSE`는 적어도 하나의 근거 있는 `DISPROVED` 결과와 그 `question_id`를 설명하는 판정 이유가 있을 때만 허용한다. 오류·timeout·누락만으로는 `DISPROVED`나 `FALSE`를 만들지 않는다.

## Docker 동적 재현

동적 검증은 정적 판단을 대체하지 않고 특정 가설의 조건을 제한된 환경에서 확인한다.

Verification Agent가 `NOT_REQUIRED | LIMITED_REPRO | FULL_REPRO`를 결정한다. 동적 재현이 필요하면 Verification이 필요한 역할·권한·인증 방식·데이터·DB/service·fixture/mock·버전·Health Check를 exact `EnvironmentRequirements`로 먼저 저장한다. 이어 mode·가설·요구사항·단계·명령·공격 입력·cleanup 정책을 고정한 exact `ReproductionPlan` 후보를 생산하고, trusted runtime이 두 `SAVE_RESULT`에서 schema·reference·권한·예산을 검사해 `COMMITTED`한다. R7의 Controller·Runner·Result Assembler는 요구사항·mode·계획을 다시 선택하거나 수정하지 않고, 허가된 계획의 정책 판정·환경 비교·실행·exact 결과 조립만 수행한다.

### LIMITED_REPRO

- 한 sanitizer, auth guard, sink 도달 또는 작은 함수 경로 확인
- 초기 verdict의 핵심 불확실성을 최소 실행으로 해소
- 외부 통신·privilege·resource를 최소화

### FULL_REPRO

- 해당 취약점 유형이 end-to-end 재현을 요구하고 안전한 환경이 준비된 경우
- container 내부에 대상과 의존성을 구성하고 공격 입력부터 observable effect까지 재현
- 재현 명령·환경·입력·관찰 결과·제한을 PoC artifact로 정리

### 실행 경계

- 같은 `workspace_id`와 `commit_id`, 승인된 Docker image/digest 사용
- Verification이 생산한 current exact `EnvironmentRequirements`와 이를 가리키는 `ReproductionPlan`에 mode, exact 가설, 단계별 command·공격 입력과 정리 정책 reference를 고정하고 `RUN_SANDBOX.input_refs`에 전체 계획 closure를 포함
- Runtime Validator는 `RUN_SANDBOX` 요청자의 권한·상태·예산, exact 계획과 current requirements revision만 확인하며 환경 조건이나 image·command·file·network·resource·cleanup 정책의 의미를 대신 판단하지 않음
- Sandbox Controller가 exact plan·requirements reference와 image digest, command/tool allowlist, mount·file path, default-deny network, resource/time/process, non-root와 cleanup 정책을 검사하고 통과한 계획만 Runner에 전달
- Sandbox Runner는 실제 환경과 모든 requirement·Health Check를 기록하고 필수 항목이 모두 `MATCH`일 때만 공격 단계를 실행하며, 요구사항·허용 대체값·정책·명령·입력을 임의로 바꾸지 않음
- Docker build와 실행은 분석용 `CodeWorkspace`를 직접 수정하지 않고 sandbox 내부 복사본에서 수행
- 기본 network deny, resource/time/process 제한, non-root와 read-only mount 우선
- host socket, host secret, production credential과 범위 밖 target 접근 금지
- 동적 결과의 exit code, stdout/stderr reference, artifact hash와 hypothesis 연결 저장
- Sandbox 실행 log는 실제 `step_id`·command·공격 입력 reference를 승인 계획과 연결하고 계획에 없는 단계나 입력을 실행하지 않음
- 환경 구축 실패·필수 요구사항 차이와 취약점 반증을 구분
- 필수 차이·실행 불가능·정책 차단·계획 변경이 필요하면 Sandbox Controller나 Runner가 exact 상태와 이유를 반환한다. Verification Agent가 환경 조건이나 허용 대체값을 바꾸면 새 requirements와 이를 가리키는 새 plan을 함께 만들고, 단계만 바꾸면 새 plan만 만든다. 두 경우 모두 새 실행 요청이 필요하며 이 R6 판단은 Sandbox 정책 검사를 우회하지 않는다.

### 동적 결과를 Verification에 전달하는 방법

R7은 PoC·환경·요구사항별 실제 값과 차이·Health Check·정책 판정·단계 로그의 상세 파일 형식을 설계한다. R4 공통 계약은 `EnvironmentRequirements`, plan과 실제 `sandbox_environment`의 exact 연결 및 `DynamicReproductionResult`의 reference·상태 조합만 고정한다.

- `poc_ref`: 이번 재현과 연결된 exact PoC 묶음. 생성되지 않았거나 필요하지 않으면 `null`이며, 존재만으로 실행·성공을 뜻하지 않는다.
- `policy_decision_ref`: Sandbox Controller의 exact 정책 판정. `POLICY_BLOCKED`이면 필수이며 Technical Gate 결과와 섞지 않는다.
- `runner_invoked`: Runner 실제 호출 여부. `false`이면 `steps_ref=null`, `true`이면 첫 단계 실패를 포함해 `steps_ref`가 필수다.
- `environment_created`: 실제 Sandbox 환경 생성 여부. `false`이면 `environment_ref=null`, `true`이면 실제 생성 환경과 requirement별 `MATCH | MISMATCH | NOT_CHECKED | ERROR`를 담은 reference가 필수다. `environment_ref`는 계획용 요구사항이나 Sandbox 보안 profile과 같은 개념이 아니다.
- `cleanup_required`: 정리 대상 발생 여부. `false`일 때만 `cleanup_status=NOT_REQUIRED`이며, 실제 자원이 생겼으면 `SUCCEEDED | FAILED`로 정리 결과를 남긴다.

### R7 동적 artifact 상세 계약

R7 artifact는 공통 `RecordMeta`와 `StoredDataRef` identity를 사용하며 모두 immutable이다. `record_id`·`content_hash`가 확정된 뒤 payload를 수정하지 않고, 보완·redaction 재처리·cleanup 후속 결과는 새 revision으로 저장한다. Result Assembler는 “latest”를 조회하지 않고 현재 attempt가 생산한 exact revision만 사용한다.

아래 R7 상세 schema는 공통 계약을 확장하거나 공통 필드를 새로 요구하지 않는다. 공통 `sandbox_environment.checks[].actual_ref`, `sandbox_step_log.entries[].observation_refs`, `DynamicReproductionResult.policy_decision_ref | environment_ref | steps_ref | observation_refs | poc_ref`와 `TransitionCommit.output_refs`가 상세 artifact의 exact `StoredDataRef`를 연결한다. 모든 schema의 `meta`는 공통 `RecordMeta`이고 `schema_version`은 같은 major 안에서만 하위 호환한다.

| `data_kind` | `schema_version` | 최종 producer | 완료 조건과 공통 연결 |
|---|---|---|---|
| `sandbox_policy_decision` | `r7.sandbox_policy_decision/1` | Sandbox Controller | 모든 검사 항목과 `ALLOW | DENY` 확정 후 immutable; `policy_decision_ref` |
| `sandbox_environment_detail` | `r7.sandbox_environment_detail/1` | Sandbox Runner environment builder | 생성된 자원 snapshot과 모든 requirement 비교 종료; `EnvironmentCheck.actual_ref/evidence_refs` |
| `sandbox_step_execution_detail` | `r7.sandbox_step_execution_detail/1` | Sandbox Runner | 실행 시도 종료 후 exit/signal·stream·resource usage 확정; `SandboxStepEntry.observation_refs` |
| `dynamic_observation` | `r7.dynamic_observation/1` | Sandbox Runner 또는 승인된 Observation Collector | capture 종료와 redaction 최종 상태 확정; step/result `observation_refs` |
| `sandbox_cleanup_record` | `r7.sandbox_cleanup_record/1` | Sandbox Cleanup Coordinator | 현재 cleanup 시도가 `SUCCEEDED | FAILED`로 종료; result assembly trace |
| `poc_bundle` | `r7.poc_bundle/1` | PoC Bundle Assembler | draft·실행 증명·redaction manifest 검증 후 commit; `poc_ref` |
| `sandbox_result_assembly_trace` | `r7.sandbox_result_assembly_trace/1` | Sandbox Result Assembler | 결과에 사용한 모든 exact input과 cleanup record를 고정; 결과와 같은 `TransitionCommit.output_refs` |

R7 내부 producer 이름은 책임 경계를 뜻한다. Agent/LLM이 후보 입력이나 설명을 제안할 수는 있지만 Controller 정책 판정, Runner 실행 사실, Collector 관측 사실, cleanup 결과, PoC 최종 저장 및 Result 조립 record의 producer가 될 수 없다.

#### Controller 정책 판정 `sandbox_policy_decision`

Controller는 Runner 호출 전에 다음 내용을 구조화해 저장한다.

```yaml
SandboxPolicyDecision:
  meta: RecordMeta
  data_kind: sandbox_policy_decision
  schema_version: r7.sandbox_policy_decision/1
  producer: SANDBOX_CONTROLLER
  reproduction_plan_ref: StoredDataRef
  environment_requirements_ref: StoredDataRef
  action_decision_ref: StoredDataRef
  sandbox_profile_ref: StoredDataRef
  policy_revision_ref: StoredDataRef
  plan_closure_hash: string
  checks: [SandboxPolicyCheck]
  final_decision: ALLOW | DENY
  runner_handoff_authorized: boolean
  runner_handoff_plan_ref: StoredDataRef | null
  runner_handoff_hash: string | null
  evaluated_at: timestamp
  completed_at: timestamp

SandboxPolicyCheck:
  check_id: string
  domain: IMAGE | COMMAND_TOOL | FILE_MOUNT | NETWORK | RESOURCE | PROCESS | TIME | PRIVILEGE | CLEANUP
  status: PASS | FAIL
  reason_code: string | null
  safe_detail: string | null
  evidence_refs: [StoredDataRef]
```

- exact `ReproductionPlan`·`EnvironmentRequirements` reference와 전체 plan closure hash
- Runtime Validator의 `RUN_SANDBOX` action decision reference
- Sandbox profile reference, policy revision reference와 평가 시각
- image digest, command/tool, mount/file, network, CPU·memory·disk·process·time, privilege와 cleanup 항목별 `PASS | FAIL`
- 실패한 항목의 안정적인 reason code와 secret·host path를 제거한 safe detail
- 최종 `ALLOW | DENY`
- `ALLOW`일 때 Runner에 전달한 exact plan reference와 handoff hash, `DENY`일 때 Runner 미호출 사실

항목별 검사 결과가 하나라도 `FAIL`이면 최종 결과는 `DENY`다. policy/profile revision을 변경해 다시 실행하려면 기존 판정을 덮어쓰지 않고 Verification의 새 계획 또는 공통 계약이 허용하는 동일 closure의 새 attempt에서 새 action·정책 판정을 만든다.

`ALLOW`는 모든 check가 `PASS`, `runner_handoff_authorized=true`, 두 handoff 필드가 non-null이고 handoff plan/hash가 검사한 exact plan closure와 같아야 한다. `DENY`는 하나 이상의 `FAIL`, `runner_handoff_authorized=false`, 두 handoff 필드가 `null`이어야 한다. 이는 Controller의 handoff 허가 사실이며 공통 결과의 `runner_invoked` 실제 실행 사실과 다르다. Controller는 최종 판정 뒤 같은 record를 수정하지 않는다.

#### 실제 환경 `sandbox_environment`

`sandbox_environment`는 계획용 설정이 아니라 해당 attempt에서 실제로 생성된 자원·실행 조건과 requirement 비교를 공격 단계 전에 확정한 immutable snapshot이다.

```yaml
SandboxEnvironmentDetail:
  meta: RecordMeta
  data_kind: sandbox_environment_detail
  schema_version: r7.sandbox_environment_detail/1
  producer: SANDBOX_RUNNER_ENVIRONMENT_BUILDER
  reproduction_plan_ref: StoredDataRef
  requirements_ref: StoredDataRef
  policy_decision_ref: StoredDataRef
  images: [ActualImage]
  runtime_versions: [ActualVersion]
  services: [ActualService]
  fixtures_and_identities: [ActualFixtureIdentity]
  mount_policy_ref: StoredDataRef
  network_policy_ref: StoredDataRef
  resource_limit_ref: StoredDataRef
  generated_resources: [SandboxResourceEntry]
  requirement_actuals: [RequirementActual]
  captured_at: timestamp
  completed_at: timestamp

RequirementActual:
  requirement_id: string
  status: MATCH | MISMATCH | NOT_CHECKED | ERROR
  actual_ref: StoredDataRef | null
  evidence_refs: [StoredDataRef]
  safe_difference: string | null

SandboxResourceEntry:
  resource_id: string
  resource_type: CONTAINER | IMAGE | VOLUME | NETWORK | FILE | FIXTURE | ACCOUNT | CREDENTIAL
  creation_ref: StoredDataRef

ActualImage:
  role: APPLICATION | BASE | SERVICE | MOCK
  image_digest: string
  build_provenance_ref: StoredDataRef

ActualVersion:
  component: string
  version: string
  lock_or_config_hash: string | null

ActualService:
  service_id: string
  service_type: APPLICATION | DATABASE | CACHE | MOCK | SUPPORTING
  image_digest: string | null
  network_alias: string
  health_observation_ref: StoredDataRef

ActualFixtureIdentity:
  logical_id: string
  kind: FIXTURE | TEST_ACCOUNT | ROLE | DATA_STATE
  privilege_summary: [string]
  secret_handle_ref: StoredDataRef | null
  creation_evidence_refs: [StoredDataRef]
```

- application/base image digest, runtime·package manager·주요 dependency version과 lock/config hash
- 실제 service·DB·Mock 목록, 각 image digest·격리 network alias·health 결과
- sandbox 상대 mount와 writable 범위, 적용된 resource/process/time limit와 network egress 범위
- fixture·테스트 계정·권한·데이터 상태의 비밀값 없는 식별자와 생성 결과
- 적용한 설정 key 목록과 redacted value hash; credential·token·cookie 원문 금지
- 생성된 container·network·volume·temporary image/file·fixture/account/credential의 불투명 resource ID와 생성 ledger
- 원본 plan·Controller 판정·workspace·commit·hypothesis·attempt의 exact linkage

`requirements_ref`는 plan의 `environment_requirements_ref`가 가리키는 current exact `EnvironmentRequirements` revision과 같아야 한다. `checks`는 모든 `requirement_id`를 한 번씩 다루며 공통 `EnvironmentCheck.status=MATCH | MISMATCH | NOT_CHECKED | ERROR`를 사용한다. 각 check에는 비밀값을 제거한 actual 또는 exact `actual_ref`, difference, evidence와 Health Check 결과를 연결한다. 필수 항목이 모두 `MATCH`일 때만 environment status는 `READY`이고 공격 단계를 시작할 수 있다.

공통 `SandboxEnvironment`가 먼저 자신의 exact detail을 가리키는 순환 구조를 만들지 않는다. environment builder는 detail을 저장한 뒤 각 공통 `EnvironmentCheck.actual_ref/evidence_refs`에 해당 detail 또는 하위 actual artifact의 exact reference를 연결하고 공통 environment snapshot을 commit한다. detail과 공통 snapshot은 같은 plan·requirements·policy·analysis·hypothesis·attempt identity로 결합한다. required requirement가 하나라도 `MISMATCH | NOT_CHECKED | ERROR`이면 공격 단계를 시작하지 않는다. `PARTIAL`에 허용되는 차이는 R6가 plan/requirements에 선택 항목 또는 허용 fallback으로 사전 명시한 차이뿐이다.

#### Runner 단계 로그 `sandbox_step_log`

Runner가 호출되면 첫 단계 시작 전 append-only log를 열고 실패·timeout·취소를 포함한 모든 시도를 순서대로 기록한다.

- exact plan·policy decision·실제 environment와 Runner invocation reference
- `step_id`, 실행 순번, `command_ref`, exact `attack_input_refs`
- 시작·종료 시각, exit code 또는 signal/timeout/cancel reason
- stdout·stderr의 redacted artifact reference와 원본 byte count·content hash
- 단계에서 생산된 observation reference와 resource usage
- 공통 `SandboxStepEntry.status=SUCCEEDED | FAILED | SKIPPED | CANCELLED`와 최초 실패 위치. timeout은 entry `FAILED`와 결과 `failure_reason=TIMEOUT`, 실행 전 중단은 `SKIPPED`와 safe reason으로 구분

Runner가 호출되지 않으면 빈 로그를 만들지 않는다. 호출됐지만 환경 차이로 첫 공격 단계 전에 멈추면 공통 계약대로 `entries=[]` 또는 계획상 entry를 `SKIPPED`로 남긴 exact log를 저장하고 실제 공격 입력은 비운다. 계획에 없는 단계·command·입력은 기록 후 실행하는 것이 아니라 Controller/Runner 경계에서 차단한다.

공통 `SandboxStepLog` schema 자체는 바꾸지 않는다. 실행 시각·exit/signal·stdout/stderr·resource usage 같은 상세 실행 정보는 다음 detail artifact로 저장하고 해당 `SandboxStepEntry.observation_refs`에 연결한다.

```yaml
SandboxStepExecutionDetail:
  meta: RecordMeta
  data_kind: sandbox_step_execution_detail
  schema_version: r7.sandbox_step_execution_detail/1
  producer: SANDBOX_RUNNER
  reproduction_plan_ref: StoredDataRef
  policy_decision_ref: StoredDataRef
  environment_ref: StoredDataRef
  step_id: string
  sequence: integer
  command_ref: StoredDataRef
  attack_input_refs: [StoredDataRef]
  status: SUCCEEDED | FAILED | CANCELLED
  started_at: timestamp
  finished_at: timestamp
  exit_code: integer | null
  signal: string | null
  stop_reason: string | null
  stdout_ref: StoredDataRef | null
  stderr_ref: StoredDataRef | null
  stdout_byte_count: integer
  stderr_byte_count: integer
  resource_usage_ref: StoredDataRef
```

실행된 entry에는 정확히 하나의 같은 `step_id`·sequence·command·input을 가진 execution detail이 필요하다. 정상 종료는 `exit_code`가 필수이고 `signal=null`, signal/timeout/cancel 종료는 `exit_code=null`과 safe `signal` 또는 `stop_reason`이 필수다. stdout/stderr가 없으면 reference는 `null`, byte count는 `0`이다. `SKIPPED` entry에는 execution detail을 만들지 않는다. HTTP·DB·파일 등 의미 관측은 별도 `dynamic_observation`으로 같은 entry에 추가한다.

#### 자원·cleanup 기록

환경 snapshot을 cleanup 뒤에 수정하지 않는다. R7 runtime은 같은 동적 실행 attempt의 append-only cleanup record에 다음 내용을 남기고 Result Assembler가 이를 집계해 공통 `cleanup_required`와 `cleanup_status`를 채운다.

```yaml
SandboxCleanupRecord:
  meta: RecordMeta
  data_kind: sandbox_cleanup_record
  schema_version: r7.sandbox_cleanup_record/1
  producer: SANDBOX_CLEANUP_COORDINATOR
  reproduction_plan_ref: StoredDataRef
  policy_decision_ref: StoredDataRef
  environment_ref: StoredDataRef | null
  cleanup_policy_ref: StoredDataRef
  resources: [CleanupResourceResult]
  status: SUCCEEDED | FAILED
  recovery_work_ref: StoredDataRef | null
  started_at: timestamp
  finished_at: timestamp

CleanupResourceResult:
  resource_id: string
  resource_type: CONTAINER | IMAGE | VOLUME | NETWORK | FILE | FIXTURE | ACCOUNT | CREDENTIAL
  status: SUCCEEDED | FAILED
  safe_reason: string | null
  isolation_state: REMOVED | QUARANTINED | REMAINING
```

- exact cleanup policy와 nullable environment reference
- 자원별 불투명 resource ID, `CONTAINER | IMAGE | VOLUME | NETWORK | FILE | FIXTURE | ACCOUNT | CREDENTIAL` 종류와 생성 근거
- `SUCCEEDED | FAILED` 정리 결과, 시도 시각, safe reason과 남은 자원 격리 상태
- 강제 정리가 필요한 경우 recovery work reference와 운영 알림 ID

공통 `DynamicReproductionResult`에 새 `cleanup_ref`를 임의로 추가하지 않는다. 상세 cleanup record의 exact revision은 `SAVE_RESULT` 입력과 `sandbox_result_assembly_trace.cleanup_record_ref`에 고정하고, 그 trace와 결과를 같은 `TransitionCommit.output_refs`에서 atomic commit한다. Runner 미호출이나 `environment_ref=null`이어도 Controller 차단 전에 다른 임시 자원이 생겼다면 cleanup record와 `cleanup_required=true`가 필요하다. 자원이 전혀 없을 때만 cleanup record 없이 `cleanup_required=false`, `cleanup_status=NOT_REQUIRED`를 사용한다.

#### 동적 관측 artifact

각 `observation_ref`는 관측 종류, capture point, 수집 시각, producer, 관련 `step_id`·command·attack input, redaction 상태와 content hash를 가진다. 관측 종류별 최소 내용은 다음과 같다.

```yaml
DynamicObservation:
  meta: RecordMeta
  data_kind: dynamic_observation
  schema_version: r7.dynamic_observation/1
  producer: SANDBOX_RUNNER | SANDBOX_OBSERVATION_COLLECTOR
  reproduction_plan_ref: StoredDataRef
  policy_decision_ref: StoredDataRef
  environment_ref: StoredDataRef | null
  steps_ref: StoredDataRef | null
  step_id: string | null
  command_ref: StoredDataRef | null
  attack_input_refs: [StoredDataRef]
  observation_kind: STEP_EXECUTION | HTTP | LOG | DB_CHANGE | FILE_CHANGE | COMMAND_CANARY | MOCK_CALLBACK | HEADLESS_BROWSER
  capture_point: string
  payload_ref: StoredDataRef
  redaction_status: SUCCEEDED | FAILED
  content_hash: string
  captured_at: timestamp
  finalized_at: timestamp
```

일반 `observation_refs`로 승격되는 record는 `redaction_status=SUCCEEDED`만 허용한다. redaction 실패 record는 제한 저장소의 실패·감사 추적에만 남고 `payload_ref`를 일반 evidence closure에 포함하지 않는다. 환경 snapshot commit 전의 구성/Health Check 관측은 순환 참조를 피하기 위해 `environment_ref=null`, `steps_ref=null`, `step_id=null`, `command_ref=null`, `attack_input_refs=[]`일 수 있으며 plan·policy·attempt identity로 공통 environment check에 연결한다. 공격 단계 관측은 `environment_ref`와 `step_id`가 필수다.

| 관측 | 최소 기록 |
|---|---|
| HTTP 요청·응답 | method, 격리 target ID와 path, status, header allowlist, redacted body ref/hash, request-response correlation |
| application·middleware·server log | component, stream, timestamp, correlation/canary, redacted event ref/hash |
| DB 변화 | DB/schema logical ID, normalized query template, redacted parameter hash, before/after row hash와 허용된 safe field |
| 파일 변화 | sandbox 상대 path, operation, before/after hash·size, canary; host 절대 path 저장 금지 |
| command canary | command reference, exit status, stdout/stderr observation과 expected/actual marker |
| Mock callback | approved Mock ID, method/path, received timestamp, redacted payload hash와 correlation |
| Headless Browser | 격리 URL ID, action/selector, DOM 또는 console/network 관측 hash, redacted screenshot ref |

관측이 없다는 사실은 반증 Evidence가 아니다. 수집 채널이 실패하면 `FAILED + OBSERVATION`이고, 관측 일부가 신뢰 가능하며 공격 경로 일부를 실제 실행했다면 그 관측과 limitation을 연결해 `PARTIAL + NONE`을 사용할 수 있다.

#### PoC 묶음 `poc_bundle`

PoC는 실행 전 생성본과 Runner가 실제 사용한 실행본을 구분한다.

```yaml
PoCBundle:
  meta: RecordMeta
  data_kind: poc_bundle
  schema_version: r7.poc_bundle/1
  producer: POC_BUNDLE_ASSEMBLER
  reproduction_plan_ref: StoredDataRef
  hypothesis_ref: StoredDataRef
  draft_ref: StoredDataRef
  execution_attestation_ref: StoredDataRef | null
  policy_decision_ref: StoredDataRef
  environment_ref: StoredDataRef | null
  steps_ref: StoredDataRef | null
  attack_input_refs: [StoredDataRef]
  observation_refs: [StoredDataRef]
  files: [PoCFileEntry]
  execution_status: NOT_EXECUTED | EXECUTED | EXECUTION_FAILED
  redaction_manifest_ref: StoredDataRef
  limitations: [string]
  committed_at: timestamp

PoCFileEntry:
  role: GENERATED | EXECUTED | SUPPORTING
  media_type: string
  content_ref: StoredDataRef
  content_hash: string
```

- manifest schema/version, plan·hypothesis·workspace·commit·attempt reference
- 안전한 사전 조건, fixture·계정·권한의 불투명 ID와 재실행 순서
- 파일별 역할 `GENERATED | EXECUTED | SUPPORTING`, media type, redacted content reference와 hash
- 실행본의 exact command·attack input·step log·observation reference와 실행 상태
- expected effect와 실제 관측을 분리한 설명
- 운영환경과의 차이, version/Mock/fallback, 미실행 단계와 기타 limitation
- redaction manifest, 제외한 secret 종류, 재실행에 필요한 승인 profile과 cleanup 요약

정책 차단 전에 생성된 PoC는 `execution_status=NOT_EXECUTED`로 보존할 수 있지만 실행 성공이나 관측 근거가 아니다. 실제 실행을 주장하려면 PoC 실행본 digest가 `SandboxStepLog`의 command/input과 일치하고 관련 observation이 있어야 한다.

PoC authority는 다음처럼 분리한다.

1. 비-LLM `PoC Draft Builder`가 승인된 exact plan 안에서 후보 입력을 정규화·안전화해 immutable `poc_draft`를 저장한다. LLM 출력은 이 builder의 입력 후보일 뿐 저장 권한이나 실행 사실 권한이 없다.
2. Runner만 실제 사용한 command/input digest, step 및 observation을 묶은 immutable `poc_execution_attestation`을 생성해 `EXECUTED | EXECUTION_FAILED`를 증명한다.
3. 비-LLM `PoC Bundle Assembler`가 draft, Runner attestation, redaction 결과와 hash를 검증하고 최종 `poc_bundle` revision을 commit한다.
4. 정책 차단으로 Runner가 호출되지 않으면 attestation 없이 Controller의 `DENY` exact reference를 사용해 `NOT_EXECUTED` bundle을 commit할 수 있다.
5. 공통 `poc_ref`는 항상 이 최종 committed bundle revision을 가리키며 draft, LLM 제안 또는 처리 중 bundle을 가리키지 않는다.

#### redaction·hash·보존

raw stdout/stderr, request/response body, DB 값, screenshot과 PoC 파일은 먼저 제한 저장소에 격리하고 redaction 성공 후에만 일반 `StoredDataRef`로 승격한다. 일반 artifact에는 credential·cookie·authorization header·개인정보·host secret·전체 browser profile을 넣지 않는다. 일반 `content_hash`는 redacted bytes에 대해 계산하고, raw-to-redacted 대응과 raw hash는 접근 통제된 감사 metadata에만 둔다.

redaction이 실패하면 raw artifact는 격리·짧은 보존·접근 감사 대상이며 `observation_refs`, `poc_ref`, Gate 또는 Reporter 입력으로 전달하지 않는다. 보존 만료나 삭제는 record identity를 재사용하지 않고 tombstone과 사유를 남긴다.

#### Result finalization barrier와 늦은 결과

Result Assembler는 다음 barrier가 모두 닫힌 뒤에만 `DynamicReproductionResult` 후보를 만든다.

1. Runner가 step log를 seal하고 더 이상 entry를 추가하지 않는다.
2. 승인된 Collector가 bounded drain deadline까지 수집을 끝내고 collection manifest를 `CLOSED`로 확정한다.
3. 결과에 넣을 observation과 PoC payload의 redaction이 모두 `SUCCEEDED` 또는 제외 사유가 확정되어 처리 중 artifact가 없다.
4. PoC Bundle Assembler가 최종 `EXECUTED | EXECUTION_FAILED | NOT_EXECUTED` revision을 commit한다.
5. cleanup 대상이 있으면 현재 cleanup 시도가 `SUCCEEDED | FAILED`로 끝나고 exact cleanup record가 확정된다. 대상이 없으면 `NOT_REQUIRED` 조건을 검증한다.
6. Result Assembler가 아래 trace를 만들고 `SAVE_RESULT`가 exact plan·policy·environment·steps·observation·PoC·cleanup 조합을 재검증한다.

```yaml
SandboxResultAssemblyTrace:
  meta: RecordMeta
  data_kind: sandbox_result_assembly_trace
  schema_version: r7.sandbox_result_assembly_trace/1
  producer: SANDBOX_RESULT_ASSEMBLER
  reproduction_plan_ref: StoredDataRef
  policy_decision_ref: StoredDataRef | null
  environment_ref: StoredDataRef | null
  steps_ref: StoredDataRef | null
  observation_refs: [StoredDataRef]
  poc_ref: StoredDataRef | null
  cleanup_record_ref: StoredDataRef | null
  dynamic_result_ref: StoredDataRef
  collection_manifest_ref: StoredDataRef | null
  finalized_at: timestamp
```

collection close 뒤 도착한 observation은 기존 결과나 같은 attempt의 새 revision에 끼워 넣지 않고 `LATE_ARTIFACT` 운영 추적으로 격리한다. 그 관측이 판정에 필요하면 R6가 새 Verification/dynamic attempt를 만든다. cleanup `FAILED` 결과 commit 뒤 운영 janitor가 정리에 성공해도 기존 결과를 수정하지 않고 원 cleanup record에 연결된 recovery record를 append한다. recovery는 현재 자원 안전 상태를 갱신하지만 과거 결과의 `cleanup_status=FAILED`를 성공으로 소급 변경하지 않는다.

#### 보존 만료·tombstone과 downstream 재검증

Technical Gate, Reporter, Human Review packet 준비 및 `DISCLOSE` 직전 Runtime Validator는 자신이 소비하는 exact observation·PoC payload의 availability와 hash를 다시 검사한다. `TOMBSTONED | CORRUPT | REDACTION_REVOKED`이면 과거 Verification·Gate·ReportDraft·HumanReviewPacket은 감사 이력으로는 남지만 새 작업이나 현재 공개에 재사용할 수 없다. 이미 수행한 외부 공개 이력을 지우지는 않되 같은 packet으로 재공개하지 않는다.

- 누락 payload가 Verification verdict, impact 또는 Gate 판단의 필수 근거면 새 Verification generation에서 남은 근거와 limitation을 다시 평가하고 새 Gate 결과를 받아야 한다.
- Verification/Gate의 필수 근거는 유지되고 보고서 첨부물만 만료됐다면 Verification을 다시 판정하지 않고 Reporter/Human Review/공개를 중단한 뒤 대체 artifact와 새 report/packet revision을 만든다.
- 어느 경우에도 payload 부재를 취약점 반증, `hypothesis_outcome=DISPROVED` 또는 Verification `FALSE`로 자동 변환하지 않는다.

R4 공통 stale/invalidation lifecycle이 확정되면 R7 runtime은 그 공통 상태·reason code를 사용한다. 그 전에도 fail-closed 원칙으로 downstream 호출을 막고, 삭제된 payload를 대신해 예전 Technical `ACCEPT`나 공개 승인을 current로 취급하지 않는다.

Sandbox runtime의 비-LLM Result Assembler는 같은 analysis·workspace·commit·hypothesis에 속한 exact R6 plan closure와, `DynamicReproductionResult.meta.attempt_id`와 같은 R7 실행 attempt의 정책 판정·환경·step log·실행 PoC만 결과에 넣는다. R6가 먼저 만든 계획·요구사항의 `attempt_id`를 R7 실행 attempt와 억지로 같게 만들지 않는다. `DynamicReproductionResult`에 요구사항 reference를 중복 저장하지 않고 `reproduction_plan_ref -> environment_requirements_ref`와 `environment_ref -> requirements_ref`가 같은 record revision인지 검사한다. `DynamicReproductionState`, work output과 `TransitionCommit`이 같은 COMMITTED 결과를 가리킨 뒤 Verification Agent가 `dynamic_result_ref`, 환경 차이와 exact `poc_ref`를 읽는다. Technical Evidence Gate Agent는 Verification에 연결된 정책 판정·환경·step log·PoC와 outcome이 서로 맞는지 검토하고, Reporter는 두 Gate를 통과한 결과만 보고서 초안에 사용한다. Provider 오류, 정책 차단, setup·환경 차이·실행·관측 실패는 이 전달 과정에서 `FALSE`로 바뀌지 않는다.

### 동적 재현 상태와 실제 반증

동적 재현 상태는 `NOT_REQUESTED | RUNNING | SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED`다. 실행이 끝난 결과는 `DynamicReproductionResult.status`에 `SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED` 중 하나를 기록한다.

- 필수 환경을 만들지 못하거나 필수 requirement가 `MISMATCH | NOT_CHECKED | ERROR`이면 공격 단계를 시작하지 않고 `FAILED + ENVIRONMENT_SETUP`으로 R6에 돌려보낸다.
- 공격 경로를 일부 실행하고 신뢰할 수 있는 관측을 하나 이상 얻었지만 R6가 requirements에서 선택 항목 또는 허용 fallback으로 사전 승인한 환경 차이 때문에 전체 확인이 부족하면 `PARTIAL + NONE`이다. required requirement 차이는 `PARTIAL`이 아니라 공격 미실행과 `FAILED + ENVIRONMENT_SETUP`이다. `PARTIAL`이면 `hypothesis_outcome=INCONCLUSIVE`이고 `hypothesis_evidence_refs`와 `limitations`가 각각 하나 이상 있어야 한다.
- `SUCCEEDED`는 계획한 필수 단계와 관측을 끝냈다는 실행 상태다. 관측이 가설을 지지했는지, 반증했는지, 결론을 주지 못했는지는 `hypothesis_outcome`에 따로 기록한다.
- `hypothesis_outcome`은 `SUPPORTED | DISPROVED | INCONCLUSIVE`이며 Verification verdict가 아니다. `SUPPORTED | DISPROVED`는 실제 관측을 가리키는 `hypothesis_evidence_refs`가 필요하다.
- `DISPROVED`일 때만 `hypothesis_disproved=true`와 비어 있지 않은 `disproof_evidence_refs`를 사용한다. 반증 근거는 일반 가설 근거 목록에도 포함한다.
- `FAILED | BLOCKED | CANCELLED`, 실행하지 못함, 빈 출력과 exit code만으로는 `DISPROVED`, `hypothesis_disproved=true` 또는 `FALSE`를 만들 수 없다.

### 대표 결과 예시

| 상황 | 결과와 artifact |
|---|---|
| image 또는 필수 service를 만들지 못해 공격 경로 미실행 | `FAILED + ENVIRONMENT_SETUP + INCONCLUSIVE`; 완료된 환경 관측과 오류만 보존하고 `PARTIAL`로 과장하지 않음 |
| 공격 명령이 시작됐지만 실행 오류로 필수 관측 없음 | `FAILED + EXECUTION + INCONCLUSIVE`; `runner_invoked=true`, exact `steps_ref`와 생성 자원 cleanup 결과 필수 |
| 공격 경로를 실행했지만 필수 관측 채널 수집 실패 | `FAILED + OBSERVATION + INCONCLUSIVE`; 실행 log와 수집 실패 위치 보존 |
| 제한 시간 안에 필수 단계가 끝나지 않음 | `FAILED + TIMEOUT + INCONCLUSIVE`; timeout step과 당시 관측·cleanup 보존 |
| Controller가 실행 전에 정책 거절, 자원 없음 | `BLOCKED + POLICY_BLOCKED + INCONCLUSIVE`; `policy_decision_ref` 필수, Runner·step·공격 입력·관측 없음, `cleanup_status=NOT_REQUIRED` |
| Controller 차단 전 임시 자원이 생성됨 | `BLOCKED + POLICY_BLOCKED + INCONCLUSIVE`; Runner 미호출이면 `steps_ref=null`, 실제 환경과 자원 ledger·cleanup `SUCCEEDED | FAILED` 필수 |
| 공격 경로 일부와 신뢰 관측은 있으나 사전 승인된 optional/fallback 환경 차이로 전체 확인 불가 | `PARTIAL + NONE + INCONCLUSIVE`; evidence와 limitation 각각 필수. required 차이면 공격 미실행과 `FAILED + ENVIRONMENT_SETUP` |
| 계획한 경로를 정상 실행해 가설과 반대되는 관측 확보 | 실행 status와 별도로 `DISPROVED`; 정상 단계 log와 `hypothesis_evidence_refs`·`disproof_evidence_refs` 필수 |

동적 결과 상태와 공통 실행 상태는 뜻이 다르다. `DYNAMIC_REPRO`의 `PARTIAL`은 신뢰 관측과 `limitations`를 가진 `DynamicReproductionResult` 자체가 누락 범위를 설명하므로 실제 오류가 없으면 `AnalysisError`나 `DataGap`을 만들지 않는다. `BLOCKED + POLICY_BLOCKED`는 정책에 막힌 사실을 Sandbox가 정상적으로 기록한 종료 결과이므로 공통 `WorkExecutionState`는 `SUCCEEDED`로 끝난다. 여기서 `SUCCEEDED`는 요청 처리가 완료되었다는 뜻일 뿐 재현 성공이나 가설 지지를 뜻하지 않는다. retry·승인·입력을 기다리는 경우에만 공통 상태 `BLOCKED`를 사용한다. `CANCELLED`는 취소 결과와 공통 취소 상태를 같은 atomic transition에서 저장하고, 취소 뒤 늦게 도착한 결과는 격리한다.

모든 종료 결과는 `DynamicReproductionState.dynamic_result_ref`, `WorkExecutionState.output_refs`와 `TransitionCommit.output_refs`가 같은 `DynamicReproductionResult.record_id`를 가리킬 때만 Verification에 전달한다. Verification Agent는 이 결과를 정적·찬반 근거와 함께 읽어 최종 `TRUE | FALSE | HOLD`를 결정한다.
- Sandbox Controller는 exact 정책 판정을 저장하고 통과한 계획만 Runner에 전달한다. Runner는 exact 요구사항과 실제 환경·Health Check를 비교하고 필수 차이가 있으면 공격 단계 전에 멈춘다. 비-LLM Sandbox Result Assembler는 Runner 호출 여부와 실제 환경 비교·정리 여부를 포함한 `DynamicReproductionResult`를 조립한다. 결과 저장 전 `SAVE_RESULT`가 계획·requirements·정책 판정·실제 환경·단계·공격 입력·PoC·정리 조합을 다시 대조하며, Verification Agent는 `COMMITTED`된 결과를 소비할 뿐 요구사항 비교나 동적 결과를 직접 생산하지 않는다. Sandbox는 outcome까지만 기록한다. Verification Agent가 환경 차이를 허용해 환경 조건을 바꾸면 새 요구사항과 이를 가리키는 새 계획을 함께 만들고, 실행 단계만 바꾸면 새 계획만 만든 뒤 limitations와 정적·동적·찬반 근거를 함께 보고 최종 `TRUE | FALSE | HOLD`를 결정한다.

## Technical `REVISE` 처리

Technical Evidence Gate의 `REVISE`는 Orchestration이나 Chaining Agent가 받을 작업이 아니다. 같은 hypothesis의 ACTIVE `VerificationAssignment` owner가 직접 받고 누락된 Context·Pro/Con·정적 근거·동적 재현·PoC 연결·restriction·설명을 보완한다. runtime은 종료된 기존 work를 되돌리지 않고 새 generation의 VERIFICATION work를 만들고 hypothesis 상태를 `TERMINAL -> VERIFYING`으로 원자 전환한다. CWE 보완이 필요하면 CWE producer와 새 label revision을 조정하되 CWE 소유권을 가져오지 않는다.

```text
VerificationResult revision N
-> Technical Gate REVISE
-> same Verification owner
-> new evidence and/or revised CWE
-> VerificationResult revision N+1
-> new Technical Gate work
```

`REVISE`는 provider retry나 동일 입력 재투표가 아니다. 새 work는 새 `input_hash`, `dedupe_key`, `work_id`, `attempt_number=1`, `trigger=INITIAL`을 사용한다. 이전 Gate 결과가 N을 가리키면 N+1에 재사용할 수 없다.

## VerificationResult에 남길 정보

최종 결과는 verdict뿐 아니라 질문별 `FalsificationResult`, supporting/counter evidence, restrictions, bypass·alternate path·impact 후보, REQUIRED/PROVIDED Primitive 후보, `origin=VERIFICATION` material child proposal, unresolved conditions, debate 지표와 동적 재현 reference를 포함한다. HOLD의 REQUIRED 후보는 즉시 admission할 수 있다. TRUE의 REQUIRED 후보는 그 취약점의 악용 선행 조건으로만 보존되고, PROVIDED 후보가 두 Gate를 정상 통과해 admission될 때 `required_preconditions`에 복사된다. 이 정보가 CWE, 두 Gate, Primitive admission과 사람 검토의 입력이 된다.

supporting/counter evidence는 자유 형식 문자열이 아니라 `EvidenceClaim`으로 기록한다. 각 claim은 작성 역할, 실제 저장 근거와 코드 주장에 필요한 현재 workspace·commit의 위치를 포함한다. 우회·대체 경로·영향 확대 후보는 `CandidateRef(candidate_state=UNVALIDATED)`로 구분하고 새 material claim이면 별도 가설로 재검증한다. debate token·시간과 판정 변화는 `VerificationMetrics`에 저장하며 provider가 token을 제공하지 않으면 값을 추정하지 않고 `null`로 둔다.
