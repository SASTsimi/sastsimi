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

Verification Agent가 `NOT_REQUIRED | LIMITED_REPRO | FULL_REPRO`를 결정한다. 동적 재현이 필요하면 Verification이 mode·가설·단계·명령·공격 입력·cleanup 정책을 고정한 exact `ReproductionPlan` 후보를 생산하고, trusted runtime이 `SAVE_RESULT(result_kind=reproduction_plan)`로 schema·reference·권한·예산을 검사해 `COMMITTED`한다. R7의 Sandbox Controller·Runner·비-LLM Result Assembler는 mode를 다시 선택하거나 계획을 수정하지 않고, 허가된 계획의 정책 판정·실행·exact 결과 조립만 수행한다.

### LIMITED_REPRO

- 한 sanitizer, auth guard, sink 도달 또는 작은 함수 경로 확인
- 초기 verdict의 핵심 불확실성을 최소 실행으로 해소
- 외부 통신·privilege·resource를 최소화

### FULL_REPRO

- 해당 취약점 유형이 end-to-end 재현을 요구하고 안전한 환경이 준비된 경우
- container 내부에 대상과 의존성을 구성하고 공격 입력부터 observable effect까지 재현
- 재현 명령·환경·입력·관찰 결과·제한을 PoC artifact로 정리

### 승인된 계획의 수신과 실행 순서

Verification Agent가 `LIMITED_REPRO | FULL_REPRO`를 선택하고 `ReproductionPlan`을 생산한다. R7은 아래 구성 요소의 설계·구현 담당 역할이며 mode 선택, 계획 생산 또는 실행 주체를 뜻하지 않는다.

| 실행 입력 | 실행 전 확인할 조건 |
|---|---|
| `ReproductionPlan` | `COMMITTED`된 exact record이며 현재 가설·`workspace_id`·`commit_id`와 일치 |
| `RUN_SANDBOX` ActionDecision | Runtime Validator가 요청자·현재 work·상태·예산·exact plan reference를 확인한 `ALLOW + UNUSED` decision |
| sandbox profile과 image | 계획·action의 `sandbox_profile_ref`, image digest, tool·file·network·resource 범위가 고정되어 있으며 Sandbox Controller가 세부 정책을 검사 |
| plan closure | `hypothesis_ref`, 모든 step의 `command_ref`·`attack_input_refs`, `cleanup_policy_ref`가 action input에 빠짐없이 포함 |

실행은 다음 순서를 따른다.

1. Runtime Validator가 요청자·현재 work·상태·예산·exact plan reference를 검사하고 `RUN_SANDBOX`의 `ALLOW + UNUSED` ActionDecision을 만든다. 이 허가는 Sandbox 정책 통과나 Docker 실행 성공을 뜻하지 않는다.
2. Sandbox Controller 호출 직전 trusted 실행 runtime이 requester identity·권한, state version, 남은 budget, exact input·config reference와 `valid_until`을 다시 확인한다. 하나라도 달라졌으면 decision을 `UNUSED -> EXPIRED`로 바꾸고 실행하지 않는다.
3. 모두 그대로이면 runtime이 decision을 `UNUSED -> USED`로 compare-and-set claim한다. claim에 실패하면 실행하지 않으며, 성공한 exact USED decision revision과 계획만 Sandbox Controller에 전달한다.
4. Sandbox Controller가 image·command·file·network·resource·cleanup 정책을 한 번 검사하고 exact `sandbox_policy_decision` record를 저장한다. `DENY`이면 Sandbox Runner를 호출하지 않고, `ALLOW`이면 record에 연결된 exact 계획만 Runner에 전달한다.
5. Sandbox Runner는 `ReproductionPlan.steps` 순서와 계획에 있는 `command_ref`·`attack_input_refs`만 실행한다. Runner runtime은 실제 `step_id`·command·공격 입력·상태·관측을 append-only `SandboxStepLog`에 기록한다.
6. 성공·실패·취소 여부와 관계없이 Sandbox Runner가 exact `cleanup_policy_ref`에 따라 정리를 시도하고 Sandbox runtime이 결과를 기록한다.
7. 비-LLM Result Assembler가 plan, 최초 USED claim decision revision, Controller 정책 판정, Runner 호출 여부, 실제 환경, step log, PoC, 관측과 cleanup을 같은 attempt의 exact reference로 연결한 `DynamicReproductionResult` 후보를 만든다.
8. `SAVE_RESULT`가 실행 전 승인 내용과 정책 판정·실제 환경·Runner log·PoC·cleanup 조합을 다시 대조한다. 같은 결과를 가리키는 atomic commit이 완료된 뒤에만 Verification Agent가 결과를 읽는다.

누락되거나 맞지 않는 reference를 Sandbox Controller나 Sandbox Runner가 추측해 채우거나, 계획 밖 command·공격 입력으로 대체해서는 안 된다. 실행 전 불일치는 실행하지 않고, 실행 뒤 불일치는 결과를 `COMMITTED`하지 않는다.

### Controller 정책 판정 record

`action_decision_ref`와 `policy_decision_ref`는 서로 다른 판단을 가리킨다. 전자는 Runtime Validator가 현재 권한·상태·예산에서 Controller 호출을 허가한 `RUN_SANDBOX` USED decision이고, 후자는 Controller가 실제 Sandbox 정책을 검사해 만든 exact `sandbox_policy_decision` record다. Runtime 허가를 정책 통과로 해석하거나 두 reference를 서로 대신 사용하지 않는다.

Controller 정책 판정 record는 최소한 다음 내용을 다시 검증할 수 있어야 한다.

- 현재 analysis·workspace·commit·hypothesis·attempt identity와 exact `action_decision_ref`
- 검사한 `ReproductionPlan`의 exact record reference·content hash와 전체 plan closure
- Sandbox profile exact revision, 적용한 policy revision과 image digest
- command/tool, file/mount, network, resource/time/process, non-root와 cleanup 항목별 `ALLOW | DENY` 결과
- secret·host path·내부 정책 내용을 노출하지 않는 안정적인 reason code와 redacted 거절 설명
- 최종 `ALLOW | DENY` 결과와 `ALLOW`일 때 Runner에 전달한 exact plan reference·content hash

`policy_decision_ref`는 이 immutable record를 가리킨다. `failure_reason=POLICY_BLOCKED`이면 반드시 존재하고 final decision은 `DENY`여야 한다. Controller 판단 전에 취소되어 record가 생성되지 않은 `CANCELLED`에서만 `null`을 허용한다. Result Assembler가 이 reference를 결과에 넣고, `SAVE_RESULT`는 plan·profile·policy revision·Runner handoff와 record가 일치하지 않으면 결과를 `COMMITTED`하지 않는다.

### 실행 경계

- 같은 `workspace_id`와 `commit_id`, 승인된 Docker image/digest 사용
- Verification이 생산하고 Runtime Validator가 schema·reference·호출 권한·상태·예산을 확인해 `COMMITTED`한 `ReproductionPlan`에 mode, exact 가설, 단계별 command·공격 입력과 정리 정책 reference를 고정하고 `RUN_SANDBOX.input_refs`에 전체 계획 closure를 포함
- Runtime Validator는 `RUN_SANDBOX` 요청자의 권한·상태·예산과 exact 계획 reference만 확인하며 image·command·file·network·resource·cleanup 정책을 다시 판단하지 않음
- Sandbox Controller가 image digest, command/tool allowlist, mount·file path, default-deny network, resource/time/process, non-root와 cleanup 정책을 검사해 exact 정책 판정을 저장하고 통과한 계획만 Runner에 전달
- Sandbox Runner는 Controller의 `ALLOW` record에 연결된 exact 계획만 실행하고 임의로 정책·명령·입력을 바꾸지 않음
- 비-LLM Result Assembler만 같은 attempt의 exact 정책 판정·환경·step log·PoC·cleanup reference를 `DynamicReproductionResult`로 조립
- Docker build와 실행은 분석용 `CodeWorkspace`를 직접 수정하지 않고 sandbox 내부 복사본에서 수행
- 기본 network deny, resource/time/process 제한, non-root와 read-only mount 우선
- host socket, host secret, production credential과 범위 밖 target 접근 금지
- 동적 결과의 exit code, stdout/stderr reference, artifact hash와 hypothesis 연결 저장
- Sandbox 실행 log는 실제 `step_id`·command·공격 입력 reference를 승인 계획과 연결하고 계획에 없는 단계나 입력을 실행하지 않음
- 환경 구축 실패와 취약점 반증을 구분
- 실행 불가능·정책 차단·계획 변경이 필요하면 Sandbox Controller나 Sandbox Runner가 상태와 이유를 반환하고, Verification Agent가 필요성을 다시 판단해 새 plan revision과 새 실행 요청을 만든다.

### 재실행과 stale 결과

| 상황 | Sandbox 구성 요소와 runtime의 처리 | Verification에 전달 |
|---|---|---|
| 정상 실행 | current plan과 최초 USED claim decision revision의 exact 단계만 실행하고 log·cleanup·result를 atomic commit | `COMMITTED`된 결과만 전달 |
| exact 실행 조건이 같은 일시 오류 | sandbox profile·policy revision, image digest, command/tool 허용 범위, file/mount/network 범위, resource/time/process limit, cleanup policy와 나머지 plan closure reference가 모두 동일한 일시적 runtime·Runner 오류일 때만 기존 plan을 재사용할 수 있다. 기존 attempt와 결과는 보존하고 새 attempt·새 `RUN_SANDBOX` action·decision·새 Controller 정책 판정으로 실행하며 이전 USED decision과 정책 판정은 재사용하지 않는다. | 새 attempt의 확정 결과만 전달 |
| profile·policy·plan closure 변경 | 위 exact reference 중 하나라도 바뀌면 기존 plan을 재사용하거나 수정하지 않는다. 기존 실패·차단 결과를 보존하고 Verification이 변경 조건을 반영한 새 `ReproductionPlan`을 생산한다. trusted runtime이 새 plan을 `COMMITTED`한 뒤 새 work generation·attempt·`RUN_SANDBOX` action·decision을 만들고 Controller가 새 exact 정책 판정을 저장한다. | 새 plan과 그 실행·정책 승인에 연결된 `COMMITTED` 결과만 전달 |
| 환경·실행·관측·timeout 실패 | 완료한 단계와 관측, 정확한 failure reason, limitations와 cleanup 상태를 기록 | 실패 사실을 전달하되 반증으로 변환하지 않음 |
| 취소·supersede·revision 불일치 | 실행 전이면 시작하지 않고, 실행 뒤 늦게 도착한 log·result는 `STALE_RESULT`로 commit을 거절 | 전달하지 않음 |

retry 여부와 새 plan 생성은 Verification Agent와 trusted runtime의 현재 work·budget·policy 판단을 따른다. 정책 차단은 일시적 실행 오류로 취급해 자동 retry하지 않는다. 모든 attempt의 실패·차단·성공 결과와 Controller 정책 판정은 append-only로 보존하며 새 record로 이전 record를 덮어쓰지 않는다. Sandbox Controller와 Sandbox Runner는 숨은 추가 실행을 시작하거나 이전 ActionDecision·정책 판정을 다른 attempt에 재사용하지 않는다.

### 동적 결과 artifact 연결과 역할

`DynamicReproductionResult`의 artifact reference는 모두 같은 analysis·workspace·commit·hypothesis·attempt에 속한 exact `StoredDataRef`다. Result Assembler는 “latest”를 다시 조회하거나 다른 attempt의 artifact를 섞지 않는다.

- `poc_ref`: 이번 재현과 연결된 exact `poc_bundle`. 없거나 필요하지 않으면 `null`이며 존재만으로 실행·성공을 뜻하지 않는다.
- `policy_decision_ref`: Controller의 exact `sandbox_policy_decision`. Controller 판단 전에 취소된 경우를 제외하고 존재하며 `POLICY_BLOCKED`이면 필수다.
- `runner_invoked`와 `steps_ref`: Runner 미호출이면 `false + null`, 호출했으면 첫 단계 전 실패를 포함해 `true + exact SandboxStepLog`다.
- `environment_created`와 `environment_ref`: 실제 환경 미생성이면 `false + null`, 생성했으면 계획용 설정이 아닌 이번 attempt의 exact `sandbox_environment`를 가리킨다.
- `cleanup_required`와 `cleanup_status`: 정리 대상이 없을 때만 `false + NOT_REQUIRED`이고, 하나라도 있으면 `true + SUCCEEDED | FAILED`다.

Controller는 정책 판정을, Runner runtime은 단계 log를 생산한다. Sandbox runtime은 실제 환경과 cleanup 결과를 기록하고, 승인된 PoC 생성 담당은 exact PoC 묶음을 만든다. 비-LLM Result Assembler만 이 reference와 상태를 결과로 조립한다. Verification Agent는 `COMMITTED` 결과를 정적·찬반 근거와 함께 읽어 최종 판정하며, artifact나 동적 결과를 직접 만들거나 수정하지 않는다.

### 정책 차단 결과

Sandbox Controller가 정책을 거절하면 Runner를 호출하지 않으므로 실행 단계 log인 `SandboxStepLog`를 만들지 않는다. 이 경로의 `DynamicReproductionResult`는 다음 불변조건을 만족해야 한다.

- `status=BLOCKED`, `failure_reason=POLICY_BLOCKED`
- exact `policy_decision_ref`가 필수이고 가리키는 final decision은 `DENY`
- `runner_invoked=false`, `steps_ref=null`
- 실제 공격 입력과 관측이 없으므로 `attack_input_refs=[]`, `observation_refs=[]`
- 실제 환경을 만들지 않았으면 `environment_created=false`, `environment_ref=null`; 만들었으면 `true`와 exact `environment_ref`
- `hypothesis_outcome=INCONCLUSIVE`, `hypothesis_evidence_refs=[]`, `hypothesis_disproved=false`, `disproof_evidence_refs=[]`
- Sandbox 자원을 만들지 않았다면 `cleanup_required=false`, `cleanup_status=NOT_REQUIRED`
- 정책 검사 전에 생성된 PoC가 있으면 exact `poc_ref`를 남길 수 있지만 실행이나 재현 성공으로 해석하지 않음

Controller가 정책 검사 준비 중 Sandbox 자원을 하나라도 만들었다면 exact `cleanup_policy_ref`에 따라 정리를 시도하고 `cleanup_required=true`, `cleanup_status=SUCCEEDED | FAILED`를 기록한다. Runner를 호출한 경우에는 정책 차단 경로가 아니라 실제 실행 경로이므로 `runner_invoked=true`와 exact `SandboxStepLog`를 남기고, 정리 대상이 있으면 cleanup을 수행한다. `SAVE_RESULT`는 `runner_invoked`·`environment_created`·`cleanup_required`와 nullable reference·cleanup 상태의 조합, `POLICY_BLOCKED`의 exact 정책 판정을 함께 확인한다.

### 동적 재현 상태와 실제 반증

동적 재현 상태는 `NOT_REQUESTED | RUNNING | SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED`다. 실행이 끝난 결과는 `DynamicReproductionResult.status`에 `SUCCEEDED | PARTIAL | FAILED | BLOCKED | CANCELLED` 중 하나를 기록한다.

- 필수 환경을 만들지 못해 대상 애플리케이션이나 관련 공격 경로를 실행하지 못하면 `FAILED + ENVIRONMENT_SETUP`이다.
- 공격 경로를 일부 실행하고 신뢰할 수 있는 관측을 하나 이상 얻었지만 운영환경 차이 등으로 전체 확인이 부족하면 `PARTIAL + NONE`이다. 이때 `hypothesis_outcome=INCONCLUSIVE`이고 `hypothesis_evidence_refs`와 `limitations`가 각각 하나 이상 있어야 한다.
- `SUCCEEDED`는 계획한 필수 단계와 관측을 끝냈다는 실행 상태다. 관측이 가설을 지지했는지, 반증했는지, 결론을 주지 못했는지는 `hypothesis_outcome`에 따로 기록한다.
- `hypothesis_outcome`은 `SUPPORTED | DISPROVED | INCONCLUSIVE`이며 Verification verdict가 아니다. `SUPPORTED | DISPROVED`는 실제 관측을 가리키는 `hypothesis_evidence_refs`가 필요하다.
- `DISPROVED`일 때만 `hypothesis_disproved=true`와 비어 있지 않은 `disproof_evidence_refs`를 사용한다. 반증 근거는 일반 가설 근거 목록에도 포함한다.
- `FAILED | BLOCKED | CANCELLED`, 실행하지 못함, 빈 출력과 exit code만으로는 `DISPROVED`, `hypothesis_disproved=true` 또는 `FALSE`를 만들 수 없다.

동적 결과 상태와 공통 실행 상태는 뜻이 다르다. `DYNAMIC_REPRO`의 `PARTIAL`은 신뢰 관측과 `limitations`를 가진 `DynamicReproductionResult` 자체가 누락 범위를 설명하므로 실제 오류가 없으면 `AnalysisError`나 `DataGap`을 만들지 않는다. `BLOCKED + POLICY_BLOCKED`는 정책에 막힌 사실을 Sandbox가 정상적으로 기록한 종료 결과이므로 공통 `WorkExecutionState`는 `SUCCEEDED`로 끝난다. 여기서 `SUCCEEDED`는 요청 처리가 완료되었다는 뜻일 뿐 재현 성공이나 가설 지지를 뜻하지 않는다. retry·승인·입력을 기다리는 경우에만 공통 상태 `BLOCKED`를 사용한다. `CANCELLED`는 취소 결과와 공통 취소 상태를 같은 atomic transition에서 저장하고, 취소 뒤 늦게 도착한 결과는 격리한다.

모든 종료 결과는 `DynamicReproductionState.dynamic_result_ref`, `WorkExecutionState.output_refs`와 `TransitionCommit.output_refs`가 같은 `DynamicReproductionResult.record_id`를 가리킬 때만 Verification에 전달한다. Verification Agent는 이 결과를 정적·찬반 근거와 함께 읽어 최종 `TRUE | FALSE | HOLD`를 결정한다.
- Sandbox Controller는 exact 정책 판정을 저장하고 `ALLOW`인 계획만 Runner에 전달한다. Runner runtime은 `SandboxStepLog`를 생산하고, 비-LLM Result Assembler는 정책 판정·Runner 호출·실제 환경·step log·PoC·cleanup을 `DynamicReproductionResult`로 조립한다. 결과 저장 전 `SAVE_RESULT`가 이 조합과 승인 계획을 다시 대조하며, Verification Agent는 `COMMITTED` 결과를 소비할 뿐 artifact나 동적 결과를 직접 생산하지 않는다. Sandbox는 outcome까지만 기록하고 Verification Agent가 limitations와 정적·동적·찬반 근거를 함께 보고 최종 `TRUE | FALSE | HOLD`를 결정한다.

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
