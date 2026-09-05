# 검증과 동적 재현

## 쉽게 말하면

검증 Agent가 배정된 가설 안에서 코드·찬성·반대·동적 근거와 Gate 보완 흐름을 직접 관리하는 과정입니다.

**상세 기준:** [04. 검증과 동적 재현](../04-verification-and-dynamic-reproduction.md)

모르는 단어는 [쉬운 용어집](../../GLOSSARY.md)에서 확인하세요.

## 코드 위치와 우회를 함께 확인하는 검증

검증 Agent는 가설에 연결된 코드 요소·위치·경로에서 호출하는 함수, 호출되는 함수, 데이터 흐름, 인증·권한 검사와 요청 경로를 조회합니다. 실제로 확인한 사실과 아직 확인하지 못한 가정을 나눕니다. 입력 검사·안전 처리·인증·권한·소유권이 공격을 막는 조건인지, 우회 경로가 있는지, 다른 공격에 필요한 능력과 영향 확대 후보가 있는지 기록합니다.

새 endpoint, sink, 권한 경계 또는 독립 영향은 `HypothesisProposal(origin=VERIFICATION)`으로 분리하고 trusted validation·전역 등록 뒤 새 Verification에서 다시 검증한다.

## Debate 모드

- `BASIC`: Verification이 직접 찬반을 검토하는 격리된 평가 전용 모드
- `CONDITIONAL_DEBATE`: trigger가 있을 때 Pro/Con을 부르는 격리된 평가 전용 모드
- `ALWAYS_DEBATE`: 모든 유효 가설에 Pro/Con을 부르는 운영의 유일한 허용 모드

운영에서는 예산 부족을 이유로 Pro/Con을 생략하지 않습니다. `BUDGET_EXCEEDED`로 현재 검증 작업을 중단하고, 새 예산이 승인된 작업에서 다시 진행합니다. 평가 모드의 BASIC·조건부 결과는 Gate, Primitive 또는 보고서 입력으로 사용하지 않습니다.

평가용 `CONDITIONAL_DEBATE`는 versioned 설정의 `CONFLICTING_EVIDENCE | HIGH_IMPACT_OR_COST | INITIAL_HOLD | AUTH_OR_SANITIZER_BYPASS | ONE_SIDED_EVIDENCE | REVISE_ALTERNATE_PATH` trigger를 사용합니다. 충족된 code는 `debate_triggers`에 기록합니다. 아무 trigger도 충족하지 않으면 `debate_skip_reason=NO_TRIGGER_MATCH`, BASIC이면 `MODE_BASIC`을 기록합니다. 실제 Pro/Con을 실행하면 skip reason은 `null`입니다.

Verification은 Pro와 Con을 부르기 전에 같은 가설·proposal·workspace·commit·코드 경로·Context·정적 근거·인증/방어 로직·반증 질문·검증 항목·`PlaybookPolicy`·`VerificationPlaybook`·`PlaybookApplication`을 공통 입력 snapshot으로 고정하고 `debate_input_hash`로 식별합니다. 두 Agent는 같은 application의 질문 ID 집합을 사용하고 서로의 결론·출력·session은 받지 않습니다. 각 Agent는 별도 child work·call identity와 `parent_session_ref=null`인 독립 `NEW` session에서 병렬 실행됩니다. trusted prompt builder는 공통 reference와 역할별 instruction만으로 prompt를 만들며, 상대 결과를 prompt·context·parent/predecessor·저장소 조회·tool 입출력으로 전달하면 `CROSS_ROLE_INPUT_DENIED`로 차단합니다.

Pro와 Con은 각각 exact `EvidenceAgentResult`를 저장합니다. 두 child work가 모두 성공하고 두 결과가 schema-valid·COMMITTED이며 같은 부모 Verification·generation·`debate_input_hash`를 가리킬 때만 합성합니다. final `VerificationResult`는 `pro_evidence_ref`와 `con_evidence_ref`로 두 결과를 정확히 하나씩 연결합니다.

한쪽이 실패·timeout·인증 실패·빈 출력이면 다른 한쪽만으로 운영 final verdict를 만들지 않습니다. 재시도 가능 시 실패 child와 부모 Verification을 `BLOCKED`, 가설을 `VERIFYING`으로 유지하고 실패 역할만 새 identity·`NEW` session으로 재시도합니다. retry가 성공해 current 결과 두 개가 모여야 join을 재개합니다. 시도 소진 또는 복구 불가능 시 실패 child를 먼저 확정하고 부모 Verification과 가설을 `FAILED`로 끝내며 `verification_result_ref=null`을 유지합니다. 공통 입력 revision이 바뀌거나 부모 종료 뒤 늦게 도착한 결과는 `STALE_RESULT`로 격리합니다. 어느 실패도 `FALSE | HOLD` 근거로 사용하지 않습니다.

token과 전체 시간·판정 변화·HOLD 해소·새 후보 수는 `VerificationMetrics`에, 역할별 호출 수·상태·retry·failover·provider·session·실제 usage는 `LLMInvocationLog`에 기록합니다. R8은 이 기록을 비교 평가에 사용하지만 개별 실행이나 verdict를 결정하지 않습니다.

## 검증 플레이북

공통 및 웹 취약점 6종의 구체적인 확인 항목은 [R6 검증 플레이북](../verification-playbooks.md)을 따릅니다. 플레이북은 누락을 줄이는 참고 절차이며 점수표나 자동 판정표가 아닙니다.

운영에서 어떤 유형별 플레이북을 사용할지와 질문을 어떻게 적용할지는 아래 `판정과 동적 재현` 절의 `PlaybookPolicy`·`PlaybookApplication` 규칙을 따릅니다.

## 판정과 동적 재현

- `TRUE`: 명시된 경로와 전제가 evidence로 지지되고 현재 generation의 실행 성공·validated PoC가 있음
- `FALSE`: named falsification이 가설을 반증함
- `HOLD`: 핵심 문맥·환경·조건이 부족하거나 충돌함

판정 뒤 흐름도 다릅니다. `FALSE`는 terminal이며 Primitive와 Chaining으로 가지 않습니다. `HOLD`는 `required_primitive_candidates`가 하나 이상일 때만 후보 전체를 `inputs`로, `result=null`로 가진 Primitive를 Gate 없이 저장합니다. 후보가 없으면 Primitive와 Chaining work를 만들지 않고 HOLD 처리를 끝냅니다. `TRUE`는 validated PoC와 R5-01이 그 exact Verification에 맞춰 만든 current `CWELabel`을 Technical Gate가 `ACCEPT`한 뒤 정책 확인으로 갑니다. 금지 테스트 위반이 확정되지 않아 current admission이 `ALLOW`인 경우에만 제공 능력별 `result` Primitive가 됩니다. 다른 Rule Scope 판단은 Reporter만 제어합니다.

### verdict 이후 수명주기

- `FALSE`: Primitive 후보·Gate·Chaining 없이 종료합니다.
- `HOLD`: `required_primitive_candidates`가 하나 이상일 때만 후보 전체가 `inputs`이고 `result=null`인 Primitive 하나를 Gate 없이 저장합니다. 목록이 비어 있으면 Primitive와 Chaining work를 만들지 않고 HOLD 처리를 끝냅니다.
- final `TRUE`: current generation의 성공한 동적 결과·validated PoC와 current `CWELabel`을 갖춘 뒤 Technical Gate로 갑니다. Technical `ACCEPT`와 current `PrimitiveAdmissionDecision.decision=ALLOW` 전에는 result Primitive나 Chaining 입력이 아닙니다.
- Technical `REVISE`: 같은 ACTIVE Verification owner가 새 work·generation·result revision에서 다시 검증하며 과거 동적 결과·PoC·CWE·Gate·admission 자격을 재사용하지 않습니다.
- admission `ALLOW`: provided 후보마다 `result`가 있는 Primitive 하나를 만들고, 각 Primitive의 `inputs`에는 같은 TRUE의 required 후보 전체를 복사합니다.
- admission `DENY`: result Primitive와 Chaining을 차단하지만 부모 verdict를 바꾸지 않습니다.
- Rule Scope의 범위·영향·보고 가능성 실패는 Reporter를 차단할 수 있지만, current admission이 `ALLOW`이면 내부 Chaining 자격은 유지됩니다.

R6는 후보와 Gate action·exact reference를 만들고, trusted runtime이 commit·current pointer·Primitive 저장과 `PrimitiveIndexState` 갱신을 수행합니다. Chaining은 같은 workspace·commit, entity 또는 코드 흐름 연결, 권한 조건, 순서, 합산 restrictions와 실제 근거를 확인해 `TRUE + HOLD`와 `TRUE + TRUE`만 검사합니다. `draft_id`는 매칭 기준이 아니며, 매칭이 성립한 뒤 해당 input을 `PrimitiveMatchCandidate.matched_input_id`로 지목할 때만 사용합니다.

Chaining 결과를 저장하기 직전에 사용한 Primitive와 `source_primitive_match_id` 계보의 모든 result Primitive가 current admission `ALLOW`인지 다시 확인합니다. 하나라도 stale이거나 `DENY`이면 `STALE_RESULT`로 거절하고 새 child hypothesis를 만들지 않습니다. 기존 부모 verdict는 변경하지 않습니다.

판정에는 최소 근거가 필요합니다. TRUE는 핵심 공격 경로와 필요한 조건을 지지하는 근거가 있어야 합니다. FALSE는 이름이 있는 반증 질문이 실제 근거로 `DISPROVED`된 경우에만 가능합니다. 오류·timeout·정보 부족·Sandbox 실패는 FALSE 근거가 아닙니다. HOLD는 판단에 필요한 조건이나 환경이 아직 부족하다는 뜻입니다.

### Chaining 자식 가설의 검증 시작점 복구

`origin=CHAINING` 자식 proposal은 `target_entities`, `target_locations` 또는 `suspected_path`가 비어 있을 수 있습니다. 이 경우 Verification은 exact proposal의 `source_primitive_match_id`로 exact `PrimitiveMatchCandidate`를 찾습니다.

그다음 `upstream_result_ref`가 가리키는 Primitive의 `result.entity_refs`, `downstream_input_ref`가 가리키는 Primitive에서 `draft_id == matched_input_id`인 입력의 `entity_refs`, 그리고 아직 충족되지 않은 나머지 `inputs[].entity_refs`를 확인합니다. 매칭된 downstream input의 `entity_refs`는 두 Primitive가 실제로 결합하는 코드 지점을 확인하는 데 사용합니다.

`matched_input_id`는 입력 항목의 ID일 뿐 코드 위치가 아닙니다. 따라서 ID, 권한 조건과 근거만 확보해서는 복구가 완료된 것으로 보지 않습니다. 현재 `proposal.meta.workspace_id`와 `proposal.meta.commit_id`에 속하는 유효한 entity 또는 location을 최소 하나 이상 확보해야 합니다.

계보가 끊겼거나, 매칭된 downstream input을 찾을 수 없거나, 유효한 entity 또는 location을 복구하지 못하면 proposal 등록과 Verification 배정을 거절합니다. 이미 작업이 시작됐다면 final `VerificationResult`를 만들지 않고 verdict 없이 중단합니다.

proposal, match candidate, 부모 Primitive 또는 복구한 reference 중 하나라도 다른 workspace·commit을 가리키면 해당 reference만 빼고 계속하지 않습니다. 계보 전체를 유효하지 않은 입력으로 처리합니다. 정상적으로 시작점을 복구한 경우에도 부모 verdict를 자식에게 물려주지 않고, 현재 코드에서 Context를 다시 조회하여 자식 가설을 처음부터 검증합니다.

기본 Context가 부족하면 검증 Agent가 같은 workspace·commit을 기준으로 추가 Context를 요청합니다. 조회 실패·timeout·권한 오류는 `AnalysisError`로, 그 때문에 확인하지 못한 범위는 `DataGap`으로 기록하며 오류 자체를 verdict 근거로 사용하지 않습니다. 일부 조회가 실패했더라도 제한 retry·대체 조회·다른 정상 근거로 모든 `ValidationCheck`, 반증 질문과 운영 Pro/Con을 완료했다면 실제 근거에 따라 final `TRUE | FALSE | HOLD`를 만들 수 있습니다. 하나라도 완료하지 못했다면 final `VerificationResult`를 만들지 않습니다. 재시도 가능하면 Verification work를 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지합니다. 복구할 수 없거나 재시도 한도를 소진하면 work와 가설 처리 상태를 `FAILED`로 끝냅니다. 정상 검증을 모두 마친 뒤에도 부족한 조건이 남는 경우에만 실제 근거와 `unresolved_conditions`를 연결해 `HOLD`로 판정할 수 있습니다. 운영 Pro/Con 전에 예산이 부족한 경우도 `BUDGET_EXCEEDED`로 작업을 중단하고 final verdict를 저장하지 않습니다.

`initial_verdict`는 중간 판단이며 운영 Gate·Primitive·보고서 입력으로 사용할 수 없습니다. initial TRUE이면 동적 근거가 별도로 필요하지 않아도 PoC 확인을 요청합니다. final TRUE는 독립 Pro/Con과 현재 generation의 성공한 동적 결과·validated PoC를 종합한 최종 판단입니다.

R8의 versioned evaluation corpus는 우선 지원할 유형을 정하는 평가 근거입니다. 운영에서 실제 허용할 유형과 exact 플레이북 수정본은 사람이 승인한 `PlaybookPolicy`로 확정합니다. 플레이북과 유형 mapping 후보는 R6 담당이 작성하지만 등록만으로 운영 지원 목록을 바꾸지는 못합니다.

검증 작업을 등록할 때 trusted runtime은 가설의 exact proposal에 유형 후보가 하나이고 승인 policy에 같은 mapping이 있을 때만 유형별 플레이북을 선택합니다. 그 외에는 공통 플레이북을 사용합니다. 선택한 policy·playbook·이유와 플레이북 질문에 새로 발급한 ID는 `PlaybookApplication`으로 작업 입력에 고정합니다. 직접 검증, Pro, Con, 최종 판정과 결과 저장은 모두 같은 application을 사용하며, `VerificationResult`는 exact `playbook_ref`와 `playbook_application_ref`를 함께 기록합니다.

검증 도중 새 policy나 플레이북 revision이 등록돼도 진행 중인 검증에는 섞지 않습니다. 같은 work의 재시도는 처음 고정한 application과 질문 ID를 유지합니다. 새 Verification work 또는 generation은 새 application과 질문 ID를 만들며 이전 결과를 섞지 않습니다.

가설 자체의 반증 질문과 이번 `PlaybookApplication`의 질문에는 모두 전역 `question_id`가 있습니다. 플레이북의 `template_key`는 사람이 읽는 이름일 뿐 실제 질문 ID가 아닙니다. 최종 결과는 두 질문 집합을 빠짐없이 정확히 한 번씩 처리하고 질문마다 `DISPROVED`, `NOT_DISPROVED`, `INCONCLUSIVE` 중 하나와 근거를 남깁니다. 실제 근거가 있는 `DISPROVED`가 하나 이상일 때만 `FALSE`가 가능합니다. `NOT_DISPROVED`는 반증하지 못했다는 뜻일 뿐 가설을 증명하지 않습니다.

가설의 각 필수 검증 항목에는 `validation_id`가 있습니다. final 결과는 같은 ID의 결과가 빠짐없이 한 번씩 있고, 모두 `COMPLETE`이며 실제 근거를 가리킬 때만 저장합니다. 하나라도 완료하지 못하면 final 판정을 만들지 않습니다. 재시도 가능하면 Verification work를 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지합니다. 복구할 수 없거나 재시도 한도를 소진하면 work와 가설을 함께 `FAILED`로 끝냅니다. 이 실패는 `FALSE`나 `HOLD`가 아니며 Gate 입력도 아닙니다.

Pro와 Con은 항상 별도의 새 대화에서 실행합니다. 상대 역할의 결론이나 대화를 이어받지 않으며, 실패 후 재시도나 provider 변경도 같은 역할의 새 대화로 시작합니다. Verification Agent만 두 결과를 함께 읽고 최종 판정을 만듭니다.

결과를 저장하기 전에는 결과 종류, 저장 담당 역할, 정확한 작업·시도·코드 버전, policy·playbook·application exact revision, 전체 질문 ID 집합과 후보 내용 hash를 함께 검사합니다. `TRUE`는 supporting evidence와 현재 generation의 `SUCCEEDED + SUPPORTED` 결과·validated `poc_ref`, `FALSE`는 근거가 있는 `DISPROVED`, `HOLD`는 `unresolved_conditions`와 정상 확인 근거가 필요합니다. 오류·timeout·빈 Context·예산 초과 상태만으로 어떤 final verdict도 저장할 수 없습니다. validated PoC 없는 TRUE는 저장과 Technical Gate 호출이 모두 차단됩니다.

| 요청 목적 | 뜻 |
|---|---|
| `POC_CONFIRMATION` | 정적·Pro·Con으로 initial TRUE가 된 가설을 실제 PoC로 확인 |
| `VERDICT_EVIDENCE` | 최종 판정에 꼭 필요한 실행 관측 확보 |

R6는 목적·재현 목표·필요 환경·Sandbox profile·관련 근거를 `DynamicReproductionRequest`로 만듭니다. R7 Agent는 이 exact 요청에서 `EnvironmentRequirements`와 mode·exact command가 없는 `ReproductionPlan`을 먼저 생산하고, 외부 경계를 통과한 뒤 Sandbox 안에서 PoC candidate를 만듭니다. 한 Verification generation에는 동적 work 하나만 허용합니다. Agent가 스스로 해결할 retry는 같은 attempt 또는 외부 대기 없는 새 attempt이고, 외부 설정·정책·승인·resource 변경을 기다릴 때만 `BLOCKED`입니다. Technical `REVISE`로 새 generation이 시작되면 한도를 새로 적용합니다.

Docker는 clean/non-root, network default-deny와 자원·시간 제한을 사용합니다. Runtime Validator와 Sandbox Controller가 current request/requirements와 외부 격리 경계를 확인합니다. Setup Automation이 recipe·image·container·cleanup을 맡고, R7 Agent는 Sandbox 안에서 command·PoC·관찰·재시도를 자율적으로 정합니다. Session Manager가 실제 event를 AgentLog에 기록하고 same-attempt validated PoC와 결과를 확정합니다.

`poc_candidate_ref`는 실행 전 스크립트·입력입니다. exact candidate 실행이 `SUCCEEDED + SUPPORTED`로 끝난 경우에만 validated `poc_ref`를 만듭니다. 생성 실패, 실행 실패, `DISPROVED | INCONCLUSIVE`에서는 `poc_ref=null`입니다. candidate와 실패 로그는 남겨도 최종 PoC로 부르지 않습니다.

`POC_CONFIRMATION` 또는 `VERDICT_EVIDENCE`가 `SUPPORTED`이면 R6는 정적·Pro·Con·동적 근거와 validated PoC를 합쳐 final TRUE를 만듭니다. 실제 반증이면 FALSE, 정상 실행했지만 결론이 부족하면 HOLD가 될 수 있습니다. PoC 생성·환경 구성·정책·실행 자체가 실패했다면 final verdict를 만들지 않습니다. Agent가 자체 해결할 수 있으면 같은 attempt에서 계속하거나 `RUNNING → READY → RUNNING`으로 새 retry attempt를 실행합니다. 외부 설정·정책·승인·resource 변경을 기다리는 경우에만 같은 work를 `BLOCKED`로 두고, 복구할 수 없거나 재시도 한도를 소진하면 `FAILED`로 끝내며 Gate를 호출하지 않습니다.

Technical Gate가 `REVISE`를 반환하면 같은 ACTIVE `VerificationAssignment` owner가 직접 받습니다. 프로그램은 새 generation의 Verification work와 `TERMINAL -> VERIFYING` 전이를 먼저 원자적으로 만들고, 필요한 Context·Pro/Con·정적 근거와 설명을 보완합니다. final TRUE를 다시 만들려면 새 generation의 동적 work와 validated PoC도 필요합니다. 새 final TRUE가 확정되면 R5-01 `CWE_LABELING`이 CWE 정렬을 다시 평가하고, 값이 같아도 새 Verification을 직접 가리키는 새 `CWELabel` revision을 만든 뒤 새 Gate work를 요청합니다. 이는 provider retry나 동일 입력 재투표가 아닙니다.

`status`는 실행 완료 정도이고 `hypothesis_outcome: SUPPORTED | DISPROVED | INCONCLUSIVE`은 관측과 가설의 관계입니다. 둘 다 최종 판정이 아닙니다. 실제 반증은 `DISPROVED`, `hypothesis_disproved: true`, 관측 근거가 함께 있어야 합니다. 생성·환경·실행 실패는 관측 반증이 아니므로 `FALSE | HOLD`로 바꾸지 않습니다. 저장 확정 marker와 request·plan·result·PoC reference가 모두 일치할 때만 Verification이 읽습니다. 상세 내용은 [검증과 동적 재현](../04-verification-and-dynamic-reproduction.md)을 따릅니다.


## R6 동적 요청과 결과 소비 요약

R6의 선택은 다음과 같습니다.

- 정적·Pro·Con만으로 `VerificationResult.initial_verdict=TRUE`이면 `DynamicReproductionRequest.purpose=POC_CONFIRMATION`을 한 번 요청합니다.
- 실행 관측 없이는 판정할 수 없으면 `DynamicReproductionRequest.purpose=VERDICT_EVIDENCE`를 한 번 요청합니다. 여기서 `DynamicReproductionResult.hypothesis_outcome=SUPPORTED`가 나오면 같은 `meta.attempt_id`에서 검증된 `poc_ref`를 `VerificationResult.verdict=TRUE`에 사용하므로 PoC 확인을 다시 요청하지 않습니다.
- 정적·Pro·Con으로 근거 있는 `VerificationResult.verdict=FALSE | HOLD`를 확정할 수 있으면 동적 요청을 생략할 수 있지만, validated `poc_ref`가 없는 `VerificationResult.verdict=TRUE`는 만들 수 없습니다.
- 한 `verification_generation`에는 동적 work를 하나만 허용합니다. Technical `REVISE`는 새 `verification_generation`이므로 `purpose`를 다시 정하고 새 work를 최대 한 번 요청합니다.

`DynamicReproductionResult.status=SUCCEEDED`와 `hypothesis_outcome=SUPPORTED`, 실제 `hypothesis_evidence_refs`, 같은 `meta.attempt_id`에서 검증된 `poc_ref`가 모두 있으면 `VerificationResult.verdict=TRUE` 후보입니다. `hypothesis_outcome=DISPROVED`, `hypothesis_disproved=true`, 실제 `disproof_evidence_refs`와 named falsification이 연결되면 `VerificationResult.verdict=FALSE` 근거입니다. `status=SUCCEEDED | PARTIAL`과 `hypothesis_outcome=INCONCLUSIVE`이면 `hypothesis_evidence_refs`, `limitations`, `VerificationResult.unresolved_conditions`를 기록할 수 있을 때 `verdict=HOLD` 후보입니다.

R6는 current `DynamicReproductionState.status=SUCCEEDED | PARTIAL | BLOCKED | FAILED | CANCELLED`에 연결된 `dynamic_result_ref`를 읽습니다. `DynamicReproductionState.dynamic_result_ref`, `WorkExecutionState.output_refs`, `TransitionCommit.output_refs`는 같은 exact `DynamicReproductionResult.meta.record_id`를 가리켜야 합니다. `WorkExecutionState.last_transition_commit_ref`는 이 결과를 확정한 `TransitionCommit.state=COMMITTED` revision을 가리켜야 합니다. `DynamicReproductionState.status=BLOCKED`는 외부 조치를 기다리는 비종료 상태이며 `finished_at=null`을 유지합니다.

결과 제출 중 `WorkExecutionState.status=RUNNING`이면 `DynamicReproductionResult.meta.attempt_id`를 `WorkExecutionState.active_attempt_id`와 비교합니다. R6가 current 반환 결과를 소비할 때는 `active_attempt_id=null`이므로 이 값과 비교하지 않고, 결과의 `meta.attempt_id`를 `last_transition_commit_ref`가 가리키는 `COMMITTED TransitionCommit.attempt_id` 및 해당 `WorkAttempt.attempt_id`와 비교합니다. attempt가 다르면 `ATTEMPT_NOT_ACTIVE`로 거절합니다.

고정 입력·`request_ref`·`verification_generation`이 다르면 `STALE_RESULT`, exact reference의 `record_id` 또는 `content_hash`가 다르면 `RECORD_REVISION_MISMATCH`로 거절합니다. 현재 `WorkExecutionState.state_version`은 `TransitionCommit.target_state_version`과 비교합니다. `StateTransition.expected_state_version=TransitionCommit.expected_state_version`, `StateTransition.new_state_version=TransitionCommit.target_state_version`, `target_state_version=expected_state_version+1` 관계를 위반하면 `STATE_VERSION_CONFLICT`로 거절합니다. `meta.workspace_id`, `meta.commit_id`, `meta.hypothesis_id`, `request_ref`, `purpose`와 `DynamicReproductionRequest.hypothesis_ref`도 현재 Verification과 exact match해야 합니다.

정책 차단·환경 구성·Agent·PoC 생성·실행 실패·timeout·취소는 verdict가 아닙니다. `DynamicReproductionResult.status=BLOCKED | FAILED | CANCELLED`와 `hypothesis_outcome=INCONCLUSIVE`를 기록하고 final `VerificationResult`와 Gate 요청을 만들지 않습니다. `BLOCKED`는 비종료 대기 상태이고 `FAILED | CANCELLED`는 종료 상태입니다.

R6는 `DynamicReproductionRequest.verification_assignment_ref`, `verification_generation`, `hypothesis_ref`, `purpose`, `initial_verdict`, `goal`, `environment_needs`, `sandbox_profile_ref`, `code_refs`, `static_evidence_refs`, `pro_evidence_ref`, `con_evidence_ref`를 기록합니다. `EnvironmentRequirements`, `ReproductionPlan`, recipe, command, payload와 PoC는 R7이 생산합니다.
