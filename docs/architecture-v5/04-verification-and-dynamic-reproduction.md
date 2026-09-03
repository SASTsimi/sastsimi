# 04. 검증과 동적 재현

- **이 문서는 무엇을 설명하나요?** 취약점 가설의 찬성·반대 근거를 확인하고 필요하면 Docker에서 재현하는 절차를 설명합니다.
- **누가 읽어야 하나요?** 검증·반박·플레이북과 동적검증·Sandbox 담당자가 우선 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** `TRUE / FALSE / HOLD` 판정 기준, 추가 근거 요청과 재현 범위를 확인합니다.

`Verification`은 가설을 근거로 확인하는 과정이고 `verdict`는 그 기술 판정입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## Verification의 목적과 제어권

Verification Agent는 배정받은 한 가설 안에서 검증 흐름 전체를 소유한다. 가설이 실제 코드 흐름과 실행 조건에서 성립하는지 검토하고 `TRUE | FALSE | HOLD`를 판정하며, 필요한 Context·Pro/Con·동적 재현 요청·보완 작업과 Gate 제출 시점을 선택한다. 제한 조건·우회 후보·필요 능력·제공 가능 능력·실질 영향의 상승 가능성도 함께 기록한다. R6는 재현 목적과 필요한 조건을 요청하지만 실행 환경·계획·PoC를 직접 만들지 않는다.

이 제어권은 실행 허가 권한이 아니다. Verification이 `REQUEST_DYNAMIC_REPRO` 등 다음 작업을 제안하면 비-LLM Runtime Validator가 `ActionRequest`, exact revision, 역할, 상태, 예산과 provider/session을 확인한다. R7이 환경·계획·PoC candidate를 만든 뒤 `RUN_SANDBOX`를 요청하며, 허가된 뒤에는 Sandbox Controller가 Docker 세부 정책을 검사한다. Controller가 승인한 exact 계획만 Sandbox Runner가 실행한다.

## 기본 검증 순서

1. 배정된 가설의 `workspace_id`, `commit_id`, entity, location과 suspected path를 확인한다.
2. `CodeContextRequest`로 caller/callee, data flow, auth guard와 route 문맥을 필요한 만큼 조회한다. 추가 Context 요청은 현재 가설과 같은 `workspace_id`·`commit_id`를 사용해야 한다. 조회 실패·timeout·권한 오류는 `AnalysisError`로, 그 때문에 확인하지 못한 범위는 `DataGap`으로 기록하며 오류 자체를 verdict 근거로 사용하지 않는다. 일부 조회가 실패했더라도 제한 retry·대체 조회·다른 정상 근거로 모든 `ValidationCheck`, 반증 질문과 운영 Pro/Con을 완료했다면 실제 근거에 따라 final `TRUE | FALSE | HOLD`를 만들 수 있다. 필수 Context 또는 운영 Pro/Con을 확보하지 못해 검증이 하나라도 미완료이면 final `VerificationResult`를 저장하지 않는다. 재시도할 수 있으면 work를 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지하며, 더 시도할 수 없으면 work와 `HypothesisProcessState`를 원자적으로 `FAILED`로 끝낸다. 운영 Pro/Con 전에 예산이 부족한 경우에도 `BUDGET_EXCEEDED`로 작업을 중단하고 final verdict를 저장하지 않는다. Context 부족이나 조회 실패를 `DISPROVED` 또는 `FALSE`로 변환하지 않는다.
3. observed fact와 assumption을 분리하고 각 `FalsificationQuestion.question_id`를 확인한다.
4. 운영 분석이면 Pro/Con Agent를 서로 독립된 NEW session으로 병렬 호출해 supporting/counter evidence를 모두 수집한다. BASIC 또는 조건부 debate는 격리된 평가 실행에서만 선택한다.
5. 정적·Pro·Con 근거로 initial verdict와 unresolved condition을 만든다.
6. initial TRUE이면 동적 근거가 별도로 필요하지 않아도 `purpose=POC_CONFIRMATION`을 요청한다. 최종 판정에 실행 근거가 필요하면 `purpose=VERDICT_EVIDENCE`를 요청한다.
7. R7의 실행 결과를 종합해 final verdict를 만든다. final TRUE에는 현재 generation의 재현 성공과 validated `poc_ref`가 반드시 필요하다. 정적·Pro·Con만으로 충분한 FALSE 또는 HOLD는 동적 요청 없이 확정할 수 있다.
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

최종 결과는 등록 가설의 모든 반증 질문에 `DISPROVED | NOT_DISPROVED | INCONCLUSIVE` 중 하나를 기록한다. 또한 모든 `validation_checks`를 같은 `validation_id`의 `ValidationCheckResult`로 정확히 한 번씩 답하고, 각 항목을 `COMPLETE`와 실제 근거 reference로 마쳐야 한다. 하나라도 빠지거나 `INCOMPLETE`이면 final `VerificationResult`를 저장하지 않는다. `DISPROVED`에는 실제 `evidence_refs`가 필요하고, `NOT_DISPROVED`는 가설이 참이라는 증거로 승격하지 않는다. `FALSE`는 적어도 하나의 근거 있는 `DISPROVED` 결과와 그 `question_id`를 설명하는 판정 이유가 있을 때만 허용한다. 오류·timeout·누락만으로는 `DISPROVED`나 `FALSE`를 만들지 않는다.

검증 절차를 끝내지 못했지만 재시도할 수 있으면 Verification work를 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지한다. 허용된 재시도를 소진했거나 복구할 수 없으면 failed work와 `HypothesisProcessState.status=FAILED`를 한 번에 확정하고 `verification_result_ref=null`로 둔다. 이 종료는 `HOLD`나 `FALSE`가 아니며 Gate로 보내지 않는다.

| 판정 | 최소 필수 근거 | 허용하지 않는 판정 이유 |
|---|---|---|
| `TRUE` | 현재 가설의 핵심 exploit path를 지지하는 정적·Pro·Con 근거, 현재 generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 validated `poc_ref` | 단순 추측, `NOT_DISPROVED`, validated PoC가 없거나 현재 generation과 다른 동적 결과 |
| `FALSE` | named falsification의 `question_id`, `outcome=DISPROVED`, 하나 이상의 실제 `evidence_refs`와 이를 연결하는 판정 이유 | 오류, timeout, 빈 Context, 예산 초과, Sandbox 실패 |
| `HOLD` | 하나 이상의 `unresolved_conditions`와 정상적으로 확인한 범위 및 결론을 막는 조건을 설명하는 실제 evidence reference | 취약점이 아니라는 의미로 사용하거나 PROVIDED 능력으로 승격 |

### HOLD와 실행 오류의 결정 기준

| 상황 | 처리 | final `VerificationResult` 저장 |
|---|---|---|
| 같은 workspace·commit에서 Context 조회가 정상 종료됐지만 필요한 정보가 부족함 | 부족한 내용을 `unresolved_conditions`에 기록하고 필수 검증을 계속한다. 필수 검증을 완료한 뒤에도 조건이 남으면 `HOLD`로 판정한다. | 가능 |
| 일부 Context 조회가 실패·timeout·권한 오류로 끝났지만 제한 retry·대체 조회·다른 정상 근거로 모든 필수 검증과 운영 Pro/Con을 완료함 | 실패 사건은 `AnalysisError`, 확인하지 못한 범위는 `DataGap`으로 남기고 오류가 아닌 실제 근거로 판정한다. | 가능 |
| Context 조회 오류 때문에 필수 Context 또는 운영 Pro/Con을 확보하지 못해 검증이 하나라도 미완료됨 | final 결과를 만들지 않는다. 재시도 가능하면 work는 `BLOCKED`, 가설은 `VERIFYING`으로 유지하고, 더 시도할 수 없으면 work와 가설 처리 상태를 원자적으로 `FAILED`로 끝낸다. | 금지 |
| 운영 Pro/Con을 시작하기 전에 예산이 부족함 | `BUDGET_EXCEEDED`로 현재 Verification work를 중단한다. Pro/Con을 생략한 final verdict를 만들지 않는다. | 금지 |
| 운영 Pro/Con 등 필수 검증은 완료했지만 추가 환경·Context·capability가 부족함 | 남은 조건을 `unresolved_conditions`에 기록하고 `HOLD`로 판정할 수 있다. | 가능 |

정상적으로 조회됐지만 결과가 비어 있거나 일부만 반환된 것은 정보 부족으로 처리한다. 요청 실패·timeout·권한 오류는 실행 오류지만, final 결과 허용 여부는 오류의 존재 자체가 아니라 모든 필수 검증의 완료 여부로 결정한다. Runtime은 오류를 verdict로 바꾸거나 미완료 검증 대신 `HOLD`를 만들지 않는다.

미지원 취약점 유형도 후속 Issue만 생성하고 현재 실행을 끝내서는 안 된다. 공통 플레이북으로 수행할 수 있는 검증을 먼저 진행하고, 정상 검증 후 유형별 정보가 부족하면 `HOLD`, 실행 자체가 실패하면 실행 오류를 기록한다. 그 상태를 기록한 뒤 유형별 플레이북 추가 Issue를 연결한다. 후속 Issue는 현재 실행 상태나 verdict를 대신하지 않는다.

### Initial verdict와 final verdict

`initial_verdict`는 기본 Context와 Verification Agent가 직접 확인한 사실을 바탕으로 만든 중간 판단이다. 운영 분석에서는 독립 Pro/Con과 필요한 동적 재현이 끝나기 전의 initial verdict를 Gate·Primitive·Reporter 입력으로 사용할 수 없다. 특히 initial TRUE는 PoC 확인을 시작하기 위한 중간 상태일 뿐 final TRUE가 아니다.

final `verdict`는 필요한 Pro/Con과 동적 결과를 포함해 현재 work에서 사용할 수 있는 모든 근거를 종합한 최종 판단이다. 모든 final TRUE는 현재 generation의 성공한 동적 재현과 validated PoC를 포함한다. initial verdict와 final verdict가 다르면 `verdict_rationale`에 변경 이유를 남긴다. 이 변화가 Debate로 인한 것이면 `VerificationMetrics.verdict_changed_after_debate=true`로 기록한다.

새 evidence나 Technical `REVISE`로 결과가 바뀌면 기존 record를 수정하지 않고 새 `VerificationResult` revision을 만든다. 과거 revision을 검토한 Gate 결과는 새 revision에 재사용하지 않는다.

### Verification `TRUE`와 Technical `ACCEPT`의 경계

Verification의 `TRUE`는 R6가 정적·Pro/Con 근거와 현재 generation의 성공한 동적 재현·validated PoC를 종합해 현재 가설의 핵심 공격 경로와 필요한 조건이 성립한다고 판정한 결과다.

Technical Evidence Gate의 `ACCEPT`는 R5가 exact final TRUE revision을 대상으로 evidence와 코드 경로의 연결, 동적 재현·PoC와 restriction, CWE와 다음 단계 전달 준비 상태가 충분한지 별도로 검토한 결과다.

따라서 R6가 `TRUE`를 만들었다고 해서 Technical `ACCEPT`가 자동으로 보장되지는 않는다. Technical Gate는 같은 verdict revision에 대해 `ACCEPT | REVISE | REJECT`를 반환할 수 있지만 기존 verdict를 직접 변경하지 않는다. `REVISE`가 반환되면 같은 ACTIVE Verification owner가 근거를 보완해 새 `VerificationResult` revision을 만든다.

## 취약점 유형별 검증 플레이북

지원 취약점 유형 목록은 R8의 versioned evaluation corpus에서 확정한다. 현재는 지원 목록이 확정되지 않았으므로 이번 설계에서는 모든 유형에 공통으로 적용할 플레이북 구조와 작성 규칙을 먼저 확정한다. 지원 목록이 확정되면 이 구조를 사용해 유형별 플레이북을 별도 revision으로 추가한다.

목록이 확정된 뒤 각 지원 취약점 유형은 같은 이름으로 식별 가능한 검증 플레이북을 가진다. 플레이북은 Agent에게 자유로운 결론을 요구하는 prompt가 아니라, 해당 유형에서 빠뜨리면 안 되는 확인 항목과 반증 질문을 정의한 실행 가능한 검증 절차다.

플레이북 후보는 R6 검증·반박·플레이북 담당이 작성하고, trusted playbook registry runtime이 schema와 revision을 검사해 변경 불가능한 record로 등록한다. Verification work를 등록할 때 trusted runtime은 지원 유형과 일치하는 current exact `TYPE_SPECIFIC` revision을 선택하고, 적용 가능한 유형별 플레이북이 없으면 current exact `COMMON` revision을 선택해 `WorkExecutionState.input_refs`에 고정한다.

Verification의 직접 검증, 독립 Pro/Con 실행, final 합성과 결과 저장은 모두 work에 고정된 동일한 플레이북 revision을 사용한다. 검증 도중 current revision이 변경돼도 진행 중인 work에는 새 revision을 섞지 않는다. 단순 retry는 기존 revision을 유지하고, 새 revision을 적용하려면 새 Verification work 또는 새 verification generation을 만들어야 한다.

각 플레이북에는 최소한 다음 항목을 기록한다.

| 항목 | 설명 |
|---|---|
| `vulnerability_type` | 플레이북이 다루는 취약점 유형 |
| 사전 조건 | 공격자가 먼저 만족해야 하는 권한·입력·환경 |
| source | 공격자 입력이나 제어 값이 시작되는 위치 |
| sink | 위험 동작 또는 영향이 발생하는 위치 |
| 경로 확인 | source에서 sink까지 이어지는 호출·데이터 흐름 |
| 방어 확인 | validator, sanitizer, canonicalization, 인증·인가와 권한 검사 |
| 반증 질문 | 무엇이 실제 근거로 확인되면 가설이 반증되는지 |
| 정적 evidence | 필요한 코드 위치·호출 관계·도구 결과 |
| 동적 evidence | 실행으로 확인해야 하는 조건과 observable effect |
| restriction | 공격이 가능한 범위를 제한하는 조건 |
| HOLD 조건 | 아직 해결되지 않으면 최종 판단을 보류해야 하는 조건 |

지원 목록이 확정되기 전에는 임의의 취약점 유형을 지원 대상으로 가정하지 않는다. 목록 확정 후에도 지원 목록에 없는 유형을 기존 플레이북에 억지로 맞추지 않는다. 필요한 검증 항목을 확정할 수 없으면 공통 플레이북으로 현재 실행을 먼저 처리한다. 정상적으로 필수 검증을 완료했지만 정보가 부족하면 `unresolved_conditions`와 `HOLD`를 기록한 뒤 후속 Issue를 연결한다. 실행 자체가 실패했다면 verdict 없이 실행 오류를 기록한 뒤 후속 Issue를 연결한다. 새로운 endpoint·sink·권한 경계·공격 단계·독립 impact가 발견되면 현재 verdict에 합치지 않고 material child proposal로 분리한다.

## Docker 동적 재현

동적 검증은 정적 판단을 대체하지 않고 특정 가설을 제한된 환경에서 실제로 확인한다. 모든 final TRUE에는 실행으로 확인된 PoC가 필요하므로 initial TRUE도 반드시 이 단계를 거친다.

### R6 요청과 R7 생산 책임

R6는 다음 항목을 가진 `DynamicReproductionRequest`를 만든다.

- `hypothesis_ref`와 현재 `verification_generation`
- `purpose: POC_CONFIRMATION | VERDICT_EVIDENCE`
- 재현 목표와 요청 이유
- 필요한 역할·권한·인증·데이터·service 같은 `environment_needs`
- 적용할 `sandbox_profile_ref`
- 관련 코드·정적·Pro·Con 근거 reference

`POC_CONFIRMATION`은 정적·Pro·Con으로 initial TRUE가 나온 뒤 실제 PoC로 확인하는 목적이다. `VERDICT_EVIDENCE`는 실행 관측이 있어야 최종 판정을 내릴 수 있을 때 사용한다. R6는 목적을 고르지만 실행 mode, `EnvironmentRequirements`, `ReproductionPlan` 또는 PoC를 생산하지 않는다.

R6는 `DynamicReproductionRequest`만 생산하고 R7은 `EnvironmentRequirements`, `ReproductionPlan`, PoC candidate와 `DynamicReproductionResult`를 생산한다.

R7은 요청을 읽고 exact `EnvironmentRequirements`를 확정하며 위험과 재현 범위에 맞는 `LIMITED_REPRO | FULL_REPRO` mode를 선택한다. 이어 명령·공격 입력·관측·cleanup을 고정한 `ReproductionPlan`과 실행 전 `poc_candidate_ref`를 만든다. 각 결과는 trusted runtime의 schema·reference·권한·예산 검사를 거쳐 `COMMITTED`된 뒤에만 다음 단계로 전달한다.

### generation당 한 번의 동적 재현 work

- 한 Verification generation에는 `DYNAMIC_REPRO` work를 하나만 등록한다.
- `POC_CONFIRMATION`과 `VERDICT_EVIDENCE`를 같은 generation에서 각각 별도 work로 실행하지 않는다.
- PoC 재작성·환경 수정·실행 재시도는 같은 `work_id`의 새 `attempt_id`다.
- Technical Gate `REVISE`는 새 Verification generation이므로 새 동적 재현 work 하나를 허용한다.
- 같은 generation의 중복 요청은 `hypothesis_id + verification_generation` 고유키로 차단한다.

### 실행 경계

- 같은 `workspace_id`와 `commit_id`, 승인된 Docker image/digest 사용
- R7이 생산한 current exact `EnvironmentRequirements`와 이를 가리키는 `ReproductionPlan`에 mode, exact 가설, 단계별 command·공격 입력·PoC candidate와 정리 정책 reference 고정
- Runtime Validator는 `RUN_SANDBOX` 요청자의 R7 권한·상태·예산, exact 계획과 current requirements revision만 확인
- Sandbox Controller가 image digest, command/tool allowlist, mount·file path, default-deny network, resource/time/process, non-root와 cleanup 정책을 검사하고 통과한 계획만 Runner에 전달
- Sandbox Runner는 실제 환경과 모든 requirement·Health Check를 기록하고 필수 항목이 모두 `MATCH`일 때만 공격 단계 실행
- Docker build와 실행은 분석용 `CodeWorkspace`를 직접 수정하지 않고 Sandbox 내부 복사본에서 수행
- host socket, host secret, production credential과 범위 밖 target 접근 금지
- 실제 `step_id`·command·공격 입력·exit code·stdout/stderr·artifact hash와 hypothesis 연결 저장
- 환경 구축 실패·필수 요구사항 차이·정책 차단·취약점 반증을 서로 다른 상태와 이유로 기록

### PoC candidate와 validated PoC

- `poc_candidate_ref`는 실행 전에 만든 스크립트·공격 입력 묶음이다. 실패한 시도도 로그와 함께 보존할 수 있지만 검증된 PoC가 아니다.
- validated `poc_ref`는 exact candidate를 실행해 재현이 성공하고 `status=SUCCEEDED`, `hypothesis_outcome=SUPPORTED`인 경우에만 저장한다.
- candidate 생성 실패면 `poc_candidate_ref=null`, `poc_ref=null`이다.
- candidate는 만들었지만 실행 실패, `DISPROVED`, `INCONCLUSIVE`이면 `poc_ref=null`이다.
- reference가 존재한다는 사실만으로 성공을 추론하지 않는다. validated `poc_ref`는 성공 실행 로그와 동적 근거를 가리켜야 한다.

### 결과를 R6가 판정하는 방법

| 목적과 실행 결과 | R6 처리 |
|---|---|
| `POC_CONFIRMATION` + `SUCCEEDED/SUPPORTED` | 정적·Pro·Con·동적 근거와 validated PoC를 합쳐 final TRUE 생성 후 Technical Gate 진행 |
| `VERDICT_EVIDENCE` + `SUCCEEDED/SUPPORTED` | 같은 실행의 validated PoC를 연결해 final TRUE 생성 후 Technical Gate 진행 |
| 정상 실행에서 실제 반증 `DISPROVED` | 근거 있는 final FALSE |
| 정상 실행했지만 결론 불충분 `INCONCLUSIVE` | 근거와 남은 조건을 가진 final HOLD |
| PoC 생성·환경 구성·정책·실행 자체 실패 | final verdict 없이 동적 work와 Verification을 `BLOCKED | FAILED`; Gate 금지 |

`DynamicReproductionResult.hypothesis_outcome`은 Sandbox의 관측 요약이며 최종 verdict가 아니다. `SUPPORTED | DISPROVED`에는 실제 관측을 가리키는 `hypothesis_evidence_refs`가 필요하다. `DISPROVED`일 때만 `hypothesis_disproved=true`와 `disproof_evidence_refs`를 사용한다. 오류·빈 출력·exit code만으로는 반증이나 FALSE를 만들 수 없다.

### 생성·구성·실행 실패 처리

- 다시 시도할 수 있으면 같은 work를 `BLOCKED`, `waiting_for=RETRY`로 두고 새 attempt를 시작한다.
- 외부 설정이나 환경 수정이 필요하면 `BLOCKED`, `waiting_for=INPUT | APPROVAL | DEPENDENCY`로 두고 수정될 때까지 기다린다.
- 복구할 수 없거나 retry 한도를 소진하면 work와 가설 처리를 `FAILED`로 끝낸다.
- 이 경로에서는 final `VerificationResult`와 validated `poc_ref`를 만들지 않고 Technical Gate를 호출하지 않는다.
- 실패를 자동으로 `FALSE | HOLD`로 바꾸지 않는다.

종료된 동적 결과는 `DynamicReproductionState.dynamic_result_ref`, `WorkExecutionState.output_refs`와 `TransitionCommit.output_refs`가 같은 exact `DynamicReproductionResult.record_id`를 가리킬 때만 R6에 전달한다. R6는 결과를 소비해 final verdict를 만들지만 R7의 요구사항·계획·동적 결과를 대신 생산하지 않는다.

## Technical `REVISE` 처리

Technical Evidence Gate의 `REVISE`는 Orchestration이나 Chaining Agent가 받을 작업이 아니다. 같은 hypothesis의 ACTIVE `VerificationAssignment` owner가 직접 받고 누락된 Context·Pro/Con·정적 근거·동적 재현·PoC 연결·restriction·설명을 보완한다. runtime은 종료된 기존 work를 되돌리지 않고 새 generation의 VERIFICATION work를 만들고 hypothesis 상태를 `TERMINAL -> VERIFYING`으로 원자 전환한다. 새 generation에서 final TRUE를 다시 만들려면 그 generation의 동적 재현 work와 validated PoC도 새로 연결해야 한다. CWE 보완이 필요하면 CWE producer와 새 label revision을 조정하되 CWE 소유권을 가져오지 않는다.

```text
VerificationResult revision N
-> Technical Gate REVISE
-> same Verification owner
-> new evidence and/or revised CWE + current-generation validated PoC
-> VerificationResult revision N+1
-> new Technical Gate work
```

`REVISE`는 provider retry나 동일 입력 재투표가 아니다. 새 work는 새 `input_hash`, `dedupe_key`, `work_id`, `attempt_number=1`, `trigger=INITIAL`을 사용한다. 새 Verification generation에는 동적 재현 work 하나를 다시 허용한다. 이전 Gate 결과와 동적 결과가 N을 가리키면 N+1에 재사용할 수 없다.

## VerificationResult에 남길 정보

최종 결과는 verdict뿐 아니라 질문별 `FalsificationResult`, supporting/counter evidence, restrictions, bypass·alternate path·impact 후보, REQUIRED/PROVIDED Primitive 후보, `origin=VERIFICATION` material child proposal, unresolved conditions, debate 지표와 동적 재현 reference를 포함한다. HOLD의 REQUIRED 후보는 즉시 admission할 수 있다. TRUE의 REQUIRED 후보는 그 취약점의 악용 선행 조건으로만 보존되고, PROVIDED 후보가 두 Gate를 정상 통과해 admission될 때 `required_preconditions`에 복사된다. 이 정보가 CWE, 두 Gate, Primitive admission, Reporter와 `AnalysisRunResult`의 입력이 된다.

supporting/counter evidence는 자유 형식 문자열이 아니라 `EvidenceClaim`으로 기록한다. 각 claim은 작성 역할, 실제 저장 근거와 코드 주장에 필요한 현재 workspace·commit의 위치를 포함한다. 우회·대체 경로·영향 확대 후보는 `CandidateRef(candidate_state=UNVALIDATED)`로 구분하고 새 material claim이면 별도 가설로 재검증한다. debate token·시간과 판정 변화는 `VerificationMetrics`에 저장하며 provider가 token을 제공하지 않으면 값을 추정하지 않고 `null`로 둔다.

### 저장 전 무결성 검사

final `VerificationResult` 후보를 저장하기 전에 trusted runtime은 `SAVE_RESULT(result_kind=verification_result)` 요청에서 결과 생산 역할, 현재 `work_ref`·`attempt_id`, `workspace_id`·`commit_id`, candidate result reference와 candidate 전체의 `content_hash`를 함께 검사한다.

검사 이후 candidate bytes·`content_hash`, 현재 work·attempt 또는 상태 revision이 변경되면 기존 저장 허가를 재사용하지 않는다. 해당 결과는 `STALE_RESULT | RECORD_REVISION_MISMATCH | STATE_VERSION_CONFLICT` 중 실제 원인을 기록하고 저장을 거절한다.

결과 reference, 종료 상태 전이와 `TransitionCommit.output_refs`가 같은 `VerificationResult.record_id`를 가리키고 `TransitionCommit.state=COMMITTED`가 된 exact revision만 Technical Evidence Gate의 입력으로 사용할 수 있다.
