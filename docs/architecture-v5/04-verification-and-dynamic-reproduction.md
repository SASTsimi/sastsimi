# 04. 검증과 동적 재현

- **이 문서는 무엇을 설명하나요?** 취약점 가설의 찬성·반대 근거를 확인하고 필요하면 Docker에서 재현하는 절차를 설명합니다.
- **누가 읽어야 하나요?** 검증·반박·플레이북과 동적검증·Sandbox 담당자가 우선 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** `TRUE / FALSE / HOLD` 판정 기준, 추가 근거 요청과 재현 범위를 확인합니다.

`Verification`은 가설을 근거로 확인하는 과정이고 `verdict`는 그 기술 판정입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## Verification의 목적과 제어권

Verification Agent는 배정받은 한 가설 안에서 검증 흐름 전체를 소유한다. 가설이 실제 코드 흐름과 실행 조건에서 성립하는지 검토하고 `TRUE | FALSE | HOLD`를 판정하며, 필요한 Context·Pro/Con·동적 재현 요청·보완 작업과 Gate 제출 시점을 선택한다. 제한 조건·우회 후보·필요 능력·제공 가능 능력·실질 영향의 상승 가능성도 함께 기록한다. R6는 재현 목적과 필요한 조건을 요청하지만 실행 환경·계획·PoC를 직접 만들지 않는다.

이 제어권은 실행 허가 권한이 아니다. Verification이 `REQUEST_DYNAMIC_REPRO` 등 다음 작업을 제안하면 비-LLM Runtime Validator가 `ActionRequest`, exact revision, 역할, 상태, 예산과 provider/session을 확인한다. R7 Setup Automation이 `RUN_SANDBOX`를 요청하면 Sandbox Controller가 host·Docker daemon/socket·mount/namespace·secret·egress·workspace·R8 resource/lifecycle 같은 외부 격리 경계를 검사한다. 허가된 Sandbox 안에서는 R7 Agent가 command·PoC·관찰·재시도를 자율적으로 정하고, 비-LLM Reproduction Session Manager가 실제 event와 결과를 확정한다.

## 기본 검증 순서

1. 배정된 가설의 `workspace_id`, `commit_id`, entity, location과 suspected path를 확인한다.
2. `CodeContextRequest`로 caller/callee, data flow, auth guard와 route 문맥을 필요한 만큼 조회한다. 추가 Context 요청은 현재 가설과 같은 `workspace_id`·`commit_id`를 사용해야 한다. 조회 실패·timeout·권한 오류는 `AnalysisError`로, 그 때문에 확인하지 못한 범위는 `DataGap`으로 기록하며 오류 자체를 verdict 근거로 사용하지 않는다. 일부 조회가 실패했더라도 제한 retry·대체 조회·다른 정상 근거로 모든 `ValidationCheck`, 반증 질문과 운영 Pro/Con을 완료했다면 실제 근거에 따라 final `TRUE | FALSE | HOLD`를 만들 수 있다. 필수 Context 또는 운영 Pro/Con을 확보하지 못해 검증이 하나라도 미완료이면 final `VerificationResult`를 저장하지 않는다. 재시도할 수 있으면 work를 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지하며, 더 시도할 수 없으면 work와 `HypothesisProcessState`를 원자적으로 `FAILED`로 끝낸다. 운영 Pro/Con 전에 예산이 부족한 경우에도 `BUDGET_EXCEEDED`로 작업을 중단하고 final verdict를 저장하지 않는다. Context 부족이나 조회 실패를 `DISPROVED` 또는 `FALSE`로 변환하지 않는다.
3. observed fact와 assumption을 분리하고 각 `FalsificationQuestion.question_id`를 확인한다.
4. 운영 분석이면 Pro/Con Agent를 서로 독립된 NEW session으로 병렬 호출해 supporting/counter evidence를 모두 수집한다. BASIC 또는 조건부 debate는 격리된 평가 실행에서만 선택한다.
5. 정적·Pro·Con 근거로 initial verdict와 unresolved condition을 만든다.
6. initial TRUE이면 동적 근거가 별도로 필요하지 않아도 `purpose=POC_CONFIRMATION`을 요청한다. 최종 판정에 실행 근거가 필요하면 `purpose=VERDICT_EVIDENCE`를 요청한다.
7. R7의 실행 결과를 종합해 final verdict를 만든다. final TRUE에는 현재 generation의 재현 성공과 validated `poc_ref`가 반드시 필요하다. 정적·Pro·Con만으로 충분한 FALSE 또는 HOLD는 동적 요청 없이 확정할 수 있다.
8. HOLD면 Primitive `inputs`가 될 부족 조건을, TRUE면 Technical `ACCEPT` 뒤 R4 admission runtime이 평가할 Primitive `result` 후보 능력을 기록한다. FALSE는 Primitive 후보를 만들지 않는다.
9. 새 endpoint·sink·권한 경계·공격 단계·독립 impact를 발견하면 `HypothesisProposal(origin=VERIFICATION)`으로 분리한다.
10. final TRUE를 확정하면 R5-01 `CWE_LABELING` work를 요청한다. R5-01이 exact Verification에 맞는 current `CWELabel`을 확정한 뒤 Technical Evidence Gate를 요청한다. `REVISE`면 같은 Verification owner가 새 Verification을 만들고 R5-01이 CWE 정렬을 다시 평가해 새 label revision을 만든 뒤 다시 제출한다.
11. HOLD의 부족 조건은 result 없는 Primitive로 즉시 Chaining에 넘길 수 있고, TRUE는 exact Technical `ACCEPT` 뒤 같은 chain의 Rule Scope 또는 정책 수집 결과로 R4가 current `PrimitiveAdmissionDecision=ALLOW`를 확정한 경우 result Primitive로 넘길 수 있다. Rule·Scope·Impact 결과는 현재 보고 경로에 별도로 적용한다.

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

mode와 실행·생략 기록은 다음 조합만 허용한다.

| purpose | mode | Pro/Con 실행 | `debate_triggers` | `debate_skip_reason` |
|---|---|---|---|---|
| `PRODUCTION` | `ALWAYS_DEBATE` | 필수 | `[]` | `null` |
| `EVALUATION` | `ALWAYS_DEBATE` | 필수 | `[]` | `null` |
| `EVALUATION` | `CONDITIONAL_DEBATE` | trigger가 하나 이상 충족되면 실행 | 충족된 trigger code 목록 | 실행하면 `null`, 생략하면 `NO_TRIGGER_MATCH` |
| `EVALUATION` | `BASIC` | 실행하지 않음 | `[]` | `MODE_BASIC` |

평가용 조건부 Debate는 다음 versioned trigger code를 사용한다.

| trigger code | 의미 |
|---|---|
| `CONFLICTING_EVIDENCE` | 정적 근거 또는 도구 결과가 서로 충돌함 |
| `HIGH_IMPACT_OR_COST` | 예상 impact가 크거나 후속 검증 비용이 큼 |
| `INITIAL_HOLD` | 기본 검토가 핵심 조건 부족으로 HOLD 가능성을 보임 |
| `AUTH_OR_SANITIZER_BYPASS` | 인증·인가·sanitizer 우회 확인이 필요함 |
| `ONE_SIDED_EVIDENCE` | 현재 근거가 찬성 또는 반대 한쪽에만 치우침 |
| `REVISE_ALTERNATE_PATH` | Technical `REVISE` 또는 이전 검토가 alternate path 확인을 요구함 |

`debate_triggers`에는 실제 충족된 code만 중복 없이 기록한다. trigger 집합과 판정 규칙은 versioned Debate 설정에서 읽으며 R6가 실행 중 임의로 추가·변경하지 않는다. `CONDITIONAL_DEBATE`에서 목록이 비어 있으면 Pro/Con을 호출하지 않고 `debate_skip_reason=NO_TRIGGER_MATCH`를 남긴다. 호출을 실행한 결과에 skip reason을 남기거나, 생략하면서 skip reason을 비워 두는 후보는 저장하지 않는다.

운영 분석에서는 named falsification으로 빠르게 반증될 가능성이 있거나 duplicate/unsupported 후보여도 Pro/Con을 생략하지 않는다. 예산이 부족하면 `BUDGET_EXCEEDED`로 현재 Verification work를 중단하며 Pro/Con을 생략한 final verdict를 만들지 않는다. 새 예산이 승인된 새 work에서만 이어서 검증한다.

### 공통 입력 snapshot과 독립 호출

Verification은 호출 전에 current ACTIVE `VerificationAssignment`, exact `VulnerabilityHypothesis`와 proposal, `workspace_id`, `commit_id`, 코드 경로·Context·정적 근거·인증 및 방어 로직 reference, 반증 질문, 검증 항목, 사람이 승인한 exact `PlaybookPolicy`, 선택한 `VerificationPlaybook`과 work별 `PlaybookApplication`, versioned Debate·budget 설정을 하나의 공통 입력 snapshot으로 고정한다. canonical JSON으로 만든 이 공통 입력의 SHA-256을 `debate_input_hash`로 사용한다. 역할별 system instruction·prompt template·worker와 session/call ID는 hash에서 제외한다. Pro와 Con의 `LLMCallSpec.context_refs`는 이 공통 reference 집합과 exact match해야 하며, 역할별 prompt payload와 output schema가 달라도 입력 가설·코드·policy·playbook·application revision과 질문 ID 집합, `debate_input_hash`는 같아야 한다.

Pro와 Con은 context contamination을 막기 위해 항상 서로 다른 `NEW` session에서 시작한다. 각 호출은 `requested_by=PRO | CON`, 같은 역할의 `LLMCallSpec.agent_role`, `session_mode=NEW`, `session_policy=NEW`, `parent_session_ref=null`과 서로 다른 `work_id`·`attempt_id`·`llm_call_id`·spec·action·decision·실제 session을 사용한다. provider가 session ID를 주지 않으면 adapter가 호출마다 서로 다른 local `session_ref`를 발급한다.

trusted prompt builder는 고정된 공통 입력 reference와 역할별 instruction만으로 immutable `prompt_payload_ref`를 만든다. 상대 Agent의 output·결론·session·work·attempt·call log·action/decision은 `context_refs`, `prompt_payload_ref`, parent/predecessor, result-store 조회, retrieval/tool 요청 또는 tool output 어느 경로로도 전달할 수 없다. runtime은 호출 직전과 결과 저장 전에 이 경계를 검사하고 위반하면 `CROSS_ROLE_INPUT_DENIED`로 호출과 join을 중단한다.

### 병렬 실행과 join 조건

운영 실행은 다음 순서를 따른다.

| 순서 | 처리 | 다음 단계 조건 |
|---|---|---|
| 1. preflight | purpose·mode, assignment owner, exact 공통 입력, provider/session 정책과 R8 budget profile을 검사한다. | 운영에서는 두 최초 호출을 모두 시작할 예산과 권한이 있어야 한다. 하나라도 준비되지 않으면 어느 호출도 시작하지 않는다. |
| 2. dispatch | Pro와 Con의 work·call spec·action을 각각 만들고 두 호출을 병렬 실행한다. | 두 호출은 같은 공통 입력 snapshot과 서로 다른 identity·NEW session을 사용한다. |
| 3. collect | Pro와 Con이 각각 exact `EvidenceAgentResult(role=PRO | CON)`를 별도 record로 저장하고, child work output·성공 attempt·`llm_call_id`·`LLMInvocationResult`·`LLMInvocationLog.parsed_output_ref`를 같은 result revision에 연결한다. | 한쪽 결과를 다른 쪽 입력으로 전달하지 않으며 각 결과가 schema-valid·`COMMITTED`여야 한다. |
| 4. join | 두 child work가 모두 `SUCCEEDED`이고, 두 결과가 같은 analysis·가설·부모 Verification work·generation·`debate_input_hash`를 가리키는지 확인한다. | 조건을 모두 만족한 exact Pro 결과 하나와 Con 결과 하나만 Verification 합성 입력으로 사용한다. |
| 5. synthesize | Verification만 두 결과와 직접 확인한 근거를 읽고 `VerificationResult.pro_evidence_ref`, `con_evidence_ref`, `debate_input_hash`에 exact 연결을 남긴다. | final 합성용 `LLMCallSpec.context_refs`와 `SAVE_RESULT.input_refs`에도 두 result reference를 각각 한 번 넣으며, 단독 결과로 운영 final verdict를 만들지 않는다. |

한쪽이 `FAILED | INVALID_OUTPUT | TIMED_OUT | RATE_LIMITED | AUTH_REQUIRED`이면 성공한 반대쪽 결과만으로 합성하지 않는다. 재시도할 수 있으면 실패한 Pro/Con child work와 부모 Verification work를 실제 대기 이유를 가진 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지한다. 허용된 repair·retry·provider failover는 실패한 역할에서만 수행할 수 있고, 같은 공통 입력 snapshot을 유지하는 동안에는 먼저 성공한 반대쪽의 COMMITTED 결과를 보존할 수 있다. retry와 failover도 새 `attempt_id`·`llm_call_id`·spec·action·decision·`NEW` session을 만들고 같은 역할의 바로 앞 허용 실패만 predecessor로 연결한다. 실패한 역할의 retry가 성공하고 두 current child 결과가 join 조건을 모두 만족할 때만 부모 Verification을 다시 진행한다.

공통 입력의 가설·Context·코드·policy·playbook·application revision, application 질문 ID 집합 또는 Verification generation이 바뀌면 이전 Pro/Con output을 새 snapshot과 섞지 않는다. 기존 결과는 stale로 보존하고 새 Verification work에서 두 역할을 다시 호출한다. 부모가 취소·교체·종료된 뒤 늦게 도착한 child 결과도 `STALE_RESULT`로 격리한다.

허용된 retry·failover 뒤에도 한쪽의 유효 output을 확보하지 못하면 실패 child의 `FAILED`를 먼저 COMMITTED해 부모의 실행과 join을 막는다. 이어 부모 Verification work의 `FAILED`와 `HypothesisProcessState.status=FAILED`를 공통 원자 전이로 확정하고 `verification_result_ref=null`을 유지한다. 중간에 전파가 끊기면 recovery가 이를 완료할 때까지 부모를 다시 실행하지 않는다. 어느 실패도 `FALSE | HOLD`의 근거가 아니다.

## Debate 효과 측정

각 가설에는 다음 자료를 연결해 조건부 정책을 향후 평가할 수 있게 한다.

- `VerificationResult`: mode, 충족 trigger, skip reason과 `VerificationMetrics`
- `VerificationMetrics`: Pro·Con·합성 token, 전체 elapsed time, Debate 전후 verdict 변화, `HOLD` 해소, false-positive 감소 후보와 새 bypass·restriction·falsification 수
- 역할별 `LLMInvocationLog`: 고유 call 수, provider·model·session, status, elapsed time, 실제 usage, retry·failover predecessor와 오류

Pro·Con 호출 횟수는 같은 Verification work와 역할에 속한 중복 없는 `llm_call_id` 수로 계산한다. retry 횟수와 failover 횟수는 각각 유효한 `retry_of_llm_call_id`와 `failover_from_llm_call_id`가 있는 log 수로 계산한다. provider가 token usage를 제공하지 않으면 추정값을 쓰지 않고 `null`과 unavailable 이유를 남긴다. R8은 이 exact log와 metric을 읽어 mode별 품질·비용을 비교하며 개별 호출이나 verdict를 변경하지 않는다.

검증에서 확인한 restriction은 문장만 저장하지 않는다. proposal에서 이어진 restriction은 같은 `restriction_id`와 전체 근거 객체를 유지하고, 새 restriction은 현재 generation의 코드·정적·Pro/Con·동적 근거 reference를 붙인다. 근거가 아직 없으면 restriction으로 확정하지 않고 `unresolved_conditions` 또는 `limitations`에 남긴다.

`BASIC | CONDITIONAL_DEBATE`가 더 정확하거나 저렴한지는 동일 corpus의 격리된 평가에서만 측정한다. 평가 결과가 운영 기본 변경의 합격선을 통과하고 별도 설계 결정을 남기기 전까지 운영은 `ALWAYS_DEBATE`를 유지한다.

### Debate 계약 검증 시나리오

| 시나리오 | 기대 결과 |
|---|---|
| 운영 `ALWAYS_DEBATE` | 같은 exact 입력으로 Pro와 Con이 각각 독립 `NEW` session에서 호출되고, 둘 다 유효하게 끝난 뒤에만 합성함 |
| 정상 join | 두 COMMITTED `EvidenceAgentResult`가 같은 부모·generation·`debate_input_hash`를 가리키고 final 결과의 `pro_evidence_ref`·`con_evidence_ref`에 각각 정확히 한 번 연결됨 |
| 평가 `BASIC` | Pro/Con 호출 없이 `debate_triggers=[]`, `debate_skip_reason=MODE_BASIC`을 기록하며 Gate·Primitive·Reporter 입력을 거절함 |
| 평가 `CONDITIONAL_DEBATE`, trigger 충족 | 충족 code를 기록하고 두 Agent를 호출하며 `debate_skip_reason=null`임 |
| 평가 `CONDITIONAL_DEBATE`, trigger 불충족 | Pro/Con 호출 없이 `debate_triggers=[]`, `debate_skip_reason=NO_TRIGGER_MATCH`를 기록함 |
| session·입력 독립성 위반 | 같은 session·call identity, non-null session parent 또는 상대 output을 prompt·context·조회·tool 경로에 넣은 호출을 `CROSS_ROLE_INPUT_DENIED`로 거절함 |
| 한쪽 timeout 뒤 retry 성공 | 실패 child와 부모를 `BLOCKED`, 가설을 `VERIFYING`으로 유지하고, 같은 snapshot의 current Pro·Con 두 결과가 모인 뒤 부모 join을 재개함 |
| 한쪽 실패 또는 빈 출력이 끝내 복구되지 않음 | 실패 child를 먼저 확정한 뒤 부모 Verification과 가설을 `FAILED`로 끝내고 `verification_result_ref=null`을 유지함 |
| 두 최초 호출을 시작할 budget 부족 | 어느 호출도 시작하지 않고 `BUDGET_EXCEEDED`를 기록하며 final verdict를 만들지 않음 |
| retry 전 공통 입력 revision 변경 | 이전 성공·실패 output을 stale로 보존하고 새 work에서 Pro와 Con을 모두 다시 호출함 |
| 다른 부모·generation·입력 hash 결과의 join | `STALE_RESULT`로 거절하고 current 입력으로 Pro와 Con을 모두 다시 실행함 |
| 부모 종료 뒤 늦게 도착한 child 결과 | 합성하지 않고 `STALE_RESULT`로 격리함 |
| 평가 결과의 운영 승격 시도 | Technical Gate, Primitive admission과 Reporter action을 runtime이 거절함 |

## 판정 의미

- `TRUE`: 현재 가설의 핵심 exploit path와 필요한 조건이 evidence로 지지된다. restriction이 있으면 그대로 보존한다.
- `FALSE`: 가설의 필수 조건을 묻는 named falsification 하나 이상이 실제 근거로 `DISPROVED`되었다. 다른 path 가능성까지 부정하지 않는다.
- `HOLD`: 핵심 정보·환경·재현 조건이 부족하거나 상충해 현재 증거로 결론을 낼 수 없다.

`HOLD`는 실패가 아니다. 누락 정보와 필요한 capability를 구조화해 exact final Verification revision에 연결된 result 없는 Primitive의 `inputs`로 즉시 저장하고 Chaining Agent의 matching 입력으로 사용할 수 있다. HOLD는 두 Gate를 거치지 않으며 확인된 능력이나 취약점으로 승격되지 않는다.

`TRUE`도 판정 직후에는 Chaining 입력이 아니다. 현재 revision이 Technical `ACCEPT`를 받은 뒤 R4 `PRIMITIVE_ADMISSION_RUNTIME`이 Rule Scope 또는 정책 수집 결과를 매핑한 current `PrimitiveAdmissionDecision=ALLOW`가 있어야 제공 능력을 `result`로 가진 Primitive가 된다. prohibited-testing `FAIL`은 `DENY`로 차단하지만 `UNCERTAIN | COLLECTION_FAILED`와 다른 report eligibility 실패는 Reporter만 차단한다. `FALSE`는 terminal internal result이며 Primitive와 Chaining work를 만들지 않는다.

최종 결과는 등록 가설의 모든 반증 질문에 `DISPROVED | NOT_DISPROVED | INCONCLUSIVE` 중 하나를 기록한다. 또한 모든 `validation_checks`를 같은 `validation_id`의 `ValidationCheckResult`로 정확히 한 번씩 답하고, 각 항목을 `COMPLETE`와 실제 근거 reference로 마쳐야 한다. 하나라도 빠지거나 `INCOMPLETE`이면 final `VerificationResult`를 저장하지 않는다. `DISPROVED`에는 실제 `evidence_refs`가 필요하고, `NOT_DISPROVED`는 가설이 참이라는 증거로 승격하지 않는다. `FALSE`는 적어도 하나의 근거 있는 `DISPROVED` 결과와 그 `question_id`를 설명하는 판정 이유가 있을 때만 허용한다. 오류·timeout·누락만으로는 `DISPROVED`나 `FALSE`를 만들지 않는다.

검증 절차를 끝내지 못했지만 재시도할 수 있으면 Verification work를 `BLOCKED`로 두고 가설은 `VERIFYING`을 유지한다. 허용된 재시도를 소진했거나 복구할 수 없으면 failed work와 `HypothesisProcessState.status=FAILED`를 한 번에 확정하고 `verification_result_ref=null`로 둔다. 이 종료는 `HOLD`나 `FALSE`가 아니며 Gate로 보내지 않는다.

| 판정 | 최소 필수 근거 | 허용하지 않는 판정 이유 |
|---|---|---|
| `TRUE` | 현재 가설의 핵심 exploit path를 지지하는 정적·Pro·Con 근거, 현재 generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 validated `poc_ref` | 단순 추측, `NOT_DISPROVED`, validated PoC가 없거나 현재 generation과 다른 동적 결과 |
| `FALSE` | named falsification의 `question_id`, `outcome=DISPROVED`, 하나 이상의 실제 `evidence_refs`와 이를 연결하는 판정 이유 | 오류, timeout, 빈 Context, 예산 초과, Sandbox 실패 |
| `HOLD` | 하나 이상의 `unresolved_conditions`와 정상적으로 확인한 범위 및 결론을 막는 조건을 설명하는 실제 evidence reference | 취약점이 아니라는 의미로 사용하거나 result가 있는 능력으로 승격 |

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

## final verdict 이후 Gate·Primitive·Chaining 수명주기

R6가 final `VerificationResult`를 준비한 뒤의 진행은 다음 상태 전이표를 따른다.

| final verdict 또는 Gate 결과 | R6가 기록·요청하는 것 | trusted runtime이 강제하는 것 | 다음 단계 |
|---|---|---|---|
| `FALSE` | 두 Primitive 후보 목록을 비운다. | Gate·Primitive·Chaining work 등록을 거절한다. | 종료 |
| `HOLD` | `required_primitive_candidates`와 근거·`unresolved_conditions`를 기록한다. | exact final HOLD를 확인하고 후보 전체를 `inputs`로, `result=null`로 가진 Primitive 하나를 저장한다. | Gate 없이 Chaining 후보 |
| Gate 전 final `TRUE` | required/provided 후보와 current-generation 동적 결과·validated PoC를 기록하고 R5-01 `CWE_LABELING`을 요청한다. | current `CWELabel` 전에는 Technical Gate를, Technical `ACCEPT`와 admission `ALLOW` 전에는 result Primitive를 차단한다. | CWE → Technical Gate |
| Technical `REVISE` | 같은 ACTIVE assignment owner가 요청 내용을 받아 근거·설명·restriction을 보완한다. | 기존 work를 되돌리지 않고 새 VERIFICATION work·증가한 generation을 만들며 hypothesis를 `TERMINAL -> VERIFYING`으로 전환한다. | 새 final Verification |
| Technical `REJECT` | 부모 verdict를 바꾸지 않는다. | result Primitive·Chaining·Reporter 진행을 차단한다. | 내부 종결 |
| Technical `ACCEPT` | 같은 exact Verification·`CWELabel`로 Rule Scope Gate를 요청한다. | stale·mismatched reference를 거절한다. | 정책·금지 테스트 검토 |
| current admission `ALLOW` | 추가 verdict를 만들지 않는다. | provided 후보마다 Primitive 하나를 저장한다. 각 `result`는 후보 하나, `inputs`는 같은 TRUE의 `required_primitive_candidates` 전체다. | Chaining 후보 |
| current admission `DENY` | 부모 verdict를 바꾸지 않는다. | result Primitive·Chaining을 차단한다. | Reporter도 차단 |
| Rule Scope 보고 조건 실패 + admission `ALLOW` | 부모 verdict를 바꾸지 않는다. | Reporter만 차단하고 Chaining 재료 자격은 유지한다. | 내부 Chaining 가능 |

Primitive admission과 보고 가능성은 같은 판정이 아니다. R5가 정책·`testing_restriction_compliance`를 생산하면 R4 `PRIMITIVE_ADMISSION_RUNTIME`이 current `PrimitiveAdmissionDecision`을 만든다. result Primitive와 Chaining은 `decision=ALLOW`만 사용한다. Rule Scope의 범위·영향·보상 대상·`report_permission`은 Reporter 자격을 별도로 결정한다.

R6는 `required_primitive_candidates`, `provided_primitive_candidates`, Gate action과 exact reference를 생산한다. result commit, current result pointer, Primitive 저장·제거와 `PrimitiveIndexState` 갱신은 trusted runtime의 책임이다. R6는 이를 직접 admission하거나 ACTIVE로 만들지 않는다.

TRUE의 필요 조건은 별도 HOLD Primitive로 만들지 않는다. admission된 각 result Primitive의 `inputs`에 같은 TRUE의 `required_primitive_candidates` 전체를 내용·순서 그대로 복사한다. Chaining은 current `ALLOW` result Primitive가 다른 Primitive의 `inputs[].draft_id`를 근거로 충족할 때만 `TRUE + HOLD` 또는 `TRUE + TRUE` 후보를 만든다.

새 Verification generation이 만들어지면 이전 dynamic result·validated PoC·`CWELabel`·Technical review·Rule Scope review·admission decision과 그 자격을 새 generation에 재사용하지 않는다. 기존 record는 감사 이력으로 보존하되 current index와 새 Gate·Chaining 입력에서 제외한다. child proposal이나 Chaining 결과도 부모 `VerificationResult.verdict`를 변경하지 않는다.

### Initial verdict와 final verdict

`initial_verdict`는 기본 Context와 Verification Agent가 직접 확인한 사실을 바탕으로 만든 중간 판단이다. 운영 분석에서는 독립 Pro/Con과 필요한 동적 재현이 끝나기 전의 initial verdict를 Gate·Primitive·Reporter 입력으로 사용할 수 없다. 특히 initial TRUE는 PoC 확인을 시작하기 위한 중간 상태일 뿐 final TRUE가 아니다.

final `verdict`는 필요한 Pro/Con과 동적 결과를 포함해 현재 work에서 사용할 수 있는 모든 근거를 종합한 최종 판단이다. 모든 final TRUE는 현재 generation의 성공한 동적 재현과 validated PoC를 포함한다. initial verdict와 final verdict가 다르면 `verdict_rationale`에 변경 이유를 남긴다. 이 변화가 Debate로 인한 것이면 `VerificationMetrics.verdict_changed_after_debate=true`로 기록한다.

새 evidence나 Technical `REVISE`로 결과가 바뀌면 기존 record를 수정하지 않고 새 `VerificationResult` revision을 만든다. 과거 revision을 검토한 Gate 결과는 새 revision에 재사용하지 않는다.

### Verification `TRUE`와 Technical `ACCEPT`의 경계

Verification의 `TRUE`는 R6가 정적·Pro/Con 근거와 현재 generation의 성공한 동적 재현·validated PoC를 종합해 현재 가설의 핵심 공격 경로와 필요한 조건이 성립한다고 판정한 결과다.

Technical Evidence Gate의 `ACCEPT`는 R5가 exact final TRUE revision을 대상으로 evidence와 코드 경로의 연결, 동적 재현·PoC와 restriction, CWE와 다음 단계 전달 준비 상태가 충분한지 별도로 검토한 결과다.

따라서 R6가 `TRUE`를 만들었다고 해서 Technical `ACCEPT`가 자동으로 보장되지는 않는다. Technical Gate는 같은 verdict revision에 대해 `ACCEPT | REVISE | REJECT`를 반환할 수 있지만 기존 verdict를 직접 변경하지 않는다. `REVISE`가 반환되면 같은 ACTIVE Verification owner가 근거를 보완해 새 `VerificationResult` revision을 만든다.

## 취약점 유형별 검증 플레이북

공통 및 웹 취약점 6종의 실제 검증 내용은 [R6 검증 플레이북](./verification-playbooks.md)을 정본으로 사용한다. 최초 작성 범위는 `COMMON`, SQL Injection, XSS, OS Command Injection, Path Traversal, SSRF, IDOR/BOLA이며, 작성됐다는 사실만으로 운영 지원 유형이 되지는 않는다.

R8의 versioned evaluation corpus는 우선 지원할 취약점 유형을 정하는 평가 근거이고, 운영에서 실제 허용할 유형과 exact 플레이북 revision의 연결은 사람이 승인한 current `PlaybookPolicy`로 확정한다. 현재는 운영 지원 목록이 확정되지 않았으므로 모든 유형에 공통으로 적용할 플레이북 구조와 작성 규칙을 먼저 사용한다. 지원 목록이 확정되면 이 구조로 유형별 플레이북을 별도 revision으로 등록하고 승인된 policy에 연결한다.

플레이북은 Agent에게 자유로운 결론을 요구하는 prompt나 점수표가 아니다. 과거 사례와 검증 지식을 바탕으로 빠뜨리면 안 되는 사전 조건, source, sink, source-to-sink 경로, 방어, named falsification question, 정적·동적 evidence, restriction과 HOLD 조건을 안내한다. verdict는 체크 개수나 Pro·Con 중 한쪽의 승패가 아니라 현재 코드와 실제 evidence로 결정한다.

플레이북 후보와 유형 mapping 후보는 R6 검증·반박·플레이북 담당이 작성하고, trusted playbook registry runtime이 schema와 revision을 검사해 변경 불가능한 record로 등록한다. 등록만으로 운영 지원 목록을 바꿀 수는 없다. Verification work를 등록할 때 runtime은 exact `VulnerabilityHypothesis.proposal_ref`가 가리키는 `HypothesisProposal.vulnerability_type_candidates`를 읽는다. 후보가 정확히 하나이고 current `PlaybookPolicy`에 같은 유형의 mapping이 있을 때만 해당 exact `TYPE_SPECIFIC` revision을 선택한다. 후보가 없거나 여러 개이거나 policy가 허용하지 않으면 current exact `COMMON` revision을 선택한다.

runtime은 선택한 policy·playbook, 선택 이유와 플레이북 질문마다 새로 발급한 전역 `question_id`를 work별 `PlaybookApplication`으로 저장한다. Verification의 직접 검증, 독립 Pro/Con 실행, final 합성과 결과 저장은 모두 work에 고정된 동일한 application을 사용한다. final 질문 결과는 가설 자체의 반증 질문과 application 질문의 합집합을 빠짐없이 정확히 한 번씩 처리해야 한다. 검증 도중 current policy나 playbook revision이 변경돼도 진행 중인 work에는 섞지 않는다. 같은 work의 retry는 기존 application과 질문 ID를 유지하고, 새 Verification work 또는 새 verification generation에서는 새 application과 새 질문 ID를 만든다.

미지원 유형도 후속 Issue만 만들고 현재 실행을 끝내서는 안 된다. COMMON으로 필수 검증을 먼저 수행한다. 필수 검증을 완료했지만 유형별 정보가 부족하면 `unresolved_conditions`와 HOLD를 기록할 수 있고, 실행 자체가 실패하면 verdict 없이 실행 오류를 기록한다. 오류·timeout·빈 Context·Sandbox 실패는 FALSE의 반증 evidence가 아니다.

플레이북은 동적 검증의 목적과 필요한 관측만 정의한다. R6는 재현할 가설, 재현 목표, 필요한 환경 조건, `sandbox_profile_ref`와 관련 문맥을 요청하며, PoC·command·환경 계획과 `DynamicReproductionResult`는 R7이 생산한다. 모든 final TRUE에는 current generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 validated `poc_ref`가 필요하다.

| 항목 | 설명 |
| --- | --- |
| `VerificationPlaybook.vulnerability_type` | 플레이북이 다루는 취약점 유형 |
| 사전 조건 | 공격자가 먼저 만족해야 하는 권한·입력·환경 |
| source | 공격자 입력이나 제어 값이 시작되는 위치 |
| sink | 위험 동작 또는 영향이 발생하는 위치 |
| 경로 확인 | source에서 sink까지 이어지는 호출·데이터 흐름 |
| 방어 확인 | validator, sanitizer, canonicalization, 인증·인가와 권한 검사 |
| 반증 질문 | `template_key`와 질문 문장. `template_key`는 플레이북 안의 이름일 뿐 실제 `question_id`가 아니며 적용할 때 새 ID를 발급함 |
| 정적 evidence | 필요한 코드 위치·호출 관계·도구 결과 |
| 동적 evidence | 실행으로 확인해야 하는 조건과 observable effect |
| restriction | 공격이 가능한 범위를 제한하는 조건 |
| HOLD 조건 | 아직 해결되지 않으면 최종 판단을 보류해야 하는 조건 |

지원 목록이 확정되기 전에는 임의의 취약점 유형을 지원 대상으로 가정하지 않는다. 목록 확정 후에도 지원 목록에 없는 유형을 기존 플레이북에 억지로 맞추지 않는다. 필요한 검증 항목을 확정할 수 없으면 공통 플레이북으로 현재 실행을 먼저 처리한다. 정상적으로 필수 검증을 완료했지만 정보가 부족하면 `unresolved_conditions`와 `HOLD`를 기록한 뒤 후속 Issue를 연결한다. 실행 자체가 실패했다면 verdict 없이 실행 오류를 기록한 뒤 후속 Issue를 연결한다. 새로운 endpoint·sink·권한 경계·공격 단계·독립 impact가 발견되면 현재 verdict에 합치지 않고 material child proposal로 분리한다.
## Docker 동적 재현

동적 검증은 정적 판단을 대체하지 않고 특정 가설을 격리된 환경에서 실제로 확인한다. 모든 final TRUE에는 실행으로 확인된 PoC가 필요하므로 initial TRUE도 반드시 이 단계를 거친다.

### R6 요청과 R7 생산 책임

R6는 다음 항목을 가진 `DynamicReproductionRequest`만 만든다.

- `hypothesis_ref`와 현재 `verification_generation`
- `purpose: POC_CONFIRMATION | VERDICT_EVIDENCE`
- 재현 목표와 요청 이유
- 필요한 역할·권한·인증·데이터·service 같은 `environment_needs`
- 적용할 `sandbox_profile_ref`
- 관련 코드·정적·Pro·Con 근거 reference

`POC_CONFIRMATION`은 정적·Pro·Con으로 initial TRUE가 나온 뒤 실제 PoC로 확인하는 목적이다. `VERDICT_EVIDENCE`는 실행 관측이 있어야 최종 판정을 내릴 수 있을 때 사용한다. R6는 목적과 필요한 조건만 정하며 `EnvironmentRequirements`, `ReproductionPlan`, recipe, command 또는 PoC를 생산하지 않는다.

R7 내부 책임은 다음처럼 나눈다.

- **R7 Agent**: 요청을 환경 조건으로 구체화하고, 재현 전략·PoC candidate·command·관찰·동적 근거 해석을 만든다.
- **R7 Setup Automation**: 저장소 선언을 우선한 recipe, image build, container 생성·재사용·재생성과 cleanup을 실제 수행한다.
- **Sandbox Controller**: host·Docker daemon/socket·mount/namespace·secret·egress·다른 workspace·R8 resource/lifecycle 같은 Sandbox 밖의 강제 경계만 검사한다.
- **Reproduction Session Manager**: runtime/tool/lifecycle event를 append-only `AgentLog`로 기록하고 같은 attempt의 validated PoC와 `DynamicReproductionResult`를 확정하는 비-LLM result owner다.

R7은 `SUPPORTED | DISPROVED | INCONCLUSIVE` 동적 관측만 반환하며 최종 `TRUE | FALSE | HOLD`는 계속 R6가 판단한다. Session Manager는 Agent 호출·중단, command 허용, retry 또는 cleanup 전략을 결정하지 않는다.

### ReproductionPlan과 Agent 자율성

`ReproductionPlan`은 목적·가설·환경 요구사항·재현 목표·전략 요약과 선택적인 `requested_evidence`만 고정한다. `LIMITED/FULL` mode, exact command·step·payload·PoC·cleanup allowlist는 두지 않는다. `requested_evidence`는 참고 목표이며 Agent의 추가 관찰을 제한하지 않는다.

Sandbox 안에서는 Agent가 환경 설정, 저장소에 필요한 package, 계정, fixture/mock, PoC, command와 재시도를 자율적으로 선택한다. Sandbox 밖의 접근은 계속 Controller가 강제한다. Agent는 Docker daemon을 직접 다루지 않고 Setup Automation이 제공한 in-container 실행 통로만 사용한다. plan의 입력 부족·모순은 별도 record가 아니라 결과의 `plan_issues`에 남긴다.

### EnvironmentRecipe와 container lifecycle

- `EnvironmentRecipe`는 저장소·환경 단위의 불변 build recipe이며 `base_image_digest`와 실제 `built_image_digest`를 구분한다.
- Dockerfile, README, package manifest와 lockfile 등 저장소에 이미 선언된 의존성을 우선한다. 별도 Dependency Scanner나 R2 package prefetch를 전제로 하지 않는다.
- package 누락을 실제로 확인하면 Agent가 recipe source를 고치고 Setup Automation이 새 baseline image와 recipe revision을 만든다.
- 성공한 baseline image는 다른 가설에도 재사용할 수 있지만 현재 attempt에는 exact baseline ref와 digest를 가진 새 recipe binding을 남긴다.
- 각 가설의 최초 attempt는 clean Sandbox에서 시작하고, 서로 다른 가설은 writable container를 공유하지 않는다.
- 같은 가설·work 안에서는 다음 실행에 영향을 줄 상태·설정 변화가 없을 때만 container를 재사용한다.
- Agent는 `STATE_CHANGED | CONFIG_CHANGED | STATE_UNCERTAIN`으로 재생성을 요청할 수 있다. crash·비정상 종료·사후 Health Check 실패면 runtime이 `STATE_UNCERTAIN`으로 강제한다.
- `SandboxEnvironment`에는 container instance, `CREATED | REUSED`, 사유와 이전 환경 reference를 기록한다. `AgentLog`에는 재생성 요청 주체·사유·이전/새 환경을 남긴다.

### generation당 한 번의 동적 재현 work와 retry

- 한 Verification generation에는 `DYNAMIC_REPRO` work를 하나만 등록한다.
- `POC_CONFIRMATION`과 `VERDICT_EVIDENCE`를 같은 generation에서 각각 별도 work로 실행하지 않는다.
- 같은 Agent session 안의 command·PoC·환경 조정은 같은 attempt의 event다.
- session 재시작이 필요한 일시 오류는 R8 한도가 남아 있으면 실패 attempt를 보존하고 같은 work의 새 attempt로 자동 재시도한다. 외부 대기가 없으므로 work를 `BLOCKED`로 두지 않는다.
- `BLOCKED`는 외부 설정·정책·승인 또는 resource profile 변경을 기다릴 때만 사용한다. 해결 뒤 `RESUME` attempt를 만든다.
- 복구할 수 없거나 retry 한도를 소진하면 Session Manager가 `FAILED + INCONCLUSIVE`를 확정한다.
- Technical Gate `REVISE`는 새 Verification generation이므로 새 동적 재현 work 하나를 허용한다.


### AgentLog와 결과 확정

- 실제 event는 기존 runtime/tool/lifecycle 계층이 발생시키고 Session Manager가 즉시 durable log에 append한다.
- `agent_invoked`는 외부 경계 승인 뒤 Sandbox 안의 R7 Agent 실행 단계가 시작됐는지를 뜻한다. 경계 승인 전에 requirements·plan을 만든 LLM 호출과는 구분한다.
- `event_id`는 전역 고유, `sequence`는 attempt별 증가 값이며 시작·종료 event는 같은 `action_id`를 사용한다.
- crash 뒤에도 이미 확정한 event는 남고, 이전 attempt의 늦은 event는 current attempt에 섞지 않는다.
- Sandbox 실행 Agent 호출 전 정책 차단도 `agent_invoked=false`, exact 정책 결정과 `POLICY_BLOCKED` event를 가진 결과로 남긴다.
- recipe·환경·AgentLog·candidate·validated PoC와 결과는 같은 work·attempt에 연결한다. baseline recipe ref만 과거 성공 baseline을 가리킬 수 있다.

### PoC candidate와 validated PoC

- `poc_candidate_ref`는 Agent가 작성했거나 실행을 시도한 PoC다. 실패한 시도도 같은 attempt의 작성·실행 event와 함께 보존할 수 있다.
- validated `poc_ref`는 `status=SUCCEEDED`, `hypothesis_outcome=SUPPORTED`, `agent_invoked=true`이고 AgentLog가 exact candidate revision·digest를 실제 실행한 사실을 보여 줄 때만 만든다.
- validated PoC의 request·plan·recipe·environment·AgentLog·candidate·실행 action은 모두 결과와 같은 attempt여야 한다.
- 환경 실패, 정책 차단, candidate 생성·실행 실패, timeout, `DISPROVED | INCONCLUSIVE`에서는 `poc_ref=null`이다.
- reference가 존재한다는 사실만으로 성공을 추론하지 않는다.

### 결과를 R6가 판정하는 방법

| 목적과 실행 결과 | R6 처리 |
|---|---|
| `POC_CONFIRMATION` + `SUCCEEDED/SUPPORTED` + validated PoC | 정적·Pro·Con·동적 근거와 PoC를 합쳐 final TRUE 생성 후 Technical Gate 진행 |
| `VERDICT_EVIDENCE` + `SUCCEEDED/SUPPORTED` + validated PoC | 같은 실행의 validated PoC를 연결해 final TRUE 생성 후 Technical Gate 진행 |
| 정상 실행에서 실제 반증 `DISPROVED` | 근거 있는 final FALSE |
| 정상 실행 또는 신뢰 가능한 부분 완료의 `INCONCLUSIVE` | 근거와 남은 조건을 가진 final HOLD |
| 정책·환경·Agent·PoC 생성·실행 자체 실패 | final verdict 없이 동적 work와 Verification을 `BLOCKED | FAILED`; Gate 금지 |

`DynamicReproductionResult.hypothesis_outcome`은 동적 관측 요약이며 최종 verdict가 아니다. `SUPPORTED | DISPROVED`에는 실제 관측을 가리키는 `hypothesis_evidence_refs`가 필요하다. `DISPROVED`일 때만 `hypothesis_disproved=true`와 `disproof_evidence_refs`를 사용한다. 오류·빈 출력·exit code만으로는 반증이나 FALSE를 만들 수 없다. 실패 결과의 `failure_category`는 비교 가능한 범주, `failure_reason`은 민감정보를 제거한 구체적인 자유형 설명이다. plan의 부족·모순은 `plan_issues`에 직접 포함한다.

`DynamicReproductionState.dynamic_result_ref`, `WorkExecutionState.output_refs`와 `TransitionCommit.output_refs`는 같은 exact `DynamicReproductionResult.meta.record_id`를 가리키는 current 반환 동적 결과만 R6에 전달한다. current 반환 결과에는 비종료 상태인 `BLOCKED`가 포함될 수 있고 R6는 이를 대기·복구 판단에 읽을 수 있지만, final `VerificationResult`나 Technical Gate를 포함한 Gate 입력으로 사용할 수 없다. R6는 자격을 갖춘 결과를 소비해 final verdict를 만들지만 R7 산출물을 대신 생산하지 않는다. current generation의 exact request, `SUCCEEDED + SUPPORTED` 결과와 validated `poc_ref` 중 하나라도 없으면 final TRUE 저장과 Technical Gate 호출을 모두 차단한다.

## Technical `REVISE` 처리

Technical Evidence Gate의 `REVISE`는 Orchestration이나 Chaining Agent가 받을 작업이 아니다. 같은 hypothesis의 ACTIVE `VerificationAssignment` owner가 직접 받고 누락된 Context·Pro/Con·정적 근거·동적 재현·PoC 연결·restriction·설명을 보완한다. runtime은 종료된 기존 work를 되돌리지 않고 새 generation의 VERIFICATION work를 만들고 hypothesis 상태를 `TERMINAL -> VERIFYING`으로 원자 전환한다. 새 generation에서 final TRUE를 다시 만들려면 그 generation의 동적 재현 work와 validated PoC도 새로 연결해야 한다. 새 final TRUE가 확정되면 R5-01 `CWE_LABELING`이 CWE 정렬을 다시 평가하고, CWE 값이 같더라도 새 Verification을 직접 가리키는 새 `CWELabel` revision을 만든다. Verification은 CWE 생성·수정 권한을 가져오지 않는다.

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

최종 결과는 verdict뿐 아니라 질문별 `FalsificationResult`, supporting/counter evidence, restrictions, bypass·alternate path·impact 후보, `required_primitive_candidates`와 `provided_primitive_candidates`, `origin=VERIFICATION` material child proposal, unresolved conditions, debate 지표와 동적 재현 reference를 포함한다. HOLD의 required 후보는 result 없는 Primitive의 `inputs`로 즉시 admission할 수 있다. TRUE의 required 후보는 악용 선행 조건인 `inputs`, provided 후보는 Technical `ACCEPT` 뒤 R4의 current `PrimitiveAdmissionDecision=ALLOW`가 허용한 능력별 Primitive의 `result`가 된다. 이 정보가 CWE, Technical Gate, Rule Scope Gate, Primitive admission, Reporter와 `AnalysisRunResult`의 입력이 된다.

supporting/counter evidence는 자유 형식 문자열이 아니라 `EvidenceClaim`으로 기록한다. 각 claim은 작성 역할, 실제 저장 근거와 코드 주장에 필요한 현재 workspace·commit의 위치를 포함한다. 우회·대체 경로·영향 확대 후보는 `CandidateRef(candidate_state=UNVALIDATED)`로 구분하고 새 material claim이면 별도 가설로 재검증한다. debate token·시간과 판정 변화는 `VerificationMetrics`에 저장하며 provider가 token을 제공하지 않으면 값을 추정하지 않고 `null`로 둔다.

### 저장 전 무결성 검사

final `VerificationResult` 후보를 저장하기 전에 trusted runtime은 `SAVE_RESULT(result_kind=verification_result)` 요청에서 결과 생산 역할, 현재 `work_ref`·`attempt_id`, `workspace_id`·`commit_id`, candidate result reference와 candidate 전체의 `content_hash`를 함께 검사한다.

검사 이후 candidate bytes·`content_hash`, 현재 work·attempt 또는 상태 revision이 변경되면 기존 저장 허가를 재사용하지 않는다. 해당 결과는 `STALE_RESULT | RECORD_REVISION_MISMATCH | STATE_VERSION_CONFLICT` 중 실제 원인을 기록하고 저장을 거절한다.

결과 reference, 종료 상태 전이와 `TransitionCommit.output_refs`가 같은 `VerificationResult.record_id`를 가리키고 `TransitionCommit.state=COMMITTED`가 된 exact revision만 Technical Evidence Gate의 입력으로 사용할 수 있다.

## R6 동적 재현 요청과 결과 소비 계약

### R6 요청 결정표와 단일 실행 규칙

| 정적·Pro·Con 검토 상태 | R6 요청 | 같은 `verification_generation`의 처리 |
|---|---|---|
| 정적·Pro·Con만으로 `VerificationResult.initial_verdict=TRUE`이며 판정용 동적 근거는 더 필요하지 않음 | `DynamicReproductionRequest.purpose=POC_CONFIRMATION` | PoC 확인용 동적 work를 한 번 등록한다. |
| 실행 관측 없이는 final verdict를 정할 수 없음 | `DynamicReproductionRequest.purpose=VERDICT_EVIDENCE` | 판정 근거와 PoC 생성을 한 번의 동적 work에서 함께 수행한다. `DynamicReproductionResult.hypothesis_outcome=SUPPORTED`이면 같은 validated PoC를 `VerificationResult.verdict=TRUE`에 사용하며 별도 PoC work를 만들지 않는다. |
| 정적·Pro·Con으로 근거 있는 `VerificationResult.verdict=FALSE \| HOLD`를 확정할 수 있음 | 요청하지 않음 | 동적 work 없이 결과를 저장할 수 있다. 단, `VerificationResult.verdict=TRUE`는 만들 수 없다. |
| 같은 `verification_generation`에 동적 work가 이미 등록됨 | 두 번째 요청 금지 | 기존 work의 current attempt 또는 허용된 retry 결과만 기다린다. |
| Technical Gate `REVISE`로 새 `verification_generation`이 시작됨 | 필요 목적을 다시 결정 | 이전 `verification_generation`의 request·result·PoC를 재사용하지 않고 새 `verification_generation`에서 최대 한 번 요청한다. |

두 목적이 모두 필요해 보이면 `purpose=VERDICT_EVIDENCE` 하나를 선택한다. 한 `verification_generation`에서 `purpose=POC_CONFIRMATION`과 `purpose=VERDICT_EVIDENCE`를 연속으로 요청하지 않는다. R6가 만드는 불변 `DynamicReproductionRequest`에는 `verification_assignment_ref`, `verification_generation`, `hypothesis_ref`, `purpose`, `initial_verdict`, `goal`, `environment_needs`, `sandbox_profile_ref`, `code_refs`, `static_evidence_refs`, `pro_evidence_ref`, `con_evidence_ref`를 기록한다. `EnvironmentRequirements`, `ReproductionPlan`, recipe, command, payload와 PoC는 R7 책임이므로 R6 request에 미리 확정하지 않는다.

### R6 결과 소비 순서와 차단 조건

1. R6는 current `DynamicReproductionState.status=SUCCEEDED | PARTIAL | BLOCKED | FAILED | CANCELLED`에 연결된 `dynamic_result_ref`를 읽는다. `DynamicReproductionState.dynamic_result_ref`, `WorkExecutionState.output_refs`, `TransitionCommit.output_refs`는 같은 exact `DynamicReproductionResult.meta.record_id`를 가리켜야 한다. `WorkExecutionState.last_transition_commit_ref`는 이 결과를 확정한 `TransitionCommit.state=COMMITTED` revision을 가리켜야 한다. `DynamicReproductionState.status=BLOCKED`는 외부 조치를 기다리는 비종료 상태이며 `finished_at=null`을 유지한다.
2. 결과를 제출하거나 소비하기 전에 다음 기준으로 불일치 원인을 구분한다.
   - 결과 제출 중 `WorkExecutionState.status=RUNNING`이면 `DynamicReproductionResult.meta.attempt_id`가 `WorkExecutionState.active_attempt_id`와 같아야 한다. 다르면 `ATTEMPT_NOT_ACTIVE`로 거절한다.
   - R6가 current 반환 결과를 소비할 때는 `WorkExecutionState.active_attempt_id=null`이므로 이 값과 비교하지 않는다. 대신 `DynamicReproductionResult.meta.attempt_id`가 `WorkExecutionState.last_transition_commit_ref`가 가리키는 `TransitionCommit.attempt_id` 및 해당 `WorkAttempt.attempt_id`와 같아야 한다. 다르면 `ATTEMPT_NOT_ACTIVE`로 거절한다.
   - 고정된 입력, `request_ref` 또는 `DynamicReproductionRequest.verification_generation`이 현재 Verification과 다르면 `STALE_RESULT`로 격리한다.
   - exact reference의 `record_id` 또는 `content_hash`가 기대한 revision과 다르면 `RECORD_REVISION_MISMATCH`로 거절한다.
   - 현재 `WorkExecutionState.state_version`은 `TransitionCommit.target_state_version`과 같아야 한다. 또한 `StateTransition.expected_state_version`은 `TransitionCommit.expected_state_version`과 같고, `StateTransition.new_state_version`은 `TransitionCommit.target_state_version`과 같으며, `target_state_version=expected_state_version+1`이어야 한다. 이 관계를 위반하면 `STATE_VERSION_CONFLICT`로 거절한다.
   - `DynamicReproductionResult.meta.workspace_id`, `meta.commit_id`, `meta.hypothesis_id`, `request_ref`, `purpose`와, `request_ref`가 가리키는 `DynamicReproductionRequest.hypothesis_ref`도 현재 Verification과 exact match해야 한다.
3. `DynamicReproductionResult.status=SUCCEEDED`이고 `hypothesis_outcome=SUPPORTED`이면 실제 `hypothesis_evidence_refs`와 같은 `meta.attempt_id`에서 검증된 `poc_ref`가 모두 있을 때만 `VerificationResult.verdict=TRUE` 후보가 된다.
4. 정상 실행에서 `hypothesis_outcome=DISPROVED`이면 `hypothesis_disproved=true`, 실제 `disproof_evidence_refs`와 `VerificationResult.falsification_results`의 named falsification이 연결된 경우에만 `VerificationResult.verdict=FALSE` 근거가 된다.
5. `DynamicReproductionResult.status=SUCCEEDED \| PARTIAL`이고 `hypothesis_outcome=INCONCLUSIVE`이면 `hypothesis_evidence_refs`와 `limitations`를 기록하고, 남은 조건을 `VerificationResult.unresolved_conditions`에 연결할 수 있을 때만 `VerificationResult.verdict=HOLD` 후보가 된다.
6. 정책 차단·환경 구성 실패·Agent 또는 PoC 생성·실행 실패·timeout·취소는 verdict가 아니다. `DynamicReproductionResult.status=BLOCKED | FAILED | CANCELLED`와 `hypothesis_outcome=INCONCLUSIVE`를 기록하고 final `VerificationResult`와 Gate 요청을 만들지 않는다. `BLOCKED`는 외부 조치를 기다리는 비종료 상태이고, `FAILED`는 복구 불가능하거나 retry 한도를 소진한 종료 상태이며, `CANCELLED`는 사용자 또는 runtime이 중단한 종료 상태다. 각 상태에는 계약에 맞는 `failure_category`와 `failure_reason`을 기록한다.
7. 위 검사를 통과한 동적 결과만 정적·Pro·Con 근거와 합성하고 trusted runtime의 `SAVE_RESULT(result_kind=verification_result)` 검사에 제출한다.

### R6 동적 재현 검증 시나리오

| 시나리오 | 기대 결과 |
|---|---|
| `VerificationResult.initial_verdict=TRUE`, 별도 실행 근거 불필요 | `DynamicReproductionRequest.purpose=POC_CONFIRMATION` work 하나를 만들고 validated `poc_ref`가 확인된 뒤 `VerificationResult.verdict=TRUE` |
| 실행 관측이 판정에 필요 | `DynamicReproductionRequest.purpose=VERDICT_EVIDENCE` work 하나를 만들고 `DynamicReproductionResult.hypothesis_outcome=SUPPORTED`이면 같은 `poc_ref`로 `VerificationResult.verdict=TRUE` |
| 정상 실행에서 named falsification이 실제 근거로 `DynamicReproductionResult.hypothesis_outcome=DISPROVED` | `VerificationResult.verdict=FALSE`, `poc_ref=null` |
| `DynamicReproductionResult.status=SUCCEEDED \| PARTIAL`이고 `hypothesis_outcome=INCONCLUSIVE` | 실제 근거와 `VerificationResult.unresolved_conditions`가 있으면 `VerificationResult.verdict=HOLD` |
| 정책 차단·setup 실패·timeout·PoC 생성·실행 실패 또는 취소 | `DynamicReproductionResult.status=BLOCKED \| FAILED \| CANCELLED`, final `VerificationResult`와 Gate 금지 |
| 결과 제출 중 `WorkExecutionState.status=RUNNING`인데 `meta.attempt_id`가 `active_attempt_id`와 다름 | `ATTEMPT_NOT_ACTIVE`로 거절 |
| R6 결과 소비 시 `meta.attempt_id`가 `COMMITTED TransitionCommit.attempt_id` 또는 해당 `WorkAttempt.attempt_id`와 다름 | `ATTEMPT_NOT_ACTIVE`로 거절 |
| 고정 입력·`request_ref`·`verification_generation`이 현재 Verification과 다름 | `STALE_RESULT`로 격리, Verification 소비 금지 |
| exact reference의 `record_id` 또는 `content_hash`가 기대한 revision과 다름 | `RECORD_REVISION_MISMATCH`로 거절 |
| 현재 `WorkExecutionState.state_version`이 `TransitionCommit.target_state_version`과 다르거나, transition과 commit의 expected·target version 관계가 맞지 않음 | `STATE_VERSION_CONFLICT`로 거절 |
| 같은 `verification_generation`에서 두 번째 동적 목적 요청 | 중복 work 등록 거절 |
| Technical `REVISE` 뒤 이전 `verification_generation` 결과 또는 PoC 재사용 | stale로 거절하고 새 generation에서 새 동적 work 요구 |
