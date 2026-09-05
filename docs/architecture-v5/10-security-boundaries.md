# 10. 보안 경계

- **이 문서는 무엇을 설명하나요?** 저장소, LLM, 비밀정보, Docker와 공식 정책을 안전하게 다루는 규칙을 설명합니다.
- **누가 읽어야 하나요?** 모든 역할 담당자와 보안 검토자가 읽습니다.
- **읽은 뒤 무엇을 확인하거나 결정하나요?** 무엇을 믿지 않아야 하는지, 프로그램이 강제할 제한과 남는 위험을 확인합니다.

`sandbox`는 다른 시스템과 격리된 실행 환경이고 `redaction`은 로그·보고서의 비밀정보를 가리는 처리입니다. 자세한 용어는 [쉬운 용어집](../GLOSSARY.md)을 따릅니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 신뢰 실행 경계

LLM Agent는 분석·검토 결과와 다음 action을 제안하지만 enforcement authority를 갖지 않는다. 신뢰 경계 안의 비-LLM Runtime Validator가 코드 근거의 `workspace_id`·`commit_id` 일치, 지원하는 schema MAJOR, `(logical_record_id, revision_number)` 연결, 역할·호출 권한, 상태 전이, retry/failover 선행 status와 time/cost/call/retry/work/chain budget, provider/session 선택, R5-01 CWELabel과 exact Verification의 provenance 연결, Gate가 읽은 Verification·CWELabel·정책 revision, Reporter 전제조건을 강제한다. token 계획값과 사용량은 관측하지만 token 초과·누락만으로 action을 차단하지 않는다. Runtime Validator는 exact `sandbox_profile_ref`와 `DynamicReproductionLifecycleProfile` revision을 고정하고 R8 lifecycle profile의 호출 전 잔여 시간과 새 attempt 한도를 검사한다. Sandbox Controller는 R7 `sandbox_profile_ref`의 host·Docker daemon/socket·mount/namespace·secret·egress·workspace 격리와 CPU·RAM·disk·PID·요청 가능 최대 시간을 실행 경계에 강제한다. 저장소 내용과 모든 LLM 출력은 validation 전까지 비신뢰 입력이며 policy 변경 명령으로 해석하지 않는다.

## 방향

v5는 계약·정책·무결성 artifact를 아키텍처의 중심으로 확대하지 않는다. 그러나 비신뢰 저장소, LLM provider, 공식 프로그램 정책과 동적 실행을 다루므로 아래 실행 경계는 필수다.

## 1. 로컬 작업공간과 코드 조회

- 모든 사실·가설·문맥·PoC는 동일한 `workspace_id`와 연결된 `commit_id`에 연결한다.
- `Repository Loader`는 실행별 폴더에 clone하고 지정한 commit을 checkout한 뒤 HEAD를 확인한다.
- 분석 중 HEAD나 추적 파일이 바뀌면 `WORKSPACE_CHANGED`로 중단하고 기존 결과에 섞지 않는다.
- retrieval은 `workspace_root` 안의 허용 파일만 읽고 path traversal·symlink escape를 차단한다.
- `CodeLocation.file_path`는 `/` 구분자의 Git 상대 경로로 정규화하며 절대 경로, drive prefix와 `.`·`..` segment를 거절한다. symlink를 해석한 실제 대상도 `workspace_root` 안이어야 한다.
- 도구별 line·column 표현은 정본 `CodeLocation` 규칙으로 변환하고 원래 위치와 tool message는 원본 결과 reference에 보존한다.
- depth/byte/request budget과 반환 location, token 추정 관측값을 기록한다.
- 누락·truncation은 안전함 또는 `FALSE`로 해석하지 않는다.
- 지원하지 않는 schema MAJOR는 `SCHEMA_UNSUPPORTED`로 거절한다. 같은 `logical_record_id`가 아니거나 바로 이전 revision과 이어지지 않는 수정본은 `RECORD_REVISION_MISMATCH`로 거절하고 자동 변환·병합하지 않는다. `RunMeta`의 workspace·commit은 `null`에서 실제 값으로만 바인딩할 수 있고, 코드 근거 `RecordMeta`에서는 두 값이 필수·불변이다.
- 저장된 record를 가리키는 `StoredDataRef.record_id`는 참조 대상 revision의 workspace·commit·내용 hash와 일치해야 하고, 가설별 대상 record의 `RecordMeta.hypothesis_id`도 현재 가설과 같아야 한다. Technical Gate가 검토한 Verification revision이나 Rule Scope Gate가 검토한 Verification·Technical·정책 revision이 바뀌면 이전 Gate 결과를 재사용하지 않는다.
- `Restriction.fact_refs`는 exact final `StaticFactBundle` revision과 그 안의 실제 `fact_id`를 가리켜야 한다. fact/evidence reference가 모두 비어 있거나 다른 workspace·commit을 가리키는 restriction은 저장하지 않는다. proposal의 같은 `fact_id`를 `observed_facts`와 restriction 근거 양쪽에 중복 분류하지 않는다.
- 가설 중복 비교는 trusted runtime이 같은 analysis·workspace·commit의 등록 가설만 비교 후보로 좁힌 뒤 HYPOTHESIS `CALL_LLM`에 exact proposal·후보 reference를 고정한다. LLM은 후보 밖 가설을 중복 대상으로 선택할 권한이 없고 Orchestration은 review 결과를 만들거나 바꿀 수 없다.

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
- 비-LLM Runtime Validator는 action type별 `SCHEMA | AUTHORITY | IDENTITY | REVISION | STATE | BUDGET | TOOL | FILE_PATH | PROVIDER | SESSION | GATE_ORDER | REPORT_READY | REDACTION | DISCLOSURE` 중 필수 check를 모두 수행한다. `RUN_SANDBOX`의 외부 격리 경계는 이 목록에서 제외하고 Sandbox Controller가 한 번 검사한다.
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

- 각 가설의 최초 동적 재현은 clean container에서 시작하고, 서로 다른 가설은 writable container를 공유하지 않는다.
- non-root, 격리된 mount/namespace와 R7 `sandbox_profile_ref`의 CPU·RAM·disk·PID·요청 가능 최대 시간, R8 `DynamicReproductionLifecycleProfile`의 호출 전 잔여 시간·새 attempt 제한을 구분해 사용한다.
- host root/home, Docker daemon/socket, host process namespace와 광범위한 write mount를 Agent에게 제공하지 않는다.
- network는 default-deny이고 versioned profile이 허용한 egress만 연다. package 설치도 승인된 registry egress 안에서만 가능하다.
- production credential, 실제 개인정보와 범위 밖 target을 사용하지 않는다. 환경 요구사항·실제 값·Health Check·AgentLog에도 credential·cookie·token·password 원문을 넣지 않고 필요한 경우 secret store의 불투명 handle만 연결한다.
- R6의 `REQUEST_DYNAMIC_REPRO`는 Runtime Validator가 현재 Verification generation, exact request, 권한·상태·예산과 generation당 하나의 동적 work 제한을 확인한 뒤 R7에 전달한다.
- `RUN_SANDBOX`는 Runtime Validator가 R7 Setup Automation의 권한·상태·예산, exact `DynamicReproductionRequest`·current `EnvironmentRequirements`·current exact `ReproductionPlan`·`sandbox_profile_ref`·exact `DynamicReproductionLifecycleProfile`을 확인하고 action `input_refs`와 `checked_config_refs`에 같은 exact revision을 고정한 `ActionDecision=ALLOW` 뒤 Sandbox Controller로 전달한다. plan revision이 바뀌면 기존 `UNUSED` decision을 `EXPIRED`로 처리하고 새 action을 만든다. 이 ALLOW는 정책 통과나 Docker 실행 성공을 뜻하지 않는다.
- Sandbox Controller는 R7 `sandbox_profile_ref`의 host·Docker daemon/socket·mount/namespace·secret·egress·workspace 격리와 CPU·RAM·disk·PID·요청 가능 최대 시간을 강제하고 exact `sandbox_policy_decision`을 저장한다. R8 lifecycle profile의 호출 전 잔여 시간·새 attempt 한도는 Runtime Validator가 강제한다. 컨테이너 내부 command·package·PoC를 allowlist로 검사하지 않는다.
- 정책을 통과하면 R7 Setup Automation이 저장소 선언을 우선한 recipe로 image build, container 생성·재사용·재생성과 cleanup을 수행한다. Docker build와 실행은 분석용 `CodeWorkspace`를 직접 수정하지 않고 Sandbox 내부 복사본에서 수행한다.
- R7 Agent는 격리된 container 안에서 환경 설정, package, 계정, fixture/mock, PoC, command, 관찰과 재시도를 자율적으로 정한다. Agent는 Docker daemon을 직접 제어하지 않고 Setup Automation의 in-container 실행 통로만 사용한다.
- 같은 가설·work에서는 영향 있는 상태·설정 변화가 없을 때만 container를 재사용한다. `STATE_CHANGED | CONFIG_CHANGED | STATE_UNCERTAIN`이면 재생성하며 crash·비정상 종료·사후 Health Check 실패는 runtime이 `STATE_UNCERTAIN`으로 강제한다.
- 비-LLM Reproduction Session Manager가 실제 event를 durable append-only `AgentLog`에 기록한다. 전역 고유 `event_id`, attempt별 증가 `sequence`를 강제한다. `COMMAND_STARTED`와 `COMMAND_FINISHED`는 같은 exact `SandboxCommandRecord`·digest, `action_id`, attempt, environment·recipe를 가리키며 secret 원문 대신 opaque ref를 쓴 redaction 상태가 유효해야 한다. 이전 attempt의 늦은 event는 current 결과에 섞지 않는다.
- request·plan·recipe·실제 환경·AgentLog·PoC candidate·validated PoC는 같은 analysis·workspace·commit·hypothesis·work·attempt를 가리킨다. 성공한 baseline recipe 재사용은 exact baseline ref와 동일 built image digest를 가진 current-attempt binding으로 기록한다.
- validated PoC 없이 `TRUE` 저장 또는 Technical Gate 호출을 요청하면 Runtime Validator가 거절한다. validated `poc_ref`는 `SUCCEEDED + SUPPORTED`이고 same-attempt AgentLog가 exact candidate revision·digest의 실제 실행을 입증할 때만 허용한다.
- 정리 대상이 하나도 생기지 않았을 때만 `cleanup_status=NOT_REQUIRED`다. 정책 차단 전에 build·container·network·volume·임시 파일이 생겼다면 정리 성공 또는 실패와 exact cleanup reference를 기록한다.
- 환경·정책·Agent·PoC 생성·실행 실패는 가설 `FALSE | HOLD`가 아니다. 같은 R7 Agent session의 조정은 현재 attempt에 기록하고, session 재시작이 필요한 retry만 새 attempt를 사용한다. 외부 조건을 기다릴 때만 `BLOCKED`이며 조건 해결 뒤에는 같은 work에서 `trigger=RESUME`인 새 attempt를 시작한다. 한도 소진 또는 복구 불가 시 `FAILED + INCONCLUSIVE`로 종료하고 과거 attempt 결과를 current 성공 근거로 사용하지 않는다.

## 6. 프로그램 정책 신뢰 경계

- Policy Collector는 확인 가능한 공식 source만 `ProgramPolicyRecord`로 사용하고 source 확인 결과와 parser 실행 결과를 exact reference로 남긴다.
- 저장소 문서, 검색 snippet, 오래된 모델 지식과 비공식 요약을 공식 rule로 승격하지 않는다.
- source URL/reference, 게시자 확인 근거, parser 이름·버전·결과, 수집 시각, 누락과 freshness 기준·근거·만료 시각을 보존한다.
- `PolicyCollectionResult`는 `FOUND | ABSENT_CONFIRMED | COLLECTION_FAILED`를 구분한다. 공식 정책 부재를 확인한 경우에만 `ABSENT_CONFIRMED`이고, fetch·parser 실패는 `COLLECTION_FAILED`이며 Rule Scope review를 만들지 않는다.
- 공식 자료가 없음을 확인했거나 `ProgramPolicyRecord.freshness_status=STALE | UNVERIFIED`이면 `UNCERTAIN + DENY`다. 오래된 record는 감사용으로 보존할 수 있지만 `PASS | ALLOW` 근거로 사용하지 않는다.
- 확정 판단은 실제 정책 항목과 코드·동적 근거를 `RuleScopeEvidenceLink`로 연결한다. 판단을 막는 누락은 `PolicyMissingInfo`로 구조화하고 `blocks_allow=true`이면 공개 허용을 차단한다.

## 7. 근거·권한 연결

다음 연결을 보존한다.

- tool observation → 현재 `workspace_id`의 `CodeLocation`
- hypothesis claim → observed fact/assumption과 `question_id`가 있는 falsification
- retrieved context → request와 실제 location
- `FALSE` verdict → `DISPROVED` falsification question과 실제 evidence
- verdict → Pro/Con/dynamic evidence와 restriction
- result 없는 Primitive → non-empty `required_primitive_candidates`를 가진 exact final HOLD Verification revision과 inputs·restrictions
- result 있는 Primitive → validated PoC를 가진 exact final TRUE + Technical `ACCEPT` + 같은 Verification의 current `PrimitiveAdmissionDecision=ALLOW`
- Chaining candidate → work 시작 시 고정한 `considered_primitive_refs`, 실제 upstream/downstream `input_primitive_refs`, `matched_input_id`, 계보 제외 기록과 비교 근거, 아직 검증되지 않은 상태
- CWE → R5-01 `CWE_LABELING`이 만든 정확한 `CWELabel` revision, 그 label의 exact final TRUE `verification_result_ref`·generation·work·invocation provenance, evidence와 uncertainty
- Technical review → 정확한 Verification·CWELabel revision
- Rule/Scope review → 정확한 Verification·Technical review·CWELabel과 `ProgramPolicyRecord` revision
- current Finding → 같은 exact chain의 final TRUE Verification, validated PoC를 가진 current 동적 결과, current CWELabel, Technical `ACCEPT`와 current Rule Scope review(값 무관); claim 강도는 verified upstream 이하
- report claim → current non-stale Finding, 통과한 result, 두 Gate와 두 Gate가 공통으로 검토한 CWELabel revision

Verification, Chaining, Gate와 Reporter는 제출·공개 권한이 없다. `ReportDraft`는 마지막 Agent 산출물이다.

Reporter는 current Finding·Verification·CWELabel·두 Gate·정책의 exact revision을 사용하고 restriction, limitation, unresolved condition을 보존해야 한다. `CREATE_REPORT_DRAFT`의 redaction 검사가 실패하면 초안을 저장하지 않는다. 선행 revision이 바뀌면 기존 draft는 감사 이력으로만 남고 current `AnalysisRunResult.report_draft_refs`에 넣지 않는다.

Reporter work와 `ReportDraft`가 확정되면 신뢰 runtime이 `AnalysisRunResult`와 `AnalysisRunState`를 원자적으로 확정하고 Agent 자동화를 종료한다. Finding이 없으면 `REPORT_NOT_READY`로 Reporter를 호출하지 않는다. 이후 사람의 검토·수정·제출·공개에는 Agent action, 자동 상태 전이 또는 자동 권한을 제공하지 않는다.

## 위협과 최소 대응

| 위협 | 대응 |
|---|---|
| repository prompt injection | instruction/data 분리, 최소 context, output validation |
| SAST hit 자동 승격 | fact-only 정규화, Verification |
| 규칙 실행 기록이 없어도 “검사 결과 0건”으로 해석 | exact `RuleExecutionRecord` 확인, 미실행·확인 불가와 0건 분리 |
| 저비용 모델의 과도한 확정 | fixed hypothesis schema, 금지 assertion, `INVALID_OUTPUT` |
| LLM 확증 편향 | 운영상 항상 실행하는 독립 Pro/Con, 역할 간 NEW session, 두 Gate |
| session contamination | `NEW/RESUME/AUTO` policy와 결정 logging |
| 잘못된 path 연결 | location retrieval와 Technical Gate linkage 검토 |
| Verification/Chaining 후보의 오승격 | origin을 구분한 새 hypothesis로 전체 재검증 |
| Gate 전 TRUE의 체이닝 오염 | Technical `ACCEPT` 전 result Primitive admission 금지 |
| 정책 판단과 기술 재료 자격 혼합 | Rule Scope의 전용 테스트 제한 판정만 `PrimitiveAdmissionDecision`에 전달하고 다른 정책·scope·impact 판정은 Reporter에만 적용 |
| 다른 규칙 실패를 금지 테스트 위반으로 오인 | 독립 `testing_restriction_compliance`와 같은 area의 근거·누락 구조를 검사하고 `rule_compliance` 또는 link 존재만으로 추정 금지 |
| admission 변경 뒤 진행 중이거나 이미 파생된 체이닝이 오염된 재료 사용 | `source_admission_refs`로 직접·부모 체인의 current exact decision을 재검사하고, 변경·DENY이면 진행 결과 차단과 파생 결과 current 사용 중단 |
| Chaining Agent의 일반 research 확장 | ChainingResult schema와 result-owner validation으로 matching 외 출력 거절 |
| chain 폭증 | ancestor Primitive 재사용 제외, fingerprint 중복 차단과 R8 전체 시간·비용·work 예산; token은 사용량만 관측 |
| 등록만 된 유형별 플레이북의 무단 활성화 | 사람이 승인한 exact `PlaybookPolicy`와 proposal 후보 수를 검사하고 불명확·미허용 유형은 COMMON으로 fallback |
| 플레이북 질문 누락·바꿔치기 | work별 immutable `PlaybookApplication`, 전역 `question_id`, template·결과 집합의 exact 비교 |
| restriction 근거 유실·변조 | exact StaticFactBundle/fact/evidence reference, observed-fact 비중복, 소비 단계의 전체 객체 보존 |
| 중복 판정으로 새 취약점 누락 | runtime 후보 집합 고정, LLM `DUPLICATE` 대상 검사, 오류·불확실 시 fail-open 등록 |
| 같은 작업의 중복 반영 | canonical `dedupe_key`, 한 active attempt, state version compare-and-set |
| 취소·retry 뒤 늦은 결과 오염 | active attempt/input hash 검사와 `STALE_RESULT` 격리 |
| 결과와 상태 일부 저장 | atomic transaction 또는 `TransitionCommit` journal, uncommitted output 차단 |
| crash 뒤 이중 실행 | 마지막 committed transition 재사용과 attempt 이력 보존 |
| 위험한 PoC | sandbox default-deny와 resource limit |
| credential·코드 유출 | adapter secret boundary, 최소 context, redaction |
| 정책 환각 | 공식 부재를 확인한 `ABSENT_CONFIRMED`만 `UNCERTAIN + DENY`; 수집 실패 `COLLECTION_FAILED`는 Gate 미호출 |
| 오래되거나 최신성을 확인하지 못한 정책으로 보고 허용 | `freshness_status=STALE | UNVERIFIED`이면 `UNCERTAIN + DENY`, `PASS | ALLOW` 거절 |
| 새 Verification에 과거 CWELabel을 붙임 | exact Verification·generation·CWE work·attempt·LLM invocation 연결 검사, `STALE_RESULT | RECORD_REVISION_MISMATCH` |
| Gate가 CWELabel을 만들거나 수정함 | R5-01 `CWE_LABELING`만 생산하도록 result-owner 검사, `AUTHORITY_DENIED` |
| Finding이 없거나 오래된 ReportDraft가 current 결과에 포함됨 | Reporter 입력의 exact current dependency 재검사, `REPORT_NOT_READY` 또는 `STALE_RESULT` |
| Agent가 검토·제출·공개를 계속 자동화 | ReportDraft와 AnalysisRunResult 확정 뒤 Agent action이 없는 종료 경계 |
| 역할 위조, ALLOW replay 또는 stale 허가 사용 | trusted requester identity와 exact action·state·input·config·`valid_until` binding, stale이면 `UNUSED -> EXPIRED`, 유효하면 `UNUSED -> USED` 일회성 claim |
| 권한 없는 domain 결과 저장 | 역할별 `SAVE_RESULT` authority와 선행 exact ref 검사 |

## 정적분석 규칙 기록 부정 시나리오

| 입력·사건 | runtime이 반드시 확인할 것 | 기대 차단 결과 |
|---|---|---|
| `CodeFact`가 없다는 이유만으로 규칙 실행 0건을 기록 | exact `RuleExecutionRecord`, 규칙별 execution status와 raw count | 추정값 저장 금지; record가 없으면 `UNKNOWN`으로 처리 |
| `NOT_EXECUTED | UNKNOWN` 규칙에 `hit_count=0`을 기록 | selection·execution·hit count·reason 조합 | `SAVE_RESULT` 거절, 실제 상태와 이유를 다시 기록 |
| 선택한 규칙이 미실행·확인 불가인데 `ToolRunResult.status=SUCCEEDED` | selected 규칙 전체와 ToolRunResult status | 성공 상태 거절, 실제 결과에 따라 `PARTIAL | FAILED | SKIPPED`와 gap·error 기록 |
| 다른 attempt·도구 버전·설정·catalog의 규칙 실행 record를 연결 | `rule_execution_ref`, `meta.attempt_id`, 도구·버전·workspace·commit과 exact refs | `ATTEMPT_NOT_ACTIVE | STALE_RESULT | RECORD_REVISION_MISMATCH`, 정적 사실 묶음에 연결 금지 |
| retry 뒤 이전 규칙 실행 수와 새 실행 수를 합침 | `work_id`, attempt별 record와 active attempt | attempt별 기록 유지, 현재 결과에는 current attempt만 연결 |
| `fact_kind`와 다른 후보 목록에 저장하거나 여섯 목록에서 같은 `fact_id`를 중복 사용 | 종류별 목록 대응, 전체 `fact_id` 유일성, current 도구 출처 | `SCHEMA_INVALID`, `StaticFactBundle` 저장과 다음 단계 전달 금지 |
| `SANITIZER | VALIDATOR` 후보만으로 안전함·경로 차단·`FALSE`를 확정 | 실제 호출·data-flow, 적용 순서·조건, 우회 가능성과 Verification 근거 | 후보를 판정으로 승격하지 않고 R6 Verification에서 검증 |
| 후보 목록이 비었다는 이유로 해당 방어 또는 위험 요소가 없다고 확정 | `tool_runs`, 규칙 실행 범위, `gaps`, `errors` | 빈 배열을 관찰 결과로만 보존하고 안전성 추정 금지 |

## 상태·복구 부정 시나리오

| 입력·사건 | runtime이 반드시 확인할 것 | 기대 차단·복구 결과 |
|---|---|---|
| 같은 가설 검증 요청이 동시에 두 번 도착 | `dedupe_key`, 기존 `work_id` | 기존 작업 반환, 결과 한 번만 반영 |
| retry 전 attempt 결과가 새 attempt보다 늦게 도착 | `active_attempt_id`, `state_version` | `ATTEMPT_NOT_ACTIVE`, 최신 pointer 연결 금지 |
| 다른 `workspace_id` 또는 `commit_id` 결과가 합류 | work input과 result meta | `WORKSPACE_MISMATCH`, 결과 사용 금지 |
| 가설·분석 취소 뒤 결과가 도착 | work와 analysis 취소 상태 | `STALE_RESULT`, downstream 미호출 |
| Technical 보완 전 revision이 Rule Scope Gate나 Reporter로 전달 | exact Verification·CWELabel·Gate `record_id` | `RECORD_REVISION_MISMATCH`, 뒤 단계 차단 |
| 결과 record만 저장되고 종료 상태가 갱신되지 않음 | `TransitionCommit`, state pointer | journal 복구 또는 `TRANSITION_INCOMPLETE` |
| 종료 상태만 있고 output record가 없음 | pointer 대상 존재·hash | `TRANSITION_INCOMPLETE`, 다음 단계 차단 |
| 허용되지 않은 provider/model failover | 바로 앞 호출 status와 fallback profile | `INVOCATION_CHAIN_INVALID`, 결과 사용 금지 |
| crash 뒤 같은 요청이 다시 들어옴 | 마지막 `COMMITTED`, `dedupe_key` | 완료 결과 재사용 또는 허용된 새 attempt, 중복 반영 금지 |
| retry·Gate `REVISE`·chaining이 한도를 넘음 | 횟수·시간·비용·work·cycle·duplicate budget | 중단 이유 저장, Reporter 차단, verdict 자동 변경 금지 |
| `token_budget`이 비어 있거나 실제 token 사용량이 계획값을 넘음 | exact call spec과 provider usage 출처 | token만으로 `BUDGET_EXCEEDED`·`DENY`를 만들지 않고 실제 사용량 또는 unavailable을 기록 |
| 서로 다른 평가 설정의 결과를 직접 비교 | 두 `AnalysisRunResult.eval_config_refs`의 exact set equality | 비교 거절; Gate·Primitive·Reporter 결과는 변경하지 않음 |
| `PARTIAL` 결과에 누락 설명이 없음 | static/context의 `gap_ids`·`error_ids` 또는 dynamic 결과의 `limitations`, output refs | `STATE_TRANSITION_INVALID`, 부분 결과 사용 금지 |
| 외부 조건을 기다리는 동적 attempt의 `BLOCKED` 결과를 같은 work의 `BLOCKED` 상태와 연결하지 않음 | attempt 결과와 공통 work lifecycle 매핑 | 감사용 `DynamicReproductionResult`는 COMMITTED하고 같은 work를 `BLOCKED`로 유지한다. 조건 해결 뒤에는 `trigger=RESUME`인 새 attempt만 허용하며 과거 attempt 결과를 current 성공 근거로 소비하면 `STATE_TRANSITION_INVALID` |
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
| Technical Gate가 `CWELabel`을 생성·수정하거나 새 CWE를 저장하려 함 | `cwe_label` result-owner와 `requested_by` | `AUTHORITY_DENIED`, R5-01의 current label 보존 |
| 새 Verification에 같은 CWE 값의 과거 `CWELabel`을 재사용 | label의 `verification_result_ref`·generation·work·attempt·호출과 current Verification exact 비교 | `STALE_RESULT | RECORD_REVISION_MISMATCH`, R5-01의 새 평가·새 label revision 요구 |
| CWE labeling 호출 실패·timeout·인증 오류를 `FALSE | HOLD`로 바꿈 | CWE work·invocation 상태와 Verification evidence | verdict 변경 거절, work 오류를 보존하고 current label 전까지 Technical Gate 차단 |
| Technical Gate 없이 Rule Scope Gate 호출 | exact Technical review ref와 status | `GATE_ORDER_INVALID` |
| Rule Scope Gate 없이 Reporter 호출 | exact Rule Scope review와 모든 report 조건 | `REPORT_NOT_READY` |
| Finding 정규화 전이거나 stale Finding으로 Reporter 호출 | current Finding 존재와 exact chain(Verification generation/revision·CWELabel·두 Gate·동적 결과·PoC·고정 정책) | `REPORT_NOT_READY`, 새 exact chain에서 Finding 재정규화 요구 |
| Finding 생성 조건을 Reporter 6축 readiness와 동일하게 취급 | Finding: `RuleScopeImpactReview` 존재(값 무관). Reporter: `review_status`·`rule_compliance`·`scope_compliance`·`testing_restriction_compliance` = `PASS`, `security_impact` = `SUFFICIENT`, `report_permission` = `ALLOW` 전부 | 두 자격 분리, `report_permission=DENY`여도 current Finding 보존 |
| 서로 다른 Verification generation·stale upstream reference를 섞은 Finding 생성 | upstream `meta.workspace_id`·`meta.commit_id` 일치. hypothesis-local artifact에 대해서만 동일 `meta.hypothesis_id`를 요구한다. `ProgramPolicyRecord`, `PolicyCollectionResult` 등 hypothesis 비종속 정책 record에는 `hypothesis_id` 일치를 요구하지 않으며, 기존 exact `StoredDataRef`, `meta.workspace_id`·`meta.commit_id` 및 policy revision/provenance 계약으로 검증한다. `CWELabel`·`TechnicalEvidenceReview`·`RuleScopeImpactReview`가 같은 `verification_result_ref`를 가리키고 그것이 current `HypothesisProcessState.verification_result_ref`와 동일, generation은 기존 `HypothesisProcessState`·`VERIFICATION` work·`CWELabel.verification_generation` 계약으로 확인 | Finding 정규화 거절, `STALE_RESULT` 또는 revision mismatch 오류 |
| Finding이 새 verdict·impact·attack path를 만듦 | Finding claim이 verified upstream evidence closure 범위 안인지 | invalid output, verified upstream 이하 claim만 허용 |
| 공식 부재 확인 또는 수집 실패인데 `ALLOW` 출력 | collection status, policy ref와 Rule Scope 불변조건 | `ABSENT_CONFIRMED`는 invalid output과 `UNCERTAIN + DENY`; `COLLECTION_FAILED`는 Gate 호출·review 저장 거절 |
| repository prompt가 Sandbox network를 열라고 함 | Sandbox Controller가 versioned profile과 instruction source 확인 | `UNTRUSTED_INSTRUCTION` 또는 `SANDBOX_POLICY_DENIED` |
| LLM이 workspace 밖 파일을 요청 | 정규화·symlink 해석 뒤 실제 path | `FILE_ACCESS_DENIED` |
| 허용하지 않은 provider/model로 silent failover | provider profile과 선행 invocation | `PROVIDER_PROFILE_DENIED`, 호출 미실행 |
| 인증 실패를 `FALSE`로 저장하려 함 | invocation status와 falsification evidence | invalid result 또는 `AUTHORITY_DENIED`, 실행 오류 유지 |
| Reporter가 새 공격 경로를 확정 | report claim refs와 verified hypothesis | invalid output, 새 hypothesis 검증 전 사용 금지 |
| ReportDraft 이후 Agent 자동화를 계속하려 함 | 현재 stage와 final `AnalysisRunState` | 후속 Agent action 미등록, 자동화 종료 |
| Agent가 사람 검토·외부 제출·공개 action을 요청 | action registry와 요청 역할 | `ACTION_NOT_ALLOWED`, 해당 action 미실행 |
| 선행 결과가 바뀐 오래된 ReportDraft를 current 결과로 사용 | Finding·Verification·CWELabel·두 Gate·정책 exact revision | `STALE_RESULT`, 새 Gate·Reporter work 요구 |
| restriction·limitation 또는 redaction 상태가 빠진 초안을 저장 | ReportDraft 필수 필드와 `CREATE_REPORT_DRAFT` 검사 결과 | `SAVE_RESULT` 거절, 누락을 보존한 새 초안 요구 |
| 같은 ActionRequest를 동시에 두 번 검사 | unique `action_ref.record_id -> decision_id` | 기존 decision 반환, action 한 번만 claim |
| Gate 또는 Reporter가 별도 CALL_LLM으로 우회 | requester 역할과 stage action·call spec | `ACTION_NOT_ALLOWED`, stage action부터 새로 요청 |
| Technical Gate `REVISE` 뒤 같은 입력으로 재투표 | Verification·CWELabel `record_id`와 domain input hash, 이전 decision 사용 상태 | `ACTION_NOT_ALLOWED`, 보완된 Verification과 새 current CWELabel로 새 work·action 요구 |
| action 허가 뒤 Gate 입력 revision이 바뀜 | provider 호출 직전 exact refs·current state 재검사 | `UNUSED -> EXPIRED`, 호출 금지와 새 action 요구 |
| Runtime Validator가 공식 정책 의미를 다시 판단 | Rule Scope output의 생산 역할과 validator 검사 범위 | 정책 해석 금지, Gate의 `UNCERTAIN + DENY` 구조만 확인하고 Reporter 차단 |
| Pro와 Con이 같은 session 또는 parent를 공유 | 역할별 `SESSION`, `NEW`, `parent_session_ref=null`, 서로 다른 call/session ID | `ACTION_NOT_ALLOWED` 또는 `INVOCATION_CHAIN_INVALID`, 두 호출 모두 독립 action으로 다시 요청 |
| Pro 또는 Con prompt·context·조회·tool 결과에 상대 역할 output을 넣음 | trusted prompt payload, context refs, predecessor/parent, result-store query와 tool trace | `CROSS_ROLE_INPUT_DENIED`, 호출·결과 저장·합류 금지 |
| final Verification에 Pro 또는 Con exact result reference가 빠짐 | mode별 `debate_input_hash`, `pro_evidence_ref`, `con_evidence_ref` 조합 | `SAVE_RESULT` 거절, 부모 Verification 대기 또는 실패 처리 |
| Pro·Con 결과의 부모·generation·공통 입력 hash가 서로 다름 | 두 `EvidenceAgentResult`와 current parent Verification exact 비교 | `STALE_RESULT`, 두 결과를 섞지 않고 current 입력으로 다시 실행 |
| 입력이 바뀌었는데 이전에 성공한 Pro 또는 Con 결과를 재사용 | 가설·Context·코드·playbook·Debate·budget revision과 `debate_input_hash` | `STALE_RESULT`, 두 역할 모두 새 child work 또는 current generation 실행 요구 |
| 등록 가설에 없는 단일 `vulnerability_type`을 추정하거나 여러 type 후보 중 하나를 Agent가 선택 | exact `VulnerabilityHypothesis.proposal_ref`, 후보 수와 current `PlaybookPolicy` mapping | TYPE_SPECIFIC 선택 거절; 규칙에 맞는 COMMON application 생성 또는 policy 오류로 work 등록 차단 |
| 등록된 TYPE_SPECIFIC 플레이북을 사람 승인 policy 없이 운영에 사용 | `PlaybookPolicy.policy_ref`, 승인 정보와 exact playbook mapping | `AUTHORITY_DENIED`, COMMON fallback 또는 유효한 current policy 요구 |
| Pro·Con·최종 합성이 서로 다른 `PlaybookApplication` 또는 질문 ID를 사용 | 부모 work input, application의 hypothesis·proposal·policy·playbook·generation과 `debate_input_hash` | `STALE_RESULT`, 합류와 final 저장 거절 |
| final 결과의 질문 ID가 가설 질문과 application 질문의 합집합보다 빠지거나 많거나 중복됨 | 두 exact 질문 집합과 `falsification_results[].question_id` set equality | `SAVE_RESULT` 거절, 같은 application으로 누락 질문 검증 요구 |
| Pro/Con child가 `BLOCKED`인데 부모 Verification은 `RUNNING`으로 계속됨 | `parent_work_ref`, child와 parent state, `waiting_for` | 상태 변경 거절, 부모도 같은 실제 이유로 `BLOCKED`와 가설 `VERIFYING` 강제 |
| Pro/Con child가 최종 실패했는데 부모나 가설을 계속 진행 | child·parent의 committed transition과 `HypothesisProcessState` | 자식 실패를 먼저 확정해 부모 진행 차단, 이어 부모와 가설 `FAILED`를 함께 확정; final result·Gate 금지 |
| `SAVE_RESULT` 검사 뒤 candidate bytes를 바꿈 | `candidate_result_ref.stored_data_id`와 `content_hash`, current attempt·state | decision `EXPIRED` 또는 save `DENY`, 변조 후보 미저장 |
| 실행 오류만 든 `FALSE` 후보를 저장 | `result_kind`, VERIFICATION 생산자, named `DISPROVED`의 `question_id`·`evidence_refs` | `SAVE_RESULT` 거절, 오류 상태 유지와 verdict 자동 생성 금지 |
| 다른 역할이 만든 결과 후보를 저장 | result-owner registry와 `requested_by`, candidate meta | `AUTHORITY_DENIED`, candidate 격리와 최신 pointer 미연결 |
| STATIC_ANALYSIS가 아닌 역할이 `RuleExecutionRecord`를 저장하거나 수정 | `rule_execution_record` result-owner와 `requested_by` | `AUTHORITY_DENIED`, 규칙 실행 이력 불변 유지 |
| R6가 `EnvironmentRequirements`·`ReproductionPlan`·PoC 또는 `DynamicReproductionResult`를 생산 | result-owner registry와 `requested_by` | `AUTHORITY_DENIED`, R6의 `DynamicReproductionRequest`만 허용 |
| R7이 동적 요청의 purpose·가설·필요 조건·profile을 임의 변경 | exact `DynamicReproductionRequest`와 R7 산출물 | `RECORD_REVISION_MISMATCH`, 산출물 저장·실행 금지 |
| 같은 Verification generation에 두 번째 동적 work를 등록 | `hypothesis_id`, `verification_generation`, existing work | `ACTION_NOT_ALLOWED`, 기존 `work_id`를 재사용. 같은 session 조정은 현재 attempt, session 재시작은 `trigger=RETRY`, 외부 조건 해소 뒤 재개는 `trigger=RESUME`인 새 attempt로 처리 |
| `RUN_SANDBOX` 허가 뒤 request·requirements·current exact plan·`sandbox_profile_ref`·`DynamicReproductionLifecycleProfile` revision 중 하나가 바뀜 | 실행 직전 action `input_refs`, `resource_profile_ref`, `checked_config_refs`와 current state | 기존 decision `UNUSED -> EXPIRED`, 새 action 요구 |
| Sandbox 내부 command가 host·Docker socket·secret·미허용 egress에 접근하려 함 | Controller의 외부 경계와 실제 runtime identity·namespace·network | 경계에서 차단하고 `SANDBOX_POLICY_DENIED`; 내부 command allowlist로 대체하지 않음 |
| 동적 결과의 recipe·환경·AgentLog·candidate·PoC·cleanup attempt 또는 digest가 다름 | `RUN_SANDBOX` USED decision, same-attempt provenance와 결과 candidate | `SAVE_RESULT` 거절, 결과 `COMMITTED`·Verification 전달 금지 |
| `COMMAND_STARTED`와 `COMMAND_FINISHED`의 command ref·digest·action·attempt·environment가 다르거나 redaction이 유효하지 않음 | exact `SandboxCommandRecord`, 두 event와 AgentLog meta | `SAVE_RESULT` 거절, command·log 격리와 동적 결과 미확정 |
| Verification 또는 R7 Agent가 `DynamicReproductionResult`를 직접 저장 | `dynamic_reproduction_result` result-owner와 `requested_by` | `AUTHORITY_DENIED`, Reproduction Session Manager만 허용 |
| `agent_invoked`와 AgentLog의 `AGENT_STARTED` event가 다름 | result boolean과 exact `agent_log_ref` | `SAVE_RESULT`의 `SCHEMA` 검사 거절, 가설 판정 변경 금지 |
| 정책 차단 결과에 Controller 판정 reference가 없음 | `POLICY_BLOCKED`와 `policy_decision_ref` | `SAVE_RESULT` 거절, Technical Gate 결과로 대신 채우기 금지 |
| 환경을 생성·재사용했는데 exact `environment_ref` 또는 container 사유가 없음 | Setup Automation event와 exact `sandbox_environment` record | `SAVE_RESULT` 거절, plan이나 recipe로 실제 환경을 대신하지 않음 |
| ReproductionPlan에 `request_ref` 또는 `environment_requirements_ref`가 없음 | 새 MAJOR schema와 plan | `SAVE_RESULT` 거절, R7 Agent가 같은 request를 가리키는 새 requirements·plan 생성 |
| R6가 EnvironmentRequirements를 만들거나 수정함 | result-owner registry와 candidate producer | `AUTHORITY_DENIED`, 변경 후보 격리 |
| plan과 실제 환경이 다른 requirements revision을 가리킴 | `plan.environment_requirements_ref`와 `sandbox_environment.requirements_ref` exact 비교 | `RECORD_REVISION_MISMATCH`, 동적 결과 저장·Verification 전달 금지 |
| 다른 가설의 writable container를 재사용하거나 상태 변화 뒤 그대로 사용 | hypothesis/work, container instance, reuse/recreate reason과 AgentLog | `SAVE_RESULT` 거절, clean 또는 `STATE_UNCERTAIN` 재생성 요구 |
| 허용 목록에 없는 version fallback을 자동 적용함 | VERSION의 `expected | alternatives`와 실제 값 | `ENVIRONMENT_MISMATCH`, recipe 보완 또는 실패 결과 기록 |
| 오래된 EnvironmentRequirements revision을 재사용함 | logical record current head와 RUN_SANDBOX input ref | `STALE_RESULT`, current requirements와 이를 가리키는 새 plan·action 요구 |
| PoC 생성·환경 구성·실행 실패를 `FALSE | HOLD`로 변환함 | `failure_category`, 자유형 `failure_reason`, work status와 Verification candidate | 결과 또는 Verification 저장 거절, 자율 retry·외부 `BLOCKED`를 구분하고 한도 소진 시 `FAILED + INCONCLUSIVE` |
| 환경 요구사항·실제 값에 credential·token 원문을 저장함 | schema secret scan과 `secret_ref` data kind | `REDACTION` 실패, candidate 미저장 |
| R7이 request·requirements·plan·`sandbox_profile_ref`·`DynamicReproductionLifecycleProfile`을 바꾸고 Sandbox 외부 경계 재검사를 생략함 | 새 RUN_SANDBOX action과 Controller decision | `ACTION_NOT_ALLOWED`, 새 외부 경계 검사 전 실행 금지 |
| 정리 대상이 생겼는데 `NOT_REQUIRED`로 기록 | `cleanup_required`, 자원 생성 기록과 `cleanup_status` | `SAVE_RESULT` 거절, 남은 자원 격리와 운영 오류 기록 |
| PoC candidate 존재만으로 validated PoC나 재현 성공을 주장 | result의 exact `poc_candidate_ref`·`poc_ref`, outcome, AgentLog 실행 event와 content digest | `SAVE_RESULT` 또는 Gate 검토 거절, `SUCCEEDED + SUPPORTED` 실행본만 validated PoC로 허용 |
| validated PoC 없이 final TRUE를 저장하거나 Technical Gate를 호출 | current request·result·`poc_ref`와 Verification generation | `SAVE_RESULT` 또는 Gate action `DENY`, final verdict 없이 보완 work로 전환 |

## Verification ownership과 Chaining admission 시나리오

| ID | 입력·사건 | 기대 결과 |
|---|---|---|
| N1 | final HOLD | `required_primitive_candidates`가 하나 이상일 때만 후보 전체를 inputs로 가진 result 없는 Primitive를 두 Gate 없이 저장하고 Chaining 조회 허용 |
| N1-a | final HOLD + `required_primitive_candidates=[]` | Primitive와 Chaining work를 만들지 않고 HOLD 처리 종료 |
| N2 | final FALSE | terminal internal result; Primitive와 Chaining work 생성 금지 |
| N3 | final TRUE, Gate 미실행 | result Primitive admission과 Chaining 금지 |
| N4 | TRUE + Technical `ACCEPT`, 정책 수집 또는 Rule Scope 검토가 아직 종료되지 않음 | result Primitive와 Chaining을 아직 허용하지 않고 admission 입력 완료를 기다림; Finding 정규화 전이므로 Reporter도 금지 |
| N4-a | TRUE + Technical `ACCEPT`, 정책 `COLLECTION_FAILED`로 Rule Scope review 없음 | `PrimitiveAdmissionDecision=NOT_EVALUATED + ALLOW`; Rule Scope review가 없어 current Finding을 만들지 않고 Reporter 금지 |
| N5 | TRUE + Technical `ACCEPT` + Rule Scope의 다른 판단 `FAIL | UNCERTAIN | DENY`, testing restriction은 `PASS | UNCERTAIN` | `PrimitiveAdmissionDecision=ALLOW`; result Primitive와 Chaining 자격 유지. Rule Scope review가 존재하므로 신뢰 runtime이 current Finding을 정규화하되 `report_permission=DENY`이면 Reporter만 차단하고 Finding은 보존 |
| N6 | TRUE + Technical `ACCEPT` + Rule Scope review가 Reporter 6축 readiness 전부 충족 | `PrimitiveAdmissionDecision=ALLOW`; result Primitive와 Chaining 자격 유지, current Finding 정규화 후 Reporter 조건 평가 허용 |
| N6-a | current Finding 존재 후 Verification generation·CWELabel·두 Gate·동적 결과·PoC·고정 정책 중 하나가 새 revision으로 변경 | 기존 Finding은 감사 이력으로만 남고 stale 처리; 새 exact chain에서 Finding 재정규화 전까지 Reporter 금지 |
| N7 | result가 있는 TRUE Primitive + result가 없는 HOLD Primitive | upstream result가 HOLD input 하나를 근거 있게 충족하면 `origin=CHAINING` proposal을 새로 등록·검증 |
| N8 | result가 있는 서로 다른 TRUE Primitive 둘 | 앞 result가 뒤 Primitive의 `inputs` 한 항목을 근거 있게 충족할 때만 TRUE_TRUE proposal 허용 |
| N9 | TRUE+TRUE 입력 중 한 부모가 Technical 비정상이거나 direct·ancestor current `PrimitiveAdmissionDecision=ALLOW`를 충족하지 않음 | result Primitive가 될 수 없으므로 match 저장과 proposal 등록 거절 |
| N10 | match의 entity 또는 privilege 충족 근거가 없음 | uncertain candidate를 만들지 않고 `no_match_reasons`에 이유 기록 |
| N10-A | 성립한 match의 후보가 양방향 계보에서 이미 사용한 Primitive를 같은 결과에서 다시 사용 | 그 후보를 근거로 조상을 제외하고 match 입력에서 빼며, DB와 부모 verdict는 변경하지 않음 |
| N10-B | `excluded_primitive_ref`가 고정된 `considered_primitive_refs` 밖이거나 실제 match에 다시 포함됨 | `SAVE_RESULT` 거절; 같은 Chaining work가 고정한 조상 제외 전 입력과 제외 후 match를 다시 계산 |
| N10-C | `excluded_by_ref`가 같은 work 입력이 아니거나 실제 match에 사용되지 않았거나 자신도 제외됐거나 계보가 제외 대상을 포함하지 않음 | `SAVE_RESULT` 거절; 성립한 match에 사용된 Primitive와 §06 계보 관계가 확인된 exclusion만 허용 |
| N10-D | exclusion pair가 중복되거나 reason code·analysis·workspace·commit이 다름 | `SCHEMA_INVALID | STALE_RESULT` 중 실제 원인으로 저장 거절; 값을 추정하거나 다른 work reference로 교체하지 않음 |
| N10-E | CHAINING 자식이 `observed_facts`를 채우거나 부모 계보에서 검증 시작점을 복원할 수 없음 | proposal 등록과 Verification 배정 거절; `observed_facts=[]`로 고정하고 exact 부모 entity·location을 복원한 뒤 다시 제안 |
| N10-F | `source_result_refs` 또는 match candidate의 parent 가설·Verification 목록이 실제 입력 Primitive와 다르거나 중복됨 | `SAVE_RESULT` 거절; 같은 work의 upstream/downstream Primitive가 직접 가리키는 source reference의 중복 없는 합집합으로 다시 생성 |
| N10-G | `considered_primitive_refs` 또는 `input_primitive_refs`에 같은 exact reference가 중복됨 | 집합 내용이 같아도 `SCHEMA_INVALID`로 `SAVE_RESULT` 거절; work 입력과 실제 match 합집합을 각각 중복 없이 직렬화 |
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
| N27 | restriction 문장만 저장하거나 `fact_refs`와 `evidence_refs`를 모두 비움 | `SCHEMA_INVALID`; final proposal·Verification·Primitive·ReportDraft 저장 거절 |
| N27-A | INITIAL proposal restriction의 `fact_refs`가 비어 있거나 final StaticFactBundle 밖 사실을 가리킴 | `SCHEMA_INVALID`; exact 정적 사실에 연결하기 전 등록 거절 |
| N28 | 같은 `fact_id`를 proposal의 observed fact와 restriction 근거 양쪽에 넣음 | `SCHEMA_INVALID`; 서로 겹치지 않게 분류하기 전 등록 거절 |
| N29 | 중복 LLM이 runtime 후보 목록 밖 가설을 `DUPLICATE` 대상으로 지목 | review와 오류를 보존하고 `INVALID_DUPLICATE_TARGET`으로 fail-open 등록 |
| N30 | 중복 LLM 호출 실패·형식 오류·`UNCERTAIN`을 proposal 삭제로 처리 | 삭제 거절; 각각 `CHECK_FAILED | UNCERTAIN` 사유로 새 가설 등록 |
| N31 | 가설 type 후보가 없거나 여러 개인데 TYPE_SPECIFIC 플레이북을 선택 | 선택 거절; current `PlaybookPolicy.common_playbook_ref`로 새 application 생성 |
| N32 | policy에 없는 type 또는 policy와 다른 playbook revision을 선택 | work 등록 거절; exact policy mapping과 playbook을 다시 고정 |
| N33 | 플레이북 질문 template가 application에서 빠지거나 다른 문장·중복 ID로 저장됨 | application 저장 거절; template set과 새 전역 question ID를 다시 생성 |
| N34 | Verification 결과가 hypothesis 질문만 처리하고 application 질문을 누락 | `SAVE_RESULT` 거절; 두 질문 집합의 합집합을 정확히 한 번씩 검증 |
| N35 | 정책 수집 실패를 정책 부재로 바꿔 `UNCERTAIN + DENY` review를 저장 | `PolicyCollectionResult.status=COLLECTION_FAILED`와 error를 보존하고 Rule Scope Gate work·호출·review 저장 거절 |
| N36 | Rule·Scope·Impact 확정 판단에 사용한 정책 항목 또는 실제 근거 연결이 없음 | `SAVE_RESULT` 거절; 같은 area의 `RuleScopeEvidenceLink`를 exact 정책·근거 reference로 다시 생성 |
| N37 | 다른 규칙 때문에 `rule_compliance=FAIL`이지만 `testing_restriction_compliance=PASS` | 금지 테스트 위반으로 바꾸지 않고 `PrimitiveAdmissionDecision=ALLOW`; 보고 가능성만 별도로 차단 |
| N38 | `testing_restriction_compliance=FAIL`인 Rule Scope review | exact `TESTING_RESTRICTION` link를 확인하고 `PrimitiveAdmissionDecision=DENY`; result Primitive와 Chaining 금지 |
| N39 | `TESTING_RESTRICTION` link만 있고 전용 판정이 없거나 판정과 link가 모순됨 | Rule Scope review와 admission decision 저장 거절; `rule_compliance`나 link 존재로 판정 추정 금지 |
| N40 | 정책 수집이 `COLLECTION_FAILED`라 Rule Scope review가 없음 | exact collection result와 error를 보존한 `NOT_EVALUATED + ALLOW + POLICY_COLLECTION_FAILED`; 확정 위반으로 취급하지 않되 Reporter 금지 |
| N41 | Chaining work가 실제 match에 사용한 admission decision 뒤 current decision이 `DENY`로 변경됨 | 이전 Primitive를 current index에서 제거하고 진행 중 결과도 `STALE_RESULT`; 새 child 등록 금지. 사용하지 않은 후보 변경만으로는 결과를 거절하지 않음 |
| N42 | result Primitive에 current `admission_decision_ref`가 없거나 다른 Verification의 decision을 참조 | `SAVE_RESULT` 거절; same analysis·workspace·commit·hypothesis·Verification의 current ALLOW decision 요구 |
| N43 | 이미 COMMITTED된 Chaining 자식·손자 뒤 부모 admission이 `DENY`로 변경됨 | `source_admission_refs`와 `source_primitive_match_id` 계보를 따라 파생 Primitive를 current index에서 제거하고 새 Verification·Gate·Primitive·Reporter 사용 차단; 과거 verdict와 결과는 감사 이력으로만 보존 |
| N44 | `ChainingResult.source_admission_refs`가 실제 match의 direct·ancestor ALLOW decision 합집합과 다름 | `SAVE_RESULT` 거절; 누락·추가·중복·다른 계보 reference를 바로잡기 전 child 등록 금지 |

## 남는 위험

LLM 오판, static coverage gap, 실제 환경과 sandbox의 차이, provider 기능·약관 변경, policy freshness와 redaction 누락 가능성은 남는다. 따라서 두 Gate를 안전 보증으로 설명하지 않고 원문 근거·오류·제한·미확인 후보를 사람에게 함께 제공한다.
