# R3-01. 22단계 구현 모듈·입출력·저장 위치 매핑

- **이 문서는 무엇을 설명하나요?** Architecture v5의 정본 22단계를 실제 프로그램 모듈, 입력·출력 계약, 실행 권한, 저장 위치와 테스트 단위에 연결합니다.
- **누가 읽어야 하나요?** 전체 구현 담당자와 R1·R2·R4·R5·R6·R7·R8 역할 검토자가 읽습니다.
- **읽은 뒤 무엇을 결정해야 하나요?** 각 단계의 구현 위치와 연결 계약이 맞는지 검토하고, 아래 미확정 항목을 담당 Issue에서 확정해야 합니다.

> 상태: **DESIGN_AUTHORED / REVIEW_REQUIRED / NOT_IMPLEMENTED**

## 1. 기준과 문서의 권한

- 작성 기준 `main`: `3d30253acc27d57916611e0ebea2fd46344c5fa8`
- 연결 Issue: [R3-01 #24](https://github.com/SASTsimi/sastsimi/issues/24)
- 상위 Issue: [R3 #4](https://github.com/SASTsimi/sastsimi/issues/4)
- 후속 Issue: [R3-02 #25](https://github.com/SASTsimi/sastsimi/issues/25), [R3-03 #89](https://github.com/SASTsimi/sastsimi/issues/89), [R3-05 #91](https://github.com/SASTsimi/sastsimi/issues/91), [R3-06 #92](https://github.com/SASTsimi/sastsimi/issues/92)

이 문서는 번호 문서 `01`–`13`의 설계 의미를 구현 단위로 옮긴다. 데이터 이름과 상태 의미가 다르면 [08. 경량 데이터 계약](../08-lightweight-data-contracts.md)이 우선하고, 전체 순서는 [01. 시스템 개요](../01-system-overview.md)가 우선한다. 이 문서는 새 field·enum·판정 기준을 단독으로 만들지 않는다.

직접 대조한 정본은 같은 기준 commit의 [01. 시스템 개요](../01-system-overview.md), [02. 정적 사실 계층](../02-static-fact-layer.md), [03. Agent와 Orchestration](../03-agent-roles-and-orchestration.md), [04. 검증과 동적 재현](../04-verification-and-dynamic-reproduction.md), [05. Gate와 보고](../05-llm-gate-and-reporting.md), [06. Chaining](../06-chaining.md), [07. 결과와 관측성](../07-results-and-observability.md), [08. 경량 데이터 계약](../08-lightweight-data-contracts.md), [09. LLM 연결과 기록](../09-llm-provider-session-and-logging.md), [10. 보안 경계](../10-security-boundaries.md)다. 이 문서들의 revision 기준은 위 `main` commit SHA 하나로 고정한다.

여기 적은 `entry point`는 구현자가 호출 경계를 이해하기 위한 **논리 이름**이다. 최종 Python package와 함수 이름은 R3-06에서 확정한다. 저장 위치도 현재는 [07. 결과 저장과 관측성](../07-results-and-observability.md)의 논리 영역을 사용하며 SQLite·artifact store 같은 물리 제품은 R3-06에서 확정한다.

## 2. 구현 전체에서 지켜야 하는 조건

1. 실행별 로컬 clone과 `workspace_id + commit_id`가 코드 기준이다. 별도 저장소 사본 생성 모듈은 만들지 않는다.
2. 첫 구현에 별도 message queue 제품을 두지 않는다. 병렬 작업은 runtime이 `WorkExecutionState`와 제한된 worker로 관리한다.
3. LLM은 분석 결과나 다음 action을 제안하고, 비-LLM Runtime Validator와 전용 controller가 실행·저장 권한을 강제한다.
4. 정적 분석은 코드 사실 공급 계층이다. 취약점 verdict를 만들지 않는다.
5. 운영 분석은 모든 유효 가설에서 Pro와 Con을 서로 다른 `NEW` session으로 병렬 실행한다.
6. 한 Verification generation에는 `DYNAMIC_REPRO` work가 하나뿐이다. retry는 같은 `work_id`의 새 `attempt_id`다.
7. final `TRUE`에는 같은 generation의 exact `DynamicReproductionRequest`, `DynamicReproductionResult(status=SUCCEEDED, hypothesis_outcome=SUPPORTED)`와 validated `poc_ref`가 모두 필요하다.
8. `FALSE`와 `HOLD`는 CWE·두 Gate 입력이 아니다. 실행 오류도 `FALSE`나 `HOLD`로 바꾸지 않는다.
9. TRUE 경로는 `CWE_LABELING → Technical Evidence Gate → policy collection → Rule Scope Impact Gate` 순서를 지킨다.
10. Technical `REVISE`는 기존 work를 되살리지 않고 같은 ACTIVE Verification owner에게 새 generation으로 돌아간다. Runtime은 새 `PlaybookApplication`과 질문 ID를 만들고, 새 고정 입력 묶음과 `debate_input_hash`로 Pro·Con을 항상 다시 실행한다. Context 보완은 필요한 범위에서, 동적 재현은 final TRUE 후보 또는 판정용 실행 근거가 필요할 때 수행한다.
11. HOLD는 `inputs`만 있고 `result=null`인 Primitive가 될 수 있다. TRUE는 Technical `ACCEPT`와 current `PrimitiveAdmissionDecision=ALLOW`가 있어야 `result` Primitive가 된다.
12. Verification과 Chaining의 새로운 material claim은 새 가설로 등록하고 전체 Verification을 다시 수행한다.
13. Reporter는 내부 `ReportDraft`까지만 만든다. `AnalysisRunResult`가 확정되면 Agent 자동화가 끝나며 이후 사람 검토·제출·공개는 시스템 밖이다.
14. 다음 단계는 exact output이 `TransitionCommit.state=COMMITTED`이고 상태 pointer와 같은 revision을 가리킬 때만 시작한다.

## 3. 표 읽는 방법

각 단계 행은 Issue #24의 필수 항목을 다음 열로 묶어 표시한다.

- `주체`: 단계 종류, 논리 담당 역할과 실제 실행 주체
- `진입점·work`: 논리 entry point와 `WorkExecutionState.work_type`
- `입력`: exact 입력 contract와 필수 reference
- `출력`: 출력 contract와 생산 권한
- `action·검사`: 필요한 `ActionRequest.action_type`과 검사 위치
- `저장`: record·artifact·log 영역과 current pointer 갱신
- `연결`: 앞·뒤 단계, 병렬·직렬·fan-out·join
- `상태·오류`: 성공·부분 성공·실패·취소, retry와 오류 전달
- `시험·검토`: 구현할 테스트 위치, 정본 문서와 역할 검토자

`테스트 위치`는 R3-06에서 확정할 package 구조를 기준으로 한 요구 경로다. R3-06에서 이름을 바꾸더라도 테스트 책임과 시나리오는 빠뜨릴 수 없다.

## 4. 정본 22단계 구현 매핑

| 단계 | 주체 | 진입점·work | exact 입력 | 출력과 생산 권한 | action·검사 | 저장·current 처리 | 연결·병렬성 | 상태·오류·retry | 시험·정본·검토 |
|---:|---|---|---|---|---|---|---|---|---|
| 1. 분석 시작 | 사람 입력 / R3 통합 / Orchestration runtime | `AnalysisService.start_run` / 별도 work 없음, 다음 `WORKSPACE_PREP` 등록 | repository URL 또는 로컬 Git reference, 요청 commit/ref, `purpose`, versioned 실행·평가 설정 | `analysis_id`, `AnalysisRunState(RUNNING)`, `RunMeta`; 신뢰 runtime만 ID·초기 상태 생산 | 입력 schema·repository scheme·purpose 검사 후 `REGISTER_WORK(WORKSPACE_PREP)` | `runs`; `AnalysisRunState` current pointer 생성, secret·절대 workspace path는 일반 record에 미저장 | 사용자 요청 → 2; 분석마다 독립, 같은 `analysis_id` 중복 생성 금지 | 입력 오류는 `INPUT_ERROR`, 분석 `FAILED`; 아직 `workspace_id/commit_id=null`; 오류를 verdict로 만들지 않음 | `tests/integration/test_analysis_entry.py`; 01·08·10 / R3·R4 |
| 2. clone·checkout | 비-LLM 도구 / R3 통합 / Repository Loader | `WorkspaceService.prepare` / `WORKSPACE_PREP` | Step 1의 exact run ref, repository reference, 요청 commit/ref | `CodeWorkspace`; REPOSITORY_LOADER만 준비·상태 갱신 | `RUN_TOOL(requested_by=REPOSITORY_LOADER)` 후 `SAVE_RESULT`; path·Git 실행·HEAD·workspace 불변성 검사 | `runs`와 runtime 전용 workspace registry; `workspace_id → repository_url + commit_id` 보존, 로컬 절대 경로 비공개 | 1 → 2 → 3; 완료 전 정적 도구 시작 금지 | `READY`만 분석 가능. clone/checkout 실패는 `CLONE_FAILED/CHECKOUT_FAILED`, 분석 `FAILED`; HEAD 변경은 `WORKSPACE_CHANGED` | `tests/integration/test_workspace_prepare.py`, `tests/security_negative/test_workspace_boundary.py`; 01·02·08·10 / R3·R4·R2 |
| 3. AST·SAST 병렬 실행 | 외부 도구 / R2 / Static Tool Coordinator와 tool adapter | `StaticToolCoordinator.run_all` / 도구마다 `STATIC_TOOL` | READY `CodeWorkspace`, exact 분석 설정·rule catalog·tool profile | raw AST/SAST artifact, `ToolRunResult`; 규칙 기반 도구는 exact `RuleExecutionRecord`; STATIC_ANALYSIS만 생산 | tool마다 `REGISTER_WORK → START_ATTEMPT → RUN_TOOL → SAVE_RESULT`; tool/path/budget와 attempt·catalog·규칙 set 검사 | raw 결과는 content-addressed artifact, 정규 record는 `facts`, 상태·오류는 `runs`; current tool output은 COMMITTED transition으로만 노출 | AST·CodeQL·OpenGrep 등을 fan-out 병렬 실행 → 4에서 join | 도구별 `SUCCEEDED/PARTIAL/FAILED/SKIPPED`; retry는 같은 work의 새 attempt. `EXECUTED+0`, 미실행, 확인 불가를 구분하고 일부 실패를 안전함으로 해석하지 않음 | `tests/integration/static_analysis/`, `tests/contract/test_rule_execution_record.py`; 01·02·07·08·10·ADR-006 / R2·R4·R8 |
| 4. 정적 사실 정규화 | 비-LLM runtime / R2 / Static Fact Normalizer | `StaticFactService.normalize` / `STATIC_NORMALIZE` | Step 3의 모든 기대 tool 종료 상태와 exact `ToolRunResult`, `RuleExecutionRecord`, raw refs | `StaticFactBundle`; STATIC_ANALYSIS만 생산 | `SAVE_RESULT(result_kind=static_fact_bundle)`; 여섯 CodeFact 목록·fact kind·producer attempt·workspace/commit·raw ref 검사 | `facts`; exact bundle current pointer, raw artifact는 참조만 유지 | 3의 fan-in join → 4 → 5; 신뢰 결과가 있으면 일부 tool 실패 상태도 함께 정규화 | `SUCCEEDED` 또는 gap/error가 있는 `PARTIAL`; 다른 attempt·commit 혼합은 `STALE_RESULT/WORKSPACE_MISMATCH` | `tests/contract/test_static_fact_bundle.py`, `tests/integration/test_static_join.py`; 01·02·07·08·10·ADR-010 / R2·R4·R6·R8 |
| 5. 초기 가설 work 준비 | 전역 제어 / R3·R1 / Orchestration runtime | `HypothesisWorkflow.register_initial_work` / `HYPOTHESIS_PROPOSAL` | COMMITTED current `StaticFactBundle`, exact run/provider/model/prompt/budget 설정 | `WorkExecutionState(HYPOTHESIS_PROPOSAL)`과 첫 attempt; 신뢰 runtime만 work·attempt 생산 | `REGISTER_WORK`, `START_ATTEMPT`; schema·revision·state·budget·dedupe 검사 | `runs/actions`; work state current pointer와 immutable `input_refs/input_hash` | 4 → 5 → 6; bundle `PARTIAL`도 gap과 함께 허용 | 입력 revision 변경은 새 work; 예산·권한 부족은 `BLOCKED/FAILED`, 가설 verdict 없음 | `tests/integration/test_hypothesis_work_registration.py`; 01·03·07·08·10 / R3·R1·R4·R8 |
| 6. Hypothesis LLM 호출 | LLM Agent / R1 / Hypothesis Agent Runtime·Provider Adapter | `HypothesisAgent.propose` / Step 5 work의 active attempt | immutable `LLMCallSpec`, trusted prompt payload, current StaticFactBundle와 필요한 최소 code fragment refs | constrained raw response와 `LLMInvocationResult`; parsed proposal candidate는 아직 비신뢰 | `CALL_LLM(requested_by=HYPOTHESIS)`; Runtime Validator가 identity·revision·state·budget·provider·session·redaction 검사, adapter가 호출 | exposed request/response artifact와 `LLMInvocationLog`는 `invocations`; credential·hidden reasoning 미저장 | 5 → 6 → 7; 같은 run에 복수 invocation 가능하나 각 `llm_call_id` 구분 | auth/rate limit/timeout/provider/invalid output은 호출 상태·오류. 허용 repair/retry는 새 attempt·call·action·NEW session, `FALSE` 변환 금지 | `tests/integration/providers/test_hypothesis_call.py`, `tests/security_negative/test_prompt_injection.py`; 03·07·08·09·10 / R1·R3·R4·R8 |
| 7. proposal 검증·전역 등록 | LLM 출력 검증 + 비-LLM registry / R1·R3 / Proposal Validator·Duplicate Review·Hypothesis Registry | `HypothesisRegistry.validate_and_register` / Step 5 `HYPOTHESIS_PROPOSAL` | Step 6 output, exact StaticFactBundle, 같은 analysis/workspace/commit의 narrowed duplicate candidates | valid `HypothesisProposal(origin=INITIAL)`, `ProposalProcessState`; 필요 시 `HypothesisDuplicateReview`; 중복 아니면 `VulnerabilityHypothesis`와 `HypothesisProcessState(REGISTERED)` | 구조·semantic 검증과 `SAVE_RESULT`; 중복 후보가 있을 때만 HYPOTHESIS `CALL_LLM`; ID·restriction fact refs·질문·validation ID·중복 target 검사 | `hypotheses`, `invocations`, `runs`; proposal 상태와 신규 가설 등록은 atomic, exact duplicate이면 새 `hypothesis_id` 없음 | 6 → 7 → 8; proposal별 fan-out, invalid/duplicate는 해당 proposal만 종료 | repair 후 invalid는 `INVALID_OUTPUT`; duplicate check 실패·UNCERTAIN은 기록 후 fail-open 등록; 다른 proposal 계속 | `tests/contract/test_hypothesis_proposal.py`, `tests/integration/test_duplicate_registration.py`; 03·07·08·10·ADR-008 / R1·R3·R4·R8 |
| 8. Verification 배정 | 전역 제어 + 비-LLM state / R3·R6 / Assignment Runtime | `VerificationDispatcher.assign` / `VERIFICATION` 등록 | registered `VulnerabilityHypothesis`, exact proposal, current PlaybookPolicy·VerificationPlaybook | ACTIVE `VerificationAssignment`, `HypothesisProcessState(ASSIGNED/VERIFYING)`, `VERIFICATION` work와 `PlaybookApplication`; runtime만 ID·assignment·application 생산 | `REGISTER_WORK(work_type=VERIFICATION)`과 상태 전이; owner identity·dedupe·playbook 선택·question ID·atomic create 검사 | `hypotheses/runs`; assignment와 process current pointer, work input refs에 hypothesis·proposal·policy·playbook·application 고정 | 등록 가설마다 fan-out 병렬 배정 → 각 가설 9; 가설당 ACTIVE owner 하나 | assignment 충돌·stale policy·application 실패 시 실행 금지; 오류를 verdict로 변환하지 않음 | `tests/integration/test_verification_assignment.py`, `tests/contract/test_playbook_application.py`; 03·04·08·10·verification-playbooks / R3·R6·R4·R8 |
| 9. 위치 기반 Context 조회 | 비-LLM 코드 조회 / R2·R6 / Context Retrieval Service | `ContextService.retrieve` / 요청마다 `CONTEXT_RETRIEVAL` | ACTIVE assignment, current hypothesis, `CodeContextRequest`, exact workspace/commit, allowed relation과 limits. `origin=CHAINING`이고 직접 entity·location이 비어 있으면 exact `source_primitive_match_id` 계보와 부모 Primitive의 `entity_refs` | `CodeContextResponse`, code fragment artifact refs, `DataGap/AnalysisError`; Context service만 조회 결과 생산 | `READ_CODE`와 `SAVE_RESULT`; file path·workspace·commit·depth/byte/request budget·symlink boundary 검사. 체이닝 자식은 `source_primitive_match_id → PrimitiveMatchCandidate → 부모 Primitive → entity_refs`를 따라 시작점을 복원하고 current exact 계보인지 검사 | `contexts`와 code fragment artifact; request/response exact pair와 returned location 기록 | 8 → 9 → 10/11; Verification·Pro·Con이 필요한 만큼 반복 요청 가능 | 일부 실패는 retry/대체 조회 가능. 체이닝 계보가 무효·stale이거나 시작점을 하나도 복원할 수 없으면 자식 등록·배정을 거절하며, 방어적으로 Step 9에 도달한 경우 Context work를 실패시킨다. 조회 오류만으로 HOLD/FALSE 금지 | `tests/integration/test_context_retrieval.py`, `tests/integration/test_chained_child_context.py`, `tests/security_negative/test_code_path_escape.py`; 02·04·06·07·08·10 / R1·R2·R6·R4 |
| 10. Pro·Con 독립 병렬 검증 | LLM Agent fan-out/join / R6 / Pro Agent·Con Agent·Debate Join Runtime | `DebateService.run` / `PRO_EVIDENCE`와 `CON_EVIDENCE` child work | 같은 parent Verification·generation, exact hypothesis/context/static/policy/playbook/application/question set, 같은 `debate_input_hash`; 상대 역할 결과는 입력 금지 | 정확히 한 `EvidenceAgentResult(role=PRO)`와 한 `EvidenceAgentResult(role=CON)`; 각 역할만 자기 결과 생산 | child별 `REGISTER_WORK/START_ATTEMPT/CALL_LLM/SAVE_RESULT`; NEW session·역할 identity·공통 입력 set·cross-role 차단·join 검사 | `verifications`, `invocations`, `runs`; child result는 각각 COMMITTED하고 parent가 exact 두 ref를 읽음 | Pro/Con fan-out 병렬 → 두 current child가 모두 성공하면 join → 11 | 한쪽 retry 가능 실패는 그 child와 parent `BLOCKED`; 입력이 같으면 성공한 반대쪽 보존. 최종 실패는 child → parent → 가설 순서로 `FAILED`, final verdict 없음 | `tests/integration/test_debate_join.py`, `tests/security_negative/test_cross_role_isolation.py`; 03·04·07·08·09·10 / R6·R4·R8 |
| 11. initial verdict | LLM Agent / R6 / Verification Agent Runtime | `VerificationService.assess_initial` / parent `VERIFICATION` work 계속 | exact hypothesis·playbook application, completed validation checks와 falsification questions, static/context, current Pro·Con refs | initial `TRUE/FALSE/HOLD`를 포함한 Verification candidate 내부 상태와 dynamic 필요 결정; final `VerificationResult`는 아직 아님 | VERIFICATION `CALL_LLM`; structured output·질문/검증 set·근거 ref 검사. final 저장은 Step 13에서만 수행 | active work 내부 staging과 `invocations`; current final Verification pointer는 갱신하지 않음 | 10 → 11; initial TRUE는 12의 `POC_CONFIRMATION`, 실행 관측 필요 HOLD는 `VERDICT_EVIDENCE`, 정적 근거로 충분한 FALSE/HOLD는 13 | 미완료 validation·Pro/Con·필수 Context는 final 후보 금지. 실행 오류는 work `BLOCKED/FAILED`이며 initial verdict 근거가 아님 | `tests/contract/test_initial_verdict_routing.py`, `tests/security_negative/test_error_not_verdict.py`; 03·04·08·10 / R6·R4·R7 |
| 12. 동적 재현·PoC | LLM + 비-LLM Sandbox / R6 요청·R7 실행 / R7 Agent·Setup Automation·Sandbox Controller·Session Manager | `DynamicReproductionService.execute` / `DYNAMIC_REPRO` | R6의 exact `DynamicReproductionRequest`, parent Verification/generation, R8 limits; R7이 만든 current `EnvironmentRequirements`·`ReproductionPlan`; Sandbox profile | R7 Agent: requirements/plan/PoC candidate·해석. Setup: recipe/environment/cleanup. Controller: policy decision. Session Manager: append-only `AgentLog`, validated `PoCBundle`, `DynamicReproductionResult` | R6 `REQUEST_DYNAMIC_REPRO` → R7 Agent의 경계 전 `CALL_LLM(requested_by=R7_AGENT)`과 requirements/plan `SAVE_RESULT` → R7 Setup의 `RUN_SANDBOX` 요청 → Runtime Validator와 Controller의 외부 경계 검사 → 승인 뒤 Sandbox 실행 Agent 시작(`agent_invoked=true`)과 candidate·command·관찰·retry event → 역할별 `SAVE_RESULT`. Runtime Validator는 identity/revision/state/budget/same-attempt를 검사하고 Controller는 host·Docker·mount/namespace·secret·egress·workspace·resource 경계를 검사 | `dynamic`, artifact store, append-only AgentLog, `actions/runs`; `DynamicReproductionState`, work output, COMMITTED transition이 같은 final result ref를 가리킴 | 11 → 12 → 13; generation당 work 하나, Sandbox 내부 event는 직렬/반복 가능 | 같은 Agent session의 command·PoC·환경 조정은 같은 attempt의 event다. session 재시작이 필요한 일시 오류만 한도 안에서 같은 work의 새 attempt로 자동 retry하고, 외부 설정·정책·승인·resource 변경 대기만 `BLOCKED` 후 `trigger=RESUME`인 새 attempt를 만든다. 불가·한도 소진은 `FAILED+INCONCLUSIVE`; 정책 차단·실패는 final verdict 없음. validated PoC는 `SUCCEEDED+SUPPORTED`, `agent_invoked=true`, same-attempt AgentLog의 exact candidate revision·`content_digest` 실행 증명이 모두 있을 때만 생성하며 그 밖에는 `poc_ref=null` | `tests/integration/sandbox/`, `tests/integration/sandbox/test_agent_boundary.py`, `tests/integration/sandbox/test_attempt_lifecycle.py`, `tests/integration/sandbox/test_container_lifecycle.py`, `tests/contract/test_dynamic_provenance.py`, `tests/security_negative/test_sandbox_boundary.py`; 04·07·08·10·ADR-002/003/004/007 / R6·R7·R4·R8 |
| 13. final Verification | LLM Agent + trusted 저장 / R6 / Verification Agent Runtime | `VerificationService.finalize` / parent `VERIFICATION` | Step 11의 exact 정적·Pro·Con 결과, 요청했다면 COMMITTED current Dynamic result; 모든 validation/falsification result | final `VerificationResult(TRUE/FALSE/HOLD)`, optional `HypothesisProposal(origin=VERIFICATION)`; VERIFICATION만 verdict·request·material proposal 생산 | final 합성 `CALL_LLM`, `SAVE_RESULT(result_kind=verification_result)`; 질문·validation set, evidence, exact refs, same-generation TRUE/PoC 조건 검사 | `verifications/hypotheses/runs`; result·work SUCCEEDED·`HypothesisProcessState(TERMINAL)` current pointer를 atomic commit | 12 또는 11 → 13 → 14; material proposal은 20으로 분리 | supported+validated PoC만 TRUE. 실제 named disproof만 FALSE. 정상 근거와 미해결 조건만 HOLD. 동적 `BLOCKED/FAILED/CANCELLED`이면 final result 없음 | `tests/contract/test_verification_result.py`, `tests/e2e/test_verdict_paths.py`; 03·04·07·08·10 / R6·R4·R7·R5 |
| 14. verdict 분기·CWE | 비-LLM router + LLM CWE / R4·R5 / Verdict Router·Primitive Runtime·CWE Labeling Agent | `VerdictRouter.route` / HOLD는 `PRIMITIVE_UPDATE`, TRUE는 `CWE_LABEL`, FALSE는 새 work 없음 | current final `VerificationResult`; TRUE는 exact evidence closure·taxonomy, HOLD는 required candidates | FALSE terminal. HOLD `Primitive(result=null)`과 index. TRUE current `CWELabel`; HOLD Primitive는 admission decision 없음, CWE_LABELING만 label 생산 | HOLD `REGISTER_WORK/SAVE_RESULT`; TRUE `REGISTER_WORK/START_ATTEMPT/CALL_LLM(requested_by=CWE_LABELING)/SAVE_RESULT`; verdict별 허용 경로·producer·exact Verification 검사 | `primitives/cwe_labels/runs/invocations`; current Primitive index 또는 current CWELabel pointer atomic 갱신 | 13 → FALSE는 22, HOLD는 18, TRUE는 15; material proposal은 20 | CWE 오류·auth·timeout은 TRUE를 바꾸지 않고 work `BLOCKED/FAILED`, Gate 금지. HOLD 후보가 없으면 Primitive 없이 종료 | `tests/integration/test_verdict_router.py`, `tests/contract/test_cwe_provenance.py`; 01·03·04·05·06·08·09·10·ADR-009 / R4·R5·R6·R1 |
| 15. Technical Evidence Gate | LLM 검토 / R5 / Technical Gate Agent Runtime | `GateService.review_technical` / `TECHNICAL_GATE` | exact final TRUE, current same-Verification `CWELabel`, current generation dynamic request/result/validated PoC, code·Pro/Con·restriction refs | `TechnicalEvidenceReview(ACCEPT/REVISE/REJECT)`; TECHNICAL_GATE만 생산 | Verification owner의 `CALL_TECHNICAL_GATE`; Runtime Validator가 exact pair·COMMITTED·provider/session·Gate order 검사, Gate는 근거 의미 검토 | `gates/invocations/runs`; Gate work output은 exact review 하나, current pointer는 입력 hash에 종속 | 14 TRUE → 15; ACCEPT → 17, REVISE → 16, REJECT → 22 내부 종결 | provider/invalid output은 같은 domain input의 제한 retry. `REVISE`는 retry가 아님. validated PoC 없는 TRUE는 호출 전 차단 | `tests/integration/test_technical_gate.py`, `tests/security_negative/test_gate_order.py`; 03·04·05·07·08·09·10 / R5·R6·R4·R7 |
| 16. Technical REVISE loop | hypothesis-local 제어 + LLM / R6·R5 / same Verification owner·CWE Labeling·Technical Gate | `RevisionWorkflow.start_new_generation` / 새 `VERIFICATION`, `PRO_EVIDENCE`, `CON_EVIDENCE`, 이후 새 `CWE_LABEL`, `TECHNICAL_GATE` | COMMITTED `TechnicalEvidenceReview(REVISE)`, 직전 final Verification/CWE, ACTIVE assignment; runtime이 current policy·playbook으로 새 `PlaybookApplication`과 전역 question ID를 생성 | 증가한 `verification_generation`, 새 고정 입력 묶음과 `debate_input_hash`, 새 Pro·Con child work와 각 `EvidenceAgentResult`, 두 결과를 합성한 새 VerificationResult; final TRUE이면 새 dynamic work/validated PoC, 새 CWELabel revision, 새 Technical review | `REGISTER_WORK`와 state CAS; 필요 시 `READ_CODE`, Pro·Con 각각 필수 `CALL_LLM`, 조건부 `REQUEST_DYNAMIC_REPRO`, final 합성과 이후 Gate action. old work/action/decision·application·질문·Pro/Con ref 재사용 차단 | 모든 과거 revision은 history; 새 generation의 application·Pro·Con·Verification·CWE·Gate pointer만 새 exact chain으로 원자 전환 | 15 REVISE → 같은 owner. 9 Context는 필요 범위로 보완, 10 Pro·Con은 항상 새 child work로 병렬 재실행, 12 dynamic은 final TRUE 후보 또는 판정용 실행 근거가 필요할 때 실행, 이후 13/14/15 수행; Orchestration이 목적지를 선택하지 않음 | 새 Pro·Con은 같은 새 `debate_input_hash`를 사용하고 둘 다 COMMITTED·SUCCEEDED여야 join 가능. 한쪽이라도 미완료면 새 final 결과 저장 금지. 첫 attempt는 `INITIAL`; 입력 그대로인 provider 오류만 same-work `RETRY`. 보완 한도 소진은 Verification/Gate 실패이며 이전 generation 결과 자동 승격 금지 | `tests/e2e/test_technical_revise_generation.py`, `tests/security_negative/test_revise_old_debate_reuse.py`, `tests/security_negative/test_revise_debate_join.py`; 03·04·05·07·08·10 / R6·R5·R4·R7 |
| 17. 정책 수집·Rule Scope·Primitive admission | 외부 수집 + LLM Gate + 비-LLM 결정 / R5·R4 / Policy Collector·Rule Scope Agent·Admission Runtime | `PolicyAndScopeWorkflow.evaluate` / `POLICY_FETCH`, `RULE_SCOPE_GATE`, `PRIMITIVE_UPDATE` | same TRUE/CWE/Technical ACCEPT chain; official source config; exact parser/source; `PolicyCollectionResult`, `FOUND`이면 ProgramPolicyRecord | Collector: parser/collection/policy records. Gate: `RuleScopeImpactReview`. R4 runtime: `PrimitiveAdmissionDecision`; ALLOW이면 result Primitive와 index | `FETCH_POLICY/SAVE_RESULT`; Verification owner의 `CALL_RULE_SCOPE_GATE`; admission runtime의 `REGISTER_WORK/SAVE_RESULT`; source authenticity/freshness, exact chain, testing restriction decision table 검사 | `policies/gates/primitives/invocations/runs`; current policy·Rule Scope·admission/index refs. `COLLECTION_FAILED`에는 Gate review 없음 | 15 ACCEPT → 17; admission ALLOW → 18, DENY → 19/22; 모든 Rule Scope 결과는 19 보고 조건에도 사용 | fetch/parser 오류는 `COLLECTION_FAILED`, Rule Scope 호출 금지; 공식 부재는 `ABSENT_CONFIRMED → UNCERTAIN+DENY`. testing restriction FAIL만 Primitive admission DENY | `tests/integration/test_policy_scope_admission.py`, `tests/security_negative/test_testing_restriction.py`; 05·06·07·08·10·ADR-011 / R5·R4·R1·R8 |
| 18. Primitive Chaining | LLM match + trusted registry / R1 / Chaining Runtime·Chaining Agent | `ChainingService.match` / `CHAINING` | work 시작 시 고정한 current `PrimitiveIndexState`, 전체 후보인 `considered_primitive_refs`, 후보 Primitive와 그 계보의 current `ALLOW` admission refs | `ChainingResult`, `PrimitiveMatchCandidate`, `LineageExclusion`, `HypothesisProposal(origin=CHAINING)`; CHAINING만 결과·proposal을 생산하고 `source_admission_refs`에는 실제 match 입력과 그 계보의 decision만 기록 | `REGISTER_WORK`, `CALL_LLM(requested_by=CHAINING)`, `SAVE_RESULT`; 시작 시 고정한 전체 후보·admission 입력을 검사하고, 저장 시 실제 match의 direct/ancestor current `ALLOW` 집합과 `source_admission_refs`의 set-equality, result→input·lineage·fingerprint·restriction·source refs를 검사 | `chaining/hypotheses/runs/invocations`; DB를 삭제하지 않고 exact result/history 저장, child proposal은 아직 미등록 | HOLD 또는 allowed TRUE Primitive → 18; candidate별 fan-out 가능, 결과 child는 20; no-match는 22 | 실제 match의 admission이 stale/DENY이면 결과를 거절하고 부모 verdict는 유지한다. 사용하지 않은 후보의 decision 변경만으로는 결과를 거절하지 않는다. budget/LLM 실패는 `CHAINING_ERROR/BUDGET_EXCEEDED`; 미확인 match를 저장하지 않음 | `tests/contract/test_chaining_result.py`, `tests/integration/test_true_hold_true_true.py`; 03·06·07·08·10·ADR-001/005/011 / R1·R4·R5·R6·R8 |
| 19. current Finding 정규화와 보고 가능 조건 확인 | 비-LLM 신뢰 runtime / R4 storage·R5 semantic / Finding Normalization + Reporting Condition Runtime | `FindingNormalization.assemble` + `ReportingPolicy.evaluate` / `FINDING_NORMALIZE` 전용 비-LLM work(B2), 통과 시 `REPORT_DRAFT` 준비 | 같은 exact chain의 final TRUE, current dynamic+PoC, current CWELabel, Technical ACCEPT, current Rule Scope review(값 무관), restriction/limitation/unresolved condition | current `Finding`(정규화 record, 새 verdict 아님) 또는 `COLLECTION_FAILED`이면 Finding 없음; report-ready 또는 구체적 차단 사유 | Finding 정규화는 `RULE_SCOPE_GATE` `SUCCEEDED` 이후 신뢰 runtime이 exact chain·revision 일치 검사 후 atomic commit; `CREATE_REPORT_DRAFT` action의 `REVISION/REPORT_READY/REDACTION` preflight; `review_status=PASS`, `rule_compliance=PASS`, `scope_compliance=PASS`, `testing_restriction_compliance=PASS`, `security_impact=SUFFICIENT`, `report_permission=ALLOW`와 current non-stale Finding 존재를 각각 exact 검사 | `reports/actions/runs`; current Finding pointer(가설별 하나)와 허용/차단 decision. `report_permission=DENY`여도 Finding은 보존 | 17의 Rule Scope 결과 → 정규화 → pass면 21, fail/uncertain/deny면 22; admission/Chaining과 독립 축 | 정책 stale·Finding 없음·stale Finding·revision 불일치는 Reporter 차단만 하고 기술 TRUE·Primitive 자격을 바꾸지 않음 | `tests/contract/test_finding_normalization.py`, `tests/contract/test_report_readiness.py`, `tests/security_negative/test_reporter_preconditions.py`; 05·07·08·10 / R4·R5·R6·R8 |
| 20. material child 전역 등록 | 비-LLM registry + 필요 시 LLM duplicate review / R1·R3 / Proposal Validator·Hypothesis Registry·Assignment Runtime | `HypothesisRegistry.register_child` / `HYPOTHESIS_PROPOSAL`, 이후 새 `VERIFICATION` | COMMITTED Verification-origin 또는 Chaining-origin proposal, exact parent IDs; Chaining은 `source_primitive_match_id`와 admissible lineage | 새 `VulnerabilityHypothesis`, process state와 ACTIVE VerificationAssignment; 기존 부모 결과와 독립 | Step 7과 같은 validation/duplicate `CALL_LLM/SAVE_RESULT`, 이후 `REGISTER_WORK(VERIFICATION)`; origin·parent·lineage·entity 시작점 검사 | `hypotheses/runs/invocations`; parent-child refs와 새 current process pointer | 13/18 → 20 → 새 child는 8–21 전체 반복; 가설 간 병렬 가능 | duplicate/invalid는 새 child 없음. lineage가 stale/DENY면 등록·후속 사용 차단, 부모 verdict 불변 | `tests/integration/test_child_hypothesis_registration.py`, `tests/e2e/test_chaining_child_full_revalidation.py`; 03·04·06·07·08·10 / R1·R3·R4·R6 |
| 21. ReportDraft | LLM Agent / R5 / Reporter Agent Runtime | `ReportService.create_draft` / `REPORT_DRAFT` | Step 19에서 검사한 current Finding, same Verification/CWE/Technical/Rule Scope/policy exact chain, dynamic/PoC, restrictions·limitations·unresolved conditions | internal `ReportDraft`; REPORTER만 생산, 공개·제출 권한 없음 | Verification owner의 `CREATE_REPORT_DRAFT`; Runtime Validator가 Gate order/readiness/revision/redaction 검사 후 provider 호출과 `SAVE_RESULT` | `reports/invocations/runs`; draft·report work SUCCEEDED·`ReportProcessState(DRAFTED)`를 atomic commit. raw secret/hidden reasoning 미저장 | 19 pass → 21 → 22; 가설별 독립 초안 가능 | missing Finding, stale refs, redaction 실패는 `REPORT_NOT_READY/REPORT_ERROR`; upstream revision 변경 시 과거 draft는 history만 유지 | `tests/contract/test_report_draft.py`, `tests/security_negative/test_report_redaction.py`; 05·07·08·10·12 / R5·R4·R6·R7 |
| 22. 결과 집계·자동화 종료 | 비-LLM 집계 / R3·R4·R8 / Result Aggregator·State Store·Recovery Runtime | `AnalysisService.finalize_run` / 별도 Agent work 없음 | 모든 current COMMITTED 결과, states/attempts/transitions/actions/logs/resources/errors/gaps/stop reasons; report가 없으면 그 이유 | `AnalysisRunResult`와 `AnalysisRunState(COMPLETE/PARTIAL/FAILED/CANCELLED)`; 신뢰 runtime만 최종 묶음·상태 생산 | finalization 전 outstanding work/journal/pointer·current revision·lineage 검사; 결과와 run 상태를 atomic commit | `runs`와 logical 영역의 exact refs; `analysis_result_ref` current pointer. Agent 자동화 종료 뒤 새 Agent action 금지 | 모든 초기·child 가설의 종료를 join; 다른 가설 실패가 있어도 신뢰 결과가 있으면 PARTIAL 가능 | RUNNING work·미복구 PREPARED·output 없는 종료 상태는 종료 차단. recovery는 마지막 COMMITTED부터 재투영; 오류를 verdict로 만들지 않음 | `tests/e2e/test_full_run_finalization.py`, `tests/integration/test_atomic_run_result.py`; 01·03·05·07·08·10 / R3·R4·R8·전 역할 |

### 16단계 필수 부정·복구 시험

R3-06이 최종 package와 test 경로를 확정할 때 아래 세 조건을 하나의 REVISE generation 회귀 시험 묶음으로 보존한다.

1. 새 generation의 `PlaybookApplication`, 질문 ID, `verification_generation` 또는 `debate_input_hash`와 다른 과거 Pro·Con reference를 사용하면 `STALE_RESULT`로 거절한다.
2. 새 Pro와 Con이 서로 다른 `debate_input_hash` 또는 서로 다른 application·질문 집합을 사용하면 join을 거절하고 final 합성을 시작하지 않는다.
3. 새 Pro·Con 중 하나라도 없거나 child work가 `COMMITTED + SUCCEEDED`가 아니면 새 final `VerificationResult` 저장과 CWE·Technical Gate 진행을 금지한다. 재시도 가능하면 해당 child와 parent Verification을 `BLOCKED`, 복구 불가능하면 verdict 없이 `FAILED`로 끝낸다.

### 12단계 R7 경계·attempt·PoC 필수 시험

R3-06은 다음 조건을 동적 재현 회귀 시험에 포함한다.

1. 경계 전 R7 Agent의 requirements·plan 작성 호출과 경계 승인 뒤 Sandbox 실행 Agent 시작을 구분한다. 전자는 `agent_invoked`를 `true`로 만들지 않으며, 정책 차단이면 `agent_invoked=false`와 exact 정책 결정·AgentLog를 남긴다.
2. 같은 Agent session의 command·PoC·환경 조정은 같은 attempt의 event로 남긴다. session 재시작이 필요한 일시 오류만 새 retry attempt를 만들고, 외부 조건을 기다리는 경우에만 `BLOCKED` 뒤 `trigger=RESUME`인 새 attempt를 만든다. R6에 반환하는 current 결과에는 이전 attempt의 중간 실패 결과나 늦게 도착한 event를 섞지 않는다.
3. 각 가설의 첫 attempt는 clean container에서 시작하고 다른 가설끼리 writable container를 공유하지 않는다. 같은 가설에서는 영향 있는 상태·설정 변화가 없을 때만 재사용하며, `STATE_CHANGED | CONFIG_CHANGED | STATE_UNCERTAIN` 또는 crash·비정상 종료·사후 Health Check 실패이면 재생성한다.
4. validated `poc_ref`는 `SUCCEEDED + SUPPORTED + agent_invoked=true`이고 같은 attempt AgentLog가 exact `poc_candidate_ref` revision과 `content_digest`의 실제 실행을 입증할 때만 허용한다. candidate 생성·실행 실패, 정책·환경 실패, timeout, `DISPROVED | INCONCLUSIVE`에서는 `poc_ref=null`이며 candidate reference만으로 성공을 추론하지 않는다.
5. build·container·network·volume·임시 파일 중 하나라도 생성되면 성공·실패·정책 차단과 관계없이 cleanup 결과와 exact reference를 기록한다. `cleanup_status=NOT_REQUIRED`는 정리할 자원이 하나도 생성되지 않았을 때만 허용한다.

## 5. 공통 모듈과 의존 방향

22단계 어디에서나 다음 공통 모듈을 같은 의미로 사용한다.

| 공통 모듈 | 하는 일 | 직접 하면 안 되는 일 | 주요 소비 단계 |
|---|---|---|---|
| Contract Models | `RecordMeta`, `StoredDataRef`, 전문 record와 enum의 schema 검증 | verdict·정책 의미 생성, provider·DB 코드 의존 | 전 단계 |
| Work/State Runtime | work·attempt·state version·dedupe·atomic transition과 recovery 관리 | LLM 판정, 정책 해석 | 2–22 |
| Runtime Validator | action의 schema·identity·authority·revision·state·budget·provider/session·순서 검사 | 취약점·CWE·정책 의미 판정, Sandbox 내부 전략 결정 | 모든 부작용 action |
| Prompt Builder·Registry | 역할별 instruction과 허용된 exact context로 immutable prompt payload 생성 | 저장소 텍스트를 instruction으로 승격, Pro/Con 결과 교차 전달 | 6·7·10–18·21 |
| Provider Adapter·Logging Proxy | API 또는 공식 membership 연결, 호출 상태·공개 usage·safe log 정규화 | silent provider/model 전환, secret 저장 | 모든 LLM 단계 |
| Record Store | immutable revision과 current pointer 저장 | 가장 최신처럼 보이는 임의 결과 자동 선택 | 1–22 |
| Artifact Store | raw tool output, code fragment, prompt/response, PoC 같은 큰 byte 저장 | credential·불필요한 전체 코드의 일반 공개 | 3·6·9·12·21 |
| Sandbox Controller | host·Docker·mount/namespace·secret·egress·workspace·resource 외부 경계 강제 | 내부 command allowlist, 최종 verdict 판단 | 12 |
| Reproduction Session Manager | 실제 event를 append-only AgentLog로 기록하고 동적 결과·validated PoC 확정 | Agent 실행 전략·retry·cleanup 판단 | 12 |
| Result Aggregator | current exact 결과와 오류·자원을 `AnalysisRunResult`로 묶음 | 새 Agent 판단·사람 공개 결정 | 22 |

의존 방향은 `interfaces → orchestration/runtime → domain service → provider/tool adapter → storage adapter`로 둔다. Contract Models는 모든 계층이 읽을 수 있지만 provider·tool·storage 구현을 import하지 않는다. Agent는 구체 DB·Docker·provider SDK를 직접 호출하지 않고 runtime port를 사용한다. 최종 package 이름은 R3-06에서 확정한다.

## 6. 논리 저장과 pointer 규칙

| 논리 영역 | 주 record | 쓰기 주체 | current 선택 기준 |
|---|---|---|---|
| `runs` | AnalysisRunState/Result, WorkExecutionState, WorkAttempt, StateTransition, TransitionCommit, error/resource/debug refs | trusted runtime·recovery | COMMITTED transition과 상태 pointer가 같은 exact output을 가리킴 |
| `facts` | ToolRunResult, RuleExecutionRecord, StaticFactBundle | STATIC_ANALYSIS | current tool attempt와 current normalized bundle |
| `hypotheses` | ProposalProcessState, HypothesisProposal, duplicate review, VulnerabilityHypothesis, HypothesisProcessState, assignment | proposal/assignment runtime | 등록·배정 atomic transition과 active assignment |
| `contexts` | CodeContextRequest/Response와 code fragment refs | Context Retrieval Service | current Verification의 exact request/response pair |
| `verifications` | EvidenceAgentResult, VerificationResult | PRO/CON/VERIFICATION | current generation과 exact Pro/Con join을 가진 final COMMITTED result |
| `dynamic` | request, requirements, plan, recipe, environment, policy decision, AgentLog, PoC, cleanup, dynamic result | R6/R7의 등록된 producer | same work·attempt provenance와 current final result pointer |
| `cwe_labels` | CWELabel | CWE_LABELING | current final TRUE를 직접 가리키는 성공 CWE work의 유일 output |
| `gates` | TechnicalEvidenceReview, RuleScopeImpactReview | 각 Gate Agent | Gate work가 고정한 domain input set과 exact match |
| `policies` | PolicyParserResult, PolicyCollectionResult, ProgramPolicyRecord | POLICY_COLLECTOR | 수집 status와 exact official source/freshness provenance |
| `primitives` | PrimitiveAdmissionDecision, Primitive, PrimitiveIndexState | PRIMITIVE_ADMISSION_RUNTIME | final HOLD 또는 current ALLOW TRUE의 atomic index revision |
| `chaining` | ChainingResult와 match/exclusion | CHAINING | work 시작 고정 입력과 실제 사용 admission set이 current일 때 |
| `reports` | Finding, ReportDraft | 신뢰 runtime(Finding 정규화, VERIFICATION service identity, R4 B2), REPORTER(ReportDraft) | Finding: `RULE_SCOPE_GATE` 종료 뒤 exact chain을 조립한 가설별 current revision. ReportDraft: current non-stale Finding과 같은 Verification/CWE/two-Gate/policy chain |
| `actions` | ActionRequest/Decision | requester·Runtime Validator | action당 logical decision 하나, ALLOW는 exact revision에 한 번 사용 |
| `invocations` | LLMCallSpec/Request/Result/Log | Agent Runtime·adapter·Logging Proxy | exact action/spec/profile과 parsed output 연결 |

구조화 record와 큰 artifact를 같은 저장 제품에 억지로 넣지 않는다. 저장 제품이 단일 transaction을 제공하지 않으면 `TransitionCommit(PREPARED/COMMITTED/ABORTED)`을 논리적 확정점으로 사용한다. current pointer는 편의를 위한 투영이며 COMMITTED marker보다 강한 근거가 아니다.

## 7. 구현 전에 해결해야 하는 계약 빈틈

아래 항목은 이 문서 작성 중 최신 `main`에서 직접 확인한 사항이다. R3-01이 임의로 새 공통 계약을 만들지 않고 담당 Issue로 넘긴다.

### B1. R7 Agent의 LLM role enum 불일치 — 구현 시작 Blocker

[08. 경량 데이터 계약](../08-lightweight-data-contracts.md)은 `CALL_LLM`의 `requested_by=R7_AGENT`를 허용하지만 `LLMCallSpec.agent_role`과 `LLMInvocationRequest.agent_role` enum에는 `R7_AGENT`가 없다. 이대로는 Step 12의 경계 전 requirements·plan 작성 `CALL_LLM`과 경계 승인 뒤 Sandbox 실행 Agent의 역할을 같은 R7 identity로 연결할 수 없고 호출도 schema를 통과할 수 없다.

- 담당: R3-05 #91에서 prompt/call 구조 결정, R4가 공통 enum·authority test 반영
- 완료 기준: call spec, invocation request/log, Prompt Registry key와 action role 검사가 같은 R7 role을 사용함

### B2. current Finding 생산 단계·저장 권한 — R5 semantic·R4 storage binding 확정

Step 19는 `RULE_SCOPE_GATE` 성공 뒤 전용 비-LLM `FINDING_NORMALIZE` work를 실행한다. canonical schema와 atomic 저장 계약은 [08. 경량 데이터 계약](../08-lightweight-data-contracts.md)의 Finding canonical schema와 current pointer 절을 따른다.

- **R5 확정([R5-03 후속이슈], `05-llm-gate-and-reporting.md` "Finding 생성과 lifecycle", `08` §11)**: Finding은 새 Agent·Gate가 아니라 신뢰 runtime이 이미 `COMMITTED`된 exact upstream을 조립하는 정규화 record다. 생성 closure = final TRUE Verification + current generation `SUCCEEDED + SUPPORTED` 동적 결과 + validated `poc_ref` + 그 Verification을 직접 가리키는 current `CWELabel` + `TechnicalEvidenceReview.status=ACCEPT` + 같은 chain의 current `RuleScopeImpactReview`(`review_status`·`report_permission` 값 무관, `COLLECTION_FAILED`이면 Finding 없음). upstream record의 `meta.hypothesis_id`·`meta.workspace_id`·`meta.commit_id` 일치, `CWELabel`·`TechnicalEvidenceReview`·`RuleScopeImpactReview`가 같은 `verification_result_ref`를 가리키고 그것이 current `HypothesisProcessState.verification_result_ref`와 동일, generation 정합성은 새 field 없이 기존 `HypothesisProcessState`·`VERIFICATION` work generation·`CWELabel.verification_generation` 계약으로 확인, `restrictions`·`unresolved_conditions`와 evidence transitive closure 보존. Finding 존재는 Reporter의 6축 정책 readiness와 별개 축이다. stale 조건 = Verification generation/revision·CWELabel·두 Gate 재생성·동적 결과·validated PoC·고정 정책 record 변경.
- **R4 확정(storage binding)**: `result_kind=finding`, registry `finding -> Finding -> VERIFICATION`; 유일 생산 identity는 Verification trusted runtime의 Finding normalization service다. 기존 `SAVE_RESULT`를 사용하고 work의 단일 Finding output·`SUCCEEDED`·가설별 `FindingIndexState` current pointer를 `TransitionCommit`과 CAS로 확정한다. Rule Scope output은 review 한 개를 유지한다. `FindingCandidate`는 같은 schema의 staging candidate이며 별도 domain record가 아니다.
- upstream 변경은 index를 atomic stale invalidation하고 immutable Finding history를 보존한다. Reporter는 current non-stale Finding만 소비한다. `AnalysisRunResult.finding_refs`는 current index 집합이며 Reporter blocked이면 `report_draft_refs=[]`로 정상 종료할 수 있다. Finding eligibility·Reporter 6축·Primitive admission·Chaining 계약은 그대로 유지한다.
- 완료 기준 충족: schema, output binding, owner identity, pointer/revision/CAS, recovery와 Finding-only 종료를 08에 확정했다. 새 autonomous Agent·LLM Gate·action type·producer enum은 추가하지 않는다.

### B3. 일부 core output의 `SAVE_RESULT` registry 연결 누락 — 구현 시작 Blocker

work/output 표에는 `CodeWorkspace`, `ToolRunResult`, schema-valid `HypothesisProposal`, `AnalysisRunResult`가 나오지만 `SAVE_RESULT`의 핵심 result-owner registry에는 이 네 record의 `result_kind → schema → 유일 producer` 연결이 명시되어 있지 않다. 다른 registry로 관리하는 의도라면 그 저장 action과 atomic 경계를 밝혀야 한다.

- 담당: R4 공통 계약, 소비 역할은 R2·R3·R8 교차 검토
- 완료 기준: 네 output 각각의 저장 entry point, producer, current pointer와 TransitionCommit 사용 여부가 명확함

### B4. Orchestration이 LLM Agent인지 비-LLM control runtime인지 표현 불일치 — 구현 시작 전 High

번호 문서는 `Orchestration Agent`라고 부르지만 실제 권한 대부분은 비-LLM runtime에 있으며 R3-05의 prompt 대상 목록에는 Orchestration prompt가 없다. 모델이 판단하는 부분과 프로그램이 순서를 관리하는 부분을 나누지 않으면 구현자가 전체 실행 제어를 LLM에 맡길 수 있다.

- 담당: R3-05 #91과 R3-06 #92
- 완료 기준: Orchestration의 LLM 판단 entry point와 비-LLM 등록·배정·state enforcement entry point가 각각 한 번만 정의됨

이 네 항목은 R3-06 최종 구현 기준을 닫기 전에 해결해야 한다. 해결 전에도 R3-02·R3-03의 테스트 설계는 시작할 수 있지만 실제 production pipeline 구현 완료를 선언할 수 없다.

## 8. 역할별 필수 검토 범위

| 역할 | 검토할 단계 | 반드시 확인할 내용 |
|---|---:|---|
| R1 탐색·Chaining `@baeseungwon1010` | 5–8, 18, 20 | proposal 등록·중복 처리, Primitive match·lineage·child 재검증 |
| R2 정적분석·Context `@zv9uvr` | 2–4, 9 | tool별 output, 규칙 실행 0건/미실행 구분, StaticFactBundle, 안전한 code retrieval |
| R3 통합 `@YHS-Sec`, `@taehyeon-git` | 1–22 | entry point, work 등록, 병렬/join, 모듈 의존 방향과 최종 종료 |
| R4 공통 계약 `@taehyeon-git` | 전 단계 | ID·revision·state·action·저장·authority와 B1–B3 |
| R5 CWE·Gate·Reporter `@kimhr8463` | 14–17, 19, 21 | CWE exact provenance, 두 Gate 순서, Finding 생산 빈틈, Reporter 조건 |
| R6 Verification `@UltraPeachKeen` | 8–16, 20 | Context·Pro/Con·판정·dynamic request·REVISE·material child |
| R7 동적 재현 `@Potatonion` | 12–13, 15, 21 | R6/R7 경계, Sandbox 외부 경계, AgentLog·same-attempt PoC provenance |
| R8 평가·예산 `@gitterable` | 전 단계의 budget/metrics, 22 | time/cost/work/retry/resource 정책과 비교 가능한 관측값 |

각 검토자는 PR의 최신 head SHA를 기준으로 자신의 생산·소비 record, 오류 전파와 테스트 경로를 확인한다. 리뷰 중 새 commit이 생겨 검토 영역이 바뀌면 해당 역할은 새 head SHA를 다시 확인한다.

## 9. 완료 판정

- [x] 정본 22단계를 한 번씩 빠짐없이 매핑했다.
- [x] 각 단계에 주체, 논리 entry point, work, exact 입력·출력, action·검사, 저장, 상태·오류, 연결과 테스트 책임을 적었다.
- [x] LLM Agent와 비-LLM runtime/controller의 역할을 구분했다.
- [x] 병렬 fan-out/join과 변경할 수 없는 직렬 순서를 표시했다.
- [x] `FALSE`, `HOLD`, `BLOCKED`, `FAILED`, Technical `REVISE` 경로를 구분했다.
- [x] Technical `REVISE` 새 generation에서 새 application·질문·공통 입력으로 Pro·Con을 항상 다시 실행하고 과거 결과를 거절하도록 표시했다.
- [x] 체이닝 자식의 직접 코드 시작점이 비어 있으면 exact `source_primitive_match_id` 계보에서 부모 Primitive `entity_refs`를 복원하고, 무효·stale·빈 계보를 거절하도록 표시했다.
- [x] R7의 경계 전 LLM 계획, 외부 경계 검사, 경계 뒤 Agent 실행, same-session retry·새 attempt·`BLOCKED/RESUME`, container와 cleanup, validated PoC 조건을 구분했다.
- [x] Chaining work 시작 시 전체 후보·계보 admission 입력을 고정하고 저장 시 실제 match의 `source_admission_refs`만 재검사하도록 구분했다.
- [x] Reporter 호출에 필요한 Rule Scope의 여섯 판정 축을 필드명과 값으로 표시했다.
- [x] 별도 저장소 사본 생성 모듈이나 message queue 제품을 전제로 하지 않았다.
- [x] R3-01에서 확정할 수 없는 공통 계약 빈틈을 담당 역할과 후속 Issue로 분리했다.
- [ ] R1·R2·R4·R5·R6·R7·R8 교차 검토가 최신 PR head를 기준으로 완료됐다.
- [ ] B1·B3 Blocker가 담당 Issue·공통 계약에서 해결됐다.
- [x] B2의 Finding 의미·생성 closure·claim 제한·stale 조건을 R5가 확정했다([R5-03 후속이슈], `05`/`08`). R4는 `FINDING_NORMALIZE`·VERIFICATION service owner·`FindingIndexState`·CAS binding과 Finding-only 종료를 08에 확정했다.

이 문서는 구현 모듈 경계를 설명하는 설계 산출물이며 실제 runtime 코드가 구현되었다는 뜻은 아니다.
