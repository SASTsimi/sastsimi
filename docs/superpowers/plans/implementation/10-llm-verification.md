# T10 LLM Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 정적 사실에서 가설을 만들고, 독립 Pro·Con 검토를 거쳐 Verification이 근거가 있는 `FALSE | HOLD`를 안전하게 확정하는 첫 실제 LLM 검증 흐름을 구현한다.

**Architecture:** T09는 Provider 응답을 schema·semantic 검증한 canonical JSON artifact까지만 만든다. T10의 역할별 비-LLM finalizer가 그 exact artifact와 invocation provenance를 다시 확인하고 runtime-owned ID·`RecordMeta`·고정 reference를 채운 뒤에만 DomainRecord를 저장한다. Hypothesis, Pro/Con, Verification은 세 독립 lane으로 개발하고 공통 bootstrap·service composition·package export는 마지막 통합 담당자만 수정한다.

**Tech Stack:** Python 3.12+, Pydantic v2 strict contracts, asyncio, SQLAlchemy/SQLite trusted storage, pytest, Ruff, mypy strict

**Spec:** [Issue #153](https://github.com/SASTsimi/sastsimi/issues/153), [Complete Implementation Plan Task 10](../2026-09-08-sastsimi-complete-implementation.md#task-10-llm-verification-roles), [Agent roles](../../../architecture-v5/03-agent-roles-and-orchestration.md), [Verification and dynamic reproduction](../../../architecture-v5/04-verification-and-dynamic-reproduction.md), [Lightweight data contracts](../../../architecture-v5/08-lightweight-data-contracts.md), [Implementation module map](../../../architecture-v5/implementation/01-module-map.md)

## Global Constraints

- T08 Context Service와 T09 Provider·Prompt Runtime을 그대로 소비하며 가짜 Provider 호출 경로를 운영 구현으로 재사용하지 않는다.
- Agent 출력은 제안이다. LLM은 `RecordMeta`, record·proposal·question·validation·claim ID, work·attempt·generation, 상태 pointer, 저장·실행 권한을 만들거나 바꾸지 못한다.
- T09의 `LLMInvocationResult.parsed_output_ref`는 canonical JSON artifact다. 역할 finalizer는 exact `SUCCEEDED` invocation, artifact hash, role, task, purpose, work, attempt, session, 입력 closure를 확인한 뒤 DomainRecord를 만든다.
- Provider timeout·인증 실패·rate limit·취소·`INVALID_OUTPUT`은 `TRUE | FALSE | HOLD`가 아니며 DomainRecord와 후속 work를 만들지 않는다.
- 운영 분석의 Pro와 Con은 같은 `debate_input_hash`와 같은 공개 입력을 사용하되 서로 다른 child work·attempt·`llm_call_id`·`NEW` session을 사용하고 상대 결과를 읽지 않는다.
- `FALSE`는 이름이 지정된 반증 질문의 실제 `DISPROVED` 근거가 있을 때만, `HOLD`는 근거가 있는 미해결 조건이 남을 때만 저장한다.
- T11 전에는 final `TRUE`, `CWE_LABELING`, Gate, Finding, Reporter, Chaining work를 만들지 않는다. initial TRUE 후보는 `POC_CONFIRMATION` 대기 상태까지만 허용한다.
- 변경 기능의 정상 흐름 한 개와 중요한 실패 흐름 한 개를 우선 검증한다. Task 중 전체 suite 반복 실행은 금지하고 PR CI가 전체 suite를 한 번 실행한다.
- 데이터 혼합, 역할·권한 우회, 잘못된 verdict, exact reference 불일치, 비밀 노출은 Blocker/High로 즉시 수정한다. Medium/Low는 이 문서의 후속 목록에만 기록한다.
- 이미 승인된 Architecture v5 계약을 넘는 기능·schema·리팩터링은 추가하지 않는다.

---

## 1. 파일 지도와 병렬 소유권

### Lane A — Hypothesis

이 lane만 다음 파일을 수정한다.

- Create: `src/sastsimi/agents/hypothesis.py`
- Create: `tests/integration/verification/test_hypothesis_agent.py`

생산 인터페이스:

```python
class HypothesisAgent:
    async def propose(
        self,
        *,
        work: WorkExecutionState,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
        static_fact_bundle_ref: StoredDataRef,
    ) -> tuple[HypothesisProposal, ...]: ...
```

`propose`는 T09 artifact의 content-only proposal 배열을 읽는다. trusted finalizer가 각 항목에 새 `proposal_id`, 전역 `question_id`, 전역 `validation_id`, trusted `RecordMeta`를 발급한다. 이 lane은 proposal 반환까지만 맡는다. initial work 등록과 batch 저장 projection은 공유 상태를 다루므로 integration owner가 연결한다.

### Lane B — Pro/Con

이 lane만 다음 파일을 수정한다.

- Create: `src/sastsimi/agents/pro.py`
- Create: `src/sastsimi/agents/con.py`
- Modify: `src/sastsimi/verification/debate_service.py`
- Create: `tests/integration/verification/test_debate_service.py`
- Create: `tests/security_negative/test_cross_role_isolation.py`

생산 인터페이스:

```python
@dataclass(frozen=True)
class DebateCallRefs:
    decision_ref: StoredDataRef
    reservation_ref: RecordRef
    call_spec_ref: StoredDataRef

@dataclass(frozen=True)
class DebateResult:
    pro: ProEvidenceResult
    con: ConEvidenceResult
    pro_ref: StoredDataRef
    con_ref: StoredDataRef

class DebateService:
    async def run(
        self,
        *,
        verification_work: WorkExecutionState,
        public_input_refs: tuple[StoredDataRef, ...],
        pro_call: DebateCallRefs,
        con_call: DebateCallRefs,
    ) -> DebateResult: ...
```

서비스는 두 child work를 먼저 등록한 뒤 `asyncio.gather`로 병렬 호출한다. 각 역할 finalizer는 content-only claim에서 새 `claim_id`와 trusted metadata를 발급하고, 역할에 맞는 `source_role`만 허용한다. 두 호출 모두 성공한 뒤 `validate_evidence_sessions`와 exact committed-output 검사를 통과해야 join한다. 한쪽 실패 시 성공한 반대쪽 결과는 보존하지만 parent Verification은 verdict 없이 `BLOCKED` 또는 `FAILED`가 된다.

### Lane C — Verification

이 lane만 다음 파일을 수정한다.

- Create: `src/sastsimi/agents/verification.py`
- Modify: `src/sastsimi/verification/service.py`
- Create: `src/sastsimi/verification/verdict_router.py`
- Create: `src/sastsimi/verification/revision_workflow.py`
- Create: `tests/integration/verification/test_verification_service.py`
- Create: `tests/integration/verification/test_revision_workflow.py`
- Create: `tests/integration/verification/test_verdict_router.py`

생산 인터페이스:

```python
@dataclass(frozen=True)
class VerificationCallRefs:
    decision_ref: StoredDataRef
    reservation_ref: RecordRef
    call_spec_ref: StoredDataRef

@dataclass(frozen=True)
class VerdictRoute:
    work_type: Literal["PRIMITIVE_UPDATE"]
    input_refs: tuple[StoredDataRef, ...]

class VerificationService:
    async def assess_initial(
        self,
        *,
        generation: VerificationGenerationInputs,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationInitialAssessment: ...

    async def finalize_without_dynamic(
        self,
        *,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationResult: ...

class VerdictRouter:
    def route(self, result_ref: StoredDataRef) -> tuple[VerdictRoute, ...]: ...

class RevisionWorkflow:
    def start_new_generation(
        self,
        *,
        technical_review_ref: StoredDataRef,
        expected_process_ref: StoredDataRef,
        owner_identity_ref: StoredDataRef,
        requester_identity_ref: BudgetScopeRef,
        budget_binding_ref: StoredDataRef,
    ) -> VerificationRegistration: ...
```

T10의 `finalize_without_dynamic`은 `FALSE | HOLD`만 저장한다. initial TRUE이면 `VerificationInitialAssessment(next_step=POC_CONFIRMATION)`을 보존하고 finalizer가 `T11_OUTPUT_REQUIRED`로 final 결과와 downstream 등록을 막는다. `VerdictRouter`는 `FALSE`면 빈 tuple, `HOLD`면 승인 가능한 `PRIMITIVE_UPDATE` 등록 요청만 반환한다. `TRUE`, Reporting, Chaining, Gate의 직접 호출이나 concrete import는 T10에서 금지한다.

### Integration owner — 공유 파일 전담

세 lane은 다음 공유 파일을 수정하지 않는다. 병렬 lane commit을 합친 뒤 통합 담당자만 수정한다.

- Create/Modify: `src/sastsimi/agents/__init__.py`
- Create: `src/sastsimi/orchestration/hypothesis_workflow.py`
- Modify: `src/sastsimi/storage/hypothesis_projections.py`
- Modify: `src/sastsimi/verification/__init__.py`
- Modify: `src/sastsimi/runtime/services.py`
- Modify: `src/sastsimi/bootstrap.py`
- Modify: `src/sastsimi/prompts/templates/hypothesis/generate-initial/1.0.0.md`
- Create: `src/sastsimi/prompts/templates/pro/review-evidence/1.0.0.md`
- Create: `src/sastsimi/prompts/templates/con/review-evidence/1.0.0.md`
- Create: `src/sastsimi/prompts/templates/verification/assess-initial/1.0.0.md`
- Create: `src/sastsimi/prompts/templates/verification/final-verdict/1.0.0.md`
- Modify: prompt registry seed/configuration files
- Create: `tests/integration/verification/conftest.py`
- Create: `tests/integration/verification/test_false_flow.py`
- Modify: `docs/superpowers/plans/implementation/10-llm-verification.md`의 완료 증거와 후속 목록

공유 fixture, `RuntimeServices`, bootstrap, package export에는 병렬 lane이 직접 손대지 않는다. 공통 계약 변경이 정말 필요하면 lane은 구현을 멈추지 않고 정확한 Blocker/High 내용과 영향 파일을 통합 담당자에게 전달한다.

---

### Task 1: Lane A — Canonical JSON에서 등록 가능한 Hypothesis 만들기

**Files:** Lane A 소유 파일만 사용한다.

**Consumes:** exact current `StaticFactBundle`, T09 `PersistedLLMInvocation(status=SUCCEEDED)`, `parsed_output_ref` canonical JSON array artifact

**Produces:** runtime-owned ID와 metadata를 가진 `HypothesisProposal[]`

- [ ] **Step 1: 실패하는 정상 경로 test를 작성한다**

```python
async def test_hypothesis_array_is_finalized_with_runtime_owned_ids() -> None:
    proposals = await agent.propose(**authorized_two_candidate_call())
    assert len(proposals) == 2
    assert len({item.proposal_id for item in proposals}) == 2
    assert all(item.meta.record_type == "hypothesis_proposal" for item in proposals)
    assert all(item.origin == "INITIAL" for item in proposals)
```

- [ ] **Step 2: test가 LLM artifact를 DomainRecord로 직접 parse하거나 runtime ID가 없어 실패하는지 확인한다**

Run: `uv run pytest tests/integration/verification/test_hypothesis_agent.py::test_hypothesis_array_is_finalized_with_runtime_owned_ids -q`

Expected: FAIL. T09 artifact를 신뢰 record로 직접 사용할 수 없거나 finalizer가 아직 없다.

- [ ] **Step 3: content-only parser와 trusted finalizer를 최소 구현한다**

finalizer는 `LLMInvocationResult.status == SUCCEEDED`, `agent_role=HYPOTHESIS`, `task_kind=GENERATE_INITIAL`, exact artifact digest, exact work/attempt/input closure를 먼저 확인한다. Provider payload에 runtime-owned field가 있으면 T09와 같은 `OUTPUT_RUNTIME_AUTHORITY_DENIED`로 중단한다. 질문과 검증 항목 ID는 payload 순서와 무관하게 모두 새 ID를 발급한다.

- [ ] **Step 4: 권한 경계를 검증한다**

Provider payload에 `meta`, `proposal_id`, `question_id`, `validation_id`, 다른 analysis/bundle reference가 있거나 invocation이 실패 상태이면 finalizer가 proposal을 하나도 반환하지 않는 실패 test를 같은 파일에 추가한다. 같은 응답 안의 모든 ID는 runtime 발급이므로 유일해야 한다.

- [ ] **Step 5: 정상 test와 권한 실패 test를 실행한다**

Run: `uv run pytest tests/integration/verification/test_hypothesis_agent.py -q`

Expected: PASS. runtime-owned field 주입, 다른 analysis/bundle reference, 실패 invocation은 proposal을 만들지 않는다.

- [ ] **Step 6: Lane A 파일만 commit한다**

```text
git add src/sastsimi/agents/hypothesis.py tests/integration/verification/test_hypothesis_agent.py
git commit -m "feat: finalize LLM hypothesis output"
```

### Task 2: Lane B — 독립 Pro/Con 병렬 검토

**Files:** Lane B 소유 파일만 사용한다.

**Consumes:** 같은 Verification parent/generation의 exact hypothesis, context, static facts, policy, playbook application과 질문 set

**Produces:** 같은 `debate_input_hash`를 가진 독립 `ProEvidenceResult`와 `ConEvidenceResult`

- [ ] **Step 1: 실패하는 독립성 test를 작성한다**

```python
async def test_pro_and_con_use_same_inputs_in_independent_new_sessions() -> None:
    result = await debate.run(**valid_debate_request())
    assert result.pro.debate_input_hash == result.con.debate_input_hash
    assert result.pro.meta.attempt_id != result.con.meta.attempt_id
    assert result.pro.llm_call_id != result.con.llm_call_id
    assert provider.sessions_for("PRO") != provider.sessions_for("CON")
```

- [ ] **Step 2: 현재 fake 직렬 경로에서 test가 실패하는지 확인한다**

Run: `uv run pytest tests/integration/verification/test_debate_service.py::test_pro_and_con_use_same_inputs_in_independent_new_sessions -q`

Expected: FAIL. 운영 `LLMCallService`를 사용하는 병렬 서비스가 아직 없다.

- [ ] **Step 3: Pro와 Con Agent wrapper 및 병렬 DebateService를 최소 구현한다**

두 call spec은 `session_policy=NEW`, `parent_session_ref=null`이어야 한다. public input refs는 정렬·중복 제거 후 hash하고 양쪽에 byte-for-byte 동일하게 전달한다. Pro context에는 Con artifact/result/log를, Con context에는 Pro artifact/result/log를 넣지 않는다. finalizer가 `source_role`, exact parent work, child work, generation, attempt, `llm_call_id`, input hash를 신뢰값으로 채운다.

- [ ] **Step 4: 교차 열람 실패 test를 작성한다**

```python
async def test_cross_role_private_result_stops_parent_without_verdict() -> None:
    with pytest.raises(ValueError, match="CROSS_ROLE_INPUT_DENIED"):
        await debate.run(**request_with_con_result_in_pro_inputs())
    assert store.current_verification_result() is None
    assert store.downstream_work() == ()
```

- [ ] **Step 5: Lane B 핵심 test를 실행한다**

Run: `uv run pytest tests/integration/verification/test_debate_service.py tests/security_negative/test_cross_role_isolation.py -q`

Expected: PASS. 한쪽 timeout/auth/invalid output도 parent verdict를 만들지 않고 성공한 반대쪽 결과만 보존한다.

- [ ] **Step 6: Lane B 파일만 commit한다**

```text
git add src/sastsimi/agents/pro.py src/sastsimi/agents/con.py src/sastsimi/verification/debate_service.py tests/integration/verification/test_debate_service.py tests/security_negative/test_cross_role_isolation.py
git commit -m "feat: run isolated pro and con evidence agents"
```

### Task 3: Lane C — Verification 종합, routing, REVISE

**Files:** Lane C 소유 파일만 사용한다.

**Consumes:** ACTIVE assignment, exact `PlaybookApplication`, completed Context, same-generation committed Pro/Con, T09 canonical JSON artifacts

**Produces:** `VerificationInitialAssessment`, final `FALSE | HOLD`, 허용된 다음 work 등록 요청, Technical `REVISE`의 새 generation

- [ ] **Step 1: 실패하는 named-falsification FALSE test를 작성한다**

```python
async def test_false_requires_named_disproof_and_complete_checks() -> None:
    result = await verification.finalize_without_dynamic(**valid_false_request())
    assert result.verdict == "FALSE"
    assert any(item.outcome == "DISPROVED" for item in result.falsification_results)
    assert all(item.completion == "COMPLETE" for item in result.validation_results)
```

- [ ] **Step 2: 현재 fake assembly 의존 경로에서 test가 실패하는지 확인한다**

Run: `uv run pytest tests/integration/verification/test_verification_service.py::test_false_requires_named_disproof_and_complete_checks -q`

Expected: FAIL. 운영 artifact finalizer와 exact closure 합성이 아직 없다.

- [ ] **Step 3: initial/final content parser와 trusted finalizer를 최소 구현한다**

LLM은 rationale, 질문 결과, 검증 결과, evidence 선택, restrictions, unresolved conditions만 제안한다. runtime은 meta, refs, work/generation/attempt, evidence claim ID, metrics provenance를 채운다. `validate_evidence_pair`, `validate_evidence_sessions`, `validate_verification_closure`를 저장 직전에 실행한다. 실제 `DISPROVED`가 없는 FALSE, 미해결 조건이 없는 HOLD, 질문·validation ID 누락/중복, error/gap만을 evidence로 사용한 결과는 거절한다.

- [ ] **Step 4: T11 전 TRUE와 downstream 권한을 막는다**

initial TRUE는 `next_step=POC_CONFIRMATION`만 만들 수 있다. final TRUE나 dynamic/PoC reference가 없는 TRUE artifact는 `T11_OUTPUT_REQUIRED`로 거절한다. T10 router는 `FALSE`에서 아무 작업도 만들지 않고, `HOLD`에서만 `PRIMITIVE_UPDATE` 등록 요청을 만든다. Gate·Reporter·Chaining concrete package import를 정적 test로 금지한다.

- [ ] **Step 5: Technical REVISE 새 generation test를 작성한다**

```python
def test_revise_returns_to_same_owner_with_fresh_generation() -> None:
    registration = workflow.start_new_generation(**valid_revise_request())
    assert registration.work.work_generation == previous_generation + 1
    assert registration.assignment_ref == active_assignment_ref
    assert registration.application.meta.record_id != old_application.meta.record_id
```

old application/questions/Pro/Con/final result를 새 generation에 재사용하면 `STALE_RESULT` 또는 `TECHNICAL_REVISE_CLOSURE_MISMATCH`로 막는다. 새 generation은 같은 ACTIVE Verification owner를 유지하고 새 `PlaybookApplication`, 질문 ID, fixed input hash를 만든다.

- [ ] **Step 6: Lane C 핵심 test를 실행한다**

Run: `uv run pytest tests/integration/verification/test_verification_service.py tests/integration/verification/test_verdict_router.py tests/integration/verification/test_revision_workflow.py -q`

Expected: PASS. Provider 실패는 final verdict가 없고 T11 전 TRUE/Gate도 없다.

- [ ] **Step 7: Lane C 파일만 commit한다**

```text
git add src/sastsimi/agents/verification.py src/sastsimi/verification/service.py src/sastsimi/verification/verdict_router.py src/sastsimi/verification/revision_workflow.py tests/integration/verification/test_verification_service.py tests/integration/verification/test_revision_workflow.py tests/integration/verification/test_verdict_router.py
git commit -m "feat: synthesize safe verification verdicts"
```

### Task 4: Integration owner — 세 lane 결합과 공유 composition

**Files:** Integration owner 공유 파일과 통합 test만 수정한다.

**Consumes:** Lane A/B/C public interfaces

**Produces:** `RuntimeServices`와 bootstrap에서 사용할 수 있는 T10 실제 흐름, 한 개의 FALSE E2E

- [ ] **Step 1: 세 lane commit을 합치고 소유 파일 밖 변경이 없는지 확인한다**

Run: `git diff --name-only <t10-base>...HEAD`

Expected: 위 파일 지도에 포함된 파일만 나타난다. 공통 파일 충돌은 integration owner가 해결한다.

- [ ] **Step 2: package export와 runtime composition을 한 번만 연결한다**

`RuntimeServices`와 bootstrap은 production `HypothesisAgent`, `DebateService`, `VerificationService`, `VerdictRouter`, `RevisionWorkflow`를 한 조합으로 주입한다. fake scenario helper는 기존 테스트 호환용으로 남기되 production composition에서 import하거나 기본값으로 선택하지 않는다. prompt entry는 role/task/result kind와 exact schema/validator revision을 고정한다.

- [ ] **Step 3: Hypothesis batch 등록을 안전하게 연결한다**

initial `HYPOTHESIS_PROPOSAL` work는 아직 가설 ID가 없으므로 분석 단위 subject와 exact StaticFactBundle을 사용한다. 한 artifact에서 나온 proposal을 각각 검증·저장하되 한 항목의 scope/reference 실패는 그 proposal의 등록을 거절한다. 저장 projection은 Provider가 정한 ID와 work subject를 비교하지 않는다. 배열 전체의 runtime ID 유일성·same scope·exact StaticFactBundle closure를 검사한다. exact duplicate만 새 `hypothesis_id` 없이 종료하고, duplicate 검토 실패·`UNCERTAIN`은 기록 후 계약대로 등록한다.

- [ ] **Step 4: 정상 흐름 한 개를 작성한다**

```python
async def test_static_fact_to_named_falsification_false() -> None:
    result = await pipeline.run_one_hypothesis(false_provider_script())
    assert result.verification.verdict == "FALSE"
    assert result.pro.session_ref != result.con.session_ref
    assert result.downstream_work == ()
```

Run: `uv run pytest tests/integration/verification/test_false_flow.py -q`

Expected: PASS. StaticFactBundle → Hypothesis → 독립 Pro/Con → named falsification FALSE가 exact refs로 이어지고 downstream은 없다.

- [ ] **Step 5: 중요한 실패 흐름 한 개를 실행한다**

Run: `uv run pytest tests/security_negative/test_cross_role_isolation.py::test_cross_role_private_result_stops_parent_without_verdict -q`

Expected: PASS with `CROSS_ROLE_INPUT_DENIED`; final verdict·dynamic·Gate·Reporter·Chaining work는 없다.

- [ ] **Step 6: 변경 Python 파일만 정적 검사한다**

```text
uv run ruff format --check <tracked changed Python files>
uv run ruff check <tracked changed Python files>
uv run mypy --strict <tracked changed Python files>
git diff --check <t10-base>...HEAD
```

Expected: 모두 exit code 0. Windows에서 권한이 잠긴 임시 폴더를 재귀 탐색하지 말고 `git diff` 또는 `git ls-files`로 추적 파일만 전달한다.

- [ ] **Step 7: Blocker/High 점검을 한다**

아래 항목이 하나라도 재현되면 PR을 만들기 전에 수정한다.

1. 다른 analysis/work/generation/attempt의 artifact나 record가 join된다.
2. LLM payload의 meta·ID·상태·reference가 trusted 값으로 승격된다.
3. Pro/Con이 같은 session을 쓰거나 상대 결과를 입력으로 읽는다.
4. timeout/auth/invalid output이 verdict 또는 downstream work를 만든다.
5. named disproof 없는 FALSE 또는 unresolved condition 없는 HOLD가 저장된다.
6. T11 결과 없이 final TRUE 또는 Gate work가 생성된다.
7. router가 Runtime Validator를 거치지 않고 concrete downstream service를 호출한다.
8. credential, hidden reasoning, host path가 artifact·record·safe log에 남는다.

- [ ] **Step 8: 통합 commit을 만든다**

```text
git add src/sastsimi/agents/__init__.py src/sastsimi/orchestration/hypothesis_workflow.py src/sastsimi/storage/hypothesis_projections.py src/sastsimi/verification/__init__.py src/sastsimi/runtime/services.py src/sastsimi/bootstrap.py src/sastsimi/prompts/templates/hypothesis/generate-initial/1.0.0.md src/sastsimi/prompts/templates/pro/review-evidence/1.0.0.md src/sastsimi/prompts/templates/con/review-evidence/1.0.0.md src/sastsimi/prompts/templates/verification/assess-initial/1.0.0.md src/sastsimi/prompts/templates/verification/final-verdict/1.0.0.md tests/integration/verification/conftest.py tests/integration/verification/test_false_flow.py docs/superpowers/plans/implementation/10-llm-verification.md
git commit -m "feat: compose T10 LLM verification flow"
```

- [ ] **Step 9: PR #153의 최종 CI를 한 번 실행한다**

CI에서 전체 pytest, Ruff, mypy, 문서 검사를 실행한다. Task 중 로컬 전체 suite를 다시 실행하지 않는다. CI 실패가 Blocker/High 또는 이번 변경의 직접 회귀이면 수정하고, 무관한 Medium/Low는 후속 목록에 기록한다.

## 2. 완료 조건

- [ ] Hypothesis output 배열이 T09 artifact에서 trusted DomainRecord로 변환되고 runtime-owned ID로 등록된다.
- [ ] Pro/Con이 같은 입력 hash, 서로 다른 work·attempt·call·NEW session으로 실제 병렬 실행된다.
- [ ] 질문과 validation set이 완전하며 named disproof가 있는 FALSE와 근거 있는 HOLD만 저장된다.
- [ ] Provider 실패·교차 역할 입력·stale generation은 verdict와 downstream work 없이 fail closed한다.
- [ ] Technical `REVISE`가 같은 ACTIVE owner의 새 generation, 새 application, 새 질문, 새 Pro/Con으로 돌아간다.
- [ ] T11 전 final TRUE·CWE·Gate·Finding·Reporter·Chaining이 만들어지지 않는다.
- [ ] 정상 FALSE 흐름 한 개와 `CROSS_ROLE_INPUT_DENIED` 실패 흐름 한 개가 통과한다.
- [ ] 변경 파일 Ruff·mypy·diff check가 통과하고 최종 PR CI가 통과한다.
- [ ] R6·R3·R4·R8 관점의 Blocker/High 검토가 0이다.

## 3. T10 이후 작업

- T11: `DynamicReproductionRequest`, Docker Sandbox, validated PoC를 구현하고 그 exact 결과가 있을 때만 final TRUE를 연다.
- T12: CWE Labeling, Technical Evidence Gate, Rule Scope Impact Gate, Finding, Reporter를 연결한다.
- T13: HOLD/허용 TRUE Primitive와 Chaining을 연결한다.
- 추가 Provider, prompt 품질 조정, 성능 최적화, 세부 문서 다듬기는 T16 평가 또는 별도 후속 작업으로 기록한다.

## 4. 실행 기록

- 상태: `IMPLEMENTATION_READY`
- 기준 Issue: `#153`
- 선행 조건: T08 merged, T09 exact branch content available; 실제 T10 PR은 T09가 main에 병합된 commit을 base로 삼는다.
- 계획 검토 결과: 세 lane 파일 소유권이 겹치지 않고, 공유 composition은 integration owner 한 명에게만 배정했다.
