# T11 Dynamic Reproduction and Validated PoC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** R6의 exact `DynamicReproductionRequest`를 받아 격리된 실제 Docker Sandbox에서 R7이 재현을 수행하고, 같은 attempt의 실행 증거가 완전할 때만 `SUPPORTED + validated poc_ref`를 확정한다.

**Architecture:** T11은 기존 `contracts/dynamic.py`, runtime action 검증, SQLite exact-reference projection을 그대로 사용하고 가짜 Sandbox 경로만 실제 구성요소로 교체한다. Sandbox Controller는 Docker 호출 전에 외부 경계만 강제하고, Dynamic Reproduction Agent는 허용된 Sandbox 안의 전략을 자율적으로 제안하며, Reproduction Session Manager는 실제 event와 동일 attempt provenance를 근거로 결과와 PoC를 확정한다. 네 구현 lane은 파일 소유권을 겹치지 않게 나누고 bootstrap·exports·공유 fixture는 통합 담당자만 수정한다.

**Tech Stack:** Python 3.12+, Pydantic v2 strict contracts, SQLAlchemy/SQLite, `asyncio.create_subprocess_exec` 기반 Docker CLI adapter, pytest, Ruff, mypy strict, Docker Engine

**Spec:** [Issue #154](https://github.com/SASTsimi/sastsimi/issues/154), [Complete Implementation Plan Task 11](../2026-09-08-sastsimi-complete-implementation.md#task-11-dynamic-reproduction-and-validated-poc), [Verification and dynamic reproduction](../../../architecture-v5/04-verification-and-dynamic-reproduction.md), [Lightweight data contracts](../../../architecture-v5/08-lightweight-data-contracts.md), [Security boundaries](../../../architecture-v5/10-security-boundaries.md), [Implementation module map](../../../architecture-v5/implementation/01-module-map.md), [Recovery test plan](../../../architecture-v5/implementation/03-recovery-test-plan.md), [Prompt runtime](../../../architecture-v5/implementation/05-prompt-runtime.md)

## Global Constraints

- T11은 T10의 최종 병합 commit 위에서 시작한다. 현재 T11 작업 branch는 T10 구현 중간 상태에서 만들어졌으므로 T11 PR 전 최신 T10 `HypothesisAgent`, `DebateService`, `VerificationService`, `VerdictRouter`, runtime composition과 충돌·API를 다시 확인한다.
- R6만 `DynamicReproductionRequest`와 최종 `TRUE | FALSE | HOLD`를 생산한다. R7은 `EnvironmentRequirements`, `ReproductionPlan`, `EnvironmentRecipe`, `SandboxEnvironment`, PoC candidate, `AgentLog`, `DynamicReproductionConclusion`, `DynamicReproductionResult`와 validated `PoCBundle`만 생산한다.
- `ReproductionPlan`에는 `LIMITED_REPRO`, `FULL_REPRO`, exact command·step·payload·cleanup allowlist를 추가하지 않는다. Agent는 승인된 Sandbox 내부 전략을 자율적으로 제안하고 Controller는 외부 경계만 강제한다.
- Controller는 host, Docker daemon/socket, host mount·namespace, secret, 허용되지 않은 egress, live endpoint, 외부 account와 다른 workspace 접근을 Docker 호출 전에 거절한다. Sandbox 내부 command 내용을 취약점 의미로 판단하거나 command allowlist로 제한하지 않는다.
- 허용된 container는 clean start, non-root user, 최소 capability, `no-new-privileges`, default-deny network, read-only root filesystem과 profile의 CPU·RAM·disk·PID·wall-time 상한을 사용한다. Agent나 repository 입력은 이 상한을 완화할 수 없다.
- `poc_candidate_ref`는 생성 또는 실행을 시도한 입력이다. `poc_ref`는 같은 request/work/generation/attempt/recipe/environment/digest의 candidate가 실제 실행됐고 `SUCCEEDED + SUPPORTED + agent_invoked=true`인 경우에만 생성한다.
- 정책 차단, 환경 구성 실패, Docker 실패, timeout, resource limit, candidate 생성·실행 실패는 R6의 `FALSE | HOLD`로 변환하지 않는다. R7은 `BLOCKED | FAILED + INCONCLUSIVE`, `poc_ref=null`을 반환하거나 retry 가능한 동일 work의 새 attempt를 요청한다.
- 같은 가설 work의 writable container만 조건부 재사용한다. 다른 가설은 공유하지 않는다. crash·비정상 종료·health check 실패·상태 불명은 `STATE_UNCERTAIN`이며 새 clean container로 재생성한다.
- `AgentLog`는 append-only다. `event_id`는 전역 고유, `sequence`는 attempt별 1부터 증가하며 start/finish는 같은 `action_id`와 같은 candidate·command·environment·recipe digest에 연결한다. 늦게 도착한 과거 attempt event를 현재 attempt에 섞지 않는다.
- cleanup은 exact ownership label과 environment/resource reference가 일치하는 T11 test-owned resource만 대상으로 한다. 사용자의 기존 container·image·network·volume을 전체 열거하거나 삭제하지 않는다.
- 변경 기능의 정상 흐름 한 개와 중요한 실패 흐름 한 개를 먼저 검증한다. Task 중 전체 suite를 반복하지 않고, 전체 suite는 PR 최종 CI에서 한 번만 실행한다.
- 데이터 혼합, 권한 우회, 잘못된 verdict, exact reference 불일치, secret 노출, Sandbox 경계 위반은 Blocker/High로 즉시 수정한다. Medium/Low 리팩터링·테스트 확대·문서 미세 보정은 후속 목록에만 남긴다.

---

## 1. 선행 조건과 병렬 실행 순서

### T10 API 재검증 gate

T11 구현 전에 통합 담당자가 다음을 한 번 확인한다.

```powershell
git fetch origin
git log --oneline --decorate -8
rg -n "class (HypothesisAgent|DebateService|VerificationService|VerdictRouter)" src/sastsimi
rg -n "DynamicReproductionRequest|REQUEST_DYNAMIC_REPRO" src/sastsimi tests
git diff --name-status origin/main...HEAD
```

확인 결과 T10 최종 API가 이 계획의 import와 다르면 호출부 이름만 최신 API에 맞춘다. R6/R7 권한, verdict 의미, exact-ref 불변조건을 바꾸지 않는다. T10 commit이 아직 `main`에 없으면 T11 PR을 열지 않는다.

### 병렬 순서

1. 통합 담당자가 T10 final base와 기존 `SandboxPort`, dynamic contracts의 이름을 확인하고 아래 public interface를 lane 담당자에게 고정한다.
2. 사용 가능한 네 실행 slot을 모두 사용한다. root 통합 담당자가 Lane D를 수행하는 동안 독립 subagent 세 명이 Lane A, B, C를 동시에 수행한다. 각 lane은 자기 파일만 수정하고 자기 focused test만 실행한다.
3. 통합 담당자가 네 commit을 결합한 뒤에만 bootstrap, package exports, prompt registry, 공용 fixture와 CI를 수정한다.
4. 정상 Docker E2E와 중요 실패 E2E를 확인하고 독립 Blocker/High 검토를 수행한다.
5. 전체 suite는 PR CI에서 한 번 실행한다. Blocker/High가 0이고 CI가 green이면 병합한다.

## 2. 파일 지도와 충돌 없는 소유권

### Lane A — Sandbox Controller와 외부 경계

이 lane만 다음 파일을 수정한다.

- Create: `src/sastsimi/sandbox/controller.py`
- Create: `tests/security_negative/sandbox/test_boundary.py`

생산 인터페이스:

```python
@dataclass(frozen=True)
class SandboxMount:
    source: Path | None
    target: PurePosixPath
    read_only: bool

@dataclass(frozen=True)
class SandboxRunSpec:
    workspace_root: Path
    image_digest: str
    user: str
    mounts: tuple[SandboxMount, ...]
    network_mode: str
    network_targets: tuple[str, ...]
    secret_refs: tuple[StoredDataRef, ...]
    privileged: bool
    pid_mode: str | None
    ipc_mode: str | None
    capabilities: tuple[str, ...]
    cpu_limit_millicores: int
    memory_limit_bytes: int
    disk_limit_bytes: int
    pid_limit: int
    requested_execution_ms: int

@dataclass(frozen=True)
class SandboxBoundaryOutcome:
    decision: SandboxPolicyDecision
    approved_spec: SandboxRunSpec | None

class SandboxController:
    def evaluate(
        self,
        *,
        spec: SandboxRunSpec,
        action: ActionRequest,
        action_decision_ref: StoredDataRef,
        request: DynamicReproductionRequest,
        plan: ReproductionPlan,
        sandbox_profile: SandboxProfile,
        lifecycle_profile: DynamicReproductionLifecycleProfile,
        run_policy_state_ref: StoredDataRef,
        meta: RecordMeta,
    ) -> SandboxBoundaryOutcome: ...
```

`ALLOW`일 때만 `approved_spec`이 존재한다. `DENY`는 구체적이고 안전한 reason code를 가진 `SandboxPolicyDecision`을 반환하며 Docker adapter를 호출하지 않는다.

### Lane B — Environment recipe, setup, container lifecycle

이 lane만 다음 파일을 수정한다.

- Create: `src/sastsimi/sandbox/docker_adapter.py`
- Create: `src/sastsimi/sandbox/recipe_store.py`
- Create: `src/sastsimi/sandbox/setup_automation.py`
- Create: `src/sastsimi/sandbox/health_check.py`
- Create: `src/sastsimi/sandbox/cleanup.py`
- Create: `docker/base/Dockerfile`
- Create: `docker/profiles/local-default-deny.yaml`
- Create: `tests/integration/sandbox/test_container_lifecycle.py`

소비·생산 인터페이스:

```python
@dataclass(frozen=True)
class PreparedSandbox:
    recipe: EnvironmentRecipe
    environment: SandboxEnvironment
    resource_refs: tuple[StoredDataRef, ...]

class DockerAdapter:
    async def build(self, recipe_source: Path, labels: Mapping[str, str]) -> str: ...
    async def create(self, spec: SandboxRunSpec, labels: Mapping[str, str]) -> str: ...
    async def start(self, container_id: str) -> None: ...
    async def exec(
        self, container_id: str, argv: tuple[str, ...], timeout_ms: int
    ) -> DockerCommandOutcome: ...
    async def inspect(self, container_id: str) -> DockerContainerState: ...
    async def remove(self, resource_ids: tuple[str, ...]) -> None: ...

class ReproductionSetupAutomation:
    async def preflight(
        self,
        *,
        workspace_root: Path,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        meta: RecordMeta,
    ) -> PreparedRecipeSource: ...

    async def build(
        self,
        *,
        approval: SandboxBuildBoundaryOutcome,
        source: PreparedRecipeSource,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        meta: RecordMeta,
    ) -> EnvironmentRecipe: ...

    async def create(
        self,
        *,
        approval: SandboxBoundaryOutcome,
        recipe: EnvironmentRecipe,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        plan: ReproductionPlan,
        meta: RecordMeta,
    ) -> PreparedSandbox: ...

    async def recreate(
        self,
        *,
        approval: SandboxBoundaryOutcome,
        previous: PreparedSandbox,
        reason: Literal["STATE_CHANGED", "CONFIG_CHANGED", "STATE_UNCERTAIN"],
        meta: RecordMeta,
    ) -> PreparedSandbox: ...

    async def cleanup(
        self,
        *,
        request: DynamicReproductionRequest,
        environments: tuple[SandboxEnvironment, ...],
        resource_refs: tuple[StoredDataRef, ...],
        meta: RecordMeta,
    ) -> CleanupResult: ...
```

Docker CLI는 shell 문자열을 만들지 않고 고정된 executable과 argv를 `asyncio.create_subprocess_exec`로 전달한다. Container name과 label은 runtime-owned ID에서만 만들며 repository나 Agent 문자열을 이름으로 사용하지 않는다. Image build도 승인 경계 안에서 `--network none`, exact build context, secret/SSH mount 없음으로 수행하며 untrusted repository 경로를 임의의 build context나 host source로 확장하지 않는다.

### Lane C — AgentLog, Session Manager, validated PoC

이 lane만 다음 파일을 수정한다.

- Create: `src/sastsimi/sandbox/session_manager.py`
- Create: `tests/integration/sandbox/test_agent_log_session.py`
- Create: `tests/security_negative/sandbox/test_poc_promotion.py`

생산 인터페이스:

```python
@dataclass(frozen=True)
class DynamicFinalizationInput:
    request: DynamicReproductionRequest
    plan: ReproductionPlan | None
    policy: SandboxPolicyDecision | None
    recipe: EnvironmentRecipe | None
    environment: SandboxEnvironment | None
    candidate: PoCCandidate | None
    conclusion: DynamicReproductionConclusion | None
    cleanup: CleanupResult | None
    observation_refs: tuple[StoredDataRef, ...]
    status: Literal["SUCCEEDED", "PARTIAL", "FAILED", "BLOCKED", "CANCELLED"]
    failure_category: str
    failure_reason: str | None
    plan_issues: tuple[PlanIssueItem, ...]
    started_at: datetime
    finished_at: datetime

@dataclass(frozen=True)
class FinalizedDynamicRecords:
    log: AgentLog
    poc: PoCBundle | None
    result: DynamicReproductionResult

class ReproductionSessionManager:
    def start(self, *, request_ref: StoredDataRef, meta: RecordMeta) -> AgentLog: ...
    def append(self, *, previous: AgentLog, event: AgentLogEvent) -> AgentLog: ...
    def finalize(
        self, *, data: DynamicFinalizationInput, log: AgentLog, meta: RecordMeta
    ) -> FinalizedDynamicRecords: ...
```

`append`는 동일 `event_id + canonical hash` 재전달만 멱등 ACK로 받아들이고, 같은 ID/sequence의 다른 bytes와 이전 attempt event를 거절한다. `finalize`는 `validate_dynamic_closure`, `validate_command_closure`, `validate_execution_support`, cleanup coverage를 통과한 뒤에만 `PoCBundle`과 result를 반환한다.

### Lane D — Dynamic Reproduction Agent와 workflow

이 lane만 다음 파일을 수정한다.

- Create: `src/sastsimi/agents/dynamic_reproduction.py`
- Replace fake-only implementation behind public API: `src/sastsimi/reproduction/service.py`
- Create: `tests/integration/sandbox/test_dynamic_reproduction_workflow.py`

생산 인터페이스:

```python
class DynamicReproductionAgent:
    async def derive_environment(
        self, *, work: WorkExecutionState, request_ref: StoredDataRef,
        dependency_context_refs: tuple[StoredDataRef, ...], call: LLMCallRefs
    ) -> EnvironmentRequirements: ...

    async def plan_reproduction(
        self, *, work: WorkExecutionState, request_ref: StoredDataRef,
        requirements_ref: StoredDataRef, call: LLMCallRefs
    ) -> ReproductionPlan: ...

    async def create_poc_candidate(
        self, *, work: WorkExecutionState, request_ref: StoredDataRef,
        plan_ref: StoredDataRef, environment_ref: StoredDataRef, call: LLMCallRefs
    ) -> PoCCandidate: ...

    async def next_tool_request(
        self, *, work: WorkExecutionState, request_ref: StoredDataRef,
        plan_ref: StoredDataRef, environment_ref: StoredDataRef,
        log_ref: StoredDataRef, turn_number: int, call: LLMCallRefs
    ) -> DynamicReproductionToolRequest: ...

    async def interpret_attempt(
        self, *, work: WorkExecutionState, request_ref: StoredDataRef,
        plan_ref: StoredDataRef, environment_ref: StoredDataRef,
        log_ref: StoredDataRef, call: LLMCallRefs
    ) -> DynamicReproductionConclusion: ...

class DynamicReproductionService:
    async def execute(
        self, *, context: WorkContext, request_ref: StoredDataRef
    ) -> WorkHandlerResult: ...
```

각 Agent method는 T09의 성공 canonical JSON artifact를 읽고, trusted finalizer가 meta·exact refs·generation·attempt·`llm_call_id`를 주입한다. `EXECUTE_REPRODUCTION`만 승인된 Sandbox 내부 tool loop를 사용한다. 다른 네 task는 provider tool 없이 구조화 출력만 사용한다.

### Integration owner — 공유 파일 전담

네 lane은 다음 공유 파일을 수정하지 않는다. 통합 담당자만 마지막에 수정한다.

- Modify: `src/sastsimi/ports/dto.py`
- Modify: `src/sastsimi/ports/sandbox.py`
- Modify: `src/sastsimi/agents/__init__.py`
- Modify: `src/sastsimi/reproduction/__init__.py`
- Modify: `src/sastsimi/sandbox/__init__.py`
- Modify: `src/sastsimi/runtime/services.py`
- Modify: `src/sastsimi/bootstrap.py`
- Modify: prompt registry seed/configuration files
- Create: `src/sastsimi/prompts/templates/dynamic-reproduction/derive-environment/1.0.0.md`
- Create: `src/sastsimi/prompts/templates/dynamic-reproduction/plan-reproduction/1.0.0.md`
- Create: `src/sastsimi/prompts/templates/dynamic-reproduction/create-poc-candidate/1.0.0.md`
- Create: `src/sastsimi/prompts/templates/dynamic-reproduction/execute-reproduction/1.0.0.md`
- Create: `src/sastsimi/prompts/templates/dynamic-reproduction/interpret-attempt/1.0.0.md`
- Create: `tests/integration/sandbox/conftest.py`
- Create: `tests/fixtures/sandbox/sql_injection/app.py`
- Create: `tests/fixtures/sandbox/sql_injection/Dockerfile`
- Create: `tests/e2e/test_dynamic_reproduction.py`
- Modify: `.github/workflows/application-foundation.yml`
- Modify: `docs/superpowers/plans/implementation/11-dynamic-reproduction.md`의 완료 증거와 후속 목록

공통 contract 변경이 필요하면 lane 담당자는 임의 수정하지 않고 정확한 실패 test, error code, 영향 필드를 통합 담당자에게 전달한다. 승인된 schema가 표현 가능한 범위에서는 새 필드를 추가하지 않는다.

---

### Task 1: Lane A — Docker 호출 전 Sandbox 외부 경계 강제

**Files:** Lane A 소유 파일만 사용한다.

**Consumes:** exact `RUN_SANDBOX` action, Runtime Validator의 ALLOW decision, current request/plan/profile/lifecycle profile, runtime-owned workspace root

**Produces:** `SandboxBoundaryOutcome`; ALLOW일 때 immutable `SandboxRunSpec`, DENY일 때 `SandboxPolicyDecision`

- [ ] **Step 1: 금지 경계의 parameterized 실패 test를 작성한다**

```python
@pytest.mark.parametrize(
    "case",
    ["HOST_ROOT_MOUNT", "DOCKER_SOCKET", "LIVE_ENDPOINT", "RAW_SECRET", "EGRESS"],
)
def test_forbidden_boundary_is_denied_before_adapter(case: str) -> None:
    outcome = controller.evaluate(**forbidden_boundary(case))
    assert outcome.decision.decision == "DENY"
    assert outcome.approved_spec is None
    assert outcome.decision.execution_scope == "LOCAL_ONLY"
```

- [ ] **Step 2: test가 Controller 부재로 실패하는지 확인한다**

Run: `uv run pytest tests/security_negative/sandbox/test_boundary.py -q`

Expected: FAIL with import error 또는 `SandboxController` 미구현.

- [ ] **Step 3: fail-closed 경계 검사를 최소 구현한다**

다음 값을 문자열 포함 검사로 대충 판정하지 않고 구조화된 `SandboxRunSpec`에서 검사한다.

- mount source는 runtime-owned workspace 하위의 명시적 read-only clone만 허용한다. `/`, drive root, Docker socket, named pipe, workspace 밖 path는 거절한다.
- `privileged=false`, host PID/IPC/network namespace 금지, capability add 금지, non-root numeric user 필수다.
- `network_mode=DEFAULT_DENY`이며 loopback 또는 Controller가 만든 동일 격리 network 외 target은 거절한다.
- command/environment에 raw secret을 복사하지 않고 `secret_handle` reference만 허용한다. Sandbox 실행에는 secret handle도 기본 DENY다.
- 요청 resource는 profile·lifecycle 상한보다 작거나 같아야 하며 누락·불명확하면 DENY다.
- request/plan/profile/action/generation/workspace/commit exact reference 불일치는 `STALE_RESULT` 또는 전용 boundary reason으로 거절한다.

- [ ] **Step 4: 허용 spec test를 추가한다**

```python
def test_local_non_root_default_deny_spec_is_approved() -> None:
    outcome = controller.evaluate(**local_clean_spec())
    assert outcome.decision.decision == "ALLOW"
    assert outcome.approved_spec is not None
    assert outcome.approved_spec.network_mode == "DEFAULT_DENY"
    assert outcome.approved_spec.user not in {"0", "root"}
    assert outcome.approved_spec.privileged is False
```

- [ ] **Step 5: Lane A focused test를 실행한다**

Run: `uv run pytest tests/security_negative/sandbox/test_boundary.py -q`

Expected: PASS. 모든 금지 variant가 DENY이고 허용 variant만 immutable approved spec을 얻는다.

- [ ] **Step 6: Lane A만 commit한다**

```text
git add src/sastsimi/sandbox/controller.py tests/security_negative/sandbox/test_boundary.py
git commit -m "feat: enforce sandbox external boundaries"
```

### Task 2: Lane B — 실제 Docker 환경 준비, health, 재생성, cleanup

**Files:** Lane B 소유 파일만 사용한다.

**Consumes:** Lane A의 ALLOW `SandboxRunSpec`, exact request/requirements/plan, repository Dockerfile·README·manifest·lockfile context

**Produces:** immutable `EnvironmentRecipe`, READY `SandboxEnvironment`, command outcome, `CleanupResult`

- [ ] **Step 1: clean non-root/default-deny container의 실패하는 lifecycle test를 작성한다**

```python
async def test_prepare_creates_clean_non_root_default_deny_container() -> None:
    prepared = await setup.prepare(**approved_local_fixture())
    inspected = await docker.inspect(prepared.environment.container_instance_id)
    assert prepared.environment.container_action == "CREATED"
    assert prepared.environment.container_reason == "INITIAL_CLEAN"
    assert prepared.environment.status == "READY"
    assert inspected.user not in {"0", "root"}
    assert inspected.network_mode == "none"
    assert inspected.privileged is False
    assert inspected.read_only_rootfs is True
```

- [ ] **Step 2: 실제 adapter 부재로 실패하는지 확인한다**

Run: `uv run pytest tests/integration/sandbox/test_container_lifecycle.py::test_prepare_creates_clean_non_root_default_deny_container -q`

Expected: FAIL. Docker adapter 또는 Setup Automation이 없다. Docker daemon이 없는 개발 환경에서는 명시적 `SKIPPED: docker unavailable`이 가능하지만 PR Ubuntu Docker job에서는 skip을 실패로 취급한다.

- [ ] **Step 3: Docker CLI adapter를 최소 구현한다**

`docker build`, `create`, `start`, `exec`, `inspect`, `rm`은 모두 argv tuple로 실행한다. stdout/stderr는 byte artifact로 저장하기 전 redaction 경계를 거치고 command line과 environment에 secret 값을 기록하지 않는다. Build는 `--network none`, exact test/workspace build context와 runtime-owned label만 사용하고 `--secret`, `--ssh`, host bind를 받지 않는다. create argv에는 `--network none`, `--read-only`, size가 제한된 test-owned tmpfs, `--security-opt no-new-privileges`, `--cap-drop ALL`, `--pids-limit`, CPU·memory 상한, runtime-owned label과 non-root user를 반드시 포함한다. wall-time을 넘기면 adapter가 해당 action을 종료하고 environment를 `STATE_UNCERTAIN`으로 표시한다. 승인 spec 밖 option을 adapter caller가 추가할 수 없게 한다.

- [ ] **Step 4: immutable recipe와 실제 digest 기록을 구현한다**

기존 Dockerfile·manifest·lockfile을 우선 입력으로 사용한다. source bytes의 canonical hash가 recipe revision을 결정하며 `base_image_digest`와 build 후 inspect한 `built_image_digest`를 분리한다. 동일 source hash의 성공 baseline은 read-only image layer만 재사용하고 writable container는 가설 간 공유하지 않는다. 누락 package로 source를 수정하면 새 recipe revision과 새 image digest를 만든다.

- [ ] **Step 5: health failure 재생성과 exact cleanup test를 추가한다**

```python
async def test_unhealthy_container_is_recreated_and_only_owned_resources_removed() -> None:
    first = await setup.prepare(**approved_local_fixture())
    docker.mark_unhealthy(first.environment.container_instance_id)
    second = await setup.recreate(
        previous=first, reason="STATE_UNCERTAIN", meta=next_attempt_meta()
    )
    assert second.environment.container_action == "CREATED"
    assert second.environment.previous_environment_ref == reference(first.environment)
    result = await setup.cleanup(**owned_resources(first, second))
    assert result.status == "SUCCEEDED"
    assert docker.unrelated_resources_removed == ()
```

health 확인 불가·container crash·비정상 종료는 강제 `STATE_UNCERTAIN`이다. cleanup은 ownership label과 exact resource refs가 모두 맞는 자원만 제거하며 실패를 성공으로 숨기지 않는다.

- [ ] **Step 6: Lane B focused test를 실행한다**

Run: `uv run pytest tests/integration/sandbox/test_container_lifecycle.py -q`

Expected: PASS 또는 Docker 미설치 로컬에서는 명시적 skip. fake lifecycle test는 항상 PASS하고 PR Ubuntu 실제 Docker test는 반드시 실행된다.

- [ ] **Step 7: Lane B만 commit한다**

```text
git add src/sastsimi/sandbox/docker_adapter.py src/sastsimi/sandbox/recipe_store.py src/sastsimi/sandbox/setup_automation.py src/sastsimi/sandbox/health_check.py src/sastsimi/sandbox/cleanup.py docker/base/Dockerfile docker/profiles/local-default-deny.yaml tests/integration/sandbox/test_container_lifecycle.py
git commit -m "feat: manage isolated docker reproduction environments"
```

### Task 3: Lane C — append-only AgentLog와 validated PoC 확정

**Files:** Lane C 소유 파일만 사용한다.

**Consumes:** 같은 attempt에서 실제 발생한 Controller, setup, Agent, command, observation, cleanup event와 exact domain records

**Produces:** durable `AgentLog`, optional validated `PoCBundle`, final `DynamicReproductionResult`

- [ ] **Step 1: event append와 재전달 test를 작성한다**

```python
def test_log_append_is_ordered_and_idempotent_only_for_identical_event() -> None:
    log = manager.start(request_ref=request_ref, meta=attempt_meta)
    current = manager.append(previous=log, event=command_started(sequence=2))
    replay = manager.append(previous=current, event=command_started(sequence=2))
    assert replay == current
    with pytest.raises(ValueError, match="RECOVERY_FAILED"):
        manager.append(previous=current, event=changed_same_event_id(sequence=2))
```

- [ ] **Step 2: test가 Session Manager 부재로 실패하는지 확인한다**

Run: `uv run pytest tests/integration/sandbox/test_agent_log_session.py -q`

Expected: FAIL with import error 또는 append-only ACK 미구현.

- [ ] **Step 3: append-only log와 action pair 검사를 최소 구현한다**

`SESSION_STARTED` 뒤 sequence를 1씩 증가시킨다. start/finish pair는 동일 `action_id`, tool request, command record/digest, environment, recipe, candidate를 공유해야 한다. 이미 저장된 event와 같은 ID·bytes는 기존 log revision을 반환하고, 다른 bytes·다른 attempt·건너뛴 sequence·finish-only event는 거절한다. crash 뒤 finish event를 추측해서 만들지 않는다.

- [ ] **Step 4: candidate가 validated PoC로 잘못 승격되는 실패 test를 작성한다**

```python
@pytest.mark.parametrize(
    "mutation",
    ["NOT_EXECUTED", "EXIT_NONZERO", "INCONCLUSIVE", "OLD_ATTEMPT", "WRONG_DIGEST"],
)
def test_candidate_is_not_promoted_without_same_attempt_support(mutation: str) -> None:
    finalized = manager.finalize(**candidate_without_complete_support(mutation))
    assert finalized.poc is None
    assert finalized.result.poc_ref is None
    assert finalized.result.hypothesis_outcome == "INCONCLUSIVE"
```

`DISPROVED`는 정상 실행의 실제 반증 evidence가 있을 때만 허용하며 PoC는 없다. 실행 실패·timeout·policy block은 항상 `INCONCLUSIVE`이다.

- [ ] **Step 5: 정상 PoC 확정 test를 추가한다**

```python
def test_supported_execution_promotes_exact_candidate_once() -> None:
    finalized = manager.finalize(**complete_supported_attempt())
    assert finalized.result.status == "SUCCEEDED"
    assert finalized.result.hypothesis_outcome == "SUPPORTED"
    assert finalized.poc is not None
    assert finalized.result.poc_ref == reference(finalized.poc)
    assert finalized.poc.candidate_digest == candidate.content_digest
```

finalize는 기존 `validate_dynamic_closure` 전체를 호출한다. request 생산 attempt와 R7 실행 attempt가 다를 수 있다는 현재 계약은 유지하되, plan/recipe/environment/log/candidate/command/conclusion/PoC/result는 R7 동일 attempt여야 한다.

- [ ] **Step 6: Lane C focused test를 실행한다**

Run: `uv run pytest tests/integration/sandbox/test_agent_log_session.py tests/security_negative/sandbox/test_poc_promotion.py -q`

Expected: PASS. old attempt, digest mismatch, 미실행 candidate는 모두 `poc_ref=null`이고 actual supported closure만 PoC를 만든다.

- [ ] **Step 7: Lane C만 commit한다**

```text
git add src/sastsimi/sandbox/session_manager.py tests/integration/sandbox/test_agent_log_session.py tests/security_negative/sandbox/test_poc_promotion.py
git commit -m "feat: finalize dynamic evidence and validated poc"
```

### Task 4: Lane D — Dynamic Agent의 자율 tool loop와 workflow 연결

**Files:** Lane D 소유 파일만 사용한다.

**Consumes:** T09 Prompt Runtime와 Provider artifact, T10 current Verification work, exact R6 request, Lane A/B/C interfaces

**Produces:** R7 stage별 records와 terminal `WorkHandlerResult`; R6 verdict는 생산하지 않음

- [ ] **Step 1: stage와 tool 정책의 실패하는 test를 작성한다**

```python
async def test_only_execute_stage_can_request_sandbox_tools() -> None:
    requirements = await agent.derive_environment(**derive_call())
    plan = await agent.plan_reproduction(**plan_call(requirements))
    candidate = await agent.create_poc_candidate(**candidate_call(plan))
    tool = await agent.next_tool_request(**execute_call(candidate))
    conclusion = await agent.interpret_attempt(**interpret_call(tool))
    assert requirements.request_ref == request_ref
    assert plan.request_ref == request_ref
    assert candidate.request_ref == request_ref
    assert tool.action in {
        "RUN_COMMAND", "USE_POC_CANDIDATE", "REQUEST_SANDBOX_RECREATE", "FINISH"
    }
    assert conclusion.request_ref == request_ref
    assert provider.tool_calls_outside("EXECUTE_REPRODUCTION") == ()
```

- [ ] **Step 2: fake-only service 때문에 test가 실패하는지 확인한다**

Run: `uv run pytest tests/integration/sandbox/test_dynamic_reproduction_workflow.py::test_only_execute_stage_can_request_sandbox_tools -q`

Expected: FAIL. 현재 `reproduction/service.py`는 fake factory와 미리 만든 결과를 직접 조합한다.

- [ ] **Step 3: 역할별 content-only finalizer를 구현한다**

각 stage는 `LLMInvocationResult.status=SUCCEEDED`, exact role/task/purpose/work/attempt/session/input closure와 artifact hash를 확인한다. Provider가 meta, record ID, request/work/generation/attempt, environment/recipe/candidate/log reference, `poc_ref`, final dynamic result 또는 R6 verdict를 출력하면 `OUTPUT_RUNTIME_AUTHORITY_DENIED`로 거절한다. Runtime이 현재 stage에서 허용된 ID와 exact refs만 주입한다.

- [ ] **Step 4: actual workflow 순서를 구현한다**

`execute`는 다음 순서를 지킨다.

1. exact `DynamicReproductionRequest`와 current DYNAMIC_REPRO work/attempt를 확인한다.
2. `derive_environment`와 `plan_reproduction`을 Sandbox 밖 read-only/no-tools 호출로 실행한다.
3. setup preflight가 Docker를 호출하지 않고 exact recipe source를 만든다.
4. build용 `RUN_SANDBOX` action/decision을 만들고 claim한 뒤 Controller가 source와 외부 경계를 검사한다. DENY면 Docker를 호출하지 않고 Session Manager가 차단 결과와 log를 확정한다.
5. ALLOW면 image를 inspect/build하고 actual digest의 `EnvironmentRecipe`를 저장한다.
6. run용 새 `RUN_SANDBOX` action/decision이 exact recipe·actual digest·build 승인 provenance를 고정한다. 이를 claim하고 Controller가 다시 허용한 뒤에만 clean container를 만들고 Agent를 시작한다.
7. candidate를 만들고 `next_tool_request` 한 개씩 받는다. Runtime이 승인된 container 통로에서 실행하고 Session Manager가 실제 event를 기록한다.
8. `REQUEST_SANDBOX_RECREATE` 또는 강제 `STATE_UNCERTAIN`이면 current recipe·환경·사유를 고정한 새 run action/decision을 거친 뒤 recreate를 호출하고 old/new environment link를 log에 남긴다.
9. `FINISH` 뒤에만 `interpret_attempt`을 호출한다.
10. cleanup을 실행한 뒤 C의 finalize와 trusted storage terminal commit을 호출한다.

`max_new_attempts`, wall-time과 work budget을 소진하면 `FAILED + INCONCLUSIVE`; retry 가능한 일시 실패는 같은 work의 새 attempt다. exact request 또는 profile ref 변경은 같은 attempt retry가 아니라 R6의 새 Verification generation이므로 이 service가 자동 교체하지 않는다.

- [ ] **Step 5: 오류가 verdict로 변환되지 않는 test를 추가한다**

```python
@pytest.mark.parametrize("failure", ["AUTH", "TIMEOUT", "DOCKER", "POC_EXECUTION"])
async def test_operational_failure_has_no_r6_verdict(failure: str) -> None:
    completed = await service.execute(**workflow_with_failure(failure))
    result = store.exact_dynamic_result(completed.output_refs)
    assert result.hypothesis_outcome == "INCONCLUSIVE"
    assert result.poc_ref is None
    assert store.verification_results_after(result.meta.created_at) == ()
    assert store.gate_work_for(result.request_ref) == ()
```

- [ ] **Step 6: Lane D focused test를 실행한다**

Run: `uv run pytest tests/integration/sandbox/test_dynamic_reproduction_workflow.py -q`

Expected: PASS. stage 순서와 tool policy가 고정되고 운영 실패는 R6 verdict나 Gate를 만들지 않는다.

- [ ] **Step 7: Lane D만 commit한다**

```text
git add src/sastsimi/agents/dynamic_reproduction.py src/sastsimi/reproduction/service.py tests/integration/sandbox/test_dynamic_reproduction_workflow.py
git commit -m "feat: run dynamic reproduction agent workflow"
```

### Task 5: Integration owner — public ports, bootstrap, prompts 결합

**Files:** Integration owner 공유 파일만 수정한다.

**Consumes:** Lane A/B/C/D public interfaces와 최신 T10 final runtime API

**Produces:** bootstrap에서 선택 가능한 실제 Docker `WorkHandler`, 다섯 개 Dynamic Agent prompt, 공용 test fixture

- [ ] **Step 1: lane commit의 파일 소유권을 확인한다**

Run:

```powershell
$t11BaseCommit = git merge-base origin/main HEAD
git diff --name-only "$t11BaseCommit...HEAD"
```

Expected: 각 lane의 변경 파일이 §2 소유권과 일치한다. `bootstrap.py`, exports, registry, shared fixtures는 아직 lane commit에 없어야 한다.

- [ ] **Step 2: `SandboxPort`와 DTO를 실제 adapter interface로 연결한다**

기존 `prepare`, `execute`, `cleanup` 의미를 유지하고 approved spec·실제 outcome을 전달하는 데 필요한 내부 DTO만 추가한다. Domain contract의 필드나 producer를 바꾸지 않는다. fake adapter는 기존 T07 회귀 test에서 계속 사용할 수 있게 유지하되 운영 bootstrap의 기본 동적 경로로 선택하지 않는다.

- [ ] **Step 3: 다섯 prompt와 registry entry를 연결한다**

각 template은 다음을 명시한다.

- `derive-environment`: repository의 실제 Dockerfile·README·manifest·lockfile context만 사용하며 없는 의존성을 추측하지 않는다.
- `plan-reproduction`: 목적·전략·관찰 목표만 제시하고 exact command/step/mode를 계획에 넣지 않는다.
- `create-poc-candidate`: 실행 전 candidate만 만들며 성공 PoC라고 주장하지 않는다.
- `execute-reproduction`: 승인된 Sandbox tool을 한 turn에 하나만 요청하고 외부 경계 우회를 요청하지 않는다.
- `interpret-attempt`: 저장된 exact log와 observation만 해석해 `SUPPORTED | DISPROVED | INCONCLUSIVE`를 제안하고 R6 verdict와 validated PoC를 직접 만들지 않는다.

- [ ] **Step 4: runtime service composition과 package exports를 한 번만 수정한다**

`RuntimeServices`/bootstrap은 Controller, Setup Automation, Docker Adapter, Session Manager, Dynamic Agent, DynamicReproductionService를 dependency injection으로 조합한다. import 방향은 workflow → port, adapter → port이며 Controller/Session Manager는 LLM prompt를 갖지 않는다. fake production assembly를 실제 handler 대신 사용하지 않는 정적 assertion을 추가한다.

- [ ] **Step 5: 공유 SQL injection fixture를 만든다**

`tests/fixtures/sandbox/sql_injection/app.py`는 Python stdlib SQLite만 사용하고 사용자명 문자열을 취약하게 query에 연결하는 고정 테스트 앱으로 만든다. 정상 입력은 일반 사용자 한 명만 반환하고 PoC 입력은 admin row를 반환한다. Dockerfile은 fixture를 image에 복사하고 non-root user로 실행할 수 있게 하며 host bind mount나 network가 없어도 동작한다. fixture는 오직 테스트가 생성한 disposable container에서만 실행한다.

- [ ] **Step 6: shared import·registry focused test를 실행한다**

Run: `uv run pytest tests/unit/runtime/test_prompt_registry.py tests/integration/storage/test_runtime_composition.py -q`

Expected: PASS. 다섯 stage가 정확히 한 ACTIVE template을 갖고 실제 service가 주입된다.

- [ ] **Step 7: integration 파일만 commit한다**

```text
git add src/sastsimi/ports/dto.py src/sastsimi/ports/sandbox.py src/sastsimi/agents/__init__.py src/sastsimi/reproduction/__init__.py src/sastsimi/sandbox/__init__.py src/sastsimi/runtime/services.py src/sastsimi/bootstrap.py src/sastsimi/prompts/templates tests/integration/sandbox/conftest.py tests/fixtures/sandbox/sql_injection
git commit -m "feat: compose real dynamic reproduction runtime"
```

### Task 6: 정상 Docker E2E와 중요 실패 E2E

**Files:** Integration owner test/CI 파일만 수정한다.

**Consumes:** 통합된 T11 workflow

**Produces:** 실제 Docker 정상 증거 한 개와 Docker 전 차단 실패 증거 한 묶음

- [ ] **Step 1: 실제 정상 E2E를 작성한다**

```python
async def test_supported_fixture_produces_validated_poc() -> None:
    completed = await run_dynamic_fixture("sql_injection")
    result = store.exact_dynamic_result(completed.output_refs)
    poc = store.get_exact(result.poc_ref)
    assert result.status == "SUCCEEDED"
    assert result.hypothesis_outcome == "SUPPORTED"
    assert result.agent_invoked is True
    assert isinstance(poc, PoCBundle)
    assert result.poc_ref == reference(poc)
    assert result.cleanup_status == "SUCCEEDED"
    assert store.verification_results_after(result.meta.created_at) == ()
```

이 test는 실제 Docker daemon을 사용하며 container inspect 결과에서 non-root, default-deny network, capability drop, read-only root filesystem과 resource limit을 확인한다. validated PoC의 request/work/generation/attempt/environment/recipe/candidate digest/log action이 모두 동일 closure인지 다시 검사한다.

- [ ] **Step 2: Docker 전 정책 차단 E2E를 작성한다**

```python
@pytest.mark.parametrize(
    "forbidden",
    ["HOST_MOUNT", "DOCKER_SOCKET", "LIVE_ENDPOINT", "SECRET", "EGRESS"],
)
async def test_forbidden_request_is_blocked_before_docker(forbidden: str) -> None:
    completed = await run_forbidden_dynamic_request(forbidden)
    result = store.exact_dynamic_result(completed.output_refs)
    assert completed.docker_calls == 0
    assert result.status == "BLOCKED"
    assert result.failure_category == "POLICY_BLOCKED"
    assert result.hypothesis_outcome == "INCONCLUSIVE"
    assert result.agent_invoked is False
    assert result.poc_ref is None
    assert result.cleanup_required is False
    assert result.cleanup_status == "NOT_REQUIRED"
    assert store.agent_log(result.agent_log_ref).events[-2].event_type == "POLICY_BLOCKED"
    assert store.verification_results_after(result.meta.created_at) == ()
```

- [ ] **Step 3: 핵심 두 흐름만 실행한다**

Run: `uv run pytest tests/e2e/test_dynamic_reproduction.py tests/security_negative/sandbox/test_boundary.py tests/security_negative/sandbox/test_poc_promotion.py -q`

Expected: Docker가 있는 환경에서는 모두 PASS. Docker가 없는 로컬에서는 실제 정상 case만 명시적 skip이고 두 security-negative 묶음은 fake/spy adapter로 PASS한다.

- [ ] **Step 4: Ubuntu CI에서 실제 Docker test의 skip을 금지한다**

`.github/workflows/application-foundation.yml`의 Ubuntu job에 Docker availability 확인과 `tests/e2e/test_dynamic_reproduction.py::test_supported_fixture_produces_validated_poc` 실행을 추가한다. Windows job은 pure contract/security-negative test를 실행하며 Docker Desktop 환경 문제를 이유로 장시간 수정하지 않는다.

- [ ] **Step 5: E2E/CI 변경만 commit한다**

```text
git add tests/e2e/test_dynamic_reproduction.py .github/workflows/application-foundation.yml
git commit -m "test: verify isolated dynamic reproduction flow"
```

### Task 7: Blocker/High 검토, PR CI, 병합

**Files:** 기능 수정은 발견된 Blocker/High의 소유 lane 파일만 사용한다. 완료 증거는 이 계획 문서에 기록한다.

- [ ] **Step 1: focused 정적 검사를 한 번 실행한다**

Run: `uv run ruff check src/sastsimi/agents/dynamic_reproduction.py src/sastsimi/reproduction src/sastsimi/sandbox tests/integration/sandbox tests/security_negative/sandbox tests/e2e/test_dynamic_reproduction.py`

Run: `uv run mypy src/sastsimi/agents/dynamic_reproduction.py src/sastsimi/reproduction src/sastsimi/sandbox`

Expected: PASS.

- [ ] **Step 2: 세 독립 관점으로 Blocker/High만 검토한다**

- 권한/경계 검토: Docker 호출 전 차단, non-root/default-deny/resource 상한, secret/redaction, exact cleanup ownership.
- provenance/판정 검토: request/work/generation/attempt/recipe/environment/log/candidate/digest set-equality, false PoC promotion, 오류→FALSE/HOLD 변환 금지.
- workflow/recovery 검토: T10 handoff, 한 generation 한 dynamic work, append replay, stale attempt, retry/RESUME/new generation 구분, fake production 경로 제거.

세 검토 모두 Blocker/High 0이면 추가 개선을 중단한다. Medium/Low는 아래 후속 목록에만 추가한다.

검토 요청 역할은 R7(동적 재현/Sandbox), R6(request 소비와 verdict 경계), R3(Provider·Prompt/구현 통합), R4(exact reference·권한·상태), R8(예산·attempt·resource limit)이다. 각 역할은 자기 경계의 최종 T11 commit SHA를 확인한다.

- [ ] **Step 3: 계획 문서에 실제 검증 증거를 기록하고 commit한다**

기록 항목은 실행 command, PASS/FAIL/SKIP, OS와 Docker version, tested commit SHA, actual container profile, reviewer별 Blocker/High 개수다. 실행하지 않은 항목을 PASS로 기록하지 않는다.

```text
git add docs/superpowers/plans/implementation/11-dynamic-reproduction.md
git commit -m "docs: record T11 verification evidence"
```

- [ ] **Step 4: PR을 열고 전체 CI를 한 번만 실행한다**

PR은 `Closes #154`와 T10 final base SHA를 포함한다. Task 진행 중 반복하지 않았던 전체 pytest/Ruff/mypy/docs 검사는 PR CI의 최종 run에서 한 번 실행한다. 실패가 Blocker/High 또는 CI blocker이면 수정하고 해당 실패 test만 로컬 재실행한 뒤 새 CI를 기다린다.

- [ ] **Step 5: 병합 조건을 확인한다**

다음이 모두 참일 때만 병합한다.

- 최신 `main`과 충돌 없음.
- Ubuntu actual Docker 정상 E2E가 skip 없이 PASS.
- 금지 경계 variants에서 Docker 호출 0건.
- `SUPPORTED` 정상 case만 validated `poc_ref`가 존재.
- 모든 실패 case에 R6 final verdict와 Gate work가 없음.
- cleanup 결과와 잔존 test-owned resource 검사가 PASS.
- 독립 검토 세 개의 Blocker/High가 모두 0.
- 최종 CI 전체 green.

---

## 3. T11 완료 후에만 넘길 출력

R6가 소비할 수 있는 출력은 exact current `DynamicReproductionResult` 하나다.

- `SUCCEEDED + SUPPORTED + validated poc_ref`: R6가 모든 정적·Pro·Con·동적 근거를 종합해 final TRUE 여부를 판단한다.
- `SUCCEEDED + DISPROVED`: R6가 실제 반증 근거를 읽어 final FALSE 여부를 판단한다.
- `SUCCEEDED | PARTIAL + INCONCLUSIVE`: R6가 정상 관측 범위와 미해결 조건을 읽어 HOLD 여부를 판단할 수 있다.
- `BLOCKED | FAILED | CANCELLED + INCONCLUSIVE`: final verdict가 없으며 Gate로 전달하지 않는다.

T11 service, Controller, Setup Automation, Session Manager가 직접 `TRUE | FALSE | HOLD`, CWE, Gate, Finding, Reporter 또는 Chaining 결과를 만들면 권한 위반이다.

## 4. 후속 목록 — 이번 Task에서 구현하지 않음

- **T08 동기화 지점(H7)**: 이 보안 보정 branch는 `f7ab0b6`의
  `RepositoryProfile` 계약을 기준으로 한다. T11 통합자는 최신 T08을 합친 뒤
  `content_sha256`, 탐지 hint, gap/error 필드와 current profile revision을 recipe
  source manifest 및 Runtime authorization input에 정확히 연결하고, 값이
  불명확하거나 누락되면 legacy host mount로 우회하지 말고 build를 중단한다.
- 다양한 언어·framework별 Sandbox base image 최적화.
- 원격 container runtime, Kubernetes, microVM 지원.
- package cache와 image GC 고도화.
- 여러 PoC candidate 자동 순위화와 장기 탐색.
- UI 기반 실시간 AgentLog 시각화.
- performance benchmark 확대와 추가 취약점 fixture.
- Windows Docker Desktop 전용 실제 실행 지원.

위 항목은 T11의 Blocker/High가 아니며 확정 Architecture v5 범위를 넘어가므로 이번 PR에 추가하지 않는다.
