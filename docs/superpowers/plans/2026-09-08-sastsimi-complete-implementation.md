# SASTSIMI Complete Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

- 상태: `APPROVED_FOR_IMPLEMENTATION`
- 기준 `main`: `5657fc7b51af33271a940af37ca48bbfcdc14553`
- 검토 PR: [#120](https://github.com/SASTsimi/sastsimi/pull/120)
- 승인 근거: substantive review SHA `491f5e3393151f6c02691d1d4235758821fe2838`에서 두 독립 검토 모두 `Critical 0 / Important 0`; 승인 상태 전환 커밋은 PR #120의 최종 HEAD 검토로 확인

**Goal:** 승인된 Architecture v5를 설치·실행·복구·검증할 수 있는 유지보수 가능한 SASTSIMI Python 프로그램으로 완성한다.

**Architecture:** CPython 3.12 단일 프로세스 모듈형 애플리케이션을 사용한다. 공통 계약과 port를 안쪽에 두고 LLM Provider, 정적 도구, SQLite, 파일 artifact와 Docker는 adapter로 분리하며, 가설 내부 업무 흐름은 `verification/`, `reproduction/`, `chaining/`에 둔다.

**Tech Stack:** CPython `>=3.12,<3.13`, uv, Pydantic 2, SQLAlchemy 2, Alembic, SQLite, asyncio, argparse, PyYAML safe loading, Ruff, mypy strict, pytest, Docker Linux containers.

**Spec:** `docs/superpowers/specs/2026-09-08-sastsimi-maintainable-implementation-design.md`

## Global Constraints

- 기준 설계의 field, enum, verdict, Gate, 권한과 exact reference 의미를 코드 편의를 위해 바꾸지 않는다.
- Agent 역할과 Prompt는 특정 Provider나 모델에 고정하지 않는다. 호출은 exact `provider_profile_ref + model`로 결정한다.
- LLM Agent는 DB, Docker host, Provider SDK, ID 발급과 상태 current pointer를 직접 제어하지 않는다.
- 오류·timeout·인증·예산·정책·Sandbox 실패를 `TRUE | FALSE | HOLD`로 변환하지 않는다.
- final `TRUE`에는 current generation의 `SUCCEEDED + SUPPORTED` 동적 결과와 validated PoC가 필요하다.
- Reporter는 report-ready TRUE Finding만 처리하고 `ReportDraft`에서 Agent 자동화를 종료한다.
- 외부 호출 중 SQLite write transaction을 유지하지 않는다.
- 모든 config, prompt, schema, record와 artifact는 exact revision과 SHA-256 provenance를 갖는다.
- 실제 capability 시험 전 Provider·정적 도구·Docker profile은 운영 `ACTIVE`가 아니다.
- main을 직접 수정하지 않는다. 각 구현 단위는 branch, test, 독립 검토, PR, CI와 merge 순서를 따른다.
- 같은 공통 파일을 여러 구현 Agent가 동시에 수정하지 않는다.
- 상위 `SAST시미` 폴더의 Git 저장소 밖 자료는 삭제·이동하지 않는다.

---

## 1. 기준과 진행 방식

- 최종 승인 PR head: `0647514f9d3d288fbedfa983c5b828d88c909df8`
- 최종 승인 merge: `2de1f6767d8bc25ee7383adacb3082b4ff761f8a`
- post-merge 설계 감사: `8afd37794ac581039d626f1df52f1be06533b13a`
- 구현 전환 시작 main: `691585cd4bd26d6f7bc4d173868e5a710d829126`
- 유지보수 구현 설계 merge: `5657fc7b51af33271a940af37ca48bbfcdc14553`

이 파일은 전체 의존 순서와 공통 완료 조건을 고정하는 마스터 계획이다. 각 Task는 시작 전에 `docs/superpowers/plans/implementation/NN-<task>.md`에 그 PR만을 위한 TDD 실행 계획을 작성한다. 자식 계획은 이 파일의 인터페이스를 바꾸지 않으며, 변경이 필요하면 먼저 이 계획과 승인 ADR을 수정하는 별도 PR을 만든다.

각 Task의 구현 Agent와 두 검토 Agent는 분리한다.

- 구현 Agent: 테스트를 먼저 작성하고 최소 코드를 구현한다.
- 계약·설계 검토 Agent: Architecture v5와 exact reference·권한·상태를 검토한다.
- 코드 품질·보안 검토 Agent: 의존 방향, 실패 처리, 비밀정보와 공격 경계를 검토한다.
- Controller: 실제 diff·시험·CI·검토 SHA를 확인하고 PR을 병합한다.

## 2. 최종 파일 구조

```text
pyproject.toml
uv.lock
.gitattributes
.gitignore
.github/workflows/ci.yml
src/sastsimi/
  __init__.py
  __main__.py
  bootstrap.py
  contracts/
  ports/
  config/
  runtime/
  orchestration/
  verification/
  reproduction/
  chaining/
  prompts/templates/
  agents/
  policy/
  reporting/
  evaluation/
  providers/
  static_analysis/
  sandbox/
  storage/
  interfaces/cli/
config/
  profiles/
  prompts/registry.yaml
  playbooks/
  static-rules/
schemas/generated/
evals/
  corpus/
  graders/
  scenarios/
  configs/
migrations/versions/
docker/base/
docker/profiles/
tests/
  unit/
  contract/
  integration/
  e2e/
  security_negative/
  capability/
  fixtures/
scripts/
docs/
.superpowers/sdd/sastsimi-complete-implementation/progress.md
```

## 3. 공통 공개 인터페이스

아래 이름은 뒤 Task의 연결 기준이다. 세부 field는 `08-lightweight-data-contracts.md` 정본에서 생성하며 자식 계획이 별도 의미를 만들지 않는다.

```python
RecordRef = RunStoredDataRef | StoredDataRef | PolicyCacheRef
BudgetScopeRef = RunStoredDataRef | StoredDataRef

class RecordStore(Protocol):
    def get_exact(self, ref: RecordRef) -> Record: ...
    def stage_record(self, record: Record) -> RecordRef: ...
    def commit_transition(self, request: TransitionCommitRequest) -> TransitionCommit: ...

class ArtifactStore(Protocol):
    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact: ...
    def commit(self, staged: StagedArtifact) -> StoredDataRef: ...
    def open_verified(self, ref: StoredDataRef) -> BinaryIO: ...

class UnitOfWork(Protocol):
    records: RecordStore
    artifacts: ArtifactStore
    def commit(self, request: TransitionCommitRequest) -> TransitionCommit: ...
    def rollback(self) -> None: ...

class WorkHandler(Protocol):
    async def execute(self, context: WorkContext) -> WorkHandlerResult: ...

class LLMProviderAdapter(Protocol):
    async def probe(self, profile: ProviderProfile) -> CapabilityProbeResult: ...
    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult: ...
    async def cancel(self, invocation_id: str) -> CancellationResult: ...

class PolicySourcePort(Protocol):
    async def fetch_official(self, request: OfficialPolicyFetchRequest) -> OfficialPolicySource: ...

class StaticToolAdapter(Protocol):
    async def probe(self, profile_ref: StoredDataRef) -> ToolCapabilityResult: ...
    async def run(self, request: StaticToolRequest) -> ToolRunResult: ...
    async def cancel(self, attempt_id: str) -> CancellationResult: ...

class SandboxPort(Protocol):
    async def prepare(self, request: SandboxPrepareRequest) -> SandboxEnvironment: ...
    async def execute(self, request: ApprovedSandboxCommand) -> SandboxCommandRecord: ...
    async def cleanup(self, request: SandboxCleanupRequest) -> CleanupResult: ...

class BudgetLedgerPort(Protocol):
    def reserve(self, request: BudgetReservationRequest) -> BudgetReservation: ...
    def commit_usage(self, request: BudgetCommitRequest) -> BudgetLedgerEntry: ...
    def release(self, request: BudgetReleaseRequest) -> BudgetReservation: ...
    def remaining(self, budget_scope_ref: BudgetScopeRef, analysis_id: str) -> BudgetRemaining: ...
```

`runtime/worker_pool.py`는 `WorkHandler`만 호출한다. handler instance의 `WorkType` 연결은 `bootstrap.py`에서 수행한다. `VerdictRouter`는 reporting·chaining concrete module을 import하지 않고 runtime public service에 typed work 등록 요청만 제출한다.

`PolicyPreparationService`와 `BudgetProfileRegistry`는 외부 adapter가 아니라 application service다. 전자는 Task 12의 `policy/`가, 후자는 Task 6의 `runtime/`이 생산한다. 뒤 Task는 위 port와 service를 새로 정의하지 않고 주입받아 사용한다.

## 4. Task와 PR 의존 순서

```text
T01 repository cleanup
  -> T02 architecture boundary correction
      -> T03 application foundation
          -> T04 core contracts
              -> T05 domain contracts
                  -> T06 storage, state, budget, recovery
                      -> T07 fake 22-step vertical slice
                          +-> T08 real static fact layer ----+
                          +-> T09 provider and prompt runtime +-> T10 LLM verification roles
                                  -> T11 dynamic reproduction
                                      -> T12 CWE, gates, finding, reporter
                                          -> T13 primitive and chaining
                                              -> T14 parallelism and resilience
                                                  -> T15 security hardening
                                                      -> T16 capability and evaluation
                                                          -> T17 release candidate
```

T08의 tool fixture 준비와 T09의 Provider capability 조사처럼 공통 파일을 쓰지 않는 읽기·fixture 작업은 병렬로 수행할 수 있다. 실제 branch 병합은 의존 순서를 지킨다.

### T08–T17 속도 우선 실행 규칙

T08부터 T17까지는 각 Task의 기존 검증 문구보다 아래 규칙을 우선한다. Task 진행 중에는 변경 기능의 정상 흐름 1개와 안전성에 직접 관련된 중요 실패 흐름 1개 수준의 집중 테스트만 실행하고, 전체 테스트는 최종 PR CI에서 한 번 실행한다. 데이터 혼합, 권한 우회, 잘못된 판정, exact reference 불일치, 비밀정보 노출, Sandbox 경계 위반에 해당하는 Blocker/High는 즉시 수정한다. 그 밖의 Medium/Low, 추가 리팩터링, 테스트 확대, 문서 미세 보정은 후속 목록으로 남긴다. 핵심 완료 조건을 충족한 Task는 작은 논리 커밋으로 보존하고 CI가 통과하면 즉시 병합한다. 독립적인 조사·fixture·비공유 파일 작업은 병렬로 수행하되, 실제 병합은 위 의존 순서를 지킨다.

### Task 1: Repository cleanup and navigation

**Files:**
- Create: `docs/superpowers/plans/implementation/01-repository-cleanup.md`
- Create: `scripts/audit-doc-inventory.ps1`
- Create: `.github/workflows/docs.yml`
- Modify: `docs/DOCUMENT_GUIDE.md`
- Modify: `docs/README.md`
- Modify: `docs/superpowers/README.md`
- Delete: 파일별 allowlist 검사에서 정본·ADR·validator·provenance 의존이 없다고 증명된 역사 문서만

**Interfaces:**
- Consumes: tracked Markdown 목록과 현재 Architecture validator
- Produces: 역할별 문서 탐색 경로, 삭제 근거 목록, clean-checkout 문서 검사

- [ ] 파일별 inbound link, validator reference, final approval reference와 ADR reference를 출력하는 실패 우선 inventory 시험을 작성한다.
- [ ] 삭제 후보가 required reference이면 audit가 실패하는지 확인한다.
- [ ] exact 삭제 allowlist와 보존 목록을 작성한다.
- [ ] allowlist 파일만 제거하고 모든 index를 수정한다.
- [ ] `powershell -File scripts/validate-architecture-docs.ps1`와 새 inventory 검사를 실행한다.
- [ ] clean clone 또는 clean linked worktree에서 로컬 Markdown link 0 missing을 확인한다.
- [ ] Windows와 Ubuntu에서 Architecture validator·inventory·link·`git diff --check`만 실행하는 최소 문서 CI를 추가한다.
- [ ] 독립 문서·provenance 검토 뒤 PR을 병합한다.

### Task 2: Canonical boundary correction

**Files:**
- Create: `docs/superpowers/plans/implementation/02-architecture-boundary-correction.md`
- Create: `docs/review/decisions/ADR-016-maintainable-workflow-packages.md`
- Modify: `docs/architecture-v5/03-agent-roles-and-orchestration.md`
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Modify: `docs/architecture-v5/implementation/01-module-map.md`
- Modify: `docs/architecture-v5/implementation/06-implementation-baseline.md`
- Modify: `docs/governance/OPEN_QUESTIONS.md`
- Modify: `scripts/validate-architecture-docs.ps1`

**Interfaces:**
- Consumes: ADR-015과 유지보수 구현 spec
- Produces: workflow service별 exact module과 import rule

- [ ] stale serialization·database·result storage 표현과 run-init Docker 표현을 찾는 실패 검사를 추가한다.
- [ ] `DebateService`, `VerificationService`, `VerdictRouter`, `RevisionWorkflow`, `DynamicReproductionService`, `ChainingService`의 exact module을 validator에 고정한다.
- [ ] ADR-016에 변경하지 않는 권한·schema·Gate 의미를 명시한다.
- [ ] 번호 문서, 구현 문서, governance와 ADR index를 같은 결론으로 수정한다.
- [ ] 전체 Architecture validator와 link 검사를 실행한다.
- [ ] R3·R4 및 영향 역할의 독립 검토 뒤 PR을 병합한다.

### Task 3: Application foundation

**Files:**
- Create: `docs/superpowers/plans/implementation/03-application-foundation.md`
- Create: `pyproject.toml`, `uv.lock`, `.gitattributes`, `.gitignore`
- Create: `src/sastsimi/__init__.py`, `src/sastsimi/__main__.py`, `src/sastsimi/bootstrap.py`
- Create: `src/sastsimi/interfaces/cli/main.py`, `commands.py`, `output.py`, `exit_codes.py`
- Create: `src/sastsimi/config/models.py`, `loader.py`, `precedence.py`, `secrets.py`
- Create: `src/sastsimi/logging.py`
- Create: `tests/unit/test_config.py`, `tests/integration/test_cli.py`, `tests/contract/test_architecture_imports.py`
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: Python 3.12와 ADR-016 package graph
- Produces: `python -m sastsimi`, `sastsimi doctor`, typed config와 import boundary checker

- [ ] CLI와 config precedence 실패 시험을 작성한다.
- [ ] 최소 package와 argparse entrypoint를 구현한다.
- [ ] secret 원문과 host 절대 경로를 로그에서 거절하는 redaction 시험과 구현을 추가한다.
- [ ] AST 기반 import 검사로 금지 edge가 실패하는지 확인한다.
- [ ] uv lock, Ruff, mypy strict, pytest와 문서 검사를 CI job으로 만든다.
- [ ] Windows와 Ubuntu core 명령이 같은 exit code 계약을 따르는지 시험한다.
- [ ] 품질·보안 독립 검토 뒤 PR을 병합한다.

### Task 4: Core contracts and canonical serialization

Implementation record: [T04 core contracts](implementation/04-core-contracts.md).

**Files:**
- Create: `docs/superpowers/plans/implementation/04-core-contracts.md`
- Create: `src/sastsimi/contracts/ids.py`, `refs.py`, `records.py`, `work.py`, `actions.py`, `budget.py`, `canonical_json.py`, `schema_export.py`
- Create: `src/sastsimi/ports/clock.py`, `id_generator.py`, `work_handler.py`, `record_store.py`, `artifact_store.py`, `budget_ledger.py`
- Create: `tests/unit/contracts/`, `tests/contract/test_record_ref_kinds.py`, `tests/contract/test_canonical_json.py`
- Create: `src/sastsimi/ports/unit_of_work.py`, `llm_provider.py`, `static_tool.py`, `policy_source.py`, `sandbox.py`
- Create: `schemas/generated/` outputs

**Interfaces:**
- Consumes: 08 공통 계약과 Canonical JSON v1 fixture
- Produces: strict Pydantic base model, exact IDs/refs, Work/Attempt/Action/Transition/Budget schema

- [ ] canonical bytes fixture와 SHA-256 expected value 시험을 먼저 작성한다.
- [ ] 다른 analysis·workspace·commit·record revision/hash 교차 사용 실패 시험을 작성한다.
- [ ] `extra='forbid'`, timezone-aware datetime, strict enum과 explicit null을 공통 base에 구현한다.
- [ ] canonical serializer와 content hash 자기 포함 거절을 구현한다.
- [ ] run-level ExecutionBudgetProfile과 work-level profile·binding·reservation·ledger 계약을 구현한다.
- [ ] UnitOfWork·LLM Provider·정적 도구·정책 출처·Sandbox·Budget Ledger port와 fake contract 시험을 구현한다.
- [ ] generated JSON Schema가 source model과 동일한지 재생성 diff 시험을 추가한다.
- [ ] R4·R8 계약 검토 뒤 PR을 병합한다.

### Task 5: Domain contracts

**Files:**
- Create: `docs/superpowers/plans/implementation/05-domain-contracts.md`
- Create: `src/sastsimi/contracts/static.py`, `hypothesis.py`, `verification.py`, `dynamic.py`, `policy.py`, `gates.py`, `chaining.py`, `reporting.py`, `evaluation.py`
- Create: `tests/contract/domain/`, `tests/security_negative/test_cross_domain_record_ref.py`
- Update: `schemas/generated/`

**Interfaces:**
- Consumes: Task 4의 `RecordMeta`, `StoredDataRef`, Work·Action·Budget type
- Produces: 08 result-owner registry에 있는 모든 domain record schema

- [ ] result kind별 정상·필수 field 누락 fixture를 작성한다.
- [ ] 다른 generation·attempt·hypothesis·source owner를 섞는 부정 fixture를 작성한다.
- [ ] StaticFactBundle의 0건·미실행·부분 성공과 fact kind partition을 구현한다.
- [ ] Hypothesis·Pro/Con·Verification·dynamic·PoC provenance validator를 구현한다.
- [ ] CWE·두 Gate·Finding·ReportDraft와 Primitive·Chaining exact closure validator를 구현한다.
- [ ] Policy·Evaluation·usage·error record를 구현한다.
- [ ] result-owner registry와 schema inventory를 스크립트로 생성하고 현재 항목의 100%가 source model·export schema·owner와 연결되는지 검사한다.
- [ ] R1·R2·R4·R5·R6·R7·R8 영역 검토 뒤 PR을 병합한다.

### Task 6: Storage, state, budget and recovery

**Files:**
- Create: `docs/superpowers/plans/implementation/06-storage-runtime-recovery.md`
- Create: `src/sastsimi/storage/`, `src/sastsimi/runtime/`, `migrations/`
- Create: `tests/integration/storage/`, `tests/integration/budget/`, `tests/integration/recovery/`
- Create: `tests/security_negative/test_budget_double_debit.py`

**Interfaces:**
- Consumes: Tasks 4~5 contracts와 port
- Produces: SQLite RecordStore, ArtifactStore, UnitOfWork, Runtime Validator, Work/Attempt services, Budget Registry·ledger, startup recovery

- [ ] SQLite PRAGMA, migration pending, empty upgrade와 downgrade/re-upgrade 실패 시험을 작성한다.
- [ ] staging·PREPARED·CAS·rename·COMMITTED 각 checkpoint의 crash fixture를 작성한다.
- [ ] work별 active attempt 최대 1과 duplicate work 반환 시험을 작성한다.
- [ ] ACTIVE ExecutionBudgetProfile 없이 WORKSPACE_PREP이 차단되는 시험을 작성한다.
- [ ] full ACTIVE BudgetProfileBinding과 reservation 없이 후속 work·attempt·외부 호출이 차단되는 시험을 작성한다.
- [ ] 동시 reservation, usage commit 1회, release와 crash 후 불명확 예약 보존을 구현한다.
- [ ] stale·late 결과가 current pointer를 변경하지 못하게 CAS와 TransitionCommit을 구현한다.
- [ ] LLM·정적 도구·정책 HTTP·Docker port가 대기 중일 때 SQLite write transaction이 열려 있지 않아 두 번째 connection이 정상 기록 가능한지 검사한다.
- [ ] 전체 artifact hash 검사와 orphan recovery를 구현한다.
- [ ] R3·R4·R8 검토 뒤 PR을 병합한다.

### Task 7: Fake 22-step vertical slice

**Files:**
- Create: `docs/superpowers/plans/implementation/07-fake-vertical-slice.md`
- Create: `src/sastsimi/orchestration/`, `verification/`, `reproduction/`, `chaining/`, `reporting/`, `policy/`, `evaluation/`
- Create: `src/sastsimi/providers/fake.py`, `static_analysis/fake.py`, `sandbox/fake.py`
- Create: `src/sastsimi/interfaces/cli/analyze.py`, `results.py`, `reports.py`
- Create: `tests/e2e/test_fake_true_pipeline.py`, `test_fake_false_pipeline.py`, `test_fake_hold_pipeline.py`, `test_fake_revise_pipeline.py`, `test_fake_chaining_pipeline.py`

**Interfaces:**
- Consumes: Tasks 4~6의 모든 contract·runtime·storage
- Produces: deterministic fake handler로 실제 저장·Action·예산을 통과하는 정본 22단계와 실행 가능한 analyze/results/report CLI

- [ ] final TRUE에 current validated PoC가 없으면 실패하는 E2E부터 작성한다.
- [ ] FALSE falsification evidence와 HOLD unresolved condition 부정 시험을 작성한다.
- [ ] ACTIVE 예산 binding과 reservation을 사용하는 deterministic fake adapter를 구현한다.
- [ ] run-init 정책 준비와 정적 분석 병렬 fan-out부터 Hypothesis → Pro/Con → Verification → dynamic → CWE → 두 Gate → Primitive admission → Primitive/index → Chaining/no-match → Finding → ReportDraft까지 22단계를 연결한다.
- [ ] no-match 종료와 material child proposal 재등록 중 적어도 한 경로가 동일 runtime/port를 통과하는지 검사한다.
- [ ] CLI에서 분석 시작, 진행·결과 조회와 ReportDraft 조회를 fake pipeline에 연결한다.
- [ ] Technical REVISE가 같은 owner의 새 generation과 새 dynamic·PoC·CWE를 요구하는지 시험한다.
- [ ] ReportDraft 뒤 외부 제출 action이 존재하지 않는지 검사한다.
- [ ] 저장된 AnalysisRunResult의 결과·오류·시간·usage·가설 수 closure를 검사한다.
- [ ] 전체 역할 계약·코드 보안 검토 뒤 PR을 병합한다.

### Task 8: Real static fact layer

**Files:**
- Create: `docs/superpowers/plans/implementation/08-static-fact-layer.md`
- Create: `src/sastsimi/static_analysis/repository_loader.py`, `coordinator.py`, `ast_adapter.py`, `codeql_adapter.py`, `open_grep_adapter.py`, `normalizer.py`, `context_retrieval.py`
- Create: `tests/unit/static_analysis/`, `tests/integration/static_analysis/`, `tests/security_negative/test_code_path_escape.py`

**Interfaces:**
- Consumes: `StaticToolAdapter`, CodeWorkspace·ToolRunResult·RuleExecutionRecord contracts
- Produces: 실제 repository URL 또는 local path와 exact commit에 묶인 `RepositoryProfile`·`CodeWorkspace`, 검증된 tool 선택, StaticFactBundle과 bounded Context response

- [ ] 사용자가 준 실제 repository URL 또는 local path와 commit을 입력 정본으로 저장하고, 허용된 scheme·root와 exact revision을 검증한 뒤 별도 workspace에 safe clone/checkout한다. branch 이름이 아닌 실제 HEAD commit을 영속 코드 정체성으로 남긴다.
- [ ] safe checkout의 언어, manifest/lockfile, build 명령, Dockerfile 유무와 정적 도구 적용 가능성을 `RepositoryProfile`에 exact provenance로 정규화한다. 원본 repository나 사용자 local tree는 변경하지 않는다.
- [ ] `RepositoryProfile`과 T16이 검증해 `ACTIVE`로 게시한 capability profile의 교집으로 AST·CodeQL·OpenGrep 등 실행 tool을 선택한다. 탐지만 되었거나 미설치·미검증 tool은 자동 활성화하지 않고 DataGap/실행 오류로 보존한다.
- [ ] clone·checkout HEAD 불일치와 symlink/path escape 실패 시험을 작성한다.
- [ ] 외부 process를 argument list와 `shell=False`로 실행하는 adapter base를 구현한다.
- [ ] AST·CodeQL·OpenGrep probe와 tool별 timeout·cancel을 구현한다.
- [ ] 규칙별 selected/executed/raw hit count로 0건과 미실행을 분리한다.
- [ ] partial 결과와 DataGap을 보존하는 fan-in normalizer를 구현한다.
- [ ] 같은 workspace·commit에서만 context를 조회한다.
- [ ] R2·R3·R4·R8 검토 뒤 PR을 병합한다.

### Task 9: Provider and Prompt Runtime

**Files:**
- Create: `docs/superpowers/plans/implementation/09-provider-prompt-runtime.md`
- Create: `src/sastsimi/providers/base.py`, `normalization.py`, `openai_api.py`
- Create: `src/sastsimi/prompts/registry.py`, `loader.py`, `builder.py`, `redaction.py`, `validation.py`
- Create: `src/sastsimi/runtime/llm_call_service.py`, `provider_profile_registry.py`, `prompt_registry.py`
- Create: `config/prompts/registry.yaml`, `src/sastsimi/prompts/templates/`
- Create: `tests/contract/prompts/`, `tests/integration/providers/`, `tests/security_negative/test_prompt_injection.py`

**Interfaces:**
- Consumes: `LLMProviderAdapter`, ProviderProfile·PromptRegistryEntry·PromptPayload·LLMCallSpec contracts
- Produces: 비활성 후보 adapter 목록, fake와 한 API adapter의 probe/invoke/cancel, trusted Provider Profile Registry·Prompt Registry 전이, immutable prompt payload와 structured output 검사

- [ ] PVD와 사람 승인 전 후보 adapter에는 `ProviderProfile`을 발급하지 않고 domain 호출에 사용하지 못하는 시험을 작성한다.
- [ ] registry/template/schema/validator hash와 purpose mismatch 실패 시험을 작성한다.
- [ ] untrusted data가 instruction으로 승격되지 않는 projection 시험을 작성한다.
- [ ] schema·semantic repair가 새 call/action/session을 만드는지 시험한다.
- [ ] API credential 원문이 record·artifact·log에 남지 않는지 검사한다.
- [ ] retry·fallback은 고정된 정책에 있을 때만 새 action/attempt로 실행하고, 조용한 Provider·model 변경을 금지한다.
- [ ] 기술 검증된 exact ProviderProfile로만 `EVALUATION` Prompt entry를 활성화하고, 평가 추천과 사람 승인 없이는 `PRODUCTION` Prompt entry를 `ACTIVE`로 만들지 않는 전이 시험을 작성한다.
- [ ] Issue #118 prompt 결과를 canonical template 한곳에 연결하고 중복 문서를 만들지 않는다.
- [ ] R1·R3·R4·R8 검토 뒤 PR을 병합한다.

### Task 10: LLM verification roles

**Files:**
- Create: `docs/superpowers/plans/implementation/10-llm-verification.md`
- Create: `src/sastsimi/agents/hypothesis.py`, `pro.py`, `con_agent.py`, `verification.py`
- Create: `src/sastsimi/verification/debate_service.py`, `service.py`, `verdict_router.py`, `revision_workflow.py`
- Create: `tests/integration/verification/`, `tests/security_negative/test_cross_role_isolation.py`

**Interfaces:**
- Consumes: Prompt Runtime, Context service, runtime work/action services
- Produces: 등록 가능한 Hypothesis proposal, 독립 Pro/Con, Verification initial/final result와 REVISE request

- [ ] T08 Context service와 T09 Prompt Runtime이 모두 병합되지 않으면 이 Task를 시작하지 않는다.
- [ ] Pro/Con이 같은 input hash와 서로 다른 NEW session을 사용하는 시험을 작성한다.
- [ ] 한 역할이 상대 결과를 읽으면 `CROSS_ROLE_INPUT_DENIED`가 되는 시험을 작성한다.
- [ ] 질문 누락·중복, falsification 없는 FALSE, unresolved condition 없는 HOLD를 거절한다.
- [ ] timeout·auth·invalid output이면 final verdict가 없도록 구현한다.
- [ ] VerdictRouter가 runtime work 등록만 요청하고 reporting/chaining concrete import가 없음을 검사한다.
- [ ] R6·R3·R4·R8 검토 뒤 PR을 병합한다.

### Task 11: Dynamic reproduction and validated PoC

**Files:**
- Create: `docs/superpowers/plans/implementation/11-dynamic-reproduction.md`
- Create: `src/sastsimi/agents/dynamic_reproduction.py`
- Create: `src/sastsimi/reproduction/service.py`
- Create: `src/sastsimi/sandbox/setup_automation.py`, `controller.py`, `session_manager.py`, `docker_adapter.py`, `recipe_store.py`, `health_check.py`, `cleanup.py`
- Create: `docker/base/`, `docker/profiles/`, `tests/integration/sandbox/`, `tests/security_negative/sandbox/`

**Interfaces:**
- Consumes: exact DynamicReproductionRequest, current `RepositoryProfile`·`CodeWorkspace`, SandboxPort, Budget Runtime
- Produces: repository build 근거에 묶인 EnvironmentRequirements·plan·`EnvironmentRecipe`, 격리 Docker environment, AgentLog, candidate, validated PoC와 DynamicReproductionResult

- [ ] current `RepositoryProfile`의 exact commit·manifest·lockfile·Dockerfile 유무를 읽어 재현 가능한 `EnvironmentRecipe`를 만든다. Dockerfile이 있으면 검증된 내용과 digest를 고정하고, 없으면 언어·package/build 근거와 `ACTIVE` capability profile로 최소 recipe를 만들며 추측한 명령을 실행하지 않는다.
- [ ] `EnvironmentRecipe` → image build → 격리 container run → health check → 구조화된 command/event → cleanup을 같은 work/attempt와 exact digest로 연결한다. Dockerfile 유·무 두 경로를 모두 시험한다.
- [ ] package 설치, build, application start, auth/credential, health check 실패는 `BLOCKED | FAILED`와 DataGap/AnalysisError로 보존하고 취약점 `FALSE | HOLD`로 바꾸지 않는다. 정상 완주와 same-attempt 근거가 있을 때만 validated PoC와 dynamic result를 Gate에 넘긴다.
- [ ] live asset, host mount, Docker socket, secret와 비허용 egress 차단 시험을 작성한다.
- [ ] non-root user, 최소 Linux capability, default-deny network와 CPU·RAM·disk·PID·wall-time 한도를 profile 밖에서 완화할 수 없는지 검사한다.
- [ ] candidate 존재만으로 validated PoC가 되지 않는 시험을 작성한다.
- [ ] same attempt의 command start/finish, environment, recipe와 digest가 모두 맞을 때만 PoC를 검증한다.
- [ ] crash·health check 실패 시 STATE_UNCERTAIN 재생성과 AgentLog 연결을 구현한다.
- [ ] policy 차단·환경 실패·timeout을 FALSE/HOLD로 바꾸지 않는다.
- [ ] cleanup 실패를 성공으로 숨기지 않고 잔존 container·network·volume을 탐지·기록·재정리하는 시험을 작성한다.
- [ ] 의도적으로 취약한 프로젝트 관리 fixture에서만 실제 Docker E2E를 수행한다.
- [ ] R7·R6·R3·R4·R8 보안 검토 뒤 PR을 병합한다.

### Task 12: CWE, two Gates, Finding and Reporter

**Files:**
- Create: `docs/superpowers/plans/implementation/12-gates-reporting.md`
- Create: `src/sastsimi/agents/cwe_labeling.py`, `technical_gate.py`, `rule_scope_gate.py`, `policy_parser.py`, `reporter.py`
- Create: `src/sastsimi/reporting/`
- Create: `src/sastsimi/policy/program_catalog.py`, `preparation_service.py`, `collector.py`, `cache_service.py`, `adapters/official_http.py`
- Create: `tests/integration/reporting/`, `tests/security_negative/test_stale_report.py`

**Interfaces:**
- Consumes: Program Catalog entry, PolicySourcePort, current final TRUE와 validated PoC
- Produces: run-init에 고정된 RunPolicyState, 해당 Verification을 직접 가리키는 current CWELabel, Technical review, Rule Scope review, current Finding와 ReportDraft

- [ ] 새 Verification에 stale CWE·Gate·Finding·ReportDraft를 재사용하는 실패 시험을 작성한다.
- [ ] run 시작 때 정책 준비를 정적 분석과 병렬 실행하고, 공식 출처·cache provenance로 확정한 RunPolicyState를 같은 run 동안 고정한다.
- [ ] Program Catalog 조회·Policy Collector·공식 HTTP adapter·cache fallback과 최신성 만료를 각각 시험한다.
- [ ] final TRUE마다 `CWE_LABELING` work가 current Verification exact revision을 직접 가리키는 새 CWELabel을 만들고, generation이 바뀌면 같은 CWE라도 새 provenance revision으로 재평가하는지 검사한다.
- [ ] Technical REVISE가 verdict를 변경하지 않고 같은 owner 새 generation으로 돌아가게 한다.
- [ ] policy 수집 실패와 공식 정책 부재를 다른 상태로 보존한다.
- [ ] testing restriction과 다른 scope·impact 값을 Primitive 결정으로 선저장하지 않고 exact Rule Scope 결과로 Task 13에 넘긴다.
- [ ] 다른 scope·impact 실패는 Finding을 보존하고 Reporter만 차단한다.
- [ ] ReportDraft의 모든 `path:line`을 EvidenceClaim 위치와 대조한다.
- [ ] R5·R3·R4·R6·R8 검토 뒤 PR을 병합한다.

### Task 13: Primitive and Chaining

**Files:**
- Create: `docs/superpowers/plans/implementation/13-primitive-chaining.md`
- Create: `src/sastsimi/agents/chaining.py`, `src/sastsimi/chaining/service.py`
- Create: `src/sastsimi/reporting/primitive_admission.py`
- Create: `tests/integration/chaining/`, `tests/security_negative/test_chaining_provenance.py`

**Interfaces:**
- Consumes: TRUE는 final result + Technical ACCEPT + RunPolicyState + exact PolicyCollectionResult + 조건부 RuleScopeImpactReview, HOLD는 `required_primitive_candidates`
- Produces: TRUE의 PrimitiveAdmissionDecision, 허용 TRUE/HOLD Primitive, atomic current PrimitiveIndexState revision, directional matches, no-match reasons, duplicate key와 `origin=CHAINING` 새 proposal

- [ ] FALSE, candidate 없는 HOLD와 restriction DENY TRUE가 index에 들어가지 않는 시험을 작성한다.
- [ ] reporting package의 trusted PrimitiveAdmissionRuntime은 TRUE의 exact result chain·Technical ACCEPT·frozen RunPolicyState·PolicyCollectionResult를 검사한다.
- [ ] `FOUND | ABSENT_CONFIRMED` collection에는 current RuleScopeImpactReview가 필수이고 testing restriction FAIL만 DENY로 매핑한다.
- [ ] `COLLECTION_FAILED`에는 Rule Scope 없이 `NOT_EVALUATED + ALLOW`를 기록하며, PolicyCollectionResult 자체가 없으면 decision·Primitive·index를 만들지 않는다.
- [ ] TRUE는 PrimitiveAdmissionDecision과, ALLOW일 때의 Primitive·새 PrimitiveIndexState를 하나의 `PRIMITIVE_UPDATE` COMMITTED transition으로 확정한다.
- [ ] HOLD는 admission decision 없이 required candidate를 검사한 Primitive와 새 PrimitiveIndexState를 하나의 transition으로 확정한다.
- [ ] Chaining Agent와 ChainingService는 확정된 Primitive와 work 시작 때 고정한 PrimitiveIndexState만 소비하며 admission·Primitive를 생산하지 않는다.
- [ ] upstream result가 downstream input을 충족하는 방향만 match하게 구현한다.
- [ ] 고정한 considered refs, exclusion pair, lineage와 source result closure를 검사한다.
- [ ] TRUE+TRUE와 TRUE+HOLD child를 자동 TRUE가 아닌 새 가설로 등록한다.
- [ ] parent 변경 뒤 stale chain 결과와 중복 child를 차단한다.
- [ ] R1·R4·R5·R6·R8 검토 뒤 PR을 병합한다.

### Task 14: Production composition, parallelism, cancellation and resilience

**Files:**
- Create: `docs/superpowers/plans/implementation/14-parallelism-resilience.md`
- Create or modify: production `WorkHandler` registry, bounded worker pool, lease heartbeat, atomic claim/run-control storage, exact cancellation-target adapter and recovery service
- Create or modify: production orchestration composition, result aggregation, bootstrap과 CLI `run/status/cancel/resume/result`
- Create: `tests/integration/concurrency/`, `tests/integration/recovery/test_full_restart.py`
- Create: production composition/CLI focused integration and E2E tests

**Interfaces:**
- Consumes: T08~T13에서 병합된 모든 claimed-context `WorkHandler`, 실제 repository URL/local path + exact commit, exact budget/resource/capability profile
- Produces: `RepositoryProfile` → 검증된 tool 선택 → static/LLM → dynamic Docker → Gates → Markdown ReportDraft를 완주하는 production CLI flow, 분석 전체 한도 내 병렬 실행, durable cancel/resume와 중복 외부 호출이 없는 deterministic restart

- [ ] T07 `FakePipeline`과 fake adapter는 계약·fixture 회귀 시험용으로 격리하고 production bootstrap/CLI registry에서 선택되지 않게 한다.
- [ ] production `analyze <repository-url-or-local-path> --commit <exact-commit> --program <program-id>`가 안전한 clone/checkout과 `RepositoryProfile`부터 시작한다. `status <analysis-id>`는 work별 진행·BLOCKED/실패 이유를, `results <analysis-id>`는 final verdict·gap·error를, `reports <analysis-id>`는 current ReportDraft 목록·Markdown 조회를 영속 상태에서 읽는다. `cancel/resume`은 기존 durable 경계를 유지한다.
- [ ] T13 병합 후 실제 public API를 기준으로 모든 `WorkType`의 production handler가 하나씩 있고, 이미 claim된 `WorkContext`만 소비하며 자식 work를 READY로만 등록하는지 연속으로 확정한다.
- [ ] barrier를 사용해 duplicate claim과 늦은 결과 race를 재현한다.
- [ ] `ExecutionBudgetProfile.max_parallel_work`를 `DYNAMIC_REPRO`를 포함한 모든 work type의 **분석 전체 단일 동시 실행 한도**로 원자적 claim transaction에서 검사한다. Provider의 `max_parallel_calls`와 Pro·Con의 `max_parallel_evidence_calls`는 그 안의 추가 한도로 계속 적용하며, 별도 Sandbox 동시성 한도는 만들지 않는다.
- [ ] 취소 latch를 work 등록·READY enqueue·claim·결과 commit·run finalization의 같은 신뢰 transaction 경계에서 다시 읽는다. 확인된 실제 사용만 ledger에 commit하고, claimed 상태이거나 사용 여부가 불확실한 reservation은 release·commit하지 않고 `RESERVED`로 보존해 recovery가 해소하도록 하며 unavailable usage 사유를 기록한다.
- [ ] 프로세스 중단 뒤 PREPARED·lease·current pointer와 exact 외부 실행 target을 복구하고, 결과가 불확실한 Provider·Sandbox 작업을 자동으로 다시 보내지 않는다.
- [ ] 한 가설 실패가 다른 가설을 verdict 없이 취소하지 않는지 검사한다.
- [ ] production CLI가 fake pipeline이 아닌 완전한 handler registry·worker pool·result aggregator·finalizer를 통해 실제 URL과 local path fixture의 safe checkout, static/LLM, Dockerfile 유·무 dynamic recipe, Gates와 Markdown ReportDraft까지 최소 하나의 정상 분석을 완주하는지 검사한다.
- [ ] R3·R4·R8 검토 뒤 PR을 병합한다.

### Task 15: Security hardening

**Files:**
- Create: `docs/superpowers/plans/implementation/15-security-hardening.md`
- Create or modify: `tests/security_negative/` 전체, redaction·path·reference·Sandbox enforcement
- Create: `docs/security.md`

**Interfaces:**
- Consumes: 완성된 fake pipeline과 모든 adapter boundary
- Produces: 위협별 차단 증거와 안전한 기본값

- [ ] prompt injection이 설정·권한·Provider·Gate 순서를 바꾸지 못하게 시험한다.
- [ ] 변조 hash, forged ref, cross-run cache와 stale action decision을 차단한다.
- [ ] API key·cookie·token·session·host path가 stdout/stderr/log/artifact에 없는지 scan한다.
- [ ] Docker daemon/socket·mount·namespace·network·resource 경계를 부정 시험한다.
- [ ] 실패 시험별 AnalysisError와 no-domain-output side effect를 확인한다.
- [ ] 보안 독립 검토 뒤 PR을 병합한다.

### Task 16: Provider, tool and evaluation capability

**Files:**
- Create: `docs/superpowers/plans/implementation/16-capability-evaluation.md`
- Create: `src/sastsimi/providers/codex_subscription.py`, `anthropic_api.py`, `claude_subscription.py`
- Add: 후보 Provider·tool adapter와 `tests/capability/`
- Create: `src/sastsimi/evaluation/`, `evals/`
- Create: `src/sastsimi/interfaces/cli/eval.py`, `provider.py`, `tools.py`
- Update: provider/profile registry와 사용자 설정 문서

**Interfaces:**
- Consumes: capability probe 계약, `RepositoryProfile` 후보, 격리된 evaluation path
- Produces: 비활성 후보 adapter의 conformance 결과, PVD evidence, trusted runtime이 게시한 ProviderProfile·tool/build profile, RepositoryProfile에 적용할 tool 선택 결과, EvaluationRunResult와 사람이 승인할 수 있는 Prompt activation recommendation

- [ ] 최소 production capability matrix는 Python과 JavaScript repository를 각각 포함하고, 언어별 AST/정적 도구, package 설치·build·start, Dockerfile 있음/없음 경로를 나누어 probe한다.
- [ ] capability evidence가 exact 도구 version/digest·OS·언어·repository 특성·실행 경계에서 재현되고 trusted review를 통과한 profile만 `ACTIVE`로 게시한다. 존재 탐지, 단일 성공, 수동 설치만으로 production tool/build profile을 활성화하지 않는다.
- [ ] package 설치·build·start·auth/credential 실패, Dockerfile 부재, 지원하지 않는 언어/tool 조합은 capability `BLOCKED | REJECTED` 또는 DataGap이며 취약점 `FALSE | HOLD`가 아니다. Dockerfile이 없을 때는 검증된 generated recipe profile이 있을 때만 dynamic 경로를 활성화한다.
- [ ] 실제 credential 없이 default test가 외부 호출을 하지 않는지 검사한다.
- [ ] 후보 adapter는 먼저 비활성 상태로 구현하고 공통 probe/invoke/cancel·오류 정규화 conformance 시험을 통과시킨다.
- [ ] OpenAI API·Codex 회원제·Anthropic API·Claude 회원제 각각을 공식 지원 경로로 구현 가능한지 검증하며, 미지원 또는 credential 부재는 `BLOCKED` 증거로 남기고 지원을 주장하지 않는다.
- [ ] PVD exact evidence와 사람 승인이 있는 후보만 trusted Provider Profile Registry가 `SUPPORTED | EXPERIMENTAL | REJECTED` ProviderProfile로 게시하며, ProviderProfile에 Prompt의 `ACTIVE` 상태를 넣지 않는다.
- [ ] exact environment·client·model 조합의 PVD-01~15를 기록한다.
- [ ] dynamic tool loop 대상에는 PVD-16을 추가로 실행한다.
- [ ] Git·AST·CodeQL·OpenGrep·Docker exact version probe를 기록한다.
- [ ] 실제 OS/container `StaticOutputQuotaPort` backend에서 exact action·attempt·profile revision·cap binding을 검증하고, 빠른 cap+1 쓰기가 물리적으로 거절되며 그 사실이 sticky `limit_breached + breach_evidence`로 재조회되는지 시험한다. 실행 후 breach가 확인되면 CodeQL 결과는 `STATIC_OUTPUT_LIMIT`으로 폐기해야 한다. 이 증거가 없거나 plain-directory/polling-only 방식이면 CodeQL production profile을 활성화하지 않는다.
- [ ] 같은 `comparison_group_id` 안에서 `corpus_refs`, `ground_truth_refs`, `grader_refs`, output schema와 budget profile을 exact set-equal로 고정하고, 비교 축 외 Provider·model·session·prompt 입력도 같은 경우만 비교한다.
- [ ] CLI에서 Provider/tool capability 실행, evaluation 실행·결과 조회·비교를 명시적으로 시작할 수 있게 한다.
- [ ] PVD를 통과한 ProviderProfile로 `EVALUATION` Prompt entry를 사용하고, exact `ACCEPT_FOR_PRODUCTION` R8 recommendation과 사람 승인이 모두 있어야 trusted Prompt Registry Runtime이 실행 의미가 같은 새 `PRODUCTION ACTIVE` entry revision을 만들도록 검사한다.
- [ ] R3·R7·R8 및 역할 소유자 검토 뒤 PR을 병합한다.

### Task 17: Release candidate and final integration

**Files:**
- Create: `docs/superpowers/plans/implementation/17-release-candidate.md`
- Modify: `README.md`, `CONTRIBUTING.md`
- Create: `docs/installation.md`, `docs/usage.md`, `docs/provider-setup.md`, `docs/troubleshooting.md`, `docs/architecture-to-code.md`
- Finalize: configuration example, fixture repository, migration과 release CI

**Interfaces:**
- Consumes: Tasks 1~16의 merged main
- Produces: 설치·인증할 수 있고 실제 repository를 Markdown 보고서까지 분석하는 release candidate와 최종 검증 보고서

- [ ] 사용자 문서를 설치 → data/config 경로 준비 → Provider/tool 인증·capability 확인 → URL 또는 local path와 exact commit 분석 → 진행/실패 이유 조회 → 결과 → Markdown ReportDraft 조회·export → 취소·동일 입력 재개 → 복구 순서로, 복사해 실행할 수 있는 명령과 예상 상태를 포함해 작성한다.
- [ ] Python·JavaScript, Dockerfile 유·무를 포함한 release scenario에서 실제 입력 → safe checkout → `RepositoryProfile` → `ACTIVE` tool 선택 → static/LLM → `EnvironmentRecipe`/Docker → Gates → Markdown ReportDraft의 exact reference closure를 검증한다. Fake adapter/pipeline은 이 production 출시 증거에 포함하지 않는다.
- [ ] clean Windows·Ubuntu 환경에서 `uv sync --frozen --all-groups`를 실행한다.
- [ ] 빈 DB와 이전 revision migration을 검증한다.
- [ ] TRUE·FALSE·HOLD·BLOCKED·FAILED·REVISE·정책 DENY·Chaining·Provider·Sandbox·crash recovery E2E를 실행한다.
- [ ] 실제 Provider, 실제 정적 분석과 안전한 Docker fixture 경로를 최소 하나씩 검증한다.
- [ ] secret scan, architecture validator, Ruff, mypy와 전체 pytest를 실행한다.
- [ ] README와 installation/usage/provider-setup/troubleshooting 문서에 설치 → 설정 → 인증 → 실제 URL/local path + commit 분석 → 상태·실패 조회 → 결과 → Markdown ReportDraft → 복구 흐름을 기록한다.
- [ ] 모든 open Critical·Important가 0인지 최종 독립 검토한다.
- [ ] 최종 PR head SHA와 검토 SHA가 같을 때만 병합한다.

## 5. 공통 PR 검증 명령

```text
uv sync --frozen --all-groups
uv run ruff format --check .
uv run ruff check .
uv run mypy --strict src tests
uv run pytest tests/unit -q
uv run pytest tests/contract -q
uv run pytest tests/integration -q
uv run pytest tests/e2e -q
uv run pytest tests/security_negative -q
pwsh -File scripts/validate-architecture-docs.ps1
git diff --check origin/main...HEAD
```

T01과 T02는 T01에서 추가한 최소 문서 CI와 로컬 Architecture validator·inventory·link·diff 검사를 병합 조건으로 사용한다. T03부터는 전체 CI를 사용하되 아직 생성되지 않은 시험 디렉터리는 존재하는 범위만 실행하고 PR 본문에 미실행 이유를 적는다. Windows 로컬 명령은 `powershell -ExecutionPolicy Bypass -File ...`, Ubuntu CI 명령은 `pwsh -File ...`로 실행한다. capability job은 명시 실행이며 skip을 성공으로 기록하지 않는다.

## 6. PR 완료 판정

- branch가 최신 `origin/main`을 포함한다.
- 현재 Task가 생산한 required CI(T01~T02 문서 CI, T03 이후 전체 CI)가 성공한다.
- merge conflict가 없다.
- Critical 0, Important 0이다.
- Architecture 계약 위반과 security blocker가 없다.
- 자식 계획의 test 명령과 실제 output이 PR에 기록된다.
- 구현 Agent와 독립 검토 Agent가 다르다.
- 최종 검토 SHA와 PR HEAD가 같다.
- 병합 뒤 새 main에서 smoke test가 성공한다.
- 진행 기록에 Issue, PR, commit, CI와 다음 Task를 갱신한다.
