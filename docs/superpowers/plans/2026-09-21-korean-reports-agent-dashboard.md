# Korean Reports and Live Agent Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** WSL에서 실행 중인 SASTSIMI 분석을 읽기 전용 웹 화면으로 확인하고, 검증 가능한 Agent 활동과 실제 validated PoC가 포함된 한국어 `F-###.md` 보고서를 제공한다.

**Architecture:** 기존 SQLite와 content-addressed artifact를 정본으로 유지한다. SimpleRuntime은 단계 상태와 감사 이벤트를 같은 transaction으로 확정하고, 대시보드는 허용된 필드만 투영해 2초 polling으로 읽는다. 보고서와 대시보드는 판정을 만들지 않고 exact Finding·Verification·PoC·Gate 결과만 표현한다.

**Tech Stack:** Python 3.12, Pydantic 2, SQLite, 표준 라이브러리 `http.server`, HTML/CSS/JavaScript, pytest, Ruff, mypy

**Spec:** `docs/superpowers/specs/2026-09-21-korean-reports-agent-dashboard-design.md`

## Global Constraints

- 실제 E2E 지원 환경은 WSL2 Linux 사용자 공간과 Linux Docker 컨테이너다.
- Dashboard 기본 주소는 `127.0.0.1:8765`이며 외부 bind를 허용하지 않는다.
- Dashboard는 `GET | HEAD`만 허용하고 분석 상태나 artifact를 변경하지 않는다.
- 숨겨진 chain-of-thought, 전체 프롬프트, 전체 모델 응답, token, cookie와 secret을 저장하거나 표시하지 않는다.
- 오류·인증 실패·도구 실패를 취약점 `FALSE`로 바꾸지 않는다.
- final `TRUE` 보고서는 same-attempt validated PoC와 exact execution 연결을 요구한다.
- Rule Scope `DENY | UNCERTAIN`은 `CONFIRMED_RESTRICTED` 내부 보고서로만 표시하고 외부 공개를 허용하지 않는다.
- 현재 성공 checkpoint와 Docker image를 재사용하고 실패한 단계부터 재개한다.
- 새 프론트엔드 빌드 체계와 Node.js 의존성을 추가하지 않는다.

## Review Focus

- 같은 분석에서 동시에 Finding 두 개가 확정돼도 서로 다른 `F-###`가 원자적으로 할당되어야 한다. Task 1의 concurrency test로 고정한다.
- 실패 후 재시도하는 Agent 이벤트가 이전 attempt를 덮어쓰거나 섞으면 안 된다. Task 3의 append-only retry test로 고정한다.
- stdout·LLM 결과에 secret 모양 문자열이나 호스트 절대 경로가 있어도 감사 API와 보고서에 노출되면 안 된다. Task 2와 Task 3의 redaction failure test로 고정한다.
- URL의 analysis/report 식별자에 traversal 문자가 있어도 임의 파일이나 다른 분석 데이터를 읽으면 안 된다. Task 5의 route test로 고정한다.
- 대시보드를 실행하지 않았거나 대시보드가 실패해도 분석 Runtime은 정상 진행해야 한다. Task 6의 process-separation test로 고정한다.

---

### Task 1: 안정적인 Finding 표시 번호

**Files:**
- Create: `src/sastsimi/reporting/finding_display_id.py`
- Test: `tests/unit/reporting/test_finding_display_id.py`

**Interfaces:**
- Consumes: `Path`로 받은 기존 `sastsimi.sqlite3`, `analysis_id: str`, exact `finding_ref: StoredDataRef`
- Produces: `FindingDisplayIdStore.get_or_allocate(analysis_id: str, finding_ref: StoredDataRef) -> str`, `FindingDisplayIdStore.resolve(analysis_id: str, display_id: str) -> StoredDataRef`

- [ ] **Step 1: Write the failing stable allocation and concurrency tests**

```python
def test_same_finding_keeps_display_id_and_next_finding_increments(tmp_path):
    store = FindingDisplayIdStore(tmp_path / "sastsimi.sqlite3")
    assert store.get_or_allocate("analysis-1", ref("finding-a")) == "F-001"
    assert store.get_or_allocate("analysis-1", ref("finding-a")) == "F-001"
    assert store.get_or_allocate("analysis-1", ref("finding-b")) == "F-002"
    assert store.get_or_allocate("analysis-2", ref("finding-a")) == "F-001"

def test_concurrent_allocation_never_reuses_a_number(tmp_path):
    store = FindingDisplayIdStore(tmp_path / "sastsimi.sqlite3")
    with ThreadPoolExecutor(max_workers=2) as pool:
        values = tuple(pool.map(
            lambda item: store.get_or_allocate("analysis-1", ref(item)),
            ("finding-a", "finding-b"),
        ))
    assert set(values) == {"F-001", "F-002"}
```

- [ ] **Step 2: Run tests and verify RED**

Run: `uv run pytest -q tests/unit/reporting/test_finding_display_id.py -p no:cacheprovider`

Expected: FAIL because `FindingDisplayIdStore` does not exist.

- [ ] **Step 3: Implement the transactional registry**

```python
class FindingDisplayIdStore:
    def get_or_allocate(self, analysis_id: str, finding_ref: StoredDataRef) -> str:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._find(connection, analysis_id, finding_ref.content_hash)
            if current is not None:
                return current
            number = connection.execute(
                "SELECT COALESCE(MAX(display_number), 0) + 1 "
                "FROM finding_display_ids WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO finding_display_ids "
                "(analysis_id, finding_hash, finding_ref_json, display_number) "
                "VALUES (?, ?, ?, ?)",
                (analysis_id, finding_ref.content_hash,
                 finding_ref.model_dump_json(), number),
            )
            return f"F-{number:03d}"
```

Use a composite primary key on `(analysis_id, finding_hash)` and a unique key on `(analysis_id, display_number)`. Validate `display_id` with `F-[0-9]{3,}` before lookup.

- [ ] **Step 4: Run focused tests and static checks**

Run: `uv run pytest -q tests/unit/reporting/test_finding_display_id.py -p no:cacheprovider`

Run: `uv run ruff check src/sastsimi/reporting/finding_display_id.py tests/unit/reporting/test_finding_display_id.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/sastsimi/reporting/finding_display_id.py tests/unit/reporting/test_finding_display_id.py
git commit -m "feat: allocate stable finding display ids"
```

### Task 2: 한국어 네 구역 보고서와 실제 PoC

**Files:**
- Modify: `src/sastsimi/simple_runtime/stages.py`
- Modify: `src/sastsimi/simple_runtime/models.py`
- Modify: `src/sastsimi/simple_runtime/store.py`
- Modify: `src/sastsimi/reporting/markdown_export.py`
- Modify: `src/sastsimi/reporting/finding_display_id.py`
- Test: `tests/simple_runtime/test_simple_report.py`
- Modify: `tests/simple_runtime/test_simple_runtime.py`
- Modify: `tests/unit/reporting/test_markdown_export.py`

**Interfaces:**
- Consumes: exact Finding, Verification, CWE, Technical Gate, Rule Scope Gate, PoC candidate content, execution result/stdout/stderr references
- Produces: UTF-8 Markdown with exactly four top-level `###` sections and destination `<reports>/<analysis_id>/<F-###>.md`

- [ ] **Step 1: Write failing renderer tests**

```python
def assert_korean_report(markdown: str) -> None:
    assert markdown.count("### Summary") == 1
    assert markdown.count("### Details") == 1
    assert markdown.count("### PoC") == 1
    assert markdown.count("### Impact") == 1
    assert "#!/bin/sh" in markdown
    assert "실행 명령" in markdown
    assert "실행 결과" in markdown
    assert "validated PoC" in markdown

def test_restricted_report_preserves_scope_denial_and_real_poc(...):
    markdown, path = render_simple_report(scope_status="DENY")
    assert path.name == "F-001.md"
    assert "외부 제출·공개 금지" in markdown
    assert "CONFIRMED_RESTRICTED" in markdown
    assert_korean_report(markdown)

def test_report_rejects_candidate_without_validated_execution(...):
    with pytest.raises(ValueError, match="REPORT_VALIDATED_POC_MISSING"):
        render_simple_report(validated_poc_ref=None)
```

Update the existing `ReportMarkdownService` test to expect `F-001.md`, the four headings, real PoC content, and no old thirteen-section heading list.

- [ ] **Step 2: Run tests and verify RED**

Run: `uv run pytest -q tests/simple_runtime/test_simple_report.py tests/unit/reporting/test_markdown_export.py -p no:cacheprovider`

Expected: FAIL because current SimpleRuntime prints only a PoC reference and generic `/bin/sh` sentence, while the existing exporter uses the old section layout and internal finding filename.

- [ ] **Step 3: Require Korean structured Reporter output**

Change `ReporterStage` instructions and schema to require Korean `title`, `summary`, `details`, `impact`, `limitations`, and `review_items`. The SimpleRuntime-only `recommendation` field is replaced by `impact`; the full Runtime keeps its existing `ReportContent.recommendation` contract and renders that verified value together with Rule Scope `security_impact` under `Impact`.

The prompt must include:

```text
모든 사람이 읽는 문장은 한국어로 작성한다. supplied exact record에 없는 사실,
공격 경로, 영향 또는 재현 결과를 추가하지 않는다. 내부 사고 과정이 아니라
검증된 근거와 결론만 간결하게 작성한다.
```

- [ ] **Step 4: Dereference the exact validated PoC chain**

Add a helper that reads the exact validated PoC JSON, confirms its `candidate_ref`, `content_ref`, `execution_ref`, and `attempt_id` match the current successful checkpoints, then reads the script and redacted stdout/stderr. Do not search for a “latest” candidate.

```python
@dataclass(frozen=True)
class RenderedPoC:
    content: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    attempt_id: str
    validated_ref: StoredDataRef
```

Raise `REPORT_VALIDATED_POC_MISSING`, `REPORT_POC_ATTEMPT_MISMATCH`, or `REPORT_POC_REFERENCE_MISMATCH` before creating a Markdown file.

- [ ] **Step 5: Render the four-section Markdown**

```python
lines = [
    f"# {title}",
    f"- 보고서 번호: `{display_id}`",
    f"- 상태: `{report_status}`",
    *restricted_warning,
    "",
    "### Summary", "", summary,
    "",
    "### Details", "", details_with_refs,
    "",
    "### PoC", "", execution_summary,
    "```sh", poc.content.rstrip(), "```",
    "",
    "### Impact", "", impact_with_limits,
    "",
]
```

Run the existing sensitive-content inspection over the complete rendered bytes before atomic write.

- [ ] **Step 6: Use the display registry in both report paths**

`ReporterStage` must call `FindingDisplayIdStore` with its exact Finding output reference. `ReportMarkdownService._destination` uses `CurrentReport.draft.finding_ref`, which is already the exact Finding reference. The CLI still accepts the internal `finding_id` for compatibility, while output summaries add `display_id` and exported paths use `F-###.md`.

Do not delete existing content-hash-named Markdown files. Report list/query APIs expose only the current exact Finding mapping and its `F-###` path, so archival files are not presented as current output.

- [ ] **Step 7: Invalidate only the old report renderer checkpoint**

Add `stage_version: str = "1"` to `StageCheckpoint`, define `STAGE_VERSION[SimpleStage.REPORT_DONE] = "2"`, and require the stored version to match in `SimpleCheckpointStore.reusable`. `mark_running` records the current stage version. Existing PyGoat checkpoints deserialize with version `1`, so only `REPORT_DONE` is regenerated; previous static, hypothesis, Pro·Con, PoC, Verification and Gate checkpoints remain reusable.

Add a regression test:

```python
def test_report_version_change_reuses_every_prior_stage(tmp_path):
    store = seeded_store_with_version_one_report(tmp_path)
    assert not store.reusable(identity, SimpleStage.REPORT_DONE, report_inputs)
    assert store.reusable(identity, SimpleStage.FINDING_DONE, finding_inputs)
```

- [ ] **Step 8: Run report tests and static checks**

Run: `uv run pytest -q tests/simple_runtime/test_simple_report.py tests/simple_runtime/test_simple_runtime.py tests/unit/reporting/test_markdown_export.py tests/unit/interfaces/test_report_cli.py -p no:cacheprovider`

Run: `uv run ruff check src/sastsimi/simple_runtime/stages.py src/sastsimi/simple_runtime/models.py src/sastsimi/simple_runtime/store.py src/sastsimi/reporting tests/simple_runtime/test_simple_report.py tests/simple_runtime/test_simple_runtime.py tests/unit/reporting/test_markdown_export.py`

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/sastsimi/simple_runtime/stages.py src/sastsimi/simple_runtime/models.py src/sastsimi/simple_runtime/store.py src/sastsimi/reporting tests/simple_runtime/test_simple_report.py tests/simple_runtime/test_simple_runtime.py tests/unit/reporting/test_markdown_export.py tests/unit/interfaces/test_report_cli.py
git commit -m "feat: export Korean reports with validated poc"
```

### Task 3: Append-only Agent 감사 이벤트

**Files:**
- Create: `src/sastsimi/observability/__init__.py`
- Create: `src/sastsimi/observability/agent_activity.py`
- Create: `src/sastsimi/storage/agent_activity.py`
- Modify: `src/sastsimi/simple_runtime/store.py`
- Modify: `src/sastsimi/simple_runtime/runner.py`
- Test: `tests/unit/observability/test_agent_activity.py`
- Modify: `tests/simple_runtime/test_simple_runtime.py`

**Interfaces:**
- Consumes: stage identity, exact input/output refs, attempt, safe structured rationale, provider/model/digests, tool result refs and safe failure
- Produces: `AgentActivityEvent`, `AgentActivityStore.append(event)`, `AgentActivityStore.list_analysis(analysis_id, hypothesis_id=None)`

- [ ] **Step 1: Write failing event safety and append-only tests**

```python
def test_retry_events_are_append_only_and_attempt_scoped(tmp_path):
    store = AgentActivityStore(tmp_path / "sastsimi.sqlite3")
    store.append(event("BLOCKED", attempt_id="attempt-1", sequence=1))
    store.append(event("STAGE_STARTED", attempt_id="attempt-2", sequence=1))
    values = store.list_analysis("analysis-1", hypothesis_id="hypothesis-1")
    assert [(item.attempt_id, item.kind) for item in values] == [
        ("attempt-1", ActivityKind.STAGE_BLOCKED),
        ("attempt-2", ActivityKind.STAGE_STARTED),
    ]

def test_event_rejects_secret_and_host_absolute_path(tmp_path):
    store = AgentActivityStore(tmp_path / "sastsimi.sqlite3")
    with pytest.raises(ValueError, match="AGENT_ACTIVITY_UNSAFE"):
        store.append(event("DECISION_RECORDED", summary_ko="token=sk-live-value"))
    with pytest.raises(ValueError, match="AGENT_ACTIVITY_UNSAFE"):
        store.append(event("DECISION_RECORDED", summary_ko="C:\\Users\\name\\repo"))
```

- [ ] **Step 2: Run tests and verify RED**

Run: `uv run pytest -q tests/unit/observability/test_agent_activity.py -p no:cacheprovider`

Expected: FAIL because the event model and store do not exist.

- [ ] **Step 3: Implement the public event model**

```python
class ActivityKind(StrEnum):
    STAGE_STARTED = "STAGE_STARTED"
    EVIDENCE_REVIEWED = "EVIDENCE_REVIEWED"
    CONTEXT_REQUESTED = "CONTEXT_REQUESTED"
    EVIDENCE_RECORDED = "EVIDENCE_RECORDED"
    TOOL_REQUESTED = "TOOL_REQUESTED"
    TOOL_COMPLETED = "TOOL_COMPLETED"
    DECISION_RECORDED = "DECISION_RECORDED"
    STAGE_COMPLETED = "STAGE_COMPLETED"
    STAGE_BLOCKED = "STAGE_BLOCKED"
    STAGE_FAILED = "STAGE_FAILED"

class AgentActivityEvent(ContractModel):
    event_id: str
    analysis_id: str
    workspace_id: str
    commit_id: str
    hypothesis_id: str | None
    stage: str
    agent_role: str
    attempt_id: str
    sequence: int
    kind: ActivityKind
    status: str
    summary_ko: str
    input_refs: tuple[StoredDataRef, ...] = ()
    output_refs: tuple[StoredDataRef, ...] = ()
    tool_name: str | None = None
    tool_result_refs: tuple[StoredDataRef, ...] = ()
    provider: str | None = None
    model: str | None = None
    prompt_digest: str | None = None
    output_digest: str | None = None
    error_code: str | None = None
    started_at: datetime
    finished_at: datetime | None = None
    elapsed_ms: int | None = None
```

Validate non-empty identifiers, 64-character lowercase digests when present, non-negative times, exact reference scope, and permitted status/kind combinations.

- [ ] **Step 4: Implement safe append and query**

Create `agent_activity_events` with unique `event_id` and unique `(analysis_id, hypothesis_key, attempt_id, sequence)`. Before insertion, call the existing provider-text safety check and an explicit Windows/POSIX host absolute-path detector on all user-visible strings. Store canonical JSON, never raw prompt or response.

- [ ] **Step 5: Commit stage checkpoint and terminal event atomically**

Extend `SimpleCheckpointStore._write` to accept `activity_events: tuple[AgentActivityEvent, ...] = ()` and insert them using the same connection before commit. `mark_running`, `complete`, and `mark_failure` each supply one lifecycle event. A duplicate event ID with different canonical content must raise `AGENT_ACTIVITY_EVENT_CONFLICT`.

- [ ] **Step 6: Map stages to safe summaries**

Create a fixed mapping from `SimpleStage` to public role name. Lifecycle summaries describe only observed actions, for example:

```python
ROLE_BY_STAGE = {
    SimpleStage.PRO_CON_DONE: "Pro·Con Agents",
    SimpleStage.VERIFICATION_INITIAL_DONE: "Verification Agent",
    SimpleStage.POC_CANDIDATE_DONE: "Dynamic Reproduction Agent",
    SimpleStage.POC_EXECUTION_DONE: "Reproduction Runtime",
    SimpleStage.CWE_DONE: "CWE Labeling Agent",
    SimpleStage.TECH_GATE_DONE: "Technical Gate Agent",
    SimpleStage.SCOPE_GATE_DONE: "Rule Scope Gate Agent",
    SimpleStage.REPORT_DONE: "Reporter Agent",
}
```

Store exact refs and structured `rationale`/status summaries only. Do not copy full prompt context or model response.

- [ ] **Step 7: Run event and Runtime tests**

Run: `uv run pytest -q tests/unit/observability/test_agent_activity.py tests/simple_runtime/test_simple_runtime.py -p no:cacheprovider`

Run: `uv run ruff check src/sastsimi/observability src/sastsimi/storage/agent_activity.py src/sastsimi/simple_runtime/store.py src/sastsimi/simple_runtime/runner.py tests/unit/observability tests/simple_runtime/test_simple_runtime.py`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/sastsimi/observability src/sastsimi/storage/agent_activity.py src/sastsimi/simple_runtime/store.py src/sastsimi/simple_runtime/runner.py tests/unit/observability tests/simple_runtime/test_simple_runtime.py
git commit -m "feat: record safe agent activity events"
```

### Task 4: Agent 근거·도구·판정 이벤트 연결

**Files:**
- Modify: `src/sastsimi/simple_runtime/provider.py`
- Modify: `src/sastsimi/simple_runtime/stages.py`
- Modify: `src/sastsimi/simple_runtime/models.py`
- Modify: `src/sastsimi/simple_runtime/runner.py`
- Test: `tests/simple_runtime/test_agent_activity_flow.py`

**Interfaces:**
- Consumes: `SimpleLLMCallResult`, structured stage output, PoC candidate/execution/interpretation refs
- Produces: stage result의 `activity_events: tuple[AgentActivityEvent, ...]`와 Runtime이 원자적으로 저장하는 근거·도구·판정 이벤트

- [ ] **Step 1: Write the failing full activity flow test**

```python
@pytest.mark.asyncio
async def test_pro_con_dynamic_and_verification_emit_auditable_summaries(...):
    await runner.resume_hypothesis(identity)
    events = activity_store.list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert any(item.agent_role == "Pro·Con Agents" and
               item.kind is ActivityKind.EVIDENCE_RECORDED for item in events)
    assert any(item.tool_name == "docker" and
               item.kind is ActivityKind.TOOL_COMPLETED for item in events)
    assert any(item.agent_role == "Verification Agent" and
               item.kind is ActivityKind.DECISION_RECORDED for item in events)
    assert all("<UNTRUSTED_EXACT_INPUTS>" not in item.summary_ko for item in events)
```

- [ ] **Step 2: Run test and verify RED**

Run: `uv run pytest -q tests/simple_runtime/test_agent_activity_flow.py -p no:cacheprovider`

Expected: FAIL because only lifecycle events exist.

- [ ] **Step 3: Carry safe call metadata without raw messages**

Extend `SimpleLLMCallResult` with `invocation_id`, `provider`, `model`, `started_at`, `finished_at`, and `elapsed_ms`. Keep only prompt/output digests. Provider failures return safe status and no raw stderr in activity summaries.

- [ ] **Step 4: Add stage-specific structured events**

- Pro·Con: evidence summary and exact cited refs.
- Verification: verdict and stored rationale.
- PoC candidate: candidate/content refs and digest, not a duplicate script body.
- PoC execution: Docker tool request/result refs, exit code, timeout and interpreted outcome.
- CWE/Gates/Reporter: label/status and stored rationale.
- Context request: create only when the Runtime actually issues an additional context request.

Add events to `StageResult.activity_events`; `SimpleCheckpointStore.complete` commits the checkpoint, output refs, and events together.

- [ ] **Step 5: Run flow and safety tests**

Run: `uv run pytest -q tests/simple_runtime/test_agent_activity_flow.py tests/simple_runtime/test_simple_runtime.py -p no:cacheprovider`

Expected: PASS with no raw prompt or secret in serialized event payloads.

- [ ] **Step 6: Commit**

```bash
git add src/sastsimi/simple_runtime/provider.py src/sastsimi/simple_runtime/stages.py src/sastsimi/simple_runtime/models.py src/sastsimi/simple_runtime/runner.py tests/simple_runtime/test_agent_activity_flow.py
git commit -m "feat: expose auditable agent decisions"
```

### Task 5: 읽기 전용 Dashboard query와 안전한 API 모델

**Files:**
- Create: `src/sastsimi/dashboard/__init__.py`
- Create: `src/sastsimi/dashboard/models.py`
- Create: `src/sastsimi/dashboard/query.py`
- Test: `tests/unit/dashboard/test_query.py`

**Interfaces:**
- Consumes: `sastsimi.sqlite3`, `agent_activity_events`, `simple_runtime_checkpoints`, `analysis_runs`, current report display registry
- Produces: `DashboardQuery.list_analyses()`, `DashboardQuery.get_analysis(analysis_id)`, `DashboardQuery.list_events(analysis_id, after_event_id=None)`, `DashboardQuery.report_path(analysis_id, display_id)`

- [ ] **Step 1: Write failing scoped projection tests**

```python
def test_query_projects_current_progress_without_cross_analysis_data(seed_db):
    query = DashboardQuery(seed_db.data_dir)
    detail = query.get_analysis("analysis-a")
    assert detail.analysis_id == "analysis-a"
    assert detail.completed_count == 3
    assert all(item.analysis_id == "analysis-a" for item in detail.hypotheses)
    assert "C:\\" not in detail.model_dump_json()

def test_report_path_rejects_traversal_and_other_analysis(seed_db):
    query = DashboardQuery(seed_db.data_dir)
    with pytest.raises(DashboardNotFound):
        query.report_path("analysis-a", "../F-001")
    with pytest.raises(DashboardNotFound):
        query.report_path("analysis-a", "F-999")
```

- [ ] **Step 2: Run tests and verify RED**

Run: `uv run pytest -q tests/unit/dashboard/test_query.py -p no:cacheprovider`

Expected: FAIL because `DashboardQuery` does not exist.

- [ ] **Step 3: Implement four public view models**

```python
class AnalysisSummaryView(ContractModel): ...
class HypothesisProgressView(ContractModel): ...
class AgentActivityView(ContractModel): ...
class FindingReportView(ContractModel): ...
```

Expose IDs, stages, states, counts, safe summaries, relative report URL, timestamps and elapsed time only. Do not expose artifact filesystem paths, raw prompt payloads, session refs, container IDs or credentials.

- [ ] **Step 4: Implement read-only SQLite projection**

Open SQLite with `mode=ro`. List analyses from the union of `analysis_runs` and `simple_runtime_checkpoints`. For full Runtime rows, parse `AnalysisRunState` and published safe result records; for SimpleRuntime rows, parse exact `StageCheckpoint`. Deduplicate on `analysis_id` and select the more recently updated state without changing either source.

- [ ] **Step 5: Resolve reports only through the display registry**

Require `analysis_id` to match `[A-Za-z0-9_-]{1,128}` and `display_id` to match `F-[0-9]{3,}`. Resolve the exact Finding ref through `FindingDisplayIdStore`, then return only `<data-dir>/reports/<analysis_id>/<display_id>.md` after checking the resolved parent remains inside the reports root.

- [ ] **Step 6: Run query tests and static checks**

Run: `uv run pytest -q tests/unit/dashboard/test_query.py -p no:cacheprovider`

Run: `uv run ruff check src/sastsimi/dashboard tests/unit/dashboard`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/sastsimi/dashboard tests/unit/dashboard
git commit -m "feat: project read-only dashboard data"
```

### Task 6: localhost HTTP server와 실시간 화면

**Files:**
- Create: `src/sastsimi/dashboard/server.py`
- Create: `src/sastsimi/dashboard/static/index.html`
- Create: `src/sastsimi/dashboard/static/app.css`
- Create: `src/sastsimi/dashboard/static/app.js`
- Test: `tests/integration/dashboard/test_server.py`

**Interfaces:**
- Consumes: `DashboardQuery`, `data_dir`, exact host and port
- Produces: `serve_dashboard(data_dir: Path, host: str, port: int) -> None`, local HTML and read-only JSON routes

- [ ] **Step 1: Write failing route and method tests**

```python
def test_server_is_local_read_only_and_refreshes_persisted_state(server):
    assert get(server, "/api/analyses").status == 200
    first = get_json(server, "/api/analyses/analysis-1")
    server.seed_next_checkpoint()
    second = get_json(server, "/api/analyses/analysis-1")
    assert second["completed_count"] == first["completed_count"] + 1
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert request(server, method, "/api/analyses").status == 405

def test_server_rejects_non_loopback_bind(tmp_path):
    with pytest.raises(ValueError, match="DASHBOARD_LOOPBACK_ONLY"):
        create_server(tmp_path, host="0.0.0.0", port=8765)
```

- [ ] **Step 2: Run tests and verify RED**

Run: `uv run pytest -q tests/integration/dashboard/test_server.py -p no:cacheprovider`

Expected: FAIL because the server and routes do not exist.

- [ ] **Step 3: Implement the standard-library server**

Use `ThreadingHTTPServer` and a request handler that supports:

```text
GET  /
GET  /static/app.css
GET  /static/app.js
GET  /api/analyses
GET  /api/analyses/<analysis_id>
GET  /api/analyses/<analysis_id>/events
GET  /reports/<analysis_id>/<display_id>.md
HEAD for the same paths
```

Return `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`, and exact route content types (`text/html; charset=utf-8`, `text/css; charset=utf-8`, `text/javascript; charset=utf-8`, `application/json; charset=utf-8`, or `text/markdown; charset=utf-8`). Never reflect an unvalidated path into HTML or an error body.

- [ ] **Step 4: Build the no-framework UI**

The page polls `/api/analyses` every two seconds, then the selected analysis detail and events. Render with `textContent`, never `innerHTML` for stored data. Show repository/commit label, elapsed time, actual stage counts, hypothesis cards, Agent timeline, Pro·Con summaries, PoC/Gate/Finding status and `F-###` links. Use no fake percentage.

- [ ] **Step 5: Prove dashboard failure is isolated from analysis**

Add a test that shuts down the server while a fake SimpleRuntime advances checkpoints. Assert Runtime reaches `REPORT_DONE`; the dashboard process owns no write connection and its absence does not change analysis behavior.

- [ ] **Step 6: Run server tests and static checks**

Run: `uv run pytest -q tests/integration/dashboard/test_server.py -p no:cacheprovider`

Run: `uv run ruff check src/sastsimi/dashboard tests/integration/dashboard`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/sastsimi/dashboard tests/integration/dashboard
git commit -m "feat: add local read-only analysis dashboard"
```

### Task 7: CLI 연결, 문서와 WSL smoke

**Files:**
- Create: `src/sastsimi/interfaces/cli/dashboard.py`
- Modify: `src/sastsimi/interfaces/cli/main.py`
- Modify: `README.md`
- Modify: `docs/DOCUMENT_GUIDE.md`
- Test: `tests/unit/interfaces/test_dashboard_cli.py`

**Interfaces:**
- Consumes: `sastsimi dashboard --host 127.0.0.1 --port 8765`, configured `data_dir`
- Produces: blocking local dashboard process, startup URL on stderr/stdout without secret/path exposure

- [ ] **Step 1: Write failing CLI tests**

```python
def test_dashboard_cli_starts_loopback_server(monkeypatch, tmp_path):
    called = {}
    monkeypatch.setattr(dashboard_command, "serve_dashboard",
                        lambda data_dir, host, port: called.update(
                            data_dir=data_dir, host=host, port=port))
    assert main(["--data-dir", str(tmp_path), "dashboard"]) == 0
    assert called["host"] == "127.0.0.1"
    assert called["port"] == 8765

def test_dashboard_cli_rejects_external_host(tmp_path):
    assert main(["--data-dir", str(tmp_path), "dashboard",
                 "--host", "0.0.0.0"]) != 0
```

- [ ] **Step 2: Run tests and verify RED**

Run: `uv run pytest -q tests/unit/interfaces/test_dashboard_cli.py -p no:cacheprovider`

Expected: FAIL because the command is not registered.

- [ ] **Step 3: Add the dashboard command**

Register `dashboard` with defaults `127.0.0.1` and `8765`. Validate port is `1..65535`. Print only `http://127.0.0.1:<port>` and a stop instruction. Handle `KeyboardInterrupt` as a normal shutdown.

- [ ] **Step 4: Document the two-terminal WSL flow**

Add exact commands for WSL installation, dashboard startup, analysis/resume, opening `localhost`, report path, read-only limitation, unsupported Windows-native E2E, and the four-section Korean report. Do not claim unverified Provider combinations work.

- [ ] **Step 5: Run focused tests**

Run: `uv run pytest -q tests/unit/interfaces/test_dashboard_cli.py tests/integration/dashboard/test_server.py tests/simple_runtime/test_agent_activity_flow.py tests/simple_runtime/test_simple_report.py tests/unit/reporting/test_finding_display_id.py -p no:cacheprovider`

Expected: PASS.

- [ ] **Step 6: Run full local verification once**

Run: `uv run ruff check .`

Run: `uv run mypy src`

Run: `uv run pytest -q -p no:cacheprovider`

Expected: PASS. Report any unrelated pre-existing failure by exact test name; fix only Blocker/High regressions caused by this implementation.

- [ ] **Step 7: Run WSL smoke without restarting completed work**

1. Start `sastsimi dashboard` against the existing PyGoat data directory.
2. Open `http://localhost:8765` from Windows.
3. Resume the existing PyGoat analysis ID from its failed/incomplete stage.
4. Confirm current stage and new Agent events appear within the next 2-second poll.
5. Confirm an existing final TRUE resolves to `F-001.md` or the next stable number.
6. Confirm the Markdown has the four headings and actual validated PoC script/command/result.
7. Confirm Rule Scope DENY remains `CONFIRMED_RESTRICTED` and says external disclosure is forbidden.

- [ ] **Step 8: Commit**

```bash
git add src/sastsimi/interfaces/cli/dashboard.py src/sastsimi/interfaces/cli/main.py README.md docs/DOCUMENT_GUIDE.md tests/unit/interfaces/test_dashboard_cli.py
git commit -m "feat: expose WSL live analysis dashboard"
```

- [ ] **Step 9: Final branch evidence**

Record the focused test output, full local verification result, WSL dashboard URL, reused analysis ID, generated `F-###.md` path and exact limitations in the eventual PR body. Do not run CI until the branch is ready for its single final PR.
