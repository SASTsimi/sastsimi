# PR #195 Observability Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** PR #195에서 reasoning 설정, 신뢰 가능한 단계별 콘솔 로그, 안전한 전체 Markdown 뷰어, 참조 이미지와 같은 정보 구조의 대시보드, 재현 가능한 시연·녹화 도우미를 완성한다.

**Architecture:** 설정은 기존 `UserConfig`/`SimpleExecutionProfile`을 통과해 provider별 공식 입력에만 전달한다. 정적 검사와 Agent 활동은 기존 저장 이벤트·체크포인트를 확장하고, 콘솔과 웹이 같은 기록을 읽는다. 웹은 기존 loopback/read-only 경계 안에서 확인된 아티팩트만 렌더링한다.

**Tech Stack:** Python 3.12, Pydantic, SQLite, pytest, 표준 라이브러리 HTTP 서버, vanilla JS/CSS, Windows PowerShell. Markdown은 `markdown-it-py>=4.2,<5` + `nh3>=0.3,<1`로 서버에서 변환·정제한다.

**Spec:** `docs/plans/2026-09-28-pr195-observability-dashboard-design.md`

## Global Constraints

- 기존 분석/판정/Scope Gate/PoC 정책은 변경하지 않는다. 후보는 confirmed Finding과 분리한다.
- 일반 로그에 키·전체 프롬프트·원시 코드/PoC·내부 호스트 경로·숨겨진 추론을 기록하지 않는다.
- 값의 원천이 없으면 `null`/`—`로 표시하며 0이나 100%를 합성하지 않는다.
- 기존 DB·설정은 추가 필드 없이 읽혀야 하고 resume에서 완료 작업을 중복 집계하지 않는다.
- 대시보드는 loopback 전용·read-only를 유지하고, #194/#202 아티팩트·번들 검증을 보존한다.
- Windows PowerShell에서 한 줄씩 실행 가능한 설치/시연 명령을 문서화한다. MP4는 Git에 넣지 않는다.

## Review Focus

1. 설정에 없는 reasoning을 가진 오래된 profile: 기존 모델 호출이 그대로 동작해야 한다(Tasks 1–2 테스트).
2. provider/모델이 effort를 지원하지 않음: 분석 시작 전에 명시적 실패, 무시나 추측 금지(Task 2 테스트).
3. 재개·재시도 및 512개 초과 항목: 이벤트와 집계가 중복·누락 없이 지속되어야 한다(Tasks 3–4 테스트).
4. 악성 Markdown/첨부파일명/분석 ID: 스크립트 실행·임의 경로 읽기 없이 안전한 미리보기 또는 거절(Task 5 테스트).
5. 단계 총량 미확정·좁은 화면·많은 상태 칸: `—`와 상태 문구를 보이고 UI가 멈추지 않아야 한다(Task 6 테스트).

## File Map

- Config/provider: `src/sastsimi/config/user_config.py`, `src/sastsimi/setup/service.py`, `src/sastsimi/interfaces/cli/{main,setup}.py`, `src/sastsimi/simple_runtime/{provider,cursor_provider,claude_provider}.py`, `src/sastsimi/providers/{base,codex_subscription}.py`, `src/sastsimi/composition/simple_runtime_composition.py`.
- Activity: `src/sastsimi/observability/agent_activity.py`, `src/sastsimi/simple_runtime/{bootstrap_stages,stages,store}.py`, `src/sastsimi/interfaces/cli/progress.py`.
- Dashboard: `src/sastsimi/dashboard/{models,query,server,markdown_view}.py`, `src/sastsimi/dashboard/static/{index.html,app.js,app.css}`.
- Demo/docs: `scripts/record-dashboard.ps1`, `docs/dashboard-demo.md`, `docs/usage.md`, `README.md`.
- Tests stay next to the corresponding existing suites under `tests/unit/{config,simple_runtime,interfaces,observability,dashboard}`, `tests/integration/dashboard`, and `tests/integration/orchestration`.

### Task 1: Optional reasoning configuration

**Files:** Modify config, setup service/CLI, composition; test `tests/unit/config/test_user_config.py`, `tests/unit/interfaces/test_setup_cli.py`.
**Interfaces:** `UserConfig.reasoning_effort: str | None`, `agent_reasoning_efforts: dict[str,str]`; same fields on `SimpleExecutionProfile`. `SimpleExecutionProfile.resolve_reasoning_effort(agent_name: str) -> str | None` chooses override then default.

- [ ] Write `test_old_config_has_no_reasoning`, `test_agent_reasoning_overrides_default`, `test_unknown_agent_reasoning_rejected`, `test_setup_reasoning_roundtrip`; assert `None`, override, validation error, and exact saved TOML values respectively.
- [ ] Run focused tests; expect failures for new fields/options.
- [ ] Add optional fields, validators, TOML serialization, setup choices, `--reasoning-effort` and `--agent-reasoning-effort NAME=LEVEL`; propagate through profile without changing missing-value behavior.
- [ ] Run focused tests and `ruff check` on touched files; expect pass.
- [ ] Commit only this slice: `feat: configure reasoning effort per agent`.

### Task 2: Provider capability validation and delivery

**Files:** Modify `simple_runtime/{provider,cursor_provider,claude_provider}.py`, `providers/{base,codex_subscription}.py`, composition; test provider suites and a new `tests/unit/simple_runtime/test_reasoning_effort.py`.
**Interfaces:** `validate_reasoning_effort(provider: str, model: str, effort: str | None, *, supported_levels: frozenset[str] | None) -> str | None`; `CodexProcessRequest.reasoning_effort: str | None = None`. `None` means no documented capability and explicit effort raises `REASONING_EFFORT_UNSUPPORTED`; model-specific CLI rejection is non-retryable if no catalog exists.

- [ ] Write `test_unset_effort_preserves_request`, `test_codex_official_override`, `test_openai_responses_effort`, `test_claude_child_env`, `test_cursor_catalog_parameter`, `test_cursor_cli_rejects_effort`, `test_unsupported_effort_nonretryable`; assert exact child argument/SDK field or exact rejection code, with no secret in logs.
- [ ] Run provider tests; expect failures.
- [ ] Wire Codex `model_reasoning_effort` only through official process config, OpenAI `reasoning.effort` only for supported models, Claude child `CLAUDE_CODE_EFFORT_LEVEL`, Cursor SDK only from verified catalog params; never forward to Cursor CLI without documented support.
- [ ] Run provider/config tests and verify process logs expose neither credentials nor prompts; expect pass.
- [ ] Commit: `feat: validate and pass reasoning effort to providers`.

### Task 3: Durable stage metrics and console events

**Files:** Modify activity model, static bootstrap, stage event construction, store, CLI progress; test `tests/unit/observability/test_agent_activity.py`, `tests/unit/interfaces/test_progress_cli.py`, `tests/unit/simple_runtime/test_opengrep_batch_progress.py`, `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`.
**Interfaces:** Optional `AgentActivityEvent.substage: str | None`, `metrics: dict[str,int]`; `ProgressRenderer` prints `substage`, sorted metric names/values and candidate status from stored events, not raw tool output. Event IDs derive from stable analysis/work/attempt/substage boundaries. Allowed metric keys are `expected`, `processed`, `verified`, `remaining`, `candidates`, `findings`; absent keys remain unknown.

- [ ] Write `test_static_tool_boundaries_show_verified_counts` for each engine, `test_candidate_is_not_confirmed`, `test_resume_reuses_event_id`, `test_old_activity_json_loads`, `test_activity_rejects_host_path`; assert actual metric values, distinct labels, one stored event, defaults, and `AGENT_ACTIVITY_UNSAFE`.
- [ ] Run focused tests; expect failures.
- [ ] Publish bounded static and Agent events from actual per-tool outcomes; retain `null` for unknown denominators; extend console renderer and append-only log without storing sensitive payloads.
- [ ] Run focused tests and targeted static integration test; expect pass with no duplicate events.
- [ ] Commit: `feat: expose verified per-stage activity metrics`.

### Task 4: Dashboard read model and large-run correctness

**Files:** Modify dashboard models/query/server; test `tests/unit/dashboard/test_query.py`, `tests/integration/dashboard/test_server.py`.
**Interfaces:** `DashboardKpiView` has `discovery_done/total`, `verification_done/total`, `remaining_work` as `int | None` and `confirmed_findings: int`; `StatusCellView` has `id`, `kind`, `status`, `label_ko`, `detail_url`; `StatusCellPageView` has `items`, `total`, `offset`, `limit`. Add `kpis: DashboardKpiView` to `AnalysisDetailView`; `DashboardQuery.list_status_cells(analysis_id: str, *, offset: int, limit: int) -> StatusCellPageView` with `0 <= offset`, `1 <= limit <= 200`; `AgentActivityView` carries `substage`/`metrics`. New read-only `GET /api/analyses/{id}/status-cells?offset=&limit=`. Discovery derives only from verified/expected static coverage; verification derives from terminal/known hypotheses; confirmed count includes distinct reported hypotheses with `verdict == "TRUE"` and `validated_poc`.

- [ ] Write `test_kpis_count_confirmed_only`, `test_unknown_total_is_none`, `test_status_cells_page_513`, `test_status_cells_reject_other_analysis`, `test_status_cells_reject_invalid_limit`; assert confirmed-only count, `None`, `total == 513` with disjoint 200/200/113 pages, 404, and 400 respectively.
- [ ] Run dashboard tests; expect failures.
- [ ] Project KPIs from full DB/checkpoint counts rather than capped preview lists; add bounded paging and verified activity metadata; preserve existing routes and read-only methods.
- [ ] Run dashboard unit/integration tests; expect pass.
- [ ] Commit: `feat: add complete dashboard KPIs and paged status cells`.

### Task 5: Safe Markdown and artifact previews

**Files:** Add `dashboard/markdown_view.py`; modify `pyproject.toml`, dashboard models/query/server and JS; test `tests/unit/dashboard/test_markdown_view.py`, `tests/integration/dashboard/test_server.py`.
**Interfaces:** `render_markdown_safe(source: str) -> str` uses MarkdownIt with raw HTML disabled, table enabled, then `nh3.clean` allowlist; `.md` report and verified artifact API responses include `rendered_html`, raw text and download URL. Preview input is capped at 1 MiB of UTF-8 at a codepoint boundary with an explicit truncated flag; full download remains available.

- [ ] Write `test_markdown_structure`, `test_markdown_xss_is_removed`, `test_verified_md_artifact_preview`, `test_large_markdown_is_truncated`, `test_report_path_traversal_rejected`; assert rendered heading/fence/table, no script/handler/unsafe URL, verified HTML, 1 MiB limit flag, and 404.
- [ ] Run focused tests; expect failures.
- [ ] Add bounded server-side renderer and sanitized HTML field; use only verified artifact refs; JSON gets formatted text/tree, plain text keeps line breaks, binary remains download-only; preserve CSP.
- [ ] Run dashboard/security tests and `node --check src/sastsimi/dashboard/static/app.js`; expect pass.
- [ ] Commit: `feat: render all verified Markdown safely`.

### Task 6: Screenshot-inspired accessible dashboard

**Files:** Modify dashboard `static/index.html`, `app.css`, `app.js`; test dashboard server HTML contracts and JS smoke test (Node or browser).
**Interfaces:** Top cards consume `DashboardKpiView`; grid consumes paged `StatusCellView`; progress and history consume existing stage/event views. No new writable endpoint.

- [ ] Write `test_dashboard_has_four_kpi_labels`, `test_dashboard_has_status_grid_and_progress`, `test_unknown_value_label`, `test_large_grid_paging`, `test_polling_single_flight`; assert DOM labels/roles, `—`, only current page rendered, and one active fetch per resource.
- [ ] Run tests; expect failures.
- [ ] Implement charcoal layout, cyan/amber/violet/green KPI accents, responsive card/grid/history sections, visible `후보`/`확정` distinctions, focus states, and sanitized Markdown insertion.
- [ ] Run server/Node tests and inspect desktop+narrow viewport in a browser; expect readable layout and no console errors.
- [ ] Commit: `feat: refresh dashboard layout and accessibility`.

### Task 7: Demo recording, docs and final regression

**Files:** Add `scripts/record-dashboard.ps1`, `src/sastsimi/dashboard/demo.py`, `tests/fixtures/dashboard_demo.json`; modify dashboard CLI/main, demo/usage/README; test `tests/unit/interfaces/test_dashboard_cli.py` and PowerShell dry-run verification.
**Interfaces:** `dashboard --demo` serves in-memory synthetic fixture through the same read-only server with visible `DEMO` label, without writing production DB. `record-dashboard.ps1 -Url <loopback URL> -OutputPath <absolute .mp4> [-FfmpegPath <path>] [-DryRun]`; check loopback URL, explicit output outside repo, installed ffmpeg, safe child process stop; never start capture silently.

- [ ] Write `test_demo_data_is_synthetic`, `test_demo_mode_does_not_write_db`, `test_record_rejects_non_loopback`, `test_record_dry_run`; assert `DEMO` marker, unchanged data directory, refusal, and bounded ffmpeg arguments. Validate missing ffmpeg and non-MP4 paths too.
- [ ] Run focused tests; expect failures.
- [ ] Implement helper and deterministic `DEMO` fixture/path; document one-line PowerShell setup/start/record/stop commands, 3–5 minute scenario, privacy warning, and separate-video delivery.
- [ ] Run `python -m pytest`, `ruff check .`, `mypy src/sastsimi`, `node --check`, PowerShell syntax/dry-run; capture counts and failures honestly. Recheck latest `origin/main` and remote PR head before pushing.
- [ ] Commit docs/demo slice, then push normal fast-forward to PR #195 branch and attach test evidence; never force-push or merge without a separate request.
