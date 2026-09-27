# OpenGrep Rule-Batch Resume Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 공개 SimpleRuntime의 OpenGrep 규칙을 빠짐없이 순차 배치로 실행하고, 검증된 완료 배치만 같은 분석의 재개에서 재사용한다.

**Architecture:** 순수 배치 계획·검증 모듈이 원본 규칙 YAML을 분할하고 결과를 합친다. SQLite는 성공한 배치의 CAS 참조만 기록하며, `DirectStaticBootstrap`이 공통 deadline과 분석 lease 아래에서 실행·재개를 조정한다. 기존 Production 파일 배치 어댑터는 건드리지 않는다.

**Tech Stack:** Python 3.12, PyYAML 6, SQLite, 기존 CAS artifact 저장소, pytest/pytest-asyncio, OpenGrep 1.30.0.

**Spec:** `docs/superpowers/specs/2026-09-27-opengrep-rule-batch-resume-design.md`

## Global Constraints

- 모든 규칙 ID를 정확히 한 배치에 넣고, 각 배치는 원본 `rules.yml`과 동일한 workspace 루트를 스캔한다. 저장소별 특례와 새 경로 제외를 추가하지 않는다.
- 기존 Agent·프롬프트·다른 정적 도구·보고서·Production 파일 배치 어댑터를 변경하지 않는다.
- 한 배치라도 실패하면 `STATIC_DONE`은 성공이 아니며 가설·Finding·보고서를 생성하지 않는다.
- 배치는 순차 실행하고 한 번의 정적 호출에서 `min(profile.max_elapsed_seconds, 3600)`초를 공유한다. timeout/cancel은 기존 process-tree 종료를 사용한다.
- 캐시는 analysis/workspace/exact commit/repository/규칙·도구 fingerprint가 모두 일치하고 CAS를 재검증했을 때만 사용한다.
- 이미 완료한 정적 분석은 불변 snapshot이다. 새 규칙·도구로 재분석하려면 새 분석을 시작한다.
- Dify 시험은 커밋 `8387590ace4a094de812b7847fc6a4c3a27cd52b`, Codex `gpt-6-sol`, 현재 승인된 LLM 예산을 사용한다.

## Review Focus

- 빈 규칙 목록·중복 ID·YAML 객체 오염은 조용히 빈 성공이 되지 않아야 한다. Task 1의 `test_invalid_rule_catalog_fails_closed`가 고정한다.
- 첫 규칙의 결과가 500개를 넘더라도 뒤 규칙의 근거가 후속 500개에 들어갈 수 있어야 한다. Task 1의 `test_round_robin_keeps_later_rule_visible`이 고정한다.
- 같은 분석 ID라도 다른 workspace/commit/repository/tool fingerprint는 캐시를 받지 않아야 한다. Task 2의 `test_progress_key_is_exact`가 고정한다.
- 저장된 CAS가 사라지거나 바뀌면 성공인 척하지 않고 해당 배치만 재실행해야 한다. Task 3의 `test_corrupt_cache_reexecutes_only_that_batch`가 고정한다.
- 첫 배치 성공 뒤 두 번째가 timeout·오류이면 정적 checkpoint는 BLOCKED이며 첫 배치만 재사용 가능해야 한다. Task 3의 `test_timeout_resume_reuses_first_batch`가 고정한다.

---

### Task 1: 규칙 계획·결과 검증 모듈

**Files:**
- Create: `src/sastsimi/simple_runtime/opengrep_rule_batches.py`
- Create: `tests/unit/simple_runtime/test_opengrep_rule_batches.py`

**Interfaces:**
- Consumes: PyYAML `safe_load`, `StoredDataRef`, `canonical_bytes`.
- Produces: `RuleBatch(index: int, rule_ids: tuple[str, ...], excluded_rule_ids: tuple[str, ...], key: str)`, `RuleBatchPlan(fingerprint: str, rule_ids: tuple[str, ...], batches: tuple[RuleBatch, ...])`; `plan_rule_batches(raw: bytes, *, tool_version: str, executable_sha256: str, batch_size: int = 3) -> RuleBatchPlan`; `parse_rule_batch(raw: bytes, batch: RuleBatch) -> dict[str, object]`; `aggregate_rule_batches(plan: RuleBatchPlan, accepted: Sequence[tuple[RuleBatch, StoredDataRef, dict[str, object]]]) -> bytes`.

- [ ] **Step 1: Write failing tests.** `test_plan_partitions_every_rule_once` asserts seven IDs yield [3,3,1], disjoint union equals all IDs, each excluded set is the exact complement, and changing YAML/tool digest changes fingerprint. `test_invalid_rule_catalog_fails_closed` covers empty, duplicate, non-string ID and unsafe YAML. `test_parse_rejects_wrong_rule_or_error` rejects out-of-batch `check_id`, malformed JSON and nonempty `errors`. `test_round_robin_keeps_later_rule_visible` gives the first rule 501 hits and a later rule one hit, asserting all 502 remain in aggregate, later hit occurs before position 500 and `candidate_snippets_truncated` is true.
- [ ] **Step 2: Run RED.** Run: `pytest -q tests/unit/simple_runtime/test_opengrep_rule_batches.py`. Expected: collection/import failure for the not-yet-created module.
- [ ] **Step 3: Implement the stated interfaces.** Validate `rules` as a nonempty list of mappings with unique safe IDs. Include plan version 1, batch size, raw YAML SHA-256, ordered IDs, configured tool version/SHA in fingerprint. Reject any batch JSON that is not an object with a list of object `results`; optional `errors` must be an empty list. Preserve per-batch `paths` and CAS refs in aggregate. Sort hits within each rule by path/line/canonical JSON and round-robin rules in source order without deduplication; emit top-level `results` for existing consumers.
- [ ] **Step 4: Run GREEN.** Run: `pytest -q tests/unit/simple_runtime/test_opengrep_rule_batches.py`. Expected: all tests pass.
- [ ] **Step 5: Commit.** `git add src/sastsimi/simple_runtime/opengrep_rule_batches.py tests/unit/simple_runtime/test_opengrep_rule_batches.py` then `git commit -m "Partition and validate OpenGrep rule batches"`.

### Task 2: 성공 배치의 내구성 있는 정확한 참조

**Files:**
- Modify: `src/sastsimi/simple_runtime/store.py`
- Create: `tests/unit/simple_runtime/test_opengrep_batch_progress.py`

**Interfaces:**
- Consumes: `CheckpointIdentity`, `StoredDataRef`, Task 1의 `RuleBatch.key`와 `RuleBatchPlan.fingerprint`.
- Produces: `SimpleCheckpointStore.opengrep_batch_ref(identity: CheckpointIdentity, repository: str, fingerprint: str, batch_key: str) -> StoredDataRef | None`; `save_opengrep_batch(identity: CheckpointIdentity, repository: str, fingerprint: str, batch_key: str, ref: StoredDataRef, *, replaces: StoredDataRef | None = None) -> None`.

- [ ] **Step 1: Write failing tests.** `test_progress_survives_reopen` saves a CAS ref, reopens SQLite, and reads the exact ref; duplicate identical save is idempotent, conflicting save raises. `test_progress_key_is_exact` checks analysis/workspace/commit/repository/fingerprint/batch isolation. `test_invalid_ref_can_be_replaced_conditionally` checks replacement only when `replaces` equals the current row and new ref scope matches identity.
- [ ] **Step 2: Run RED.** Run: `pytest -q tests/unit/simple_runtime/test_opengrep_batch_progress.py`. Expected: absent table/method assertions fail.
- [ ] **Step 3: Add one `simple_opengrep_batch_progress` table and the two methods.** Key columns: analysis_id, workspace_id, commit_id, repository, fingerprint, batch_key; value: ref_json. Follow existing survey progress transaction style; validate ref scope, use compare-and-swap update for a corrupt prior artifact, and never replace a valid ref implicitly.
- [ ] **Step 4: Run GREEN.** Run: `pytest -q tests/unit/simple_runtime/test_opengrep_batch_progress.py`. Expected: all tests pass.
- [ ] **Step 5: Commit.** `git add src/sastsimi/simple_runtime/store.py tests/unit/simple_runtime/test_opengrep_batch_progress.py` then `git commit -m "Persist verified OpenGrep batch progress"`.

### Task 3: 공개 정적 bootstrap에 배치·재개 연결

**Files:**
- Modify: `src/sastsimi/simple_runtime/bootstrap_stages.py`
- Modify: `src/sastsimi/composition/simple_runtime_composition.py`
- Modify: `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`
- Modify: `tests/simple_runtime/test_simple_analysis_application.py`
- Modify: `tests/unit/simple_runtime/test_security_policy.py`
- Create: `tests/integration/static_analysis/test_opengrep_rule_batch_cli.py`

**Interfaces:**
- Consumes: Task 1의 계획/검증/aggregate 함수, Task 2의 진행 메서드, 기존 `ProcessExecutor`·`SimpleArtifactRepository`.
- Produces: `DirectStaticBootstrap.__init__(..., store: SimpleCheckpointStore)`; `_run_opengrep(self, workspace: Path, request: SimpleAnalysisRequest, identity: CheckpointIdentity) -> bytes`. `run()`의 OpenGrep artifact는 aggregate JSON이다.

- [ ] **Step 1: Write failing integration tests.** 기존 fake가 작은 `opengrep/rules.yml`, `git status --porcelain=v1 -z --untracked-files=all`, 배치별 JSON을 제공하게 한다. `test_all_batches_use_original_config_and_full_root`는 동일 config/root, `--no-rewrite-rule-ids`, 보완집합 `--exclude-rule`, 고유 출력 경로를 확인한다. `test_timeout_resume_reuses_first_batch`는 첫 배치 성공·둘째 timeout 후 재개 시 첫 scan 미호출·aggregate 미게시를 확인하고, `tests/simple_runtime/test_simple_analysis_application.py`에서 실제 application의 정적 checkpoint가 BLOCKED임을 검증한다. `test_corrupt_cache_reexecutes_only_that_batch`는 CAS 손상 후 해당 배치만 다시 실행한다. 기존 stale-output·hour-cap 테스트를 새 signature와 공통 deadline에 맞춘다. 실제 CLI smoke는 `shutil.which("opengrep")`가 있을 때만 작은 Python/JavaScript fixture로 단일 scan과 배치 union을 비교한다.
- [ ] **Step 2: Run RED.** Run: `pytest -q tests/integration/orchestration/test_simple_runtime_static_bootstrap.py tests/integration/static_analysis/test_opengrep_rule_batch_cli.py tests/simple_runtime/test_simple_analysis_application.py tests/unit/simple_runtime/test_security_policy.py`. Expected: 새 배치 assertions/signature가 실패한다.
- [ ] **Step 3: Wire implementation.** Composition이 기존 store를 static bootstrap에 주입한다. `_run_opengrep`는 ready marker·HEAD·깨끗한 작업트리를 확인하고, 계획의 각 배치에 원본 config/동일 root와 제외 ID를 전달한다. 공통 monotonic deadline의 잔여 초만 process에 준다. 재개 때 DB 키와 CAS를 재검증하고 유효한 배치는 skip한다. 실행 배치의 오래된 출력만 제거하고, 검증 뒤 CAS→DB 순서로 기록한다. 잘못된 출력·timeout은 기존 BLOCKED 경로로 전달한다. `run()`은 모든 배치 이후에만 aggregate ref와 후속 static bundle을 만든다.
- [ ] **Step 4: Run GREEN and regression.** Run: `pytest -q tests/integration/orchestration/test_simple_runtime_static_bootstrap.py tests/integration/static_analysis/test_opengrep_rule_batch_cli.py tests/simple_runtime/test_simple_analysis_application.py tests/unit/simple_runtime/test_security_policy.py tests/unit/simple_runtime/test_opengrep_rule_batches.py tests/unit/simple_runtime/test_opengrep_batch_progress.py`. Expected: all pass or actual OpenGrep가 없는 환경에서 smoke만 skip. Run: `ruff check src/sastsimi/simple_runtime src/sastsimi/composition/simple_runtime_composition.py tests/integration/orchestration/test_simple_runtime_static_bootstrap.py tests/integration/static_analysis/test_opengrep_rule_batch_cli.py tests/unit/simple_runtime`; `mypy --strict src/sastsimi/simple_runtime src/sastsimi/composition/simple_runtime_composition.py`. Expected: exit 0 each.
- [ ] **Step 5: Commit.** 변경한 구현·테스트 파일만 `git add` 후 `git commit -m "Resume verified OpenGrep rule batches"`.

### Task 4: 운영 문서와 전체 검증

**Files:**
- Modify: `README.md`
- Modify: `docs/usage.md`
- Modify: `docs/troubleshooting.md`
- Modify: `tests/contract/test_operator_docs.py`

**Interfaces:**
- Consumes: Task 3의 실제 CLI 동작과 `STATIC_DONE` 상태.
- Produces: PowerShell 한 줄 명령, 배치 재사용·BLOCKED·시간 증가 가능성의 운영 설명.

- [ ] **Step 1: Write failing docs assertions.** `test_opengrep_batch_resume_is_documented` checks three documents for `sastsimi resume A-001`, 완료 묶음 재사용, 전체 성공 전 `BLOCKED`, 저장소별 별도 설정이 필요 없다는 설명.
- [ ] **Step 2: Run RED.** Run: `pytest -q tests/contract/test_operator_docs.py`. Expected: new docs assertion fails.
- [ ] **Step 3: Update the three documents.** Keep PowerShell commands one line each, explain that scan coverage is unchanged but total runtime may grow, and never promise every repository will reach COMPLETE.
- [ ] **Step 4: Run GREEN and whole suite.** Run: `pytest -q tests/contract/test_operator_docs.py`, `pytest -q tests`, `ruff format --check .`, `ruff check .`, `mypy --strict src tests`, `git diff --check`. Expected: exit 0; existing documented skips allowed, no failures.
- [ ] **Step 5: Commit.** `git add README.md docs/usage.md docs/troubleshooting.md tests/contract/test_operator_docs.py` then `git commit -m "Document resumable OpenGrep scans"`.

## Field Trial and PR Handoff

1. Verify the Python import resolves to the PR #202 worktree, keep the current `.venv` and Codex `gpt-6-sol` profile, and run `sastsimi resume A-006` at the pinned Dify commit. If recorded recovery STOP prevents restart, start a new analysis at that same commit without changing budget.
2. Observe per-batch DB refs and process exit without logging source code or secrets. If one invocation times out, resume within existing recovery allowance; compare scan count and reused refs. Do not bypass stage/recovery limits or treat partial aggregate as COMPLETE.
3. Confirm `STATIC_DONE=SUCCEEDED` and exact static refs before claiming static success. Confirm final `status --format json` is `COMPLETE` and report artifacts exist before claiming end-to-end success. If BLOCKED remains, report exact failure and next safe step.
4. Push the branch to existing PR #202, verify CI status for the pushed SHA, and attach the PR if not already attached. Do not claim green CI or Dify completion without fresh evidence.
