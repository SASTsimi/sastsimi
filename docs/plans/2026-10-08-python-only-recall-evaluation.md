# Python-Only Recall Evaluation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 고정 커밋의 Python 정답 사례를 사후 독립 검토와 대조해 TP/FN/HOLD/OUT_OF_SCOPE를 정직하게 산출하고, 관측된 미탐만 범용적으로 고치며 README를 간결하게 최신화한다.

**Architecture:** 기존 read-only `recall_audit`는 단계별 근거 추적기로 유지한다. v2 oracle은 분석 전에 고정하고, 별도 review ledger가 분석 후 ID 매핑과 Finding 판정을 담는다. 작은 점수 모듈은 둘과 저장된 체크포인트를 결합하고, 실제 사례가 입증한 결함만 런타임에 수정한다.

**Tech Stack:** Python 3.12, Pydantic v2, SQLite read-only URI, pytest, Ruff, mypy, Windows PowerShell.

**Spec:** `docs/plans/2026-10-08-python-only-recall-evaluation-design.md`

## Global Constraints

- Git에 추적된 제품용 Python `.py`가 정적 검사 대상이다. 비Python 제품 코드와 테스트 전용 코드를 Python 검사 성공으로 세지 않는다.
- 기존 v1 oracle와 분석 DB는 읽기·재개 가능하게 보존한다. 새 oracle/review는 분석 파이프라인 및 Agent 입력으로 전달하지 않는다.
- PoC/최종 TRUE/Technical Gate/Scope Gate 기준은 완화하지 않는다. 기술적 TP는 외부 제보 허가와 다르다.
- 읽기 전용 평가기는 분석 DB·아티팩트를 수정하지 않는다. 잘못된 대상 커밋, oracle 해시, 검토 기록, 손상된 증거에는 점수를 내지 않는다.
- 기존 사용자 변경사항, 실행 데이터, 다른 worktree는 건드리지 않는다. 새 PR은 `f49559ab` 기반 `codex/python-recall-final`에서 작성한다.
- Python 미탐 개선 수치는 같은 조건의 실측 결과에만 붙인다. 관측되지 않은 FN이나 환경 HOLD를 임의로 교정된 FN으로 보고하지 않는다.

## Review Focus

- Windows 대소문자·역슬래시·`..`가 들어간 oracle 경로: 정상적인 상대 POSIX 경로만 허용하고 오매칭을 막는다(태스크 1).
- 리뷰 파일이 다른 분석 ID 또는 예전 oracle 해시를 가리킴: JSON 점수 출력 없이 오류로 종료한다(태스크 1, 3).
- 혼합 저장소에서 JS/TS 제품 파일만 범위 밖이고 Python 조합은 모두 완료됨: Python 사례는 평가 가능하되 저장소 전체 `PARTIAL`은 유지한다(태스크 2).
- 환경 `HOLD` 또는 손상·오래된 PoC가 근처에 있음: 이를 FN/TP로 계산하지 않는다(태스크 2, 3).
- 동일 Finding을 여러 oracle 사례에 연결하거나 정답표에 없는 Finding을 FP로 처리함: 중복 매핑을 거부하고 별도 미검토 상태를 유지한다(태스크 3).

---

### Task 1: Freezeable v2 Oracle and Post-Run Review Input

**Files:**
- Modify: `src/sastsimi/simple_runtime/recall_audit.py` (`Oracle`, `OracleCase`, `_matches`)
- Create: `src/sastsimi/simple_runtime/recall_review.py`
- Modify: `tools/recall_audit.py` (strict v1/v2 loaders; no new default behavior)
- Test: `tests/unit/evaluation/test_recall_audit.py`, `tests/unit/evaluation/test_recall_audit_cli.py`

**Interfaces:**
- `OracleCase` adds `kind: Literal["FLOW", "MISSING_GUARD", "CONFIGURATION"] = "FLOW"`, `sink_path: str | None = None` and `scope: Literal["PYTHON", "OUT_OF_SCOPE"] = "PYTHON"`; absent `sink_path` means the existing `path`. In v2 `sink_line` is the affected Python operation/guard anchor for non-flow cases, not a falsely implied taint sink.
- `Oracle` adds `version: Literal[1, 2] = 1`, `completeness: Literal["UNDECLARED", "DOCUMENTED_CASES", "EXHAUSTIVE_PYTHON"] = "UNDECLARED"`; existing constructors keep working.
- `recall_review.py` exports `ReviewLedger`, `CaseReview`, `FindingReview`, `load_review(payload: bytes) -> ReviewLedger`, and `reviewed_oracle(oracle: Oracle, review: ReviewLedger, *, complete_inventory: bool) -> Oracle`. V2 review includes `analysis_id`, `oracle_sha256`, `inventory_reviewed`, case links (candidate/hypothesis/Finding IDs and rationale) and per-Finding adjudications (`MATCHED`, `FALSE_POSITIVE`, `UNMATCHED_REVIEWED` with evidence); validated identity and no duplicate IDs are mandatory. `reviewed_oracle` injects legacy vetted IDs only in memory; Task 3 validates the actual Finding inventory before setting `complete_inventory=True`.

- [ ] **Step 1: Add failing schema tests.** Assert legacy JSON still loads, v2 accepts distinct relative source/sink paths and a `MISSING_GUARD` Python anchor, rejects absolute/`..` paths and duplicate case/review/Finding IDs; identity/hash mismatch is pinned by Task 3's evaluator tests.
- [ ] **Step 2: Run focused tests red.** `& '..\..\.venv\Scripts\python.exe' -m pytest tests/unit/evaluation/test_recall_audit_cli.py -q --tb=short --basetemp=..\pytest-recall-t1-red` (verify path does not exist first; parent `build/` is ignored).
- [ ] **Step 3: Implement the exact interfaces above.** Use Pydantic `extra="forbid"`, strict types, bounded JSON input; preserve `audit_analysis(data_dir, analysis_id, oracle)` and CLI without `--review`. `_matches` compares ENTRY_POINT to `path/source_line`, other candidates to `sink_path or path/sink_line`.
- [ ] **Step 4: Run focused tests green** with a fresh `..\pytest-recall-t1-green` basetemp and commit only Task 1 paths.

### Task 2: Python-Only Completeness and HOLD-Safe Stage Audit

**Files:**
- Modify: `src/sastsimi/simple_runtime/recall_audit.py` (`_static_product_paths`, `_pipeline_complete`, per-case terminal checks)
- Test: `tests/unit/evaluation/test_recall_audit.py`

**Interfaces:**
- `_static_product_paths(...) -> frozenset[str] | None` returns selected Python product paths when every planned Python file×rule combination and AST/CodeQL evidence is verified, even if unrelated nonPython product paths are listed as out of scope.
- `_pipeline_complete(run: SimpleAnalysisRun, *, python_scope_complete: bool) -> bool` accepts terminal `PARTIAL` only when Python scope is complete, candidate/deep/chaining counts are terminal and verified surface counts contain no `UNCOVERED`/`INSUFFICIENT`.
- A case with a `HOLD` verdict or `environment_block_ref` gets `INCOMPLETE` with a specific `HOLD_*` first gap before the existing `MISSED` branches.

- [ ] **Step 1: Add failing tests.** Mixed Python+JS full Python evidence permits a reviewed Python no-candidate `MISSED` while run remains `PARTIAL`; a Python parse/rule gap and an insufficient surface remain `INCOMPLETE`; a final or initial `HOLD` cannot become `MISSED`; corrupt PoC cannot become `DETECTED`.
- [ ] **Step 2: Run new tests red** using a new `..\pytest-recall-t2-red` basetemp.
- [ ] **Step 3: Implement the three interfaces without weakening hash/currentness checks.** `PARTIAL` is never promoted on the analysis run itself; only case audit eligibility changes.
- [ ] **Step 4: Run both existing evaluation files green** with `..\pytest-recall-t2-green`, then commit Task 2 paths.

### Task 3: Strict Case-Level Score and Finding-Level Review

**Files:**
- Create: `src/sastsimi/simple_runtime/recall_scoring.py`
- Modify: `tools/recall_audit.py` (`--review` and `--score` opt-in)
- Create: `tests/unit/evaluation/test_recall_scoring.py`
- Modify: `tests/unit/evaluation/test_recall_audit_cli.py`

**Interfaces:**
- `score_analysis(data_dir: Path, analysis_id: str, oracle: Oracle, oracle_bytes: bytes, review: ReviewLedger) -> RecallScore` verifies `analysis_id`, SHA-256, current `F-NNN` refs via `FindingDisplayIdStore.resolve_existing`, and exact hypothesis/Finding refs before using `audit_analysis` output.
- JSON `case_counts` includes `TP`, `FN`, `HOLD`, `OUT_OF_SCOPE`, `REVIEW_REQUIRED`; `finding_counts` includes `FP` and `UNMATCHED_REVIEW_REQUIRED`. `recall` is `null` if any in-scope HOLD/review case remains or oracle completeness is `UNDECLARED`; otherwise `TP/(TP+FN)` with label `documented_cases` or `exhaustive_python_declared`.
- `--score` requires `--review` and v2 oracle; default CLI JSON stays backward compatible. No review input ever changes saved DB state.

- [ ] **Step 1: Add failing score tests.** Two current verified Findings mapped to one case give one TP; an independently reviewed complete `MISSING_GUARD` case without matching Finding gives FN; environmental block gives HOLD; predeclared nonPython sink gives OUT_OF_SCOPE; unmatched Finding is not FP; explicit evidence-backed false-positive adjudication gives one FP; duplicate Finding-to-case assignment, wrong review analysis/oracle hash and stale `F-NNN` ref fail closed; incomplete oracle never prints repository-wide recall.
- [ ] **Step 2: Run score tests red** with `..\pytest-recall-t3-red`.
- [ ] **Step 3: Implement scorer and CLI flags** using the exact interfaces; avoid opening SQLite in write mode or calling any allocating display-ID method.
- [ ] **Step 4: Run evaluation tests green** with `..\pytest-recall-t3-green`, verify DB and artifact directory fingerprints unchanged, then commit Task 3 paths.

### Task 4: Frozen Benchmark, Blind Trial, and Conditional Python Fix

**Files:**
- Create: `docs/validation/2026-10-08-python-recall-methodology.md`
- Create only independently reviewed, portable oracle/review files under `tests/evaluation/oracles/` and `docs/validation/` as appropriate; never include private paths, secrets, or unpublished exploitation detail.
- Conditional modify: only the proven first-gap module (`config/static-analysis/candidate-v1/opengrep/rules.yml`, `src/sastsimi/simple_runtime/attack_surfaces.py`, `src/sastsimi/simple_runtime/discovery.py`, or `src/sastsimi/simple_runtime/file_context.py`) plus its existing focused tests.

**Interfaces:**
- The frozen oracle and provenance identify the exact repository+commit, whether its case list is merely documented or exhaustively reviewed, and the SHA-256 before analysis. The post-run review ledger is a separate file. Published trial tables show TP/FN/HOLD/OUT_OF_SCOPE/review count, candidate/hypothesis/PoC stages, raw Finding and display-group count separately.

- [ ] **Step 1: Source-review DSVPWA and freeze its oracle/provenance before a fresh run.** Use `https://github.com/sgabe/DSVPWA.git` at `c98b77950bf1c54080c4113a2488ce0509b21cff`. Its README lists 12 classes, but only source-reviewed Python product-code cases belong in the Python denominator; classes requiring template/transport behavior get explicit scope/condition labels. Existing BreakableFlask route matches and vFAPI examples remain historical context, not automatically confirmed TP or whole-repository recall. The older, different DVPWA environment HOLD is not a FN.
- [ ] **Step 2: Run DSVPWA blind with the current main-derived tool and record the read-only audit/review baseline.** Do not pass oracle/review paths to `sastsimi analyze` or Agent inputs. Record exact commit, profile/model, analysis ID, run status, first gap per case and usage. Keep VulnShop (`https://github.com/dev-abhrajit/VulnShop.git` at `f201193cbd3987b62050ba32357071aec0f61c18`) untouched as the holdout until after any fix; its template-only XSS sink is not a Python TP/FN case.
- [ ] **Step 3: If a Python FN is actually confirmed, write its failing regression test in the first-gap module, run red, make the smallest repository-agnostic change, run green and rerun the same pinned DSVPWA case.** Freeze a separately source-reviewed VulnShop oracle before its first run; then run that holdout once without feeding its answers to Agents. If there is no confirmed FN, or the only issue is HOLD/out-of-scope, leave runtime detection rules unchanged and document why; do not manufacture a claimed recall gain.
- [ ] **Step 4: Test negative controls for the changed class** (safe parameterized SQL, sanitizer, distinct flows), record TP/FN and duplicate-group before/after without claiming zero FN, then commit trial evidence and any verified minimal fix.

### Task 5: README and Final Verification

**Files:**
- Modify: `README.md`
- Modify when needed: `docs/usage.md`, `docs/troubleshooting.md`, `docs/README.md`
- Test: command/help checks and full repo tests.

**Interfaces:** README contains Python product-code scope, concise PowerShell one-line commands, verdict meanings, truthful validation limits and links. Detailed migration/recovery text stays in docs, not removed from the project.

- [ ] **Step 1: Rewrite README from fetched main** to a short purpose→workflow→install/setup/analyze→interpretation→artifacts/docs structure. Include `COMPLETE` not equal no vulnerabilities; `PARTIAL` for uncovered Python/nonPython product code; scope/policy review before reporting. Do not claim a measured recall value unless Task 4 supports it.
- [ ] **Step 2: Verify commands against CLI help** and test docs links; run Ruff, mypy and all pytest tests with a fresh unique workspace-local basetemp. Fix only regressions caused by this branch.
- [ ] **Step 3: Request independent code review**, resolve actionable findings, rerun affected and full checks, then commit documentation/final fixes.
- [ ] **Step 4: Push `codex/python-recall-final`, open a PR against main, attach it to this task, and verify CI.** Report exact observed benchmark numerator/denominator, HOLD/out-of-scope counts, remaining limits, and PR link; never call an unrun check passing.
