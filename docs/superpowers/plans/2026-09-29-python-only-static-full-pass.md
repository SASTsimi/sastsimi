# Python-only static scope and complete scan passes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Analyze only deployable `.py` source while attempting every planned bounded static scan chunk and reusing verified evidence on resume.

**Architecture:** Keep the existing source-scope, coverage and evidence ledgers. Narrow the shared static source set, preserve non-code metadata through its separate verified manifest, remove the aggregate scan-pass clock, and add byte-aware Semgrep chunks. No new scheduler or status type is introduced.

**Tech Stack:** Python 3.12, Pydantic, pytest, OpenGrep, Semgrep CE, Python CodeQL, SQLite.

**Spec:** `docs/superpowers/specs/2026-09-29-python-only-static-full-pass-design.md`

## Global Constraints

- Static source is deployable `*.py` only; test-only paths and `.pyi` are excluded.
- Keep full Git safety, policy, dependency and PoC inputs; do not delete repository files.
- Remove the 180-second aggregate OpenGrep/Semgrep pass deadline, not finite per-call timeouts or cancellation.
- OpenGrep stays at 64 files/512 KiB; Semgrep adds 512 KiB to its existing 128-file/command-size limits.
- Only validated successful file×rule evidence is reused; unresolved pairs remain PARTIAL, not COMPLETE.
- Existing evidence-size/candidate safety ceilings may halt work with explicit unverified reasons; zero verified coverage remains BLOCKED.
- Run local-only analysis of an exact python-multipart commit after tests; do not submit findings automatically.

## Review Focus

1. A repository with JS plus one Python file must have only the Python file in static targets and the denominator (Task 1/2 tests).
2. An all-non-Python repository must fail clearly, rather than produce zero-work COMPLETE (Task 2 test).
3. A Python file with a very long path or more than 512 KiB must receive one finite attempt or an explicit unverified reason, never disappear (Task 4 test).
4. A legacy config containing `static_scan_pass_seconds = 180` must not silently reinstate the pass deadline (Task 3 test).
5. A cancelled child scan or corrupt cached artifact must never be reported as a verified file×rule success (Task 4/5 tests).
6. A JS-only repository with malformed `package.json` must report no Python source, not a JS metadata parsing error (Task 1 test).

---

### Task 1: Python-only source scope and preserved metadata

**Files:** Modify `src/sastsimi/static_analysis/file_scope.py`, `src/sastsimi/static_analysis/repository_profile.py`; test `tests/unit/static_analysis/test_file_scope.py`, `tests/unit/static_analysis/test_repository_profile.py`.

**Interfaces:** Preserve `build_static_file_scope(workspace: Path, tracked: Sequence[str]) -> StaticFileScope`; `selected_paths` becomes `.py` only and `fingerprint` changes via a policy version bump. Repository profile reads safe configuration/dependency manifests from full verified tracked paths, not this narrower source set.

- [ ] Write tests for mixed languages, `.pyi`, test-like declared entrypoints, same-scope fingerprint after non-Python addition, malformed JS-only manifest, and preserved `pyproject.toml` metadata.
- [ ] Run these tests and confirm expected RED behavior.
- [ ] Implement the minimal scope/filter and metadata split; do not change checkout contents.
- [ ] Run the focused tests and confirm GREEN.

### Task 2: One scope across simple/production engines and Agent evidence

**Files:** Modify `src/sastsimi/simple_runtime/bootstrap_stages.py`, `src/sastsimi/simple_runtime/static_coverage.py`, `src/sastsimi/simple_runtime/feeding.py`, `src/sastsimi/orchestration/static_work_handlers.py`, `src/sastsimi/static_analysis/codeql_provision_source.py`; test `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`, `tests/unit/simple_runtime/test_static_coverage.py`, `tests/unit/orchestration/test_static_work_handlers.py`.

**Interfaces:** Consume Task 1 `StaticFileScope.selected_paths` for AST/OpenGrep/Semgrep/CodeQL/hypothesis Agent source. Keep a separate full verified source permission for PoC setup and policy/build data. No new file×rule report schema.

- [ ] Write tests proving only `.py` reaches each engine and hypothesis Agent retrieval, PoC can still read verified Docker/config inputs, JS rules have no expected pairs, CodeQL stages only `.py`, zero Python source returns `NO_PYTHON_SOURCE`, and zero applicable rules fails `NO_PYTHON_RULES`.
- [ ] Run the focused tests and confirm expected RED behavior.
- [ ] Make the smallest downstream changes needed to use the shared Python source set in both runtimes.
- [ ] Run focused tests and confirm GREEN, including old-scope resume invalidation.

### Task 3: Remove the aggregate pass clock while keeping finite calls

**Files:** Modify `src/sastsimi/simple_runtime/bootstrap_stages.py`, `src/sastsimi/config/user_config.py`, `src/sastsimi/interfaces/cli/main.py`; test `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`, `tests/unit/config/test_user_config.py` and existing CLI setup tests.

**Interfaces:** Legacy `static_scan_pass_seconds` may parse but has no scheduling effect and is absent from newly emitted TOML. OpenGrep and Semgrep nodes remain capped at 120 seconds; CodeQL create/analyze use an independent 1800-second cap.

- [ ] Write tests showing cumulative OpenGrep and Semgrep time beyond 180 seconds still attempts later chunks, legacy TOML does not restore the deadline, and CodeQL call timeout remains finite.
- [ ] Run tests and confirm expected RED behavior.
- [ ] Remove only pass-deadline calculations/checks, decouple CodeQL, and stop emitting the deprecated setting.
- [ ] Run focused tests and confirm GREEN.

### Task 4: Byte-aware Semgrep chunks and finite timeout leaves

**Files:** Modify `src/sastsimi/simple_runtime/bootstrap_stages.py` using `src/sastsimi/simple_runtime/semgrep_fallback_plan.py`; test `tests/integration/orchestration/test_simple_runtime_static_bootstrap.py`, `tests/unit/simple_runtime/test_semgrep_fallback_plan.py`.

**Interfaces:** `split_target_chunks_by_source_bytes(roots, size_for, max_bytes=512*1024)` augments existing target-count/command planning. Existing timeout split and cache ledgers remain authoritative.

- [ ] Write tests for count/byte boundaries, oversized singleton, timeout down to a single file, no unbounded same-run retry, and a safety candidate cap recording unverified work rather than COMPLETE.
- [ ] Run tests and confirm expected RED behavior.
- [ ] Apply byte splitting and preserve existing finite node/leaf semantics.
- [ ] Run focused tests and confirm GREEN.

### Task 5: Resume, cancellation, documentation and live run

**Files:** Extend existing integration tests; update `README.md`, `docs/usage.md`, `docs/troubleshooting.md` and relevant setup documentation.

**Interfaces:** Existing exact evidence ledger, PARTIAL status, dashboard and report coverage payloads; no new public command.

- [ ] Write tests for cancelling after a successful chunk, resume skipping its verified pairs, corrupt artifact not reused, parser/partial-scan gaps retried on explicit resume, and unresolved Python pair retained as PARTIAL.
- [ ] Run tests and confirm expected RED behavior where a gap exists; avoid duplicating already-proven tests.
- [ ] Complete minimal fixes, then run focused tests and the full project pytest suite; record any failures honestly.
- [ ] Update documentation to say Python-only, no aggregate pass deadline, finite calls, cancellation, resume and PARTIAL semantics.
- [ ] Pin python-multipart to an exact Git commit, run setup/doctor as needed, start local analysis, and record analysis ID, static coverage and errors. Never claim a confirmed finding without PoC and review.
