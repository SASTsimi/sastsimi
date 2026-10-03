# Offline PoC Environment and Real-repository E2E Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Supply reproducible, offline Python dependencies to PoC Docker builds and verify the complete analysis/report path on fixtures and two pinned real repositories.

**Architecture:** A profile may name a local TAR of wheels and its SHA-256. Validate it before importing it into analysis-owned content-addressed storage, then build from an isolated TAR context containing only pinned checkout files and validated wheels. Keep both Docker build and PoC container offline; unsupported requirements remain explicit environment blocks. Perform final E2E after the companion AST/context plan.

**Tech Stack:** Python 3.12, `tarfile`, `packaging` wheel tags, Docker CLI, Pydantic, pytest, PowerShell.

**Spec:** `docs/plans/2026-10-02-real-repository-e2e-hardening-design.md`

## Global Constraints

- Work in the isolated PR #209 branch; do not modify the original Dify analysis or the user's checkout/data.
- The wheel archive and expected digest are operator-supplied. Product code never downloads from PyPI, grants Docker build networking, or logs archive contents/secrets.
- Build with `--network none`; install with `pip --no-index --find-links`; create/run PoC containers with `--network none`.
- A failed/missing dependency, incompatible wheel, unsupported sdist/VCS/apt/uv route, or degraded source-only image remains `BLOCKED`, never `DISPROVED` or `confirmed`.
- An old nonretryable Flask PoC checkpoint is immutable; test the new dependency mode with a new isolated analysis ID.
- A real benign run may have zero findings; only executed PoC plus accepted technical/scope gates can yield a submission-ready report.

## Review Focus

1. Symlinked or changing Windows archive path must not bypass regular-file, size, or SHA-256 checks (Task 1).
2. TAR traversal, duplicate/case-colliding wheel names, links, secret-like names, and decompression bombs must be rejected before CAS import or build (Task 1).
3. Windows host tags must not decide Linux wheel compatibility; unknown target tags or incompatible wheels must block precisely (Task 2).
4. A changed bundle/manifest/commit/Dockerfile/base-image/network setting must never reuse an image from the old recipe (Task 3).
5. Missing transitive/build dependencies and old nonretryable checkpoints must not become false PoC verdicts or silently rerun (Tasks 3–4).

## File map

- `src/sastsimi/config/user_config.py`: optional archive path/digest fields in the existing execution profile and TOML round-trip.
- New `src/sastsimi/simple_runtime/offline_wheels.py`: bounded archive import, wheel-name/tag validation, immutable bundle record.
- `src/sastsimi/simple_runtime/portable_docker.py`: isolated TAR build context, offline dependency layer, complete recipe/cache identity.
- `src/sastsimi/composition/simple_runtime_composition.py`: pass profile bundle settings into `DirectEnvironmentPreparer`.
- `src/sastsimi/simple_runtime/stages.py`: retain the environment gate and distinguish unsupported offline requirements.
- `pyproject.toml`: direct `packaging>=24,<27` dependency for wheel filename and tag parsing.
- `README.md` and focused runtime docs: PowerShell setup, SHA-256, safe limits, blocked/resume behavior, and proven E2E evidence.
- Tests: `tests/unit/config/test_user_config.py`, `tests/unit/simple_runtime/test_portable_docker.py`, `test_poc_execution.py`, new `test_offline_wheels.py`, `tests/simple_runtime/test_simple_report.py`, and `tests/integration/orchestration/test_streaming_candidate_pipeline.py`.

---

### Task 1: Optional profile pair and bounded archive import

**Files:** Modify `src/sastsimi/config/user_config.py`, `pyproject.toml`; create `src/sastsimi/simple_runtime/offline_wheels.py`; test `tests/unit/config/test_user_config.py`, new `tests/unit/simple_runtime/test_offline_wheels.py`.

**Interfaces:** Add `poc_wheel_archive_path: Path | None = None` and `poc_wheel_archive_sha256: str | None = None` to `SimpleExecutionProfile`, requiring both or neither and a lowercase 64-hex digest. Define `VerifiedWheelBundle(archive_ref: StoredDataRef, archive_sha256: str, wheel_names: tuple[str, ...])` and `import_wheel_bundle(path: Path, expected_sha256: str, artifacts: SimpleArtifactRepository, *, target_tags: frozenset[str] | None = None) -> VerifiedWheelBundle`. Cap input and expanded content at 64 MiB and 20,000 regular wheel files as in the existing dependency-bundle validator; reject unsafe/colliding names and non-universal wheels without target proof before persisting the exact archive bytes.

- [ ] **Step 1: Write failing tests** `test_old_profile_without_bundle_round_trips`, `test_profile_requires_path_and_digest_together`, `test_archive_rejects_symlink_digest_mismatch_and_oversize`, and `test_archive_rejects_traversal_links_duplicate_casefold_names_and_non_wheels`; assert no bundle ref is created on failure.
- [ ] **Step 2: Verify red** with `& 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe' -m pytest tests/unit/config/test_user_config.py tests/unit/simple_runtime/test_offline_wheels.py -q`.
- [ ] **Step 3: Implement** the profile pair, stable TOML serialization, the direct `packaging>=24,<27` dependency, and safe TAR importer. Use `packaging.utils.parse_wheel_filename` for wheel syntax; do not use host `packaging.tags.sys_tags()` as the target-compatibility decision.
- [ ] **Step 4: Verify green** with the same command.
- [ ] **Step 5: Commit** with `git commit -m "feat: validate operator-provided offline wheel bundles"`.

### Task 2: Target compatibility and immutable offline build input

**Files:** Modify `src/sastsimi/simple_runtime/offline_wheels.py`, `portable_docker.py`; test `tests/unit/simple_runtime/test_offline_wheels.py`, `test_portable_docker.py`.

**Interfaces:** Add `require_target_compatible_wheels(wheel_names: tuple[str, ...], target_tags: frozenset[str] | None) -> None` and `async PortableDockerRuntime.target_wheel_tags(base_image: str) -> frozenset[str] | None`; query the actual Linux Python base image without network or mounts, or admit only universal `py3-none-any` wheels when target proof is unavailable. The importer calls compatibility validation **before** CAS persistence. Extend `PortableDockerRuntime.build_or_reuse(..., context_archive: bytes | None = None) -> str` so archive mode sends a verified TAR containing `Dockerfile`, pinned tracked checkout bytes, and wheels to `docker build --file Dockerfile -`; directory mode retains current behavior when no bundle is configured. Reject a context larger than 64 MiB before invoking Docker.

- [ ] **Step 1: Write failing tests** `test_linux_target_accepts_matching_and_universal_wheels`, `test_windows_host_does_not_reject_linux_wheel`, `test_unknown_target_rejects_platform_wheel`, `test_archive_context_has_only_pinned_checkout_and_wheels`, `test_archive_context_rejects_source_symlink_or_changed_content`, and `test_tar_build_uses_network_none`.
- [ ] **Step 2: Verify red** with `& 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_offline_wheels.py tests/unit/simple_runtime/test_portable_docker.py -q`.
- [ ] **Step 3: Implement** target-tag proof and bounded immutable TAR construction, reusing the tracked-file/context safety pattern in `sandbox/recipe_store.py`; never write wheels into the checkout. Fail closed when the target platform cannot be established for a non-universal wheel.
- [ ] **Step 4: Verify green** with the same command.
- [ ] **Step 5: Commit** with `git commit -m "feat: build PoC images from isolated offline context"`.

### Task 3: Offline install, complete cache identity, and truthful failure

**Files:** Modify `src/sastsimi/simple_runtime/portable_docker.py`, `src/sastsimi/composition/simple_runtime_composition.py`, `src/sastsimi/simple_runtime/stages.py`; test `tests/unit/simple_runtime/test_portable_docker.py`, `test_poc_execution.py`.

**Interfaces:** `DirectEnvironmentPreparer(..., wheel_bundle_path: Path | None = None, wheel_bundle_sha256: str | None = None)` imports the approved archive after networkless target proof. In bundle mode, require `docker_network=NONE`, use a generated Python 3.12-slim Dockerfile rather than executing a repository Dockerfile, install with `pip --no-index --find-links`, and bind the recipe/cache key to archive digest, dependency manifest digest, commit, Dockerfile digest, inspected base-image digest, and build-network mode. Keep `GENERATED_NO_INSTALL` ineligible for a valid PoC verdict; expose precise environment error codes for unresolved transitive/build requirements and unsupported installation routes.

- [ ] **Step 1: Write failing tests** `test_bundle_mode_installs_without_index_or_build_network`, `test_bundle_mode_rejects_bridge_setting`, `test_cache_separates_changed_archive_manifest_commit_dockerfile_base_image_and_network`, `test_missing_transitive_dependency_is_blocked_not_disproved`, `test_unsupported_uv_apt_vcs_and_sdist_are_blocked`, and `test_poc_container_remains_network_none`.
- [ ] **Step 2: Verify red** with `& 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe' -m pytest tests/unit/simple_runtime/test_portable_docker.py tests/unit/simple_runtime/test_poc_execution.py -q`.
- [ ] **Step 3: Implement** the opt-in install/recipe path and profile injection; preserve the current no-bundle path and existing strict environment gate. Do not reopen old nonretryable attempts when profile settings change.
- [ ] **Step 4: Verify green** with the same command and `& 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe' -m mypy src/sastsimi/simple_runtime src/sastsimi/config src/sastsimi/composition`.
- [ ] **Step 5: Commit** with `git commit -m "feat: verify offline PoC dependency environment"`.

### Task 4: Full handoff fixture and resume safety

**Files:** Modify `tests/integration/orchestration/test_streaming_candidate_pipeline.py`, `tests/simple_runtime/test_simple_report.py`, `tests/unit/simple_runtime/test_poc_execution.py`.

**Interfaces:** Use deterministic fake Agent/Docker adapters to cover candidate-to-hypothesis-to-Pro/Con-to-PoC-to-verdict-to-technical/scope-gates-to-bilingual-bundle. The fixture may prove the plumbing, never a real-repository vulnerability. Assert exact `report_en.md`, `report_kr.md`, PoC and `evidence/` entries only after validated reproduction and gates.

- [ ] **Step 1: Write failing tests** `test_validated_fixture_exports_exact_bilingual_bundle`, `test_benign_fixture_finishes_without_finding`, `test_interrupted_resume_skips_completed_agents`, and `test_old_flask_nonretryable_checkpoint_is_not_reopened`.
- [ ] **Step 2: Verify red** with `& 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe' -m pytest tests/integration/orchestration/test_streaming_candidate_pipeline.py tests/simple_runtime/test_simple_report.py tests/unit/simple_runtime/test_poc_execution.py -q`.
- [ ] **Step 3: Implement** `build_handoff_harness(tmp_path: Path, *, poc_validated: bool, gates_accepted: bool) -> tuple[SimpleAnalysisApplication, CheckpointIdentity]` in the integration test module using the existing fake Agent/Docker ports. Bind every fake result to the exact static/PoC/gate refs; if a production handoff rejects a valid fixture, add a focused failing assertion for that handler before its minimal repair.
- [ ] **Step 4: Verify green** with the same command.
- [ ] **Step 5: Commit** with `git commit -m "test: cover end-to-end PoC and report handoff"`.

### Task 5: Two real trials, documentation, and PR evidence

**Files:** Modify `README.md` and the existing installation/runtime documentation appropriate to the verified behavior; create a brief run-evidence note under `docs/verification/` only if it excludes sensitive code/logs.

**Interfaces:** After the AST/context plan and Tasks 1–4 pass, run new pinned Flask and simpleeval analyses in isolated data directories with branch-source CLI. Record commit, tool bindings, static coverage, candidate/surface/hypothesis counts, PoC status, token use, scope gate, findings, report paths, and unresolved limits. Never reuse the blocked Flask PoC ID as proof of the new environment mode.

- [ ] **Step 1: Run focused regression** for both plans and document exact commands/results; do not claim success from an unfinished run.
- [ ] **Step 2: Run isolated real trials** with explicit wheel digest/target proof for Flask and fresh simpleeval ID; record actual terminal status or precise block without converting it to `COMPLETE`.
- [ ] **Step 3: Run full available suite and checks**: `& 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe' -m pytest -q`, `& 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe' -m ruff check .`, and `& 'C:\Users\taehy\Desktop\WHS\프로젝트\sastsimi\.venv\Scripts\python.exe' -m mypy src`; record skip count and failures.
- [ ] **Step 4: Update docs** with PowerShell one-line profile/archive/hash commands, dependency limitations, resume semantics, and only verified E2E claims; run link/command spot-checks.
- [ ] **Step 5: Commit and update PR #209** only after `git diff --check`, branch review, and CI status. Keep PR draft and report blockers if either real-world E2E remains blocked; do not merge or claim general reliability without evidence.
