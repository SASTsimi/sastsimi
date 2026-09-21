# Legacy Fake Pipeline Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the executable legacy Fake analysis pipeline so the installed product exposes and tests only the real `SimpleRuntime` analysis path.

**Architecture:** Keep `SimpleRuntime`, shared contracts, real adapters, checkpoint storage, the read-only dashboard, and report export as the product graph. Remove Fake/demo entry points first, then delete the now-unreachable Fake implementation closure and its end-to-end tests; small test-local stubs remain because they do not create an alternate product runtime.

**Tech Stack:** Python 3.12, argparse, Pydantic, SQLAlchemy, pytest, Ruff, mypy, GitHub Actions

**Spec:** `docs/superpowers/specs/2026-09-21-legacy-fake-pipeline-isolation-design.md`

## Global Constraints

- `SimpleRuntime` is the only user-facing repository-analysis runtime.
- Preserve real Provider, OpenGrep, CodeQL, Docker, checkpoint/resume, dashboard, Finding, PoC, Gate, and Markdown-report behavior.
- Do not remove test-local `FakeRunner`, `StubClient`, or in-memory test doubles that do not expose a Fake analysis product path.
- Never convert tool, authentication, environment, or runtime errors into vulnerability `FALSE`.
- A final `TRUE` still requires a successfully executed validated PoC with exact analysis, hypothesis, attempt, and record references.
- Do not weaken Sandbox boundaries, sensitive-data filtering, exact-reference validation, or stale-result rejection.
- Do not delete existing analysis data, Provider credentials, or user configuration.
- Run focused tests during tasks and the full quality/test suite only once after all implementation tasks.

## Review Focus

- An installed CLI invocation of `sastsimi demo` must fail as an unknown command while `setup`, `analyze`, `resume`, `status`, `result`, `poc`, `report`, and `dashboard` remain available; Task 1 pins this.
- Removing bootstrap exports must not break production database, query, report, or SimpleRuntime composition imports; Tasks 1 and 2 pin this with import and CLI tests.
- Product modules must not retain static or dynamic imports of deleted Fake modules; Task 2 pins this by scanning parsed production imports and importing the public facade.
- Test-local doubles must remain usable while Fake pipeline E2E tests disappear; Task 3 pins this with representative SimpleRuntime normal and blocked/resume tests.
- README and operator documents must not suggest Fake/demo output as production evidence or claim removed commands still exist; Task 4 pins this with documentation contract tests.

---

### Task 1: Remove the public Fake/demo surface

**Files:**
- Modify: `tests/unit/interfaces/test_public_simple_cli.py`
- Create: `tests/contract/test_product_runtime_surface.py`
- Modify: `src/sastsimi/interfaces/cli/main.py`
- Delete: `src/sastsimi/interfaces/cli/demo.py`
- Delete: `src/sastsimi/interfaces/cli/results.py`
- Modify: `src/sastsimi/bootstrap.py`
- Modify: `src/sastsimi/composition/runtime.py`

**Interfaces:**
- Consumes: `main(argv: list[str] | None, ...) -> int`, existing SimpleRuntime public command application, and the production exports in `sastsimi.bootstrap`.
- Produces: a CLI parser with no `demo` subcommand and a bootstrap facade with no `build_fake_pipeline` or `load_fake_progress` attributes.

- [ ] **Step 1: Write the failing public-surface tests**

```python
def test_demo_is_not_a_public_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["demo", "analyze", "--scenario", "TRUE"]) == 2
    assert "INVALID_INPUT" in capsys.readouterr().err


def test_bootstrap_does_not_export_fake_pipeline() -> None:
    import sastsimi.bootstrap as bootstrap

    assert not hasattr(bootstrap, "build_fake_pipeline")
    assert not hasattr(bootstrap, "load_fake_progress")
```

- [ ] **Step 2: Run the tests and verify RED**

Run: `uv run pytest tests/unit/interfaces/test_public_simple_cli.py::test_demo_is_not_a_public_command tests/contract/test_product_runtime_surface.py::test_bootstrap_does_not_export_fake_pipeline -q`

Expected: FAIL because `demo` is still registered and both Fake bootstrap exports exist.

- [ ] **Step 3: Remove the public parser, dispatcher, and facade exports**

Delete the `demo` import, parser construction, and dispatch branch from `interfaces/cli/main.py`; delete the two Fake-only CLI modules; remove `build_fake_pipeline` and `load_fake_progress` from `bootstrap.py` and their implementations plus Fake-only type imports from `composition/runtime.py`. Leave every production database, query, static-analysis, reporting, and SimpleRuntime export unchanged.

- [ ] **Step 4: Run the public-surface tests and verify GREEN**

Run: `uv run pytest tests/unit/interfaces/test_public_simple_cli.py tests/contract/test_product_runtime_surface.py -q`

Expected: PASS; the compact production commands still work and Fake/demo is absent.

- [ ] **Step 5: Commit the public-surface removal**

```bash
git add src/sastsimi/interfaces/cli/main.py src/sastsimi/bootstrap.py src/sastsimi/composition/runtime.py tests/unit/interfaces/test_public_simple_cli.py tests/contract/test_product_runtime_surface.py
git add -u src/sastsimi/interfaces/cli/demo.py src/sastsimi/interfaces/cli/results.py
git commit -m "refactor: remove public fake pipeline surface"
```

### Task 2: Delete the Fake product dependency closure

**Files:**
- Delete: `src/sastsimi/chaining/fake_runtime.py`
- Delete: `src/sastsimi/orchestration/fake_pipeline.py`
- Delete: `src/sastsimi/orchestration/fake_scenario_runtime.py`
- Delete: `src/sastsimi/orchestration/fake_setup.py`
- Delete: `src/sastsimi/orchestration/fake_static_runtime.py`
- Delete: `src/sastsimi/policy/fake_runtime.py`
- Delete: `src/sastsimi/ports/fake_workflow.py`
- Delete: `src/sastsimi/providers/fake.py`
- Delete: `src/sastsimi/reproduction/fake_closure.py`
- Delete: `src/sastsimi/runtime/fake_llm_configuration.py`
- Delete: `src/sastsimi/runtime/fake_llm_invocation.py`
- Delete: `src/sastsimi/runtime/fake_support.py`
- Delete: `src/sastsimi/sandbox/fake.py`
- Delete: `src/sastsimi/static_analysis/fake.py`
- Delete: `src/sastsimi/storage/fake_action_validator.py`
- Delete: `src/sastsimi/verification/fake_assembly.py`
- Delete: `src/sastsimi/verification/fake_child_registration.py`
- Modify: `src/sastsimi/chaining/__init__.py`
- Modify: `src/sastsimi/orchestration/__init__.py`
- Modify: `src/sastsimi/policy/__init__.py`
- Modify: `src/sastsimi/reproduction/__init__.py`
- Modify: `src/sastsimi/sandbox/__init__.py`
- Modify: `src/sastsimi/static_analysis/__init__.py`
- Modify: `src/sastsimi/verification/__init__.py`
- Modify or delete according to product reachability: `src/sastsimi/evaluation/service.py`, `src/sastsimi/verification/service.py`, `src/sastsimi/verification/debate_service.py`, `src/sastsimi/verification/context_service.py`, `src/sastsimi/chaining/service.py`, `src/sastsimi/policy/service.py`, `src/sastsimi/reproduction/service.py`, `src/sastsimi/reporting/service.py`
- Modify: `tests/contract/test_product_runtime_surface.py`
- Modify: `tests/contract/test_architecture_imports.py`

**Interfaces:**
- Consumes: production reachability rooted at `sastsimi.interfaces.cli.main`, `sastsimi.bootstrap`, and `sastsimi.composition.simple_runtime_composition`.
- Produces: an importable production package with no `src/sastsimi/**/fake*.py`, no product import of `fake_*` modules, and unchanged shared contract/service APIs used by `SimpleRuntime`.

- [ ] **Step 1: Add a failing AST-based product-source guard**

```python
def test_product_source_contains_no_fake_pipeline_modules_or_imports() -> None:
    source_root = Path("src/sastsimi")
    fake_files = sorted(path.as_posix() for path in source_root.rglob("fake*.py"))
    assert fake_files == []
    violations = scan_imports_for_fake_modules(source_root)
    assert violations == []
```

Implement `scan_imports_for_fake_modules` in the same test with `ast.parse`, rejecting imports whose module path contains a component beginning with `fake`, but ignoring string literals and class names in tests because this scan covers only `src/sastsimi`.

- [ ] **Step 2: Run the guard and verify RED**

Run: `uv run pytest tests/contract/test_product_runtime_surface.py::test_product_source_contains_no_fake_pipeline_modules_or_imports -q`

Expected: FAIL and list the existing Fake product modules/imports.

- [ ] **Step 3: Compute and record product reachability before deleting shared-looking services**

Run: `rg -n "evaluation\.service|verification\.(service|debate_service|context_service)|chaining\.service|policy\.service|reproduction\.service|reporting\.service" src/sastsimi tests --glob '*.py'`

Expected: output identifies whether each service is used by `SimpleRuntime` or only by the legacy pipeline. For a reachable service, replace Fake-specific helper types with the existing generic port/contract types it already consumes; for an unreachable service, delete it and remove only its package export. Record each choice in the execution ledger before editing.

- [ ] **Step 4: Remove the Fake closure and clean package exports**

Delete the exact Fake modules listed above. Remove package-level exports that point to them. Preserve generic contracts, runtime validators, production adapters, and any service shown reachable from the SimpleRuntime composition root; such a retained service must contain no Fake-module import after this step.

- [ ] **Step 5: Run package import, source guard, type, and architecture checks**

Run: `uv run pytest tests/contract/test_product_runtime_surface.py tests/contract/test_architecture_imports.py -q`

Expected: PASS with no deleted-module import failures and no product Fake module/import violations.

Run: `uv run mypy src/sastsimi`

Expected: `Success: no issues found`.

- [ ] **Step 6: Commit the dependency-closure removal**

```bash
git add src/sastsimi tests/contract/test_product_runtime_surface.py tests/contract/test_architecture_imports.py
git commit -m "refactor: delete legacy fake product runtime"
```

### Task 3: Remove Fake pipeline tests while preserving real regression coverage

**Files:**
- Delete: `tests/e2e/test_fake_chaining_pipeline.py`
- Delete: `tests/e2e/test_fake_cli.py`
- Delete: `tests/e2e/test_fake_false_pipeline.py`
- Delete: `tests/e2e/test_fake_hold_pipeline.py`
- Delete: `tests/e2e/test_fake_revise_pipeline.py`
- Delete: `tests/e2e/test_fake_true_pipeline.py`
- Delete: `tests/contract/test_fake_workflow_ownership.py`
- Delete: `tests/unit/test_fake_adapters.py`
- Delete: `tests/unit/reproduction/test_fake_cleanup_closure.py`
- Delete: `tests/unit/reproduction/test_fake_poc_closure.py`
- Delete or rewrite Fake-pipeline-only cases in: `tests/e2e/test_real_chaining_slice.py`, `tests/integration/static_analysis/test_static_join.py`, `tests/integration/static_analysis/test_repository_profile_handler.py`, `tests/integration/recovery/test_chaining_commit.py`, `tests/integration/chaining/test_input_universe.py`, `tests/integration/chaining/test_batch_registration.py`, `tests/integration/storage/test_verification_registration.py`, `tests/integration/storage/test_typed_configuration_registry.py`, `tests/unit/interfaces/test_production_analyze_cli.py`
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/simple_runtime/test_simple_analysis_application.py`
- Modify: `tests/simple_runtime/test_simple_chaining.py`

**Interfaces:**
- Consumes: `SimpleAnalysisApplication.analyze`, `.resume`, SimpleRuntime checkpoints, real chaining proposal output, and validated-PoC/report completion behavior.
- Produces: a product-focused test suite whose normal path and blocked/resume path exercise SimpleRuntime without constructing the deleted Fake pipeline.

- [ ] **Step 1: Add focused regression assertions to the SimpleRuntime tests**

Add one normal-flow assertion that a completed analysis reaches `REPORT_DONE` with an `F-` display Finding and current Markdown report, and one failure assertion that an execution/provider failure produces `BLOCKED` or `FAILED`, never `FALSE`, and resumes from its failed stage without re-running a completed static stage.

- [ ] **Step 2: Run the focused regression tests before deleting legacy tests**

Run: `uv run pytest tests/simple_runtime/test_simple_analysis_application.py tests/simple_runtime/test_simple_chaining.py -q`

Expected: PASS, proving replacement coverage already exists or has been added before legacy deletion.

- [ ] **Step 3: Delete Fake-only tests and remove Fake-only cases from mixed files**

Delete the exact Fake test files above. In mixed files, remove only cases whose fixture or body calls `build_fake_pipeline`; retain repository profiling, normalization, storage, chaining, and security tests that build their subject directly. Remove CI shard paths that name deleted tests, without reducing checks for SimpleRuntime, contracts, security negatives, reporting, or real adapters.

- [ ] **Step 4: Verify no test imports the deleted product API**

Run: `rg -n "build_fake_pipeline|load_fake_progress|FakeScenarioRuntime|sastsimi\.interfaces\.cli\.demo" tests .github --glob '*.py' --glob '*.yml' --glob '*.yaml'`

Expected: no matches.

- [ ] **Step 5: Run the retained focused tests and the known formerly hanging area**

Run: `uv run pytest tests/simple_runtime tests/integration/chaining tests/integration/recovery/test_chaining_commit.py -q`

Expected: PASS without entering the deleted Fake budget/runtime loop.

- [ ] **Step 6: Commit the test-suite transition**

```bash
git add tests .github/workflows/ci.yml
git commit -m "test: retire fake pipeline regression suite"
```

### Task 4: Synchronize operator documentation and perform the final verification

**Files:**
- Modify: `README.md`
- Modify: `docs/usage.md`
- Modify: `docs/architecture-to-code.md`
- Modify: `docs/handoff/T17_IMPLEMENTATION_HANDOFF.md`
- Modify: `tests/contract/test_operator_docs.py`
- Modify: `docs/DOCUMENT_GUIDE.md`
- Modify: `docs/GLOSSARY.md`

**Interfaces:**
- Consumes: the installed public commands and SimpleRuntime behavior delivered by Tasks 1–3.
- Produces: operator-facing documentation that describes only actual repository analysis and explicitly records that the historical Fake/demo pipeline was removed in commit history.

- [ ] **Step 1: Replace stale documentation assertions with actual-product assertions**

```python
def test_operator_docs_do_not_advertise_fake_or_demo_analysis() -> None:
    text = "\n".join(path.read_text(encoding="utf-8") for path in OPERATOR_DOCS)
    assert "demo analyze --scenario" not in text
    assert "Fake demo" not in text
    assert "sastsimi analyze" in text
    assert "sastsimi resume" in text
```

- [ ] **Step 2: Run the documentation contract and verify RED**

Run: `uv run pytest tests/contract/test_operator_docs.py -q`

Expected: FAIL on existing Fake/demo instructions.

- [ ] **Step 3: Update current operator documents**

Remove Fake/demo commands, Fake smoke evidence, and claims that the legacy command remains available. Point architecture-to-code and handoff coverage at SimpleRuntime tests. Historical implementation plans remain immutable design history; add a short superseded note only where a historical document can be mistaken for current instructions.

- [ ] **Step 4: Run focused documentation and product tests**

Run: `uv run pytest tests/contract/test_operator_docs.py tests/contract/test_product_runtime_surface.py tests/unit/interfaces/test_public_simple_cli.py tests/simple_runtime -q`

Expected: PASS.

- [ ] **Step 5: Run the final quality checks once**

Run: `uv run ruff format --check src tests`

Expected: all files already formatted.

Run: `uv run ruff check src tests`

Expected: all checks pass.

Run: `uv run mypy src tests`

Expected: `Success: no issues found`.

- [ ] **Step 6: Run the full test suite once**

Run: `uv run pytest -q`

Expected: PASS with no hang in the removed Fake-pipeline chaining tests.

- [ ] **Step 7: Commit the documentation and final verification fixes**

```bash
git add README.md docs tests/contract/test_operator_docs.py
git commit -m "docs: make simpleruntime the only analysis path"
```

- [ ] **Step 8: Push the branch and create the final PR only after local verification**

Run: `git push -u origin feat/simple-runtime-product`

Expected: push succeeds without rewriting remote history. Create one PR to `main`, run the repository CI once, fix only Blocker/High failures, and do not merge until that CI is green.
