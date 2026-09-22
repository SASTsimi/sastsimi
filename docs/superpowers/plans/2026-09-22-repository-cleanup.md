# Repository Cleanup and Documentation Synchronization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve the complete executable SASTSIMI behavior while removing historical repository clutter and making every retained document describe the current implementation.

**Architecture:** Replace planning-era documentation with one implementation-oriented architecture set derived from the public CLI, `SimpleRuntime`, active adapters, Pydantic contracts, migrations, generated schemas, and security tests. Historical files move to Git history rather than a second in-repository archive. Python code is removed only when public-entry reachability, registry/resource searches, compatibility checks, and the full regression suite all prove it is dead.

**Tech Stack:** Python 3.12, Pydantic 2, SQLAlchemy/Alembic, pytest, Ruff, mypy, Hatchling, PowerShell documentation validation, GitHub Actions

**Spec:** `docs/superpowers/specs/2026-09-22-repository-cleanup-design.md`

## Global Constraints

- Preserve the public CLI behavior of `setup`, `analyze`, `status`, `resume`, `result`, `poc`, `report`, and `dashboard`.
- Preserve error-not-FALSE, validated-PoC-before-TRUE, exact-reference, stale-result, redaction, and Sandbox-boundary rules.
- Preserve existing database migration and stored-result compatibility.
- Do not delete code, contracts, schemas, prompts, migrations, or package resources based only on legacy-looking names.
- Do not add new skips or weaken a functional, integrity, recovery, or security assertion to make cleanup pass.
- Work only on `chore/repository-cleanup`; open a PR but do not merge it to `main`.
- Baseline is `3209 passed, 23 skipped, 12 warnings` at `c5e501a9995811d6db7a143542cd0a418779ddca`.

## Review Focus

- Old Markdown links must fail validation instead of silently pointing to removed historical documents; Task 5 adds a full tracked-Markdown link test.
- An internal module reached through a string registry, subprocess worker, Alembic, or package resource must not be misclassified as dead; Task 6 checks each mechanism before deletion.
- Existing databases and reports must remain readable after source cleanup; Task 6 runs migration, stored-result, and report-query regression tests.
- The simplified architecture must not describe planned behavior as implemented; Tasks 2 and 3 cross-check every claim against an exact code module or mark it as a follow-up.
- Windows wheel users must retain the same CLI surface and bundled resources; Task 7 installs the wheel in a clean virtual environment and runs command smoke tests.

---

### Task 1: Pin the current documentation surface before deleting history

**Files:**
- Create: `tests/contract/test_current_documentation.py`
- Modify: `tests/contract/test_operator_docs.py`
- Read: `src/sastsimi/interfaces/cli/main.py`
- Read: `src/sastsimi/simple_runtime/models.py`
- Read: `src/sastsimi/simple_runtime/stages.py`

**Interfaces:**
- Consumes: the public command names from `interfaces.cli.main` and stage names from `SimpleStage`
- Produces: a failing cleanup contract that defines the new current-document set and rejects historical trees

- [ ] **Step 1: Add a documentation inventory test that expects the new structure**

```python
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_current_documentation_has_one_implementation_source_of_truth() -> None:
    required = {
        "docs/architecture/README.md",
        "docs/architecture/pipeline.md",
        "docs/architecture/runtime-and-recovery.md",
        "docs/architecture/agents-and-providers.md",
        "docs/architecture/contracts-and-storage.md",
        "docs/architecture/static-and-dynamic-analysis.md",
        "docs/architecture/gates-chaining-reporting.md",
        "docs/architecture/security-boundaries.md",
        "docs/architecture/implementation-map.md",
        "docs/decisions/README.md",
    }
    assert {path for path in required if not (ROOT / path).is_file()} == set()
    assert not (ROOT / "docs/superpowers").exists()
    assert not (ROOT / "docs/review").exists()
    assert not (ROOT / "docs/architecture-v5").exists()
    assert not (ROOT / ".superpowers").exists()
```

- [ ] **Step 2: Add public-command and SimpleRuntime-stage documentation assertions**

```python
def test_current_docs_name_public_commands_and_runtime_stages() -> None:
    text = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in (
            "README.md",
            "docs/usage.md",
            "docs/architecture/pipeline.md",
            "docs/architecture/runtime-and-recovery.md",
        )
    )
    for command in ("setup", "analyze", "status", "resume", "result", "poc", "report", "dashboard"):
        assert f"sastsimi {command}" in text
    for stage in ("STATIC_DONE", "HYPOTHESIS_DONE", "CHAINING_DONE", "TECH_GATE_DONE", "SCOPE_GATE_DONE", "REPORT_DONE"):
        assert stage in text
```

- [ ] **Step 3: Run the new tests and confirm they fail only because cleanup has not happened**

Run: `uv run pytest tests/contract/test_current_documentation.py tests/contract/test_operator_docs.py -q`

Expected: the new inventory test fails because `docs/architecture` is absent and historical directories still exist; existing operator tests remain green.

- [ ] **Step 4: Commit the red contract separately**

```powershell
git add tests/contract/test_current_documentation.py tests/contract/test_operator_docs.py
git commit -m "test: define current documentation surface"
```

### Task 2: Build implementation-aligned architecture documents

**Files:**
- Create: `docs/architecture/README.md`
- Create: `docs/architecture/pipeline.md`
- Create: `docs/architecture/runtime-and-recovery.md`
- Create: `docs/architecture/agents-and-providers.md`
- Create: `docs/architecture/contracts-and-storage.md`
- Create: `docs/architecture/static-and-dynamic-analysis.md`
- Create: `docs/architecture/gates-chaining-reporting.md`
- Create: `docs/architecture/security-boundaries.md`
- Rename: `docs/architecture-to-code.md` to `docs/architecture/implementation-map.md`
- Read: `src/sastsimi/interfaces/cli/main.py`
- Read: `src/sastsimi/simple_runtime/*.py`
- Read: `src/sastsimi/composition/simple_runtime_composition.py`
- Read: `src/sastsimi/static_analysis/*.py`
- Read: `src/sastsimi/dashboard/*.py`
- Read: `src/sastsimi/contracts/*.py`

**Interfaces:**
- Consumes: current executable modules and contract classes
- Produces: the only normative human-readable architecture set

- [ ] **Step 1: Write `pipeline.md` from the exact `SimpleStage` order**

Document the stage order as:

```text
repository preparation + static analysis
→ STATIC_DONE
→ hypothesis generation
→ HYPOTHESIS_DONE
→ Pro / Con / Verification
→ PoC candidate and execution
→ final Verification
→ CWE labeling
→ Technical Gate
→ Rule Scope Gate
→ Primitive update and Chaining
→ Finding
→ Reporter
→ REPORT_DONE
```

State explicitly that scope rejection does not erase a technically verified result; it controls disclosure/report status according to the stored gate output.

- [ ] **Step 2: Write `runtime-and-recovery.md` from checkpoint behavior**

Describe one checkpoint per analysis/hypothesis/stage, reuse of successful checkpoints, retry from the failed stage, attempt isolation, input-reference hashing, and `BLOCKED | FAILED` without FALSE conversion. Link every statement to the responsible module name (`application.py`, `runner.py`, `store.py`, `migration.py`) without local absolute paths.

- [ ] **Step 3: Write Agent, provider, static/dynamic, Gate/Chaining/reporting, contract/storage, and security documents**

Each document must contain four fixed sections:

```markdown
## 구현된 책임
## 코드 위치
## 지켜야 하는 계약
## 현재 제한
```

Use only responsibilities present in `simple_runtime/stages.py`, `simple_runtime/chaining.py`, provider implementations, active static adapters, the checkpoint/artifact stores, and security-negative tests. Put unverified provider/tool combinations in `docs/release-follow-ups.md`, not in architecture prose.

- [ ] **Step 4: Rewrite the implementation map around current modules**

The map must connect public CLI → composition → `SimpleAnalysisApplication` → `SimpleRuntimeRunner` → stages → checkpoint/artifact storage → dashboard/report queries. Keep advanced onboarding/capability and Alembic paths as supported internal/advanced surfaces, and label local evaluation as internal validation rather than the normal user path.

- [ ] **Step 5: Run stage and command documentation tests**

Run: `uv run pytest tests/contract/test_current_documentation.py::test_current_docs_name_public_commands_and_runtime_stages -q`

Expected: PASS.

- [ ] **Step 6: Commit the new current architecture set**

```powershell
git add docs/architecture docs/architecture-to-code.md
git commit -m "docs: describe the implemented runtime architecture"
```

### Task 3: Preserve accepted decisions and remove obsolete design history

**Files:**
- Create: `docs/decisions/README.md`
- Rename into `docs/decisions/`: ADR-005, ADR-006, ADR-007, ADR-008, ADR-009, ADR-010, ADR-012, ADR-013, ADR-014, ADR-015, ADR-016
- Delete: `.superpowers/`
- Delete: `docs/architecture-v5/`
- Delete: `docs/governance/`
- Delete: `docs/review/`
- Delete: `docs/superpowers/`
- Delete after consolidation: `docs/handoff/`
- Modify: `docs/release-follow-ups.md`

**Interfaces:**
- Consumes: accepted rationale that still matches code and unresolved handoff limitations
- Produces: accepted-decision history without superseded or workflow-era records, plus one current follow-up list

- [ ] **Step 1: Move only accepted ADRs and rewrite their links**

Use `git mv` for the eleven accepted ADRs listed above. Rewrite the decision index to include only `ACCEPTED` decisions, their current code boundary, and the replacement relationship in prose where a removed superseded ADR matters. Do not carry Issue numbers, reviewer assignments, or stale commit SHAs into the new index.

- [ ] **Step 2: Consolidate unresolved handoff items**

Move only still-valid items from `docs/handoff/T17_IMPLEMENTATION_HANDOFF.md` and `docs/handoff/RUNTIME_FIXES_2026-09-19.md` into `docs/release-follow-ups.md`. At minimum preserve externally unverified provider/tool combinations, CodeQL activation conditions, Fake-free external E2E status, and any cross-process clock risk that still exists in current code. Verify each item against source before keeping it.

- [ ] **Step 3: Remove historical trees**

```powershell
git rm -r .superpowers docs/architecture-v5 docs/governance docs/review docs/superpowers docs/handoff
```

Before running the command, confirm every accepted ADR exists under `docs/decisions` and the approved cleanup spec/plan commits are already in Git history.

- [ ] **Step 4: Prove no retained document links to removed history**

Run:

```powershell
rg -n "docs/(superpowers|review|governance|handoff)|architecture-v5|11-migration-from-v4" README.md CONTRIBUTING.md docs scripts .github tests
```

Expected: matches occur only in the cleanup test or deletion-migration commit context that will be updated in Tasks 4 and 5; no current guidance points to removed files.

- [ ] **Step 5: Commit the history cleanup**

```powershell
git add docs .superpowers
git commit -m "docs: remove superseded design history"
```

### Task 4: Synchronize user, contributor, and navigation documents

**Files:**
- Modify: `README.md`
- Modify: `CONTRIBUTING.md`
- Modify: `docs/README.md`
- Modify: `docs/DOCUMENT_GUIDE.md`
- Modify: `docs/GLOSSARY.md`
- Modify: `docs/installation.md`
- Modify: `docs/usage.md`
- Modify: `docs/provider-setup.md`
- Modify: `docs/troubleshooting.md`
- Modify: `docs/onboarding-evidence.md`
- Modify: `docs/release-follow-ups.md`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: the Task 2 architecture and actual argparse command definitions
- Produces: one consistent user path and one contributor path with no R1–R8 or T08–T17 workflow dependency

- [ ] **Step 1: Rewrite the docs index and guide**

The guide lists only retained files and labels them as user guide, current architecture, decision record, or follow-up. Remove Issue-role instructions, completed review status, and design-phase reading orders.

- [ ] **Step 2: Align every CLI example with argparse**

Use the public forms:

```text
sastsimi setup
sastsimi analyze <repository> --commit <exact-sha>
sastsimi status <analysis_id>
sastsimi resume <analysis_id>
sastsimi result <analysis_id>
sastsimi poc <finding_id>
sastsimi report <finding_id>
sastsimi report <finding_id> --export markdown
sastsimi dashboard
```

Keep `uv run` only in a clearly labeled source-developer section. Keep `--data-dir`, explicit profile paths, capability, onboarding, CodeQL, and evaluation commands in advanced sections rather than the first-use flow.

- [ ] **Step 3: Replace planning-era project language**

Change `pyproject.toml` description from `Architecture v5 application foundation` to a product description matching README. Remove statements that the code is only a foundation when the corresponding command is implemented. Retain explicit unverified and unsupported limitations.

- [ ] **Step 4: Simplify CONTRIBUTING without weakening review**

Describe branch → focused tests → full PR CI → review. Remove fixed team-role assignments and closed Issue hierarchy. Keep security-boundary review requirements for contract, Sandbox, verdict, reference, and secret-handling changes.

- [ ] **Step 5: Run operator documentation tests**

Run: `uv run pytest tests/contract/test_operator_docs.py tests/contract/test_distribution.py tests/unit/interfaces/test_public_simple_cli.py -q`

Expected: PASS.

- [ ] **Step 6: Commit synchronized guidance**

```powershell
git add README.md CONTRIBUTING.md docs pyproject.toml
git commit -m "docs: synchronize guidance with the current product"
```

### Task 5: Replace planning-era documentation validators

**Files:**
- Create: `scripts/validate-current-docs.ps1`
- Delete: `scripts/validate-architecture-docs.ps1`
- Delete: `scripts/audit-doc-inventory.ps1`
- Modify: `.github/workflows/docs.yml`
- Modify: `tests/contract/test_ci_workflow.py`
- Modify: `tests/contract/test_current_documentation.py`

**Interfaces:**
- Consumes: the retained docs/decision inventory and Markdown links
- Produces: a short current-doc validation command used locally and in CI

- [ ] **Step 1: Implement tracked Markdown link validation**

The PowerShell script must use `git ls-files '*.md'`, extract relative Markdown links, skip `http`, `https`, `mailto`, anchors, and `codex://`, resolve each path relative to its source file, and fail with one line per missing target. It must not require deleted historical files or exact prose copied from old reviews.

- [ ] **Step 2: Add current invariant checks**

Require the Task 2 architecture files, the user guides, accepted-decision index, and follow-up list. Reject current-document uses of removed concepts `R5-04 Human Review automation`, `LIMITED_REPRO`, `FULL_REPRO`, `SandboxStepLog`, and claims that Gate creates or modifies CWE labels. Search only retained current docs.

- [ ] **Step 3: Update Docs CI and its contract test**

Replace calls to the two old scripts with:

```yaml
- name: Validate current documentation
  shell: pwsh
  run: ./scripts/validate-current-docs.ps1
```

Update `test_ci_workflow.py` to assert the new command exists and the removed validators are not referenced.

- [ ] **Step 4: Run the new validator and tests**

Run:

```powershell
pwsh -NoProfile -File scripts/validate-current-docs.ps1
uv run pytest tests/contract/test_current_documentation.py tests/contract/test_ci_workflow.py tests/contract/test_operator_docs.py -q
```

Expected: PASS with no missing links or historical-directory references.

- [ ] **Step 5: Commit validation cleanup**

```powershell
git add scripts .github/workflows/docs.yml tests/contract
git commit -m "ci: validate only current documentation"
```

### Task 6: Remove only Python seams proven unreachable

**Files:**
- Audit candidates: `src/sastsimi/composition/local_evaluation_static.py`
- Audit candidates: `src/sastsimi/evaluation/queries.py`
- Audit candidates: `src/sastsimi/interfaces/cli/resume.py`
- Audit candidates: `src/sastsimi/orchestration/analysis_service.py`
- Audit candidates: `src/sastsimi/ports/program_resolver.py`
- Audit candidates: `src/sastsimi/ports/report_query.py`
- Audit candidates: `src/sastsimi/ports/sandbox.py`
- Audit candidates: `src/sastsimi/prompts/dynamic_reproduction.py`
- Audit candidates: `src/sastsimi/providers/openai_pvd.py`
- Audit candidates: `src/sastsimi/reporting/queries.py`
- Audit candidates: `src/sastsimi/runtime/analysis_start.py`
- Audit candidates: `src/sastsimi/runtime/chaining_child_registration.py`
- Audit candidates: `src/sastsimi/runtime/chaining_registration.py`
- Audit candidates: `src/sastsimi/runtime/handler_registry.py`
- Audit candidates: `src/sastsimi/runtime/provider_profile_registry.py`
- Audit candidates: `src/sastsimi/storage/run_scope_locator.py`
- Modify/Delete: directly associated tests only after replacement coverage is identified

**Interfaces:**
- Consumes: CLI-root import graph, registry/resource searches, Alembic graph, package build inventory, and baseline tests
- Produces: a smaller source tree with no removal of a reachable or compatibility-critical module

- [ ] **Step 1: Generate a candidate evidence table**

For each exact candidate, record in the PR notes: source importers, test importers, package exports, string references, dynamic registry/resource references, stored-data/migration role, and whether an active equivalent exists. Mark `KEEP` unless every production column is empty and replacement coverage exists.

- [ ] **Step 2: Protect known false positives**

Do not delete package `__init__.py`, Alembic modules, `python_ast_worker.py`, `quota_probe.py`, dashboard assets, prompt templates, generated schemas, or package data based on the static root graph. These are loaded by packaging, subprocess, migration, or resource mechanisms.

- [ ] **Step 3: Delete only candidates with complete evidence**

For every `DELETE` row, remove the source file, package export, and test that solely exercises the dead seam. Before removing the old test, point to an existing current-runtime test covering the same externally visible behavior. If no such test exists, retain the source and test.

- [ ] **Step 4: Run compatibility and security regression tests immediately**

Run:

```powershell
uv run pytest tests/contract tests/simple_runtime tests/integration/cli tests/integration/recovery tests/security_negative -q
uv run python -m compileall -q src/sastsimi
uv run ruff check src tests
uv run mypy src
```

Expected: PASS. Test-count reductions must equal only the explicitly deleted dead-seam tests and must be itemized in the PR.

- [ ] **Step 5: Commit source cleanup, or record a no-delete result**

If one or more candidates are proven dead:

```powershell
git add src tests
git commit -m "refactor: remove unreachable compatibility seams"
```

If none are proven dead, make no source commit and state in the PR that contracts/schemas were retained because active compatibility or security evidence exists.

### Task 7: Final clean-install verification and PR creation

**Files:**
- Modify: cleanup PR body only
- Verify: all tracked files

**Interfaces:**
- Consumes: Tasks 1–6
- Produces: a reviewable PR that is not merged

- [ ] **Step 1: Confirm repository cleanliness and diff scope**

Run:

```powershell
git status --short
git diff --check origin/main...HEAD
git diff --stat origin/main...HEAD
git ls-files | Measure-Object
```

Expected: only planned cleanup files are changed; no runtime data, credentials, absolute local paths, caches, build output, or virtual environment is tracked.

- [ ] **Step 2: Run the full final gate**

Run:

```powershell
uv run pytest
uv run ruff check .
uv run mypy src
pwsh -NoProfile -File scripts/validate-current-docs.ps1
uv build
```

Expected: all commands exit 0; pytest has no failures and no new skips compared with the baseline.

- [ ] **Step 3: Install the wheel in a clean temporary virtual environment**

Create a temporary directory outside the repository, create a Python 3.12 venv, install the newly built wheel, then run:

```text
sastsimi --help
sastsimi setup --help
sastsimi analyze --help
sastsimi dashboard --help
sastsimi db upgrade head
```

Expected: all help commands exit 0 and DB migration reaches `head` without importing a removed module or resource.

- [ ] **Step 4: Run report and dashboard smoke tests**

Run the existing public SimpleRuntime/report and dashboard tests against the final wheel candidate:

```powershell
uv run pytest tests/unit/interfaces/test_public_simple_cli.py tests/unit/interfaces/test_report_cli.py tests/integration/dashboard/test_server.py -q
```

Expected: PASS.

- [ ] **Step 5: Push and open a PR without merging**

```powershell
git push -u origin chore/repository-cleanup
gh pr create --base main --head chore/repository-cleanup --title "chore: align repository with the implemented product" --body-file .git/pr-body-repository-cleanup.md
```

The PR body must include baseline and final test counts, deleted-path groups, retained legacy-looking modules and reasons, source deletions with evidence, current known limitations, and the statement `This PR is intentionally not merged.` Remove the temporary body file after PR creation if it is inside the worktree.

- [ ] **Step 6: Observe PR CI and stop at review-ready state**

Use `gh pr checks <number> --watch`. Fix only failures caused by this branch. When checks pass, attach the PR to the task and stop without merge, squash, rebase, or auto-merge.
