# Repository Cleanup and Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Architecture v5 source of truth and implementation inputs easy to find, and make unsafe historical-document deletion fail before it can be applied.

**Architecture:** A PowerShell inventory reads only Git-tracked Markdown, resolves local Markdown links, and classifies inbound, validator, final-approval, provenance, and ADR references for every proposed deletion. The deletion allowlist is intentionally empty until a tracked historical file is proven independent; indexes guide readers to the retained source-of-truth documents and to the audit command.

**Tech Stack:** PowerShell 5.1+/pwsh, Git, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-08-sastsimi-maintainable-implementation-design.md`

## Global Constraints

- Preserve Architecture v5 `01`–`13`, implementation baseline, Wiki, governance, final approval, provenance, and every `ACCEPTED` ADR.
- Never delete a document merely because Git history retains it; delete only tracked Markdown paths explicitly listed in an allowlist after inbound, validator, final-approval, provenance, and ADR checks are clean.
- Do not modify any repository outside this Git worktree.
- Run the existing Architecture validator, the new inventory, local Markdown link check, and `git diff --check` on both Windows and Ubuntu CI.

---

### Task 1: Failing inventory contract

**Files:**
- Create: `docs/superpowers/plans/implementation/01-repository-cleanup.md`
- Create: `scripts/audit-doc-inventory.ps1`

**Interfaces:**
- Consumes: `git ls-files`, local Markdown links, `scripts/validate-architecture-docs.ps1`, `docs/review/FINAL_ARCHITECTURE_V5_APPROVAL.md`, and `docs/review/decisions/`.
- Produces: one inventory row per tracked Markdown file and a non-zero exit when a proposed deletion has a required reference.

- [ ] **Step 1: Run the missing audit command as the RED test.**

Run: `powershell -NoProfile -File scripts/audit-doc-inventory.ps1 -RepositoryRoot .`

Expected: PowerShell fails because `scripts/audit-doc-inventory.ps1` does not exist. This proves the required inventory interface is absent rather than relying on a post-hoc successful check.

- [ ] **Step 2: Implement the smallest audit interface.**

Implement `audit-doc-inventory.ps1` with `RepositoryRoot`, `DeletionAllowlist`, and `CheckLinks` parameters. It must output `Path`, `InboundLinks`, `ValidatorReferences`, `FinalApprovalReferences`, `ProvenanceReferences`, and `AdrReferences` for every Git-tracked Markdown file. It must reject an allowlist path that is untracked, outside the repository, not Markdown, or referenced by any of those required-reference sources.

- [ ] **Step 3: Verify both green and safety-negative behavior.**

Run: `powershell -NoProfile -File scripts/audit-doc-inventory.ps1 -RepositoryRoot . -CheckLinks`

Expected: exit code 0 and `Missing local Markdown links: 0`.

Run: `powershell -NoProfile -File scripts/audit-doc-inventory.ps1 -RepositoryRoot . -DeletionAllowlist docs/review/FINAL_ARCHITECTURE_V5_APPROVAL.md`

Expected: non-zero exit because the final-approval document has required references.

### Task 2: Navigation, exact allowlist, and CI

**Files:**
- Modify: `docs/DOCUMENT_GUIDE.md`
- Modify: `docs/README.md`
- Modify: `docs/superpowers/README.md`
- Create: `.github/workflows/docs.yml`

**Interfaces:**
- Consumes: the Task 1 inventory output and the Architecture v5 reading order.
- Produces: role-oriented links to source-of-truth, implementation inputs, history, audit evidence, and a two-platform documentation gate.

- [ ] **Step 1: Record the deletion decision.**

Keep the exact deletion allowlist empty. The inventory is a necessary mechanical check, but it is not proof that a historical document has no remaining decision-process or provenance value. This PR does not perform a document-by-document disposal review or replace historical links, so it retains every historical document. The audit output is the evidence file for a later deletion PR that supplies both reference and content-provenance evidence.

- [ ] **Step 2: Update navigation without changing technical meaning.**

Add links to this plan and `scripts/audit-doc-inventory.ps1`; direct readers to Architecture v5 `01`–`13`, implementation baseline, accepted ADRs, final approval, and provenance before historical records. Clearly state that historical `docs/superpowers` documents stay discoverable but are not current contracts.

- [ ] **Step 3: Add a minimal Windows/Ubuntu workflow.**

For both `windows-latest` and `ubuntu-latest`, run the Architecture validator, the inventory with `-CheckLinks`, and `git diff --check`. Use `powershell` on Windows and `pwsh` on Ubuntu.

- [ ] **Step 4: Verify the complete documentation gate.**

Run: `powershell -ExecutionPolicy Bypass -File scripts/validate-architecture-docs.ps1`

Run: `powershell -NoProfile -File scripts/audit-doc-inventory.ps1 -RepositoryRoot . -CheckLinks`

Run: `git diff --check`

Expected: all exit with code 0.

### Task 3: Review and commit

- [ ] **Step 1: Inspect the staged diff against the task brief.**

Confirm the only changed paths are the plan, audit script, documentation indexes, and docs workflow; confirm no tracked historical document was deleted.

- [ ] **Step 2: Commit the verified change.**

Run: `git add docs/DOCUMENT_GUIDE.md docs/README.md docs/superpowers/README.md docs/superpowers/plans/implementation/01-repository-cleanup.md scripts/audit-doc-inventory.ps1 .github/workflows/docs.yml`

Run: `git commit -m "docs: add repository inventory audit"`

## Self-review

- Spec coverage: covers per-file inventory, unsafe deletion failure, exact empty allowlist, preserved history, index synchronization, validator/inventory/link/diff validation, and Windows/Ubuntu docs CI.
- No placeholders: the audit interface, expected RED/GREEN commands, required output columns, retained-set rationale, and CI commands are explicit.
- Scope: no Architecture contract, ADR status, provenance record, or implementation-code change is included.
