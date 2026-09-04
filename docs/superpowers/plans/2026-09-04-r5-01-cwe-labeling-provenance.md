# R5-01 CWE Labeling Provenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind every current `CWELabel` to the exact final TRUE Verification revision that R5-01 classified before Technical Gate.

**Architecture:** Reuse `WorkExecutionState(work_type=CWE_LABEL)` as the current-label lifecycle instead of adding a second state object. Add exact Verification, generation, work and invocation provenance to `CWELabel`, then enforce one successful CWE work output per Verification revision and reject stale labels at Gate entry.

**Tech Stack:** Markdown Architecture v5 contracts, Mermaid, PowerShell documentation validator

**Spec:** `docs/superpowers/specs/2026-09-04-r5-01-cwe-labeling-provenance-design.md`

## Global Constraints

- `CWE_LABELING` is the logical producer/runtime role; `CWE_LABEL` is the work type; R5-01 is the R1~R8 owner.
- Only final `VerificationResult.verdict=TRUE` can create a Gate-input `CWELabel`.
- Every new Verification revision or generation requires a newly evaluated `CWELabel` revision, even when the CWE value is unchanged.
- Technical Gate reviews CWE alignment but never creates or mutates a label.
- Historical labels remain immutable revision history and cannot become current input for a newer Verification.

---

### Task 1: Define the canonical schema and lifecycle

**Files:**
- Modify: `docs/architecture-v5/08-lightweight-data-contracts.md`
- Modify: `docs/architecture-v5/03-agent-roles-and-orchestration.md`
- Modify: `docs/architecture-v5/05-llm-gate-and-reporting.md`

**Interfaces:**
- Consumes: final TRUE `VerificationResult`, current `HypothesisProcessState.verification_generation`, successful `CWE_LABELING` invocation
- Produces: exact `CWELabel.verification_result_ref`, `verification_generation`, `cwe_labeling_work_id`, `llm_call_id` and a successful `CWE_LABEL` work output

- [ ] Add the four required provenance fields to the canonical schema.
- [ ] Define the unique CWE work key, exact save checks and stale-label rejection.
- [ ] Replace optional CWE realignment wording with mandatory reevaluation after every new Verification revision or generation.
- [ ] Require Technical Gate's two direct inputs to be an exact Verification/label pair.

### Task 2: Synchronize architecture, Wiki, Mermaid and ownership

**Files:**
- Modify: `README.md`
- Modify: `docs/GLOSSARY.md`
- Modify: `docs/architecture-v5/01-system-overview.md`
- Modify: `docs/architecture-v5/04-verification-and-dynamic-reproduction.md`
- Modify: `docs/architecture-v5/07-results-and-observability.md`
- Modify: `docs/architecture-v5/10-security-boundaries.md`
- Modify: `docs/architecture-v5/13-architecture-diagrams.md`
- Modify: `docs/architecture-v5/README.md`
- Modify: `docs/architecture-v5/wiki/agents.md`
- Modify: `docs/architecture-v5/wiki/common-contracts.md`
- Modify: `docs/architecture-v5/wiki/diagrams.md`
- Modify: `docs/architecture-v5/wiki/gate-and-reporting.md`
- Modify: `docs/architecture-v5/wiki/pipeline.md`
- Modify: `docs/architecture-v5/wiki/results.md`
- Modify: `docs/governance/OWNERSHIP.md`
- Modify: `docs/governance/REVIEW_CHECKLIST.md`
- Modify: `docs/review/ISSUE_CATALOG.md`
- Create: `docs/review/decisions/ADR-009-r5-01-cwe-labeling-provenance.md`
- Modify: `docs/review/decisions/README.md`

**Interfaces:**
- Consumes: canonical lifecycle from Task 1
- Produces: one consistent human-readable description and matching canonical/Wiki Mermaid flow

- [ ] Name R5-01 as the actual owner everywhere ownership is described.
- [ ] Show `final TRUE -> R5-01 CWE_LABELING -> current CWELabel -> Technical Gate` in prose and diagrams.
- [ ] Explain that identical CWE values still require a new revision bound to the new Verification.
- [ ] Record the decision and supersession-safe integration rule in ADR-009.

### Task 3: Add executable documentation checks

**Files:**
- Modify: `scripts/validate-architecture-docs.ps1`

**Interfaces:**
- Consumes: canonical schema and synchronized documents from Tasks 1-2
- Produces: failing checks for missing ownership, provenance, lifecycle, stale rejection or diagram parity

- [ ] Validate all four `CWELabel` provenance fields.
- [ ] Validate producer/work/owner distinction and final TRUE-only creation.
- [ ] Validate mandatory reevaluation, immutable history and exact Gate pair rules.
- [ ] Validate canonical/Wiki Mermaid parity.
- [ ] Run the full documentation validator and `git diff --check`.

### Task 4: Integrate into main

**Files:**
- Modify: Git history only after all checks pass

**Interfaces:**
- Consumes: verified documentation changes
- Produces: one reviewed commit on remote `main`

- [ ] Fetch the latest remote main and confirm no divergence.
- [ ] Commit the complete R4 contract update.
- [ ] Push `HEAD:main` and verify local HEAD equals `origin/main`.
