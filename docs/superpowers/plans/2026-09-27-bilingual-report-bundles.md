# Bilingual Finding Report Bundles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce safe English and Korean Finding reports with separate PoC/evidence downloads and a ZIP, without breaking existing reports.

**Architecture:** Keep the two existing Reporter paths and their gate checks. One bilingual Reporter response supplies prose; shared deterministic rendering and a manifest-backed publisher create attachments. Dashboard downloads resolve only current, verified artifact references.

**Tech Stack:** Python 3.12, Pydantic, pytest, stdlib zipfile/hashlib/pathlib, existing artifact stores and loopback dashboard.

**Spec:** docs/superpowers/specs/2026-09-27-bilingual-report-bundles-design.md

## Global Constraints

- Keep the existing F-NNN.md URL/path and all v1 stored report content readable.
- New runs use one Reporter LLM invocation for both languages; do not change other Agent roles.
- Current executed PoC is shell: export poc.sh, not a falsely labeled poc.py.
- Never infer affected version ranges, severity/CVSS, patched versions, source locations, or disclosure permission.
- Package only exact validated refs and redacted bytes; no raw arbitrary evidence or secrets.
- A bundle is visible only after its manifest and every referenced file verify; resume must not redo a successful Reporter call.
- Target public Dify source at a pinned commit locally only after implementation and PR verification.

## Review Focus

1. A historical v1 report with no bilingual fields must remain readable and not trigger a new LLM call (Task 1/4 tests).
2. A candidate containing a token-like string must not put the original bytes into PoC or ZIP (Task 2 test).
3. A partially written directory or substituted Windows reparse path must not become a downloadable bundle (Task 3 test).
4. A legacy Scope Gate claiming unverified ALLOW must not expose PoC through the new route (Task 5 test).
5. An LLM-supplied unsupported path:line in either language must fail validation rather than be rendered (Task 1 test).

## File Structure

- src/sastsimi/contracts/reporting.py: versioned bilingual content contract and v1-compatible parser.
- src/sastsimi/agents/reporter.py, src/sastsimi/reporting/work_handlers.py, src/sastsimi/prompts/{production.py,local_catalog.py}, src/sastsimi/prompts/templates/reporter/create-draft/1.1.0.md: production v2 Reporter route.
- src/sastsimi/simple_runtime/stages.py: simple Reporter v2 prompt and exact-source bundle adapter.
- src/sastsimi/reporting/bilingual_bundle.py: shared facts, identical section structure, English/Korean rendering and curated evidence bytes.
- src/sastsimi/reporting/bundle_files.py: manifest, artifact-backed file publication, deterministic ZIP, guarded reading.
- src/sastsimi/reporting/markdown_export.py and src/sastsimi/storage/report_export.py: production bundle publication without changing legacy export return type.
- src/sastsimi/simple_runtime/{models.py,store.py}: explicit optional bundle manifest/archive refs on checkpoints.
- src/sastsimi/dashboard/{models.py,query.py,server.py,static/app.js}: allowlisted attachment links and verified downloads.
- src/sastsimi/interfaces/cli/{report.py,simple_evaluation.py}, README.md, docs/usage.md, docs/architecture/contracts-and-storage.md: additive bundle path output, limitations and PowerShell usage.

---

### Task 1: Versioned bilingual Reporter output

**Files:** Modify contracts/reporting.py, agents/reporter.py, reporting/work_handlers.py, prompts/production.py, prompts/local_catalog.py; create prompts/templates/reporter/create-draft/1.1.0.md; test tests/contract/domain/test_review_round1_reporting.py, tests/unit/reporting/test_production_work_handlers.py, tests/unit/prompts/test_local_evaluation_catalog.py.

**Interfaces:** Add ReportProse(title, summary, details, impact, recommendation, limitations, review_items) and BilingualReportContent(schema_version=2, en, ko, citations). parse_validated_report_content(raw: bytes, *, allowed_locations: tuple[CodeLocation, ...]) returns ReportContent | BilingualReportContent. The v1 branch must retain byte-for-byte canonical validation.

- [ ] Write tests: v1 raw bytes parse unchanged; v2 accepts both languages and shared citations; unsupported path:line in en or ko raises REPORT_CODE_LOCATION_UNSUPPORTED; missing one language fails.
- [ ] Run those exact test files and observe new v2 tests fail.
- [ ] Add the v2 contract/parser, route the production Reporter schema/template to v2, and make agent/work-handler accept the versioned output while preserving old artifact reads.
- [ ] Run the same tests plus tests/contract/prompts/test_prompt_runtime.py; expect all pass.
- [ ] Commit the contract/prompt slice.

### Task 2: Shared report text and curated attachment payloads

**Files:** Create src/sastsimi/reporting/bilingual_bundle.py; test tests/unit/reporting/test_bilingual_bundle.py.

**Interfaces:** Define BundleFacts with analysis/display/Finding IDs, tested commit, CWE, version/severity state, technical/scope status, execution command/exit code and immutable source refs. Define BundleFile(path: str, body: bytes, media_type: str). render_bundle_files(facts: BundleFacts, content: BilingualReportContent, poc: bytes, stdout: bytes | None, stderr: bytes | None) -> tuple[BundleFile, ...]. The tuple includes report_en.md, report_kr.md, poc.sh, evidence/provenance.json, and only available safe output files.

- [ ] Write tests: both Markdown files have the same ordered sections and exact refs; English headings map to GitHub advisory fields; unknown range/severity/patched version say Needs review/검토 필요; shell payload is poc.sh; unsupported filename/language is rejected; token-like PoC/output cannot appear in any BundleFile.
- [ ] Run tests/unit/reporting/test_bilingual_bundle.py and observe failure.
- [ ] Implement deterministic templates and curated provenance using existing redaction rules; prose does not set factual metadata or change gate status.
- [ ] Run the new tests and existing tests/unit/reporting/test_markdown_export.py; expect pass.
- [ ] Commit renderer and tests.

### Task 3: Manifest-backed publication and verification

**Files:** Create src/sastsimi/reporting/bundle_files.py; test tests/unit/reporting/test_bundle_files.py.

**Interfaces:** publish_bundle(root: Path, analysis_id: str, display_id: str, finding_ref: StoredDataRef, files: tuple[BundleFile, ...], put_artifact: Callable[[bytes, str], StoredDataRef]) -> PublishedBundle with manifest_ref, archive_ref and bundle_dir. read_bundle_file(manifest: ReportBundleManifest, path: str, read_verified: Callable[[StoredDataRef], bytes]) -> tuple[bytes, str]. Manifest lists each non-ZIP file path, media type, content hash and exact artifact ref; archive_ref is outside the ZIP manifest to avoid a hash cycle.

- [ ] Write tests: manifest/file/ZIP hashes agree; repeated identical publish is idempotent; missing manifest, changed or oversized file, path traversal, symlink/reparse replacement and partial write are rejected; no ZIP is advertised until publication completes.
- [ ] Run tests/unit/reporting/test_bundle_files.py and observe failure.
- [ ] Implement file-by-file temporary replacement, manifest-last visibility, bounded file sizes, safe path checks and deterministic ZIP member order.
- [ ] Run new tests and tests/unit/reporting/test_markdown_export.py; expect pass.
- [ ] Commit publisher and tests.

### Task 4: Wire both report producers without losing resume compatibility

**Files:** Modify reporting/markdown_export.py, storage/report_export.py, ports/report_export.py, simple_runtime/stages.py, simple_runtime/models.py, simple_runtime/store.py; test tests/unit/reporting/test_markdown_export.py, tests/simple_runtime/test_simple_report.py, tests/unit/simple_runtime/test_schema_validation.py.

**Interfaces:** CurrentReport.content accepts v1/v2. ReportMarkdownService.export still returns the legacy Path and publishes a bundle only for v2. StageResult and StageCheckpoint gain optional bundle_manifest_ref and bundle_archive_ref; SimpleCheckpointStore.complete copies them. ReporterStage writes a success checkpoint only after publication succeeds.

- [ ] Write tests: both producers generate matching report files and manifest; old v1 output still has only legacy Markdown; old checkpoints deserialize with None refs; a successful resume does not invoke Reporter again; failed bundle publication does not mark success.
- [ ] Run the listed tests and observe the new cases fail.
- [ ] Implement adapters using only exact validated PoC/execution/evidence refs and Task 2/3 interfaces; preserve existing single Markdown path and policy wording.
- [ ] Run the listed tests and tests/unit/orchestration/test_reporting_application.py; expect pass.
- [ ] Commit the two adapters and checkpoint change.

### Task 5: Guarded dashboard and CLI downloads

**Files:** Modify dashboard/models.py, dashboard/query.py, dashboard/server.py, dashboard/static/app.js, interfaces/cli/report.py, interfaces/cli/simple_evaluation.py; test tests/unit/dashboard/test_query.py, tests/integration/dashboard/test_server.py, tests/unit/interfaces/test_public_simple_cli.py, tests/unit/interfaces/test_report_cli.py.

**Interfaces:** FindingReportView gains optional attachment links. DashboardQuery.report_attachment(analysis_id: str, display_id: str, path: str) -> tuple[bytes, str] accepts only manifest-listed paths or bundle.zip and returns verified bytes/media type. HTTP GET/HEAD replies set Content-Disposition: attachment and retain no-store/nosniff/CSP. Existing report_content remains unchanged.

- [ ] Write tests: each attachment and ZIP downloads; forbidden name/traversal, stale Finding, hash mismatch, absent manifest, and unverified legacy ALLOW return no attachment; current ordinary .md remains available.
- [ ] Run the listed tests and observe new cases fail.
- [ ] Implement exact checkpoint/gate linkage, safe_public_report-equivalent restriction, artifact-ref reads, route parsing, headers, UI links and additive CLI bundle path fields without changing existing return values.
- [ ] Run the listed tests; expect pass.
- [ ] Commit the download/UI slice.

### Task 6: Documentation, final verification, PR and Dify trial

**Files:** Modify README.md, docs/usage.md, docs/architecture/contracts-and-storage.md; test all previous files and full suite.

- [ ] Update docs with bundle tree, advisory field mapping, unknown severity/version warning, truthful poc.sh, PowerShell single-line commands and Scope Gate limitations.
- [ ] Run ruff check ., mypy src/sastsimi, and python -B -m pytest -q using a unique accessible --basetemp; record exact results and fix regressions before claiming success.
- [ ] Review the branch diff for secrets, untracked user changes and doc/code drift; request whole-branch code review and resolve findings.
- [ ] Commit docs; push codex/bilingual-report-bundle, create PR against current main, and attach its URL to this task.
- [ ] After PR verification, check GitHub/Docker/OpenGrep access and start local analysis of https://github.com/langgenius/dify.git at 8387590ace4a094de812b7847fc6a4c3a27cd52b using Codex gpt-6-sol. Record the analysis ID and actual status; report an environment blocker honestly instead of calling it COMPLETE.
