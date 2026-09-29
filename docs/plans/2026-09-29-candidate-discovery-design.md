# Candidate Discovery Design

## Purpose

Account for every candidate emitted by completed static scans. This does not claim to find every vulnerability in a repository. Keep the Python-product-code scope and existing Hypothesis, Pro/Con, PoC, verification, and reporting roles. Discovery is triage, not a vulnerability verdict.

New analyses use candidate-discovery. Existing analyses without its version marker keep their legacy resume path and artifacts; no old checkpoint is rewritten.

## Evidence pipeline

1. Retain exact AST, OpenGrep, Semgrep-fallback, and CodeQL outputs as content-addressed artifacts. File-by-rule coverage and candidate counts are distinct. A 500-item prompt projection is not the collection source.
2. Collect all accepted results into stable, content-derived candidate IDs. Store analysis/scope identity, relative file/range, kind ENTRY_POINT, FLOW, or HINT, engine/rule provenance, and exact evidence references. FLOW requires observed source, sink, and path evidence; a standalone source/sink hit is HINT. Never infer a flow from adjacent tool hits.
3. Deduplicate only identical normalized evidence. Different source-to-sink paths or conditions remain separate even when source and sink names match. Merge engine provenance only when identity is demonstrably equal.
4. Store candidates durably and read them in pages. Large outputs are processed incrementally. Remove fixed overall candidate/hypothesis count ceilings; resource exhaustion is an explicit failure with unprocessed work preserved, never silent truncation.
5. Discovery reviews bounded batches and returns exactly one INCLUDE, EXCLUDE, or UNDECIDED decision per candidate ID with a reason and evidence reference. Schema/ID errors receive bounded retries, then ERROR. Untouched work stays PENDING. UNDECIDED advances to deep analysis; ERROR does not.
6. Every INCLUDE/UNDECIDED candidate links to candidate-specific hypothesis review and then the existing stages. No vulnerability hypothesis is an explicit terminal conclusion, not disappearance. Auxiliary free exploration runs in bounded source pages without an overall hypothesis cap. Chaining depth, duplicate and cycle protections stay finite.

## Model payload and budgets

The configured provider/model input allowance sets a conservative per-call budget. Serialize and size candidate projections before each call; split batches rather than byte-cutting a prompt. A context-limit response triggers smaller batches. A single candidate that cannot fit is ERROR while its exact evidence remains available.

The durable LLM-attempt ledger accounts for Discovery and downstream work. At a configured cumulative token/cost ceiling, stop before another billable call: analysis PAUSED, remaining candidates PENDING, guidance to raise the limit. An unchanged-limit resume returns PAUSED without retry spin. A raised limit resumes only pending work. Successful decisions and completed hypotheses reuse checkpoints keyed to analysis/scope/candidate identity.

## Completion and user visibility

COMPLETE requires verified in-scope Python product-code coverage, zero PENDING/ERROR candidates, and terminal downstream work for every INCLUDE/UNDECIDED candidate and free-exploration proposal. INCONCLUSIVE is a terminal hypothesis outcome but never confirmed. If valid downstream work finishes with static gaps or unsupported product code, analysis is PARTIAL. Corrupt evidence, checkout failure, or Agent failure stays BLOCKED/FAILED; budget exhaustion is PAUSED. Finding confirmation requires its own evidence and PoC.

CLI and dashboard distinguish file-by-rule verified/expected counts, candidate total and decision counts, deep-analysis running/terminal counts, hypotheses, and Findings. Progress uses actually completed work and resume never double-counts. Show explicitly excluded test paths and reasons, not as successful scans; this newer requirement supersedes the prior request to discard test-exclusion records. In a mixed-language repository, JS/TS product code is outside the Python-only scanner scope, displayed separately, and prevents a claim of whole-repository completeness; aggregate status remains PARTIAL while that product code is unverified.

## Compatibility and validation

Use additive SQLite storage and optional/defaulted run fields. Old run rows retain legacy resume semantics. A static scope/rule fingerprint change still requires a new analysis or the existing explicit scope-change error. Never reset user checkouts, database, or artifacts.

Test hundreds of results; >256-KiB candidate projections; distinct same-name flows and true duplicates; invalid/missing/uncertain Discovery decisions; retries/cancellation; budget pause and both kinds of resume; zero candidates; Python/JS/TS scope; test exclusions; static PARTIAL; legacy resume. Run a low-cost pinned PyJWT 2.12.1 smoke test and then a bounded Dify trial, reporting observed candidate states and static gaps without inventing COMPLETE or confirmed findings. Synchronize README and operator docs with the verified behavior.
