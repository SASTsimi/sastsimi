# Python-only static scope and complete scan passes

## Intent and baseline

SASTSIMI analyzes deployable Python product code, not every language in a mixed repository. A scan pass attempts every planned static work item unless cancelled or an existing non-time resource-safety ceiling is reached; a tool invocation remains finite. Verified evidence is reused on resume, while failed file×rule pairs remain unverified. This changes analysis coverage, not the checked-out repository or the policy/PoC inputs.

The implementation baseline is `d043026b` (`codex/reliable-full-analysis-impl`). Its existing scope includes non-test JS/TS and other files; OpenGrep and Semgrep each have a 180-second pass deadline. OpenGrep already chunks by file count and bytes, and both tools have bounded timeout splitting and persisted evidence.

## Scope contract

- The static source set is safe, tracked, deployable `*.py` files after the existing test-file exclusion. `.pyi`, `.pyw`, notebooks, JS/TS, generated assets, documentation and other non-`.py` files are not static targets. Test-like files are excluded even when a package manifest names them.
- AST, OpenGrep, Semgrep fallback, Python CodeQL staging, file×rule coverage, candidate context and hypothesis Agent source retrieval consume that same source set. Rules with no Python applicability do not create expected work. Non-Python files are out of scope, not successful scans and not unsupported product code.
- The Git safety manifest, repository policy lookup, dependency/build metadata, and isolated PoC checkout remain complete and independently verified. Use distinct source permissions/manifests: hypothesis Agents receive only Python code; PoC environment setup may receive verified Dockerfile, dependency and configuration files. These support execution but are not static findings or hypothesis code evidence. The repository profile derives metadata from the full verified tracked set, not the narrowed static source set.
- No deployable `.py` file is a clear `NO_PYTHON_SOURCE` failure, never COMPLETE. A Python source set with no applicable Python rules is a `NO_PYTHON_RULES` configuration failure; zero verified file×rule pairs is BLOCKED rather than PARTIAL. Determine an empty Python source set without parsing irrelevant `package.json` files. Increment the scope policy version/fingerprint so older cross-language coverage and Agent completion evidence cannot be reused as Python-only completion.

## Scan execution and recovery

- Remove the aggregate `static_scan_pass_seconds` deadline from OpenGrep and Semgrep. New setup/profile output omits that field; old profile files may still parse it for compatibility, but it is deprecated and has no aggregate effect.
- Keep each OpenGrep and Semgrep invocation capped at 120 seconds. Keep a finite, independent CodeQL create/analyze cap of 1800 seconds. LLM and other existing per-call ceilings are unaffected.
- OpenGrep continues to plan at most 64 files and 512 KiB of source per initial chunk. Semgrep adds a 512 KiB source cap to its existing 128-file and Windows command-length limits. An oversized single file is one bounded attempt rather than silently dropped.
- On timeout, recursively split multi-file chunks into smaller chunks; single-file attempts have only the existing bounded retry path. Never spin on one item. Preserve its explicit timeout/parse/scan error as an unverified file×rule pair if it cannot be proved.
- Cancellation propagates to the active subprocess and prevents remaining planned work from starting. A resume checks exact commit, scope fingerprint, rules and validated raw/request artifacts, skips only successful file×rule evidence, and retries unresolved pairs, including parser/partial-scan gaps, with the same finite per-run attempt rules. An automatic retry loop must not repeat a singleton indefinitely. No old-scope results satisfy the new denominator.
- The existing 500,000-candidate/4 GiB raw-evidence safety ceiling remains. If reached, record remaining combinations as unverified with an explicit resource-limit reason; do not claim all bundles were attempted or mark COMPLETE. This is a safety exception to the no-*time*-limit request, not a hidden wall-clock deadline.
- COMPLETE requires all expected Python file×rule pairs verified and no other blocking errors. Static gaps with some verified evidence yield PARTIAL with reasons; corrupted evidence, checkout failure, zero verified coverage, or required Agent failure retain their existing failure state. Findings are independently judged and do not imply complete coverage.

## Validation and live target

Tests cover Python-only selection and metadata separation, empty Python scope, all engines and Agent manifest, cumulative scan time above 180 seconds, file-count/byte chunks, timeout splitting and singleton failure, cancellation, cache reuse after interruption, and old-scope invalidation. Focused tests run before the full suite.

After implementation, pin the current commit of [Kludex/python-multipart](https://github.com/Kludex/python-multipart) and start a local SASTSIMI analysis. Its [security policy](https://github.com/Kludex/python-multipart/security) supports private reporting and lists multiple 2026 GHSAs. Published advisories are a sign of an active process, not evidence of an unpatched finding. No external service probing or submission is authorized by this task. Record the run ID, exact commit, Python file/rule coverage, state, and any operational failures; do not promise confirmed findings.
