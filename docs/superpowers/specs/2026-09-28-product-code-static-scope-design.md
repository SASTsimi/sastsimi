# Product-code static-analysis scope

## Purpose and boundary

The default static-analysis scope is tracked, deployable product source, not test-only source. The same effective scope must govern AST, OpenGrep, Semgrep fallback, CodeQL, file–rule coverage, and the source list subsequently shown to analysis agents. A test file excluded by policy is neither a successful scan nor an unresolved product-code scan. Every exclusion is auditable as `EXCLUDED_TEST_FILE` with its repository-relative path and matched reason. `include_tests = true` restores the previous all-tracked-source scope.

This is a scope change, not a claim that all remaining product code will scan successfully. Parser errors, timeouts, CodeQL scope mismatches, or unknown product-code coverage still block `COMPLETE`. The previously cancelled request to add new CodeQL languages is not part of this design: CodeQL's existing language scope remains unchanged.

## Selected approach

Use one deterministic, versioned `StaticFileScope` manifest built from the pinned commit's NUL-delimited `git ls-files` result. It carries `all_tracked`, `selected_source_paths`, and `excluded_test_paths` with one reason per path. The policy uses exact path components such as `test`, `tests`, and `__tests__`, plus anchored language-specific test basenames; substring matching (`contest`, `testimonials`) is forbidden. Ambiguous names outside a clear test directory remain in product scope unless file content gives high-confidence framework-specific test evidence. Generic `fixtures`, `mocks`, `examples`, and `integration` directories are not excluded by name alone. A source path referenced as a declared product entry point or otherwise demonstrably required by deployed code must remain selected; unresolved ambiguity favors inclusion. No Dify-specific path appears in the classifier.

The alternative of independently configured ignore globs for each engine is rejected because the scanners and coverage denominator could diverge. A wholly filtered checkout is reserved as a CodeQL fallback if the supported configuration cannot be shown to honor the exact manifest; it is not the primary route because copying a source tree can change extraction context.

## Data flow and engine parity

The manifest is created before repository profiling or scanning. AST receives its selected Python paths; OpenGrep's initial scan and bounded retries receive explicit selected paths instead of the repository root; Semgrep fallback receives the same unresolved selected file–rule pairs. Existing language-to-rule mapping still determines which pairs are applicable. Agent source surveys use selected paths while an independent complete tracked-file manifest remains available for integrity checks.

CodeQL must apply exclusions while creating its database, not merely discard findings afterward. Generate a code-scanning configuration from exact excluded relative paths, pass it through both SimpleRuntime and production CodeQL provisioning, and test it against the installed CodeQL 2.27.0 with product/test fixture files. GitHub documents `database create --codescanning-config` and `paths-ignore` for interpreted languages; this capability must be verified locally rather than inferred from documentation alone. If exact input parity cannot be proven for a repository or CodeQL build, return a scope/coverage failure and do not mark the analysis complete. Reusing a pre-exclusion database is forbidden.

`StaticFileScope` is also the single input to expected file–rule pairs. Excluded paths are outside the denominator, never added to verified pairs. Coverage evidence and reports include policy version, mode, selected source count, excluded tracked-file count, excluded source count, each excluded path and reason, per-engine attempted/verified/unresolved selected pairs, and remaining product-code errors. If scanner output unexpectedly refers to an excluded path or a selected path is omitted from the asserted scan result, fail closed rather than silently accepting the mismatch.

## Persistence, configuration, and resume

Add `include_tests = false` to the user profile and setup defaults, with an explicit true option for operators who want test analysis. Record the effective mode and policy version in the analysis/checkpoint and include the selected-path manifest digest in coverage, OpenGrep batch, and CodeQL database cache identities. A resume with a changed scope must not reuse previous scan proofs or downstream findings as if they had the same denominator. The safe operator path is a new analysis identity for the new scope; an old in-flight identity keeps its original scope or stops with an explicit scope-change error. Existing artifacts remain intact and labeled with their original scope.

## Validation and Dify retest

Unit tests cover exact directory and filename patterns, ambiguous product filenames, declared product entry points, mixed-language paths, include-tests mode, exclusion reasons, and deterministic policy hashes. Integration tests assert identical engine input sets, CodeQL fixture extraction, cache separation, fail-closed scope mismatch, resume behavior, exclusion reporting, and preservation of product-code gaps. Existing static and provider regression suites run unchanged.

For Dify commit `8387590ace4a094de812b7847fc6a4c3a27cd52b`, the preliminary conservative path classification yields about 4,305 candidate excluded source files and 38,050 file–rule pairs out of 97,328 original expected pairs; these are audit estimates, not verified scan results. Compare the final classified path manifest against project entry points and representative backend/frontend files before accepting it. Restart the Dify trial under the new scope identity, reuse only scope-compatible evidence, measure remaining parser errors/timeouts among product paths, and continue through agents/PoC/reports only if all required product coverage is verified. Record actual outcomes without manufacturing `COMPLETE` or `confirmed`.

## Sources and limitations

GitHub documents the CodeQL database-create configuration option and the interpreted-language `paths-ignore` behavior: <https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-create> and <https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options>. Those documents describe current CodeQL; the pinned local version is verified in tests. No pathname-only policy can prove the deployability of every unusual repository file, so uncertain candidates remain included and the manifest makes every exclusion reviewable.
