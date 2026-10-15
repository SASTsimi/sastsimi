# Sound Surface Successor Design

## Intent and observed state

The user wants the existing educational Python analysis A-001 to reach a genuine 100% result, without resetting its findings or treating missing evidence as success. The pinned commit is `4163acacc4134bb7b70afe0435f8926e59d433c1`. After the v4–v7 evidence rounds, static coverage is 17/17 with no static gaps, but v7 marks all 43 attack surfaces `INSUFFICIENT` and the analysis remains `PARTIAL`.

The v7 result is not 43 independent LLM rejections. All 26 inherited paths lack the new `blocking_gaps` field, so the v7 preflight cannot review them. The optional stdlib HTTP and operational XML discovery attempts also add `HTTP_HANDLER_IMPORT_UNPROVEN` and `OPERATIONAL_PARSER_UNRESOLVED` to all 43 graphs in this Flask repository. Of the 43 surfaces, 18 have no route-to-sink path (seven fixed SQL calls and eleven Flask route decorators); twelve others have truncated enclosing context. These are separate problems. Removing two global gaps alone cannot establish coverage.

## Chosen approach

Add an immutable successor evidence round after v8. Existing v4–v8 plans, progress, artifacts, and terminal proofs retain their original bytes and interpretation. A v9 plan binds the old terminal, repository commit, static scope and candidate inventory to new source-bound evidence. Only the v9 evaluator may issue a new coverage certificate. A failed or absent v9 part remains `INSUFFICIENT`; no old `COVERED` or Finding is deleted.

Three alternatives were considered. Reinterpreting v7 would invalidate replay of pinned evidence. Suppressing graph gaps would turn unknown paths into false negative claims. A new additive round costs more implementation but preserves existing data and makes every promotion auditable; it is the chosen approach.

## Evidence contracts

1. **Analyzer applicability.** Optional stdlib HTTP and XML operational analyzers emit `APPLICABLE`, `NOT_APPLICABLE`, or `UNKNOWN` from the full pinned Python manifest and relevant launcher/config files. A complete, hash-verified scan with no relevant trigger may establish `NOT_APPLICABLE` for that analyzer only. Parse errors, byte/file limits, dynamic import, shadowing, or ambiguous binding yield `UNKNOWN`. `NOT_APPLICABLE` removes only that analyzer's own unsupported-framework gap; it is not proof that no HTTP route or vulnerability exists.
2. **Inherited connected paths.** A v4-derived path is never made complete by inserting `blocking_gaps=[]` blindly. Re-read the pinned source and AST facts, prove every route, request-boundary, sink node and edge still refers to the same locations and hashes, and attribute each graph gap to a path or explicitly establish its irrelevance. A missing or ambiguous attribution blocks the path. Review all relevant paths for the surface, not only one favorable path.
3. **Fixed SQL call.** For a `SQL_EXECUTION` static-rule surface, bind the original candidate ID/rule/location to the pinned graph AST call and file hash. Require a unique call on the line, a recognized SQL method, exactly one literal string argument, and no keyword or dynamic construction. The resulting proof says only that this exact SQL call uses a fixed string; it does not certify a function, route, or other SQL call.
4. **Route declaration.** For a `REQUEST_ENTRY` decorator surface, bind a uniquely identified Flask application object, exact `@app.route(...)` AST decorator, and decorated function definition at the pinned commit. Rebinding, aliases without proof, computed decorators, and ambiguous registrations remain unknown. This establishes that the entry declaration was reviewed, not that its downstream behavior is safe.
5. **Truncated context.** Do not erase a v7 `ENCLOSING_CONTEXT_TRUNCATED` or downstream-body gap. Re-read the complete hash-pinned function/callee, divide it into bounded ordered parts without dropping lines, and require every part's review or deterministic proof before clearing that specific gap. Oversize, parse, missing part, or ambiguous call target stays insufficient.

Existing hypothesis/PoC/Scope Gate verdicts remain separate from surface coverage. `CHILD_HOLD` may clear only through the existing terminal inconclusive-child proof after all relevant paths are verified. Static gaps, candidate pending/error, and unrelated graph gaps remain blocking. `COMPLETE` and 100% require every indexed surface covered (43 in this A-001 run) and all other existing completion requirements satisfied; otherwise the analysis stays `PARTIAL` or its actual error state.

## Persistence and resume

The v9 plan, part results, negative proofs, and final coverage certificate use content-addressed artifacts and transactional checkpoint binding. Resume validates the pinned v8 parent and existing v9 rows, skips only successful matching parts, and retries missing/failed parts within the existing attempt budget. No direct DB edits or mass reset are part of this design. A model result is accepted only after schema validation and source/path proof validation.

## Verification

Tests must cover: Flask versus real stdlib HTTP and XML applicability; absent and ambiguous analyzer triggers; altered source/hash/edge; one good path plus one unresolved path; same-line SQL decoy call; dynamic SQL and keyword arguments; route-object rebinding; truncated or missing context part; v7/v8 replay unchanged; v9 interruption and idempotent resume. The live A-001 run is resumed at the same ID. Report actual covered/insufficient counts and never claim 100% if any required proof remains unavailable.
