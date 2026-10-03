# Real-repository E2E hardening for the streaming Python pipeline

Date: 2026-10-02
Target: PR #209, `codex/streaming-pipeline-optimization`

## Intent and success boundary

Make the existing Python-only streaming pipeline more dependable on different real repositories without changing Agent roles, inventing findings, or silently treating untested code as clean. A successful run may legitimately have zero findings. A `confirmed` finding and submission-ready English/Korean bundle require a reproducible PoC, accepted technical and scope gates, and evidence bound to the exact analyzed commit. No finite test matrix can guarantee error-free execution or vulnerability discovery for every repository.

The prior isolated Flask run resumed with an unlimited token budget, reused static work, and reached `POC_EXECUTION_DONE`, but ended `POC_ENVIRONMENT_UNVERIFIED`: offline `pip install` failed and a `GENERATED_NO_INSTALL` image was correctly rejected. The prior isolated simpleeval 1.0.3 run finished 10/10 static pairs but had no OpenGrep/CodeQL candidates; `super(...).eval(...)` was incorrectly stored as bare `eval`, and its only surface was reviewed with an 11-line window rather than the enclosing implementation. These are distinct causes, not token exhaustion. The Flask trial limit was local; the normal profile already defaults to unlimited cumulative tokens.

## Options and chosen approach

1. **Chosen: bounded evidence refinement plus offline verified wheels.** Preserve the v2 candidate pipeline, add syntax-faithful AST facts and an explicitly bounded second look only after insufficient evidence. Offer a user-supplied, digest-pinned wheel archive for the isolated Docker build. Keep the PoC container offline and preserve failure states.
2. Restore full-source LLM exploration and send larger prompts. This would increase duplicate context and cost and undo the approved streaming optimization without proving recall.
3. Enable Docker build networking generally. This lets arbitrary repository Dockerfile and build-backend commands use the network and widens the untrusted-code boundary.

## Candidate and surface evidence

The AST fact collector must retain whether a call is a direct name or a method on a call result. `eval(...)` and `super(...).eval(...)` must not share the same fact identity. Security-surface classification must use the structured callee identity, not infer a builtin from the last attribute name. Keep detection of other call-shaped receivers such as `Path(...).write_text(...)`; do not achieve the fix by dropping their facts.

Add a generic reflection surface for `getattr(object, nonliteral_attribute)`, which is a security-sensitive operation independent of the simpleeval project. It is a review hint, not a vulnerability verdict. Literal compatibility probes such as `getattr(ast, "Num", None)` do not qualify. Preserve path, line, symbol, fact origin, and source hash. The surface index stays bounded and deduplicated; any missed class of vulnerability remains a documented detector limitation, never proof that no vulnerability exists.

If a surface proposal returns `INSUFFICIENT` and the first context omitted relevant source or AST facts, construct at most one second, redacted, versioned context. Prefer the enclosing function/class plus directly referenced local implementation; include a small entire file only when it fits the existing 64 KiB request budget with headroom. Split deterministically if necessary. Never byte-truncate source, invent missing evidence, or repeat the first prompt unchanged. The second decision is checkpointed by exact surface, context hash, commit, static bundle, and proposal version. If evidence is still insufficient, retain the explicit insufficient/PARTIAL result.

New AST/surface/context records use disjoint versions or fingerprints. Existing v1/v2 run records remain readable and are not retroactively reclassified. A prior terminal run that needs new detection is tested as a new isolated analysis; existing completed work in an unchanged scope remains reusable. Do not rewrite the original Dify or user analysis data.

## PoC dependency environment

Expose an optional profile setting for an operator-provided Python wheel archive and expected SHA-256 digest. Import it into an analysis-owned CAS after checking regular-file identity, size, digest, archive structure, safe member names, `.whl` format, and platform compatibility, reusing the existing validated dependency-bundle rules where practical. This is explicit operator approval of these bytes for the analysis, not a shared account credential. No key, token, source snippet, or archive content enters ordinary logs.

Build from an isolated immutable context containing the pinned checkout and the validated wheels, without writing the checkout. Install using `pip --no-index --find-links`; allow only packages resolvable from that bundle. Include the wheel archive digest, dependency manifest digest, source commit, Dockerfile digest, and build-network mode in the recipe and image-cache identity. The PoC container remains `--network none`. If an unsupported sdist, VCS, apt, uv, incompatible wheel, or missing transitive dependency prevents installation, keep `BLOCKED` with a precise environment reason. Do not fall back to a source-only image for a valid PoC verdict. No automatic host/PyPI download is part of this change.

The already blocked Flask PoC checkpoint is nonretryable and must not be silently reopened under a changed dependency bundle. A new isolated run with the bundle, or a separately designed explicit invalidation protocol, is required. Existing report and Finding safety gates remain unchanged.

## Validation and PR evidence

Use red/green unit tests for the AST receiver distinction, dynamic/nonliteral `getattr`, omitted-context second look, one-time retry and resume idempotency. Add negative tests for corrupt/wrong-platform wheels, changed digest, cache separation, missing dependencies, offline runtime, and no false `DISPROVED` or `confirmed` verdict on environment failure. Add an integration fixture that exercises every Agent handoff through validated PoC, technical/scope gates, and exact `report_en.md`, `report_kr.md`, PoC and evidence bundle contents; separately test a benign zero-finding run and interrupted resume.

Re-run two pinned, distinct real Python repositories under the branch source: Flask for dependency handling and simpleeval for the AST/context path. Record exact commit, tool bindings, static coverage, candidate/surface/hypothesis counts, PoC status, token usage, scope gate, findings, report paths and unresolved limits. Do not call a synthetic fixture a real-world discovery, or mark a real candidate `confirmed` without execution evidence. Run focused tests, the full available suite, type/lint/docs checks, then update PR #209 only with verified claims. Keep it draft if real-world E2E remains blocked.
