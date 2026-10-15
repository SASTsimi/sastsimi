# Route-bound successor evidence for Python attack surfaces

## Purpose and honest success criterion

Continue the existing `python-vulns` A-001 analysis (commit
`4163acacc4134bb7b70afe0435f8926e59d433c1`) without deleting or
reinterpreting its v4–v9 evidence. The requested 100% means that every
indexed **Python product-code attack surface** has a verified disposition,
all other pipeline work is complete, and the saved terminal is replayable.
It does not mean that every vulnerability has been found, that a template's
HTML/Jinja content is secure, or that unverified paths can be counted as
covered. If any required proof or PoC execution remains unavailable, retain
`PARTIAL` or the actual blocked state and show the reason.

The current v9 plan is content-addressed and already has progress rows. Its
path certificates are not safely mutable. The 43 indexed surfaces include
23 request entries; v9 currently projects at most 20 covered surfaces.
Seven startup SQL calls in `init_db()` are incorrectly carried as same-file
route gaps. Two response-producing XSS routes have pinned Python response
paths but unlocated legacy graph gaps. The index route reaches a literal
`render_template('index.html')` call, which is a Python-to-template boundary.
The live run is separately blocked because its offline PoC base image is
unavailable while Docker Desktop is stopped. These are independent causes.

## Alternatives and decision

1. **Add a deterministic v10 successor (chosen).** Finish the pinned v9
   parts, then bind a new route-specific proof and coverage artifact to the
   v9 terminal, pinned source hashes, and progress snapshot. Reuse validated
   v9 reviews; add no new LLM batch merely to relabel an old gap. This costs
   several read/write integration points but preserves replay and provenance.
2. Patch v9 gap handling in place. Existing plan hashes, context IDs, and
   progress would change, so same-ID resume would reject or silently alter
   historical evidence. Rejected.
3. Treat all same-file gaps or external calls as covered. This would hide
   dynamic paths and conflate Python coverage with template safety. Rejected.

## Route-specific proof

Re-read only hash-pinned Python files in the existing AST manifest. Identify
each Flask route from the exact decorator and uniquely bound application
object. Build a conservative, request-rooted call graph from Python AST
definitions and direct, uniquely resolved calls. Each proof records the
route location, target call or response location, source hashes, resolved
edges, and every gap it discharges. A startup call can be declared unrelated
to a route only when its binding and call location prove it executes outside
all route-reachable functions, and the relevant call graph is closed. A
same-file relationship alone is neither evidence of reachability nor evidence
of non-reachability. Dynamic dispatch, rebinding, aliases, unresolved imports,
ambiguous callee, truncated source, or mismatched hashes fail closed.

For the two `make_response` routes, verify the pinned route-local response
path and source span. Discharge an unlocated legacy gap only if the new
closed-graph proof attributes it to a specific unrelated call or establishes
that the named route has a complete Python response path. A reachable sink
with an unresolved edge remains a gap. Review all relevant paths, not only
one favorable path.

For a literal `render_template` boundary, verify the exact route-to-call
Python edge, static template name, absence of request-derived positional or
keyword context, and a regular, hash-pinned template resource under the
checkout. The proof terminates at the Python external boundary; the template
body and Jinja includes are explicitly **outside Python source coverage**
and must be disclosed in CLI, dashboard, and reports. Dynamic template names,
context values, missing resource, or boundary ambiguity remain insufficient.
This is not a claim that the rendered response is safe from XSS.

## Persistence and completion

After v9 reaches a replayable terminal, save a new immutable v10 plan and
per-surface deterministic proof artifacts bound to: analysis/workspace ID,
commit, scope fingerprint, AST manifest and source hashes, surface index,
v9 plan and coverage refs, v9 terminal snapshot, and completed v9 progress
hash. Do not edit or delete any v9 plan, part, child, finding, or report.
The v10 verifier reconstructs the proof from pinned source and saved parent
artifacts; it does not depend on a now-replaced current terminal ref.
Transactional pinning rejects a changed parent or concurrent writer.

Only gaps discharged by a validated proof may be removed from a successor
coverage row. Existing role citations, child terminal checks, static gaps,
pending/error candidates, and PoC/Scope Gate rules continue to apply. An
unverified relevant path remains `INSUFFICIENT`. A v10 terminal may report
100% and `COMPLETE` only if all 43 Python surfaces and every other required
stage pass independently. Failed PoC execution remains a real block, not a
surface coverage success or vulnerability refutation.

The existing `resume --enrich-saved-surface-evidence` entry point first
finishes v9, then creates/reuses v10 evidence. A repeated resume with the
same parent is idempotent; changed source/commit/scope cannot reuse success.
CLI, dashboard, report, and result readers verify the newest proof version
before showing counts. They distinguish Python scope, excluded template
content, covered/insufficient surfaces, and pipeline errors.

## Verification and live run

Use tests that first fail for unrelated startup SQL contaminating all routes,
the two pinned HTML-response routes, and a literal template boundary. Include
negative cases for reachable sink, dynamic/alias/import calls, missing or
symlinked template, request-derived template context, changed source hash,
one good plus one unresolved path, missing v9 part, child HOLD/ERROR, stale
parent, replay after terminal replacement, and double resume. Preserve older
v9 replay tests. Run focused tests, then full regression tests. Restore
Docker independently, resume exact A-001 ID, and report measured counts and
remaining reasons. Do not substitute a fresh analysis ID or claim 100%
unless the persisted, independently replayed result actually reaches it.
