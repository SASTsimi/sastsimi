# ADR-018: 검증된 Finding의 보수적 묶음

- 상태: `ACCEPTED`
- 기록일: 2026-10-04
- 영향 범위: `src/sastsimi/simple_runtime/finding_flow.py`,
  `finding_groups.py`, `finding_group_projection.py`, CLI와 dashboard 조회 경로
- 대체 관계: 없음. 원본 Finding의 중복/판정 계약을 대체하지 않는 표시 투영이다.

## Purpose and boundary

Blind Python trials produced several independently verified Findings for the same input-to-dangerous-operation path. The Antony Flask `/ping` path yielded six Finding reports from CodeQL, OpenGrep, and attack-surface exploration. Present one issue for one demonstrably identical root cause without collapsing distinct input-to-sink paths. This changes how Findings are grouped for readers; it does not change the hypothesis verdict or the conditions for creating a Finding.

Original candidate origins, hypothesis links, Finding artifacts, validated PoCs, scope decisions, checkpoints, F-NNN IDs, and report bundles remain immutable and directly addressable. Nothing is deleted or reclassified as a false positive because it belongs to a group. Existing analyses remain resumable.

## Chosen approach

Sink-line/CWE matching would collapse unrelated inputs at a shared sink and is unsafe. A free-form LLM duplicate vote would be hard to validate, add cost, and could merge distinct paths. Use a conservative deterministic projection over *current verified Findings*, grounded in pinned Python source and exact input-to-sink anchors. It may leave genuine duplicates separate when evidence cannot establish identity; show those as possible duplicates for human review, never hide them automatically.

## Matching contract

1. Only current `FINDING_DONE` results with `TRUE` final verification, a validated PoC, and accepted technical gate are eligible. Existing scope review governs disclosure separately. Read the exact proposal, candidate provenance, final verification, and CWE artifacts tied to the Finding; do not use report title or prose as identity.
2. Resolve the relevant Python function or route in the pinned workspace. Derive an exact input anchor (file, access expression, attacker-controlled parameter/key and position), sink anchor (file, callsite, callee, tainted argument position), and intra-function def-use path. Include route/function identity, normalized CWE, workspace and commit in the key. A different input, sink callsite, argument, route, or proven path remains separate, even if the CWE and sink name match. A surface seed's route is not authoritative: a neighboring context may propose a vulnerability in another route. The initial implementation supports only a narrow CWE-78 pattern: a direct Flask `request` import, one static route on a directly constructed Flask app, one supported request access, and a recognized `os`/`subprocess` command call. Other CWEs, frameworks, aliased or ambiguous inputs, alternate registrations, and unsupported Python expressions remain undetermined singleton items.
3. Cross-engine candidate origins contribute evidence but do not determine identity. If source, sink, or path cannot be uniquely resolved from pinned source and existing verified evidence, do not invent an anchor or use fuzzy text matching. Keep the Finding as a singleton and expose `GROUPING_UNDETERMINED` or a non-authoritative possible-duplicate hint. A CodeQL trace contradicting a proposed anchor prevents automatic grouping.
4. The group ID is a versioned digest of the canonical key. The representative is the lowest existing F-NNN number in the group. Members and their distinct hypothesis IDs, candidate IDs, engines, PoCs, and report paths appear in stable order. A group is an analysis-level view, not a replacement Finding or verification verdict. Scope status is retained per member and group presentation never upgrades reporting permission.

## Integration and resume

A focused grouping module accepts validated Finding/proposal/provenance records and source access through the existing pinned-workspace guard. Project groups when CLI results and dashboard report lists are read. Show raw Finding count, visible group count, and undetermined singleton count separately; the group count is not a claim that all remaining reports are unique vulnerabilities. Keep the raw report collection and ZIP export unchanged; only the dashboard's *visible* list collapses group members under one representative card. Direct access/export by every original F-NNN remains unchanged. Do not rewrite historical reports or allocate an F-NNN for a group. Report content and attachments remain per Finding; the group view links all member evidence.

No new pipeline stage, schema migration, or checkpoint version is required. Recompute the versioned projection from current successful checkpoints on resume, so stale or failed Findings cannot remain grouped. A valid but insufficient member becomes a reasoned singleton. If required evidence is corrupted or cannot be read safely, the whole read-only grouping projection fails closed (`null` counts and no groups), while original Finding/report access remains unchanged; it does not alter analysis `COMPLETE`/`PARTIAL`/`BLOCKED` or `confirmed` status. Dashboard grouping considers only reports currently available for reading, which can be fewer than raw Findings while reporting is in progress. Existing gates retain sole authority for those statuses.

## Verification

Write failing tests first for two engines on the same verified path; attack-surface and static-candidate hypotheses on the same path; same sink with distinct input keys or branches; same input with distinct sinks; neighboring route context proposing the other route's vulnerability; missing/ambiguous source or path; changed source or commit; resume without double-counting; older records without candidate provenance; direct access to each report and PoC; dashboard/CLI raw and group counts. Replay the saved Antony `/ping` and GNU `/rce_vuln` artifacts read-only as integration evidence, then run focused and full tests. If observed duplicates lack sufficient proof, report the remainder rather than broadening the key unsafely.

This design does not promise every duplicate will disappear, that every Python dataflow can be resolved, or that a grouped issue may be reported externally.
