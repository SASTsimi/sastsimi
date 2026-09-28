# Policy-backed Rule Scope Gate for SimpleRuntime

Status: proposed design for review.

## Intent and success criteria

The public `analyze`/`resume` pipeline should obtain an exact, attributable security policy before Rule Scope Gate and have the gate assess the policy text, not merely whether a policy-shaped record exists. This must work without per-repository setup for ordinary public GitHub repositories while remaining safe for other repositories. Missing, ambiguous, stale, inaccessible, or unauthenticated policy must remain `UNCERTAIN`; finding generation and technical verdicts remain separate from external-report permission. No result is automatically submitted or published.

Success means a repository with an applicable official policy can produce an evidence-backed `ALLOW` or `DENY`, a repository without one produces an explained `UNCERTAIN`, and the report/dashboard show the exact source and per-axis reasoning. The design must not make A-005 `ALLOW` merely because GitHub offers a private reporting button: changedetection.io currently has no `SECURITY.md` on its Security page.

## Existing behavior and rejected shortcuts

`DirectStaticBootstrap` reads only tracked `SECURITY.md`, `.github/SECURITY.md`, and `docs/SECURITY.md` at the analyzed commit. `RuleScopeGateStage` otherwise sees no official policy collection produced by SimpleRuntime and emits `UNCERTAIN`. A repository-only policy can inform a review but is currently barred from granting `ALLOW`. The production policy path already has official-source provenance, collection/freshness records, and gate closure checks; SimpleRuntime does not wire them in.

Three possible approaches were considered:

1. **Chosen:** Add a narrow, run-scoped policy preparation adapter before the existing SimpleRuntime gate, reusing production policy-source and evidence validation *rules*. Automatically derive only GitHub-owned policy locations from the repository identity; use an explicit trusted binding for any other program source. The production collector itself requires its own work, budget, and record runtime and is not inserted into SimpleRuntime as a drop-in service.
2. Scrape arbitrary linked policies or ask the LLM to search. This might find more pages, but cannot establish publisher, applicability, or stable content and creates SSRF/prompt-injection risk. Reject.
3. Accept any `SECURITY.md` or policy-kind artifact as authorization. This is quick but confuses project reporting guidance with permission to test assets and can turn an unverified record into `ALLOW`. Reject.

## Source preparation and trust boundary

During static bootstrap, before Hypothesis/Scope Gate execution, normalize the supplied repository origin and resolve the actual target owner/repository. For public GitHub repositories, consult the official GitHub repository security-policy locations on its default branch in GitHub's documented precedence (`.github`, root, `docs`), then the same owner's inherited public `.github` policy if the repository has none. Obtain the file through GitHub's documented repository-contents API or an equivalent exact Git object lookup. Do not follow arbitrary links found in the repository, accept a policy belonging to a fork's upstream as the fork's policy, or treat a GitHub private-reporting button as testing permission. The analyzed source commit and the policy revision may differ; record both explicitly.

For non-GitHub origins or external bug-bounty programs, use only a separately approved source binding through the existing production-profile policy catalog/official HTTPS fetch boundary. This first increment does not add a free-form public `--policy-url` that could become an SSRF or authority-confusion path. Without an approved binding, keep the repository's own policy as informational evidence and the final decision fail-closed. Never infer program membership or an external policy URL from a README, search result, issue, or LLM output.

Persist one immutable policy snapshot per analysis: canonical repository/program identity, source kind, source URL or Git object identity, publisher, retrieved time, revision/ETag when available, SHA-256 of the full bytes, content type, and exact source artifact reference. Store an explicit collection outcome (`FOUND`, `ABSENT`, `UNVERIFIED`, or `FETCH_FAILED`). Give the SimpleRuntime run an explicit snapshot reference; include it in each new Scope Gate checkpoint's exact input references and pass it to the gate. Do not forge production `record_revisions` rows or rely on a policy-shaped artifact kind. Bound time, response bytes, redirects, content types, and source hosts. Failed retrieval is an evidence state, not a reason to silently use a different document or leave the analysis `RUNNING`.

## Gate data flow and decision rules

The gate receives the persisted policy snapshot and technical Finding evidence. It must verify the snapshot belongs to this analysis and target, its source is approved/current for the run, its bytes match its hash, and the *entire* policy is present in the model context. Policy is placed ahead of optional prior evidence or given a reserved context budget; an oversized document yields `UNCERTAIN` rather than silent truncation. Treat policy text as quoted data, never as instructions to the Agent.

The Agent returns structured decisions for eligibility/rules, affected asset and version scope, impact requirements, testing-method restrictions, and reporting/disclosure permission. Each non-`UNCERTAIN` axis names an exact source span and short quote; deterministic validation confirms the quote exists in the pinned policy. A deterministic reducer sets `ALLOW` only if every required axis passes and no restriction conflicts with the actual PoC. An explicit exclusion yields `DENY`; any missing or conflicting evidence yields `UNCERTAIN`. The LLM cannot override source validation or the reducer. Technical `TRUE` and Technical Gate `ACCEPT` are not rewritten by policy status.

The existing gate's published-ref lookup must not by itself authorize `ALLOW`: validate collection state, program/repository binding, source set, freshness, and exact references, and retire the unvalidated shortcut for this public runtime. Reuse the production gate's closure invariants as rules, without assuming production records can be directly consumed by SimpleRuntime. A repository `SECURITY.md` may establish a reporting channel or supported versions, but it does not prove live-host testing or third-party assets are in scope unless its authoritative source and explicit terms cover them.

## Persistence, resume, and output

Freeze the source snapshot during bootstrap. `resume` reuses it and completed Agent checkpoints; a policy revision on the internet or a code upgrade does not silently change an old analysis. Existing runs without the new optional snapshot reference keep their historical gate checkpoints; new runs include the snapshot in Gate inputs from their first execution. A legacy `ALLOW` lacking verified policy provenance is **not** report-ready and must be presented as restricted at every public read/export boundary even if its checkpoint is retained. Existing A-005 stays historically `UNCERTAIN`; a fresh analysis is required to adopt a new policy snapshot. An explicit recheck operation is out of scope. If added later, it must invalidate only the dependent Scope Gate, Finding, and Reporter checkpoints, not completed PoC or technical verification.

Persist source identity, collection outcome, per-axis statuses/citations, final status, and missing-information reasons in the gate artifact. The report and dashboard distinguish `ALLOW`, `DENY`, and `UNCERTAIN`, show why, and distinguish "automatic external reporting not authorized" from an explicit policy prohibition. An available private contact channel is not displayed as a Scope Gate pass. No automatic disclosure action is added.

## Verification and limits

Add network-free tests with mocked GitHub responses for own policy, inherited owner policy, precedence, absent policy, fork identity, unexpected redirect/host, oversized/invalid content, rate limit/fetch failure, changed policy on resume, and complete versus truncated context. Gate tests cover explicit allow, explicit deny, missing axis, contradictory restriction, false citation, forged policy-kind record, legacy unverified `ALLOW`, and separate technical versus scope outcomes. Dashboard/report tests assert source and reasons without exposing secrets. Run the existing provider, SimpleRuntime, full test, lint, type-check, and documentation checks. A low-cost live smoke may check policy discovery only; a new full Codex analysis is not required to prove this feature and must not be started solely for it without a separate usage decision.

This feature cannot manufacture a policy that a project has not published, infer authorization from GitHub's private-reporting feature, or guarantee every repository will produce `ALLOW`. Those cases should remain transparently `UNCERTAIN` with a useful source-status explanation.

## Official references

- GitHub security policy and reporting: https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/add-security-policy
- Inherited community health files and precedence: https://docs.github.com/en/enterprise-cloud@latest/communities/setting-up-your-project-for-healthy-contributions/creating-a-default-community-health-file
- GitHub repository contents API: https://docs.github.com/en/rest/repos/contents
- GitHub private reporting is separate from `SECURITY.md`: https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately
