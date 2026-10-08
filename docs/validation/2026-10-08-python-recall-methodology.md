# Python-only pinned-case recall evaluation

This document fixes the **pre-analysis** answer sets for two deliberately
vulnerable training repositories and separately records measurements made
after execution. The frozen oracle files alone establish no analysis, PoC,
Finding, true-positive count, or recall percentage.

## Frozen inputs and provenance

| Role | Repository and exact commit | Frozen v2 oracle | SHA-256 of the UTF-8 file bytes |
| --- | --- | --- | --- |
| Development trial | [sgabe/DSVPWA](https://github.com/sgabe/DSVPWA/tree/c98b77950bf1c54080c4113a2488ce0509b21cff) · `c98b77950bf1c54080c4113a2488ce0509b21cff` | [`dsvpwa-c98b7795-v2.json`](../../tests/evaluation/oracles/dsvpwa-c98b7795-v2.json) | `612504f9069a95491461abbd16028c69a71e4907e695bcc0d59b6ccdebd5a9e0` |
| Held-out trial | [dev-abhrajit/VulnShop](https://github.com/dev-abhrajit/VulnShop/tree/f201193cbd3987b62050ba32357071aec0f61c18) · `f201193cbd3987b62050ba32357071aec0f61c18` | [`vulnshop-f201193c-v2.json`](../../tests/evaluation/oracles/vulnshop-f201193c-v2.json) | `8c4f27e159a7e142dbc9b6b6349522b36aa5ec41840d727aed32b19eec112a2b` |

Both oracles declare `DOCUMENTED_CASES`, **not** `EXHAUSTIVE_PYTHON`. Their
counts cannot be called a repository-wide vulnerability denominator. The
oracles contain no post-run candidate, hypothesis, Finding, PoC, or verdict
IDs. Record those in a separate review ledger bound to the exact analysis ID
and the oracle-file SHA-256. Never pass either file to `sastsimi analyze`, an
Agent prompt, or a target checkout. A changed byte requires a new hash and a
new, clearly identified evaluation version; do not edit an oracle after seeing
an analysis result and still call it the frozen trial.

These source reviews used the GitHub API tree at the pinned SHAs and the exact
raw files linked below, rather than a moving default branch. Source anchors
are one-based lines of those pinned files; they are not assertions that a
corresponding SASTSIMI candidate or verified Finding exists.

## Development trial: DSVPWA

The pinned [README](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/README.md)
names 12 **vulnerability categories**, not 12 distinct code paths. The
pinned [`db/attacks.xml`](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/db/attacks.xml)
registers 13 routes: both SQL injection and XSS have separate paths. The
README also mentions insecure transport, for which no attack route is
registered. The oracle therefore has **14 source-reviewed documented cases**:
12 provisionally in the Python product-code scope and two predeclared outside
this benchmark scope. A Python-scope label is eligibility for later evaluation,
not a claim of successful exploit verification.

Unless a row says otherwise, the reproduction context is the default
**vulnerable** mode (`--secure` absent), a local-only server, and a fresh
in-memory database initialized by
[`server.py` 19–26](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/dsvpwa/server.py#L19-L26).
The default risk level is 1; only the two explicitly labelled risk-3 cases
need `--risk 3`. A static match alone cannot establish their exploit outcome.

| Case IDs | Route or condition | Pinned source anchors | Scope decision |
| --- | --- | --- | --- |
| `dsvpwa-login-sqli`, `dsvpwa-users-sqli` | `/login`, `/users`: distinct inputs and SQLite query construction | [`attacks.py` 463–474, 98–106](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/dsvpwa/attacks.py) | Python; do not collapse the two flows. |
| `dsvpwa-reflected-xss`, `dsvpwa-stored-xss` | `/post`, `/guestbook`: raw response content and stored comment rendering | [`attacks.py` 166–176, 184–215](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/dsvpwa/attacks.py) | Python creates unescaped HTML; browser interpretation must still be verified. |
| `dsvpwa-command-injection`, `dsvpwa-unsafe-deserialization` | `/diag`, `/extract`: shell and `pickle.loads` paths | [`attacks.py` 278–304, 330–355](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/dsvpwa/attacks.py) | Python; both are disabled unless `--risk 3` (the default is risk 1). Do not run outside a disposable isolated environment. |
| `dsvpwa-path-traversal` | `/docs`: request path reaches unrestricted local file open | [`attacks.py` 358–377](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/dsvpwa/attacks.py) | Python; this case is the file branch, not the separate URL-open branch. |
| `dsvpwa-session-fixation` | `/home` sets an attacker-supplied `SESSIONID`; `/login` reuses it | [`attacks.py` 394–401, 448–480](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/dsvpwa/attacks.py) | Python; one root-cause case requires both operations. |
| `dsvpwa-csrf-settings`, `dsvpwa-execution-after-redirect` | `/settings` changes state without intent check; `/admin` builds protected content before client-side redirect | [`attacks.py` 528–569, 261–275](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/dsvpwa/attacks.py) | Python missing-guard cases; browser/cookie behavior still needs independent proof. |
| `dsvpwa-open-redirect` | `/jump` embeds the chosen path in an emitted navigation script | [`attacks.py` 245–258](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/dsvpwa/attacks.py) | Python constructs the unsafe response; browser navigation is the impact condition. |
| `dsvpwa-clickjacking` | `/danger` has a destructive action; vulnerable-mode headers omit anti-framing controls | [`attacks.py` 572–616](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/dsvpwa/attacks.py), [`handlers.py` 264–283](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/dsvpwa/handlers.py) | Python response configuration; a frameable browser response must be verified. |
| `dsvpwa-session-hijacking-lesson` | `/profile` accepts an already valid bearer session ID | [`attacks.py` 427–445](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/dsvpwa/attacks.py), [learning guide 68–86](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/LEARNING.md) | Outside the current Python case denominator: token acquisition and expiry threat model are not established by this bearer-token lookup alone. Do not turn normal session lookup into an FN. |
| `dsvpwa-insecure-transport-lesson` | Optional TLS is off by default, but binding defaults to localhost | [`dsvpwa.py` 17–26, 32–47](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/dsvpwa.py), [learning guide 158–171](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/LEARNING.md) | Outside this static Python application-case denominator; exposure requires an independently specified network/deployment setting. `CWE-319` is reviewer-assigned, not attack-XML metadata. |

The [request dispatcher](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/dsvpwa/handlers.py#L160-L285)
parses GET parameters and invokes the registered attack classes. Its separate
`do_BDR` shell route and the `/docs` URL-open branch are not represented as
independent oracle cases because they are outside this **documented-case**
inventory. That is another reason not to claim exhaustive repository recall.
The [learning guide](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/LEARNING.md)
also distinguishes the two code-execution lessons and says the CSRF secure-mode
counterpart is not a complete CSRF defense. Preserve those conditions when
adjudicating any PoC.

## Held-out trial: VulnShop

The pinned [README vulnerability cheatsheet](https://github.com/dev-abhrajit/VulnShop/blob/f201193cbd3987b62050ba32357071aec0f61c18/README.md#L52-L108)
documents **five route-level cases** (not four CWE classes): reflected XSS,
product SQL injection, login SQL injection, admin role bypass, and profile
CSRF. The oracle has four Python-scope cases plus one predeclared out-of-scope
template case.

Reproduction assumes the README's local Flask setup and an initialized
SQLite database from [`database.py`](https://github.com/dev-abhrajit/VulnShop/blob/f201193cbd3987b62050ba32357071aec0f61c18/database.py).
The admin and CSRF cases require an authenticated ordinary user, but a tool
must not infer those conditions from a source-location match alone.

| Case IDs | Pinned source anchors | Scope decision |
| --- | --- | --- |
| `vulnshop-reflected-xss-template` | [`app.py` 28–32](https://github.com/dev-abhrajit/VulnShop/blob/f201193cbd3987b62050ba32357071aec0f61c18/app.py#L28-L32) passes the query into [`templates/search.html` 10, 18](https://github.com/dev-abhrajit/VulnShop/blob/f201193cbd3987b62050ba32357071aec0f61c18/templates/search.html#L10-L18), where `| safe` is the essential sink | Outside a `.py`-only scan; a Python entrypoint hint alone is not a Python-code TP. |
| `vulnshop-products-sqli`, `vulnshop-login-sqli` | [`app.py` 40–50, 57–70](https://github.com/dev-abhrajit/VulnShop/blob/f201193cbd3987b62050ba32357071aec0f61c18/app.py) | Two distinct Python input-to-SQL operations; do not deduplicate them. |
| `vulnshop-admin-role-bypass` | [`app.py` 101–108](https://github.com/dev-abhrajit/VulnShop/blob/f201193cbd3987b62050ba32357071aec0f61c18/app.py#L101-L108) | Python role-check omission after login check; `CWE-863` is reviewer-assigned. |
| `vulnshop-profile-csrf` | [`app.py` 116–128](https://github.com/dev-abhrajit/VulnShop/blob/f201193cbd3987b62050ba32357071aec0f61c18/app.py#L116-L128) | Python token-check omission; browser/session conditions still require proof. |

The code also contains a hardcoded Flask secret and `debug=True`
([`app.py` 5–6, 136–137](https://github.com/dev-abhrajit/VulnShop/blob/f201193cbd3987b62050ba32357071aec0f61c18/app.py)); the pinned
cheatsheet does not enumerate these as separate route-level cases. Do not
classify an additional Finding automatically as false positive merely because
it is outside this oracle. The holdout was source-reviewed to freeze its
answers **before its first run**, but it is not unseen to a human author;
do not use its answers to choose or tune the DSVPWA fix. Run it once after
locking the change.

## Adjudication and reporting protocol

1. Verify the analysis checkout URL and exact commit, both oracle hashes, the
   selected Python `.py` product-file inventory, planned file×rule coverage,
   model/profile, and analysis ID. Excluded tests or nonPython files are not
   successful Python scans.
2. Run the tool without oracle or review-ledger inputs. Keep raw candidates,
   hypotheses, PoC artifacts, Scope Gate records, Findings, and reports separate.
   A `PARTIAL`, `BLOCKED`, or `FAILED` run is never relabelled `COMPLETE` by
   evaluation.
3. After the run, independently inspect the entire Finding inventory and the
   case-specific static/deep/PoC stages. Record exact candidate, hypothesis,
   and Finding IDs with evidence in a **separate** review ledger tied to the
   oracle hash and analysis ID. One verified Finding may not satisfy two
   different cases just because a CWE or file name matches. Multiple verified
   Findings for one case count as one case TP, while retaining their raw count.
4. Score `TP` only with a current verified PoC, final TRUE, Technical Gate,
   valid report evidence, and an independently reviewed same-root-cause match.
   A covered and independently reviewed Python case without a match may be
   `FN`. Environment failures, unexecuted PoCs, nonterminal work, or Python
   file×rule coverage holes leave an unproven case at `HOLD`, never FN.
   Unrelated uncovered attack surfaces keep the **analysis** `PARTIAL`, but do
   not erase a separately verified, report-backed TP; an unmatched case under
   that partial coverage remains HOLD rather than FN. A damaged static or
   Finding artifact fails the evaluator without a numeric score; it is not
   reclassified as `HOLD`. Ambiguous matches remain `REVIEW_REQUIRED`.
   Predeclared nonPython/operational cases are `OUT_OF_SCOPE`.
5. An unmatched Finding is `UNMATCHED_REVIEW_REQUIRED`, **not** automatically
   `FP`. Count `FP` only with a separate evidence-backed false-positive review.
   Publish raw Finding count, conservative display-group count, oracle case
   counts, candidate/hypothesis/PoC stage counts, and first gaps separately.
6. Only print `TP / (TP + FN)` for the **documented, evaluable Python cases**
   if no in-scope HOLD or review-required cases remain. Never label that number
   whole-repository recall. Technical detection does not authorize an external
   vulnerability submission; policy/Scope Gate must be checked separately.

## Measured held-out result: VulnShop

The isolated Codex `gpt-6-sol` run at the frozen VulnShop commit has exact
analysis ID `7ffb6b24a8764373a7efcee57feab69e`. It finished as **PARTIAL**,
not COMPLETE: the Python static file×rule ledger is 24/24 verified, and all 25
collected candidates received a triage decision (7 INCLUDE, 15 EXCLUDE, 3
UNDECIDED), but attack-surface review recorded 16 covered and **17
insufficient** surfaces. The run processed 29 hypotheses and 28 PoC attempts;
24 raw Findings have current reports. Paused token-budget checkpoints were
resumed under the **same** analysis ID, retaining completed work. The final
LLM attempt ledger records 328 attempts, 7,320,817 input tokens, and 337,582
output tokens. These counts describe this one trial, not an expected cost for
other repositories.

This run predates the later Docker recovery-build correction in this PR. Its
saved result is evidence for the tool version used by that trial, **not** an
end-to-end rerun of the final PR tree. The trial data did not record an exact
SASTSIMI code revision, so no revision is inferred from the analysis ID or
commit history. The frozen target repository commit and oracle hash above are
separate from that unrecorded tool revision.

The separate [post-run review ledger](reviews/vulnshop-f201193c-v2-review.json)
matched 21 report-backed Findings to the frozen four Python cases. Each case
has at least one independently checked same-root
Finding with an executed PoC, final TRUE, Technical Gate ACCEPT, and report
evidence:

| Frozen Python case | Case score | Distinct raw Finding IDs reviewed as the same case |
| --- | --- | --- |
| Products SQL injection | TP | F-001, F-004–F-010, F-012 |
| Login SQL injection | TP | F-002, F-003, F-011, F-014–F-018 |
| Admin role bypass | TP | F-013, F-020, F-022 |
| Profile CSRF | TP | F-024 |

For the admin case, the reports use CWE-862 while the frozen oracle uses
CWE-863; the independent review verified the same ordinary-user `/admin`
role-check omission rather than treating a label match as proof. For profile
CSRF, F-024's headless-browser PoC recorded a cross-site form POST with the
session cookie and a changed database email. An earlier inconclusive CSRF
hypothesis is **not** counted as a TP. F-019, F-021, and F-023 are separately
reviewed findings outside the five documented route-level oracle cases;
they remain `UNMATCHED_REVIEW_REQUIRED`, **not** automatic false positives.
The template-dependent reflected XSS case remains predeclared
`OUT_OF_SCOPE` for this `.py`-only evaluation.

The strict scorer therefore reports **4 TP, 0 FN, 0 HOLD, 1 OUT_OF_SCOPE**;
`4 / 4 = 100%` is the recall of these **documented, evaluable Python cases
only**. It is not repository-wide recall, proof that the 17 insufficient
surfaces are safe, or proof of zero false positives. No Finding was separately
adjudicated false positive, so an FP rate is **not measured**. `PARTIAL` remains
the overall analysis state. Scope Gate or private-disclosure authorization
must be checked before any external report; a technically confirmed training
Finding is not automatically submission-ready.

The [saved scorer output](results/vulnshop-f201193c-v2-score.json) and
[redacted CAS-hash provenance](results/vulnshop-f201193c-v2-provenance.json)
bind all 24 Finding IDs to their PoC, final-verification, Technical Gate, and
report artifact hashes. The underlying run database and artifact bytes remain
in the isolated local trial directory and are **not** published in this PR;
the published ledger and hashes are an adjudication record, not standalone
reproducible exploit evidence. A reviewer needs those local bytes to rerun
the strict scorer and independently inspect the PoCs.

After this run, the read-only evaluator was tightened so a fully verified,
human-matched case can be TP despite unrelated uncovered surfaces, while an
unmatched case cannot become FN under `PARTIAL`. This changed the **scoring
implementation**, not the frozen oracle or saved analysis. The detector was
not tuned to VulnShop source, but this is not an untouched, preregistered
scorer result; the correction and its fail-closed regression tests are part of
this PR.

## Development-trial status

The first fresh DSVPWA run, analysis ID
`583994a460304ad2acf0b2af488faab2`, stopped as **BLOCKED** at
`POC_ENVIRONMENT_UNVERIFIED`; it did not reach a candidate terminal. Its Python
file×rule coverage was 60/60, and seven Findings had reports, but that is not
a completed recall measurement. Four reports provisionally matched different
frozen cases (command injection, `/users` SQL injection, unsafe
deserialization, and local-file traversal); three reports concerned separate
or duplicate roots outside this documented-case oracle. No final TP/FN or
recall value is assigned to this blocked run.

For the browser-based CSRF PoC, a recovery Docker build appended an
`apt-get install` after the repository Dockerfile had removed its apt package
lists. The build failed to locate Chromium. A source-only fallback image was
then correctly rejected as unverified instead of being used as PoC evidence.
This run is preserved. Ordinary `resume` cannot safely rebuild that bound
recipe; the subsequent isolated trial after the generic build fix received
a new analysis ID while using the **same pre-run oracle**.

## Measured development result: DSVPWA

The second isolated run at the frozen DSVPWA commit has exact analysis ID
`4bd80ec92d344543b9e629d52242948e`. It reached its candidate terminal
as **PARTIAL**, not COMPLETE: Python static file×rule coverage was 60/60;
50/50 candidates were triaged (28 INCLUDE, 12 EXCLUDE, 10 UNDECIDED), and
38/38 selected candidates finished deep analysis. It processed 41
hypotheses and 24 PoC attempts. Attack-surface review covered 16/51 surfaces
and left **35 insufficient**; one test file and three nonPython product files
were outside the Python product-code scan. Seven raw Findings each have a
report, executed PoC, final TRUE, Technical Gate ACCEPT, and intact PoC,
Finding, and report CAS references. Scope Gate remained **UNCERTAIN** because
no published target policy was available; these are not automatically
submission-ready.

The independent [post-run review ledger](reviews/dsvpwa-c98b7795-v2-review.json)
matches only F-001 to one frozen case: the `/users` request `id` reaches a
concatenated SQLite query. Its PoC compared ordinary and injected IDs in the
attack class **in process**; it did not replay the HTTP route. The matched
source/sink, PoC, final TRUE, Technical Gate, and report satisfy the strict
scorer's case criteria, but the narrower reproduction boundary must be kept
visible. The six other raw Findings are not matches to the frozen 12 Python
cases: F-002/003 share one static-file symlink root, F-004/005/007 share a
separate `do_BDR` shell root, and F-006 is the `/docs` URL SSRF branch rather
than the oracle's local-file traversal. They are **review-required unmatched
Findings**, not automatically false positives. Seven raw Findings thus
represent four reviewed roots, of which one matches this documented-case
oracle; display grouping never changes the source records or the TP count.

Four remaining documented cases reached a relevant hypothesis but not final
verification: reflected XSS, `/diag` command injection, unsafe
deserialization, and `/docs` local-file traversal. The XSS and command
injection PoCs did not establish their HTTP route; the deserialization
hypothesis stopped before PoC; the file-path PoCs showed an in-process
outside-directory read but not the HTTP route. Seven other documented cases
did not acquire a validated hypothesis for the **exact** route and root:
login-password SQL injection, stored XSS, session fixation, settings CSRF,
admin execution-after-redirect, jump open redirect, and clickjacking.
Related candidates or same-CWE hypotheses for different inputs/routes are
not credited to these cases. This is the observed gap breakdown, not proof
that those seven paths are safe.

The [saved strict score](results/dsvpwa-c98b7795-v2-score.json) is **1 TP,
0 established FN, 11 HOLD, 2 predeclared OUT_OF_SCOPE**, with 1 matched and
6 review-required unmatched raw Findings. `recall` is **null**, not `1/12`
or 100%, because the 35 insufficient surfaces make unmatched cases
inconclusive under `PARTIAL`. No false-positive rate is measured. The frozen
oracle and separate review ledger were never given to the analysis Agents.
The second run was launched before the later commit-pinned XML route helper,
additional OpenGrep hints, and bounded Git timeout retry were committed. Its
measured outcomes therefore cannot be attributed to those later changes.
The underlying run database and artifact bytes remain in isolated local
trial data, not in this PR; the published review and score alone do not
reproduce an exploit.

## Commit-pinned PoC route context added after the trial launch

The first DSVPWA run showed a separate PoC-generation gap: a cited Python
attack class did not itself name its HTTP route. The route was registered in
tracked `db/attacks.xml`, which another Python module loaded. The optional PoC
context helper now looks for this class-to-route relationship using pinned
Python and XML blobs, emits only bounded route/path/hash scalars, and labels
them **untrusted hints**. It does not claim a route when indexing, parsing, or
its explicit size/time limits prevent a complete check; a missing hint is not
evidence that a route is absent. Static coverage and final PoC verification
remain unchanged.

A read-only helper check against the frozen DSVPWA commit and cited
`dsvpwa/attacks.py:287` returned `CommandInjection -> /diag`, referencing
`db/attacks.xml` through `dsvpwa/handlers.py`, with pinned resource hashes.
This verifies the helper's input construction, **not** that the second
end-to-end analysis used the later patch or that its recall improved. The
isolated end-to-end trial launched before this helper was added; its score
must be attributed to its launch-time tool code, not to this final PR tree.

## Generic Python candidate hints added after the trial launch

The development trial also exposed a candidate-collection gap: several
documented Python paths had no direct static hint. The candidate rule pack
now includes bounded hints for query parsing, unsafe deserialization,
identity-cookie writes, dynamic redirect targets, and direct
`BaseHTTPRequestHandler` HTTP-method entries. They are **hints**, not verified
input-to-sink flows or vulnerability verdicts. A query parser is labelled
`POSSIBLE_REQUEST_INPUT`, not a proven request source. Constant redirects and
unrelated cookie keys have negative-rule tests; JavaScript redirects assembled
as HTML strings remain outside these new patterns because a broad string
rule would be unreliable.

A read-only OpenGrep probe of the exact DSVPWA commit scanned five tracked
Python product files with 17 selected Python rules and recorded no scan
errors. The new rules emitted six location hints: one deserialization call,
two identity-cookie writes, two HTTP method handlers, and one query parser.
These counts are **not** Finding, PoC, TP, or recall counts. The probe output
stays in ignored local trial data; no oracle was supplied to the scanner.
Adding rules changes the static scope fingerprint, so the already-running
DSVPWA analysis retains its original static evidence and cannot be cited as
an end-to-end validation of the expanded rules. A new analysis ID is required
to measure their eventual effect on verified findings.

The pinned Git reader now retries a timed-out read once, keeping each attempt
finite and rejecting partial subprocess output. This addresses a possible
transient host-I/O failure mode without relaxing commit, path, blob, or source
hash checks. It does not prove the exact cause of an earlier generic
`HYPOTHESIS_ANCHOR_INVALID`, whose inner exception was not persisted.
