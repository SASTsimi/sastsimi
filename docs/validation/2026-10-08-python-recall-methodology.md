# Python-only pinned-case recall evaluation

This document fixes the **pre-analysis** answer sets for two deliberately
vulnerable training repositories. It records evidence and scope decisions, not
an SASTSIMI result. No analysis, PoC, Finding, true-positive count, or recall
percentage is established by the existence of these files.

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
   `FN`. Environment failures, unexecuted PoCs, nonterminal work, static
   coverage holes, or damaged evidence are `HOLD`, never an FN or TP. Ambiguous
   matches remain `REVIEW_REQUIRED`. Predeclared nonPython/operational cases
   are `OUT_OF_SCOPE`.
5. An unmatched Finding is `UNMATCHED_REVIEW_REQUIRED`, **not** automatically
   `FP`. Count `FP` only with a separate evidence-backed false-positive review.
   Publish raw Finding count, conservative display-group count, oracle case
   counts, candidate/hypothesis/PoC stage counts, and first gaps separately.
6. Only print `TP / (TP + FN)` for the **documented, evaluable Python cases**
   if no in-scope HOLD or review-required cases remain. Never label that number
   whole-repository recall. Technical detection does not authorize an external
   vulnerability submission; policy/Scope Gate must be checked separately.

No actual trial outcome is entered here yet. The development and held-out
results must be appended with analysis IDs, exact counts, first-gap evidence,
and before/after conditions after those runs finish. An absent result is
**not** a zero.
