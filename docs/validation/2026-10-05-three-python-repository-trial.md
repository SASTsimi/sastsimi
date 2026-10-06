# Three-repository Python reliability trial (2026-10-05)

This trial checks three distinct, deliberately vulnerable Python applications at
pinned commits. Each run has its own data directory. No external answer key was
passed to the tool; repository README files remained in the checkout and may be
visible to normal repository inspection. Published example vulnerabilities were
consulted only after the first run reached a terminal state. These are training
repositories, not targets for disclosure.

| Repository | Pinned commit | First-run exact analysis ID | First-run terminal result |
| --- | --- | --- | --- |
| [vfapi](https://github.com/naryal2580/vfapi) | `f36f177e1a32aa49272f4eb52f8be0af3e8f6bc3` | `66dfb53639354d7998d449af50724e03` | `BLOCKED`: PoC validator rejected MongoDB `$ne` inside a quoted Python heredoc as an undeclared shell input |
| [insecure-web](https://github.com/brenesrm/insecure-web) | `5d1b791bb6c2d1397843f29ee6a0d5c9386dd667` | `c529bff7a8dc4d099b20a4b43fed5f81` | `FAILED`: verification compared a redacted source line with raw pinned Git content |
| [dvpwa](https://github.com/anxolerd/dvpwa) | `a1d8f89fac2e57093189853c6527c2b01fc1d9c1` | `61bb228a12124a79a1e04c5665671669` | `PARTIAL`: 7 non-Python product files were outside the Python scanner scope, and 6 security surfaces remained insufficiently reviewed |

The first-run candidate/decision/hypothesis/finding counts were respectively:

| Repository | Candidates | INCLUDE | EXCLUDE | UNDECIDED | Hypotheses | Findings |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| vfapi | 4 | 3 | 1 | 0 | 2 | 0 |
| insecure-web | 11 | 9 | 2 | 0 | 9 | 0 |
| dvpwa | 12 | 0 | 4 | 8 | 1 | 0 |

All three first runs had zero unresolved Python file-by-rule static scan pairs.
This does **not** mean that every vulnerability was found: static hints,
discovery decisions, hypotheses, executed PoCs, confirmed findings, and report
files are separate evidence levels. For dvpwa, out-of-scope SQL/JavaScript/shell
product files are correctly shown as a whole-repository coverage limitation;
they must not be relabeled as scanned Python code or silently ignored.

## Generic reliability fixes exercised

- Compare cited context against the pinned source using the **same redaction
  policy** that produced the context, while still checking the raw blob SHA-256.
  A changed source hash or altered safe line remains an anchor failure.
- On explicit resume, retry only a failed verification anchor with a bounded
  attempt count. Retain completed Pro/Con and sibling work; do not reopen a
  different PoC environment failure or bypass the attempt cap.
- Keep undeclared `$name` tokens rejected even in quoted Python heredocs:
  parsing Python alone cannot prove that a string will never reach a child
  shell. Construct an inert Mongo operator key at runtime, for example
  `chr(36) + 'ne'`. Quoted child-shell bodies use their own assignment scope;
  host-path and URL checks still cover the complete script. This conservative
  input check does not replace Docker isolation.
- Extend the same generic Python request-source rule with tested aiohttp
  request-body calls, FastAPI route decorators for common HTTP methods, and
  Flask JSON/cookie/header reads. These remain entry-point hints, not verified
  source-to-sink flows. Add a password-variable-specific MD5 hint without
  flagging an ordinary file checksum as a password vulnerability.

## Follow-up after the generic validator fixes

| Repository | Follow-up identity and outcome | Candidates | Hypotheses | Findings |
| --- | --- | ---: | ---: | ---: |
| vfapi | New isolated ID `7d31257c848c4c2085955c7bfe9f7fb5`; `$ne` false rejection cleared, then `BLOCKED: POC_ENVIRONMENT_UNVERIFIED` | 4 | 4 | 0 |
| insecure-web | Same ID `c529bff7a8dc4d099b20a4b43fed5f81` resumed; redacted anchor retry cleared, then `BLOCKED: POC_ENVIRONMENT_UNVERIFIED` | 11 | 9 | 0 |
| dvpwa | New isolated ID `a19e2e2ac9464def88cd9ff86d017e48` with expanded source/hash hints; `BLOCKED: POC_ENVIRONMENT_UNVERIFIED` | 19 | 4 | 0 |

All three PoC failures mean the product dependencies could not be verified in the
isolated Docker environment. Loosening Docker network isolation to make the
demonstration pass would change its security assumptions, so this trial did
not do that. The first runs and follow-ups cannot establish either a
false-negative rate or a duplicate-report reduction: they produced no
completed, independently verified finding/report sets.

The repository-provided examples, consulted after the first run, are two
injection classes in vfapi (NoSQL and SQL), a list of weak web-application
practices rather than a counted vulnerability oracle in insecure-web, and four
documented classes in dvpwa (session fixation, SQL injection, stored XSS, weak
MD5 password storage). Dvpwa also has non-Python product code; its four
classes are not a whole-repository Python-only recall denominator. The
new rule-set follow-up is exploratory rather than another oracle-blind trial.
In that follow-up, Python file-by-rule gaps stayed at zero and the 19 candidates
comprised 12 existing SQL-sink hints, six request-source entries, and one new
weak-password-hash hint at `sqli/dao/user.py:41`. Decision counts were 14
INCLUDE, two EXCLUDE, and three UNDECIDED. The new MD5 candidate reached deep
analysis but did not become a finding. An unavailable product
dependency, inconclusive hypothesis, or zero findings is not a confirmed clean
result. No training-repository result here is report-ready for real disclosure.

## Additional isolated runs (2026-10-06)

The later feature-branch runs below preserve the earlier analysis databases.
They used the same pinned commits and Codex `gpt-6-sol`, but did not all reach
the same terminal stage, so their counts are **not** a controlled recall or
false-positive-rate comparison. These results predate integration with the
newer dashboard changes on `main`.

| Repository | Earlier run | Later run | Evidence observed | Remaining limitation |
| --- | --- | --- | --- | --- |
| vfapi | `vfapi-v5`: 3 raw TRUE Findings, 3 conservative groups | `vfapi-v7`: 4 raw TRUE Findings, 4 groups | The README's `/select` SQL injection appears in both; its `/find` NoSQL injection appears as a Finding in v7 only | Both analyses are `BLOCKED`; v7 exhausted three PoC setup attempts on another hypothesis. The additional generic SQL hypothesis lacks a proven upstream input and is not another oracle hit. |
| insecure-web | `insecure-web-v2`: 10 raw TRUE Findings, 5 conservative groups | `insecure-web-v3`: 3 raw TRUE Findings, 3 groups at interruption | v2 groups repeated SQLi/XSS flow reports only when the same flow was proven | v3 stopped at 37% with an unresolved Codex call. Its lower count cannot demonstrate better deduplication or lower recall. The README does not enumerate an exact route-by-route answer key. |
| dvpwa | `dvpwa-v2`: 0 Findings | `dvpwa-v4`: 0 Findings | v4 added MD5 and session-write hints alongside student SQLi hints | v4 remains `PARTIAL`. Legacy pinned dependencies lack a verified Python 3.12 binary wheel closure; a Python-only scanner cannot cover the non-Python stored-XSS template path. No hypothesis reached a confirmed Finding. |

Every recorded Finding above still has `UNCERTAIN` Scope Gate status; none is
automatically ready for disclosure. A static hint or hypothesis is not a
confirmed vulnerability, and an incomplete run cannot turn an unprocessed
README example into a measured false negative. The follow-up also exposed
PoC fixture/storage failures and unresolved subprocess cleanup; these are
being fixed independently of vulnerability verdicts.

## Integrated branch checkpoint (2026-10-07)

The `codex/portable-poc-validation` branch includes `main` through the merged
dashboard change in PR #216. These later runs use new, isolated IDs at the same
pinned commits; no earlier database was reset. The counts below are terminal
for these three run IDs. They are not controlled before/after recall or
false-positive rates.

| Repository and run | State | Candidates | Hypotheses | Saved Findings | What the result establishes |
| --- | --- | ---: | ---: | ---: | --- |
| vfapi `vfapi-v8` (`a4c3888a8e5c49b1bea13be090d04164`) | `BLOCKED: RECOVERY_EXHAUSTED` | 20 | 11 | 9 | The repository's documented SQL and NoSQL injection classes both appear in saved Findings. A different PoC exhausted three attempts; its last script failed to recognize a keyword-only `aiosqlite.connect(database=...)` call. This is a generated-PoC failure, not a vulnerability disproof or a completed analysis. |
| insecure-web `insecure-web-v4` (`3ccba250919d469782fc8a3bb9a1c465`) | `PARTIAL` | 12 | 39 | 34 | All recorded Python file-rule checks completed, but two security surfaces remained insufficiently reviewed. The result projection shows nine groups: four proven same-flow groups and five undetermined standalone entries. The 34 raw Findings are not 34 independent vulnerabilities. |
| dvpwa `dvpwa-v5` (`71eb210d781f4eb780d76f68a5aef95e`) | `PARTIAL` | 20 | 8 | 0 | All 252 planned Python file-rule checks completed, but seven non-Python product files remain outside the Python-only scan. Pinned `aiohttp==3.5.3` has no compatible binary distribution for the configured Python 3.12 PoC environment, so the eight hypotheses stopped as inconclusive rather than being called false. |

Human review previously estimated approximately five distinct vfapi
request/weakness surfaces among its nine raw reports, but that is **not** a
verified automatic group count or an oracle score. For insecure-web, the
verified projection reduced 34 raw reports to nine displayed groups while
retaining five undetermined flows separately. Grouping solely by route or
weakness could erase distinct vulnerabilities; all original Findings and PoCs
remain available. The vfapi run cannot be resumed past its persisted
three-attempt exhaustion without a new, supported run. No result in this
section is automatically ready for external disclosure.

A read-only spot audit of insecure-web-v4's four proven groups found 29 members
with successful PoC exits and technical `ACCEPT` decisions. The groups follow
four distinct input-to-operation paths: `/dashboard` session cookie to HTML
(7), `/login` username to SQL execute (11), `/login` password to the same SQL
execute (2), and `/search` query to HTML (9). In particular, the two `/login`
inputs remain **separate groups despite sharing a sink**. Five reports remain
undetermined singletons. No cross-flow merge was found in this frozen-run spot
audit, but it is not a general proof of zero false merges or a false-positive
rate.

## PoC/runtime follow-up in progress (2026-10-07)

The PoC-candidate input now includes the pinned Pro/Con source anchor and
requested tracked files. Retry context prioritizes the current structured
candidate/execution record and gate feedback; oversized historical scripts
and logs are optional rather than silently displacing required evidence.
The initial-verification Agent may request an evidence-backed explicit
`python:X.Y[.Z]` runtime only when an operator supplies an already-local image
digest. The actual interpreter version is probed without network access.
Neither change makes unsupported dependencies installable or guarantees a PoC.

The vfapi and dvpwa rows below are terminal results after resuming the same
isolated analysis IDs. This is not a controlled before/after comparison. Both
runs used the same pinned source commits as above and kept earlier databases
intact.

| Repository and run | State | Candidates | Hypotheses | Saved Findings | Evidence and limitation |
| --- | --- | ---: | ---: | ---: | --- |
| vfapi `vfapi-v9` (`6fa2afeeb78b41e8b4a19771c509d7b5`) | `PARTIAL` (terminal) | 20 | 18 | 17 | All 12 planned Python file-rule checks completed; 18 PoC executions, 17 Finding/Scope Gate/report stages, and 17 English/Korean/PoC/evidence bundles were saved. The earlier keyword-only `aiosqlite.connect(database=...)` PoC error did not recur as a terminal failure. Ten non-Python product files are outside the Python-only scope and two security surfaces remained insufficiently reviewed, so this is not COMPLETE. The current conservative projection still displays 17 singleton reports; it has not proven a vfapi duplicate reduction. |
| dvpwa `dvpwa-v6` (`c415cb4fb2344948a97c458bce10b189`) | `PARTIAL` (terminal) | 20 | 9 | 0 | Seven Initial Verification checkpoints ended in `HOLD`: the pinned Python 3.6 dependency closure cannot be resolved with compatible Linux binary wheels. No validated PoC or Finding resulted; `HOLD` is not a vulnerability disproof. |

After the vfapi run, a read-only manual check against its pinned README's two
demonstrated attack examples found both: GET `/select` SQL injection (F-003's
validated PoC distinguishes a zero-row control from a two-row injected ASGI
response) and POST `/find` NoSQL operator injection (F-002's validated PoC
gets different HTTP 200 user results for ordinary and `$ne` filters with
MontyDB). Thus the **two documented examples are represented, 2/2**, not that
all repository vulnerabilities were found. The 17 raw Findings include
plausible repeat reports across those and other routes. A read-only human
inspection suggested several shared root causes, but the automatic projection
still leaves all 17 separate because their final evidence does not prove the
same complete flow. We rejected an experimental route-only extension after
counterexamples showed it could merge distinct SQL operations. No automatic
false-positive rate or safe duplicate-reduction count is claimed for vfapi;
its Scope Gate is `UNCERTAIN` and this training fixture is not for disclosure.

The runtime switch addresses the interpreter mismatch, **not** the legacy
wheel closure. A separate wheel-only/no-dependency-execution check in the
verified local Linux CPython 3.6 image found wheels for 16 of 18 direct pins;
`PyYAML==3.13` and `trafaret-config==2.0.2` had none. With those two excluded
solely for diagnosis, the resolver also could not obtain the conditional
transitive `idna-ssl>=1.0` wheel. This check did not produce a complete
installable closure or rerun the analysis, and never omitted the pinned
requirements in SASTSIMI. A saved dvpwa request-source candidate (`f482…`) exposed a
separate retry-guidance error: the bounded location examples included the
route at `sqli/routes.py:13` but omitted the directly called body at
`sqli/dao/student.py:41–45`. The revised guidance includes those exact lines
when evaluated against the saved context, while preserving strict allowed-line
validation. **No fresh Agent run has tested whether this changes the candidate
or Finding outcome.** Dvpwa's stored-XSS template remains outside this
Python-only static scope. These observations do not establish improved recall,
fewer false positives, a universally successful PoC pipeline, or report-ready
findings. The separate insecure-web projection is a measured within-run
display reduction, not proof that this PoC/runtime patch improved deduplication.
