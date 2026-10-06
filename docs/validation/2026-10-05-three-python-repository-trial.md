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
- Distinguish shell variables from `$` inside a non-expanding quoted heredoc
  body. Direct Python heredocs exempt only literal dictionary keys (needed for
  Mongo operators such as `$ne`); other `$variables` and bodies that may launch
  a child shell are checked. Quoted child-shell bodies use their own assignment
  scope. Keep the host-path/URL checks over the complete script. This validator
  is a conservative input check, not a proof that arbitrary Python cannot
  launch a shell; Docker isolation remains necessary.
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
