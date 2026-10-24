# Six educational repositories: pinned Python static measurement

Measured on 2026-10-24 KST from SASTSIMI `main` at
`39676cc4fa03eb83f67963a0dcf9421e05a2b222`. This is a **new AST and
OpenGrep measurement**, not a reproduction of the final presentation's full
agent/PoC/Finding benchmark. No LLM, PoC, CodeQL, Semgrep, or vulnerability
submission was run for this measurement. `AST_OPENGREP_COMPLETE` describes only
the measured Python AST and OpenGrep scope, **not** a complete SASTSIMI analysis.

## Historical result versus new evidence

The team's final presentation (`최종발표.pdf`, slides 16–17, SHA-256
`d654f0dfab6e59b7abce796d49fb27a2ec588f40c17f89891611439087c8b8f3`)
has six rows whose answer and corresponding-result totals are 53 and 50,
respectively, and records 37 duplicate reports. The ratio 50/53 is calculated
from those rows, not printed as a case-level result in the PDF.
The embedded chart workbook in the supplied `최종발표.pptx` (SHA-256
`befd8af850c99ebafc7567ea94452deeb9465eebe742252e02a5e8fe65f03627`,
`ppt/embeddings/Microsoft_Excel_Worksheet.xlsx`, `Sheet1!A1:F7`) independently
confirms the **six aggregate rows** in the table. A machine-readable
[transcription](data/six-educational-historical-aggregate.json) preserves the
original GT/TP/FP/FN counts and their source. The chart's “TP” and “FP” are
the presentation authors' categories, **not independently revalidated
Findings**.
The supplied presentation and supporting ZIP do not identify the target
commits or provide a 53-row answer → run → Finding mapping. These figures
therefore remain **historical internal counts, not a verified current-main
recall or duplicate-rate measurement**. The repositories below are independently
pinned candidates; their SHAs are not claimed to be the presentation's SHAs.
At the pinned candidates, DSVPWA's 13 documented attack IDs leave four of the
presentation's 17 cases unidentified; BreakableFlask's 8 numbered route entries
likewise leave four of 12 unidentified. The other inventories use different
units (categories, labels, or endpoints), so their matching totals alone do
not establish a case-level correspondence. The [historical aggregate record](data/six-educational-historical-aggregate.json)
records each first-party inventory's unit and source without inventing the
missing eight case definitions. Across the six pinned checkouts, the first-party
inventories describe 45 heterogeneous units in total; neither 45 nor 53 is a
verified, uniform current-main recall denominator.

| Repository | Presentation correspondence | This run: Python files / AST parsed | OpenGrep verified file×rule pairs | Verified static hints | First-party answer description at pinned SHA |
| --- | ---: | ---: | ---: | ---: | --- |
| [VAmPI](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/README.md) | 9/9 | 11/11 | 187/187 | 16 | README lists 9 broad vulnerability entries. |
| [DSVPWA](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/README.md#L7-L19) | 17/17 | 5/5 | 85/85 | 51 | README lists 12 broad categories and [attacks.xml](https://github.com/sgabe/DSVPWA/blob/c98b77950bf1c54080c4113a2488ce0509b21cff/db/attacks.xml) has 13 attack IDs, neither a 17-case mapping. This is **not** the similarly named `anxolerd/dvpwa`. |
| [BreakableFlask](https://github.com/stephenbradshaw/breakableflask/blob/553e8b2f51c14f259f565d5df478339c366a9172/vulnerability_index.md#L5-L14) | 11/12 | 1/1 | 17/17 | 18 | Numbered index has 8 top-level route entries; it does not define the slide's 12 cases. |
| [Flask AppSec Lab](https://github.com/koushikchowdary6/flask-appsec-lab/blob/64457488173d25662c6d7ce6467bb20616ebc5d3/README.md) | 3/3 | 4/4 | 68/68 | 16 | README describes 3 classes and paired vulnerable/safe routes. |
| [Python Vulns](https://github.com/cybersecurity-repo-study/python-vulns/blob/4163acacc4134bb7b70afe0435f8926e59d433c1/README.md) | 5/5 | 1/1 | 17/17 | 32 | README describes 4 classes and 5 vulnerable endpoints; class versus endpoint is a different counting unit. |
| [Vulpy](https://github.com/fportantier/vulpy/blob/5249cc8b05a1c37f6b2f757b1cf16a509c327122/README.rst) | 5/7 | 57/57 | 969/969 | 89 | README lists 7 broad categories; the checkout also contains `good` comparators. |
| **Total** | **50/53 (historical only)** | **79/79** | **1,343/1,343** | **222** | **No 53-case correspondence established.** |

### Existing full-pipeline artifacts are not a case-level reproduction

A read-only inventory of earlier local SASTSIMI run metadata found the
following artifacts. These runs were not made by this benchmark, and their
Finding IDs are neither independently verified true positives nor deduplicated
vulnerability cases.

| Earlier target | Commit relation to this measurement | Recorded Finding IDs / report drafts | Candidate terminal record | 53-case answer mapping |
| --- | --- | ---: | --- | --- |
| DSVPWA | Same pinned commit | 43 / 43 | PARTIAL | Unavailable |
| Python Vulns | Same pinned commit | 54 / 54 | PARTIAL | Unavailable |
| BreakableFlask | Different commit | 51 / 51 | PARTIAL | Unavailable |

No comparable stored full-pipeline run was identified for the other three
targets. These counts cannot be added together or substituted for the
presentation's 50 corresponding answers: several reports may describe the
same underlying issue, and the earlier runs have no reviewed answer-to-Finding
decisions. The new six-repository run below measures static execution only.

One additional **read-only, case-level replay** is possible for a previously
saved DSVPWA run. The existing [`recall_audit.py`](../../tools/recall_audit.py)
scorer, its [frozen 14-case oracle](../../tests/evaluation/oracles/dsvpwa-c98b7795-v2.json),
and [human review ledger](reviews/dsvpwa-c98b7795-v2-review.json) reproduce
the [saved score](results/dsvpwa-c98b7795-v2-score.json): **PARTIAL**,
1 matched true positive, 11 HOLD, and 2 outside the Python evaluation scope.
There are also 6 unmatched Findings still requiring review; the confirmed
false-positive count is zero, not an assertion that all six are correct.
Recall remains **undefined** because the 11 HOLD cases are not established
false negatives. This older, 14-case assessment is neither the presentation's
17-case DSVPWA denominator nor a new current-main full-pipeline run. A second
read-only audit of the older, differently pinned BreakableFlask run against its
local eight-item oracle returned **8 INCOMPLETE**, not eight false negatives or
the presentation's 11/12. Both replays used saved artifacts only; they made no
scanner, LLM, or PoC calls and did not execute target code.

All six scans returned zero scanner errors and zero unverified OpenGrep pairs.
The fresh run made 42 finite scanner calls (seven rule batches per repository),
with **111.279 seconds of summed scanner-call wall time**. This excludes Git
checkout inspection and AST work, so it is not end-to-end analysis time. An
unchanged second run made zero scanner calls and reused all 42 verified batches;
the success markers bind each batch to the rule/tool/commit/scope fingerprint,
which includes the raw Python source-byte digest.
The common file-scope policy excluded 7 test files and identified 10 non-Python
product files outside this Python-only measurement; neither category was counted
as a successful Python scan. VAmPI emitted one non-fatal Python
`SyntaxWarning` for an escape sequence; its 11 selected files still parsed and
all applicable OpenGrep pairs were explicitly scanned. A static hint is a
tool observation, not a confirmed vulnerability, a true positive, or a report.
False positives, missed cases, and deduplicated Findings are **not measured** by
this run.

## Reproducibility and limits

- Target URL and full SHA: [pinned manifest](data/six-educational-targets.json).
  The runner rejects a checkout whose `HEAD` or `origin` does not match.
- Scanner: OpenGrep `1.30.0`, executable SHA-256
  `b5cf4f8fe9f44e030aab2d579d96bd395c139db1f1ba66633676ff4d5ebc7c39`.
  Python candidate rule file SHA-256
  `50cb35975d2786150e608ece691c608d3fcf6de5a674fd1fc4876818ef18c814`.
  Of its 25 configured rules, 17 apply to `.py` files. The scanner was called
  in the product's three-rule batches with a finite per-call timeout.
- The runner uses the current `build_static_file_scope`, `plan_rule_batches`,
  `plan_static_coverage`, `assess_scan`, and `finish_coverage` implementations.
  It accepts coverage only from explicitly scanned, error-free file×rule
  combinations. An incomplete or invalid batch remains a gap. Complete batch
  artifacts are reused only under the matching commit/scope/rule/tool identity.
- Raw JSON and the detailed `summary.json` remain under ignored local
  `runtime-data/benchmark-20261024/raw/`, not in this PR. The runner is
  [`scripts/run_six_repo_static_benchmark.py`](../../scripts/run_six_repo_static_benchmark.py).
  The non-sensitive counts and scope fingerprints are preserved in the
  [measured summary](data/six-educational-measured-static-summary.json).
  Provide six local checkouts named as in the manifest, then run it with
  `--targets-root`, `--tool`, and `--output-dir`. It does not clone or run code
  from the targets.
- The historical denominator mixes categories, routes, and possibly distinct
  instances. A valid current-main recall comparison needs a reviewed 53-row
  oracle with each case's definition and pinned SHA, plus a run ID and
  independently validated Finding-to-case decision. Until then, a percentage
  near 50/53 cannot be honestly asserted or optimized against.
