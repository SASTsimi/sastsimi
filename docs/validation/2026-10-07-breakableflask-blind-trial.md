# Oracle-blind BreakableFlask trial (2026-10-07)

This is a local training-repository evaluation, not a disclosure result or a
repository-wide vulnerability recall measurement. The fixture contains pinned
upstream `main.py` and two dependency files, but omits the README and
vulnerability index. Source comments may still hint at attack classes. The
eight-case route oracle was frozen before execution and was not supplied to
SASTSIMI. The fixture commit is `2723a6e07ae135ca558202b653a5d5d4e063479a`.

## Final same-ID outcome

The isolated run `breakableflask-blind-v1`
(`6c4938f80f8b4325983d6b9ef9ae4b41`, displayed as `A-001`) terminated
`PARTIAL` at `HYPOTHESIS_DONE`. Its UI progress was 96% with 747 completed of
911 known work units. All 12 planned Python file-rule checks completed with no
static coverage gap. Candidate selection processed all 30 candidates:
21 INCLUDE, 9 UNDECIDED, 0 PENDING, and 0 ERROR. Deep analysis finished 21
as COMPLETE and 9 as INCONCLUSIVE. It processed 67 hypotheses and stored 51
raw TRUE Finding/report records. A TRUE record is the tool's local verdict, not
independent confirmation or permission to disclose.

The partial status is material: the attack-surface inventory has 13 COVERED,
32 INSUFFICIENT, and 0 UNCOVERED surfaces. Those 32 insufficient surfaces are
not treated as tested-negative, despite completed static file-rule checks and
candidate decisions. The overall analysis therefore must not be described as
COMPLETE.

| Frozen source-reviewed route case | What the blind run established |
| --- | --- |
| BF-01 deserialization | At least one route-matching TRUE Finding and local PoC; no independent HTTP service-process test. |
| BF-02 command injection | At least one route-matching TRUE Finding and local PoC; same-process test only. |
| BF-03 code injection | At least one route-matching TRUE Finding and local PoC; same-process test only. |
| BF-04 XML external entity | A local DTD marker was observed; external data exfiltration was not established. |
| BF-05 padding-oracle claim | A limited response difference was observed; a practical oracle or secret extraction was not established. |
| BF-06 template injection | At least one route-matching TRUE Finding and local PoC; same-process test only. |
| BF-07 SQL injection | At least one route-matching TRUE Finding and local PoC; same-process test only. |
| BF-08 JWT | The unsigned `alg=None` branch was reached; HS256/RS256 confusion was not demonstrated. |

All eight frozen route cases have at least one path-matching tool TRUE Finding
and local PoC reference. **8/8 is a route-match count, not a 100% exploit
recall rate or eight independently verified reportable vulnerabilities.** The
PoCs used isolated Docker containers and a same-process Flask test client;
external service-process behavior and impact still require human review.

## Reports, duplicate display, and disclosure boundary

All 51 report records have CAS-verified PoC, report, manifest, and archive
references. Their materialized bundles contain `report_en.md`,
`report_kr.md`, a `poc.py` or `poc.sh`, and an `evidence/` directory. The
conservative display projection shows 36 representative groups from 51 raw
Findings. Only three groups have proven same-flow anchors (covering 18 raw
Findings); 33 other groups remain singletons with grouping undetermined.
Original Findings and PoCs remain intact. Newly added JWT-related reports
F-048–F-051 may overlap, but current evidence does not justify merging them.

All 51 Scope Gates are `UNCERTAIN` because a supported policy origin and
applicable disclosure scope were not established for this training fixture.
Thus none of these reports is automatically submission-ready. Other findings
outside the eight-case oracle have no independent truth labels, so an
overall false-positive rate cannot be calculated.

## Interpretation and follow-up

The initial same-ID checkpoint stopped on `POC_SENSITIVE_CONTENT` and later
needed a narrow report-validator replay. Both were repaired and resumed from
saved work rather than starting a new analysis. One later PoC initially failed
with `ModuleNotFoundError: jwt`; the generic environment-replan path added
PyJWT in its disposable container and the same hypothesis completed. These
recovery events remain part of the audit trail.

The previous upstream checkout included answer documents, whereas this
fixture omitted them. Different source context and code revisions make those
runs unsuitable for a controlled before/after detection comparison. The
within-run progression from fewer to 51 Findings is cumulative completion,
not measured recall improvement. A saved-context reuse optimization was
committed after this process started and was **not** measured by this live run.
