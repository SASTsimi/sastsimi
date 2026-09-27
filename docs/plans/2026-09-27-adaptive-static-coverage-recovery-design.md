# Adaptive static coverage recovery for large repositories

## 검토 요약

- Dify 전용 예외 없이 Semgrep 재검사 묶음을 최대 128파일로 늘리고, 실패한
  묶음만 쪼개며 파일별 시간 초과는 최대 한 번 더 시험한다.
- 이전 32파일 성공 기록은 재검증해 재사용한다. 부분 성공도 실제 확인된
  파일·규칙 조합만 재사용한다. JSON 출력은 파일에 받아 크기와 무결성을
  확인한다.
- 파싱 오류가 남으면 정적 검사를 `BLOCKED`로 유지한다. 별도 정적 시험을
  먼저 돌린 뒤 A-007의 남은 시도를 사용할지 판단한다. 사용자의 저장된
  설정과 고정된 Dify 소스는 바꾸지 않는다.

## Intent and acceptance boundary

Improve the existing OpenGrep-to-Semgrep fallback in PR #202 so that a large
repository can make progress without rescanning verified work. The field test is
the pinned Dify commit `8387590ace4a094de812b7847fc6a4c3a27cd52b` and the
existing A-007 analysis. The implementation must be repository-independent:
no Dify-specific paths, rule exceptions, or generated-file exclusions.

The coverage gate remains fail-closed. A file/rule pair is complete only when
the exact local rule was run on that file and the scanner returned a valid
result without a relevant parse error, skip, or timeout. AST and Python CodeQL
results remain independently available but cannot stand in for OpenGrep rule
coverage. Unverified pairs keep the static stage `BLOCKED`, not `COMPLETE`.
This design does not promise that every repository, or even the pinned Dify
commit, can reach `COMPLETE` with the installed parsers.

## Observed problem

The separate five-minute Dify static trial recorded 97,328 applicable
file/rule pairs, of which 23,877 were verified. The remaining 73,451 comprise
73,400 pairs not reached before that trial's time limit and 51 pairs with
file-specific errors. Those 51 pairs belong to 14 JS/TS files: seven TS/TSX
files have repeatable parser errors and seven JS/MJS assets timed out. An
isolated Semgrep 1.178.0 run with a longer per-file timeout still reported a
syntax error in `cli/src/sys/io/streams.ts`; its `paths.scanned` entry is not
proof of complete parsing. This diagnostic did not modify A-007.

The current fallback groups missing pairs by original OpenGrep batch and
selected rules, launches Semgrep sequentially for at most 32 targets, and
captures JSON through a 32 MiB stdout buffer. The trial projected roughly
954 launches for its original missing pairs. Success-only caching preserves
complete chunks, but a partial chunk is re-run in full after resume.

## Alternatives and choice

1. **Chosen: adaptive, bounded fallback on the existing rule plan.** Reuse
   verified 32-target results, scan the remaining targets in larger
   Windows-command-line-safe chunks, and isolate only failures. Keep the
   existing coverage verifier and cache fingerprint. This changes the fewest
   interfaces while reducing redundant scanner startup work.
2. Increase the global deadline or run several 32-target workers in parallel.
   A longer deadline does not repair parser errors; parallel workers risk CPU
   and memory contention and do not address silent stdout truncation.
3. Exclude generated or vendor-like files. This would make counts smaller by
   policy rather than prove coverage and contradicts the agreed gate, so it
   is not part of this change.

## Components and data flow

`DirectStaticBootstrap` keeps the current six OpenGrep rule batches and their
fingerprint. It first validates and reuses existing successful OpenGrep and
Semgrep attempts. For each remaining set of exact file/rule pairs, a small
deterministic planner forms chunks bounded by both target count (128) and a
conservative quoted Windows command-line length (24,000 UTF-16 code units).
No extra concurrency is introduced. The old 32-target partition is
reconstructed before new planning so its successful attempts remain
reusable. New chunk keys still derive from the original batch key, selected
rule IDs, and exact target paths.

`run_semgrep_fallback` runs only the local pinned executable and local YAML.
It writes JSON to a fresh, analysis-scoped output file rather than relying on
the process stdout cap. The caller verifies exit status, file existence,
bounded size, valid JSON shape, and unchanged executable digest before using
the output. A stale output file cannot satisfy a retry. Raw output and safe
coverage summaries are stored separately; source contents, full prompts, and
absolute user paths are not written to ordinary logs.

The existing `assess_scan` verifier remains the authority for crediting
file/rule pairs. A partial, parse-error, or skipped-file response can add only
the pairs it actually proves. The remaining targets are split into smaller
chunks, down to a single file when useful, under one shared elapsed deadline.
An output-size or command-line-limit failure also splits a multi-file chunk.
A single-file timeout receives one bounded retry with a 30-second Semgrep
per-file timeout; a repeated syntax error is retained as a gap rather than
rewritten or ignored. Splitting and retry counts are capped to prevent loops.
Successful subchunks and validated pairs from partial results are reused on
resume under the same commit, rules, file list, and tool digest. Reuse of a
partial result requires reconstructing the exact target/rule tuple from the
deterministic partition and re-running `assess_scan` on its raw artifact; a hash
key alone is not enough. A pinned single-file parser error remains an
unresolved gap and is not retried on resume until the tool or input changes.
Changed tools or inputs invalidate the corresponding proof.

## Error and resume behavior

Tool unavailable, process timeout, oversized/malformed output, parser error,
and coverage gap have distinct safe error codes. Every attempt retains its
existing DB identity/status/error fields and raw artifact when available; only
error-free verified pairs advance the count. The scheduler stops at the shared
configured deadline, persists progress, and returns `BLOCKED` with remaining
relative paths and rules. It does not convert a scanner failure to zero
findings. Cancellation must still terminate child processes.

The user's persistent profile is unchanged. For the actual A-007 resume, the
locally installed Semgrep binding is enabled only in the in-memory execution
profile; no account login, automatic installation, remote rules, or network
access is required. The changed fallback fingerprint causes a fresh coverage
decision. Complete OpenGrep batches have an independent cache. A-007's partial
first batch is keyed by the old coverage fingerprint and is not automatically
reused: its raw artifact may be carried forward only after the exact analysis,
commit, clean tracked checkout, original batch key/tool digest, and current
`assess_scan` result are checked. Otherwise it is rescanned; a prior count is
never copied blindly. First, a separate static-only trial must exercise the
new scheduler against the pinned Dify checkout. That trial's successful
artifacts are not implicitly shared with A-007 because they have a different
analysis identity. If the trial verifies every applicable pair and the other
configured static tools succeed, resume A-007 with its remaining attempt. If
the same deterministic parser gap persists, report the exact unverified pairs
and request a separate decision before spending A-007's remaining attempt on
a known blocked path. If static coverage clears, A-007 continues through the
existing hypothesis, PoC, scope, and report stages with its configured
`gpt-6-sol` model and current usage limits. An unresolved parser gap remains
an honest `BLOCKED` outcome.

## Verification and rollout

- Test normal JSON, malformed/missing/oversized output, stale output, changed
  tool digest, Windows argument bounds, per-file timeout retry, cancellation,
  split termination, partial pair credit, legacy 32-target reuse, new-chunk
  resume, and no duplicate findings.
- Run targeted unit and integration tests, then existing provider and full
  suites. Do not report a passing suite unless the command actually passed.
- Run the pinned Dify static-only trial, record expected/verified/gap counts
  and remaining reasons, and only then decide whether A-007 can safely resume.
- Update README and operator/troubleshooting documentation with the actual
  behavior and limitation, and add results to PR #202. Do not claim complete
  analysis, validated PoC, or report bundles when static coverage is blocked.

This design does not add a new parser, alter rule semantics, change the
coverage policy, or guarantee that the installed scanners can parse every
valid JS/TS construct. Those would require a separate design and proof.
