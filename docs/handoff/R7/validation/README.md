# R7 Dynamic Reproduction Validation Drafts

These drafts verify four R7 environment and lifecycle cases with one reusable,
synthetic, local-only Flask project. Project code and analysis results are case
inputs; they are not embedded in the reusable Agent prompts.

## Fixture ground truth

`fixture/app.py` deliberately resolves an untrusted report name without
checking that the result remains under `reports/`.

Verified locally on 2026-09-09 with Python 3.12.13 and Flask 3.1.2:

```text
uv run --project . python reproduce.py public.txt
=> {"status_code": 200, "content": "PUBLIC_REPORT"}

uv run --project . python reproduce.py ../fixtures/probe.txt
=> {"status_code": 200, "content": "R7_LOCAL_PROBE"}
```

The marker remains inside the synthetic project. No external account, secret,
host target, live service, or network access is used during reproduction.

## Case file contract

Each `*.input.json` is a scenario specification for the future input assembler,
not a canonical SASTsimi record by itself. It contains:

- `scope`: IDs that every projected record and event must share.
- `records`: exact symbolic records available before the stimulus.
- `steps` or `stimulus`: invocation order and injected runtime facts.
- `source`: whether the case uses a real tool result or synthetic data.

Each paired `*.expected.json` contains:

- `expected_record_projections`: each entry names its `record_type`, trusted
  `producer`, and stable canonical `fields`. Omitted canonical fields are
  filled by the trusted runtime.
- `assertions`: evaluation predicates for exact references, ownership,
  nullability, enum values, evidence, and variable natural-language content.
- `must_not_claim`: conclusions that must never appear in generated output or
  trusted result assembly.

Supported assertion operators in these drafts are:

| Operator | Meaning |
|---|---|
| `EQUALS` | The selected value equals literal `value` or the field selected by `value_from`. |
| `NON_NULL` | The selected value exists and is not null. |
| `ABSENT` | The selected value is null, empty, or not produced as specified. |
| `CONTAINS` | A string or collection contains every item in `value`. |
| `ALL_EQUAL` | Every selected collection item equals `value`. |
| `EXCLUDES` | The selected collection contains none of `value`. |
| `SAME_SCOPE` | Referenced records share the case analysis, workspace, commit, hypothesis, work, and attempt scope. |
| `PRODUCED_BY` | The selected record was produced by the role named in `value`. |

The envelope formats are machine-described by `validation-case.schema.json`
and `validation-expectation.schema.json`. They describe validation fixtures,
not production SASTsimi records or Prompt Registry output schemas.

Free-form rationale text is not compared byte-for-byte. Assertions instead
name the facts and distinctions that the text must preserve.

## Paired cases

| Input | Expected result | Purpose |
|---|---|---|
| `environment-ready.input.json` | `environment-ready.expected.json` | R7 derives requirements and a plan, then trusted setup reports a READY environment. |
| `environment-setup-failure.input.json` | `environment-setup-failure.expected.json` | A required Python version check fails after admission but before the Sandbox Agent starts. |
| `execution-cancelled.input.json` | `execution-cancelled.expected.json` | Runtime cancellation interrupts an accepted PoC execution and excludes late output. |
| `cleanup-failure.input.json` | `cleanup-failure.expected.json` | Supporting evidence and a validated PoC remain valid while post-run cleanup fails. |

## Ownership boundary

The R7 LLM produces `EnvironmentRequirements`, `ReproductionPlan`,
`PoCCandidate`, `DynamicReproductionToolRequest`, and
`DynamicReproductionConclusion` only. Sandbox admission, environment creation,
runtime cancellation, cleanup, append-only `AgentLog`, validated `PoCBundle`,
and final `DynamicReproductionResult` are trusted runtime responsibilities.
