# R7 task prompt validation suites

Each task directory contains one input and expected-result pair covering normal
output, schema error, semantic error, prompt injection, and stale or
cross-attempt input.

- [`DERIVE_ENVIRONMENT`](./derive-environment/cases.input.json)
- [`PLAN_REPRODUCTION`](./plan-reproduction/cases.input.json)
- [`CREATE_POC_CANDIDATE`](./create-poc-candidate/cases.input.json)
- [`EXECUTE_REPRODUCTION`](./execute-reproduction/cases.input.json)
- [`INTERPRET_ATTEMPT`](./interpret-attempt/cases.input.json)

Run `uv run python scripts/validate-r7-handoff.py` from the repository root to
validate all 25 task cases and the four lifecycle pairs.
