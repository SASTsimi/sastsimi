# T04 Core contracts and canonical serialization

- Status: implemented locally; independent R4/R8 review, CI and merge remain controller-owned.
- Authority: [contracts](../../../architecture-v5/08-lightweight-data-contracts.md), [baseline §§8.1–8.4](../../../architecture-v5/implementation/06-implementation-baseline.md), [public ports](../2026-09-08-sastsimi-complete-implementation.md#3-공통-공개-인터페이스), [ADR-015](../../../review/decisions/ADR-015-r3-implementation-baseline.md).

## Ownership and public surface

`contracts` owns strict immutable Pydantic values, opaque runtime-distinct IDs,
Run/Record/PolicyCache metadata, the three exact reference kinds, work/attempt/
transition/commit, Action and execution/work/verification/dynamic budget records.
Canonical list fields use immutable tuples in Python and JSON arrays on the wire.
Required nullable fields remain required; wire input uses `model_validate_json`,
while Python construction requires enum instances, aware datetimes and typed IDs.
Package exports expose the models, enums and pure contextual validation helpers.

`ports` owns 11 runtime-checkable Protocol boundaries plus frozen transport DTOs.
Later domain types are intentionally reference-only `BoundaryRecord` aliases in
`ports.dto`, not new canonical domain schemas. Task 5 replaces those aliases with
its actual domain types; adapters must resolve and validate their exact refs.

## Invariants and deferred responsibilities

Local validators reject extra fields, coercion, aliases, naive timestamps,
negative limits, wrong metadata/ID kinds, malformed revision chains, invalid
state/version/attempt combinations, action-specific field misuse, unequal or
duplicate check sets, incompatible decision use states and invalid reservation
finalization. Missing work-limit selection always denies execution.

`validate_exact_ref` checks record kind, exact record ID/hash and run or
workspace/commit scope. The consuming analysis is required when resolving run
and code records; `StoredDataRef` itself deliberately has no analysis field.
Policy cache refs use their own program/schema scope. Raw artifact refs may keep
`record_id=null`; references to stored records must call `require_record_ref`.
Run metadata may contain the explicitly allowed code-scoped configuration refs;
their consuming analysis must be verified after resolution.

Persistence uniqueness, CAS, current-pointer/graph validation, approval-source
verification, atomic reservation, budget accounting and crash recovery are Task 6.
Domain outcome/provenance closure checks and all Task 5 schemas are out of scope.
No SQL, provider SDK, HTTP, Docker or runtime implementation is included.

## Canonical JSON and schema workflow

`canonical_bytes` implements `canonical-json-v1`: exact field names and nulls,
UTC six-digit fractional seconds with `Z`, enum values, lowercase UUIDs, integer
numbers only, preserved Unicode code points, sorted keys and compact UTF-8.
List order is preserved unless the caller supplies an explicit field-path sort
policy. `content_hash` returns lowercase SHA-256 and rejects the target object's
own top-level `content_hash`. Nested exact-reference hashes remain provenance;
this interpretation was confirmed by the Task 4 controller during implementation.
The approved Korean fixture is exactly 63 bytes and hashes to
`957b116406dddaf7928bd028a12602346873237f935f866530949547422122da`.

23 initial core schemas are generated as JSON Schema 2020-12 at
`schemas/generated/<data_kind>/1.schema.json`. These are initial implementation
schemas, not migration defaults for earlier persisted records. Generate with:

```text
uv run python -c "from pathlib import Path; from sastsimi.contracts import export_schemas; export_schemas(Path('schemas/generated'))"
uv run python -c "from pathlib import Path; from sastsimi.contracts import check_schemas; check_schemas(Path('schemas/generated'))"
```

Generated files are committed and never hand-edited. Checking rejects missing,
extra and changed files; regeneration preserves/report unknown files instead of
deleting them. Structural JSON Schema complements Pydantic semantic validation;
cross-field, resolved-ref and persistence rules are not all expressible in schema.

## Verification

```text
uv run pytest tests/unit/contracts tests/contract/test_canonical_json.py tests/contract/test_record_ref_kinds.py tests/contract/test_core_ports.py -q
uv run pytest -q
uv run ruff format --check .
uv run ruff check .
uv run mypy --strict src tests
powershell -NoProfile -File scripts/validate-architecture-docs.ps1
powershell -NoProfile -File scripts/audit-doc-inventory.ps1 -RepositoryRoot <repository-root> -CheckLinks
git diff --check
```

Red-first evidence includes missing common modules, model families and ports;
subsequent regressions exposed wrong run-profile scope handling, missing
post-workspace metadata validation, overbroad transition schema enums and nested
hash self-inclusion handling. The full execution report records red/green output,
self-review and environmental cache/PATH details.

Final local checks: 92 focused tests and 233 full-suite tests passed; Ruff format,
Ruff lint and strict mypy passed for all 48 Python files. Generated schema drift
check passed. Architecture validation reported 0 failures and the document
inventory/link audit reported 0 missing local links. Windows temporary-directory
access required elevated test execution; uv used the ignored `.cache/uv` path.
