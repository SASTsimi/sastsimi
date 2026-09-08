# Task 5: Canonical domain contracts

## Authority and scope

The canonical source is [Architecture v5 §08](../../../architecture-v5/08-lightweight-data-contracts.md), with scenarios from the [contract test plan](../../../architecture-v5/implementation/02-contract-test-plan.md). This implementation extends reviewed Task 4 core metadata, IDs, references, canonical JSON, work, action and budget contracts. The current result-owner paragraph contains 40 result kinds: 38 domain-owned kinds and two existing budget kinds.

## Ownership and implementation sequence

1. Establish a failing source/schema/owner inventory test directly against the current canonical paragraph.
2. Implement static facts, context, rule execution and committed normalization checks in `static.py`.
3. Implement proposals, duplicate review and assignment in `hypothesis.py`; playbooks, independent Pro/Con evidence and verdict closure in `verification.py`.
4. Implement the R6 request and R7 requirements, plan, recipe, environment, boundary decision, command, append-only log, candidate, validated PoC, cleanup, conclusion and result vocabulary in `dynamic.py`.
5. Implement admission, Primitive/index and exact Chaining parent/child closure in `chaining.py`.
6. Implement official policy collection, parser provenance and the only cross-analysis cache exception in `policy.py`; CWE and ordered Gates in `gates.py`; normalized Finding and final automated ReportDraft closure in `reporting.py`.
7. Implement safe diagnostics, immutable usage/count maps, evaluation comparisons and terminal run summaries in `evaluation.py` and the appropriate owning modules.
8. Replace owned port aliases with canonical types, regenerate schemas/inventory, and run full verification.

`_domain.py` owns shared pure scope, exact-reference, uniqueness and safe-diagnostic checks. `closure.py` owns the reusable committed-current work/attempt/transition boundary. `result_registry.py` is the single immutable mapping of result kind to model and unique producer. No helper is an alternative schema authority.

## Closure consumption contract

Pydantic construction validates local structure, nullability, scope and locally decidable status invariants. Consumers must additionally resolve exact referenced records, call `validate_committed_output` for the current work/attempt/COMMITTED transition, and compose the named family closure validators before using a record. A record-shaped value alone is never proof of currentness. Current-pointer lookup, authenticated identity selection, transaction ordering and compare-and-set are trusted runtime responsibilities, not supplied by an untrusted record.

Pro/Con joining retains independent NEW sessions and attempts. Dynamic closure joins the R7 execution attempt without equating it to the R6 request producer attempt. Candidate bytes are digest-bound and do not become a validated PoC merely through schema validation. Technical Gate accepts final TRUE only with current successful supported dynamic evidence and validated PoC. Finding creation requires a trusted normalizer identity and an exact ACTIVE assignment; Technical REVISE does not replace that assignment. Reporter preserves original condition pointers and values through both Gates. ReportDraft is the final automated artifact.

Cache reuse validates the old collection/policy/parser closure, binds an exact PolicyCacheRef, preserves source/parser/freshness content and creates new current-analysis policy records. The cache exception is narrowly restricted to declared provenance fields and is checked by resolved closure validators.

Review round 1 strengthens this boundary: static normalization accepts explained PARTIAL work and resolves rule execution/catalog provenance even when normalized facts are empty. R7 consumers supply resolved commands/tool requests, supporting evidence and the complete attempt environment/resource inventory. Each request need maps to one or more concrete requirement IDs (identity mapping by default); the pure check preserves kind, mandatory flags and exact sources, without interpreting free-text goals. Command/event, executed-PoC, boundary-policy, conclusion and cleanup checks remain separate named pure validators. Terminal run validation requires a `ResolvedAnalysisInventory` snapshot with exact expected references for every authoritative list, all resolved records, current Verification pointers and generations; it never manufactures absent results. Recursive provider-unit immutability protects canonical hashes after construction.

## Schema generation and tests

`schema_export.py` combines Task 4 core models and the registry and emits deterministic JSON Schema 2020-12. Check mode rejects missing, extra and drifted files. `scripts/generate-result-inventory.py` derives and checks all 40 mappings against §08, emitting `schemas/result-owner-inventory.json`. The complete export contains 61 schema files; supporting nested value models are included through schema definitions.

Incremental RED/GREEN tests precede implementation by family. An independent canonical-block fixture builder checks all 40 positive wire records, all required-field deletions, Python round trips, and automated-disclosure rejection. Focused negatives cover wrong owners/kinds, scope, stale attempt/generation/hash, independent evidence sessions, candidate digest and executed log provenance, Gate order, original condition preservation, unsafe diagnostics and immutable maps. Full-suite, import architecture, strict mypy, Ruff, schema/inventory drift and documentation checks gate the local commit.

## Explicit non-goals and integration boundaries

Task 6+ owns storage, migrations, current-pointer selection, authenticated service identity resolution, transactional publication/recovery, runtime budgets and orchestration. Later adapters own provider calls, invocation contracts, Docker execution, source HTTP collection, runtime secret scanning/redaction and LLM prompts. No such side effects are implemented here. Evaluation cannot authorize production verdicts, Gates, admission or reporting. No disclosure automation or human-review workflow is introduced. No push, remote item changes or merge is part of this task.
