# T03 Application foundation

- Status: implemented locally; independent review/CI/merge remain controller-owned.
- Tracking: Issue #126, parent #121.
- Inputs: [master plan](../2026-09-08-sastsimi-complete-implementation.md), [design](../../specs/2026-09-08-sastsimi-maintainable-implementation-design.md), [baseline](../../../architecture-v5/implementation/06-implementation-baseline.md), [ADR-015](../../../review/decisions/ADR-015-r3-implementation-baseline.md), [ADR-016](../../../review/decisions/ADR-016-maintainable-workflow-packages.md).

## Scope and decisions

Installable CPython 3.12 foundation only: argparse doctor, typed configuration,
safe JSON Lines, AST import contract, exact uv dependency lock and core CI.
No domain records, providers, storage, Docker execution or workflow implementation.

Configuration is explicitly selected flat TOML with required schema_version=1;
no repository discovery. Every source validates before merging. Only log_level,
output_format and data_dir are overrideable; schema_version is file-only.
Secret references use explicit env:NAME or handle:UUID syntax and never resolve.
Host paths remain excluded local config fields. Doctor does not create data dirs.

CLI enters via bootstrap to assemble configuration; bootstrap contains no domain
decisions. Doctor platform inspection belongs to the CLI command adapter.
The AST rule table includes all approved future packages. Root __main__ is the
entry-point exception, bootstrap is the sole composition root, and logging is an
independent standard-library utility accessed by CLI through bootstrap.

## TDD execution

- [x] Write configuration, CLI and safe logging tests and observe missing behavior.
- [x] Write allowed/forbidden import fixtures, observe forbidden edges escaping.
- [x] Implement the minimum foundation and fail-closed AST checker.
- [x] Generate uv.lock with uv, then frozen sync and packaging smoke checks.
- [x] Format, lint, strict type check and run all existing tests.
- [x] Run architecture validator, inventory/link audit and base-to-head whitespace.
- [x] Self-review, commit logical changes and hand clean tracked tree to controller.

## Verification

`uv sync --frozen --all-groups`, `uv run ruff format --check .`,
`uv run ruff check .`, `uv run mypy --strict src tests`, `uv run pytest tests -q`,
Architecture validator and inventory audit with Windows PowerShell, plus
`git diff --check ca4b337a2ef7aa406435bdc0c7c829f4b57ab4d4..HEAD`.
Ubuntu 24.04 and Windows Server 2022 run the same current suites in CI.
Missing future suites and real capability probes are not reported as passed.

Initial RED: 68 failed, 1 passed with the package absent and forbidden import
fixtures exposing the permissive checker. Additional AST RED: 4 failed, 72 passed
for cycle, dynamic-import and private-import bypasses. Final local GREEN:
140 passed, Ruff clean, mypy strict clean across 19 Python files, Architecture
validator 0 failures and inventory/link audit 0 missing links.

Local verification uses Windows and CPython 3.12.10 with uv 0.12.5. Dependency
downloads and pytest temporary-directory access required sandbox escalation;
the ignored cache is `.cache/uv`. Ubuntu execution remains a CI result to obtain.
Ruff 0.16 discovers Markdown code fences by default, so `*.md` is excluded
from Ruff; all Python remains checked. Initial mechanical code-fence formatting
was restored and canonical documents have no content changes.

Examples: `sastsimi doctor --format json` and
`sastsimi --config approved.toml --log-level DEBUG doctor`.
Global flags precede the command. Docker/provider support is never inferred
from these foundation checks.

Independent review fix round 1 reproduced unsafe stdlib logging error fallback
and builtin dynamic-import bypasses (17 failed, 30 passed targeted RED).
SafeJsonHandler now owns serialization/write/flush failure handling, emits only
a fixed failure event and never prints raw records or traceback details.
SafeEvent repr hides fields and identifiers. Import enforcement rejects builtin
import machinery/aliases, reflective import/exec access and computed call targets.
Targeted GREEN: 47 passed; full GREEN: 94 passed.

Independent review fix round 2 narrowed the import guard after 11 positive
fixtures failed: ordinary getattr/vars, named factory dispatch and benign
builtin/metadata use do not create dependency edges and are now allowed.
Checks target actual import/exec members and captures, including reflective
lookup on known import namespaces. An additional two failing alias/dictionary
fixtures were fixed before verification. Targeted GREEN: 51 passed; full GREEN:
117 passed. The round-1 blanket reflection/computed-call restrictions are removed.

Independent review fix round 3 added known-namespace dictionary get/imported
dictionary/annotated binding coverage and lexical shadowing pairs. Initial RED:
12 failed, 58 passed. Annotation-only, global declaration and method-scope
self-review fixtures added another RED of 4 failed, 70 passed.
The checker now separates namespace/accessor classification, function-local name
collection, lexical binding updates, access policy and ordinary import targets.
It does not evaluate arbitrary calls, runtime dictionary contents or control flow.
Targeted GREEN: 74 passed; full GREEN: 140 passed.
