# Candidate static-analysis materials v1

This directory is an immutable **candidate** input set for controlled evaluation.
It is not approved or production-ready. A successful smoke test does not activate
these materials; production activation still requires the repository's normal
capability evidence, approval, exact-reference, and profile checks.

- The OpenGrep rules directory contains generic Python and JavaScript fact-candidate rules for
  OpenGrep 1.16.5. The rules identify possible sources, sinks, sanitizers,
  validators, and authorization checks. A match is not a vulnerability verdict.
- `codeql/` wraps only the Python queries bundled in CodeQL 2.27.0 under
  `codeql/python-queries@1.8.10`. It does not download a query pack.
- Each tool has separate catalog, selection, and mapping JSON. The mapping fields
  match `StaticRuleMapping`; the runtime must persist exact references before use.
- `manifest.json` pins the complete material file list, sizes, and SHA-256 values.

After an intentional edit, regenerate the manifest with:

```text
python scripts/generate_candidate_static_materials.py
```

Use `--check` in tests or review to reject an unrecorded change.

The CodeQL query target is the exact pack coordinate
`sastsimi/python-security-candidate@1.0.0`. Treating the mounted directory as
a recursive query directory bypasses its default suite and is not equivalent.
