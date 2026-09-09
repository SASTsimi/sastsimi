# R7 path traversal validation fixture

This project is a synthetic local-only Flask application. It contains a
deliberate path traversal flaw for evaluating R7 dynamic reproduction behavior.

Health Check:

```text
uv run --project . python reproduce.py public.txt
```

Reproduction probe:

```text
uv run --project . python reproduce.py ../fixtures/probe.txt
```
