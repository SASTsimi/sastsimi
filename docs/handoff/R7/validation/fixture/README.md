# R7 path traversal validation fixture

This project is a synthetic local-only Flask application. It contains a
deliberate path traversal flaw for evaluating R7 dynamic reproduction behavior.

- `allowed-files/allowed.txt` is the file that the application is intended to
  read during the normal baseline check.
- `outside-allowed-directory/path-traversal-target.txt` is outside that intended
  directory. Reading it through `../` demonstrates path traversal.

Health Check:

```text
uv run --project . python reproduce.py allowed.txt
```

Path traversal request:

```text
uv run --project . python reproduce.py ../outside-allowed-directory/path-traversal-target.txt
```
