# changedetection.io Model and Trial Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve the user's existing Codex configuration while making `gpt-6-sol` the persistent default, then run one pinned real analysis to obtain actionable evidence.

**Architecture:** Add one small, tested transaction at the user-configuration boundary because the public SimpleRuntime reads both `config.toml` and `profile.toml`. Verify the exact model through the official Codex CLI before changing either file. Run the existing public `analyze` path and record its terminal status and safe error evidence; any observed product defect receives a separate, concrete TDD plan after its cause is known.

**Tech Stack:** Python 3.12, Pydantic, pytest, official Codex CLI membership login, Windows PowerShell, existing SASTSIMI CLI and Docker runtime.

**Spec:** `docs/changedetection-stability-design.md`

## Global Constraints

- Branch: `codex/changedetection-stability`, based on PR #198; never discard user changes or analysis data.
- Keep `provider = "codex"`; change only the default `model` in both user config files, preserving all other values and Agent overrides.
- Validate `gpt-6-sol` with a minimal official Codex CLI call before writing either setting; on rejection, retain both original files.
- Pin `dgtlmoon/changedetection.io` to the exact SHA verified immediately before execution; candidate: `d789fe3ea5809eef0134943917ef50f47259121b`.
- Use the public SimpleRuntime command without `--profile`; retain the configured one-hour, one-million-token and cost limits. The Codex CLI does not currently return per-call token or cost measurements to SimpleRuntime, so the latter two limits cannot be enforced for this provider; record this limitation in the validation result.
- Never emit credentials, full prompts, or sensitive source into ordinary logs; do not convert tool errors to vulnerability `FALSE`.
- No target-name, SHA, or host-path special cases; no external disclosure or target repository modification.

## Review Focus

1. Inaccessible `gpt-6-sol` must leave both user files unchanged (Task 2 smoke-before-write order).
2. A mismatched config/profile provider, data directory, or old model must fail before writing (Task 1 mismatch test).
3. An invalid model string must fail before writing (Task 1 invalid-model test).
4. A second-file write failure must restore both original byte sequences (Task 1 rollback test).
5. Existing Agent overrides, limits, tool pins and credentials references must remain unchanged (Task 1 preservation test).

---

## Scope boundary

This is the first independently testable plan for the approved spec: model persistence plus a real diagnostic run. The spec also covers defect repair and documentation. Their exact files and tests depend on the run's observed failure, so a second plan will name the failing component and its regression tests after Task 3; inventing a fix now would conceal uncertainty.

## File map

- Create `src/sastsimi/config/default_model.py`: validated, reversible default-model update for the existing two-file SimpleRuntime configuration.
- Create `tests/unit/config/test_default_model.py`: preservation, mismatch, invalid-input, and rollback tests with temporary user files.
- Create `docs/validation/2026-09-26-changedetection-trial.md`: pinned command, analysis ID, safe stage/error observations, and decision on whether a generic repair is needed.
- Do not modify README, provider adapters, Docker, static analysis, or checkpoints in this plan; those follow the actual diagnosis.

### Task 1: Safe two-file default-model update

**Files:**
- Create: `src/sastsimi/config/default_model.py`
- Test: `tests/unit/config/test_default_model.py`

**Interfaces:**
- Consumes: `UserConfigStore.load/save`, `load_simple_execution_profile`, `UserConfig.model_validate`, `SimpleExecutionProfile.model_validate`, and the existing private atomic writer in `sastsimi.config.user_config`.
- Produces: `set_default_model(model: str, store: UserConfigStore | None = None) -> None`; Task 2 calls this only after Codex accepts the model.

- [ ] **Step 1: Write the failing preservation and guard tests.** Use this concrete fixture and assertions. Add the three mismatch cases (`provider`, `data_dir`, `model`) by writing a changed profile to `config.profile_path`, calling the function, and comparing both raw files to their pre-call bytes. Call `set_default_model(" bad\nmodel", store)` for the invalid-input case and assert the same unchanged bytes.

```python
from pathlib import Path

import pytest

from sastsimi.config.default_model import set_default_model
from sastsimi.config.user_config import (
    SimpleExecutionProfile,
    SimpleToolBinding,
    UserConfig,
    UserConfigStore,
    load_simple_execution_profile,
)


@pytest.fixture
def paired(tmp_path: Path) -> tuple[UserConfigStore, UserConfig]:
    store = UserConfigStore(tmp_path / "config.toml")
    config = UserConfig(
        data_dir=tmp_path / "data",
        profile_path=tmp_path / "profile.toml",
        auth_mode="SUBSCRIPTION_LOGIN",
        provider="codex",
        model="old-model",
        credential_ref="OFFICIAL_CLIENT_SESSION",
        execution_profile="FULL",
        max_cost_minor_units=12345,
        max_tokens=123456,
        max_elapsed_seconds=777,
        docker_network="BRIDGE",
        enabled_tools=("AST", "OPENGREP", "CODEQL", "DOCKER"),
        detected_versions={"git": "2.51.0"},
        setup_ready=True,
        agent_models={"verification_result": "existing-override"},
    )
    profile = SimpleExecutionProfile(
        provider_profile_ref="local-codex",
        provider="codex",
        model="old-model",
        auth_mode="SUBSCRIPTION_LOGIN",
        credential_ref="OFFICIAL_CLIENT_SESSION",
        data_dir=config.data_dir,
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=12345,
        max_tokens=123456,
        max_elapsed_seconds=777,
        docker_network="BRIDGE",
        tools={"codex": SimpleToolBinding(
            executable_path=tmp_path / "codex.exe", version="1.0.0",
            executable_sha256="a" * 64,
        )},
        agent_models={"verification_result": "existing-override"},
    )
    store.save(config)
    profile.write(config.profile_path)
    return store, config


def test_preserves_every_other_field(paired) -> None:
    store, config = paired
    before_config = store.load()
    before_profile = load_simple_execution_profile(config.profile_path)
    set_default_model("gpt-6-sol", store)
    after_config = store.load()
    after_profile = load_simple_execution_profile(config.profile_path)
    assert after_config.model == after_profile.model == "gpt-6-sol"
    assert after_config.model_dump(exclude={"model"}) == before_config.model_dump(
        exclude={"model"}
    )
    assert after_profile.model_dump(exclude={"model"}) == before_profile.model_dump(
        exclude={"model"}
    )
```

```python
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider", "openai"),
        ("data_dir", Path("C:/different")),
        ("model", "other-model"),
    ],
)
def test_mismatch_does_not_write(paired, field: str, value: object) -> None:
    store, config = paired
    profile = load_simple_execution_profile(config.profile_path)
    profile.model_copy(update={field: value}).write(config.profile_path)
    original = (store.path.read_bytes(), config.profile_path.read_bytes())
    with pytest.raises(ValueError, match="DEFAULT_MODEL_PROFILE_MISMATCH"):
        set_default_model("gpt-6-sol", store)
    assert (store.path.read_bytes(), config.profile_path.read_bytes()) == original


def test_invalid_model_does_not_write(paired) -> None:
    store, config = paired
    original = (store.path.read_bytes(), config.profile_path.read_bytes())
    with pytest.raises(ValueError):
        set_default_model(" bad\nmodel", store)
    assert (store.path.read_bytes(), config.profile_path.read_bytes()) == original
```

- [ ] **Step 2: Run the new tests and confirm RED.**

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/config/test_default_model.py -q
```

Expected: collection fails because `sastsimi.config.default_model` does not exist.

- [ ] **Step 3: Implement the transaction.** Validate both current files and the new model before writing. Save the original UTF-8 byte sequences. Write profile then config through their existing atomic methods; on any exception, restore both originals with the atomic writer and re-raise. Do not touch `agent_models`, provider, tool pins, or limits.

```python
from __future__ import annotations

from sastsimi.config.user_config import (
    SimpleExecutionProfile,
    UserConfig,
    UserConfigStore,
    _atomic_write,
    load_simple_execution_profile,
)


def set_default_model(model: str, store: UserConfigStore | None = None) -> None:
    selected = store or UserConfigStore()
    config = selected.load()
    profile = load_simple_execution_profile(config.profile_path)
    if (
        config.provider != "codex"
        or profile.provider != config.provider
        or profile.data_dir != config.data_dir
        or profile.model != config.model
    ):
        raise ValueError("DEFAULT_MODEL_PROFILE_MISMATCH")
    next_config = UserConfig.model_validate(
        {**config.model_dump(), "model": model}
    )
    next_profile = SimpleExecutionProfile.model_validate(
        {**profile.model_dump(), "model": model}
    )
    original_config = selected.path.read_bytes()
    original_profile = config.profile_path.read_bytes()
    try:
        next_profile.write(config.profile_path)
        selected.save(next_config)
    except BaseException:
        _atomic_write(config.profile_path, original_profile.decode("utf-8"))
        _atomic_write(selected.path, original_config.decode("utf-8"))
        raise
```

- [ ] **Step 4: Add the second-write failure test and confirm rollback.** Monkeypatch the fixture store's `save` method to raise `OSError("injected")` after the profile write; assert both files equal their original bytes and no `*.tmp` remains.

```python
def test_second_write_failure_restores_both(
    paired, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, config = paired
    originals = (store.path.read_bytes(), config.profile_path.read_bytes())

    def fail_save(_config: UserConfig) -> Path:
        raise OSError("injected")

    monkeypatch.setattr(store, "save", fail_save)
    with pytest.raises(OSError, match="injected"):
        set_default_model("gpt-6-sol", store)
    assert (store.path.read_bytes(), config.profile_path.read_bytes()) == originals
    assert not list(tmp_path.glob("*.tmp"))
```

- [ ] **Step 5: Run GREEN and related regression checks.**

```powershell
.\.venv\Scripts\python.exe -m pytest tests/unit/config/test_default_model.py tests/unit/config/test_user_config.py -q
```

```powershell
.\.venv\Scripts\python.exe -m ruff check src/sastsimi/config/default_model.py tests/unit/config/test_default_model.py
```

```powershell
.\.venv\Scripts\python.exe -m mypy src/sastsimi/config/default_model.py
```

- [ ] **Step 6: Commit this independently testable change.**

```powershell
git add -- src/sastsimi/config/default_model.py tests/unit/config/test_default_model.py
```

```powershell
git commit -m "fix: preserve user settings when changing default model"
```

### Task 2: Verify model access, then persist the user default

**Files:** User-local `%LOCALAPPDATA%\sastsimi\sastsimi\config.toml` and `profile.toml` through the Task 1 interface; no repository code changes.

**Interfaces:**
- Consumes: `set_default_model("gpt-6-sol")` and the user's current official Codex CLI login.
- Produces: both validated on-disk models use `gpt-6-sol`, or both remain unchanged with an explicit authentication/model error.

- [ ] **Step 1: Check the local prerequisite state without exposing secrets.**

```powershell
.\.venv\Scripts\sastsimi.exe doctor --format json
```

```powershell
codex login status
```

```powershell
docker info --format '{{.ServerVersion}} {{.OSType}}'
```

- [ ] **Step 2: Confirm actual account access with a minimal read-only Codex call.** This is the only model call before changing the files. If auth or model access fails, record its safe error and stop this task without writing the settings.

```powershell
codex exec -m gpt-6-sol --sandbox read-only --ephemeral --skip-git-repo-check "Reply with exactly OK; do not use tools."
```

Expected: exit code 0 and short `OK` response. Official API documentation confirms the model ID, but this account-specific check is required because documented availability does not prove this login can use it.

- [ ] **Step 3: Apply the tested update through the installed `.venv`.** If the external config directory is outside the sandbox, request the narrow filesystem escalation for these two files rather than changing data-dir.

```powershell
.\.venv\Scripts\python.exe -c "from sastsimi.config.default_model import set_default_model; set_default_model('gpt-6-sol')"
```

- [ ] **Step 4: Read both files back through their Pydantic loaders, print only provider/model and assert consistency.**

```powershell
.\.venv\Scripts\python.exe -c "from sastsimi.config.user_config import UserConfigStore,load_simple_execution_profile; c=UserConfigStore().load(); p=load_simple_execution_profile(c.profile_path); assert c.provider==p.provider=='codex' and c.model==p.model=='gpt-6-sol'; print(c.provider, c.model, p.model)"
```

### Task 3: Run the pinned public analysis and capture a diagnosis

**Files:**
- Create: `docs/validation/2026-09-26-changedetection-trial.md`

**Interfaces:**
- Consumes: the persisted Task 2 profile and the existing `sastsimi analyze/status/result/resume` CLI.
- Produces: an exact run ID, final or blocked state, safe error code and stage, and a decision about a concrete generic repair plan.

- [ ] **Step 1: Recheck the remote branch's current SHA.** Use the selected exact commit if still reachable; if upstream moved, pin the newly observed exact SHA in the validation record before running. Do not analyze an unpinned branch.

```powershell
git ls-remote https://github.com/dgtlmoon/changedetection.io.git refs/heads/master
```

- [ ] **Step 2: Run the public SimpleRuntime path with the pinned SHA, not `analyze --profile`.** Require Step 1 output to equal `d789fe3ea5809eef0134943917ef50f47259121b`; if it changed, record the new SHA and amend this command before running. Keep the final JSON in the current PowerShell session for Step 3. The configured cost and token limits are not enforceable when Codex CLI reports no usage.

```powershell
$analysis = .\.venv\Scripts\sastsimi.exe analyze https://github.com/dgtlmoon/changedetection.io.git --commit d789fe3ea5809eef0134943917ef50f47259121b --format json | ConvertFrom-Json
```

- [ ] **Step 3: Observe the new analysis ID and terminal state using read-only CLI commands.** The ID comes from Step 2 output; never assume it is A-001/A-003. If the process needs a new PowerShell session, copy the displayed ID into `$analysisId` before querying. For a blocked retryable run, invoke `resume` once after identifying the cause, then query status again. Do not retry an auth or model rejection.

```powershell
$analysisId = $analysis.data.analysis_id
```

```powershell
.\.venv\Scripts\sastsimi.exe status $analysisId --format json
```

```powershell
.\.venv\Scripts\sastsimi.exe result $analysisId --format json
```

For a retryable `BLOCKED` result after its cause is addressed:

```powershell
.\.venv\Scripts\sastsimi.exe resume $analysisId --format json
```

- [ ] **Step 4: Record only safe facts.** The validation document must contain the exact commit, CLI invocation, display/exact analysis ID if created, stage, status, error code, elapsed time and available safe artifact references. Classify any failure as model/auth, host tool, target dependency, SASTSIMI defect, or actual PoC disproof; do not claim a finding or scope approval solely from a tool success.

- [ ] **Step 5: Gate the next plan.** If a SASTSIMI defect is reproducible, write a separate TDD plan naming the exact source function, regression test and generic fix before editing product behavior. If the run succeeds without a defect, write the documentation-cleanup plan against observed CLI output. If external state blocks progress, report the smallest required user action rather than marking the tool fixed.

- [ ] **Step 6: Commit the diagnostic record without private artifacts or full prompts.**

```powershell
git add -- docs/validation/2026-09-26-changedetection-trial.md
```

```powershell
git commit -m "docs: record pinned changedetection analysis trial"
```
