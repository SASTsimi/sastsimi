"""Fail-closed proof for a PoC's omitted Django migration switch."""

from __future__ import annotations

import importlib

import pytest

ERROR = (
    b"NodeNotFoundError\n"
    b"traceback: handle > __init__ > __init__ > build_graph > "
    b"validate_consistency > raise_error\n"
)
OUTPUT = (
    b"pinned_source=verified\n"
    b"project_settings_source=verified\n"
    b"project_urlconf_source=verified\n"
    b"project_routes=190\n"
    b"reversible_superuser_routes=2\n"
)
PROJECT = b"""
import os
HELPDESK_TEAMS_MODE_ENABLED = (
    os.getenv("HELPDESK_TEAMS_MODE_ENABLED", "false").lower() == "true"
)
INSTALLED_APPS = ["django.contrib.auth", "helpdesk"]
if HELPDESK_TEAMS_MODE_ENABLED:
    INSTALLED_APPS.extend(["pinax.teams"])
ROOT_URLCONF = "example.urls"
"""
APP = b"""
from django.conf import settings
HELPDESK_TEAMS_MODE_ENABLED = getattr(settings, "HELPDESK_TEAMS_MODE_ENABLED", True)
if HELPDESK_TEAMS_MODE_ENABLED:
    HELPDESK_TEAMS_MIGRATION_DEPENDENCIES = getattr(
        settings, "HELPDESK_TEAMS_MIGRATION_DEPENDENCIES",
        [("pinax_teams", "0004_auto_20170511_0856")],
    )
else:
    HELPDESK_TEAMS_MIGRATION_DEPENDENCIES = []
"""
MIGRATION = b"""
from helpdesk import settings as helpdesk_settings
class Migration:
    dependencies = (
        [("helpdesk", "0027_previous")]
        + helpdesk_settings.HELPDESK_TEAMS_MIGRATION_DEPENDENCIES
    )
"""
CANDIDATE = b"""#!/bin/sh
python3 - <<'PY'
import ast
from pathlib import Path
root = Path('/workspace')
def static_assignments(path):
    values = {}
    tree = ast.parse(path.read_text())
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError, SyntaxError):
            continue
        for name in [
            target.id for target in node.targets
            if isinstance(target, ast.Name)
        ]:
            values[name] = value
    return values
def main():
    candidates = []
    for path in root.rglob('settings.py'):
        values = static_assignments(path)
        candidates.append((path, values))
    _, defaults = max(candidates, key=lambda item: str(item[0]))
    apps = list(defaults['INSTALLED_APPS'])
    settings_values = {
        key: value for key, value in defaults.items()
        if key.startswith('HELPDESK_') and isinstance(
            value, (bool, int, str, list, tuple, dict)
        )
    }
    settings_values.update({'INSTALLED_APPS': apps, 'DATABASES': {'default': {}}})
    from django.conf import settings
    settings.configure(**settings_values)
    import django
    django.setup()
    from django.core.management import call_command
    call_command('migrate', run_syncdb=True)
main()
PY
"""


def classify(
    *,
    stderr: bytes = ERROR,
    stdout: bytes = OUTPUT,
    candidate: bytes = CANDIDATE,
    projects: tuple[bytes, ...] = (PROJECT, PROJECT),
    app: bytes = APP,
    migration: bytes = MIGRATION,
) -> str | None:
    # The assertion stays an ordinary red test before the new module exists.
    try:
        module = importlib.import_module(
            "sastsimi.simple_runtime.django_migration_graph_omission"
        )
    except ModuleNotFoundError:
        return None
    result = module.django_migration_graph_settings_omission(
        stderr,
        stdout,
        candidate,
        projects,
        app,
        migration,
        app_name="helpdesk",
    )
    assert result is None or isinstance(result, str)
    return result


def test_computed_default_off_omitted_by_literal_collector_is_repairable() -> None:
    assert classify() == "HELPDESK_TEAMS_MODE_ENABLED"


@pytest.mark.parametrize(
    ("change", "value"),
    [
        ("stderr", b"ValueError\ntraceback: resolve_related_fields\n"),
        ("stdout", OUTPUT + b"SASTSIMI_POC_INCONCLUSIVE\n"),
        ("projects", (PROJECT, PROJECT.replace(b'"false"', b'"true"'))),
        ("app", APP.replace(b'ENABLED", True', b'ENABLED", False')),
        (
            "migration",
            MIGRATION.replace(
                b" + helpdesk_settings.HELPDESK_TEAMS_MIGRATION_DEPENDENCIES", b""
            ),
        ),
        (
            "candidate",
            CANDIDATE.replace(b"call_command('migrate', run_syncdb=True)", b"pass"),
        ),
        (
            "candidate",
            CANDIDATE.replace(
                b"settings.configure(**settings_values)",
                b"settings_values['HELPDESK_TEAMS_MODE_ENABLED'] = False\n"
                b"    settings.configure(**settings_values)",
            ),
        ),
        (
            "candidate",
            CANDIDATE.replace(b"ast.literal_eval(node.value)", b"eval(node.value)"),
        ),
        ("projects", (PROJECT.replace(b'"helpdesk"]', b'"helpdesk", "pinax_teams"]'),)),
        (
            "candidate",
            CANDIDATE.replace(
                b"    candidates = []",
                b"    root = Path('/tmp/other')\n    candidates = []",
            ),
        ),
        (
            "candidate",
            CANDIDATE.replace(
                b"for path in root.rglob('settings.py'):",
                b"for path in Path('/tmp/other').rglob('settings.py'):",
            ),
        ),
        (
            "candidate",
            CANDIDATE.replace(
                b"    apps = list(defaults['INSTALLED_APPS'])",
                b"    defaults = {'INSTALLED_APPS': ['helpdesk']}\n"
                b"    apps = list(defaults['INSTALLED_APPS'])",
            ),
        ),
        (
            "candidate",
            CANDIDATE.replace(
                b"    settings_values = {",
                b"    apps.append('pinax_teams')\n    settings_values = {",
            ),
        ),
        (
            "candidate",
            CANDIDATE.replace(
                b"    _, defaults = max(candidates, key=lambda item: str(item[0]))",
                b"    candidates[0] = (Path('/tmp/other'), "
                b"{'INSTALLED_APPS': ['helpdesk']})\n"
                b"    _, defaults = max(candidates, key=lambda item: str(item[0]))",
            ),
        ),
    ],
)
def test_ambiguous_or_already_handled_evidence_is_not_repairable(
    change: str, value: object
) -> None:
    if change == "stderr":
        assert isinstance(value, bytes)
        result = classify(stderr=value)
    elif change == "stdout":
        assert isinstance(value, bytes)
        result = classify(stdout=value)
    elif change == "candidate":
        assert isinstance(value, bytes)
        result = classify(candidate=value)
    elif change == "projects":
        assert isinstance(value, tuple)
        result = classify(projects=value)
    elif change == "app":
        assert isinstance(value, bytes)
        result = classify(app=value)
    elif change == "migration":
        assert isinstance(value, bytes)
        result = classify(migration=value)
    else:
        pytest.fail(f"unexpected fixture field: {change}")
    assert result is None


REPAIRED = CANDIDATE.replace(
    b"    settings.configure(**settings_values)",
    b"    settings_values['HELPDESK_TEAMS_MODE_ENABLED'] = False\n"
    b"    settings.configure(**settings_values)",
)


def replay_forbidden(candidate: bytes) -> bool:
    module = importlib.import_module(
        "sastsimi.simple_runtime.django_migration_graph_omission"
    )
    guard = getattr(module, "django_migration_settings_replay_forbidden", None)
    return True if guard is None else guard(candidate, "HELPDESK_TEAMS_MODE_ENABLED")


def test_replay_requires_explicit_false_immediately_before_configure() -> None:
    assert replay_forbidden(REPAIRED) is False


@pytest.mark.parametrize(
    "candidate",
    [
        CANDIDATE,
        REPAIRED.replace(b"'] = False", b"'] = True"),
        REPAIRED.replace(
            b"    settings.configure(**settings_values)",
            b"    settings_values.update({'DEBUG': False})\n"
            b"    settings.configure(**settings_values)",
        ),
        REPAIRED.replace(
            b"    django.setup()",
            b"    settings.HELPDESK_TEAMS_MODE_ENABLED = True\n    django.setup()",
        ),
        REPAIRED.replace(
            b"    django.setup()",
            b"    alias = settings_values\n    django.setup()",
        ),
        REPAIRED.replace(
            b"    django.setup()",
            b"    setattr(settings, 'HELPDESK_TEAMS_MODE_ENABLED', True)\n"
            b"    django.setup()",
        ),
    ],
)
def test_replay_rejects_missing_late_or_mutable_override(candidate: bytes) -> None:
    assert replay_forbidden(candidate) is True


def test_project_scan_rejects_shadowed_path_constructor() -> None:
    candidate = CANDIDATE.replace(
        b"root = Path('/workspace')",
        b"def Path(_ignored): return _ignored\nroot = Path('/workspace')",
    )
    assert classify(candidate=candidate) is None


def test_project_apps_rejects_unconditional_augmented_installed_apps() -> None:
    project = PROJECT.replace(
        b'ROOT_URLCONF = "example.urls"',
        b'INSTALLED_APPS += ["pinax_teams"]\nROOT_URLCONF = "example.urls"',
    )
    assert classify(projects=(project, project)) is None


def test_project_apps_rejects_alias_mutation() -> None:
    project = PROJECT.replace(
        b'ROOT_URLCONF = "example.urls"',
        b"apps_alias = INSTALLED_APPS\n"
        b'apps_alias.append("pinax_teams")\nROOT_URLCONF = "example.urls"',
    )
    assert classify(projects=(project, project)) is None


def test_project_apps_rejects_switch_rebinding() -> None:
    project = PROJECT.replace(
        b'ROOT_URLCONF = "example.urls"',
        b'HELPDESK_TEAMS_MODE_ENABLED = True\nROOT_URLCONF = "example.urls"',
    )
    assert classify(projects=(project, project)) is None


def test_replay_rejects_augmented_setting_mutation_after_configure() -> None:
    candidate = REPAIRED.replace(
        b"    django.setup()",
        b"    settings.HELPDESK_TEAMS_MODE_ENABLED += True\n    django.setup()",
    )
    assert replay_forbidden(candidate) is True


def test_scan_rejects_root_function_rebinding() -> None:
    candidate = CANDIDATE.replace(
        b"root = Path('/workspace')",
        b"root = Path('/workspace')\ndef root(): return Path('/elsewhere')",
    )
    assert classify(candidate=candidate) is None


def test_candidate_rejects_defaults_subscript_mutation() -> None:
    candidate = CANDIDATE.replace(
        b"    apps = list(defaults['INSTALLED_APPS'])",
        b"    defaults['HELPDESK_TEAMS_MODE_ENABLED'] = True\n"
        b"    apps = list(defaults['INSTALLED_APPS'])",
    )
    assert classify(candidate=candidate) is None


def test_candidate_rejects_augmented_config_dict_mutation() -> None:
    candidate = CANDIDATE.replace(
        b"    settings.configure(**settings_values)",
        b"    settings_values |= {'HELPDESK_TEAMS_MODE_ENABLED': True}\n"
        b"    settings.configure(**settings_values)",
    )
    assert classify(candidate=candidate) is None


def test_candidate_preserves_read_only_defaults_get() -> None:
    candidate = CANDIDATE.replace(
        b"    apps = list(defaults['INSTALLED_APPS'])",
        b"    urlconf = defaults.get('ROOT_URLCONF')\n"
        b"    apps = list(defaults['INSTALLED_APPS'])",
    )
    assert classify(candidate=candidate) == "HELPDESK_TEAMS_MODE_ENABLED"


def test_project_scan_exposes_only_verified_workspace_root() -> None:
    module = importlib.import_module(
        "sastsimi.simple_runtime.django_migration_graph_omission"
    )
    scan = getattr(module, "django_migration_graph_project_scan_root", None)
    assert scan is not None and scan(CANDIDATE) == "/workspace"
