"""A migration setup failure may warrant one source-bound PoC replan."""

from __future__ import annotations

from typing import TypedDict

from sastsimi.simple_runtime import django_migration_graph_omission


class _ReplayBound(TypedDict):
    flag: str
    app_name: str
    project_modules: tuple[str, ...]


ERROR = (
    b"NodeNotFoundError\nTraceback (most recent call last):\n"
    b"  at handle:40\n  at __init__:71\n  at __init__:92\n"
    b"  at build_graph:115\n  at validate_consistency:127\n"
    b"  at raise_error:133\n"
)
PROJECT = b"""
import os
FORUM_TEAMS_MODE_ENABLED = (
    os.getenv("FORUM_TEAMS_MODE_ENABLED", "false").lower() == "true"
)
INSTALLED_APPS = ["django.contrib.auth", "forum"]
if FORUM_TEAMS_MODE_ENABLED:
    INSTALLED_APPS.extend(["optional_plugin"])
ROOT_URLCONF = "example.urls"
"""
TEST_PROJECT = b"""
INSTALLED_APPS = ["django.contrib.auth", "forum"]
ROOT_URLCONF = "tests.urls"
FORUM_TEAMS_MIGRATION_DEPENDENCIES = []
"""
APP = b"""
from django.conf import settings
FORUM_TEAMS_MODE_ENABLED = getattr(settings, "FORUM_TEAMS_MODE_ENABLED", True)
if FORUM_TEAMS_MODE_ENABLED:
    FORUM_TEAMS_MIGRATION_DEPENDENCIES = getattr(
        settings, "FORUM_TEAMS_MIGRATION_DEPENDENCIES",
        [("optional_plugin", "0004_setup")],
    )
else:
    FORUM_TEAMS_MIGRATION_DEPENDENCIES = []
"""
MIGRATION = b"""
from forum import settings as forum_settings
class Migration:
    dependencies = [("forum", "0027_previous")] + (
        forum_settings.FORUM_TEAMS_MIGRATION_DEPENDENCIES
    )
"""
CANDIDATE = b"""#!/bin/sh
python3 - <<'PY'
import ast
from pathlib import Path
root = Path('/workspace')
project_flags = {}
for candidate in root.rglob('settings.py'):
    if candidate == root / 'src/forum/settings.py' or '.git' in candidate.parts:
        continue
    tree = ast.parse(candidate.read_text(encoding='utf-8'))
    names = {item.id for node in tree.body if isinstance(node, ast.Assign)
             for item in node.targets if isinstance(item, ast.Name)}
    if not {'ROOT_URLCONF', 'INSTALLED_APPS'} <= names:
        continue
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for item in node.targets:
            if isinstance(item, ast.Name) and item.id.startswith('FORUM_'):
                try:
                    project_flags[item.id] = ast.literal_eval(node.value)
                except (ValueError, TypeError, SyntaxError):
                    pass
    break
from django.conf import settings
fixture_settings = dict(ROOT_URLCONF='fixture_urls',
                        INSTALLED_APPS=['django.contrib.auth', 'forum'],
                        DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3',
                                               'NAME': ':memory:'}})
fixture_settings.update(project_flags)
settings.configure(**fixture_settings)
import django
django.setup()
from django.core.management import call_command
call_command('migrate', run_syncdb=True)
from django.test import Client
response = Client().get('/target/')
PY
"""
NATIVE_REPLAN = b"""#!/bin/sh
python3 - <<'PY'
import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'demodesk.config.settings'
import django
django.setup()
from django.core.management import call_command
call_command('migrate', run_syncdb=True)
from django.test import Client
response = Client().get('/target/')
PY
"""


def classify(**overrides: object) -> str | None:
    args: dict[str, object] = {
        "stderr": ERROR,
        "stdout": b"",
        "candidate": CANDIDATE,
        "projects": (PROJECT, TEST_PROJECT),
        "app_settings": APP,
        "migration": MIGRATION,
        "app_name": "forum",
    }
    args.update(overrides)
    classifier = getattr(
        django_migration_graph_omission, "django_migration_fixture_source_gap", None
    )
    return None if classifier is None else classifier(**args)


def test_source_bound_synthetic_fixture_gap_is_replan_eligible() -> None:
    assert classify() == "FORUM_TEAMS_MODE_ENABLED"


def test_function_only_traceback_and_unrelated_literal_key_are_supported() -> None:
    stderr = ERROR.replace(b"  at ", b"  in ")
    stderr = __import__("re").sub(rb":[0-9]+", b"", stderr)
    candidate = CANDIDATE.replace(
        b"settings.configure(**fixture_settings)",
        b"fixture_settings['LOG' + '_LEVEL'] = 0\n"
        b"settings.configure(**fixture_settings)",
    )
    assert classify(stderr=stderr, candidate=candidate) == "FORUM_TEAMS_MODE_ENABLED"


def test_bounded_fixture_inside_exception_wrapper_is_supported() -> None:
    body = CANDIDATE.split(b"python3 - <<'PY'\n", 1)[1].rsplit(b"\nPY", 1)[0]
    wrapped = (
        b"#!/bin/sh\npython3 - <<'PY'\ntry:\n"
        + b"\n".join(b"    " + line for line in body.splitlines())
        + b"\nexcept Exception:\n    pass\nPY\n"
    )
    assert classify(candidate=wrapped) == "FORUM_TEAMS_MODE_ENABLED"


def test_unrelated_error_or_route_success_is_not_replan_eligible() -> None:
    assert classify(stderr=b"ImportError\n") is None
    assert classify(stdout=b"confirmed\n") is None


def test_missing_source_proof_or_migration_is_not_replan_eligible() -> None:
    assert classify(projects=(TEST_PROJECT,)) is None
    assert (
        classify(app_settings=APP.replace(b'ENABLED", True', b'ENABLED", False'))
        is None
    )
    assert (
        classify(
            migration=MIGRATION.replace(
                b"forum_settings.FORUM_TEAMS_MIGRATION_DEPENDENCIES", b"[]"
            )
        )
        is None
    )


def test_candidate_must_really_use_synthetic_settings_and_migration() -> None:
    assert (
        classify(
            candidate=CANDIDATE.replace(
                b"settings.configure(**fixture_settings)", b"pass"
            )
        )
        is None
    )
    assert (
        classify(
            candidate=CANDIDATE.replace(
                b"call_command('migrate', run_syncdb=True)", b"pass"
            )
        )
        is None
    )
    assert (
        classify(
            candidate=CANDIDATE.replace(
                b"root = Path('/workspace')", b"root = Path('/tmp')"
            )
        )
        is None
    )
    assert (
        classify(
            candidate=CANDIDATE.replace(
                b"project_flags[item.id] = ast.literal_eval(node.value)",
                b"project_flags[item.id] = eval(node.value)",
            )
        )
        is None
    )


def test_migration_bypass_and_explicit_flag_do_not_need_this_replan() -> None:
    assert (
        classify(
            candidate=CANDIDATE.replace(
                b"fixture_settings.update(project_flags)",
                b"fixture_settings['FORUM_TEAMS_MODE_ENABLED'] = False\n"
                b"fixture_settings.update(project_flags)",
            )
        )
        is None
    )
    assert (
        classify(
            candidate=CANDIDATE.replace(
                b"fixture_settings.update(project_flags)",
                b"fixture_settings['MIGRATION_MODULES'] = {'forum': None}\n"
                b"fixture_settings.update(project_flags)",
            )
        )
        is None
    )


def test_replanned_candidate_must_run_real_migrations_before_route() -> None:
    guard = getattr(
        django_migration_graph_omission,
        "django_migration_fixture_replay_forbidden",
        None,
    )
    assert guard is not None
    assert guard(CANDIDATE) is False
    assert (
        guard(CANDIDATE.replace(b"call_command('migrate', run_syncdb=True)", b"pass"))
        is True
    )
    assert guard(CANDIDATE.replace(b"run_syncdb=True", b"fake=True")) is True
    assert (
        guard(
            CANDIDATE.replace(
                b"fixture_settings.update(project_flags)",
                b"fixture_settings['MIGRATION_MODULES'] = {'forum': None}\n"
                b"fixture_settings.update(project_flags)",
            )
        )
        is True
    )
    assert (
        guard(
            CANDIDATE.replace(
                b"call_command('migrate', run_syncdb=True)",
                b"Client().get('/target/')\ncall_command('migrate', run_syncdb=True)",
            )
        )
        is True
    )


def test_source_bound_replan_rejects_cosmetic_changes_and_nonexecuting_migration() -> (
    None
):
    guard = django_migration_graph_omission.django_migration_fixture_replay_forbidden
    bound: _ReplayBound = {
        "flag": "FORUM_TEAMS_MODE_ENABLED",
        "app_name": "forum",
        "project_modules": ("demodesk.config.settings",),
    }
    assert guard(CANDIDATE, **bound) is True
    assert (
        guard(
            CANDIDATE.replace(
                b"root.rglob('settings.py')", b"root.glob('config/settings.py')"
            ),
            **bound,
        )
        is True
    )
    assert guard(NATIVE_REPLAN, **bound) is False
    assert (
        guard(
            NATIVE_REPLAN.replace(
                b"demodesk.config.settings", b"other.config.settings"
            ),
            **bound,
        )
        is True
    )
    assert (
        guard(
            NATIVE_REPLAN.replace(
                b"call_command('migrate', run_syncdb=True)",
                b"if False:\n    call_command('migrate', run_syncdb=True)",
            ),
            **bound,
        )
        is True
    )
    assert (
        guard(
            NATIVE_REPLAN.replace(
                b"call_command('migrate', run_syncdb=True)",
                b"try:\n    call_command('migrate', run_syncdb=True)\n"
                b"except Exception:\n    pass",
            ),
            **bound,
        )
        is True
    )
    assert (
        guard(
            NATIVE_REPLAN.replace(
                b"django.setup()",
                b"fixture_settings = {}\n"
                b"fixture_settings['MIGR' + 'ATION_MODULES'] = {'forum': None}\n"
                b"django.setup()",
            ),
            **bound,
        )
        is True
    )
    assert (
        guard(
            NATIVE_REPLAN.replace(
                b"django.setup()",
                b"settings.MIGRATION_MODULES = {'forum': None}\ndjango.setup()",
            ),
            **bound,
        )
        is True
    )
    assert (
        guard(
            NATIVE_REPLAN.replace(
                b"django.setup()",
                b"def call_command(*args, **kwargs):\n    return None\ndjango.setup()",
            ),
            **bound,
        )
        is True
    )
    assert (
        guard(
            NATIVE_REPLAN.replace(
                b"django.setup()",
                b"os.environ['DJANGO_SETTINGS_MODULE'] = "
                b"'other.config.settings'\ndjango.setup()",
            ),
            **bound,
        )
        is True
    )
    assert (
        guard(
            NATIVE_REPLAN.replace(
                b"django.setup()",
                b"environment = os.environ\n"
                b"environment['DJANGO_SETTINGS_MODULE'] = "
                b"'other.config.settings'\ndjango.setup()",
            ),
            **bound,
        )
        is True
    )
    assert (
        guard(NATIVE_REPLAN.replace(b"run_syncdb=True", b"**{'fake': True}"), **bound)
        is True
    )
    assert (
        guard(
            NATIVE_REPLAN.replace(b"run_syncdb=True", b"**{'fake' + '_initial': True}"),
            **bound,
        )
        is True
    )
    assert (
        guard(
            NATIVE_REPLAN.replace(
                b"django.setup()",
                b"from django.conf import settings\n"
                b"setattr(settings, 'MIGR' + 'ATION_MODULES', {'forum': None})\n"
                b"django.setup()",
            ),
            **bound,
        )
        is True
    )
    assert (
        guard(
            NATIVE_REPLAN.replace(
                b"django.setup()",
                b"from django.conf import settings\n"
                b"settings.__dict__['MIGRATION_MODULES'] = {'forum': None}\n"
                b"django.setup()",
            ),
            **bound,
        )
        is True
    )


def test_pinned_source_projection_selects_eligible_project_without_secret_text() -> (
    None
):
    projection = (
        django_migration_graph_omission.django_migration_fixture_source_projection(
            flag="FORUM_TEAMS_MODE_ENABLED",
            app_name="forum",
            project_sources=(
                (
                    "demodesk/config/settings.py",
                    PROJECT + b"\nAPI_KEY = 'must_not_leak'\n",
                ),
                ("tests/settings.py", TEST_PROJECT),
            ),
            app_settings=APP,
            migration=MIGRATION,
        )
    )
    assert projection is not None
    assert projection["verified_project_modules"] == ["demodesk.config.settings"]
    assert projection["optional_dependency_nodes"] == [
        ["optional_plugin", "0004_setup"]
    ]
    assert "must_not_leak" not in str(projection)
