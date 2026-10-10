"""A generated Django harness may omit a pinned, default-off relation switch."""

from __future__ import annotations

import pytest

from sastsimi.simple_runtime.django_relation_settings_omission import (
    django_relation_setting_mismatch,
    django_relation_settings_replay_forbidden,
)

_FAILURE = (
    b"ValueError\n"
    b"Traceback: __get__ > foreign_related_fields > __get__ > "
    b"related_fields > resolve_related_fields > resolve_related_fields\n"
)
_STDOUT = b"PINNED_SOURCE_OK sha256=abcdef\nCALLER=edit\nURLCONF=repository_project\n"
_CANDIDATE = b"""#!/bin/sh
python - <<'PY'
import ast
from pathlib import Path
from django.conf import settings

def literals(path):
    values = {}
    for node in ast.parse(path.read_text()).body:
        if not isinstance(node, ast.Assign):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                values[target.id] = value
    return values

def main():
    from widget.models import Article
    project_path = Path('/workspace/project/config/settings.py')
    project = literals(project_path)
    installed = list(project.get('INSTALLED_APPS', ()))
    if 'widget' not in installed:
        installed.append('widget')
    options = dict(INSTALLED_APPS=installed, ROOT_URLCONF='project.urls')
    options.update({key: value for key, value in project.items()
                    if key.startswith('WIDGET_')
                    and isinstance(value, (str, int, bool))})
    settings.configure(**options)
    import django
    django.setup()
    call_command('migrate', run_syncdb=True)

main()
PY
"""
_PROJECT = b"""import os
WIDGET_TEAMS_ENABLED = (
    os.getenv('WIDGET_TEAMS_ENABLED', 'false').lower() == 'true'
)
INSTALLED_APPS = ['django.contrib.auth', 'widget']
"""
_APP_SETTINGS = b"""from django.conf import settings
WIDGET_TEAMS_ENABLED = getattr(settings, 'WIDGET_TEAMS_ENABLED', True)
if WIDGET_TEAMS_ENABLED:
    WIDGET_TEAMS_MODEL = getattr(settings, 'WIDGET_TEAMS_MODEL', 'optional_teams.Team')
else:
    WIDGET_TEAMS_MODEL = settings.AUTH_USER_MODEL
"""
_MODELS = b"""from django.db import models
from widget import settings as widget_settings
class Article(models.Model):
    team = models.ForeignKey(
        widget_settings.WIDGET_TEAMS_MODEL, on_delete=models.CASCADE
    )
"""


def _classify(
    *,
    stderr: bytes = _FAILURE,
    stdout: bytes = _STDOUT,
    candidate: bytes = _CANDIDATE,
    project: bytes = _PROJECT,
    app_settings: bytes = _APP_SETTINGS,
    models: bytes = _MODELS,
) -> str | None:
    return django_relation_setting_mismatch(
        stderr,
        stdout,
        candidate,
        project,
        app_settings,
        models,
        app_name="widget",
    )


def test_default_off_relation_omission_is_identified_without_repository_names() -> None:
    assert _classify() == "WIDGET_TEAMS_ENABLED"


def test_relation_classifier_rejects_weak_or_contradictory_evidence() -> None:
    assert _classify(stderr=b"ValueError\nTraceback: unrelated\n") is None
    assert _classify(stdout=_STDOUT + b"TEMP_DATABASE_MIGRATED\n") is None
    assert (
        _classify(
            candidate=_CANDIDATE.replace(
                b"settings.configure(**options)",
                b"options['WIDGET_TEAMS_ENABLED'] = False\n"
                b"    settings.configure(**options)",
            )
        )
        is None
    )
    assert _classify(project=_PROJECT.replace(b"'false'", b"'true'")) is None
    assert (
        _classify(app_settings=_APP_SETTINGS.replace(b", True)", b", False)")) is None
    )
    assert _classify(models=b"class Article: pass\n") is None
    assert (
        _classify(
            candidate=_CANDIDATE.replace(
                b"options.update({key: value for key, value in project.items()",
                b"options.update({key: value for key, value in unknown.items()",
            )
        )
        is None
    )


@pytest.mark.parametrize(
    "mutation",
    (
        b"    values.update({'WIDGET_TEAMS_ENABLED': False})\n",
        b"    alias = values\n    alias['WIDGET_TEAMS_ENABLED'] = False\n",
    ),
)
def test_relation_classifier_rejects_collector_values_mutation(
    mutation: bytes,
) -> None:
    candidate = _CANDIDATE.replace(
        b"    return values\n", mutation + b"    return values\n"
    )
    assert _classify(candidate=candidate) is None


@pytest.mark.parametrize(
    "mutation",
    (
        b"    options.setdefault('WIDGET_TEAMS_ENABLED', False)\n",
        b"    options.__setitem__('WIDGET_TEAMS_ENABLED', False)\n",
        b"    options |= {'WIDGET_TEAMS_ENABLED': False}\n",
        b"    alias = options\n    alias['WIDGET_TEAMS_ENABLED'] = False\n",
    ),
)
def test_relation_classifier_rejects_unbounded_options_mutation(
    mutation: bytes,
) -> None:
    candidate = _CANDIDATE.replace(
        b"    settings.configure(**options)\n",
        mutation + b"    settings.configure(**options)\n",
    )
    assert _classify(candidate=candidate) is None


def test_relation_classifier_rejects_path_name_shadow() -> None:
    candidate = _CANDIDATE.replace(
        b"def main():\n",
        b"def Path(value):\n    return 'zother/config/settings.py'\n\ndef main():\n",
    )
    assert _classify(candidate=candidate) is None


def test_relation_classifier_rejects_path_constructor_alias() -> None:
    candidate = _CANDIDATE.replace(
        b"def main():\n",
        b"path_alias = Path\n"
        b"path_alias.__new__ = lambda cls, value: value\n\n"
        b"def main():\n",
    )
    assert _classify(candidate=candidate) is None


def test_replay_guard_requires_explicit_false_before_configuration() -> None:
    assert django_relation_settings_replay_forbidden(_CANDIDATE, "WIDGET_TEAMS_ENABLED")
    repaired = _CANDIDATE.replace(
        b"    settings.configure(**options)",
        b"    options['WIDGET_TEAMS_ENABLED'] = False\n"
        b"    settings.configure(**options)",
    )
    assert not django_relation_settings_replay_forbidden(
        repaired, "WIDGET_TEAMS_ENABLED"
    )
    assert django_relation_settings_replay_forbidden(
        repaired.replace(b"= False", b"= True"), "WIDGET_TEAMS_ENABLED"
    )
    assert django_relation_settings_replay_forbidden(
        repaired.replace(
            b"    settings.configure(**options)",
            b"    options = {}\n    settings.configure(**options)",
        ),
        "WIDGET_TEAMS_ENABLED",
    )
    assert django_relation_settings_replay_forbidden(
        repaired.replace(
            b"    settings.configure(**options)",
            b"    options['WIDGET_TEAMS_ENABLED'] = True\n"
            b"    settings.configure(**options)",
        ),
        "WIDGET_TEAMS_ENABLED",
    )


@pytest.mark.parametrize(
    "mutation",
    (
        b"    options.setdefault('WIDGET_TEAMS_ENABLED', True)\n",
        b"    options.__setitem__('WIDGET_TEAMS_ENABLED', True)\n",
        b"    options |= {'WIDGET_TEAMS_ENABLED': True}\n",
        b"    alias = options\n    alias['WIDGET_TEAMS_ENABLED'] = True\n",
    ),
)
def test_replay_guard_rejects_options_mutation_after_false_override(
    mutation: bytes,
) -> None:
    repaired = _CANDIDATE.replace(
        b"    settings.configure(**options)\n",
        b"    options['WIDGET_TEAMS_ENABLED'] = False\n"
        + mutation
        + b"    settings.configure(**options)\n",
    )
    assert django_relation_settings_replay_forbidden(repaired, "WIDGET_TEAMS_ENABLED")


@pytest.mark.parametrize(
    "mutation",
    (
        b"    options.setdefault('WIDGET_TEAMS_ENABLED', True)\n",
        b"    options.__setitem__('WIDGET_TEAMS_ENABLED', True)\n",
        b"    options |= {'WIDGET_TEAMS_ENABLED': True}\n",
        b"    alias = options\n    alias['WIDGET_TEAMS_ENABLED'] = True\n",
    ),
)
def test_replay_guard_rejects_unbounded_options_before_final_override(
    mutation: bytes,
) -> None:
    repaired = _CANDIDATE.replace(
        b"    settings.configure(**options)\n",
        mutation
        + b"    options['WIDGET_TEAMS_ENABLED'] = False\n"
        + b"    settings.configure(**options)\n",
    )
    assert django_relation_settings_replay_forbidden(repaired, "WIDGET_TEAMS_ENABLED")


@pytest.mark.parametrize(
    "mutation",
    (
        b"settings.WIDGET_TEAMS_ENABLED = True",
        b"setattr(settings, 'WIDGET_TEAMS_ENABLED', True)",
        b"setattr(settings, dynamic_flag, True)",
        b"delattr(settings, 'WIDGET_TEAMS_ENABLED')",
        b"alias = settings\n    alias.WIDGET_TEAMS_ENABLED = True",
        b"alias = settings\n    setattr(alias, 'WIDGET_TEAMS_ENABLED', True)",
        b"from django.conf import settings as alias\n"
        b"    alias.WIDGET_TEAMS_ENABLED = True",
        b"globals()['settings'].WIDGET_TEAMS_ENABLED = True",
        b"vars(settings)['WIDGET_TEAMS_ENABLED'] = True",
        b"configure_again = settings.configure\n"
        b"    configure_again(WIDGET_TEAMS_ENABLED=True)",
    ),
)
def test_replay_guard_rejects_settings_mutation_after_false_override(
    mutation: bytes,
) -> None:
    repaired = _CANDIDATE.replace(
        b"    settings.configure(**options)",
        b"    options['WIDGET_TEAMS_ENABLED'] = False\n"
        b"    settings.configure(**options)\n    " + mutation,
    )
    assert django_relation_settings_replay_forbidden(repaired, "WIDGET_TEAMS_ENABLED")
