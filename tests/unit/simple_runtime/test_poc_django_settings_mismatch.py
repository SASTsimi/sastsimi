"""A generated Django configuration must preserve a pinned migration switch."""

from __future__ import annotations

from sastsimi.simple_runtime import recovery

_FAILURE = (
    b"NodeNotFoundError\nTraceback (most recent call last):\n"
    b"  at unresolved_frame:31\n  at call_command:195\n"
    b"  at build_graph:313\n  at validate_consistency:200\n"
)
_CANDIDATE = b"""#!/bin/sh
python - <<'PY'
from django.conf import settings
settings.configure(
    ROOT_URLCONF='demo.config.urls',
    INSTALLED_APPS=['django.contrib.auth', 'widget'],
)
import django
django.setup()
from django.core.management import call_command
call_command('migrate', run_syncdb=True)
PY
"""
_PROJECT_SETTINGS = b"""import os
WIDGET_TEAMS_ENABLED = (
    os.getenv('WIDGET_TEAMS_ENABLED', 'false').lower() == 'true'
)
INSTALLED_APPS = ['django.contrib.auth', 'widget']
"""
_APP_SETTINGS = b"""from django.conf import settings
WIDGET_TEAMS_ENABLED = getattr(settings, 'WIDGET_TEAMS_ENABLED', True)
if WIDGET_TEAMS_ENABLED:
    WIDGET_MIGRATION_DEPENDENCIES = getattr(
        settings, 'WIDGET_MIGRATION_DEPENDENCIES', [('optional_teams', '0001')]
    )
else:
    WIDGET_MIGRATION_DEPENDENCIES = []
"""
_MIGRATION = b"""from widget import settings as widget_settings
class Migration:
    dependencies = [('widget', '0001')] + widget_settings.WIDGET_MIGRATION_DEPENDENCIES
"""


def test_pinned_settings_mismatch_identifies_only_the_missing_boolean_switch() -> None:
    assert (
        recovery.django_migration_setting_mismatch(
            _FAILURE,
            b"",
            _CANDIDATE,
            _PROJECT_SETTINGS,
            _APP_SETTINGS,
            _MIGRATION,
            app_name="widget",
        )
        == "WIDGET_TEAMS_ENABLED"
    )


def test_pinned_settings_mismatch_rejects_unrelated_or_resolved_failures() -> None:
    mismatch = recovery.django_migration_setting_mismatch
    assert (
        mismatch(
            b"NoReverseMatch\n",
            b"",
            _CANDIDATE,
            _PROJECT_SETTINGS,
            _APP_SETTINGS,
            _MIGRATION,
            app_name="widget",
        )
        is None
    )
    assert (
        mismatch(
            _FAILURE,
            b"route reproduced\n",
            _CANDIDATE,
            _PROJECT_SETTINGS,
            _APP_SETTINGS,
            _MIGRATION,
            app_name="widget",
        )
        is None
    )
    assert (
        mismatch(
            _FAILURE,
            b"",
            _CANDIDATE.replace(
                b"INSTALLED_APPS=[", b"WIDGET_TEAMS_ENABLED=False, INSTALLED_APPS=["
            ),
            _PROJECT_SETTINGS,
            _APP_SETTINGS,
            _MIGRATION,
            app_name="widget",
        )
        is None
    )
    assert (
        mismatch(
            _FAILURE,
            b"",
            _CANDIDATE,
            _PROJECT_SETTINGS,
            _APP_SETTINGS.replace(b"True)", b"False)"),
            _MIGRATION,
            app_name="widget",
        )
        is None
    )
    assert (
        mismatch(
            _FAILURE,
            b"",
            _CANDIDATE,
            _PROJECT_SETTINGS,
            _APP_SETTINGS,
            b"class Migration: dependencies = []\n",
            app_name="widget",
        )
        is None
    )


def test_settings_replay_rejects_repeat_configuration() -> None:
    assert recovery.django_settings_replay_forbidden(_CANDIDATE, "WIDGET_TEAMS_ENABLED")
    fixed = _CANDIDATE.replace(
        b"INSTALLED_APPS=[", b"WIDGET_TEAMS_ENABLED=False, INSTALLED_APPS=["
    )
    assert not recovery.django_settings_replay_forbidden(fixed, "WIDGET_TEAMS_ENABLED")
    assert recovery.django_settings_replay_forbidden(
        fixed.replace(b"WIDGET_TEAMS_ENABLED=False", b"WIDGET_TEAMS_ENABLED=True"),
        "WIDGET_TEAMS_ENABLED",
    )
