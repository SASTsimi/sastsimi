"""An explicit saved-surface v4 opt-in reaches both CLI execution paths."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from sastsimi.interfaces.cli.main import main
from sastsimi.progress.models import ProgressSnapshot
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication


class _EnrichmentApplication(_PublicApplication):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bool]] = []

    def resume(
        self,
        analysis_id: str,
        *,
        enrich_saved_surface_evidence: bool = False,
        **_kwargs: object,
    ) -> dict[str, object]:
        self.calls.append(("plain", analysis_id, enrich_saved_surface_evidence))
        return super().resume(analysis_id)

    def resume_with_progress(
        self,
        analysis_id: str,
        _callback: Callable[[ProgressSnapshot], None],
        *,
        enrich_saved_surface_evidence: bool = False,
        **_kwargs: object,
    ) -> dict[str, object]:
        self.calls.append(("progress", analysis_id, enrich_saved_surface_evidence))
        return super().resume(analysis_id)


def test_flag_is_exclusive_and_forwarded_through_plain_and_progress_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    application = _EnrichmentApplication()
    config = _config(tmp_path)
    args = ["resume", "A-001", "--enrich-saved-surface-evidence"]

    assert (
        main(
            [*args, "--format", "json"],
            public_application=application,
            user_config_store=config,
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["data"]["status"] == "COMPLETE"
    assert main(args, public_application=application, user_config_store=config) == 0
    capsys.readouterr()
    assert application.calls == [
        ("plain", "A-001", True),
        ("progress", "A-001", True),
    ]

    assert (
        main(
            [*args, "--supplement-saved-v2-ast-orphans", "--format", "json"],
            public_application=application,
            user_config_store=config,
        )
        == 2
    )
    assert len(application.calls) == 2
