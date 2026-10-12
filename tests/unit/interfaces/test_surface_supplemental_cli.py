"""CLI opt-in for a saved v2 AST-only surface review is not implicit."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from sastsimi.interfaces.cli.main import main
from sastsimi.progress.models import ProgressSnapshot
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication


class _SupplementApplication(_PublicApplication):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bool]] = []

    def resume(
        self,
        analysis_id: str,
        *,
        supplement_saved_v2_ast_orphans: bool = False,
        **_kwargs: object,
    ) -> dict[str, object]:
        self.calls.append(("plain", analysis_id, supplement_saved_v2_ast_orphans))
        return super().resume(analysis_id)

    def resume_with_progress(
        self,
        analysis_id: str,
        _callback: Callable[[ProgressSnapshot], None],
        *,
        supplement_saved_v2_ast_orphans: bool = False,
    ) -> dict[str, object]:
        self.calls.append(("progress", analysis_id, supplement_saved_v2_ast_orphans))
        return super().resume(analysis_id)


def test_surface_supplement_flag_reaches_json_and_progress_resume(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    application = _SupplementApplication()
    config = _config(tmp_path)
    args = ["resume", "A-001", "--supplement-saved-v2-ast-orphans"]

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
