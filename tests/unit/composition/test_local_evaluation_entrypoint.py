from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from sastsimi.composition.local_evaluation_entrypoint import (
    build_local_evaluation_analyze,
)
from tests.unit.config.test_local_evaluation_profile import _profile_text


def test_shipped_entrypoint_runs_concrete_preflight_before_sync_composition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sastsimi.composition import local_evaluation_preflight as preflight

    profile_path = tmp_path / "local-evaluation.toml"
    profile_path.write_text(_profile_text(tmp_path), encoding="utf-8")

    def reject(*_args: object, **_kwargs: object) -> object:
        raise ValueError("LOCAL_CAPABILITY_PREFLIGHT_REACHED")

    monkeypatch.setattr(preflight, "resolve_local_approved_capabilities", reject)
    entrypoint = build_local_evaluation_analyze()

    with pytest.raises(ValueError, match="LOCAL_CAPABILITY_PREFLIGHT_REACHED"):
        asyncio.run(
            entrypoint(
                SimpleNamespace(
                    data_dir=tmp_path / "data",
                    repository="https://example.invalid/repository.git",
                    commit="a" * 40,
                    profile=profile_path,
                )
            )
        )
