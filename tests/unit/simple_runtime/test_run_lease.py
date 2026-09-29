from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime import run_lease
from sastsimi.simple_runtime.run_lease import AnalysisRunBusy, analysis_run_lease


def test_analysis_lease_prevents_duplicate_runner_and_releases_after_exit(
    tmp_path: Path,
) -> None:
    with analysis_run_lease(tmp_path, "analysis-1"):
        with pytest.raises(AnalysisRunBusy):
            with analysis_run_lease(tmp_path, "analysis-1"):
                pytest.fail("second runner must not enter")
        with analysis_run_lease(tmp_path, "analysis-2"):
            pass

    with analysis_run_lease(tmp_path, "analysis-1"):
        pass


def test_analysis_lease_releases_after_exception(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="interrupted"):
        with analysis_run_lease(tmp_path, "analysis-1"):
            raise RuntimeError("interrupted")

    with analysis_run_lease(tmp_path, "analysis-1"):
        pass


def test_lease_probe_is_read_only_and_distinguishes_active_from_released(
    tmp_path: Path,
) -> None:
    lease_directory = tmp_path / "db" / "analysis-leases"
    assert run_lease.analysis_run_lease_active(tmp_path, "analysis-1") is False
    assert not lease_directory.exists()

    with analysis_run_lease(tmp_path, "analysis-1"):
        lease_file = next(lease_directory.iterdir())
        before = (lease_file.stat().st_size, lease_file.stat().st_mtime_ns)
        assert run_lease.analysis_run_lease_active(tmp_path, "analysis-1") is True
        assert (lease_file.stat().st_size, lease_file.stat().st_mtime_ns) == before

    assert run_lease.analysis_run_lease_active(tmp_path, "analysis-1") is False
    assert lease_file.read_bytes() == b"\0"
