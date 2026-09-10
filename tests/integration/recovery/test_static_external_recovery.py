from pathlib import Path

import pytest

from sastsimi.orchestration.static_external_runner import _guarded_read


def test_static_recovery_read_is_bounded(tmp_path: Path) -> None:
    candidate = tmp_path / "observation.json"
    candidate.write_bytes(b"12345")

    with pytest.raises(ValueError, match="STATIC_ACTION_RECEIPT_INVALID"):
        _guarded_read(candidate, 4)


def test_static_recovery_never_follows_observation_link(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_bytes(b"{}")
    linked = tmp_path / "observation.json"
    try:
        linked.symlink_to(real)
    except OSError:
        pytest.skip("symlinks are unavailable on this host")

    with pytest.raises(ValueError, match="STATIC_ACTION_RECEIPT_INVALID"):
        _guarded_read(linked, 64)
