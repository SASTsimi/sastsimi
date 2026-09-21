from __future__ import annotations


def test_bootstrap_does_not_export_fake_pipeline() -> None:
    import sastsimi.bootstrap as bootstrap

    assert not hasattr(bootstrap, "build_fake_pipeline")
    assert not hasattr(bootstrap, "load_fake_progress")
