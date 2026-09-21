from __future__ import annotations

from sastsimi.simple_runtime.bootstrap_stages import DirectStaticBootstrap


def test_source_checkout_static_materials_are_complete() -> None:
    root = DirectStaticBootstrap._static_material_root()

    assert (root / "opengrep" / "rules.yml").is_file()
    assert (root / "codeql" / "python-security.qls").is_file()
    assert (root / "codeql" / "qlpack.yml").is_file()
