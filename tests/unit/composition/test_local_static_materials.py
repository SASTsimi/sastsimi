from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sastsimi.composition.local_static_materials import (
    load_local_candidate_static_materials,
)

ROOT = Path(__file__).parents[3]
MATERIALS = ROOT / "config" / "static-analysis" / "candidate-v1"


def test_loader_builds_the_exact_runtime_material_closure() -> None:
    value = load_local_candidate_static_materials(MATERIALS)

    assert value.enabled_tools == ("AST", "OPENGREP", "CODEQL")
    assert value.codeql_query_pack_sha256 == (
        "b34dec784e43da96f45b65099db69297851f89c95b63049cc946b18c469a738a"
    )
    manifest = json.loads(value.evidence[value.analysis_config_sha256])
    assert set(manifest["tools"]) == {"OPENGREP", "CODEQL"}
    assert set(value.rule_closures) == {"OPENGREP", "CODEQL"}
    assert value.route_digests["AST"] == (value.analysis_config_sha256,)
    assert len(value.route_digests["OPENGREP"]) == 4
    assert len(value.route_digests["CODEQL"]) == 4
    assert all(
        digest in value.evidence
        for digests in value.route_digests.values()
        for digest in digests
    )


def test_loader_rejects_a_file_changed_after_the_candidate_manifest(
    tmp_path: Path,
) -> None:
    root = tmp_path / "candidate-v1"
    shutil.copytree(MATERIALS, root)
    (root / "opengrep" / "rules.yml").write_text("rules: []\n", encoding="utf-8")

    with pytest.raises(ValueError, match="LOCAL_STATIC_MATERIAL_STALE"):
        load_local_candidate_static_materials(root)
