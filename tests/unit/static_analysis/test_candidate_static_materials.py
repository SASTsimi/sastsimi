"""Candidate static-analysis materials stay exact and explicitly unapproved."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[3]
MATERIAL_ROOT = ROOT / "config" / "static-analysis" / "candidate-v1"


def _json(relative: str) -> dict[str, object]:
    value = json.loads((MATERIAL_ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _rule_ids(document: dict[str, object]) -> tuple[str, ...]:
    rules = document["rules"]
    assert isinstance(rules, list)
    return tuple(str(rule["rule_id"]) for rule in rules)


def _selected_rule_ids(document: dict[str, object]) -> tuple[str, ...]:
    selected = document["selected_rule_ids"]
    assert isinstance(selected, list)
    return tuple(str(rule_id) for rule_id in selected)


def test_candidate_manifest_is_current_and_deterministic() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "generate_candidate_static_materials.py"),
            "--check",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    manifest = _json("manifest.json")
    assert manifest["schema_version"] == 1
    assert manifest["material_set"] == "sastsimi-static-candidate-v1"
    assert manifest["status"] == "CANDIDATE"
    assert manifest["production_ready"] is False
    entries = manifest["files"]
    assert isinstance(entries, list)
    assert [entry["path"] for entry in entries] == sorted(
        path.relative_to(MATERIAL_ROOT).as_posix()
        for path in MATERIAL_ROOT.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    )
    for entry in entries:
        data = (MATERIAL_ROOT / entry["path"]).read_bytes()
        assert entry["size_bytes"] == len(data)
        assert entry["sha256"] == hashlib.sha256(data).hexdigest()
    canonical_entries = json.dumps(
        entries,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert (
        manifest["material_set_sha256"] == hashlib.sha256(canonical_entries).hexdigest()
    )


def test_candidate_catalog_selection_and_mapping_ids_are_exact() -> None:
    opengrep_catalog = _json("opengrep/rule-catalog.json")
    opengrep_selection = _json("opengrep/rule-selection.json")
    opengrep_mapping = _json("opengrep/rule-mapping.json")
    codeql_catalog = _json("codeql/rule-catalog.json")
    codeql_selection = _json("codeql/rule-selection.json")
    codeql_mapping = _json("codeql/rule-mapping.json")

    for document in (
        opengrep_catalog,
        opengrep_selection,
        opengrep_mapping,
        codeql_catalog,
        codeql_selection,
        codeql_mapping,
    ):
        assert document["schema_version"] == 1
        assert document["status"] == "CANDIDATE"
        assert document["production_ready"] is False

    opengrep_rule_ids = _rule_ids(opengrep_catalog)
    assert opengrep_rule_ids == tuple(sorted(opengrep_rule_ids))
    assert _selected_rule_ids(opengrep_selection) == opengrep_rule_ids
    assert _rule_ids(opengrep_mapping) == opengrep_rule_ids

    rules_document = yaml.safe_load(
        (MATERIAL_ROOT / "opengrep" / "rules.yml").read_text(encoding="utf-8")
    )
    native_rule_ids = tuple(sorted(rule["id"] for rule in rules_document["rules"]))
    assert native_rule_ids == opengrep_rule_ids
    assert {
        language for rule in rules_document["rules"] for language in rule["languages"]
    } == {"javascript", "python"}

    codeql_rule_ids = _rule_ids(codeql_catalog)
    assert codeql_rule_ids == tuple(sorted(codeql_rule_ids))
    assert _selected_rule_ids(codeql_selection) == codeql_rule_ids
    assert _rule_ids(codeql_mapping) == codeql_rule_ids

    mappings = codeql_mapping["rules"]
    assert isinstance(mappings, list)
    assert all(
        mapping["result_fact_kind"] == "SINK"
        and mapping["flow_start_fact_kind"] == "SOURCE"
        and mapping["requires_code_flow"] is True
        for mapping in mappings
    )


def test_codeql_wrapper_is_pinned_to_built_in_2_27_0_materials() -> None:
    pack = yaml.safe_load(
        (MATERIAL_ROOT / "codeql" / "qlpack.yml").read_text(encoding="utf-8")
    )
    suite = yaml.safe_load(
        (MATERIAL_ROOT / "codeql" / "python-security.qls").read_text(encoding="utf-8")
    )

    assert pack == {
        "library": False,
        "name": "sastsimi/python-security-candidate",
        "version": "1.0.0",
        "defaultSuiteFile": "python-security.qls",
        "dependencies": {"codeql/python-queries": "1.8.10"},
    }
    assert suite[0]["queries"] == "."
    assert suite[0]["from"] == "codeql/python-queries"
    assert suite[0]["include"]["id"] == list(
        _selected_rule_ids(_json("codeql/rule-selection.json"))
    )


def test_candidate_materials_do_not_encode_evaluation_targets() -> None:
    forbidden = {
        "pygoat",
        "itsdangerous",
        "19d17cc8874861142b330636d068bbde54e86b85",
        "096c8d42545d3b68ea21a4f890fb2b2d8979c0bd",
    }
    combined = "\n".join(
        path.read_text(encoding="utf-8").lower()
        for path in MATERIAL_ROOT.rglob("*")
        if path.is_file()
    )

    assert forbidden.isdisjoint(combined)


# mypy: disable-error-code="import-untyped"
