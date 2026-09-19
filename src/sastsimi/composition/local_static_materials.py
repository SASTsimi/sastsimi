"""Load the immutable candidate static materials for local evaluation only."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Literal, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.orchestration.static_adapter_context import ApprovedStaticRuleClosure
from sastsimi.ports.dto import StaticRuleMapping
from sastsimi.static_analysis.codeql_adapter import digest_path

type LocalStaticTool = Literal["AST", "OPENGREP", "CODEQL"]


@dataclass(frozen=True, slots=True)
class LocalStaticMaterialSet:
    """Runtime-ready evidence derived from one exact CANDIDATE manifest."""

    enabled_tools: tuple[LocalStaticTool, ...]
    analysis_config_sha256: str
    codeql_query_pack_sha256: str
    evidence: MappingProxyType[str, bytes]
    route_digests: MappingProxyType[str, tuple[str, ...]]
    rule_closures: MappingProxyType[str, ApprovedStaticRuleClosure]


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json(path: Path, code: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError(code) from None
    if not isinstance(value, dict):
        raise ValueError(code)
    return cast(dict[str, object], value)


def _safe_relative(value: object) -> str:
    if not isinstance(value, str) or "\\" in value:
        raise ValueError("LOCAL_STATIC_MATERIAL_MANIFEST_INVALID")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("LOCAL_STATIC_MATERIAL_MANIFEST_INVALID")
    return path.as_posix()


def _verified_files(root: Path) -> dict[str, bytes]:
    manifest = _json(root / "manifest.json", "LOCAL_STATIC_MATERIAL_MANIFEST_INVALID")
    entries = manifest.get("files")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("material_set") != "sastsimi-static-candidate-v1"
        or manifest.get("status") != "CANDIDATE"
        or manifest.get("production_ready") is not False
        or not isinstance(entries, list)
    ):
        raise ValueError("LOCAL_STATIC_MATERIAL_MANIFEST_INVALID")
    expected_paths = tuple(
        sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and path.name != "manifest.json"
        )
    )
    payloads: dict[str, bytes] = {}
    normalized_entries: list[dict[str, object]] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "sha256",
            "size_bytes",
        }:
            raise ValueError("LOCAL_STATIC_MATERIAL_MANIFEST_INVALID")
        relative = _safe_relative(entry["path"])
        target = root.joinpath(*PurePosixPath(relative).parts)
        try:
            resolved = target.resolve(strict=True)
            resolved.relative_to(root)
            if target.is_symlink() or not resolved.is_file():
                raise OSError
            payload = resolved.read_bytes()
        except (OSError, ValueError):
            raise ValueError("LOCAL_STATIC_MATERIAL_STALE") from None
        digest = _digest(payload)
        if (
            entry["sha256"] != digest
            or entry["size_bytes"] != len(payload)
            or relative in payloads
        ):
            raise ValueError("LOCAL_STATIC_MATERIAL_STALE")
        payloads[relative] = payload
        normalized_entries.append(
            {"path": relative, "sha256": digest, "size_bytes": len(payload)}
        )
    if tuple(payloads) != expected_paths or manifest.get(
        "material_set_sha256"
    ) != _digest(canonical_bytes(normalized_entries)):
        raise ValueError("LOCAL_STATIC_MATERIAL_STALE")
    return payloads


def _rule_material(
    payloads: dict[str, bytes], tool: Literal["opengrep", "codeql"]
) -> tuple[bytes, bytes, bytes, ApprovedStaticRuleClosure]:
    documents: list[dict[str, object]] = []
    for name in ("rule-catalog.json", "rule-selection.json", "rule-mapping.json"):
        try:
            value = json.loads(payloads[f"{tool}/{name}"])
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("LOCAL_STATIC_RULE_MATERIAL_INVALID") from None
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != 1
            or value.get("status") != "CANDIDATE"
            or value.get("production_ready") is not False
        ):
            raise ValueError("LOCAL_STATIC_RULE_MATERIAL_INVALID")
        documents.append(cast(dict[str, object], value))
    catalog, selection, mapping = documents
    catalog_rules = catalog.get("rules")
    selected_ids = selection.get("selected_rule_ids")
    selected_packs = selection.get("selected_rule_packs")
    mapping_rules = mapping.get("rules")
    if (
        not isinstance(catalog_rules, list)
        or not isinstance(selected_ids, list)
        or not isinstance(selected_packs, list)
        or not isinstance(mapping_rules, list)
    ):
        raise ValueError("LOCAL_STATIC_RULE_MATERIAL_INVALID")
    try:
        catalog_ids = tuple(str(item["rule_id"]) for item in catalog_rules)
        selections = tuple(str(item) for item in selected_ids)
        packs = tuple(str(item) for item in selected_packs)
        mappings = tuple(_mapping(item) for item in mapping_rules)
    except (KeyError, TypeError, ValueError):
        raise ValueError("LOCAL_STATIC_RULE_MATERIAL_INVALID") from None
    mapping_ids = tuple(item.rule_id for item in mappings)
    if (
        not catalog_ids
        or catalog_ids != tuple(sorted(set(catalog_ids)))
        or selections != catalog_ids
        or mapping_ids != catalog_ids
        or not packs
        or len(packs) != len(set(packs))
    ):
        raise ValueError("LOCAL_STATIC_RULE_MATERIAL_INVALID")
    catalog_bytes = canonical_bytes(
        {"schema_version": 1, "rule_ids": list(catalog_ids)}
    )
    selection_bytes = canonical_bytes(
        {
            "schema_version": 1,
            "rule_ids": list(selections),
            "rule_packs": list(packs),
        }
    )
    mapping_bytes = canonical_bytes(
        {
            "schema_version": 1,
            "mappings": [asdict(item) for item in mappings],
        }
    )
    closure = ApprovedStaticRuleClosure(
        catalog_sha256=_digest(catalog_bytes),
        selection_sha256=_digest(selection_bytes),
        mapping_sha256=_digest(mapping_bytes),
        catalog_rule_ids=catalog_ids,
        selected_rule_ids=selections,
        mappings=mappings,
    )
    return catalog_bytes, selection_bytes, mapping_bytes, closure


def _mapping(value: object) -> StaticRuleMapping:
    if not isinstance(value, dict) or set(value) != {
        "rule_id",
        "result_fact_kind",
        "flow_start_fact_kind",
        "requires_code_flow",
    }:
        raise ValueError("LOCAL_STATIC_RULE_MATERIAL_INVALID")
    rule_id = value["rule_id"]
    result = value["result_fact_kind"]
    flow_start = value["flow_start_fact_kind"]
    code_flow = value["requires_code_flow"]
    if (
        not isinstance(rule_id, str)
        or not rule_id
        or not isinstance(result, str)
        or not result
        or (flow_start is not None and not isinstance(flow_start, str))
        or not isinstance(code_flow, bool)
    ):
        raise ValueError("LOCAL_STATIC_RULE_MATERIAL_INVALID")
    return StaticRuleMapping(rule_id, result, flow_start, code_flow)


def load_local_candidate_static_materials(root: Path) -> LocalStaticMaterialSet:
    """Verify and translate CANDIDATE files without claiming Production approval."""

    try:
        root = root.resolve(strict=True)
    except OSError:
        raise ValueError("LOCAL_STATIC_MATERIAL_ROOT_INVALID") from None
    if not root.is_dir() or root.is_symlink():
        raise ValueError("LOCAL_STATIC_MATERIAL_ROOT_INVALID")
    payloads = _verified_files(root)
    opengrep = _rule_material(payloads, "opengrep")
    codeql = _rule_material(payloads, "codeql")
    query_root = root / "codeql"
    query_digest = digest_path(query_root)
    try:
        opengrep_rules = payloads["opengrep/rules.yml"]
        qlpack = payloads["codeql/qlpack.yml"]
        suite = payloads["codeql/python-security.qls"]
    except KeyError:
        raise ValueError("LOCAL_STATIC_MATERIAL_MANIFEST_INVALID") from None
    native: dict[str, bytes] = {
        _digest(opengrep_rules): opengrep_rules,
        _digest(qlpack): qlpack,
        _digest(suite): suite,
    }
    manifest_bytes = canonical_bytes(
        {
            "schema_version": 1,
            "tools": {
                "OPENGREP": {"config_sha256": _digest(opengrep_rules)},
                "CODEQL": {
                    "query_pack_sha256": query_digest,
                    "files": [
                        {"path": "python-security.qls", "sha256": _digest(suite)},
                        {"path": "qlpack.yml", "sha256": _digest(qlpack)},
                    ],
                },
            },
        }
    )
    analysis_digest = _digest(manifest_bytes)
    evidence: dict[str, bytes] = {analysis_digest: manifest_bytes, **native}
    route_digests: dict[str, tuple[str, ...]] = {"AST": (analysis_digest,)}
    closures: dict[str, ApprovedStaticRuleClosure] = {}
    for name, built in (("OPENGREP", opengrep), ("CODEQL", codeql)):
        catalog_bytes, selection_bytes, mapping_bytes, closure = built
        for payload in (catalog_bytes, selection_bytes, mapping_bytes):
            evidence[_digest(payload)] = payload
        route_digests[name] = (
            analysis_digest,
            closure.catalog_sha256,
            closure.selection_sha256,
            closure.mapping_sha256,
        )
        closures[name] = closure
    return LocalStaticMaterialSet(
        enabled_tools=("AST", "OPENGREP", "CODEQL"),
        analysis_config_sha256=analysis_digest,
        codeql_query_pack_sha256=query_digest,
        evidence=MappingProxyType(evidence),
        route_digests=MappingProxyType(route_digests),
        rule_closures=MappingProxyType(closures),
    )


__all__ = ["LocalStaticMaterialSet", "load_local_candidate_static_materials"]
