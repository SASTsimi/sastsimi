"""Deterministic Python security surfaces and conservative review coverage.

The index is a navigation aid, not a vulnerability verdict or a proof that
every security-sensitive operation in the repository has been classified.
Static file/rule gaps stay separate from surfaces so neither can silently
become a negative finding.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Literal, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .ast_facts import index_ast_manifest, read_ast_file_facts
from .candidates import StaticCandidate

SurfaceStatus = Literal["COVERED", "UNCOVERED", "INSUFFICIENT"]
ReviewPart = Literal["ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"]

_REQUIRED_PARTS: frozenset[ReviewPart] = frozenset(
    {"ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"}
)
_RULE_TYPES = {
    "auth-check": "AUTHENTICATION",
    "permission-check": "AUTHORIZATION",
    "request-source": "REQUEST_ENTRY",
    "command-sink": "COMMAND_EXECUTION",
    "html-sink": "HTML_RENDER",
    "http-client-sink": "OUTBOUND_REQUEST",
    "path-sink": "FILE_ACCESS",
    "sql-sink": "SQL_EXECUTION",
    "sanitizer": "SANITIZATION_CONTROL",
    "validator": "VALIDATION_CONTROL",
}


@dataclass(frozen=True, slots=True)
class StaticGap:
    path: str
    rule_id: str
    reason: str
    engine: str = "STATIC"


@dataclass(frozen=True, slots=True)
class AttackSurface:
    surface_id: str
    type: str
    path: str
    symbol: str
    line: int
    linked_candidate_ids: tuple[str, ...]
    evidence_refs: tuple[StoredDataRef, ...]
    detector: str
    flow_identity: str | None = None
    coverage_status: SurfaceStatus = "UNCOVERED"
    review_evidence_refs: tuple[StoredDataRef, ...] = ()

    def to_json(self) -> dict[str, object]:
        return {
            "surface_id": self.surface_id,
            "type": self.type,
            "path": self.path,
            "symbol": self.symbol,
            "line": self.line,
            "linked_candidate_ids": list(self.linked_candidate_ids),
            "evidence_refs": [
                ref.model_dump(mode="json") for ref in self.evidence_refs
            ],
            "detector": self.detector,
            "flow_identity": self.flow_identity,
            "coverage_status": self.coverage_status,
            "review_evidence_refs": [
                ref.model_dump(mode="json") for ref in self.review_evidence_refs
            ],
        }


@dataclass(frozen=True, slots=True)
class SurfaceIndex:
    scope_fingerprint: str
    static_bundle_hash: str
    ast_manifest_hash: str
    workspace_id: str
    commit_id: str
    candidate_inventory_hash: str
    candidate_count: int
    surfaces: tuple[AttackSurface, ...]
    static_gaps: tuple[StaticGap, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_attack_surface_index_v1",
            "scope_fingerprint": self.scope_fingerprint,
            "static_bundle_hash": self.static_bundle_hash,
            "ast_manifest_hash": self.ast_manifest_hash,
            "workspace_id": self.workspace_id,
            "commit_id": self.commit_id,
            "candidate_inventory_hash": self.candidate_inventory_hash,
            "candidate_count": self.candidate_count,
            "surfaces": [surface.to_json() for surface in self.surfaces],
            "static_gaps": [
                {
                    "path": gap.path,
                    "rule_id": gap.rule_id,
                    "reason": gap.reason,
                    "engine": gap.engine,
                }
                for gap in self.static_gaps
            ],
        }


def surface_index_from_json(payload: object) -> SurfaceIndex:
    """Read a persisted index without rebuilding the whole AST on resume."""

    try:
        if (
            not isinstance(payload, dict)
            or payload.get("kind") != "simple_attack_surface_index_v1"
        ):
            raise ValueError

        def required_text(value: object) -> str:
            if not isinstance(value, str) or not value:
                raise ValueError
            return value

        raw_surfaces = payload["surfaces"]
        raw_gaps = payload["static_gaps"]
        count = payload["candidate_count"]
        if not isinstance(raw_surfaces, list) or not isinstance(raw_gaps, list):
            raise ValueError
        if type(count) is not int or count < 0:
            raise ValueError
        surfaces: list[AttackSurface] = []
        for row in raw_surfaces:
            if not isinstance(row, dict):
                raise ValueError
            linked = row["linked_candidate_ids"]
            evidence = row["evidence_refs"]
            review = row["review_evidence_refs"]
            line = row["line"]
            if (
                not isinstance(linked, list)
                or not isinstance(evidence, list)
                or not isinstance(review, list)
                or type(line) is not int
                or line < 1
                or row["coverage_status"] != "UNCOVERED"
                or review
                or row["flow_identity"] is not None
                and not isinstance(row["flow_identity"], str)
            ):
                raise ValueError
            surfaces.append(
                AttackSurface(
                    surface_id=required_text(row["surface_id"]),
                    type=required_text(row["type"]),
                    path=required_text(row["path"]),
                    symbol=required_text(row["symbol"]),
                    line=line,
                    linked_candidate_ids=tuple(required_text(item) for item in linked),
                    evidence_refs=tuple(
                        StoredDataRef.model_validate(item) for item in evidence
                    ),
                    detector=required_text(row["detector"]),
                    flow_identity=row["flow_identity"],
                )
            )
        gaps: list[StaticGap] = []
        for row in raw_gaps:
            if not isinstance(row, dict) or not isinstance(row.get("path"), str):
                raise ValueError
            gaps.append(
                StaticGap(
                    path=row["path"],
                    rule_id=required_text(row["rule_id"]),
                    reason=required_text(row["reason"]),
                    engine=required_text(row["engine"]),
                )
            )
        index = SurfaceIndex(
            scope_fingerprint=required_text(payload["scope_fingerprint"]),
            static_bundle_hash=required_text(payload["static_bundle_hash"]),
            ast_manifest_hash=required_text(payload["ast_manifest_hash"]),
            workspace_id=required_text(payload["workspace_id"]),
            commit_id=required_text(payload["commit_id"]),
            candidate_inventory_hash=required_text(payload["candidate_inventory_hash"]),
            candidate_count=count,
            surfaces=tuple(surfaces),
            static_gaps=tuple(gaps),
        )
        if index.to_json() != payload or len(
            {surface.surface_id for surface in surfaces}
        ) != len(surfaces):
            raise ValueError
        return index
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("SURFACE_INDEX_CHECKPOINT_INVALID") from error


@dataclass(frozen=True, slots=True)
class SurfaceReview:
    """A completed review whose artifact explicitly names the reviewed parts."""

    surface_id: str
    candidate_id: str | None
    hypothesis_id: str | None
    verification_status: Literal["COMPLETE", "PENDING", "ERROR"]
    reviewed_parts: frozenset[ReviewPart]
    evidence_locations: tuple[str, ...]
    evidence_refs: tuple[StoredDataRef, ...]


@dataclass(frozen=True, slots=True)
class SurfaceCoverage:
    scope_fingerprint: str
    static_bundle_hash: str
    ast_manifest_hash: str
    candidate_inventory_hash: str
    candidate_count: int
    surfaces: tuple[AttackSurface, ...]
    static_gaps: tuple[StaticGap, ...]

    @property
    def complete(self) -> bool:
        return not self.static_gaps and all(
            surface.coverage_status == "COVERED" for surface in self.surfaces
        )

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_attack_surface_coverage_v1",
            "scope_fingerprint": self.scope_fingerprint,
            "static_bundle_hash": self.static_bundle_hash,
            "ast_manifest_hash": self.ast_manifest_hash,
            "candidate_inventory_hash": self.candidate_inventory_hash,
            "candidate_count": self.candidate_count,
            "surfaces": [surface.to_json() for surface in self.surfaces],
            "static_gaps": [
                {
                    "path": gap.path,
                    "rule_id": gap.rule_id,
                    "reason": gap.reason,
                    "engine": gap.engine,
                }
                for gap in self.static_gaps
            ],
            "complete": self.complete,
        }


@dataclass(slots=True)
class _Draft:
    path: str
    line: int
    type: str
    symbol: str
    detector: str
    flow_identity: str | None
    candidate_ids: set[str]
    evidence_refs: set[StoredDataRef]


def _ast_call_type(name: str) -> str | None:
    name = name.casefold()
    leaf = name.rsplit(".", 1)[-1]
    if name in {"authenticate", "login_required"} or leaf == "is_authenticated":
        return "AUTHENTICATION"
    if leaf in {
        "authorize",
        "check_permission",
        "has_permission",
        "has_perm",
        "has_perms",
        "permission_required",
    }:
        return "AUTHORIZATION"
    if name in {"os.system", "os.popen"} or name in {
        "subprocess.run",
        "subprocess.call",
        "subprocess.popen",
        "subprocess.check_call",
        "subprocess.check_output",
    }:
        return "COMMAND_EXECUTION"
    if name in {"eval", "exec"}:
        return "DYNAMIC_CODE_EXECUTION"
    if leaf in {"write_text", "write_bytes", "unlink"} or name in {
        "os.remove",
        "os.unlink",
        "shutil.rmtree",
    }:
        return "FILE_WRITE"
    if name == "open" or name.endswith(".open"):
        return "FILE_ACCESS"
    if leaf in {"execute", "executemany", "raw"} and any(
        part in name.split(".")[:-1]
        for part in {"cursor", "connection", "db", "database"}
    ):
        return "SQL_EXECUTION"
    if name in {
        "pickle.load",
        "pickle.loads",
        "yaml.load",
        "marshal.load",
        "marshal.loads",
        "dill.load",
        "dill.loads",
    }:
        return "DESERIALIZATION"
    if name in {"mark_safe", "render_template_string"} or name.endswith(".mark_safe"):
        return "HTML_RENDER"
    if name in {"route", "webhook", "handle_request"} or name.endswith(".route"):
        return "REQUEST_ENTRY"
    if name.startswith(("requests.", "httpx.")) and leaf in {
        "request",
        "get",
        "post",
        "put",
        "patch",
        "delete",
    }:
        return "OUTBOUND_REQUEST"
    return None


def _rule_type(rule_id: str, kind: str) -> str:
    lowered = rule_id.casefold()
    for suffix, surface_type in _RULE_TYPES.items():
        if lowered.endswith("." + suffix):
            return surface_type
    if "sql-injection" in lowered:
        return "SQL_EXECUTION"
    if "command" in lowered and "injection" in lowered:
        return "COMMAND_EXECUTION"
    if "unsafe-deserial" in lowered:
        return "DESERIALIZATION"
    if kind == "ENTRY_POINT":
        return "REQUEST_ENTRY"
    return "DATA_FLOW" if kind == "FLOW" else "STATIC_SECURITY_HINT"


def _coverage_data(
    bundle: Mapping[str, object], artifacts: SimpleArtifactRepository | None
) -> Mapping[str, object]:
    inline = bundle.get("static_coverage")
    if isinstance(inline, dict):
        value = inline
    else:
        if artifacts is None:
            raise ValueError("SURFACE_EVIDENCE_UNAVAILABLE")
        try:
            ref = StoredDataRef.model_validate(bundle["static_coverage_ref"])
            value = json.loads(artifacts.read(ref))
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise ValueError("SURFACE_EVIDENCE_INVALID") from error
    if (
        not isinstance(value, dict)
        or value.get("kind") != "simple_static_coverage_v1"
        or not isinstance(value.get("fingerprint"), str)
        or not value["fingerprint"]
        or not isinstance(value.get("gaps"), list)
    ):
        raise ValueError("SURFACE_EVIDENCE_INVALID")
    return value


def _ast_files(
    summary: Mapping[str, object], artifacts: SimpleArtifactRepository | None
) -> Iterator[tuple[str, tuple[dict[str, object], ...], StoredDataRef | None]]:
    if summary.get("format_version") == 2:
        if artifacts is None:
            raise ValueError("SURFACE_EVIDENCE_UNAVAILABLE")
        try:
            indexed = index_ast_manifest(artifacts, summary)
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise ValueError("SURFACE_EVIDENCE_INVALID") from error
        for path in sorted(indexed):
            try:
                ref, facts, _gap = read_ast_file_facts(
                    artifacts, summary, path, manifest_index=indexed
                )
            except (OSError, KeyError, TypeError, ValueError) as error:
                raise ValueError("SURFACE_EVIDENCE_INVALID") from error
            yield path, facts, ref
        return
    inline_facts = summary.get("facts")
    if not isinstance(inline_facts, list):
        raise ValueError("SURFACE_EVIDENCE_INVALID")
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for fact in inline_facts:
        if not isinstance(fact, dict) or not isinstance(fact.get("path"), str):
            raise ValueError("SURFACE_EVIDENCE_INVALID")
        grouped[fact["path"]].append(fact)
    for path in sorted(grouped):
        yield path, tuple(grouped[path]), None


def _static_gaps(
    coverage: Mapping[str, object], summary: Mapping[str, object]
) -> tuple[StaticGap, ...]:
    result: set[StaticGap] = set()
    rows = coverage.get("gaps")
    assert isinstance(rows, list)
    for row in rows:
        if not isinstance(row, dict) or not all(
            isinstance(row.get(key), str) and row[key]
            for key in ("path", "rule_id", "reason")
        ):
            raise ValueError("SURFACE_EVIDENCE_INVALID")
        result.add(
            StaticGap(
                path=row["path"],
                rule_id=row["rule_id"],
                reason=row["reason"],
            )
        )
    for field_name, reason in (
        ("parse_errors", "AST_PARSE_ERROR"),
        ("oversize_paths", "AST_SOURCE_TOO_LARGE"),
    ):
        paths = summary.get(field_name, [])
        if not isinstance(paths, list):
            raise ValueError("SURFACE_EVIDENCE_INVALID")
        for path in paths:
            if not isinstance(path, str) or not path:
                raise ValueError("SURFACE_EVIDENCE_INVALID")
            result.add(StaticGap(path, "AST", reason, "AST"))
    for row in cast(list[object], coverage.get("unavailable_paths", [])):
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise ValueError("SURFACE_EVIDENCE_INVALID")
        result.add(
            StaticGap(
                path=row["path"],
                rule_id="STATIC",
                reason=str(row.get("reason") or "STATIC_UNAVAILABLE"),
            )
        )
    for field_name in ("unsupported_files", "out_of_scope_product_files"):
        entries = coverage.get(field_name, [])
        if not isinstance(entries, list):
            raise ValueError("SURFACE_EVIDENCE_INVALID")
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("path"), str)
                or not entry["path"]
            ):
                raise ValueError("SURFACE_EVIDENCE_INVALID")
            result.add(
                StaticGap(
                    path=entry["path"],
                    rule_id="STATIC_SCOPE",
                    reason=str(entry.get("reason") or "UNSUPPORTED_PRODUCT_FILE"),
                )
            )
    unsupported = coverage.get("unsupported", [])
    if not isinstance(unsupported, list):
        raise ValueError("SURFACE_EVIDENCE_INVALID")
    for row in unsupported:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("extension"), str)
            or type(row.get("file_count")) is not int
            or row["file_count"] < 0
        ):
            raise ValueError("SURFACE_EVIDENCE_INVALID")
        if row["file_count"]:
            result.add(
                StaticGap(
                    "",
                    "STATIC_SCOPE",
                    f"UNSUPPORTED_EXTENSION:{row['extension']}",
                )
            )
    if coverage.get("unavailable") is True:
        result.add(StaticGap("", "STATIC", "STATIC_UNAVAILABLE"))
    codeql_error = coverage.get("codeql_error")
    if isinstance(codeql_error, str) and codeql_error:
        result.add(StaticGap("", "CODEQL", codeql_error, "CODEQL"))
    expected = coverage.get("expected_count")
    verified = coverage.get("verified_count")
    if type(expected) is int and expected == 0:
        result.add(StaticGap("", "STATIC", "NO_STATIC_RULES"))
    if (
        type(expected) is int
        and type(verified) is int
        and expected > verified
        and not coverage.get("gaps")
    ):
        result.add(StaticGap("", "STATIC", "UNVERIFIED_PAIRS_UNSPECIFIED"))
    return tuple(
        sorted(
            result, key=lambda item: (item.path, item.rule_id, item.reason, item.engine)
        )
    )


def candidate_inventory_hash(candidates: Sequence[StaticCandidate]) -> str:
    """Bind every immutable candidate field, including engine origins, for replay."""

    ordered = sorted(candidates, key=lambda item: item.candidate_id)
    if len({item.candidate_id for item in ordered}) != len(ordered):
        raise ValueError("SURFACE_CANDIDATE_ID_DUPLICATE")
    digest = hashlib.sha256(b"simple_candidate_inventory_v1\n")
    for candidate in ordered:
        projection = candidate.model_dump(
            mode="json",
            exclude={
                "decision",
                "decision_reason",
                "decision_evidence_refs",
                "decision_attempt_ref",
                "deep_status",
            },
        )
        digest.update(canonical_bytes(projection))
        digest.update(b"\n")
    return digest.hexdigest()


def build_attack_surface_index(
    static_bundle: Mapping[str, object],
    ast_manifest: Mapping[str, object],
    candidates: Sequence[StaticCandidate],
    *,
    artifacts: SimpleArtifactRepository | None = None,
) -> SurfaceIndex:
    """Index classified Python operations without treating candidates as reviews."""

    if static_bundle.get("kind") != "simple_static_fact_bundle":
        raise ValueError("SURFACE_STATIC_BUNDLE_INVALID")
    bundled_ast = static_bundle.get("ast_summary")
    if bundled_ast is not None and canonical_bytes(bundled_ast) != canonical_bytes(
        ast_manifest
    ):
        raise ValueError("SURFACE_AST_BUNDLE_MISMATCH")
    workspace_id = static_bundle.get("workspace_id")
    commit_id = static_bundle.get("commit_id")
    if not isinstance(workspace_id, str) or not isinstance(commit_id, str):
        raise ValueError("SURFACE_STATIC_BUNDLE_INVALID")
    coverage = _coverage_data(static_bundle, artifacts)
    scope = cast(str, coverage["fingerprint"])
    bundle_hash = hashlib.sha256(canonical_bytes(static_bundle)).hexdigest()
    manifest_hash = hashlib.sha256(canonical_bytes(ast_manifest)).hexdigest()
    drafts: dict[tuple[str, int, str, str, str | None], _Draft] = {}
    ast_by_location: dict[
        tuple[str, int, str], list[tuple[str, int, str, str, str | None]]
    ] = defaultdict(list)

    for path, facts, file_ref in _ast_files(ast_manifest, artifacts):
        if not path.lower().endswith((".py", ".pyi")):
            continue
        for fact in facts:
            fact_kind, line, name = fact.get("kind"), fact.get("line"), fact.get("name")
            if type(line) is not int or line < 1 or not isinstance(name, str):
                raise ValueError("SURFACE_EVIDENCE_INVALID")
            if fact_kind == "Call":
                surface_type = _ast_call_type(name)
            elif fact_kind in {"FunctionDef", "AsyncFunctionDef"} and name in {
                "route",
                "webhook",
                "handle_request",
            }:
                surface_type = "REQUEST_ENTRY"
            else:
                surface_type = None
            if surface_type is None:
                continue
            key: tuple[str, int, str, str, str | None] = (
                path,
                line,
                surface_type,
                name,
                None,
            )
            if key not in drafts:
                drafts[key] = _Draft(
                    path, line, surface_type, name, "AST", None, set(), set()
                )
                ast_by_location[(path, line, surface_type)].append(key)
            if file_ref is not None:
                drafts[key].evidence_refs.add(file_ref)

    for candidate in sorted(candidates, key=lambda item: item.candidate_id):
        if not candidate.path.lower().endswith((".py", ".pyi")):
            continue
        if (
            str(candidate.evidence_ref.workspace_id) != workspace_id
            or str(candidate.evidence_ref.commit_id) != commit_id
        ):
            raise ValueError("SURFACE_EVIDENCE_SCOPE_MISMATCH")
        for origin in candidate.origins:
            if (
                str(origin.artifact_ref.workspace_id) != workspace_id
                or str(origin.artifact_ref.commit_id) != commit_id
            ):
                raise ValueError("SURFACE_EVIDENCE_SCOPE_MISMATCH")
            surface_type = _rule_type(origin.rule_id, candidate.kind)
            flow = (
                candidate.flow_identity or candidate.evidence_key
                if candidate.kind == "FLOW"
                else None
            )
            matches = ast_by_location.get(
                (candidate.path, candidate.line, surface_type), []
            )
            if flow is None and len(matches) == 1:
                key = matches[0]
            else:
                key = (
                    candidate.path,
                    candidate.line,
                    surface_type,
                    origin.rule_id,
                    flow,
                )
            draft = drafts.get(key)
            if draft is None:
                draft = _Draft(
                    candidate.path,
                    candidate.line,
                    surface_type,
                    origin.rule_id,
                    "STATIC_RULE",
                    flow,
                    set(),
                    set(),
                )
                drafts[key] = draft
            draft.candidate_ids.add(candidate.candidate_id)
            draft.evidence_refs.add(candidate.evidence_ref)
            draft.evidence_refs.add(origin.artifact_ref)

    surfaces: list[AttackSurface] = []
    for key in sorted(drafts, key=lambda item: (*item[:4], item[4] or "")):
        item = drafts[key]
        stable = {
            "version": 1,
            "scope_fingerprint": scope,
            "static_bundle_hash": bundle_hash,
            "path": item.path,
            "line": item.line,
            "type": item.type,
            "symbol": item.symbol,
            "flow_identity": item.flow_identity,
        }
        surface_id = hashlib.sha256(canonical_bytes(stable)).hexdigest()
        surfaces.append(
            AttackSurface(
                surface_id=surface_id,
                type=item.type,
                path=item.path,
                symbol=item.symbol,
                line=item.line,
                linked_candidate_ids=tuple(sorted(item.candidate_ids)),
                evidence_refs=tuple(
                    sorted(item.evidence_refs, key=lambda ref: ref.content_hash)
                ),
                detector=item.detector,
                flow_identity=item.flow_identity,
            )
        )
    return SurfaceIndex(
        scope_fingerprint=scope,
        static_bundle_hash=bundle_hash,
        ast_manifest_hash=manifest_hash,
        workspace_id=workspace_id,
        commit_id=commit_id,
        candidate_inventory_hash=candidate_inventory_hash(candidates),
        candidate_count=len(candidates),
        surfaces=tuple(surfaces),
        static_gaps=_static_gaps(coverage, ast_manifest),
    )


def evaluate_surface_coverage(
    index: SurfaceIndex, reviewed_evidence: Sequence[SurfaceReview]
) -> SurfaceCoverage:
    """Require completed, location-bound review evidence for each surface."""

    by_id: dict[str, list[SurfaceReview]] = defaultdict(list)
    known = {surface.surface_id for surface in index.surfaces}
    for review in reviewed_evidence:
        if review.surface_id not in known:
            raise ValueError("SURFACE_REVIEW_UNKNOWN_ID")
        by_id[review.surface_id].append(review)
    reviewed: list[AttackSurface] = []
    for surface in index.surfaces:
        attempts = by_id.get(surface.surface_id, [])
        status: SurfaceStatus = "UNCOVERED" if not attempts else "INSUFFICIENT"
        expected_location = f"{surface.path}:{surface.line}"
        raw_refs = {ref.content_hash for ref in surface.evidence_refs}
        proof_refs: set[StoredDataRef] = set()
        for review in attempts:
            if (
                review.verification_status == "COMPLETE"
                and _REQUIRED_PARTS <= review.reviewed_parts
                and expected_location in review.evidence_locations
                and review.evidence_refs
                and (
                    review.candidate_id is None
                    or review.candidate_id in surface.linked_candidate_ids
                )
                and all(
                    str(ref.workspace_id) == index.workspace_id
                    and str(ref.commit_id) == index.commit_id
                    and ref.content_hash not in raw_refs
                    for ref in review.evidence_refs
                )
            ):
                status = "COVERED"
                proof_refs.update(review.evidence_refs)
        reviewed.append(
            replace(
                surface,
                coverage_status=status,
                review_evidence_refs=tuple(
                    sorted(proof_refs, key=lambda ref: ref.content_hash)
                ),
            )
        )
    return SurfaceCoverage(
        scope_fingerprint=index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=index.candidate_inventory_hash,
        candidate_count=index.candidate_count,
        surfaces=tuple(reviewed),
        static_gaps=index.static_gaps,
    )
