"""Compare a pinned, external vulnerability oracle with saved analysis state."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import Counter
from collections.abc import Mapping
from contextlib import AbstractContextManager, closing, nullcontext
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Literal, TypedDict
from urllib.parse import urlsplit

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import (
    index_ast_manifest,
    validate_ast_manifest,
)
from sastsimi.simple_runtime.attack_surfaces import (
    StaticGap,
    SurfaceCoverage,
    candidate_inventory_hash,
    surface_index_from_json,
)
from sastsimi.simple_runtime.candidates import StaticCandidate
from sastsimi.simple_runtime.chaining import (
    SimpleChainingStage,
    validated_chaining_children,
)
from sastsimi.simple_runtime.finding_group_projection import _verified_closure
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    STAGE_ORDER,
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
    terminal_gate_outcome,
)


@dataclass(frozen=True, slots=True)
class OracleCase:
    case_id: str
    cwe: str
    path: str
    source_line: int | None
    sink_line: int
    rationale: str
    # IDs are checked by a human against pinned source/PoC after the run. A
    # matching line alone is never proof that two vulnerability paths coincide.
    vetted_candidate_ids: tuple[str, ...] = ()
    vetted_hypothesis_ids: tuple[str, ...] = ()
    finding_inventory_reviewed: bool = False
    kind: Literal["FLOW", "MISSING_GUARD", "CONFIGURATION"] = "FLOW"
    sink_path: str | None = None
    scope: Literal["PYTHON", "OUT_OF_SCOPE"] = "PYTHON"


@dataclass(frozen=True, slots=True)
class Oracle:
    repository: str
    commit: str
    cases: tuple[OracleCase, ...]
    version: Literal[1, 2] = 1
    completeness: Literal["UNDECLARED", "DOCUMENTED_CASES", "EXHAUSTIVE_PYTHON"] = (
        "UNDECLARED"
    )


class AuditCaseResult(TypedDict):
    case_id: str
    status: str
    first_gap: str | None
    candidate_ids: list[str]
    vetted_candidate_ids: list[str]
    decisions: dict[str, str]
    deep_states: dict[str, str]
    hypothesis_ids: list[str]
    vetted_hypothesis_ids: list[str]
    finding_inventory_reviewed: bool


class AuditResult(TypedDict):
    analysis_id: str
    oracle_commit: str
    analysis_complete: bool
    cases: list[AuditCaseResult]
    counts: dict[str, int]


def repository_targets_match(oracle_repository: str, run_repository: str) -> bool:
    """Treat only a trailing GitHub HTTPS ``.git`` suffix as equivalent."""

    if oracle_repository == run_repository:
        return True

    def github_target(value: str) -> str | None:
        try:
            parsed = urlsplit(value)
        except ValueError:
            return None
        if (
            parsed.scheme != "https"
            or parsed.netloc != "github.com"
            or parsed.query
            or parsed.fragment
        ):
            return None
        parts = parsed.path.split("/")
        if len(parts) != 3 or parts[0] or not parts[1] or not parts[2]:
            return None
        repository = parts[2].removesuffix(".git")
        if not repository:
            return None
        return f"{parts[1]}/{repository}"

    left = github_target(oracle_repository)
    return left is not None and left == github_target(run_repository)


def _analysis_run(
    connection: sqlite3.Connection, analysis_id: str
) -> SimpleAnalysisRun:
    row = connection.execute(
        "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
        (analysis_id,),
    ).fetchone()
    if row is None:
        raise ValueError("RECALL_ANALYSIS_NOT_FOUND")
    return SimpleAnalysisRun.model_validate_json(row[0])


def _static_product_paths(
    connection: sqlite3.Connection, data_dir: Path, run: SimpleAnalysisRun
) -> tuple[frozenset[str], frozenset[StaticGap]] | None:
    """Require exact, hash-verified full static evidence before measuring a miss."""

    bundle_ref = run.static_bundle_ref
    coverage_ref = run.static_coverage_ref
    scope = run.candidate_scope_fingerprint
    if not scope or bundle_ref is None or coverage_ref is None:
        return None
    rows = connection.execute(
        "SELECT checkpoint_json FROM simple_runtime_checkpoints "
        "WHERE analysis_id = ? AND stage = ?",
        (run.analysis_id, SimpleStage.STATIC_DONE.value),
    ).fetchall()
    if len(rows) != 1:
        return None
    checkpoint = StageCheckpoint.model_validate_json(rows[0][0])
    if (
        checkpoint.identity
        != CheckpointIdentity(
            analysis_id=run.analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=None,
        )
        or checkpoint.status is not StageStatus.SUCCEEDED
        or checkpoint.stage_version != STAGE_VERSION[SimpleStage.STATIC_DONE]
        or len(checkpoint.output_refs) < 2
        or checkpoint.output_refs[1] != bundle_ref
    ):
        return None
    paths = RuntimePaths(data_dir)
    if not all(
        value.is_dir()
        for value in (paths.staging, paths.artifacts / "sha256", paths.quarantine)
    ):
        return None
    artifacts = SimpleArtifactRepository(
        data_dir, checkpoint.identity, create_dirs=False
    )
    try:
        bundle = json.loads(artifacts.read_bounded(bundle_ref, 16 * 1024 * 1024))
        if not isinstance(bundle, dict):
            return None
        if any(
            bundle.get(key) != expected
            for key, expected in (
                ("kind", "simple_static_fact_bundle"),
                ("analysis_id", run.analysis_id),
                ("workspace_id", run.workspace_id),
                ("commit_id", run.commit_id),
            )
        ):
            return None
        if (
            StoredDataRef.model_validate(bundle.get("static_coverage_ref"))
            != coverage_ref
        ):
            return None
        manifest_ref = StoredDataRef.model_validate(bundle.get("source_manifest_ref"))
        manifest = json.loads(artifacts.read_bounded(manifest_ref, 16 * 1024 * 1024))
        coverage = json.loads(artifacts.read_bounded(coverage_ref, 16 * 1024 * 1024))
    except (OSError, ValueError, TypeError, UnicodeError, KeyError):
        return None
    if (
        not isinstance(manifest, dict)
        or manifest.get("kind") != "simple_tracked_sources"
    ):
        return None
    selected = manifest.get("paths")
    if (
        not isinstance(selected, list)
        or not selected
        or any(
            not isinstance(item, str)
            or Path(item).suffix.lower() not in {".py", ".pyi"}
            for item in selected
        )
        or len(set(selected)) != len(selected)
        or not isinstance(coverage, dict)
        or coverage.get("kind") != "simple_static_coverage_v1"
        or coverage.get("fingerprint") != scope
        or any(
            coverage.get(key) != expected
            for key, expected in (
                ("analysis_id", run.analysis_id),
                ("workspace_id", run.workspace_id),
                ("commit_id", run.commit_id),
            )
        )
    ):
        return None
    expected = coverage.get("expected_count")
    verified = coverage.get("verified_count")
    limitation_lists = (
        "gaps",
        "unsupported",
        "unsupported_files",
        "unavailable_paths",
        "ast_parse_errors",
        "ast_oversize_paths",
        "engine_errors",
    )
    out_of_scope = coverage.get("out_of_scope_product_files")
    if not isinstance(out_of_scope, list) or any(
        not isinstance(item, dict)
        or not isinstance(item.get("path"), str)
        or not item["path"]
        or not isinstance(item.get("reason"), str)
        or not item["reason"]
        or item["path"] in selected
        or PurePosixPath(item["path"]).is_absolute()
        or "\\" in item["path"]
        or ":" in item["path"]
        or ".." in PurePosixPath(item["path"]).parts
        or Path(item["path"]).suffix.lower() == ".py"
        or (
            Path(item["path"]).suffix.lower() == ".pyi"
            and item["reason"]
            not in {
                "python_stub_not_scanned",
                "declared_non_python_entry",
            }
        )
        for item in out_of_scope
    ):
        return None
    if out_of_scope:
        try:
            poc_manifest_ref = StoredDataRef.model_validate(
                bundle.get("poc_source_manifest_ref")
            )
            poc_manifest = json.loads(
                artifacts.read_bounded(poc_manifest_ref, 16 * 1024 * 1024)
            )
        except (OSError, ValueError, TypeError, UnicodeError, KeyError):
            return None
        if (
            not isinstance(poc_manifest, dict)
            or poc_manifest.get("kind") != "simple_tracked_sources"
            or not isinstance(poc_manifest.get("paths"), list)
        ):
            return None
        poc_paths = poc_manifest["paths"]
        if (
            any(not isinstance(item, str) or not item for item in poc_paths)
            or len(set(poc_paths)) != len(poc_paths)
            or not set(selected).issubset(poc_paths)
            or any(item["path"] not in poc_paths for item in out_of_scope)
        ):
            return None
    if (
        type(expected) is not int
        or type(verified) is not int
        or expected <= 0
        or verified != expected
        or any(not isinstance(coverage.get(key), list) for key in limitation_lists)
        or any(coverage.get(key) for key in limitation_lists)
        or (
            coverage.get("unavailable") is not None
            and coverage.get("unavailable") is not False
        )
        or coverage.get("codeql_error")
        or any(
            type(coverage.get(key, 0)) is not int or coverage.get(key, 0) != 0
            for key in ("ast_parse_error_count", "ast_oversize_count")
        )
        or coverage.get("ast_truncated") is not False
        or (
            coverage.get("codeql_configured") is True
            and coverage.get("codeql_executed") is not True
        )
    ):
        return None
    if run.static_disposition == "PARTIAL" and not out_of_scope:
        return None
    out_of_scope_gaps = frozenset(
        StaticGap(item["path"], "STATIC_SCOPE", item["reason"]) for item in out_of_scope
    )
    if len(out_of_scope_gaps) != len(out_of_scope):
        return None
    return frozenset(selected), out_of_scope_gaps


def _pipeline_complete(
    run: SimpleAnalysisRun, *, python_scope_complete: bool, nonpython_out_of_scope: bool
) -> bool:
    terminal = run.candidate_terminal
    return bool(
        terminal is not None
        and (
            terminal.status == "COMPLETE"
            or (
                terminal.status == "PARTIAL"
                and python_scope_complete
                and nonpython_out_of_scope
            )
        )
        and terminal.producer_finished
        and terminal.pending_child_count == 0
        and terminal.scope_fingerprint == run.candidate_scope_fingerprint
        and run.static_bundle_ref is not None
        and terminal.bundle_hash == run.static_bundle_ref.content_hash
        and not any(
            terminal.decision_counts.get(key, 0) for key in ("PENDING", "ERROR")
        )
        and not any(
            terminal.deep_counts.get(key, 0) for key in ("PENDING", "RUNNING", "ERROR")
        )
        and not any(
            terminal.surface_counts.get(key, 0) for key in ("UNCOVERED", "INSUFFICIENT")
        )
    )


def _root_hypothesis_current(
    connection: sqlite3.Connection, data_dir: Path, run: SimpleAnalysisRun
) -> bool:
    """Do not trust a terminal marker after its root provenance was rejected."""

    if run.static_bundle_ref is None:
        return False
    rows = connection.execute(
        "SELECT checkpoint_json FROM simple_runtime_checkpoints "
        "WHERE analysis_id = ? AND hypothesis_key = '' AND stage = ?",
        (run.analysis_id, SimpleStage.HYPOTHESIS_DONE.value),
    ).fetchall()
    if len(rows) != 1:
        return False
    checkpoint = StageCheckpoint.model_validate_json(rows[0][0])
    if (
        checkpoint.identity
        != CheckpointIdentity(
            analysis_id=run.analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=None,
        )
        or checkpoint.status is not StageStatus.SUCCEEDED
        or checkpoint.stage_version != STAGE_VERSION[SimpleStage.HYPOTHESIS_DONE]
        or run.static_bundle_ref not in checkpoint.input_refs
        or not checkpoint.output_refs
    ):
        return False
    paths = RuntimePaths(data_dir)
    if not all(
        value.is_dir()
        for value in (paths.staging, paths.artifacts / "sha256", paths.quarantine)
    ):
        return False
    artifacts = SimpleArtifactRepository(
        data_dir, checkpoint.identity, create_dirs=False
    )
    try:
        for ref in checkpoint.output_refs:
            artifacts.read_bounded(ref, 128 * 1024 * 1024)
    except (OSError, ValueError, TypeError, UnicodeError):
        return False
    return True


def strict_terminal_proof(
    connection: sqlite3.Connection, data_dir: Path, run: SimpleAnalysisRun
) -> bool:
    """Prove that a claimed Python terminal covers its current durable inputs.

    An absent or still-running terminal is unfinished. A finished marker whose
    saved evidence disagrees with the marker is invalid, not a measured miss.
    This function only reads the caller's SQLite snapshot and CAS artifacts.
    """

    terminal = run.candidate_terminal
    if (
        terminal is None
        or not terminal.producer_finished
        or terminal.pending_child_count
    ):
        return False
    try:
        return _strict_terminal_proof(connection, data_dir, run)
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        UnicodeError,
        sqlite3.Error,
    ) as error:
        raise ValueError("RECALL_REVIEW_TERMINAL_EVIDENCE_INVALID") from error


def _verified_terminal_decision(
    artifacts: SimpleArtifactRepository,
    checkpoint: StageCheckpoint | None,
    verified_refs: set[StoredDataRef],
    *,
    kind: str,
    result_field: str,
    expected: str,
) -> bool:
    """A terminal verdict is not evidence without its same-attempt CAS result."""

    if (
        checkpoint is None
        or not checkpoint.attempt_id
        or len(checkpoint.output_refs) != 1
        or checkpoint.input_hash != input_reference_hash(checkpoint.input_refs)
    ):
        return False
    payload = json.loads(artifacts.read_bounded(checkpoint.output_refs[0], 1024 * 1024))
    result = payload.get("result") if isinstance(payload, dict) else None
    sources = payload.get("source_refs") if isinstance(payload, dict) else None
    if not isinstance(sources, list):
        return False
    source_refs = tuple(StoredDataRef.model_validate(value) for value in sources)
    if not set(checkpoint.input_refs).issubset(source_refs):
        return False
    for ref in source_refs:
        if ref in verified_refs:
            continue
        if ref.record_id is None:
            artifacts.read_bounded(ref, 128 * 1024 * 1024)
        else:
            artifacts.read(ref)
        verified_refs.add(ref)
    return (
        isinstance(payload, dict)
        and payload.get("kind") == kind
        and payload.get("attempt_id") == checkpoint.attempt_id
        and isinstance(result, dict)
        and result.get(result_field) == expected
    )


def _verified_terminal_chain(
    artifacts: SimpleArtifactRepository, checkpoint: StageCheckpoint | None
) -> tuple[StoredDataRef, ...] | None:
    if (
        checkpoint is None
        or len(checkpoint.output_refs) != 1
        or checkpoint.input_hash != input_reference_hash(checkpoint.input_refs)
    ):
        return None
    payload = json.loads(
        artifacts.read_bounded(checkpoint.output_refs[0], 16 * 1024 * 1024)
    )
    if not isinstance(payload, dict):
        return None
    parents = payload.get("considered_primitive_refs")
    children = payload.get("children")
    if (
        payload.get("kind") != "simple_chaining_result"
        or payload.get("analysis_id") != checkpoint.identity.analysis_id
        or payload.get("source_hypothesis_id") != checkpoint.identity.hypothesis_id
        or not isinstance(parents, list)
        or not isinstance(children, list)
        or not all(isinstance(child, dict) for child in children)
        or payload.get("status")
        != ("MATERIAL_CHILD" if children else "NO_MATERIAL_CHILD")
    ):
        return None
    considered = tuple(StoredDataRef.model_validate(value) for value in parents)
    if len(set(considered)) != len(considered):
        return None
    for ref in checkpoint.input_refs:
        if ref.record_id is None:
            artifacts.read_bounded(ref, 128 * 1024 * 1024)
        else:
            artifacts.read(ref)
    validated = validated_chaining_children(artifacts, considered, children)
    if canonical_bytes(validated) != canonical_bytes(children):
        return None
    return considered


def _strict_terminal_proof(
    connection: sqlite3.Connection, data_dir: Path, run: SimpleAnalysisRun
) -> bool:
    terminal = run.candidate_terminal
    assert terminal is not None
    bundle = run.static_bundle_ref
    scope = run.candidate_scope_fingerprint
    if (
        bundle is None
        or not scope
        or terminal.bundle_hash != bundle.content_hash
        or terminal.scope_fingerprint != scope
        or terminal.surface_index_hash is None
        or terminal.surface_coverage_hash is None
        or terminal.chaining_pool_fingerprint is None
        or terminal.chaining_batch_count is None
    ):
        raise ValueError("terminal marker lacks current input hashes")
    identity = CheckpointIdentity(
        analysis_id=run.analysis_id,
        workspace_id=run.workspace_id,
        commit_id=run.commit_id,
        hypothesis_id=None,
    )
    rows = connection.execute(
        "SELECT checkpoint_json FROM simple_runtime_checkpoints "
        "WHERE analysis_id = ? AND hypothesis_key = '' AND stage = ?",
        (run.analysis_id, SimpleStage.HYPOTHESIS_DONE.value),
    ).fetchall()
    if len(rows) != 1:
        raise ValueError("root hypothesis checkpoint missing")
    checkpoint = StageCheckpoint.model_validate_json(rows[0][0])
    if (
        checkpoint.identity != identity
        or checkpoint.stage is not SimpleStage.HYPOTHESIS_DONE
        or checkpoint.stage_version != STAGE_VERSION[SimpleStage.HYPOTHESIS_DONE]
        or checkpoint.status is not StageStatus.SUCCEEDED
        or bundle not in checkpoint.input_refs
        or len(checkpoint.output_refs) != 2
        or checkpoint.output_refs[0].content_hash != terminal.surface_index_hash
        or checkpoint.output_refs[1].content_hash != terminal.surface_coverage_hash
    ):
        raise ValueError("terminal surface refs differ from root checkpoint")

    artifacts = SimpleArtifactRepository(data_dir, identity, create_dirs=False)
    index_payload = json.loads(
        artifacts.read_bounded(checkpoint.output_refs[0], 128 * 1024 * 1024)
    )
    coverage_payload = json.loads(
        artifacts.read_bounded(checkpoint.output_refs[1], 128 * 1024 * 1024)
    )
    index = surface_index_from_json(index_payload)
    if (
        index.scope_fingerprint != scope
        or index.static_bundle_hash != bundle.content_hash
        or index.workspace_id != run.workspace_id
        or index.commit_id != run.commit_id
    ):
        raise ValueError("surface index scope differs from run")
    static_bundle = json.loads(artifacts.read_bounded(bundle, 16 * 1024 * 1024))
    ast_summary = (
        static_bundle.get("ast_summary") if isinstance(static_bundle, dict) else None
    )
    if (
        not isinstance(ast_summary, dict)
        or index.ast_manifest_hash
        != hashlib.sha256(canonical_bytes(ast_summary)).hexdigest()
        or index.index_version != (2 if ast_summary.get("format_version") == 3 else 1)
    ):
        raise ValueError("surface index AST summary differs from static bundle")
    validate_ast_manifest(artifacts, ast_summary)
    if index.index_version == 2:
        manifest = index_ast_manifest(artifacts, ast_summary)
        expected_source_hashes = tuple(
            (path, str(entry["source_sha256"]))
            for path, entry in sorted(manifest.items())
        )
        if index.ast_source_hashes != expected_source_hashes:
            raise ValueError("surface index AST source hashes differ from manifest")

    candidates: list[StaticCandidate] = []
    decisions: Counter[str] = Counter()
    deep: Counter[str] = Counter()
    cursor = connection.execute(
        "SELECT candidate_id, candidate_json, decision, deep_status "
        "FROM simple_static_candidates WHERE analysis_id = ? AND workspace_id = ? "
        "AND commit_id = ? AND scope_fingerprint = ? ORDER BY candidate_id",
        (run.analysis_id, run.workspace_id, run.commit_id, scope),
    )
    while page := cursor.fetchmany(500):
        for candidate_id, candidate_json, decision, deep_status in page:
            candidate = StaticCandidate.model_validate_json(candidate_json)
            if candidate.candidate_id != candidate_id:
                raise ValueError("candidate ledger ID differs from candidate")
            candidates.append(candidate)
            decisions[str(decision)] += 1
            if decision in {"INCLUDE", "UNDECIDED"}:
                deep[str(deep_status)] += 1
    if (
        index.candidate_count != len(candidates)
        or index.candidate_inventory_hash != candidate_inventory_hash(candidates)
        or dict(decisions)
        != {key: count for key, count in terminal.decision_counts.items() if count}
        or dict(deep)
        != {key: count for key, count in terminal.deep_counts.items() if count}
    ):
        raise ValueError("candidate inventory or counts differ from terminal")

    if not isinstance(coverage_payload, dict):
        raise ValueError("surface coverage is not an object")
    surface_rows = coverage_payload.get("surfaces")
    if not isinstance(surface_rows, list) or len(surface_rows) != len(index.surfaces):
        raise ValueError("surface coverage does not match index")
    covered_surfaces = []
    for source, row in zip(index.surfaces, surface_rows, strict=True):
        if not isinstance(row, dict) or row.get("coverage_status") not in {
            "COVERED",
            "UNCOVERED",
            "INSUFFICIENT",
        }:
            raise ValueError("surface coverage status invalid")
        raw_refs = row.get("review_evidence_refs")
        if not isinstance(raw_refs, list):
            raise ValueError("surface review refs invalid")
        review_refs = tuple(StoredDataRef.model_validate(value) for value in raw_refs)
        if row["coverage_status"] == "COVERED" and not review_refs:
            raise ValueError("covered surface lacks review evidence")
        if row["coverage_status"] != "COVERED" and review_refs:
            raise ValueError("uncovered surface claims review evidence")
        for ref in source.evidence_refs + review_refs:
            artifacts.read_bounded(ref, 128 * 1024 * 1024)
        covered_surfaces.append(
            replace(
                source,
                coverage_status=row["coverage_status"],
                review_evidence_refs=review_refs,
            )
        )
    coverage = SurfaceCoverage(
        scope_fingerprint=index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=index.candidate_inventory_hash,
        candidate_count=index.candidate_count,
        surfaces=tuple(covered_surfaces),
        static_gaps=index.static_gaps,
    )
    counts = {
        status: sum(item.coverage_status == status for item in coverage.surfaces)
        for status in ("COVERED", "UNCOVERED", "INSUFFICIENT")
    }
    if coverage_payload != coverage.to_json() or terminal.surface_counts != counts:
        raise ValueError("surface coverage or counts differ from index")
    if terminal.status == "COMPLETE" and (
        run.static_disposition != "FULL" or not coverage.complete
    ):
        raise ValueError("complete terminal has uncovered surfaces or static gaps")

    hypothesis_ids = {
        row[0]
        for row in connection.execute(
            "SELECT hypothesis_id FROM simple_candidate_hypotheses "
            "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ?",
            (run.analysis_id, run.workspace_id, run.commit_id),
        )
    }
    if terminal.hypothesis_count != len(hypothesis_ids):
        raise ValueError("terminal hypothesis count differs from ledger")
    poc_index = STAGE_ORDER.index(SimpleStage.POC_EXECUTION_DONE)
    terminal_chains: list[tuple[StoredDataRef, ...]] = []
    verified_source_refs: set[StoredDataRef] = set()
    for hypothesis_id in hypothesis_ids:
        child_identity = identity.model_copy(update={"hypothesis_id": hypothesis_id})
        child_artifacts = SimpleArtifactRepository(
            data_dir, child_identity, create_dirs=False
        )
        stages: dict[SimpleStage, StageCheckpoint] = {}
        stale_stage = False
        stale_poc_or_downstream = False
        for stage_value, raw in connection.execute(
            "SELECT stage, checkpoint_json FROM simple_runtime_checkpoints "
            "WHERE analysis_id = ? AND hypothesis_key = ?",
            (run.analysis_id, hypothesis_id),
        ):
            child_checkpoint = StageCheckpoint.model_validate_json(raw)
            if (
                child_checkpoint.identity != child_identity
                or child_checkpoint.stage.value != stage_value
            ):
                raise ValueError("terminal hypothesis checkpoint identity differs")
            if (
                child_checkpoint.stage in HYPOTHESIS_STAGES
                and child_checkpoint.stage_version
                != STAGE_VERSION[child_checkpoint.stage]
            ):
                stale_stage = True
                if STAGE_ORDER.index(child_checkpoint.stage) >= poc_index:
                    stale_poc_or_downstream = True
            if (
                child_checkpoint.status is StageStatus.SUCCEEDED
                and child_checkpoint.stage_version
                == STAGE_VERSION[child_checkpoint.stage]
            ):
                stages[child_checkpoint.stage] = child_checkpoint
        terminal_poc = (
            child_artifacts.verified_terminal_poc_outcome(
                stages.get(SimpleStage.POC_EXECUTION_DONE)
            )
            is not None
        )
        if stale_stage and not (terminal_poc and not stale_poc_or_downstream):
            raise ValueError("terminal hypothesis has stale stage")
        final = stages.get(SimpleStage.VERIFICATION_FINAL_DONE)
        chain = stages.get(SimpleStage.CHAINING_DONE)
        gate = stages.get(SimpleStage.TECH_GATE_DONE)
        finding = stages.get(SimpleStage.FINDING_DONE)
        report = stages.get(SimpleStage.REPORT_DONE)
        verified_final = (
            final is not None
            and final.verdict in {"FALSE", "HOLD"}
            and _verified_terminal_decision(
                child_artifacts,
                final,
                verified_source_refs,
                kind="simple_verification_result",
                result_field="verdict",
                expected=final.verdict,
            )
        )
        verified_gate = (
            gate is not None
            and terminal_gate_outcome(gate) is not None
            and gate.gate_decision is not None
            and _verified_terminal_decision(
                child_artifacts,
                gate,
                verified_source_refs,
                kind="simple_technical_gate",
                result_field="status",
                expected=gate.gate_decision,
            )
        )
        chain_refs = (
            _verified_terminal_chain(child_artifacts, chain)
            if verified_final and final is not None and final.verdict == "HOLD"
            else None
        )
        verified_report = False
        if (
            finding is not None
            and report is not None
            and len(finding.output_refs) == 1
            and finding.output_refs[0] in report.input_refs
            and report.input_hash == input_reference_hash(report.input_refs)
            and report.output_refs
        ):
            closure = _verified_closure(stages, finding.output_refs[0], child_artifacts)
            verified_report = (
                closure is not None
                and closure[2]
                and report.validated_poc_ref == closure[1]
            )
            if verified_report:
                for ref in report.output_refs:
                    child_artifacts.read_bounded(ref, 16 * 1024 * 1024)
        if not (
            child_artifacts.verified_terminal_initial_outcome(
                stages.get(SimpleStage.VERIFICATION_INITIAL_DONE)
            )
            is not None
            or terminal_poc
            or (
                verified_final
                and final is not None
                and (
                    final.verdict == "FALSE"
                    or final.verdict == "HOLD"
                    and chain_refs is not None
                )
            )
            or verified_gate
            or verified_report
        ):
            raise ValueError("terminal hypothesis has unfinished work")
        if chain_refs is not None:
            terminal_chains.append(chain_refs)
    admitted_by_hash: dict[str, StoredDataRef] = {}
    primitive_rows = connection.execute(
        "SELECT checkpoint_json FROM simple_runtime_checkpoints "
        "WHERE analysis_id = ? AND stage = ?",
        (run.analysis_id, SimpleStage.PRIMITIVE_ADMISSION_DONE.value),
    ).fetchall()
    for row in primitive_rows:
        admission = StageCheckpoint.model_validate_json(row[0])
        owner = admission.identity
        if (
            admission.stage is not SimpleStage.PRIMITIVE_ADMISSION_DONE
            or admission.status is not StageStatus.SUCCEEDED
            or admission.stage_version
            != STAGE_VERSION[SimpleStage.PRIMITIVE_ADMISSION_DONE]
            or owner.analysis_id != run.analysis_id
            or owner.workspace_id != run.workspace_id
            or owner.commit_id != run.commit_id
            or owner.hypothesis_id not in hypothesis_ids
        ):
            continue
        for ref in admission.output_refs:
            value = json.loads(artifacts.read_bounded(ref, 128 * 1024 * 1024))
            if not isinstance(value, dict) or value.get("kind") != "simple_primitive":
                continue
            if (
                value.get("analysis_id") != run.analysis_id
                or value.get("workspace_id") != run.workspace_id
                or value.get("commit_id") != run.commit_id
                or value.get("source_hypothesis_id") != owner.hypothesis_id
            ):
                raise ValueError("admitted primitive has mismatched owner")
            admitted_by_hash[ref.content_hash] = ref
    if any(
        admitted_by_hash.get(ref.content_hash) != ref
        for considered in terminal_chains
        for ref in considered
    ):
        raise ValueError("terminal chaining parent was not admitted")
    admitted = tuple(admitted_by_hash[key] for key in sorted(admitted_by_hash))
    fingerprint = hashlib.sha256(
        canonical_bytes(
            {
                "analysis_id": run.analysis_id,
                "workspace_id": run.workspace_id,
                "commit_id": run.commit_id,
                "primitive_refs": admitted,
            }
        )
    ).hexdigest()
    if terminal.chaining_pool_fingerprint != fingerprint:
        raise ValueError("chaining fingerprint differs from admitted pool")
    # The partitioner only reads the exact primitive refs. Its store and client
    # are unused for this pure planning operation.
    planner = SimpleChainingStage(store=None, client=None, artifacts=artifacts)  # type: ignore[arg-type]
    partitions = planner._bounded_pair_partitions(admitted)
    batch_count = len(partitions)
    if terminal.chaining_batch_count != batch_count:
        raise ValueError("chaining batch count differs from current plan")
    ledger = connection.execute(
        "SELECT batch_index, batch_count, result_ref_json "
        "FROM simple_chaining_pool_batches WHERE analysis_id = ? "
        "AND workspace_id = ? AND commit_id = ? AND pool_fingerprint = ? "
        "ORDER BY batch_index",
        (run.analysis_id, run.workspace_id, run.commit_id, fingerprint),
    ).fetchall()
    if len(ledger) != batch_count:
        raise ValueError("chaining batch ledger is incomplete")
    for batch_index, (row, partition) in enumerate(
        zip(ledger, partitions, strict=True)
    ):
        left, right, same_block = partition
        considered = left if same_block else left + right
        considered_hashes = {ref.content_hash for ref in considered}
        unconsidered = tuple(
            ref for ref in admitted if ref.content_hash not in considered_hashes
        )
        if row[0] != batch_index or row[1] != batch_count:
            raise ValueError("chaining batch ledger index or count differs")
        result_ref = StoredDataRef.model_validate_json(row[2])
        result = json.loads(artifacts.read_bounded(result_ref, 128 * 1024 * 1024))
        if not isinstance(result, dict):
            raise ValueError("chaining batch result is not an object")
        raw_considered = result.get("considered_primitive_refs")
        raw_unconsidered = result.get("unconsidered_primitive_refs")
        children = result.get("children")
        if (
            not isinstance(raw_considered, list)
            or not isinstance(raw_unconsidered, list)
            or not isinstance(children, list)
            or len(children) >= 4
            or result.get("kind") != "simple_chaining_result"
            or result.get("analysis_id") != run.analysis_id
            or result.get("source_hypothesis_id") is not None
            or result.get("pool_fingerprint") != fingerprint
            or type(result.get("batch_index")) is not int
            or result.get("batch_index") != batch_index
            or type(result.get("batch_count")) is not int
            or result.get("batch_count") != batch_count
            or result.get("status")
            != ("MATERIAL_CHILD" if children else "NO_MATERIAL_CHILD")
            or tuple(StoredDataRef.model_validate(ref) for ref in raw_considered)
            != considered
            or tuple(StoredDataRef.model_validate(ref) for ref in raw_unconsidered)
            != unconsidered
        ):
            raise ValueError("chaining batch result differs from current plan")
        validated = validated_chaining_children(
            artifacts,
            considered,
            children,
            pair_partition=(
                frozenset(ref.content_hash for ref in left),
                frozenset(ref.content_hash for ref in right),
            ),
        )
        if canonical_bytes(children) != canonical_bytes(validated):
            raise ValueError("chaining batch children invalid")

    static_scope = _static_product_paths(connection, data_dir, run)
    if static_scope is None:
        if terminal.status == "COMPLETE":
            raise ValueError("complete terminal lacks verified static evidence")
        return False
    if any(surface.coverage_status != "COVERED" for surface in coverage.surfaces):
        return False
    if frozenset(index.static_gaps) != static_scope[1]:
        return False
    # A declared .pyi stub is outside this .py-only scan. _static_product_paths
    # already verifies its exact out-of-scope reason against the saved ledger.
    if any(gap.path.lower().endswith(".py") for gap in index.static_gaps):
        return False
    return _pipeline_complete(
        run,
        python_scope_complete=True,
        nonpython_out_of_scope=bool(static_scope[1]),
    )


def _matches(
    case: OracleCase,
    candidate: StaticCandidate,
    *,
    reviewed_root_cause: bool = False,
) -> bool:
    target_path = (
        case.path if candidate.kind == "ENTRY_POINT" else case.sink_path or case.path
    )
    if candidate.path != target_path:
        return False
    target = case.source_line if candidate.kind == "ENTRY_POINT" else case.sink_line
    if target is None or not candidate.line <= target <= candidate.end_line:
        return False
    trace = candidate.flow_trace
    trace_cwe = trace.get("cwe") if isinstance(trace, dict) else None
    if isinstance(trace_cwe, str) and not reviewed_root_cause:
        return trace_cwe.upper() == case.cwe.upper()
    return True


def _linked_hypotheses(
    connection: sqlite3.Connection,
    run: SimpleAnalysisRun,
    candidate_ids: tuple[str, ...],
) -> tuple[str, ...]:
    if not candidate_ids:
        return ()
    found: set[str] = set()
    for offset in range(0, len(candidate_ids), 500):
        batch = candidate_ids[offset : offset + 500]
        placeholders = ",".join("?" for _ in batch)
        rows = connection.execute(
            "SELECT DISTINCT hypothesis_id FROM simple_candidate_hypothesis_links "
            "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
            f"AND scope_fingerprint = ? AND candidate_id IN ({placeholders})",
            (
                run.analysis_id,
                run.workspace_id,
                run.commit_id,
                run.candidate_scope_fingerprint,
                *batch,
            ),
        ).fetchall()
        found.update(str(row[0]) for row in rows)
    return tuple(sorted(found))


def _hypothesis_stages(
    connection: sqlite3.Connection,
    run: SimpleAnalysisRun,
    hypothesis_id: str,
) -> dict[SimpleStage, StageCheckpoint]:
    rows = connection.execute(
        "SELECT checkpoint_json FROM simple_runtime_checkpoints "
        "WHERE analysis_id = ? AND hypothesis_key = ?",
        (run.analysis_id, hypothesis_id),
    ).fetchall()
    checkpoints = (StageCheckpoint.model_validate_json(row[0]) for row in rows)
    return {
        checkpoint.stage: checkpoint
        for checkpoint in checkpoints
        if checkpoint.identity.analysis_id == run.analysis_id
        and checkpoint.identity.workspace_id == run.workspace_id
        and checkpoint.identity.commit_id == run.commit_id
        and checkpoint.identity.hypothesis_id == hypothesis_id
    }


def _confirmed(
    data_dir: Path,
    run: SimpleAnalysisRun,
    hypothesis_id: str,
    case: OracleCase,
    stages: dict[SimpleStage, StageCheckpoint],
    *,
    reviewed_root_cause: bool = False,
) -> bool:
    """Reuse the strict Finding closure and require a current report artifact."""

    finding = stages.get(SimpleStage.FINDING_DONE)
    report = stages.get(SimpleStage.REPORT_DONE)
    cwe = stages.get(SimpleStage.CWE_DONE)
    if (
        finding is None
        or len(finding.output_refs) != 1
        or report is None
        or report.status is not StageStatus.SUCCEEDED
        or report.stage_version != STAGE_VERSION[SimpleStage.REPORT_DONE]
        or not report.output_refs
        or finding.output_refs[0] not in report.input_refs
        or report.validated_poc_ref is None
        or cwe is None
        or len(cwe.output_refs) != 1
    ):
        return False
    paths = RuntimePaths(data_dir)
    if not all(
        value.is_dir()
        for value in (paths.staging, paths.artifacts / "sha256", paths.quarantine)
    ):
        return False
    artifacts = SimpleArtifactRepository(
        data_dir,
        CheckpointIdentity(
            analysis_id=run.analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=hypothesis_id,
        ),
        create_dirs=False,
    )
    try:
        closure = _verified_closure(stages, finding.output_refs[0], artifacts)
        if closure is None or not closure[2] or report.validated_poc_ref != closure[1]:
            return False
        cwe_data = json.loads(artifacts.read_bounded(cwe.output_refs[0], 1024 * 1024))
        if (
            not isinstance(cwe_data, dict)
            or cwe_data.get("kind") != "simple_cwe_label"
            or not isinstance(cwe_data.get("result"), dict)
            or not isinstance(cwe_data["result"].get("primary_cwe"), str)
            or not cwe_data["result"]["primary_cwe"]
            or not reviewed_root_cause
            and cwe_data["result"]["primary_cwe"] != case.cwe
        ):
            return False
        for ref in report.output_refs:
            artifacts.read_bounded(ref, 16 * 1024 * 1024)
    except (OSError, ValueError, TypeError, UnicodeError):
        return False
    return True


def audit_analysis(
    data_dir: Path,
    analysis_id: str,
    oracle: Oracle,
    *,
    connection: sqlite3.Connection | None = None,
    reviewed_root_causes: bool = False,
    matched_hypotheses_by_case: Mapping[str, frozenset[str]] | None = None,
) -> AuditResult:
    """Read an existing analysis without initializing or changing its database."""

    if reviewed_root_causes and matched_hypotheses_by_case is None:
        raise ValueError("RECALL_REVIEW_MATCH_MAPPING_REQUIRED")

    borrowed = connection is not None
    manager: AbstractContextManager[sqlite3.Connection]
    if borrowed:
        assert connection is not None
        manager = nullcontext(connection)
    else:
        database = RuntimePaths(data_dir).database.resolve(strict=True)
        manager = closing(
            sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
        )
    with manager as connection:
        if not borrowed:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN")
        run = _analysis_run(connection, analysis_id)
        if run.commit_id != oracle.commit or not repository_targets_match(
            oracle.repository, run.repository
        ):
            raise ValueError("RECALL_ORACLE_TARGET_MISMATCH")
        static_scope = _static_product_paths(connection, data_dir, run)
        static_paths = static_scope[0] if static_scope is not None else None
        root_current = _root_hypothesis_current(connection, data_dir, run)
        terminal_complete = (
            static_scope is not None
            and root_current
            and _pipeline_complete(
                run,
                python_scope_complete=True,
                nonpython_out_of_scope=bool(static_scope[1]),
            )
        )
        cursor = connection.execute(
            "SELECT candidate_id, candidate_json, decision, deep_status "
            "FROM simple_static_candidates "
            "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
            "AND scope_fingerprint = ? ORDER BY candidate_id",
            (
                run.analysis_id,
                run.workspace_id,
                run.commit_id,
                run.candidate_scope_fingerprint,
            ),
        )
        matches_by_case: list[list[tuple[StaticCandidate, str, str]]] = [
            [] for _ in oracle.cases
        ]
        observed_decisions: Counter[str] = Counter()
        observed_deep: Counter[str] = Counter()
        while rows := cursor.fetchmany(500):
            for row in rows:
                candidate = StaticCandidate.model_validate_json(row["candidate_json"])
                if candidate.candidate_id != row["candidate_id"]:
                    raise ValueError("RECALL_CANDIDATE_ID_MISMATCH")
                item = (candidate, str(row["decision"]), str(row["deep_status"]))
                observed_decisions[item[1]] += 1
                if item[1] in {"INCLUDE", "UNDECIDED"}:
                    observed_deep[item[2]] += 1
                for index, case in enumerate(oracle.cases):
                    if _matches(
                        case, candidate, reviewed_root_cause=reviewed_root_causes
                    ):
                        matches_by_case[index].append(item)
        terminal = run.candidate_terminal
        ledger_consistent = bool(
            terminal is not None
            and dict(observed_decisions)
            == {key: count for key, count in terminal.decision_counts.items() if count}
            and dict(observed_deep)
            == {key: count for key, count in terminal.deep_counts.items() if count}
        )
        pipeline_complete = terminal_complete and ledger_consistent
        cases: list[AuditCaseResult] = []
        for case, matched in zip(oracle.cases, matches_by_case, strict=True):
            reviewed_matches = (
                None
                if matched_hypotheses_by_case is None
                else matched_hypotheses_by_case.get(case.case_id, frozenset())
            )
            candidate_ids = tuple(item[0].candidate_id for item in matched)
            decisions = {item[0].candidate_id: item[1] for item in matched}
            deep_states = {item[0].candidate_id: item[2] for item in matched}
            vetted_ids = tuple(
                item for item in candidate_ids if item in case.vetted_candidate_ids
            )
            hypothesis_ids = tuple(
                sorted(
                    set(
                        _linked_hypotheses(connection, run, candidate_ids)
                        + case.vetted_hypothesis_ids
                    )
                )
            )
            relevant_hypothesis_ids = tuple(
                sorted(
                    set(
                        _linked_hypotheses(connection, run, vetted_ids)
                        + case.vetted_hypothesis_ids
                    )
                )
            )
            stages = {
                hypothesis_id: _hypothesis_stages(connection, run, hypothesis_id)
                for hypothesis_id in relevant_hypothesis_ids
            }
            vetted_stages = {
                key: value
                for key, value in stages.items()
                if key in case.vetted_hypothesis_ids
            }
            complete = (
                static_paths is not None
                and pipeline_complete
                and case.path in static_paths
                and (case.sink_path is None or case.sink_path in static_paths)
            )
            if set(case.vetted_candidate_ids) - set(vetted_ids):
                status, first_gap = "INCOMPLETE", "ORACLE_CANDIDATE_MAPPING_INVALID"
            elif not root_current:
                status, first_gap = (
                    "INCOMPLETE",
                    "STATIC_EVIDENCE_UNVERIFIED"
                    if static_paths is None
                    else "ROOT_HYPOTHESIS_UNVERIFIED",
                )
            elif any(
                _confirmed(
                    data_dir,
                    run,
                    key,
                    case,
                    item,
                    reviewed_root_cause=reviewed_root_causes,
                )
                for key, item in vetted_stages.items()
                if reviewed_matches is None or key in reviewed_matches
            ):
                status, first_gap = "DETECTED", None
            elif not ledger_consistent:
                status, first_gap = "INCOMPLETE", "CANDIDATE_LEDGER_MISMATCH"
            elif any(
                checkpoint.verdict == "HOLD"
                or checkpoint.environment_block_ref is not None
                for item in stages.values()
                for checkpoint in item.values()
            ):
                status, first_gap = "INCOMPLETE", "HOLD_VERIFICATION"
            elif any(
                checkpoint.status in {StageStatus.FAILED, StageStatus.BLOCKED}
                for item in stages.values()
                for checkpoint in item.values()
            ):
                status, first_gap = (
                    "INCOMPLETE",
                    "POC_EXECUTION_ERROR"
                    if any(
                        item.get(SimpleStage.POC_EXECUTION_DONE) is not None
                        and item[SimpleStage.POC_EXECUTION_DONE].status
                        in {StageStatus.FAILED, StageStatus.BLOCKED}
                        for item in stages.values()
                    )
                    else "AGENT_ERROR",
                )
            elif any(
                (final := item.get(SimpleStage.VERIFICATION_FINAL_DONE)) is not None
                and final.status is StageStatus.SUCCEEDED
                and final.verdict == "TRUE"
                for key, item in vetted_stages.items()
                if reviewed_matches is None or key in reviewed_matches
            ):
                status, first_gap = "INCOMPLETE", "FINDING_EVIDENCE_UNVERIFIED"
            elif not complete:
                status, first_gap = (
                    "INCOMPLETE",
                    (
                        "STATIC_EVIDENCE_UNVERIFIED"
                        if static_paths is None
                        else "ORACLE_OUT_OF_SCOPE"
                        if case.path not in static_paths
                        else "PIPELINE_UNFINISHED"
                    ),
                )
            elif not matched and not case.vetted_hypothesis_ids:
                status, first_gap = "MISSED", "STATIC_CANDIDATE"
            elif matched and not vetted_ids and not case.vetted_hypothesis_ids:
                status, first_gap = (
                    "POSSIBLE",
                    (
                        "HYPOTHESIS"
                        if all(item[0].kind == "ENTRY_POINT" for item in matched)
                        else "CANDIDATE_IDENTITY_UNVERIFIED"
                    ),
                )
            elif vetted_ids and all(
                decisions[value] == "EXCLUDE" for value in vetted_ids
            ):
                status, first_gap = (
                    ("MISSED" if complete else "INCOMPLETE"),
                    "DISCOVERY",
                )
            elif any(
                decisions[value] in {"PENDING", "ERROR"} for value in vetted_ids
            ) or any(
                deep_states[value] in {"PENDING", "RUNNING", "ERROR"}
                for value in vetted_ids
            ):
                status, first_gap = "INCOMPLETE", "DISCOVERY_OR_DEEP_PENDING"
            elif not relevant_hypothesis_ids:
                status, first_gap = (
                    ("MISSED", "HYPOTHESIS")
                    if vetted_ids
                    and all(
                        deep_states[value] in {"NO_HYPOTHESIS", "INCONCLUSIVE"}
                        for value in vetted_ids
                    )
                    else ("INCOMPLETE", "HYPOTHESIS")
                )
            elif any(
                item.get(SimpleStage.VERIFICATION_FINAL_DONE) is None
                for item in stages.values()
            ):
                status, first_gap = "INCOMPLETE", "VALIDATION_UNFINISHED"
            else:
                status, first_gap = (
                    ("MISSED", "VALIDATION")
                    if case.vetted_hypothesis_ids
                    else ("POSSIBLE", "HYPOTHESIS_IDENTITY_UNVERIFIED")
                )
            if status == "MISSED" and not case.finding_inventory_reviewed:
                status, first_gap = "POSSIBLE", "FINDING_INVENTORY_UNREVIEWED"
            cases.append(
                {
                    "case_id": case.case_id,
                    "status": status,
                    "first_gap": first_gap,
                    "candidate_ids": list(candidate_ids),
                    "vetted_candidate_ids": list(vetted_ids),
                    "decisions": decisions,
                    "deep_states": deep_states,
                    "hypothesis_ids": list(hypothesis_ids),
                    "vetted_hypothesis_ids": list(case.vetted_hypothesis_ids),
                    "finding_inventory_reviewed": case.finding_inventory_reviewed,
                }
            )
    return {
        "analysis_id": analysis_id,
        "oracle_commit": oracle.commit,
        "analysis_complete": pipeline_complete,
        "cases": cases,
        "counts": dict(Counter(str(item["status"]) for item in cases)),
    }
