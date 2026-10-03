"""Read-only projection of current Finding closures into conservative groups."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore

from .artifacts import SimpleArtifactRepository
from .ast_facts import index_ast_manifest, read_ast_file_facts
from .candidates import CandidateOrigin, StaticCandidate
from .finding_flow import FlowEvidenceInvalid, resolve_flow_anchor
from .finding_groups import (
    FindingGroupProjection,
    VerifiedFindingMember,
    group_verified_findings,
)
from .gate_guard import technical_gate_accepted
from .models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from .scope_policy import project_scope_review

_MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
_REQUIRED_STAGES = (
    SimpleStage.PRO_CON_DONE,
    SimpleStage.POC_CANDIDATE_DONE,
    SimpleStage.POC_EXECUTION_DONE,
    SimpleStage.VERIFICATION_FINAL_DONE,
    SimpleStage.CWE_DONE,
    SimpleStage.TECH_GATE_DONE,
    SimpleStage.SCOPE_GATE_DONE,
    SimpleStage.FINDING_DONE,
)


def _artifact_reader(
    data_dir: Path, identity: CheckpointIdentity
) -> SimpleArtifactRepository:
    # The repository's normal constructor ensures directories. Require them to
    # preexist so a dashboard read cannot repair or create runtime state.
    paths = RuntimePaths(data_dir)
    if not all(
        path.is_dir()
        for path in (paths.staging, paths.artifacts / "sha256", paths.quarantine)
    ):
        raise ValueError("FINDING_GROUP_ARTIFACT_STORE_UNAVAILABLE")
    return SimpleArtifactRepository(data_dir, identity)


def _json(artifacts: SimpleArtifactRepository, ref: StoredDataRef) -> dict[str, Any]:
    try:
        value = json.loads(artifacts.read_bounded(ref, _MAX_EVIDENCE_BYTES))
    except (OSError, ValueError, TypeError, UnicodeError) as error:
        raise ValueError("FINDING_GROUP_REQUIRED_EVIDENCE_INVALID") from error
    if not isinstance(value, dict):
        raise ValueError("FINDING_GROUP_REQUIRED_EVIDENCE_INVALID")
    return value


def _ref(value: object) -> StoredDataRef:
    try:
        return StoredDataRef.model_validate(value)
    except (ValueError, TypeError) as error:
        raise ValueError("FINDING_GROUP_REQUIRED_EVIDENCE_INVALID") from error


def _current(
    run: SimpleAnalysisRun, checkpoints: Sequence[StageCheckpoint]
) -> dict[str, dict[SimpleStage, StageCheckpoint]]:
    found: dict[str, dict[SimpleStage, StageCheckpoint]] = {}
    repeated: set[str] = set()
    for item in checkpoints:
        identity = item.identity
        if (
            identity.analysis_id != run.analysis_id
            or identity.workspace_id != run.workspace_id
            or identity.commit_id != run.commit_id
            or identity.hypothesis_id is None
        ):
            continue
        key = identity.hypothesis_id
        if item.stage in found.setdefault(key, {}):
            repeated.add(key)
        found[key][item.stage] = item
    for key in repeated:
        found.pop(key, None)
    return found


def _verified_closure(
    stages: Mapping[SimpleStage, StageCheckpoint],
    finding_ref: StoredDataRef,
    artifacts: SimpleArtifactRepository,
) -> tuple[dict[str, Any], StoredDataRef] | None:
    if any(
        (item := stages.get(stage)) is None
        or item.stage_version != STAGE_VERSION[stage]
        or item.status is not StageStatus.SUCCEEDED
        or not item.output_refs
        for stage in _REQUIRED_STAGES
    ):
        return None
    finding = stages[SimpleStage.FINDING_DONE]
    dynamic = stages[SimpleStage.POC_EXECUTION_DONE]
    final = stages[SimpleStage.VERIFICATION_FINAL_DONE]
    candidate = stages[SimpleStage.POC_CANDIDATE_DONE]
    technical = stages[SimpleStage.TECH_GATE_DONE]
    if (
        finding.output_refs != (finding_ref,)
        or final.verdict != "TRUE"
        or finding.verdict != "TRUE"
        or dynamic.validated_poc_ref is None
        or final.validated_poc_ref != dynamic.validated_poc_ref
        or finding.validated_poc_ref != dynamic.validated_poc_ref
        or len(candidate.output_refs) < 2
        or len(dynamic.output_refs) != 1
        or not technical_gate_accepted(technical, artifacts)
    ):
        return None
    raw = _json(artifacts, finding_ref)
    validated = dynamic.validated_poc_ref
    if (
        raw.get("kind") != "simple_finding"
        or raw.get("analysis_id") != finding.identity.analysis_id
        or raw.get("hypothesis_id") != finding.identity.hypothesis_id
        or _ref(raw.get("validated_poc_ref")) != validated
    ):
        raise ValueError("FINDING_GROUP_REQUIRED_EVIDENCE_INVALID")
    source_refs = raw.get("source_refs")
    if not isinstance(source_refs, list):
        raise ValueError("FINDING_GROUP_REQUIRED_EVIDENCE_INVALID")
    try:
        source_set = {_ref(value) for value in source_refs}
    except TypeError as error:
        raise ValueError("FINDING_GROUP_REQUIRED_EVIDENCE_INVALID") from error
    if not all(
        ref in source_set
        for stage in _REQUIRED_STAGES
        if stage is not SimpleStage.FINDING_DONE
        for ref in stages[stage].output_refs
    ):
        raise ValueError("FINDING_GROUP_REQUIRED_EVIDENCE_INVALID")
    candidate_ref, content_ref = candidate.output_refs[:2]
    execution_ref = dynamic.output_refs[0]
    poc = _json(artifacts, candidate_ref)
    execution = _json(artifacts, execution_ref)
    validated_poc = _json(artifacts, validated)
    if (
        _ref(poc.get("content_ref")) != content_ref
        or _ref(execution.get("candidate_ref")) != candidate_ref
        or _ref(execution.get("content_ref")) != content_ref
        or _ref(validated_poc.get("candidate_ref")) != candidate_ref
        or _ref(validated_poc.get("content_ref")) != content_ref
        or _ref(validated_poc.get("execution_ref")) != execution_ref
        or not dynamic.attempt_id
        or execution.get("attempt_id") != dynamic.attempt_id
        or validated_poc.get("attempt_id") != dynamic.attempt_id
    ):
        raise ValueError("FINDING_GROUP_REQUIRED_EVIDENCE_INVALID")
    return raw, validated


def _candidate(
    database_path: Path, run: SimpleAnalysisRun, candidate_id: str
) -> StaticCandidate | None:
    if run.candidate_scope_fingerprint is None:
        return None
    connection = sqlite3.connect(
        f"file:{database_path.resolve().as_posix()}?mode=ro", uri=True
    )
    try:
        row = connection.execute(
            "SELECT candidate_json FROM simple_static_candidates "
            "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
            "AND scope_fingerprint = ? AND candidate_id = ?",
            (
                run.analysis_id,
                run.workspace_id,
                run.commit_id,
                run.candidate_scope_fingerprint,
                candidate_id,
            ),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    finally:
        connection.close()
    if row is None:
        return None
    try:
        candidate = StaticCandidate.model_validate_json(row[0])
    except (ValueError, TypeError):
        return None
    return candidate if candidate.candidate_id == candidate_id else None


def _trace_endpoint(
    location: object, path: str, workspace: Path
) -> dict[str, object] | None:
    if not isinstance(location, dict):
        return None
    nested = location.get("location")
    if not isinstance(nested, dict):
        return None
    physical = nested.get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    artifact = physical.get("artifactLocation")
    region = physical.get("region")
    if not isinstance(artifact, dict) or not isinstance(region, dict):
        return None
    uri = artifact.get("uri")
    line = region.get("startLine")
    if not isinstance(uri, str) or type(line) is not int:
        return None
    parsed = urlsplit(uri)
    uri_path = unquote(parsed.path if parsed.scheme else uri).replace("\\", "/")
    if uri_path.startswith("/") and len(uri_path) > 2 and uri_path[2] == ":":
        uri_path = uri_path[1:]
    resolved = (
        (workspace / uri_path).resolve()
        if not Path(uri_path).is_absolute()
        else Path(uri_path).resolve()
    )
    expected = (workspace / path).resolve()
    return {"path": path if resolved == expected else uri_path, "line": line}


def _normalized_trace(
    trace: Mapping[str, object] | None, path: str, workspace: Path
) -> Mapping[str, object] | None:
    if trace is None:
        return None
    if "source" in trace and "sink" in trace:
        return trace
    flows = trace.get("codeFlows")
    if not isinstance(flows, list) or len(flows) != 1 or not isinstance(flows[0], dict):
        return {"source": {}, "sink": {}}
    threads = flows[0].get("threadFlows")
    if (
        not isinstance(threads, list)
        or len(threads) != 1
        or not isinstance(threads[0], dict)
    ):
        return {"source": {}, "sink": {}}
    locations = threads[0].get("locations")
    if not isinstance(locations, list) or len(locations) < 2:
        return {"source": {}, "sink": {}}
    source = _trace_endpoint(locations[0], path, workspace)
    sink = _trace_endpoint(locations[-1], path, workspace)
    return {"source": source or {}, "sink": sink or {}}


def project_current_finding_groups(
    run: SimpleAnalysisRun,
    checkpoints: Sequence[StageCheckpoint],
    eligible: Mapping[str, StoredDataRef],
    *,
    data_dir: Path,
    database_path: Path,
) -> FindingGroupProjection:
    """Read existing closures and abstain whenever exact flow proof is absent."""

    if not eligible:
        return group_verified_findings(())
    identity = CheckpointIdentity(
        analysis_id=run.analysis_id,
        workspace_id=run.workspace_id,
        commit_id=run.commit_id,
        hypothesis_id=None,
    )
    artifacts = _artifact_reader(data_dir, identity)
    current = _current(run, checkpoints)
    manifest: dict[str, dict[str, Any]] = {}
    ast_summary: dict[str, Any] | None = None
    if run.static_bundle_ref is not None:
        bundle = _json(artifacts, run.static_bundle_ref)
        if bundle.get("kind") == "simple_static_fact_bundle" and isinstance(
            bundle.get("ast_summary"), dict
        ):
            ast_summary = bundle["ast_summary"]
            try:
                manifest = index_ast_manifest(artifacts, ast_summary)
            except (OSError, ValueError, TypeError):
                manifest = {}
    members: list[VerifiedFindingMember] = []
    for display_id, finding_ref in eligible.items():
        try:
            resolved = FindingDisplayIdStore.resolve_existing(
                database_path, run.analysis_id, display_id
            )
        except (OSError, ValueError, sqlite3.Error, LookupError) as error:
            raise ValueError("FINDING_GROUP_DISPLAY_REFERENCE_INVALID") from error
        if resolved != finding_ref:
            raise ValueError("FINDING_GROUP_DISPLAY_REFERENCE_INVALID")
        raw = _json(artifacts, finding_ref)
        hypothesis_id = raw.get("hypothesis_id")
        if not isinstance(hypothesis_id, str):
            raise ValueError("FINDING_GROUP_REQUIRED_EVIDENCE_INVALID")
        stages = current.get(hypothesis_id)
        if stages is None:
            continue
        closure = _verified_closure(stages, finding_ref, artifacts)
        if closure is None:
            continue
        finding, validated = closure
        pro = stages[SimpleStage.PRO_CON_DONE]
        if not pro.input_refs:
            raise ValueError("FINDING_GROUP_REQUIRED_EVIDENCE_INVALID")
        proposal_ref = pro.input_refs[0]
        try:
            safe_proposal = json.loads(artifacts.read_prompt_proposal(proposal_ref))
            if not isinstance(safe_proposal, dict):
                raise ValueError("invalid proposal")
            original_ref = safe_proposal.get("original_proposal_ref")
            proposal = (
                _json(artifacts, _ref(original_ref)) if original_ref else safe_proposal
            )
        except (OSError, ValueError, TypeError) as error:
            raise ValueError("FINDING_GROUP_REQUIRED_EVIDENCE_INVALID") from error
        if (
            proposal.get("kind") != "simple_hypothesis_proposal"
            or proposal.get("analysis_id") != run.analysis_id
            or proposal.get("hypothesis_id") != hypothesis_id
        ):
            raise ValueError("FINDING_GROUP_REQUIRED_EVIDENCE_INVALID")
        cwe_ref = stages[SimpleStage.CWE_DONE].output_refs[0]
        cwe_raw = _json(artifacts, cwe_ref)
        cwe_result = cwe_raw.get("result")
        cwe = cwe_result.get("primary_cwe") if isinstance(cwe_result, dict) else None
        if cwe_raw.get("kind") != "simple_cwe_label" or not isinstance(cwe, str):
            raise ValueError("FINDING_GROUP_REQUIRED_EVIDENCE_INVALID")
        scope = project_scope_review(
            stages[SimpleStage.SCOPE_GATE_DONE],
            artifacts,
            policy_snapshot_ref=run.policy_snapshot_ref,
            repository_url=run.repository,
        )
        scope_status = str(scope["status"])
        proposal_body = proposal.get("proposal")
        raw_locations = (
            proposal_body.get("code_locations")
            if isinstance(proposal_body, dict)
            else None
        )
        paths = (
            {
                location.rpartition(":")[0].replace("\\", "/")
                for location in raw_locations
                if isinstance(location, str) and ":" in location
            }
            if isinstance(raw_locations, list)
            else set()
        )
        candidate_id = proposal.get("candidate_id")
        surface_id = proposal.get("surface_id")
        candidate = (
            _candidate(database_path, run, candidate_id)
            if isinstance(candidate_id, str)
            else None
        )
        origins: tuple[CandidateOrigin, ...] = candidate.origins if candidate else ()
        candidate_ids = (candidate_id,) if isinstance(candidate_id, str) else ()
        anchor = None
        reason = "FLOW_PROVENANCE_UNAVAILABLE"
        if (
            isinstance(proposal_body, dict)
            and run.workspace_path is not None
            and (candidate is not None or isinstance(surface_id, str))
            and len(paths) == 1
        ):
            path = next(iter(paths))
            entry = manifest.get(path)
            if entry is not None and isinstance(entry.get("source_sha256"), str):
                try:
                    if ast_summary is not None:
                        read_ast_file_facts(
                            artifacts, ast_summary, path, manifest_index=manifest
                        )
                    anchor = resolve_flow_anchor(
                        run.workspace_path,
                        path,
                        entry["source_sha256"],
                        proposal_body,
                        cwe,
                        _normalized_trace(
                            candidate.flow_trace, path, run.workspace_path
                        )
                        if candidate
                        else None,
                    )
                    reason = "FLOW_NOT_RESOLVED" if anchor is None else ""
                except (OSError, ValueError, FlowEvidenceInvalid):
                    reason = "PINNED_SOURCE_OR_AST_INVALID"
        members.append(
            VerifiedFindingMember(
                analysis_id=run.analysis_id,
                workspace_id=run.workspace_id,
                commit_id=run.commit_id,
                display_id=display_id,
                finding_ref=finding_ref,
                hypothesis_id=hypothesis_id,
                validated_poc_ref=validated,
                proposal_ref=proposal_ref,
                cwe_ref=cwe_ref,
                candidate_ids=candidate_ids,
                candidate_origins=origins,
                scope_status=scope_status,
                anchor=anchor,
                undetermined_reason=reason if anchor is None else None,
                surface_id=surface_id if isinstance(surface_id, str) else None,
            )
        )
    return group_verified_findings(members)
