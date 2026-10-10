"""Pinned, append-only replay plan for saved v2 AST/source context gaps."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import SurfaceIndex
from .file_context import prepare_file_context
from .models import CheckpointIdentity
from .store import SimpleCheckpointStore, SurfaceExplorationProgressRecord
from .surface_contexts import SurfaceContext
from .surface_supplemental_contexts import build_surface_context_supplements


def _context_ref(identity: CheckpointIdentity, digest: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(digest),
        data_kind="artifact",
        content_hash=digest,
        workspace_id=WorkspaceId(identity.workspace_id),
        commit_id=CommitId(identity.commit_id),
        record_id=None,
    )


def _saved_v2_context(
    identity: CheckpointIdentity,
    record: SurfaceExplorationProgressRecord,
    artifacts: SimpleArtifactRepository,
) -> tuple[SurfaceContext, dict[str, object]]:
    ref = _context_ref(identity, record.context_hash)
    payload = json.loads(artifacts.read(ref))
    if not isinstance(payload, dict):
        raise ValueError("SURFACE_SUPPLEMENT_SCOPE_MISMATCH")
    try:
        part_index = payload["part_index"]
        part_count = payload["part_count"]
        omitted_source = payload["omitted_source_line_count"]
        omitted_ast = payload["omitted_ast_fact_count"]
    except KeyError as error:
        raise ValueError("SURFACE_SUPPLEMENT_SCOPE_MISMATCH") from error
    if (
        payload.get("kind") != "simple_surface_context_v2"
        or payload.get("surface_id") != record.surface_id
        or type(part_index) is not int
        or type(part_count) is not int
        or type(omitted_source) is not int
        or type(omitted_ast) is not int
    ):
        raise ValueError("SURFACE_SUPPLEMENT_SCOPE_MISMATCH")
    context = SurfaceContext(
        surface_id=record.surface_id,
        context_id=record.context_id,
        context_hash=record.context_hash,
        context_ref=ref,
        part_index=part_index,
        part_count=part_count,
        prompt_bytes=len(canonical_bytes(payload)),
        source_sha256=record.source_sha256,
        source_unavailable_reason=None,
        ast_unavailable_reason=None,
        omitted_source_line_count=omitted_source,
        omitted_ast_fact_count=omitted_ast,
    )
    return context, cast(dict[str, object], payload)


def _has_ast_only_part(payload: dict[str, object]) -> bool:
    source = payload.get("source_lines")
    facts = payload.get("ast_facts")
    if not isinstance(source, list) or not isinstance(facts, list):
        raise ValueError("SURFACE_SUPPLEMENT_SCOPE_MISMATCH")
    lines = {
        row.get("line")
        for row in source
        if isinstance(row, dict) and type(row.get("line")) is int
    }
    return any(
        not isinstance(fact, dict)
        or type(fact.get("line")) is not int
        or fact["line"] not in lines
        for fact in facts
    )


def build_saved_surface_supplement_plan(
    identity: CheckpointIdentity,
    scope: str,
    static_bundle_ref: StoredDataRef,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    ast_summary: dict[str, object],
    workspace: Path,
    artifacts: SimpleArtifactRepository,
    store: SimpleCheckpointStore,
) -> tuple[dict[str, object], tuple[SurfaceContext, ...]]:
    """Recompute every old orphan against pinned evidence, never a fresh scan."""

    if (
        index.index_version != 2
        or index.scope_fingerprint != scope
        or index.static_bundle_hash != static_bundle_ref.content_hash
        or str(artifacts.identity.workspace_id) != identity.workspace_id
        or str(artifacts.identity.commit_id) != identity.commit_id
    ):
        raise ValueError("SURFACE_SUPPLEMENT_SCOPE_MISMATCH")
    progress = store.list_surface_exploration_progress(identity, scope)
    grouped: dict[str, list[tuple[SurfaceContext, dict[str, object]]]] = defaultdict(
        list
    )
    orphan_parents: set[str] = set()
    for record in progress.values():
        if record.proposal_version != 2:
            continue
        if (
            record.static_bundle_hash != static_bundle_ref.content_hash
            or record.index_hash != index_ref.content_hash
        ):
            raise ValueError("SURFACE_SUPPLEMENT_SCOPE_MISMATCH")
        context, payload = _saved_v2_context(identity, record, artifacts)
        grouped[record.surface_id].append((context, payload))
        if _has_ast_only_part(payload):
            orphan_parents.add(context.context_id)
    supplemental: list[SurfaceContext] = []
    entries: list[dict[str, object]] = []
    for surface in index.surfaces:
        saved = grouped.pop(surface.surface_id, [])
        if not saved or not any(
            context.context_id in orphan_parents for context, _ in saved
        ):
            continue
        prepared = prepare_file_context(artifacts, ast_summary, workspace, surface.path)
        built = build_surface_context_supplements(index, surface, prepared, saved)
        if not built:
            raise ValueError("SURFACE_SUPPLEMENT_CONTEXT_MISSING")
        for item in built:
            ref = artifacts.put_json(item.payload)
            if ref.content_hash != item.context_hash:
                raise ValueError("SURFACE_SUPPLEMENT_CONTEXT_HASH_MISMATCH")
            parent_id = item.payload.get("parent_v2_context_id")
            if not isinstance(parent_id, str) or parent_id not in orphan_parents:
                raise ValueError("SURFACE_SUPPLEMENT_PARENT_INVALID")
            context = SurfaceContext(
                surface_id=surface.surface_id,
                context_id=item.context_id,
                context_hash=item.context_hash,
                context_ref=ref,
                part_index=cast(int, item.payload["part_index"]),
                part_count=cast(int, item.payload["part_count"]),
                prompt_bytes=item.prompt_bytes,
                source_sha256=prepared.source_sha256,
                source_unavailable_reason=None,
                ast_unavailable_reason=None,
                omitted_source_line_count=0,
                omitted_ast_fact_count=0,
            )
            supplemental.append(context)
            entries.append(
                {
                    "surface_id": surface.surface_id,
                    "context_id": item.context_id,
                    "context_hash": item.context_hash,
                    "parent_v2_context_id": parent_id,
                    "source_sha256": prepared.source_sha256,
                }
            )
    if any(
        context.context_id in orphan_parents
        for saved in grouped.values()
        for context, _ in saved
    ) or len(orphan_parents) != len(
        {cast(str, item["parent_v2_context_id"]) for item in entries}
    ):
        raise ValueError("SURFACE_SUPPLEMENT_SCOPE_MISMATCH")
    plan: dict[str, object] = {
        "kind": "simple_surface_supplement_plan_v3",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope_fingerprint": scope,
        "static_bundle_hash": static_bundle_ref.content_hash,
        "surface_index_hash": index_ref.content_hash,
        "parent_v2_context_ids": sorted(orphan_parents),
        "contexts": entries,
    }
    return plan, tuple(supplemental)
