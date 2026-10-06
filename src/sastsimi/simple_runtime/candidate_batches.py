"""Stable, byte-budgeted batches of selected static evidence candidates."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import redact_projected_json
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .ast_facts import index_ast_manifest
from .call_path_facts import PythonCallPathIndex, build_python_call_path_index
from .candidates import StaticCandidate
from .file_context import (
    PreparedFileContext,
    build_file_context,
    prepare_file_context,
)
from .models import CheckpointIdentity
from .store import SimpleCheckpointStore

MAX_CANDIDATES_PER_BATCH = 16
# The qualified per-ID JSON schema currently uses ~1.6 KiB before the fixed
# instructions and transport framing. Reserve generous byte headroom when
# splitting; the caller still checks the exact rendered prompt and schema.
PROMPT_HEADROOM_BYTES = 4096


class CandidateContextOverflow(ValueError):
    """Even one candidate cannot fit; callers must record an explicit ERROR."""

    def __init__(self, candidate_ids: tuple[str, ...]) -> None:
        self.candidate_ids = candidate_ids
        super().__init__("CANDIDATE_CONTEXT_OVERFLOW")


@dataclass(frozen=True, slots=True)
class CandidateBatch:
    batch_id: str
    scope_fingerprint: str
    path: str
    candidate_ids: tuple[str, ...]
    candidates: tuple[StaticCandidate, ...]
    shared_context_ref: StoredDataRef
    prompt_bytes: int
    max_prompt_bytes: int


def candidate_batch_id(
    scope_fingerprint: str,
    path: str,
    candidate_ids: tuple[str, ...],
    context_hash: str,
) -> str:
    key = {
        "kind": "simple_candidate_batch_v1",
        "scope_fingerprint": scope_fingerprint,
        "path": path,
        "candidate_ids": candidate_ids,
        "shared_context_hash": context_hash,
    }
    return hashlib.sha256(canonical_bytes(key)).hexdigest()


def candidate_prompt_projection(candidate: StaticCandidate) -> dict[str, object]:
    value = {
        "candidate_id": candidate.candidate_id,
        "kind": candidate.kind,
        "path": candidate.path,
        "line": candidate.line,
        "end_line": candidate.end_line,
        "summary": candidate.summary,
        "evidence_excerpt": candidate.evidence_excerpt,
        "evidence_ref_hash": candidate.evidence_ref.content_hash,
        "evidence_key": candidate.evidence_key,
        "flow_identity": candidate.flow_identity,
        "flow_trace": candidate.flow_trace,
        "origins": [
            {"engine": origin.engine, "rule_id": origin.rule_id}
            for origin in candidate.origins
        ],
        "discovery_decision": candidate.decision,
        "discovery_reason": candidate.decision_reason,
    }
    projected = json.loads(redact_projected_json(canonical_bytes(value)).data)
    if not isinstance(projected, dict):
        raise ValueError("CANDIDATE_BATCH_REDACTION_FAILED")
    return projected


def _assemble_batch(
    *,
    artifacts: SimpleArtifactRepository,
    ast_summary: Mapping[str, object],
    workspace: Path,
    prepared: PreparedFileContext,
    candidates: Sequence[StaticCandidate],
    scope_fingerprint: str,
    max_prompt_bytes: int,
    call_path_index: PythonCallPathIndex | None = None,
    include_downstream: bool = False,
    include_enclosing: bool = False,
) -> CandidateBatch:
    path = prepared.path
    context_ref = build_file_context(
        artifacts,
        ast_summary,
        workspace,
        path,
        candidates,
        prepared=prepared,
        call_path_index=call_path_index,
        include_downstream=include_downstream,
        include_enclosing=include_enclosing,
    )
    context_payload = json.loads(artifacts.read(context_ref))
    prompt_bytes = PROMPT_HEADROOM_BYTES + len(
        canonical_bytes(
            {
                "shared_context": context_payload,
                "candidates": [
                    candidate_prompt_projection(item) for item in candidates
                ],
            }
        )
    )
    candidate_ids = tuple(item.candidate_id for item in candidates)
    if prompt_bytes > max_prompt_bytes:
        raise CandidateContextOverflow(candidate_ids)
    return CandidateBatch(
        batch_id=candidate_batch_id(
            scope_fingerprint, path, candidate_ids, context_ref.content_hash
        ),
        scope_fingerprint=scope_fingerprint,
        path=path,
        candidate_ids=candidate_ids,
        candidates=tuple(candidates),
        shared_context_ref=context_ref,
        prompt_bytes=prompt_bytes,
        max_prompt_bytes=max_prompt_bytes,
    )


def iter_candidate_batches(
    store: SimpleCheckpointStore,
    identity: CheckpointIdentity,
    scope_fingerprint: str,
    *,
    artifacts: SimpleArtifactRepository,
    ast_summary: Mapping[str, object],
    workspace: Path,
    max_prompt_bytes: int,
    db_page_size: int = 32,
    context_version: int = 1,
) -> Iterator[CandidateBatch]:
    """Yield selected candidates in stable file order across database pages."""

    if (
        max_prompt_bytes < 1024
        or db_page_size < 1
        or context_version not in {1, 2, 3, 4}
    ):
        raise ValueError("CANDIDATE_BATCH_BUDGET_INVALID")
    manifest_index = index_ast_manifest(artifacts, ast_summary)
    call_path_index = (
        build_python_call_path_index(workspace, tuple(manifest_index))
        if context_version in {2, 3, 4}
        else None
    )
    after: tuple[str, str] | None = None
    prepared: PreparedFileContext | None = None
    pending: list[StaticCandidate] = []
    current_batch: CandidateBatch | None = None
    while True:
        page = store.list_candidate_batch_page(
            identity, scope_fingerprint, after=after, limit=db_page_size
        )
        if not page:
            break
        for candidate in page:
            if prepared is None or candidate.path != prepared.path:
                if current_batch is not None:
                    yield current_batch
                prepared = prepare_file_context(
                    artifacts,
                    ast_summary,
                    workspace,
                    candidate.path,
                    manifest_index=manifest_index,
                )
                pending = []
                current_batch = None
            if len(pending) >= MAX_CANDIDATES_PER_BATCH:
                if current_batch is None:
                    raise RuntimeError("CANDIDATE_BATCH_INTERNAL_MISSING")
                yield current_batch
                pending = []
                current_batch = None
            proposed = [*pending, candidate]
            try:
                candidate_batch = _assemble_batch(
                    artifacts=artifacts,
                    ast_summary=ast_summary,
                    workspace=workspace,
                    prepared=prepared,
                    candidates=proposed,
                    scope_fingerprint=scope_fingerprint,
                    max_prompt_bytes=max_prompt_bytes,
                    call_path_index=call_path_index,
                    include_downstream=context_version in {3, 4},
                    include_enclosing=context_version == 4,
                )
            except CandidateContextOverflow:
                if current_batch is None:
                    raise CandidateContextOverflow((candidate.candidate_id,)) from None
                yield current_batch
                pending = [candidate]
                current_batch = _assemble_batch(
                    artifacts=artifacts,
                    ast_summary=ast_summary,
                    workspace=workspace,
                    prepared=prepared,
                    candidates=pending,
                    scope_fingerprint=scope_fingerprint,
                    max_prompt_bytes=max_prompt_bytes,
                    call_path_index=call_path_index,
                    include_downstream=context_version in {3, 4},
                    include_enclosing=context_version == 4,
                )
            else:
                pending = proposed
                current_batch = candidate_batch
        last = page[-1]
        after = (last.path, last.candidate_id)
    if current_batch is not None:
        yield current_batch
