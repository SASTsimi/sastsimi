"""Pure context planning and bounded reads from an exact tracked workspace."""

from __future__ import annotations

import hashlib
import os
import stat
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from pydantic import TypeAdapter

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import (
    CodeFact,
    CodeLocation,
    CodeRelation,
    CodeSymbol,
    CodeWorkspace,
    ContextRetrievalLimits,
    StaticFactBundle,
)
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.context import (
    ChainingContextRecords,
    ContextCeilingProfile,
    ContextReadPlan,
    ContextRetrievalIntent,
    RelationQuery,
)
from sastsimi.ports.dto import MonotonicActionDeadline, TrackedFile

_CONTEXT_PLAN_ADAPTER = TypeAdapter(ContextReadPlan)


def _key(value: object) -> bytes:
    return canonical_bytes(value)


def _unique_sorted[T](values: Iterable[T]) -> tuple[T, ...]:
    by_key = {_key(value): value for value in values}
    return tuple(by_key[key] for key in sorted(by_key))


def _location_key(location: CodeLocation) -> tuple[object, ...]:
    return (
        str(location.file_path),
        location.start_line,
        location.start_column or 0,
        location.end_line,
        location.end_column or 0,
    )


def _same_location(left: CodeLocation, right: CodeLocation) -> bool:
    return _key(left) == _key(right)


def _contains(container: CodeLocation, item: CodeLocation) -> bool:
    if container.file_path != item.file_path:
        return False
    return (
        container.start_line <= item.start_line and item.end_line <= container.end_line
    )


def _node_matches(
    symbol_id: str | None,
    location: CodeLocation,
    symbol_ids: frozenset[str],
    locations: Sequence[CodeLocation],
) -> bool:
    return (symbol_id is not None and symbol_id in symbol_ids) or any(
        _same_location(location, candidate) for candidate in locations
    )


def _limits_within(
    requested: ContextRetrievalLimits,
    ceiling: ContextRetrievalLimits,
    work_timeout_ms: int,
) -> bool:
    names = (
        "max_depth",
        "max_fragments",
        "max_bytes",
        "max_requests_per_hypothesis",
        "timeout_ms",
    )
    return all(
        getattr(requested, name) <= getattr(ceiling, name) for name in names
    ) and (requested.timeout_ms <= work_timeout_ms)


def _lineage_seeds(
    lineage: ChainingContextRecords | None,
) -> tuple[tuple[CodeSymbol, ...], tuple[CodeLocation, ...], tuple[StoredDataRef, ...]]:
    if lineage is None:
        return (), (), ()
    match_id = lineage.proposal.source_primitive_match_id
    matches = tuple(
        candidate
        for candidate in lineage.chaining_result.primitive_match_candidates
        if candidate.primitive_match_id == match_id
    )
    if len(matches) != 1:
        raise ValueError("CONTEXT_LINEAGE_MISMATCH")
    match = matches[0]
    if (
        lineage.proposal.origin != "CHAINING"
        or reference(lineage.proposal) != lineage.proposal_ref
        or reference(lineage.chaining_result) != lineage.chaining_result_ref
        or tuple(
            item
            for item in lineage.chaining_result.chained_hypothesis_proposals
            if reference(item) == lineage.proposal_ref
        )
        != (lineage.proposal,)
        or match.upstream_result_ref != lineage.upstream_ref
        or match.downstream_input_ref != lineage.downstream_ref
        or lineage.upstream.result is None
        or (match.workspace_id, match.commit_id)
        != (lineage.proposal.meta.workspace_id, lineage.proposal.meta.commit_id)
        or (lineage.upstream.workspace_id, lineage.upstream.commit_id)
        != (match.workspace_id, match.commit_id)
        or (lineage.downstream.workspace_id, lineage.downstream.commit_id)
        != (match.workspace_id, match.commit_id)
        or set(match.parent_hypothesis_ids)
        != set(lineage.proposal.parent_hypothesis_ids)
        or set(match.parent_hypothesis_ids)
        != {
            lineage.upstream.source_hypothesis_id,
            lineage.downstream.source_hypothesis_id,
        }
        or set(match.parent_verification_refs)
        != {
            lineage.upstream.source_verification_ref,
            lineage.downstream.source_verification_ref,
        }
    ):
        raise ValueError("CONTEXT_LINEAGE_MISMATCH")
    downstream_matches = tuple(
        item
        for item in lineage.downstream.inputs
        if item.draft_id == match.matched_input_id
    )
    if len(downstream_matches) != 1:
        raise ValueError("CONTEXT_LINEAGE_MISMATCH")
    drafts = (
        lineage.upstream.result,
        *lineage.upstream.inputs,
        downstream_matches[0],
        *(
            item
            for item in lineage.downstream.inputs
            if item is not downstream_matches[0]
        ),
    )
    entities = _unique_sorted(
        entity for draft in drafts for entity in draft.entity_refs
    )
    locations = _unique_sorted(entity.location for entity in entities)
    if not locations:
        raise ValueError("CONTEXT_LINEAGE_START_REQUIRED")
    refs = (
        lineage.chaining_result_ref,
        lineage.upstream_ref,
        lineage.downstream_ref,
    )
    return entities, locations, refs


def _select_relations(
    query: RelationQuery,
    bundle: StaticFactBundle,
    symbol_ids: frozenset[str],
    locations: tuple[CodeLocation, ...],
) -> tuple[CodeRelation, ...]:
    if query == "CALLERS":
        return tuple(
            relation
            for relation in bundle.call_edges
            if _node_matches(
                relation.to_symbol_id, relation.to_location, symbol_ids, locations
            )
        )
    if query == "CALLEES":
        return tuple(
            relation
            for relation in bundle.call_edges
            if _node_matches(
                relation.from_symbol_id, relation.from_location, symbol_ids, locations
            )
        )
    if query == "DATA_FLOW_NEIGHBORS":
        return tuple(
            relation
            for relation in bundle.data_flow_candidates
            if _node_matches(
                relation.from_symbol_id, relation.from_location, symbol_ids, locations
            )
            or _node_matches(
                relation.to_symbol_id, relation.to_location, symbol_ids, locations
            )
        )
    if query == "ROUTE_BINDINGS":
        return tuple(
            relation
            for relation in bundle.route_bindings
            if _node_matches(
                relation.from_symbol_id, relation.from_location, symbol_ids, locations
            )
            or _node_matches(
                relation.to_symbol_id, relation.to_location, symbol_ids, locations
            )
        )
    direct_guards = tuple(
        fact
        for fact in bundle.auth_and_permission_checks
        if (fact.symbol_id is not None and fact.symbol_id in symbol_ids)
        or any(_contains(location, fact.location) for location in locations)
    )
    outgoing = tuple(
        relation
        for relation in bundle.call_edges
        if _node_matches(
            relation.from_symbol_id, relation.from_location, symbol_ids, locations
        )
    )
    target_guards = tuple(
        fact
        for fact in bundle.auth_and_permission_checks
        if any(
            (fact.symbol_id is not None and fact.symbol_id == relation.to_symbol_id)
            or _contains(relation.to_location, fact.location)
            for relation in outgoing
        )
    )
    guards = _unique_sorted((*direct_guards, *target_guards))
    guard_symbols = frozenset(
        fact.symbol_id for fact in guards if fact.symbol_id is not None
    )
    guard_locations = tuple(fact.location for fact in guards)
    return tuple(
        relation
        for relation in outgoing
        if (
            _node_matches(
                relation.to_symbol_id,
                relation.to_location,
                guard_symbols,
                guard_locations,
            )
            or any(_contains(relation.to_location, fact.location) for fact in guards)
        )
    )


def _facts_for(
    query: RelationQuery,
    bundle: StaticFactBundle,
    symbol_ids: frozenset[str],
    locations: tuple[CodeLocation, ...],
) -> tuple[CodeFact, ...]:
    if query == "DATA_FLOW_NEIGHBORS":
        candidates = tuple(
            fact
            for fact in bundle.facts()
            if fact.fact_kind in {"SOURCE", "SINK", "SANITIZER", "VALIDATOR", "OTHER"}
        )
    elif query == "AUTH_GUARDS":
        candidates = bundle.auth_and_permission_checks
    else:
        return ()
    return tuple(
        fact
        for fact in candidates
        if (fact.symbol_id is not None and fact.symbol_id in symbol_ids)
        or any(_same_location(fact.location, location) for location in locations)
        or (
            query == "AUTH_GUARDS"
            and any(_contains(location, fact.location) for location in locations)
        )
    )


def plan_context_retrieval(
    *,
    intent: ContextRetrievalIntent,
    bundle: StaticFactBundle,
    workspace: CodeWorkspace,
    work: WorkExecutionState,
    ceilings: ContextCeilingProfile,
    work_timeout_ms: int,
    lineage: ChainingContextRecords | None = None,
) -> ContextReadPlan:
    """Produce a deterministic graph/path plan without touching the filesystem."""
    if (
        not isinstance(work.meta, RecordMeta)
        or not isinstance(bundle.meta, RecordMeta)
        or work.work_type != "CONTEXT_RETRIEVAL"
        or work.status != "RUNNING"
        or work.active_attempt_id is None
        or workspace.status != "READY"
        or workspace.commit_id is None
        or (workspace.analysis_id, workspace.workspace_id, workspace.commit_id)
        != (work.meta.analysis_id, work.meta.workspace_id, work.meta.commit_id)
        or (bundle.meta.analysis_id, bundle.meta.workspace_id, bundle.meta.commit_id)
        != (work.meta.analysis_id, work.meta.workspace_id, work.meta.commit_id)
        or intent.bundle_ref.record_id != bundle.meta.record_id
        or intent.bundle_ref.content_hash != content_hash(bundle)
        or intent.proposal_ref.workspace_id != work.meta.workspace_id
        or intent.proposal_ref.commit_id != work.meta.commit_id
        or ceilings.ref.workspace_id != work.meta.workspace_id
        or ceilings.ref.commit_id != work.meta.commit_id
    ):
        raise ValueError("CONTEXT_SCOPE_MISMATCH")
    if work_timeout_ms <= 0 or not _limits_within(
        intent.requested_limits, ceilings.limits, work_timeout_ms
    ):
        raise ValueError("CONTEXT_LIMIT_EXCEEDED")

    lineage_entities, lineage_locations, raw_lineage_refs = _lineage_seeds(lineage)
    if lineage is not None:
        if (
            lineage.proposal_ref != intent.proposal_ref
            or lineage.proposal.source_primitive_match_id is None
            or any(
                entity not in lineage_entities for entity in intent.requested_entities
            )
            or any(
                location not in lineage_locations
                for location in intent.requested_locations
            )
        ):
            raise ValueError("CONTEXT_LINEAGE_MISMATCH")
    entities = list(_unique_sorted((*intent.requested_entities, *lineage_entities)))
    locations = list(
        _unique_sorted(
            (
                *intent.requested_locations,
                *lineage_locations,
                *(entity.location for entity in entities),
            )
        )
    )
    selected_relations: list[CodeRelation] = []

    for query in intent.relation_query:
        query_entities = tuple(entities)
        query_locations = tuple(locations)
        frontier_entities = query_entities
        frontier_locations = query_locations
        for _depth in range(intent.requested_limits.max_depth):
            symbol_ids = frozenset(entity.symbol_id for entity in frontier_entities)
            relations = _select_relations(query, bundle, symbol_ids, frontier_locations)
            if not relations:
                break
            selected_relations.extend(relations)
            next_locations = _unique_sorted(
                location
                for relation in relations
                for location in (relation.from_location, relation.to_location)
            )
            relation_ids = {
                identifier
                for relation in relations
                for identifier in (relation.from_symbol_id, relation.to_symbol_id)
                if identifier is not None
            }
            next_entities = _unique_sorted(
                entity
                for entity in bundle.entities
                if entity.symbol_id in relation_ids
                or any(_same_location(entity.location, item) for item in next_locations)
            )
            before = {_key(value) for value in (*entities, *locations)}
            frontier_entities = tuple(
                item for item in next_entities if _key(item) not in before
            )
            frontier_locations = tuple(
                item for item in next_locations if _key(item) not in before
            )
            entities = list(_unique_sorted((*entities, *next_entities)))
            locations = list(_unique_sorted((*locations, *next_locations)))
            if not frontier_entities and not frontier_locations:
                break
        symbol_ids = frozenset(entity.symbol_id for entity in entities)
        selected_facts = _facts_for(query, bundle, symbol_ids, tuple(locations))
        fact_locations = tuple(fact.location for fact in selected_facts)
        fact_ids = {
            fact.symbol_id for fact in selected_facts if fact.symbol_id is not None
        }
        entities = list(
            _unique_sorted(
                (
                    *entities,
                    *(
                        entity
                        for entity in bundle.entities
                        if entity.symbol_id in fact_ids
                    ),
                )
            )
        )
        locations = list(_unique_sorted((*locations, *fact_locations)))

    final_entities = _unique_sorted(entities)
    final_locations = _unique_sorted(locations)
    relations = _unique_sorted(selected_relations)
    paths = tuple(sorted({str(location.file_path) for location in final_locations}))
    if not paths:
        raise ValueError("CONTEXT_LOCATION_REQUIRED")
    for path in paths:
        _safe_git_path(path)
    lineage_refs = _unique_sorted(raw_lineage_refs)
    intent_hash = context_intent_hash(intent)
    return ContextReadPlan(
        intent_hash=intent_hash,
        workspace_id=str(workspace.workspace_id),
        commit_id=str(workspace.commit_id),
        proposal_ref=intent.proposal_ref,
        bundle_ref=intent.bundle_ref,
        ceiling_profile_ref=ceilings.ref,
        requested_limits=intent.requested_limits,
        entities=final_entities,
        locations=final_locations,
        relations=relations,
        file_paths=paths,
        lineage_refs=lineage_refs,
    )


def context_intent_hash(intent: ContextRetrievalIntent) -> str:
    normalized_intent = (
        "context_intent_v1",
        intent.proposal_ref,
        intent.bundle_ref,
        intent.requested_limits,
        _unique_sorted(intent.requested_entities),
        _unique_sorted(intent.requested_locations),
        tuple(sorted(set(intent.relation_query))),
        intent.reason,
    )
    return content_hash(normalized_intent)


def decode_context_read_plan(raw: bytes) -> ContextReadPlan:
    """Decode only the frozen closed dataclass shape used for authorization."""
    try:
        plan = _CONTEXT_PLAN_ADAPTER.validate_json(raw)
    except ValueError as error:
        raise ValueError("CONTEXT_PLAN_CHANGED") from error
    if encode_context_read_plan(plan) != raw:
        raise ValueError("CONTEXT_PLAN_CHANGED")
    return plan


def encode_context_read_plan(plan: ContextReadPlan) -> bytes:
    """Encode the frozen plan through its exact adapter before canonicalization."""
    return canonical_bytes(_CONTEXT_PLAN_ADAPTER.dump_python(plan, mode="python"))


@dataclass(frozen=True)
class ContextFragment:
    location: CodeLocation
    data: bytes


@dataclass(frozen=True)
class ContextReadObservation:
    fragments: tuple[ContextFragment, ...]
    truncated: bool
    returned_bytes: int
    replacement_paths: tuple[str, ...]
    failed_paths: tuple[str, ...]


def _safe_git_path(value: str) -> PurePosixPath:
    if not value or "\\" in value:
        raise ValueError("CONTEXT_PATH_UNSAFE")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("CONTEXT_PATH_UNSAFE")
    if len(path.parts[0]) == 2 and path.parts[0][1] == ":":
        raise ValueError("CONTEXT_PATH_UNSAFE")
    return path


def _link_like(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_nlink,
        getattr(value, "st_file_attributes", 0),
    )


def _range_bytes(text: str, location: CodeLocation) -> bytes:
    lines = text.splitlines(keepends=True)
    if location.start_line > len(lines) or location.end_line > len(lines):
        raise ValueError("CONTEXT_RANGE_INVALID")
    selected = lines[location.start_line - 1 : location.end_line]
    if location.start_column is not None and location.end_column is not None:
        first_length = len(selected[0].rstrip("\r\n"))
        last_length = len(selected[-1].rstrip("\r\n"))
        if (
            location.start_column > first_length + 1
            or location.end_column > last_length + 1
        ):
            raise ValueError("CONTEXT_RANGE_INVALID")
        if location.start_line == location.end_line:
            selected[0] = selected[0][
                location.start_column - 1 : location.end_column - 1
            ]
        else:
            selected[0] = selected[0][location.start_column - 1 :]
            selected[-1] = selected[-1][: location.end_column - 1]
    return "".join(selected).encode("utf-8")


def _coalesced(locations: Sequence[CodeLocation]) -> tuple[CodeLocation, ...]:
    result: list[CodeLocation] = []
    for location in sorted(locations, key=_location_key):
        if (
            not result
            or result[-1].file_path != location.file_path
            or (location.start_line > result[-1].end_line)
        ):
            result.append(location)
            continue
        previous = result[-1]
        result[-1] = previous.model_copy(
            update={
                "end_line": max(previous.end_line, location.end_line),
                "start_column": None,
                "end_column": None,
            }
        )
    return tuple(result)


def read_context_files(
    *,
    plan: ContextReadPlan,
    workspace_root: Path,
    tracked_files: tuple[TrackedFile, ...],
    deadline: MonotonicActionDeadline,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
    cancelled: Callable[[], bool] = lambda: False,
    sensitive_names: frozenset[str] = frozenset(
        {".env", ".env.local", "id_rsa", "id_ed25519"}
    ),
) -> ContextReadObservation:
    """Read only the authorized, tracked paths with no-follow identity checks."""
    if cancelled() or deadline.remaining_ms(monotonic_ns()) <= 0:
        return ContextReadObservation((), True, 0, (), ())
    root = workspace_root.resolve(strict=True)
    if _link_like(workspace_root) or not root.is_dir():
        raise ValueError("CONTEXT_PATH_UNSAFE")
    manifest = {item.git_path: item for item in tracked_files}
    for authorized_path in plan.file_paths:
        _safe_git_path(authorized_path)
    if set(plan.file_paths) - set(manifest):
        raise ValueError("CONTEXT_PATH_UNTRACKED")
    fragments: list[ContextFragment] = []
    replacements: set[str] = set()
    failures: set[str] = set()
    total = 0
    truncated = False
    for location in _coalesced(plan.locations):
        if len(fragments) >= plan.requested_limits.max_fragments:
            truncated = True
            break
        if cancelled() or deadline.remaining_ms(monotonic_ns()) <= 0:
            truncated = True
            break
        git_path = str(location.file_path)
        path = _safe_git_path(git_path)
        if any(part.casefold() in sensitive_names for part in path.parts):
            raise ValueError("CONTEXT_PATH_SENSITIVE")
        tracked = manifest.get(git_path)
        if tracked is None or tracked.git_mode not in {"100644", "100755"}:
            raise ValueError("CONTEXT_PATH_UNTRACKED")
        candidate = root.joinpath(*path.parts)
        current = root
        for part in path.parts:
            current /= part
            if _link_like(current):
                raise ValueError("CONTEXT_PATH_UNSAFE")
        descriptor = -1
        try:
            before = candidate.lstat()
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or getattr(before, "st_file_attributes", 0) & 0x400
                or before.st_size != tracked.size_bytes
            ):
                raise ValueError("CONTEXT_PATH_UNSAFE")
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
            flags = (
                os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(candidate, flags)
            opened = os.fstat(descriptor)
            if _identity(opened) != _identity(before):
                raise ValueError("CONTEXT_FILE_CHANGED")
            remaining = plan.requested_limits.max_bytes - total
            if opened.st_size > remaining:
                truncated = True
                break
            chunks: list[bytes] = []
            unread = opened.st_size
            while unread:
                if cancelled() or deadline.remaining_ms(monotonic_ns()) <= 0:
                    truncated = True
                    break
                chunk = os.read(descriptor, min(unread, 64 * 1024))
                if not chunk:
                    raise ValueError("CONTEXT_FILE_CHANGED")
                chunks.append(chunk)
                unread -= len(chunk)
            if truncated:
                break
            raw = b"".join(chunks)
            after = candidate.lstat()
            if _identity(after) != _identity(opened):
                raise ValueError("CONTEXT_FILE_CHANGED")
            if raw.startswith(b"version https://git-lfs.github.com/spec/v1"):
                raise ValueError("CONTEXT_LFS_POINTER")
            decoded = raw.decode("utf-8", errors="replace")
            if "\ufffd" in decoded:
                replacements.add(git_path)
            fragment = _range_bytes(decoded, location)
            if total + len(fragment) > plan.requested_limits.max_bytes:
                truncated = True
                break
            fragments.append(ContextFragment(location, fragment))
            total += len(fragment)
        except OSError:
            failures.add(git_path)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    return ContextReadObservation(
        tuple(fragments),
        truncated,
        total,
        tuple(sorted(replacements)),
        tuple(sorted(failures)),
    )


def context_request_fingerprint(
    plan: ContextReadPlan,
    analysis_id: str,
    hypothesis_id: str,
    relation_query: tuple[RelationQuery, ...] = (),
) -> str:
    return hashlib.sha256(
        canonical_bytes(
            (
                "context_request_v1",
                analysis_id,
                hypothesis_id,
                plan.workspace_id,
                plan.commit_id,
                plan.intent_hash,
                plan.proposal_ref,
                plan.bundle_ref,
                plan.ceiling_profile_ref,
                plan.requested_limits,
                plan.entities,
                plan.locations,
                relation_query,
                tuple(sorted(plan.file_paths)),
                plan.lineage_refs,
            )
        )
    ).hexdigest()
