"""Paged static evidence candidates; Discovery outcomes are stored separately."""

from __future__ import annotations

import hashlib
import json
import stat
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol, cast
from urllib.parse import unquote, urlsplit

from pydantic import Field

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .models import CheckpointIdentity


class CandidatePageStore(Protocol):
    def candidate_cursor(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        artifact_ref: StoredDataRef,
    ) -> int: ...

    def upsert_candidate_page(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        artifact_ref: StoredDataRef,
        start_offset: int,
        end_offset: int,
        candidates: tuple[StaticCandidate, ...],
    ) -> None: ...


CandidateKind = Literal["ENTRY_POINT", "FLOW", "HINT"]
CandidateDecision = Literal["PENDING", "INCLUDE", "EXCLUDE", "UNDECIDED", "ERROR"]
CandidateDeepStatus = Literal[
    "PENDING", "RUNNING", "COMPLETE", "NO_HYPOTHESIS", "ERROR"
]


class CandidateOrigin(ContractModel):
    engine: str
    rule_id: str
    artifact_ref: StoredDataRef
    result_index: int = Field(ge=0)


class StaticCandidate(ContractModel):
    candidate_id: str
    kind: CandidateKind
    path: str
    line: int = Field(ge=0)
    end_line: int = Field(ge=0)
    evidence_ref: StoredDataRef
    origins: tuple[CandidateOrigin, ...]
    flow_identity: str | None = None
    evidence_key: str
    start_column: int = Field(default=0, ge=0)
    end_column: int = Field(default=0, ge=0)
    summary: str = ""
    evidence_excerpt: str = ""
    flow_trace: dict[str, object] | None = None
    decision: CandidateDecision = "PENDING"
    decision_reason: str = ""
    decision_evidence_refs: tuple[StoredDataRef, ...] = ()
    decision_attempt_ref: StoredDataRef | None = None
    deep_status: CandidateDeepStatus = "PENDING"


@dataclass(frozen=True, slots=True)
class RawCandidatePage:
    engine: Literal["opengrep", "codeql"]
    start_offset: int
    end_offset: int
    rows: tuple[dict[str, object], ...]


class _JsonReader:
    """Read JSON structurally in bounded chunks, retaining only one result row."""

    def __init__(self, path: Path) -> None:
        self._stream = path.open("r", encoding="utf-8")
        self._buffer = ""
        self._pos = 0

    def __enter__(self) -> _JsonReader:
        return self

    def __exit__(self, *_args: object) -> None:
        self._stream.close()

    def peek(self) -> str:
        if self._pos >= len(self._buffer):
            self._buffer = self._stream.read(64 * 1024)
            self._pos = 0
        return self._buffer[self._pos] if self._buffer else ""

    def take(self) -> str:
        value = self.peek()
        if value:
            self._pos += 1
        return value

    def whitespace(self) -> str:
        while self.peek() in {" ", "\t", "\r", "\n"}:
            self.take()
        return self.peek()

    def expect(self, expected: str) -> None:
        if self.whitespace() != expected:
            raise ValueError("CANDIDATE_RAW_JSON_INVALID")
        self.take()

    def string(self) -> str:
        if self.whitespace() != '"':
            raise ValueError("CANDIDATE_RAW_JSON_INVALID")
        chars = ['"']
        self.take()
        escaped = False
        while True:
            char = self.take()
            if not char:
                raise ValueError("CANDIDATE_RAW_JSON_INVALID")
            chars.append(char)
            if char == '"' and not escaped:
                break
            if char == "\\" and not escaped:
                escaped = True
            else:
                escaped = False
        try:
            value = json.loads("".join(chars))
        except json.JSONDecodeError as error:
            raise ValueError("CANDIDATE_RAW_JSON_INVALID") from error
        if not isinstance(value, str):
            raise ValueError("CANDIDATE_RAW_JSON_INVALID")
        return value

    def scalar(self) -> object:
        chars: list[str] = []
        while self.peek() and self.peek() not in {",", "]", "}", " ", "\t", "\r", "\n"}:
            chars.append(self.take())
        try:
            return json.loads("".join(chars))
        except json.JSONDecodeError as error:
            raise ValueError("CANDIDATE_RAW_JSON_INVALID") from error

    def skip(self, depth: int = 0) -> None:
        if depth > 128:
            raise ValueError("CANDIDATE_RAW_JSON_TOO_DEEP")
        token = self.whitespace()
        if token == "{":
            self.take()
            if self.whitespace() == "}":
                self.take()
                return
            while True:
                self.string()
                self.expect(":")
                self.skip(depth + 1)
                next_token = self.whitespace()
                if next_token == "}":
                    self.take()
                    return
                self.expect(",")
        elif token == "[":
            self.take()
            if self.whitespace() == "]":
                self.take()
                return
            while True:
                self.skip(depth + 1)
                next_token = self.whitespace()
                if next_token == "]":
                    self.take()
                    return
                self.expect(",")
        elif token == '"':
            self.string()
        elif token:
            self.scalar()
        else:
            raise ValueError("CANDIDATE_RAW_JSON_INVALID")

    def row(self) -> dict[str, object]:
        if self.whitespace() != "{":
            raise ValueError("CANDIDATE_RAW_RESULT_INVALID")
        chars: list[str] = []
        depth = 0
        in_string = False
        escaped = False
        while True:
            char = self.take()
            if not char:
                raise ValueError("CANDIDATE_RAW_JSON_INVALID")
            chars.append(char)
            if in_string:
                if char == '"' and not escaped:
                    in_string = False
                if char == "\\" and not escaped:
                    escaped = True
                else:
                    escaped = False
                continue
            if char == '"':
                in_string = True
            elif char in {"{", "["}:
                depth += 1
                if depth > 128:
                    raise ValueError("CANDIDATE_RAW_JSON_TOO_DEEP")
            elif char in {"}", "]"}:
                depth -= 1
                if depth == 0:
                    break
                if depth < 0:
                    raise ValueError("CANDIDATE_RAW_JSON_INVALID")
        try:
            value = json.loads("".join(chars))
        except json.JSONDecodeError as error:
            raise ValueError("CANDIDATE_RAW_JSON_INVALID") from error
        if not isinstance(value, dict):
            raise ValueError("CANDIDATE_RAW_RESULT_INVALID")
        return cast(dict[str, object], value)


def _raw_rows(reader: _JsonReader) -> Iterator[tuple[str, dict[str, object]]]:
    targets = {("results",): "opengrep", ("runs", "*", "results"): "codeql"}
    found = False

    def walk(
        path: tuple[str, ...], depth: int = 0
    ) -> Iterator[tuple[str, dict[str, object]]]:
        nonlocal found
        if depth > 128:
            raise ValueError("CANDIDATE_RAW_JSON_TOO_DEEP")
        engine = targets.get(path)
        if engine is not None:
            found = True
            reader.expect("[")
            if reader.whitespace() == "]":
                reader.take()
                return
            while True:
                yield engine, reader.row()
                token = reader.whitespace()
                if token == "]":
                    reader.take()
                    return
                reader.expect(",")
        elif not any(target[: len(path)] == path for target in targets):
            reader.skip(depth)
        elif reader.whitespace() == "{":
            reader.take()
            if reader.whitespace() == "}":
                reader.take()
                return
            while True:
                key = reader.string()
                reader.expect(":")
                yield from walk((*path, key), depth + 1)
                token = reader.whitespace()
                if token == "}":
                    reader.take()
                    return
                reader.expect(",")
        elif reader.whitespace() == "[":
            reader.take()
            if reader.whitespace() == "]":
                reader.take()
                return
            while True:
                yield from walk((*path, "*"), depth + 1)
                token = reader.whitespace()
                if token == "]":
                    reader.take()
                    return
                reader.expect(",")
        else:
            raise ValueError("CANDIDATE_RAW_JSON_INVALID")

    yield from walk(())
    if reader.whitespace():
        raise ValueError("CANDIDATE_RAW_JSON_INVALID")
    if not found:
        raise ValueError("CANDIDATE_RAW_RESULTS_MISSING")


def _verified_artifact_path(
    artifacts: SimpleArtifactRepository, ref: StoredDataRef
) -> Path:
    identity = artifacts.identity
    if (
        ref.record_id is not None
        or ref.data_kind != "artifact"
        or str(ref.stored_data_id) != ref.content_hash
        or str(ref.workspace_id) != identity.workspace_id
        or str(ref.commit_id) != identity.commit_id
    ):
        raise ValueError("CANDIDATE_RAW_REF_SCOPE_MISMATCH")
    path = artifacts.artifacts.path_for(ref.content_hash)
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(artifacts.artifacts.root):
        raise ValueError("CANDIDATE_RAW_PATH_UNSAFE")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise ValueError("CANDIDATE_RAW_PATH_UNSAFE")
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != ref.content_hash:
        raise ValueError("CANDIDATE_RAW_HASH_MISMATCH")
    return path


def iter_raw_candidate_pages(
    artifacts: SimpleArtifactRepository,
    artifact_ref: StoredDataRef,
    *,
    after_offset: int = 0,
    page_size: int = 100,
) -> Iterator[RawCandidatePage]:
    """Yield verified raw hits in bounded pages; offsets refer to hit indexes."""

    if after_offset < 0 or page_size <= 0:
        raise ValueError("CANDIDATE_PAGE_ARGUMENT_INVALID")
    path = _verified_artifact_path(artifacts, artifact_ref)
    before = path.stat()
    with _JsonReader(path) as reader:
        rows: list[dict[str, object]] = []
        offset = 0
        page_engine: Literal["opengrep", "codeql"] | None = None
        for engine, row in _raw_rows(reader):
            if offset >= after_offset:
                if rows and page_engine != engine:
                    yield RawCandidatePage(
                        page_engine or "opengrep",
                        offset - len(rows),
                        offset,
                        tuple(rows),
                    )
                    rows = []
                page_engine = cast(Literal["opengrep", "codeql"], engine)
                rows.append(row)
                if len(rows) >= page_size:
                    yield RawCandidatePage(
                        page_engine, offset + 1 - len(rows), offset + 1, tuple(rows)
                    )
                    rows = []
            offset += 1
        if rows:
            yield RawCandidatePage(
                page_engine or "opengrep", offset - len(rows), offset, tuple(rows)
            )
        if after_offset > offset:
            raise ValueError("CANDIDATE_CURSOR_PAST_END")
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("CANDIDATE_RAW_CHANGED")


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, dict) else {}


def _path(value: object, workspace: Path | None = None) -> str:
    raw = str(value or "").replace("\\", "/")
    parsed = Path(raw)
    if parsed.is_absolute():
        if workspace is None:
            raise ValueError("CANDIDATE_PATH_UNSAFE")
        try:
            root = workspace.resolve(strict=True)
            resolved = parsed.resolve(strict=True)
            relative = resolved.relative_to(root)
        except (OSError, ValueError) as error:
            raise ValueError("CANDIDATE_PATH_UNSAFE") from error
        return relative.as_posix()
    if raw.startswith("/") or ":" in raw or ".." in raw.split("/"):
        raise ValueError("CANDIDATE_PATH_UNSAFE")
    normalized = PurePosixPath(raw).as_posix()
    return "" if normalized == "." else normalized


def _line(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("CANDIDATE_LOCATION_INVALID")
    try:
        result = int(value)
    except ValueError as error:
        raise ValueError("CANDIDATE_LOCATION_INVALID") from error
    if result < 0:
        raise ValueError("CANDIDATE_LOCATION_INVALID")
    return result


def _sarif_location(
    row: Mapping[str, object], workspace: Path | None
) -> tuple[str, int, int, int, int]:
    locations = row.get("locations")
    if not isinstance(locations, list) or not locations:
        return "", 0, 0, 0, 0
    first = _mapping(locations[0])
    physical = _mapping(first.get("physicalLocation"))
    artifact = _mapping(physical.get("artifactLocation"))
    region = _mapping(physical.get("region"))
    start = _line(region.get("startLine"))
    start_column = _line(region.get("startColumn"))
    end_column = _line(
        region.get("endColumn") if region.get("endColumn") is not None else start_column
    )
    raw_uri = str(artifact.get("uri") or "")
    uri = urlsplit(raw_uri)
    if (uri.scheme and uri.scheme != "file") or uri.netloc not in {
        "",
        "localhost",
    }:
        raise ValueError("CANDIDATE_PATH_UNSAFE")
    if uri.query or uri.fragment:
        raise ValueError("CANDIDATE_PATH_UNSAFE")
    try:
        decoded_path = unquote(uri.path, errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("CANDIDATE_PATH_UNSAFE") from error
    if (
        uri.scheme == "file"
        and decoded_path.startswith("/")
        and len(decoded_path) > 2
        and decoded_path[2] == ":"
    ):
        decoded_path = decoded_path[1:]
    return (
        _path(decoded_path, workspace),
        start,
        _line(region.get("endLine") or start),
        start_column,
        end_column,
    )


def _flow_trace(row: Mapping[str, object], engine: str) -> dict[str, object] | None:
    if engine == "codeql":
        flows = row.get("codeFlows")
        if isinstance(flows, list) and flows:
            return {"codeFlows": flows}
        return None
    trace = _mapping(row.get("extra")).get("dataflow_trace")
    return cast(dict[str, object], trace) if isinstance(trace, dict) else None


def _codeql_flow_rows(
    row: Mapping[str, object],
) -> tuple[Mapping[str, object], ...]:
    """Keep each SARIF thread flow separate without losing its raw result index."""

    flows = row.get("codeFlows")
    if not isinstance(flows, list) or not flows:
        return (row,)
    if len(flows) == 1:
        threads = _mapping(flows[0]).get("threadFlows")
        if not isinstance(threads, list) or len(threads) <= 1:
            return (row,)
    variants: list[Mapping[str, object]] = []
    for flow in flows:
        threads = _mapping(flow).get("threadFlows")
        if isinstance(threads, list) and len(threads) > 1:
            for thread in threads:
                single_flow = dict(_mapping(flow))
                single_flow["threadFlows"] = [thread]
                variants.append({**row, "codeFlows": [single_flow]})
        else:
            variants.append({**row, "codeFlows": [flow]})
    return tuple(variants)


def _match_hash(row: Mapping[str, object]) -> str | None:
    """Fingerprint match-specific values without engine or location metadata."""

    extra = _mapping(row.get("extra"))
    bindings: dict[str, object] = {}
    for name, raw in _mapping(extra.get("metavars")).items():
        binding = _mapping(raw)
        if "abstract_content" in binding:
            bindings[name] = binding["abstract_content"]
        elif "value" in binding:
            bindings[name] = binding["value"]
        elif binding:
            remaining = {
                key: value
                for key, value in binding.items()
                if key not in {"start", "end"}
            }
            if remaining:
                bindings[name] = remaining
        elif raw is not None:
            bindings[name] = raw

    match: dict[str, object] = {}
    if bindings:
        match["metavars"] = bindings
    conditions = extra.get("conditions")
    if conditions is None:
        conditions = row.get("conditions")
    if conditions:
        match["conditions"] = conditions
    return hashlib.sha256(canonical_bytes(match)).hexdigest() if match else None


def _sarif_hint_hash(row: Mapping[str, object]) -> str | None:
    """Retain SARIF evidence beyond the primary location and result message."""

    supplemental: dict[str, object] = {}
    locations = row.get("locations")
    if isinstance(locations, list) and len(locations) > 1:
        supplemental["secondary_locations"] = locations[1:]
    for key in ("relatedLocations", "properties"):
        value = row.get(key)
        if value:
            supplemental[key] = value
    if not supplemental:
        return None
    return hashlib.sha256(canonical_bytes(supplemental)).hexdigest()


def _kind(
    row: Mapping[str, object], engine: str, trace: dict[str, object] | None
) -> CandidateKind:
    if trace is not None:
        if engine == "codeql":
            flows = trace.get("codeFlows")
            if isinstance(flows, list):
                for flow in flows:
                    threads = _mapping(flow).get("threadFlows")
                    if not isinstance(threads, list):
                        continue
                    for thread in threads:
                        locations = _mapping(thread).get("locations")
                        if isinstance(locations, list) and len(locations) >= 2:
                            return "FLOW"
        elif (
            trace.get("taint_source") is not None
            and trace.get("taint_sink") is not None
            and "intermediate_vars" in trace
        ):
            return "FLOW"
    extra = _mapping(row.get("extra"))
    metadata = _mapping(extra.get("metadata"))
    if metadata.get("candidate_kind") == "ENTRY_POINT":
        return "ENTRY_POINT"
    return "HINT"


def normalize_candidate_page(
    identity: CheckpointIdentity,
    scope_fingerprint: str,
    engine: str,
    artifact_ref: StoredDataRef,
    rows: Sequence[Mapping[str, object]],
    start_offset: int = 0,
    *,
    workspace: Path | None = None,
) -> tuple[StaticCandidate, ...]:
    """Normalize one bounded raw-result page without inventing source-to-sink flow."""

    if not scope_fingerprint or not engine or start_offset < 0:
        raise ValueError("CANDIDATE_SCOPE_INVALID")
    if (
        str(artifact_ref.workspace_id) != identity.workspace_id
        or str(artifact_ref.commit_id) != identity.commit_id
    ):
        raise ValueError("CANDIDATE_RAW_REF_SCOPE_MISMATCH")
    result: list[StaticCandidate] = []
    for index, row in enumerate(rows, start_offset):
        if engine == "codeql":
            variants = _codeql_flow_rows(row)
            if len(variants) != 1 or variants[0] is not row:
                seen_ids: set[str] = set()
                for variant in variants:
                    for candidate in normalize_candidate_page(
                        identity,
                        scope_fingerprint,
                        engine,
                        artifact_ref,
                        (variant,),
                        index,
                        workspace=workspace,
                    ):
                        if candidate.candidate_id not in seen_ids:
                            result.append(candidate)
                            seen_ids.add(candidate.candidate_id)
                continue
        row_engine = engine
        if engine == "codeql":
            path, line, end_line, start_column, end_column = _sarif_location(
                row, workspace
            )
            message = _mapping(row.get("message"))
            summary = str(message.get("text") or "")
            excerpt = summary
            rule_id = str(row.get("ruleId") or "")
        else:
            path = _path(row.get("path"), workspace)
            start = _mapping(row.get("start"))
            end = _mapping(row.get("end"))
            line = _line(start.get("line"))
            end_line = _line(end.get("line") or line)
            start_column = _line(
                start.get("col")
                if start.get("col") is not None
                else start.get("column")
            )
            end_column = _line(
                end.get("col")
                if end.get("col") is not None
                else end.get("column")
                if end.get("column") is not None
                else start_column
            )
            extra = _mapping(row.get("extra"))
            summary = str(extra.get("message") or "")
            excerpt = str(extra.get("lines") or summary)
            rule_id = str(row.get("check_id") or "")
        trace = _flow_trace(row, engine)
        kind = _kind(row, engine, trace)
        trace_hash = (
            hashlib.sha256(canonical_bytes(trace)).hexdigest()
            if trace is not None
            else None
        )
        semantic_key = row.get("semantic_key")
        if semantic_key is None:
            metadata = _mapping(_mapping(row.get("extra")).get("metadata"))
            semantic_key = metadata.get("semantic_key")
        if semantic_key is not None and kind == "FLOW" and trace_hash is not None:
            evidence_key = f"semantic:{semantic_key}:trace:{trace_hash}"
        elif semantic_key is not None:
            evidence_key = f"semantic:{semantic_key}"
        elif trace_hash is not None:
            evidence_key = f"trace:{trace_hash}"
        else:
            evidence_key = f"hint:{row_engine}:{rule_id}:{excerpt}"
        if kind == "HINT" and engine == "codeql":
            match_hash = _sarif_hint_hash(row)
        elif kind in {"FLOW", "HINT", "ENTRY_POINT"}:
            match_hash = _match_hash(row)
        else:
            match_hash = None
        if match_hash is not None:
            evidence_key = f"{evidence_key}:match:{match_hash}"
        stable = {
            "scope_fingerprint": scope_fingerprint,
            "commit_id": identity.commit_id,
            "kind": kind,
            "path": path,
            "line": line,
            "end_line": end_line,
            "evidence_key": evidence_key,
        }
        if start_column or end_column:
            stable["start_column"] = start_column
            stable["end_column"] = end_column
        candidate_id = hashlib.sha256(canonical_bytes(stable)).hexdigest()
        result.append(
            StaticCandidate(
                candidate_id=candidate_id,
                kind=kind,
                path=path,
                line=line,
                end_line=end_line,
                start_column=start_column,
                end_column=end_column,
                evidence_ref=artifact_ref,
                origins=(
                    CandidateOrigin(
                        engine=row_engine,
                        rule_id=rule_id,
                        artifact_ref=artifact_ref,
                        result_index=index,
                    ),
                ),
                flow_identity=trace_hash if kind == "FLOW" else None,
                evidence_key=evidence_key,
                summary=summary,
                evidence_excerpt=excerpt,
                flow_trace=trace,
            )
        )
    return tuple(result)


def ingest_static_candidates(
    identity: CheckpointIdentity,
    scope_fingerprint: str,
    static_bundle_ref: StoredDataRef,
    artifacts: SimpleArtifactRepository,
    store: CandidatePageStore,
    *,
    page_size: int = 100,
    workspace: Path | None = None,
) -> int:
    """Resume exact static raw artifacts and persist every candidate before triage."""

    if identity.hypothesis_id is not None or artifacts.identity != identity:
        raise ValueError("CANDIDATE_SCOPE_INVALID")
    bundle = json.loads(artifacts.read(static_bundle_ref))
    if (
        not isinstance(bundle, dict)
        or bundle.get("kind") != "simple_static_fact_bundle"
    ):
        raise ValueError("CANDIDATE_STATIC_BUNDLE_INVALID")
    engine_refs = bundle.get("engine_raw_refs", [])
    engine_sources = bundle.get("engine_raw_sources", [])
    tool_refs = bundle.get("tool_result_refs", [])
    if (
        not isinstance(engine_refs, list)
        or not isinstance(engine_sources, list)
        or not isinstance(tool_refs, list)
    ):
        raise ValueError("CANDIDATE_STATIC_BUNDLE_INVALID")
    selected: list[
        tuple[StoredDataRef, list[tuple[str, frozenset[tuple[str, str]] | None]]]
    ] = []
    positions: dict[str, int] = {}

    def add_source(
        ref: StoredDataRef,
        engine: str,
        verified_pairs: frozenset[tuple[str, str]] | None,
    ) -> None:
        position = positions.get(ref.content_hash)
        if position is None:
            positions[ref.content_hash] = len(selected)
            selected.append((ref, [(engine, verified_pairs)]))
        elif (engine, verified_pairs) not in selected[position][1]:
            selected[position][1].append((engine, verified_pairs))

    if engine_refs and not engine_sources:
        raise ValueError("CANDIDATE_PROOF_MISSING")
    source_hashes: set[str] = set()
    for source in engine_sources:
        if not isinstance(source, dict) or source.get("engine") not in {
            "opengrep",
            "semgrep",
        }:
            raise ValueError("CANDIDATE_STATIC_BUNDLE_INVALID")
        ref = StoredDataRef.model_validate(source.get("ref"))
        raw_pairs = source.get("verified_pairs")
        if not isinstance(raw_pairs, list):
            raise ValueError("CANDIDATE_PROOF_MISSING")
        pairs: set[tuple[str, str]] = set()
        for item in raw_pairs:
            if not isinstance(item, dict):
                raise ValueError("CANDIDATE_PROOF_INVALID")
            path = _path(item.get("path"))
            rule_id = item.get("rule_id")
            if not path or not isinstance(rule_id, str) or not rule_id:
                raise ValueError("CANDIDATE_PROOF_INVALID")
            pairs.add((path, rule_id))
        source_hashes.add(ref.content_hash)
        add_source(ref, str(source["engine"]), frozenset(pairs))
    expected_hashes = {
        StoredDataRef.model_validate(raw).content_hash for raw in engine_refs
    }
    if not source_hashes <= expected_hashes:
        raise ValueError("CANDIDATE_STATIC_BUNDLE_INVALID")
    # Bootstrap's tool refs are AST, merged OpenGrep, optional CodeQL SARIF.
    # Do not treat the location-merged projection as an unproven source.
    for raw in tool_refs[2:]:
        add_source(StoredDataRef.model_validate(raw), "codeql", None)
    added = 0
    for ref, sources in selected:
        offset = store.candidate_cursor(identity, scope_fingerprint, ref)
        for page in iter_raw_candidate_pages(
            artifacts, ref, after_offset=offset, page_size=page_size
        ):
            retained: list[StaticCandidate] = []
            for position, row in enumerate(page.rows, page.start_offset):
                first_engine = "codeql" if page.engine == "codeql" else sources[0][0]
                normalized = normalize_candidate_page(
                    identity,
                    scope_fingerprint,
                    first_engine,
                    ref,
                    (row,),
                    position,
                    workspace=workspace,
                )
                for first in normalized:
                    pair = (first.path, first.origins[0].rule_id)
                    eligible = [
                        engine
                        for engine, verified_pairs in sources
                        if verified_pairs is None or pair in verified_pairs
                    ]
                    if not eligible:
                        continue
                    primary = (
                        first
                        if first_engine == eligible[0]
                        else normalize_candidate_page(
                            identity,
                            scope_fingerprint,
                            eligible[0],
                            ref,
                            (row,),
                            position,
                            workspace=workspace,
                        )[0]
                    )
                    if len(eligible) > 1:
                        primary = primary.model_copy(
                            update={
                                "origins": tuple(
                                    origin.model_copy(update={"engine": engine})
                                    for origin in primary.origins
                                    for engine in eligible
                                )
                            }
                        )
                    retained.append(primary)
            store.upsert_candidate_page(
                identity,
                scope_fingerprint,
                ref,
                page.start_offset,
                page.end_offset,
                tuple(retained),
            )
            added += len(retained)
    return added
