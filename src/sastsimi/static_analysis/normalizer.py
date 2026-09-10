"""Pure deterministic fan-in for verified static-tool observations."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.ids import GapId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, validate_exact_ref
from sastsimi.contracts.static import (
    CodeFact,
    CodeLocation,
    CodeRelation,
    CodeSymbol,
    CodeWorkspace,
    DataGap,
    RuleExecutionRecord,
    StaticFactBundle,
    StaticToolProfile,
    ToolRunResult,
    ToolSource,
    validate_rule_execution,
)
from sastsimi.ports.dto import CandidateLocation, StaticToolObservation

type RawDecoder = Callable[
    [bytes, ToolRunResult, StaticToolProfile, tuple[str, ...]], StaticToolObservation
]
type DecoderKey = tuple[str, str, str, str]


@dataclass(frozen=True)
class StaticNormalizationInput:
    result_ref: StoredDataRef
    result: ToolRunResult
    profile_ref: StoredDataRef
    profile: StaticToolProfile
    raw_bytes: bytes | None
    rule_execution: RuleExecutionRecord | None = None
    catalog_rule_ids: tuple[str, ...] = ()


def decoder_key(
    profile_ref: StoredDataRef, tool_name: str, tool_version: str
) -> DecoderKey:
    if profile_ref.record_id is None:
        raise ValueError("STATIC_DECODER_PROFILE_INVALID")
    return (
        str(profile_ref.record_id),
        profile_ref.content_hash,
        tool_name,
        tool_version,
    )


def _stable(prefix: str, value: object) -> str:
    return prefix + "-" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _location(workspace: CodeWorkspace, candidate: CandidateLocation) -> CodeLocation:
    if workspace.commit_id is None:
        raise ValueError("WORKSPACE_NOT_READY")
    return CodeLocation(
        workspace_id=workspace.workspace_id,
        commit_id=workspace.commit_id,
        file_path=candidate.file_path,
        start_line=candidate.start_line,
        start_column=candidate.start_column,
        end_line=candidate.end_line,
        end_column=candidate.end_column,
    )


def _contains(outer: CodeLocation, inner: CodeLocation) -> bool:
    if outer.file_path != inner.file_path:
        return False
    outer_start = (outer.start_line, outer.start_column or 0)
    outer_end = (outer.end_line, outer.end_column or 2**31)
    inner_start = (inner.start_line, inner.start_column or 0)
    inner_end = (inner.end_line, inner.end_column or 2**31)
    return outer_start <= inner_start and inner_end <= outer_end


def _span(location: CodeLocation) -> tuple[int, int]:
    return (
        location.end_line - location.start_line,
        (location.end_column or 2**31) - (location.start_column or 0),
    )


class StaticNormalizer:
    """Normalize only verified bytes through an immutable exact decoder registry."""

    def __init__(self, decoders: Mapping[DecoderKey, RawDecoder]) -> None:
        if len(decoders) != len(set(decoders)):
            raise ValueError("STATIC_DECODER_REGISTRY_INVALID")
        self._decoders = MappingProxyType(dict(decoders))

    def normalize(
        self,
        *,
        bundle_meta: RecordMeta,
        workspace: CodeWorkspace,
        materials: tuple[StaticNormalizationInput, ...],
    ) -> StaticFactBundle:
        if workspace.status != "READY" or workspace.commit_id is None:
            raise ValueError("WORKSPACE_NOT_READY")
        if (
            bundle_meta.attempt_id is not None
            or bundle_meta.workspace_id != workspace.workspace_id
            or bundle_meta.commit_id != workspace.commit_id
            or bundle_meta.analysis_id != workspace.analysis_id
        ):
            raise ValueError("STATIC_NORMALIZATION_SCOPE_MISMATCH")
        ordered = tuple(
            sorted(
                materials,
                key=lambda item: (
                    item.result.tool_name,
                    item.result.tool_version,
                    str(item.result.meta.attempt_id),
                    str(item.result.meta.record_id),
                ),
            )
        )
        attempts = tuple(item.result.meta.attempt_id for item in ordered)
        if None in attempts or len(attempts) != len(set(attempts)):
            raise ValueError("STATIC_TOOL_ATTEMPT_DUPLICATE")

        decoded: list[tuple[StaticNormalizationInput, StaticToolObservation]] = []
        for material in ordered:
            self._validate_material(bundle_meta, material)
            if material.result.status not in {"SUCCEEDED", "PARTIAL"}:
                continue
            raw = material.raw_bytes
            if raw is None or material.result.raw_result_ref is None:
                raise ValueError("RAW_RESULT_REQUIRED")
            if (
                hashlib.sha256(raw).hexdigest()
                != material.result.raw_result_ref.content_hash
            ):
                raise ValueError("HASH_MISMATCH")
            try:
                decoder = self._decoders[
                    decoder_key(
                        material.profile_ref,
                        material.result.tool_name,
                        material.result.tool_version,
                    )
                ]
            except KeyError as error:
                raise ValueError("STATIC_DECODER_NOT_FOUND") from error
            observation = decoder(
                raw,
                material.result,
                material.profile,
                material.catalog_rule_ids,
            )
            if (
                observation.raw_output != raw
                or (
                    observation.tool_name,
                    observation.tool_version,
                    observation.tool_kind,
                    observation.status,
                )
                != (
                    material.result.tool_name,
                    material.result.tool_version,
                    material.result.tool_kind,
                    material.result.status,
                )
                or observation.analyzed_paths != material.result.coverage.analyzed_paths
                or observation.skipped_paths != material.result.coverage.skipped_paths
                or observation.analyzed_languages
                != material.result.coverage.analyzed_languages
                or observation.skipped_languages
                != material.result.coverage.skipped_languages
            ):
                raise ValueError("STATIC_DECODER_OUTPUT_MISMATCH")
            decoded.append((material, observation))
        if not decoded:
            raise ValueError("STATIC_NORMALIZATION_NO_USABLE_INPUT")

        symbols, source_symbol_ids, ast_symbols = self._symbols(workspace, decoded)
        facts: list[CodeFact] = []
        relations: list[CodeRelation] = []
        normalization_gaps: list[DataGap] = []
        for material, observation in decoded:
            attempt_id = material.result.meta.attempt_id
            raw_result_ref = material.result.raw_result_ref
            if attempt_id is None or raw_result_ref is None:
                raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
            source = ToolSource(
                attempt_id=attempt_id,
                tool_name=material.result.tool_name,
                tool_version=material.result.tool_version,
                rule_id=None,
                raw_result_ref=raw_result_ref,
            )
            local = source_symbol_ids[str(material.result.meta.attempt_id)]
            for candidate_fact in observation.facts:
                location = _location(workspace, candidate_fact.location)
                symbol_id = self._resolve_symbol(
                    candidate_fact.symbol_source_key, location, local, ast_symbols
                )
                producer = source.model_copy(update={"rule_id": candidate_fact.rule_id})
                self._validate_rule_source(material, candidate_fact.rule_id)
                facts.append(
                    CodeFact(
                        fact_id=_stable(
                            "fact",
                            (
                                candidate_fact.fact_kind,
                                symbol_id,
                                location,
                                producer,
                            ),
                        ),
                        fact_kind=candidate_fact.fact_kind,  # type: ignore[arg-type]
                        symbol_id=symbol_id,
                        location=location,
                        producer=producer,
                    )
                )
            for candidate_relation in observation.relations:
                from_location = _location(workspace, candidate_relation.from_location)
                to_location = _location(workspace, candidate_relation.to_location)
                from_symbol = self._resolve_symbol(
                    candidate_relation.from_symbol_source_key,
                    from_location,
                    local,
                    ast_symbols,
                )
                to_symbol = self._resolve_symbol(
                    candidate_relation.to_symbol_source_key,
                    to_location,
                    local,
                    ast_symbols,
                )
                producer = source.model_copy(
                    update={"rule_id": candidate_relation.rule_id}
                )
                self._validate_rule_source(material, candidate_relation.rule_id)
                relations.append(
                    CodeRelation(
                        relation_id=_stable(
                            "relation",
                            (
                                candidate_relation.relation_kind,
                                from_symbol,
                                from_location,
                                to_symbol,
                                to_location,
                                producer,
                            ),
                        ),
                        relation_kind=candidate_relation.relation_kind,  # type: ignore[arg-type]
                        from_symbol_id=from_symbol,
                        from_location=from_location,
                        to_symbol_id=to_symbol,
                        to_location=to_location,
                        producer=producer,
                    )
                )
                if from_symbol is None or to_symbol is None:
                    normalization_gaps.append(
                        self._gap(
                            bundle_meta, candidate_relation.source_key, from_location
                        )
                    )

        symbols = tuple(sorted(set(symbols), key=lambda item: item.symbol_id))
        facts = list({item.fact_id: item for item in facts}.values())
        relations = list({item.relation_id: item for item in relations}.values())
        all_locations = tuple(
            sorted(
                {
                    canonical_bytes(item).decode(): item
                    for item in (
                        *(symbol.location for symbol in symbols),
                        *(fact.location for fact in facts),
                        *(relation.from_location for relation in relations),
                        *(relation.to_location for relation in relations),
                    )
                }.values(),
                key=lambda item: (
                    item.file_path,
                    item.start_line,
                    item.start_column or 0,
                    item.end_line,
                    item.end_column or 0,
                ),
            )
        )
        all_gaps = tuple(
            sorted(
                (
                    *(gap for material in ordered for gap in material.result.gaps),
                    *normalization_gaps,
                ),
                key=lambda item: str(item.gap_id),
            )
        )
        all_errors = tuple(
            sorted(
                (error for material in ordered for error in material.result.errors),
                key=lambda item: str(item.error_id),
            )
        )
        return StaticFactBundle(
            meta=bundle_meta,
            entities=symbols,
            locations=all_locations,
            source_candidates=self._facts(facts, "SOURCE"),
            sink_candidates=self._facts(facts, "SINK"),
            sanitizer_candidates=self._facts(facts, "SANITIZER"),
            validator_candidates=self._facts(facts, "VALIDATOR"),
            auth_and_permission_checks=tuple(
                sorted(
                    (
                        fact
                        for fact in facts
                        if fact.fact_kind in {"AUTH_CHECK", "PERMISSION_CHECK"}
                    ),
                    key=lambda item: item.fact_id,
                )
            ),
            other_facts=self._facts(facts, "OTHER"),
            call_edges=self._relations(
                relations, {"CALL", "IMPORT", "INHERITANCE", "OTHER"}
            ),
            data_flow_candidates=self._relations(relations, {"DATA_FLOW"}),
            route_bindings=self._relations(relations, {"ROUTE_BINDING"}),
            tool_runs=tuple(item.result for item in ordered),
            gaps=all_gaps,
            errors=all_errors,
        )

    @staticmethod
    def _validate_material(
        bundle_meta: RecordMeta, material: StaticNormalizationInput
    ) -> None:
        validate_exact_ref(
            material.result_ref,
            material.result.meta,
            content_hash(material.result),
            analysis_id=bundle_meta.analysis_id,
        )
        validate_exact_ref(
            material.profile_ref,
            material.profile.meta,
            content_hash(material.profile),
            analysis_id=bundle_meta.analysis_id,
        )
        if (
            material.result.meta.workspace_id != bundle_meta.workspace_id
            or material.result.meta.commit_id != bundle_meta.commit_id
            or material.profile.meta.workspace_id != bundle_meta.workspace_id
            or material.profile.meta.commit_id != bundle_meta.commit_id
            or material.result.meta.attempt_id is None
            or material.profile.status != "APPROVED"
            or material.profile.purpose not in {"FIXTURE", "EVALUATION"}
            or (
                material.result.tool_name,
                material.result.tool_version,
                material.result.tool_kind,
            )
            != (
                material.profile.tool_name,
                material.profile.expected_version,
                material.profile.tool_kind,
            )
        ):
            raise ValueError("STATIC_NORMALIZATION_INPUT_MISMATCH")
        if material.rule_execution is not None:
            validate_rule_execution(
                material.result,
                material.rule_execution,
                material.catalog_rule_ids,
            )

    @staticmethod
    def _symbols(
        workspace: CodeWorkspace,
        decoded: list[tuple[StaticNormalizationInput, StaticToolObservation]],
    ) -> tuple[
        tuple[CodeSymbol, ...], dict[str, dict[str, str]], tuple[CodeSymbol, ...]
    ]:
        values: dict[str, CodeSymbol] = {}
        ast_values: dict[str, CodeSymbol] = {}
        sources: dict[str, dict[str, str]] = {}
        for material, observation in decoded:
            attempt = str(material.result.meta.attempt_id)
            local: dict[str, str] = {}
            for candidate in observation.symbols:
                location = _location(workspace, candidate.location)
                symbol_id = _stable(
                    "symbol",
                    (
                        candidate.symbol_kind,
                        candidate.native_kind,
                        candidate.name,
                        location,
                    ),
                )
                symbol = CodeSymbol(
                    symbol_id=symbol_id,
                    symbol_kind=candidate.symbol_kind,  # type: ignore[arg-type]
                    native_kind=candidate.native_kind,
                    name=candidate.name,
                    location=location,
                )
                values[symbol_id] = symbol
                if material.result.tool_kind == "STRUCTURE":
                    ast_values[symbol_id] = symbol
                local[candidate.source_key] = symbol_id
            sources[attempt] = local
        return tuple(values.values()), sources, tuple(ast_values.values())

    @staticmethod
    def _resolve_symbol(
        source_key: str | None,
        location: CodeLocation,
        local: Mapping[str, str],
        symbols: tuple[CodeSymbol, ...],
    ) -> str | None:
        if source_key is not None and source_key in local:
            return local[source_key]
        containing = [item for item in symbols if _contains(item.location, location)]
        if not containing:
            return None
        narrowest = min(_span(item.location) for item in containing)
        matches = [item for item in containing if _span(item.location) == narrowest]
        return matches[0].symbol_id if len(matches) == 1 else None

    @staticmethod
    def _validate_rule_source(
        material: StaticNormalizationInput, rule_id: str | None
    ) -> None:
        if rule_id is None:
            return
        record = material.rule_execution
        if record is None:
            raise ValueError("RULE_EXECUTION_REQUIRED")
        matches = tuple(rule for rule in record.rules if rule.rule_id == rule_id)
        if (
            len(matches) != 1
            or matches[0].execution_status != "EXECUTED"
            or not matches[0].hit_count
        ):
            raise ValueError("FACT_WITHOUT_RAW_HIT")

    @staticmethod
    def _gap(meta: RecordMeta, source_key: str, location: CodeLocation) -> DataGap:
        return DataGap(
            gap_id=GapId(_stable("gap", (source_key, location))),
            stage="STATIC_ANALYSIS",
            code="STATIC_SYMBOL_UNRESOLVED",
            reason="MISSING",
            description="A static relation endpoint has no unique containing symbol",
            affected_paths=(location.file_path,),
            affected_languages=(),
            affected_locations=(location,),
            retryable=False,
            related_record_ids=(),
            created_at=meta.created_at,
        )

    @staticmethod
    def _facts(values: list[CodeFact], kind: str) -> tuple[CodeFact, ...]:
        return tuple(
            sorted(
                (item for item in values if item.fact_kind == kind),
                key=lambda item: item.fact_id,
            )
        )

    @staticmethod
    def _relations(
        values: list[CodeRelation], kinds: set[str]
    ) -> tuple[CodeRelation, ...]:
        return tuple(
            sorted(
                (item for item in values if item.relation_kind in kinds),
                key=lambda item: item.relation_id,
            )
        )
