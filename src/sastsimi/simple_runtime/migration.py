from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any

from sastsimi.contracts.refs import StoredDataRef

from .models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from .store import SimpleCheckpointStore

type RecordEntry = tuple[dict[str, Any], StoredDataRef]


def _database_path(data_dir: Path) -> Path:
    candidates = (data_dir / "db" / "sastsimi.sqlite3", data_dir / "sastsimi.sqlite3")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("SIMPLE_RUNTIME_SOURCE_DATABASE_NOT_FOUND")


def _read_records(data_dir: Path, analysis_id: str) -> list[RecordEntry]:
    database_path = _database_path(data_dir).resolve()
    connection = sqlite3.connect(
        f"file:{database_path.as_posix()}?mode=ro",
        uri=True,
    )
    try:
        rows = connection.execute(
            """
            SELECT r.payload, r.ref
            FROM records AS r
            JOIN record_revisions AS published ON published.record_id = r.record_id
            """
        ).fetchall()
    finally:
        connection.close()
    records: list[RecordEntry] = []
    for payload_json, ref_json in rows:
        payload = json.loads(payload_json)
        if payload.get("meta", {}).get("analysis_id") != analysis_id:
            continue
        try:
            ref = StoredDataRef.model_validate_json(ref_json)
        except ValueError:
            continue
        records.append((payload, ref))
    return records


def _newest(entries: list[RecordEntry]) -> RecordEntry | None:
    if not entries:
        return None
    return max(
        entries,
        key=lambda item: (
            int(item[0]["meta"].get("revision_number", 0)),
            str(item[0]["meta"].get("created_at", "")),
        ),
    )


def _checkpoint(
    identity: CheckpointIdentity,
    stage: SimpleStage,
    inputs: tuple[StoredDataRef, ...],
    outputs: tuple[StoredDataRef, ...],
    *,
    status: StageStatus = StageStatus.SUCCEEDED,
    attempt_id: str | None = None,
    recipe_ref: StoredDataRef | None = None,
    image_digest: str | None = None,
    container_id: str | None = None,
    validated_poc_ref: StoredDataRef | None = None,
) -> StageCheckpoint:
    return StageCheckpoint(
        identity=identity,
        stage=stage,
        status=status,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        output_refs=outputs,
        attempt_id=attempt_id,
        recipe_ref=recipe_ref,
        image_digest=image_digest,
        container_id=container_id,
        validated_poc_ref=validated_poc_ref,
    )


def _save_imported_once(
    store: SimpleCheckpointStore,
    checkpoint: StageCheckpoint,
) -> None:
    """Never replace progress already produced by SimpleRuntime."""

    existing = store.get(checkpoint.identity, checkpoint.stage)
    if existing is None:
        store.save_checkpoint(checkpoint)
        return
    if (
        existing.recipe_ref is None
        and checkpoint.recipe_ref is not None
        and checkpoint.image_digest is not None
    ):
        store.save_checkpoint(
            existing.model_copy(
                update={
                    "recipe_ref": checkpoint.recipe_ref,
                    "image_digest": checkpoint.image_digest,
                    "container_id": checkpoint.container_id,
                }
            )
        )


def import_existing_analysis(
    data_dir: str | Path,
    analysis_id: str,
    store: SimpleCheckpointStore,
) -> tuple[CheckpointIdentity, ...]:
    """Import only exact, proven reusable records; never mutate the old runtime."""

    records = _read_records(Path(data_dir), analysis_id)
    by_kind_hypothesis: dict[tuple[str, str | None], list[RecordEntry]] = defaultdict(
        list
    )
    for payload, ref in records:
        meta = payload["meta"]
        by_kind_hypothesis[(meta["record_type"], meta.get("hypothesis_id"))].append(
            (payload, ref)
        )

    static_entry = _newest(by_kind_hypothesis[("static_fact_bundle", None)])
    profile_entry = _newest(by_kind_hypothesis[("repository_profile", None)])
    hypotheses = by_kind_hypothesis[("vulnerability_hypothesis", None)]
    if not hypotheses:
        hypotheses = [
            entry
            for (kind, hypothesis_id), entries in by_kind_hypothesis.items()
            if kind == "vulnerability_hypothesis" and hypothesis_id is not None
            for entry in entries
        ]
    if static_entry is None or not hypotheses:
        raise ValueError("SIMPLE_RUNTIME_IMPORT_MISSING_BASELINE")

    static_payload, static_ref = static_entry
    static_meta = static_payload["meta"]
    analysis_identity = CheckpointIdentity(
        analysis_id=analysis_id,
        workspace_id=static_meta["workspace_id"],
        commit_id=static_meta["commit_id"],
        hypothesis_id=None,
    )
    profile_refs = (profile_entry[1],) if profile_entry else ()
    _save_imported_once(
        store,
        _checkpoint(
            analysis_identity,
            SimpleStage.STATIC_DONE,
            profile_refs,
            (static_ref,),
        )
    )

    newest_hypotheses: dict[str, RecordEntry] = {}
    for entry in hypotheses:
        hypothesis_id = entry[0]["meta"].get("hypothesis_id")
        if hypothesis_id is None:
            continue
        current = newest_hypotheses.get(hypothesis_id)
        if current is None or _newest([current, entry]) == entry:
            newest_hypotheses[hypothesis_id] = entry
    _save_imported_once(
        store,
        _checkpoint(
            analysis_identity,
            SimpleStage.HYPOTHESIS_DONE,
            (static_ref,),
            tuple(entry[1] for entry in newest_hypotheses.values()),
        )
    )

    identities: list[CheckpointIdentity] = []
    for hypothesis_id, (hypothesis_payload, hypothesis_ref) in sorted(
        newest_hypotheses.items()
    ):
        meta = hypothesis_payload["meta"]
        identity = CheckpointIdentity(
            analysis_id=analysis_id,
            workspace_id=meta["workspace_id"],
            commit_id=meta["commit_id"],
            hypothesis_id=hypothesis_id,
        )
        pro = _newest(by_kind_hypothesis[("pro_evidence_result", hypothesis_id)])
        con = _newest(by_kind_hypothesis[("con_evidence_result", hypothesis_id)])
        initial = _newest(
            by_kind_hypothesis[("verification_initial_assessment", hypothesis_id)]
        )
        if pro is None or con is None or initial is None:
            continue
        _save_imported_once(
            store,
            _checkpoint(
                identity,
                SimpleStage.PRO_CON_DONE,
                (hypothesis_ref, static_ref),
                (pro[1], con[1]),
            )
        )
        request = _newest(
            by_kind_hypothesis[("dynamic_reproduction_request", hypothesis_id)]
        )
        context = _newest(
            by_kind_hypothesis[("code_context_response", hypothesis_id)]
        )
        plan = _newest(by_kind_hypothesis[("reproduction_plan", hypothesis_id)])
        initial_outputs = (
            (initial[1],)
            + ((request[1],) if request else ())
            + ((plan[1],) if plan else ())
            + ((context[1],) if context else ())
        )
        _save_imported_once(
            store,
            _checkpoint(
                identity,
                SimpleStage.VERIFICATION_INITIAL_DONE,
                (pro[1], con[1]),
                initial_outputs,
                attempt_id=initial[0]["meta"].get("attempt_id"),
            )
        )

        recipes = by_kind_hypothesis[("environment_recipe", hypothesis_id)]
        built_recipes = [
            entry for entry in recipes if entry[0].get("built_image_digest")
        ]
        recipe = _newest(built_recipes)
        environments = by_kind_hypothesis[("sandbox_environment", hypothesis_id)]
        environment = _newest(environments)
        if recipe is not None:
            _save_imported_once(
                store,
                _checkpoint(
                    identity,
                    SimpleStage.POC_CANDIDATE_DONE,
                    initial_outputs,
                    (),
                    status=StageStatus.PENDING,
                    recipe_ref=recipe[1],
                    image_digest=recipe[0].get("built_image_digest"),
                    container_id=(
                        environment[0].get("container_instance_id")
                        if environment is not None
                        else None
                    ),
                )
            )

        supported_results = [
            entry
            for entry in by_kind_hypothesis[
                ("dynamic_reproduction_result", hypothesis_id)
            ]
            if entry[0].get("status") == "SUCCEEDED"
            and entry[0].get("hypothesis_outcome") == "SUPPORTED"
            and entry[0].get("poc_ref") is not None
            and entry[0].get("poc_candidate_ref") is not None
        ]
        dynamic = _newest(supported_results)
        if dynamic is not None:
            dynamic_payload, dynamic_ref = dynamic
            candidate_ref = StoredDataRef.model_validate(
                dynamic_payload["poc_candidate_ref"]
            )
            poc_ref = StoredDataRef.model_validate(dynamic_payload["poc_ref"])
            attempt_id = dynamic_payload["meta"].get("attempt_id")
            _save_imported_once(
                store,
                _checkpoint(
                    identity,
                    SimpleStage.POC_CANDIDATE_DONE,
                    initial_outputs,
                    (candidate_ref,),
                    attempt_id=attempt_id,
                    recipe_ref=recipe[1] if recipe else None,
                    image_digest=(
                        recipe[0].get("built_image_digest") if recipe else None
                    ),
                )
            )
            _save_imported_once(
                store,
                _checkpoint(
                    identity,
                    SimpleStage.POC_EXECUTION_DONE,
                    (candidate_ref,),
                    (dynamic_ref, poc_ref),
                    attempt_id=attempt_id,
                    validated_poc_ref=poc_ref,
                )
            )
        identities.append(identity)
    return tuple(identities)
