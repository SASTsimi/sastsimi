"""Database-enforced uniqueness for committed Chaining matches."""

from pathlib import Path

import pytest
from sqlalchemy import func, select

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.chaining import ChainingResult
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.chaining import ChainingMatchIdentity
from sastsimi.storage import models
from sastsimi.storage.chaining_registration import ChainingMatchReservationStore
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import upgrade
from sastsimi.storage.repositories import SQLiteRecordStore
from tests.contract.domain.canonical_fixtures import make


def _ref(kind: str, record_id: str) -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": record_id,
            "data_kind": kind,
            "content_hash": "a" * 64,
            "workspace_id": "workspace-a",
            "commit_id": "commit-a",
            "record_id": record_id,
        }
    )


def _match(
    match_id: str,
    upstream: str,
    downstream: str,
    input_id: str,
) -> ChainingMatchIdentity:
    return ChainingMatchIdentity(
        primitive_match_id=match_id,
        upstream_result_ref=_ref("primitive", upstream),
        downstream_input_ref=_ref("primitive", downstream),
        matched_input_id=input_id,
    )


def _database(tmp_path: Path) -> Database:
    database = Database(tmp_path / "runtime.db")
    upgrade(database)
    return database


def _count(database: Database) -> int:
    with database.engine.connect() as connection:
        return int(
            connection.execute(
                select(func.count()).select_from(models.chaining_match_reservations)
            ).scalar_one()
        )


def _result(
    record_id: str,
    identities: tuple[ChainingMatchIdentity, ...],
) -> ChainingResult:
    primitive_refs = tuple(
        dict.fromkeys(
            ref
            for identity in identities
            for ref in (
                identity.upstream_result_ref,
                identity.downstream_input_ref,
            )
        )
    )
    candidates = tuple(
        {
            "primitive_match_id": identity.primitive_match_id,
            "upstream_result_ref": identity.upstream_result_ref,
            "downstream_input_ref": identity.downstream_input_ref,
            "matched_input_id": identity.matched_input_id,
            "parent_hypothesis_ids": ("parent-a", "parent-b"),
            "parent_verification_refs": (
                _ref("verification_result", "verification-a"),
                _ref("verification_result", "verification-b"),
            ),
            "workspace_id": "workspace-a",
            "commit_id": "commit-a",
            "evidence_refs": (_ref("verification_result", "evidence-a"),),
            "candidate_state": "UNVALIDATED",
        }
        for identity in identities
    )
    proposals = tuple(
        make("HypothesisProposal")
        | {
            "meta": make("HypothesisProposal")["meta"]
            | {
                "record_id": f"proposal-{identity.primitive_match_id}-r1",
                "logical_record_id": f"proposal-{identity.primitive_match_id}-l1",
                "analysis_id": "analysis-a",
                "workspace_id": "workspace-a",
                "commit_id": "commit-a",
            },
            "proposal_id": f"proposal-{identity.primitive_match_id}",
            "origin": "CHAINING",
            "target_locations": (
                {
                    "workspace_id": "workspace-a",
                    "commit_id": "commit-a",
                    "file_path": "src/app.py",
                    "start_line": 1,
                    "end_line": 2,
                    "start_column": None,
                    "end_column": None,
                },
            ),
            "suspected_path": (
                {
                    "workspace_id": "workspace-a",
                    "commit_id": "commit-a",
                    "file_path": "src/app.py",
                    "start_line": 1,
                    "end_line": 2,
                    "start_column": None,
                    "end_column": None,
                },
            ),
            "parent_hypothesis_ids": ("parent-a", "parent-b"),
            "source_primitive_match_id": identity.primitive_match_id,
        }
        for identity in identities
    )
    wire = make("ChainingResult")
    wire["meta"] = wire["meta"] | {
        "record_id": record_id,
        "logical_record_id": record_id,
        "analysis_id": "analysis-a",
        "workspace_id": "workspace-a",
        "commit_id": "commit-a",
    }
    wire |= {
        "considered_primitive_refs": primitive_refs,
        "input_primitive_refs": primitive_refs,
        "primitive_match_candidates": candidates,
        "chained_hypothesis_proposals": proposals,
    }
    return ChainingResult.model_validate_json(canonical_bytes(wire))


def _reserve(
    database: Database,
    result: ChainingResult,
    identities: tuple[ChainingMatchIdentity, ...],
) -> None:
    records = SQLiteRecordStore(database)
    with database.write() as connection:
        source_ref = records.stage(connection, result)
        records.publish(connection, source_ref)
        assert isinstance(source_ref, StoredDataRef)
        ChainingMatchReservationStore(records, connection).reserve_for_result(
            source_result_ref=source_ref,
            identities=identities,
        )


def test_match_reservations_are_idempotent_for_the_same_source_result(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    identities = (_match("match-a", "upstream-a", "downstream-a", "input-a"),)
    source = _result("result-a", identities)

    _reserve(database, source, identities)
    source_ref = reference(source)
    assert isinstance(source_ref, StoredDataRef)
    records = SQLiteRecordStore(database)
    with database.write() as connection:
        ChainingMatchReservationStore(records, connection).reserve_for_result(
            source_result_ref=source_ref,
            identities=identities,
        )

    assert _count(database) == 1


def test_directional_collision_rolls_back_the_complete_reservation_batch(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    existing = (_match("existing", "upstream-b", "downstream-b", "input-b"),)
    _reserve(database, _result("result-a", existing), existing)

    candidates = (
        _match(
            "new-before-collision",
            "upstream-a",
            "downstream-a",
            "input-a",
        ),
        _match("different-id", "upstream-b", "downstream-b", "input-b"),
    )
    with pytest.raises(ValueError, match="CHAINING_MATCH_DUPLICATE"):
        _reserve(database, _result("result-b", candidates), candidates)

    assert _count(database) == 1


def test_match_id_collision_with_a_different_triple_rolls_back(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    first = (_match("shared-id", "upstream-a", "downstream-a", "input-a"),)
    _reserve(database, _result("result-a", first), first)

    second = (_match("shared-id", "upstream-b", "downstream-b", "input-b"),)
    with pytest.raises(ValueError, match="CHAINING_MATCH_DUPLICATE"):
        _reserve(database, _result("result-b", second), second)

    assert _count(database) == 1


@pytest.mark.parametrize("proposal_count", (0, 2), ids=("missing", "duplicate"))
def test_storage_rejects_match_proposal_closure_bypass(
    tmp_path: Path,
    proposal_count: int,
) -> None:
    database = _database(tmp_path)
    identities = (_match("match-a", "upstream-a", "downstream-a", "input-a"),)
    valid = _result("result-a", identities)
    proposal = valid.chained_hypothesis_proposals[0]
    invalid = valid.model_copy(
        update={"chained_hypothesis_proposals": (proposal,) * proposal_count}
    )

    with pytest.raises(ValueError, match="CHAINING_PROPOSAL_CLOSURE"):
        _reserve(database, invalid, identities)

    assert _count(database) == 0
