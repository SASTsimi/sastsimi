"""Fail-closed storage checks for Chaining provenance and transaction scope."""

from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.chaining import PinnedChainingUniverse
from sastsimi.storage.chaining_projection import _expected_lineage_exclusions
from sastsimi.storage.chaining_registration import (
    ChainingCommittedSourceStore,
    ChainingMatchReservationStore,
)
from sastsimi.storage.repositories import SQLiteRecordStore
from tests.integration.chaining.test_match_uniqueness import (
    _database,
    _match,
    _result,
)


def test_match_reservation_rejects_identities_not_bound_to_the_exact_result(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    expected = (_match("match-a", "upstream-a", "downstream-a", "input-a"),)
    supplied = (_match("match-b", "upstream-b", "downstream-b", "input-b"),)
    result = _result("result-a", expected)
    records = SQLiteRecordStore(database)

    with pytest.raises(ValueError, match="CHAINING_RESERVATION_SOURCE_MISMATCH"):
        with database.write() as connection:
            result_ref = records.stage(connection, result)
            records.publish(connection, result_ref)
            assert isinstance(result_ref, StoredDataRef)
            ChainingMatchReservationStore(records, connection).reserve_for_result(
                source_result_ref=result_ref,
                identities=supplied,
            )


def test_uncommitted_chaining_result_is_not_a_recovery_source(tmp_path: Path) -> None:
    database = _database(tmp_path)
    identity = (_match("match-a", "upstream-a", "downstream-a", "input-a"),)
    result = _result("result-a", identity)
    result_ref = reference(result)
    assert isinstance(result_ref, StoredDataRef)
    records = SQLiteRecordStore(database)
    with database.write() as connection:
        records.publish(connection, records.stage(connection, result))

    with pytest.raises(ValueError, match="RESULT_NOT_COMMITTED"):
        ChainingCommittedSourceStore(records).chaining_result(result_ref)


def test_lineage_exclusions_are_recomputed_for_both_match_sides() -> None:
    identity = (_match("match-a", "upstream-a", "downstream-a", "input-a"),)
    base = _result("result-a", identity)
    ancestor = StoredDataRef.model_validate(
        base.considered_primitive_refs[0].model_dump()
        | {"record_id": "ancestor", "stored_data_id": "ancestor"}
    )
    result = base.model_copy(
        update={
            "considered_primitive_refs": (
                *base.considered_primitive_refs,
                ancestor,
            )
        }
    )
    calls: list[StoredDataRef] = []

    class Lineage:
        def ancestors(
            self,
            *,
            primitive_ref: StoredDataRef,
            universe: PinnedChainingUniverse,
        ) -> tuple[StoredDataRef, ...]:
            assert primitive_ref in universe.considered_primitive_refs
            calls.append(primitive_ref)
            return (
                (ancestor,) if primitive_ref == identity[0].upstream_result_ref else ()
            )

    exclusions = _expected_lineage_exclusions(
        result,
        PinnedChainingUniverse(
            trigger_primitive_ref=identity[0].upstream_result_ref,
            index_refs=(
                StoredDataRef.model_validate(
                    ancestor.model_dump()
                    | {
                        "data_kind": "primitive_index_state",
                        "record_id": "index",
                        "stored_data_id": "index",
                    }
                ),
            ),
            considered_primitive_refs=result.considered_primitive_refs,
        ),
        Lineage(),
    )

    assert calls == [
        identity[0].upstream_result_ref,
        identity[0].downstream_input_ref,
    ]
    assert len(exclusions) == 1
    assert exclusions[0].excluded_primitive_ref == ancestor
    assert exclusions[0].excluded_by_ref == identity[0].upstream_result_ref
