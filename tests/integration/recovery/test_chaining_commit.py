"""Chaining reservations occur only in the final transition transaction."""

from pathlib import Path

from pytest import MonkeyPatch
from sqlalchemy import Connection

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.contracts.chaining import ChainingResult
from sastsimi.storage import transition_service
from sastsimi.storage.repositories import SQLiteRecordStore


def test_transition_preflight_is_read_only_and_finalization_reserves_once(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    calls = 0
    original = transition_service.reserve_chaining_result_matches

    def tracked(
        records: SQLiteRecordStore,
        connection: Connection,
        result: ChainingResult,
    ) -> None:
        nonlocal calls
        calls += 1
        original(records, connection, result)

    monkeypatch.setattr(
        transition_service,
        "reserve_chaining_result_matches",
        tracked,
    )

    result = build_fake_pipeline(tmp_path).analyze(scenario="CHAINING")

    assert result.status == "COMPLETE"
    assert calls == 1
