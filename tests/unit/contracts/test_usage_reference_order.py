from sastsimi.contracts.evaluation import canonical_usage_refs
from sastsimi.contracts.refs import StoredDataRef


def _usage_ref(record_id: str, digest: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=record_id,
        data_kind="llm_invocation_result",
        record_id=record_id,
        content_hash=digest * 64,
        workspace_id="workspace",
        commit_id="commit",
    )


def test_usage_references_have_one_canonical_order() -> None:
    first = _usage_ref("record-a", "a")
    second = _usage_ref("record-b", "b")

    assert canonical_usage_refs((second, first, second)) == (first, second)
    assert canonical_usage_refs((first, second)) == (first, second)


# mypy: disable-error-code="arg-type"
