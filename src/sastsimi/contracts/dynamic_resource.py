"""Stable identity helpers for attempt-owned dynamic resources."""

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.ids import StoredDataId
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef


def owned_container_resource_ref(
    *, container_id: str, meta: RecordMeta
) -> StoredDataRef:
    """Derive the opaque container ref from runtime identity and attempt scope."""

    if meta.hypothesis_id is None or meta.attempt_id is None:
        raise ValueError("SANDBOX_RESOURCE_SCOPE_REQUIRED")
    payload = {
        "resource_type": "container",
        "resource_id": container_id,
        "analysis_id": meta.analysis_id,
        "workspace_id": meta.workspace_id,
        "commit_id": meta.commit_id,
        "hypothesis_id": meta.hypothesis_id,
        "attempt_id": meta.attempt_id,
    }
    digest = content_hash(payload)
    return StoredDataRef(
        stored_data_id=StoredDataId(f"sandbox-resource-{digest}"),
        data_kind="sandbox_resource",
        content_hash=digest,
        workspace_id=meta.workspace_id,
        commit_id=meta.commit_id,
        record_id=None,
    )


__all__ = ["owned_container_resource_ref"]
