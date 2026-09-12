"""Prompt activation must remain isolated between production analyses."""

from sqlalchemy import create_engine, insert, select

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import AnalysisId, LogicalRecordId, RecordId, WorkspaceId
from sastsimi.contracts.llm import PromptRegistryEntry, ProviderProfile
from sastsimi.storage import models
from sastsimi.storage.configuration_registry import ConfigurationRegistry
from tests.contract.domain.canonical_fixtures import make


def _ref(kind: str, name: str) -> dict[str, object]:
    return {
        "stored_data_id": f"{name}-{kind}-stored",
        "data_kind": kind,
        "content_hash": "a" * 64,
        "workspace_id": f"{name}-workspace",
        "commit_id": f"{name}-commit",
        "record_id": f"{name}-{kind}-record",
    }


def _move_refs(value: object, name: str) -> None:
    if isinstance(value, dict):
        if "stored_data_id" in value:
            value["workspace_id"] = f"{name}-workspace"
            value["commit_id"] = f"{name}-commit"
        for nested in value.values():
            _move_refs(nested, name)
    elif isinstance(value, list):
        for nested in value:
            _move_refs(nested, name)


def _scoped_entry(name: str) -> PromptRegistryEntry:
    payload = make("PromptRegistryEntry")
    _move_refs(payload, name)
    payload["meta"] |= {
        "record_id": RecordId(f"{name}-entry-record"),
        "logical_record_id": LogicalRecordId(f"{name}-entry-logical"),
        "analysis_id": AnalysisId(f"{name}-analysis"),
        "workspace_id": WorkspaceId(f"{name}-workspace"),
        "commit_id": f"{name}-commit",
    }
    return PromptRegistryEntry.model_validate_json(
        canonical_bytes(
            payload
            | {
                "provider_profile_refs": [_ref("provider_profile", name)],
                "status": "ACTIVE",
            }
        )
    )


def _scoped_provider(name: str) -> ProviderProfile:
    payload = make("ProviderProfile")
    payload["meta"] |= {
        "record_id": RecordId(f"{name}-provider-record"),
        "logical_record_id": LogicalRecordId(f"{name}-provider-logical"),
        "analysis_id": AnalysisId(f"{name}-analysis"),
        "workspace_id": WorkspaceId(f"{name}-workspace"),
        "commit_id": f"{name}-commit",
    }
    return ProviderProfile.model_validate_json(
        canonical_bytes(
            payload
            | {"validation_evidence_ref": _ref("provider_validation_evidence", name)}
        )
    )


def test_same_role_task_can_be_active_in_two_analysis_scopes() -> None:
    first = _scoped_entry("first")
    second = _scoped_entry("second")
    first_provider = _scoped_provider("first")
    second_provider = _scoped_provider("second")
    engine = create_engine("sqlite://")
    models.metadata.create_all(engine)

    with engine.begin() as connection:
        for entry in (first, second):
            connection.execute(
                insert(models.prompt_active_entries).values(
                    analysis_id=str(entry.meta.analysis_id),
                    workspace_id=str(entry.meta.workspace_id),
                    commit_id=str(entry.meta.commit_id),
                    agent_role=entry.agent_role,
                    task_kind=entry.task_kind,
                    purpose=entry.purpose,
                    logical_record_id=str(entry.meta.logical_record_id),
                    record_id=str(entry.meta.record_id),
                    state_version=1,
                )
            )
        connection.execute(
            insert(models.current_records),
            tuple(
                {
                    "logical_record_id": str(record.meta.logical_record_id),
                    "record_id": str(record.meta.record_id),
                    "state_version": 1,
                }
                for record in (first, second, first_provider, second_provider)
            ),
        )

        ConfigurationRegistry.require_current_selection(
            connection, first, first_provider
        )
        ConfigurationRegistry.require_current_selection(
            connection, second, second_provider
        )
        rows = connection.execute(select(models.prompt_active_entries)).all()

    assert len(rows) == 2
