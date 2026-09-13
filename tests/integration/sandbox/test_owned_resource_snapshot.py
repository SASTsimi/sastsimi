from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.sandbox import cleanup as cleanup_module
from sastsimi.sandbox.cleanup import OwnedResourceRegistry
from sastsimi.sandbox.docker_adapter import DockerAdapter
from sastsimi.sandbox.setup_automation import ReproductionSetupAutomation
from tests.integration.sandbox.test_container_lifecycle import _meta


def _inventory(path: Path | None) -> tuple[OwnedResourceRegistry, StoredDataRef]:
    meta = _meta("sandbox_environment", "snapshot")
    registry = OwnedResourceRegistry(journal_path=path)
    labels = ReproductionSetupAutomation._container_labels(meta)
    registry.reserve_container(
        container_name=DockerAdapter.runtime_container_name(labels), labels=labels
    )
    labels = ReproductionSetupAutomation._image_labels(meta)
    registry.reserve_image(
        image_tag=DockerAdapter.runtime_image_tag(labels), labels=labels
    )
    ref = registry.register_container(
        container_id="container-1",
        labels=ReproductionSetupAutomation._container_labels(meta),
        meta=meta,
    )
    labels = ReproductionSetupAutomation._image_labels(meta)
    registry.register_image(
        image_digest="sha256:" + "a" * 64,
        image_tag=DockerAdapter.runtime_image_tag(labels),
        labels=labels,
        meta=meta,
        preservation_reason="REUSABLE_BASELINE",
    )
    return registry, ref


def test_complete_inventory_is_stable_detached_and_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = tmp_path / "owned.json"
    registry, ref = _inventory(journal)
    meta = _meta("sandbox_environment", "snapshot")
    before = journal.read_bytes()
    calls: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        calls.append("side-effect")
        raise AssertionError("snapshot attempted a side effect")

    monkeypatch.setattr(OwnedResourceRegistry, "_persist", forbidden)
    monkeypatch.setattr(cleanup_module, "uuid4", forbidden)
    for method in ("inspect", "remove", "create", "inspect_image_tag", "remove_images"):
        monkeypatch.setattr(DockerAdapter, method, forbidden)
    snapshot = registry.snapshot(meta=meta)
    assert len(snapshot.resources) == 2
    assert len(snapshot.container_intents) == len(snapshot.image_intents) == 1
    assert snapshot.resources[0].resource_kind == "CONTAINER"
    assert snapshot.resources[0].ref == ref
    assert snapshot.resources[0].reconcile_required is False
    assert snapshot.resources[1].preservation_reason == "REUSABLE_BASELINE"
    assert len(snapshot.fingerprint) == 64
    assert snapshot == OwnedResourceRegistry(journal_path=journal).snapshot(meta=meta)
    assert snapshot == registry.snapshot(meta=meta)
    assert journal.read_bytes() == before
    assert calls == []

    with pytest.raises(FrozenInstanceError):
        snapshot.fingerprint = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        snapshot.resources[0].resource_id = "changed"  # type: ignore[misc]
    for entry in (
        *snapshot.resources,
        *snapshot.container_intents,
        *snapshot.image_intents,
    ):
        with pytest.raises(TypeError):
            entry.labels["sastsimi.owner"] = "changed"  # type: ignore[index]
    with pytest.raises(ValueError):
        snapshot.resources[0].ref.content_hash = "b" * 64
    original = registry.exact(ref)
    assert original is not None
    assert snapshot.resources[0] is not original
    assert snapshot.resources[0].ref is not original.ref
    assert snapshot.resources[0].labels is not original.labels
    assert registry.snapshot(meta=meta) == snapshot


@pytest.mark.parametrize("entry_list", ["resources", "intents", "image_intents"])
@pytest.mark.parametrize(
    "label",
    [
        "analysis-id",
        "workspace-id",
        "commit-id",
        "hypothesis-id",
        "attempt-id",
        "owner",
    ],
)
@pytest.mark.parametrize("missing", [False, True])
def test_any_foreign_or_missing_label_rejects_entire_inventory(
    tmp_path: Path, entry_list: str, label: str, missing: bool
) -> None:
    journal = tmp_path / "owned.json"
    _inventory(journal)
    value = json.loads(journal.read_bytes())
    labels = value[entry_list][0]["labels"]
    if missing:
        del labels[f"sastsimi.{label}"]
    else:
        labels[f"sastsimi.{label}"] = "foreign"
    journal.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError):
        OwnedResourceRegistry(journal_path=journal).snapshot(
            meta=_meta("sandbox_environment", "snapshot")
        )


@pytest.mark.parametrize(
    "corruption",
    [
        "duplicate-ref",
        "duplicate-id",
        "duplicate-container-intent",
        "duplicate-image-intent",
        "duplicate-tag",
        "intent-resource-name",
        "intent-resource-tag",
        "hash",
        "ref-kind",
        "ref-id",
        "ref-record",
        "ref-workspace",
        "ref-commit",
        "resource-kind",
        "resource-id",
        "image-digest",
        "image-tag",
        "labels-kind",
        "labels-extra",
        "labels-value",
        "preservation",
        "lookup",
        "reconcile",
        "container-tag",
        "unknown-field",
        "duplicate-json-key",
        "truncated",
    ],
)
def test_corrupt_or_ambiguous_journal_cannot_produce_partial_snapshot(
    tmp_path: Path, corruption: str
) -> None:
    journal = tmp_path / "owned.json"
    _inventory(journal)
    value: dict[str, Any] = json.loads(journal.read_bytes())
    container = next(r for r in value["resources"] if r["resource_kind"] == "CONTAINER")
    image = next(r for r in value["resources"] if r["resource_kind"] == "IMAGE")
    if corruption == "duplicate-ref":
        value["resources"].append(dict(container))
    elif corruption == "duplicate-id":
        duplicate = dict(container)
        duplicate["ref"] = dict(container["ref"], stored_data_id="another-ref")
        value["resources"].append(duplicate)
    elif corruption == "duplicate-container-intent":
        value["intents"].append(dict(value["intents"][0]))
    elif corruption == "duplicate-image-intent":
        value["image_intents"].append(dict(value["image_intents"][0]))
    elif corruption == "duplicate-tag":
        duplicate = dict(image, resource_id="sha256:" + "b" * 64)
        duplicate["ref"] = dict(image["ref"], stored_data_id="another-ref")
        value["resources"].append(duplicate)
    elif corruption == "intent-resource-name":
        value["intents"][0]["container_name"] = container["resource_id"]
    elif corruption == "intent-resource-tag":
        value["image_intents"][0] = {
            "image_tag": image["resource_tag"],
            "labels": image["labels"],
        }
    elif corruption.startswith("ref-") or corruption == "hash":
        field, replacement = {
            "hash": ("content_hash", "bad-hash"),
            "ref-kind": ("data_kind", "agent_log"),
            "ref-id": ("stored_data_id", "wrong"),
            "ref-record": ("record_id", "unexpected-record"),
            "ref-workspace": ("workspace_id", "foreign"),
            "ref-commit": ("commit_id", "foreign"),
        }[corruption]
        container["ref"][field] = replacement
    elif corruption == "resource-kind":
        container["resource_kind"] = "NETWORK"
    elif corruption == "resource-id":
        container["resource_id"] = "/host/path"
    elif corruption == "image-digest":
        image["resource_id"] = "not-a-digest"
    elif corruption == "image-tag":
        image["resource_tag"] = "foreign:tag"
    elif corruption == "labels-kind":
        container["labels"]["sastsimi.resource-kind"] = "image"
    elif corruption == "labels-extra":
        container["labels"]["secret"] = "credential"
    elif corruption == "labels-value":
        container["labels"]["sastsimi.resource-id"] = "/host/path"
    elif corruption == "preservation":
        container["preservation_reason"] = "REUSABLE_BASELINE"
    elif corruption == "lookup":
        container["lookup_by_name"] = 1
    elif corruption == "reconcile":
        container["reconcile_required"] = "false"
    elif corruption == "container-tag":
        container["resource_tag"] = "unexpected:tag"
    elif corruption == "unknown-field":
        container["secret"] = "credential"
    payload = json.dumps(value)
    if corruption == "duplicate-json-key":
        payload = payload[:-1] + ', "intents": []}'
    elif corruption == "truncated":
        payload = payload[:25]
    journal.write_text(payload, encoding="utf-8")
    with pytest.raises(ValueError):
        OwnedResourceRegistry(journal_path=journal).snapshot(
            meta=_meta("sandbox_environment", "snapshot")
        )


@pytest.mark.parametrize(
    "state", ["reconcile_required", "lookup_by_name", "preservation_reason"]
)
def test_state_change_invalidates_inventory_fingerprint(
    tmp_path: Path, state: str
) -> None:
    journal = tmp_path / "owned.json"
    registry, _ = _inventory(journal)
    meta = _meta("sandbox_environment", "snapshot")
    before = registry.snapshot(meta=meta)
    value = json.loads(journal.read_bytes())
    kind = "IMAGE" if state == "preservation_reason" else "CONTAINER"
    resource = next(r for r in value["resources"] if r["resource_kind"] == kind)
    resource[state] = None if state == "preservation_reason" else True
    journal.write_text(json.dumps(value), encoding="utf-8")
    after = OwnedResourceRegistry(journal_path=journal).snapshot(meta=meta)
    assert after.fingerprint != before.fingerprint
    for entries in value.values():
        entries.reverse()
    journal.write_text(json.dumps(value), encoding="utf-8")
    assert OwnedResourceRegistry(journal_path=journal).snapshot(meta=meta) == after


def test_inventory_add_remove_and_empty_scope_change_fingerprint() -> None:
    meta = _meta("sandbox_environment", "snapshot")
    registry = OwnedResourceRegistry()
    empty = registry.snapshot(meta=meta)
    assert empty != registry.snapshot(
        meta=_meta("sandbox_environment", "snapshot", attempt_id="another-attempt")
    )
    registry, ref = _inventory(None)
    populated = registry.snapshot(meta=meta)
    assert populated.fingerprint != empty.fingerprint
    registry.forget(ref)
    assert registry.snapshot(meta=meta).fingerprint != populated.fingerprint


@pytest.mark.parametrize("field", ["attempt_id", "hypothesis_id"])
def test_missing_current_scope_is_rejected_even_for_empty_registry(field: str) -> None:
    meta = _meta("sandbox_environment", "snapshot").model_copy(update={field: None})
    with pytest.raises(ValueError):
        OwnedResourceRegistry().snapshot(meta=meta)
