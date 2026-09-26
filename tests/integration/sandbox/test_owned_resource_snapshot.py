from __future__ import annotations

import errno
import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path
from threading import Event
from typing import Any

import pytest
from sqlalchemy import insert

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.sandbox import cleanup as cleanup_module
from sastsimi.sandbox.cleanup import OwnedResourceRegistry
from sastsimi.sandbox.docker_adapter import DockerAdapter
from sastsimi.sandbox.setup_automation import ReproductionSetupAutomation
from sastsimi.storage import models
from sastsimi.storage.run_control import RunControlStore
from tests.integration.runtime_support import Harness
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


def test_journal_retries_transient_replace_denial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = tmp_path / "owned.json"
    real_replace = os.replace
    attempts = 0

    def flaky_replace(source: Path, target: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise PermissionError(errno.EACCES, "transient sharing violation")
        real_replace(source, target)

    monkeypatch.setattr(os, "replace", flaky_replace)

    _inventory(journal)

    assert attempts > 1
    assert json.loads(journal.read_text(encoding="utf-8"))["resources"]


def test_journal_stops_after_bounded_replace_denials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = 0

    def deny_replace(_source: Path, _target: Path) -> None:
        nonlocal attempts
        attempts += 1
        raise PermissionError(errno.EACCES, "persistent access denied")

    monkeypatch.setattr(os, "replace", deny_replace)

    with pytest.raises(PermissionError, match="persistent access denied"):
        _inventory(tmp_path / "owned.json")

    assert attempts == 5
    assert list(tmp_path.glob(".owned.json.*.tmp")) == []


def test_resource_publication_precedes_serialized_cancellation_latch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path)
    with harness.database.write() as connection:
        connection.execute(
            insert(models.analysis_runs).values(analysis_id="analysis-1", payload="{}")
        )
    controls = RunControlStore(harness.database, harness.clock)
    journal = tmp_path / "owned.json"
    registry = OwnedResourceRegistry(
        journal_path=journal,
        mutation_admission=controls.admit_resource_mutation,
    )
    meta = _meta("sandbox_environment", "serialized-before-latch")
    labels = ReproductionSetupAutomation._container_labels(meta)
    name = DockerAdapter.runtime_container_name(labels)
    persisted = Event()
    release = Event()
    latch_started = Event()
    real_persist = registry._persist

    def paused_persist() -> None:
        real_persist()
        persisted.set()
        assert release.wait(5)

    def request_cancel() -> None:
        latch_started.set()
        controls.request_cancel("analysis-1", "OWNER_DEAD")

    monkeypatch.setattr(registry, "_persist", paused_persist)
    with ThreadPoolExecutor(max_workers=2) as pool:
        mutation = pool.submit(
            registry.reserve_container, container_name=name, labels=labels
        )
        assert persisted.wait(5)
        latch = pool.submit(request_cancel)
        assert latch_started.wait(5)
        assert not controls.cancel_requested("analysis-1")
        release.set()
        mutation.result(timeout=5)
        latch.result(timeout=5)

    assert controls.cancel_requested("analysis-1")
    assert OwnedResourceRegistry(journal_path=journal).pending_resource_ids() == (name,)


def test_latched_run_rejects_resource_publication_without_journal_mutation(
    tmp_path: Path,
) -> None:
    harness = Harness(tmp_path)
    with harness.database.write() as connection:
        connection.execute(
            insert(models.analysis_runs).values(analysis_id="analysis-1", payload="{}")
        )
    controls = RunControlStore(harness.database, harness.clock)
    controls.request_cancel("analysis-1", "OWNER_DEAD")
    journal = tmp_path / "owned.json"
    registry = OwnedResourceRegistry(
        journal_path=journal,
        mutation_admission=controls.admit_resource_mutation,
    )
    meta = _meta("sandbox_environment", "rejected-after-latch")
    labels = ReproductionSetupAutomation._container_labels(meta)

    with pytest.raises(ValueError, match="RUN_CANCELLED"):
        registry.reserve_container(
            container_name=DockerAdapter.runtime_container_name(labels),
            labels=labels,
        )
    with pytest.raises(ValueError, match="RUN_CANCELLED"):
        registry.register_container(
            container_id="late-container",
            labels=labels,
            meta=meta,
        )

    assert not journal.exists()
    assert registry.pending_resource_ids() == ()


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
def test_invalid_root_or_unrequested_attempt_is_handled_without_scope_mixing(
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
        if entry_list == "image_intents" and label in {
            "hypothesis-id",
            "attempt-id",
        }:
            value[entry_list][0]["image_tag"] = DockerAdapter.runtime_image_tag(labels)
    journal.write_text(json.dumps(value), encoding="utf-8")
    if not missing and label in {"hypothesis-id", "attempt-id"}:
        snapshot = OwnedResourceRegistry(journal_path=journal).snapshot(
            meta=_meta("sandbox_environment", "snapshot")
        )
        assert all(
            entry.labels[f"sastsimi.{label}"] != "foreign"
            for entry in snapshot.resources
        )
        assert all(
            entry.labels[f"sastsimi.{label}"] != "foreign"
            for entry in snapshot.container_intents
        )
        assert all(
            entry.labels[f"sastsimi.{label}"] != "foreign"
            for entry in snapshot.image_intents
        )
        return
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
    registry, container_ref = _inventory(journal)
    meta = _meta("sandbox_environment", "snapshot")
    if state == "lookup_by_name":
        container = registry.exact(container_ref)
        assert container is not None
        registry.forget(container_ref)
        registry.register_container(
            container_id=DockerAdapter.runtime_container_name(container.labels),
            labels=container.labels,
            meta=meta,
        )
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


@pytest.mark.parametrize("entry_kind", ["intent", "container-id", "container-name"])
@pytest.mark.parametrize("persisted", [False, True])
@pytest.mark.parametrize("missing", ["resource-kind", "resource-id", "both"])
def test_container_snapshot_requires_complete_resource_labels(
    tmp_path: Path, entry_kind: str, persisted: bool, missing: str
) -> None:
    meta = _meta("sandbox_environment", "snapshot")
    labels = dict(ReproductionSetupAutomation._container_labels(meta))
    name = DockerAdapter.runtime_container_name(labels)
    if missing in {"resource-kind", "both"}:
        del labels["sastsimi.resource-kind"]
    if missing in {"resource-id", "both"}:
        del labels["sastsimi.resource-id"]
    journal = tmp_path / "owned.json"
    registry = OwnedResourceRegistry(journal_path=journal if persisted else None)
    if entry_kind == "intent":
        registry.reserve_container(container_name=name, labels=labels)
    else:
        registry.register_container(
            container_id=name if entry_kind == "container-name" else "container-1",
            labels=labels,
            meta=meta,
            lookup_by_name=entry_kind == "container-name",
        )
    with pytest.raises(ValueError):
        if persisted:
            registry = OwnedResourceRegistry(journal_path=journal)
        registry.snapshot(meta=meta)


@pytest.mark.parametrize("entry_kind", ["intent", "container-name"])
@pytest.mark.parametrize("persisted", [False, True])
def test_container_name_must_match_exact_ownership_labels(
    tmp_path: Path, entry_kind: str, persisted: bool
) -> None:
    meta = _meta("sandbox_environment", "snapshot")
    labels = ReproductionSetupAutomation._container_labels(meta)
    foreign_labels = dict(labels) | {"sastsimi.resource-id": "another-resource"}
    foreign_name = DockerAdapter.runtime_container_name(foreign_labels)
    journal = tmp_path / "owned.json"
    registry = OwnedResourceRegistry(journal_path=journal if persisted else None)
    if entry_kind == "intent":
        registry.reserve_container(container_name=foreign_name, labels=labels)
    else:
        # The stored ref matches this name, isolating the missing label/name check.
        registry.register_container(
            container_id=foreign_name, labels=labels, meta=meta, lookup_by_name=True
        )
    with pytest.raises(ValueError):
        if persisted:
            registry = OwnedResourceRegistry(journal_path=journal)
        registry.snapshot(meta=meta)


@pytest.mark.parametrize("lookup_by_name", [False, True])
def test_complete_container_identity_is_preserved_across_snapshot_reload(
    tmp_path: Path, lookup_by_name: bool
) -> None:
    meta = _meta("sandbox_environment", "snapshot")
    labels = ReproductionSetupAutomation._container_labels(meta)
    identity = (
        DockerAdapter.runtime_container_name(labels)
        if lookup_by_name
        else "container-1"
    )
    journal = tmp_path / "owned.json"
    registry = OwnedResourceRegistry(journal_path=journal)
    ref = registry.register_container(
        container_id=identity, labels=labels, meta=meta, lookup_by_name=lookup_by_name
    )
    snapshot = registry.snapshot(meta=meta)
    assert snapshot.resources[0].resource_id == identity
    assert snapshot.resources[0].lookup_by_name is lookup_by_name
    assert snapshot.resources[0].ref == ref
    assert OwnedResourceRegistry(journal_path=journal).snapshot(meta=meta) == snapshot
