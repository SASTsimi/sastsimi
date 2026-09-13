"""Immutable, attempt-owned inventory values; no external resource authority."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, fields, replace
from types import MappingProxyType
from typing import Literal

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic_resource import (
    owned_container_resource_ref,
    owned_image_resource_ref,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef

from .docker_adapter import DockerAdapter

_SCOPE_KEYS = (
    "analysis-id",
    "workspace-id",
    "commit-id",
    "hypothesis-id",
    "attempt-id",
)
_RESOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class OwnedResource:
    ref: StoredDataRef
    resource_id: str
    labels: Mapping[str, str]
    resource_kind: Literal["CONTAINER", "IMAGE"] = "CONTAINER"
    resource_tag: str | None = None
    lookup_by_name: bool = False
    preservation_reason: Literal["REUSABLE_BASELINE"] | None = None
    reconcile_required: bool = False


@dataclass(frozen=True, slots=True)
class ContainerOwnershipIntent:
    container_name: str
    labels: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class ImageOwnershipIntent:
    image_tag: str
    labels: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class OwnedResourceSnapshot:
    """Detached inventory observation, not permission to remove any resource.

    All entries belong to the supplied exact attempt. Preserved images remain
    preservation data only. The fingerprint covers scope and every entry field.
    """

    resources: tuple[OwnedResource, ...]
    container_intents: tuple[ContainerOwnershipIntent, ...]
    image_intents: tuple[ImageOwnershipIntent, ...]
    fingerprint: str


def ownership_scope(labels: Mapping[str, str]) -> tuple[str, ...]:
    """Validate the existing canonical labels without contacting Docker."""

    normalized = DockerAdapter._validated_labels(labels)
    return tuple(normalized[f"sastsimi.{key}"] for key in _SCOPE_KEYS)


def snapshot_inventory(
    *,
    resources: tuple[OwnedResource, ...],
    container_intents: tuple[ContainerOwnershipIntent, ...],
    image_intents: tuple[ImageOwnershipIntent, ...],
    meta: RecordMeta,
) -> OwnedResourceSnapshot:
    """Validate the whole inventory before returning a detached snapshot."""

    meta = RecordMeta.model_validate(meta)
    if meta.hypothesis_id is None or meta.attempt_id is None:
        raise ValueError("SANDBOX_RESOURCE_SCOPE_REQUIRED")
    expected_scope = tuple(
        str(getattr(meta, key.replace("-", "_"))) for key in _SCOPE_KEYS
    )
    identities: set[str] = set()
    refs: set[bytes] = set()

    def unique(identity: str) -> None:
        if not _RESOURCE_ID.fullmatch(identity) or identity in identities:
            raise ValueError("SANDBOX_RESOURCE_IDENTITY_INVALID")
        identities.add(identity)

    entries: tuple[
        OwnedResource | ContainerOwnershipIntent | ImageOwnershipIntent, ...
    ] = (*resources, *container_intents, *image_intents)
    for entry in entries:
        if ownership_scope(entry.labels) != expected_scope:
            raise ValueError("SANDBOX_RESOURCE_SCOPE_MISMATCH")
    for resource in resources:
        unique(resource.resource_id)
        if (
            type(resource.lookup_by_name) is not bool
            or type(resource.reconcile_required) is not bool
            or resource.preservation_reason not in {None, "REUSABLE_BASELINE"}
        ):
            raise ValueError("SANDBOX_RESOURCE_STATE_INVALID")
        if resource.resource_kind == "CONTAINER":
            if (
                resource.resource_tag is not None
                or resource.preservation_reason is not None
                or resource.labels.get("sastsimi.resource-kind", "container")
                != "container"
            ):
                raise ValueError("SANDBOX_RESOURCE_KIND_INVALID")
            expected_ref = owned_container_resource_ref(
                container_id=resource.resource_id, meta=meta
            )
        elif resource.resource_kind == "IMAGE":
            if not _IMAGE_DIGEST.fullmatch(
                resource.resource_id
            ) or resource.resource_tag != DockerAdapter.runtime_image_tag(
                resource.labels
            ):
                raise ValueError("SANDBOX_IMAGE_IDENTITY_INVALID")
            unique(resource.resource_tag)
            expected_ref = owned_image_resource_ref(
                image_digest=resource.resource_id, meta=meta
            )
        else:
            raise ValueError("SANDBOX_RESOURCE_KIND_INVALID")
        ref = StoredDataRef.model_validate(resource.ref)
        key = canonical_bytes(ref)
        if ref != expected_ref or key in refs:
            raise ValueError("SANDBOX_RESOURCE_REFERENCE_INVALID")
        refs.add(key)
    for container_intent in container_intents:
        unique(container_intent.container_name)
        if (
            container_intent.labels.get("sastsimi.resource-kind", "container")
            != "container"
        ):
            raise ValueError("SANDBOX_RESOURCE_KIND_INVALID")
    for image_intent in image_intents:
        unique(image_intent.image_tag)
        if image_intent.image_tag != DockerAdapter.runtime_image_tag(
            image_intent.labels
        ):
            raise ValueError("SANDBOX_IMAGE_IDENTITY_INVALID")

    frozen_resources = tuple(
        replace(
            item,
            labels=MappingProxyType(dict(sorted(item.labels.items()))),
            ref=item.ref.model_copy(deep=True),
        )
        for item in sorted(
            resources, key=lambda item: (item.resource_kind, item.resource_id)
        )
    )
    frozen_containers = tuple(
        replace(item, labels=MappingProxyType(dict(sorted(item.labels.items()))))
        for item in sorted(container_intents, key=lambda item: item.container_name)
    )
    frozen_images = tuple(
        replace(item, labels=MappingProxyType(dict(sorted(item.labels.items()))))
        for item in sorted(image_intents, key=lambda item: item.image_tag)
    )
    fingerprint = content_hash(
        {
            "scope": expected_scope,
            "resources": [_entry_value(item) for item in frozen_resources],
            "container_intents": [_entry_value(item) for item in frozen_containers],
            "image_intents": [_entry_value(item) for item in frozen_images],
        }
    )
    return OwnedResourceSnapshot(
        frozen_resources, frozen_containers, frozen_images, fingerprint
    )


def _entry_value(
    entry: OwnedResource | ContainerOwnershipIntent | ImageOwnershipIntent,
) -> dict[str, object]:
    return {field.name: getattr(entry, field.name) for field in fields(entry)}
