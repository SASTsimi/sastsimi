"""LOCAL_EVALUATION prompt graph publication without Production authority."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from io import BytesIO
from pathlib import Path

import pytest

from sastsimi.composition.local_codex_binding import LocalCodexBindingRecords
from sastsimi.composition.local_prompt_configuration import (
    build_local_prompt_configuration_plan,
    publish_local_prompt_configuration,
    restore_local_prompt_configuration_plan,
)
from sastsimi.composition.local_subscription_route import codex_route
from sastsimi.config.package_resources import builtin_package_root
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.dto import StagedArtifact
from sastsimi.providers.local_codex_validation import validate_local_codex_binding
from tests.unit.providers.test_local_codex_validation import (
    _Clock,
    _Ids,
    _ProbeRunner,
    _records,
)


class _Artifacts:
    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    def stage_bytes(self, data: bytes, media_type: str) -> StagedArtifact:
        return StagedArtifact(data=data, media_type=media_type)

    def commit(self, staged: StagedArtifact) -> StoredDataRef:
        digest = hashlib.sha256(staged.data).hexdigest()
        self.values[digest] = staged.data
        return StoredDataRef(
            stored_data_id=digest,
            data_kind="artifact",
            content_hash=digest,
            workspace_id="ws1",
            commit_id="c1",
            record_id=None,
        )

    def open_verified(self, ref: StoredDataRef) -> BytesIO:
        return BytesIO(self.values[ref.content_hash])


class _Publisher:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        if not name.startswith("register_"):
            raise AttributeError(name)

        def publish(record: object, **kwargs: object) -> StoredDataRef:
            self.calls.append((name, kwargs.get("local_evidence_ref")))
            result = reference(record)  # type: ignore[arg-type]
            assert isinstance(result, StoredDataRef)
            return result

        return publish


def _safe_records() -> LocalCodexBindingRecords:
    records = _records()
    provider = records.provider.model_copy(
        update={
            "capabilities": records.provider.capabilities.model_copy(
                update={
                    "resume_session": "UNSUPPORTED",
                    "runtime_tool_loop": "UNSUPPORTED",
                }
            ),
            "limitations": (
                *records.provider.limitations,
                "RESUME_SESSION_UNSUPPORTED",
            ),
        }
    )
    return LocalCodexBindingRecords(
        records.validation,
        records.client,
        provider,
        replace(records.binding, provider_profile=provider),
    )


@pytest.mark.asyncio
async def test_plan_and_publish_complete_local_prompt_graph() -> None:
    records = _safe_records()
    artifacts = _Artifacts()
    validated = await validate_local_codex_binding(
        records=records,
        artifacts=artifacts,  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=_ProbeRunner(),
        unauthenticated_runner=_ProbeRunner(),
        probe_timeout_ms=500,
    )
    plan = build_local_prompt_configuration_plan(
        repository_root=Path.cwd(),
        subscription=codex_route(records=records, validation=validated),
        artifacts=artifacts,  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        timeout_ms=30_000,
        max_parallel_calls=2,
        max_calls_per_work=4,
        max_retries=1,
    )

    assert len(plan.routes) == 17
    assert len(plan.prompt_entries) == 17
    assert len(plan.output_schemas) == 17
    assert all(item.purpose == "LOCAL_EVALUATION" for item in plan.prompt_entries)
    assert all(item.quality_evaluation_ref is None for item in plan.prompt_entries)
    assert not hasattr(plan, "evaluation_recommendation")

    publisher = _Publisher()
    published = publish_local_prompt_configuration(
        plan=plan,
        configuration=publisher,  # type: ignore[arg-type]
    )

    assert len(published.bindings) == 17
    assert published.provider_profile_ref == reference(validated.provider)
    names = [name for name, _ in publisher.calls]
    assert names[:4] == [
        "register_local_provider_validation",
        "register_local_client_execution",
        "register_local_provider_profile",
        "register_local_provider_profile",
    ]
    assert all(
        evidence == validated.evidence_ref
        for name, evidence in publisher.calls[:4]
        if name.startswith("register_local_")
    )
    assert names.count("register_prompt_entry") == 17


@pytest.mark.asyncio
async def test_plan_loads_templates_from_installed_package_root() -> None:
    records = _safe_records()
    artifacts = _Artifacts()
    validated = await validate_local_codex_binding(
        records=records,
        artifacts=artifacts,  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=_ProbeRunner(),
        unauthenticated_runner=_ProbeRunner(),
        probe_timeout_ms=500,
    )

    plan = build_local_prompt_configuration_plan(
        repository_root=builtin_package_root(),
        subscription=codex_route(records=records, validation=validated),
        artifacts=artifacts,  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        timeout_ms=30_000,
        max_parallel_calls=2,
        max_calls_per_work=4,
        max_retries=1,
    )

    assert len(plan.prompt_entries) == 17


@pytest.mark.asyncio
async def test_resume_reuses_exact_published_prompt_graph() -> None:
    records = _safe_records()
    artifacts = _Artifacts()
    validated = await validate_local_codex_binding(
        records=records,
        artifacts=artifacts,  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=_ProbeRunner(),
        unauthenticated_runner=_ProbeRunner(),
        probe_timeout_ms=500,
    )
    plan = build_local_prompt_configuration_plan(
        repository_root=builtin_package_root(),
        subscription=codex_route(records=records, validation=validated),
        artifacts=artifacts,  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        timeout_ms=30_000,
        max_parallel_calls=2,
        max_calls_per_work=4,
        max_retries=1,
    )

    restored = restore_local_prompt_configuration_plan(
        published_records=plan.approval_records,
        current_records=plan.approval_records,
        subscription=codex_route(records=records, validation=validated),
    )

    assert restored is not None
    restored_plan, restored_validation = restored
    assert restored_plan.prompt_entries == plan.prompt_entries
    assert restored_plan.supported_provider == plan.supported_provider
    assert restored_validation.provider == plan.supported_provider
    assert restored_validation.evidence_ref == validated.evidence_ref


@pytest.mark.asyncio
async def test_resume_rejects_partial_active_prompt_graph() -> None:
    records = _safe_records()
    artifacts = _Artifacts()
    validated = await validate_local_codex_binding(
        records=records,
        artifacts=artifacts,  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=_ProbeRunner(),
        unauthenticated_runner=_ProbeRunner(),
        probe_timeout_ms=500,
    )
    plan = build_local_prompt_configuration_plan(
        repository_root=builtin_package_root(),
        subscription=codex_route(records=records, validation=validated),
        artifacts=artifacts,  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        timeout_ms=30_000,
        max_parallel_calls=2,
        max_calls_per_work=4,
        max_retries=1,
    )

    with pytest.raises(
        ValueError, match="LOCAL_PROMPT_RESUME_CONFIGURATION_INCOMPLETE"
    ):
        restore_local_prompt_configuration_plan(
            published_records=plan.approval_records,
            current_records=plan.approval_records[:-1],
            subscription=codex_route(records=records, validation=validated),
        )


@pytest.mark.asyncio
async def test_plan_rejects_supported_provider_not_from_exact_binding() -> None:
    records = _safe_records()
    artifacts = _Artifacts()
    validated = await validate_local_codex_binding(
        records=records,
        artifacts=artifacts,  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=_ProbeRunner(),
        unauthenticated_runner=_ProbeRunner(),
        probe_timeout_ms=500,
    )
    wrong = validated.provider.model_copy(update={"model": "other-model"})

    with pytest.raises(ValueError, match="LOCAL_PROMPT_PROVIDER_BINDING_MISMATCH"):
        build_local_prompt_configuration_plan(
            repository_root=Path.cwd(),
            subscription=codex_route(
                records=records,
                validation=validated.__class__(
                    provider=wrong,
                    evidence_ref=validated.evidence_ref,
                    binding=validated.binding,
                ),
            ),
            artifacts=artifacts,  # type: ignore[arg-type]
            ids=_Ids(),
            clock=_Clock(),
            timeout_ms=30_000,
            max_parallel_calls=2,
            max_calls_per_work=4,
            max_retries=1,
        )


@pytest.mark.asyncio
async def test_plan_rejects_resume_capable_local_provider() -> None:
    records = _records()
    artifacts = _Artifacts()
    validated = await validate_local_codex_binding(
        records=records,
        artifacts=artifacts,  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=_ProbeRunner(),
        unauthenticated_runner=_ProbeRunner(),
        probe_timeout_ms=500,
    )

    with pytest.raises(ValueError, match="LOCAL_PROMPT_PROVIDER_BINDING_MISMATCH"):
        build_local_prompt_configuration_plan(
            repository_root=Path.cwd(),
            subscription=codex_route(records=records, validation=validated),
            artifacts=artifacts,  # type: ignore[arg-type]
            ids=_Ids(),
            clock=_Clock(),
            timeout_ms=30_000,
            max_parallel_calls=2,
            max_calls_per_work=4,
            max_retries=1,
        )


# mypy: disable-error-code="arg-type,unused-ignore"
