"""Safe operator commands for production Provider and prompt onboarding."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.orchestration.production_capabilities import (
    ProfileBackedProductionCapabilityBundle,
    production_profile_hash,
)
from sastsimi.orchestration.production_onboarding import (
    FilesystemProductionOnboardingStore,
    OnboardedProductionCapabilityBundleLoader,
    ProductionOnboardingManifest,
    ProductionOnboardingUnavailable,
    read_builtin_prompt,
)
from sastsimi.prompts.production import REQUIRED_PRODUCTION_PROMPT_ROUTES

_MAX_INPUT_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class OnboardingCommandResult:
    code: ExitCode
    data: dict[str, object]


def run_requirements(
    profile: ProductionProfile, *, repository_root: Path
) -> OnboardingCommandResult:
    """List work that must produce evidence; never infer a successful PVD."""

    try:
        routes = [
            {
                "model": configured.model,
                "prompt_key": configured.prompt_key,
                "provider_profile_key": configured.provider_profile_key,
                "role": configured.role,
                "task_kind": configured.task_kind,
                "template_path": str(required.template_path),
                "template_sha256": hashlib.sha256(
                    read_builtin_prompt(repository_root, required.template_path)
                ).hexdigest(),
            }
            for configured in profile.llm_routes
            for required in REQUIRED_PRODUCTION_PROMPT_ROUTES
            if (configured.role, configured.task_kind)
            == (required.role, required.task_kind)
        ]
    except (OSError, ValueError):
        return _blocked("PRODUCTION_PROMPT_TEMPLATE_UNAVAILABLE")
    if len(routes) != len(REQUIRED_PRODUCTION_PROMPT_ROUTES):
        return _blocked("PRODUCTION_PROMPT_ROUTE_SET_INCOMPLETE")
    return OnboardingCommandResult(
        ExitCode.CAPABILITY_UNSUPPORTED,
        {
            "profile_hash": production_profile_hash(profile),
            "required_pvd_tests": [f"PVD-{index:02d}" for index in range(1, 16)],
            "required_routes": routes,
            "status": "BLOCKED",
        },
    )


def run_prepare(
    data_dir: Path,
    *,
    profile: ProductionProfile,
    manifest_path: Path,
    evidence_paths: tuple[Path, ...],
    repository_root: Path,
    clock: Callable[[], datetime],
) -> OnboardingCommandResult:
    """Import exact observations and validate the complete approval receipt."""

    try:
        manifest_data = _read_bounded(manifest_path)
        manifest = ProductionOnboardingManifest.model_validate_json(manifest_data)
        store = FilesystemProductionOnboardingStore(data_dir)
        for path in evidence_paths:
            store.put_evidence(_read_bounded(path))
        store.save(manifest)
        _validator(store, repository_root, clock).load_for_profile(profile)
    except ProductionOnboardingUnavailable as error:
        return _blocked(str(error))
    except (OSError, ValueError):
        return _blocked("PRODUCTION_ONBOARDING_INPUT_INVALID")
    return _ready(profile)


def run_status(
    data_dir: Path,
    *,
    profile: ProductionProfile,
    repository_root: Path,
    clock: Callable[[], datetime],
) -> OnboardingCommandResult:
    """Revalidate current PVD, terms, evaluation and built-in prompt evidence."""

    try:
        store = FilesystemProductionOnboardingStore(data_dir)
        _validator(store, repository_root, clock).load_for_profile(profile)
    except ProductionOnboardingUnavailable as error:
        return _blocked(str(error))
    except (OSError, ValueError):
        return _blocked("PRODUCTION_ONBOARDING_INPUT_INVALID")
    return _ready(profile)


def _validator(
    store: FilesystemProductionOnboardingStore,
    repository_root: Path,
    clock: Callable[[], datetime],
) -> OnboardedProductionCapabilityBundleLoader:
    def unreachable_provision(
        **_values: object,
    ) -> ProfileBackedProductionCapabilityBundle:
        raise AssertionError("status validation must not provision a production run")

    return OnboardedProductionCapabilityBundleLoader(
        store=store,
        repository_root=repository_root,
        clock=clock,
        provision=unreachable_provision,
    )


def _read_bounded(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise ValueError("ONBOARDING_INPUT_PATH_INVALID")
    data = path.read_bytes()
    if not data or len(data) > _MAX_INPUT_BYTES:
        raise ValueError("ONBOARDING_INPUT_SIZE_INVALID")
    return data


def _ready(profile: ProductionProfile) -> OnboardingCommandResult:
    return OnboardingCommandResult(
        ExitCode.OK,
        {"profile_hash": production_profile_hash(profile), "status": "READY"},
    )


def _blocked(reason_code: str) -> OnboardingCommandResult:
    return OnboardingCommandResult(
        ExitCode.CAPABILITY_UNSUPPORTED,
        {"reason_code": reason_code, "status": "BLOCKED"},
    )


__all__ = [
    "OnboardingCommandResult",
    "run_prepare",
    "run_requirements",
    "run_status",
]
