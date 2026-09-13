"""Safe operator commands for production Provider and prompt onboarding."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TypedDict

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
_PLAN_NAME = "onboarding-plan.json"
_HOST_PROBE_KINDS = ("GIT", "PYTHON_AST", "CODEQL", "OPENGREP", "DOCKER")


@dataclass(frozen=True, slots=True)
class OnboardingCommandResult:
    code: ExitCode
    data: dict[str, object]


class _OnboardingRequirements(TypedDict):
    profile_hash: str
    required_pvd_tests: list[str]
    required_routes: list[dict[str, object]]


def run_init(
    output_dir: Path,
    *,
    profile: ProductionProfile,
    repository_root: Path,
) -> OnboardingCommandResult:
    """Create a non-authoritative operator plan without claiming probe success."""

    plan_path = output_dir / _PLAN_NAME
    try:
        if output_dir.is_symlink():
            raise ValueError("ONBOARDING_OUTPUT_PATH_INVALID")
        output_dir.mkdir(parents=True, exist_ok=True)
        if plan_path.exists() or plan_path.is_symlink():
            return _blocked_with_code(
                "ONBOARDING_PLAN_ALREADY_EXISTS", ExitCode.CONFIG_ERROR
            )
        requirements = _requirements(profile, repository_root=repository_root)
        provider_models = sorted(
            {
                (provider.provider_profile_key, provider.product, route.model)
                for provider in profile.providers
                for route in profile.llm_routes
                if route.provider_profile_key == provider.provider_profile_key
            }
        )
        capability_probes = [
            _probe_plan(kind, host_id=profile.host_id)
            for kind in _HOST_PROBE_KINDS
        ]
        capability_probes.extend(
            _probe_plan(
                "OPENAI_API",
                host_id=profile.host_id,
                model=model,
                credential_ref=provider.credential_ref.reference,
            )
            for key, product, model in provider_models
            for provider in profile.providers
            if product == "OPENAI_API" and provider.provider_profile_key == key
        )
        plan = {
            "schema_version": 1,
            "kind": "SASTSIMI_PRODUCTION_ONBOARDING_PLAN",
            "status": "PREPARATION_REQUIRED",
            "profile_hash": requirements["profile_hash"],
            "host_id": profile.host_id,
            "capability_probes": capability_probes,
            "provider_probe_gaps": [
                {
                    "provider_profile_key": key,
                    "product": product,
                    "model": model,
                    "status": "DEDICATED_PROBE_COMMAND_REQUIRED",
                }
                for key, product, model in provider_models
                if product != "OPENAI_API"
            ],
            "pvd_checks": [
                {
                    "provider_profile_key": key,
                    "product": product,
                    "model": model,
                    "test_id": test_id,
                    "result": "PENDING",
                    "evidence_sha256": None,
                }
                for key, product, model in provider_models
                for test_id in requirements["required_pvd_tests"]
            ],
            "route_reviews": [
                route | {"decision": "PENDING", "evidence_sha256": None}
                for route in requirements["required_routes"]
            ],
            "required_provisioning_slots": {
                "capabilities": [
                    "GIT_CLONE",
                    "GIT_CHECKOUT",
                    "PYTHON_RUNTIME",
                    "AST",
                    "CODEQL",
                    "OPENGREP",
                    "DOCKER",
                ],
                "artifacts": [
                    "WORKSPACE_STORAGE",
                    "STATIC_ANALYSIS",
                    "VERIFICATION_PLAYBOOKS",
                    "SANDBOX_PROFILE",
                    "POLICY_CATALOG",
                    "PROVIDER_CONFIGURATION",
                    "PROMPT_ROUTES",
                ],
            },
            "next_steps": [
                "Run each listed capability probe and retain its exact receipt.",
                "Run every pending provider validation and retain exact evidence.",
                "Complete route evaluation and human approval for each route.",
                "Create the signed provisioning and onboarding manifests separately.",
                "Import only completed evidence with onboarding prepare.",
            ],
        }
        payload = (
            json.dumps(plan, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        with plan_path.open("xb") as stream:
            stream.write(payload)
    except FileExistsError:
        return _blocked_with_code(
            "ONBOARDING_PLAN_ALREADY_EXISTS", ExitCode.CONFIG_ERROR
        )
    except (OSError, ValueError):
        return _blocked_with_code(
            "ONBOARDING_PLAN_CREATE_FAILED", ExitCode.CONFIG_ERROR
        )
    return OnboardingCommandResult(
        ExitCode.OK,
        {
            "plan_path": str(plan_path),
            "profile_hash": requirements["profile_hash"],
            "status": "PREPARATION_REQUIRED",
        },
    )


def run_requirements(
    profile: ProductionProfile, *, repository_root: Path
) -> OnboardingCommandResult:
    """List work that must produce evidence; never infer a successful PVD."""

    try:
        requirements = _requirements(profile, repository_root=repository_root)
    except (OSError, ValueError):
        return _blocked("PRODUCTION_PROMPT_TEMPLATE_UNAVAILABLE")
    return OnboardingCommandResult(
        ExitCode.CAPABILITY_UNSUPPORTED,
        requirements | {"status": "BLOCKED"},
    )


def _requirements(
    profile: ProductionProfile, *, repository_root: Path
) -> _OnboardingRequirements:
    routes: list[dict[str, object]] = [
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
    if len(routes) != len(REQUIRED_PRODUCTION_PROMPT_ROUTES):
        raise ValueError("PRODUCTION_PROMPT_ROUTE_SET_INCOMPLETE")
    return {
        "profile_hash": production_profile_hash(profile),
        "required_pvd_tests": [f"PVD-{index:02d}" for index in range(1, 16)],
        "required_routes": routes,
    }


def _probe_plan(
    kind: str,
    *,
    host_id: str,
    model: str | None = None,
    credential_ref: str | None = None,
) -> dict[str, object]:
    argv = [
        "sastsimi",
        "--data-dir",
        "<DATA_DIR>",
        "capability",
        "--host-id",
        host_id,
        "probe",
        kind,
    ]
    if model is not None:
        argv.extend(("--model", model))
    if credential_ref is not None:
        argv.extend(("--credential-ref", credential_ref))
    return {"argv": argv, "kind": kind, "status": "NOT_RUN"}


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


def _blocked_with_code(
    reason_code: str, code: ExitCode
) -> OnboardingCommandResult:
    return OnboardingCommandResult(
        code,
        {"reason_code": reason_code, "status": "BLOCKED"},
    )


__all__ = [
    "OnboardingCommandResult",
    "run_init",
    "run_prepare",
    "run_requirements",
    "run_status",
]
