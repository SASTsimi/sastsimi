"""Safe operator commands for production Provider and prompt onboarding."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
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
from sastsimi.orchestration.production_onboarding_builder import (
    ApprovedProbeResolver,
    ProductionOnboardingBundleIndex,
    compose_production_onboarding,
    safe_evidence_digest,
)
from sastsimi.prompts.production import REQUIRED_PRODUCTION_PROMPT_ROUTES

_MAX_INPUT_BYTES = 4 * 1024 * 1024
_PLAN_NAME = "onboarding-plan.json"
_HOST_PROBE_KINDS = (
    "GIT",
    "PYTHON_AST",
    "PYTHON_RUNTIME",
    "CODEQL",
    "OPENGREP",
    "DOCKER",
)


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
            _probe_plan(kind, host_id=profile.host_id) for kind in _HOST_PROBE_KINDS
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
    last_pvd = (
        16
        if any(route.role == "DYNAMIC_REPRODUCTION" for route in profile.llm_routes)
        else 15
    )
    return {
        "profile_hash": production_profile_hash(profile),
        "required_pvd_tests": [f"PVD-{index:02d}" for index in range(1, last_pvd + 1)],
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
        evidence = tuple(_read_bounded(path) for path in evidence_paths)
        with TemporaryDirectory(prefix="sastsimi-onboarding-stage-") as stage:
            staged_store = FilesystemProductionOnboardingStore(Path(stage))
            for data in evidence:
                staged_store.put_evidence(data)
            staged_store.save(manifest)
            _validator(staged_store, repository_root, clock).load_for_profile(profile)
        store = FilesystemProductionOnboardingStore(data_dir)
        for data in evidence:
            store.put_evidence(data)
        store.save(manifest)
        _validator(store, repository_root, clock).load_for_profile(profile)
    except ProductionOnboardingUnavailable as error:
        return _blocked(str(error))
    except (OSError, ValueError):
        return _blocked("PRODUCTION_ONBOARDING_INPUT_INVALID")
    return _ready(profile)


def run_compose(
    data_dir: Path,
    *,
    profile: ProductionProfile,
    approval_input_path: Path,
    slot_template_paths: tuple[Path, ...],
    evidence_paths: tuple[Path, ...],
    output_dir: Path,
    repository_root: Path,
    clock: Callable[[], datetime],
    resolve_probe: ApprovedProbeResolver,
) -> OnboardingCommandResult:
    """Atomically compose already-approved exact inputs into a portable bundle."""

    del data_dir
    try:
        if output_dir.exists() or output_dir.is_symlink():
            raise ValueError("ONBOARDING_BUNDLE_ALREADY_EXISTS")
        parent = output_dir.parent.resolve()
        parent.mkdir(parents=True, exist_ok=True)
        approval_input = _read_bounded(approval_input_path)
        slot_templates = tuple(_read_bounded(path) for path in slot_template_paths)
        evidence = _read_evidence(evidence_paths)
        composed = compose_production_onboarding(
            approval_input=approval_input,
            slot_templates=slot_templates,
            evidence=evidence,
            profile_hash=production_profile_hash(profile),
            host_id=profile.host_id,
            resolve_probe=resolve_probe,
        )
        with TemporaryDirectory(
            prefix=".sastsimi-onboarding-compose-", dir=parent
        ) as temporary:
            stage = Path(temporary) / "bundle"
            stage.mkdir()
            _write_file(stage / "production-onboarding.json", composed.onboarding_bytes)
            _write_file(
                stage / "production-provisioning.json", composed.provisioning_bytes
            )
            _write_file(stage / "bundle-index.json", composed.index_bytes)
            for digest, data in composed.evidence.items():
                _write_file(
                    stage / "evidence" / "sha256" / digest[:2] / digest[2:], data
                )

            # Keep the validation CAS outside the staged output path.  Besides
            # ensuring validation cannot mutate the bundle, this avoids the
            # legacy Windows path limit after adding two SHA-256 directories.
            with TemporaryDirectory(prefix="sastsimi-onboarding-validate-") as valid:
                validation_store = FilesystemProductionOnboardingStore(Path(valid))
                for data in composed.evidence.values():
                    validation_store.put_evidence(data)
                validation_store.save(composed.onboarding)
                _validator(validation_store, repository_root, clock).load_for_profile(
                    profile
                )
            os.replace(stage, output_dir)
    except ProductionOnboardingUnavailable as error:
        return _blocked(str(error))
    except (OSError, ValueError):
        return _blocked("PRODUCTION_ONBOARDING_COMPOSE_INVALID")
    return OnboardingCommandResult(
        ExitCode.OK,
        {
            "evidence_count": len(composed.evidence),
            "onboarding_manifest_sha256": composed.index.onboarding_manifest_sha256,
            "profile_hash": production_profile_hash(profile),
            "provisioning_manifest_sha256": (
                composed.index.provisioning_manifest_sha256
            ),
            "status": "COMPOSED",
        },
    )


def run_prepare_bundle(
    data_dir: Path,
    *,
    profile: ProductionProfile,
    bundle_dir: Path,
    repository_root: Path,
    clock: Callable[[], datetime],
) -> OnboardingCommandResult:
    """Import one composed bundle only when its hash index is exact and complete."""

    try:
        if not bundle_dir.is_dir() or bundle_dir.is_symlink():
            raise ValueError("ONBOARDING_BUNDLE_PATH_INVALID")
        index = ProductionOnboardingBundleIndex.model_validate_json(
            _read_bounded(bundle_dir / "bundle-index.json")
        )
        manifest_path = bundle_dir / "production-onboarding.json"
        manifest_data = _read_bounded(manifest_path)
        if (
            hashlib.sha256(manifest_data).hexdigest()
            != index.onboarding_manifest_sha256
        ):
            raise ValueError("ONBOARDING_BUNDLE_MANIFEST_STALE")
        evidence_paths = tuple(
            bundle_dir / "evidence" / "sha256" / digest[:2] / digest[2:]
            for digest in index.evidence_sha256
        )
        expected_files = {
            bundle_dir / "bundle-index.json",
            manifest_path,
            bundle_dir / "production-provisioning.json",
            *evidence_paths,
        }
        discovered_files: set[Path] = set()
        for path in bundle_dir.rglob("*"):
            if path.is_symlink():
                raise ValueError("ONBOARDING_BUNDLE_PATH_INVALID")
            if path.is_file():
                discovered_files.add(path)
            elif not path.is_dir():
                raise ValueError("ONBOARDING_BUNDLE_PATH_INVALID")
        if discovered_files != expected_files:
            raise ValueError("ONBOARDING_BUNDLE_FILE_SET_MISMATCH")
        for digest, path in zip(index.evidence_sha256, evidence_paths, strict=True):
            if hashlib.sha256(_read_bounded(path)).hexdigest() != digest:
                raise ValueError("ONBOARDING_BUNDLE_EVIDENCE_STALE")
        provisioning_path = (
            bundle_dir
            / "evidence"
            / "sha256"
            / index.provisioning_manifest_sha256[:2]
            / index.provisioning_manifest_sha256[2:]
        )
        if _read_bounded(bundle_dir / "production-provisioning.json") != _read_bounded(
            provisioning_path
        ):
            raise ValueError("ONBOARDING_BUNDLE_PROVISIONING_STALE")
    except (OSError, ValueError):
        return _blocked("PRODUCTION_ONBOARDING_BUNDLE_INVALID")
    return run_prepare(
        data_dir,
        profile=profile,
        manifest_path=manifest_path,
        evidence_paths=evidence_paths,
        repository_root=repository_root,
        clock=clock,
    )


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


def _read_evidence(paths: tuple[Path, ...]) -> dict[str, bytes]:
    evidence: dict[str, bytes] = {}
    for path in paths:
        data = _read_bounded(path)
        digest = safe_evidence_digest(data)
        previous = evidence.setdefault(digest, data)
        if previous != data:
            raise ValueError("ONBOARDING_EVIDENCE_HASH_MISMATCH")
    return evidence


def _write_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


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


def _blocked_with_code(reason_code: str, code: ExitCode) -> OnboardingCommandResult:
    return OnboardingCommandResult(
        code,
        {"reason_code": reason_code, "status": "BLOCKED"},
    )


__all__ = [
    "OnboardingCommandResult",
    "run_compose",
    "run_init",
    "run_prepare",
    "run_prepare_bundle",
    "run_requirements",
    "run_status",
]
