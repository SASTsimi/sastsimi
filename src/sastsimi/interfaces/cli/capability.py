"""Safe operator commands for probing and approving production capabilities."""

from __future__ import annotations

import hashlib
import platform
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import getnode

from sastsimi.capabilities import (
    CapabilityProbeReceipt,
    ProductionCapabilityProbeService,
    build_production_capability_probe_service,
)
from sastsimi.capabilities.models import ProbeKind
from sastsimi.config.secrets import SecretReference
from sastsimi.contracts.refs import HostConfigurationRef
from sastsimi.interfaces.cli.exit_codes import ExitCode


class CapabilityService(Protocol):
    def probe(
        self,
        kind: ProbeKind,
        *,
        model: str | None = None,
        credential_ref: SecretReference | None = None,
    ) -> CapabilityProbeReceipt: ...

    def list(self) -> tuple[CapabilityProbeReceipt, ...]: ...

    def approve(
        self, probe_id: str, *, expected_target_hash: str
    ) -> HostConfigurationRef: ...


@dataclass(frozen=True)
class CapabilityCommandResult:
    code: ExitCode
    data: dict[str, object]


_EXECUTABLE_BY_KIND: dict[ProbeKind, tuple[str, str] | None] = {
    "GIT": ("git", "git"),
    "PYTHON_AST": None,
    "PYTHON_RUNTIME": None,
    "OPENGREP": ("opengrep", "opengrep"),
    "DOCKER": ("docker", "docker"),
    "OPENAI_API": None,
    "CODEQL": ("docker", "docker"),
}


def build_service(
    data_dir: Path,
    *,
    kind: ProbeKind | None,
    host_id: str | None,
    docker_host: str | None,
    codeql_container_config: Any | None = None,
) -> ProductionCapabilityProbeService:
    """Compose only the executable needed by this operator action."""

    executable_paths: dict[str, Path] = {}
    executable = _EXECUTABLE_BY_KIND.get(kind) if kind is not None else None
    if executable is not None:
        key, command = executable
        located = shutil.which(command)
        if located is not None:
            executable_paths[key] = Path(located).resolve(strict=True)
    selected_docker_host = None
    if "docker" in executable_paths:
        selected_docker_host = docker_host or _default_docker_host()
    return build_production_capability_probe_service(
        data_dir,
        host_id=host_id or _default_host_id(),
        executable_paths=executable_paths,
        docker_host=selected_docker_host,
        codeql_container_config=codeql_container_config,
    )


def run_probe(
    data_dir: Path,
    *,
    kind: str,
    model: str | None,
    credential_ref: str | None,
    host_id: str | None,
    docker_host: str | None,
    codeql_container_config: Any | None = None,
) -> CapabilityCommandResult:
    probe_kind = cast(ProbeKind, kind)
    try:
        secret_ref = (
            SecretReference(reference=credential_ref)
            if credential_ref is not None
            else None
        )
        service = build_service(
            data_dir,
            kind=probe_kind,
            host_id=host_id,
            docker_host=docker_host,
            codeql_container_config=codeql_container_config,
        )
        receipt = service.probe(
            probe_kind,
            model=model,
            credential_ref=secret_ref,
        )
    except (LookupError, OSError, ValueError):
        return _blocked("Capability probe could not be completed")
    code = (
        ExitCode.OK if receipt.status == "PASSED" else ExitCode.CAPABILITY_UNSUPPORTED
    )
    return CapabilityCommandResult(code, _safe_receipt(receipt))


def run_list(
    data_dir: Path,
    *,
    host_id: str | None,
) -> CapabilityCommandResult:
    try:
        service = build_service(
            data_dir,
            kind=None,
            host_id=host_id,
            docker_host=None,
        )
        receipts = service.list()
    except (LookupError, OSError, ValueError):
        return _blocked("Capability records could not be read")
    return CapabilityCommandResult(
        ExitCode.OK,
        {"count": len(receipts), "probes": [_safe_receipt(item) for item in receipts]},
    )


def run_approve(
    data_dir: Path,
    *,
    probe_id: str,
    target_hash: str,
    host_id: str | None,
    docker_host: str | None,
    codeql_container_config: Any | None = None,
) -> CapabilityCommandResult:
    try:
        lookup = build_service(
            data_dir,
            kind=None,
            host_id=host_id,
            docker_host=None,
        )
        matches = tuple(item for item in lookup.list() if item.probe_id == probe_id)
        if len(matches) != 1:
            raise LookupError("CAPABILITY_PROBE_NOT_FOUND")
        receipt = matches[0]
        if receipt.kind == "CODEQL" and codeql_container_config is None:
            raise ValueError("CODEQL_PRODUCTION_PROFILE_REQUIRED")
        service = build_service(
            data_dir,
            kind=receipt.kind,
            host_id=host_id,
            docker_host=docker_host,
            codeql_container_config=codeql_container_config,
        )
        profile_ref = service.approve(
            probe_id,
            expected_target_hash=target_hash,
        )
    except (LookupError, OSError, ValueError):
        return CapabilityCommandResult(
            ExitCode.CAPABILITY_UNSUPPORTED,
            {
                "probe_id": probe_id,
                "safe_summary": "Capability approval was denied",
                "status": "BLOCKED",
            },
        )
    return CapabilityCommandResult(
        ExitCode.OK,
        {
            "probe_id": probe_id,
            "profile_ref": profile_ref.model_dump(mode="json"),
            "status": "ACTIVE",
        },
    )


def _safe_receipt(receipt: CapabilityProbeReceipt) -> dict[str, object]:
    approved = receipt.approved_profile_ref
    return {
        "activation_supported": receipt.activation_supported,
        "approval_target_hash": receipt.approval_target_hash,
        "approved_profile_ref": (
            approved.model_dump(mode="json") if approved is not None else None
        ),
        "kind": receipt.kind,
        "probe_id": receipt.probe_id,
        "safe_summary": receipt.safe_summary,
        "status": receipt.status,
    }


def _blocked(summary: str) -> CapabilityCommandResult:
    return CapabilityCommandResult(
        ExitCode.CAPABILITY_UNSUPPORTED,
        {"safe_summary": summary, "status": "BLOCKED"},
    )


def _windows_machine_guid() -> str | None:
    """Read the Windows installation GUID, or None when it is unavailable."""

    try:
        import winreg  # type: ignore[import-not-found,unused-ignore]
    except ImportError:
        return None
    registry: Any = winreg
    try:
        with registry.OpenKey(
            registry.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            registry.KEY_READ | registry.KEY_WOW64_64KEY,
        ) as key:
            guid = registry.QueryValueEx(key, "MachineGuid")[0]
    except OSError:
        return None
    return guid.strip() if isinstance(guid, str) and guid.strip() else None


def _machine_identifier() -> str:
    """Return an identifier that is the same on every run of this machine.

    ``uuid.getnode()`` is documented to return a random 48-bit value when the
    hardware address cannot be read, and some CPython builds take that path on
    every process.  A host identity derived from it would differ between the
    probe and the approval, so a stable operating-system identifier is read
    first and the random fallback is refused outright.
    """

    for path in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value
    if platform.system().lower() == "windows":
        guid = _windows_machine_guid()
        if guid is not None:
            return guid
    node = getnode()
    # CPython sets the multicast bit on the randomly generated fallback.
    if node >> 40 & 1:
        raise ValueError("HOST_IDENTITY_UNSTABLE")
    return f"{node:012x}"


def _default_host_id() -> str:
    material = f"{platform.system()}|{platform.node()}|{_machine_identifier()}".encode()
    return "host-" + hashlib.sha256(material).hexdigest()[:24]


def _default_docker_host() -> str:
    if platform.system().lower() == "windows":
        return "npipe:////./pipe/docker_engine"
    return "unix:///var/run/docker.sock"


__all__ = [
    "CapabilityCommandResult",
    "build_service",
    "run_approve",
    "run_list",
    "run_probe",
]
