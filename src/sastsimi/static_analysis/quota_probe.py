"""Exercise an explicitly supplied trusted static-output quota boundary.

This is a consumer of the host quota port, not a directory-size quota backend.
The host must enforce writes and retain denied-write evidence independently of
the process. A small destructive probe uses its own disposable lease only.
"""

from __future__ import annotations

import errno
import os
import stat
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from sastsimi.contracts.refs import HostConfigurationRef
from sastsimi.ports.dto import StaticOutputQuotaBinding, StaticOutputQuotaProof
from sastsimi.ports.static_tool import (
    ProductionStaticOutputQuotaPort,
    StaticOutputPurpose,
)


def prove_static_output_quota(
    port: ProductionStaticOutputQuotaPort | None,
    *,
    profile_ref: HostConfigurationRef,
    database_limit_bytes: int | None,
    output_limit_bytes: int,
) -> StaticOutputQuotaProof | None:
    """Prove denial and sticky evidence, then exact DB/execution allocations."""

    if (
        port is None
        or not getattr(port, "backend_key", "")
        or len(getattr(port, "enforcement_identity_sha256", "")) != 64
        or not isinstance(database_limit_bytes, int)
        or isinstance(database_limit_bytes, bool)
        or database_limit_bytes <= 0
        or output_limit_bytes <= 0
    ):
        return None
    action_id = "quota-probe-" + str(uuid4())
    bindings: list[StaticOutputQuotaBinding] = []
    purposes: tuple[tuple[StaticOutputPurpose, int], ...] = (
        ("PROBE", 65536),
        ("DATABASE", database_limit_bytes),
        ("EXECUTION", output_limit_bytes),
    )
    try:
        with ExitStack() as cleanup:
            for purpose, limit in purposes:
                binding = port.allocate(
                    purpose=purpose,
                    action_id=action_id,
                    attempt_id=action_id,
                    profile_ref=profile_ref,
                    limit_bytes=limit,
                )
                cleanup.callback(
                    port.finalize, lease_id=binding.lease_id, outcome="PROBE_COMPLETE"
                )
                if (
                    not binding.lease_id
                    or not binding.binding_id
                    or not binding.backend_key
                    or not binding.enforcement_evidence
                    or binding.hard_enforced is not True
                    or binding.limit_breached is not False
                    or binding.breach_evidence is not None
                    or binding.action_id != action_id
                    or binding.attempt_id != action_id
                    or binding.profile_ref != profile_ref
                    or binding.effective_limit_bytes != limit
                    or binding.backend_key != port.backend_key
                    or hashlib_compare_identity(
                        binding.enforcement_evidence,
                        port.enforcement_identity_sha256,
                    )
                    is False
                    or _verify(port, binding) != binding
                ):
                    return None
                _safe_root(binding.root)
                if any(
                    previous.lease_id == binding.lease_id
                    or previous.binding_id == binding.binding_id
                    or binding.root.is_relative_to(previous.root)
                    or previous.root.is_relative_to(binding.root)
                    or previous.backend_key != binding.backend_key
                    for previous in bindings
                ):
                    return None
                bindings.append(binding)
                if purpose == "PROBE" and not _write_denial(port, binding):
                    return None
        backend_keys = {binding.backend_key for binding in bindings}
        if len(backend_keys) != 1:
            return None
        return StaticOutputQuotaProof(
            backend_key=backend_keys.pop(),
            enforcement_identity_sha256=port.enforcement_identity_sha256,
            database_limit_bytes=database_limit_bytes,
            execution_limit_bytes=output_limit_bytes,
        )
    except Exception:
        # Backend, filesystem, or cleanup failure cannot become activation.
        return None


def hashlib_compare_identity(evidence: str, expected_sha256: str) -> bool:
    """Bind every lease to the approved backend identity without storing secrets."""

    import hashlib

    return hashlib.sha256(evidence.encode("utf-8")).hexdigest() == expected_sha256


def _safe_root(root: Path) -> None:
    if not root.is_absolute() or root == Path(root.anchor):
        raise ValueError("STATIC_QUOTA_ROOT_INVALID")
    for path in (root, *root.parents):
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or path.is_symlink()
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("STATIC_QUOTA_ROOT_INVALID")
    if root.resolve(strict=True) != root or any(root.iterdir()):
        raise ValueError("STATIC_QUOTA_ROOT_INVALID")


def _verify(
    port: ProductionStaticOutputQuotaPort,
    binding: StaticOutputQuotaBinding,
) -> StaticOutputQuotaBinding:
    return port.verify(
        lease_id=binding.lease_id,
        action_id=binding.action_id,
        attempt_id=binding.attempt_id,
        profile_ref=binding.profile_ref,
        root=binding.root,
        limit_bytes=binding.effective_limit_bytes,
    )


def _write_denial(
    port: ProductionStaticOutputQuotaPort,
    binding: StaticOutputQuotaBinding,
) -> bool:
    # Two files distinguish the aggregate attempt ceiling from a per-file cap.
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    with ExitStack() as cleanup:
        descriptors: list[int] = []
        for _index in range(2):
            fd = os.open(binding.root / (str(uuid4()) + ".probe"), flags, 0o600)
            cleanup.callback(os.close, fd)
            descriptors.append(fd)
        half = binding.effective_limit_bytes // 2
        if os.write(descriptors[0], b"x" * half) != half:
            return False
        denied = False
        remaining = binding.effective_limit_bytes - half + 1
        try:
            while remaining:
                written = os.write(descriptors[1], b"x" * remaining)
                if written <= 0:
                    return False
                remaining -= written
            os.fsync(descriptors[1])
        except OSError as error:
            denied = error.errno in {errno.ENOSPC, errno.EDQUOT}
        if not denied:
            return False
        breached = _verify(port, binding)
        if (
            breached.limit_breached is not True
            or not breached.breach_evidence
            or replace(breached, limit_breached=False, breach_evidence=None) != binding
        ):
            return False
        # Free the written bytes: a measurement-only or resetting status fails.
        for fd in descriptors:
            os.ftruncate(fd, 0)
        return _verify(port, binding) == breached
