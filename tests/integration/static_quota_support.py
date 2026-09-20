"""A kernel-write boundary double; all probe files and engine logic remain real."""

import errno
import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef
from sastsimi.ports.dto import StaticOutputQuotaBinding
from sastsimi.ports.static_tool import StaticOutputPurpose


class TestQuota:
    __test__ = False
    backend_key = "test-kernel-quota"
    enforcement_identity_sha256 = hashlib.sha256(b"test-enforcement").hexdigest()

    def __init__(
        self,
        root: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        enforce: bool = True,
        sticky: bool = True,
        unbounded_purpose: StaticOutputPurpose | None = None,
        reset_when_empty: bool = False,
    ) -> None:
        self.root = root
        self.bindings: dict[str, StaticOutputQuotaBinding] = {}
        self.enforce = enforce
        self.sticky = sticky
        self.unbounded_purpose = unbounded_purpose
        self.reset_when_empty = reset_when_empty
        self.finalized: list[tuple[str, str]] = []
        write = os.write

        def bounded_write(fd: int, data: bytes) -> int:
            identity = os.fstat(fd)
            for key, binding in self.bindings.items():
                files = tuple(binding.root.iterdir())
                if any(p.stat().st_ino == identity.st_ino for p in files):
                    used = sum(p.stat().st_size for p in files)
                    if (
                        self.enforce
                        and used + len(data) > binding.effective_limit_bytes
                    ):
                        if self.sticky:
                            self.bindings[key] = replace(
                                binding,
                                limit_breached=True,
                                breach_evidence="kernel-denied-write",
                            )
                        raise OSError(errno.ENOSPC, "quota denied")
            return write(fd, data)

        monkeypatch.setattr(os, "write", bounded_write)

    def allocate(
        self,
        *,
        purpose: StaticOutputPurpose,
        action_id: str,
        attempt_id: str,
        profile_ref: StoredDataRef | HostConfigurationRef,
        limit_bytes: int,
    ) -> StaticOutputQuotaBinding:
        key = f"lease-{len(self.bindings)}"
        root = self.root / key
        root.mkdir(parents=True)
        binding = StaticOutputQuotaBinding(
            binding_id=key,
            lease_id=key,
            backend_key="test-kernel-quota",
            enforcement_evidence="test-enforcement",
            root=root,
            action_id=action_id,
            attempt_id=attempt_id,
            profile_ref=profile_ref,
            effective_limit_bytes=limit_bytes,
            hard_enforced=purpose != self.unbounded_purpose,
            limit_breached=False,
            breach_evidence=None,
        )
        self.bindings[key] = binding
        return binding

    def verify(
        self,
        *,
        lease_id: str,
        action_id: str,
        attempt_id: str,
        profile_ref: StoredDataRef | HostConfigurationRef,
        root: Path,
        limit_bytes: int,
    ) -> StaticOutputQuotaBinding:
        binding = self.bindings[lease_id]
        if self.reset_when_empty and not any(p.stat().st_size for p in root.iterdir()):
            return replace(binding, limit_breached=False, breach_evidence=None)
        return binding

    def finalize(self, *, lease_id: str, outcome: str) -> None:
        self.finalized.append((lease_id, outcome))
