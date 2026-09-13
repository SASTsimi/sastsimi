"""Observed container state shared through Docker ports."""

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DockerContainerState:
    container_id: str
    image_digest: str
    user: str
    network_mode: str
    privileged: bool
    read_only_rootfs: bool
    running: bool
    exit_code: int
    health_status: str | None
    labels: Mapping[str, str]
