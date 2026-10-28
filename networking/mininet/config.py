"""Configuration for the deterministic Stage 2 Mininet topology."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from os import getenv


@dataclass(frozen=True, slots=True)
class TopologyConfig:
    """Local-only topology and controller connection settings."""

    controller_host: str
    controller_port: int

    @classmethod
    def from_environment(cls) -> TopologyConfig:
        """Load controller coordinates without coupling to Mininet."""

        return cls(
            controller_host=getenv("SDN_STAGE2_CONTROLLER_HOST", "127.0.0.1"),
            controller_port=int(getenv("SDN_STAGE2_CONTROLLER_PORT", "6653")),
        )

    def validate(self) -> None:
        """Restrict controller traffic to this host and a valid TCP port."""

        if not ip_address(self.controller_host).is_loopback:
            raise ValueError("Stage 2 controller host must be a loopback IP address")
        if not 1 <= self.controller_port <= 65535:
            raise ValueError("Stage 2 controller port must be between 1 and 65535")
