"""Configuration contract for local development and future services."""

from __future__ import annotations

from dataclasses import dataclass
from os import getenv


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime configuration supplied through environment variables."""

    environment: str
    log_level: str
    seed: int
    enable_live_network: bool
    enable_mitigation: bool


def load_settings() -> Settings:
    """Load Stage 1 settings without activating any external system."""

    return Settings(
        environment=getenv("SDN_DEFENSE_ENV", "development"),
        log_level=getenv("SDN_DEFENSE_LOG_LEVEL", "INFO"),
        seed=int(getenv("SDN_DEFENSE_SEED", "2026")),
        enable_live_network=getenv("SDN_DEFENSE_ENABLE_LIVE_NETWORK", "false").lower()
        == "true",
        enable_mitigation=getenv("SDN_DEFENSE_ENABLE_MITIGATION", "false").lower() == "true",
    )

