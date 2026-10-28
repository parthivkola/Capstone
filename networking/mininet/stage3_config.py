"""Hard bounds and fixed local targets for Stage 3 traffic scenarios."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from math import isfinite


class Scenario(StrEnum):
    """The six named, bounded Stage 3 scenarios."""

    ARP_SPOOF = "arp-spoof"
    DHCP_STARVATION = "dhcp-starvation"
    PORT_SCAN = "port-scan"
    SYN_FLOOD = "syn-flood"
    ROGUE_DEVICE = "rogue-device"
    DNS_ANOMALY = "dns-anomaly"


@dataclass(frozen=True, slots=True)
class ScenarioBounds:
    """Scenario limits; targets are fixed to the Stage 2 topology."""

    target: str
    duration_seconds: float
    maximum_duration_seconds: float
    rate_per_second: float
    maximum_rate_per_second: float
    maximum_events: int


SCENARIO_BOUNDS: dict[Scenario, ScenarioBounds] = {
    Scenario.ARP_SPOOF: ScenarioBounds("h1 (ARP view of h3)", 5, 5, 1, 1, 5),
    Scenario.DHCP_STARVATION: ScenarioBounds("h3 local DHCP fixture", 4, 4, 1, 1, 4),
    Scenario.PORT_SCAN: ScenarioBounds("h3", 8, 10, 1, 1, 8),
    Scenario.SYN_FLOOD: ScenarioBounds("h3:18080", 5, 5, 10, 10, 50),
    Scenario.ROGUE_DEVICE: ScenarioBounds("s1 (existing h2 port)", 10, 30, 1, 1, 10),
    Scenario.DNS_ANOMALY: ScenarioBounds("h3 local DNS fixture", 10, 10, 1, 1, 10),
}
SCENARIO_TARGET_IDS = {
    Scenario.ARP_SPOOF: "h1",
    Scenario.DHCP_STARVATION: "h3",
    Scenario.PORT_SCAN: "h3",
    Scenario.SYN_FLOOD: "h3",
    Scenario.ROGUE_DEVICE: "s1",
    Scenario.DNS_ANOMALY: "h3",
}

PORT_SCAN_ALLOWLIST = (22, 53, 67, 80, 443, 8080, 18080, 5353)
DNS_TEST_NAMES = tuple(f"unusual-{index}.test" for index in range(1, 11))
DHCP_CLIENT_MACS = tuple(f"02:00:00:00:03:{index:02x}" for index in range(1, 5))
DHCP_POOL = tuple(f"10.0.0.{address}" for address in range(100, 104))


def bounded_value(value: float, maximum: float, name: str) -> float:
    """Validate a positive scenario parameter without silently clamping it."""

    if not isfinite(value) or value <= 0 or value > maximum:
        raise ValueError(f"{name} must be greater than 0 and at most {maximum}")
    return value


def validate_target(scenario: Scenario, target: str | None) -> str:
    """Allow only the scenario's explicitly named fixed Mininet target."""

    expected = SCENARIO_TARGET_IDS[scenario]
    if target is not None and target != expected:
        raise ValueError(f"{scenario.value} target is fixed to {expected}")
    return expected


def validate_scenario_parameters(
    scenario: Scenario,
    duration_seconds: float | None = None,
    rate_per_second: float | None = None,
    ports: tuple[int, ...] | None = None,
) -> tuple[float, float, tuple[int, ...]]:
    """Return validated effective settings and a fixed allowlisted port set."""

    bounds = SCENARIO_BOUNDS[scenario]
    duration = bounded_value(
        bounds.duration_seconds if duration_seconds is None else duration_seconds,
        bounds.maximum_duration_seconds,
        "duration_seconds",
    )
    rate = bounded_value(
        bounds.rate_per_second if rate_per_second is None else rate_per_second,
        bounds.maximum_rate_per_second,
        "rate_per_second",
    )
    selected_ports = PORT_SCAN_ALLOWLIST if ports is None else ports
    if scenario is Scenario.PORT_SCAN:
        if not selected_ports or len(selected_ports) > 8:
            raise ValueError("port scan requires 1 to 8 explicitly allowlisted TCP ports")
        if len(set(selected_ports)) != len(selected_ports):
            raise ValueError("port scan ports must not contain duplicates")
        if any(port not in PORT_SCAN_ALLOWLIST for port in selected_ports):
            raise ValueError("port scan ports must come from the fixed local allowlist")
    elif ports is not None:
        raise ValueError("--ports is supported only for the fixed h3 TCP port-scan scenario")
    return duration, rate, tuple(selected_ports)
