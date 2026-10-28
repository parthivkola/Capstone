"""Bounded, testbed-only selection for controller packet-evidence observations."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PacketEvidencePolicy:
    """Fixed observation scope for the existing isolated Stage 3 port scan."""

    ingress_port: int = 2
    egress_port: int = 3
    source_ip: str = "10.0.0.2"
    destination_ip: str = "10.0.0.3"
    destination_ports: tuple[int, ...] = (22, 53, 67, 80, 443, 8080, 18080, 5353)
    controller_copy_max_bytes: int = 54
    flow_priority: int = 20
    flow_cookie: int = 0x534445560001
    flow_hard_timeout_seconds: int = 30
    max_observations_per_second: int = 4
    max_observations_per_run: int = 16

    def __post_init__(self) -> None:
        if self.ingress_port <= 0 or self.egress_port <= 0:
            raise ValueError("packet evidence ports must be positive")
        if not self.source_ip or not self.destination_ip:
            raise ValueError("packet evidence IP scope is required")
        if not self.destination_ports or len(set(self.destination_ports)) != len(
            self.destination_ports
        ):
            raise ValueError("packet evidence ports must be non-empty and unique")
        if any(port < 1 or port > 65535 for port in self.destination_ports):
            raise ValueError("packet evidence destination ports must be valid TCP ports")
        if not 54 <= self.controller_copy_max_bytes <= 128:
            raise ValueError("controller copies must contain only a bounded header prefix")
        if not 1 <= self.max_observations_per_second <= 100:
            raise ValueError("packet evidence rate must be between 1 and 100 per second")
        if not 1 <= self.max_observations_per_run <= 1000:
            raise ValueError("packet evidence run cap must be between 1 and 1000")
        if not 1 <= self.flow_hard_timeout_seconds <= 60:
            raise ValueError("packet evidence rules must expire within 60 seconds")


class PacketEvidenceBudget:
    """Deterministic rolling-rate and per-run acceptance budget with constant memory."""

    def __init__(self, policy: PacketEvidencePolicy) -> None:
        self.policy = policy
        self._run_id: str | None = None
        self._accepted_times: deque[int] = deque(maxlen=policy.max_observations_per_second)
        self._offered = 0
        self._accepted = 0
        self._dropped_rate = 0
        self._dropped_run = 0
        self._last_monotonic_ns: int | None = None
        self._first_observed_ns: int | None = None

    @property
    def run_id(self) -> str | None:
        return self._run_id

    @property
    def accepted_count(self) -> int:
        return self._accepted

    def begin_run(self, run_id: str) -> None:
        if not run_id:
            raise ValueError("packet evidence run ID must be non-empty")
        if self._run_id is not None:
            raise RuntimeError("finish the active packet evidence run before starting another")
        self._run_id = run_id
        self._accepted_times.clear()
        self._offered = 0
        self._accepted = 0
        self._dropped_rate = 0
        self._dropped_run = 0
        self._last_monotonic_ns = None
        self._first_observed_ns = None

    def offer(self, run_id: str | None, monotonic_ns: int) -> bool:
        """Return true for a retained event; false for absent run or bounded drop."""

        if monotonic_ns < 0:
            raise ValueError("monotonic timestamp must be non-negative")
        if run_id is None:
            return False
        if run_id != self._run_id:
            raise ValueError("packet evidence run ID does not match the active run")
        if self._last_monotonic_ns is not None and monotonic_ns < self._last_monotonic_ns:
            raise ValueError("packet evidence monotonic time moved backwards")
        self._last_monotonic_ns = monotonic_ns
        if self._first_observed_ns is None:
            self._first_observed_ns = monotonic_ns
        self._offered += 1
        cutoff = monotonic_ns - 1_000_000_000
        while self._accepted_times and self._accepted_times[0] <= cutoff:
            self._accepted_times.popleft()
        if self._accepted >= self.policy.max_observations_per_run:
            self._dropped_run += 1
            return False
        if len(self._accepted_times) >= self.policy.max_observations_per_second:
            self._dropped_rate += 1
            return False
        self._accepted_times.append(monotonic_ns)
        self._accepted += 1
        return True

    def finish_run(self, run_id: str, *, ended_at: str) -> dict[str, object]:
        if self._run_id != run_id:
            raise ValueError("cannot finish a packet evidence run that is not active")
        summary: dict[str, object] = {
            "run_id": run_id,
            "ended_at": ended_at,
            "packetins_offered": self._offered,
            "observations_accepted": self._accepted,
            "observations_dropped": self._dropped_rate + self._dropped_run,
            "dropped_rate_limit": self._dropped_rate,
            "dropped_run_limit": self._dropped_run,
            "max_observations_per_second": self.policy.max_observations_per_second,
            "max_observations_per_run": self.policy.max_observations_per_run,
            "first_observation_monotonic_ns": self._first_observed_ns,
            "last_observation_monotonic_ns": self._last_monotonic_ns,
            "memory_queue_capacity": 0,
            "sampling_policy": "accept-in-arrival-order-with-rolling-1s-and-run-caps",
        }
        self._run_id = None
        self._accepted_times.clear()
        self._offered = 0
        self._accepted = 0
        self._dropped_rate = 0
        self._dropped_run = 0
        self._last_monotonic_ns = None
        self._first_observed_ns = None
        return summary
