"""Independent OVS flow-table polling for Stage 7 enforcement confirmation."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from time import monotonic, sleep

from services.mitigation.orchestrator import SwitchObservation
from src.sdn_defense.contracts import MitigationScope


class OvsFlowVerifier:
    """Verify cookie and expected match through ``ovs-ofctl dump-flows``."""

    def __init__(
        self,
        bridge: str,
        *,
        executable: str = "ovs-ofctl",
        protocol: str = "OpenFlow13",
        clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] = sleep,
        poll_interval_seconds: float = 0.05,
    ) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", bridge):
            raise ValueError("bridge must be a local OVS bridge name")
        if poll_interval_seconds <= 0:
            raise ValueError("poll interval must be positive")
        self.bridge = bridge
        self.executable = executable
        self.protocol = protocol
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic_clock or monotonic
        self._sleep = sleeper
        self._poll_interval = poll_interval_seconds

    def wait_for_present(
        self, cookie: int, scope: MitigationScope, timeout_seconds: float
    ) -> SwitchObservation:
        expected = self._expected_match(scope)
        return self._poll(
            cookie,
            timeout_seconds,
            lambda dump: any(
                self._line_matches(line, cookie, expected) for line in dump.splitlines()
            ),
            expected_present=True,
        )

    def wait_for_absent(self, cookie: int, timeout_seconds: float) -> SwitchObservation:
        return self._poll(
            cookie,
            timeout_seconds,
            lambda dump: any(self._cookie_matches(line, cookie) for line in dump.splitlines()),
            expected_present=False,
        )

    def dump_flows(self) -> str:
        """Read current bridge state; command errors are never treated as absence."""

        result = subprocess.run(
            [self.executable, "-O", self.protocol, "dump-flows", self.bridge],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            raise RuntimeError(f"ovs-ofctl flow dump failed: {result.stderr.strip()}")
        return result.stdout

    def _poll(
        self,
        cookie: int,
        timeout_seconds: float,
        predicate: Callable[[str], bool],
        *,
        expected_present: bool,
    ) -> SwitchObservation:
        if timeout_seconds <= 0:
            raise ValueError("verification timeout must be positive")
        deadline = self._monotonic() + timeout_seconds
        last_dump = ""
        while True:
            last_dump = self.dump_flows()
            present = predicate(last_dump)
            if present is expected_present:
                detail = (
                    "cookie/match observed in OVS dump" if present else "cookie absent in OVS dump"
                )
                return SwitchObservation(present, self._clock(), detail)
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                return SwitchObservation(
                    present,
                    self._clock(),
                    f"expected present={expected_present} for cookie 0x{cookie:x}; "
                    f"last observed present={present}",
                )
            self._sleep(min(self._poll_interval, remaining))

    @staticmethod
    def _cookie_matches(line: str, cookie: int) -> bool:
        found = re.search(r"\bcookie=0x([0-9a-fA-F]+)", line)
        return found is not None and int(found.group(1), 16) == cookie

    @classmethod
    def _line_matches(cls, line: str, cookie: int, expected: tuple[str, ...]) -> bool:
        return (
            cls._cookie_matches(line, cookie)
            and all(term in line for term in expected)
            and "actions=drop" in line
        )

    @staticmethod
    def _expected_match(scope: MitigationScope) -> tuple[str, ...]:
        selectors = dict(scope.selectors)
        aliases = {
            "src_ip": "nw_src",
            "dst_ip": "nw_dst",
            "src_mac": "dl_src",
            "dst_mac": "dl_dst",
            "in_port": "in_port",
            "src_port": "tp_src",
            "dst_port": "tp_dst",
        }
        terms: list[str] = []
        for key, value in selectors.items():
            if key == "datapath_id":
                continue
            if key == "ip_protocol":
                protocol_value = int(value)
                terms.append(
                    {6: "tcp", 17: "udp"}.get(protocol_value, f"ip_proto={protocol_value}")
                )
            elif key in aliases:
                terms.append(f"{aliases[key]}={value}")
            else:
                raise ValueError(f"scope selector cannot be independently verified: {key}")
        if not terms:
            raise ValueError("scope has no verifiable OpenFlow match selectors")
        return tuple(terms)
