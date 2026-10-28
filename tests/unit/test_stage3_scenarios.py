"""Pure tests for Stage 3 safety bounds and packet construction."""

from __future__ import annotations

import ipaddress
import json
import struct
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from networking.mininet.config import TopologyConfig
from networking.mininet.stage3_agents import event_count
from networking.mininet.stage3_config import (
    PORT_SCAN_ALLOWLIST,
    Scenario,
    validate_scenario_parameters,
    validate_target,
)
from networking.mininet.stage3_packets import (
    ETH_ARP,
    ETH_IPV4,
    arp_reply_frame,
    dhcp_bootp_message,
    dns_query,
    dns_question_name,
    internet_checksum,
    ipv4_tcp_syn_frame,
    mac_bytes,
    parse_dhcp_message,
)
from networking.mininet.stage3_scenarios import (
    ScenarioJournal,
    _record_agent_line,
    _require_h1_h3_connectivity,
    _run_metadata,
    _write_experiment_context,
)
from src.sdn_defense.telemetry import ScenarioRunMetadata, read_experiment_context


def test_topology_connectivity_retries_arp_and_records_each_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Host:
        def __init__(self) -> None:
            self.results = [
                "1 packets transmitted, 0 received, 100% packet loss",
                "1 packets transmitted, 1 received, 0% packet loss",
            ]

        def cmd(self, _command: str) -> str:
            return self.results.pop(0)

    class Network:
        def __init__(self) -> None:
            self.host = Host()

        def get(self, name: str) -> Host:
            assert name == "h1"
            return self.host

    class Journal:
        def __init__(self) -> None:
            self.entries: list[dict[str, object]] = []

        def write(self, event_type: str, **fields: object) -> None:
            self.entries.append({"event_type": event_type, **fields})

    journal = Journal()
    monkeypatch.setattr("networking.mininet.stage3_scenarios.time.sleep", lambda _s: None)
    _require_h1_h3_connectivity(Network(), journal, "test-baseline")  # type: ignore[arg-type]
    assert [entry["success"] for entry in journal.entries] == [False, True]
    assert journal.entries[0]["retry_reason"] == "initial ARP or forwarding convergence"


def test_topology_connectivity_fails_after_bounded_attempts() -> None:
    class Host:
        def cmd(self, _command: str) -> str:
            return "1 packets transmitted, 0 received, 100% packet loss"

    class Network:
        def get(self, name: str) -> Host:
            assert name == "h1"
            return Host()

    class Journal:
        def __init__(self) -> None:
            self.attempts = 0

        def write(self, _event_type: str, **_fields: object) -> None:
            self.attempts += 1

    journal = Journal()
    with pytest.raises(RuntimeError, match="failed after 3 attempts"):
        _require_h1_h3_connectivity(Network(), journal, "test-baseline")  # type: ignore[arg-type]
    assert journal.attempts == 3


@pytest.mark.parametrize("scenario", list(Scenario))
def test_scenario_defaults_are_within_hard_bounds(scenario: Scenario) -> None:
    """Default parameters for every scenario pass the configured caps."""

    validate_scenario_parameters(scenario)


def test_duration_and_rate_cannot_exceed_scenario_caps() -> None:
    """Scenario settings reject a value that would exceed its documented cap."""

    with pytest.raises(ValueError, match="duration_seconds"):
        validate_scenario_parameters(Scenario.SYN_FLOOD, duration_seconds=5.01)
    with pytest.raises(ValueError, match="rate_per_second"):
        validate_scenario_parameters(Scenario.SYN_FLOOD, rate_per_second=10.01)
    with pytest.raises(ValueError, match="duration_seconds"):
        validate_scenario_parameters(Scenario.SYN_FLOOD, duration_seconds=float("nan"))


def test_target_is_fixed_to_documented_mininet_entity() -> None:
    """An arbitrary host/address cannot be selected as a scenario target."""

    assert validate_target(Scenario.ARP_SPOOF, "h1") == "h1"
    with pytest.raises(ValueError, match="fixed to h3"):
        validate_target(Scenario.SYN_FLOOD, "192.0.2.9")


def test_port_scan_accepts_only_fixed_allowlist_and_at_most_eight_ports() -> None:
    """Port scans cannot accept arbitrary ports or a larger target set."""

    validate_scenario_parameters(Scenario.PORT_SCAN, ports=PORT_SCAN_ALLOWLIST)
    with pytest.raises(ValueError, match="allowlist"):
        validate_scenario_parameters(Scenario.PORT_SCAN, ports=(22, 12345))
    with pytest.raises(ValueError, match="1 to 8"):
        validate_scenario_parameters(Scenario.PORT_SCAN, ports=PORT_SCAN_ALLOWLIST + (22,))


def test_event_count_respects_rate_duration_and_event_cap() -> None:
    """Packet sender counts stay under configured event caps."""

    assert event_count(5, 10, 50) == 50
    assert event_count(1.1, 1, 10) == 2
    assert event_count(100, 100, 4) == 4


def test_arp_reply_frame_is_fixed_unicast_arp_reply() -> None:
    """ARP packet construction uses only supplied local endpoint addresses."""

    frame = arp_reply_frame("02:00:00:00:00:02", "10.0.0.3", "02:00:00:00:00:01", "10.0.0.1")
    assert frame[:6] == mac_bytes("02:00:00:00:00:01")
    assert struct.unpack_from("!H", frame, 12)[0] == ETH_ARP
    assert struct.unpack_from("!H", frame, 20)[0] == 2
    assert frame[28:32] == ipaddress.IPv4Address("10.0.0.3").packed


def test_syn_frame_is_bare_tcp_syn_to_fixed_flow_endpoint() -> None:
    """SYN construction has no payload and carries valid IP/TCP checksums."""

    frame = ipv4_tcp_syn_frame(
        "02:00:00:00:00:02",
        "02:00:00:00:00:03",
        "10.0.0.2",
        "10.0.0.3",
        40_001,
        18_080,
        123,
    )
    assert struct.unpack_from("!H", frame, 12)[0] == ETH_IPV4
    ip_header = frame[14:34]
    assert internet_checksum(ip_header) == 0
    tcp = frame[34:]
    assert struct.unpack_from("!HH", tcp)[1] == 18_080
    assert tcp[13] == 0x02
    assert len(tcp) == 20
    pseudo = frame[26:34] + struct.pack("!BBH", 0, 6, len(tcp))
    assert internet_checksum(pseudo + tcp) == 0


def test_dhcp_payload_round_trips_fixed_client_identity() -> None:
    """DHCP fixtures parse only a declared client identity and requested address."""

    payload = dhcp_bootp_message(
        message_type=3,
        xid=0xD4000001,
        client_mac="02:00:00:00:03:01",
        requested_ip="10.0.0.100",
        server_ip="10.0.0.3",
    )
    assert parse_dhcp_message(payload) == (
        3,
        0xD4000001,
        "02:00:00:00:03:01",
        "10.0.0.100",
    )


def test_dns_queries_are_restricted_to_reserved_test_zone() -> None:
    """DNS test query helper accepts only names under the reserved .test zone."""

    packet = dns_query("unusual-1.test", 0x1234)
    assert dns_question_name(packet) == "unusual-1.test"
    with pytest.raises(ValueError, match="reserved .test"):
        dns_query("example.com", 0x1234)


def test_dry_run_describes_fixed_target_without_starting_mininet() -> None:
    """Dry-run validates and reports scenario bounds without invoking Mininet."""

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "networking.mininet.stage3_scenarios",
            "syn-flood",
            "--dry-run",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    record = json.loads(result.stdout)
    assert record["target_id"] == "h3"
    assert record["target"] == "h3:18080"
    assert record["maximum_events"] == 50


def test_dry_run_is_available_for_all_scenarios_without_network_privileges() -> None:
    """All six named scenarios can be validated without starting Mininet."""

    for scenario in Scenario:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "networking.mininet.stage3_scenarios",
                scenario.value,
                "--dry-run",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        assert json.loads(result.stdout)["scenario"] == scenario.value


def test_agent_event_keeps_json_fields_and_event_type(tmp_path: Path) -> None:
    """Agent event forwarding keeps event identity and avoids journal key collisions."""

    path = tmp_path / "scenario.jsonl"
    journal = ScenarioJournal(path, run_id="run-test")
    source_event_type = _record_agent_line('{"event_type":"syn_sent","count":1}', journal, "sender")
    journal.close()

    record = json.loads(path.read_text(encoding="utf-8"))
    assert source_event_type == "syn_sent"
    assert record["event_type"] == "agent_event"
    assert record["source_event_type"] == "syn_sent"
    assert record["count"] == 1
    assert record["run_id"] == "run-test"


def test_journal_without_explicit_run_id_keeps_it_missing(tmp_path: Path) -> None:
    path = tmp_path / "uncorrelated.jsonl"
    journal = ScenarioJournal(path)
    journal.write("scenario_started", scenario="syn-flood")
    journal.close()
    record = json.loads(path.read_text(encoding="utf-8"))
    assert "run_id" not in record


def test_scenario_run_metadata_has_stable_scope_and_topology_identity() -> None:
    """Run metadata correlates bounded source/target scope without labeling flows."""

    started = datetime(2026, 1, 1, tzinfo=UTC)
    config = TopologyConfig("127.0.0.1", 6653)
    first = _run_metadata("run-x", Scenario.PORT_SCAN, started, config, (22, 80))
    second = _run_metadata("run-x", Scenario.PORT_SCAN, started, config, (22, 80))
    assert first == second
    assert first.scenario_id == "port-scan"
    assert dict(first.source_scope)["host"] == "h2"
    assert dict(first.destination_scope)["host"] == "h3"
    assert first.protocol == "TCP"
    assert first.ports == (22, 80)
    assert len(first.topology_config_id) == 64


def test_run_id_context_is_explicit_and_inactive_context_is_not_attached(tmp_path: Path) -> None:
    """A run ID reaches observers only through the configured context file."""

    started = datetime(2026, 1, 1, tzinfo=UTC)
    metadata = _run_metadata(
        "explicit-run", Scenario.PORT_SCAN, started, TopologyConfig("127.0.0.1", 6653), (22,)
    )
    path = tmp_path / "active-context.json"
    _write_experiment_context(path, metadata, active=True)
    active_context = read_experiment_context(path)
    assert active_context is not None and active_context["run_id"] == "explicit-run"
    _write_experiment_context(
        path,
        ScenarioRunMetadata(
            run_id=metadata.run_id,
            scenario_id=metadata.scenario_id,
            start_at=metadata.start_at,
            end_at=datetime(2026, 1, 1, 0, 0, 2, tzinfo=UTC),
            topology_config_id=metadata.topology_config_id,
            source_scope=metadata.source_scope,
            destination_scope=metadata.destination_scope,
            protocol=metadata.protocol,
            ports=metadata.ports,
        ),
        active=False,
    )
    inactive_context = read_experiment_context(path)
    assert inactive_context is not None and inactive_context["active"] is False
