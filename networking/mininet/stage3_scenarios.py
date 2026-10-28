"""Run one bounded Stage 3 scenario on the isolated three-host Mininet topology."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import shutil
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from networking.mininet.config import TopologyConfig
from networking.mininet.stage3_config import (
    SCENARIO_BOUNDS,
    Scenario,
    validate_scenario_parameters,
    validate_target,
)
from src.sdn_defense.telemetry import ScenarioRunMetadata

H1_IP = "10.0.0.1"
H3_IP = "10.0.0.3"
H3_MAC = "02:00:00:00:00:03"
PORT_SCAN_PORTS = (22, 53, 67, 80, 443, 8080, 18080, 5353)
FIXTURE_ACTIONS = {Scenario.DHCP_STARVATION: "dhcp-fixture", Scenario.DNS_ANOMALY: "dns-fixture"}


class ScenarioJournal:
    """Write parseable timestamped configuration, observations, and cleanup events."""

    def __init__(self, path: Path, *, run_id: str | None = None) -> None:
        if run_id is not None and not run_id:
            raise ValueError("run_id must be non-empty when explicitly provided")
        self.path = path
        self.run_id = run_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = path.open("w", encoding="utf-8")

    def write(self, event_type: str, **fields: Any) -> None:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            **fields,
        }
        if self.run_id is not None:
            entry["run_id"] = self.run_id
        line = json.dumps(entry, sort_keys=True)
        print(line, flush=True)
        self.stream.write(line + "\n")
        self.stream.flush()

    def close(self) -> None:
        self.stream.close()


def _parse_ports(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(port) for port in value.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError("ports must be comma-separated integers") from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=[scenario.value for scenario in Scenario])
    parser.add_argument("--duration", type=float, help="duration in seconds, limited by scenario")
    parser.add_argument("--rate", type=float, help="events per second, limited by scenario")
    parser.add_argument(
        "--target",
        choices=("h1", "h3", "s1"),
        help="explicit fixed Mininet target (must match the scenario's documented target)",
    )
    parser.add_argument(
        "--ports",
        type=_parse_ports,
        help="port-scan subset only; comma-separated members of the fixed h3 allowlist",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        help="JSONL scenario record (default: experiments/stage3/runs/<timestamp>.jsonl)",
    )
    parser.add_argument("--run-id", help="explicit run ID supplied by a telemetry harness")
    parser.add_argument(
        "--dry-run", action="store_true", help="validate and print settings without Mininet"
    )
    return parser


def _scenario_count(
    scenario: Scenario, duration: float, rate: float, ports: tuple[int, ...]
) -> int:
    import math

    maximum = SCENARIO_BOUNDS[scenario].maximum_events
    if scenario is Scenario.PORT_SCAN:
        return min(len(ports), maximum, max(1, math.ceil(duration * rate)))
    return min(maximum, max(1, math.ceil(duration * rate)))


def _ensure_privileged_isolated_host() -> None:
    if os.geteuid() != 0:
        raise PermissionError(
            "Stage 3 scenarios require root inside the isolated Mininet development host"
        )
    if shutil.which("mn") is None or shutil.which("ovs-vsctl") is None:
        raise RuntimeError("Mininet and Open vSwitch commands must be installed")
    service = subprocess.run(
        ["systemctl", "is-active", "--quiet", "openvswitch"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if service.returncode != 0:
        raise RuntimeError("Open vSwitch must be active before starting the isolated topology")


def _agent_argv(action: str, **arguments: object) -> list[str]:
    argv = [sys.executable, "-m", "networking.mininet.stage3_agents", action]
    for name, value in arguments.items():
        argv.extend((f"--{name.replace('_', '-')}", str(value)))
    return argv


def _start_agent(host: Any, action: str, **arguments: object) -> subprocess.Popen[str]:
    project_root = str(Path(__file__).resolve().parents[2])
    return cast(
        subprocess.Popen[str],
        host.popen(
            _agent_argv(action, **arguments),
            env={"PYTHONPATH": project_root, "PYTHONUNBUFFERED": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        ),
    )


def _record_agent_line(line: str, journal: ScenarioJournal, category: str) -> str | None:
    """Persist one agent JSON event while preserving its event type as a field."""

    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        journal.write(category, line=line)
        return None
    if not isinstance(entry, dict):
        journal.write(category, value=entry)
        return None
    source_event = entry.pop("event_type", "unknown")
    journal.write("agent_event", category=category, source_event_type=source_event, **entry)
    return str(source_event)


def _record_process_output(process: subprocess.Popen[str], journal: ScenarioJournal) -> None:
    if process.stdout is None:
        return
    for line in process.stdout:
        content = line.strip()
        if not content:
            continue
        _record_agent_line(content, journal, "sender")


def _run_agent(
    host: Any,
    journal: ScenarioJournal,
    action: str,
    timeout_seconds: float,
    **arguments: object,
) -> None:
    process = _start_agent(host, action, **arguments)
    try:
        try:
            return_code = process.wait(timeout=timeout_seconds + 2)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
            raise TimeoutError(
                f"{action} exceeded its {timeout_seconds:g}-second runtime bound"
            ) from None
        _record_process_output(process, journal)
        if return_code != 0:
            raise RuntimeError(f"{action} exited with status {return_code}")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        if process.stdout is not None:
            process.stdout.close()


def _start_fixture(
    host: Any, journal: ScenarioJournal, action: str, duration: float
) -> subprocess.Popen[str]:
    process = _start_agent(host, action, duration=duration)
    if process.stdout is None:
        process.kill()
        raise RuntimeError(f"could not observe {action} readiness")
    ready_deadline = time.monotonic() + 2
    while time.monotonic() < ready_deadline:
        available, _, _ = select.select([process.stdout], [], [], 0.1)
        if process.poll() is not None:
            break
        if not available:
            continue
        line = process.stdout.readline().strip()
        if not line:
            continue
        event_type = _record_agent_line(line, journal, "fixture")
        if event_type is not None and event_type.endswith("_fixture_ready"):
            return process
    _stop_fixture(process, journal)
    raise TimeoutError(f"{action} did not become ready within two seconds")


def _stop_fixture(process: subprocess.Popen[str], journal: ScenarioJournal) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        remainder, _ = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        remainder, _ = process.communicate(timeout=2)
    if remainder:
        for line in remainder.splitlines():
            _record_agent_line(line, journal, "fixture")
    if process.returncode not in (0, -signal.SIGTERM):
        journal.write("fixture_exit_warning", return_code=process.returncode)


def _capture_switch_state(journal: ScenarioJournal, label: str) -> None:
    flow_result = subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"],
        check=False,
        capture_output=True,
        text=True,
    )
    port_result = subprocess.run(
        ["ovs-vsctl", "list-ports", "s1"],
        check=False,
        capture_output=True,
        text=True,
    )
    journal.write(
        "switch_observation",
        label=label,
        flow_dump=flow_result.stdout.strip(),
        flow_dump_error=flow_result.stderr.strip() if flow_result.returncode else None,
        ports=port_result.stdout.splitlines(),
        ports_error=port_result.stderr.strip() if port_result.returncode else None,
    )


def _require_h1_h3_connectivity(network: Any, journal: ScenarioJournal, phase: str) -> None:
    """Record and require bounded local reachability, allowing initial ARP resolution."""
    h1 = network.get("h1")
    last_result = ""
    for attempt in range(1, 4):
        last_result = h1.cmd(f"timeout --signal=TERM --kill-after=1s 5s ping -c 1 -W 1 {H3_IP}")
        succeeded = "1 received" in last_result or "1 packets received" in last_result
        journal.write(
            "connectivity_probe",
            phase=phase,
            attempt=attempt,
            success=succeeded,
            result=last_result.strip()[-2000:],
            retry_reason=("initial ARP or forwarding convergence" if not succeeded else None),
        )
        if succeeded:
            return
        if attempt < 3:
            time.sleep(0.25)
    raise RuntimeError(
        f"bounded h1-to-h3 {phase} connectivity check failed after 3 attempts; "
        "inspect the connectivity_probe journal records"
    )


def _verify_fixed_topology(network: Any, journal: ScenarioJournal) -> None:
    actual_hosts = tuple(host.name for host in network.hosts)
    if actual_hosts != ("h1", "h2", "h3"):
        raise RuntimeError(f"unexpected Mininet hosts: {actual_hosts}")
    expected = {"h1": H1_IP, "h2": "10.0.0.2", "h3": H3_IP}
    for name, address in expected.items():
        host = network.get(name)
        if host.IP() != address:
            raise RuntimeError(f"{name} address is {host.IP()}, expected {address}")
    journal.write("topology_verified", hosts=expected, switch="s1", external_links=0)
    _require_h1_h3_connectivity(network, journal, "topology-baseline")


def _run_metadata(
    run_id: str,
    scenario: Scenario,
    started_at: datetime,
    controller: TopologyConfig,
    ports: tuple[int, ...],
) -> ScenarioRunMetadata:
    """Describe fixed scenario scope for later correlation, not per-flow labels."""

    source_scope: dict[str, str | int] = {"host": "h2", "ip": "10.0.0.2"}
    destination_scope: dict[str, str | int]
    protocol: str | None
    scenario_ports: tuple[int, ...]
    if scenario is Scenario.ARP_SPOOF:
        source_scope = {"host": "h2", "mac": "02:00:00:00:00:02"}
        destination_scope = {"host": "h1", "ip": H1_IP}
        protocol, scenario_ports = "ARP", ()
    elif scenario is Scenario.PORT_SCAN:
        destination_scope = {"host": "h3", "ip": H3_IP}
        protocol, scenario_ports = "TCP", ports
    elif scenario is Scenario.SYN_FLOOD:
        destination_scope = {"host": "h3", "ip": H3_IP}
        protocol, scenario_ports = "TCP", (18080,)
    elif scenario is Scenario.ROGUE_DEVICE:
        destination_scope = {"switch": "s1", "port_host": "h2"}
        protocol, scenario_ports = None, ()
    elif scenario is Scenario.DHCP_STARVATION:
        destination_scope = {"host": "h3", "fixture": "local-dhcp"}
        protocol, scenario_ports = "UDP", (67, 68)
    else:
        destination_scope = {"host": "h3", "ip": H3_IP, "fixture": "local-dns"}
        protocol, scenario_ports = "UDP", (53,)
    topology_config = {
        "topology": "stage2-three-host-s1-v1",
        "controller_host": controller.controller_host,
        "controller_port": controller.controller_port,
        "scenario_id": scenario.value,
        "ports": list(scenario_ports),
    }
    config_id = hashlib.sha256(
        json.dumps(topology_config, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return ScenarioRunMetadata(
        run_id=run_id,
        scenario_id=scenario.value,
        start_at=started_at,
        end_at=None,
        topology_config_id=config_id,
        source_scope=tuple(sorted(source_scope.items())),
        destination_scope=tuple(sorted(destination_scope.items())),
        protocol=protocol,
        ports=scenario_ports,
    )


def _write_experiment_context(path: Path, metadata: ScenarioRunMetadata, *, active: bool) -> None:
    """Atomically publish explicit scenario context for a local Ryu observer."""

    record = {
        **metadata.to_dict(),
        "active": active,
        "context_updated_at": datetime.now(UTC).isoformat(),
    }
    temporary = path.with_name(f"{path.name}.tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def _restore_arp(network: Any, journal: ScenarioJournal) -> None:
    h1 = network.get("h1")
    h1.cmd(f"ip neigh flush to {H3_IP} dev h1-eth0")
    result = h1.cmd(f"ping -c 1 -W 1 {H3_IP}")
    neighbors = h1.cmd(f"ip neigh show to {H3_IP} dev h1-eth0").strip()
    restored = H3_MAC.lower() in neighbors.lower()
    journal.write(
        "arp_cleanup", expected_h3_mac=H3_MAC, neighbor_entry=neighbors, restored=restored
    )
    if "1 received" not in result and "1 packets received" not in result:
        raise RuntimeError("h1-to-h3 reachability did not recover after ARP cleanup")
    if not restored:
        raise RuntimeError("h1 did not relearn the expected h3 MAC after ARP cleanup")


def _run_scenario(
    network: Any,
    scenario: Scenario,
    duration: float,
    rate: float,
    ports: tuple[int, ...],
    journal: ScenarioJournal,
) -> None:
    count = _scenario_count(scenario, duration, rate, ports)
    arguments = {"duration": duration, "rate": rate}
    h2 = network.get("h2")
    h3 = network.get("h3")
    if scenario is Scenario.ARP_SPOOF:
        try:
            _run_agent(h2, journal, "arp-spoof", duration, interface="h2-eth0", **arguments)
        finally:
            _restore_arp(network, journal)
    elif scenario is Scenario.SYN_FLOOD:
        _run_agent(h2, journal, "syn-flood", duration, interface="h2-eth0", **arguments)
    elif scenario is Scenario.PORT_SCAN:
        _run_agent(
            h2,
            journal,
            "port-scan",
            duration,
            ports=",".join(str(port) for port in ports[:count]),
            **arguments,
        )
    elif scenario is Scenario.DHCP_STARVATION:
        fixture = _start_fixture(h3, journal, FIXTURE_ACTIONS[scenario], duration)
        try:
            _run_agent(
                h2,
                journal,
                "dhcp-clients",
                duration,
                count=count,
                **arguments,
            )
        finally:
            _stop_fixture(fixture, journal)
            journal.write("dhcp_cleanup", fixture_pool_reset=True, fixture_process_stopped=True)
    elif scenario is Scenario.DNS_ANOMALY:
        fixture = _start_fixture(h3, journal, FIXTURE_ACTIONS[scenario], duration)
        try:
            _run_agent(h2, journal, "dns-clients", duration, count=count, **arguments)
        finally:
            _stop_fixture(fixture, journal)
            journal.write("dns_cleanup", fixture_stopped=True, upstream_forwarding=False)
    elif scenario is Scenario.ROGUE_DEVICE:
        journal.write("rogue_link_transition", host="h2", switch="s1", state="down")
        try:
            network.configLinkStatus("h2", "s1", "down")
            network.configLinkStatus("h2", "s1", "up")
            journal.write("rogue_link_transition", host="h2", switch="s1", state="up")
            _run_agent(
                h2,
                journal,
                "rogue-device",
                min(duration, 30),
                interface="h2-eth0",
                duration=min(duration, 30),
                rate=rate,
            )
        finally:
            network.configLinkStatus("h2", "s1", "up")
            journal.write("rogue_link_cleanup", host="h2", switch="s1", state="up")


def main() -> None:
    """Validate settings, create only the fixed Mininet topology, and clean it up."""

    arguments = _parser().parse_args()
    scenario = Scenario(arguments.scenario)
    duration, rate, ports = validate_scenario_parameters(
        scenario,
        arguments.duration,
        arguments.rate,
        arguments.ports,
    )
    target_id = validate_target(scenario, arguments.target)
    if scenario is not Scenario.PORT_SCAN and arguments.ports is not None:
        raise ValueError("--ports is supported only for port-scan")
    bounds = SCENARIO_BOUNDS[scenario]
    log_path = arguments.log_file or Path("experiments/stage3/runs") / (
        f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{scenario.value}.jsonl"
    )
    if arguments.dry_run:
        print(
            json.dumps(
                {
                    "scenario": scenario.value,
                    "target": bounds.target,
                    "target_id": target_id,
                    "duration_seconds": duration,
                    "rate_per_second": rate,
                    "maximum_events": _scenario_count(scenario, duration, rate, ports),
                    "ports": ports[: _scenario_count(scenario, duration, rate, ports)]
                    if scenario is Scenario.PORT_SCAN
                    else None,
                    "log_file": str(log_path),
                    "network_scope": "fixed local Mininet h1/h2/h3 on s1",
                },
                sort_keys=True,
            )
        )
        return

    _ensure_privileged_isolated_host()
    controller = TopologyConfig.from_environment()
    controller.validate()
    journal = ScenarioJournal(log_path, run_id=arguments.run_id)
    run_started_at = datetime.now(UTC)
    context_value = os.environ.get("SDN_OBSERVATION_CONTEXT_FILE")
    context_path = Path(context_value) if context_value else None
    if context_path is not None and journal.run_id is None:
        journal.close()
        raise ValueError("SDN_OBSERVATION_CONTEXT_FILE requires an explicit --run-id")
    run_metadata = (
        _run_metadata(journal.run_id, scenario, run_started_at, controller, ports)
        if journal.run_id is not None
        else None
    )
    network: Any | None = None
    run_succeeded = False
    try:
        if context_path is not None and run_metadata is not None:
            _write_experiment_context(context_path, run_metadata, active=True)
        start_fields: dict[str, object] = {
            "scenario": scenario.value,
            "target": bounds.target,
            "target_id": target_id,
            "duration_seconds": duration,
            "rate_per_second": rate,
            "event_cap": _scenario_count(scenario, duration, rate, ports),
            "ports": (
                ports[: _scenario_count(scenario, duration, rate, ports)]
                if scenario is Scenario.PORT_SCAN
                else None
            ),
            "controller_host": controller.controller_host,
            "controller_port": controller.controller_port,
            "mitigation": "not implemented",
        }
        if run_metadata is not None:
            start_fields["scenario_run"] = run_metadata.to_dict()
        journal.write("scenario_started", **start_fields)
        from networking.mininet.stage2_topology import create_network

        network = create_network(controller)
        _verify_fixed_topology(network, journal)
        _capture_switch_state(journal, "before")
        try:
            _run_scenario(network, scenario, duration, rate, ports, journal)
        finally:
            _capture_switch_state(journal, "after")
            if scenario is Scenario.ROGUE_DEVICE:
                network.configLinkStatus("h2", "s1", "up")
        _require_h1_h3_connectivity(network, journal, "post-scenario-baseline")
        journal.write("scenario_completed", baseline_reachability="h1-to-h3 passed")
        run_succeeded = True
    finally:
        end_at = datetime.now(UTC)
        completed_metadata = (
            ScenarioRunMetadata(
                run_id=run_metadata.run_id,
                scenario_id=run_metadata.scenario_id,
                start_at=run_metadata.start_at,
                end_at=end_at,
                topology_config_id=run_metadata.topology_config_id,
                source_scope=run_metadata.source_scope,
                destination_scope=run_metadata.destination_scope,
                protocol=run_metadata.protocol,
                ports=run_metadata.ports,
            )
            if run_metadata is not None
            else None
        )
        try:
            if context_path is not None and completed_metadata is not None:
                _write_experiment_context(context_path, completed_metadata, active=False)
        finally:
            try:
                if network is not None:
                    try:
                        network.stop()
                    except Exception as error:
                        journal.write("topology_stop_failed", error=str(error))
                        raise
                    journal.write("topology_stopped", clean_shutdown=True)
            finally:
                journal.write(
                    "run_completed",
                    scenario_id=scenario.value,
                    start_at=(
                        run_metadata.to_dict()["start_at"]
                        if run_metadata is not None
                        else run_started_at.isoformat()
                    ),
                    end_at=end_at.isoformat(),
                    topology_config_id=(
                        run_metadata.topology_config_id if run_metadata is not None else None
                    ),
                    run_status="complete" if run_succeeded else "incomplete",
                )
                journal.close()


if __name__ == "__main__":
    try:
        main()
    except (OSError, PermissionError, RuntimeError, TimeoutError, ValueError) as error:
        print(f"Stage 3 scenario failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
