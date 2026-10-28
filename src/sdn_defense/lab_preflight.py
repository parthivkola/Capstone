"""Read-only preflight for an explicitly isolated local Mininet lab."""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

CommandRunner = Callable[[list[str], float], subprocess.CompletedProcess[str]]


@dataclass(frozen=True, slots=True)
class CommandResult:
    command: tuple[str, ...]
    returncode: int | None
    output: str

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0


def _run(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout,
    )


def _command_result(
    command: list[str], runner: CommandRunner, timeout: float = 3.0
) -> CommandResult:
    if not shutil.which(command[0]):
        return CommandResult(tuple(command), None, "not installed")
    try:
        result = runner(command, timeout)
    except subprocess.TimeoutExpired:
        return CommandResult(tuple(command), None, f"timed out after {timeout:g}s")
    except OSError as error:
        return CommandResult(tuple(command), None, str(error))
    output = (result.stdout or result.stderr).strip()
    return CommandResult(tuple(command), result.returncode, output)


def _parse_ovs_bridges(text: str) -> dict[str, list[str]]:
    bridges: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        bridge_match = re.match(r'\s*Bridge\s+"([^"]+)"', line)
        if bridge_match:
            current = bridge_match.group(1)
            bridges[current] = []
            continue
        port_match = re.match(r'\s*Port\s+"([^"]+)"', line)
        if port_match and current is not None:
            bridges[current].append(port_match.group(1))
    return bridges


def _port_available(host: str, port: int) -> tuple[bool, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
    except OSError as error:
        return False, str(error)
    finally:
        sock.close()
    return True, "available for local bind"


def inspect_lab(
    *,
    acknowledge_isolation: bool = False,
    controller_port: int = 6653,
    runner: CommandRunner = _run,
    effective_uid: int | None = None,
    port_check: Callable[[str, int], tuple[bool, str]] = _port_available,
    ryu_manager: str = "ryu-manager",
) -> dict[str, Any]:
    """Inspect tools, OVS ownership and local scope without changing host state."""

    uid = os.geteuid() if effective_uid is None else effective_uid
    commands = {
        "mininet": _command_result(["mn", "--version"], runner),
        "ovs_version": _command_result(["ovs-vsctl", "--version"], runner),
        "ovs_bridges": _command_result(["ovs-vsctl", "show"], runner),
        "ovs_openflow": _command_result(["ovs-ofctl", "--version"], runner),
        "ryu": _command_result([ryu_manager, "--version"], runner),
        "interfaces": _command_result(["ip", "-brief", "link"], runner),
        "ovs_service": _command_result(["systemctl", "is-active", "openvswitch"], runner),
    }
    bridge_result = commands["ovs_bridges"]
    bridges = _parse_ovs_bridges(bridge_result.output) if bridge_result.succeeded else None
    port_free, port_reason = port_check("127.0.0.1", controller_port)
    interface_output = commands["interfaces"].output
    non_loopback_interfaces = [
        line.split()[0]
        for line in interface_output.splitlines()
        if line.split() and line.split()[0] != "lo"
    ]
    of_match = re.search(
        r"OpenFlow versions\s+(0x[0-9a-f]+):(0x[0-9a-f]+)",
        commands["ovs_openflow"].output,
    )
    openflow13_supported = bool(
        of_match
        and int(of_match.group(1), 16) <= 0x04 <= int(of_match.group(2), 16)
    )
    ovs_service_active = commands["ovs_service"].succeeded and (
        commands["ovs_service"].output == "active"
    )

    blockers: list[str] = []
    if uid != 0:
        blockers.append(
            "Mininet requires root privileges; request them explicitly for an approved lab command."
        )
    if not commands["mininet"].succeeded:
        blockers.append("Mininet is unavailable or its version check failed.")
    if not commands["ovs_version"].succeeded or not commands["ovs_openflow"].succeeded:
        blockers.append("Open vSwitch tooling/version checks did not pass.")
    if not openflow13_supported:
        blockers.append("Open vSwitch does not report support for OpenFlow 1.3.")
    if not ovs_service_active:
        blockers.append("Open vSwitch service is not confirmed active.")
    if not bridge_result.succeeded:
        blockers.append(
            "OVS bridge ownership could not be inspected. Do not start Mininet; "
            "an operator must inspect it with: sudo ovs-vsctl show"
        )
    elif bridges:
        blockers.append(
            "Existing OVS bridges were found; this preflight cannot prove their ports "
            "are isolated. "
            "Use a dedicated lab OVS instance after operator review."
        )
    if not commands["ryu"].succeeded:
        blockers.append("The configured Ryu runtime is unavailable or failed its version check.")
    if not commands["interfaces"].succeeded:
        blockers.append("Host interfaces could not be inventoried; isolation cannot be assessed.")
    if not port_free:
        blockers.append(
            f"Controller port 127.0.0.1:{controller_port} is unavailable: {port_reason}"
        )
    if not acknowledge_isolation:
        blockers.append(
            "Explicit operator acknowledgment is missing; rerun with --ack-isolated-lab only "
            "after confirming the topology is confined to Mininet namespaces."
        )

    requirements_met = (
        uid == 0
        and commands["mininet"].succeeded
        and commands["ovs_version"].succeeded
        and commands["ovs_openflow"].succeeded
        and openflow13_supported
        and ovs_service_active
        and bridge_result.succeeded
        and bridges == {}
        and commands["ryu"].succeeded
        and commands["interfaces"].succeeded
        and port_free
        and acknowledge_isolation
    )
    return {
        "status": "PASS" if requirements_met else "BLOCKED",
        "read_only": True,
        "effective_uid": uid,
        "requires_root": True,
        "acknowledge_isolation": acknowledge_isolation,
        "controller": {"host": "127.0.0.1", "port": controller_port, "port_available": port_free},
        "controller_port_reason": port_reason,
        "openflow13_supported": openflow13_supported,
        "ovs_service_active": ovs_service_active,
        "topology_scope": {
            "source": "networking/mininet/stage2_topology.py",
            "declared_hosts": ["h1", "h2", "h3"],
            "declared_switches": ["s1"],
            "host_uplinks_declared": False,
            "controller_target": "loopback",
        },
        "commands": {
            name: {
                "argv": list(result.command),
                "returncode": result.returncode,
                "output": result.output,
            }
            for name, result in commands.items()
        },
        "ovs_bridges": bridges,
        "interfaces": commands["interfaces"].output if commands["interfaces"].succeeded else None,
        "non_loopback_interfaces": non_loopback_interfaces,
        "external_connectivity": (
            "UNVERIFIED_OVS_INVENTORY_UNAVAILABLE"
            if bridges is None
            else "REQUIRES_REVIEW_EXISTING_BRIDGES"
            if bridges
            else "NO_HOST_UPLINK_DECLARED_IN_STAGE2_TOPOLOGY"
        ),
        "blockers": blockers,
        "scope_note": (
            "No commands in this preflight change services, bridges, interfaces, firewall rules, "
            "or processes. An empty OVS bridge inventory plus loopback controller is required; "
            "the operator acknowledgment does not override failed machine checks."
        ),
    }


def format_preflight(result: Mapping[str, Any]) -> str:
    """Render a concise operator report."""

    lines = [
        f"Lab preflight: {result['status']}",
        f"Effective UID: {result['effective_uid']} (root required for Mininet)",
        f"Ryu controller: 127.0.0.1:{result['controller']['port']} "
        f"({'available' if result['controller']['port_available'] else 'occupied'})",
        f"OpenFlow 1.3 support: {'yes' if result['openflow13_supported'] else 'unknown/no'}",
        f"OVS service active: {'yes' if result['ovs_service_active'] else 'no/unknown'}",
        f"OVS bridges: {result['ovs_bridges'] if result['ovs_bridges'] is not None else 'UNKNOWN'}",
        f"External connectivity: {result['external_connectivity']}",
        "Declared Stage 2 scope: h1/h2/h3 behind s1; no host uplinks; controller loopback.",
    ]
    for name, item in result["commands"].items():
        output = item["output"] or "no output"
        lines.append(f"{name}: rc={item['returncode']} — {output.splitlines()[0]}")
    if result["blockers"]:
        lines.append("Blockers:")
        lines.extend(f"- {item}" for item in result["blockers"])
    lines.append(
        "Read-only: no services, networking, bridges, firewall rules, or processes were changed."
    )
    return "\n".join(lines)
