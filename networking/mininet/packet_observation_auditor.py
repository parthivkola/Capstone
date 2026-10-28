"""Read-only audit of currently existing OVS and collector configuration."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from networking.mininet.packet_observation_config import parse_ovsdb_table

CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]

OVS_COLUMNS: dict[str, list[str]] = {
    "Bridge": ["_uuid", "name", "ports", "mirrors"],
    "Port": ["_uuid", "name", "interfaces", "external_ids"],
    "Interface": [
        "_uuid", "name", "type", "mac", "mac_in_use", "ofport", "external_ids"
    ],
    "Mirror": [
        "_uuid", "name", "select_all", "select_src_port", "select_dst_port",
        "select_vlan", "filter", "output_port", "output_vlan", "snaplen",
        "statistics", "external_ids",
    ],
}


def _sanitize_error(stderr: str, returncode: int) -> tuple[str, str]:
    message = " ".join(stderr.split())
    lowered = message.lower()
    if "permission denied" in lowered or "operation not permitted" in lowered:
        return "NOT_ACCESSIBLE", "permission denied accessing the requested state"
    if "cannot find device" in lowered or "does not exist" in lowered:
        return "NOT_PRESENT", "requested interface or namespace is not present"
    if "no such file" in lowered or "not found" in lowered:
        return "NOT_ACCESSIBLE", "required command or system endpoint is unavailable"
    if not message:
        return "NOT_ACCESSIBLE", f"read-only query exited with status {returncode}"
    message = re.sub(r"(?i)(password|token|secret)=\S+", r"\1=[redacted]", message)
    return "NOT_ACCESSIBLE", message[:300]


def _run_json_command(
    command: list[str], runner: CommandRunner
) -> tuple[Any | None, dict[str, Any]]:
    try:
        result = runner(command)
    except FileNotFoundError:
        return None, {
            "command": command,
            "returncode": None,
            "state": "NOT_ACCESSIBLE",
            "error": "required command is unavailable",
        }
    except OSError as exc:
        return None, {
            "command": command,
            "returncode": None,
            "state": "NOT_ACCESSIBLE",
            "error": _sanitize_error(str(exc), 1)[1],
        }
    if result.returncode:
        state, error = _sanitize_error(result.stderr, result.returncode)
        return None, {
            "command": command,
            "returncode": result.returncode,
            "state": state,
            "error": error,
        }
    try:
        return json.loads(result.stdout), {
            "command": command,
            "returncode": 0,
            "state": "READ",
            "error": None,
        }
    except json.JSONDecodeError:
        return None, {
            "command": command,
            "returncode": 0,
            "state": "NOT_ACCESSIBLE",
            "error": "read-only query returned invalid JSON",
        }


def _read_table(
    table: str, runner: CommandRunner
) -> tuple[list[dict[str, Any]] | None, dict[str, Any]]:
    columns = OVS_COLUMNS[table]
    command = ["ovs-vsctl", "--format=json", f"--columns={','.join(columns)}", "list", table]
    payload, record = _run_json_command(command, runner)
    if payload is None:
        return None, record
    try:
        return parse_ovsdb_table(payload), record
    except (TypeError, ValueError) as exc:
        record["state"] = "NOT_ACCESSIBLE"
        record["error"] = f"invalid OVSDB table response: {type(exc).__name__}"
        return None, record


def _resolve_ovs_references(
    bridges: list[dict[str, Any]],
    ports: list[dict[str, Any]],
    interfaces: list[dict[str, Any]],
    mirrors: list[dict[str, Any]],
) -> dict[str, Any]:
    ports_by_uuid = {str(row.get("_uuid")): row for row in ports}
    interfaces_by_uuid = {str(row.get("_uuid")): row for row in interfaces}
    resolved_bridges: list[dict[str, Any]] = []
    for bridge in bridges:
        bridge_ports = [
            ports_by_uuid[ref]
            for ref in bridge.get("ports", [])
            if str(ref) in ports_by_uuid
        ]
        bridge_mirrors = [
            row
            for row in mirrors
            if str(row.get("_uuid")) in {str(ref) for ref in bridge.get("mirrors", [])}
        ]
        resolved_ports: list[dict[str, Any]] = []
        for port in bridge_ports:
            attached = [
                interfaces_by_uuid[ref]
                for ref in port.get("interfaces", [])
                if str(ref) in interfaces_by_uuid
            ]
            resolved_ports.append({**port, "resolved_interfaces": attached})
        resolved_mirrors = []
        for mirror in bridge_mirrors:
            def names(refs: Any) -> list[str]:
                return sorted(
                    str(ports_by_uuid[str(ref)].get("name"))
                    for ref in (refs or [])
                    if str(ref) in ports_by_uuid
                )

            output_ref = mirror.get("output_port")
            output = ports_by_uuid.get(str(output_ref)) if output_ref else None
            resolved_mirrors.append(
                {
                    **mirror,
                    "select_src_port_names": names(mirror.get("select_src_port")),
                    "select_dst_port_names": names(mirror.get("select_dst_port")),
                    "output_port_name": output.get("name") if output else None,
                }
            )
        resolved_bridges.append(
            {
                **bridge,
                "resolved_ports": resolved_ports,
                "resolved_mirrors": resolved_mirrors,
            }
        )
    return {"bridges": resolved_bridges}


def _read_collector(namespace: str, interface: str, runner: CommandRunner) -> dict[str, Any]:
    command = ["ip", "netns", "list"]
    try:
        netns_result = runner(command)
    except FileNotFoundError:
        return {"state": "NOT_ACCESSIBLE", "namespace": namespace,
                "error": "required command is unavailable", "command": command}
    except OSError as exc:
        return {"state": "NOT_ACCESSIBLE", "namespace": namespace,
                "error": _sanitize_error(str(exc), 1)[1], "command": command}
    if netns_result.returncode:
        state, error = _sanitize_error(netns_result.stderr, netns_result.returncode)
        return {"state": state, "error": error, "namespace": namespace,
                "command": command, "returncode": netns_result.returncode}
    namespaces = [line.split()[0] for line in netns_result.stdout.splitlines() if line.split()]
    if namespace not in namespaces:
        return {
            "state": "NOT_PRESENT",
            "namespace": namespace,
            "interface": interface,
            "error": None,
        }
    queries = {
        "link": ["ip", "-n", namespace, "-j", "-d", "link", "show", "dev", interface],
        "addresses": ["ip", "-n", namespace, "-j", "address", "show", "dev", interface],
        "ipv4_routes": ["ip", "-n", namespace, "-4", "-j", "route", "show", "table", "all"],
        "ipv6_routes": ["ip", "-n", namespace, "-6", "-j", "route", "show", "table", "all"],
    }
    values: dict[str, Any] = {}
    commands = []
    for key, command in queries.items():
        value, record = _run_json_command(command, runner)
        commands.append(record)
        if value is None:
            return {
                "state": "NOT_PRESENT" if record["state"] == "NOT_PRESENT" else record["state"],
                "namespace": namespace,
                "interface": interface,
                "error": record["error"],
                "commands": commands,
            }
        values[key] = value
    link_rows = values["link"]
    if not link_rows:
        return {
            "state": "NOT_PRESENT",
            "namespace": namespace,
            "interface": interface,
            "error": None,
            "commands": commands,
        }
    address_rows = values["addresses"]
    addresses = [addr for row in address_rows for addr in row.get("addr_info", [])]
    return {
        "state": "PRESENT",
        "namespace": namespace,
        "interface": interface,
        "link": link_rows[0],
        "mac": link_rows[0].get("address"),
        "ipv4_addresses": [addr for addr in addresses if addr.get("family") == "inet"],
        "ipv6_addresses": [addr for addr in addresses if addr.get("family") == "inet6"],
        "ipv4_routes": values["ipv4_routes"],
        "ipv6_routes": values["ipv6_routes"],
        "error": None,
        "commands": commands,
    }


def _requested_checks(
    requested: dict[str, Any] | None, realized: dict[str, Any], checks: list[dict[str, Any]]
) -> bool:
    if requested is None:
        return False
    bridge_name = requested.get("bridge_name")
    bridge = next(
        (row for row in realized["ovs"]["bridges"] if row.get("name") == bridge_name),
        None,
    )
    if bridge is None:
        checks.append({"name": "requested_bridge_present", "passed": False,
                       "expected": bridge_name, "observed": None,
                       "state": "NOT_PRESENT"})
        return True
    checks.append({"name": "requested_bridge_present", "passed": True,
                   "expected": bridge_name, "observed": bridge_name, "state": "READ"})
    mirror_expectation = requested.get("mirror", {})
    mirrors = bridge.get("resolved_mirrors", [])
    expected_name = mirror_expectation.get("name")
    mirror = next((row for row in mirrors if row.get("name") == expected_name), None)
    if mirror is None:
        checks.append({"name": "requested_mirror_present", "passed": False,
                       "expected": expected_name, "observed": [m.get("name") for m in mirrors],
                       "state": "NOT_PRESENT"})
        return True
    checks.append({"name": "no_unexpected_additional_mirror", "passed": len(mirrors) == 1,
                   "expected": [expected_name],
                   "observed": [m.get("name") for m in mirrors], "state": "READ"})
    comparisons = {
        "select_src_port": mirror_expectation.get("select_src_port"),
        "select_dst_port_names": mirror_expectation.get("select_dst_port", []),
        "output_port_name": mirror_expectation.get("output_port"),
        "snaplen": mirror_expectation.get("snaplen"),
        "select_all": mirror_expectation.get("select_all", False),
        "select_vlan": mirror_expectation.get("select_vlan", []),
        "output_vlan": mirror_expectation.get("output_vlan"),
        "filter": mirror_expectation.get("filter"),
    }
    mismatches = False
    observed_source_names = mirror.get("select_src_port_names", [])
    actual_by_key = {
        "select_src_port": (
            observed_source_names[0]
            if len(observed_source_names) == 1
            else observed_source_names
        ),
        "select_dst_port_names": mirror.get("select_dst_port_names", []),
        "output_port_name": mirror.get("output_port_name"),
        "snaplen": mirror.get("snaplen"),
        "select_all": mirror.get("select_all"),
        "select_vlan": mirror.get("select_vlan", []),
        "output_vlan": mirror.get("output_vlan"),
        "filter": mirror.get("filter"),
    }
    for key, expected in comparisons.items():
        actual = actual_by_key[key]
        passed = actual == expected
        mismatches |= not passed
        checks.append({"name": f"requested_{key}_matches", "passed": passed,
                       "expected": expected, "observed": actual,
                       "state": "READ"})
    expected_ports = requested.get("expected_bridge_ports")
    if expected_ports is not None:
        actual_ports = sorted(row.get("name") for row in bridge.get("resolved_ports", []))
        expected_sorted = sorted(expected_ports)
        passed = actual_ports == expected_sorted
        mismatches |= not passed
        checks.append({"name": "bridge_ports_match_requested", "passed": passed,
                       "expected": expected_sorted, "observed": actual_ports,
                       "state": "READ"})
    output_name = mirror.get("output_port_name")
    output_port = next(
        (row for row in bridge.get("resolved_ports", []) if row.get("name") == output_name),
        None,
    )
    output_interfaces = [
        row.get("name") for row in (output_port or {}).get("resolved_interfaces", [])
    ]
    collector_expected = requested.get("collector", {})
    expected_host_iface = collector_expected.get("host_interface")
    if expected_host_iface is not None:
        passed = output_interfaces == [expected_host_iface]
        mismatches |= not passed
        checks.append({"name": "mirror_output_resolves_to_expected_interface",
                       "passed": passed, "expected": [expected_host_iface],
                       "observed": output_interfaces, "state": "READ"})
    return mismatches


def run_read_only_audit(
    *,
    requested: dict[str, Any] | None = None,
    bridge_name: str = "s1",
    collector_namespace: str = "s7collector",
    collector_interface: str = "s7rcv0",
    runner: CommandRunner | None = None,
    captured_at: str | None = None,
) -> dict[str, Any]:
    """Query current system state without creating or changing network state."""
    command_runner = runner or (
        lambda command: subprocess.run(command, capture_output=True, text=True, check=False)
    )
    command_records: list[dict[str, Any]] = []
    tables: dict[str, list[dict[str, Any]] | None] = {}
    for table in OVS_COLUMNS:
        rows, record = _read_table(table, command_runner)
        tables[table] = rows
        command_records.append(record)

    required_ovs_read_failed = any(rows is None for rows in tables.values())
    ovs_state: dict[str, Any] | None = None
    if not required_ovs_read_failed:
        ovs_state = _resolve_ovs_references(
            tables["Bridge"] or [], tables["Port"] or [],
            tables["Interface"] or [], tables["Mirror"] or [],
        )
    collector_state = _read_collector(collector_namespace, collector_interface, command_runner)
    mininet_mapping = {
        "state": "NOT_APPLICABLE",
        "reason": "standalone auditor does not start or introspect a Mininet runtime object",
        "hosts": None,
    }
    if requested is not None:
        mininet_mapping["state"] = "UNAVAILABLE"
        mininet_mapping["reason"] = (
            "no direct live Mininet host-to-switch mapping source was supplied"
        )
    realized = {
        "ovs": ovs_state,
        "ovs_state": "NOT_ACCESSIBLE" if required_ovs_read_failed else "READ",
        "target_bridge": (
            next((row for row in (ovs_state or {}).get("bridges", [])
                  if row.get("name") == bridge_name), None)
        ),
        "mininet_mapping": mininet_mapping,
        "collector": collector_state,
    }
    checks: list[dict[str, Any]] = []
    if required_ovs_read_failed:
        for record in command_records:
            if record["state"] != "READ":
                checks.append({"name": f"read_{record['command'][-1]}_table",
                               "passed": False, "expected": "readable live OVSDB table",
                               "observed": None, "state": record["state"],
                               "error": record["error"]})
    elif realized["target_bridge"] is None:
        checks.append({"name": "target_bridge_present", "passed": False,
                       "expected": bridge_name, "observed": None,
                       "state": "NOT_PRESENT"})
    if requested is not None and not required_ovs_read_failed:
        mismatch = _requested_checks(requested, realized, checks)
    else:
        mismatch = False
    if requested is not None:
        if mininet_mapping["state"] != "READ":
            checks.append({"name": "mininet_host_port_mapping_read", "passed": False,
                           "expected": "direct currently running topology evidence",
                           "observed": None, "state": mininet_mapping["state"],
                           "error": mininet_mapping["reason"]})
        if collector_state.get("state") != "PRESENT":
            checks.append({"name": "collector_state_read", "passed": False,
                           "expected": {"namespace": collector_namespace,
                                        "interface": collector_interface},
                           "observed": None, "state": collector_state.get("state"),
                           "error": collector_state.get("error")})
            if collector_state.get("state") == "NOT_PRESENT":
                mismatch = True
        if mininet_mapping["state"] != "READ":
            # Lack of a live topology mapping is unavailable evidence, not a
            # mismatch inferred from interface naming.
            pass
    incomplete = required_ovs_read_failed or (
        requested is not None and (
            mininet_mapping["state"] != "READ"
            or collector_state.get("state") == "NOT_ACCESSIBLE"
            or collector_state.get("state") == "NOT_PRESENT"
        )
    ) or (
        requested is not None
        and any(not check["passed"] for check in checks)
        and not mismatch
    )
    # An inaccessible read cannot establish a mismatch: only compare requested
    # values against successfully observed state. Preserve that distinction in
    # the exit status when (for example) OVSDB denied access.
    status = (
        "AUDIT_INCOMPLETE"
        if required_ovs_read_failed
        else "CONFIGURATION_MISMATCH"
        if mismatch
        else "AUDIT_INCOMPLETE"
        if incomplete
        else "AUDIT_COMPLETE"
    )
    manifest = None
    if status == "AUDIT_COMPLETE":
        manifest = {
            "schema_version": 1,
            "record_type": "packet_observation_configuration_manifest",
            "experiment_id": f"readonly-audit-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}",
            "captured_at": captured_at or datetime.now(UTC).isoformat(),
            "requested": requested or {},
            "realized": realized,
            "preflight": {"passed": True, "checks": checks},
        }
    return {
        "audit_schema_version": 1,
        "record_type": "packet_observation_read_only_audit",
        "status": status,
        "captured_at": captured_at or datetime.now(UTC).isoformat(),
        "requested": requested,
        "realized": realized,
        "checks": checks,
        "commands": command_records,
        "manifest": manifest,
        "packet_behavior_tested": False,
    }
