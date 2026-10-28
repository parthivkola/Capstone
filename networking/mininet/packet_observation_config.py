"""Manifest parsing and checks for isolated packet-observation setup."""

from __future__ import annotations

from typing import Any


def decode_ovsdb_value(value: Any) -> Any:
    """Decode the JSON atom/set/map wrappers used by ovs-vsctl --format=json."""
    if not isinstance(value, list) or len(value) != 2 or not isinstance(value[0], str):
        return value
    kind, contents = value
    if kind in {"uuid", "named-uuid"}:
        return contents
    if kind == "set":
        return [decode_ovsdb_value(item) for item in contents]
    if kind == "map":
        return {
            str(decode_ovsdb_value(key)): decode_ovsdb_value(item)
            for key, item in contents
        }
    return value


def parse_ovsdb_table(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn an ovs-vsctl JSON table response into ordinary row dictionaries."""
    headings = payload.get("headings")
    data = payload.get("data")
    if not isinstance(headings, list) or not isinstance(data, list):
        raise ValueError("invalid ovs-vsctl JSON table response")
    rows: list[dict[str, Any]] = []
    for raw_row in data:
        if not isinstance(raw_row, list) or len(raw_row) != len(headings):
            raise ValueError("OVSDB row does not match its headings")
        row = {
            str(heading): decode_ovsdb_value(value)
            for heading, value in zip(headings, raw_row, strict=True)
        }
        for optional_column in {
            "type", "mac", "mac_in_use", "ofport", "filter", "output_port", "select_all",
            "output_vlan", "snaplen",
        }:
            optional_value = row.get(optional_column)
            if isinstance(optional_value, list):
                row[optional_column] = optional_value[0] if optional_value else None
        rows.append(row)
    return rows


def evaluate_configuration_preflight(
    requested: dict[str, Any], realized: dict[str, Any]
) -> dict[str, Any]:
    """Compare independently read OVS/Mininet/collector state to the request."""
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, expected: Any, actual: Any) -> None:
        checks.append(
            {
                "name": name,
                "passed": bool(passed),
                "expected": expected,
                "observed": actual,
            }
        )

    bridge = realized.get("bridge", {})
    mirrors = realized.get("mirrors", [])
    ports = realized.get("ports", [])
    port_by_uuid = {str(row.get("uuid")): row for row in ports}
    interfaces = realized.get("interfaces", [])
    interface_by_uuid = {str(row.get("uuid")): row for row in interfaces}

    mirror_name = requested["mirror"]["name"]
    bridge_mirror_ids = set(bridge.get("mirrors", []))
    realized_bridge_mirrors = [
        row for row in mirrors if str(row.get("uuid")) in bridge_mirror_ids
    ]
    named_mirrors = [row for row in realized_bridge_mirrors if row.get("name") == mirror_name]
    check("bridge_exists", bool(bridge), requested["bridge_name"], bridge.get("name"))
    check(
        "requested_mirror_exists_on_bridge",
        len(named_mirrors) == 1,
        mirror_name,
        [row.get("name") for row in realized_bridge_mirrors],
    )
    check(
        "no_unexpected_additional_mirror",
        len(realized_bridge_mirrors) == 1 and len(named_mirrors) == 1,
        [mirror_name],
        [row.get("name") for row in realized_bridge_mirrors],
    )

    mirror = named_mirrors[0] if len(named_mirrors) == 1 else {}
    source_ids = list(mirror.get("select_src_port", []))
    destination_ids = list(mirror.get("select_dst_port", []))
    source_names = sorted(
        str(port_by_uuid[item].get("name")) for item in source_ids if item in port_by_uuid
    )
    destination_names = sorted(
        str(port_by_uuid[item].get("name"))
        for item in destination_ids
        if item in port_by_uuid
    )
    output_id = mirror.get("output_port")
    output_name = port_by_uuid.get(str(output_id), {}).get("name") if output_id else None
    selected_expected = requested["mirror"]["select_src_port"]
    output_expected = requested["mirror"]["output_port"]
    check(
        "requested_source_port_matches_realized",
        source_names == [selected_expected],
        [selected_expected],
        source_names,
    )
    check(
        "requested_destination_selection_matches_realized",
        destination_names == requested["mirror"].get("select_dst_port", []),
        requested["mirror"].get("select_dst_port", []),
        destination_names,
    )
    check(
        "requested_output_port_matches_realized",
        output_name == output_expected,
        output_expected,
        output_name,
    )
    check(
        "requested_snaplen_matches_realized",
        mirror.get("snaplen") == requested["mirror"]["snaplen"],
        requested["mirror"]["snaplen"],
        mirror.get("snaplen"),
    )
    for field in ("select_all", "select_vlan", "output_vlan", "filter"):
        expected = requested["mirror"].get(field)
        actual = mirror.get(field)
        if field in {"select_vlan"}:
            actual = sorted(actual or [])
            expected = sorted(expected or [])
        check(f"requested_{field}_matches_realized", actual == expected, expected, actual)

    host_mapping = realized.get("host_mapping", {})
    selected_host = requested["mirror"]["selected_host"]
    selected_host_port = host_mapping.get(selected_host, {}).get("switch_port_name")
    check(
        "selected_source_port_maps_to_intended_host",
        selected_host_port == selected_expected,
        {"host": selected_host, "switch_port_name": selected_expected},
        {"host": selected_host, "switch_port_name": selected_host_port},
    )
    collector = realized.get("collector", {})
    output_port_interfaces = port_by_uuid.get(str(output_id), {}).get("interfaces", [])
    output_interface_names = sorted(
        str(interface_by_uuid[item].get("name"))
        for item in output_port_interfaces
        if item in interface_by_uuid
    )
    expected_output_interface = requested["collector"]["host_interface"]
    check(
        "mirror_output_resolves_to_collector_host_interface",
        output_interface_names == [expected_output_interface]
        and collector.get("host_interface") == expected_output_interface,
        [expected_output_interface],
        output_interface_names,
    )
    check(
        "collector_interface_in_expected_namespace",
        collector.get("namespace") == requested["collector"]["namespace"]
        and collector.get("interface") == requested["collector"]["interface"],
        {
            "namespace": requested["collector"]["namespace"],
            "interface": requested["collector"]["interface"],
        },
        {"namespace": collector.get("namespace"), "interface": collector.get("interface")},
    )
    switch_port_names = {str(row.get("name")) for row in ports}
    expected_switch_port_names = set(requested["expected_bridge_ports"])
    check(
        "bridge_has_only_expected_ports",
        switch_port_names == expected_switch_port_names,
        sorted(expected_switch_port_names),
        sorted(switch_port_names),
    )
    output_count = sum(
        row.get("name") == output_expected for row in ports
    )
    check(
        "no_unexpected_observation_output_interface",
        output_count == 1 and output_interface_names == [expected_output_interface],
        {"output_port": output_expected, "interfaces": [expected_output_interface]},
        {"output_port_count": output_count, "interfaces": output_interface_names},
    )
    return {"passed": all(row["passed"] for row in checks), "checks": checks}


def build_configuration_manifest(
    *,
    experiment_id: str,
    captured_at: str,
    requested: dict[str, Any],
    realized: dict[str, Any] | None,
    read_error: str | None = None,
) -> dict[str, Any]:
    """Build a schema-versioned requested-versus-realized audit artifact."""
    if realized is None:
        preflight = {
            "passed": False,
            "checks": [
                {
                    "name": "realized_configuration_readback",
                    "passed": False,
                    "expected": "complete OVS/Mininet/collector state",
                    "observed": None,
                    "error": read_error or "readback unavailable",
                }
            ],
        }
    else:
        preflight = evaluate_configuration_preflight(requested, realized)
    return {
        "schema_version": 1,
        "record_type": "packet_observation_configuration_manifest",
        "experiment_id": experiment_id,
        "captured_at": captured_at,
        "requested": requested,
        "realized": realized,
        "preflight": preflight,
    }
