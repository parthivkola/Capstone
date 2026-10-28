"""Tests for readback manifest parsing and fail-closed configuration checks."""

from __future__ import annotations

from typing import Any

from networking.mininet.packet_observation_config import (
    build_configuration_manifest,
    decode_ovsdb_value,
    evaluate_configuration_preflight,
    parse_ovsdb_table,
)


def test_ovsdb_json_values_decode_sets_maps_and_optional_scalars() -> None:
    assert decode_ovsdb_value(["uuid", "port-1"]) == "port-1"
    assert decode_ovsdb_value(["set", [["uuid", "p1"], ["uuid", "p2"]]]) == [
        "p1",
        "p2",
    ]
    assert decode_ovsdb_value(["map", [["a", "b"]]]) == {"a": "b"}
    rows = parse_ovsdb_table(
        {
            "headings": ["_uuid", "snaplen", "select_src_port"],
            "data": [
                [
                    ["uuid", "mirror-1"],
                    ["set", [54]],
                    ["set", [["uuid", "port-2"]]],
                ]
            ],
        }
    )
    assert rows == [
        {"_uuid": "mirror-1", "snaplen": 54, "select_src_port": ["port-2"]}
    ]


def _configuration() -> tuple[dict[str, Any], dict[str, Any]]:
    requested = {
        "bridge_name": "s1",
        "expected_bridge_ports": ["s1", "s1-eth1", "s1-eth2", "s1-eth3", "s7obs0"],
        "mirror": {
            "name": "repeat-B1",
            "select_src_port": "s1-eth2",
            "selected_host": "h2",
            "select_dst_port": [],
            "select_vlan": [],
            "select_all": False,
            "filter": None,
            "output_port": "s7obs0",
            "output_vlan": None,
            "snaplen": 54,
        },
        "collector": {
            "namespace": "s7collector",
            "interface": "s7rcv0",
            "host_interface": "s7obs0",
        },
    }
    realized = {
        "bridge": {
            "uuid": "bridge-1",
            "name": "s1",
            "port_uuids": ["p-local", "p1", "p2", "p3", "p-out"],
            "mirrors": ["m-1"],
        },
        "ports": [
            {"uuid": "p-local", "name": "s1", "interfaces": ["i-local"]},
            {"uuid": "p1", "name": "s1-eth1", "interfaces": ["i1"]},
            {"uuid": "p2", "name": "s1-eth2", "interfaces": ["i2"]},
            {"uuid": "p3", "name": "s1-eth3", "interfaces": ["i3"]},
            {"uuid": "p-out", "name": "s7obs0", "interfaces": ["i-out"]},
        ],
        "interfaces": [
            {"uuid": f"i{n}", "name": f"s1-eth{n}"} for n in (1, 2, 3)
        ]
        + [{"uuid": "i-local", "name": "s1"}, {"uuid": "i-out", "name": "s7obs0"}],
        "mirrors": [
            {
                "uuid": "m-1",
                "name": "repeat-B1",
                "select_all": False,
                "select_src_port": ["p2"],
                "select_dst_port": [],
                "select_vlan": [],
                "filter": None,
                "output_port": "p-out",
                "output_vlan": None,
                "snaplen": 54,
                "statistics": {},
                "external_ids": {},
            }
        ],
        "host_mapping": {
            "h1": {"switch_port_name": "s1-eth1"},
            "h2": {"switch_port_name": "s1-eth2"},
            "h3": {"switch_port_name": "s1-eth3"},
        },
        "collector": {
            "namespace": "s7collector",
            "interface": "s7rcv0",
            "host_interface": "s7obs0",
        },
    }
    return requested, realized


def test_realized_configuration_preflight_passes_for_matching_state() -> None:
    requested, realized = _configuration()
    result = evaluate_configuration_preflight(requested, realized)
    assert result["passed"] is True
    assert all(check["passed"] for check in result["checks"])


def test_preflight_fails_closed_on_source_port_or_snaplen_mismatch() -> None:
    requested, realized = _configuration()
    realized["mirrors"][0]["select_src_port"] = ["p1"]
    realized["mirrors"][0]["snaplen"] = 128
    result = evaluate_configuration_preflight(requested, realized)
    failed = {check["name"] for check in result["checks"] if not check["passed"]}
    assert result["passed"] is False
    assert "requested_source_port_matches_realized" in failed
    assert "requested_snaplen_matches_realized" in failed
    assert "selected_source_port_maps_to_intended_host" not in failed


def test_preflight_rejects_extra_mirror_and_wrong_collector_output() -> None:
    requested, realized = _configuration()
    realized["bridge"]["mirrors"].append("m-extra")
    realized["mirrors"].append(
        {"uuid": "m-extra", "name": "unexpected", "output_port": "p3"}
    )
    realized["collector"]["host_interface"] = "other0"
    result = evaluate_configuration_preflight(requested, realized)
    failed = {check["name"] for check in result["checks"] if not check["passed"]}
    assert result["passed"] is False
    assert "no_unexpected_additional_mirror" in failed
    assert "mirror_output_resolves_to_collector_host_interface" in failed


def test_preflight_rejects_switch_port_that_does_not_map_to_h2() -> None:
    requested, realized = _configuration()
    realized["host_mapping"]["h2"]["switch_port_name"] = "s1-eth1"
    result = evaluate_configuration_preflight(requested, realized)
    failed = {check["name"] for check in result["checks"] if not check["passed"]}
    assert result["passed"] is False
    assert "selected_source_port_maps_to_intended_host" in failed


def test_manifest_separates_requested_and_realized_and_records_readback_failure() -> None:
    requested, realized = _configuration()
    passed = build_configuration_manifest(
        experiment_id="run-1",
        captured_at="2026-10-09T00:00:00+00:00",
        requested=requested,
        realized=realized,
    )
    assert passed["requested"] is requested
    assert passed["realized"] is realized
    assert passed["preflight"]["passed"] is True

    failed = build_configuration_manifest(
        experiment_id="run-2",
        captured_at="2026-10-09T00:00:01+00:00",
        requested=requested,
        realized=None,
        read_error="PermissionError: OVSDB denied",
    )
    assert failed["preflight"]["passed"] is False
    assert failed["preflight"]["checks"][0]["error"] == "PermissionError: OVSDB denied"
