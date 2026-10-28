"""Unit tests for the standalone read-only OVS configuration auditor."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from networking.mininet.packet_observation_auditor import run_read_only_audit
from scripts import audit_stage7_packet_observation_config as auditor_cli


def _ovs_payload(headings: list[str], rows: list[list[Any]]) -> str:
    return json.dumps({"headings": headings, "data": rows})


def _uuid(value: str) -> list[str]:
    return ["uuid", value]


def _set(*values: Any) -> list[Any]:
    return ["set", list(values)]


def _stateful_runner(
    *, mirror_source: str = "p2", mirror_snaplen: int = 54, include_mirror: bool = True,
    include_namespace: bool = True,
) -> tuple[Callable[[list[str]], subprocess.CompletedProcess[str]], list[list[str]]]:
    calls: list[list[str]] = []
    table_data = {
        "Bridge": (
            ["_uuid", "name", "ports", "mirrors"],
            [[
                _uuid("b1"),
                "s1",
                _set(_uuid("pl"), _uuid("p1"), _uuid("p2"), _uuid("p3"), _uuid("po")),
                _set(_uuid("m1")) if include_mirror else _set(),
            ]],
        ),
        "Port": (
            ["_uuid", "name", "interfaces", "external_ids"],
            [
                [_uuid(pid), name, _set(_uuid(iid)), ["map", []]]
                for pid, name, iid in [
                    ("pl", "s1", "il"), ("p1", "s1-eth1", "i1"),
                    ("p2", "s1-eth2", "i2"), ("p3", "s1-eth3", "i3"),
                    ("po", "s7obs0", "io"),
                ]
            ],
        ),
        "Interface": (
            ["_uuid", "name", "type", "mac", "mac_in_use", "ofport", "external_ids"],
            [
                [_uuid(iid), name, ["set", []], ["set", []], ["set", []],
                 ["set", [index]], ["map", []]]
                for index, (iid, name) in enumerate(
                    [("il", "s1"), ("i1", "s1-eth1"), ("i2", "s1-eth2"),
                     ("i3", "s1-eth3"), ("io", "s7obs0")]
                )
            ],
        ),
        "Mirror": (
            ["_uuid", "name", "select_all", "select_src_port", "select_dst_port",
             "select_vlan", "filter", "output_port", "output_vlan", "snaplen",
             "statistics", "external_ids"],
            [[_uuid("m1"), "repeat-B1", _set(False), _set(_uuid(mirror_source)),
              _set(), _set(), ["set", []], _set(_uuid("po")), ["set", []],
              _set(mirror_snaplen), ["map", []], ["map", []]]]
            if include_mirror else [],
        ),
    }

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command == ["ip", "netns", "list"]:
            output = "s7collector\n" if include_namespace else ""
            return subprocess.CompletedProcess(command, 0, output, "")
        if command[:3] == ["ip", "-n", "s7collector"]:
            if command[-3:] == ["show", "dev", "missing0"]:
                return subprocess.CompletedProcess(
                    command, 1, "", "Cannot find device \"missing0\""
                )
            if command[-3:] == ["show", "dev", "s7rcv0"] and "link" in command:
                value = [
                    {
                        "ifindex": 12,
                        "ifname": "s7rcv0",
                        "address": "02:aa:bb:cc:dd:ee",
                        "operstate": "UP",
                    }
                ]
            elif "address" in command:
                value = [{"ifname": "s7rcv0", "addr_info": [
                    {"family": "inet", "local": "192.0.2.3"},
                    {"family": "inet6", "local": "fe80::3"},
                ]}]
            elif "-4" in command:
                value = []
            else:
                value = [{"dst": "fe80::/64", "dev": "s7rcv0"}]
            return subprocess.CompletedProcess(command, 0, json.dumps(value), "")
        table = command[-1]
        headings, rows = table_data[table]
        return subprocess.CompletedProcess(command, 0, _ovs_payload(headings, rows), "")

    return runner, calls


def _request() -> dict[str, Any]:
    return {
        "bridge_name": "s1",
        "expected_bridge_ports": ["s1", "s1-eth1", "s1-eth2", "s1-eth3", "s7obs0"],
        "mirror": {
            "name": "repeat-B1", "select_src_port": "s1-eth2",
            "select_dst_port": [], "select_vlan": [], "select_all": False,
            "filter": None, "output_port": "s7obs0", "output_vlan": None,
            "snaplen": 54,
        },
        "collector": {"namespace": "s7collector", "interface": "s7rcv0",
                       "host_interface": "s7obs0"},
    }


def test_auditor_reads_and_resolves_bridge_ports_interfaces_and_mirror() -> None:
    runner, calls = _stateful_runner()
    result = run_read_only_audit(runner=runner, requested=None)
    assert result["status"] == "AUDIT_COMPLETE"
    bridge = result["realized"]["target_bridge"]
    assert bridge["_uuid"] == "b1"
    assert {row["name"] for row in bridge["resolved_ports"]} == {
        "s1", "s1-eth1", "s1-eth2", "s1-eth3", "s7obs0"
    }
    mirror = bridge["resolved_mirrors"][0]
    assert mirror["_uuid"] == "m1"
    assert mirror["select_src_port_names"] == ["s1-eth2"]
    assert mirror["output_port_name"] == "s7obs0"
    assert mirror["snaplen"] == 54
    assert result["realized"]["collector"]["ipv4_addresses"][0]["local"] == "192.0.2.3"
    assert result["realized"]["collector"]["ipv6_routes"][0]["dev"] == "s7rcv0"
    assert all(call[0] in {"ovs-vsctl", "ip"} for call in calls)


def test_absent_mirror_is_reported_and_requested_configuration_mismatches() -> None:
    runner, _ = _stateful_runner(include_mirror=False)
    result = run_read_only_audit(runner=runner, requested=_request())
    assert result["status"] == "CONFIGURATION_MISMATCH"
    assert result["manifest"] is None
    assert any(check["state"] == "NOT_PRESENT" for check in result["checks"])


def test_permission_denied_ovsdb_is_incomplete_without_manifest() -> None:
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[0] == "ovs-vsctl":
            return subprocess.CompletedProcess(
                command, 1, "", "database connection failed (Permission denied)"
            )
        if command == ["ip", "netns", "list"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(f"unexpected command {command}")

    result = run_read_only_audit(runner=runner, requested=_request())
    assert result["status"] == "AUDIT_INCOMPLETE"
    assert result["manifest"] is None
    assert all(record["state"] == "NOT_ACCESSIBLE" for record in result["commands"])
    assert len(calls) == 5


def test_missing_collector_and_mininet_mapping_remain_unavailable() -> None:
    runner, _ = _stateful_runner(include_namespace=False)
    result = run_read_only_audit(runner=runner, requested=_request())
    assert result["status"] == "CONFIGURATION_MISMATCH"
    assert result["manifest"] is None
    assert result["realized"]["collector"]["state"] == "NOT_PRESENT"
    assert result["realized"]["mininet_mapping"]["state"] == "UNAVAILABLE"


def test_missing_collector_interface_is_not_reported_as_read() -> None:
    runner, _ = _stateful_runner()
    # Adapt the fake ip response only for the requested interface.
    def missing_interface_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        if "missing0" in command:
            return subprocess.CompletedProcess(
                command, 1, "", "Cannot find device \"missing0\""
            )
        return runner(command)

    result = run_read_only_audit(
        runner=missing_interface_runner,
        requested=_request(),
        collector_interface="missing0",
    )
    assert result["status"] == "CONFIGURATION_MISMATCH"
    assert result["manifest"] is None
    assert result["realized"]["collector"]["state"] == "NOT_PRESENT"


def test_mirror_mismatch_is_configuration_mismatch_and_fails_closed() -> None:
    runner, _ = _stateful_runner(mirror_source="p1", mirror_snaplen=128)
    result = run_read_only_audit(runner=runner, requested=_request())
    assert result["status"] == "CONFIGURATION_MISMATCH"
    assert result["manifest"] is None
    failed_names = {check["name"] for check in result["checks"] if not check["passed"]}
    assert "requested_select_src_port_matches" in failed_names
    assert "requested_snaplen_matches" in failed_names


def test_only_read_commands_are_invoked() -> None:
    runner, calls = _stateful_runner()
    run_read_only_audit(runner=runner)
    for call in calls:
        assert call[0] in {"ovs-vsctl", "ip"}
        assert not any(
            token in {"add", "del", "set", "clear", "create", "remove", "mod-probe"}
            for token in call
        )
        assert "ping" not in call
        assert "mn" not in call


def test_cli_incomplete_audit_returns_nonzero_without_manifest(
    tmp_path: Path, monkeypatch: Any, capsys: Any
) -> None:
    output_path = tmp_path / "must-not-exist" / "manifest.json"
    monkeypatch.setattr(
        auditor_cli,
        "run_read_only_audit",
        lambda **kwargs: {"status": "AUDIT_INCOMPLETE", "manifest": None},
    )

    result = auditor_cli.main(["--manifest-output", str(output_path)])

    assert result == auditor_cli.EXIT_CODES["AUDIT_INCOMPLETE"]
    assert not output_path.exists()
    assert not output_path.parent.exists()
    assert json.loads(capsys.readouterr().out)["manifest_write"]["written"] is False

