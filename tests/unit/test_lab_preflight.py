"""Read-only and fail-closed lab preflight tests."""

from __future__ import annotations

import subprocess
from collections.abc import Callable

from pytest import MonkeyPatch

from src.sdn_defense.lab_preflight import inspect_lab


def _runner_for(
    outputs: dict[str, tuple[int, str]],
) -> Callable[[list[str], float], subprocess.CompletedProcess[str]]:
    def runner(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        assert timeout == 3.0
        key = command[0] if command[0] == "ryu-manager" else " ".join(command)
        defaults = {
            "ovs-ofctl --version": (0, "ovs-ofctl version\nOpenFlow versions 0x1:0x6"),
            "systemctl is-active openvswitch": (0, "active"),
            "ip -brief link": (0, "lo UNKNOWN"),
        }
        code, output = outputs.get(key, defaults.get(key, (0, "tool version")))
        return subprocess.CompletedProcess(command, code, output, "")

    return runner


def test_preflight_pass_requires_inspectable_empty_ovs_and_explicit_ack(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr("src.sdn_defense.lab_preflight.shutil.which", lambda _name: "/bin/tool")
    outputs = {
        "ovs-vsctl show": (0, ""),
        "ip -brief link": (0, "lo UNKNOWN"),
        "systemctl is-active openvswitch": (0, "active"),
    }
    result = inspect_lab(
        acknowledge_isolation=True,
        effective_uid=0,
        runner=_runner_for(outputs),
        port_check=lambda _host, _port: (True, "available"),
    )
    assert result["status"] == "PASS"
    assert result["ovs_bridges"] == {}
    assert result["read_only"] is True
    assert result["external_connectivity"] == "NO_HOST_UPLINK_DECLARED_IN_STAGE2_TOPOLOGY"


def test_preflight_fails_closed_on_permission_denied_ovs(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr("src.sdn_defense.lab_preflight.shutil.which", lambda _name: "/bin/tool")
    outputs = {
        "ovs-vsctl show": (1, "database connection failed (Permission denied)"),
        "ip -brief link": (0, "lo UNKNOWN"),
    }
    result = inspect_lab(
        acknowledge_isolation=True,
        effective_uid=1000,
        runner=_runner_for(outputs),
        port_check=lambda _host, _port: (True, "available"),
    )
    assert result["status"] == "BLOCKED"
    assert result["ovs_bridges"] is None
    assert result["external_connectivity"] == "UNVERIFIED_OVS_INVENTORY_UNAVAILABLE"
    assert any("sudo ovs-vsctl show" in message for message in result["blockers"])


def test_preflight_rejects_existing_bridges_and_busy_controller_port(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr("src.sdn_defense.lab_preflight.shutil.which", lambda _name: "/bin/tool")
    outputs = {
        "ovs-vsctl show": (0, 'Bridge "br0"\n    Port "eno1"'),
        "ip -brief link": (0, "eno1 UP"),
    }
    result = inspect_lab(
        acknowledge_isolation=True,
        effective_uid=0,
        runner=_runner_for(outputs),
        port_check=lambda _host, _port: (False, "Address already in use"),
    )
    assert result["status"] == "BLOCKED"
    assert result["ovs_bridges"] == {"br0": ["eno1"]}
    assert any("Existing OVS bridges" in message for message in result["blockers"])
    assert any("6653" in message for message in result["blockers"])


def test_preflight_handles_tool_timeout_as_blocked(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr("src.sdn_defense.lab_preflight.shutil.which", lambda _name: "/bin/tool")

    def runner(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if command[:2] == ["ovs-vsctl", "show"]:
            raise subprocess.TimeoutExpired(command, timeout)
        return subprocess.CompletedProcess(command, 0, "version", "")

    result = inspect_lab(
        acknowledge_isolation=True,
        effective_uid=0,
        runner=runner,
        port_check=lambda _host, _port: (True, "available"),
    )
    assert result["status"] == "BLOCKED"
    assert "timed out" in result["commands"]["ovs_bridges"]["output"]
