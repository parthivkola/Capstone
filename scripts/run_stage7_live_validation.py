"""Root-required local Mininet/OVS/Ryu enforcement-substrate validation.

Run only on the isolated development host documented in
``docs/architecture/stage7-live-enforcement.md``. It generates bounded UDP echo
probes between Mininet hosts; it does not run attack scenarios.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic, sleep
from typing import Any, cast

from networking.ovs.verification import OvsFlowVerifier
from networking.ryu.stage7_socket_adapter import SocketRyuMitigationAdapter
from services.mitigation.orchestrator import MitigationOrchestrator, OrchestrationConfig
from src.sdn_defense.contracts import (
    ActionType,
    EnforcementStatus,
    MitigationAction,
    MitigationScope,
    ScopeKind,
)

ROOT = Path.cwd()
BRIDGE = "s1"
CONTROLLER_PORT = 6653
GATEWAY_PORT = 16654
TTL_ACTION_ID = "stage7-live-ttl-test"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run(command: list[str], *, timeout: float = 8.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)


def verify_preconditions() -> dict[str, Any]:
    require(os.geteuid() == 0, "run with sudo: this local Mininet/OVS test requires root")
    required = ("mn", "ovs-vsctl", "ovs-ofctl", "systemctl")
    missing = [name for name in required if shutil.which(name) is None]
    require(not missing, f"missing required commands: {missing}")
    ryu_manager = Path(os.environ.get("SDN_STAGE2_RYU_MANAGER", ".venv-ryu/bin/ryu-manager"))
    require(ryu_manager.is_file() and os.access(ryu_manager, os.X_OK), "Ryu launcher unavailable")
    service = run(["systemctl", "is-active", "--quiet", "openvswitch"])
    require(service.returncode == 0, "openvswitch service is not active")
    existing = run(["ovs-vsctl", "br-exists", BRIDGE])
    require(existing.returncode != 0, "s1 already exists; refusing to touch an existing bridge")
    for port in (CONTROLLER_PORT, GATEWAY_PORT):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as error:
            raise RuntimeError(
                f"required local test port {port} is unavailable: {error}"
            ) from error
        finally:
            probe.close()
    version = run(["ovs-vsctl", "--version"])
    require(version.returncode == 0, f"cannot query OVS version: {version.stderr}")
    return {"ovs_version": version.stdout.splitlines()[0], "bridge": BRIDGE}


def wait_for(predicate: Any, timeout: float, message: str) -> None:
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        if predicate():
            return
        sleep(0.1)
    raise RuntimeError(message)


def udp_server(host: Any, port: int) -> subprocess.Popen[bytes]:
    source = (
        "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
        "s.bind(('0.0.0.0',int(sys.argv[1]))); "
        "exec('while True:\\n data,addr=s.recvfrom(1024)\\n s.sendto(b\\\"ok\\\",addr)')"
    )
    return cast(
        subprocess.Popen[bytes],
        host.popen(
            ["python3", "-c", source, str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        ),
    )


def udp_probe(host: Any, destination: str, port: int, *, expect_reply: bool) -> bool:
    source = (
        "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
        "s.settimeout(0.35); s.sendto(b'bounded-stage7-probe',(sys.argv[1],int(sys.argv[2]))); "
        "print(s.recvfrom(16)[0].decode())"
    )
    process = host.popen(
        ["python3", "-c", source, destination, str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, _stderr = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        return False
    received = process.returncode == 0 and stdout.strip() == b"ok"
    return received is expect_reply


def make_action(
    *,
    datapath_id: str,
    action_id: str,
    port: int,
    ttl_seconds: int = 10,
    action: ActionType = ActionType.BLOCK,
) -> MitigationAction:
    now = datetime.now(UTC)
    scope = MitigationScope.from_mapping(
        ScopeKind.TUPLE,
        {
            "datapath_id": datapath_id,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "ip_protocol": 17,
            "dst_port": port,
        },
    )
    return MitigationAction(
        action_id=action_id,
        action=action,
        scope=scope,
        created_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        ttl_seconds=ttl_seconds,
        reason="bounded Stage 7 local enforcement validation",
        evidence_refs=("stage7-local-test-fixture",),
        policy_version="stage7-live-validation",
        decision_id=f"decision:{action_id}",
    )


def expected_cookie(action_id: str) -> int:
    digest = hashlib.sha256(f"stage7-live-test:{action_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def main() -> None:
    report: dict[str, Any] = {
        "started_at": datetime.now(UTC).isoformat(),
        "environment": {},
        "checks": {},
        "events": [],
    }
    controller: subprocess.Popen[bytes] | None = None
    network: Any | None = None
    log_stream: Any | None = None
    servers: list[subprocess.Popen[bytes]] = []
    orchestrator: MitigationOrchestrator | None = None
    active_actions: list[str] = []
    output = Path(
        os.environ.get("SDN_STAGE7_VALIDATION_REPORT", "/tmp/stage7-live-validation.json")
    )
    try:
        report["environment"] = verify_preconditions()
        ryu_source = os.environ.get("RYU_SOURCE_DIR", "")
        require(
            bool(ryu_source and Path(ryu_source).is_dir()),
            "set RYU_SOURCE_DIR to the pinned Ryu source checkout",
        )
        environment = {
            **os.environ,
            "PYTHONPATH": os.pathsep.join(
                (str(ROOT), ryu_source, os.environ.get("PYTHONPATH", ""))
            ),
            "SDN_STAGE2_MONITOR_INTERVAL_SECONDS": "1.0",
            "SDN_STAGE7_GATEWAY_PORT": str(GATEWAY_PORT),
            "SDN_STAGE7_FLOW_MOD_VERIFIED": "true",
        }
        log_path = Path("/tmp/stage7-live-ryu.log")
        log_stream = log_path.open("wb")
        manager = str(Path(os.environ.get("SDN_STAGE2_RYU_MANAGER", ".venv-ryu/bin/ryu-manager")))
        controller = subprocess.Popen(
            [
                manager,
                "--ofp-tcp-listen-port",
                str(CONTROLLER_PORT),
                "networking.ryu.stage2_controller",
                "networking.ryu.stage7_gateway",
            ],
            cwd=ROOT,
            env=environment,
            stdout=log_stream,
            stderr=subprocess.STDOUT,
        )
        wait_for(
            lambda: _tcp_open("127.0.0.1", CONTROLLER_PORT),
            15,
            "Ryu OpenFlow listener did not start",
        )
        wait_for(
            lambda: _tcp_open("127.0.0.1", GATEWAY_PORT),
            15,
            "Stage 7 loopback gateway did not start",
        )

        from networking.mininet.config import TopologyConfig
        from networking.mininet.stage2_topology import create_network

        network = create_network(TopologyConfig("127.0.0.1", CONTROLLER_PORT))
        h1, h2, h3 = network.get("h1"), network.get("h2"), network.get("h3")
        bridge_proto = run(["ovs-vsctl", "get", "bridge", BRIDGE, "protocols"])
        controllers = run(["ovs-vsctl", "get-controller", BRIDGE])
        dpid_result = run(["ovs-vsctl", "get", "bridge", BRIDGE, "datapath_id"])
        require(
            bridge_proto.returncode == 0 and "OpenFlow13" in bridge_proto.stdout,
            "bridge did not select OpenFlow 1.3",
        )
        require(
            controllers.returncode == 0 and "127.0.0.1" in controllers.stdout,
            "OVS controller is not loopback Ryu",
        )
        require(
            dpid_result.returncode == 0, f"cannot read bridge datapath ID: {dpid_result.stderr}"
        )
        datapath_id = dpid_result.stdout.strip().strip('"')
        datapath_id = datapath_id.removeprefix("0x").zfill(16)
        wait_for(
            lambda: "stage7_datapath_connected" in log_path.read_text(errors="replace"),
            10,
            "Ryu did not discover the switch datapath",
        )
        report["environment"].update(
            {
                "openflow_protocol": bridge_proto.stdout.strip(),
                "controller": controllers.stdout.strip(),
                "datapath_id": datapath_id,
                "ryu_log": str(log_path),
            }
        )
        show = run(["ovs-ofctl", "-O", "OpenFlow13", "show", BRIDGE])
        require(show.returncode == 0, f"OpenFlow 1.3 switch query failed: {show.stderr}")
        dump = run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", BRIDGE])
        require(dump.returncode == 0, f"OpenFlow 1.3 flow dump failed: {dump.stderr}")
        meters = run(["ovs-ofctl", "-O", "OpenFlow13", "meter-features", BRIDGE])
        meter_limit = re.search(r"max_meter\s*=\s*(\d+)", meters.stdout)
        meter_bands = re.search(r"band_types\s*=\s*(\d+)", meters.stdout)
        report["environment"].update(
            {
                "openflow_show": show.stdout,
                "cookie_dump_supported": dump.returncode == 0 and "cookie=" in dump.stdout,
                "meter_features_exit_code": meters.returncode,
                "meter_features_output": meters.stdout.strip() or meters.stderr.strip(),
                "meter_max_meter": None if meter_limit is None else int(meter_limit.group(1)),
                "meter_band_types": None if meter_bands is None else int(meter_bands.group(1)),
                "meter_support_verified": (
                    meters.returncode == 0
                    and meter_limit is not None
                    and int(meter_limit.group(1)) > 0
                    and meter_bands is not None
                    and int(meter_bands.group(1)) > 0
                ),
            }
        )

        servers.extend((udp_server(h2, 18081), udp_server(h2, 18082), udp_server(h3, 18081)))
        sleep(0.3)
        require(
            udp_probe(h1, "10.0.0.2", 18081, expect_reply=True),
            "baseline h1→h2 target traffic failed",
        )
        require(
            udp_probe(h1, "10.0.0.2", 18082, expect_reply=True),
            "baseline h1→h2 non-target traffic failed",
        )
        require(
            udp_probe(h1, "10.0.0.3", 18081, expect_reply=True), "baseline h1→h3 traffic failed"
        )

        verifier = OvsFlowVerifier(BRIDGE)
        adapter = SocketRyuMitigationAdapter(port=GATEWAY_PORT, flow_mod_support_verified=True)
        orchestrator = MitigationOrchestrator(adapter, verifier, config=OrchestrationConfig(3.0))

        protected_action = make_action(
            datapath_id=datapath_id, action_id="stage7-protected-test", port=18081
        )
        protected = orchestrator.apply(
            protected_action, protected_scopes=((protected_action.scope, "test protected tuple"),)
        )
        require(protected.status is EnforcementStatus.REJECTED, "protected action was not rejected")
        require(
            not any(
                f"cookie=0x{expected_cookie(protected_action.action_id):x}" in line
                for line in verifier.dump_flows().splitlines()
            ),
            "protected action installed a flow",
        )

        action = make_action(
            datapath_id=datapath_id, action_id="stage7-block-test", port=18081, ttl_seconds=10
        )
        confirmed = orchestrator.apply(action)
        require(
            confirmed.status is EnforcementStatus.CONFIRMED,
            f"exact block not confirmed: {confirmed.reason}",
        )
        active_actions.append(action.action_id)
        require(
            confirmed.rule_cookie == expected_cookie(action.action_id),
            "cookie/action correlation failed",
        )
        require(
            udp_probe(h1, "10.0.0.2", 18081, expect_reply=False),
            "target traffic was not blocked",
        )
        require(
            udp_probe(h1, "10.0.0.2", 18082, expect_reply=True), "non-target port was disrupted"
        )
        require(
            udp_probe(h1, "10.0.0.3", 18081, expect_reply=True),
            "unrelated host traffic was disrupted",
        )
        rolled_back = orchestrator.rollback(action.action_id)
        active_actions.remove(action.action_id)
        require(
            rolled_back.status is EnforcementStatus.ROLLED_BACK,
            f"rollback not verified: {rolled_back.reason}",
        )
        already_absent = adapter.rollback(action.action_id)
        require(
            already_absent.status.value == "REJECTED",
            "rollback of an already removed action was not rejected",
        )
        require(
            udp_probe(h1, "10.0.0.2", 18081, expect_reply=True),
            "target traffic did not recover after rollback",
        )

        ttl_action = make_action(
            datapath_id=datapath_id, action_id=TTL_ACTION_ID, port=18081, ttl_seconds=2
        )
        ttl_confirmed = orchestrator.apply(ttl_action)
        require(
            ttl_confirmed.status is EnforcementStatus.CONFIRMED,
            f"TTL rule not confirmed: {ttl_confirmed.reason}",
        )
        active_actions.append(TTL_ACTION_ID)
        sleep(2.2)
        expired = orchestrator.expire(TTL_ACTION_ID, now=datetime.now(UTC))
        active_actions.remove(TTL_ACTION_ID)
        require(
            expired.status is EnforcementStatus.ROLLED_BACK,
            f"TTL rollback not verified: {expired.reason}",
        )
        require(
            udp_probe(h1, "10.0.0.2", 18081, expect_reply=True),
            "traffic did not recover after TTL expiry",
        )

        unsupported = make_action(
            datapath_id=datapath_id,
            action_id="stage7-rate-test",
            port=18081,
            action=ActionType.RATE_LIMIT,
        )
        rate_result = adapter.apply(unsupported)
        require(
            rate_result.status.value == "UNSUPPORTED", "rate limit was not reported unsupported"
        )
        missing_dp = make_action(
            datapath_id="000000000000ffff", action_id="stage7-missing-dp", port=18081
        )
        missing_result = adapter.apply(missing_dp)
        require(
            missing_result.status.value == "UNSUPPORTED",
            "unavailable datapath was not rejected as unsupported",
        )

        report["events"] = [event.to_dict() for event in orchestrator.events]
        report["checks"] = {
            "baseline_target_traffic": "PASS",
            "baseline_non_target_traffic": "PASS",
            "baseline_other_host_traffic": "PASS",
            "protected_scope_rejection": "PASS",
            "exact_rule_confirmed_in_ovs": "PASS",
            "target_blocked": "PASS",
            "unrelated_flows_preserved": "PASS",
            "exact_rollback_confirmed": "PASS",
            "traffic_restored_after_rollback": "PASS",
            "short_test_ttl_expiry_and_cleanup": "PASS",
            "rate_limit_unsupported": "PASS",
            "unavailable_datapath_unsupported": "PASS",
        }
        report["result"] = "PASS"
    except Exception as error:
        report["result"] = "FAIL"
        report["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        for server in servers:
            try:
                if server.poll() is None:
                    server.terminate()
                    try:
                        server.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=2)
            except Exception as error:
                report.setdefault("cleanup_errors", []).append(f"host server cleanup: {error}")
        if orchestrator is not None:
            for action_id in tuple(active_actions):
                try:
                    orchestrator.rollback(action_id, reason="failure cleanup")
                except Exception as error:
                    report.setdefault("cleanup_errors", []).append(
                        f"action {action_id} cleanup: {error}"
                    )
        if network is not None:
            try:
                network.stop()
            except Exception as error:
                report.setdefault("cleanup_errors", []).append(f"Mininet cleanup: {error}")
        if controller is not None:
            try:
                if controller.poll() is None:
                    controller.send_signal(signal.SIGINT)
                    try:
                        controller.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        controller.terminate()
                        try:
                            controller.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            controller.kill()
                            controller.wait(timeout=3)
            except Exception as error:
                report.setdefault("cleanup_errors", []).append(f"Ryu cleanup: {error}")
        if log_stream is not None:
            try:
                log_stream.close()
            except Exception as error:
                report.setdefault("cleanup_errors", []).append(f"Ryu log cleanup: {error}")
        report["finished_at"] = datetime.now(UTC).isoformat()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"Stage 7 live validation {report.get('result', 'INCOMPLETE')}: {output}")


def _tcp_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.25):
            return True
    except OSError:
        return False


if __name__ == "__main__":
    main()
