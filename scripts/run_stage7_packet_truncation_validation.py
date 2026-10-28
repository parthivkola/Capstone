"""Validate OVS mirror snaplen at an isolated metadata-only collector."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from networking.mininet.config import TopologyConfig
from networking.mininet.stage2_topology import create_network

SNAPLEN = 128
UDP_PORT = 39000
UDP_PAYLOAD_SIZE = 400
OBSERVATION_PORT = "s7obs0"
COLLECTOR_PORT = "s7rcv0"
COLLECTOR_NAMESPACE = "s7collector"
TEST_COOKIE = 0x573700000001

COLLECTOR_CODE = r"""
import json, socket, struct, sys, time
interface, snaplen, output = sys.argv[1], int(sys.argv[2]), sys.argv[3]

def datetime_now():
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat()

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sock.bind((interface, 0))
sock.settimeout(0.25)
deadline = time.monotonic() + 8.0
found = None
while time.monotonic() < deadline:
    try:
        frame, address = sock.recvfrom(65535)
    except TimeoutError:
        continue
    if len(frame) < 42 or frame[12:14] != b'\x08\x00':
        continue
    ihl = (frame[14] & 0x0f) * 4
    if frame[23] != 17 or len(frame) < 14 + ihl + 8:
        continue
    udp_offset = 14 + ihl
    src_port, dst_port = struct.unpack('!HH', frame[udp_offset:udp_offset + 4])
    src_ip = socket.inet_ntoa(frame[26:30])
    dst_ip = socket.inet_ntoa(frame[30:34])
    if (src_ip, dst_ip, dst_port) != ('10.0.0.1', '10.0.0.3', 39000):
        continue
    found = {
        'timestamp_utc': datetime_now(),
        'sequence': 1,
        'received_frame_length': len(frame),
        'configured_snaplen': snaplen,
        'ethertype': 'IPv4',
        'protocol': 'UDP',
        'source_ip': src_ip,
        'destination_ip': dst_ip,
        'source_port': src_port,
        'destination_port': dst_port,
        'socket_packet_type': int(address[2]),
    }
    break
sock.close()
if found is None:
    result = {'received_packet_count': 0, 'configured_snaplen': snaplen}
else:
    result = {'received_packet_count': 1, 'observation': found,
              'socket_drop_stats_available': False}
with open(output, 'w', encoding='utf-8') as stream:
    json.dump(result, stream, sort_keys=True)
    stream.write('\n')
print(json.dumps(result, sort_keys=True))
"""

SENDER_CODE = r"""
import json, select, socket, struct, sys, time
interface, destination_port = sys.argv[1], int(sys.argv[2])
capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
capture.bind((interface, 0))
capture.setblocking(False)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.settimeout(3.0)
payload = b'X' * 400
client.sendto(payload, ('10.0.0.3', destination_port))
reply, _ = client.recvfrom(64)
deadline = time.monotonic() + 3.0
frame_info = None
while time.monotonic() < deadline:
    ready, _, _ = select.select([capture], [], [], 0.1)
    if not ready:
        continue
    frame, address = capture.recvfrom(65535)
    if len(frame) < 42 or frame[12:14] != b'\x08\x00' or address[2] != 4:
        continue
    ihl = (frame[14] & 0x0f) * 4
    if frame[23] != 17 or len(frame) < 14 + ihl + 8:
        continue
    udp_offset = 14 + ihl
    _, dst_port = struct.unpack('!HH', frame[udp_offset:udp_offset + 4])
    if dst_port == destination_port:
        frame_info = {'original_frame_length': len(frame),
                      'protocol': 'UDP', 'destination_port': dst_port,
                      'transmitted_payload_length': len(payload),
                      'echoed_payload_length': len(reply)}
        break
capture.close()
client.close()
if frame_info is None:
    raise SystemExit('did not observe the transmitted UDP frame on h1')
print(json.dumps(frame_info, sort_keys=True))
"""


def _run(command: list[str], *, timeout: float = 10.0) -> str:
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.stdout.strip()


def _ping(host: Any, label: str) -> dict[str, object]:
    stdout, stderr, returncode = host.pexec("ping -c 3 -W 1 10.0.0.3")
    return {
        "label": label,
        "success": returncode == 0,
        "returncode": returncode,
        "summary": next(
            (line.strip() for line in stdout.splitlines() if "packets transmitted" in line),
            stderr.strip()[-300:],
        ),
    }


def _packet_in_forward_count(log_path: Path) -> int:
    if not log_path.exists():
        return 0
    return sum('"event_type": "packet_in_forwarded"' in line for line in log_path.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines())


def _ryu_saw_test_udp(log_path: Path) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    if not log_path.exists():
        return matches
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        marker = "stage2_event="
        if marker not in line:
            continue
        try:
            event = json.loads(line.split(marker, 1)[1])
        except json.JSONDecodeError:
            continue
        observation = event.get("observation")
        if not isinstance(observation, dict):
            continue
        payload = observation.get("payload")
        if not isinstance(payload, dict):
            continue
        if (
            payload.get("src_ip") == "10.0.0.1"
            and payload.get("dst_ip") == "10.0.0.3"
            and payload.get("dst_port") == UDP_PORT
        ):
            matches.append(event)
    return matches


def _wait_ryu(process: subprocess.Popen[bytes], log_path: Path) -> None:
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Ryu exited early; inspect {log_path}")
        try:
            with socket.create_connection(("127.0.0.1", 6653), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("Ryu did not listen on 127.0.0.1:6653")


def _preflight(ryu_manager: Path) -> None:
    if os.geteuid() != 0:
        raise PermissionError("run this isolated Mininet/OVS validation as root")
    for executable in ("mn", "ovs-vsctl", "ovs-ofctl", "ip"):
        if shutil.which(executable) is None:
            raise RuntimeError(f"required executable unavailable: {executable}")
    if not ryu_manager.is_file() or not os.access(ryu_manager, os.X_OK):
        raise RuntimeError(f"Ryu manager is unavailable: {ryu_manager}")
    if subprocess.run(["systemctl", "is-active", "--quiet", "openvswitch"]).returncode:
        raise RuntimeError("Open vSwitch service is not active")
    if subprocess.run(["ovs-vsctl", "br-exists", "s1"], check=False).returncode == 0:
        raise RuntimeError("refusing to use pre-existing s1 bridge")
    namespaces = subprocess.run(
        ["ip", "netns", "list"], check=True, capture_output=True, text=True
    ).stdout.splitlines()
    if any(line.split()[0] == COLLECTOR_NAMESPACE for line in namespaces):
        raise RuntimeError(f"refusing to replace existing namespace {COLLECTOR_NAMESPACE}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener_probe:
        listener_probe.settimeout(0.2)
        try:
            listener_probe.connect(("127.0.0.1", 6653))
        except OSError:
            pass
        else:
            raise RuntimeError("refusing to use an existing listener on 127.0.0.1:6653")


def run(output_dir: Path, ryu_manager: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite experiment artifacts: {output_dir}")
    _preflight(ryu_manager)
    output_dir.mkdir(parents=True)
    run_id = str(uuid.uuid4())
    namespace = COLLECTOR_NAMESPACE
    ryu_log = output_dir / "ryu.log"
    collector_result_path = output_dir / "collector-metadata.json"
    ryu_process: subprocess.Popen[bytes] | None = None
    network: Any = None
    collector_process: subprocess.Popen[str] | None = None
    namespace_created = False
    veth_created = False
    bridge_port_added = False
    mirror_attached = False
    summary: dict[str, object] = {
        "schema_version": 1,
        "run_id": run_id,
        "experiment": "single bounded UDP truncation check; not an attack scenario",
        "configured_snaplen_bytes": SNAPLEN,
        "raw_packet_bytes_persisted": False,
        "pcap_created": False,
        "detector_or_mitigation_invoked": False,
    }
    env = os.environ.copy()
    env["SDN_STAGE2_PACKET_EVIDENCE_ENABLED"] = "false"
    env["SDN_STAGE2_INSTALL_TEST_RULE"] = "false"
    env.pop("SDN_TELEMETRY_JSONL", None)
    ryu_log_stream = ryu_log.open("wb")
    try:
        ryu_process = subprocess.Popen(
            [str(ryu_manager), "networking.ryu.stage2_controller"],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            stdout=ryu_log_stream,
            stderr=subprocess.STDOUT,
        )
        _wait_ryu(ryu_process, ryu_log)
        config = TopologyConfig.from_environment()
        config.validate()
        network = create_network(config)
        time.sleep(1.0)
        ports = _run(["ovs-vsctl", "list-ports", "s1"]).splitlines()
        if "s1-eth1" not in ports or "s1-eth3" not in ports:
            raise RuntimeError(f"unexpected Stage 2 bridge ports: {ports}")
        host1 = network.get("h1")
        host3 = network.get("h3")
        baseline = _ping(host1, "before_mirror")
        if not baseline["success"]:
            raise RuntimeError("baseline Mininet reachability failed")
        packetins_after_baseline = _packet_in_forward_count(ryu_log)

        _run(["ip", "netns", "add", namespace])
        namespace_created = True
        _run(
            [
                "ip",
                "link",
                "add",
                OBSERVATION_PORT,
                "type",
                "veth",
                "peer",
                "name",
                COLLECTOR_PORT,
            ]
        )
        veth_created = True
        _run(["ip", "link", "set", COLLECTOR_PORT, "netns", namespace])
        _run(["ip", "link", "set", OBSERVATION_PORT, "up"])
        _run(["ip", "-n", namespace, "link", "set", "lo", "up"])
        _run(["ip", "-n", namespace, "link", "set", COLLECTOR_PORT, "up"])
        _run(["ovs-vsctl", "add-port", "s1", OBSERVATION_PORT])
        bridge_port_added = True
        _run(
            [
                "ovs-vsctl",
                "--",
                "--id=@src",
                "get",
                "Port",
                "s1-eth1",
                "--",
                "--id=@out",
                "get",
                "Port",
                OBSERVATION_PORT,
                "--",
                "--id=@mirror",
                "create",
                "Mirror",
                "name=stage7-truncation-validation",
                "select_src_port=@src",
                "output_port=@out",
                f"snaplen={SNAPLEN}",
                "--",
                "set",
                "Bridge",
                "s1",
                "mirrors=@mirror",
            ]
        )
        mirror_attached = True
        mirror_row = _run(
            [
                "ovs-vsctl",
                "--format=json",
                "--columns=name,snaplen,select_src_port,output_port",
                "list",
                "Mirror",
            ]
        )
        collector_addresses = _run(["ip", "-n", namespace, "-brief", "address", "show"])
        collector_routes = _run(["ip", "-n", namespace, "route", "show"])
        collector_control_probe = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                sys.executable,
                "-c",
                "import socket; s=socket.socket(); s.settimeout(.5); "
                "raise SystemExit(0 if s.connect_ex(('127.0.0.1',6653)) != 0 else 1)",
            ],
            check=False,
        )
        if collector_control_probe.returncode != 0:
            raise RuntimeError("collector namespace unexpectedly reached Ryu loopback listener")

        # A tightly scoped forwarding rule ensures the probe itself is handled by
        # OVS rather than delivered as PacketIn to Ryu.
        in_port = int(_run(["ovs-vsctl", "get", "Interface", "s1-eth1", "ofport"]))
        out_port = int(_run(["ovs-vsctl", "get", "Interface", "s1-eth3", "ofport"]))
        if (in_port, out_port) != (1, 3):
            raise RuntimeError(f"unexpected isolated topology port numbers: {in_port}->{out_port}")
        test_flow = (
            f"cookie=0x{TEST_COOKIE:x},priority=200,in_port={in_port},udp,"
            f"tp_dst={UDP_PORT},actions=output:{out_port}"
        )
        _run(["ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1", test_flow])
        active_ping = _ping(host1, "while_mirror_active")
        if not active_ping["success"]:
            raise RuntimeError("Mininet reachability failed while mirror was active")
        packetins_before_probe = _packet_in_forward_count(ryu_log)

        server_code = (
            "import socket,time; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
            f"s.bind(('10.0.0.3',{UDP_PORT})); s.settimeout(10); "
            "d,a=s.recvfrom(2048); s.sendto(str(len(d)).encode(),a); "
            "print('received_payload_length='+str(len(d)),flush=True)"
        )
        server_process = host3.popen([sys.executable, "-u", "-c", server_code])
        time.sleep(0.2)
        if server_process.poll() is not None:
            raise RuntimeError("bounded UDP test receiver did not start")
        collector_process = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                sys.executable,
                "-c",
                COLLECTOR_CODE,
                COLLECTOR_PORT,
                str(SNAPLEN),
                str(collector_result_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        sender_code = SENDER_CODE.replace("'X' * 400", f"'X' * {UDP_PAYLOAD_SIZE}")
        probe_started_at = datetime.now(UTC)
        sender_out, sender_err, sender_status = host1.pexec(
            sys.executable,
            "-c",
            sender_code,
            "h1-eth0",
            str(UDP_PORT),
        )
        if sender_status != 0:
            raise RuntimeError(f"bounded UDP sender failed: {sender_err.strip()}")
        try:
            collector_stdout, collector_stderr = collector_process.communicate(timeout=10)
        except subprocess.TimeoutExpired as error:
            collector_process.kill()
            collector_process.communicate()
            raise RuntimeError("collector did not receive the bounded mirror copy") from error
        if collector_process.returncode != 0:
            raise RuntimeError(f"collector failed: {collector_stderr.strip()}")
        time.sleep(0.1)
        probe_ended_at = datetime.now(UTC)
        original_metadata = json.loads(sender_out.strip().splitlines()[-1])
        collector_metadata = json.loads(collector_result_path.read_text(encoding="utf-8"))
        observed = collector_metadata.get("observation")
        if not isinstance(observed, dict):
            raise RuntimeError(f"no matching UDP frame reached collector: {collector_stdout}")
        ryu_test_observations = _ryu_saw_test_udp(ryu_log)
        if ryu_test_observations:
            raise RuntimeError(
                "Ryu recorded the test UDP tuple; the mirror/control-plane boundary is unproven"
            )
        received_length = int(observed["received_frame_length"])
        original_length = int(original_metadata["original_frame_length"])
        if not (received_length <= SNAPLEN and received_length < original_length):
            raise RuntimeError(
                f"truncation not established: received={received_length}, "
                f"original={original_length}, snaplen={SNAPLEN}"
            )
        after_mirror_dump = _run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"])
        test_cookie_present = f"cookie=0x{TEST_COOKIE:x}" in after_mirror_dump
        if not test_cookie_present:
            raise RuntimeError("the exact test forwarding rule was not visible on OVS")
        summary.update(
            {
                "ovs_version": _run(["ovs-vsctl", "--version"]).splitlines()[0],
                "openflow_protocol": "OpenFlow13",
                "topology": "Stage2 isolated h1-h2-h3 star; collector in separate netns",
                "datapath_id": "0000000000000001",
                "mirror": {
                    "configured_snaplen_bytes": SNAPLEN,
                    "ovsdb_mirror_rows_json": mirror_row,
                    "selected_ingress_port": "s1-eth1 / h1",
                    "observation_output_port": OBSERVATION_PORT,
                    "collector_namespace": namespace,
                    "collector_addresses": collector_addresses,
                    "collector_routes": collector_routes,
                },
                "packet": {
                    "original_frame_length_bytes": original_length,
                    "transmitted_udp_payload_length_bytes": UDP_PAYLOAD_SIZE,
                    "received_frame_length_bytes": received_length,
                    "result": (
                        "exact_snaplen"
                        if received_length == SNAPLEN
                        else "shorter_than_snaplen"
                    ),
                    "shorter_than_original": received_length < original_length,
                    "collector_metadata": observed,
                    "raw_packet_bytes_persisted": False,
                    "payload_persisted": False,
                },
                "isolation": {
                    "collector_namespace_reached_ryu_loopback": False,
                    "collector_ipv4_route_table_empty": collector_routes == "",
                    "collector_ip_addresses": collector_addresses,
                    "ryu_packet_in_forward_count_after_baseline": packetins_after_baseline,
                    "ryu_packet_in_forward_count_before_probe": packetins_before_probe,
                    "ryu_packet_in_forward_count_after_probe": _packet_in_forward_count(ryu_log),
                    "ryu_test_tuple_observations": ryu_test_observations,
                    "probe_interval_utc": [
                        probe_started_at.isoformat(),
                        probe_ended_at.isoformat(),
                    ],
                    "ryu_received_test_packet": False,
                    "observation_output_is_not_forwarding_path": True,
                },
                "reachability": {
                    "before_mirror": baseline,
                    "while_mirror_active": active_ping,
                },
                "temporary_test_flow": test_flow,
                "temporary_test_cookie_visible_on_ovs": test_cookie_present,
                "collector_stdout_metadata_only": collector_stdout.strip(),
            }
        )
        summary["timestamp_utc"] = datetime.now(UTC).isoformat()
        (output_dir / "validation-summary.json").write_text(
            json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
    finally:
        if collector_process is not None and collector_process.poll() is None:
            collector_process.terminate()
            try:
                collector_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                collector_process.kill()
                collector_process.wait(timeout=2)
        if mirror_attached:
            subprocess.run(["ovs-vsctl", "clear", "Bridge", "s1", "mirrors"], check=False)
        if bridge_port_added:
            subprocess.run(
                ["ovs-vsctl", "--if-exists", "del-port", "s1", OBSERVATION_PORT], check=False
            )
        if network is not None:
            try:
                post_cleanup_reachability = _ping(network.get("h1"), "after_mirror_cleanup")
                reachability = summary.get("reachability")
                if not isinstance(reachability, dict):
                    reachability = {}
                reachability["after_mirror_cleanup"] = post_cleanup_reachability
                summary["reachability"] = reachability
            except Exception as error:
                summary["post_cleanup_reachability_error"] = type(error).__name__
            network.stop()
        if namespace_created:
            subprocess.run(["ip", "netns", "del", namespace], check=False)
        if veth_created:
            subprocess.run(["ip", "link", "del", OBSERVATION_PORT], check=False)
        if ryu_process is not None and ryu_process.poll() is None:
            ryu_process.send_signal(signal.SIGINT)
            try:
                ryu_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ryu_process.terminate()
                try:
                    ryu_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    ryu_process.kill()
                    ryu_process.wait(timeout=3)
        ryu_log_stream.close()
        cleanup = {
            "bridge_absent": subprocess.run(
                ["ovs-vsctl", "br-exists", "s1"], check=False
            ).returncode != 0,
            "namespace_absent": namespace
            not in subprocess.run(
                ["ip", "netns", "list"], check=True, capture_output=True, text=True
            ).stdout,
            "observation_interface_absent": subprocess.run(
                ["ip", "link", "show", OBSERVATION_PORT], check=False, capture_output=True
            ).returncode != 0,
            "ryu_listener_absent": _listener_absent(),
            "mirror_configuration_absent": not _mirror_exists(),
        }
        summary["cleanup"] = cleanup
        if not all(cleanup.values()):
            summary["cleanup_error"] = "one or more cleanup checks failed"
        if summary.get("reachability"):
            (output_dir / "validation-summary.json").write_text(
                json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
            )
    return summary


def _listener_absent() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        try:
            probe.connect(("127.0.0.1", 6653))
        except OSError:
            return True
    return False


def _mirror_exists() -> bool:
    result = subprocess.run(
        ["ovs-vsctl", "--format=json", "--columns=name", "list", "Mirror"],
        check=True,
        capture_output=True,
        text=True,
    )
    parsed = json.loads(result.stdout)
    headings = parsed.get("headings", [])
    rows = parsed.get("data", [])
    if not headings or "name" not in headings:
        return False
    name_column = headings.index("name")
    return any(row[name_column] == "stage7-truncation-validation" for row in rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("experiments/stage7-telemetry/truncation-validation-2026-10-08-01"),
    )
    parser.add_argument(
        "--ryu-manager", type=Path, default=Path(".venv-ryu/bin/ryu-manager")
    )
    args = parser.parse_args()
    print(json.dumps(run(args.output_dir, args.ryu_manager), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
