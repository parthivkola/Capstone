"""Run one isolated TCP header-boundary check with an OVS mirror."""

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

SNAPLEN = 54
TCP_PORT = 39001
PAYLOAD_SIZE = 256
OBSERVATION_PORT = "s7obs0"
COLLECTOR_PORT = "s7rcv0"
COLLECTOR_NAMESPACE = "s7collector"
MIRROR_NAME = "stage7-tcp-54-boundary"
TEST_COOKIE = 0x573700000054

COLLECTOR_CODE = r"""
import json, socket, struct, sys, time
interface, snaplen, output = sys.argv[1], int(sys.argv[2]), sys.argv[3]
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sock.bind((interface, 0)); sock.settimeout(.25)
deadline = time.monotonic() + 8
found = None
while time.monotonic() < deadline:
    try: frame, address = sock.recvfrom(65535)
    except TimeoutError: continue
    if len(frame) < 14 or frame[12:14] != b'\x08\x00': continue
    if len(frame) < 34: continue
    ihl = (frame[14] & 15) * 4
    if frame[23] != 6 or ihl < 20 or len(frame) < 14 + ihl + 20: continue
    tcp_offset = 14 + ihl
    src_port, dst_port = struct.unpack('!HH', frame[tcp_offset:tcp_offset+4])
    src_ip = socket.inet_ntoa(frame[26:30]); dst_ip = socket.inet_ntoa(frame[30:34])
    if (src_ip, dst_ip, dst_port) != ('10.0.0.1', '10.0.0.3', 39001): continue
    tcp_header_length = (frame[tcp_offset+12] >> 4) * 4
    flags = frame[tcp_offset+13]
    ip_total_length = struct.unpack('!H', frame[16:18])[0]
    ip_options_length = ihl - 20
    tcp_options_length = tcp_header_length - 20
    complete_tcp_header = len(frame) >= tcp_offset + tcp_header_length
    visible_payload = (max(0, len(frame) - (tcp_offset + tcp_header_length))
                       if complete_tcp_header else None)
    found = {
      'timestamp_utc': __import__('datetime').datetime.now(
          __import__('datetime').timezone.utc).isoformat(),
      'received_frame_length_bytes': len(frame), 'configured_snaplen_bytes': snaplen,
      'ethertype': 'IPv4', 'ethernet_header_length_bytes': 14,
      'ipv4_header_length_bytes': ihl, 'ipv4_ihl_words': ihl // 4,
      'ipv4_options_length_bytes': ip_options_length,
      'ipv4_total_length_bytes': ip_total_length,
      'tcp_header_length_bytes': tcp_header_length,
      'tcp_data_offset_words': tcp_header_length // 4,
      'tcp_options_length_bytes': tcp_options_length,
      'tcp_header_complete': complete_tcp_header,
      'tcp_source_port': src_port, 'tcp_destination_port': dst_port,
      'tcp_flags_byte': flags,
      'tcp_flags': [name for bit, name in [
          (1,'FIN'),(2,'SYN'),(4,'RST'),(8,'PSH'),(16,'ACK'),
          (32,'URG'),(64,'ECE'),(128,'CWR')] if flags & bit],
      'source_ip': src_ip, 'destination_ip': dst_ip,
      'application_payload_bytes_visible': visible_payload,
      'socket_packet_type': int(address[2]),
      'raw_bytes_persisted': False,
    }
    break
sock.close()
result = {'received_packet_count': int(found is not None), 'observation': found,
          'socket_drop_stats_available': False}
with open(output, 'w', encoding='utf-8') as stream:
    json.dump(result, stream, sort_keys=True); stream.write('\n')
print(json.dumps(result, sort_keys=True))
"""

SENDER_CODE = r"""
import json, socket, struct, sys, time
interface, source_mac, destination_mac, payload_size = (
    sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]))
def checksum(data):
    if len(data) & 1: data += b'\0'
    words = struct.unpack('!' + 'H' * (len(data)//2), data)
    value = sum(words)
    while value >> 16: value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff
src_ip, dst_ip = '10.0.0.1', '10.0.0.3'
src_port, dst_port = 40123, 39001
payload = b'T' * payload_size
tcp_len = 20 + len(payload)
tcp = struct.pack('!HHIIHHHH', src_port, dst_port, 123456, 0,
                  (5 << 12) | 0x18, 4096, 0, 0) + payload
pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack('!BBH', 0, 6, tcp_len)
tcp_sum = checksum(pseudo + tcp)
tcp = tcp[:16] + struct.pack('!H', tcp_sum) + tcp[18:]
ip_len = 20 + len(tcp)
ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_len, 0x4242, 0x4000, 64, 6, 0,
                 socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
ip_sum = checksum(ip); ip = ip[:10] + struct.pack('!H', ip_sum) + ip[12:]
eth = (bytes.fromhex(destination_mac.replace(':','')) +
       bytes.fromhex(source_mac.replace(':','')) + b'\x08\x00')
frame = eth + ip + tcp
cap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
cap.bind((interface, 0)); cap.settimeout(2)
sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); sender.bind((interface, 0))
sent = sender.send(frame)
while True:
    outgoing, address = cap.recvfrom(65535)
    if (address[2] == 4 and len(outgoing) >= 54 and
            outgoing[12:14] == b'\x08\x00' and outgoing[23] == 6):
        off = 14 + (outgoing[14] & 15) * 4
        sport, dport = struct.unpack('!HH', outgoing[off:off+4])
        if sport == src_port and dport == dst_port: break
result = {'original_frame_length_bytes': len(outgoing), 'sender_socket_send_length_bytes': sent,
          'ipv4_header_length_bytes': (outgoing[14] & 15) * 4,
          'ipv4_ihl_words': outgoing[14] & 15,
          'tcp_header_length_bytes': (outgoing[off+12] >> 4) * 4,
          'tcp_data_offset_words': outgoing[off+12] >> 4,
          'tcp_source_port': sport, 'tcp_destination_port': dport,
          'tcp_flags_byte': outgoing[off+13], 'source_ip': src_ip, 'destination_ip': dst_ip,
          'transmitted_payload_length_bytes': payload_size,
          'raw_bytes_persisted': False}
print(json.dumps(result, sort_keys=True))
cap.close(); sender.close()
"""


def _run(command: list[str], *, timeout: float = 12.0) -> str:
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
    return result.stdout.strip()


def _ping(host: Any, label: str) -> dict[str, object]:
    stdout, stderr, code = host.pexec("ping -c 3 -W 1 10.0.0.3")
    return {
        "label": label,
        "success": code == 0,
        "returncode": code,
        "summary": next(
            (line.strip() for line in stdout.splitlines() if "packets transmitted" in line),
            stderr.strip()[-250:],
        ),
    }


def _wait_ryu(process: subprocess.Popen[bytes], log: Path) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Ryu exited early; inspect {log}")
        try:
            with socket.create_connection(("127.0.0.1", 6653), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("Ryu did not listen on 127.0.0.1:6653")


def _preflight(ryu_manager: Path) -> None:
    if os.geteuid() != 0:
        raise PermissionError("run as root in the isolated Mininet/OVS testbed")
    for name in ("mn", "ovs-vsctl", "ovs-ofctl", "ip"):
        if shutil.which(name) is None:
            raise RuntimeError(f"required executable unavailable: {name}")
    if not ryu_manager.is_file() or not os.access(ryu_manager, os.X_OK):
        raise RuntimeError(f"Ryu manager unavailable: {ryu_manager}")
    if subprocess.run(["systemctl", "is-active", "--quiet", "openvswitch"]).returncode:
        raise RuntimeError("OVS service is not active")
    if subprocess.run(["ovs-vsctl", "br-exists", "s1"], check=False).returncode == 0:
        raise RuntimeError("refusing pre-existing s1 bridge")
    namespaces = subprocess.run(
        ["ip", "netns", "list"], check=True, capture_output=True, text=True
    ).stdout
    if any(
        line.split() and line.split()[0] == COLLECTOR_NAMESPACE for line in namespaces.splitlines()
    ):
        raise RuntimeError("collector namespace already exists")
    with socket.socket() as probe:
        probe.settimeout(0.2)
        try:
            probe.connect(("127.0.0.1", 6653))
        except OSError:
            pass
        else:
            raise RuntimeError("refusing existing Ryu listener on 6653")


def _ryu_saw_tuple(path: Path) -> list[str]:
    matches = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        marker = "stage2_event="
        if marker not in line:
            continue
        try:
            event = json.loads(line.split(marker, 1)[1])
        except json.JSONDecodeError:
            continue
        observation = event.get("observation", {})
        payload = observation.get("payload", {}) if isinstance(observation, dict) else {}
        if (
            isinstance(payload, dict)
            and payload.get("src_ip") == "10.0.0.1"
            and payload.get("dst_ip") == "10.0.0.3"
            and payload.get("dst_port") == TCP_PORT
        ):
            matches.append(line)
    return matches


def run(output_dir: Path, ryu_manager: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite {output_dir}")
    _preflight(ryu_manager)
    output_dir.mkdir(parents=True)
    run_id = str(uuid.uuid4())
    log_path = output_dir / "ryu.log"
    collector_result_path = output_dir / "collector-metadata.json"
    ryu: subprocess.Popen[bytes] | None = None
    network: Any = None
    collector: subprocess.Popen[str] | None = None
    namespace_created = veth_created = bridge_port_added = mirror_attached = False
    flow_added = False
    summary: dict[str, object] = {
        "schema_version": 1,
        "run_id": run_id,
        "experiment": "one synthetic benign TCP packet; header-boundary validation only",
        "snaplen_bytes": SNAPLEN,
        "detector_or_policy_or_mitigation_invoked": False,
        "raw_packet_bytes_or_payload_persisted": False,
        "pcap_created": False,
    }
    env = os.environ.copy()
    env["SDN_STAGE2_PACKET_EVIDENCE_ENABLED"] = "false"
    env["SDN_STAGE2_INSTALL_TEST_RULE"] = "false"
    env.pop("SDN_TELEMETRY_JSONL", None)
    log_stream = log_path.open("wb")
    try:
        ryu = subprocess.Popen(
            [str(ryu_manager), "networking.ryu.stage2_controller"],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            stdout=log_stream,
            stderr=subprocess.STDOUT,
        )
        _wait_ryu(ryu, log_path)
        config = TopologyConfig.from_environment()
        config.validate()
        network = create_network(config)
        time.sleep(1)
        host1, host3 = network.get("h1"), network.get("h3")
        if not _ping(host1, "pre_mirror")["success"]:
            raise RuntimeError("baseline reachability failed")
        ports = _run(["ovs-vsctl", "list-ports", "s1"]).splitlines()
        if "s1-eth1" not in ports or "s1-eth3" not in ports:
            raise RuntimeError(f"unexpected topology ports {ports}")

        _run(["ip", "netns", "add", COLLECTOR_NAMESPACE])
        namespace_created = True
        _run(
            ["ip", "link", "add", OBSERVATION_PORT, "type", "veth", "peer", "name", COLLECTOR_PORT]
        )
        veth_created = True
        _run(["ip", "link", "set", COLLECTOR_PORT, "netns", COLLECTOR_NAMESPACE])
        _run(["ip", "link", "set", OBSERVATION_PORT, "up"])
        _run(["ip", "-n", COLLECTOR_NAMESPACE, "link", "set", "lo", "up"])
        _run(["ip", "-n", COLLECTOR_NAMESPACE, "link", "set", COLLECTOR_PORT, "up"])
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
                "--id=@m",
                "create",
                "Mirror",
                f"name={MIRROR_NAME}",
                "select_src_port=@src",
                "output_port=@out",
                f"snaplen={SNAPLEN}",
                "--",
                "set",
                "Bridge",
                "s1",
                "mirrors=@m",
            ]
        )
        mirror_attached = True

        in_port = int(_run(["ovs-vsctl", "get", "Interface", "s1-eth1", "ofport"]))
        out_port = int(_run(["ovs-vsctl", "get", "Interface", "s1-eth3", "ofport"]))
        if (in_port, out_port) != (1, 3):
            raise RuntimeError(f"unexpected datapath ports {in_port}->{out_port}")
        flow = (
            f"cookie=0x{TEST_COOKIE:x},priority=200,in_port={in_port},"
            f"eth_type=0x0800,ip_proto=6,tcp,tp_dst={TCP_PORT},"
            f"actions=output:{out_port}"
        )
        _run(["ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1", flow])
        flow_added = True
        active = _ping(host1, "mirror_active")
        if not active["success"]:
            raise RuntimeError("reachability failed while mirror active")

        ipv4_addresses = _run(["ip", "-n", COLLECTOR_NAMESPACE, "-4", "-brief", "address", "show"])
        ipv6_addresses = _run(["ip", "-n", COLLECTOR_NAMESPACE, "-6", "-brief", "address", "show"])
        ipv4_routes = _run(["ip", "-n", COLLECTOR_NAMESPACE, "-4", "route", "show"])
        ipv6_routes = _run(["ip", "-n", COLLECTOR_NAMESPACE, "-6", "route", "show"])
        loopback_probe = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                COLLECTOR_NAMESPACE,
                sys.executable,
                "-c",
                "import socket; s=socket.socket(); s.settimeout(.4); "
                "raise SystemExit(0 if s.connect_ex(('127.0.0.1',6653)) != 0 else 1)",
            ],
            check=False,
        )
        if loopback_probe.returncode:
            raise RuntimeError("collector namespace reached Ryu loopback unexpectedly")

        collector = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                COLLECTOR_NAMESPACE,
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
        sender_code = SENDER_CODE
        sender_out, sender_err, sender_status = host1.pexec(
            sys.executable,
            "-c",
            sender_code,
            "h1-eth0",
            host1.MAC(),
            host3.MAC(),
            str(PAYLOAD_SIZE),
        )
        if sender_status:
            raise RuntimeError(f"sender failed: {sender_err.strip()}")
        try:
            collector_out, collector_err = collector.communicate(timeout=10)
        except subprocess.TimeoutExpired as exc:
            collector.kill()
            collector.communicate()
            raise RuntimeError("collector did not observe matching TCP packet") from exc
        if collector.returncode:
            raise RuntimeError(f"collector failed: {collector_err.strip()}")
        sender = json.loads(sender_out.strip().splitlines()[-1])
        collected = json.loads(collector_result_path.read_text(encoding="utf-8"))
        observation = collected.get("observation")
        if not isinstance(observation, dict):
            raise RuntimeError(f"no matching TCP packet reached collector: {collector_out}")
        ryu_matches = _ryu_saw_tuple(log_path)
        complete = bool(observation["tcp_header_complete"])
        no_payload = observation["application_payload_bytes_visible"] == 0
        exact = observation["received_frame_length_bytes"] == SNAPLEN
        if not exact or not complete or not no_payload:
            raise RuntimeError(
                "54-byte boundary did not include complete measured TCP headers without payload"
            )
        summary.update(
            {
                "ovs_version": _run(["ovs-vsctl", "--version"]).splitlines()[0],
                "openflow": "OpenFlow 1.3",
                "datapath_id": "0000000000000001",
                "sender_measurement": sender,
                "collector_observation": observation,
                "header_boundary": {
                    "snaplen": SNAPLEN,
                    "exact_boundary": exact,
                    "original_frame_substantially_larger": sender["original_frame_length_bytes"]
                    > SNAPLEN,
                    "all_measured_headers_complete": complete,
                    "application_payload_bytes_visible": observation[
                        "application_payload_bytes_visible"
                    ],
                    "result": "exact_boundary_complete_headers_no_payload",
                },
                "mirror": {
                    "name": MIRROR_NAME,
                    "snaplen": SNAPLEN,
                    "selected_ingress": "s1-eth1 / h1",
                    "output": OBSERVATION_PORT,
                    "collector_namespace": COLLECTOR_NAMESPACE,
                },
                "isolation": {
                    "collector_namespace_reached_host_ryu_loopback": False,
                    "collector_ipv4_addresses": ipv4_addresses,
                    "collector_ipv4_routes": ipv4_routes,
                    "collector_ipv6_addresses": ipv6_addresses,
                    "collector_ipv6_routes": ipv6_routes,
                    "ipv6_isolation_claimed": False,
                    "ryu_received_matching_packetin": bool(ryu_matches),
                    "ryu_matching_events": ryu_matches,
                    "observation_interface_not_forwarding_path": True,
                },
                "reachability": {"before_mirror": "passed", "while_mirror_active": active},
                "temporary_forwarding_flow": flow,
                "collector_metadata_stdout": collector_out.strip(),
                "created_at_utc": datetime.now(UTC).isoformat(),
            }
        )
    finally:
        if collector is not None and collector.poll() is None:
            collector.terminate()
            try:
                collector.wait(timeout=2)
            except subprocess.TimeoutExpired:
                collector.kill()
                collector.wait(timeout=2)
        if mirror_attached:
            subprocess.run(["ovs-vsctl", "clear", "Bridge", "s1", "mirrors"], check=False)
        if flow_added:
            subprocess.run(
                [
                    "ovs-ofctl",
                    "-O",
                    "OpenFlow13",
                    "del-flows",
                    "s1",
                    f"cookie=0x{TEST_COOKIE:x}/-1",
                ],
                check=False,
            )
        if bridge_port_added:
            subprocess.run(
                ["ovs-vsctl", "--if-exists", "del-port", "s1", OBSERVATION_PORT], check=False
            )
        if network is not None:
            try:
                post = _ping(network.get("h1"), "after_mirror_cleanup")
                reachability = summary.get("reachability")
                if not isinstance(reachability, dict):
                    reachability = {}
                    summary["reachability"] = reachability
                reachability["after_cleanup"] = post
            except Exception as exc:
                summary["post_cleanup_reachability_error"] = type(exc).__name__
            network.stop()
        if namespace_created:
            subprocess.run(["ip", "netns", "del", COLLECTOR_NAMESPACE], check=False)
        if veth_created:
            subprocess.run(["ip", "link", "del", OBSERVATION_PORT], check=False)
        if ryu is not None and ryu.poll() is None:
            ryu.send_signal(signal.SIGINT)
            try:
                ryu.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ryu.terminate()
                ryu.wait(timeout=3)
        log_stream.close()
        summary["cleanup"] = {
            "bridge_absent": subprocess.run(
                ["ovs-vsctl", "br-exists", "s1"], check=False
            ).returncode
            != 0,
            "namespace_absent": COLLECTOR_NAMESPACE
            not in subprocess.run(
                ["ip", "netns", "list"], check=True, capture_output=True, text=True
            ).stdout,
            "observation_interface_absent": subprocess.run(
                ["ip", "link", "show", OBSERVATION_PORT], check=False, capture_output=True
            ).returncode
            != 0,
            "ryu_listener_absent": _listener_absent(),
            "mirror_configuration_absent": not _mirror_exists(),
        }
        (output_dir / "validation-summary.json").write_text(
            json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
    return summary


def _listener_absent() -> bool:
    with socket.socket() as probe:
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
    return bool(
        headings
        and "name" in headings
        and any(row[headings.index("name")] == MIRROR_NAME for row in rows)
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("experiments/stage7-telemetry/tcp-truncation-validation-2026-10-08-01"),
    )
    parser.add_argument("--ryu-manager", type=Path, default=Path(".venv-ryu/bin/ryu-manager"))
    args = parser.parse_args()
    print(json.dumps(run(args.output_dir, args.ryu_manager), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
