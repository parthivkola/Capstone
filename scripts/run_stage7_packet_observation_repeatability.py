"""Collect six bounded repeatability runs for the OVS snaplen=54 observer."""

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
from networking.mininet.packet_observation_config import (
    build_configuration_manifest,
    parse_ovsdb_table,
)
from networking.mininet.stage2_topology import create_network
from networking.mininet.stage3_config import PORT_SCAN_ALLOWLIST

SNAPLEN = 54
MAX_OBSERVATIONS_PER_SECOND = 32
MAX_OBSERVATIONS_PER_RUN = 256
COLLECTOR_NAMESPACE = "s7collector"
OBSERVATION_PORT = "s7obs0"
COLLECTOR_PORT = "s7rcv0"
H1_IP = "10.0.0.1"
H2_IP = "10.0.0.2"
H3_IP = "10.0.0.3"

COLLECTOR_CODE = r"""
import json, os, signal, socket, struct, sys, time
interface, run_id, output = sys.argv[1:4]
snaplen, rate_cap, run_cap = map(int, sys.argv[4:7])
stop = False
def halt(*_):
    global stop
    stop = True
signal.signal(signal.SIGTERM, halt)
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sock.bind((interface, 0)); sock.settimeout(.1)
drop_option = getattr(socket, 'SO_RXQ_OVFL', None)
drop_counter_supported = False
if drop_option is not None:
    try:
        sock.setsockopt(socket.SOL_SOCKET, drop_option, 1)
        drop_counter_supported = True
    except OSError:
        pass
records = []
seen = accepted = rate_dropped = cap_dropped = 0
rx_drops = None
start = time.monotonic(); second_bucket = int(start)
bucket_count = 0
while not stop and time.monotonic() - start < 20:
    try:
        frame, ancillary, _, address = sock.recvmsg(65535, 256)
    except TimeoutError:
        continue
    except OSError:
        break
    seen += 1
    for level, kind, value in ancillary:
        if level == socket.SOL_SOCKET and drop_option is not None and kind == drop_option:
            rx_drops = int.from_bytes(value[:4], byteorder=sys.byteorder)
    now = time.monotonic(); bucket = int(now)
    if bucket != second_bucket:
        second_bucket, bucket_count = bucket, 0
    if accepted >= run_cap:
        cap_dropped += 1
        continue
    if bucket_count >= rate_cap:
        rate_dropped += 1
        continue
    bucket_count += 1; accepted += 1
    rec = {
      'schema_version': 1, 'record_type': 'packet_header_observation',
      'run_id': run_id,
      'observed_at': __import__('datetime').datetime.now(
          __import__('datetime').timezone.utc).isoformat(),
      'frame_length_bytes': len(frame), 'configured_snaplen_bytes': snaplen,
      'socket_packet_type': int(address[2]), 'source_interface': interface,
      'source_mac': None, 'destination_mac': None, 'ethertype': None,
      'source_ip': None, 'destination_ip': None,
      'source_port': None, 'destination_port': None, 'ip_protocol': None,
      'ipv4_ihl_words': None, 'ipv4_header_length_bytes': None,
      'tcp_data_offset_words': None, 'tcp_header_length_bytes': None,
      'tcp_flags_byte': None, 'tcp_flags': [], 'tcp_header_complete': None,
      'application_payload_bytes_visible': 0,
      'payload_visibility_assessable': False,
    }
    if len(frame) >= 14:
        rec['destination_mac'] = ':'.join(f'{v:02x}' for v in frame[0:6])
        rec['source_mac'] = ':'.join(f'{v:02x}' for v in frame[6:12])
        ethertype = struct.unpack('!H', frame[12:14])[0]
        rec['ethertype'] = f'0x{ethertype:04x}'
        if ethertype == 0x0800 and len(frame) >= 34:
            ihl = (frame[14] & 15) * 4
            proto = frame[23]
            rec['source_ip'] = socket.inet_ntoa(frame[26:30])
            rec['destination_ip'] = socket.inet_ntoa(frame[30:34])
            rec['ip_protocol'] = proto
            rec['ipv4_ihl_words'] = ihl // 4
            rec['ipv4_header_length_bytes'] = ihl
            rec['ipv4_total_length_bytes'] = struct.unpack('!H', frame[16:18])[0]
            if ihl >= 20 and len(frame) >= 14 + ihl:
                rec['payload_visibility_assessable'] = True
                if proto == 6 and len(frame) >= 14 + ihl + 20:
                    off = 14 + ihl
                    src, dst = struct.unpack('!HH', frame[off:off+4])
                    tcp_len = (frame[off+12] >> 4) * 4
                    flags = frame[off+13]
                    complete = len(frame) >= off + tcp_len
                    rec.update({'source_port': src, 'destination_port': dst,
                      'tcp_data_offset_words': tcp_len // 4,
                      'tcp_header_length_bytes': tcp_len,
                      'tcp_flags_byte': flags,
                      'tcp_flags': [name for bit, name in [
                          (1,'FIN'),(2,'SYN'),(4,'RST'),(8,'PSH'),
                          (16,'ACK'),(32,'URG'),(64,'ECE'),(128,'CWR')]
                          if flags & bit],
                      'tcp_header_complete': complete})
                    rec['application_payload_bytes_visible'] = max(
                        0, len(frame) - (off + tcp_len)
                    )
                elif proto == 17 and len(frame) >= 14 + ihl + 8:
                    off = 14 + ihl
                    src, dst = struct.unpack('!HH', frame[off:off+4])
                    rec.update({'source_port': src, 'destination_port': dst})
                    rec['application_payload_bytes_visible'] = max(0, len(frame) - (off + 8))
                elif proto == 1 and len(frame) > 14 + ihl + 8:
                    rec['application_payload_bytes_visible'] = len(frame) - (14 + ihl + 8)
        elif ethertype == 0x0806:
            rec['payload_visibility_assessable'] = True
        elif ethertype == 0x86dd and len(frame) == 54:
            rec['payload_visibility_assessable'] = True
    records.append(rec)
sock.close()
result = {'schema_version': 1, 'record_type': 'collector_run_summary', 'run_id': run_id,
 'frames_seen': seen, 'observations_accepted': accepted,
 'rate_limit_drops': rate_dropped, 'run_cap_drops': cap_dropped,
 'socket_drop_counter_available': drop_counter_supported,
 'socket_drops_reported': rx_drops, 'observation_rate_cap_per_second': rate_cap,
 'observation_cap_per_run': run_cap, 'run_duration_seconds': round(time.monotonic()-start, 6),
 'observations': records}
with open(output, 'w', encoding='utf-8') as f: json.dump(result, f, sort_keys=True); f.write('\n')
print(json.dumps({k:v for k,v in result.items() if k != 'observations'}, sort_keys=True))
"""

SENDER_MONITOR_CODE = r"""
import json, signal, socket, struct, sys, time
interface, run_id, workload, output = sys.argv[1:5]
ports = {22,53,67,80,443,8080,18080,5353}
target = '10.0.0.3'; source = '10.0.0.1' if workload == 'benign' else '10.0.0.2'
stop = False
def halt(*_):
    global stop
    stop = True
signal.signal(signal.SIGTERM, halt)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((interface,0)); s.settimeout(.1)
records=[]; start=time.monotonic()
while not stop and time.monotonic()-start < 20:
    try: frame, addr = s.recvfrom(65535)
    except TimeoutError: continue
    if addr[2] != 4 or len(frame) < 34 or frame[12:14] != b'\x08\x00': continue
    ihl=(frame[14]&15)*4
    if (len(frame)<14+ihl or socket.inet_ntoa(frame[26:30]) != source
            or socket.inet_ntoa(frame[30:34]) != target): continue
    proto=frame[23]
    item={'run_id':run_id,'timestamp_utc':__import__('datetime').datetime.now(
      __import__('datetime').timezone.utc).isoformat(),'original_frame_length_bytes':len(frame),
      'source_ip':source,'destination_ip':target,'ip_protocol':proto,
      'payload_bytes_persisted':False}
    if workload == 'benign' and proto == 1 and len(frame)>=14+ihl+8:
        item.update({'packet_kind':'icmp_echo_request'})
    elif workload == 'port_scan' and proto == 6 and len(frame)>=14+ihl+20:
        off=14+ihl; src,dst=struct.unpack('!HH',frame[off:off+4]); flags=frame[off+13]
        if dst not in ports or not flags & 2: continue
        item.update({'packet_kind':'tcp_syn_probe','source_port':src,'destination_port':dst,'tcp_flags_byte':flags})
    else: continue
    records.append(item)
s.close()
with open(output,'w',encoding='utf-8') as f:
    json.dump({'run_id':run_id,'records':records},f,sort_keys=True)
    f.write('\n')
print(json.dumps({'run_id':run_id,'record_count':len(records),'records':records},sort_keys=True))
"""


def _utc() -> str:
    return datetime.now(UTC).isoformat()


def _run(command: list[str], *, timeout: float = 12.0) -> str:
    return subprocess.run(
        command, check=True, capture_output=True, text=True, timeout=timeout
    ).stdout.strip()


def _ovs_rows(table: str, columns: list[str]) -> list[dict[str, Any]]:
    raw = _run(
        ["ovs-vsctl", "--format=json", f"--columns={','.join(columns)}", "list", table]
    )
    return parse_ovsdb_table(json.loads(raw))


def _interface_metadata(net: Any, host_name: str, interface_rows: list[dict[str, Any]],
                        port_rows: list[dict[str, Any]]) -> dict[str, Any]:
    host = net.get(host_name)
    host_intf = host.defaultIntf()
    link = host_intf.link
    if link is None:
        raise RuntimeError(f"{host_name} has no active Mininet link")
    if link.intf1.name == host_intf.name:
        switch_intf = link.intf2
    elif link.intf2.name == host_intf.name:
        switch_intf = link.intf1
    else:
        raise RuntimeError(f"could not resolve the switch endpoint for {host_name}")
    interface = next((row for row in interface_rows if row.get("name") == switch_intf.name), None)
    if interface is None:
        raise RuntimeError(f"OVS has no Interface row for {switch_intf.name}")
    owner_port = next(
        (row for row in port_rows if interface.get("_uuid") in row.get("interfaces", [])),
        None,
    )
    if owner_port is None:
        raise RuntimeError(f"OVS has no Port containing interface {switch_intf.name}")
    return {
        "host": host_name,
        "host_interface": host_intf.name,
        "host_mac": host_intf.MAC(),
        "switch_interface": switch_intf.name,
        "switch_port_name": owner_port.get("name"),
        "switch_port_uuid": owner_port.get("_uuid"),
        "switch_interface_uuid": interface.get("_uuid"),
        "switch_interface_mac": interface.get("mac_in_use") or interface.get("mac"),
        "openflow_port": interface.get("ofport"),
    }


def _collect_realized_configuration(net: Any, mirror_name: str) -> dict[str, Any]:
    bridge_rows = _ovs_rows("Bridge", ["_uuid", "name", "ports", "mirrors"])
    port_rows = _ovs_rows("Port", ["_uuid", "name", "interfaces"])
    interface_rows = _ovs_rows(
        "Interface", ["_uuid", "name", "type", "mac", "mac_in_use", "ofport"]
    )
    mirror_rows = _ovs_rows(
        "Mirror",
        [
            "_uuid", "name", "select_all", "select_src_port", "select_dst_port",
            "select_vlan", "filter", "output_port", "output_vlan", "snaplen",
            "statistics", "external_ids",
        ],
    )
    matching_bridges = [row for row in bridge_rows if row.get("name") == "s1"]
    if len(matching_bridges) != 1:
        raise RuntimeError(f"expected one OVS bridge s1; found {len(matching_bridges)}")
    bridge = matching_bridges[0]
    bridge_port_ids = set(bridge.get("ports", []))
    bridge_ports = [row for row in port_rows if row.get("_uuid") in bridge_port_ids]
    bridge_interfaces = [
        row
        for port in bridge_ports
        for row in interface_rows
        if row.get("_uuid") in port.get("interfaces", [])
    ]
    bridge_mirror_ids = set(bridge.get("mirrors", []))
    bridge_mirrors = [row for row in mirror_rows if row.get("_uuid") in bridge_mirror_ids]
    named = [row for row in bridge_mirrors if row.get("name") == mirror_name]
    mirror = named[0] if len(named) == 1 else None
    port_by_uuid = {str(row.get("_uuid")): row for row in bridge_ports}

    def port_names(refs: Any) -> list[str]:
        return sorted(
            str(port_by_uuid[item].get("name"))
            for item in (refs or [])
            if item in port_by_uuid
        )

    realized_mirror = None
    if mirror is not None:
        output_id = mirror.get("output_port")
        realized_mirror = {
            "uuid": mirror.get("_uuid"),
            "name": mirror.get("name"),
            "select_all": mirror.get("select_all"),
            "select_src_port": mirror.get("select_src_port", []),
            "select_src_port_names": port_names(mirror.get("select_src_port")),
            "select_dst_port": mirror.get("select_dst_port", []),
            "select_dst_port_names": port_names(mirror.get("select_dst_port")),
            "select_vlan": mirror.get("select_vlan", []),
            "filter": mirror.get("filter"),
            "output_port": output_id,
            "output_port_name": port_by_uuid.get(str(output_id), {}).get("name"),
            "output_vlan": mirror.get("output_vlan"),
            "snaplen": mirror.get("snaplen"),
            "statistics": mirror.get("statistics"),
            "external_ids": mirror.get("external_ids", {}),
        }

    mapping = {
        host: _interface_metadata(net, host, bridge_interfaces, bridge_ports)
        for host in ("h1", "h2", "h3")
    }
    host_output_link = _run(["ip", "-j", "-d", "link", "show", "dev", OBSERVATION_PORT])
    collector_link = _run(
        ["ip", "-n", COLLECTOR_NAMESPACE, "-j", "-d", "link", "show", "dev", COLLECTOR_PORT]
    )
    collector_addresses = _run(
        ["ip", "-n", COLLECTOR_NAMESPACE, "-j", "address", "show", "dev", COLLECTOR_PORT]
    )
    collector_v4_routes = _run(
        ["ip", "-n", COLLECTOR_NAMESPACE, "-4", "-j", "route", "show", "table", "all"]
    )
    collector_v6_routes = _run(
        ["ip", "-n", COLLECTOR_NAMESPACE, "-6", "-j", "route", "show", "table", "all"]
    )
    host_link = json.loads(host_output_link)[0]
    peer_link = json.loads(collector_link)[0]
    collector_address_rows = json.loads(collector_addresses)
    namespace_path = Path("/var/run/netns") / COLLECTOR_NAMESPACE
    collector = {
        "namespace": COLLECTOR_NAMESPACE,
        "namespace_inode": namespace_path.stat().st_ino,
        "host_interface": OBSERVATION_PORT,
        "host_interface_state": host_link,
        "interface": COLLECTOR_PORT,
        "interface_state": peer_link,
        "interface_ifindex": peer_link.get("ifindex"),
        "interface_mac": peer_link.get("address"),
        "ipv4_addresses": [
            address
            for row in collector_address_rows
            for address in row.get("addr_info", [])
            if address.get("family") == "inet"
        ],
        "ipv6_addresses": [
            address
            for row in collector_address_rows
            for address in row.get("addr_info", [])
            if address.get("family") == "inet6"
        ],
        "ipv4_routes": json.loads(collector_v4_routes),
        "ipv6_routes": json.loads(collector_v6_routes),
    }
    return {
        "bridge": {
            "uuid": bridge.get("_uuid"),
            "name": bridge.get("name"),
            "port_uuids": bridge.get("ports", []),
            "mirrors": bridge.get("mirrors", []),
        },
        "ports": [
            {
                "uuid": row.get("_uuid"),
                "name": row.get("name"),
                "interfaces": row.get("interfaces", []),
            }
            for row in bridge_ports
        ],
        "interfaces": [
            {
                "uuid": row.get("_uuid"),
                "name": row.get("name"),
                "type": row.get("type"),
                "mac": row.get("mac"),
                "mac_in_use": row.get("mac_in_use"),
                "ofport": row.get("ofport"),
            }
            for row in bridge_interfaces
        ],
        "mirrors": [
            {
                "uuid": row.get("_uuid"),
                "name": row.get("name"),
                "select_all": row.get("select_all"),
                "select_src_port": row.get("select_src_port", []),
                "select_dst_port": row.get("select_dst_port", []),
                "select_vlan": row.get("select_vlan", []),
                "filter": row.get("filter"),
                "output_port": row.get("output_port"),
                "output_vlan": row.get("output_vlan"),
                "snaplen": row.get("snaplen"),
                "statistics": row.get("statistics"),
                "external_ids": row.get("external_ids", {}),
            }
            for row in bridge_mirrors
        ],
        "mirror_readable": realized_mirror,
        "host_mapping": mapping,
        "collector": collector,
    }


def _requested_configuration(name: str) -> dict[str, Any]:
    return {
        "bridge_name": "s1",
        "expected_bridge_ports": ["s1", "s1-eth1", "s1-eth2", "s1-eth3", OBSERVATION_PORT],
        "mirror": {
            "name": f"repeat-{name}",
            "select_src_port": "s1-eth2",
            "selected_host": "h2",
            "select_dst_port": [],
            "select_vlan": [],
            "select_all": False,
            "filter": None,
            "output_port": OBSERVATION_PORT,
            "output_vlan": None,
            "snaplen": SNAPLEN,
            "explicitly_set_by_runner": [
                "name", "select_src_port", "output_port", "snaplen"
            ],
            "expected_ovs_schema_defaults_for_omitted_fields": [
                "select_dst_port", "select_vlan", "select_all", "filter", "output_vlan"
            ],
        },
        "collector": {
            "namespace": COLLECTOR_NAMESPACE,
            "interface": COLLECTOR_PORT,
            "host_interface": OBSERVATION_PORT,
        },
    }


def _write_configuration_manifest(
    run_dir: Path, run_id: str, name: str, net: Any
) -> dict[str, Any]:
    requested = _requested_configuration(name)
    realized: dict[str, Any] | None = None
    read_error = None
    try:
        realized = _collect_realized_configuration(net, requested["mirror"]["name"])
    except (
        OSError,
        RuntimeError,
        ValueError,
        KeyError,
        IndexError,
        TypeError,
        subprocess.SubprocessError,
    ) as exc:
        read_error = f"{type(exc).__name__}: {exc}"
    manifest = build_configuration_manifest(
        experiment_id=run_id,
        captured_at=_utc(),
        requested=requested,
        realized=realized,
        read_error=read_error,
    )
    path = run_dir / "configuration-manifest.json"
    path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return manifest


def _ping(host: Any, count: int, label: str) -> dict[str, object]:
    results = []
    for _ in range(count):
        out = host.cmd(f"ping -c 1 -W 1 {H3_IP}")
        results.append("1 received" in out or "1 packets received" in out)
        time.sleep(1)
    return {"label": label, "attempts": count, "replies": sum(results), "success": all(results)}


def _proc_usage(pid: int | None) -> dict[str, float | int] | None:
    if pid is None:
        return None
    try:
        stat = Path(f"/proc/{pid}/stat").read_text().split()
        statm = Path(f"/proc/{pid}/statm").read_text().split()
        ticks = int(stat[13]) + int(stat[14])
        rss_pages = int(statm[1])
        return {
            "cpu_seconds": ticks / os.sysconf("SC_CLK_TCK"),
            "rss_bytes": rss_pages * os.sysconf("SC_PAGE_SIZE"),
        }
    except (FileNotFoundError, IndexError, ValueError):
        return None


def _delta(
    before: dict[str, float | int] | None, after: dict[str, float | int] | None
) -> dict[str, float | int] | None:
    if before is None or after is None:
        return None
    return {key: after[key] - before[key] for key in before}


def _wait_ryu(proc: subprocess.Popen[bytes], log_path: Path) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"Ryu exited early; inspect {log_path}")
        try:
            with socket.create_connection(("127.0.0.1", 6653), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("Ryu did not listen on loopback TCP 6653")


def _preflight(ryu_path: Path, output: Path) -> None:
    if os.geteuid() != 0:
        raise PermissionError("repeatability test requires root in the isolated Mininet host")
    for name in ("mn", "ovs-vsctl", "ovs-ofctl", "ip"):
        if shutil.which(name) is None:
            raise RuntimeError(f"missing executable {name}")
    if not ryu_path.is_file() or not os.access(ryu_path, os.X_OK):
        raise RuntimeError(f"Ryu unavailable: {ryu_path}")
    if subprocess.run(["systemctl", "is-active", "--quiet", "openvswitch"]).returncode:
        raise RuntimeError("OVS service is not active")
    if subprocess.run(["ovs-vsctl", "br-exists", "s1"], check=False).returncode == 0:
        raise RuntimeError("refusing pre-existing s1 bridge")
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")
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


def _make_collector(output: Path, run_id: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            COLLECTOR_NAMESPACE,
            sys.executable,
            "-c",
            COLLECTOR_CODE,
            COLLECTOR_PORT,
            run_id,
            str(output),
            str(SNAPLEN),
            str(MAX_OBSERVATIONS_PER_SECOND),
            str(MAX_OBSERVATIONS_PER_RUN),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _stop_process(proc: subprocess.Popen[str] | None) -> tuple[str, str]:
    if proc is None:
        return "", ""
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
    try:
        return proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        return proc.communicate(timeout=3)


def _ryu_tuple_seen(log_path: Path, source: str) -> bool:
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "stage2_event=" not in line:
            continue
        try:
            event = json.loads(line.split("stage2_event=", 1)[1])
        except json.JSONDecodeError:
            continue
        observation = event.get("observation", {})
        payload = observation.get("payload", {}) if isinstance(observation, dict) else {}
        if (
            isinstance(payload, dict)
            and payload.get("src_ip") == source
            and payload.get("dst_ip") == H3_IP
            and payload.get("dst_port") in PORT_SCAN_ALLOWLIST
        ):
            return True
    return False


def _run_one(name: str, workload: str, root: Path, ryu_path: Path) -> dict[str, object]:
    run_dir = root / name
    run_dir.mkdir()
    run_id = str(uuid.uuid4())
    ryu_log = run_dir / "ryu.log"
    collector_path = run_dir / "collector-metadata.json"
    sender_path = run_dir / "sender-metadata.json"
    journal_path = run_dir / "scenario-journal.jsonl"
    env = os.environ.copy()
    env["SDN_STAGE2_PACKET_EVIDENCE_ENABLED"] = "false"
    env["SDN_STAGE2_INSTALL_TEST_RULE"] = "false"
    env.pop("SDN_TELEMETRY_JSONL", None)
    ryu_stream = ryu_log.open("wb")
    ryu = None
    net = None
    collector = None
    sender = None
    namespace = False
    veth = False
    port_added = False
    mirror = False
    forward_flow = False
    ryu_usage_start = None
    ryu_usage_end = None
    collector_usage_start = None
    collector_usage_end = None
    sender_usage_start = None
    sender_usage_end = None
    summary: dict[str, object] = {
        "schema_version": 1,
        "run_id": run_id,
        "run_name": name,
        "workload": workload,
        "snaplen_bytes": SNAPLEN,
        "mirror_source_port": "s1-eth2 / h2 (constant to avoid mirroring ICMP payload)",
        "observation_limits": {
            "max_per_second": MAX_OBSERVATIONS_PER_SECOND,
            "max_per_run": MAX_OBSERVATIONS_PER_RUN,
        },
        "payload_bytes_persisted": False,
        "pcap_created": False,
    }
    try:
        ryu = subprocess.Popen(
            [str(ryu_path), "networking.ryu.stage2_controller"],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            stdout=ryu_stream,
            stderr=subprocess.STDOUT,
        )
        _wait_ryu(ryu, ryu_log)
        ryu_usage_start = _proc_usage(ryu.pid)
        config = TopologyConfig.from_environment()
        config.validate()
        net = create_network(config)
        time.sleep(0.7)
        h1, h2 = net.get("h1"), net.get("h2")
        ports = _run(["ovs-vsctl", "list-ports", "s1"]).splitlines()
        if not {"s1-eth1", "s1-eth2", "s1-eth3"}.issubset(ports):
            raise RuntimeError(f"unexpected bridge ports: {ports}")
        _run(["ip", "netns", "add", COLLECTOR_NAMESPACE])
        namespace = True
        _run(
            ["ip", "link", "add", OBSERVATION_PORT, "type", "veth", "peer", "name", COLLECTOR_PORT]
        )
        veth = True
        _run(["ip", "link", "set", COLLECTOR_PORT, "netns", COLLECTOR_NAMESPACE])
        _run(["ip", "link", "set", OBSERVATION_PORT, "up"])
        _run(["ip", "-n", COLLECTOR_NAMESPACE, "link", "set", "lo", "up"])
        _run(["ip", "-n", COLLECTOR_NAMESPACE, "link", "set", COLLECTOR_PORT, "up"])
        control_probe = subprocess.run(
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
        if control_probe.returncode:
            raise RuntimeError(f"{name}: collector unexpectedly reached Ryu loopback")
        _run(["ovs-vsctl", "add-port", "s1", OBSERVATION_PORT])
        port_added = True
        _run(
            [
                "ovs-vsctl",
                "--",
                "--id=@src",
                "get",
                "Port",
                "s1-eth2",
                "--",
                "--id=@out",
                "get",
                "Port",
                OBSERVATION_PORT,
                "--",
                "--id=@m",
                "create",
                "Mirror",
                f"name=repeat-{name}",
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
        mirror = True
        configuration_manifest = _write_configuration_manifest(run_dir, run_id, name, net)
        summary["configuration_manifest"] = "configuration-manifest.json"
        preflight = configuration_manifest["preflight"]
        summary["configuration_preflight_passed"] = preflight["passed"]
        if not preflight["passed"]:
            failures = [
                check["name"]
                for check in preflight["checks"]
                if not check["passed"]
            ]
            raise RuntimeError(
                f"{name}: realized configuration preflight failed: {failures}"
            )
        # No scenario/reachability workload is emitted before the requested-versus-
        # realized manifest has passed. This first check precedes collector startup.
        reach_before = _ping(h1, 3, "after_config_before_collector")
        if not reach_before["success"]:
            raise RuntimeError(f"{name}: post-configuration reachability failed")
        if workload == "port_scan":
            flow = (
                "cookie=0x573700000100,priority=200,in_port=2,eth_type=0x0800,"
                f"ipv4_src={H2_IP},ipv4_dst={H3_IP},ip_proto=6,actions=output:3"
            )
            _run(["ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1", flow])
            forward_flow = True
        collector = _make_collector(collector_path, run_id)
        collector_usage_start = _proc_usage(collector.pid)
        time.sleep(0.1)
        reach_active = _ping(h1, 3, "while_observation_active")
        if not reach_active["success"]:
            raise RuntimeError(f"{name}: active-observation reachability failed")
        sender_host = h1 if workload == "benign" else h2
        sender_cmd = [
            sys.executable,
            "-c",
            SENDER_MONITOR_CODE,
            "h1-eth0" if workload == "benign" else "h2-eth0",
            run_id,
            workload,
            str(sender_path),
        ]
        sender = sender_host.popen(
            sender_cmd,
            env={"PYTHONPATH": str(Path(__file__).resolve().parents[1])},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        sender_usage_start = _proc_usage(sender.pid)
        started = _utc()
        journal: list[dict[str, Any]] = []
        journal.append(
            {
                "schema_version": 1,
                "record_type": "scenario_run_start",
                "run_id": run_id,
                "scenario_id": "controlled_connectivity" if workload == "benign" else "port-scan",
                "timestamp_utc": started,
                "source_scope": H1_IP if workload == "benign" else H2_IP,
                "destination_scope": H3_IP,
                "ports": list(PORT_SCAN_ALLOWLIST) if workload == "port_scan" else [],
                "duration_seconds": 8 if workload == "port_scan" else None,
                "rate_per_second": 1 if workload == "port_scan" else None,
            }
        )
        workload_started = time.monotonic()
        generated = 0
        if workload == "benign":
            for index in range(6):
                result = h1.cmd(f"ping -c 1 -W 1 {H3_IP}")
                success = "1 received" in result or "1 packets received" in result
                journal.append(
                    {
                        "schema_version": 1,
                        "record_type": "connectivity_event",
                        "run_id": run_id,
                        "index": index + 1,
                        "success": success,
                        "timestamp_utc": _utc(),
                    }
                )
                if not success:
                    raise RuntimeError(f"{name}: bounded ping {index + 1} failed")
                generated += 1
                time.sleep(1)
        else:
            cmd = [
                sys.executable,
                "-m",
                "networking.mininet.stage3_agents",
                "port-scan",
                "--duration",
                "8",
                "--rate",
                "1",
                "--ports",
                ",".join(str(p) for p in PORT_SCAN_ALLOWLIST),
            ]
            proc = h2.popen(
                cmd,
                env={
                    "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
                    "PYTHONUNBUFFERED": "1",
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                out, _ = proc.communicate(timeout=11)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise RuntimeError(
                    f"{name}: bounded Stage 3 port scan exceeded its time limit"
                ) from None
            if proc.returncode:
                raise RuntimeError(f"{name}: Stage 3 agent exited {proc.returncode}: {out}")
            for line in out.splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event["run_id"] = run_id
                event["record_type"] = "scenario_probe_event"
                journal.append(event)
                if event.get("event_type") == "fixed_tcp_probe":
                    generated += 1
        elapsed = time.monotonic() - workload_started
        ended = _utc()
        journal.append(
            {
                "schema_version": 1,
                "record_type": "scenario_run_end",
                "run_id": run_id,
                "timestamp_utc": ended,
                "generated_event_count": generated,
                "run_duration_seconds": elapsed,
                "status": "complete",
            }
        )
        journal_path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in journal), encoding="utf-8"
        )
        time.sleep(0.4)
        collector_usage_end = _proc_usage(collector.pid)
        sender_usage_end = _proc_usage(sender.pid)
        ryu_usage_end = _proc_usage(ryu.pid if ryu else None)
        sender_out, _ = _stop_process(sender)
        sender = None
        collector_out, _ = _stop_process(collector)
        collector = None
        sender_meta = json.loads(sender_path.read_text(encoding="utf-8"))
        collector_meta = json.loads(collector_path.read_text(encoding="utf-8"))
        observations = collector_meta["observations"]
        if any(
            int(row.get("application_payload_bytes_visible", 0) or 0) > 0 for row in observations
        ):
            summary["payload_exposure_failure"] = True
            raise RuntimeError(
                f"{name}: collector observed application payload bytes; stopping campaign"
            )
        if any(int(row["frame_length_bytes"]) > SNAPLEN for row in observations):
            raise RuntimeError(f"{name}: collector frame exceeded snaplen")
        tcp_rows = [
            row
            for row in observations
            if row.get("ip_protocol") == 6
            and row.get("source_ip") == H2_IP
            and row.get("destination_ip") == H3_IP
        ]
        observed_ports = sorted(
            {
                int(row["destination_port"])
                for row in tcp_rows
                if row.get("destination_port") is not None
            }
        )
        generated_ports = sorted(
            {int(row["port"]) for row in journal if row.get("event_type") == "fixed_tcp_probe"}
        )
        missing = (
            sorted(set(generated_ports) - set(observed_ports)) if workload == "port_scan" else []
        )
        if workload == "port_scan" and missing:
            raise RuntimeError(
                f"{name}: missing destination ports {missing}; stopped without retry"
            )
        expected_sender_count = 6 if workload == "benign" else len(PORT_SCAN_ALLOWLIST)
        if len(sender_meta["records"]) != expected_sender_count:
            raise RuntimeError(
                f"{name}: sender saw {len(sender_meta['records'])}/"
                f"{expected_sender_count} expected workload frames"
            )
        if workload == "port_scan" and generated != 8:
            raise RuntimeError(f"{name}: scenario generated {generated}/8 probes")
        ryu_match = _ryu_tuple_seen(ryu_log, H2_IP)
        if ryu_match:
            raise RuntimeError(f"{name}: a mirrored scan tuple appeared in Ryu PacketIn log")
        summary.update(
            {
                "started_at_utc": started,
                "ended_at_utc": ended,
                "run_duration_seconds": elapsed,
                "scenario_generated_count": generated,
                "sender_observed_workload_count": len(sender_meta["records"]),
                "sender_records": sender_meta["records"],
                "collector_frame_count": len(observations),
                "collector_summary": {
                    key: value for key, value in collector_meta.items() if key != "observations"
                },
                "collector_observations": observations,
                "exact_54_byte_count": sum(row["frame_length_bytes"] == 54 for row in observations),
                "over_54_byte_count": sum(row["frame_length_bytes"] > 54 for row in observations),
                "under_54_byte_count": sum(row["frame_length_bytes"] < 54 for row in observations),
                "collector_frames_seen": collector_meta["frames_seen"],
                "collector_rate_limit_drops": collector_meta["rate_limit_drops"],
                "collector_run_cap_drops": collector_meta["run_cap_drops"],
                "collector_socket_drop_counter_available": collector_meta[
                    "socket_drop_counter_available"
                ],
                "collector_socket_drops_reported": collector_meta["socket_drops_reported"],
                "destination_ports_generated": generated_ports,
                "destination_ports_observed": observed_ports,
                "destination_ports_missing": missing,
                "port_coverage": (
                    len(set(generated_ports) & set(observed_ports)) / len(generated_ports)
                    if generated_ports
                    else None
                ),
                "payload_observations": sum(
                    bool(row.get("application_payload_bytes_visible")) for row in observations
                ),
                "ryu_received_mirrored_tuple": ryu_match,
                "reachability": {
                    "after_configuration_before_collector": reach_before,
                    "while_active": reach_active,
                },
                "scenario_journal": "scenario-journal.jsonl",
                "collector_metadata": "collector-metadata.json",
                "sender_metadata": "sender-metadata.json",
                "ryu_log": "ryu.log",
                "isolation": {
                    "collector_namespace": COLLECTOR_NAMESPACE,
                    "collector_interface": COLLECTOR_PORT,
                    "collector_ipv4_addresses": configuration_manifest["realized"][
                        "collector"
                    ]["ipv4_addresses"],
                    "collector_ipv6_addresses": configuration_manifest["realized"][
                        "collector"
                    ]["ipv6_addresses"],
                    "collector_ipv4_routes": configuration_manifest["realized"][
                        "collector"
                    ]["ipv4_routes"],
                    "collector_ipv6_routes": configuration_manifest["realized"][
                        "collector"
                    ]["ipv6_routes"],
                    "collector_ipv4_route_table_empty": not configuration_manifest[
                        "realized"
                    ]["collector"]["ipv4_routes"],
                    "collector_reached_ryu_loopback": False,
                    "ipv6_isolation_claimed": False,
                },
                "collector_stdout": collector_out.strip(),
                "sender_stdout": sender_out.strip(),
                "resource_usage": {
                    "ryu_start": ryu_usage_start,
                    "ryu_end": ryu_usage_end,
                    "ryu_delta": _delta(ryu_usage_start, ryu_usage_end),
                    "collector_start": collector_usage_start,
                    "collector_end": collector_usage_end,
                    "collector_delta": _delta(collector_usage_start, collector_usage_end),
                    "sender_start": sender_usage_start,
                    "sender_end": sender_usage_end,
                    "sender_delta": _delta(sender_usage_start, sender_usage_end),
                },
                "eventlet_rlock_warning": "1 RLock(s) were not greened"
                in ryu_log.read_text(encoding="utf-8", errors="replace"),
                "ryu_traceback_count": ryu_log.read_text(encoding="utf-8", errors="replace").count(
                    "Traceback"
                ),
            }
        )
    finally:
        if sender is not None:
            _stop_process(sender)
        if collector is not None:
            _stop_process(collector)
        if mirror:
            subprocess.run(["ovs-vsctl", "clear", "Bridge", "s1", "mirrors"], check=False)
        if forward_flow:
            subprocess.run(
                ["ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s1", "cookie=0x573700000100/-1"],
                check=False,
            )
        if port_added:
            subprocess.run(
                ["ovs-vsctl", "--if-exists", "del-port", "s1", OBSERVATION_PORT], check=False
            )
        if net is not None:
            try:
                reach_after = _ping(net.get("h1"), 3, "after_cleanup")
                reach = summary.get("reachability")
                if isinstance(reach, dict):
                    reach["after_cleanup"] = reach_after
            except Exception as exc:
                summary["post_cleanup_reachability_error"] = type(exc).__name__
            net.stop()
        if namespace:
            subprocess.run(["ip", "netns", "del", COLLECTOR_NAMESPACE], check=False)
        if veth:
            subprocess.run(["ip", "link", "del", OBSERVATION_PORT], check=False)
        if ryu is not None and ryu.poll() is None:
            ryu.send_signal(signal.SIGINT)
            try:
                ryu.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ryu.terminate()
                ryu.wait(timeout=3)
        ryu_stream.close()
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
            "mirror_configuration_absent": not _mirror_exists(f"repeat-{name}"),
        }
        (run_dir / "run-summary.json").write_text(
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


def _mirror_exists(name: str) -> bool:
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
        headings and "name" in headings and any(row[headings.index("name")] == name for row in rows)
    )


def run(output: Path, ryu_path: Path) -> dict[str, object]:
    output = output.resolve()
    _preflight(ryu_path, output)
    output.mkdir(parents=True)
    runs = []
    plan = [
        ("B1", "benign"),
        ("B2", "benign"),
        ("B3", "benign"),
        ("S1", "port_scan"),
        ("S2", "port_scan"),
        ("S3", "port_scan"),
    ]
    for name, workload in plan:
        result = _run_one(name, workload, output, ryu_path)
        runs.append(result)
        cleanup = result.get("cleanup")
        if not isinstance(cleanup, dict) or not all(bool(value) for value in cleanup.values()):
            raise RuntimeError(f"{name}: cleanup verification failed; stopping campaign")
        if result.get("payload_observations", 0):
            raise RuntimeError(f"{name}: payload exposure; stopping campaign")
    summary = {
        "schema_version": 1,
        "experiment": "three benign and three bounded port-scan mirror snaplen=54 runs",
        "snaplen_bytes": SNAPLEN,
        "run_names": [name for name, _ in plan],
        "runs": runs,
        "completed_at_utc": _utc(),
        "raw_packet_bytes_or_payload_persisted": False,
        "pcap_created": False,
        "detector_or_policy_or_mitigation_invoked": False,
    }
    (output / "campaign-summary.json").write_text(
        json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("experiments/stage7-telemetry/packet-observation-repeatability-2026-10-09"),
    )
    parser.add_argument("--ryu-manager", type=Path, default=Path(".venv-ryu/bin/ryu-manager"))
    args = parser.parse_args()
    print(json.dumps(run(args.output_dir, args.ryu_manager), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
