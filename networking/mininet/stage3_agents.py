"""Bounded packet senders and local fixtures run inside Mininet host namespaces."""

from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import math
import signal
import socket
import struct
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from networking.mininet.stage3_config import (
    DHCP_CLIENT_MACS,
    DHCP_POOL,
    DNS_TEST_NAMES,
    SCENARIO_BOUNDS,
    Scenario,
    validate_scenario_parameters,
)
from networking.mininet.stage3_packets import (
    arp_reply_frame,
    arp_request_frame,
    dhcp_bootp_message,
    dns_query,
    dns_question_name,
    ipv4_tcp_syn_frame,
    parse_dhcp_message,
)

H1_IP = "10.0.0.1"
H2_IP = "10.0.0.2"
H3_IP = "10.0.0.3"
H1_MAC = "02:00:00:00:00:01"
H2_MAC = "02:00:00:00:00:02"
H3_MAC = "02:00:00:00:00:03"
_STOP_REQUESTED = False


def request_stop(_signal_number: int, _frame: Any) -> None:
    """Allow fixture termination to close sockets and reset in-memory state."""

    global _STOP_REQUESTED
    _STOP_REQUESTED = True


def emit(event_type: str, **fields: Any) -> None:
    """Write one parseable timestamped local scenario event."""

    print(
        json.dumps(
            {"timestamp": datetime.now(UTC).isoformat(), "event_type": event_type, **fields},
            sort_keys=True,
        ),
        flush=True,
    )


def event_count(duration: float, rate: float, maximum: int) -> int:
    """Cap packet count so the final scheduled event remains inside duration."""

    return min(maximum, max(1, math.ceil(duration * rate)))


def pace(
    started: float,
    index: int,
    rate: float,
    duration: float,
    previous_event: float | None = None,
) -> float:
    """Wait for both the configured schedule and minimum inter-event interval."""

    deadline = started + index / rate
    if previous_event is not None:
        deadline = max(deadline, previous_event + 1 / rate)
    deadline = min(deadline, started + duration)
    delay = deadline - time.monotonic()
    if delay > 0:
        time.sleep(delay)
    if time.monotonic() > started + duration + 0.01:
        raise TimeoutError("scenario duration bound elapsed")
    return time.monotonic()


def raw_sender(interface: str) -> socket.socket:
    """Open a packet socket bound to the named Mininet interface only."""

    _verify_lab_interface(interface, "h2", H2_IP, H2_MAC)
    sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sender.bind((interface, 0))
    return sender


def _verify_lab_interface(interface: str, host: str, address: str, mac: str) -> None:
    """Require the exact expected address and MAC on a Mininet namespace interface."""

    expected_interface = f"{host}-eth0"
    if interface != expected_interface:
        raise ValueError(f"scenario requires the fixed Mininet interface {expected_interface}")
    try:
        socket.if_nametoindex(interface)
        actual_mac = Path(f"/sys/class/net/{interface}/address").read_text().strip().lower()
        request = struct.pack("256s", interface.encode("ascii")[:15])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as inspector:
            response = fcntl.ioctl(inspector.fileno(), 0x8915, request)
        actual_ip = str(ipaddress.IPv4Address(response[20:24]))
    except OSError as error:
        raise RuntimeError(f"required Mininet interface {interface} is unavailable") from error
    if actual_mac != mac.lower() or actual_ip != address:
        raise RuntimeError(
            f"{interface} identity mismatch: expected {address}/{mac}, got {actual_ip}/{actual_mac}"
        )


def send_arp_spoof(interface: str, duration: float, rate: float) -> None:
    """Send bounded h2 claims for h3's fixed IP directly to h1's fixed MAC."""

    duration, rate, _ = validate_scenario_parameters(Scenario.ARP_SPOOF, duration, rate)
    count = event_count(duration, rate, SCENARIO_BOUNDS[Scenario.ARP_SPOOF].maximum_events)
    frame = arp_reply_frame(H2_MAC, H3_IP, H1_MAC, H1_IP)
    sender = raw_sender(interface)
    started = time.monotonic()
    previous_event = None
    try:
        for index in range(count):
            previous_event = pace(started, index, rate, duration, previous_event)
            sender.send(frame)
            emit(
                "arp_claim_sent",
                source_host="h2",
                target_host="h1",
                claimed_ip=H3_IP,
                count=index + 1,
            )
    finally:
        sender.close()


def send_syns(interface: str, duration: float, rate: float) -> None:
    """Send bare bounded SYN frames from h2 to the one fixed h3 TCP port."""

    duration, rate, _ = validate_scenario_parameters(Scenario.SYN_FLOOD, duration, rate)
    count = event_count(duration, rate, SCENARIO_BOUNDS[Scenario.SYN_FLOOD].maximum_events)
    sender = raw_sender(interface)
    started = time.monotonic()
    previous_event = None
    try:
        for index in range(count):
            previous_event = pace(started, index, rate, duration, previous_event)
            packet = ipv4_tcp_syn_frame(
                H2_MAC,
                H3_MAC,
                H2_IP,
                H3_IP,
                40_000 + index,
                18_080,
                0x5D300000 + index,
            )
            sender.send(packet)
            emit(
                "syn_sent", source_host="h2", target_host="h3", target_port=18_080, count=index + 1
            )
    finally:
        sender.close()


def send_rogue_discovery(interface: str, duration: float, rate: float) -> None:
    """Send bounded ARP requests from the existing h2 interface after link-up."""

    duration, rate, _ = validate_scenario_parameters(Scenario.ROGUE_DEVICE, duration, rate)
    count = event_count(duration, rate, SCENARIO_BOUNDS[Scenario.ROGUE_DEVICE].maximum_events)
    frame = arp_request_frame(H2_MAC, H2_IP, H3_IP)
    sender = raw_sender(interface)
    started = time.monotonic()
    previous_event = None
    try:
        for index in range(count):
            previous_event = pace(started, index, rate, duration, previous_event)
            sender.send(frame)
            emit("rogue_device_discovery_sent", host="h2", switch="s1", count=index + 1)
    finally:
        sender.close()


def port_scan(duration: float, rate: float, ports: tuple[int, ...]) -> None:
    """Probe only the fixed allowlist of h3 TCP ports sequentially."""

    duration, rate, checked_ports = validate_scenario_parameters(
        Scenario.PORT_SCAN, duration, rate, ports
    )
    _verify_lab_interface("h2-eth0", "h2", H2_IP, H2_MAC)
    count = min(len(checked_ports), event_count(duration, rate, 8))
    started = time.monotonic()
    previous_event = None
    for index, port in enumerate(checked_ports[:count]):
        previous_event = pace(started, index, rate, duration, previous_event)
        result: str
        try:
            with socket.create_connection(
                (H3_IP, port),
                timeout=min(0.25, 1 / rate),
                source_address=(H2_IP, 0),
            ):
                result = "open"
        except ConnectionRefusedError:
            result = "closed"
        except TimeoutError:
            result = "timeout"
        emit("fixed_tcp_probe", target_host="h3", port=port, result=result, count=index + 1)


def dhcp_server(duration: float) -> None:
    """Serve a four-address, in-memory DHCP fixture bound only to h3's Mininet IP."""

    if duration <= 0 or duration > 4:
        raise ValueError("DHCP fixture duration must be at most 4 seconds")
    _verify_lab_interface("h3-eth0", "h3", H3_IP, H3_MAC)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((H3_IP, 67))
    sock.settimeout(0.1)
    signal.signal(signal.SIGTERM, request_stop)
    global _STOP_REQUESTED
    _STOP_REQUESTED = False
    offers: dict[str, str] = {}
    leases: dict[str, str] = {}
    emit("dhcp_fixture_ready", bind_address=H3_IP, pool=list(DHCP_POOL))
    deadline = time.monotonic() + duration
    try:
        while time.monotonic() < deadline and not _STOP_REQUESTED:
            try:
                payload, peer = sock.recvfrom(1500)
            except TimeoutError:
                continue
            parsed = parse_dhcp_message(payload)
            if parsed is None:
                continue
            message_type, xid, client_mac, requested_ip = parsed
            if client_mac not in DHCP_CLIENT_MACS or peer[0] != H2_IP or peer[1] != 68:
                emit("dhcp_fixture_rejected", peer=peer[0], client_mac=client_mac)
                continue
            if message_type == 1 and client_mac not in offers:
                allocated = next(
                    (address for address in DHCP_POOL if address not in offers.values()), None
                )
                if allocated is None:
                    emit("dhcp_pool_full", client_mac=client_mac)
                    continue
                offers[client_mac] = allocated
                response_type = 2
                address = allocated
            elif message_type == 3 and offers.get(client_mac) == requested_ip:
                leases[client_mac] = requested_ip or ""
                response_type = 5
                address = requested_ip or "0.0.0.0"
            else:
                emit("dhcp_request_ignored", message_type=message_type, client_mac=client_mac)
                continue
            response = dhcp_bootp_message(
                message_type=response_type,
                xid=xid,
                client_mac=client_mac,
                server_ip=H3_IP,
                offered_ip=address,
            )
            sock.sendto(response, peer)
            emit(
                "dhcp_fixture_response",
                message_type="offer" if response_type == 2 else "ack",
                client_mac=client_mac,
                address=address,
                leases=len(leases),
            )
    finally:
        sock.close()
        emit("dhcp_fixture_stopped", leases=len(leases), pool_reset=True)


def dhcp_clients(duration: float, rate: float, count: int) -> None:
    """Use only four declared BOOTP client identities against local h3 fixture."""

    maximum = SCENARIO_BOUNDS[Scenario.DHCP_STARVATION].maximum_events
    if (
        count < 1
        or count > maximum
        or count > event_count(duration, rate, maximum)
        or duration > 4
        or rate > 1
        or duration <= 0
        or rate <= 0
    ):
        raise ValueError(
            "DHCP clients are limited to four identities, one/second, and four seconds"
        )
    _verify_lab_interface("h2-eth0", "h2", H2_IP, H2_MAC)
    started = time.monotonic()
    previous_event = None
    for index, client_mac in enumerate(DHCP_CLIENT_MACS[:count]):
        previous_event = pace(started, index, rate, duration, previous_event)
        xid = 0xD4000000 + index
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client.bind((H2_IP, 68))
            client.settimeout(0.25)
            discover = dhcp_bootp_message(
                message_type=1,
                xid=xid,
                client_mac=client_mac,
            )
            client.sendto(discover, (H3_IP, 67))
            try:
                offer, _ = client.recvfrom(1500)
            except TimeoutError:
                emit("dhcp_offer_missing", client_mac=client_mac)
                continue
            parsed = parse_dhcp_message(offer)
            if parsed is None or parsed[0] != 2:
                raise RuntimeError("DHCP fixture returned an invalid offer")
            offered_ip = str(ipaddress.ip_address(offer[16:20]))
            request = dhcp_bootp_message(
                message_type=3,
                xid=xid,
                client_mac=client_mac,
                requested_ip=offered_ip,
                server_ip=H3_IP,
            )
            client.sendto(request, (H3_IP, 67))
            try:
                ack, _ = client.recvfrom(1500)
            except TimeoutError:
                emit("dhcp_ack_missing", client_mac=client_mac)
                continue
            ack_parsed = parse_dhcp_message(ack)
            if ack_parsed is None or ack_parsed[0] != 5:
                raise RuntimeError("DHCP fixture returned an invalid acknowledgement")
            emit(
                "dhcp_client_acknowledged",
                client_mac=client_mac,
                address=offered_ip,
                count=index + 1,
            )


def dns_fixture(duration: float) -> None:
    """Answer only fixed .test names on h3; never recurse or forward requests."""

    if duration <= 0 or duration > 10:
        raise ValueError("DNS fixture duration must be at most 10 seconds")
    _verify_lab_interface("h3-eth0", "h3", H3_IP, H3_MAC)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((H3_IP, 53))
    sock.settimeout(0.1)
    signal.signal(signal.SIGTERM, request_stop)
    global _STOP_REQUESTED
    _STOP_REQUESTED = False
    emit("dns_fixture_ready", bind_address=H3_IP, recursion=False)
    deadline = time.monotonic() + duration
    try:
        while time.monotonic() < deadline and not _STOP_REQUESTED:
            try:
                query, peer = sock.recvfrom(1500)
            except TimeoutError:
                continue
            name = dns_question_name(query)
            if name not in DNS_TEST_NAMES or peer[0] != H2_IP:
                emit("dns_fixture_rejected", peer=peer[0], name=name)
                continue
            transaction_id, request_flags = struct.unpack_from("!HH", query)
            response_flags = 0x8000 | (request_flags & 0x0100) | 0x0003
            response = (
                struct.pack("!HHHHHH", transaction_id, response_flags, 1, 0, 0, 0) + query[12:]
            )
            sock.sendto(response, peer)
            emit("dns_fixture_answer", name=name, peer=peer[0], recursion=False)
    finally:
        sock.close()
        emit("dns_fixture_stopped", upstream_forwarding=False)


def dns_clients(duration: float, rate: float, count: int) -> None:
    """Send a fixed list of at most ten valid queries under the reserved .test zone."""

    if (
        count < 1
        or count > 10
        or count > event_count(duration, rate, 10)
        or duration > 10
        or rate > 1
        or duration <= 0
        or rate <= 0
    ):
        raise ValueError("DNS queries are limited to ten names, one/second, and ten seconds")
    _verify_lab_interface("h2-eth0", "h2", H2_IP, H2_MAC)
    started = time.monotonic()
    previous_event = None
    for index, name in enumerate(DNS_TEST_NAMES[:count]):
        previous_event = pace(started, index, rate, duration, previous_event)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(0.5)
            client.bind((H2_IP, 0))
            query = dns_query(name, 0xD500 + index)
            client.sendto(query, (H3_IP, 53))
            try:
                response, _ = client.recvfrom(1500)
            except TimeoutError:
                emit("dns_response_missing", name=name)
                continue
            response_id, flags = struct.unpack_from("!HH", response)
            if response_id != 0xD500 + index or not flags & 0x8000:
                raise RuntimeError("DNS fixture returned an invalid response")
            emit("dns_query_sent", target_host="h3", name=name, rcode=flags & 0xF, count=index + 1)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    for action in ("arp-spoof", "syn-flood", "rogue-device"):
        command = subparsers.add_parser(action)
        command.add_argument("--interface", required=True)
        command.add_argument("--duration", type=float, required=True)
        command.add_argument("--rate", type=float, required=True)
    scan = subparsers.add_parser("port-scan")
    scan.add_argument("--duration", type=float, required=True)
    scan.add_argument("--rate", type=float, required=True)
    scan.add_argument(
        "--ports", type=lambda value: tuple(int(part) for part in value.split(",")), required=True
    )
    dhcp_server_parser = subparsers.add_parser("dhcp-fixture")
    dhcp_server_parser.add_argument("--duration", type=float, required=True)
    dhcp_client_parser = subparsers.add_parser("dhcp-clients")
    dhcp_client_parser.add_argument("--duration", type=float, required=True)
    dhcp_client_parser.add_argument("--rate", type=float, required=True)
    dhcp_client_parser.add_argument("--count", type=int, required=True)
    dns_server_parser = subparsers.add_parser("dns-fixture")
    dns_server_parser.add_argument("--duration", type=float, required=True)
    dns_client_parser = subparsers.add_parser("dns-clients")
    dns_client_parser.add_argument("--duration", type=float, required=True)
    dns_client_parser.add_argument("--rate", type=float, required=True)
    dns_client_parser.add_argument("--count", type=int, required=True)
    return parser


def main() -> None:
    """Dispatch one sender or local service fixture inside a Mininet host."""

    arguments = _parser().parse_args()
    action = arguments.action
    if action == "arp-spoof":
        send_arp_spoof(arguments.interface, arguments.duration, arguments.rate)
    elif action == "syn-flood":
        send_syns(arguments.interface, arguments.duration, arguments.rate)
    elif action == "rogue-device":
        send_rogue_discovery(arguments.interface, arguments.duration, arguments.rate)
    elif action == "port-scan":
        port_scan(arguments.duration, arguments.rate, arguments.ports)
    elif action == "dhcp-fixture":
        dhcp_server(arguments.duration)
    elif action == "dhcp-clients":
        dhcp_clients(arguments.duration, arguments.rate, arguments.count)
    elif action == "dns-fixture":
        dns_fixture(arguments.duration)
    elif action == "dns-clients":
        dns_clients(arguments.duration, arguments.rate, arguments.count)


if __name__ == "__main__":
    try:
        main()
    except (OSError, TimeoutError, ValueError, RuntimeError) as error:
        emit("scenario_agent_failed", error=str(error))
        raise SystemExit(1) from error
