"""Small standard-library packet builders used only inside Mininet namespaces."""

from __future__ import annotations

import ipaddress
import struct

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
IP_UDP = 17
IP_TCP = 6


def mac_bytes(value: str) -> bytes:
    """Encode a conventional colon-separated MAC address."""

    octets = value.split(":")
    if len(octets) != 6:
        raise ValueError("MAC address must contain six octets")
    try:
        encoded = bytes(int(octet, 16) for octet in octets)
    except ValueError as error:
        raise ValueError("MAC address contains a non-hexadecimal octet") from error
    if any(not 0 <= int(octet, 16) <= 255 for octet in octets):
        raise ValueError("MAC address octets must be between 00 and ff")
    return encoded


def internet_checksum(data: bytes) -> int:
    """Compute the standard 16-bit one's-complement Internet checksum."""

    if len(data) % 2:
        data += b"\x00"
    total = sum(int(word) for word in struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet_frame(destination: str, source: str, ethertype: int, payload: bytes) -> bytes:
    """Build an Ethernet II frame."""

    return mac_bytes(destination) + mac_bytes(source) + struct.pack("!H", ethertype) + payload


def arp_reply_frame(
    source_mac: str,
    claimed_ip: str,
    target_mac: str,
    target_ip: str,
) -> bytes:
    """Build one explicit unicast ARP reply frame for the fixed local lab."""

    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        ETH_IPV4,
        6,
        4,
        2,
        mac_bytes(source_mac),
        ipaddress.IPv4Address(claimed_ip).packed,
        mac_bytes(target_mac),
        ipaddress.IPv4Address(target_ip).packed,
    )
    return ethernet_frame(target_mac, source_mac, ETH_ARP, arp)


def arp_request_frame(source_mac: str, source_ip: str, target_ip: str) -> bytes:
    """Build one broadcast ARP request for the fixed local rogue-device scenario."""

    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        ETH_IPV4,
        6,
        4,
        1,
        mac_bytes(source_mac),
        ipaddress.IPv4Address(source_ip).packed,
        b"\x00" * 6,
        ipaddress.IPv4Address(target_ip).packed,
    )
    return ethernet_frame("ff:ff:ff:ff:ff:ff", source_mac, ETH_ARP, arp)


def ipv4_udp_frame(
    source_mac: str,
    destination_mac: str,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    payload: bytes,
    identification: int = 1,
) -> bytes:
    """Build a checksummed IPv4/UDP Ethernet frame."""

    source = ipaddress.IPv4Address(source_ip).packed
    destination = ipaddress.IPv4Address(destination_ip).packed
    udp_length = 8 + len(payload)
    udp_zero_checksum = struct.pack("!HHHH", source_port, destination_port, udp_length, 0)
    pseudo = source + destination + struct.pack("!BBH", 0, IP_UDP, udp_length)
    udp_checksum = internet_checksum(pseudo + udp_zero_checksum + payload) or 0xFFFF
    udp = struct.pack("!HHHH", source_port, destination_port, udp_length, udp_checksum) + payload
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        identification & 0xFFFF,
        0,
        64,
        IP_UDP,
        0,
        source,
        destination,
    )
    checksum = internet_checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return ethernet_frame(destination_mac, source_mac, ETH_IPV4, header + udp)


def ipv4_tcp_syn_frame(
    source_mac: str,
    destination_mac: str,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    sequence: int,
) -> bytes:
    """Build a single bare TCP SYN frame without a socket handshake or payload."""

    source = ipaddress.IPv4Address(source_ip).packed
    destination = ipaddress.IPv4Address(destination_ip).packed
    tcp_without_checksum = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence & 0xFFFFFFFF,
        0,
        5 << 4,
        0x02,
        64240,
        0,
        0,
    )
    pseudo = source + destination + struct.pack("!BBH", 0, IP_TCP, len(tcp_without_checksum))
    tcp_checksum = internet_checksum(pseudo + tcp_without_checksum)
    tcp = tcp_without_checksum[:16] + struct.pack("!H", tcp_checksum) + tcp_without_checksum[18:]
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        sequence & 0xFFFF,
        0,
        64,
        IP_TCP,
        0,
        source,
        destination,
    )
    header = header[:10] + struct.pack("!H", internet_checksum(header)) + header[12:]
    return ethernet_frame(destination_mac, source_mac, ETH_IPV4, header + tcp)


def dhcp_options(message_type: int, extra: bytes = b"") -> bytes:
    """Encode minimal DHCP options ending with the mandatory end marker."""

    if not 1 <= message_type <= 8:
        raise ValueError("DHCP message type must be between 1 and 8")
    return b"\x35\x01" + bytes([message_type]) + extra + b"\xff"


def dhcp_bootp_message(
    *,
    message_type: int,
    xid: int,
    client_mac: str,
    requested_ip: str | None = None,
    server_ip: str | None = None,
    offered_ip: str = "0.0.0.0",
) -> bytes:
    """Encode one minimal BOOTP/DHCP client or server payload."""

    mac = mac_bytes(client_mac)
    is_client = message_type in {1, 3}
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1 if is_client else 2,
        1,
        6,
        0,
        xid & 0xFFFFFFFF,
        0,
        0x8000,
        b"\x00" * 4,
        ipaddress.IPv4Address(offered_ip).packed,
        ipaddress.IPv4Address(server_ip or "0.0.0.0").packed,
        b"\x00" * 4,
        mac + b"\x00" * 10,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    options = b"\x63\x82\x53\x63"
    extra = b""
    if requested_ip is not None:
        extra += b"\x32\x04" + ipaddress.IPv4Address(requested_ip).packed
    if server_ip is not None and is_client:
        extra += b"\x36\x04" + ipaddress.IPv4Address(server_ip).packed
    if not is_client:
        extra += b"\x33\x04\x00\x00\x0e\x10"
        extra += b"\x01\x04\xff\xff\xff\x00"
    return bootp + options + dhcp_options(message_type, extra)


def parse_dhcp_message(payload: bytes) -> tuple[int, int, str, str | None] | None:
    """Return DHCP type, xid, client MAC, and requested IP from a BOOTP payload."""

    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    xid = struct.unpack_from("!I", payload, 4)[0]
    client_mac = ":".join(f"{octet:02x}" for octet in payload[28:34])
    options = payload[240:]
    message_type: int | None = None
    requested_ip: str | None = None
    offset = 0
    while offset < len(options):
        option = options[offset]
        offset += 1
        if option == 255:
            break
        if option == 0:
            continue
        if offset >= len(options):
            return None
        length = options[offset]
        offset += 1
        value = options[offset : offset + length]
        if len(value) != length:
            return None
        offset += length
        if option == 53 and length == 1:
            message_type = value[0]
        elif option == 50 and length == 4:
            requested_ip = str(ipaddress.IPv4Address(value))
    if message_type is None:
        return None
    return message_type, xid, client_mac, requested_ip


def dns_query(name: str, transaction_id: int) -> bytes:
    """Encode one uncompressed IN/A query restricted to the reserved .test zone."""

    normalized = name.rstrip(".").lower()
    if not normalized.endswith(".test"):
        raise ValueError("DNS test names must be under the reserved .test domain")
    labels = normalized.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise ValueError("DNS labels must contain between 1 and 63 characters")
    encoded_name = (
        b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    )
    return (
        struct.pack("!HHHHHH", transaction_id & 0xFFFF, 0x0100, 1, 0, 0, 0)
        + encoded_name
        + struct.pack("!HH", 1, 1)
    )


def dns_question_name(message: bytes) -> str | None:
    """Read the first DNS question name, rejecting compressed or malformed input."""

    if len(message) < 17:
        return None
    offset = 12
    labels: list[str] = []
    while offset < len(message):
        size = message[offset]
        offset += 1
        if size == 0:
            break
        if size & 0xC0 or size > 63 or offset + size > len(message):
            return None
        try:
            labels.append(message[offset : offset + size].decode("ascii").lower())
        except UnicodeDecodeError:
            return None
        offset += size
    if not labels or offset + 4 > len(message):
        return None
    return ".".join(labels)
