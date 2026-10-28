"""Technology-neutral flow records and deterministic observation extraction."""

from __future__ import annotations

import ast
import hashlib
import ipaddress
import json
import math
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "record_id",
        "observed_at",
        "observation_source",
        "datapath_id",
        "table_id",
        "priority",
        "cookie",
        "duration_seconds",
        "packet_count",
        "byte_count",
        "eth_type",
        "ip_protocol",
        "protocol",
        "src_ip",
        "dst_ip",
        "src_mac",
        "dst_mac",
        "src_port",
        "dst_port",
        "in_port",
        "tcp_flags",
        "is_empty",
        "match_raw",
    }
)
_MATCH_KEYS = {
    "eth_type",
    "ip_proto",
    "ipv4_src",
    "ipv4_dst",
    "ipv6_src",
    "ipv6_dst",
    "eth_src",
    "eth_dst",
    "tcp_src",
    "tcp_dst",
    "udp_src",
    "udp_dst",
    "in_port",
    "tcp_flags",
}
_MATCH_TEXT = re.compile(r"oxm_fields=(\{.*\})")
_PROTOCOL_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}


@dataclass(frozen=True, slots=True)
class FlowRecord:
    """One controller flow-stat snapshot; values remain in source units."""

    schema_version: int
    record_id: str
    observed_at: str | None
    observation_source: str
    datapath_id: str | None
    table_id: int | None
    priority: int | None
    cookie: str | None
    duration_seconds: float | None
    packet_count: int | None
    byte_count: int | None
    eth_type: int | None
    ip_protocol: int | None
    protocol: str | None
    src_ip: str | None
    dst_ip: str | None
    src_mac: str | None
    dst_mac: str | None
    src_port: int | None
    dst_port: int | None
    in_port: int | None
    tcp_flags: int | None
    is_empty: bool | None
    match_raw: str | None

    def to_dict(self) -> dict[str, Any]:
        """Return the fixed-schema JSON-compatible representation."""

        return asdict(self)


class FlowRecordError(ValueError):
    """Raised when an observation cannot be represented without ambiguity."""


def extract_flow_record(observation: Mapping[str, object]) -> FlowRecord:
    """Convert one Ryu flow-stat observation into a validated immutable record.

    The function does no fitting, scaling, imputation, labeling, or data-dependent
    selection. Missing source fields remain ``None``.
    """

    event_type = observation.get("event_type")
    if event_type not in (None, "flow_statistics"):
        raise FlowRecordError("observation event_type must be flow_statistics")

    match_value = observation.get("match")
    match_fields = _parse_match(match_value)
    observed_at = _parse_timestamp(observation.get("timestamp"))
    packet_count = _optional_int(observation.get("packet_count"), "packet_count")
    byte_count = _optional_int(observation.get("byte_count"), "byte_count")
    ip_protocol = _optional_range(
        _first(observation, match_fields, "ip_protocol", "ip_proto"), "ip_protocol", 0, 255
    )
    protocol = _protocol_name(ip_protocol)
    explicit_protocol = observation.get("protocol")
    if explicit_protocol is not None:
        if not isinstance(explicit_protocol, str) or not explicit_protocol:
            raise FlowRecordError("protocol must be a non-empty string when provided")
        canonical = explicit_protocol.lower()
        if protocol is not None and canonical != protocol:
            raise FlowRecordError("protocol conflicts with ip_protocol")
        protocol = canonical

    raw_fields: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "observed_at": observed_at,
        "observation_source": "ryu_flow_statistics",
        "datapath_id": _optional_text(observation.get("datapath_id"), "datapath_id"),
        "table_id": _optional_range(observation.get("table_id"), "table_id", 0, 255),
        "priority": _optional_range(observation.get("priority"), "priority", 0, 65535),
        "cookie": _cookie(observation.get("cookie")),
        "duration_seconds": _duration(observation.get("duration_seconds")),
        "packet_count": packet_count,
        "byte_count": byte_count,
        "eth_type": _optional_range(
            _first(observation, match_fields, "eth_type"), "eth_type", 0, 65535
        ),
        "ip_protocol": ip_protocol,
        "protocol": protocol,
        "src_ip": _ip_address(
            _first(observation, match_fields, "src_ip", "ipv4_src", "ipv6_src"), "src_ip"
        ),
        "dst_ip": _ip_address(
            _first(observation, match_fields, "dst_ip", "ipv4_dst", "ipv6_dst"), "dst_ip"
        ),
        "src_mac": _optional_text(
            _first(observation, match_fields, "src_mac", "eth_src"), "src_mac"
        ),
        "dst_mac": _optional_text(
            _first(observation, match_fields, "dst_mac", "eth_dst"), "dst_mac"
        ),
        "src_port": _optional_range(
            _first(observation, match_fields, "src_port", "tcp_src", "udp_src"),
            "src_port",
            0,
            65535,
        ),
        "dst_port": _optional_range(
            _first(observation, match_fields, "dst_port", "tcp_dst", "udp_dst"),
            "dst_port",
            0,
            65535,
        ),
        "in_port": _optional_range(
            _first(observation, match_fields, "in_port"), "in_port", 0, 2**32 - 1
        ),
        "tcp_flags": _optional_range(
            _first(observation, match_fields, "tcp_flags"), "tcp_flags", 0, 65535
        ),
        "is_empty": packet_count == 0 and byte_count == 0
        if packet_count is not None and byte_count is not None
        else None,
        "match_raw": match_value if isinstance(match_value, str) else None,
    }
    return _make_record(raw_fields)


def deduplicate_records(records: list[FlowRecord]) -> list[FlowRecord]:
    """Remove exact duplicate snapshots by deterministic record ID, preserving order."""

    seen: set[str] = set()
    unique: list[FlowRecord] = []
    for record in records:
        if record.record_id not in seen:
            seen.add(record.record_id)
            unique.append(record)
    return unique


def write_jsonl(records: list[FlowRecord], path: str | Path) -> None:
    """Write UTF-8 JSON Lines with stable key ordering and one final newline."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(
                json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False)
            )
            stream.write("\n")


def read_jsonl(path: str | Path, *, deduplicate: bool = False) -> list[FlowRecord]:
    """Load and validate JSONL records; optionally discard exact duplicates."""

    records: list[FlowRecord] = []
    with Path(path).open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    raise FlowRecordError("JSONL row must be an object")
                records.append(_record_from_dict(payload))
            except (json.JSONDecodeError, FlowRecordError, TypeError) as exc:
                raise FlowRecordError(f"invalid JSONL record on line {line_number}: {exc}") from exc
    return deduplicate_records(records) if deduplicate else records


def extract_ryu_log(path: str | Path) -> list[FlowRecord]:
    """Read ``stage2_event=<json>`` lines and extract flow-stat events only."""

    records: list[FlowRecord] = []
    with Path(path).open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            marker = "stage2_event="
            if marker not in line:
                continue
            payload_text = line.split(marker, 1)[1].strip()
            try:
                payload = json.loads(payload_text)
                if payload.get("event_type") == "flow_statistics":
                    records.append(extract_flow_record(payload))
            except (json.JSONDecodeError, FlowRecordError, AttributeError) as exc:
                raise FlowRecordError(f"invalid Ryu event on line {line_number}: {exc}") from exc
    return records


def _record_from_dict(payload: dict[str, Any]) -> FlowRecord:
    if set(payload) != _RECORD_FIELDS:
        raise FlowRecordError("record fields do not match schema version 1")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise FlowRecordError("unsupported schema_version")
    source = payload.get("observation_source")
    if source != "ryu_flow_statistics":
        raise FlowRecordError("unsupported observation_source")
    observation = {
        "event_type": "flow_statistics",
        "timestamp": payload["observed_at"],
        "datapath_id": payload["datapath_id"],
        "table_id": payload["table_id"],
        "priority": payload["priority"],
        "cookie": payload["cookie"],
        "duration_seconds": payload["duration_seconds"],
        "packet_count": payload["packet_count"],
        "byte_count": payload["byte_count"],
        "eth_type": payload["eth_type"],
        "ip_protocol": payload["ip_protocol"],
        "protocol": payload["protocol"],
        "src_ip": payload["src_ip"],
        "dst_ip": payload["dst_ip"],
        "src_mac": payload["src_mac"],
        "dst_mac": payload["dst_mac"],
        "src_port": payload["src_port"],
        "dst_port": payload["dst_port"],
        "in_port": payload["in_port"],
        "tcp_flags": payload["tcp_flags"],
        "match": payload["match_raw"],
    }
    record = extract_flow_record(observation)
    if payload.get("is_empty") != record.is_empty or payload.get("record_id") != record.record_id:
        raise FlowRecordError("record_id or derived is_empty does not match record contents")
    return record


def _make_record(fields: dict[str, object]) -> FlowRecord:
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"), allow_nan=False)
    record_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return FlowRecord(record_id=record_id, **fields)  # type: ignore[arg-type]


def _parse_match(value: object) -> dict[str, object]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        result = dict(value)
    elif isinstance(value, str):
        match = _MATCH_TEXT.search(value)
        if match is None:
            return {}
        try:
            parsed = ast.literal_eval(match.group(1))
        except (SyntaxError, ValueError) as exc:
            raise FlowRecordError("match string is not a literal OXM mapping") from exc
        if not isinstance(parsed, dict):
            raise FlowRecordError("match string OXM fields must be a mapping")
        result = parsed
    else:
        raise FlowRecordError("match must be a mapping or Ryu match string")
    return {key: result[key] for key in _MATCH_KEYS if key in result}


def _first(observation: Mapping[str, object], match: Mapping[str, object], *names: str) -> object:
    for name in names:
        if name in observation and observation[name] is not None:
            return observation[name]
    for name in names:
        if name in match and match[name] is not None:
            return match[name]
    return None


def _protocol_name(number: int | None) -> str | None:
    return _PROTOCOL_NAMES.get(number) if number is not None else None


def _optional_int(value: object, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FlowRecordError(f"{name} must be a non-negative integer")
    return value


def _optional_range(value: object, name: str, minimum: int, maximum: int) -> int | None:
    number = _optional_int(value, name)
    if number is not None and not minimum <= number <= maximum:
        raise FlowRecordError(f"{name} must be between {minimum} and {maximum}")
    return number


def _duration(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FlowRecordError("duration_seconds must be a finite non-negative number")
    duration = float(value)
    if not math.isfinite(duration) or duration < 0:
        raise FlowRecordError("duration_seconds must be a finite non-negative number")
    return duration


def _optional_text(value: object, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise FlowRecordError(f"{name} must be a non-empty string")
    return value


def _ip_address(value: object, name: str) -> str | None:
    text = _optional_text(value, name)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise FlowRecordError(f"{name} must be a valid IPv4 or IPv6 address") from exc


def _cookie(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise FlowRecordError("cookie must be a non-negative integer or hexadecimal string")
    if isinstance(value, int) and value >= 0:
        return f"0x{value:x}"
    if isinstance(value, str):
        try:
            number = int(value, 0)
        except ValueError as exc:
            raise FlowRecordError(
                "cookie must be a non-negative integer or hexadecimal string"
            ) from exc
        if number >= 0:
            return f"0x{number:x}"
    raise FlowRecordError("cookie must be a non-negative integer or hexadecimal string")


def _parse_timestamp(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise FlowRecordError("timestamp must be an ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FlowRecordError("timestamp must be a valid ISO 8601 string") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise FlowRecordError("timestamp must include a timezone")
    return parsed.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
