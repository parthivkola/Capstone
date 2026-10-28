"""Typed live telemetry contracts and rule-counter window construction.

This module records observations only. It has no detector, policy, or mitigation
dependencies and does not reuse CICFlowMeter feature names or semantics.
"""

from __future__ import annotations

import ast
import hashlib
import ipaddress
import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TypeAlias

from src.sdn_defense.flow_records import FlowRecord, extract_flow_record

SCENARIO_RUN_SCHEMA_VERSION = 1
OBSERVATION_SCHEMA_VERSION = 1
OBSERVATION_WINDOW_SCHEMA_VERSION = 1
OBSERVATION_PROVENANCE_VERSION = "sdn-live-observation-v1"
_OFP_MATCH = re.compile(r"oxm_fields=(\{.*\})")
_MATCH_ALIASES = {
    "eth_type": "eth_type",
    "ip_proto": "ip_protocol",
    "ipv4_src": "src_ip",
    "ipv6_src": "src_ip",
    "ipv4_dst": "dst_ip",
    "ipv6_dst": "dst_ip",
    "eth_src": "src_mac",
    "eth_dst": "dst_mac",
    "tcp_src": "src_port",
    "udp_src": "src_port",
    "tcp_dst": "dst_port",
    "udp_dst": "dst_port",
    "in_port": "in_port",
    "tcp_flags": "tcp_flags",
}
_SUPPORTED_OXM_KEYS = frozenset(_MATCH_ALIASES)
_FORBIDDEN_PAYLOAD_KEYS = {
    "attack",
    "attacktype",
    "isattack",
    "malicious",
    "anomaly",
    "classification",
    "confidence",
    "attackscore",
    "riskscore",
    "mitigation",
}
JsonScalar: TypeAlias = str | int | float | bool | None


class ObservationType(StrEnum):
    """Raw observation kinds; the names do not imply attack interpretation."""

    ETHERNET_PACKET_IN = "ETHERNET_PACKET_IN"
    ARP_PACKET_IN = "ARP_PACKET_IN"
    IPV4_PACKET_IN = "IPV4_PACKET_IN"
    TCP_PACKET_IN = "TCP_PACKET_IN"
    UDP_PACKET_IN = "UDP_PACKET_IN"
    PORT_DESCRIPTION = "PORT_DESCRIPTION"
    DHCP_MESSAGE = "DHCP_MESSAGE"  # Envelope reserved; no DHCP parser is implemented here.
    DNS_MESSAGE = "DNS_MESSAGE"  # Envelope reserved; no DNS parser is implemented here.
    DEVICE_INVENTORY = "DEVICE_INVENTORY"  # Envelope reserved; no inventory is implemented.


class WindowValidity(StrEnum):
    """Whether a window has complete counter and timing evidence."""

    VALID = "VALID"
    PARTIAL = "PARTIAL"
    BASELINE_ONLY = "BASELINE_ONLY"
    INVALID = "INVALID"
    CLOSED = "CLOSED"


class WindowReason(StrEnum):
    """Explicit reasons a window has missing or unusable derived values."""

    FIRST_OBSERVATION = "FIRST_OBSERVATION"
    REPEATED_OBSERVATION = "REPEATED_OBSERVATION"
    COUNTER_RESET = "COUNTER_RESET"
    MISSING_COUNTER = "MISSING_COUNTER"
    INVALID_ELAPSED_TIME = "INVALID_ELAPSED_TIME"
    OBSERVATION_GAP = "OBSERVATION_GAP"
    MISSING_TIMESTAMP = "MISSING_TIMESTAMP"
    RULE_DISAPPEARED = "RULE_DISAPPEARED"
    DATAPATH_DISCONNECTED = "DATAPATH_DISCONNECTED"
    RUN_BOUNDARY = "RUN_BOUNDARY"
    INCOMPLETE_SNAPSHOT = "INCOMPLETE_SNAPSHOT"


class TimingSource(StrEnum):
    """Clock used to measure the interval between controller observations."""

    COLLECTOR_MONOTONIC = "COLLECTOR_MONOTONIC"
    UTC_WALL_CLOCK_FALLBACK = "UTC_WALL_CLOCK_FALLBACK"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class TelemetryScope:
    """Observed packet/port selectors, distinct from a mitigation scope."""

    datapath_id: str | None = None
    selectors: tuple[tuple[str, str | int], ...] = ()

    def __post_init__(self) -> None:
        names = [name for name, _value in self.selectors]
        allowed = {
            "in_port",
            "src_mac",
            "dst_mac",
            "src_ip",
            "dst_ip",
            "ip_protocol",
            "src_port",
            "dst_port",
        }
        if len(names) != len(set(names)) or set(names) - allowed:
            raise ValueError("telemetry scope selectors must be unique supported observations")

    @classmethod
    def from_mapping(
        cls, datapath_id: str | None, selectors: Mapping[str, str | int]
    ) -> TelemetryScope:
        return cls(datapath_id, tuple(sorted(selectors.items())))

    def to_dict(self) -> dict[str, object]:
        return {"datapath_id": self.datapath_id, "selectors": dict(self.selectors)}


@dataclass(frozen=True, slots=True)
class TelemetryObservation:
    """One raw protocol/port observation with source and version provenance."""

    observation_id: str
    observation_type: ObservationType
    observed_at: datetime
    source: str
    scope: TelemetryScope | None
    payload: tuple[tuple[str, JsonScalar], ...]
    provenance_version: str
    run_id: str | None = None
    collector_monotonic_ns: int | None = None
    schema_version: int = OBSERVATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_aware(self.observed_at, "observed_at")
        if not self.observation_id or not self.source or not self.provenance_version:
            raise ValueError("observation ID, source, and provenance version are required")
        if self.run_id is not None and not self.run_id:
            raise ValueError("run_id must be non-empty when provided")
        if self.collector_monotonic_ns is not None and self.collector_monotonic_ns < 0:
            raise ValueError("collector monotonic time must be non-negative")
        keys = [key for key, _value in self.payload]
        if len(keys) != len(set(keys)):
            raise ValueError("observation payload keys must be unique")
        for key, value in self.payload:
            if not key or _normalized_payload_key(key) in _FORBIDDEN_PAYLOAD_KEYS:
                raise ValueError("telemetry payload cannot contain detector or attack labels")
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("telemetry payload numeric values must be finite")

    @classmethod
    def create(
        cls,
        *,
        observation_id: str,
        observation_type: ObservationType,
        observed_at: datetime,
        source: str,
        payload: Mapping[str, JsonScalar],
        provenance_version: str,
        scope: TelemetryScope | None = None,
        run_id: str | None = None,
        collector_monotonic_ns: int | None = None,
    ) -> TelemetryObservation:
        return cls(
            observation_id=observation_id,
            observation_type=observation_type,
            observed_at=observed_at,
            source=source,
            scope=scope,
            payload=tuple(sorted(payload.items())),
            provenance_version=provenance_version,
            run_id=run_id,
            collector_monotonic_ns=collector_monotonic_ns,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "observation_type": self.observation_type.value,
            "observed_at": _iso(self.observed_at),
            "source": self.source,
            "run_id": self.run_id,
            "scope": None if self.scope is None else self.scope.to_dict(),
            "payload": dict(self.payload),
            "provenance_version": self.provenance_version,
            "collector_monotonic_ns": self.collector_monotonic_ns,
        }


@dataclass(frozen=True, slots=True)
class ScenarioRunMetadata:
    """Additive controlled-run context; it does not label individual flows."""

    run_id: str
    scenario_id: str
    start_at: datetime
    end_at: datetime | None
    topology_config_id: str
    source_scope: tuple[tuple[str, str | int], ...]
    destination_scope: tuple[tuple[str, str | int], ...]
    protocol: str | None
    ports: tuple[int, ...]
    schema_version: int = SCENARIO_RUN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_aware(self.start_at, "scenario start_at")
        if self.end_at is not None:
            _require_aware(self.end_at, "scenario end_at")
            if self.end_at < self.start_at:
                raise ValueError("scenario end_at cannot precede start_at")
        if not self.run_id or not self.scenario_id or not self.topology_config_id:
            raise ValueError("run, scenario, and topology/config IDs are required")
        if any(port < 0 or port > 65535 for port in self.ports):
            raise ValueError("scenario ports must be within the transport port range")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "start_at": _iso(self.start_at),
            "end_at": None if self.end_at is None else _iso(self.end_at),
            "topology_config_id": self.topology_config_id,
            "source_scope": dict(self.source_scope),
            "destination_scope": dict(self.destination_scope),
            "protocol_scope": {"protocol": self.protocol, "ports": list(self.ports)},
        }


@dataclass(frozen=True, slots=True)
class CanonicalRuleIdentity:
    """Deterministic identity from OpenFlow metadata and normalized selectors."""

    datapath_id: str
    table_id: int
    priority: int
    cookie: str
    selectors: tuple[tuple[str, str | int], ...]
    identity_id: str

    @classmethod
    def from_flow_record(cls, record: FlowRecord) -> CanonicalRuleIdentity:
        if (
            record.datapath_id is None
            or record.table_id is None
            or record.priority is None
            or record.cookie is None
        ):
            raise ValueError("rule identity requires datapath, table, priority, and cookie")
        selectors = _canonical_match_selectors(record)
        datapath_id = _normalize_datapath(record.datapath_id)
        cookie = _normalize_cookie(record.cookie)
        identity_payload = {
            "datapath_id": datapath_id,
            "table_id": record.table_id,
            "priority": record.priority,
            "cookie": cookie,
            "selectors": dict(selectors),
        }
        identity_id = hashlib.sha256(
            json.dumps(identity_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return cls(
            datapath_id=datapath_id,
            table_id=record.table_id,
            priority=record.priority,
            cookie=cookie,
            selectors=selectors,
            identity_id=identity_id,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "datapath_id": self.datapath_id,
            "table_id": self.table_id,
            "priority": self.priority,
            "cookie": self.cookie,
            "selectors": dict(self.selectors),
            "identity_id": self.identity_id,
        }


@dataclass(frozen=True, slots=True)
class FlowSnapshot:
    """A FlowRecord plus collector-side timing/correlation, without changing it."""

    record: FlowRecord
    collector_monotonic_ns: int | None = None
    run_id: str | None = None
    collection_id: str | None = None
    datapath_epoch_id: str | None = None

    def __post_init__(self) -> None:
        if self.collector_monotonic_ns is not None and self.collector_monotonic_ns < 0:
            raise ValueError("collector monotonic time must be non-negative")
        if self.run_id is not None and not self.run_id:
            raise ValueError("run_id must be non-empty when provided")
        if self.collection_id is not None and not self.collection_id:
            raise ValueError("collection_id must be non-empty when provided")
        if self.datapath_epoch_id is not None and not self.datapath_epoch_id:
            raise ValueError("datapath_epoch_id must be non-empty when provided")


def flow_snapshot_from_observation(
    observation: Mapping[str, object],
    *,
    run_id: str | None = None,
    collection_id: str | None = None,
    datapath_epoch_id: str | None = None,
) -> FlowSnapshot:
    """Preserve collector timing alongside the unchanged Stage 4 FlowRecord."""

    monotonic_value = observation.get("collector_monotonic_ns")
    if monotonic_value is not None and (
        isinstance(monotonic_value, bool) or not isinstance(monotonic_value, int)
    ):
        raise ValueError("collector_monotonic_ns must be an integer when provided")
    record = extract_flow_record(observation)
    observed_collection_id = observation.get("collection_id", collection_id)
    observed_epoch_id = observation.get("datapath_epoch_id", datapath_epoch_id)
    if observed_collection_id is not None and not isinstance(observed_collection_id, str):
        raise ValueError("collection_id must be a string when provided")
    if observed_epoch_id is not None and not isinstance(observed_epoch_id, str):
        raise ValueError("datapath_epoch_id must be a string when provided")
    if collection_id is not None and observed_collection_id != collection_id:
        raise ValueError("snapshot collection provenance conflicts with its collection")
    if datapath_epoch_id is not None and observed_epoch_id != datapath_epoch_id:
        raise ValueError("snapshot epoch provenance conflicts with its collection")
    return FlowSnapshot(record, monotonic_value, run_id, observed_collection_id, observed_epoch_id)


def read_experiment_context(path: Path | None) -> dict[str, object] | None:
    """Read an explicit active run context; absent/malformed context is never guessed."""

    if path is None or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError("experiment context file cannot be read") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("experiment context file is malformed JSON") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != SCENARIO_RUN_SCHEMA_VERSION
        or not isinstance(value.get("run_id"), str)
        or not isinstance(value.get("scenario_id"), str)
    ):
        raise ValueError("experiment context schema or required identity is invalid")
    return value


@dataclass(frozen=True, slots=True)
class ObservationWindow:
    """One interval of OpenFlow rule-counter changes, not packet-flow features."""

    schema_version: int
    window_id: str
    observation_source: str
    datapath_id: str
    rule_identity: CanonicalRuleIdentity
    start_at: datetime | None
    end_at: datetime | None
    measured_elapsed_seconds: float | None
    timing_source: TimingSource
    source_record_ids: tuple[str, ...]
    validity: WindowValidity
    reason: WindowReason | None
    rule_packet_delta: int | None
    rule_byte_delta: int | None
    rule_packet_rate_per_second: float | None
    rule_byte_rate_per_second: float | None
    provenance_version: str
    run_id: str | None = None

    def __post_init__(self) -> None:
        if not self.window_id or not self.observation_source or not self.provenance_version:
            raise ValueError("window ID, observation source, and provenance are required")
        if not self.source_record_ids:
            raise ValueError("an observation window must reference at least one source record")
        if self.start_at is not None:
            _require_aware(self.start_at, "window start_at")
        if self.end_at is not None:
            _require_aware(self.end_at, "window end_at")
        if self.measured_elapsed_seconds is not None and (
            not math.isfinite(self.measured_elapsed_seconds) or self.measured_elapsed_seconds <= 0
        ):
            raise ValueError("measured elapsed seconds must be finite and positive")
        if self.validity is WindowValidity.VALID and (
            self.start_at is None
            or self.end_at is None
            or self.measured_elapsed_seconds is None
            or self.rule_packet_delta is None
            or self.rule_byte_delta is None
        ):
            raise ValueError("valid windows require times and both counter deltas")
        for rate in (self.rule_packet_rate_per_second, self.rule_byte_rate_per_second):
            if rate is not None and (not math.isfinite(rate) or rate < 0):
                raise ValueError("rule rates must be finite and non-negative")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "feature_schema_id": "stage7-live-rule-window-v1",
            "feature_order": [
                "rule_packet_delta",
                "rule_byte_delta",
                "rule_packet_rate_per_second",
                "rule_byte_rate_per_second",
            ],
            "window_id": self.window_id,
            "observation_source": self.observation_source,
            "datapath_id": self.datapath_id,
            "rule_identity": self.rule_identity.to_dict(),
            "start_at": None if self.start_at is None else _iso(self.start_at),
            "end_at": None if self.end_at is None else _iso(self.end_at),
            "measured_elapsed_seconds": self.measured_elapsed_seconds,
            "timing_source": self.timing_source.value,
            "source_record_ids": list(self.source_record_ids),
            "validity": self.validity.value,
            "reason": None if self.reason is None else self.reason.value,
            "rule_packet_delta": self.rule_packet_delta,
            "rule_byte_delta": self.rule_byte_delta,
            "rule_packet_rate_per_second": self.rule_packet_rate_per_second,
            "rule_byte_rate_per_second": self.rule_byte_rate_per_second,
            "provenance_version": self.provenance_version,
            "run_id": self.run_id,
        }


@dataclass(frozen=True, slots=True)
class _PreviousSnapshot:
    snapshot: FlowSnapshot
    identity: CanonicalRuleIdentity
    observed_at: datetime | None


class CounterDeltaEngine:
    """Pair successive snapshots of the same exact rule and emit explicit gaps."""

    def __init__(self, *, maximum_gap_seconds: float | None = None) -> None:
        if maximum_gap_seconds is not None and (
            isinstance(maximum_gap_seconds, bool)
            or not math.isfinite(maximum_gap_seconds)
            or maximum_gap_seconds <= 0
        ):
            raise ValueError("maximum_gap_seconds must be finite and positive")
        self.maximum_gap_seconds = maximum_gap_seconds
        self._previous: dict[str, _PreviousSnapshot] = {}

    def observe(self, snapshot: FlowSnapshot) -> ObservationWindow:
        """Consume one snapshot; new/reset/repeated counters never become zero deltas."""

        record = snapshot.record
        identity = CanonicalRuleIdentity.from_flow_record(record)
        current_time = _parse_aware_iso(record.observed_at)
        previous = self._previous.get(identity.identity_id)
        if previous is None:
            self._previous[identity.identity_id] = _PreviousSnapshot(
                snapshot, identity, current_time
            )
            return self._window(
                identity,
                start_at=None,
                end_at=current_time,
                elapsed=None,
                timing=TimingSource.UNAVAILABLE,
                record_ids=(record.record_id,),
                validity=WindowValidity.BASELINE_ONLY,
                reason=(
                    WindowReason.MISSING_TIMESTAMP
                    if current_time is None
                    else WindowReason.FIRST_OBSERVATION
                ),
                run_id=snapshot.run_id,
            )

        old_record = previous.snapshot.record
        if old_record.record_id == record.record_id:
            return self._window(
                identity,
                start_at=previous.observed_at,
                end_at=current_time,
                elapsed=None,
                timing=TimingSource.UNAVAILABLE,
                record_ids=(old_record.record_id, record.record_id),
                validity=WindowValidity.INVALID,
                reason=WindowReason.REPEATED_OBSERVATION,
                run_id=snapshot.run_id,
            )

        if previous.snapshot.run_id != snapshot.run_id:
            self._previous[identity.identity_id] = _PreviousSnapshot(
                snapshot, identity, current_time
            )
            return self._window(
                identity,
                start_at=previous.observed_at,
                end_at=current_time,
                elapsed=None,
                timing=TimingSource.UNAVAILABLE,
                record_ids=(old_record.record_id, record.record_id),
                validity=WindowValidity.BASELINE_ONLY,
                reason=WindowReason.RUN_BOUNDARY,
                run_id=snapshot.run_id,
            )

        elapsed, timing = _elapsed(previous.snapshot, snapshot, previous.observed_at, current_time)
        if elapsed is None:
            self._previous[identity.identity_id] = _PreviousSnapshot(
                snapshot, identity, current_time
            )
            return self._window(
                identity,
                start_at=previous.observed_at,
                end_at=current_time,
                elapsed=None,
                timing=timing,
                record_ids=(old_record.record_id, record.record_id),
                validity=WindowValidity.INVALID,
                reason=(
                    WindowReason.MISSING_TIMESTAMP
                    if previous.observed_at is None or current_time is None
                    else WindowReason.INVALID_ELAPSED_TIME
                ),
                run_id=snapshot.run_id,
            )

        if self.maximum_gap_seconds is not None and elapsed > self.maximum_gap_seconds:
            self._previous[identity.identity_id] = _PreviousSnapshot(
                snapshot, identity, current_time
            )
            return self._window(
                identity,
                start_at=previous.observed_at,
                end_at=current_time,
                elapsed=elapsed,
                timing=timing,
                record_ids=(old_record.record_id, record.record_id),
                validity=WindowValidity.INVALID,
                reason=WindowReason.OBSERVATION_GAP,
                run_id=snapshot.run_id,
            )

        old_packets, new_packets = old_record.packet_count, record.packet_count
        old_bytes, new_bytes = old_record.byte_count, record.byte_count
        if _counter_decreased(old_packets, new_packets) or _counter_decreased(old_bytes, new_bytes):
            self._previous[identity.identity_id] = _PreviousSnapshot(
                snapshot, identity, current_time
            )
            return self._window(
                identity,
                start_at=previous.observed_at,
                end_at=current_time,
                elapsed=elapsed,
                timing=timing,
                record_ids=(old_record.record_id, record.record_id),
                validity=WindowValidity.INVALID,
                reason=WindowReason.COUNTER_RESET,
                run_id=snapshot.run_id,
            )

        packet_delta = _counter_delta(old_packets, new_packets)
        byte_delta = _counter_delta(old_bytes, new_bytes)
        reason = (
            WindowReason.MISSING_COUNTER if packet_delta is None or byte_delta is None else None
        )
        validity = WindowValidity.PARTIAL if reason is not None else WindowValidity.VALID
        self._previous[identity.identity_id] = _PreviousSnapshot(snapshot, identity, current_time)
        return self._window(
            identity,
            start_at=previous.observed_at,
            end_at=current_time,
            elapsed=elapsed,
            timing=timing,
            record_ids=(old_record.record_id, record.record_id),
            validity=validity,
            reason=reason,
            packet_delta=packet_delta,
            byte_delta=byte_delta,
            run_id=snapshot.run_id,
        )

    def close_missing(
        self,
        datapath_id: str,
        active_rule_identity_ids: Iterable[str],
        *,
        snapshot_complete: bool,
        observed_at: datetime,
        collector_monotonic_ns: int | None = None,
    ) -> tuple[ObservationWindow, ...]:
        """Close absent rules only when the caller confirms a complete switch snapshot."""

        _require_aware(observed_at, "snapshot observed_at")
        if not snapshot_complete:
            return ()
        active = set(active_rule_identity_ids)
        closed: list[ObservationWindow] = []
        for identity_id, previous in tuple(self._previous.items()):
            if previous.identity.datapath_id != _normalize_datapath(datapath_id):
                continue
            if identity_id in active:
                continue
            elapsed, timing = _elapsed(
                previous.snapshot,
                FlowSnapshot(
                    previous.snapshot.record,
                    collector_monotonic_ns,
                    previous.snapshot.run_id,
                    previous.snapshot.collection_id,
                    previous.snapshot.datapath_epoch_id,
                ),
                previous.observed_at,
                observed_at,
            )
            closed.append(
                self._window(
                    previous.identity,
                    start_at=previous.observed_at,
                    end_at=observed_at,
                    elapsed=elapsed,
                    timing=timing,
                    record_ids=(previous.snapshot.record.record_id,),
                    validity=WindowValidity.CLOSED,
                    reason=WindowReason.RULE_DISAPPEARED,
                    run_id=previous.snapshot.run_id,
                )
            )
            del self._previous[identity_id]
        return tuple(closed)

    def datapath_disconnected(
        self,
        datapath_id: str,
        *,
        observed_at: datetime,
        collector_monotonic_ns: int | None = None,
    ) -> tuple[ObservationWindow, ...]:
        """Clear a datapath baseline so reconnect observations cannot cross-pair."""

        _require_aware(observed_at, "disconnect observed_at")
        normalized = _normalize_datapath(datapath_id)
        closed: list[ObservationWindow] = []
        for identity_id, previous in tuple(self._previous.items()):
            if previous.identity.datapath_id != normalized:
                continue
            elapsed, timing = _elapsed(
                previous.snapshot,
                FlowSnapshot(
                    previous.snapshot.record,
                    collector_monotonic_ns,
                    previous.snapshot.run_id,
                    previous.snapshot.collection_id,
                    previous.snapshot.datapath_epoch_id,
                ),
                previous.observed_at,
                observed_at,
            )
            closed.append(
                self._window(
                    previous.identity,
                    start_at=previous.observed_at,
                    end_at=observed_at,
                    elapsed=elapsed,
                    timing=timing,
                    record_ids=(previous.snapshot.record.record_id,),
                    validity=WindowValidity.CLOSED,
                    reason=WindowReason.DATAPATH_DISCONNECTED,
                    run_id=previous.snapshot.run_id,
                )
            )
            del self._previous[identity_id]
        return tuple(closed)

    @staticmethod
    def _window(
        identity: CanonicalRuleIdentity,
        *,
        start_at: datetime | None,
        end_at: datetime | None,
        elapsed: float | None,
        timing: TimingSource,
        record_ids: tuple[str, ...],
        validity: WindowValidity,
        reason: WindowReason | None,
        packet_delta: int | None = None,
        byte_delta: int | None = None,
        run_id: str | None,
    ) -> ObservationWindow:
        packet_rate = (
            packet_delta / elapsed if packet_delta is not None and elapsed is not None else None
        )
        byte_rate = byte_delta / elapsed if byte_delta is not None and elapsed is not None else None
        identity_text = json.dumps(
            {
                "identity_id": identity.identity_id,
                "records": record_ids,
                "reason": None if reason is None else reason.value,
                "run_id": run_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return ObservationWindow(
            schema_version=OBSERVATION_WINDOW_SCHEMA_VERSION,
            window_id=hashlib.sha256(identity_text.encode()).hexdigest(),
            observation_source="openflow_rule_counter_delta",
            datapath_id=identity.datapath_id,
            rule_identity=identity,
            start_at=start_at,
            end_at=end_at,
            measured_elapsed_seconds=elapsed,
            timing_source=timing,
            source_record_ids=record_ids,
            validity=validity,
            reason=reason,
            rule_packet_delta=packet_delta,
            rule_byte_delta=byte_delta,
            rule_packet_rate_per_second=packet_rate,
            rule_byte_rate_per_second=byte_rate,
            provenance_version=OBSERVATION_PROVENANCE_VERSION,
            run_id=run_id,
        )


def _canonical_match_selectors(record: FlowRecord) -> tuple[tuple[str, str | int], ...]:
    raw_match = record.match_raw
    if raw_match is not None:
        match = _parse_full_oxm(raw_match)
        unknown = set(match) - _SUPPORTED_OXM_KEYS
        if unknown:
            raise ValueError(
                f"cannot identify rule with unsupported OXM selectors: {sorted(unknown)}"
            )
        normalized: dict[str, str | int] = {}
        transport: set[str] = set()
        for raw_name, raw_value in match.items():
            name = _MATCH_ALIASES[raw_name]
            value = _normalize_selector_value(name, raw_value)
            if raw_name in ("tcp_src", "tcp_dst"):
                transport.add("tcp")
            elif raw_name in ("udp_src", "udp_dst"):
                transport.add("udp")
            if name in normalized and normalized[name] != value:
                raise ValueError(f"conflicting raw match aliases for {name}")
            normalized[name] = value
        if len(transport) > 1:
            raise ValueError("rule match contains conflicting TCP and UDP selector families")
        if transport:
            normalized["transport_protocol"] = next(iter(transport))
        return tuple(sorted(normalized.items()))

    normalized_fields: dict[str, str | int] = {}
    fields: tuple[tuple[str, str | int | None], ...] = (
        ("eth_type", record.eth_type),
        ("ip_protocol", record.ip_protocol),
        ("src_ip", record.src_ip),
        ("dst_ip", record.dst_ip),
        ("src_mac", record.src_mac),
        ("dst_mac", record.dst_mac),
        ("src_port", record.src_port),
        ("dst_port", record.dst_port),
        ("in_port", record.in_port),
        ("tcp_flags", record.tcp_flags),
    )
    for field_name, field_value in fields:
        if field_value is not None:
            normalized_fields[field_name] = _normalize_selector_value(field_name, field_value)
    if record.src_port is not None or record.dst_port is not None:
        if record.ip_protocol == 6:
            normalized_fields["transport_protocol"] = "tcp"
        elif record.ip_protocol == 17:
            normalized_fields["transport_protocol"] = "udp"
    return tuple(sorted(normalized_fields.items()))


def _parse_full_oxm(raw_match: str) -> dict[str, object]:
    if raw_match.strip() in {"OFPMatch()", "{}"}:
        return {}
    found = _OFP_MATCH.search(raw_match)
    if found is None:
        raise ValueError("raw match format is not a recognized Ryu OXM mapping")
    try:
        parsed = ast.literal_eval(found.group(1))
    except (SyntaxError, ValueError) as exc:
        raise ValueError("raw OXM match is not a literal mapping") from exc
    if not isinstance(parsed, dict) or any(not isinstance(key, str) for key in parsed):
        raise ValueError("raw OXM match must be a string-keyed mapping")
    return parsed


def _normalize_selector_value(name: str, value: object) -> str | int:
    if name in {"src_ip", "dst_ip"}:
        if not isinstance(value, str):
            raise ValueError(f"{name} match must be an IP address string")
        return str(ipaddress.ip_address(value))
    if name in {"src_mac", "dst_mac"}:
        if not isinstance(value, str):
            raise ValueError(f"{name} match must be a MAC address string")
        normalized = value.lower()
        if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", normalized):
            raise ValueError(f"{name} match must be a six-octet MAC address")
        return normalized
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} selector must be a non-negative integer")
    return value


def _normalize_datapath(value: str) -> str:
    text = value.lower().removeprefix("0x")
    try:
        return f"{int(text, 16):016x}"
    except ValueError as exc:
        raise ValueError("datapath ID must be hexadecimal") from exc


def _normalize_cookie(value: str) -> str:
    try:
        number = int(value, 0)
    except ValueError as exc:
        raise ValueError("cookie must be an integer or hexadecimal value") from exc
    if number < 0:
        raise ValueError("cookie must be non-negative")
    return f"0x{number:x}"


def _counter_decreased(previous: int | None, current: int | None) -> bool:
    return previous is not None and current is not None and current < previous


def _counter_delta(previous: int | None, current: int | None) -> int | None:
    if previous is None or current is None:
        return None
    return current - previous


def _elapsed(
    previous: FlowSnapshot,
    current: FlowSnapshot,
    previous_wall: datetime | None,
    current_wall: datetime | None,
) -> tuple[float | None, TimingSource]:
    if previous.collector_monotonic_ns is not None and current.collector_monotonic_ns is not None:
        elapsed = (current.collector_monotonic_ns - previous.collector_monotonic_ns) / 1e9
        return (
            (elapsed, TimingSource.COLLECTOR_MONOTONIC)
            if elapsed > 0
            else (
                None,
                TimingSource.COLLECTOR_MONOTONIC,
            )
        )
    if previous_wall is None or current_wall is None:
        return None, TimingSource.UNAVAILABLE
    elapsed = (current_wall - previous_wall).total_seconds()
    return (
        (elapsed, TimingSource.UTC_WALL_CLOCK_FALLBACK)
        if elapsed > 0
        else (
            None,
            TimingSource.UTC_WALL_CLOCK_FALLBACK,
        )
    )


def _parse_aware_iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_aware(value: datetime, name: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def _normalized_payload_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())
