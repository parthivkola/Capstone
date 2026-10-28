"""Append-only telemetry recording, multipart collection, and read-only replay checks."""

from __future__ import annotations

import json
import math
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from src.sdn_defense.flow_records import FlowRecord
from src.sdn_defense.telemetry import (
    TelemetryObservation,
    _iso,
    _require_aware,
)

RECORDER_SCHEMA_VERSION = 2
_RECORD_SCHEMAS = {
    "recorder_metadata": RECORDER_SCHEMA_VERSION,
    "run_metadata": 1,
    "run_boundary": 1,
    "connection_boundary": 2,
    "flow_collection": 2,
    "flow_snapshot": 2,
    "observation_window": 1,
    "telemetry_observation": 1,
    "packet_evidence_coverage": 1,
    "incomplete_collection": 2,
}
_SUPPORTED_RECORD_SCHEMAS = {
    kind: ({1, version} if version > 1 else {1}) for kind, version in _RECORD_SCHEMAS.items()
}


@dataclass(frozen=True, slots=True)
class FlowStatsCollection:
    """One complete multipart flow-stat response tied to one XID and datapath."""

    collection_id: str
    datapath_id: int
    xid: int
    started_at: datetime
    completed_at: datetime
    started_monotonic_ns: int
    completed_monotonic_ns: int
    records: tuple[dict[str, object], ...]
    run_id: str | None
    parts_received: int
    datapath_epoch_id: str


@dataclass(slots=True)
class _PendingCollection:
    datapath_id: int
    xid: int
    started_at: datetime
    started_monotonic_ns: int
    timeout_at_monotonic_ns: int
    run_id: str | None
    datapath_epoch_id: str
    last_received_monotonic_ns: int | None = None
    parts_received: int = 0
    records: list[dict[str, object]] = field(default_factory=list)
    fingerprints: set[str] = field(default_factory=set)


class MultipartFlowStatsAssembler:
    """Assemble OpenFlow multipart replies without cross-request mixing."""

    def __init__(self, *, timeout_seconds: float = 5.0) -> None:
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be finite and positive")
        self.timeout_ns = int(timeout_seconds * 1_000_000_000)
        self._pending: dict[tuple[int, int, str], _PendingCollection] = {}
        self._last_xid_by_epoch: dict[str, int] = {}

    def start(
        self,
        *,
        datapath_id: int,
        xid: int,
        started_at: datetime,
        started_monotonic_ns: int,
        datapath_epoch_id: str,
        run_id: str | None = None,
    ) -> str:
        _require_aware(started_at, "collection started_at")
        if not datapath_epoch_id:
            raise ValueError("datapath_epoch_id is required")
        key = datapath_id, xid, datapath_epoch_id
        last_xid = self._last_xid_by_epoch.get(datapath_epoch_id)
        if last_xid is not None and xid <= last_xid:
            raise ValueError("flow-stat request XID is stale or out of order within epoch")
        if key in self._pending:
            raise ValueError("duplicate pending flow-stat request identity")
        self._pending[key] = _PendingCollection(
            datapath_id=datapath_id,
            xid=xid,
            started_at=started_at,
            started_monotonic_ns=started_monotonic_ns,
            timeout_at_monotonic_ns=started_monotonic_ns + self.timeout_ns,
            run_id=run_id,
            datapath_epoch_id=datapath_epoch_id,
        )
        self._last_xid_by_epoch[datapath_epoch_id] = xid
        return _collection_id(datapath_id, xid, datapath_epoch_id)

    def add_part(
        self,
        *,
        datapath_id: int,
        xid: int,
        datapath_epoch_id: str,
        records: list[dict[str, object]],
        more: bool,
        received_at: datetime,
        received_monotonic_ns: int,
    ) -> FlowStatsCollection | None:
        """Add a response part; return data only when the protocol final flag arrives."""

        _require_aware(received_at, "collection received_at")
        pending = self._pending.get((datapath_id, xid, datapath_epoch_id))
        if pending is None:
            raise KeyError("flow-stat part has no matching datapath/XID request")
        if received_monotonic_ns >= pending.timeout_at_monotonic_ns:
            del self._pending[(datapath_id, xid, datapath_epoch_id)]
            raise TimeoutError("multipart_timeout")
        if received_monotonic_ns < pending.started_monotonic_ns or (
            pending.last_received_monotonic_ns is not None
            and received_monotonic_ns <= pending.last_received_monotonic_ns
        ):
            del self._pending[(datapath_id, xid, datapath_epoch_id)]
            raise ValueError("flow-stat multipart part is out of timestamp order")
        fingerprint_records = [
            {
                key: value
                for key, value in record.items()
                if key not in {"timestamp", "collector_monotonic_ns"}
            }
            for record in records
        ]
        fingerprint = json.dumps(fingerprint_records, sort_keys=True, separators=(",", ":"))
        if fingerprint in pending.fingerprints:
            del self._pending[(datapath_id, xid, datapath_epoch_id)]
            raise ValueError("duplicate flow-stat multipart part")
        pending.fingerprints.add(fingerprint)
        pending.parts_received += 1
        pending.last_received_monotonic_ns = received_monotonic_ns
        pending.records.extend(records)
        if more:
            return None
        del self._pending[(datapath_id, xid, datapath_epoch_id)]
        return FlowStatsCollection(
            collection_id=_collection_id(datapath_id, xid, datapath_epoch_id),
            datapath_id=datapath_id,
            xid=xid,
            started_at=pending.started_at,
            completed_at=received_at,
            started_monotonic_ns=pending.started_monotonic_ns,
            completed_monotonic_ns=received_monotonic_ns,
            records=tuple(pending.records),
            run_id=pending.run_id,
            parts_received=pending.parts_received,
            datapath_epoch_id=pending.datapath_epoch_id,
        )

    def expire(self, now_monotonic_ns: int) -> tuple[dict[str, object], ...]:
        expired: list[dict[str, object]] = []
        for key, pending in tuple(self._pending.items()):
            if now_monotonic_ns < pending.timeout_at_monotonic_ns:
                continue
            expired.append(
                {
                    "collection_id": _collection_id(
                        pending.datapath_id, pending.xid, pending.datapath_epoch_id
                    ),
                    "datapath_id": f"{pending.datapath_id:016x}",
                    "xid": pending.xid,
                    "started_at": _iso(pending.started_at),
                    "parts_received": pending.parts_received,
                    "partial_record_count": len(pending.records),
                    "run_id": pending.run_id,
                    "datapath_epoch_id": pending.datapath_epoch_id,
                    "complete": False,
                    "reason": "multipart_timeout",
                    "terminal_state": "TIMED_OUT",
                    "expired_monotonic_ns": now_monotonic_ns,
                }
            )
            del self._pending[key]
        return tuple(expired)

    def disconnect(
        self,
        datapath_id: int,
        *,
        reason: str = "datapath_disconnected",
        terminal_state: str = "DISCONNECTED",
    ) -> tuple[dict[str, object], ...]:
        incomplete: list[dict[str, object]] = []
        for key, pending in tuple(self._pending.items()):
            if pending.datapath_id != datapath_id:
                continue
            incomplete.append(
                {
                    "collection_id": _collection_id(
                        pending.datapath_id, pending.xid, pending.datapath_epoch_id
                    ),
                    "datapath_id": f"{pending.datapath_id:016x}",
                    "xid": pending.xid,
                    "started_at": _iso(pending.started_at),
                    "parts_received": pending.parts_received,
                    "partial_record_count": len(pending.records),
                    "run_id": pending.run_id,
                    "datapath_epoch_id": pending.datapath_epoch_id,
                    "complete": False,
                    "reason": reason,
                    "terminal_state": terminal_state,
                }
            )
            del self._pending[key]
        return tuple(incomplete)

    def invalidate_epoch(
        self, datapath_id: int, epoch_id: str, *, reason: str
    ) -> tuple[dict[str, object], ...]:
        """Invalidate only requests linked to one observed connection epoch."""

        incomplete: list[dict[str, object]] = []
        for key, pending in tuple(self._pending.items()):
            if pending.datapath_id != datapath_id or pending.datapath_epoch_id != epoch_id:
                continue
            incomplete.append(
                {
                    "collection_id": _collection_id(datapath_id, pending.xid, epoch_id),
                    "datapath_id": f"{datapath_id:016x}",
                    "xid": pending.xid,
                    "started_at": _iso(pending.started_at),
                    "parts_received": pending.parts_received,
                    "partial_record_count": len(pending.records),
                    "run_id": pending.run_id,
                    "datapath_epoch_id": epoch_id,
                    "complete": False,
                    "reason": reason,
                    "terminal_state": "DISCONNECTED",
                }
            )
            del self._pending[key]
        return tuple(incomplete)

    def invalidate_all(
        self, *, reason: str, terminal_state: str = "AMBIGUOUS"
    ) -> tuple[dict[str, object], ...]:
        """Cancel every pending request after an ambiguous/global boundary."""

        incomplete: list[dict[str, object]] = []
        for key, pending in tuple(self._pending.items()):
            incomplete.append(
                {
                    "collection_id": _collection_id(
                        pending.datapath_id, pending.xid, pending.datapath_epoch_id
                    ),
                    "datapath_id": f"{pending.datapath_id:016x}",
                    "xid": pending.xid,
                    "started_at": _iso(pending.started_at),
                    "parts_received": pending.parts_received,
                    "partial_record_count": len(pending.records),
                    "run_id": pending.run_id,
                    "datapath_epoch_id": pending.datapath_epoch_id,
                    "complete": False,
                    "reason": reason,
                    "terminal_state": terminal_state,
                }
            )
            del self._pending[key]
        return tuple(incomplete)

    def cancel_for_run_change(self, new_run_id: str | None) -> tuple[dict[str, object], ...]:
        """Cancel requests whose captured run differs from an observed new context."""

        cancelled: list[dict[str, object]] = []
        for key, pending in tuple(self._pending.items()):
            if pending.run_id == new_run_id:
                continue
            cancelled.append(
                {
                    "collection_id": _collection_id(
                        pending.datapath_id, pending.xid, pending.datapath_epoch_id
                    ),
                    "datapath_id": f"{pending.datapath_id:016x}",
                    "xid": pending.xid,
                    "started_at": _iso(pending.started_at),
                    "parts_received": pending.parts_received,
                    "partial_record_count": len(pending.records),
                    "run_id": pending.run_id,
                    "datapath_epoch_id": pending.datapath_epoch_id,
                    "complete": False,
                    "reason": "run_boundary_invalidated_pending_collection",
                    "terminal_state": "CANCELLED",
                }
            )
            del self._pending[key]
        return tuple(cancelled)


def _collection_id(datapath_id: int, xid: int, epoch_id: str) -> str:
    """Include connection lineage so an XID reused after reconnect cannot alias."""

    return f"{epoch_id}:{datapath_id:016x}:{xid:08x}"


class DatapathEpochLifecycleState(StrEnum):
    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class DatapathEpoch:
    """Epoch minted by this controller process for one observed connection."""

    epoch_id: str
    datapath_id: int
    sequence: int
    controller_instance_id: str
    connected_at: datetime
    connected_monotonic_ns: int
    state: DatapathEpochLifecycleState = DatapathEpochLifecycleState.ACTIVE


@dataclass(frozen=True, slots=True)
class EpochConnectionResult:
    epoch: DatapathEpoch
    replaced_epoch: DatapathEpoch | None = None


class DatapathEpochTracker:
    """Mint epochs from observed connection objects and invalidate boundaries.

    Connection objects are retained by identity while the controller process is
    alive. They are internal event evidence, not serialized or caller-provided
    epoch identifiers.
    """

    def __init__(self) -> None:
        self._instance_id = uuid.uuid4().hex
        self._next_sequence = 0
        self._active: dict[int, tuple[object, DatapathEpoch]] = {}
        self._observed: list[tuple[object, DatapathEpoch]] = []

    @property
    def controller_instance_id(self) -> str:
        return self._instance_id

    def connect(
        self,
        datapath_id: int,
        connection: object,
        *,
        observed_at: datetime,
        observed_monotonic_ns: int,
    ) -> EpochConnectionResult:
        _require_aware(observed_at, "datapath connected_at")
        active = self._active.get(datapath_id)
        if active is not None and active[0] is connection:
            return EpochConnectionResult(active[1])
        reused_connection_object = any(
            observed_connection is connection for observed_connection, _epoch in self._observed
        )
        replaced: DatapathEpoch | None = None
        if active is not None:
            replaced = _replace_epoch_state(active[1], DatapathEpochLifecycleState.AMBIGUOUS)
            self._active.pop(datapath_id, None)
            self._replace_observed_epoch(active[0], replaced)
        self._next_sequence += 1
        epoch_id = f"{self._instance_id}:{datapath_id:016x}:{self._next_sequence}"
        epoch = DatapathEpoch(
            epoch_id=epoch_id,
            datapath_id=datapath_id,
            sequence=self._next_sequence,
            controller_instance_id=self._instance_id,
            connected_at=observed_at,
            connected_monotonic_ns=observed_monotonic_ns,
            state=(
                DatapathEpochLifecycleState.AMBIGUOUS
                if reused_connection_object
                else DatapathEpochLifecycleState.ACTIVE
            ),
        )
        if epoch.state is DatapathEpochLifecycleState.ACTIVE:
            self._active[datapath_id] = (connection, epoch)
        self._observed.append((connection, epoch))
        return EpochConnectionResult(epoch, replaced)

    def epoch_for_connection(self, datapath_id: int, connection: object) -> DatapathEpoch | None:
        for observed_connection, epoch in reversed(self._observed):
            if observed_connection is connection and epoch.datapath_id == datapath_id:
                return epoch
        return None

    def active_epoch(self, datapath_id: int) -> DatapathEpoch | None:
        value = self._active.get(datapath_id)
        return None if value is None else value[1]

    def disconnect(self, datapath_id: int, connection: object) -> DatapathEpoch | None:
        active = self._active.get(datapath_id)
        if active is None:
            return self.epoch_for_connection(datapath_id, connection)
        if active[0] is not connection:
            prior = self.epoch_for_connection(datapath_id, connection)
            if prior is not None:
                return prior
            state = DatapathEpochLifecycleState.AMBIGUOUS
        else:
            state = DatapathEpochLifecycleState.CLOSED
        closed = _replace_epoch_state(active[1], state)
        self._replace_observed_epoch(active[0], closed)
        if active[0] is connection or state is DatapathEpochLifecycleState.AMBIGUOUS:
            self._active.pop(datapath_id, None)
        return closed

    def invalidate_all(self) -> tuple[DatapathEpoch, ...]:
        """Invalidate all active epochs after a disconnect without a DPID."""

        invalidated: list[DatapathEpoch] = []
        for datapath_id, (connection, epoch) in tuple(self._active.items()):
            ambiguous = _replace_epoch_state(epoch, DatapathEpochLifecycleState.AMBIGUOUS)
            self._replace_observed_epoch(connection, ambiguous)
            invalidated.append(ambiguous)
            del self._active[datapath_id]
        return tuple(invalidated)

    def _replace_observed_epoch(self, connection: object, epoch: DatapathEpoch) -> None:
        self._observed = [
            (candidate, epoch if candidate is connection else prior)
            for candidate, prior in self._observed
        ]


def _replace_epoch_state(epoch: DatapathEpoch, state: DatapathEpochLifecycleState) -> DatapathEpoch:
    return DatapathEpoch(
        epoch_id=epoch.epoch_id,
        datapath_id=epoch.datapath_id,
        sequence=epoch.sequence,
        controller_instance_id=epoch.controller_instance_id,
        connected_at=epoch.connected_at,
        connected_monotonic_ns=epoch.connected_monotonic_ns,
        state=state,
    )


class TelemetryJsonlRecorder:
    """Append-only JSONL output with explicit typed record envelopes."""

    def __init__(self, path: str | Path, *, source_version: str) -> None:
        if not source_version:
            raise ValueError("source_version is required")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.source_version = source_version
        self._stream = self.path.open("a", encoding="utf-8", newline="\n")
        self.write(
            "recorder_metadata",
            recorded_at=_iso(datetime.now(UTC)),
            source_version=source_version,
        )

    def write(self, record_type: str, **fields: object) -> None:
        if record_type not in _RECORD_SCHEMAS:
            raise ValueError(f"unsupported telemetry record type: {record_type}")
        envelope = {
            "record_type": record_type,
            "schema_version": _RECORD_SCHEMAS[record_type],
            **fields,
        }
        encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":"), allow_nan=False)
        self._stream.write(encoded + "\n")
        self._stream.flush()

    def write_observation(self, observation: TelemetryObservation) -> None:
        self.write("telemetry_observation", observation=observation.to_dict())

    def close(self) -> None:
        self._stream.flush()
        self._stream.close()


def validate_telemetry_jsonl(path: str | Path) -> dict[str, int]:
    """Validate record envelopes, run consistency, times, and window provenance."""

    counts: dict[str, int] = {}
    run_by_observation: dict[str, str | None] = {}
    record_ids: set[str] = set()
    last_time_by_run: dict[str | None, datetime] = {}
    open_runs: set[str] = set()
    with Path(path).open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            try:
                item: Any = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError("JSONL value must be an object")
                kind = item.get("record_type")
                if (
                    kind not in _RECORD_SCHEMAS
                    or item.get("schema_version") not in _SUPPORTED_RECORD_SCHEMAS[kind]
                ):
                    raise ValueError("unknown record type or unsupported schema version")
                counts[kind] = counts.get(kind, 0) + 1
                if kind == "flow_snapshot":
                    record = item.get("flow_record")
                    if not isinstance(record, dict) or not isinstance(record.get("record_id"), str):
                        raise ValueError("flow_snapshot requires flow_record.record_id")
                    try:
                        validated_record = FlowRecord(**record)
                    except TypeError as exc:
                        raise ValueError(
                            "flow_record fields do not match the Stage 4 contract"
                        ) from exc
                    if validated_record.schema_version != 1:
                        raise ValueError("unsupported FlowRecord schema version")
                    if item.get("schema_version") == 2 and (
                        not _nonempty_string(item.get("collection_id"))
                        or not _nonempty_string(item.get("datapath_epoch_id"))
                    ):
                        raise ValueError("schema-2 flow_snapshot requires collection and epoch IDs")
                    if record["record_id"] in record_ids:
                        raise ValueError("duplicate FlowRecord record_id in telemetry stream")
                    record_ids.add(record["record_id"])
                    snapshot_run = _optional_run_id(item.get("run_id"))
                    run_by_observation[record["record_id"]] = snapshot_run
                    _check_order(last_time_by_run, snapshot_run, _parse_time(item.get("timestamp")))
                if kind == "flow_collection" and item.get("schema_version") == 2:
                    if not _nonempty_string(item.get("collection_id")) or not _nonempty_string(
                        item.get("datapath_epoch_id")
                    ):
                        raise ValueError(
                            "schema-2 flow_collection requires collection and epoch IDs"
                        )
                    if item.get("state") != "requested" and not (
                        item.get("complete") is True and item.get("terminal_state") == "COMPLETE"
                    ):
                        raise ValueError("schema-2 flow_collection has an invalid terminal state")
                if kind == "connection_boundary" and item.get("schema_version") == 2:
                    if not _nonempty_string(item.get("controller_instance_id")):
                        raise ValueError(
                            "schema-2 connection_boundary requires controller identity"
                        )
                    if item.get("state") == "connected" and (
                        not _nonempty_string(item.get("datapath_epoch_id"))
                        or not _nonempty_string(item.get("datapath_id"))
                        or isinstance(item.get("epoch_sequence"), bool)
                        or not isinstance(item.get("epoch_sequence"), int)
                        or item.get("epoch_sequence", 0) < 1
                    ):
                        raise ValueError("connected schema-2 boundary requires datapath epoch")
                if kind == "incomplete_collection" and item.get("schema_version") == 2:
                    collection_id = item.get("collection_id")
                    epoch_id = item.get("datapath_epoch_id")
                    if collection_id is not None and not _nonempty_string(collection_id):
                        raise ValueError("incomplete collection ID must be non-empty or null")
                    if collection_id is not None and not _nonempty_string(epoch_id):
                        raise ValueError("linked incomplete collection requires its epoch ID")
                if kind == "telemetry_observation":
                    observation = item.get("observation")
                    if not isinstance(observation, dict):
                        raise ValueError("telemetry_observation envelope is malformed")
                    if observation.get("schema_version") != 1:
                        raise ValueError("unsupported TelemetryObservation schema version")
                    observation_id = observation.get("observation_id")
                    if not isinstance(observation_id, str) or not observation_id:
                        raise ValueError("telemetry observation ID is missing")
                    if observation_id in run_by_observation:
                        raise ValueError("duplicate telemetry observation ID")
                    run_id = _optional_run_id(observation.get("run_id"))
                    run_by_observation[observation_id] = run_id
                    timestamp = _parse_time(observation.get("observed_at"))
                    _check_order(last_time_by_run, run_id, timestamp)
                if kind == "observation_window":
                    window = item.get("observation_window")
                    if not isinstance(window, dict):
                        raise ValueError("observation_window envelope is malformed")
                    if window.get("schema_version") != 1:
                        raise ValueError("unsupported ObservationWindow schema version")
                    if not isinstance(window.get("window_id"), str) or not isinstance(
                        window.get("provenance_version"), str
                    ):
                        raise ValueError("window ID and provenance version are required")
                    sources = window.get("source_record_ids")
                    if (
                        not isinstance(sources, list)
                        or not sources
                        or not set(sources) <= record_ids
                    ):
                        raise ValueError(
                            "window sources must reference previously recorded flow snapshots"
                        )
                    window_run = _optional_run_id(window.get("run_id"))
                    is_boundary = window.get("reason") == "RUN_BOUNDARY"
                    has_derived_delta = any(
                        window.get(field) is not None
                        for field in ("rule_packet_delta", "rule_byte_delta")
                    )
                    if is_boundary and has_derived_delta:
                        raise ValueError("run-boundary windows cannot contain counter deltas")
                    if not is_boundary and any(
                        run_by_observation.get(source) != window_run for source in sources
                    ):
                        raise ValueError("window run_id does not match its source snapshots")
                    timestamp = _parse_time(window.get("end_at"))
                    if timestamp is not None:
                        _check_order(last_time_by_run, window_run, timestamp)
                if kind in {
                    "run_metadata",
                    "run_boundary",
                    "connection_boundary",
                    "flow_collection",
                    "incomplete_collection",
                    "packet_evidence_coverage",
                }:
                    run_id = _optional_run_id(item.get("run_id"))
                    timestamp_value = (
                        item.get("timestamp") or item.get("start_at") or item.get("completed_at")
                    )
                    timestamp = _parse_time(timestamp_value)
                    if timestamp is not None:
                        _check_order(last_time_by_run, run_id, timestamp)
                if kind == "run_metadata":
                    metadata = item.get("metadata")
                    if (
                        not isinstance(metadata, dict)
                        or metadata.get("schema_version") != 1
                        or metadata.get("run_id") != item.get("run_id")
                    ):
                        raise ValueError("run metadata does not match its record envelope")
                if kind == "run_boundary":
                    run_id = _optional_run_id(item.get("run_id"))
                    state = item.get("state")
                    if run_id is None or state not in {"started", "ended"}:
                        raise ValueError("run boundary needs a run_id and started/ended state")
                    if state == "started":
                        if run_id in open_runs:
                            raise ValueError("run boundary started twice without an end")
                        open_runs.add(run_id)
                    else:
                        if run_id not in open_runs:
                            raise ValueError("run boundary ended without a recorded start")
                        open_runs.remove(run_id)
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ValueError(f"invalid telemetry JSONL line {line_number}: {exc}") from exc
    counts["incomplete_runs"] = len(open_runs)
    return counts


def _optional_run_id(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError("run_id must be a non-empty string or null")
    return value


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _parse_time(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string or null")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    _require_aware(parsed, "telemetry timestamp")
    return parsed.astimezone(UTC)


def _check_order(
    last: dict[str | None, datetime], run_id: str | None, current: datetime | None
) -> None:
    if current is None:
        return
    previous = last.get(run_id)
    if previous is not None and current < previous:
        raise ValueError("timestamp order moved backwards within run")
    last[run_id] = current
