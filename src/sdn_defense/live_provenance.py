"""Offline audit of source records required for live rule-counter features.

This module validates recorder evidence; it does not authenticate a JSONL file
cryptographically. Ryu event fixtures used by tests are synthetic.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from src.sdn_defense.live_features import SnapshotPair


class CollectionTerminalState(StrEnum):
    """Terminal outcomes understood by the source-provenance contract."""

    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"
    DISCONNECTED = "DISCONNECTED"
    AMBIGUOUS = "AMBIGUOUS"


class DatapathEpochState(StrEnum):
    """Observed lifecycle state of a datapath connection epoch."""

    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class CollectionProvenance:
    """Collection lineage reconstructed from request and terminal records."""

    collection_id: str
    datapath_id: str
    xid: int
    terminal_state: CollectionTerminalState
    request_record_index: int
    terminal_record_index: int
    datapath_epoch_id: str | None
    run_id: str | None
    part_count: int | None


@dataclass(frozen=True, slots=True)
class DatapathEpochProvenance:
    """Connection lineage reconstructed from observed boundary records."""

    datapath_id: str
    epoch_id: str
    connected_record_index: int
    state: DatapathEpochState
    terminal_record_index: int | None = None


@dataclass(frozen=True, slots=True)
class ProvenanceAudit:
    """Result of checking a pair against its append-ordered recorder events."""

    accepted: bool
    reason: str | None
    previous_collection_id: str | None
    current_collection_id: str | None
    datapath_epoch_id: str | None
    collections: tuple[CollectionProvenance, ...] = ()
    epoch: DatapathEpochProvenance | None = None


def audit_snapshot_pair_provenance(
    pair: SnapshotPair, records: Sequence[Mapping[str, Any]]
) -> ProvenanceAudit:
    """Require two source-linked completed collections in one observed epoch.

    The record sequence must be in recorder append order. Required provenance
    fields are deliberately strict. Epoch IDs must be linked to a connection
    boundary carrying a controller-instance nonce and monotonic epoch sequence.
    This structural audit does not cryptographically authenticate JSONL records.
    """

    previous, current = pair.previous, pair.current
    if previous is None or current is None:
        return _reject(pair, "MISSING_SNAPSHOT")
    if previous is current or (
        previous.snapshot.record.record_id == current.snapshot.record.record_id
    ):
        return _reject(pair, "DUPLICATE_SNAPSHOT")
    if previous.snapshot.run_id != current.snapshot.run_id:
        return _reject(pair, "RUN_BOUNDARY")
    if previous.datapath_epoch_id != current.datapath_epoch_id:
        return _reject(pair, "DATAPATH_EPOCH_BOUNDARY")

    audited: list[tuple[int, int, str, CollectionProvenance, int]] = []
    for evidence in (previous, current):
        if not evidence.collection_complete:
            return _reject(pair, "COLLECTION_NOT_MARKED_COMPLETE")
        collection_id = evidence.collection_id
        request_matches = [
            (index, record)
            for index, record in enumerate(records)
            if record.get("record_type") == "flow_collection"
            and record.get("collection_id") == collection_id
            and record.get("state") == "requested"
            and record.get("schema_version") == 2
        ]
        completion_matches = [
            (index, record)
            for index, record in enumerate(records)
            if record.get("record_type") == "flow_collection"
            and record.get("collection_id") == collection_id
            and record.get("complete") is True
            and record.get("schema_version") == 2
        ]
        if len(request_matches) != 1 or len(completion_matches) != 1:
            return _reject(pair, "COLLECTION_REQUEST_OR_COMPLETION_NOT_UNIQUE")
        request_index, request = request_matches[0]
        completion_index, completion = completion_matches[0]
        if request_index >= completion_index:
            return _reject(pair, "COLLECTION_EVENT_ORDER_INVALID")
        if completion.get("terminal_state") != CollectionTerminalState.COMPLETE.value:
            return _reject(pair, "COLLECTION_TERMINAL_STATE_NOT_COMPLETE")
        if any(
            record.get("record_type") == "incomplete_collection"
            and record.get("collection_id") == collection_id
            for record in records
        ):
            return _reject(pair, "COLLECTION_HAS_INCOMPLETE_TERMINAL_EVENT")

        run_id = evidence.snapshot.run_id
        snapshot_matches = [
            (index, record)
            for index, record in enumerate(records)
            if record.get("record_type") == "flow_snapshot"
            and record.get("collection_id") == collection_id
            and record.get("run_id") == run_id
            and record.get("schema_version") == 2
            and _record_id(record) == evidence.snapshot.record.record_id
        ]
        if len(snapshot_matches) != 1:
            return _reject(pair, "SNAPSHOT_SOURCE_LINK_NOT_UNIQUE")
        snapshot_index, snapshot_record = snapshot_matches[0]
        epoch_id = evidence.datapath_epoch_id
        datapath_id = evidence.snapshot.record.datapath_id
        if not epoch_id:
            return _reject(pair, "DATAPATH_EPOCH_ID_MISSING")
        if not isinstance(datapath_id, str) or not datapath_id:
            return _reject(pair, "DATAPATH_ID_MISSING")
        if (
            request.get("datapath_epoch_id") != epoch_id
            or completion.get("datapath_epoch_id") != epoch_id
            or snapshot_record.get("datapath_epoch_id") != epoch_id
        ):
            return _reject(pair, "DATAPATH_EPOCH_SOURCE_LINK_MISSING_OR_CONTRADICTORY")
        if not _same_datapath(datapath_id, request.get("datapath_id")) or not _same_datapath(
            datapath_id, completion.get("datapath_id")
        ):
            return _reject(pair, "COLLECTION_DATAPATH_MISMATCH")
        if snapshot_index <= completion_index or snapshot_index <= request_index:
            return _reject(pair, "SNAPSHOT_OUTSIDE_COLLECTION_BOUNDARY")
        if (
            evidence.snapshot.collection_id != collection_id
            or evidence.snapshot.datapath_epoch_id != epoch_id
        ):
            return _reject(pair, "TYPED_SNAPSHOT_PROVENANCE_MISSING_OR_CONTRADICTORY")
        if any(
            record.get("record_type") == "run_boundary"
            for record in records[request_index + 1 : snapshot_index]
        ):
            return _reject(pair, "RUN_BOUNDARY_DURING_COLLECTION")
        if request.get("run_id") != run_id or completion.get("run_id") != run_id:
            return _reject(pair, "COLLECTION_RUN_MISMATCH")
        if request.get("xid") != completion.get("xid"):
            return _reject(pair, "COLLECTION_XID_MISMATCH")
        part_count = completion.get("part_count")
        if isinstance(part_count, bool) or not isinstance(part_count, int) or part_count < 1:
            return _reject(pair, "COMPLETION_PART_COUNT_INVALID")
        xid = request.get("xid")
        if isinstance(xid, bool) or not isinstance(xid, int):
            return _reject(pair, "COLLECTION_XID_INVALID")
        if not 0 <= xid <= 0xFFFFFFFF:
            return _reject(pair, "COLLECTION_XID_INVALID")
        expected_collection_id = f"{epoch_id}:{_parse_datapath_id(datapath_id):016x}:{xid:08x}"
        if collection_id != expected_collection_id:
            return _reject(pair, "COLLECTION_IDENTITY_NOT_SOURCE_BACKED")
        connection_index = _connection_epoch_start_index(
            records, request_index, snapshot_index, datapath_id, epoch_id
        )
        if connection_index is None:
            return _reject(pair, "CONNECTION_EPOCH_NOT_OBSERVED_OR_CROSSED")
        if not _epoch_identity_matches(records[connection_index], datapath_id, epoch_id):
            return _reject(pair, "CONNECTION_EPOCH_IDENTITY_NOT_SOURCE_BACKED")
        collection_provenance = CollectionProvenance(
            collection_id=collection_id,
            datapath_id=datapath_id,
            xid=xid,
            terminal_state=CollectionTerminalState.COMPLETE,
            request_record_index=request_index,
            terminal_record_index=completion_index,
            datapath_epoch_id=epoch_id,
            run_id=run_id,
            part_count=part_count,
        )
        audited.append(
            (request_index, completion_index, epoch_id, collection_provenance, connection_index)
        )

    (
        previous_request,
        previous_completion,
        epoch_id,
        previous_collection,
        connection_index,
    ) = audited[0]
    current_request, current_completion, current_epoch, current_collection, _ = audited[1]
    if epoch_id != current_epoch:
        return _reject(pair, "DATAPATH_EPOCH_BOUNDARY")
    if previous_completion >= current_request:
        return _reject(pair, "COLLECTION_ORDER_OR_OVERLAP_INVALID")
    if any(
        _invalidates_epoch(record, epoch_id)
        for record in records[previous_completion + 1 : current_request]
    ):
        return _reject(pair, "DATAPATH_EPOCH_CLOSED_BETWEEN_SNAPSHOTS")

    previous_snapshot_index = next(
        index
        for index, record in enumerate(records)
        if record.get("record_type") == "flow_snapshot"
        and record.get("collection_id") == previous.collection_id
        and _record_id(record) == previous.snapshot.record.record_id
    )
    current_snapshot_index = next(
        index
        for index, record in enumerate(records)
        if record.get("record_type") == "flow_snapshot"
        and record.get("collection_id") == current.collection_id
        and _record_id(record) == current.snapshot.record.record_id
    )
    if previous_snapshot_index >= current_snapshot_index:
        return _reject(pair, "SNAPSHOT_ORDER_INVALID")
    if any(
        record.get("record_type") == "run_boundary"
        for record in records[previous_snapshot_index + 1 : current_snapshot_index]
    ):
        return _reject(pair, "RUN_BOUNDARY_EVENT_BETWEEN_SNAPSHOTS")
    close_events = [
        (index, record)
        for index, record in enumerate(records)
        if index > current_snapshot_index and _invalidates_epoch(record, epoch_id)
    ]
    epoch_state = DatapathEpochState.CLOSED if close_events else DatapathEpochState.ACTIVE
    epoch = DatapathEpochProvenance(
        datapath_id=previous_collection.datapath_id,
        epoch_id=epoch_id,
        connected_record_index=connection_index,
        state=epoch_state,
        terminal_record_index=close_events[0][0] if close_events else None,
    )
    return ProvenanceAudit(
        True,
        None,
        previous.collection_id,
        current.collection_id,
        epoch_id,
        (previous_collection, current_collection),
        epoch,
    )


def _connection_epoch_start_index(
    records: Sequence[Mapping[str, Any]],
    request_index: int,
    completion_index: int,
    datapath_id: str,
    epoch_id: str,
) -> int | None:
    boundaries = [
        index
        for index, record in enumerate(records)
        if record.get("record_type") == "connection_boundary"
        and _same_datapath(datapath_id, record.get("datapath_id"))
        and record.get("schema_version") == 2
    ]
    prior = [index for index in boundaries if index <= request_index]
    if not prior:
        return None
    matching_connects = [
        index
        for index in boundaries
        if index <= completion_index
        and records[index].get("state") == "connected"
        and records[index].get("datapath_epoch_id") == epoch_id
        and records[index].get("schema_version") == 2
    ]
    if len(matching_connects) != 1:
        return None
    latest_prior = records[prior[-1]]
    if (
        latest_prior.get("state") != "connected"
        or latest_prior.get("datapath_epoch_id") != epoch_id
    ):
        return None
    connect_index = prior[-1]
    for index in range(connect_index + 1, completion_index + 1):
        record = records[index]
        if (
            record.get("record_type") == "connection_boundary"
            and record.get("state") in {"disconnected", "ambiguous", "ambiguous_global_disconnect"}
            and record.get("datapath_id") is None
        ):
            return None
        if (
            record.get("record_type") == "connection_boundary"
            and _same_datapath(datapath_id, record.get("datapath_id"))
            and (record.get("state") != "connected" or record.get("datapath_epoch_id") != epoch_id)
        ):
            return None
    return connect_index


def _record_id(record: Mapping[str, Any]) -> object:
    flow_record = record.get("flow_record")
    if not isinstance(flow_record, Mapping):
        return None
    return flow_record.get("record_id")


def _invalidates_epoch(record: Mapping[str, Any], epoch_id: str) -> bool:
    if record.get("record_type") != "connection_boundary":
        return False
    if record.get("schema_version") != 2:
        return False
    if record.get("state") not in {"disconnected", "ambiguous", "ambiguous_global_disconnect"}:
        return False
    if record.get("datapath_id") is None:
        affected = record.get("affected_epoch_ids")
        return not isinstance(affected, list) or epoch_id in affected
    return record.get("datapath_epoch_id") == epoch_id


def _epoch_identity_matches(record: Mapping[str, Any], datapath_id: str, epoch_id: str) -> bool:
    instance_id = record.get("controller_instance_id")
    sequence = record.get("epoch_sequence")
    if not isinstance(instance_id, str) or not instance_id:
        return False
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        return False
    normalized_dpid = f"{_parse_datapath_id(datapath_id):016x}"
    return epoch_id == f"{instance_id}:{normalized_dpid}:{sequence}"


def _same_datapath(left: str, right: object) -> bool:
    if not isinstance(right, str) or not right:
        return False
    try:
        return _parse_datapath_id(left) == _parse_datapath_id(right)
    except ValueError:
        return left == right


def _parse_datapath_id(value: str) -> int:
    if value.startswith("0x"):
        return int(value, 16)
    if len(value) == 16 and all(character in "0123456789abcdefABCDEF" for character in value):
        return int(value, 16)
    return int(value, 10)


def _reject(pair: SnapshotPair, reason: str) -> ProvenanceAudit:
    return ProvenanceAudit(
        False,
        reason,
        None if pair.previous is None else pair.previous.collection_id,
        None if pair.current is None else pair.current.collection_id,
        None if pair.current is None else pair.current.datapath_epoch_id,
    )
