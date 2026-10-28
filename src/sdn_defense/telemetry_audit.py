"""Read-only audit and cadence summaries for recorded Stage 7 rule telemetry."""

from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from src.sdn_defense.flow_records import FlowRecord
from src.sdn_defense.live_features import SnapshotEvidence, SnapshotPair
from src.sdn_defense.live_provenance import audit_snapshot_pair_provenance
from src.sdn_defense.telemetry import CanonicalRuleIdentity, FlowSnapshot
from src.sdn_defense.telemetry_io import validate_telemetry_jsonl


def audit_telemetry_jsonl(path: str | Path) -> dict[str, Any]:
    """Validate schemas and source lineage, then report supported cadence only.

    PacketIn/port observations are counted separately and are never used to
    construct rule-counter snapshot pairs or cadence measurements.
    """

    source = Path(path)
    schema_counts = validate_telemetry_jsonl(source)
    records: list[dict[str, Any]] = []
    with source.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                raise ValueError(f"blank JSONL line {line_number} is not auditable")
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError(f"JSONL line {line_number} must contain an object")
            records.append(item)

    issues: list[str] = []
    if schema_counts.get("incomplete_runs", 0):
        issues.append(f"unclosed_run_boundaries:{schema_counts['incomplete_runs']}")
    request_by_id: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    completion_by_id: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    incomplete_by_id: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    snapshots_by_collection: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    connected_epochs: list[tuple[int, dict[str, Any]]] = []
    boundaries = [
        (index, record)
        for index, record in enumerate(records)
        if record.get("record_type") in {"connection_boundary", "run_boundary"}
    ]

    for index, record in enumerate(records):
        kind = record.get("record_type")
        collection_id = record.get("collection_id")
        if kind == "flow_collection":
            if record.get("schema_version") != 2:
                issues.append(f"legacy_flow_collection_schema:{index}")
                continue
            if record.get("state") == "requested":
                if isinstance(collection_id, str):
                    request_by_id[collection_id].append((index, record))
            elif record.get("complete") is True and isinstance(collection_id, str):
                completion_by_id[collection_id].append((index, record))
        elif kind == "incomplete_collection":
            if record.get("schema_version") != 2:
                issues.append(f"legacy_incomplete_collection_schema:{index}")
            if isinstance(collection_id, str):
                incomplete_by_id[collection_id].append((index, record))
            else:
                issues.append(f"unlinked_incomplete_collection:{index}")
        elif kind == "flow_snapshot":
            if record.get("schema_version") != 2:
                issues.append(f"legacy_flow_snapshot_schema:{index}")
                continue
            if isinstance(collection_id, str):
                snapshots_by_collection[collection_id].append((index, record))
            else:
                issues.append(f"snapshot_missing_collection_id:{index}")
        elif kind == "connection_boundary" and record.get("state") == "connected":
            connected_epochs.append((index, record))

    all_collection_ids = set(request_by_id) | set(completion_by_id) | set(incomplete_by_id)
    all_collection_ids |= set(snapshots_by_collection)
    requested_run_ids = {
        record.get("run_id") for requests in request_by_id.values() for _index, record in requests
    }
    if len(requested_run_ids) != 1 or None in requested_run_ids:
        issues.append("missing_or_mixed_run_ids")
    collection_rows: list[dict[str, Any]] = []
    for collection_id in sorted(all_collection_ids):
        requests = request_by_id.get(collection_id, [])
        completions = completion_by_id.get(collection_id, [])
        incomplete = incomplete_by_id.get(collection_id, [])
        terminals = len(completions) + len(incomplete)
        valid = len(requests) == 1 and terminals == 1 and len(completions) == 1 and not incomplete
        if len(requests) != 1:
            issues.append(f"request_count_invalid:{collection_id}:{len(requests)}")
        if terminals != 1:
            issues.append(f"terminal_count_invalid:{collection_id}:{terminals}")
        if len(completions) > 1 or len(incomplete) > 1 or (completions and incomplete):
            issues.append(f"contradictory_or_duplicate_terminal:{collection_id}")
        if not valid:
            if incomplete:
                issues.append(f"incomplete_collection:{collection_id}")
            if snapshots_by_collection.get(collection_id):
                issues.append(f"snapshot_without_unique_complete_collection:{collection_id}")
        if requests and completions:
            request_index, request = requests[0]
            completion_index, completion = completions[0]
            if request_index >= completion_index:
                issues.append(f"collection_event_order_invalid:{collection_id}")
                valid = False
            if any(
                index > request_index
                and index < completion_index
                and _boundary_invalidates(record, request.get("datapath_epoch_id"))
                for index, record in boundaries
            ):
                issues.append(f"collection_crosses_run_or_epoch_boundary:{collection_id}")
                valid = False
            if not _request_completion_match(request, completion):
                issues.append(f"collection_lineage_mismatch:{collection_id}")
                valid = False
            if not _collection_identity_matches(collection_id, request):
                issues.append(f"collection_identity_mismatch:{collection_id}")
                valid = False
            if not _has_preceding_connection(
                connected_epochs,
                request_index,
                request.get("datapath_id"),
                request.get("datapath_epoch_id"),
            ):
                issues.append(f"connection_epoch_not_observed_before_request:{collection_id}")
                valid = False
            snapshots = snapshots_by_collection.get(collection_id, [])
            expected_records = completion.get("record_count")
            if not _nonnegative_int(expected_records) or expected_records != len(snapshots):
                issues.append(f"snapshot_count_mismatch:{collection_id}")
                valid = False
            for snapshot_index, snapshot in snapshots:
                if snapshot_index <= completion_index or not _snapshot_matches(
                    snapshot, completion
                ):
                    issues.append(f"snapshot_lineage_mismatch:{collection_id}:{snapshot_index}")
                    valid = False
        collection_rows.append(
            {
                "collection_id": collection_id,
                "requested": len(requests) == 1,
                "complete": valid,
                "request_count": len(requests),
                "completion_count": len(completions),
                "incomplete_count": len(incomplete),
                "snapshot_count": len(snapshots_by_collection.get(collection_id, [])),
                "run_id": requests[0][1].get("run_id") if requests else None,
                "datapath_id": requests[0][1].get("datapath_id") if requests else None,
                "datapath_epoch_id": requests[0][1].get("datapath_epoch_id") if requests else None,
            }
        )

    pair_results, pair_issues = _audit_pairs(records, completion_by_id, snapshots_by_collection)
    issues.extend(pair_issues)
    if not pair_results:
        issues.append("no_source_verified_snapshot_pairs")
    cadence = _cadence_summary(collection_rows, request_by_id, completion_by_id, pair_results)
    if cadence["monotonic_order_errors"]:
        issues.append("monotonic_timestamp_order_invalid")
    observation_types = Counter(
        str(record.get("observation", {}).get("observation_type", "UNKNOWN"))
        for record in records
        if record.get("record_type") == "telemetry_observation"
        and isinstance(record.get("observation"), dict)
    )
    packetin_count = sum(
        count for kind, count in observation_types.items() if kind.endswith("_PACKET_IN")
    )
    return {
        "schema_version": 1,
        "source_file": source.name,
        "status": "AUDIT_COMPLETE" if not issues else "AUDIT_INCOMPLETE",
        "schema_record_counts": dict(sorted(schema_counts.items())),
        "counts": {
            "requests": sum(len(items) for items in request_by_id.values()),
            "complete_collection_terminal_records": sum(
                len(items) for items in completion_by_id.values()
            ),
            "incomplete_collection_terminal_records": sum(
                len(items) for items in incomplete_by_id.values()
            ),
            "collections_with_valid_complete_lineage": sum(
                bool(row["complete"]) for row in collection_rows
            ),
            "flow_snapshot_records": sum(
                len(items) for items in snapshots_by_collection.values()
            ),
            "lineage_linked_flow_snapshot_records": sum(
                int(row["snapshot_count"]) for row in collection_rows if row["complete"]
            ),
            # Preserve original count keys for existing consumers; the fields
            # above make raw-record and validated-lineage counts distinct.
            "complete_collections": sum(len(items) for items in completion_by_id.values()),
            "incomplete_collections": sum(len(items) for items in incomplete_by_id.values()),
            "snapshots": sum(len(items) for items in snapshots_by_collection.values()),
            "source_verified_pairs": sum(result["accepted"] for result in pair_results),
            "rejected_pairs": sum(not result["accepted"] for result in pair_results),
            "packetin_observations_excluded_from_feature_evidence": packetin_count,
            "telemetry_observation_types_excluded_from_feature_evidence": dict(
                sorted(observation_types.items())
            ),
        },
        "collections": collection_rows,
        "pairs": pair_results,
        "cadence": cadence,
        "issues": sorted(set(issues)),
        "feature_vectors_generated": False,
    }


def render_audit_report(summary: Mapping[str, Any]) -> str:
    """Render a deterministic human-readable audit summary."""

    counts = summary["counts"]
    cadence = summary["cadence"]
    return "\n".join(
        [
            "# Stage 7 Rule-Counter Telemetry Audit",
            "",
            f"- Status: **{summary['status']}**",
            f"- Source: `{summary['source_file']}`",
            f"- Request / COMPLETE terminal / incomplete terminal records: "
            f"{counts['requests']} / {counts['complete_collection_terminal_records']} / "
            f"{counts['incomplete_collection_terminal_records']}",
            f"- Collections with valid complete lineage: "
            f"{counts['collections_with_valid_complete_lineage']}",
            f"- Flow snapshot records / lineage-linked snapshot records: "
            f"{counts['flow_snapshot_records']} / "
            f"{counts['lineage_linked_flow_snapshot_records']}",
            f"- Source-verified pairs accepted / rejected: {counts['source_verified_pairs']} / "
            f"{counts['rejected_pairs']}",
            f"- PacketIn observations excluded from feature evidence: "
            f"{counts['packetin_observations_excluded_from_feature_evidence']}",
            f"- Request cadence samples (monotonic): {cadence['request_gap_samples']}",
            f"- Request gap min/median/max seconds: {cadence['request_gap_summary_seconds']}",
            f"- Request-to-completion durations (monotonic): {cadence['duration_samples']}",
            f"- Completion-to-completion gaps min/median/max seconds: "
            f"{cadence['completion_gap_summary_seconds']}",
            f"- Source-verified same-rule snapshot gaps min/median/max seconds: "
            f"{cadence['snapshot_gap_summary_seconds']}",
            f"- Incomplete/invalid collections excluded from cadence: "
            f"{cadence['incomplete_or_invalid_collections']}",
            f"- Missing/invalid monotonic timing collections: "
            f"{cadence['missing_timing_collections']} / "
            f"{cadence['invalid_timing_collections']}",
            f"- Empty complete collections: {cadence['empty_complete_collections']}",
            "- Snapshot-to-snapshot gaps: not computed by this report.",
            "- Maximum-gap policy: **not selected**",
            "",
            "## Issues",
            "",
            *([f"- `{issue}`" for issue in summary["issues"]] or ["- None"]),
            "",
            "PacketIn and port-description observations are counted separately.",
            "They do not construct rule-counter pairs or cadence measurements.",
            "",
        ]
    )


def _request_completion_match(request: Mapping[str, Any], completion: Mapping[str, Any]) -> bool:
    fields = ("datapath_id", "datapath_epoch_id", "xid", "run_id")
    if any(request.get(field) != completion.get(field) for field in fields):
        return False
    if any(
        not isinstance(request.get(field), str) or not request.get(field)
        for field in ("datapath_id", "datapath_epoch_id", "run_id")
    ):
        return False
    start_ns = request.get("started_monotonic_ns")
    completion_start_ns = completion.get("started_monotonic_ns")
    end_ns = completion.get("completed_monotonic_ns")
    part_count = completion.get("part_count")
    record_count = completion.get("record_count")
    if (
        not isinstance(part_count, int)
        or isinstance(part_count, bool)
        or part_count < 1
        or not isinstance(record_count, int)
        or isinstance(record_count, bool)
        or record_count < 0
    ):
        return False
    return (
        request.get("state") == "requested"
        and completion.get("complete") is True
        and completion.get("terminal_state") == "COMPLETE"
        and request.get("timestamp") == request.get("started_at")
        and completion.get("started_at") == request.get("started_at")
        and completion.get("timestamp") == completion.get("completed_at")
        and isinstance(start_ns, int)
        and not isinstance(start_ns, bool)
        and isinstance(completion_start_ns, int)
        and not isinstance(completion_start_ns, bool)
        and start_ns == completion_start_ns
        and isinstance(end_ns, int)
        and not isinstance(end_ns, bool)
        and end_ns >= start_ns
    )


def _collection_identity_matches(collection_id: str, request: Mapping[str, Any]) -> bool:
    dpid = request.get("datapath_id")
    xid = request.get("xid")
    epoch_id = request.get("datapath_epoch_id")
    if not isinstance(dpid, str) or not isinstance(epoch_id, str):
        return False
    if not isinstance(xid, int) or isinstance(xid, bool) or not 0 <= xid <= 0xFFFFFFFF:
        return False
    try:
        numeric_dpid = int(dpid, 16)
    except ValueError:
        return False
    if not 0 <= numeric_dpid <= 0xFFFFFFFFFFFFFFFF:
        return False
    canonical_dpid = f"{numeric_dpid:016x}"
    return collection_id == f"{epoch_id}:{canonical_dpid}:{xid:08x}"


def _nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _snapshot_matches(snapshot: Mapping[str, Any], completion: Mapping[str, Any]) -> bool:
    flow_record = snapshot.get("flow_record")
    if not isinstance(flow_record, dict):
        return False
    return (
        snapshot.get("datapath_epoch_id") == completion.get("datapath_epoch_id")
        and snapshot.get("run_id") == completion.get("run_id")
        and snapshot.get("timestamp") == completion.get("completed_at")
        and snapshot.get("collector_monotonic_ns") == completion.get("completed_monotonic_ns")
        and flow_record.get("datapath_id") == completion.get("datapath_id")
        and _same_timestamp(flow_record.get("observed_at"), snapshot.get("timestamp"))
    )


def _same_timestamp(left: object, right: object) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        left_value = datetime.fromisoformat(left.replace("Z", "+00:00"))
        right_value = datetime.fromisoformat(right.replace("Z", "+00:00"))
    except ValueError:
        return False
    return left_value == right_value


def _boundary_invalidates(record: Mapping[str, Any], epoch_id: object) -> bool:
    if record.get("record_type") == "run_boundary":
        return True
    affected_epochs = record.get("affected_epoch_ids")
    affects_epoch = isinstance(affected_epochs, list) and epoch_id in affected_epochs
    return record.get("record_type") == "connection_boundary" and (
        record.get("datapath_epoch_id") == epoch_id
        or affects_epoch
        or record.get("state") == "ambiguous_global_disconnect"
    )


def _has_preceding_connection(
    events: Sequence[tuple[int, dict[str, Any]]],
    request_index: int,
    datapath_id: object,
    epoch_id: object,
) -> bool:
    return any(
        index < request_index
        and record.get("datapath_id") == datapath_id
        and record.get("datapath_epoch_id") == epoch_id
        and record.get("state") == "connected"
        and record.get("schema_version") == 2
        and isinstance(record.get("controller_instance_id"), str)
        and isinstance(record.get("epoch_sequence"), int)
        and not isinstance(record.get("epoch_sequence"), bool)
        and record.get("datapath_epoch_id")
        == f"{record.get('controller_instance_id')}:{datapath_id}:{record.get('epoch_sequence')}"
        for index, record in events
    )


def _audit_pairs(
    records: Sequence[dict[str, Any]],
    completion_by_id: Mapping[str, list[tuple[int, dict[str, Any]]]],
    snapshots_by_collection: Mapping[str, list[tuple[int, dict[str, Any]]]],
) -> tuple[list[dict[str, Any]], list[str]]:
    collections: list[tuple[int, str, dict[str, Any], list[tuple[int, dict[str, Any]]]]] = []
    for collection_id, completions in completion_by_id.items():
        if len(completions) != 1 or completions[0][1].get("terminal_state") != "COMPLETE":
            continue
        index, completion = completions[0]
        collections.append(
            (index, collection_id, completion, snapshots_by_collection.get(collection_id, []))
        )
    collections.sort(key=lambda item: item[0])
    previous_by_scope: dict[tuple[object, object, str], SnapshotEvidence] = {}
    previous_collection_by_scope: dict[tuple[object, object], str] = {}
    pair_results: list[dict[str, Any]] = []
    issues: list[str] = []
    for _index, collection_id, completion, snapshots in collections:
        run_id = completion.get("run_id")
        epoch_id = completion.get("datapath_epoch_id")
        if (
            not isinstance(run_id, str)
            or not run_id
            or not isinstance(epoch_id, str)
            or not epoch_id
        ):
            issues.append(f"snapshot_pair_missing_run_or_epoch:{collection_id}")
            continue
        scope = (run_id, epoch_id)
        identities: dict[str, SnapshotEvidence] = {}
        for _snapshot_index, snapshot_record in snapshots:
            try:
                flow_record_payload = snapshot_record["flow_record"]
                flow_record = FlowRecord(**flow_record_payload)
                identity = CanonicalRuleIdentity.from_flow_record(flow_record).identity_id
                if identity in identities:
                    issues.append(
                        f"duplicate_rule_identity_in_collection:{collection_id}:{identity}"
                    )
                    continue
                typed = FlowSnapshot(
                    flow_record,
                    snapshot_record.get("collector_monotonic_ns"),
                    run_id,
                    collection_id,
                    epoch_id,
                )
            except (KeyError, TypeError, ValueError) as error:
                issues.append(
                    f"snapshot_identity_or_parse_invalid:{collection_id}:{type(error).__name__}"
                )
                continue
            identities[identity] = SnapshotEvidence(typed, collection_id, True, str(epoch_id or ""))

        for key in tuple(previous_by_scope):
            if key[:2] == scope and key[2] not in identities:
                del previous_by_scope[key]
        if scope in previous_collection_by_scope:
            for identity, current in identities.items():
                previous = previous_by_scope.get((run_id, epoch_id, identity))
                if previous is None or previous.collection_id == collection_id:
                    continue
                pair = SnapshotPair(
                    pair_id=f"{previous.snapshot.record.record_id}:{current.snapshot.record.record_id}",
                    previous=previous,
                    current=current,
                )
                previous_ns = previous.snapshot.collector_monotonic_ns
                current_ns = current.snapshot.collector_monotonic_ns
                result_accepted: bool
                result_reason: str | None
                if (
                    isinstance(previous_ns, bool)
                    or not isinstance(previous_ns, int)
                    or isinstance(current_ns, bool)
                    or not isinstance(current_ns, int)
                    or current_ns <= previous_ns
                ):
                    result_accepted = False
                    result_reason = "SNAPSHOT_MONOTONIC_ORDER_INVALID"
                    snapshot_gap_seconds = None
                else:
                    provenance = audit_snapshot_pair_provenance(pair, records)
                    result_accepted = provenance.accepted
                    result_reason = provenance.reason
                    snapshot_gap_seconds = (
                        (current_ns - previous_ns) / 1e9 if result_accepted else None
                    )
                pair_results.append(
                    {
                        "pair_id": pair.pair_id,
                        "accepted": result_accepted,
                        "reason": result_reason,
                        "snapshot_gap_seconds": snapshot_gap_seconds,
                    }
                )
                if not result_accepted:
                    issues.append(f"source_pair_rejected:{result_reason}")
        for identity, evidence in identities.items():
            previous_by_scope[(run_id, epoch_id, identity)] = evidence
        previous_collection_by_scope[scope] = collection_id
    return pair_results, issues


def _cadence_summary(
    collection_rows: Sequence[Mapping[str, Any]],
    request_by_id: Mapping[str, list[tuple[int, dict[str, Any]]]],
    completion_by_id: Mapping[str, list[tuple[int, dict[str, Any]]]],
    pair_results: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    ordered_requests: dict[tuple[object, object], list[tuple[int, int]]] = defaultdict(list)
    ordered_completions: dict[tuple[object, object], list[tuple[int, int]]] = defaultdict(list)
    durations: list[float] = []
    missing = 0
    invalid = 0
    excluded = 0
    empty = 0
    for collection_id, requests in request_by_id.items():
        completions = completion_by_id.get(collection_id, [])
        row = next((item for item in collection_rows if item["collection_id"] == collection_id), {})
        if len(requests) != 1 or len(completions) != 1:
            excluded += 1
            continue
        request_index, request = requests[0]
        completion_index, completion = completions[0]
        start_ns = request.get("started_monotonic_ns")
        end_ns = completion.get("completed_monotonic_ns")
        if (
            isinstance(start_ns, bool)
            or not isinstance(start_ns, int)
            or isinstance(end_ns, bool)
            or not isinstance(end_ns, int)
        ):
            missing += 1
            if not row.get("complete"):
                excluded += 1
            continue
        if end_ns < start_ns:
            invalid += 1
            excluded += 1
            continue
        if not row.get("complete"):
            excluded += 1
            continue
        scope = (request.get("run_id"), request.get("datapath_epoch_id"))
        ordered_requests[scope].append((request_index, start_ns))
        ordered_completions[scope].append((completion_index, end_ns))
        durations.append((end_ns - start_ns) / 1e9)
        if completion.get("record_count") == 0:
            empty += 1
    request_gaps: list[float] = []
    completion_gaps: list[float] = []
    snapshot_gaps = [
        float(pair["snapshot_gap_seconds"])
        for pair in pair_results
        if pair.get("accepted") is True
        and isinstance(pair.get("snapshot_gap_seconds"), (int, float))
        and not isinstance(pair.get("snapshot_gap_seconds"), bool)
    ]
    ordering_errors = 0
    gap_sources = (
        (ordered_requests, request_gaps),
        (ordered_completions, completion_gaps),
    )
    for values, output in gap_sources:
        for samples in values.values():
            samples.sort()
            for prior, current in zip(samples, samples[1:], strict=False):
                if current[1] >= prior[1]:
                    output.append((current[1] - prior[1]) / 1e9)
                else:
                    ordering_errors += 1
    return {
        "request_gap_samples": len(request_gaps),
        "request_gaps_seconds": request_gaps,
        "completion_gap_samples": len(completion_gaps),
        "completion_gaps_seconds": completion_gaps,
        "source_verified_snapshot_gap_samples": len(snapshot_gaps),
        "source_verified_snapshot_gaps_seconds": snapshot_gaps,
        "duration_samples": len(durations),
        "collection_durations_seconds": durations,
        "request_gap_summary_seconds": _summary(request_gaps),
        "completion_gap_summary_seconds": _summary(completion_gaps),
        "snapshot_gap_summary_seconds": _summary(snapshot_gaps),
        "collection_duration_summary_seconds": _summary(durations),
        "missing_timing_collections": missing,
        "invalid_timing_collections": invalid,
        "incomplete_or_invalid_collections": excluded,
        "empty_complete_collections": empty,
        "monotonic_order_errors": ordering_errors,
        "max_gap_policy_seconds": None,
    }


def _summary(values: Sequence[float]) -> dict[str, float] | None:
    if not values:
        return None
    return {
        "minimum": min(values),
        "median": statistics.median(values),
        "maximum": max(values),
    }
