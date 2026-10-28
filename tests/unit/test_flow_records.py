"""Tests for deterministic, technology-neutral flow feature extraction."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.sdn_defense.flow_records import (
    FlowRecordError,
    deduplicate_records,
    extract_flow_record,
    extract_ryu_log,
    read_jsonl,
    write_jsonl,
)


def _sample(**updates: object) -> dict[str, object]:
    observation: dict[str, object] = {
        "event_type": "flow_statistics",
        "timestamp": "2026-10-05T17:44:58.250441+00:00",
        "datapath_id": "0000000000000001",
        "table_id": 0,
        "priority": 100,
        "cookie": "0x534432",
        "packet_count": 1,
        "byte_count": 74,
        "duration_seconds": 1,
        "match": (
            "OFPMatch(oxm_fields={'eth_type': 2048, 'ipv4_src': '10.0.0.1', "
            "'ipv4_dst': '10.0.0.3', 'ip_proto': 6, 'tcp_dst': 18080})"
        ),
    }
    observation.update(updates)
    return observation


def test_extracts_normal_ryu_flow_with_canonical_values() -> None:
    record = extract_flow_record(_sample())
    assert record.protocol == "tcp"
    assert (record.src_ip, record.dst_ip) == ("10.0.0.1", "10.0.0.3")
    assert record.dst_port == 18080
    assert record.packet_count == 1
    assert record.byte_count == 74
    assert record.observed_at == "2026-10-05T17:44:58.250441Z"
    assert record.tcp_flags is None
    assert record.is_empty is False


def test_missing_features_remain_null_and_empty_counters_are_marked() -> None:
    record = extract_flow_record(
        {"event_type": "flow_statistics", "packet_count": 0, "byte_count": 0}
    )
    assert record.observed_at is None
    assert record.src_ip is None
    assert record.duration_seconds is None
    assert record.is_empty is True


@pytest.mark.parametrize("duration", [float("nan"), float("inf"), -1, -float("inf")])
def test_rejects_nonfinite_or_negative_duration(duration: float) -> None:
    with pytest.raises(FlowRecordError):
        extract_flow_record(_sample(duration_seconds=duration))


def test_rejects_invalid_counters_ports_and_naive_timestamps() -> None:
    for change in (
        {"packet_count": -1},
        {"match": {"tcp_dst": 65536}},
        {"timestamp": "2026-10-05T17:44:58"},
    ):
        with pytest.raises(FlowRecordError):
            extract_flow_record(_sample(**change))


def test_duplicate_ids_are_stable_and_deduplication_preserves_order() -> None:
    first = extract_flow_record(_sample())
    same = extract_flow_record(_sample())
    later = extract_flow_record(_sample(timestamp="2026-10-05T17:44:59Z"))
    assert first.record_id == same.record_id
    assert first.record_id != later.record_id
    assert deduplicate_records([first, same, later]) == [first, later]


def test_jsonl_round_trip_is_byte_deterministic_and_validated(tmp_path: Path) -> None:
    records = [extract_flow_record(_sample()), extract_flow_record(_sample(packet_count=0))]
    first_path = tmp_path / "one.jsonl"
    second_path = tmp_path / "two.jsonl"
    write_jsonl(records, first_path)
    write_jsonl(records, second_path)
    assert first_path.read_bytes() == second_path.read_bytes()
    assert read_jsonl(first_path) == records
    assert read_jsonl(first_path, deduplicate=True) == records

    payload = json.loads(first_path.read_text().splitlines()[0])
    payload["record_id"] = "not-the-content-hash"
    first_path.write_text(json.dumps(payload) + "\n")
    with pytest.raises(FlowRecordError, match="record_id"):
        read_jsonl(first_path)


def test_extracts_only_flow_stats_from_ryu_log(tmp_path: Path) -> None:
    path = tmp_path / "controller.log"
    path.write_text(
        'stage2_event={"event_type":"switch_features_received"}\n'
        'stage2_event={"event_type":"flow_statistics","packet_count":0,"byte_count":0}\n'
    )
    assert len(extract_ryu_log(path)) == 1
