"""Pure tests for live telemetry contracts; no detector or enforcement is involved."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from src.sdn_defense.flow_records import FlowRecord, extract_flow_record
from src.sdn_defense.telemetry import (
    OBSERVATION_PROVENANCE_VERSION,
    CanonicalRuleIdentity,
    CounterDeltaEngine,
    FlowSnapshot,
    ObservationType,
    ScenarioRunMetadata,
    TelemetryObservation,
    TelemetryScope,
    TimingSource,
    WindowReason,
    WindowValidity,
    flow_snapshot_from_observation,
)
from src.sdn_defense.telemetry_io import (
    DatapathEpochTracker,
    MultipartFlowStatsAssembler,
    TelemetryJsonlRecorder,
    validate_telemetry_jsonl,
)


def _record(
    *,
    at: datetime,
    packets: int | None = 10,
    bytes_: int | None = 500,
    cookie: str = "0x10",
    match: str = "OFPMatch(oxm_fields={'eth_type': 2048, 'ipv4_src': '10.0.0.1'})",
) -> FlowRecord:
    return extract_flow_record(
        {
            "event_type": "flow_statistics",
            "timestamp": at.isoformat(),
            "datapath_id": "1",
            "table_id": 0,
            "priority": 10,
            "cookie": cookie,
            "packet_count": packets,
            "byte_count": bytes_,
            "match": match,
        }
    )


def test_canonical_identity_uses_normalized_logical_selectors() -> None:
    at = datetime.now(UTC)
    first = CanonicalRuleIdentity.from_flow_record(_record(at=at))
    same = CanonicalRuleIdentity.from_flow_record(
        _record(at=at, match="OFPMatch(oxm_fields={ 'ipv4_src' : '10.0.0.1', 'eth_type':2048 })")
    )
    assert first.identity_id == same.identity_id
    assert (
        first.identity_id
        != CanonicalRuleIdentity.from_flow_record(
            _record(at=at, match="OFPMatch(oxm_fields={'eth_type': 2048, 'ipv4_src': '10.0.0.2'})")
        ).identity_id
    )
    assert (
        first.identity_id
        != CanonicalRuleIdentity.from_flow_record(_record(at=at, cookie="0x11")).identity_id
    )
    assert (
        first.identity_id
        != CanonicalRuleIdentity.from_flow_record(
            extract_flow_record({**_record(at=at).to_dict(), "table_id": 1})
        ).identity_id
    )
    assert (
        first.identity_id
        != CanonicalRuleIdentity.from_flow_record(
            extract_flow_record({**_record(at=at).to_dict(), "priority": 11})
        ).identity_id
    )


def test_counter_engine_emits_baseline_then_measured_rule_delta() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    engine = CounterDeltaEngine()
    baseline = engine.observe(
        FlowSnapshot(_record(at=start, packets=10, bytes_=500), 1_000_000_000)
    )
    assert baseline.validity is WindowValidity.BASELINE_ONLY
    window = engine.observe(
        FlowSnapshot(
            _record(at=start + timedelta(seconds=2), packets=15, bytes_=900), 3_000_000_000
        )
    )
    assert window.validity is WindowValidity.VALID
    assert window.rule_packet_delta == 5
    assert window.rule_byte_delta == 400
    assert window.measured_elapsed_seconds == 2
    assert window.rule_packet_rate_per_second == 2.5
    assert window.timing_source is TimingSource.COLLECTOR_MONOTONIC
    assert window.source_record_ids[0] != window.source_record_ids[1]
    assert not {"Flow Pkts/s", "Flow Byts/s", "Flow Duration"} & set(window.to_dict())


def test_counter_reset_missing_counter_and_repeated_snapshot_are_not_zero() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    engine = CounterDeltaEngine()
    first = _record(at=at, packets=10, bytes_=500)
    engine.observe(FlowSnapshot(first, 1_000_000_000))
    repeated = engine.observe(FlowSnapshot(first, 2_000_000_000))
    assert repeated.reason is WindowReason.REPEATED_OBSERVATION
    assert repeated.rule_packet_delta is None

    reset = engine.observe(
        FlowSnapshot(_record(at=at + timedelta(seconds=1), packets=2, bytes_=100), 3_000_000_000)
    )
    assert reset.reason is WindowReason.COUNTER_RESET
    assert reset.rule_packet_delta is None

    missing = engine.observe(
        FlowSnapshot(_record(at=at + timedelta(seconds=2), packets=None, bytes_=120), 4_000_000_000)
    )
    assert missing.validity is WindowValidity.PARTIAL
    assert missing.rule_packet_delta is None
    assert missing.rule_byte_delta == 20


def test_rule_replacement_and_run_boundary_do_not_pair_counters() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    engine = CounterDeltaEngine()
    engine.observe(FlowSnapshot(_record(at=at), 1_000_000_000, "run-a"))
    replacement = engine.observe(
        FlowSnapshot(_record(at=at + timedelta(seconds=1), cookie="0x11"), 2_000_000_000, "run-a")
    )
    assert replacement.reason is WindowReason.FIRST_OBSERVATION
    boundary = engine.observe(
        FlowSnapshot(_record(at=at + timedelta(seconds=2)), 3_000_000_000, "run-b")
    )
    assert boundary.reason is WindowReason.RUN_BOUNDARY
    assert boundary.rule_packet_delta is None


def test_gap_missing_time_disappearance_and_disconnect_are_explicit() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    engine = CounterDeltaEngine(maximum_gap_seconds=2)
    engine.observe(FlowSnapshot(_record(at=at), 1_000_000_000, "r"))
    assert (
        engine.close_missing(
            "1", (), snapshot_complete=False, observed_at=at + timedelta(seconds=1)
        )
        == ()
    )
    gap = engine.observe(FlowSnapshot(_record(at=at + timedelta(seconds=3)), 4_000_000_000, "r"))
    assert gap.reason is WindowReason.OBSERVATION_GAP
    closed = engine.close_missing(
        "1",
        (),
        snapshot_complete=True,
        observed_at=at + timedelta(seconds=4),
        collector_monotonic_ns=5_000_000_000,
    )
    assert len(closed) == 1 and closed[0].reason is WindowReason.RULE_DISAPPEARED
    engine.observe(FlowSnapshot(_record(at=at + timedelta(seconds=5)), 6_000_000_000, "r"))
    disconnected = engine.datapath_disconnected(
        "1", observed_at=at + timedelta(seconds=6), collector_monotonic_ns=7_000_000_000
    )
    assert disconnected[0].reason is WindowReason.DATAPATH_DISCONNECTED
    reconnected = engine.observe(
        FlowSnapshot(_record(at=at + timedelta(seconds=7)), 8_000_000_000, "r")
    )
    assert reconnected.validity is WindowValidity.BASELINE_ONLY


def test_counter_engine_gap_boundary_is_inclusive_and_boolean_limit_is_rejected() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    engine = CounterDeltaEngine(maximum_gap_seconds=2.0)
    first = _record(at=at, packets=10, bytes_=500)
    engine.observe(FlowSnapshot(first, 1_000_000_000, "run"))
    boundary = engine.observe(
        FlowSnapshot(
            _record(at=at + timedelta(seconds=2), packets=12, bytes_=520),
            3_000_000_000,
            "run",
        )
    )
    assert boundary.validity is WindowValidity.VALID
    assert boundary.measured_elapsed_seconds == 2.0
    assert boundary.rule_packet_delta == 2

    with pytest.raises(ValueError, match="finite and positive"):
        CounterDeltaEngine(maximum_gap_seconds=True)


def test_observation_contract_provenance_scope_and_label_guard() -> None:
    observed_at = datetime.now(UTC)
    scope = TelemetryScope.from_mapping(
        "0000000000000001", {"in_port": 1, "src_mac": "02:00:00:00:00:01"}
    )
    observation = TelemetryObservation.create(
        observation_id="obs-1",
        observation_type=ObservationType.ARP_PACKET_IN,
        observed_at=observed_at,
        source="ryu_packet_in",
        scope=scope,
        payload={"arp_opcode": 1},
        provenance_version=OBSERVATION_PROVENANCE_VERSION,
        run_id="run-1",
    )
    assert observation.to_dict()["run_id"] == "run-1"
    with pytest.raises(ValueError, match="attack labels"):
        TelemetryObservation.create(
            observation_id="obs-2",
            observation_type=ObservationType.ARP_PACKET_IN,
            observed_at=observed_at,
            source="ryu_packet_in",
            scope=None,
            payload={"is_attack": False},
            provenance_version=OBSERVATION_PROVENANCE_VERSION,
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        TelemetryObservation.create(
            observation_id="obs-3",
            observation_type=ObservationType.ETHERNET_PACKET_IN,
            observed_at=datetime.now(),
            source="ryu_packet_in",
            scope=None,
            payload={},
            provenance_version=OBSERVATION_PROVENANCE_VERSION,
        )


def test_scenario_run_metadata_is_explicit_and_validated() -> None:
    started = datetime(2026, 1, 1, tzinfo=UTC)
    metadata = ScenarioRunMetadata(
        run_id="run-1",
        scenario_id="port-scan",
        start_at=started,
        end_at=started + timedelta(seconds=2),
        topology_config_id="sha256:abc",
        source_scope=(("host", "h2"),),
        destination_scope=(("host", "h3"),),
        protocol="TCP",
        ports=(22, 80),
    )
    assert metadata.to_dict()["scenario_id"] == "port-scan"
    assert metadata.to_dict()["protocol_scope"] == {"protocol": "TCP", "ports": [22, 80]}


def test_invalid_elapsed_time_produces_no_rates() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    engine = CounterDeltaEngine()
    engine.observe(FlowSnapshot(_record(at=at), 10))
    same_clock = engine.observe(FlowSnapshot(_record(at=at + timedelta(seconds=1), packets=12), 10))
    assert same_clock.reason is WindowReason.INVALID_ELAPSED_TIME
    assert same_clock.rule_packet_rate_per_second is None


def test_ryu_snapshot_conversion_preserves_collector_monotonic_time() -> None:
    observation = {
        "event_type": "flow_statistics",
        "timestamp": "2026-01-01T00:00:00Z",
        "datapath_id": "1",
        "table_id": 0,
        "priority": 1,
        "cookie": "0x1",
        "packet_count": 5,
        "byte_count": 200,
        "duration_seconds": 1,
        "match": "OFPMatch()",
        "collector_monotonic_ns": 1234,
        "collection_id": "controller:0000000000000001:1:00000001:0000000a",
        "datapath_epoch_id": "controller:0000000000000001:1",
    }
    snapshot = flow_snapshot_from_observation(observation, run_id="run-1")
    assert snapshot.record.packet_count == 5
    assert snapshot.collector_monotonic_ns == 1234
    assert snapshot.run_id == "run-1"
    assert snapshot.collection_id == observation["collection_id"]
    assert snapshot.datapath_epoch_id == observation["datapath_epoch_id"]


def test_multipart_one_part_and_empty_collection_are_complete(tmp_path: Path) -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assembler = MultipartFlowStatsAssembler()
    assembler.start(
        datapath_id=1,
        xid=10,
        started_at=at,
        started_monotonic_ns=100,
        datapath_epoch_id="epoch-a",
        run_id="r",
    )
    collection = assembler.add_part(
        datapath_id=1,
        xid=10,
        datapath_epoch_id="epoch-a",
        records=[{"cookie": "0x1"}],
        more=False,
        received_at=at + timedelta(milliseconds=2),
        received_monotonic_ns=2_000_100,
    )
    assert collection is not None and collection.records == ({"cookie": "0x1"},)
    assert collection.run_id == "r"

    assembler.start(
        datapath_id=1, xid=11, started_at=at, started_monotonic_ns=100, datapath_epoch_id="epoch-a"
    )
    empty = assembler.add_part(
        datapath_id=1,
        xid=11,
        datapath_epoch_id="epoch-a",
        records=[],
        more=False,
        received_at=at + timedelta(milliseconds=1),
        received_monotonic_ns=1_000_100,
    )
    assert empty is not None and empty.records == ()


def test_multipart_interleaving_timeout_disconnect_and_wrong_datapath() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assembler = MultipartFlowStatsAssembler(timeout_seconds=1)
    assembler.start(
        datapath_id=1,
        xid=10,
        started_at=at,
        started_monotonic_ns=100,
        datapath_epoch_id="epoch-a",
        run_id="a",
    )
    assembler.start(
        datapath_id=1,
        xid=11,
        started_at=at,
        started_monotonic_ns=100,
        datapath_epoch_id="epoch-a",
        run_id="b",
    )
    assert (
        assembler.add_part(
            datapath_id=1,
            xid=10,
            datapath_epoch_id="epoch-a",
            records=[{"part": 1}],
            more=True,
            received_at=at,
            received_monotonic_ns=200,
        )
        is None
    )
    with pytest.raises(KeyError, match="matching datapath/XID"):
        assembler.add_part(
            datapath_id=2,
            xid=10,
            datapath_epoch_id="epoch-a",
            records=[],
            more=False,
            received_at=at,
            received_monotonic_ns=300,
        )
    completed = assembler.add_part(
        datapath_id=1,
        xid=11,
        datapath_epoch_id="epoch-a",
        records=[{"part": 2}],
        more=False,
        received_at=at + timedelta(milliseconds=1),
        received_monotonic_ns=400,
    )
    assert completed is not None and completed.run_id == "b"
    assembler.start(
        datapath_id=1, xid=13, started_at=at, started_monotonic_ns=500, datapath_epoch_id="epoch-a"
    )
    assert (
        assembler.add_part(
            datapath_id=1,
            xid=13,
            datapath_epoch_id="epoch-a",
            records=[{"part": 1}],
            more=True,
            received_at=at,
            received_monotonic_ns=600,
        )
        is None
    )
    final = assembler.add_part(
        datapath_id=1,
        xid=13,
        datapath_epoch_id="epoch-a",
        records=[{"part": 2}],
        more=False,
        received_at=at + timedelta(milliseconds=2),
        received_monotonic_ns=2_000_500,
    )
    assert final is not None and final.parts_received == 2
    assert final.records == ({"part": 1}, {"part": 2})
    assert assembler.expire(1_000_000_101)[0]["reason"] == "multipart_timeout"
    assembler.start(
        datapath_id=1, xid=14, started_at=at, started_monotonic_ns=100, datapath_epoch_id="epoch-a"
    )
    assert assembler.disconnect(1)[0]["reason"] == "datapath_disconnected"


def test_multipart_duplicate_part_is_rejected() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assembler = MultipartFlowStatsAssembler()
    assembler.start(
        datapath_id=1, xid=1, started_at=at, started_monotonic_ns=1, datapath_epoch_id="epoch-a"
    )
    fragment: list[dict[str, object]] = [{"table_id": 0}]
    assembler.add_part(
        datapath_id=1,
        xid=1,
        datapath_epoch_id="epoch-a",
        records=fragment,
        more=True,
        received_at=at,
        received_monotonic_ns=2,
    )
    with pytest.raises(ValueError, match="duplicate"):
        assembler.add_part(
            datapath_id=1,
            xid=1,
            datapath_epoch_id="epoch-a",
            records=fragment,
            more=True,
            received_at=at,
            received_monotonic_ns=3,
        )


def test_synthetic_datapath_epochs_follow_connection_object_lifecycle() -> None:
    tracker = DatapathEpochTracker()
    at = datetime(2026, 1, 1, tzinfo=UTC)
    first_connection = object()
    second_connection = object()
    first = tracker.connect(1, first_connection, observed_at=at, observed_monotonic_ns=10).epoch
    duplicate_event = tracker.connect(
        1, first_connection, observed_at=at, observed_monotonic_ns=11
    ).epoch
    assert duplicate_event.epoch_id == first.epoch_id

    replacement = tracker.connect(
        1, second_connection, observed_at=at + timedelta(seconds=1), observed_monotonic_ns=20
    )
    assert replacement.epoch.epoch_id != first.epoch_id
    assert replacement.replaced_epoch is not None
    assert replacement.replaced_epoch.state == "AMBIGUOUS"
    old_epoch = tracker.epoch_for_connection(1, first_connection)
    assert old_epoch is not None
    assert old_epoch.state == "AMBIGUOUS"
    active_epoch = tracker.active_epoch(1)
    assert active_epoch is not None
    assert active_epoch.epoch_id == replacement.epoch.epoch_id

    # A late DEAD event for the old connection cannot invalidate the new one.
    disconnected_old = tracker.disconnect(1, first_connection)
    assert disconnected_old is not None
    assert disconnected_old.epoch_id == first.epoch_id
    active_epoch = tracker.active_epoch(1)
    assert active_epoch is not None
    assert active_epoch.epoch_id == replacement.epoch.epoch_id
    disconnected_current = tracker.disconnect(1, second_connection)
    assert disconnected_current is not None
    assert disconnected_current.state == "CLOSED"
    assert tracker.active_epoch(1) is None

    other_connection = object()
    other = tracker.connect(2, other_connection, observed_at=at, observed_monotonic_ns=30).epoch
    invalidated = tracker.invalidate_all()
    assert len(invalidated) == 1
    assert invalidated[0].epoch_id == other.epoch_id
    assert invalidated[0].state == "AMBIGUOUS"
    assert tracker.active_epoch(2) is None

    # Reuse of one datapath object after close cannot establish a fresh
    # transport generation, so the replacement stays inactive/ambiguous.
    reused = tracker.connect(1, second_connection, observed_at=at, observed_monotonic_ns=40)
    assert reused.epoch.epoch_id != replacement.epoch.epoch_id
    assert reused.epoch.state == "AMBIGUOUS"
    assert tracker.active_epoch(1) is None


def test_reconnect_cancels_old_epoch_collection_before_same_xid_reuse() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    tracker = DatapathEpochTracker()
    assembler = MultipartFlowStatsAssembler()
    first_connection, second_connection = object(), object()
    first_epoch = tracker.connect(
        1, first_connection, observed_at=at, observed_monotonic_ns=1
    ).epoch
    assembler.start(
        datapath_id=1,
        xid=100,
        started_at=at,
        started_monotonic_ns=10,
        datapath_epoch_id=first_epoch.epoch_id,
        run_id="synthetic-run",
    )
    second_epoch = tracker.connect(
        1,
        second_connection,
        observed_at=at + timedelta(seconds=1),
        observed_monotonic_ns=1_000_000_001,
    )
    assert second_epoch.replaced_epoch is not None
    invalidated = assembler.invalidate_epoch(1, first_epoch.epoch_id, reason="synthetic_reconnect")
    assert invalidated[0]["terminal_state"] == "DISCONNECTED"
    assembler.start(
        datapath_id=1,
        xid=100,
        started_at=at + timedelta(seconds=1),
        started_monotonic_ns=1_000_000_010,
        datapath_epoch_id=second_epoch.epoch.epoch_id,
        run_id="synthetic-run",
    )
    with pytest.raises(KeyError, match="matching datapath/XID"):
        assembler.add_part(
            datapath_id=1,
            xid=100,
            datapath_epoch_id=first_epoch.epoch_id,
            records=[{"stale": True}],
            more=False,
            received_at=at + timedelta(seconds=1),
            received_monotonic_ns=1_000_000_020,
        )
    completed = assembler.add_part(
        datapath_id=1,
        xid=100,
        datapath_epoch_id=second_epoch.epoch.epoch_id,
        records=[{"current": True}],
        more=False,
        received_at=at + timedelta(seconds=1),
        received_monotonic_ns=1_000_000_021,
    )
    assert completed is not None
    assert completed.datapath_epoch_id == second_epoch.epoch.epoch_id


def test_multipart_epoch_mismatch_timeout_disconnect_and_global_invalidation() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assembler = MultipartFlowStatsAssembler(timeout_seconds=1)
    assembler.start(
        datapath_id=1,
        xid=20,
        started_at=at,
        started_monotonic_ns=100,
        datapath_epoch_id="epoch-a",
    )
    with pytest.raises(KeyError, match="matching datapath/XID"):
        assembler.add_part(
            datapath_id=1,
            xid=20,
            datapath_epoch_id="epoch-b",
            records=[],
            more=False,
            received_at=at,
            received_monotonic_ns=200,
        )
    timeout = assembler.expire(1_000_000_100)
    assert timeout[0]["datapath_epoch_id"] == "epoch-a"
    assert timeout[0]["terminal_state"] == "TIMED_OUT"
    with pytest.raises(KeyError, match="matching datapath/XID"):
        assembler.add_part(
            datapath_id=1,
            xid=20,
            datapath_epoch_id="epoch-a",
            records=[],
            more=False,
            received_at=at,
            received_monotonic_ns=1_000_000_101,
        )

    assembler.start(
        datapath_id=1,
        xid=22,
        started_at=at,
        started_monotonic_ns=2_000_000_000,
        datapath_epoch_id="epoch-a",
        run_id="run-a",
    )
    cancelled_on_run = assembler.cancel_for_run_change("run-b")
    assert cancelled_on_run[0]["terminal_state"] == "CANCELLED"
    assert cancelled_on_run[0]["reason"] == "run_boundary_invalidated_pending_collection"
    with pytest.raises(KeyError, match="matching datapath/XID"):
        assembler.add_part(
            datapath_id=1,
            xid=22,
            datapath_epoch_id="epoch-a",
            records=[],
            more=False,
            received_at=at,
            received_monotonic_ns=2_000_000_001,
        )

    assembler.start(
        datapath_id=1,
        xid=23,
        started_at=at,
        started_monotonic_ns=2_000_000_000,
        datapath_epoch_id="epoch-a",
    )
    cancelled = assembler.disconnect(1)[0]
    assert cancelled["terminal_state"] == "DISCONNECTED"
    assembler.start(
        datapath_id=2,
        xid=22,
        started_at=at,
        started_monotonic_ns=2_000_000_000,
        datapath_epoch_id="epoch-c",
    )
    ambiguous = assembler.invalidate_all(reason="unknown_disconnect")
    assert ambiguous[0]["terminal_state"] == "AMBIGUOUS"
    assert ambiguous[0]["datapath_epoch_id"] == "epoch-c"


def test_duplicate_terminal_reply_cannot_complete_another_collection() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assembler = MultipartFlowStatsAssembler()
    assembler.start(
        datapath_id=1,
        xid=5,
        started_at=at,
        started_monotonic_ns=1,
        datapath_epoch_id="epoch-a",
    )
    first = assembler.add_part(
        datapath_id=1,
        xid=5,
        datapath_epoch_id="epoch-a",
        records=[{"cookie": 1}],
        more=False,
        received_at=at,
        received_monotonic_ns=2,
    )
    assert first is not None
    with pytest.raises(KeyError, match="matching datapath/XID"):
        assembler.add_part(
            datapath_id=1,
            xid=5,
            datapath_epoch_id="epoch-a",
            records=[{"cookie": 1}],
            more=False,
            received_at=at,
            received_monotonic_ns=3,
        )
    with pytest.raises(ValueError, match="stale or out of order"):
        assembler.start(
            datapath_id=1,
            xid=5,
            started_at=at,
            started_monotonic_ns=4,
            datapath_epoch_id="epoch-a",
        )


def test_multipart_rejects_non_monotonic_parts_and_stale_request_xids() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assembler = MultipartFlowStatsAssembler()
    assembler.start(
        datapath_id=1,
        xid=1,
        started_at=at,
        started_monotonic_ns=10,
        datapath_epoch_id="epoch-a",
    )
    assembler.add_part(
        datapath_id=1,
        xid=1,
        datapath_epoch_id="epoch-a",
        records=[{"part": 1}],
        more=True,
        received_at=at,
        received_monotonic_ns=20,
    )
    with pytest.raises(ValueError, match="timestamp order"):
        assembler.add_part(
            datapath_id=1,
            xid=1,
            datapath_epoch_id="epoch-a",
            records=[{"part": 2}],
            more=False,
            received_at=at,
            received_monotonic_ns=19,
        )
    with pytest.raises(ValueError, match="stale or out of order"):
        assembler.start(
            datapath_id=1,
            xid=1,
            started_at=at,
            started_monotonic_ns=30,
            datapath_epoch_id="epoch-a",
        )


def test_reply_arriving_after_timeout_is_not_completed() -> None:
    at = datetime(2026, 1, 1, tzinfo=UTC)
    assembler = MultipartFlowStatsAssembler(timeout_seconds=1)
    assembler.start(
        datapath_id=1,
        xid=1,
        started_at=at,
        started_monotonic_ns=10,
        datapath_epoch_id="epoch-a",
    )
    with pytest.raises(TimeoutError, match="multipart_timeout"):
        assembler.add_part(
            datapath_id=1,
            xid=1,
            datapath_epoch_id="epoch-a",
            records=[{"counter": 1}],
            more=False,
            received_at=at + timedelta(seconds=1),
            received_monotonic_ns=1_000_000_010,
        )


def test_jsonl_recorder_and_replay_validate_window_provenance(tmp_path: Path) -> None:
    path = tmp_path / "telemetry.jsonl"
    at = datetime(2026, 1, 1, tzinfo=UTC)
    recorder = TelemetryJsonlRecorder(path, source_version="test")
    record = _record(at=at, packets=10, bytes_=500)
    recorder.write(
        "flow_snapshot",
        timestamp=at.isoformat(),
        run_id="r1",
        collection_id="synthetic-collection",
        datapath_epoch_id="synthetic-epoch",
        flow_record=record.to_dict(),
    )
    recorder.write(
        "observation_window",
        observation_window={
            "schema_version": 1,
            "window_id": "window-1",
            "provenance_version": OBSERVATION_PROVENANCE_VERSION,
            "run_id": "r1",
            "source_record_ids": [record.record_id],
            "end_at": at.isoformat(),
        },
    )
    recorder.close()
    counts = validate_telemetry_jsonl(path)
    assert counts == {
        "recorder_metadata": 1,
        "flow_snapshot": 1,
        "observation_window": 1,
        "incomplete_runs": 0,
    }
    lines = path.read_text(encoding="utf-8").splitlines()
    snapshot = json.loads(lines[1])
    assert snapshot["schema_version"] == 2
    snapshot["schema_version"] = 1
    historical_path = tmp_path / "historical-v1.jsonl"
    historical_path.write_text("\n".join([lines[0], json.dumps(snapshot), lines[2]]) + "\n")
    assert validate_telemetry_jsonl(historical_path)["flow_snapshot"] == 1


def test_jsonl_replay_accepts_bounded_packet_evidence_coverage(tmp_path: Path) -> None:
    path = tmp_path / "packet-evidence.jsonl"
    recorder = TelemetryJsonlRecorder(path, source_version="test")
    recorder.write(
        "packet_evidence_coverage",
        timestamp="2026-10-08T00:00:01Z",
        run_id="run-1",
        observations_accepted=2,
        observations_dropped=1,
        dropped_rate_limit=1,
        dropped_run_limit=0,
        max_observations_per_second=4,
        max_observations_per_run=16,
        memory_queue_capacity=0,
    )
    recorder.close()

    counts = validate_telemetry_jsonl(path)

    assert counts["packet_evidence_coverage"] == 1
    assert counts["incomplete_runs"] == 0


def test_jsonl_replay_rejects_unknown_schema_and_wrong_run_reference(tmp_path: Path) -> None:
    path = tmp_path / "invalid.jsonl"
    path.write_text('{"record_type":"flow_snapshot","schema_version":99}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="line 1"):
        validate_telemetry_jsonl(path)


def test_jsonl_replay_reports_incomplete_run_and_rejects_reversed_time(tmp_path: Path) -> None:
    path = tmp_path / "incomplete.jsonl"
    recorder = TelemetryJsonlRecorder(path, source_version="test")
    recorder.write(
        "run_boundary",
        timestamp="2026-01-01T00:00:00Z",
        run_id="run-open",
        state="started",
    )
    recorder.close()
    counts = validate_telemetry_jsonl(path)
    assert counts["incomplete_runs"] == 1

    path = tmp_path / "ordered.jsonl"
    recorder = TelemetryJsonlRecorder(path, source_version="test")
    recorder.write(
        "run_boundary",
        timestamp="2026-01-01T00:00:02Z",
        run_id="run-time",
        state="started",
    )
    recorder.write(
        "run_boundary",
        timestamp="2026-01-01T00:00:01Z",
        run_id="run-time",
        state="ended",
    )
    recorder.close()
    with pytest.raises(ValueError, match="backwards"):
        validate_telemetry_jsonl(path)
