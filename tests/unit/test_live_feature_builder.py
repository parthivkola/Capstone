"""Synthetic-only tests for the Stage 7I.2 rule-counter feature builder."""

from datetime import UTC, datetime, timedelta

import pytest

from src.sdn_defense.flow_records import extract_flow_record
from src.sdn_defense.live_features import (
    LIVE_FEATURE_ORDER,
    LIVE_FEATURE_SCHEMA_ID,
    CounterCoverageState,
    FeatureState,
    FeatureWindowState,
    LiveRuleFeatureVector,
    RuleCounterFeatureBuilder,
    SnapshotEvidence,
    SnapshotPair,
)
from src.sdn_defense.live_provenance import audit_snapshot_pair_provenance
from src.sdn_defense.telemetry import FlowSnapshot


def _snapshot(
    *,
    name: str,
    second: int,
    monotonic_ns: int | None,
    packets: int | None = 10,
    bytes_: int | None = 500,
    cookie: str = "0x10",
    run_id: str | None = "run-synthetic",
    epoch: str = "synthetic-controller:0000000000000001:1",
    complete: bool = True,
    match: str = "OFPMatch(oxm_fields={'eth_type': 2048, 'ipv4_src': '10.0.0.1'})",
) -> SnapshotEvidence:
    at = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=second)
    record = extract_flow_record(
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
    xid = 1 if name == "old" else 2
    collection_id = f"{epoch}:0000000000000001:{xid:08x}"
    return SnapshotEvidence(
        snapshot=FlowSnapshot(record, monotonic_ns, run_id, collection_id, epoch),
        collection_id=collection_id,
        collection_complete=complete,
        datapath_epoch_id=epoch,
    )


def _pair(
    *,
    previous: SnapshotEvidence | None = None,
    current: SnapshotEvidence | None = None,
    pair_id: str = "pair-1",
) -> SnapshotPair:
    return SnapshotPair(
        pair_id,
        previous or _snapshot(name="old", second=0, monotonic_ns=1_000_000_000),
        current or _snapshot(name="new", second=2, monotonic_ns=3_000_000_000),
    )


def _builder(maximum_gap_seconds: float = 10) -> RuleCounterFeatureBuilder:
    return RuleCounterFeatureBuilder(maximum_gap_seconds=maximum_gap_seconds)


def _source_records(pair: SnapshotPair, *, epoch: str | None = None) -> list[dict[str, object]]:
    """Synthetic recorder lifecycle, explicitly not emitted by a live Ryu run."""

    assert pair.previous is not None and pair.current is not None
    records: list[dict[str, object]] = [
        {
            "record_type": "connection_boundary",
            "schema_version": 2,
            "state": "connected",
            "datapath_id": "0000000000000001",
            "datapath_epoch_id": epoch or pair.previous.datapath_epoch_id,
            "controller_instance_id": "synthetic-controller",
            "epoch_sequence": 1,
        }
    ]
    for evidence in (pair.previous, pair.current):
        collection_id = evidence.collection_id
        observed_at = evidence.snapshot.record.observed_at
        xid = 1 if evidence is pair.previous else 2
        common: dict[str, object] = {
            "collection_id": collection_id,
            "datapath_id": "0000000000000001",
            "datapath_epoch_id": epoch or evidence.datapath_epoch_id,
            "xid": xid,
            "run_id": evidence.snapshot.run_id,
            "started_at": observed_at,
        }
        records.extend(
            [
                {
                    "record_type": "flow_collection",
                    "schema_version": 2,
                    "state": "requested",
                    **common,
                },
                {
                    "record_type": "flow_collection",
                    "schema_version": 2,
                    "complete": True,
                    "terminal_state": "COMPLETE",
                    "part_count": 1,
                    "completed_at": observed_at,
                    **common,
                },
                {
                    "record_type": "flow_snapshot",
                    "schema_version": 2,
                    "collection_id": collection_id,
                    "datapath_epoch_id": epoch or evidence.datapath_epoch_id,
                    "run_id": evidence.snapshot.run_id,
                    "flow_record": evidence.snapshot.record.to_dict(),
                },
            ]
        )
    return records


def test_positive_deltas_rates_schema_and_provenance() -> None:
    vector = _builder().build(
        _pair(
            current=_snapshot(
                name="new", second=2, monotonic_ns=3_000_000_000, packets=15, bytes_=900
            )
        )
    )
    assert vector.window_state is FeatureWindowState.VALID
    assert vector.feature_schema_id == LIVE_FEATURE_SCHEMA_ID
    assert vector.feature_order == LIVE_FEATURE_ORDER
    assert vector.predictor_values == (5, 400, 2.5, 200.0)
    assert all(state is FeatureState.MEASURED for state in vector.feature_validity)
    assert vector.source_flow_record_ids[0] != vector.source_flow_record_ids[1]
    assert vector.run_id == "run-synthetic"


def test_equal_counters_are_measured_zero_not_missing() -> None:
    vector = _builder().build(_pair())
    assert vector.predictor_values == (0, 0, 0.0, 0.0)
    assert vector.feature_validity == (FeatureState.MEASURED,) * 4


@pytest.mark.parametrize(
    ("previous", "current", "reason"),
    [
        (None, _snapshot(name="new", second=1, monotonic_ns=2_000_000_000), "MISSING"),
        (_snapshot(name="old", second=0, monotonic_ns=1_000_000_000), None, "MISSING"),
    ],
)
def test_missing_snapshot_is_incomplete_not_zero(
    previous: SnapshotEvidence | None,
    current: SnapshotEvidence | None,
    reason: str,
) -> None:
    vector = _builder().build(SnapshotPair("missing-pair", previous, current))
    assert vector.window_state is FeatureWindowState.INCOMPLETE
    assert all(value is None for value in vector.predictor_values)
    assert all(state is FeatureState.INCOMPLETE for state in vector.feature_validity)
    assert reason in (vector.invalid_reason or "")


def test_incomplete_collection_and_datapath_epoch_are_not_paired() -> None:
    incomplete = _builder().build(
        _pair(current=_snapshot(name="new", second=2, monotonic_ns=3_000_000_000, complete=False))
    )
    assert incomplete.invalid_reason == "INCOMPLETE_STATISTICS_COLLECTION"
    assert all(value is None for value in incomplete.predictor_values)

    old = _snapshot(name="old", second=0, monotonic_ns=1_000_000_000)
    new = _snapshot(
        name="new",
        second=2,
        monotonic_ns=3_000_000_000,
        epoch="synthetic-controller:0000000000000001:2",
    )
    epoch = _builder().build(_pair(previous=old, current=new))
    assert epoch.invalid_reason == "DATAPATH_EPOCH_BOUNDARY"


def test_missing_or_ambiguous_collection_provenance_is_rejected() -> None:
    snapshot = _snapshot(name="old", second=0, monotonic_ns=1_000_000_000)
    with pytest.raises(ValueError, match="collection_complete must be boolean"):
        SnapshotEvidence(
            snapshot=FlowSnapshot(snapshot.snapshot.record, 1_000_000_000, "run-synthetic"),
            collection_id="collection-with-unknown-completeness",
            collection_complete=None,  # type: ignore[arg-type]
            datapath_epoch_id="epoch-1",
        )
    with pytest.raises(ValueError, match="collection and datapath epoch IDs are required"):
        SnapshotEvidence(
            snapshot=snapshot.snapshot,
            collection_id="collection-1",
            collection_complete=True,
            datapath_epoch_id="",
        )


def test_maximum_gap_boundary_is_inclusive() -> None:
    vector = _builder(maximum_gap_seconds=2.0).build(
        _pair(
            previous=_snapshot(name="old", second=0, monotonic_ns=1_000_000_000),
            current=_snapshot(name="new", second=2, monotonic_ns=3_000_000_000, packets=12),
        )
    )
    assert vector.window_state is FeatureWindowState.VALID
    assert vector.measured_elapsed_seconds == 2.0
    assert vector.predictor_values == (2, 0, 1.0, 0.0)
    assert all(state is FeatureState.MEASURED for state in vector.feature_validity)


def test_synthetic_source_linked_completed_collections_are_accepted() -> None:
    pair = _pair()
    audit = audit_snapshot_pair_provenance(pair, _source_records(pair))
    assert audit.accepted
    assert audit.reason is None
    assert audit.datapath_epoch_id == "synthetic-controller:0000000000000001:1"
    vector = _builder().build_source_verified(pair, _source_records(pair))
    assert vector.predictor_values == (0, 0, 0.0, 0.0)

    multipart = _source_records(pair)
    multipart[2]["part_count"] = 2
    multipart[5]["part_count"] = 2
    assert audit_snapshot_pair_provenance(pair, multipart).accepted


def test_historical_schema_one_records_cannot_pass_source_verified_gate() -> None:
    pair = _pair()
    records = _source_records(pair)
    for record in records:
        if record.get("record_type") in {
            "connection_boundary",
            "flow_collection",
            "flow_snapshot",
        }:
            record["schema_version"] = 1

    audit = audit_snapshot_pair_provenance(pair, records)

    assert not audit.accepted
    assert audit.reason == "COLLECTION_REQUEST_OR_COMPLETION_NOT_UNIQUE"
    with pytest.raises(ValueError, match="snapshot provenance rejected"):
        _builder().build_source_verified(pair, records)


def test_timeout_or_incomplete_terminal_event_is_rejected() -> None:
    pair = _pair()
    records = _source_records(pair)
    records.append(
        {
            "record_type": "incomplete_collection",
            "collection_id": pair.previous.collection_id,  # type: ignore[union-attr]
            "complete": False,
            "reason": "multipart_timeout",
        }
    )
    audit = audit_snapshot_pair_provenance(pair, records)
    assert not audit.accepted
    assert audit.reason == "COLLECTION_HAS_INCOMPLETE_TERMINAL_EVENT"
    with pytest.raises(ValueError, match="snapshot provenance rejected"):
        _builder().build_source_verified(pair, records)


def test_missing_or_contradictory_epoch_lifecycle_is_rejected() -> None:
    pair = _pair()
    records = _source_records(pair)
    for record in records:
        if record.get("record_type") in {"connection_boundary", "flow_collection", "flow_snapshot"}:
            record.pop("datapath_epoch_id", None)
    audit = audit_snapshot_pair_provenance(pair, records)
    assert not audit.accepted
    assert audit.reason == "DATAPATH_EPOCH_SOURCE_LINK_MISSING_OR_CONTRADICTORY"

    records = _source_records(pair)
    records[0].pop("controller_instance_id", None)
    records[0].pop("epoch_sequence", None)
    audit = audit_snapshot_pair_provenance(pair, records)
    assert not audit.accepted
    assert audit.reason == "CONNECTION_EPOCH_IDENTITY_NOT_SOURCE_BACKED"

    records = _source_records(pair)
    records.insert(
        4,
        {
            "record_type": "connection_boundary",
            "state": "disconnected",
            "datapath_id": "1",
            "datapath_epoch_id": "synthetic-controller:0000000000000001:1",
        },
    )
    audit = audit_snapshot_pair_provenance(pair, records)
    assert not audit.accepted
    assert audit.reason in {
        "CONNECTION_EPOCH_NOT_OBSERVED_OR_CROSSED",
        "DATAPATH_EPOCH_CLOSED_BETWEEN_SNAPSHOTS",
    }

    previous = _snapshot(name="old", second=0, monotonic_ns=1_000_000_000)
    current = _snapshot(
        name="new",
        second=2,
        monotonic_ns=3_000_000_000,
        epoch="synthetic-controller:0000000000000001:2",
    )
    reconnected_pair = SnapshotPair("reconnected", previous, current)
    audit = audit_snapshot_pair_provenance(reconnected_pair, _source_records(reconnected_pair))
    assert not audit.accepted
    assert audit.reason == "DATAPATH_EPOCH_BOUNDARY"

    records = _source_records(pair)
    records.insert(
        1,
        {
            "record_type": "connection_boundary",
            "schema_version": 2,
            "state": "connected",
            "datapath_id": "1",
            "datapath_epoch_id": "synthetic-controller:0000000000000001:1",
            "controller_instance_id": "synthetic-controller",
            "epoch_sequence": 1,
        },
    )
    audit = audit_snapshot_pair_provenance(pair, records)
    assert not audit.accepted
    assert audit.reason == "CONNECTION_EPOCH_NOT_OBSERVED_OR_CROSSED"


def test_run_boundary_event_between_source_snapshots_is_rejected() -> None:
    pair = _pair()
    records = _source_records(pair)
    records.insert(
        4,
        {"record_type": "run_boundary", "run_id": "run-synthetic", "state": "ended"},
    )
    audit = audit_snapshot_pair_provenance(pair, records)
    assert not audit.accepted
    assert audit.reason == "RUN_BOUNDARY_EVENT_BETWEEN_SNAPSHOTS"

    records = _source_records(pair)
    records.insert(
        2,
        {"record_type": "run_boundary", "run_id": "run-synthetic", "state": "ended"},
    )
    audit = audit_snapshot_pair_provenance(pair, records)
    assert not audit.accepted
    assert audit.reason == "RUN_BOUNDARY_DURING_COLLECTION"

    records = _source_records(pair)
    records.insert(
        4,
        {
            "record_type": "connection_boundary",
            "state": "disconnected",
            "datapath_id": None,
            "datapath_epoch_id": None,
        },
    )
    audit = audit_snapshot_pair_provenance(pair, records)
    assert not audit.accepted


def test_no_numeric_gap_limit_is_selected_by_the_builder() -> None:
    with pytest.raises(TypeError):
        RuleCounterFeatureBuilder()  # type: ignore[call-arg]


def test_changed_rule_identity_and_run_boundary_are_rejected() -> None:
    old = _snapshot(name="old", second=0, monotonic_ns=1_000_000_000)
    changed_cookie = _snapshot(
        name="new", second=2, monotonic_ns=3_000_000_000, packets=20, cookie="0x11"
    )
    changed = _builder().build(_pair(previous=old, current=changed_cookie))
    assert changed.invalid_reason == "RULE_IDENTITY_CHANGED"

    other_run = _snapshot(
        name="new", second=2, monotonic_ns=3_000_000_000, packets=20, run_id="other-run"
    )
    boundary = _builder().build(_pair(previous=old, current=other_run))
    assert boundary.invalid_reason == "RUN_BOUNDARY"


def test_reset_decrease_and_uint64_wrap_are_invalid_not_zero() -> None:
    old = _snapshot(name="old", second=0, monotonic_ns=1_000_000_000, packets=2**64 - 1, bytes_=500)
    wrapped = _snapshot(name="new", second=2, monotonic_ns=3_000_000_000, packets=1, bytes_=600)
    vector = _builder().build(_pair(previous=old, current=wrapped))
    assert vector.features[0].state is FeatureState.INVALID
    assert vector.features[0].value is None
    assert vector.features[0].reason == "PACKET_COUNTER_DECREASE_RESET_OR_WRAP"
    assert vector.features[1].value == 100

    reset = _builder().build(
        _pair(
            current=_snapshot(
                name="new", second=2, monotonic_ns=3_000_000_000, packets=2, bytes_=100
            )
        )
    )
    assert reset.features[0].state is FeatureState.INVALID
    assert reset.features[0].value is None


def test_missing_counter_only_invalidates_dependent_features() -> None:
    vector = _builder().build(
        _pair(current=_snapshot(name="new", second=2, monotonic_ns=3_000_000_000, packets=None))
    )
    assert vector.features[0].state is FeatureState.UNKNOWN
    assert vector.features[0].value is None
    assert vector.features[1].value == 0
    assert vector.features[2].state is FeatureState.UNKNOWN
    assert vector.features[3].value == 0
    assert vector.window_state is FeatureWindowState.PARTIAL


def test_duplicate_and_out_of_order_pairs_are_invalid() -> None:
    old = _snapshot(name="same", second=0, monotonic_ns=1_000_000_000)
    duplicate = _builder().build(_pair(previous=old, current=old))
    assert duplicate.invalid_reason == "DUPLICATE_SNAPSHOT"

    later = _snapshot(name="later", second=1, monotonic_ns=2_000_000_000)
    earlier = _snapshot(name="earlier", second=2, monotonic_ns=1_500_000_000, packets=12)
    out_of_order = _builder().build(_pair(previous=later, current=earlier))
    assert out_of_order.invalid_reason == "ZERO_DURATION_OR_OUT_OF_ORDER_SNAPSHOT"
    assert all(value is None for value in out_of_order.predictor_values)


def test_zero_duration_and_excessive_gap_are_incomplete_or_invalid() -> None:
    zero_duration = _builder().build(
        _pair(
            previous=_snapshot(name="old", second=0, monotonic_ns=2_000_000_000),
            current=_snapshot(name="new", second=1, monotonic_ns=2_000_000_000, packets=11),
        )
    )
    assert zero_duration.window_state is FeatureWindowState.INVALID
    assert zero_duration.invalid_reason == "ZERO_DURATION_OR_OUT_OF_ORDER_SNAPSHOT"

    gap = _builder(maximum_gap_seconds=1).build(
        _pair(current=_snapshot(name="new", second=2, monotonic_ns=3_000_000_000, packets=12))
    )
    assert gap.window_state is FeatureWindowState.INCOMPLETE
    assert gap.invalid_reason == "OBSERVATION_GAP_EXCEEDS_CONFIGURED_LIMIT"
    assert all(value is None for value in gap.predictor_values)


def test_missing_monotonic_time_is_not_replaced_by_wall_clock_rate() -> None:
    vector = _builder().build(
        _pair(
            previous=_snapshot(name="old", second=0, monotonic_ns=1_000_000_000),
            current=_snapshot(name="new", second=2, monotonic_ns=None, packets=12),
        )
    )
    assert vector.window_state is FeatureWindowState.INVALID
    assert vector.timing_source == "UNAVAILABLE"
    assert all(value is None for value in vector.predictor_values)


def test_build_many_has_deterministic_rule_order() -> None:
    alpha = _pair(pair_id="alpha")
    other_rule = _snapshot(name="new", second=2, monotonic_ns=3_000_000_000, match="OFPMatch()")
    beta = _pair(current=other_rule, pair_id="beta")
    first = _builder().build_many([beta, alpha])
    second = _builder().build_many([alpha, beta])
    assert [item.pair_id for item in first] == [item.pair_id for item in second]


def test_serialization_round_trip_and_predictor_projection_excludes_context() -> None:
    vector = _builder().build(_pair(pair_id="stable-pair"))
    serialized = vector.to_json()
    restored = LiveRuleFeatureVector.from_json(serialized)
    assert restored.to_json() == serialized
    assert restored.predictor_dict() == vector.predictor_dict()
    assert set(vector.predictor_dict()) == {
        "schema_version",
        "feature_schema_id",
        "feature_order",
        "values",
        "validity",
    }
    assert "run_id" not in vector.predictor_dict()
    assert "scenario_id" not in vector.predictor_dict()
    assert "label" not in vector.predictor_dict()
    assert vector.coverage_state is CounterCoverageState.COUNTER_WINDOW_COMPLETE
    assert vector.schema_builder_version == "stage7-live-feature-builder-v1"
    assert vector.collector_version is None
    assert vector.ovs_version is None


def test_available_source_versions_are_preserved_as_provenance() -> None:
    pair = SnapshotPair(
        "versioned-pair",
        _snapshot(name="old", second=0, monotonic_ns=1_000_000_000),
        _snapshot(name="new", second=2, monotonic_ns=3_000_000_000, packets=12),
        collector_version="collector-test-1",
        telemetry_provenance_version="flow-stats-schema-1",
        ovs_version="ovs-test-1",
    )
    vector = _builder().build(pair)
    restored = LiveRuleFeatureVector.from_json(vector.to_json())
    assert restored.collector_version == "collector-test-1"
    assert restored.telemetry_provenance_version == "flow-stats-schema-1"
    assert restored.ovs_version == "ovs-test-1"


def test_repeated_input_is_byte_identical_and_schema_order_is_enforced() -> None:
    builder = _builder()
    pair = _pair(pair_id="repeatable")
    assert builder.build(pair).to_json() == builder.build(pair).to_json()
    serialized = builder.build(pair).to_dict()
    serialized["feature_order"] = list(reversed(LIVE_FEATURE_ORDER))
    with pytest.raises(ValueError, match="feature order"):
        LiveRuleFeatureVector.from_dict(serialized)

    changed_pair = _pair(
        pair_id="repeatable",
        current=_snapshot(name="new", second=2, monotonic_ns=3_000_000_000, packets=14, bytes_=500),
    )
    assert builder.build(pair).window_id != builder.build(changed_pair).window_id


def test_invalid_evidence_cannot_be_serialized_as_measured_zero() -> None:
    serialized = (
        _builder()
        .build(
            _pair(current=_snapshot(name="new", second=2, monotonic_ns=3_000_000_000, packets=None))
        )
        .to_dict()
    )
    predictors = serialized["predictors"]
    assert isinstance(predictors, dict)
    predictors["rule_packet_delta"] = {
        "value": 0,
        "state": "UNKNOWN",
        "reason": "PACKET_COUNTER_MISSING",
    }
    with pytest.raises(ValueError, match="unavailable feature value must be null"):
        LiveRuleFeatureVector.from_dict(serialized)


def test_gap_limit_must_be_explicit_and_positive() -> None:
    with pytest.raises(TypeError):
        RuleCounterFeatureBuilder()  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="finite and positive"):
        RuleCounterFeatureBuilder(maximum_gap_seconds=0)

    with pytest.raises(ValueError, match="finite and positive"):
        RuleCounterFeatureBuilder(maximum_gap_seconds=True)
