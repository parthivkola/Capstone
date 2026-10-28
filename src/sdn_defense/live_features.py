"""Deterministic offline feature vectors from explicitly paired rule snapshots.

This module has no network, detector, model, policy, or mitigation dependency.
Its features retain OpenFlow rule-counter semantics.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TypeAlias

from src.sdn_defense.flow_records import FlowRecord
from src.sdn_defense.telemetry import CanonicalRuleIdentity, FlowSnapshot

LIVE_FEATURE_SCHEMA_VERSION = 1
LIVE_FEATURE_SCHEMA_ID = "stage7-live-rule-window-v1"
LIVE_FEATURE_BUILDER_VERSION = "stage7-live-feature-builder-v1"
LIVE_FEATURE_ORDER = (
    "rule_packet_delta",
    "rule_byte_delta",
    "rule_packet_rate_per_second",
    "rule_byte_rate_per_second",
)
_COUNTER_MAX = 2**64 - 1


class FeatureState(StrEnum):
    """Validity of one predictor value; missing evidence is never numeric zero."""

    MEASURED = "MEASURED"
    UNKNOWN = "UNKNOWN"
    INCOMPLETE = "INCOMPLETE"
    INVALID = "INVALID"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class FeatureWindowState(StrEnum):
    """Overall pair validity, separate from each feature's validity."""

    VALID = "VALID"
    PARTIAL = "PARTIAL"
    INCOMPLETE = "INCOMPLETE"
    INVALID = "INVALID"


class CounterCoverageState(StrEnum):
    """Completeness of the paired flow-stat collection, not packet coverage."""

    COUNTER_WINDOW_COMPLETE = "COUNTER_WINDOW_COMPLETE"
    COUNTER_WINDOW_INCOMPLETE = "COUNTER_WINDOW_INCOMPLETE"
    NOT_ASSESSED = "NOT_ASSESSED"


@dataclass(frozen=True, slots=True)
class FeatureValue:
    """A predictor value and its explicit validity state."""

    value: int | float | None
    state: FeatureState
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.state is FeatureState.MEASURED:
            if self.value is None:
                raise ValueError("measured feature requires a value")
            if isinstance(self.value, bool) or not isinstance(self.value, (int, float)):
                raise ValueError("measured feature must be numeric")
            if isinstance(self.value, float) and not math.isfinite(self.value):
                raise ValueError("measured feature must be finite")
            if self.value < 0:
                raise ValueError("rule-counter features cannot be negative")
        elif self.value is not None:
            raise ValueError("unavailable feature value must be null")
        if self.state is FeatureState.MEASURED and self.reason is not None:
            raise ValueError("measured feature cannot have an invalidity reason")

    def to_dict(self) -> dict[str, object]:
        return {"value": self.value, "state": self.state.value, "reason": self.reason}

    @classmethod
    def from_dict(cls, value: object) -> FeatureValue:
        if not isinstance(value, dict) or set(value) != {"value", "state", "reason"}:
            raise ValueError("feature value has an invalid schema")
        raw_value = value["value"]
        if raw_value is not None and (
            isinstance(raw_value, bool) or not isinstance(raw_value, (int, float))
        ):
            raise ValueError("feature value must be numeric or null")
        try:
            state = FeatureState(value["state"])
        except (TypeError, ValueError) as exc:
            raise ValueError("feature state is unsupported") from exc
        reason = value["reason"]
        if reason is not None and not isinstance(reason, str):
            raise ValueError("feature reason must be a string or null")
        return cls(raw_value, state, reason)


@dataclass(frozen=True, slots=True)
class SnapshotEvidence:
    """One FlowSnapshot plus collector facts about its containing collection."""

    snapshot: FlowSnapshot
    collection_id: str
    collection_complete: bool
    datapath_epoch_id: str

    def __post_init__(self) -> None:
        if not self.collection_id or not self.datapath_epoch_id:
            raise ValueError("collection and datapath epoch IDs are required")
        if not isinstance(self.collection_complete, bool):
            raise ValueError("collection_complete must be boolean")


@dataclass(frozen=True, slots=True)
class SnapshotPair:
    """Explicit pair supplied by a caller; no hidden pairing or imputation."""

    pair_id: str
    previous: SnapshotEvidence | None
    current: SnapshotEvidence | None
    collector_version: str | None = None
    telemetry_provenance_version: str | None = None
    ovs_version: str | None = None

    def __post_init__(self) -> None:
        if not self.pair_id:
            raise ValueError("pair_id is required")
        for name, value in (
            ("collector_version", self.collector_version),
            ("telemetry_provenance_version", self.telemetry_provenance_version),
            ("ovs_version", self.ovs_version),
        ):
            if value is not None and not value:
                raise ValueError(f"{name} must be non-empty when provided")


FeatureNumber: TypeAlias = int | float | None


@dataclass(frozen=True, slots=True)
class LiveRuleFeatureVector:
    """Versioned v1 features with provenance kept outside the predictor block."""

    schema_version: int
    feature_schema_id: str
    feature_order: tuple[str, ...]
    window_id: str
    pair_id: str
    run_id: str | None
    datapath_id: str | None
    datapath_epoch_id: str | None
    rule_identity_id: str | None
    source_flow_record_ids: tuple[str, ...]
    start_at: datetime | None
    end_at: datetime | None
    measured_elapsed_seconds: float | None
    timing_source: str
    collector_version: str | None
    telemetry_provenance_version: str | None
    ovs_version: str | None
    schema_builder_version: str
    coverage_state: CounterCoverageState
    window_state: FeatureWindowState
    invalid_reason: str | None
    features: tuple[FeatureValue, ...]

    def __post_init__(self) -> None:
        if self.schema_version != LIVE_FEATURE_SCHEMA_VERSION:
            raise ValueError("unsupported live feature schema version")
        if self.feature_schema_id != LIVE_FEATURE_SCHEMA_ID:
            raise ValueError("unsupported live feature schema ID")
        if self.feature_order != LIVE_FEATURE_ORDER or len(self.features) != len(
            LIVE_FEATURE_ORDER
        ):
            raise ValueError("feature order does not match the v1 contract")
        if not self.window_id or not self.pair_id:
            raise ValueError("window and pair IDs are required")
        if self.schema_builder_version != LIVE_FEATURE_BUILDER_VERSION:
            raise ValueError("unsupported feature-builder version")
        for name, timestamp in (("start_at", self.start_at), ("end_at", self.end_at)):
            if timestamp is not None and timestamp.tzinfo is None:
                raise ValueError(f"{name} must be timezone-aware")
        if self.measured_elapsed_seconds is not None and (
            not math.isfinite(self.measured_elapsed_seconds)
            or self.measured_elapsed_seconds <= 0
        ):
            raise ValueError("measured elapsed time must be finite and positive")

    @property
    def predictor_values(self) -> tuple[FeatureNumber, ...]:
        """Ordered predictor values only; validity and provenance are separate."""

        return tuple(feature.value for feature in self.features)

    @property
    def feature_validity(self) -> tuple[FeatureState, ...]:
        return tuple(feature.state for feature in self.features)

    def predictor_dict(self) -> dict[str, object]:
        """Return the model-facing projection without IDs, labels, or context."""

        return {
            "schema_version": self.schema_version,
            "feature_schema_id": self.feature_schema_id,
            "feature_order": list(self.feature_order),
            "values": dict(zip(self.feature_order, self.predictor_values, strict=True)),
            "validity": {
                name: state.value
                for name, state in zip(self.feature_order, self.feature_validity, strict=True)
            },
        }

    def to_dict(self) -> dict[str, object]:
        """Serialize the full vector; labels and scenario names are not accepted."""

        return {
            "schema_version": self.schema_version,
            "feature_schema_id": self.feature_schema_id,
            "feature_order": list(self.feature_order),
            "window_id": self.window_id,
            "pair_id": self.pair_id,
            "run_id": self.run_id,
            "datapath_id": self.datapath_id,
            "datapath_epoch_id": self.datapath_epoch_id,
            "rule_identity_id": self.rule_identity_id,
            "source_flow_record_ids": list(self.source_flow_record_ids),
            "start_at": _iso(self.start_at),
            "end_at": _iso(self.end_at),
            "measured_elapsed_seconds": self.measured_elapsed_seconds,
            "timing_source": self.timing_source,
            "collector_version": self.collector_version,
            "telemetry_provenance_version": self.telemetry_provenance_version,
            "ovs_version": self.ovs_version,
            "schema_builder_version": self.schema_builder_version,
            "coverage_state": self.coverage_state.value,
            "window_state": self.window_state.value,
            "invalid_reason": self.invalid_reason,
            "predictors": {
                name: feature.to_dict()
                for name, feature in zip(self.feature_order, self.features, strict=True)
            },
        }

    def to_json(self) -> str:
        """Canonical deterministic JSON serialization."""

        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False)

    @classmethod
    def from_dict(cls, value: object) -> LiveRuleFeatureVector:
        """Validate and deserialize one complete v1 vector."""

        expected = {
            "schema_version",
            "feature_schema_id",
            "feature_order",
            "window_id",
            "pair_id",
            "run_id",
            "datapath_id",
            "datapath_epoch_id",
            "rule_identity_id",
            "source_flow_record_ids",
            "start_at",
            "end_at",
            "measured_elapsed_seconds",
            "timing_source",
            "collector_version",
            "telemetry_provenance_version",
            "ovs_version",
            "schema_builder_version",
            "coverage_state",
            "window_state",
            "invalid_reason",
            "predictors",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("live feature vector has an invalid schema")
        if type(value["schema_version"]) is not int:
            raise ValueError("schema_version must be an integer")
        order = value["feature_order"]
        if not isinstance(order, list) or tuple(order) != LIVE_FEATURE_ORDER:
            raise ValueError("feature order does not match the v1 contract")
        predictors = value["predictors"]
        if not isinstance(predictors, dict) or set(predictors) != set(LIVE_FEATURE_ORDER):
            raise ValueError("predictors do not match the v1 contract")
        record_ids = value["source_flow_record_ids"]
        if not isinstance(record_ids, list) or any(not isinstance(x, str) for x in record_ids):
            raise ValueError("source record IDs are malformed")
        for field in ("window_id", "pair_id", "timing_source"):
            if not isinstance(value[field], str):
                raise ValueError(f"{field} must be a string")
        for field in (
            "run_id",
            "datapath_id",
            "datapath_epoch_id",
            "rule_identity_id",
            "collector_version",
            "telemetry_provenance_version",
            "ovs_version",
        ):
            if value[field] is not None and not isinstance(value[field], str):
                raise ValueError(f"{field} must be a string or null")
        reason = value["invalid_reason"]
        if reason is not None and not isinstance(reason, str):
            raise ValueError("invalid_reason must be a string or null")
        try:
            state = FeatureWindowState(value["window_state"])
        except (TypeError, ValueError) as exc:
            raise ValueError("window state is unsupported") from exc
        try:
            coverage = CounterCoverageState(value["coverage_state"])
        except (TypeError, ValueError) as exc:
            raise ValueError("coverage state is unsupported") from exc
        elapsed = value["measured_elapsed_seconds"]
        if elapsed is not None and (
            isinstance(elapsed, bool) or not isinstance(elapsed, (float, int))
        ):
            raise ValueError("elapsed time must be numeric or null")
        return cls(
            schema_version=value["schema_version"],
            feature_schema_id=value["feature_schema_id"],
            feature_order=tuple(order),
            window_id=value["window_id"],
            pair_id=value["pair_id"],
            run_id=value["run_id"],
            datapath_id=value["datapath_id"],
            datapath_epoch_id=value["datapath_epoch_id"],
            rule_identity_id=value["rule_identity_id"],
            source_flow_record_ids=tuple(record_ids),
            start_at=_parse_optional_time(value["start_at"], "start_at"),
            end_at=_parse_optional_time(value["end_at"], "end_at"),
            measured_elapsed_seconds=None if elapsed is None else float(elapsed),
            timing_source=value["timing_source"],
            collector_version=value["collector_version"],
            telemetry_provenance_version=value["telemetry_provenance_version"],
            ovs_version=value["ovs_version"],
            schema_builder_version=value["schema_builder_version"],
            coverage_state=coverage,
            window_state=state,
            invalid_reason=reason,
            features=tuple(FeatureValue.from_dict(predictors[name]) for name in LIVE_FEATURE_ORDER),
        )

    @classmethod
    def from_json(cls, raw: str) -> LiveRuleFeatureVector:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("live feature JSON is malformed") from exc
        return cls.from_dict(value)


class RuleCounterFeatureBuilder:
    """Build contract-v1 features from explicit offline or audited pairs.

    The maximum gap is required from the caller because no numeric gap limit
    has been frozen in a research protocol. ``build`` is the deterministic
    transform for synthetic/offline pairs. A live-source caller must use
    ``build_source_verified`` with the append-ordered recorder stream.
    """

    def __init__(self, *, maximum_gap_seconds: float) -> None:
        if (
            isinstance(maximum_gap_seconds, bool)
            or not math.isfinite(maximum_gap_seconds)
            or maximum_gap_seconds <= 0
        ):
            raise ValueError("maximum_gap_seconds must be finite and positive")
        self.maximum_gap_seconds = maximum_gap_seconds

    def build(self, pair: SnapshotPair) -> LiveRuleFeatureVector:
        """Validate the supplied pair and compute only the four v1 features."""

        previous = pair.previous
        current = pair.current
        evidence = tuple(item for item in (previous, current) if item is not None)
        record_ids = tuple(item.snapshot.record.record_id for item in evidence)
        run_id = current.snapshot.run_id if current is not None else None
        epoch = current.datapath_epoch_id if current is not None else None
        digest = _window_id(pair)

        if previous is None or current is None:
            return self._unavailable(
                pair,
                evidence,
                record_ids,
                FeatureWindowState.INCOMPLETE,
                FeatureState.INCOMPLETE,
                "MISSING_PREVIOUS_OR_CURRENT_SNAPSHOT",
                run_id,
                epoch,
            )
        old_record = previous.snapshot.record
        new_record = current.snapshot.record

        if not previous.collection_complete or not current.collection_complete:
            return self._unavailable(
                pair,
                evidence,
                record_ids,
                FeatureWindowState.INCOMPLETE,
                FeatureState.INCOMPLETE,
                "INCOMPLETE_STATISTICS_COLLECTION",
                run_id,
                epoch,
            )
        if previous.datapath_epoch_id != current.datapath_epoch_id:
            return self._unavailable(
                pair,
                evidence,
                record_ids,
                FeatureWindowState.INCOMPLETE,
                FeatureState.INCOMPLETE,
                "DATAPATH_EPOCH_BOUNDARY",
                run_id,
                epoch,
            )
        if previous.snapshot.run_id != current.snapshot.run_id:
            return self._unavailable(
                pair,
                evidence,
                record_ids,
                FeatureWindowState.INCOMPLETE,
                FeatureState.INCOMPLETE,
                "RUN_BOUNDARY",
                run_id,
                epoch,
            )
        if old_record.record_id == new_record.record_id:
            return self._unavailable(
                pair,
                evidence,
                record_ids,
                FeatureWindowState.INVALID,
                FeatureState.INVALID,
                "DUPLICATE_SNAPSHOT",
                run_id,
                epoch,
            )

        try:
            old_identity = _identity(old_record)
            new_identity = _identity(new_record)
        except ValueError:
            return self._unavailable(
                pair,
                evidence,
                record_ids,
                FeatureWindowState.INVALID,
                FeatureState.INVALID,
                "RULE_IDENTITY_UNAVAILABLE_OR_AMBIGUOUS",
                run_id,
                epoch,
            )
        if old_identity.identity_id != new_identity.identity_id:
            return self._unavailable(
                pair,
                evidence,
                record_ids,
                FeatureWindowState.INCOMPLETE,
                FeatureState.INCOMPLETE,
                "RULE_IDENTITY_CHANGED",
                run_id,
                epoch,
            )
        if old_record.observation_source != new_record.observation_source:
            return self._unavailable(
                pair,
                evidence,
                record_ids,
                FeatureWindowState.INVALID,
                FeatureState.INVALID,
                "OBSERVATION_SOURCE_CHANGED",
                run_id,
                epoch,
            )

        old_at = _parse_record_time(old_record.observed_at)
        new_at = _parse_record_time(new_record.observed_at)
        old_ns = previous.snapshot.collector_monotonic_ns
        new_ns = current.snapshot.collector_monotonic_ns
        if old_at is None or new_at is None or old_ns is None or new_ns is None:
            return self._unavailable(
                pair,
                evidence,
                record_ids,
                FeatureWindowState.INVALID,
                FeatureState.UNKNOWN,
                "MONOTONIC_TIMING_OR_TIMESTAMP_MISSING",
                run_id,
                epoch,
                old_identity.identity_id,
                old_at,
                new_at,
            )
        elapsed = (new_ns - old_ns) / 1_000_000_000
        if elapsed <= 0 or new_at <= old_at:
            return self._unavailable(
                pair,
                evidence,
                record_ids,
                FeatureWindowState.INVALID,
                FeatureState.INVALID,
                "ZERO_DURATION_OR_OUT_OF_ORDER_SNAPSHOT",
                run_id,
                epoch,
                old_identity.identity_id,
                old_at,
                new_at,
            )
        if elapsed > self.maximum_gap_seconds:
            return self._unavailable(
                pair,
                evidence,
                record_ids,
                FeatureWindowState.INCOMPLETE,
                FeatureState.INCOMPLETE,
                "OBSERVATION_GAP_EXCEEDS_CONFIGURED_LIMIT",
                run_id,
                epoch,
                old_identity.identity_id,
                old_at,
                new_at,
                elapsed,
            )

        packet = _counter_feature(old_record.packet_count, new_record.packet_count, "PACKET")
        byte = _counter_feature(old_record.byte_count, new_record.byte_count, "BYTE")
        packet_rate = _rate_feature(packet, elapsed)
        byte_rate = _rate_feature(byte, elapsed)
        features = (packet, byte, packet_rate, byte_rate)
        measured_count = sum(item.state is FeatureState.MEASURED for item in features)
        if measured_count == len(features):
            window_state = FeatureWindowState.VALID
        elif measured_count == 0 and any(item.state is FeatureState.INVALID for item in features):
            window_state = FeatureWindowState.INVALID
        else:
            window_state = FeatureWindowState.PARTIAL
        reasons = tuple(dict.fromkeys(item.reason for item in features if item.reason))
        invalid_reason = ";".join(reasons) if reasons else None
        return LiveRuleFeatureVector(
            schema_version=LIVE_FEATURE_SCHEMA_VERSION,
            feature_schema_id=LIVE_FEATURE_SCHEMA_ID,
            feature_order=LIVE_FEATURE_ORDER,
            window_id=digest,
            pair_id=pair.pair_id,
            run_id=run_id,
            datapath_id=new_identity.datapath_id,
            datapath_epoch_id=current.datapath_epoch_id,
            rule_identity_id=new_identity.identity_id,
            source_flow_record_ids=record_ids,
            start_at=old_at,
            end_at=new_at,
            measured_elapsed_seconds=elapsed,
            timing_source="COLLECTOR_MONOTONIC",
            collector_version=pair.collector_version,
            telemetry_provenance_version=pair.telemetry_provenance_version,
            ovs_version=pair.ovs_version,
            schema_builder_version=LIVE_FEATURE_BUILDER_VERSION,
            coverage_state=(
                CounterCoverageState.COUNTER_WINDOW_COMPLETE
                if window_state is FeatureWindowState.VALID
                else CounterCoverageState.COUNTER_WINDOW_INCOMPLETE
            ),
            window_state=window_state,
            invalid_reason=invalid_reason,
            features=features,
        )

    def build_source_verified(
        self, pair: SnapshotPair, source_records: Iterable[dict[str, object]]
    ) -> LiveRuleFeatureVector:
        """Build only after the recorder stream proves collection/epoch lineage.

        This offline gate verifies record relationships, not file authenticity.
        The current Ryu stream lacks datapath epoch IDs and is expected to fail
        until that source instrumentation is added and separately validated.
        """

        from src.sdn_defense.live_provenance import audit_snapshot_pair_provenance

        audit = audit_snapshot_pair_provenance(pair, tuple(source_records))
        if not audit.accepted:
            raise ValueError(f"snapshot provenance rejected: {audit.reason}")
        return self.build(pair)

    def build_many(self, pairs: Iterable[SnapshotPair]) -> tuple[LiveRuleFeatureVector, ...]:
        """Build a deterministic ordering for a finite collection of explicit pairs."""

        vectors = tuple(self.build(pair) for pair in pairs)
        return tuple(
            sorted(
                vectors,
                key=lambda item: (
                    item.rule_identity_id or "",
                    _iso(item.start_at) or "",
                    item.pair_id,
                ),
            )
        )

    def _unavailable(
        self,
        pair: SnapshotPair,
        evidence: tuple[SnapshotEvidence, ...],
        record_ids: tuple[str, ...],
        window_state: FeatureWindowState,
        feature_state: FeatureState,
        reason: str,
        run_id: str | None,
        epoch: str | None,
        rule_identity_id: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        elapsed: float | None = None,
    ) -> LiveRuleFeatureVector:
        if evidence:
            selected = evidence[-1]
            run_id = selected.snapshot.run_id
            epoch = selected.datapath_epoch_id
            with suppress(ValueError):
                rule_identity_id = _identity(selected.snapshot.record).identity_id
            end_at = _parse_record_time(selected.snapshot.record.observed_at)
        if len(evidence) == 2:
            start_at = _parse_record_time(evidence[0].snapshot.record.observed_at)
        value = FeatureValue(None, feature_state, reason)
        return LiveRuleFeatureVector(
            schema_version=LIVE_FEATURE_SCHEMA_VERSION,
            feature_schema_id=LIVE_FEATURE_SCHEMA_ID,
            feature_order=LIVE_FEATURE_ORDER,
            window_id=_window_id(pair),
            pair_id=pair.pair_id,
            run_id=run_id,
            datapath_id=(
                evidence[-1].snapshot.record.datapath_id if evidence else None
            ),
            datapath_epoch_id=epoch,
            rule_identity_id=rule_identity_id,
            source_flow_record_ids=record_ids,
            start_at=start_at,
            end_at=end_at,
            measured_elapsed_seconds=elapsed,
            timing_source=(
                "COLLECTOR_MONOTONIC"
                if evidence
                and all(item.snapshot.collector_monotonic_ns is not None for item in evidence)
                else "UNAVAILABLE"
            ),
            collector_version=pair.collector_version,
            telemetry_provenance_version=pair.telemetry_provenance_version,
            ovs_version=pair.ovs_version,
            schema_builder_version=LIVE_FEATURE_BUILDER_VERSION,
            coverage_state=(
                CounterCoverageState.NOT_ASSESSED
                if not evidence
                else CounterCoverageState.COUNTER_WINDOW_INCOMPLETE
            ),
            window_state=window_state,
            invalid_reason=reason,
            features=(value, value, value, value),
        )


def _counter_feature(previous: int | None, current: int | None, label: str) -> FeatureValue:
    if previous is None or current is None:
        return FeatureValue(None, FeatureState.UNKNOWN, f"{label}_COUNTER_MISSING")
    if (
        isinstance(previous, bool)
        or isinstance(current, bool)
        or not isinstance(previous, int)
        or not isinstance(current, int)
        or previous < 0
        or current < 0
        or previous > _COUNTER_MAX
        or current > _COUNTER_MAX
    ):
        return FeatureValue(None, FeatureState.INVALID, f"{label}_COUNTER_OUT_OF_RANGE")
    if current < previous:
        return FeatureValue(None, FeatureState.INVALID, f"{label}_COUNTER_DECREASE_RESET_OR_WRAP")
    return FeatureValue(current - previous, FeatureState.MEASURED)


def _rate_feature(delta: FeatureValue, elapsed: float) -> FeatureValue:
    if delta.state is not FeatureState.MEASURED:
        return FeatureValue(None, delta.state, delta.reason)
    assert delta.value is not None
    rate = float(delta.value) / elapsed
    if not math.isfinite(rate):
        return FeatureValue(None, FeatureState.INVALID, "RATE_NOT_FINITE")
    return FeatureValue(rate, FeatureState.MEASURED)


def _identity(record: FlowRecord) -> CanonicalRuleIdentity:
    return CanonicalRuleIdentity.from_flow_record(record)


def _parse_record_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _parse_optional_time(value: object, field_name: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be an ISO timestamp or null")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} is malformed") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return parsed.astimezone(UTC)


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _window_id(pair: SnapshotPair) -> str:
    payload = json.dumps(
        {
            "feature_schema_id": LIVE_FEATURE_SCHEMA_ID,
            "pair_id": pair.pair_id,
            "snapshots": [
                None
                if item is None
                else {
                    "record_id": item.snapshot.record.record_id,
                    "collection_id": item.collection_id,
                    "datapath_epoch_id": item.datapath_epoch_id,
                }
                for item in (pair.previous, pair.current)
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
