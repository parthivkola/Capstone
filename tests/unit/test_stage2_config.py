"""Unit tests for pure Stage 2 configuration and event contracts."""

from pathlib import Path

import pytest
from pytest import MonkeyPatch

from networking.mininet.config import TopologyConfig
from networking.ryu.config import ControllerConfig
from networking.ryu.structured_events import (
    datapath_id_text,
    flow_statistics_log_details,
    run_start_timestamp,
    stage2_event,
)
from networking.ryu.validate_stage2 import verify_test_rule_effect, verify_test_rule_removed
from src.sdn_defense.telemetry_io import TelemetryJsonlRecorder, validate_telemetry_jsonl


def test_controller_defaults_keep_the_explicit_test_rule_disabled(
    monkeypatch: MonkeyPatch,
) -> None:
    """The reversible test rule remains opt-in."""

    monkeypatch.delenv("SDN_STAGE2_INSTALL_TEST_RULE", raising=False)
    monkeypatch.delenv("SDN_STAGE2_PACKET_EVIDENCE_ENABLED", raising=False)

    assert ControllerConfig.from_environment().install_explicit_test_rule is False
    assert ControllerConfig.from_environment().packet_evidence_enabled is False
    assert ControllerConfig.from_environment().record_packetin_telemetry is True


def test_packetin_telemetry_recording_can_be_disabled_without_changing_packet_evidence(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("SDN_STAGE2_RECORD_PACKETIN_TELEMETRY", "false")
    monkeypatch.setenv("SDN_STAGE2_PACKET_EVIDENCE_ENABLED", "false")
    config = ControllerConfig.from_environment()
    assert config.record_packetin_telemetry is False
    assert config.packet_evidence_enabled is False


def test_packet_evidence_requires_explicit_recorder_and_run_context(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SDN_STAGE2_PACKET_EVIDENCE_ENABLED", "true")
    monkeypatch.delenv("SDN_TELEMETRY_JSONL", raising=False)
    monkeypatch.delenv("SDN_OBSERVATION_CONTEXT_FILE", raising=False)

    with pytest.raises(ValueError, match="JSONL recorder and explicit run context"):
        ControllerConfig.from_environment().validate()

    monkeypatch.setenv("SDN_TELEMETRY_JSONL", str(tmp_path / "telemetry.jsonl"))
    monkeypatch.setenv("SDN_OBSERVATION_CONTEXT_FILE", str(tmp_path / "context.json"))
    config = ControllerConfig.from_environment()
    config.validate()
    assert config.packet_evidence_max_per_second == 4
    assert config.packet_evidence_max_per_run == 16


def test_controller_config_reads_explicit_test_rule_settings(monkeypatch: MonkeyPatch) -> None:
    """Stage 2 test rule parameters are environment-configurable."""

    monkeypatch.setenv("SDN_STAGE2_INSTALL_TEST_RULE", "true")
    monkeypatch.setenv("SDN_STAGE2_TEST_RULE_EGRESS_PORT", "3")

    config = ControllerConfig.from_environment()

    assert config.install_explicit_test_rule is True
    assert config.test_rule_egress_port == 3


def test_topology_config_uses_local_controller_defaults(monkeypatch: MonkeyPatch) -> None:
    """The default controller endpoint is loopback-only."""

    monkeypatch.delenv("SDN_STAGE2_CONTROLLER_HOST", raising=False)
    monkeypatch.delenv("SDN_STAGE2_CONTROLLER_PORT", raising=False)

    assert TopologyConfig.from_environment() == TopologyConfig("127.0.0.1", 6653)


def test_feature_gap_is_configurable_and_must_be_positive(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("SDN_STAGE2_MAX_FEATURE_GAP_SECONDS", "7.5")
    config = ControllerConfig.from_environment()
    config.validate()
    assert config.maximum_feature_gap_seconds == 7.5

    monkeypatch.setenv("SDN_STAGE2_MAX_FEATURE_GAP_SECONDS", "inf")
    with pytest.raises(ValueError, match="finite and positive"):
        ControllerConfig.from_environment().validate()


def test_topology_config_rejects_non_loopback_controller() -> None:
    """The topology cannot connect to an Internet-facing controller."""

    with pytest.raises(ValueError, match="loopback"):
        TopologyConfig("192.0.2.10", 6653).validate()


def test_structured_event_contains_timestamp_datapath_and_type() -> None:
    """Controller observations have parseable minimum fields."""

    event = stage2_event("switch_features_received", 1, port_no=3)

    assert event["event_type"] == "switch_features_received"
    assert event["datapath_id"] == "0000000000000001"
    assert event["port_no"] == 3
    assert "timestamp" in event


def test_flow_statistics_log_details_do_not_duplicate_envelope_fields() -> None:
    details = flow_statistics_log_details(
        {
            "event_type": "flow_statistics",
            "datapath_id": "1",
            "packet_count": 4,
            "collection_id": "collection-1",
            "datapath_epoch_id": "epoch-1",
        }
    )

    event = stage2_event("flow_statistics", 1, **details)

    assert event["packet_count"] == 4
    assert event["collection_id"] == "collection-1"
    assert event["datapath_epoch_id"] == "epoch-1"


def test_missing_datapath_id_remains_missing() -> None:
    assert datapath_id_text(None) is None
    assert datapath_id_text(1) == "0000000000000001"


def test_run_boundary_uses_append_time_and_preserves_declared_start_in_metadata() -> None:
    # A scenario timestamp can predate delayed controller attachment. It is
    # context, not the timestamp of the JSONL record being appended.
    assert run_start_timestamp({"start_at": "2026-01-01T00:00:00Z"}, "later") == "later"
    assert run_start_timestamp({}, "fallback") == "fallback"


def test_delayed_scenario_start_does_not_backdate_appended_telemetry(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    run_id = "fresh-run"
    now = "2026-10-28T08:00:00+00:00"
    recorder = TelemetryJsonlRecorder(path, source_version="unit-test")
    recorder.write(
        "run_metadata",
        timestamp=run_start_timestamp({"start_at": "2020-01-01T00:00:00Z"}, now),
        run_id=run_id,
        metadata={"schema_version": 1, "run_id": run_id, "start_at": "2020-01-01T00:00:00Z"},
    )
    recorder.write("run_boundary", timestamp=now, run_id=run_id, state="started")
    recorder.write(
        "run_boundary",
        timestamp="2026-10-28T08:00:01+00:00",
        run_id=run_id,
        state="ended",
    )
    recorder.close()

    counts = validate_telemetry_jsonl(path)
    assert counts["run_boundary"] == 2
    assert counts["incomplete_runs"] == 0


def test_test_rule_effect_requires_packet_counter() -> None:
    """The validation parser accepts only a test rule that observed traffic."""

    flow_dump = "cookie=0x534432, n_packets=1, n_bytes=54, tcp,tp_dst=18080 actions=output:3"

    verify_test_rule_effect(flow_dump)


def test_test_rule_removal_requires_cookie_to_be_absent() -> None:
    """The rule verifier accepts a dump after the explicit cookie is removed."""

    verify_test_rule_removed("cookie=0x0, n_packets=2, actions=CONTROLLER")
