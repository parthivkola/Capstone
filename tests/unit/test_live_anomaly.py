from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from apps.api.live_service import LiveScoringService
from src.sdn_defense.controller_status import ControllerStatusPublisher, ControllerStatusReader
from src.sdn_defense.live_anomaly import (
    LIVE_ANOMALY_MODEL_ID,
    LiveEvidenceError,
    ValidatedLiveWindow,
    calibrate_benign_runs,
    load_calibration,
    save_calibration,
    score_window,
)
from src.sdn_defense.live_features import LIVE_FEATURE_ORDER, LIVE_FEATURE_SCHEMA_ID


def _raw_window(**overrides: Any) -> dict[str, Any]:
    start = datetime.now(UTC) - timedelta(seconds=2)
    end = start + timedelta(seconds=2)
    value: dict[str, Any] = {
        "schema_version": 1,
        "feature_schema_id": LIVE_FEATURE_SCHEMA_ID,
        "feature_order": list(LIVE_FEATURE_ORDER),
        "window_id": "window-1",
        "observation_source": "openflow_rule_counter_delta",
        "datapath_id": "0000000000000001",
        "rule_identity": {"identity_id": "rule-1"},
        "start_at": start.isoformat(),
        "end_at": end.isoformat(),
        "measured_elapsed_seconds": 2.0,
        "source_record_ids": ["snapshot-a", "snapshot-b"],
        "validity": "VALID",
        "provenance_version": "sdn-live-observation-v1",
        "run_id": "live-run",
        "rule_packet_delta": 4,
        "rule_byte_delta": 400,
        "rule_packet_rate_per_second": 2.0,
        "rule_byte_rate_per_second": 200.0,
    }
    value.update(overrides)
    return value


def _window(run_id: str = "live-run", window_id: str = "window-live") -> ValidatedLiveWindow:
    start = datetime.now(UTC) - timedelta(seconds=1)
    end = start + timedelta(seconds=1)
    return ValidatedLiveWindow(
        window_id=window_id,
        run_id=run_id,
        datapath_id="0000000000000001",
        datapath_epoch_id="epoch-1",
        rule_identity_id="rule-1",
        start_at=start.isoformat(),
        end_at=end.isoformat(),
        elapsed_seconds=1.0,
        features={
            "rule_packet_delta": 4.0,
            "rule_byte_delta": 400.0,
            "rule_packet_rate_per_second": 4.0,
            "rule_byte_rate_per_second": 400.0,
        },
        source_record_ids=("snapshot-a", "snapshot-b"),
        source_artifact="experiments/stage7-telemetry/live-run/telemetry.jsonl",
        source_sha256="a" * 64,
    )


def _model(training_run: str = "benign-training") -> dict[str, Any]:
    return {
        "artifact_format": "sentinel-live-robust-baseline-v1",
        "model_id": LIVE_ANOMALY_MODEL_ID,
        "version": "0.1.0",
        "task": "benign-baseline anomaly scoring; not attack classification",
        "status": "PROVISIONAL_BENIGN_CALIBRATION",
        "feature_schema_id": LIVE_FEATURE_SCHEMA_ID,
        "feature_order": list(LIVE_FEATURE_ORDER),
        "explanation_method": "robust-z feature deviations",
        "threshold": 4.0,
        "maximum_gap_seconds": 30.0,
        "training_runs": [{"run_id": training_run}],
        "profiles": {
            "rule-1": {
                "n_windows": 5,
                "features": {
                    name: {"median": 1.0, "mad": 0.5, "scale": 1.0, "n": 5}
                    for name in LIVE_FEATURE_ORDER
                },
            }
        },
    }


def test_window_validation_rejects_incomplete_gap_and_wrong_schema() -> None:
    parsed = ValidatedLiveWindow.parse(
        _raw_window(),
        source_artifact="fixture.jsonl",
        source_sha256="b" * 64,
        max_gap_seconds=3.0,
    )
    assert parsed.features["rule_packet_delta"] == 4.0
    assert parsed.datapath_epoch_id == ""

    with pytest.raises(LiveEvidenceError, match="maximum observation gap"):
        ValidatedLiveWindow.parse(
            _raw_window(measured_elapsed_seconds=4.0),
            source_artifact="fixture.jsonl",
            source_sha256="b" * 64,
            max_gap_seconds=3.0,
        )
    with pytest.raises(LiveEvidenceError, match="feature names or order"):
        ValidatedLiveWindow.parse(
            _raw_window(feature_order=list(reversed(LIVE_FEATURE_ORDER))),
            source_artifact="fixture.jsonl",
            source_sha256="b" * 64,
            max_gap_seconds=3.0,
        )
    with pytest.raises(LiveEvidenceError, match="valid live feature"):
        ValidatedLiveWindow.parse(
            _raw_window(validity="INCOMPLETE"),
            source_artifact="fixture.jsonl",
            source_sha256="b" * 64,
            max_gap_seconds=3.0,
        )


def test_score_explanation_reports_signed_feature_deviations() -> None:
    result = score_window(_model(), _window())
    assert result["result"] == "UNUSUAL"
    assert result["score"] == 399.0
    assert result["score_semantics"].endswith("not a probability")
    assert result["explanation"]["mitigation_authorized"] is False
    assert result["explanation"]["features"][0]["feature"] == "rule_byte_delta"
    assert result["explanation"]["features"][0]["signed_deviation"] == 399.0


def test_benign_calibration_requires_explicit_clean_run_and_records_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import src.sdn_defense.live_anomaly as anomaly

    paths = [tmp_path / "benign-a.jsonl", tmp_path / "benign-b.jsonl"]
    for path in paths:
        path.write_text("test input placeholder\n", encoding="utf-8")
    samples = {
        path: [_window(run_id=path.stem, window_id=f"{path.stem}-{index}") for index in range(3)]
        for path in paths
    }
    monkeypatch.setattr(
        anomaly,
        "read_telemetry_windows",
        lambda path, **_kwargs: (
            samples[path],
            {"counts": {"source_verified_pairs": 2}},
        ),
    )
    root = Path(__file__).resolve().parents[2]
    relative_sources = (
        "networking/ryu/config.py",
        "networking/ryu/stage2_controller.py",
        "src/sdn_defense/telemetry.py",
        "src/sdn_defense/live_features.py",
        "src/sdn_defense/live_anomaly.py",
    )
    source_hashes = {
        source: hashlib.sha256((root / source).read_bytes()).hexdigest()
        for source in relative_sources
    }
    summaries = [
        (
            path,
            {
                "run_id": path.stem,
                "scenario_id": "controlled-connectivity-observation",
                "cleanup_verified": True,
                "environment": {"source_sha256": source_hashes},
            },
        )
        for path in paths
    ]
    model = calibrate_benign_runs(summaries)
    assert model["status"] == "PROVISIONAL_BENIGN_CALIBRATION"
    assert {run["run_id"] for run in model["training_runs"]} == {"benign-a", "benign-b"}
    with pytest.raises(LiveEvidenceError, match="only explicitly benign"):
        calibrate_benign_runs(
            [(paths[0], {"run_id": "attack", "scenario_id": "port-scan", "cleanup_verified": True})]
        )


def test_calibration_hash_and_live_service_persist_once_across_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import apps.api.live_service as live_service_module

    model_directory = tmp_path / "var/models/stage7-live-robust-v1"
    model = _model()
    save_calibration(model, model_directory)
    assert load_calibration(model_directory)["model_id"] == LIVE_ANOMALY_MODEL_ID

    telemetry_root = tmp_path / "experiments/stage7-telemetry/run-live"
    telemetry_root.mkdir(parents=True)
    stream_dir = telemetry_root / "live-stream"
    stream_dir.mkdir()
    telemetry_file = stream_dir / "telemetry-00000000-0000-0000-0000-000000000001.jsonl"
    telemetry_file.write_text("live source placeholder\n", encoding="utf-8")
    window = _window()
    monkeypatch.setattr(
        live_service_module,
        "read_telemetry_windows",
        lambda *_args, **_kwargs: ([window], {"status": "AUDIT_COMPLETE"}),
    )

    status_file = tmp_path / "var/runtime/ryu-status.json"
    ControllerStatusPublisher(status_file).publish(
        controller_instance_id="controller-1",
        datapaths=[{"datapath_id": window.datapath_id, "epoch_id": window.datapath_epoch_id}],
    )
    reader = ControllerStatusReader(status_file, stale_after_seconds=10.0)
    database = tmp_path / "sentinel.sqlite3"
    service = LiveScoringService(tmp_path, database, reader)
    first = service.poll_once()
    assert first["live_detection"] == "PROVISIONAL_ANOMALY_SCORING"
    assert first["accepted_windows_this_poll"] == 1
    assert first["eligible_windows_this_poll"] == 1
    assert first["telemetry"] == "FRESH_WINDOWS"
    second = service.poll_once()
    assert second["accepted_windows_this_poll"] == 0
    assert second["eligible_windows_this_poll"] == 1
    assert service.scores()[1] == 1
    assert service.ledger()[1] == 1

    restarted = LiveScoringService(tmp_path, database, reader)
    third = restarted.poll_once()
    assert third["accepted_windows_this_poll"] == 0
    assert restarted.scores()[1] == 1

    (model_directory / "baseline.json").write_text("{}", encoding="utf-8")
    with pytest.raises(LiveEvidenceError, match="hash mismatch"):
        load_calibration(model_directory)


def test_persisted_scores_do_not_make_stale_controller_look_like_fresh_telemetry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import apps.api.live_service as live_service_module

    save_calibration(_model(), tmp_path / "var/models/stage7-live-robust-v1")
    telemetry_dir = tmp_path / "experiments/stage7-telemetry/run-live/live-stream"
    telemetry_dir.mkdir(parents=True)
    (telemetry_dir / "telemetry-00000000-0000-0000-0000-000000000001.jsonl").write_text(
        "valid during fixture\n", encoding="utf-8"
    )
    window = _window()
    monkeypatch.setattr(
        live_service_module,
        "read_telemetry_windows",
        lambda *_args, **_kwargs: ([window], {"status": "AUDIT_COMPLETE"}),
    )

    status_path = tmp_path / "var/runtime/ryu-status.json"
    ControllerStatusPublisher(status_path).publish(
        controller_instance_id="controller-1",
        datapaths=[{"datapath_id": window.datapath_id, "epoch_id": window.datapath_epoch_id}],
    )
    active_reader = ControllerStatusReader(status_path, stale_after_seconds=10.0)
    database = tmp_path / "state.sqlite3"
    service = LiveScoringService(tmp_path, database, active_reader)
    assert service.poll_once()["accepted_windows_total"] == 1

    stale_reader = ControllerStatusReader(status_path, stale_after_seconds=0.000001)
    stale = LiveScoringService(tmp_path, database, stale_reader).poll_once()
    assert stale["controller"] == "STALE"
    assert stale["accepted_windows_total"] == 1
    assert stale["telemetry"] == "STALE_OR_UNAVAILABLE"
