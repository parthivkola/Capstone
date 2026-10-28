"""Safety tests for run-aware live dataset assembly and model gates."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src.sdn_defense.live_dataset import (
    LiveDatasetError,
    _assign_run_splits,
    _scenario_journal,
    build_live_dataset,
    sha256,
    train_preliminary_live_model,
)


def test_run_assignment_never_splits_one_run_across_partitions() -> None:
    metadata = {f"benign-{index}": {"label": "BENIGN"} for index in range(3)} | {
        f"scan-{index}": {"label": "PORT_SCAN"} for index in range(3)
    }
    splits = _assign_run_splits(metadata)
    assert set(splits.values()) == {"train", "validation", "test"}
    assert len({splits[run_id] for run_id in metadata if run_id.startswith("benign")}) == 3
    assert len({splits[run_id] for run_id in metadata if run_id.startswith("scan")}) == 3


def test_run_assignment_rejects_too_few_independent_runs() -> None:
    with pytest.raises(LiveDatasetError, match="three independent runs"):
        _assign_run_splits({"one": {"label": "BENIGN"}, "two": {"label": "BENIGN"}})


def test_scenario_label_requires_target_and_successful_child_evidence(tmp_path: Path) -> None:
    journal = tmp_path / "port-scan-run.jsonl"
    journal.write_text(
        json.dumps(
            {
                "event_type": "scenario_started",
                "run_id": "run-1",
                "scenario": "port-scan",
                "target": "h3",
                "scenario_run": {"destination_scope": {"ip": "10.0.0.3"}},
            }
        )
        + "\n"
        + json.dumps({"event_type": "run_completed", "run_id": "run-1", "scenario_id": "port-scan"})
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "port-scan-process.json").write_text(
        json.dumps({"timeout": False, "return_code": 0}), encoding="utf-8"
    )
    assert _scenario_journal(journal, run_id="run-1", scenario="port-scan")["target"] == "10.0.0.3"
    with pytest.raises(LiveDatasetError, match="label/target"):
        _scenario_journal(journal, run_id="different-run", scenario="port-scan")


def test_dataset_builder_rejects_unverified_or_missing_run_artifacts(tmp_path: Path) -> None:
    run = tmp_path / "unverified"
    run.mkdir()
    (run / "run-manifest.json").write_text(
        json.dumps({"state": "FAILED", "source_type": "LIVE", "cleanup_verified": True}),
        encoding="utf-8",
    )
    (run / "collection-summary.json").write_text("{}", encoding="utf-8")
    output = tmp_path / "dataset"
    with pytest.raises(LiveDatasetError, match="not verified live evidence"):
        build_live_dataset([run, run, run], output_directory=output)
    assert not output.exists()


def test_dataset_builder_rejects_corrupted_summary_hash(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    summary = run / "collection-summary.json"
    summary.write_text("{}", encoding="utf-8")
    (run / "run-manifest.json").write_text(
        json.dumps(
            {
                "state": "VERIFIED_FOR_RESEARCH_DATASET",
                "source_type": "LIVE",
                "cleanup_verified": True,
                "summary_sha256": "0" * 64,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(LiveDatasetError, match="summary hash mismatch"):
        build_live_dataset([run, run, run], output_directory=tmp_path / "new-dataset")


def test_training_input_rejects_duplicate_ids_and_invalid_features(tmp_path: Path) -> None:
    rows_path = tmp_path / "windows.jsonl"
    row: dict[str, Any] = {
        "window_id": "same-window",
        "run_id": "run-one",
        "ground_truth": "BENIGN",
        "feature_schema_id": "stage7-live-rule-window-v1",
        "features": {
            "rule_packet_delta": 1,
            "rule_byte_delta": 64,
            "rule_packet_rate_per_second": 0.5,
            "rule_byte_rate_per_second": float("nan"),
        },
    }
    rows_path.write_text(json.dumps(row, allow_nan=True) + "\n", encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "feature_schema_id": "stage7-live-rule-window-v1",
                "feature_order": [
                    "rule_packet_delta",
                    "rule_byte_delta",
                    "rule_packet_rate_per_second",
                    "rule_byte_rate_per_second",
                ],
                "rows_sha256": sha256(rows_path),
                "run_splits": {"run-one": "train"},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(LiveDatasetError, match="invalid feature values"):
        train_preliminary_live_model(
            dataset_manifest_path=manifest_path,
            output_directory=tmp_path / "new-model",
        )

    row["features"]["rule_byte_rate_per_second"] = 1.0
    rows_path.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n", encoding="utf-8")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["rows_sha256"] = sha256(rows_path)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(LiveDatasetError, match="duplicate or missing window ID"):
        train_preliminary_live_model(
            dataset_manifest_path=manifest_path,
            output_directory=tmp_path / "other-model",
        )
