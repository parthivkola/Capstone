"""Validation for the frozen Stage 5C.1 CSE protocol metadata."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_PATH = ROOT / "experiments/stage5c1/cse-protocol.json"


def _protocol() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(PROTOCOL_PATH.read_text(encoding="utf-8")))


def test_common_schema_and_twenty_february_projection_are_frozen() -> None:
    protocol = _protocol()
    schema = protocol["common_schema"]
    columns = schema["ordered_columns"]
    assert schema["column_count"] == 80
    assert len(columns) == 80
    assert len(set(columns)) == 80
    assert columns[-1] == "Label"
    projection = schema["twenty_february_projection"]
    assert projection["retain_columns_in_order"] == columns
    assert projection["extra_source_columns"] == ["Flow ID", "Src IP", "Src Port", "Dst IP"]
    assert projection["raw_file_modified"] is False


def test_feature_and_row_quality_policies_are_explicit() -> None:
    protocol = _protocol()
    feature = protocol["feature_policy"]
    excluded = {entry["column"] for entry in feature["excluded_from_model_features"]}
    assert {"Flow ID", "Src IP", "Dst IP", "Timestamp"} <= excluded
    assert "Label" in excluded
    assert feature["no_silent_column_removal"] is True

    quality = protocol["row_quality_policy"]
    repeated = quality["repeated_header"]
    assert repeated["action"] == "exclude_row"
    assert repeated["trim_or_normalize_for_detection"] is False
    assert repeated["known_repeated_header_total"] == 59
    assert repeated["known_selected_holdout_files_have_repeated_header_rows"] == 0

    nonfinite = quality["nonfinite"]
    assert nonfinite["nan"] == "exclude row"
    assert nonfinite["positive_infinity"] == "exclude row"
    assert nonfinite["negative_infinity"] == "exclude row"
    assert nonfinite["finite_zero"] == "retain row"
    assert nonfinite["impute_or_replace"] is False


def test_reciprocal_source_holdouts_are_disjoint_and_have_label_support() -> None:
    protocol = _protocol()
    experiments = {item["id"]: item for item in protocol["source_file_holdouts"]}
    first = experiments["CSE-SFH-A"]
    second = experiments["CSE-SFH-B"]
    assert first["train"] == [
        "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
        "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
        "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
        "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
        "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
        "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
    ]
    assert first["test"] == ["Friday-23-02-2018_TrafficForML_CICFlowMeter.csv"]
    assert second["train"] == [
        "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
        "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
        "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
        "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
        "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
        "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
    ]
    assert second["test"] == ["Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv"]
    for experiment in (first, second):
        assert not (set(experiment["train"]) & set(experiment["test"]))
        assert experiment["row_randomization_across_sources"] is False
        assert set(experiment["test_label_counts"]) <= set(experiment["train_label_counts"])


def test_loic_http_support_is_explicit_and_unseen_condition_stays_separate() -> None:
    condition = _protocol()["unseen_class_condition"]
    assert condition["label"] == "DDoS attacks-LOIC-HTTP"
    assert condition["source"].startswith("Thuesday-20-02-2018")
    assert condition["training_support_in_frozen_known_class_experiments"] is True
    assert condition["support_counts_in_frozen_known_class_training"] == {
        "CSE-SFH-A": 576191,
        "CSE-SFH-B": 576191,
    }
    assert "separate unseen-class/source experiment" in condition["policy"]


def test_source_manifest_covers_ten_immutable_files() -> None:
    protocol = _protocol()
    files = protocol["source_files"]
    assert len(files) == 10
    assert len({item["path"] for item in files}) == 10
    assert all(len(item["sha256_from_stage5c_audit"]) == 64 for item in files)
    assert all(item["roles"] for item in files)
    assert protocol["models_trained"] is False
