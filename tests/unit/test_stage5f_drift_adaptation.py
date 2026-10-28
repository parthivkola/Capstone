from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from ml.evaluation.stage5f_drift_adaptation import (
    ATTACK,
    BENIGN,
    FROZEN_WINDOW_ORDER,
    MAX_BUFFER_ROWS,
    PSI_COMPARISON_ROWS,
    PSI_FEATURE_THRESHOLD,
    PSI_FEATURES_TO_TRIGGER,
    PSI_REFERENCE_ROWS,
    _bin_counts,
    _fit_psi_bins,
    _partition_ordinals,
    _partition_seed_for_run,
    _prepared_path,
    _sample_ordinals,
    _select_window_buffer,
    adaptation_latency,
    binary_label,
    f1_score_from_confusion,
    psi_report,
    psi_triggered,
    psi_values,
    released_window_after_boundary,
    rollback_reasons,
    should_attempt_update,
)


def test_implementation_window_order_matches_frozen_protocol() -> None:
    root = Path(__file__).resolve().parents[2]
    with (root / "experiments/stage5f/drift-adaptation-protocol.json").open(
        encoding="utf-8"
    ) as stream:
        protocol = json.load(stream)
    observed = [
        (item["window_id"], item["source_file"])
        for item in protocol["source_and_window_design"]["sequential_evaluation_windows"]
    ]
    expected = [
        ("W1", "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"),
        ("W2", "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv"),
        ("W3", "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"),
        ("W4", "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv"),
    ]
    assert list(FROZEN_WINDOW_ORDER) == expected
    assert observed == expected


def test_prepared_path_uses_stage5d_manifest_basename() -> None:
    root = Path(__file__).resolve().parents[2]
    source = {
        "file": "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
        "prepared_path": (
            "data/processed/stage5d/cse-cic-ids2018/"
            "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv.model-ready.csv.gz"
        ),
    }
    resolved = _prepared_path(root, source)
    assert resolved.name == (
        "Friday-02-03-2018_TrafficForML_CICFlowMeter.model-ready.csv.gz"
    )
    assert resolved.is_file()


def test_binary_label_mapping_is_benign_vs_all_other_labels() -> None:
    assert binary_label("Benign") == 0
    assert binary_label("DDoS attacks-LOIC-HTTP") == 1
    assert binary_label("Bot") == 1
    with pytest.raises(ValueError, match="empty label"):
        binary_label("")


def test_sha_partition_is_deterministic_disjoint_and_exact_ratio() -> None:
    ordinals = np.arange(1000, dtype=np.int64)
    first = _partition_ordinals(ordinals, 2026, "source.csv", BENIGN)
    second = _partition_ordinals(ordinals, 2026, "source.csv", BENIGN)
    assert all(np.array_equal(left, right) for left, right in zip(first, second, strict=True))
    assert [len(part) for part in first] == [700, 150, 150]
    assert len(set(np.concatenate(first).tolist())) == len(ordinals)
    other_seed = _partition_ordinals(ordinals, 2027, "source.csv", BENIGN)
    assert not np.array_equal(first[0], other_seed[0])


def test_all_model_seeds_share_the_frozen_initial_partitions() -> None:
    root = Path(__file__).resolve().parents[2]
    with (root / "experiments/stage5f/drift-adaptation-protocol.json").open(
        encoding="utf-8"
    ) as stream:
        protocol = json.load(stream)
    source_ordinals = np.arange(10_000, dtype=np.int64)
    partitions = [
        _partition_ordinals(
            source_ordinals,
            _partition_seed_for_run(protocol, model_seed),
            "frozen-source.csv",
            BENIGN,
        )
        for model_seed in (2026, 2027, 2028, 2029, 2030)
    ]
    assert [_partition_seed_for_run(protocol, seed) for seed in range(2026, 2031)] == [
        2026
    ] * 5
    for result in partitions[1:]:
        assert all(
            np.array_equal(expected, actual)
            for expected, actual in zip(partitions[0], result, strict=True)
        )


def test_deterministic_sample_has_requested_size_and_repeatable_membership() -> None:
    first = _sample_ordinals(1000, 100, 2026, "sample")
    second = _sample_ordinals(1000, 100, 2026, "sample")
    assert first.shape == (100,)
    assert np.array_equal(first, second)
    assert np.all(first[:-1] < first[1:])
    assert PSI_REFERENCE_ROWS == 50_000
    assert PSI_COMPARISON_ROWS == 10_000
    with pytest.raises(ValueError, match="cannot sample"):
        _sample_ordinals(9, 10, 2026, "too-many")


def test_psi_decile_bins_use_reference_and_handle_constant_feature() -> None:
    reference = np.column_stack(
        [np.arange(1000, dtype=np.float32), np.full(1000, 7, dtype=np.float32)]
    )
    bins = _fit_psi_bins(reference)
    assert len(bins) == 2
    assert len(bins[0]["edges"]) == 11
    assert bins[1]["constant_reference_value"] == 7.0
    assert len(bins[0]["reference_counts"]) == len(bins[0]["edges"]) + 1
    assert len(bins[1]["reference_counts"]) == 3
    assert np.array_equal(_bin_counts(np.array([6.0, 7.0, 8.0]), np.array([]), 7.0), [1, 1, 1])


def test_psi_calculation_and_five_feature_operational_trigger() -> None:
    reference = np.tile(np.arange(1000, dtype=np.float32)[:, None], (1, 6))
    bins = _fit_psi_bins(reference)
    counts = [spec["reference_counts"] for spec in bins]
    same = reference[:10]
    values_same = psi_values(counts, same, bins)
    shifted = np.full((10, 6), 10_000, dtype=np.float32)
    values_shifted = psi_values(counts, shifted, bins)
    assert np.all(values_same >= 0)
    assert np.all(values_shifted > values_same)
    assert psi_triggered(np.full(4, PSI_FEATURE_THRESHOLD)) is False
    assert psi_triggered(np.full(PSI_FEATURES_TO_TRIGGER, PSI_FEATURE_THRESHOLD)) is True
    assert PSI_FEATURE_THRESHOLD == 0.20


def test_initial_validation_psi_uses_frozen_sample_and_trigger_rule() -> None:
    reference = np.tile(np.arange(50_000, dtype=np.float32)[:, None], (1, 6))
    bins = _fit_psi_bins(reference)
    reference_counts = [spec["reference_counts"] for spec in bins]
    validation_comparison = np.full((PSI_COMPARISON_ROWS, 6), 100_000, dtype=np.float32)
    result = psi_report(reference_counts, validation_comparison, bins)
    assert result["comparison_rows"] == 10_000
    assert result["feature_threshold"] == 0.20
    assert result["required_signaled_features"] == 5
    assert result["signaled_feature_count"] == 6
    assert result["psi_triggered"] is True


def test_label_release_delay_and_terminal_window() -> None:
    assert released_window_after_boundary(1) == (None, False)
    assert released_window_after_boundary(2) == ("W1", False)
    assert released_window_after_boundary(3) == ("W2", False)
    assert released_window_after_boundary(4) == ("W3", True)
    with pytest.raises(ValueError):
        released_window_after_boundary(5)


def test_adaptation_latency_records_release_decision_and_fit_completion() -> None:
    result = adaptation_latency(1_000_000_000, 1_250_000_000, 2_000_000_000)
    assert result["release_to_decision_seconds"] == 0.25
    assert result["decision_to_fit_complete_seconds"] == 0.75
    assert result["release_to_fit_complete_seconds"] == 1.0
    assert result["candidate_fit_complete_monotonic_ns"] == 2_000_000_000
    with pytest.raises(ValueError, match="monotonic"):
        adaptation_latency(2, 1, 3)


def test_strategy_schedule_static_periodic_and_triggered_rules() -> None:
    for window in ("W1", "W2", "W3", "W4"):
        assert should_attempt_update("static", window, True) is False
    assert should_attempt_update("periodic", "W1", True) is False
    assert should_attempt_update("periodic", "W2", False) is True
    assert should_attempt_update("periodic", "W3", True) is False
    assert should_attempt_update("periodic", "W4", True) is False
    assert should_attempt_update("drift_triggered", "W1", False) is False
    assert should_attempt_update("drift_triggered", "W1", True) is True
    assert should_attempt_update("drift_triggered", "W4", True) is False
    with pytest.raises(ValueError):
        should_attempt_update("unknown", "W1", True)


def test_rollback_thresholds_and_acceptance() -> None:
    initial = {"macro_f1": 0.8, "benign_fpr": 0.03}
    accepted = {"macro_f1": 0.76, "benign_fpr": 0.04}
    assert rollback_reasons(initial, accepted) == []
    assert rollback_reasons(initial, {"macro_f1": 0.749, "benign_fpr": 0.04}) == [
        "anchor_macro_f1_drop_gt_0.05"
    ]
    assert rollback_reasons(initial, {"macro_f1": 0.8, "benign_fpr": 0.051}) == [
        "anchor_benign_fpr_increase_gt_0.02"
    ]


def test_buffer_selection_is_deterministic_bounded_and_source_local(tmp_path: Path) -> None:
    rows = [
        [str(float(row + column)) for column in range(77)] + [BENIGN if row % 3 else "Bot"]
        for row in range(30)
    ]
    path = tmp_path / "tiny.csv.gz"
    with gzip.open(path, "wt", encoding="utf-8", newline="") as stream:
        stream.write(",".join([*(f"f{i}" for i in range(77)), "Label"]) + "\n")
        for row in rows:
            stream.write(",".join(row) + "\n")
    source: dict[str, Any] = {
        "file": "tiny.csv",
        "prepared_path": "tiny.csv.gz",
        "prepared_rows": 30,
        "prepared_class_counts": {BENIGN: 20, "Bot": 10},
    }
    first = _select_window_buffer(tmp_path, source, 2026, "W1")
    second = _select_window_buffer(tmp_path, source, 2026, "W1")
    assert np.array_equal(first[0], second[0])
    assert np.array_equal(first[1], second[1])
    assert first[2] == second[2]
    assert first[2]["rows_by_class"] == {BENIGN: 20, ATTACK: 10}
    assert len(first[1]) <= MAX_BUFFER_ROWS
    assert len(first[2]["selected_ordinals_sha256"]) == 64


def test_binary_confusion_metrics_cover_both_classes() -> None:
    confusion = np.asarray([[80, 20], [10, 90]], dtype=np.int64)
    f1 = f1_score_from_confusion(confusion)
    assert len(f1) == 2
    assert 0.0 < f1[0] < 1.0
    assert 0.0 < f1[1] < 1.0
