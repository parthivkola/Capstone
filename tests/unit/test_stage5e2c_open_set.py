from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from ml.evaluation.stage5e2a_cse import TEST_SOURCE, UNSEEN_LABEL
from ml.evaluation.stage5e2b_novelty import BENIGN_LABEL
from ml.evaluation.stage5e2c_open_set import (
    RF_CONFIGURATION,
    apply_confidence_threshold,
    open_set_metrics,
    select_confidence_threshold,
    summarize_open_set_predictions,
    verify_stage_preflight,
)


def _fixture(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    names = [f"source-{index}.csv" for index in range(6)] + [TEST_SOURCE]
    features = [f"feature-{index}" for index in range(77)]
    stats = []
    integrity_files = []
    for index, name in enumerate(names):
        classes = {BENIGN_LABEL: 100}
        if index < 6:
            classes["Bot"] = 20
        else:
            classes[UNSEEN_LABEL] = 20
        raw_hash = f"raw-hash-{index}"
        prepared_hash = f"prepared-hash-{index}"
        stats.append(
            {
                "file": name,
                "sha256": raw_hash,
                "frozen_expected_sha256": raw_hash,
                "source_hash_matches_frozen_audit": True,
                "output_sha256": prepared_hash,
                "output_path": f"data/{name}.gz",
                "final_usable_row_count": sum(classes.values()),
                "class_counts": classes,
            }
        )
        integrity_files.append(
            {
                "file": name,
                "sha256": prepared_hash,
                "feature_names": features,
                "feature_dtype": "float32",
                "target_column": "Label",
            }
        )
    manifest = {"source_statistics": stats}
    integrity = {"passed": True, "files": integrity_files}
    frozen_result = {"holdouts": [{"model": RF_CONFIGURATION}, {"model": RF_CONFIGURATION}]}
    (root / "experiments/stage5d").mkdir(parents=True)
    (root / "experiments/stage5d/cse-source-holdout-rf.json").write_text(
        json.dumps(frozen_result), encoding="utf-8"
    )
    return integrity, manifest


def test_preflight_excludes_tuesday_and_loic_from_training(tmp_path: Path) -> None:
    integrity, manifest = _fixture(tmp_path)
    report = verify_stage_preflight(tmp_path, integrity, manifest)

    assert report["training_source_count"] == 6
    assert all(item["file"] != TEST_SOURCE for item in report["training_sources"])
    assert report["test_source_excluded_from_model_fit_and_threshold_selection"] is True
    assert report["loic_http_absent_from_training_labels"] is True
    assert UNSEEN_LABEL not in report["training_label_vocabulary"]
    assert report["feature_count"] == 77
    assert report["rf_configuration"]["configuration"] == RF_CONFIGURATION
    assert report["preprocessing_check"]["tuesday_used_for_preprocessing_fit"] is False


def test_preflight_fails_if_loic_occurs_in_a_training_source(tmp_path: Path) -> None:
    integrity, manifest = _fixture(tmp_path)
    manifest["source_statistics"][0]["class_counts"][UNSEEN_LABEL] = 1
    with pytest.raises(ValueError, match="LOIC-HTTP occurs"):
        verify_stage_preflight(tmp_path, integrity, manifest)


def test_confidence_threshold_is_deterministic_and_has_strict_direction() -> None:
    confidences = np.arange(1, 101, dtype=np.float64) / 100
    first = select_confidence_threshold(confidences, 0.01)
    second = select_confidence_threshold(confidences, 0.01)

    assert first == second
    assert first["validation_benign_rejected_count"] == 1
    assert first["validation_benign_rejection_rate"] == 0.01
    decisions = apply_confidence_threshold(
        np.asarray([0.01, first["threshold"], 1.0]), first["threshold"]
    )
    assert decisions.tolist() == [True, False, False]


def test_threshold_confidence_ties_are_indivisible_and_conservative() -> None:
    result = select_confidence_threshold(np.asarray([0.1, 0.1, 0.9, 0.9]), 0.25)
    assert result["validation_benign_rejected_count"] == 0
    assert result["validation_benign_rejection_rate"] == 0.0


def test_threshold_selector_accepts_only_validation_scores_not_test_labels() -> None:
    parameter_names = list(inspect.signature(select_confidence_threshold).parameters)
    assert parameter_names == ["benign_validation_confidences", "target_rejection_rate"]


def test_open_set_metrics_compute_rejection_recall_precision_and_f1() -> None:
    result = open_set_metrics(
        {"benign_known": 95, "benign_unknown": 5, "loic_known": 70, "loic_unknown": 30}
    )
    assert result["benign_rejection_rate_fpr"] == 0.05
    assert result["loic_http_unknown_recall"] == 0.3
    assert result["loic_http_known_rate"] == 0.7
    assert result["unknown_precision"] == 30 / 35
    assert result["unknown_f1"] == pytest.approx(2 * (30 / 35) * 0.3 / ((30 / 35) + 0.3))
    assert result["balanced_accuracy"] == 0.625
    assert result[
        "confusion_matrix_actual_rows_benign_then_loic_http_predicted_columns_known_then_unknown"
    ] == [[95, 5], [70, 30]]


def test_loic_known_class_distribution_excludes_unknown_predictions() -> None:
    result = summarize_open_set_predictions(
        [BENIGN_LABEL, BENIGN_LABEL, UNSEEN_LABEL, UNSEEN_LABEL],
        np.asarray([0.2, 0.8, 0.3, 0.9]),
        ["Bot", "Bot", "Bot", "XSS"],
        {"1%": {"threshold": 0.5}},
        ["Bot", "XSS"],
    )["1%"]
    assert result["benign_unknown"] == 1
    assert result["benign_known"] == 1
    assert result["loic_unknown"] == 1
    assert result["loic_known"] == 1
    assert result["loic_predicted_known_class_distribution"] == {"Bot": 0, "XSS": 1}
