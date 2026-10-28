from typing import Any

import numpy as np
import pytest

from ml.evaluation.stage5e2a_cse import TEST_SOURCE, UNSEEN_LABEL
from ml.evaluation.stage5e2b_novelty import (
    BENIGN_LABEL,
    ISOLATION_FOREST_CONFIGURATION,
    apply_threshold,
    binary_metrics,
    select_threshold,
    validation_positions,
    verify_preflight,
)


def _integrity_and_manifest() -> tuple[dict[str, Any], dict[str, Any]]:
    names = [f"source-{index}.csv" for index in range(6)] + [TEST_SOURCE]
    features = [f"feature-{index}" for index in range(77)]
    manifest_rows = []
    integrity_files = []
    for index, name in enumerate(names):
        raw_digest = f"raw-{index}"
        prepared_digest = f"prepared-{index}"
        classes = {BENIGN_LABEL: 10}
        if index == 0:
            classes["Bot"] = 2
        if index == 6:
            classes[UNSEEN_LABEL] = 3
        manifest_rows.append(
            {
                "file": name,
                "sha256": raw_digest,
                "frozen_expected_sha256": raw_digest,
                "source_hash_matches_frozen_audit": True,
                "output_sha256": prepared_digest,
                "output_path": f"/tmp/{name}.gz",
                "final_usable_row_count": sum(classes.values()),
                "class_counts": classes,
            }
        )
        integrity_files.append(
            {
                "file": name,
                "sha256": prepared_digest,
                "feature_names": features,
                "feature_dtype": "float32",
                "target_column": "Label",
            }
        )
    return {"passed": True, "files": integrity_files}, {"source_statistics": manifest_rows}


def test_preflight_verifies_six_sources_schema_hashes_and_unseen_condition() -> None:
    integrity, manifest = _integrity_and_manifest()
    report = verify_preflight(integrity, manifest)

    assert report["passed"] is True
    assert report["training_source_count"] == 6
    assert report["test_source"]["file"] == TEST_SOURCE
    assert all(item["file"] != TEST_SOURCE for item in report["training_sources"])
    assert report["loic_http_absent_from_training_source_labels"] is True
    assert report["feature_count"] == 77
    assert report["prepared_hashes_match_stage5d_manifest"] is True


def test_preflight_fails_if_training_source_has_loic_http() -> None:
    integrity, manifest = _integrity_and_manifest()
    manifest["source_statistics"][0]["class_counts"][UNSEEN_LABEL] = 1
    with pytest.raises(ValueError, match="LOIC-HTTP occurs"):
        verify_preflight(integrity, manifest)


def test_preflight_fails_if_prepared_hash_differs() -> None:
    integrity, manifest = _integrity_and_manifest()
    integrity["files"][0]["sha256"] = "changed"
    with pytest.raises(ValueError, match="preflight failed"):
        verify_preflight({"passed": False, "failures": ["hash mismatch"]}, manifest)
    with pytest.raises(ValueError, match="hash differs"):
        verify_preflight(integrity, manifest)


def test_validation_partition_is_deterministic_and_exact_per_source() -> None:
    first = validation_positions(100, seed=2026, source_name="source.csv")
    second = validation_positions(100, seed=2026, source_name="source.csv")
    other_source = validation_positions(100, seed=2026, source_name="other.csv")

    assert len(first) == 20
    assert np.array_equal(first, second)
    assert not np.array_equal(first, other_source)
    assert len(np.unique(first)) == len(first)


def test_threshold_selection_and_score_direction_are_deterministic() -> None:
    scores = np.arange(1000, dtype=np.float64)
    first = select_threshold(scores, 0.01)
    second = select_threshold(scores, 0.01)

    assert first == second
    assert first["threshold"] == 990.0
    assert first["validation_benign_fpr"] == 0.01
    assert apply_threshold(np.asarray([990.0, 989.0]), first["threshold"]).tolist() == [True, False]


def test_threshold_ties_choose_nearest_conservative_attainable_fpr() -> None:
    report = select_threshold(np.asarray([0.0, 1.0, 2.0, 2.0]), 0.25)
    assert report["validation_benign_unknown_count"] == 0
    assert report["validation_benign_fpr"] == 0.0


def test_binary_metrics_report_requested_counts_and_rates() -> None:
    report = binary_metrics(
        {"benign_known": 99, "benign_unknown": 1, "loic_known": 40, "loic_unknown": 60}
    )
    assert report["benign_fpr"] == 0.01
    assert report["benign_rejection_rate"] == 0.01
    assert report["loic_http_unknown_recall"] == 0.6
    assert report["unknown_precision"] == 60 / 61
    assert report["confusion_matrix"] == [[99, 1], [40, 60]]


def test_isolation_configuration_is_explicit_and_uses_fixed_seed() -> None:
    assert ISOLATION_FOREST_CONFIGURATION["random_state"] == 2026
    assert ISOLATION_FOREST_CONFIGURATION["n_estimators"] == 100
    assert ISOLATION_FOREST_CONFIGURATION["contamination"] == "auto"
    # The custom validation threshold, not estimator.predict, defines UNKNOWN.
    assert apply_threshold(np.asarray([0.9]), 0.8).tolist() == [True]
