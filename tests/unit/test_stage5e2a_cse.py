import csv
import gzip
from pathlib import Path
from typing import Any, cast

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from ml.evaluation.stage5e2a_cse import (
    TEST_SOURCE,
    UNSEEN_LABEL,
    _closed_set_metrics,
    _stream_test_predictions,
    verify_preflight_for_experiment,
)


def _preflight() -> tuple[dict[str, object], list[str]]:
    source_names = [f"train-{index}.csv" for index in range(6)] + [TEST_SOURCE]
    schema = [f"feature-{index}" for index in range(77)]
    files: list[dict[str, object]] = [
        {
            "file": source_names[0],
            "feature_names": schema,
            "class_counts": {"Benign": 4, "Attack": 2},
        },
    ]
    files.extend(
        {
            "file": name,
            "feature_names": schema,
            "class_counts": {"Benign": 3},
        }
        for name in source_names[1:6]
    )
    files.append(
        {
            "file": TEST_SOURCE,
            "feature_names": schema,
            "class_counts": {"Benign": 2, UNSEEN_LABEL: 3},
        }
    )
    return {"passed": True, "files": files}, source_names


def test_preflight_requires_tuesday_test_and_training_absence_of_loic() -> None:
    preflight, sources = _preflight()
    result = verify_preflight_for_experiment(preflight, sources)
    assert result["passed"] is True
    assert result["test_source"] == TEST_SOURCE
    assert TEST_SOURCE not in result["training_sources"]
    assert UNSEEN_LABEL not in result["training_label_vocabulary"]
    assert result["loic_http_absent_from_training"] is True
    assert result["feature_count"] == 77


def test_preflight_fails_if_loic_has_training_support() -> None:
    preflight, sources = _preflight()
    files = cast(dict[str, Any], preflight)["files"]
    files[0]["class_counts"][UNSEEN_LABEL] = 1
    with pytest.raises(ValueError, match="LOIC-HTTP unexpectedly"):
        verify_preflight_for_experiment(preflight, sources)


def test_closed_set_metrics_include_test_only_class_in_macro_denominator() -> None:
    # Actual rows: Benign=2, known Attack=1, unseen LOIC=3. The model can
    # predict only Benign or Attack and assigns all LOIC rows to those classes.
    labels = ["Benign", "Attack", UNSEEN_LABEL]
    matrix = np.asarray([[2, 0, 0], [0, 1, 0], [1, 2, 0]])
    result = _closed_set_metrics(matrix, labels)

    assert result["accuracy"] == 3 / 6
    assert result["macro_f1_denominator_class_count"] == 3
    assert result["per_class"][UNSEEN_LABEL]["f1"] == 0.0
    assert result["per_class"][UNSEEN_LABEL]["test_support"] == 3
    assert result["benign_fpr"] == 0.0
    assert result["attack_fnr_as_benign"] == 1 / 4


def test_streamed_predictions_map_training_codes_into_eval_only_class_axis(
    tmp_path: Path,
) -> None:
    class FixedPredictor:
        def predict(self, features: np.ndarray) -> np.ndarray:
            assert features.shape == (2, 1)
            return np.asarray([0, 1])

    source = tmp_path / "prepared.csv.gz"
    with gzip.open(source, "wt", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["feature", "Label"])
        writer.writerow(["1.0", "Benign"])
        writer.writerow(["2.0", "A-unseen-test-only"])

    matrix, supports, _ = _stream_test_predictions(
        source,
        cast(RandomForestClassifier, FixedPredictor()),
        1,
        {"Benign": 0, "Z-known": 1},
        ["Benign", "Z-known"],
        ["A-unseen-test-only", "Benign", "Z-known"],
    )

    assert matrix.tolist() == [[0, 0, 1], [0, 1, 0], [0, 0, 0]]
    assert supports == {"Benign": 1, "A-unseen-test-only": 1}
