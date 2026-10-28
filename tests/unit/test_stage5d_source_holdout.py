from collections import Counter

import numpy as np

from ml.evaluation.stage5d_cse import _metrics, validate_holdout_support


def test_holdout_support_checks_disjoint_sources_and_labels() -> None:
    result = validate_holdout_support(
        ["train-a.csv", "train-b.csv"],
        ["test.csv"],
        {
            "train-a.csv": Counter({"Benign": 3}),
            "train-b.csv": Counter({"Attack": 2}),
            "test.csv": Counter({"Benign": 1, "Attack": 1}),
        },
    )
    assert result["train_test_disjoint"] is True
    assert result["all_test_labels_supported"] is True


def test_holdout_support_identifies_source_overlap() -> None:
    try:
        validate_holdout_support(
            ["shared.csv"], ["shared.csv"], {"shared.csv": Counter({"Benign": 1})}
        )
    except ValueError as exc:
        assert "source overlap" in str(exc)
    else:
        raise AssertionError("overlapping source must fail")


def test_holdout_support_reports_missing_training_label_support() -> None:
    result = validate_holdout_support(
        ["train.csv"],
        ["test.csv"],
        {"train.csv": Counter({"Benign": 1}), "test.csv": Counter({"Novel": 1})},
    )
    assert result["all_test_labels_supported"] is False
    assert result["test_labels_without_training_support"] == ["Novel"]


def test_metrics_include_class_scores_confusion_and_benign_rates() -> None:
    result = _metrics(
        np.asarray(["Benign", "Attack", "Attack"], dtype=object),
        np.asarray(["Attack", "Benign", "Attack"], dtype=object),
        ["Attack", "Benign"],
    )
    assert result["accuracy"] == 1 / 3
    assert result["confusion_matrix"] == [[1, 1], [1, 0]]
    assert result["benign_false_positive_rate"] == 1.0
    assert result["attack_false_negative_rate_as_benign"] == 0.5
    assert set(result["per_class"]) == {"Attack", "Benign"}
    assert result["macro_f1_test_supported_classes"] == result["macro_f1"]
