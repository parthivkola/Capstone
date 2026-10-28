from typing import Any, cast

from ml.evaluation.stage5e_error_analysis import analyze_holdout, compare_existing_metrics


def _holdout() -> dict[str, object]:
    return {
        "holdout_id": "CSE-SFH-A",
        "train_rows": 12,
        "test_rows": 8,
        "train_class_distribution": {"Benign": 10, "Attack": 2},
        "test_class_distribution": {"Benign": 5, "Attack": 3},
        "metrics": {
            "confusion_matrix_labels": ["Benign", "Attack"],
            "confusion_matrix": [[4, 1], [2, 1]],
            "accuracy": 0.625,
            "weighted_f1": 0.6,
            "macro_f1_test_supported_classes": 0.58,
            "macro_f1": 0.58,
            "benign_false_positive_rate": 0.2,
            "attack_false_negative_rate_as_benign": 2 / 3,
            "per_class": {"Benign": {"f1": 0.727}, "Attack": {"f1": 0.4}},
        },
    }


def test_analysis_derives_support_errors_and_ratio_from_confusion_matrix() -> None:
    result = analyze_holdout(_holdout())
    benign = result["class_analysis"]["Benign"]
    attack = result["class_analysis"]["Attack"]

    assert benign["training_support"] == 10
    assert benign["test_support"] == 5
    assert benign["predicted_support"] == 6
    assert benign["test_to_training_support_ratio"] == 0.5
    assert benign["benign_to_attack_error_count"] == 1
    assert benign["benign_to_attack_error_rate_among_benign"] == 0.2
    assert attack["training_support"] == 2
    assert attack["test_support"] == 3
    assert attack["predicted_support"] == 2
    assert attack["precision"] == 0.5
    assert attack["recall"] == 1 / 3
    assert attack["attack_to_benign_error_count"] == 2
    assert attack["attack_to_benign_error_rate_within_class"] == 2 / 3
    assert attack["benign_to_attack_error_count"] == 1
    assert result["existing_metrics_unchanged"]["accuracy"] == 0.625


def test_analysis_fails_if_confusion_totals_disagree_with_support() -> None:
    bad = _holdout()
    bad["metrics"]["confusion_matrix"] = [[3, 1], [2, 1]]  # type: ignore[index]
    try:
        analyze_holdout(bad)
    except ValueError as exc:
        assert "row totals" in str(exc)
    else:
        raise AssertionError("inconsistent confusion matrix must fail")


def test_predicted_only_class_has_zero_f1_and_undefined_recall() -> None:
    holdout = _holdout()
    metrics = cast(dict[str, Any], holdout["metrics"])
    metrics["confusion_matrix_labels"] = ["Benign", "Attack", "Other"]
    metrics["confusion_matrix"] = [
        [3, 1, 1],
        [2, 1, 0],
        [0, 0, 0],
    ]
    result = analyze_holdout(holdout)
    other = result["class_analysis"]["Other"]
    assert other["precision"] == 0.0
    assert other["recall"] is None
    assert other["f1"] == 0.0


def test_metric_comparison_preserves_values_and_reports_reciprocal_delta() -> None:
    first = analyze_holdout(_holdout())
    second_data = _holdout()
    second_data["holdout_id"] = "CSE-SFH-B"
    second_data["metrics"]["accuracy"] = 0.5  # type: ignore[index]
    second = analyze_holdout(second_data)
    result = compare_existing_metrics([first, second])

    assert result["holdout_A"]["accuracy"] == 0.625
    assert result["holdout_B"]["accuracy"] == 0.5
    assert result["B_minus_A"]["accuracy"] == -0.125
