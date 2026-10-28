"""Derive class support and error counts from frozen Stage 5D RF confusion matrices."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def analyze_holdout(holdout: Mapping[str, Any]) -> dict[str, Any]:
    metrics = holdout["metrics"]
    labels = list(metrics["confusion_matrix_labels"])
    matrix = metrics["confusion_matrix"]
    if not labels or len(labels) != len(set(labels)):
        raise ValueError("confusion matrix labels must be unique and non-empty")
    if len(matrix) != len(labels) or any(len(row) != len(labels) for row in matrix):
        raise ValueError("confusion matrix dimensions do not match labels")
    if "Benign" not in labels:
        raise ValueError("expected the frozen CSE benign label 'Benign'")
    train_counts: Mapping[str, int] = holdout["train_class_distribution"]
    test_counts: Mapping[str, int] = holdout["test_class_distribution"]
    benign_index = labels.index("Benign")
    row_support = [sum(row) for row in matrix]
    column_support = [
        sum(matrix[row][column] for row in range(len(labels))) for column in range(len(labels))
    ]
    observed_test = {label: row_support[index] for index, label in enumerate(labels)}
    if any(observed_test[label] != test_counts.get(label, 0) for label in labels) or any(
        label not in observed_test and count != 0 for label, count in test_counts.items()
    ):
        raise ValueError("confusion matrix row totals do not match test class support")
    if sum(row_support) != holdout["test_rows"]:
        raise ValueError("confusion matrix total does not match test row count")
    benign_support = row_support[benign_index]
    benign_to_any_attack = benign_support - matrix[benign_index][benign_index]
    classes: dict[str, dict[str, Any]] = {}
    for index, label in enumerate(labels):
        train_support = int(train_counts.get(label, 0))
        test_support = row_support[index]
        predicted_support = column_support[index]
        true_positive = int(matrix[index][index])
        precision = (
            true_positive / predicted_support
            if predicted_support
            else (0.0 if test_support else None)
        )
        recall = true_positive / test_support if test_support else None
        if test_support or predicted_support:
            f1 = (
                2 * precision * recall / (precision + recall)
                if precision is not None and recall is not None and precision + recall > 0
                else 0.0
            )
        else:
            f1 = None
        if label == "Benign":
            attack_to_benign_count = None
            attack_to_benign_rate = None
            benign_to_attack_count = benign_to_any_attack
            benign_to_attack_rate = (
                benign_to_any_attack / benign_support if benign_support else None
            )
            benign_to_this_attack: dict[str, Any] | None = None
        else:
            attack_to_benign_count = int(matrix[index][benign_index])
            attack_to_benign_rate = attack_to_benign_count / test_support if test_support else None
            benign_to_attack_count = int(matrix[benign_index][index])
            benign_to_attack_rate = (
                benign_to_attack_count / benign_support if benign_support else None
            )
            benign_to_this_attack = {
                "count": benign_to_attack_count,
                "rate_among_benign_test_rows": benign_to_attack_rate,
            }
        classes[label] = {
            "training_support": train_support,
            "test_support": test_support,
            "predicted_support": predicted_support,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "test_to_training_support_ratio": (
                test_support / train_support if train_support else None
            ),
            "attack_to_benign_error_count": attack_to_benign_count,
            "attack_to_benign_error_rate_within_class": attack_to_benign_rate,
            "benign_to_attack_error_count": benign_to_attack_count,
            "benign_to_attack_error_rate_among_benign": benign_to_attack_rate,
            "benign_to_this_attack": benign_to_this_attack,
        }
    return {
        "holdout_id": holdout["holdout_id"],
        "training_rows": holdout["train_rows"],
        "test_rows": holdout["test_rows"],
        "class_analysis": classes,
        "confusion_matrix": {
            "labels": labels,
            "counts_actual_rows_predicted_columns": matrix,
        },
        "existing_metrics_unchanged": {
            "accuracy": metrics["accuracy"],
            "weighted_f1": metrics["weighted_f1"],
            "primary_test_supported_macro_f1": metrics["macro_f1_test_supported_classes"],
            "primary_macro_f1_as_recorded": metrics["macro_f1"],
            "benign_fpr": metrics["benign_false_positive_rate"],
            "attack_fnr_as_benign": metrics["attack_false_negative_rate_as_benign"],
            "per_class_f1": {
                label: metrics["per_class"].get(label, {}).get("f1") for label in labels
            },
        },
    }


def compare_existing_metrics(analyses: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if len(analyses) != 2:
        raise ValueError("expected exactly the frozen reciprocal holdouts A and B")
    by_id = {item["holdout_id"]: item for item in analyses}
    if set(by_id) != {"CSE-SFH-A", "CSE-SFH-B"}:
        raise ValueError("holdout IDs differ from frozen CSE-SFH-A/B")
    fields = (
        "accuracy",
        "weighted_f1",
        "primary_test_supported_macro_f1",
        "benign_fpr",
        "attack_fnr_as_benign",
    )
    a = by_id["CSE-SFH-A"]["existing_metrics_unchanged"]
    b = by_id["CSE-SFH-B"]["existing_metrics_unchanged"]
    return {
        "holdout_A": {field: a[field] for field in fields},
        "holdout_B": {field: b[field] for field in fields},
        "B_minus_A": {field: b[field] - a[field] for field in fields},
        "note": (
            "Values are copied from the frozen Stage 5D metrics; differences are descriptive only."
        ),
    }
