"""Train-only preprocessing and classical baseline metrics."""

from __future__ import annotations

import math
import statistics
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)

IDENTIFIER_TOKENS = ("id", "ip", "timestamp", "time", "date", "filename", "source_file")
LABEL_NAMES = {"label", "attack_cat", "attack_category", "class", "type", "attack"}
MISSING_CATEGORICAL_TOKENS = {
    "",
    "?",
    "na",
    "n/a",
    "null",
    "none",
    "nan",
    "+nan",
    "-nan",
    "inf",
    "+inf",
    "-inf",
    "infinity",
    "+infinity",
    "-infinity",
}


def is_excluded_feature(name: str) -> bool:
    """Exclude label and obvious identifiers using explicit name rules."""
    lowered = name.strip().lower().replace("-", "_").replace(" ", "_")
    if lowered in LABEL_NAMES:
        return True
    if any(token in lowered.split("_") for token in ("attack", "category", "label", "class")):
        return True
    parts = lowered.split("_")
    return any(token in parts for token in IDENTIFIER_TOKENS) or lowered.endswith("_id")


@dataclass(slots=True)
class TrainOnlyTabularEncoder:
    """Infer numeric/categorical fields and fit imputations/vocabulary on train rows only."""

    requested_features: tuple[str, ...] | None = None
    feature_names_: tuple[str, ...] = ()
    numeric_features_: tuple[str, ...] = ()
    categorical_features_: tuple[str, ...] = ()
    numeric_medians_: dict[str, float] | None = None
    categorical_modes_: dict[str, str] | None = None
    vectorizer_: DictVectorizer | None = None

    def fit(self, rows: Sequence[Mapping[str, str]]) -> TrainOnlyTabularEncoder:
        if not rows:
            raise ValueError("cannot fit preprocessing on empty training data")
        names = self.requested_features or tuple(rows[0].keys())
        selected = tuple(name for name in names if not is_excluded_feature(name))
        if not selected:
            raise ValueError("no eligible features remain after identifier/label exclusions")
        numeric: list[str] = []
        categorical: list[str] = []
        medians: dict[str, float] = {}
        modes: dict[str, str] = {}
        for name in selected:
            values = [_parse_number(row.get(name, "")) for row in rows]
            present = [number for is_numeric, number in values if is_numeric and number is not None]
            if present and all(is_numeric for is_numeric, _ in values):
                numeric.append(name)
                medians[name] = statistics.median(present)
            else:
                categorical.append(name)
                counts = Counter(
                    value.strip()
                    for row in rows
                    if (value := row.get(name, "").strip())
                    and value.casefold() not in MISSING_CATEGORICAL_TOKENS
                )
                modes[name] = (
                    min(counts, key=lambda value: (-counts[value], value)) if counts else ""
                )
        self.feature_names_ = selected
        self.numeric_features_ = tuple(numeric)
        self.categorical_features_ = tuple(categorical)
        self.numeric_medians_ = medians
        self.categorical_modes_ = modes
        transformed = [self._encode_row(row) for row in rows]
        self.vectorizer_ = DictVectorizer(sparse=True, sort=True)
        self.vectorizer_.fit(transformed)
        return self

    def transform(self, rows: Sequence[Mapping[str, str]]) -> Any:
        if self.vectorizer_ is None:
            raise RuntimeError("encoder must be fit on training rows before transform")
        return self.vectorizer_.transform([self._encode_row(row) for row in rows])

    def _encode_row(self, row: Mapping[str, str]) -> dict[str, float | str]:
        if self.numeric_medians_ is None or self.categorical_modes_ is None:
            raise RuntimeError("encoder must be fit before rows are encoded")
        encoded: dict[str, float | str] = {}
        for name in self.numeric_features_:
            _, number = _parse_number(row.get(name, ""))
            encoded[name] = self.numeric_medians_[name] if number is None else number
        for name in self.categorical_features_:
            raw_token = row.get(name, "").strip()
            token = (
                self.categorical_modes_[name]
                if raw_token.casefold() in MISSING_CATEGORICAL_TOKENS
                else raw_token
            )
            encoded[name] = token
        return encoded


def _parse_number(value: str) -> tuple[bool, float | None]:
    token = value.strip()
    if token.casefold() in {"", "?", "na", "n/a", "null", "none"}:
        return True, None
    try:
        number = float(token)
    except ValueError:
        return False, None
    return True, number if math.isfinite(number) else None


def majority_predictions(labels: Sequence[str], count: int) -> list[str]:
    if not labels:
        raise ValueError("training labels cannot be empty")
    counts = Counter(labels)
    majority = min(counts, key=lambda label: (-counts[label], label))
    return [majority] * count


def evaluate_predictions(
    truth: Sequence[str], predictions: Sequence[str], *, class_labels: Sequence[str] | None = None
) -> dict[str, Any]:
    if len(truth) != len(predictions):
        raise ValueError("truth and predictions must have equal length")
    labels = sorted(set(truth) | set(predictions)) if class_labels is None else list(class_labels)
    precision, recall, f1, support = precision_recall_fscore_support(
        truth, predictions, labels=labels, zero_division=0
    )
    weighted = precision_recall_fscore_support(
        truth, predictions, labels=labels, average="weighted", zero_division=0
    )[2]
    matrix = confusion_matrix(truth, predictions, labels=labels)
    output: dict[str, Any] = {
        "accuracy": float(accuracy_score(truth, predictions)),
        "macro_precision": float(np.mean(precision)) if len(precision) else 0.0,
        "macro_recall": float(np.mean(recall)) if len(recall) else 0.0,
        "macro_f1": float(np.mean(f1)) if len(f1) else 0.0,
        "weighted_f1": float(weighted),
        "classes": {
            label: {
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index]),
            }
            for index, label in enumerate(labels)
        },
        "confusion_matrix": matrix.tolist(),
        "confusion_matrix_labels": labels,
    }
    if "Normal" in labels:
        benign_index = labels.index("Normal")
        benign_fp = int(matrix[benign_index, :].sum() - matrix[benign_index, benign_index])
        benign_total = int(matrix[benign_index, :].sum())
        output["false_positive_rate_benign_as_attack"] = (
            benign_fp / benign_total if benign_total else None
        )
        attack_indices = [index for index, label in enumerate(labels) if label != "Normal"]
        attack_total = int(matrix[attack_indices, :].sum())
        attack_missed_as_benign = int(matrix[attack_indices, benign_index].sum())
        output["false_negative_rate_attack_as_benign"] = (
            attack_missed_as_benign / attack_total if attack_total else None
        )
    return output


def run_random_forest(
    train_matrix: Any,
    train_labels: Sequence[str],
    test_matrix: Any,
    *,
    seed: int,
    n_estimators: int = 100,
    max_depth: int = 18,
    min_samples_leaf: int = 2,
) -> tuple[list[str], dict[str, float]]:
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        max_features="sqrt",
        min_samples_leaf=min_samples_leaf,
        class_weight="balanced_subsample",
        random_state=seed,
        n_jobs=1,
    )
    started = time.perf_counter()
    model.fit(train_matrix, train_labels)
    train_seconds = time.perf_counter() - started
    started = time.perf_counter()
    predictions = model.predict(test_matrix)
    predict_seconds = time.perf_counter() - started
    return [str(value) for value in predictions], {
        "training_seconds": train_seconds,
        "inference_seconds_total": predict_seconds,
        "inference_seconds_per_row": predict_seconds / max(len(predictions), 1),
    }


def run_isolation_forest(
    train_matrix: Any,
    train_labels: Sequence[str],
    validation_matrix: Any,
    validation_labels: Sequence[str],
    test_matrix: Any,
    *,
    seed: int,
) -> tuple[list[str], dict[str, float]]:
    """Fit on training benign rows; select cutpoint at validation benign 5th score percentile."""
    benign_train = np.asarray(train_labels) == "Normal"
    benign_validation = np.asarray(validation_labels) == "Normal"
    if not benign_train.any() or not benign_validation.any():
        raise ValueError("Isolation Forest requires benign training and validation rows")
    model = IsolationForest(n_estimators=100, contamination="auto", random_state=seed, n_jobs=1)
    started = time.perf_counter()
    model.fit(train_matrix[benign_train])
    train_seconds = time.perf_counter() - started
    validation_scores = model.decision_function(validation_matrix[benign_validation])
    threshold = float(np.quantile(validation_scores, 0.05))
    started = time.perf_counter()
    test_scores = model.decision_function(test_matrix)
    predictions = ["Normal" if score >= threshold else "Attack" for score in test_scores]
    inference_seconds = time.perf_counter() - started
    return predictions, {
        "training_seconds": train_seconds,
        "inference_seconds_total": inference_seconds,
        "inference_seconds_per_row": inference_seconds / max(len(predictions), 1),
        "validation_benign_score_threshold": threshold,
    }
