"""Closed-set unseen-class/source RF evaluation for Stage 5E.2A."""

from __future__ import annotations

import csv
import gzip
import json
import time
from collections import Counter
from pathlib import Path
from typing import Any, cast

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from ml.evaluation.stage5d_cse import EXPECTED_FEATURE_COUNT, SEED, _peak_rss_bytes

TEST_SOURCE = "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv"
UNSEEN_LABEL = "DDoS attacks-LOIC-HTTP"
CHUNK_ROWS = 50_000
RF_CONFIGURATION: dict[str, Any] = {
    "name": "RandomForestClassifier",
    "n_estimators": 100,
    "max_depth": 18,
    "max_features": "sqrt",
    "min_samples_leaf": 2,
    "class_weight": "balanced_subsample",
    "random_state": SEED,
    "n_jobs": 1,
}


def verify_preflight_for_experiment(
    preflight: dict[str, Any], source_files: list[str]
) -> dict[str, Any]:
    """Assert frozen prepared artifacts and the Tuesday unseen-label condition."""
    if not preflight.get("passed"):
        raise ValueError(f"Stage 5D preflight failed: {preflight.get('failures')}")
    files = {item["file"]: item for item in preflight["files"]}
    if set(files) != set(source_files):
        raise ValueError("prepared artifact source list differs from Stage 5D manifest")
    test_file = files.get(TEST_SOURCE)
    if test_file is None:
        raise ValueError("Tuesday-20-02 prepared source is absent")
    train_sources = sorted(set(source_files) - {TEST_SOURCE})
    if TEST_SOURCE in train_sources or len(train_sources) != 6:
        raise ValueError("Tuesday-20-02 must be excluded completely from training")
    train_vocabulary = sorted(
        {label for source in train_sources for label in files[source]["class_counts"]}
    )
    if UNSEEN_LABEL in train_vocabulary:
        raise ValueError("LOIC-HTTP unexpectedly occurs in the training label vocabulary")
    if UNSEEN_LABEL not in test_file["class_counts"]:
        raise ValueError("Tuesday test source does not contain the expected LOIC-HTTP label")
    feature_schemas = {tuple(item["feature_names"]) for item in files.values()}
    if len(feature_schemas) != 1:
        raise ValueError("prepared predictors do not share the frozen ordered schema")
    features = next(iter(feature_schemas))
    if len(features) != EXPECTED_FEATURE_COUNT:
        raise ValueError(f"expected {EXPECTED_FEATURE_COUNT} predictors, found {len(features)}")
    return {
        "passed": True,
        "training_sources": train_sources,
        "test_source": TEST_SOURCE,
        "sources_disjoint": TEST_SOURCE not in train_sources,
        "feature_count": len(features),
        "feature_names": list(features),
        "training_label_vocabulary": train_vocabulary,
        "loic_http_absent_from_training": True,
        "loic_http_test_support": int(test_file["class_counts"][UNSEEN_LABEL]),
        "all_prepared_artifacts_passed_stage5d_preflight": True,
    }


def _load_training_arrays(
    paths: list[Path], feature_count: int, row_count: int, label_codes: dict[str, int]
) -> tuple[np.ndarray, np.ndarray]:
    x = np.empty((row_count, feature_count), dtype=np.float32)
    y = np.empty(row_count, dtype=np.int8)
    offset = 0
    for path in paths:
        with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
            reader = csv.reader(stream)
            header = next(reader, None)
            if header is None or len(header) != feature_count + 1 or header[-1] != "Label":
                raise ValueError(f"preflighted training schema changed: {path}")
            for row in reader:
                if len(row) != feature_count + 1 or row[-1] not in label_codes:
                    raise ValueError(f"invalid training record in {path} at row {offset + 2}")
                x[offset] = np.asarray(row[:-1], dtype=np.float32)
                y[offset] = label_codes[row[-1]]
                offset += 1
    if offset != row_count:
        raise ValueError(f"training row count changed: observed {offset}, expected {row_count}")
    return x, y


def _stream_test_predictions(
    path: Path,
    model: RandomForestClassifier,
    feature_count: int,
    label_codes: dict[str, int],
    training_labels: list[str],
    evaluation_labels: list[str],
) -> tuple[np.ndarray, Counter[str], float]:
    """Predict test chunks; retain only confusion counts, not all predictions."""
    evaluation_codes = {label: index for index, label in enumerate(evaluation_labels)}
    matrix = np.zeros((len(evaluation_labels), len(evaluation_labels)), dtype=np.int64)
    support: Counter[str] = Counter()
    elapsed = 0.0
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        if header is None or len(header) != feature_count + 1 or header[-1] != "Label":
            raise ValueError(f"preflighted test schema changed: {path}")
        while True:
            feature_rows: list[list[float]] = []
            truth_rows: list[str] = []
            for _ in range(CHUNK_ROWS):
                try:
                    row = next(reader)
                except StopIteration:
                    break
                if len(row) != feature_count + 1 or row[-1] not in evaluation_codes:
                    raise ValueError(f"invalid test record in {path}")
                feature_rows.append([float(value) for value in row[:-1]])
                truth_rows.append(row[-1])
            if not truth_rows:
                break
            features = np.asarray(feature_rows, dtype=np.float32)
            started = time.perf_counter()
            predicted_codes = model.predict(features)
            elapsed += time.perf_counter() - started
            for actual, predicted_code in zip(truth_rows, predicted_codes, strict=True):
                support[actual] += 1
                predicted_label = training_labels[int(predicted_code)]
                matrix[evaluation_codes[actual], evaluation_codes[predicted_label]] += 1
    return matrix, support, elapsed


def _closed_set_metrics(matrix: np.ndarray, labels: list[str]) -> dict[str, Any]:
    supports = matrix.sum(axis=1)
    predicted_supports = matrix.sum(axis=0)
    true_positives = np.diag(matrix)
    precision = np.divide(
        true_positives,
        predicted_supports,
        out=np.zeros(len(labels), dtype=float),
        where=predicted_supports > 0,
    )
    recall = np.divide(
        true_positives,
        supports,
        out=np.zeros(len(labels), dtype=float),
        where=supports > 0,
    )
    f1 = np.divide(
        2 * precision * recall,
        precision + recall,
        out=np.zeros(len(labels), dtype=float),
        where=(precision + recall) > 0,
    )
    test_supported = supports > 0
    benign_index = labels.index("Benign")
    benign_total = int(supports[benign_index])
    attack_total = int(supports.sum() - benign_total)
    benign_fp = int(supports[benign_index] - matrix[benign_index, benign_index])
    attack_fn = int(matrix[:, benign_index].sum() - matrix[benign_index, benign_index])
    return {
        "accuracy": float(true_positives.sum() / supports.sum()) if supports.sum() else 0.0,
        "macro_f1": float(f1[test_supported].mean()) if test_supported.any() else 0.0,
        "macro_f1_denominator": "unique labels present in the test source; includes LOIC-HTTP",
        "macro_f1_denominator_class_count": int(test_supported.sum()),
        "weighted_f1": float(np.average(f1, weights=supports)) if supports.sum() else 0.0,
        "per_class": {
            label: {
                "precision": float(precision[index])
                if supports[index] or predicted_supports[index]
                else None,
                "recall": float(recall[index]) if supports[index] else None,
                "f1": float(f1[index]) if supports[index] or predicted_supports[index] else None,
                "test_support": int(supports[index]),
                "predicted_support": int(predicted_supports[index]),
            }
            for index, label in enumerate(labels)
            if supports[index] > 0
        },
        "confusion_matrix_labels": labels,
        "confusion_matrix_actual_rows_predicted_columns": matrix.tolist(),
        "benign_fpr": benign_fp / benign_total if benign_total else None,
        "attack_fnr_as_benign": attack_fn / attack_total if attack_total else None,
    }


def run_experiment(root: Path, preflight: dict[str, Any]) -> dict[str, Any]:
    """Run the full Tuesday-held-out RF experiment after preflight succeeds."""
    manifest_path = root / "experiments/stage5d/cse-preparation.json"
    with manifest_path.open(encoding="utf-8") as stream:
        manifest = cast(dict[str, Any], json.load(stream))
    source_stats = {item["file"]: item for item in manifest["source_statistics"]}
    paths = {name: root / item["output_path"] for name, item in source_stats.items()}
    checked = verify_preflight_for_experiment(preflight, list(source_stats))
    train_sources = checked["training_sources"]
    if set(train_sources) & {TEST_SOURCE}:
        raise ValueError("source-disjoint check failed")
    train_labels = checked["training_label_vocabulary"]
    label_codes = {label: index for index, label in enumerate(train_labels)}
    train_rows = sum(source_stats[name]["final_usable_row_count"] for name in train_sources)
    test_rows = int(source_stats[TEST_SOURCE]["final_usable_row_count"])
    x_train, y_train = _load_training_arrays(
        [paths[name] for name in train_sources], EXPECTED_FEATURE_COUNT, train_rows, label_codes
    )
    model = RandomForestClassifier(
        n_estimators=RF_CONFIGURATION["n_estimators"],
        max_depth=RF_CONFIGURATION["max_depth"],
        max_features=RF_CONFIGURATION["max_features"],
        min_samples_leaf=RF_CONFIGURATION["min_samples_leaf"],
        class_weight=RF_CONFIGURATION["class_weight"],
        random_state=RF_CONFIGURATION["random_state"],
        n_jobs=RF_CONFIGURATION["n_jobs"],
    )
    training_started = time.perf_counter()
    model.fit(x_train, y_train)
    training_seconds = time.perf_counter() - training_started
    del x_train, y_train

    test_vocab = sorted(source_stats[TEST_SOURCE]["class_counts"])
    evaluation_labels = sorted(set(train_labels) | set(test_vocab))
    matrix, observed_test_counts, inference_seconds = _stream_test_predictions(
        paths[TEST_SOURCE],
        model,
        EXPECTED_FEATURE_COUNT,
        label_codes,
        train_labels,
        evaluation_labels,
    )
    if sum(observed_test_counts.values()) != test_rows:
        raise ValueError("streamed test row count differs from preparation manifest")
    if dict(sorted(observed_test_counts.items())) != source_stats[TEST_SOURCE]["class_counts"]:
        raise ValueError("streamed test label distribution differs from preparation manifest")
    metrics = _closed_set_metrics(matrix, evaluation_labels)
    loic_index = evaluation_labels.index(UNSEEN_LABEL)
    loic_row = matrix[loic_index]
    known_class_distribution = {
        label: int(loic_row[index])
        for index, label in enumerate(evaluation_labels)
        if label in label_codes
    }
    loic_total = int(observed_test_counts[UNSEEN_LABEL])
    return {
        "experiment_id": "CSE-5E2A-TUESDAY-LOIC-HTTP-CLOSED-SET-RF",
        "stage": "5E.2A",
        "condition": "closed-set unseen-class/source baseline; not novelty detection",
        "preflight": checked,
        "model": RF_CONFIGURATION,
        "feature_count": EXPECTED_FEATURE_COUNT,
        "feature_names": checked["feature_names"],
        "feature_preprocessing": (
            "frozen Stage 5D fixed CSV numeric-to-float32 conversion; no fitted transform"
        ),
        "label_encoding": (
            "sorted training-source vocabulary only; integer codes assigned from training labels"
        ),
        "training_rows": train_rows,
        "test_rows": test_rows,
        "training_class_vocabulary": train_labels,
        "training_class_distribution": {
            label: sum(source_stats[name]["class_counts"].get(label, 0) for name in train_sources)
            for label in train_labels
        },
        "test_class_distribution": dict(sorted(observed_test_counts.items())),
        "unseen_label": {
            "label": UNSEEN_LABEL,
            "absent_from_training_vocabulary": UNSEEN_LABEL not in label_codes,
            "test_flows": loic_total,
            "predicted_class_distribution": known_class_distribution,
            "predicted_distribution_rates": {
                label: count / loic_total for label, count in known_class_distribution.items()
            },
            "loic_http_to_benign_count": int(loic_row[evaluation_labels.index("Benign")]),
            "loic_http_to_benign_rate": float(
                loic_row[evaluation_labels.index("Benign")] / loic_total
            ),
            "loic_http_to_each_known_class": {
                label: {
                    "count": count,
                    "rate": count / loic_total,
                }
                for label, count in known_class_distribution.items()
            },
            "closed_set_constraint": (
                "Classifier has no unknown/reject output; every LOIC-HTTP flow is assigned "
                "to one training class."
            ),
        },
        "metrics": metrics,
        "training_seconds": training_seconds,
        "inference_seconds_total_predict_calls_only": inference_seconds,
        "inference_seconds_per_test_flow": inference_seconds / max(test_rows, 1),
        "peak_process_rss_bytes": _peak_rss_bytes(),
        "peak_memory_measurement": (
            "process peak RSS from getrusage; includes preflight and data loading, not GPU memory"
        ),
        "stage5d_comparison": {
            "methodologically_comparable": False,
            "reason": (
                "Stage 5D A/B are known-class evaluations on different held-out sources and "
                "label supports; Tuesday is an unseen-class/source condition. Metric values "
                "are retained separately and are not used as direct performance comparisons."
            ),
        },
    }
